package cli

// claudetrust.go writes the ONE key `snug host trust` records, into the host's
// real ~/.claude.json.
//
// It is the only place snug writes a host dotfile it otherwise only reads
// (hostTrustsTarget, claude.go). Three rules follow from that, and they are the
// whole of this file:
//
//   - PRESERVE. The file is Claude Code's own state and can run to six figures
//     of bytes. Unmarshalling it into a map[string]any and re-marshalling would
//     reorder every key and re-render every number; that is not a write, it is
//     a rewrite of somebody else's file. So the edit is a byte SPLICE:
//     json.Decoder gives the exact offsets of the value being replaced, and
//     every byte outside that range is copied through untouched.
//
//   - REFUSE RATHER THAN CLOBBER. A top level that is not an object, a
//     `projects` that is not an object, a duplicate key at any level being
//     edited, a file that does not parse as strict JSON, a file over the cap:
//     each refuses and writes nothing. Claude Code reads JSONC here and snug
//     does not, so a hand-edited file is exactly the one that must not be
//     rewritten from a partial understanding.
//
//   - ATOMIC, AND NOT LAST-WRITER-WINS BY ACCIDENT. Write a temp file in the
//     same directory, fsync, rename. Claude Code may be running and rewriting
//     this file the same way; the destination is re-stat'ed immediately before
//     the rename and a changed device/inode/size/mtime refuses, which narrows
//     the window in which snug could drop somebody else's update to the
//     microseconds between the stat and the rename. It does not close it, and
//     saying it does would be the kind of claim CLAUDE.md's "no silent
//     downgrade" is about.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/hostread"
)

// claudeTrustPlan is what the command decided before it printed anything: the
// bytes that would be written, and the identity of the file they were derived
// from, so the commit can tell that nothing moved underneath it.
type claudeTrustPlan struct {
	path    string // ~/.claude.json, as the human would name it
	write   string // where the rename actually lands; differs when path is a symlink
	next    []byte // the bytes to write
	created bool   // the file does not exist; the write creates it
	already bool   // the key is already true; there is nothing to do
	before  os.FileInfo
}

// planClaudeTrust reads the host file and produces the bytes that would replace
// it. It writes nothing.
func planClaudeTrust(home, key string) (claudeTrustPlan, error) {
	path := filepath.Join(home, ".claude.json")
	plan := claudeTrustPlan{path: path, write: path}

	// A dotfile-repo symlink is a real arrangement, and os.Rename does NOT
	// follow one: renaming onto ~/.claude.json would replace the LINK with a
	// regular file and leave the repo it pointed at untouched — a silent
	// clobber of something the user set up on purpose. So resolve it and land
	// the rename on the file itself. A DANGLING link is refused instead:
	// creating the file it names is a different decision from recording a key
	// in one that exists.
	if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		real, rerr := filepath.EvalSymlinks(path)
		if rerr != nil {
			return plan, fmt.Errorf("%s is a symlink that does not resolve (%v) — nothing was "+
				"written; point it at a file that exists, or remove it and re-run",
				visibleValue(path), rerr)
		}
		plan.write = real
	}

	// hostread.Required, not Optional: this command NAMED the file, so
	// "present but a FIFO", "present but 9 GB" and "present but unreadable" are
	// refusals with their own message rather than the silent "not trusted" the
	// read on the sandbox path degrades to (hostTrustsTarget). Only ENOENT is
	// an ordinary state here, and it is the state a host that has never run
	// Claude Code is in — which is the host issue #460 is about.
	doc, err := hostread.Required(path, maxClaudeJSONBytes)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		plan.created = true
		plan.next = freshClaudeTrustDoc(key)
		return plan, nil
	default:
		return plan, fmt.Errorf("%w — nothing was written; snug will not replace a file it "+
			"could not read whole", err)
	}
	if fi, serr := os.Stat(plan.write); serr == nil {
		plan.before = fi
	}

	next, changed, perr := claudeTrustPatch(doc, key)
	if perr != nil {
		return plan, fmt.Errorf("%s %v — nothing was written. Claude Code reads JSONC here "+
			"(comments, trailing commas) and snug reads strict JSON only, so fix the file or add "+
			"the key by hand: projects.%s.hasTrustDialogAccepted = true",
			visibleValue(path), perr, jsonString(key))
	}
	plan.next, plan.already = next, !changed
	return plan, nil
}

// freshClaudeTrustDoc is the whole file snug authors when the host has never
// run Claude Code. ONE key: onboarding, updates and everything else stay
// unanswered, because this command was asked to record one decision and
// authoring a second on the host would be exactly the widening issue #460
// refuses.
func freshClaudeTrustDoc(key string) []byte {
	return []byte("{\n  \"projects\": {\n    " + jsonString(key) +
		": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n")
}

// commitClaudeTrust writes plan.next over plan.write atomically.
func commitClaudeTrust(plan claudeTrustPlan) error {
	dir := filepath.Dir(plan.write)
	tmp, err := os.CreateTemp(dir, ".claude.json.snug-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file next to %s: %w — the write is a rename, so "+
			"the temporary file has to live in the same directory", visibleValue(plan.write), err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename has taken the name away

	perm := fs.FileMode(0o600)
	if plan.before != nil {
		perm = plan.before.Mode().Perm()
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("setting mode %v on %s: %w", perm, name, err)
	}
	if _, err := tmp.Write(plan.next); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flushing %s: %w — a rename over a file that was never on disk trades "+
			"one file for none", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", name, err)
	}

	// The last look before the swap. Claude Code writes this file too; if it
	// has done so since planClaudeTrust read it, this rename would silently
	// drop that update, so it refuses and asks for a re-run instead.
	if err := claudeJSONUnchanged(plan); err != nil {
		return err
	}
	if err := os.Rename(name, plan.write); err != nil {
		return fmt.Errorf("replacing %s with %s: %w", visibleValue(plan.write), name, err)
	}
	return nil
}

// claudeJSONUnchanged is that check. Device, inode, size and mtime: Claude Code
// writes this file by rename too, so a new inode is the shape a concurrent
// write actually takes, and size/mtime cover an in-place rewrite.
func claudeJSONUnchanged(plan claudeTrustPlan) error {
	now, err := os.Stat(plan.write)
	if plan.created {
		if err == nil {
			return fmt.Errorf("%s appeared while snug was preparing to create it — nothing was "+
				"written; re-run `snug host trust` to fold the key into the file that is there now",
				visibleValue(plan.write))
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s went away while snug was preparing to write it (%v) — nothing was "+
			"written; re-run `snug host trust`", visibleValue(plan.write), err)
	}
	if sameClaudeJSON(plan.before, now) {
		return nil
	}
	return fmt.Errorf("%s changed on disk while snug was preparing to write it — Claude Code is "+
		"probably running. Nothing was written; quit it, or just re-run `snug host trust`, which "+
		"would otherwise have thrown away whatever it just wrote", visibleValue(plan.write))
}

func sameClaudeJSON(before, now os.FileInfo) bool {
	if before == nil || now == nil {
		return false
	}
	if before.Size() != now.Size() || !before.ModTime().Equal(now.ModTime()) {
		return false
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := now.Sys().(*syscall.Stat_t)
	if !aok || !bok {
		return true // no inode to compare; size and mtime already agreed
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// ── the splice ───────────────────────────────────────────────────────────────

// claudeTrustPatch sets projects.<key>.hasTrustDialogAccepted = true in doc and
// returns the result. changed is false when the key is already true, in which
// case out is doc unmodified.
func claudeTrustPatch(doc []byte, key string) (out []byte, changed bool, err error) {
	return jsonSetPath(doc, "", []string{"projects", key, "hasTrustDialogAccepted"}, "true")
}

// jsonMember is one member of a JSON object, with byte offsets into the object
// it came from. lead is the whitespace before its key with any comma stripped —
// "\n  " in a pretty file, "" in a compact one — and it is what lets an
// INSERTED member match the file's own layout instead of announcing itself.
type jsonMember struct {
	key      string
	lead     string
	valStart int
	valEnd   int
}

// jsonObjectMembers splits obj, which must be a JSON object, into its members
// in file order. closeAt is the index of its final '}'.
//
// json.Decoder is doing the parsing: InputOffset() after Decode is the end of
// the value and json.RawMessage is exactly the value's bytes, so
// end-len(raw) is where the value starts. That pair is what makes a splice
// possible at all, and it is the reason nothing here re-implements a scanner.
func jsonObjectMembers(obj []byte) (members []jsonMember, closeAt int, err error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, notStrictJSON(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, errors.New("is not a JSON object")
	}
	cursor := int(dec.InputOffset())
	for dec.More() {
		kt, kerr := dec.Token()
		if kerr != nil {
			return nil, 0, notStrictJSON(kerr)
		}
		k, ok := kt.(string)
		if !ok {
			return nil, 0, errors.New("has a member whose name is not a string")
		}
		keyStart := cursor + bytes.IndexByte(obj[cursor:], '"')
		var raw json.RawMessage
		if derr := dec.Decode(&raw); derr != nil {
			return nil, 0, notStrictJSON(derr)
		}
		end := int(dec.InputOffset())
		members = append(members, jsonMember{
			key:      k,
			lead:     strings.TrimPrefix(string(obj[cursor:keyStart]), ","),
			valStart: end - len(raw),
			valEnd:   end,
		})
		cursor = end
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return nil, 0, notStrictJSON(err)
	}
	return members, int(dec.InputOffset()) - 1, nil
}

// jsonSetPath binds path (a chain of object keys) to the literal leaf inside
// obj, preserving every byte it did not have to change. lead is the whitespace
// obj's own member carried, and exists only so a freshly created member is
// indented like the file around it.
//
// A duplicate of a key on the path refuses: Go's decoder takes the last such
// member and Claude Code's takes whichever its parser takes, so an edit to
// "the" member is an edit to one of two things nobody agreed on.
func jsonSetPath(obj []byte, lead string, path []string, leaf string) (out []byte, changed bool, err error) {
	members, closeAt, err := jsonObjectMembers(obj)
	if err != nil {
		return nil, false, err
	}
	var found *jsonMember
	for i := range members {
		if members[i].key != path[0] {
			continue
		}
		if found != nil {
			return nil, false, fmt.Errorf("names %s twice", jsonString(path[0]))
		}
		found = &members[i]
	}

	if found != nil {
		if len(path) == 1 {
			if string(obj[found.valStart:found.valEnd]) == leaf {
				return obj, false, nil
			}
			return splice(obj, found.valStart, found.valEnd, []byte(leaf)), true, nil
		}
		inner, ichanged, ierr := jsonSetPath(obj[found.valStart:found.valEnd], found.lead, path[1:], leaf)
		if ierr != nil {
			return nil, false, fmt.Errorf("member %s %v", jsonString(path[0]), ierr)
		}
		if !ichanged {
			return obj, false, nil
		}
		return splice(obj, found.valStart, found.valEnd, inner), true, nil
	}

	// Not present: insert it as the last member, wearing the layout its
	// siblings wear.
	memberLead := deeperLead(lead)
	if n := len(members); n > 0 {
		memberLead = members[n-1].lead
	}
	fresh := []byte(jsonString(path[0]) + ": " + renderChain(memberLead, path[1:], leaf))
	if len(members) == 0 {
		return splice(obj, closeAt, closeAt, append(append([]byte(memberLead), fresh...), []byte(lead)...)), true, nil
	}
	last := members[len(members)-1]
	return splice(obj, last.valEnd, last.valEnd, append([]byte(","+memberLead), fresh...)), true, nil
}

// renderChain builds the nested objects a missing path needs, indented one
// level deeper per link, so inserting into a 2-space file produces 2-space
// output and inserting into a compact one produces compact output.
func renderChain(lead string, path []string, leaf string) string {
	if len(path) == 0 {
		return leaf
	}
	inner := deeperLead(lead)
	return "{" + inner + jsonString(path[0]) + ": " + renderChain(inner, path[1:], leaf) + lead + "}"
}

// deeperLead is one indentation level in, or nothing at all when the object
// being edited is written on a single line.
func deeperLead(lead string) string {
	if !strings.Contains(lead, "\n") {
		return ""
	}
	return lead + "  "
}

// notStrictJSON keeps every error out of this file readable as a BARE CLAUSE,
// so the caller's "<path> <clause> — nothing was written" is one sentence
// whether the decoder refused or the shape did.
func notStrictJSON(err error) error {
	return fmt.Errorf("does not parse as strict JSON (%v)", err)
}

func splice(b []byte, from, to int, with []byte) []byte {
	out := make([]byte, 0, len(b)-(to-from)+len(with))
	out = append(out, b[:from]...)
	out = append(out, with...)
	return append(out, b[to:]...)
}

// jsonString quotes s as a JSON string with HTML escaping OFF. A directory
// containing '&' or '<' is a real directory, and & in the key would be the
// same JSON value spelled so that the human cannot grep for it in their own
// file.
func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return `""`
	}
	return strings.TrimSuffix(b.String(), "\n")
}
