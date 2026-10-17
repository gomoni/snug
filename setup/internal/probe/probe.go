// Package probe asks the real snug whether the person's own profiles resolve,
// and turns a refusal into one warning line. Where the refusal is a rename
// snug itself names, it can also rewrite that one token in the file.
package probe

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/verify"
)

// Warning is one problem found in a user's profile file.
type Warning struct {
	File     string   // full path of the user's file
	Profiles []string // names refused for this reason
	Line     string   // one line: "vyskocilm uses @cwd-rw, renamed @target-rw"
	Full     string   // snug's message, for `?`
	Old, New string   // set only for a mechanical rename
}

// renamed matches the rename refusal snug prints. It is not anchored: a caller
// may wrap the message in its own context.
var renamed = regexp.MustCompile(`(@[a-z0-9-]+) is now (@[a-z0-9-]+):`)

// Scope returns the profiles worth probing against one target: those that
// pin an identity, because the IDENTITY row may offer any of them, and those
// d includes. A profile of the person's own that is neither (a marp setup
// beside a Go project) is left alone: its problems with this target are not
// problems of this profile.
func Scope(profiles []ingest.Profile, d *draft.Draft) []ingest.Profile {
	var out []ingest.Profile
	for _, p := range profiles {
		if p.Identity.Pins() || slices.Contains(d.Include, p.Name) {
			out = append(out, p)
		}
	}
	return out
}

// Check runs `snug --dry-run --json -p NAME TARGET` for each profile, in the
// person's own configuration, and returns one Warning per problem: profiles of
// one file refused with the same rename are one Warning. snug == "" returns nil
// and runs nothing. A profile snug answers nothing for is a Warning too,
// because a profile that was not checked must not look like one that passed.
//
// Abuse: the profile names come from the person's own directories and snug's
// message from snug; neither is the target's. Both still reach the screen
// through safe.Inline.
func Check(ctx context.Context, run hostfacts.Runner, snug, target string, profiles []ingest.Profile) []Warning {
	if snug == "" {
		return nil
	}
	var out []Warning
	seen := map[string]bool{}
	for _, p := range profiles {
		if !draft.ValidProfileName(p.Name) || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		file := filepath.Join(p.Dir, p.File)
		res, _ := run(ctx, nil, snug, "--dry-run", "--json", "-p", p.Name, target)
		doc, err := verify.Parse(res.Stdout)
		if err != nil {
			out = append(out, Warning{File: file, Profiles: []string{p.Name}, Line: p.Name + ": not checked, snug printed no document"})
			continue
		}
		if doc.Snug.Outcome == "ok" && doc.Snug.PolicyResolved {
			continue
		}
		msg := "snug refused it and gave no message"
		if doc.Refusal != nil && doc.Refusal.Message != "" {
			msg = doc.Refusal.Message
		}
		msg = strings.Join(strings.Fields(safe.Inline(msg)), " ")
		if m := renamed.FindStringSubmatch(msg); m != nil {
			i := slices.IndexFunc(out, func(w Warning) bool { return w.File == file && w.Old == m[1] && w.New == m[2] })
			if i < 0 {
				out = append(out, Warning{File: file, Full: msg, Old: m[1], New: m[2]})
				i = len(out) - 1
			}
			out[i].Profiles = append(out[i].Profiles, p.Name)
			continue
		}
		out = append(out, Warning{File: file, Profiles: []string{p.Name}, Full: msg, Line: lineOf(p.Name, msg)})
	}
	for i := range out {
		if w := &out[i]; w.Old != "" {
			verb := "uses"
			if len(w.Profiles) > 1 {
				verb = "use"
			}
			w.Line = strings.Join(w.Profiles, ", ") + " " + verb + " " + w.Old + ", renamed " + w.New
		}
	}
	return out
}

// lineOf is the one-line form of snug's refusal msg for profile name: the
// name, then the first sentence of msg. snug starts most messages with
// `profile "NAME"`; that is dropped, so the name is not said twice.
func lineOf(name, msg string) string {
	if rest, ok := strings.CutPrefix(msg, "profile "+strconv.Quote(name)+" "); ok {
		return name + " " + firstSentence(rest)
	}
	return name + ": " + firstSentence(msg)
}

// firstSentence is msg up to its first ". " or its end.
func firstSentence(msg string) string {
	if i := strings.Index(msg, ". "); i >= 0 {
		msg = msg[:i+1]
	}
	return msg
}

// BackupPath is where a file is copied before a fix: file + ".bak-" + the date.
func BackupPath(file string, now time.Time) string {
	return file + ".bak-" + now.Format("20060102")
}

// FixRename returns body with every string equal to old inside an `include`
// array replaced by new, and every other byte unchanged. It reads just enough
// TOML to skip comments and strings (multi-line ones too), so an `@cwd-rw` in
// a comment, a description or a multi-line string is left alone; it does not
// parse the file and never re-serialises it. A quoted key "include" is not
// recognised, which leaves such a file unfixed, never wrongly fixed.
func FixRename(body []byte, old, new string) []byte {
	var out bytes.Buffer
	i := 0
	for i < len(body) {
		c := body[i]
		switch {
		case c == '#':
			j := indexByteFrom(body, '\n', i)
			out.Write(body[i:j])
			i = j
		case c == '"' || c == '\'':
			j := skipString(body, i)
			out.Write(body[i:j])
			i = j
		case isKeyByte(c):
			j := i
			for j < len(body) && isKeyByte(body[j]) {
				j++
			}
			out.Write(body[i:j])
			if string(body[i:j]) == "include" && (i == 0 || !isKeyByte(body[i-1])) {
				if k, ok := arrayStart(body, j); ok {
					out.Write(body[j:k])
					i = rewriteArray(&out, body, k, old, new)
					continue
				}
			}
			i = j
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.Bytes()
}

func isKeyByte(c byte) bool {
	return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func indexByteFrom(b []byte, c byte, from int) int {
	if i := bytes.IndexByte(b[from:], c); i >= 0 {
		return from + i
	}
	return len(b)
}

// skipString returns the index just past the TOML string that starts at i.
func skipString(b []byte, i int) int {
	q := b[i]
	if bytes.HasPrefix(b[i:], []byte{q, q, q}) {
		j := i + 3
		for j < len(b) {
			switch {
			case q == '"' && b[j] == '\\':
				j += 2
			case bytes.HasPrefix(b[j:], []byte{q, q, q}):
				j += 3
				for j < len(b) && b[j] == q {
					j++
				}
				return j
			default:
				j++
			}
		}
		return len(b)
	}
	j := i + 1
	for j < len(b) && b[j] != q && b[j] != '\n' {
		if q == '"' && b[j] == '\\' {
			j++
		}
		j++
	}
	if j < len(b) && b[j] == q {
		j++
	}
	if j > len(b) {
		j = len(b)
	}
	return j
}

// arrayStart reports where the "[" of `= [` is when only blanks separate it
// from the key ending at j; the returned index is just past the "[".
func arrayStart(b []byte, j int) (int, bool) {
	blank := func(c byte) bool { return c == ' ' || c == '\t' }
	for j < len(b) && blank(b[j]) {
		j++
	}
	if j >= len(b) || b[j] != '=' {
		return 0, false
	}
	j++
	for j < len(b) && (blank(b[j]) || b[j] == '\n' || b[j] == '\r') {
		j++
	}
	if j >= len(b) || b[j] != '[' {
		return 0, false
	}
	return j + 1, true
}

// rewriteArray copies b from the first element of an array to just past its
// closing bracket into out, replacing strings equal to old, and returns the
// index after the bracket.
func rewriteArray(out *bytes.Buffer, b []byte, i int, old, new string) int {
	for i < len(b) {
		c := b[i]
		switch {
		case c == ']':
			out.WriteByte(c)
			return i + 1
		case c == '#':
			j := indexByteFrom(b, '\n', i)
			out.Write(b[i:j])
			i = j
		case c == '"' || c == '\'':
			j := skipString(b, i)
			if j-i == len(old)+2 && b[j-1] == c && string(b[i+1:j-1]) == old {
				out.WriteByte(c)
				out.WriteString(new)
				out.WriteByte(c)
			} else {
				out.Write(b[i:j])
			}
			i = j
		default:
			out.WriteByte(c)
			i++
		}
	}
	return i
}
