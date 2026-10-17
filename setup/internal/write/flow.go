package write

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/probe"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/verify"
)

// Plan is what writing the profile would do, checked and ready to show.
type Plan struct {
	Path      string // profileDir/NAME.toml
	Old, New  string
	Overwrite bool
	// Notes are things the person should read before saying yes: nothing in
	// them stops the write.
	Notes []string
	// Blocked is why the file must not be written. A plan with Blocked set is
	// never applied: the file would not do what the screen says, and a user
	// believing otherwise is a silent downgrade.
	Blocked []string
}

// Prepare checks d against the real snug and returns the Plan for writing it
// to profileDir/NAME.toml. It writes nothing.
//
// With snug == "" nothing is verified and Notes says so. Otherwise
// verify.Run resolves the draft with others (the user files that define the
// identity profile it includes and what those include) beside it, and every
// difference between that and the draft goes to Blocked. The one exception is
// a refusal that names a profile of idWarn: the identity profile the person
// chose is broken in their own file, and the new file is still what the
// screen says, so that goes to Notes ("profile will not run").
//
// A profile called NAME defined anywhere but profileDir/NAME.toml blocks the
// write: the new file would shadow or duplicate it. The error is for what
// cannot be answered at all: an unusable name, an unreadable existing file,
// snug printing no document.
func Prepare(ctx context.Context, d *draft.Draft, profileDir, snug string, run hostfacts.Runner, profiles []ingest.Profile, others []verify.File, idWarn *probe.Warning) (Plan, error) {
	if !draft.ValidProfileName(d.Name) {
		return Plan{}, fmt.Errorf("%q is not a profile name (letters, digits and dashes; no underscore, dot or leading @); change NAME", safe.Inline(d.Name))
	}
	p := Plan{Path: filepath.Join(profileDir, d.Name+".toml"), New: d.Render()}
	for _, pr := range profiles {
		if pr.Name != d.Name {
			continue
		}
		if def := filepath.Join(pr.Dir, pr.File); filepath.Clean(def) != filepath.Clean(p.Path) {
			p.Blocked = append(p.Blocked, fmt.Sprintf("profile %s is defined in %s; change NAME", d.Name, safe.Inline(def)))
		}
	}
	old, exists, err := ReadProfile(p.Path)
	if err != nil {
		return Plan{}, fmt.Errorf("cannot look at %s: %w", p.Path, err)
	}
	p.Old, p.Overwrite = old, exists

	if snug == "" {
		p.Notes = append(p.Notes, "not verified by snug")
		return p, nil
	}
	doc, err := verify.Run(ctx, run, snug, d, others)
	if err != nil {
		return Plan{}, fmt.Errorf("snug could not check the profile: %w", err)
	}
	diffs := verify.Compare(d, doc)
	if len(diffs) == 0 {
		return p, nil
	}
	if name := refusedIdentity(doc, d, idWarn); name != "" {
		p.Notes = append(p.Notes, name+": refused by snug, profile will not run")
		return p, nil
	}
	for _, df := range diffs {
		p.Blocked = append(p.Blocked, strings.Join(strings.Fields(safe.Inline(df.What)), " "))
	}
	return p, nil
}

// refusedIdentity returns the name of the profile in idWarn that snug's
// refusal names and d includes, or "".
func refusedIdentity(doc verify.Doc, d *draft.Draft, idWarn *probe.Warning) string {
	if idWarn == nil || doc.Snug.Outcome == "ok" || doc.Refusal == nil {
		return ""
	}
	for _, n := range idWarn.Profiles {
		if slices.Contains(d.Include, n) && namesProfile(doc.Refusal.Message, n) {
			return n
		}
	}
	return ""
}

// namesProfile reports whether msg contains name as a whole word, so that
// "work" is not found in "network".
func namesProfile(msg, name string) bool {
	word := func(c byte) bool {
		return c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	for i := 0; ; {
		j := strings.Index(msg[i:], name)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(name)
		if (j == 0 || !word(msg[j-1])) && (end == len(msg) || !word(msg[end])) {
			return true
		}
		i = j + 1
	}
}

// Screen is the diff, the notes and, when the plan can be applied, the
// question.
func (p Plan) Screen() string {
	var b strings.Builder
	if p.Overwrite {
		fmt.Fprintf(&b, "overwrites %s\n", safe.Inline(p.Path))
	} else {
		fmt.Fprintf(&b, "writes %s (new file)\n", safe.Inline(p.Path))
	}
	b.WriteString(LineDiff(p.Old, p.New) + "\n")
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "! %s\n", safe.Inline(n))
	}
	if len(p.Blocked) > 0 {
		b.WriteString("not written: the file would not do what the screen says\n")
		for _, n := range p.Blocked {
			fmt.Fprintf(&b, "! %s\n", n)
		}
		return b.String()
	}
	b.WriteString("write? y/n ")
	return b.String()
}

// Apply writes the plan. It refuses a Blocked plan, and refuses to overwrite
// a file that is no longer what the diff was made against.
func Apply(p Plan) error {
	if len(p.Blocked) > 0 {
		return fmt.Errorf("not writing %s: %s", p.Path, p.Blocked[0])
	}
	if p.Overwrite {
		cur, exists, err := ReadProfile(p.Path)
		if err != nil {
			return err
		}
		if !exists || cur != p.Old {
			return fmt.Errorf("%s changed since the diff was shown; run snug-setup again", p.Path)
		}
	}
	return WriteProfile(p.Path, p.New, p.Overwrite)
}

// RunLine is the command that runs the profile: the directory is "." when it
// is cwd.
func RunLine(d *draft.Draft, cwd string) string {
	if filepath.Clean(d.Host.Target) == filepath.Clean(cwd) {
		return d.RunLine(".")
	}
	return d.RunLine(d.Host.Target)
}

// PrepareFix reads the file a rename warning is about and returns it with the
// one token replaced, and where the original will be saved. It refuses a
// warning with no rename, a file that is not a regular file (a symlink is
// refused, because the replacement would turn it into a copy), and a file in
// which the token is not written inside an include array.
func PrepareFix(w probe.Warning, now time.Time) (path, backup string, oldBody, newBody []byte, err error) {
	if w.Old == "" || w.New == "" {
		return "", "", nil, nil, errors.New("this warning has no mechanical fix")
	}
	if err := regularFile(w.File); err != nil {
		return "", "", nil, nil, err
	}
	old, _, err := ReadProfile(w.File)
	if err != nil {
		return "", "", nil, nil, err
	}
	neu := probe.FixRename([]byte(old), w.Old, w.New)
	if bytes.Equal(neu, []byte(old)) {
		return "", "", nil, nil, fmt.Errorf("%s has no %s inside an include list, so there is nothing to rename; edit it by hand", safe.Inline(w.File), w.Old)
	}
	return w.File, probe.BackupPath(w.File, now), []byte(old), neu, nil
}

func regularFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; snug-setup does not rewrite through one, edit the file it points to", safe.Inline(path))
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", safe.Inline(path))
	}
	return nil
}

// ApplyFix saves oldBody to backup, then replaces path with newBody, keeping
// path's mode. It refuses when path is no longer a regular file holding
// exactly oldBody, and when backup already exists: an earlier backup holds an
// earlier original, which a second fix on the same day must not overwrite.
// The check and the rename are not atomic; a process that rewrites the file
// in between wins the race and loses nothing but the fix, because the backup
// is written first.
func ApplyFix(path, backup string, oldBody, newBody []byte) error {
	if err := regularFile(path); err != nil {
		return err
	}
	cur, _, err := ReadProfile(path)
	if err != nil {
		return err
	}
	if cur != string(oldBody) {
		return fmt.Errorf("%s changed since the diff was shown; run snug-setup again", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	// HOSTREAD-EXEMPT: O_CREATE|O_EXCL fails on any existing name, FIFO
	// included, so this never opens a file it did not create.
	bf, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; move it away or fix the file by hand", backup)
		}
		return err
	}
	if _, err := bf.Write(oldBody); err != nil {
		bf.Close()
		return err
	}
	if err := bf.Close(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snug-setup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(newBody); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
