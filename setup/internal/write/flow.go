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
// A path at profileDir/NAME.toml that is a symlink or not a regular file
// blocks the write with the message PrepareFix gives for the same case: the
// rename in Apply would replace the link, not the file behind it.
//
// A profile called NAME defined anywhere but profileDir/NAME.toml blocks the
// write: the new file would shadow or duplicate it. The error is for what
// cannot be answered at all: an unusable name, an unreadable existing file,
// snug printing no document.
func Prepare(ctx context.Context, d *draft.Draft, profileDir, snug string, run hostfacts.Runner, profiles []ingest.Profile, others []verify.File, idWarn *probe.Warning) (Plan, error) {
	p, done, err := newPlan(d, profileDir, profiles)
	if err != nil || done {
		return p, err
	}
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

// newPlan is the part of Prepare that needs no snug: the name, the other
// definitions of it, and the file that is there now. done is true when the
// plan is already blocked and nothing more can be asked of it.
func newPlan(d *draft.Draft, profileDir string, profiles []ingest.Profile) (p Plan, done bool, err error) {
	if !draft.ValidProfileName(d.Name) {
		return Plan{}, false, fmt.Errorf("%q is not a profile name (letters, digits and dashes; no underscore, dot or leading @); change NAME", safe.Inline(d.Name))
	}
	p = Plan{Path: filepath.Join(profileDir, d.Name+".toml"), New: d.Render()}
	for _, pr := range profiles {
		if pr.Name != d.Name {
			continue
		}
		if def := filepath.Join(pr.Dir, pr.File); filepath.Clean(def) != filepath.Clean(p.Path) {
			p.Blocked = append(p.Blocked, fmt.Sprintf("profile %s is defined in %s; change NAME", d.Name, safe.Inline(def)))
		}
	}
	if err := regularFile(p.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.Overwrite = true
		p.Blocked = append(p.Blocked, err.Error())
		return p, true, nil
	}
	old, exists, err := ReadProfile(p.Path)
	if err != nil {
		return Plan{}, false, fmt.Errorf("cannot look at %s: %w", p.Path, err)
	}
	p.Old, p.Overwrite = old, exists
	return p, false, nil
}

// PrepareIdentity returns the Plan for writing d, the identity profile
// BuildIdentity made, to profileDir/NAME.toml. It writes nothing and does not
// ask snug: the profile alone selects nothing worth comparing, and the project
// profile that includes it is checked with this file beside it. It blocks and
// errors on the same conditions as Prepare.
func PrepareIdentity(d *draft.Draft, profileDir string, profiles []ingest.Profile) (Plan, error) {
	p, _, err := newPlan(d, profileDir, profiles)
	return p, err
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

// Title is the one line that says what applying the plan does to the file.
func (p Plan) Title() string {
	if p.Overwrite {
		return "overwrites " + safe.Inline(p.Path)
	}
	return "writes " + safe.Inline(p.Path) + " (new file)"
}

// Body is the diff, then the notes, then, for a blocked plan, why it cannot
// be applied. It ends without a newline and asks nothing.
func (p Plan) Body() string {
	var b strings.Builder
	b.WriteString(LineDiff(p.Old, p.New))
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "\n! %s", safe.Inline(n))
	}
	if len(p.Blocked) > 0 {
		b.WriteString("\nnot written: the file would not do what the screen says")
		for _, n := range p.Blocked {
			fmt.Fprintf(&b, "\n! %s", n)
		}
	}
	return b.String()
}

// Together returns the one confirmation screen for writing plans in order: a
// title naming every file, and a body that heads each plan's own with the file
// it is about. A single plan is shown as Title and Body show it. blocked is
// true when any plan is: none of them is then written, because the later ones
// include the earlier.
func Together(plans ...Plan) (title, body string, blocked bool) {
	if len(plans) == 1 {
		return plans[0].Title(), plans[0].Body(), len(plans[0].Blocked) > 0
	}
	var titles, bodies []string
	for _, p := range plans {
		titles = append(titles, p.Title())
		bodies = append(bodies, "== "+safe.Inline(p.Path)+"\n"+p.Body())
		blocked = blocked || len(p.Blocked) > 0
	}
	return strings.Join(titles, ", and "), strings.Join(bodies, "\n\n"), blocked
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

// AfterWrite returns the lines to print once the profile is written: the run
// line when snug will find the file, and otherwise a note saying it will not.
// defaultDir is where snug reads profiles from without help. A profileDir
// shaped `X/snug/profiles.d` gets the run line behind `XDG_CONFIG_HOME=X`;
// any other directory gets the note alone, because no run line would find the
// profile there.
func AfterWrite(runLine, profileDir, defaultDir string) []string {
	if filepath.Clean(profileDir) == filepath.Clean(defaultDir) {
		return []string{runLine}
	}
	note := "snug will not look in " + safe.Inline(profileDir) + ": it reads " + safe.Inline(defaultDir)
	snugDir := filepath.Dir(profileDir)
	if filepath.Base(profileDir) == "profiles.d" && filepath.Base(snugDir) == "snug" {
		return []string{note, "XDG_CONFIG_HOME=" + draft.ShellQuote(filepath.Dir(snugDir)) + " " + runLine}
	}
	return []string{note + "; move the file there to use it"}
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

// IdentityFiles returns the user files that define the profiles names and,
// transitively, the non-built-in profiles they include, as the extra files
// verify.Run needs beside the draft. A file that defines skip (the profile
// being written) is left out, so the check never sees an older copy of it.
// No names returns nil.
func IdentityFiles(files []ingest.ProfileFile, profiles []ingest.Profile, skip string, names ...string) []verify.File {
	if len(names) == 0 {
		return nil
	}
	need := slices.Clone(names)
	for i := 0; i < len(need); i++ {
		for _, p := range profiles {
			if p.Name != need[i] {
				continue
			}
			for _, inc := range p.Include {
				if !strings.HasPrefix(inc, "@") && !slices.Contains(need, inc) {
					need = append(need, inc)
				}
			}
		}
	}
	var out []verify.File
	for i, f := range files {
		if slices.Contains(f.Defines, skip) {
			continue
		}
		if slices.ContainsFunc(f.Defines, func(n string) bool { return slices.Contains(need, n) }) {
			out = append(out, verify.File{Name: fmt.Sprintf("%d-%s", i, f.Name), Body: f.Body})
		}
	}
	return out
}

// LineOf returns the 1-based number of the first line of rendered containing
// token, or 0 when none does.
func LineOf(rendered, token string) int {
	if token == "" {
		return 0
	}
	for i, l := range strings.Split(rendered, "\n") {
		if strings.Contains(l, token) {
			return i + 1
		}
	}
	return 0
}

// DryRunText runs `snug --dry-run -p NAME TARGET` for d the way verify.Run
// does (the draft and others as the only profiles of a scratch configuration
// directory) and returns what snug printed, for a human to read.
func DryRunText(ctx context.Context, run hostfacts.Runner, snug string, d *draft.Draft, others []verify.File) (string, error) {
	xdg, err := os.MkdirTemp("", "snug-setup-dry-")
	if err != nil {
		return "", fmt.Errorf("making a scratch config directory: %w (set TMPDIR to a writable directory)", err)
	}
	defer os.RemoveAll(xdg)
	dir := filepath.Join(xdg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range others {
		if err := os.WriteFile(filepath.Join(dir, f.Name), f.Body, 0o600); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, d.Name+".toml"), []byte(d.Render()), 0o600); err != nil {
		return "", err
	}
	args := append([]string{"--dry-run"}, d.RunArgs(d.Host.Target)...)
	res, err := run(ctx, []string{"XDG_CONFIG_HOME=" + xdg}, snug, args...)
	out := string(res.Stdout)
	if len(res.Stderr) > 0 {
		out += "\n" + string(res.Stderr)
	}
	return out, err
}
