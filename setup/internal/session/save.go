package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/verify"
)

// Save writes the draft to ProfileDir/NAME.toml after snug has resolved it to
// what the intent ledger asks for. name, when not "", names the draft first.
// It refuses, writing nothing, when any question other than a second-profile
// question is open (naming the line that answers each), when the draft is
// empty, when the draft has no name, when snug is not on PATH, and when snug
// refuses the draft or resolves it differently from the ledger. A different
// file of the same name is not overwritten: Save opens an Overwrite question
// and returns false. It reports whether the file now holds the draft.
func (s *Session) Save(ctx context.Context, name string) (bool, []Line) {
	if open := s.blocking(); len(open) > 0 {
		out := []Line{info("not saved: %d question(s) are open, and a profile is saved only once each has an answer:", len(open))}
		for _, p := range open {
			out = append(out, info("  #%d %s\n      %s", p.N, p.Question, p.Answer))
		}
		return false, out
	}
	if s.d.Empty() {
		return false, []Line{info("nothing to save yet.")}
	}
	if name != "" {
		if !intent.ValidProfileName(name) {
			return false, []Line{info("%q is not a profile name (letters, digits and dashes; no underscore, dot or leading @); not saved.", safe.Inline(name))}
		}
		s.d.Name = name
	}
	if s.d.Name == "" {
		return false, []Line{info("not saved: the profile has no name. Type /save NAME (letters, digits and dashes), or say \"call it NAME\".")}
	}
	ok, out := s.check(ctx)
	if !ok {
		return false, out
	}
	body := s.d.Render()
	path := filepath.Join(s.cfg.ProfileDir, s.d.Name+".toml")
	old, exists, err := ReadProfile(path)
	if err != nil {
		return false, append(out, info("not saved: cannot look at %s: %s", path, safe.Inline(err.Error())))
	}
	if exists && old == body {
		s.lastSaved = body
		out = append(out, info("%s already holds exactly this profile.", path))
		return true, append(out, s.afterSave(ctx)...)
	}
	if exists {
		p := s.open(Pending{Kind: Overwrite, path: path, body: body, Options: strings.Split(lineDiff(old, body), "\n")})
		return false, append(out, p.Line())
	}
	if err := WriteProfile(path, body, false); err != nil {
		return false, append(out, info("not saved: could not write %s: %s", path, safe.Inline(err.Error())))
	}
	s.lastSaved = body
	out = append(out, info("wrote %s", path))
	return true, append(out, s.afterSave(ctx)...)
}

// acceptOverwrite writes the body that was checked, and only that body: a
// draft that changed since the check lapses the question.
func (s *Session) acceptOverwrite(ctx context.Context, p Pending) []Line {
	s.close(p.N)
	if s.d.Render() != p.body {
		return []Line{info("the draft changed after the check, so #%d lapsed; /save again.", p.N)}
	}
	if err := WriteProfile(p.path, p.body, true); err != nil {
		return []Line{info("not saved: could not write %s: %s", p.path, safe.Inline(err.Error()))}
	}
	s.lastSaved = p.body
	return append([]Line{info("wrote %s", p.path)}, s.afterSave(ctx)...)
}

// check runs the real snug on the draft and compares the policy it resolves
// with the ledger. Without snug there is no check, and so no save.
func (s *Session) check(ctx context.Context) (bool, []Line) {
	snug, err := s.cfg.LookPath("snug")
	if err != nil {
		return false, []Line{info("not saved: snug is not on PATH, and snug-setup saves only a draft snug has resolved to what you asked for.\n" +
			"Build it in a snug checkout (go build -o ~/.local/bin/snug ./cmd/snug) and put that directory on PATH, then save again.")}
	}
	doc, err := verify.Run(ctx, s.cfg.Run, snug, s.d, s.checkFiles())
	if err != nil {
		return false, []Line{info("not saved: the check against snug failed: %s", safe.Inline(err.Error()))}
	}
	args := strings.Join(s.d.RunArgs(s.cfg.Host.Target), " ")
	diffs := verify.Compare(s.d, doc)
	if len(diffs) == 0 {
		return true, []Line{info("checked: snug %s resolves to what the intent ledger asks for.", args)}
	}
	how := "resolves this draft differently from what was asked"
	if doc.Snug.Outcome != "ok" {
		how = "refuses this draft"
	}
	out := []Line{info("not saved: snug %s (XDG_CONFIG_HOME=<a scratch directory holding only the draft> snug --dry-run --json %s):", how, args)}
	for _, d := range diffs {
		out = append(out, info("  - %s", safe.Clean(d.String())))
	}
	return false, out
}

// maxProfile bounds what ReadProfile reads; a profile is a few hundred bytes.
const maxProfile = 1 << 20

// ReadProfile returns the file at path and whether it exists. A missing file
// is not an error; anything at path that is not a regular file is, and so is
// a file larger than maxProfile.
func ReadProfile(path string) (body string, exists bool, err error) {
	// HOSTREAD-EXEMPT: opened O_NONBLOCK and refused below unless fstat says
	// regular file, so a FIFO at the name cannot block the open or the read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", true, err
	}
	if !fi.Mode().IsRegular() {
		return "", true, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfile+1))
	if err == nil && len(b) > maxProfile {
		err = fmt.Errorf("%s is larger than %d bytes, which no profile snug-setup writes is", path, maxProfile)
	}
	return string(b), true, err
}

// WriteProfile writes body to path: O_EXCL for a new file, so a file that
// appeared since the check is not replaced, and a rename over the old one
// for an overwrite, so a crash leaves either file whole.
func WriteProfile(path, body string, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if !overwrite {
		// HOSTREAD-EXEMPT: O_CREATE|O_EXCL fails on any existing name, FIFO
		// included, so this never opens a file it did not create.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(body); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snug-setup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// afterSave has snug itself read the file and returns the line that uses it.
func (s *Session) afterSave(ctx context.Context) []Line {
	name := s.d.Name
	var out []Line
	snug, err := s.cfg.LookPath("snug")
	switch {
	case err != nil:
		out = append(out, info("snug is not on PATH, so the file was not checked by snug."))
	default:
		xdg, ok := xdgFor(s.cfg.ProfileDir)
		if !ok {
			out = append(out, info("%s is not <XDG_CONFIG_HOME>/snug/profiles.d, so snug will not look there and the file was not checked.", s.cfg.ProfileDir))
			break
		}
		res, err := s.cfg.Run(ctx, []string{"XDG_CONFIG_HOME=" + xdg}, snug, "profile", "show", name)
		if err != nil {
			return append(out, warn("snug REFUSED the profile (snug profile show %s): %s\n%s\nThe file is still there; fix it or save over it.",
				name, safe.Inline(err.Error()), safe.Clean(strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))))
		}
		out = append(out, info("snug accepts it (snug profile show %s).", name))
	}
	return append(out, info("Run it with:\n  %s", s.d.RunLine(s.cfg.Host.Target)))
}

func xdgFor(profileDir string) (string, bool) {
	d := filepath.Clean(profileDir)
	if filepath.Base(d) != "profiles.d" || filepath.Base(filepath.Dir(d)) != "snug" {
		return "", false
	}
	return filepath.Dir(filepath.Dir(d)), true
}

// lineDiff marks the lines only in old with "- " and the lines only in new
// with "+ ", in new's order after old's. It is a summary for a human, not a patch.
func lineDiff(old, new string) string {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			m[l] = true
		}
		return m
	}
	oldSet, newSet := set(old), set(new)
	var out []string
	for _, l := range strings.Split(strings.TrimRight(old, "\n"), "\n") {
		if old != "" && !newSet[l] {
			out = append(out, "- "+safe.Inline(l))
		}
	}
	for _, l := range strings.Split(strings.TrimRight(new, "\n"), "\n") {
		if !oldSet[l] {
			out = append(out, "+ "+l)
		}
	}
	if len(out) == 0 {
		return "(no line changes)"
	}
	return strings.Join(out, "\n")
}
