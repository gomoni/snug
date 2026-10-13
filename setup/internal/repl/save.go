package repl

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/session"
	"github.com/gomoni/snug/setup/internal/verify"
)

// save writes the draft to ProfileDir/NAME.toml after snug has resolved it to
// what the intent ledger asks for, showing what will change and asking. It
// reports whether the file now holds the draft.
func (r *REPL) save(ctx context.Context) bool {
	if r.draft.Empty() {
		r.say("nothing to save yet.")
		return false
	}
	if r.draft.Name == "" {
		name, ok := r.prompt("name for this profile: ")
		if !ok || name == "" {
			r.say("no name; not saved.")
			return false
		}
		if !intent.ValidProfileName(name) {
			r.say("%q is not a profile name (letters, digits and dashes; no underscore, dot or leading @); not saved.", name)
			return false
		}
		r.draft.Name = name
	}
	if !r.check(ctx) {
		return false
	}
	body := r.draft.Render()
	path := filepath.Join(r.cfg.ProfileDir, r.draft.Name+".toml")

	old, exists, err := session.ReadProfile(path)
	if err != nil {
		r.say("cannot look at %s: %v", path, err)
		return false
	}
	if exists && old == body {
		r.say("%s already holds exactly this profile.", path)
		r.lastSaved = body
		r.afterSave(ctx)
		return true
	}
	if exists {
		r.say("%s exists. Changes:", path)
		r.say("%s", lineDiff(old, body))
		if !r.confirm("Overwrite it?", false) {
			r.say("not saved.")
			return false
		}
	} else {
		r.say("Will write %s:", path)
		r.say("%s", lineDiff("", body))
		if !r.confirm("Write it?", true) {
			r.say("not saved.")
			return false
		}
	}
	if err := session.WriteProfile(path, body, exists); err != nil {
		r.say("could not write %s: %v", path, err)
		return false
	}
	r.lastSaved = body
	r.say("wrote %s", path)
	r.afterSave(ctx)
	return true
}

// check runs the real snug on the draft and compares the policy it resolves
// with the ledger. Without snug there is no check, and so no save.
func (r *REPL) check(ctx context.Context) bool {
	snug, err := r.cfg.LookPath("snug")
	if err != nil {
		r.say("not saved: snug is not on PATH, and snug-setup saves only a draft snug has resolved to what you asked for.\n" +
			"Build it in a snug checkout (go build -o ~/.local/bin/snug ./cmd/snug) and put that directory on PATH, then /save again.")
		return false
	}
	doc, err := verify.Run(ctx, r.cfg.Run, snug, r.draft, nil)
	if err != nil {
		r.say("not saved: the check against snug failed: %v", err)
		return false
	}
	diffs := verify.Compare(r.draft, doc)
	if len(diffs) == 0 {
		r.say("checked: snug %s resolves to what the intent ledger asks for.", strings.Join(r.draft.RunArgs(r.cfg.Host.Target), " "))
		return true
	}
	how := "resolves this draft differently from what was asked"
	if doc.Snug.Outcome != "ok" {
		how = "refuses this draft"
	}
	r.say("not saved: snug %s (snug --dry-run --json %s):", how, strings.Join(r.draft.RunArgs(r.cfg.Host.Target), " "))
	for _, d := range diffs {
		r.say("  - %s", d)
	}
	return false
}

// afterSave has snug itself read the file and prints the line that uses it.
func (r *REPL) afterSave(ctx context.Context) {
	name := r.draft.Name
	snug, err := r.cfg.LookPath("snug")
	switch {
	case err != nil:
		r.say("snug is not on PATH, so the file was not checked by snug.")
	default:
		xdg, ok := xdgFor(r.cfg.ProfileDir)
		if !ok {
			r.say("%s is not <XDG_CONFIG_HOME>/snug/profiles.d, so snug will not look there and the file was not checked.", r.cfg.ProfileDir)
			break
		}
		res, err := r.cfg.Run(ctx, []string{"XDG_CONFIG_HOME=" + xdg}, snug, "profile", "show", name)
		if err != nil {
			r.say("snug REFUSED the profile (snug profile show %s): %v\n%s\nThe file is still there; fix it or save over it.", name, err, strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
			return
		}
		r.say("snug accepts it (snug profile show %s).", name)
	}
	r.say("Run it with:\n  %s", r.draft.RunLine(r.cfg.Host.Target))
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
			out = append(out, "- "+l)
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
