package tui

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/probe"
	"github.com/gomoni/snug/setup/internal/suggest"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	home   = "/home/alice"
	target = "/home/alice/work/snug-setup"
)

func idProfile(name, email string, include ...string) ingest.Profile {
	return ingest.Profile{
		Name: name, File: "accounts.toml", Dir: home + "/.config/snug/profiles.d", Include: include,
		Identity: ingest.ProfileIdentity{SSHHost: "github.com", Email: email, GHUser: name},
	}
}

func facts() ingest.Facts {
	return ingest.Facts{
		Target: ingest.TargetFacts{
			Claude:     true,
			Languages:  []ingest.Lang{{Name: "go", Marker: "go.mod", Project: "github.com/gomoni/snug-setup"}},
			Containers: []string{"Containerfile"},
		},
		Profiles: []ingest.Profile{idProfile("vyskocilm", "m@example.org", "gh-cli"), idProfile("plainsof", "p@example.org")},
		Repo: &ingest.RepoFacts{
			Remotes: []ingest.Remote{ingest.ParseRemoteURL("git@github.com:gomoni/snug.git")},
			Authors: []ingest.Person{{Name: "M", Email: "m@example.org", Commits: 10}},
			Sampled: 10,
		},
	}
}

var renameWarning = probe.Warning{
	File: home + "/.config/snug/profiles.d/accounts.toml", Profiles: []string{"vyskocilm"},
	Line: "vyskocilm uses @cwd-rw, renamed @target-rw", Full: "@cwd-rw is now @target-rw: the grant was always {target}",
	Old: "@cwd-rw", New: "@target-rw",
}

var otherWarning = probe.Warning{
	File: home + "/.config/snug/profiles.d/other.toml", Profiles: []string{"x"}, Line: "x: something else is wrong", Full: "something else is wrong. details.",
}

func config(f ingest.Facts, warns ...probe.Warning) Config {
	sel := suggest.Suggest(f, home, target)
	return Config{
		Target:   "~/work/snug-setup",
		Sel:      sel,
		Warnings: warns,
		NoColor:  true,
		Build: func(s suggest.Selection) (*draft.Draft, map[suggest.RowID]string) {
			return suggest.Build(s, draft.Host{Home: home, Target: target}, f.Profiles)
		},
		DryRun: func(d *draft.Draft) (string, error) { return "dry run of " + d.Name, nil },
	}
}

func press(m Model, keys ...string) Model {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "space":
			msg = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "ctrl+c":
			msg = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

func sized(m Model, w int) Model {
	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 40})
	return next.(Model)
}

func screen(m Model) string { return m.View().Content }

func lineWith(t *testing.T, m Model, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(screen(m), "\n") {
		if strings.HasPrefix(strings.TrimLeft(l, "▸ "), prefix) {
			return l
		}
	}
	t.Fatalf("no line starting %q in:\n%s", prefix, screen(m))
	return ""
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs:\n%s", path, got)
	}
}

func TestViewInitialGolden(t *testing.T) {
	m := sized(New(config(facts(), renameWarning)), 100)
	golden(t, "initial", screen(m))
}

func TestCycleMarksChanged(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "space") // NETWORK
	l := lineWith(t, m, "NETWORK")
	if !strings.Contains(l, "* off — @claude needs @net   u revert") {
		t.Errorf("changed row: %q", l)
	}
	if m.Outcome().Sel.Pick[suggest.Agent] != 0 {
		t.Errorf("changing NETWORK changed AGENT")
	}
	m = press(m, "u")
	if l := lineWith(t, m, "NETWORK"); strings.Contains(l, "*") || strings.Contains(l, "u revert") {
		t.Errorf("after u: %q", l)
	}
}

func TestUnsureToggleShowsCircle(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "j", "space") // CONTAINERS
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "● @podman-build") || !strings.Contains(l, "* on") {
		t.Errorf("%q", l)
	}
	m = press(m, "u")
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "○ @podman-build") {
		t.Errorf("%q", l)
	}
}

func TestRevertAll(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "space", "j", "j", "space", "U")
	if strings.Contains(screen(m), "   u revert") {
		t.Errorf("rows still changed:\n%s", screen(m))
	}
	for _, r := range m.Outcome().Sel.Rows {
		if m.Outcome().Sel.Changed(r.ID) {
			t.Errorf("row %d still changed", r.ID)
		}
	}
}

func TestWhyPanelShowsAbuse(t *testing.T) {
	m := sized(New(config(facts())), 400)
	m = press(m, "j", "j", "j", "j", "j", "?")
	for _, f := range strings.Fields(draft.Abuse["@net"]) {
		if !strings.Contains(screen(m), f) {
			t.Fatalf("abuse sentence missing %q:\n%s", f, screen(m))
		}
	}
	m = press(m, "?")
	if strings.Contains(screen(m), "exfiltrate") {
		t.Errorf("panel did not close")
	}
}

func TestWhyOnWarningShowsSnugsMessage(t *testing.T) {
	m := sized(New(config(facts(), renameWarning)), 200)
	for range 9 {
		m = press(m, "j")
	}
	m = press(m, "?")
	if !strings.Contains(screen(m), "the grant was always {target}") {
		t.Errorf("%s", screen(m))
	}
}

func TestQuitAsksWhenChanged(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "space", "q")
	if !strings.Contains(screen(m), "quit without writing? y/n") {
		t.Fatalf("%s", screen(m))
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'n', Text: "n"})
	if cmd != nil {
		t.Errorf("n quit")
	}
	m = press(m, "n")
	if strings.Contains(screen(m), "quit without") {
		t.Errorf("n did not cancel")
	}
	m = press(m, "ctrl+c")
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if cmd == nil {
		t.Errorf("y did not quit")
	}
	if m.Outcome().Result != Quit {
		t.Errorf("result %v", m.Outcome().Result)
	}
}

func TestQuitDirectWhenUnchanged(t *testing.T) {
	m := sized(New(config(facts())), 100)
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil {
		t.Errorf("q did not quit an unchanged screen")
	}
}

func TestFixOnlyOnRename(t *testing.T) {
	m := sized(New(config(facts(), otherWarning, renameWarning)), 100)
	for range 9 {
		m = press(m, "j")
	}
	m, _ = update2(m, "f")
	if m.Outcome().Fix != nil || m.Outcome().Result != Quit || !strings.Contains(screen(m), "no mechanical fix") {
		t.Errorf("f on a non-rename: %+v\n%s", m.Outcome(), screen(m))
	}
	m = press(m, "j")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'f', Text: "f"})
	m = next.(Model)
	if cmd == nil || m.Outcome().Result != Fix || m.Outcome().Fix == nil || m.Outcome().Fix.Old != "@cwd-rw" {
		t.Errorf("f on a rename: %+v", m.Outcome())
	}
}

func update2(m Model, k string) (Model, tea.Cmd) {
	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune(k)[0], Text: k})
	return next.(Model), cmd
}

func TestWriteAndEditOutcomes(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "space")
	m, cmd := update2(m, "w")
	o := m.Outcome()
	if cmd == nil || o.Result != Write || o.Sel.Pick[suggest.Network] != 1 {
		t.Errorf("w: %+v", o)
	}
	m, _ = update2(sized(New(config(facts())), 100), "e")
	if m.Outcome().Result != Edit {
		t.Errorf("e: %+v", m.Outcome())
	}
}

func TestToolsFollowsIdentity(t *testing.T) {
	m := sized(New(config(facts())), 100)
	if l := lineWith(t, m, "TOOLS"); !strings.Contains(l, "gh-cli") || !strings.Contains(l, "from vyskocilm") {
		t.Fatalf("%q", l)
	}
	m = press(m, "j", "j", "j", "space") // IDENTITY: vyskocilm -> plainsof
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "plainsof") {
		t.Fatalf("%q", l)
	}
	l := lineWith(t, m, "TOOLS")
	if strings.Contains(l, "gh-cli") || strings.Contains(l, "*") {
		t.Errorf("tools after identity change: %q", l)
	}
}

func TestToolsWhyNamesTheFile(t *testing.T) {
	m := sized(New(config(facts())), 200)
	for range 7 {
		m = press(m, "j")
	}
	m = press(m, "?")
	if !strings.Contains(screen(m), "accounts.toml") {
		t.Errorf("%s", screen(m))
	}
}

func TestViewTruncatesReason(t *testing.T) {
	f := facts()
	f.Repo.Remotes = []ingest.Remote{ingest.ParseRemoteURL("git@github.com:gomoni/" + strings.Repeat("long-repository-name-", 5) + ".git")}
	m := sized(New(config(f, renameWarning, otherWarning)), 60)
	m = press(m, "j", "j", "j", "j", "j", "space")
	m.cfg.Notes = []string{strings.Repeat("a note that is far too long ", 5)}
	m.cfg.SnugMissing = true
	cut := false
	for _, l := range strings.Split(screen(m), "\n") {
		if n := utf8.RuneCountInString(l); n > 60 {
			t.Errorf("%d runes: %q", n, l)
		}
		if strings.HasPrefix(strings.TrimLeft(l, "▸ "), "IDENTITY") && strings.HasSuffix(l, "…") {
			cut = true
		}
	}
	if !cut {
		t.Errorf("a long reason must end in an ellipsis:\n%s", screen(m))
	}
}

func TestSnugMissingLine(t *testing.T) {
	c := config(facts())
	c.SnugMissing, c.DryRun = true, nil
	m := sized(New(c), 100)
	if !strings.Contains(screen(m), "! snug not on PATH: profiles not checked") {
		t.Errorf("%s", screen(m))
	}
	if strings.Contains(screen(m), "d dry-run") {
		t.Errorf("d advertised without snug")
	}
	m = press(m, "d")
	if !strings.Contains(screen(m), "snug not on PATH") || strings.Contains(screen(m), "dry run of") {
		t.Errorf("%s", screen(m))
	}
}

func TestDryRunShowsSnugOutput(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "d")
	if !strings.Contains(screen(m), "dry run of snug-setup") || strings.Contains(screen(m), "NETWORK") {
		t.Errorf("%s", screen(m))
	}
	m = press(m, "x")
	if !strings.Contains(screen(m), "NETWORK") {
		t.Errorf("any key must return:\n%s", screen(m))
	}
}

func TestDryRunErrorIsShown(t *testing.T) {
	c := config(facts())
	c.DryRun = func(*draft.Draft) (string, error) { return "", errors.New("boom") }
	m := press(sized(New(c), 100), "d")
	if !strings.Contains(screen(m), "boom") {
		t.Errorf("%s", screen(m))
	}
}

func TestEditNameInline(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "enter")
	if m.edit == nil {
		t.Fatal("not editing")
	}
	for range 20 {
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyBackspace})
		m = next.(Model)
	}
	for _, r := range "mine" {
		next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
		m = next.(Model)
	}
	m = press(m, "enter")
	if m.edit != nil || m.Outcome().Sel.Text[suggest.Name] != "mine" || !strings.Contains(lineWith(t, m, "NAME"), "* changed") {
		t.Errorf("name %q\n%s", m.Outcome().Sel.Text[suggest.Name], screen(m))
	}
	m = press(m, "enter", "esc")
	if m.edit != nil || m.Outcome().Sel.Text[suggest.Name] != "mine" {
		t.Errorf("esc must cancel without changing")
	}
}

func TestInvalidNameIsNotedNotRefused(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m.sel.Text[suggest.Name] = "bad_name"
	if l := lineWith(t, m, "NAME"); !strings.Contains(l, "not in the profile") {
		t.Errorf("the row must say the file lacks it: %q", l)
	}
}

func TestParentROUnderHomeNotifiesNotRefuses(t *testing.T) {
	c := config(ingest.Facts{})
	c.Sel = suggest.Suggest(ingest.Facts{}, home, home+"/app")
	c.Build = func(s suggest.Selection) (*draft.Draft, map[suggest.RowID]string) {
		return suggest.Build(s, draft.Host{Home: home, Target: home + "/app"}, nil)
	}
	m := sized(New(c), 140)
	m = press(m, "j", "j", "space")
	l := lineWith(t, m, "BASE")
	if !strings.Contains(l, "@parent-ro") || !strings.Contains(l, "* changed") || !strings.Contains(l, "not in the profile") {
		t.Errorf("%q", l)
	}
}

func TestNoControlBytesWithoutColor(t *testing.T) {
	m := sized(New(config(facts(), renameWarning)), 100)
	if strings.ContainsRune(screen(m), 0x1b) {
		t.Errorf("NoColor output has escapes")
	}
}
