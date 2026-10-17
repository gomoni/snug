package tui

import (
	"errors"
	"flag"
	"fmt"
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

// reviewLog records what Apply was asked to do, so a test can tell "went back"
// from "wrote".
type reviewLog struct {
	applied []string
	err     error
	blocked bool
	body    string
}

func (l *reviewLog) review(title, done string) Review {
	body := l.body
	if body == "" {
		body = "+ include = [\"@net\"]"
	}
	return Review{Title: title, Body: body, Blocked: l.blocked, Done: done, Apply: func() error {
		if l.err != nil {
			return l.err
		}
		l.applied = append(l.applied, title)
		return nil
	}}
}

func withLog(c Config, l *reviewLog) Config {
	c.Plan = func(s suggest.Selection) (Review, error) {
		return l.review("writes "+s.Text[suggest.Name]+".toml (new file)", "wrote x.toml"), nil
	}
	c.PlanFix = func(w probe.Warning) (Review, error) { return l.review("fixes "+w.File, "fixed "+w.File), nil }
	return c
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
		case "pgdown":
			msg = tea.KeyPressMsg{Code: tea.KeyPgDown}
		case "pgup":
			msg = tea.KeyPressMsg{Code: tea.KeyPgUp}
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
	m = press(m, "j", "j", "j", "j", "j", "j", "space", "space") // CONTAINERS: socket, build
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
	for range 8 {
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

func TestFixOnNonRenameSaysSo(t *testing.T) {
	var l reviewLog
	m := sized(New(withLog(config(facts(), otherWarning, renameWarning), &l)), 100)
	m = press(m, "j", "j", "j", "j", "j", "j", "j", "j") // otherWarning
	m = press(m, "f")
	if m.pg != nil || !strings.Contains(screen(m), "no mechanical fix") || len(l.applied) != 0 {
		t.Errorf("f on a non-rename:\n%s", screen(m))
	}
}

func TestFixIsConfirmedInTheScreen(t *testing.T) {
	var l reviewLog
	m := sized(New(withLog(config(facts(), otherWarning, renameWarning), &l)), 100)
	m = press(m, "j", "j", "j", "j", "j", "j", "j", "j", "j") // renameWarning
	m = press(m, "f")
	if !strings.Contains(screen(m), "fixes "+renameWarning.File) || !strings.Contains(screen(m), " y fix") {
		t.Fatalf("no fix screen:\n%s", screen(m))
	}
	if len(l.applied) != 0 {
		t.Fatalf("applied before y: %v", l.applied)
	}
	m = press(m, "n")
	if strings.Contains(screen(m), "y fix") || !strings.Contains(screen(m), "NAME") || len(l.applied) != 0 {
		t.Errorf("n did not return to the main screen:\n%s", screen(m))
	}
	next, cmd := press(m, "f").Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	m = next.(Model)
	o := m.Outcome()
	if cmd == nil || o.Result != Fixed || o.Done != "fixed "+renameWarning.File || len(l.applied) != 1 {
		t.Errorf("y: %+v applied %v", o, l.applied)
	}
}

func TestWriteIsConfirmedInTheScreen(t *testing.T) {
	var l reviewLog
	m := sized(New(withLog(config(facts()), &l)), 100)
	m = press(m, "j", "j", "j", "j", "j", "space") // NETWORK off
	m = press(m, "w")
	for _, want := range []string{"writes snug-setup.toml (new file)", `+ include = ["@net"]`, " y write"} {
		if !strings.Contains(screen(m), want) {
			t.Errorf("review lacks %q:\n%s", want, screen(m))
		}
	}
	if strings.Contains(screen(m), "NETWORK") || len(l.applied) != 0 {
		t.Fatalf("the review shows the main screen or wrote early:\n%s", screen(m))
	}
	for _, back := range []string{"n", "esc"} {
		b := press(m, back)
		if !strings.Contains(screen(b), "NETWORK") || b.Outcome().Sel.Pick[suggest.Network] != 1 || len(l.applied) != 0 {
			t.Errorf("%s: selection lost or wrote:\n%s", back, screen(b))
		}
	}
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	o := next.(Model).Outcome()
	if cmd == nil || o.Result != Write || o.Done != "wrote x.toml" || len(l.applied) != 1 || o.Sel.Pick[suggest.Network] != 1 {
		t.Errorf("y: %+v cmd %v applied %v", o, cmd != nil, l.applied)
	}
}

func TestEditIsConfirmedThenOutcomeEdit(t *testing.T) {
	var l reviewLog
	m := sized(New(withLog(config(facts()), &l)), 100)
	m = press(m, "e")
	if !strings.Contains(screen(m), "y write, then open $EDITOR") {
		t.Fatalf("%s", screen(m))
	}
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if cmd == nil || next.(Model).Outcome().Result != Edit {
		t.Errorf("e then y: %+v", next.(Model).Outcome())
	}
}

func TestCtrlCOnAReviewWritesNothing(t *testing.T) {
	var l reviewLog
	m := press(sized(New(withLog(config(facts()), &l)), 100), "w")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil || next.(Model).Outcome().Result != Interrupted || len(l.applied) != 0 {
		t.Errorf("%+v applied %v", next.(Model).Outcome(), l.applied)
	}
}

func TestBlockedReviewCannotBeApplied(t *testing.T) {
	l := reviewLog{blocked: true}
	m := press(sized(New(withLog(config(facts()), &l)), 100), "w")
	if strings.Contains(screen(m), " y write") || !strings.Contains(screen(m), "esc back") {
		t.Errorf("a blocked review offers y:\n%s", screen(m))
	}
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	if cmd != nil || len(l.applied) != 0 || next.(Model).rev == nil {
		t.Errorf("y on a blocked review did something")
	}
}

func TestPlanErrorIsShownNotFatal(t *testing.T) {
	c := config(facts())
	c.Plan = func(suggest.Selection) (Review, error) {
		return Review{}, errors.New(`"bad_name" is not a profile name (letters, digits and dashes; no underscore, dot or leading @); change NAME`)
	}
	m := press(sized(New(c), 60), "w")
	if m.pg != nil || m.Outcome().Result != Quit {
		t.Fatalf("a Plan error left the main screen: %+v", m.Outcome())
	}
	s := screen(m)
	if !strings.Contains(s, "change NAME") || !strings.Contains(s, "IDENTITY") {
		t.Errorf("error not on the main screen:\n%s", s)
	}
	for _, l := range strings.Split(s, "\n") {
		if n := utf8.RuneCountInString(l); n > 60 {
			t.Errorf("%d runes: %q", n, l)
		}
	}
}

func TestApplyErrorReturnsToTheMainScreen(t *testing.T) {
	l := reviewLog{err: errors.New("x.toml changed since the diff was shown; run snug-setup again")}
	m := press(sized(New(withLog(config(facts()), &l)), 100), "w", "y")
	if m.Outcome().Result != Quit || !strings.Contains(screen(m), "changed since the diff") || !strings.Contains(screen(m), "NAME") {
		t.Errorf("%+v\n%s", m.Outcome(), screen(m))
	}
}

func TestReviewScrolls(t *testing.T) {
	var body []string
	for i := range 100 {
		body = append(body, fmt.Sprintf("line %03d", i))
	}
	l := reviewLog{body: strings.Join(body, "\n")}
	m := press(sized(New(withLog(config(facts()), &l)), 80), "w")
	has := func(s string) bool { return strings.Contains(screen(m), s) }
	if !has("line 000") || has("line 099") {
		t.Fatalf("not at the top:\n%s", screen(m))
	}
	m = press(m, "G")
	if has("line 000") || !has("line 099") {
		t.Errorf("G:\n%s", screen(m))
	}
	m = press(m, "g", "j", "j")
	if has("line 000") || !has("line 002") {
		t.Errorf("g j j:\n%s", screen(m))
	}
	m = press(m, "pgdown")
	if has("line 002") || !has("line 039") {
		t.Errorf("pgdown:\n%s", screen(m))
	}
	m = press(m, "pgup", "k")
	if !has("line 001") {
		t.Errorf("pgup k:\n%s", screen(m))
	}
	if n := strings.Count(screen(m), "\n") + 1; n > 40 {
		t.Errorf("%d lines on a 40 line terminal", n)
	}
}

func TestWhyOffRowShowsWhatTurningItOnGrants(t *testing.T) {
	m := sized(New(config(facts())), 400)
	m = press(m, "j", "j", "j", "j", "j", "space", "?") // NETWORK, off
	if !strings.Contains(lineWith(t, m, "NETWORK"), "off") {
		t.Fatalf("not off:\n%s", screen(m))
	}
	for _, f := range strings.Fields(draft.Abuse["@net"]) {
		if !strings.Contains(screen(m), f) {
			t.Fatalf("abuse sentence of @net missing %q:\n%s", f, screen(m))
		}
	}
}

func TestWhyFileIsCleaned(t *testing.T) {
	w := otherWarning
	w.File = home + "/.config/snug/profiles.d/a\x1b[2Jb.toml"
	m := sized(New(config(facts(), w)), 200)
	for range 8 {
		m = press(m, "j")
	}
	m = press(m, "?")
	if strings.ContainsRune(screen(m), 0x1b) {
		t.Errorf("an escape reached the screen:\n%q", screen(m))
	}
}

func toIdentity(m Model) Model { return press(m, "j", "j", "j") }

func TestToolsRowIsGone(t *testing.T) {
	m := sized(New(config(facts())), 100)
	if strings.Contains(screen(m), "TOOLS") {
		t.Errorf("TOOLS is on the screen:\n%s", screen(m))
	}
}

func TestEnterNeverCycles(t *testing.T) {
	m := sized(New(config(facts())), 100)
	for cursor := 0; cursor < len(m.sel.Rows); cursor++ {
		m.cursor = cursor
		next := press(m, "enter")
		if next.edit != nil || next.idm != nil {
			next = press(next, "esc")
		}
		if next.Outcome().Sel.Pick[suggest.RowID(cursor)] != m.sel.Pick[suggest.RowID(cursor)] || next.anyChanged() {
			t.Errorf("enter on row %d changed the selection", cursor)
		}
	}
}

func TestEnterOpensOnlyNameDescIdentity(t *testing.T) {
	m := sized(New(config(facts())), 100)
	for cursor := 0; cursor < len(m.sel.Rows); cursor++ {
		m.cursor = cursor
		next := press(m, "enter")
		wantEdit := cursor == int(suggest.Name) || cursor == int(suggest.Desc)
		wantMenu := cursor == int(suggest.Identity)
		if (next.edit != nil) != wantEdit || (next.idm != nil) != wantMenu {
			t.Errorf("row %d: edit=%v menu=%v", cursor, next.edit != nil, next.idm != nil)
		}
	}
}

func TestSpaceStillCyclesIdentity(t *testing.T) {
	m := toIdentity(sized(New(config(facts())), 100))
	m = press(m, "space")
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "plainsof") {
		t.Errorf("%q", l)
	}
}

func TestIdentitySubmenuGolden(t *testing.T) {
	f := facts()
	f.Profiles[0].Identity = ingest.ProfileIdentity{
		SSHHost: "github.com", SSHKey: "{home}/.ssh/github_auth.pub", SigningKey: "{home}/.ssh/github_sign.pub",
		GitName: "M V", Email: "m@example.org", GHUser: "vyskocilm", GHHost: "github.com",
	}
	f.SSH = ingest.SSHFacts{Hosts: ingest.ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))}
	m := toIdentity(sized(New(config(f)), 100))
	m = press(m, "enter")
	golden(t, "identity-menu", screen(m))
}

func TestIdentitySubmenuPicksAndGoesBack(t *testing.T) {
	m := toIdentity(sized(New(config(facts())), 100))
	m = press(m, "enter")
	if m.idm == nil || m.idm.cursor != 1 {
		t.Fatalf("menu not opened on the current pick: %+v", m.idm)
	}
	m = press(m, "j", "space")
	if m.Outcome().Sel.Pick[suggest.Identity] != 2 {
		t.Fatalf("space did not pick: %d", m.Outcome().Sel.Pick[suggest.Identity])
	}
	m = press(m, "enter")
	if m.idm == nil || m.Outcome().Sel.Pick[suggest.Identity] != 2 {
		t.Errorf("enter must do nothing in the menu")
	}
	m = press(m, "esc")
	if m.idm != nil {
		t.Fatalf("esc did not go back")
	}
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "plainsof") || !strings.Contains(l, "* changed") || !strings.Contains(l, "u revert") {
		t.Errorf("%q", l)
	}
	if l := lineWith(t, m, "DESC"); !strings.Contains(l, "plainsof") {
		t.Errorf("DESC did not follow IDENTITY: %q", l)
	}
	m = press(m, "u")
	if l := lineWith(t, m, "IDENTITY"); strings.Contains(l, "*") || !strings.Contains(l, "vyskocilm") {
		t.Errorf("u: %q", l)
	}
	m = press(m, "enter", "q")
	if m.idm != nil || m.askQuit {
		t.Errorf("q in the menu must go back, not quit")
	}
}

func TestIdentitySubmenuShowsDetailAndWhy(t *testing.T) {
	f := facts()
	f.Profiles[0].Identity = ingest.ProfileIdentity{SSHHost: "github.com", SSHKey: "{home}/.ssh/github_auth.pub", GitName: "M V", Email: "m@example.org", GHUser: "vyskocilm"}
	f.SSH = ingest.SSHFacts{Hosts: ingest.ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))}
	m := toIdentity(sized(New(config(f)), 100))
	m = press(m, "enter")
	for _, want := range []string{"none", "vyskocilm   suggested", "ssh   github.com  github_auth", "~/.ssh/config  Host github.com  → github_auth", "git   M V <m@example.org>", "gh    vyskocilm", "also includes: gh-cli", "plainsof"} {
		if !strings.Contains(screen(m), want) {
			t.Errorf("no %q in:\n%s", want, screen(m))
		}
	}
	if strings.Contains(screen(m), "it pins the remote") {
		t.Errorf("why shown before ?")
	}
	m = press(m, "?")
	if !strings.Contains(screen(m), "it pins the remote's host") {
		t.Errorf("? shows no reason:\n%s", screen(m))
	}
}

func TestIdentitySubmenuTextIsCleanedAndFits(t *testing.T) {
	f := facts()
	f.Profiles[0].Identity.GHUser = "evil\x1b[2J" + strings.Repeat("x", 200)
	f.Profiles[0].Identity.GitName = "n\u202ex"
	m := toIdentity(sized(New(config(f)), 60))
	m = press(m, "enter")
	if strings.ContainsAny(screen(m), "\x1b\u202e") {
		t.Errorf("forging rune on the screen:\n%q", screen(m))
	}
	for _, l := range strings.Split(screen(m), "\n") {
		if n := utf8.RuneCountInString(l); n > 60 {
			t.Errorf("%d runes: %q", n, l)
		}
	}
}

func TestIdentitySubmenuScrollsToCursor(t *testing.T) {
	f := facts()
	for i := range 12 {
		f.Profiles = append(f.Profiles, idProfile(fmt.Sprintf("acct%02d", i), "x@example.org"))
	}
	c := config(f)
	m := toIdentity(New(c))
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = press(next.(Model), "enter")
	for range 14 {
		m = press(m, "j")
	}
	if !strings.Contains(screen(m), "▸ ( ) acct11") {
		t.Errorf("cursor not visible:\n%s", screen(m))
	}
	if n := strings.Count(screen(m), "\n") + 1; n > 12 {
		t.Errorf("%d lines on a 12 line terminal", n)
	}
}

func TestContainersCyclesSocketBuildNone(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "j") // CONTAINERS
	want := []string{"@podman-socket", "@podman-build", "○ @podman-build"}
	for i, w := range want {
		m = press(m, "space")
		if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, w) {
			t.Errorf("space %d: want %q in %q", i+1, w, l)
		}
	}
	if m.anyChanged() {
		t.Errorf("a full cycle must end at the suggestion")
	}
}

func TestContainersWithoutFileStillReachable(t *testing.T) {
	f := facts()
	f.Target.Containers = nil
	m := sized(New(config(f)), 100)
	m = press(m, "j", "j", "j", "j", "j", "j")
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "—") {
		t.Fatalf("%q", l)
	}
	m = press(m, "space")
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "@podman-socket") || !strings.Contains(l, "* on") {
		t.Errorf("%q", l)
	}
}

func TestFooterNamesEnterOnlyWhereItOpens(t *testing.T) {
	m := sized(New(config(facts())), 100)
	has := func(m Model) bool { return strings.Contains(screen(m), "enter ") }
	if !has(m) {
		t.Errorf("NAME: no enter in footer")
	}
	if has(press(m, "j", "j")) {
		t.Errorf("BASE: enter advertised")
	}
	if !has(toIdentity(m)) {
		t.Errorf("IDENTITY: no enter in footer")
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
	if strings.Contains(screen(m), "NETWORK") {
		t.Errorf("an unknown key left the dry-run view:\n%s", screen(m))
	}
	for _, back := range []string{"q", "esc"} {
		if b := press(m, back); !strings.Contains(b.View().Content, "NETWORK") {
			t.Errorf("%s did not return:\n%s", back, screen(b))
		}
	}
}

func TestDryRunScrolls(t *testing.T) {
	var out []string
	for i := range 200 {
		out = append(out, fmt.Sprintf("row %03d", i))
	}
	c := config(facts())
	c.DryRun = func(*draft.Draft) (string, error) { return strings.Join(out, "\n"), nil }
	m := press(sized(New(c), 80), "d")
	has := func(s string) bool { return strings.Contains(screen(m), s) }
	if !has("row 000") || has("row 199") {
		t.Fatalf("the head is not shown first:\n%s", screen(m))
	}
	m = press(m, "G")
	if !has("row 199") || has("row 000") {
		t.Errorf("G:\n%s", screen(m))
	}
	m = press(m, "pgup")
	if has("row 199") {
		t.Errorf("pgup stayed at the end:\n%s", screen(m))
	}
	m = press(m, "g", "j")
	if has("row 000") || !has("row 001") {
		t.Errorf("g j:\n%s", screen(m))
	}
	if n := strings.Count(screen(m), "\n") + 1; n > 40 {
		t.Errorf("%d lines on a 40 line terminal", n)
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
