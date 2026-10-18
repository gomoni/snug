package tui

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
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
		Profiles:    []ingest.Profile{idProfile("vyskocilm", "m@example.org", "gh-cli"), idProfile("plainsof", "p@example.org")},
		GHInstalled: true,
		GH:          []hostfacts.GHAccount{{Host: "github.com", User: "vyskocilm"}, {Host: "github.com", User: "plainsof"}},
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
		DryRun: func(s suggest.Selection) (string, error) { return "dry run of " + s.Text[suggest.Name], nil },
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

func TestContainersCycleSocketBuildNone(t *testing.T) {
	m := sized(New(config(facts())), 100)
	m = press(m, "j", "j", "j", "j", "j", "j") // CONTAINERS, suggested off with a Containerfile
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "CONTAINERS —") || !strings.Contains(l, "○ @podman-build?") {
		t.Fatalf("suggested off: %q", l)
	}
	for _, want := range []string{"CONTAINERS @podman-socket", "CONTAINERS @podman-build", "CONTAINERS —"} {
		m = press(m, "space")
		if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, want) {
			t.Errorf("after space want %q: %q", want, l)
		}
	}
	if m.anyChanged() {
		t.Errorf("a full cycle must end at the suggestion")
	}
	m = press(m, "space", "space") // build, changed
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "* changed   u revert") {
		t.Errorf("changed: %q", l)
	}
	m = press(m, "u")
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "CONTAINERS —") || strings.Contains(l, "*") {
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

func TestSpaceOnTheMainIdentityRowDoesNothing(t *testing.T) {
	m := toIdentity(sized(New(config(facts())), 100))
	before := m.Outcome().Sel
	m = press(m, "space", "space")
	after := m.Outcome().Sel
	if !maps.Equal(before.Block, after.Block) || !maps.Equal(before.Parts, after.Parts) || m.anyChanged() {
		t.Errorf("space changed the identity: %v -> %v", before.Block, after.Block)
	}
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "vyskocilm") || strings.Contains(l, "*") {
		t.Errorf("%q", l)
	}
	if !strings.Contains(screen(m), "enter open") {
		t.Errorf("the footer must still say enter opens the menu:\n%s", screen(m))
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
		t.Fatalf("menu not opened on the first block's pick: %+v", m.idm)
	}
	m = press(m, "j", "space")
	if got := m.Outcome().Sel.Block[suggest.BlockSSH]; got != 2 {
		t.Fatalf("space did not pick: %d", got)
	}
	if got := m.Outcome().Sel.Block[suggest.BlockGH]; got != 1 {
		t.Fatalf("picking ssh moved the gh block to %d", got)
	}
	m = press(m, "enter")
	if m.idm == nil || m.Outcome().Sel.Block[suggest.BlockSSH] != 2 {
		t.Errorf("enter must do nothing in the menu")
	}
	m = press(m, "esc")
	if m.idm != nil {
		t.Fatalf("esc did not go back")
	}
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "ssh plainsof, git vyskocilm, gh vyskocilm") || !strings.Contains(l, "* changed") || !strings.Contains(l, "u revert") {
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
	for range 13 {
		m = press(m, "j")
	}
	if !strings.Contains(screen(m), "▸ ( ) acct11") {
		t.Errorf("cursor not visible:\n%s", screen(m))
	}
	if n := strings.Count(screen(m), "\n") + 1; n > 12 {
		t.Errorf("%d lines on a 12 line terminal", n)
	}
}

func TestIdentityGhWarnings(t *testing.T) {
	f := facts()
	f.GH = []hostfacts.GHAccount{{Host: "github.com", User: "plainsof"}}
	m := sized(New(config(f)), 120)
	const want = "! vyskocilm: gh not logged in as vyskocilm on github.com — gh auth login --hostname github.com"
	if !strings.Contains(screen(m), want) {
		t.Errorf("no login warning:\n%s", screen(m))
	}
	m2 := press(toIdentity(m), "enter")
	if !strings.Contains(screen(m2), want) || strings.Count(screen(m2), "gh not logged in") != 1 {
		t.Errorf("submenu must list it under the entry only:\n%s", screen(m2))
	}
	m.sel = m.sel.WithBlock(suggest.BlockGH, 2)
	if strings.Contains(screen(m), "gh not logged in") {
		t.Errorf("plainsof is logged in:\n%s", screen(m))
	}

	f = facts()
	f.GHInstalled, f.GH = false, nil
	m = sized(New(config(f)), 120)
	if !strings.Contains(screen(m), "! gh not on PATH: vyskocilm's gh login not checked") {
		t.Errorf("no missing-gh line:\n%s", screen(m))
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
	if l := lineWith(t, m, "CONTAINERS"); !strings.Contains(l, "@podman-socket") || !strings.Contains(l, "* changed") {
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
	c.DryRun = func(suggest.Selection) (string, error) { return strings.Join(out, "\n"), nil }
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
	c.DryRun = func(suggest.Selection) (string, error) { return "", errors.New("boom") }
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

func TestEditConfirmSaysItEndsTheProgram(t *testing.T) {
	var l reviewLog
	m := sized(New(withLog(config(facts()), &l)), 200)
	m = press(m, "e")
	if m.rev == nil || m.rev.r.Title != EditTitle || !strings.HasPrefix(screen(m), "e writes the profile, opens $EDITOR, and ends snug-setup — the screen does not come back. y/n") {
		t.Errorf("title:\n%s", screen(m))
	}
	if !strings.Contains(screen(m), "writes snug-setup.toml (new file)") {
		t.Errorf("the file line is gone:\n%s", screen(m))
	}
	if w := press(sized(New(withLog(config(facts()), &l)), 200), "w"); strings.Contains(screen(w), "ends snug-setup") {
		t.Errorf("w must not claim to end the program")
	}
}

func TestFooterEditIsLast(t *testing.T) {
	m := sized(New(config(facts())), 200)
	if !strings.HasSuffix(strings.TrimRight(screen(m), " \n"), "q quit  e edit & exit") {
		t.Errorf("footer:\n%s", screen(m))
	}
}

// hostOnly is a host with a github.com remote, one gh login, a global author,
// an ssh config line and a git signing key, and no profile of the person's own.
func hostOnly() ingest.Facts {
	key := func(stem string) hostfacts.SSHKey {
		return hostfacts.SSHKey{Stem: stem, Path: home + "/.ssh/" + stem + ".pub", Blob: "AAAA" + stem}
	}
	f := facts()
	f.Profiles = nil
	f.SSH = ingest.SSHFacts{Hosts: ingest.ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))}
	f.Keys = []hostfacts.SSHKey{key("github_auth"), key("github_sign")}
	f.Authors = []hostfacts.GitAuthor{{Name: "M V", Email: "m@example.org"}}
	f.GitSigningKey = home + "/.ssh/github_sign.pub"
	f.GH = []hostfacts.GHAccount{{Host: "github.com", User: "vyskocilm", Active: true}}
	f.Binaries = map[string]ingest.Binary{"gh": {Path: home + "/bin/gh", Resolved: home + "/bin/gh"}}
	return f
}

func TestIdentitySubmenuFromHostGolden(t *testing.T) {
	m := toIdentity(sized(New(config(hostOnly())), 100))
	m = press(m, "enter")
	golden(t, "identity-menu-from-host", screen(m))
}

func TestFromHostIsTheRowValueAndNothingElseChanged(t *testing.T) {
	m := sized(New(config(hostOnly())), 100)
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "vyskocilm") || strings.Contains(l, "*") {
		t.Errorf("%q", l)
	}
}

func TestSubmenuCursorReachesEverySwitchAndSpaceOnlyTogglesIt(t *testing.T) {
	m := press(toIdentity(sized(New(config(hostOnly())), 100)), "enter")
	if m.idm.cursor != 1 {
		t.Fatalf("opens on the first block's pick, got item %d", m.idm.cursor)
	}
	var seen []suggest.Part
	for range 12 {
		at := m.idm.cursor
		m = press(m, "j")
		if m.idm.cursor == at {
			break
		}
		if it := m.sel.IdentityItems()[m.idm.cursor]; it.IsPart {
			seen = append(seen, it.Part)
			if it.Part == suggest.PartSigning {
				before := m.sel.Block
				m = press(m, "space")
				if m.sel.PartOn(suggest.PartSigning) || !maps.Equal(before, m.sel.Block) {
					t.Errorf("space on the sign line: on=%v blocks %v", m.sel.PartOn(suggest.PartSigning), m.sel.Block)
				}
				if !strings.Contains(screen(m), "▸       [ ] sign github_sign") {
					t.Errorf("the line does not show it is off:\n%s", screen(m))
				}
				m = press(m, "space")
				if !m.sel.PartOn(suggest.PartSigning) {
					t.Errorf("a second space did not switch it back on")
				}
			}
		}
	}
	want := []suggest.Part{suggest.PartSigning, suggest.PartGHBinary}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("switches reached %v, want %v", seen, want)
	}
}

func TestSpaceOnASourceLinePicksItWithoutTouchingSwitches(t *testing.T) {
	m := press(toIdentity(sized(New(config(hostOnly())), 100)), "enter", "k", "space")
	if m.sel.Block[suggest.BlockSSH] != 0 {
		t.Fatalf("pick %d", m.sel.Block[suggest.BlockSSH])
	}
	if m.sel.Block[suggest.BlockGit] != 1 || m.sel.Block[suggest.BlockGH] != 1 {
		t.Errorf("another block was changed: %v", m.sel.Block)
	}
	m = press(m, "j", "space")
	if m.sel.Block[suggest.BlockSSH] != 1 || !m.sel.PartOn(suggest.PartSigning) {
		t.Errorf("pick %d, sign %v", m.sel.Block[suggest.BlockSSH], m.sel.PartOn(suggest.PartSigning))
	}
}

func TestQuestionMarkOnASwitchShowsItsReasonAndTheAbuseSentence(t *testing.T) {
	m := press(toIdentity(sized(New(config(hostOnly())), 100)), "enter")
	for m.sel.IdentityItems()[m.idm.cursor].Part != suggest.PartSigning || !m.sel.IdentityItems()[m.idm.cursor].IsPart {
		m = press(m, "j")
	}
	m = press(m, "?")
	for _, want := range []string{"SIGNING ORACLE", "git config user.signingkey"} {
		if !strings.Contains(screen(m), want) {
			t.Errorf("no %q in:\n%s", want, screen(m))
		}
	}
}

func TestQuestionMarkOnTheGHBinaryLineSaysItAddsNoAuthority(t *testing.T) {
	m := press(toIdentity(sized(New(config(hostOnly())), 100)), "enter")
	for !m.sel.IdentityItems()[m.idm.cursor].IsPart || m.sel.IdentityItems()[m.idm.cursor].Part != suggest.PartGHBinary {
		m = press(m, "j")
	}
	m = press(m, "?")
	if !strings.Contains(strings.Join(strings.Fields(screen(m)), " "), "the sandbox can run every gh command the staged token authorises; the binary adds no authority of its own.") {
		t.Errorf("%s", screen(m))
	}
}

func TestQuestionMarkOnTheMainIdentityRowCarriesTheAbuseForFromHost(t *testing.T) {
	m := press(toIdentity(sized(New(config(hostOnly())), 100)), "?")
	if !strings.Contains(screen(m), "SIGNING ORACLE") {
		t.Errorf("%s", screen(m))
	}
}

func TestDryRunReceivesTheSelection(t *testing.T) {
	c := config(hostOnly())
	var got suggest.Selection
	c.DryRun = func(s suggest.Selection) (string, error) { got = s; return "x", nil }
	press(toIdentity(sized(New(c), 100)), "enter", "k", "space", "esc", "d")
	if got.Rows == nil || got.Block[suggest.BlockSSH] != 0 {
		t.Errorf("dry run saw a selection without the pick: %v", got.Block)
	}
}

// pins gives a profile a gh pin of its own.
func ghProfile(name, user string) ingest.Profile {
	return ingest.Profile{Name: name, File: "accounts.toml", Dir: home + "/.config/snug/profiles.d", Identity: ingest.ProfileIdentity{GHUser: user}}
}

func sshProfile(name string) ingest.Profile {
	return ingest.Profile{Name: name, File: "accounts.toml", Dir: home + "/.config/snug/profiles.d",
		Identity: ingest.ProfileIdentity{SSHHost: "github.com", SSHKey: "{home}/.ssh/" + name + ".pub"}}
}

// blocksFacts has a profile that pins ssh and gh and one that pins gh only,
// and a remote that matches neither, so every block starts at none.
func blocksFacts() ingest.Facts {
	f := facts()
	a := sshProfile("a")
	a.Identity.GHUser = "a-user"
	f.Profiles = []ingest.Profile{a, ghProfile("b", "b-user")}
	f.Repo = nil
	return f
}

func openMenu(f ingest.Facts) Model {
	return press(toIdentity(sized(New(config(f)), 100)), "enter")
}

func pickLine(t *testing.T, m Model, section, label string) Model {
	t.Helper()
	for i, it := range m.sel.IdentityItems() {
		if it.IsPart || it.Block.String() != section {
			continue
		}
		if m.sel.BlockChoices(it.Block)[it.Choice].Label == label {
			m.idm.cursor = i
			return press(m, "space")
		}
	}
	t.Fatalf("no %s line %q", section, label)
	return m
}

func TestIdentitySubmenuLockedGolden(t *testing.T) {
	m := openMenu(blocksFacts())
	m = pickLine(t, m, "ssh", "a")
	m = pickLine(t, m, "gh", "none")
	if name, locked := m.sel.Effective(suggest.BlockGH); name != "a" || !locked {
		t.Fatalf("effective gh %q locked %v", name, locked)
	}
	if got := m.sel.Block[suggest.BlockGH]; got != 0 {
		t.Fatalf("gh pick %d: the pick stays none", got)
	}
	golden(t, "identity-menu-locked", screen(m))
}

func TestIdentitySubmenuMixedGolden(t *testing.T) {
	f := blocksFacts()
	f.Profiles[0].Identity.GHUser = ""
	m := openMenu(f)
	m = pickLine(t, m, "ssh", "a")
	m = pickLine(t, m, "gh", "b")
	golden(t, "identity-menu-mixed", screen(m))
	m = press(m, "esc")
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "ssh a, gh b") || strings.Contains(l, "not in the profile") {
		t.Errorf("a mixed pick is legal: %q", l)
	}
}

func TestIdentitySubmenuConflictGolden(t *testing.T) {
	m := openMenu(blocksFacts())
	m = pickLine(t, m, "ssh", "a")
	m = pickLine(t, m, "gh", "b")
	want := `profiles "a" and "b" pin different identity.gh`
	if !strings.Contains(screen(m), "! "+want) {
		t.Errorf("no ! line:\n%s", screen(m))
	}
	golden(t, "identity-menu-conflict", screen(m))
	m = press(m, "esc")
	m = sized(m, 200)
	if l := lineWith(t, m, "IDENTITY"); !strings.Contains(l, "! not in the profile: "+want) && !strings.Contains(l, "not in the profile: "+want) {
		t.Errorf("main screen: %q", l)
	}
}

func TestAConflictBlocksW(t *testing.T) {
	f := blocksFacts()
	c := config(f)
	var sawRefused map[suggest.RowID]string
	c.Plan = func(s suggest.Selection) (Review, error) {
		_, sawRefused = c.Build(s)
		return Review{Title: "t", Body: "b", Blocked: sawRefused[suggest.Identity] != "", Apply: func() error { return nil }}, nil
	}
	m := press(toIdentity(sized(New(c), 100)), "enter")
	m = pickLine(t, m, "ssh", "a")
	m = pickLine(t, m, "gh", "b")
	m = press(m, "esc", "w")
	if m.rev == nil || !m.rev.r.Blocked {
		t.Fatalf("w must open a blocked review for a refused identity: %+v", sawRefused)
	}
	m = press(m, "y")
	if m.Outcome().Result == Write {
		t.Errorf("y wrote a refused identity")
	}
}

func TestGHBinaryRowIsUnderGHOnlyWhileGHHasASource(t *testing.T) {
	f := hostOnly()
	m := openMenu(f)
	count := func(m Model) int {
		n := 0
		for _, it := range m.sel.IdentityItems() {
			if it.IsPart && it.Part == suggest.PartGHBinary {
				if it.Block != suggest.BlockGH {
					t.Errorf("binary row under %v", it.Block)
				}
				n++
			}
		}
		return n
	}
	if count(m) != 1 {
		t.Fatalf("no binary row with gh from the host")
	}
	m = pickLine(t, m, "gh", "none")
	if count(m) != 0 {
		t.Errorf("binary row with no gh source:\n%s", screen(m))
	}
}
