package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/testworld"
)

var ctx = context.Background()

func open(w *testworld.World, offline bool) *Session {
	s, _ := New(ctx, Config{Model: w.Model, Run: w.Run, Host: w.Host(), LookPath: w.LookPath, Offline: offline, ProfileDir: w.ProfDir})
	return s
}

// say is what --plain does with a request line.
func say(s *Session, request string) string {
	t, lines := s.Submit(ctx, request)
	if t != nil {
		lines = append(lines, s.Defer(ctx, t)...)
	}
	return text(lines)
}

func text(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Text + "\n")
	}
	return b.String()
}

func contains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, s := range wants {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func lacks(t *testing.T, out string, nots ...string) {
	t.Helper()
	for _, s := range nots {
		if strings.Contains(out, s) {
			t.Errorf("output has %q:\n%s", s, out)
		}
	}
}

func numbers(s *Session) []int {
	var out []int
	for _, p := range s.Pending() {
		out = append(out, p.N)
	}
	return out
}

const (
	useNet    = `{"op":"use_profile","name":"@net"}`
	usePodman = `{"op":"use_profile","name":"@podman-socket"}`
	dropNet   = `{"op":"drop_profile","name":"@net"}`
	nameWork  = `{"op":"name_profile","name":"work"}`
	assignGH2 = `{"op":"select_identity","kind":"github","account":"account2"}`
	assignGH1 = `{"op":"select_identity","kind":"github","account":"account1"}`
)

func TestCardIsPendingUntilAccepted(t *testing.T) {
	w := testworld.New(t)
	w.Reply("I need podman", usePodman, `{"op":"note","topic":"podman_offline"}`)
	s := open(w, true)
	out := say(s, "I need podman")
	contains(t, out, "? #1 your request \"I need podman\" widens the sandbox", "add @podman-socket",
		"ABUSE: the sandbox can run arbitrary code in a container", "/accept 1 applies all of it, /decline 1",
		"genuinely offline, containers included")
	if !s.Draft().Empty() || len(s.Draft().Ledger()) != 0 {
		t.Fatalf("applied before the answer: %s", s.Draft().Render())
	}
	if ps := s.Pending(); len(ps) != 1 || ps[0].Kind != Card {
		t.Fatalf("%+v", ps)
	}
	out = text(s.Accept(ctx, 1))
	if got := s.Draft().Include; !slices.Equal(got, []string{"@podman-socket"}) {
		t.Errorf("%v\n%s", got, out)
	}
	if len(s.Pending()) != 0 {
		t.Errorf("still pending: %v", numbers(s))
	}
	contains(t, s.Draft().Render(), `# intent (you): "I need podman" -> @podman-socket`)
}

func TestDeclinedCardLeavesNoTrace(t *testing.T) {
	w := testworld.New(t)
	w.Reply("needs internet", useNet, nameWork)
	s := open(w, true)
	say(s, "needs internet")
	out := text(s.Decline(1))
	contains(t, out, "not applied")
	if !s.Draft().Empty() || s.Draft().Name != "" || len(s.Draft().Ledger()) != 0 {
		t.Errorf("a declined card changed the draft: %s", s.Draft().Render())
	}
	contains(t, text(s.Accept(ctx, 1)), "there is no open question #1")
}

// TestEditsInACardTurnWaitForTheCard: an edit said beside a grant applies with
// the card, in the order it was said, so a prepend lands after the grant it
// needs.
func TestEditsInACardTurnWaitForTheCard(t *testing.T) {
	w := testworld.New(t)
	os.MkdirAll(filepath.Join(w.Home, "go", "bin"), 0o755)
	w.Reply("add ~/go/bin to PATH", `{"op":"grant_path","path":"~/go/bin","access":"ro"}`, `{"op":"set_env","name":"PATH","verb":"prepend","value":"~/go/bin"}`)
	s := open(w, true)
	say(s, "add ~/go/bin to PATH")
	if !s.Draft().Empty() {
		t.Fatalf("applied before the answer: %s", s.Draft().Render())
	}
	out := text(s.Accept(ctx, 1))
	lacks(t, out, "refused")
	contains(t, s.Draft().Render(), `ro = ["~/go/bin"]`, `PATH = ["~/go/bin"]`)
}

func TestTurnWithoutAGrantAppliesAtOnce(t *testing.T) {
	w := testworld.New(t)
	w.Reply("keep it offline", dropNet)
	s := open(w, true)
	say(s, "keep it offline")
	if len(s.Pending()) != 0 {
		t.Errorf("an edit opened a question: %v", numbers(s))
	}
	if l := s.Draft().IntentLines(); len(l) != 1 || !strings.Contains(l[0], "drop @net") {
		t.Errorf("%v", l)
	}
}

// TestModelValueWaitsForTheCard is redteam setup r1 S1: the human asks only
// for a name, the model adds an environment value and a tmpfs. Neither widens
// what the sandbox sees, but both would persist in every later run, so they
// wait on a card and a declined card saves neither.
func TestModelValueWaitsForTheCard(t *testing.T) {
	for _, extra := range []string{
		`{"op":"set_env","name":"PYTHONSTARTUP","verb":"set","value":"/tmp/x.py"}`,
		`{"op":"grant_path","path":"{target}/.git","access":"tmpfs"}`,
	} {
		w := testworld.New(t)
		w.Reply("call it work", nameWork, extra)
		s := open(w, true)
		say(s, "call it work")
		if ps := s.Pending(); len(ps) != 1 || ps[0].Kind != Card {
			t.Fatalf("%s: applied without a card: %v\n%s", extra, ps, s.Draft().Render())
		}
		if s.Draft().Name != "" || len(s.Draft().Ledger()) != 0 {
			t.Errorf("%s: applied before the answer: %s", extra, s.Draft().Render())
		}
		s.Decline(1)
		_, l := s.Save(ctx, "")
		out := text(l)
		if r := s.Draft().Render(); strings.Contains(r, "/tmp/") || strings.Contains(r, "tmpfs") {
			t.Errorf("%s: a declined value reached the profile:\n%s\n%s", extra, r, out)
		}
	}
}

func TestAlreadyTheDefaultIsNotACard(t *testing.T) {
	w := testworld.New(t)
	w.Reply("give me write access here", `{"op":"use_profile","name":"@target-rw"}`, `{"op":"note","topic":"defaults"}`)
	s := open(w, true)
	out := say(s, "give me write access here")
	if len(s.Pending()) != 0 {
		t.Errorf("a no-op opened a question: %v", numbers(s))
	}
	if n := strings.Count(out, "A bare `snug DIR` already selects @sys, @home and @target-rw"); n != 1 {
		t.Errorf("the defaults note was said %d times:\n%s", n, out)
	}
	contains(t, s.Draft().Render(), `# intent (you): "give me write access here" -> @target-rw`)
	lacks(t, s.Draft().Render(), `"@target-rw",`)

	w = testworld.New(t)
	w.Reply("give me write access here", `{"op":"use_profile","name":"@target-rw"}`)
	s = open(w, true)
	if n := strings.Count(say(s, "give me write access here"), "A bare `snug DIR` already selects"); n != 1 {
		t.Errorf("without the model's note Go says it once, said %d times", n)
	}
}

// TestUndoAcrossPendings: a commit is one human act, and its snapshot holds
// the pending list, so undo takes a turn's questions with it and puts an
// answered question back under its old number.
func TestUndoAcrossPendings(t *testing.T) {
	w := testworld.New(t)
	w.Reply("keep it offline", dropNet)
	w.Reply("I need podman", usePodman)
	w.Reply("I need podman", usePodman)
	s := open(w, true)
	say(s, "keep it offline")
	say(s, "I need podman")
	if got := numbers(s); !slices.Equal(got, []int{1}) {
		t.Fatalf("%v", got)
	}

	contains(t, text(s.Undo()), `undone: your request "I need podman"`)
	if len(s.Pending()) != 0 {
		t.Errorf("undoing the turn left its question: %v", numbers(s))
	}
	if l := s.Draft().IntentLines(); len(l) != 1 || !strings.Contains(l[0], "keep it offline") {
		t.Errorf("%v", l)
	}

	say(s, "I need podman")
	if got := numbers(s); !slices.Equal(got, []int{2}) {
		t.Fatalf("a number was reused: %v", got)
	}
	s.Accept(ctx, 2)
	if !slices.Contains(s.Draft().Include, "@podman-socket") {
		t.Fatal("not applied")
	}
	contains(t, text(s.Undo()), "undone: the answer to #2")
	if slices.Contains(s.Draft().Include, "@podman-socket") || !slices.Equal(numbers(s), []int{2}) {
		t.Errorf("undoing the accept: include %v, pending %v", s.Draft().Include, numbers(s))
	}

	s.Decline(2)
	s.Undo()
	if !slices.Equal(numbers(s), []int{2}) {
		t.Errorf("undoing the decline did not reopen #2: %v", numbers(s))
	}
	s.Undo()
	s.Undo()
	contains(t, text(s.Undo()), "nothing to undo")
	if !s.Draft().Empty() || len(s.Pending()) != 0 {
		t.Errorf("%s %v", s.Draft().Render(), numbers(s))
	}
}

func TestSaveRefusesWhilePendingNamingTheAnswer(t *testing.T) {
	w := testworld.New(t)
	w.Reply("keep it offline", dropNet)
	w.Reply("I need podman", usePodman)
	w.Reply("assign github account2", assignGH2)
	s := open(w, true)
	say(s, "keep it offline")
	say(s, "I need podman")
	say(s, "assign github account2")
	ok, lines := s.Save(ctx, "work")
	out := text(lines)
	if ok {
		t.Fatal("saved with open questions")
	}
	contains(t, out, "not saved: 2 question(s) are open", "#1 your request", "/accept 1", "#2 which GitHub login", "/pick github LOGIN, or /pick github none")
	if _, err := os.Stat(filepath.Join(w.ProfDir, "work.toml")); err == nil {
		t.Error("a file was written")
	}
	if slices.Contains(w.Cmds, "/fake/snug") || slices.ContainsFunc(w.Cmds, func(c string) bool { return strings.HasPrefix(c, "/fake/snug") }) {
		t.Error("snug was run for a save that was refused before the check")
	}
}

// TestIdentityIsAlwaysAQuestion: a host with exactly one GitHub login still
// gets the question, and only an exact /pick answers it.
func TestIdentityIsAlwaysAQuestion(t *testing.T) {
	w := testworld.New(t)
	w.GHAccounts = "github.com\n  ✓ Logged in to github.com account account2 (keyring)\n  - Active account: true\n"
	w.Reply("assign github account2", assignGH2)
	s := open(w, false)
	out := say(s, "assign github account2")
	contains(t, out, "? #1 which GitHub login should the sandbox act as? (you said \"account2\")", "github.com/account2  (active)", "/pick github LOGIN")
	if s.Draft().GH != nil {
		t.Fatal("picked without a /pick")
	}
	for _, v := range []string{"Account2", "account", "github.com/account2", "1", ""} {
		contains(t, text(s.Pick(ctx, "github", v)), "is not a GitHub login on this host: one of account2, or none", "#1 stays open")
		if s.Draft().GH != nil || len(s.Pending()) != 1 {
			t.Fatalf("%q picked something", v)
		}
	}
	contains(t, text(s.Accept(ctx, 1)), "#1 is answered by naming the identity")
	out = text(s.Pick(ctx, "github", "account2"))
	if s.Draft().GH == nil || s.Draft().GH.User != "account2" || s.Draft().SSH != nil || s.Draft().Git != nil {
		t.Fatalf("%+v %+v %+v", s.Draft().GH, s.Draft().SSH, s.Draft().Git)
	}
	contains(t, out, "pinned GitHub login github.com/account2", "no ssh key is pinned", "no git author is pinned")
	contains(t, s.Draft().Render(), `# intent (you, confirmed): "assign github account2" -> github identity account2`)
}

func TestPickNoneAndPickWithoutAQuestion(t *testing.T) {
	w := testworld.New(t)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	s := open(w, true)
	contains(t, text(s.Pick(ctx, "ssh", "id_account2")), "there is no open ssh question")
	if s.Draft().SSH != nil {
		t.Fatal("pinned without a question")
	}
	say(s, "use my ssh key")
	contains(t, text(s.Pick(ctx, "github", "account2")), "there is no open github question")
	contains(t, text(s.Pick(ctx, "ssh", "none")), "no ssh key pinned")
	if !s.Draft().Empty() || len(s.Pending()) != 0 {
		t.Errorf("%s %v", s.Draft().Render(), numbers(s))
	}
}

func TestPinOwnershipChecks(t *testing.T) {
	pin := func(w *testworld.World, offline bool) string {
		w.Reply("assign github account2", assignGH2)
		w.Reply("use the key for account2", `{"op":"select_identity","kind":"ssh","account":"account2"}`)
		s := open(w, offline)
		say(s, "assign github account2")
		s.Pick(ctx, "github", "account2")
		say(s, "use the key for account2")
		return text(s.Pick(ctx, "ssh", "id_account2"))
	}
	w := testworld.New(t)
	contains(t, pin(w, false), "checked: GitHub lists id_account2")
	for i, c := range w.Cmds {
		if strings.Contains(c, "ghp_SECRET") {
			t.Errorf("token in argv: %s", c)
		}
		if strings.HasPrefix(c, "gh api") && (len(w.Envs[i]) != 1 || w.Envs[i][0] != "GH_TOKEN=ghp_SECRET") {
			t.Errorf("gh api env %v", w.Envs[i])
		}
	}

	w = testworld.New(t)
	w.APIBlob = testworld.BlobOf(77)
	contains(t, pin(w, false), "!!! SPLIT IDENTITY !!!", "does not list the ssh key id_account2")

	w = testworld.New(t)
	contains(t, pin(w, true), "offline: not checking")
	if n := w.APICalls(); n != 0 {
		t.Errorf("%d gh api calls while offline", n)
	}

	w = testworld.New(t)
	w.APILogin = "someone-else"
	contains(t, pin(w, false), "warning: could not check")
}

// TestSecondIdentityIsASessionQuestion: a human's second select_identity of a
// pinned kind is not a ledger conflict (Propose checks only file and default
// actions), so the session asks it as a second-profile question.
func TestSecondIdentityIsASessionQuestion(t *testing.T) {
	w := testworld.New(t)
	w.Reply("assign github account2", assignGH2)
	w.Reply("now account1", assignGH1)
	w.Reply("now account1", assignGH1)
	w.Reply("account2 again", assignGH2)
	s := open(w, true)
	say(s, "assign github account2")
	s.Pick(ctx, "github", "account2")

	contains(t, say(s, "account2 again"), "already pins the GitHub login \"account2\"; nothing changed")
	out := say(s, "now account1")
	contains(t, out, "TWO ACCOUNTS ARE TWO PROFILES", "#2 the draft already pins the GitHub login \"account2\"", "/accept 2 saves this profile")
	if p := s.Pending(); len(p) != 1 || p[0].Kind != SecondProfile {
		t.Fatalf("%+v", p)
	}
	s.Decline(2)
	if s.Draft().GH.User != "account2" {
		t.Errorf("declining must keep the first identity, have %s", s.Draft().GH.User)
	}

	say(s, "now account1")
	contains(t, text(s.Accept(ctx, 3)), "this profile has no name yet: /save NAME first, then /accept 3")
	if ok, lines := s.Save(ctx, "work"); !ok {
		t.Fatalf("a second-profile question must not block the save:\n%s", text(lines))
	}
	out = text(s.Accept(ctx, 3))
	contains(t, out, "already holds exactly this profile", "started a new, empty profile.", "#4 which GitHub login", "(you said \"account1\")")
	saved, err := os.ReadFile(filepath.Join(w.ProfDir, "work.toml"))
	if err != nil {
		t.Fatal(err)
	}
	contains(t, string(saved), `user = "account2"`)
	s.Pick(ctx, "github", "account1")
	if s.Draft().GH == nil || s.Draft().GH.User != "account1" || s.Draft().Name != "" {
		t.Errorf("second profile: %+v name %q", s.Draft().GH, s.Draft().Name)
	}
	contains(t, text(s.Undo()), "undone")
	contains(t, text(s.Undo()), "nothing to undo")
}

// proposeFile is how a file's action reaches the session once compose
// suggestions exist: through the ledger, which turns a contradiction of what
// the human said into a conflict question.
func (s *Session) proposeFile(a intent.Action, file, said string, turn int) []Line {
	before := s.snapshot()
	o, p := s.d.Propose(a, draft.SourceFile, file, turn)
	defer s.commit(before, "a file's suggestion")
	if p != nil {
		return []Line{s.open(Pending{Kind: Conflict, conf: *p, said: said, at: turn}).Line()}
	}
	return outcome(o)
}

func TestConflictQuestion(t *testing.T) {
	for _, accept := range []bool{false, true} {
		w := testworld.New(t)
		w.Reply("keep it offline", dropNet)
		s := open(w, true)
		say(s, "keep it offline")
		out := text(s.proposeFile(intent.Action{Op: intent.OpUseProfile, Name: "@net"}, "docker-compose.yml", "read the compose file", 2))
		contains(t, out, `? #1 docker-compose.yml asks for @net, but you said "keep it offline" (drop @net) — add it?`, "/accept 1 takes it, /decline 1 keeps what you said")
		if slices.Contains(s.Draft().Include, "@net") {
			t.Fatal("applied before the answer")
		}
		if accept {
			s.Accept(ctx, 1)
			contains(t, s.Draft().Render(), `# intent (docker-compose.yml, accepted over "keep it offline"): -> @net`)
		} else {
			contains(t, text(s.Decline(1)), "not applied: @net.")
			contains(t, s.Draft().Render(), `# intent (docker-compose.yml, declined): @net — conflicts with "keep it offline"`)
		}
		if got := slices.Contains(s.Draft().Include, "@net"); got != accept {
			t.Errorf("accept=%v: @net in draft = %v", accept, got)
		}
		s.Undo()
		if !slices.Equal(numbers(s), []int{1}) || slices.Contains(s.Draft().Include, "@net") {
			t.Errorf("undo did not reopen the conflict: %v %v", numbers(s), s.Draft().Include)
		}
	}
}

func TestFileCannotSwapAPickedIdentity(t *testing.T) {
	w := testworld.New(t)
	w.Reply("assign github account2", assignGH2)
	s := open(w, true)
	say(s, "assign github account2")
	s.Pick(ctx, "github", "account2")
	out := text(s.proposeFile(intent.Action{Op: intent.OpSelectIdentity, Kind: "github", Account: "account1"}, "docker-compose.yml", "read it", 2))
	contains(t, out, `? #2 docker-compose.yml asks for github identity account1, but you said "assign github account2" (github identity account2) — choose one?`)
	contains(t, text(s.Decline(2)), "not applied: github identity account1.")
	if s.Draft().GH.User != "account2" {
		t.Errorf("%+v", s.Draft().GH)
	}
	s.Undo()
	contains(t, text(s.Accept(ctx, 2)), "#3 the draft already pins the GitHub login")
	if s.Draft().GH.User != "account2" {
		t.Errorf("taking the file's identity must go through a second profile: %+v", s.Draft().GH)
	}
}

func TestSentencesTakeTheDraftIntoAccount(t *testing.T) {
	pinKey := func(s *Session) string {
		say(s, "use my ssh key")
		return text(s.Pick(ctx, "ssh", "id_account2"))
	}
	w := testworld.New(t)
	w.Reply("needs internet", useNet)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	s := open(w, true)
	say(s, "needs internet")
	s.Accept(ctx, 1)
	out := pinKey(s)
	contains(t, out, "@net is in the draft")
	lacks(t, out, "needs internet")

	w = testworld.New(t)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	s = open(w, true)
	contains(t, pinKey(s), `Pushing needs @net: say "needs internet"`)

	d := draft.New(w.Host())
	for a, want := range map[intent.Action]string{
		{Op: intent.OpUseProfile, Name: "@target-rw"}:                     "@target-rw is already the default; nothing to add",
		{Op: intent.OpUseProfile, Name: "@net"}:                           "add @net",
		{Op: intent.OpGrantPath, Path: "{target}", Access: "ro"}:          "the project is read-only (run with --no-defaults)",
		{Op: intent.OpGrantPath, Path: "~/data", Access: "rw"}:            "writable: " + w.Home + "/data (persists)",
		{Op: intent.OpSelectIdentity, Kind: "github", Account: "x\ny"}:    `pick a GitHub login (you said "x y")`,
		{Op: intent.OpRefuse, Code: "host_port"}:                          "the model read this as a request snug refuses (host_port)",
		{Op: intent.OpSetEnv, Name: "EDITOR", Verb: "set", Value: "vim"}:  "set EDITOR=vim",
		{Op: intent.OpStageBinary, Host: "/opt/x/bin/x", Name: "x"}:       "stage /opt/x/bin/x as /snug/bin/x",
		{Op: intent.OpSetEnv, Name: "PAGER", Verb: "inherit"}:             "copy PAGER from your environment",
		{Op: intent.OpDropPath, Path: "/srv/a"}:                           "remove /srv/a from the draft",
		{Op: intent.OpAsk, Question: "which one?"}:                        `the model asks: "which one?"`,
		{Op: intent.OpListIdentities, Kind: "ssh"}:                        "list the ssh keys on this host",
		{Op: intent.OpGrantPath, Path: "/scratch", Access: "tmpfs"}:       "scratch tmpfs at /scratch (empty, gone when the sandbox exits)",
		{Op: intent.OpSetEnv, Name: "PATH", Verb: "prepend", Value: "/x"}: "put /x in front of PATH",
	} {
		if got := Sentence(d, a); got != want {
			t.Errorf("%+v: %q, want %q", a, got, want)
		}
	}
	d.Include = []string{"@podman-build"}
	if got := Sentence(d, intent.Action{Op: intent.OpUseProfile, Name: "@podman-socket"}); got != "@podman-socket is already in the draft" {
		t.Errorf("%q", got)
	}
}

// TestApplyAppliesOnlyTheTicked is the TUI's card: an unticked grant leaves no
// trace, an edit in the same turn applies regardless.
func TestApplyAppliesOnlyTheTicked(t *testing.T) {
	w := testworld.New(t)
	w.Reply("podman and internet, call it work", usePodman, useNet, nameWork)
	s := open(w, true)
	turn, _ := s.Submit(ctx, "podman and internet, call it work")
	if turn == nil || !turn.HasCard() {
		t.Fatalf("%+v", turn)
	}
	if c := []Class{turn.Items[0].Class, turn.Items[1].Class, turn.Items[2].Class}; !slices.Equal(c, []Class{ClassGrant, ClassGrant, ClassEdit}) || !turn.Items[0].Ticked {
		t.Fatalf("%v", c)
	}
	out := text(s.Apply(ctx, turn, []int{1}))
	contains(t, out, "not applied (unticked): add @podman-socket")
	if !slices.Equal(s.Draft().Include, []string{"@net"}) || s.Draft().Name != "work" || len(s.Pending()) != 0 {
		t.Errorf("%v %q %v", s.Draft().Include, s.Draft().Name, numbers(s))
	}
	lacks(t, s.Draft().Render(), `"@podman-socket"`)
}

// TestModelTextIsInlined: what the model wrote reaches a line only as one
// line, with nothing a terminal acts on.
func TestModelTextIsInlined(t *testing.T) {
	w := testworld.New(t)
	w.RawReply("x", `{"actions":[{"op":"ask","question":"fine\u001b[2J\u202eevil\nchecked: GitHub lists it"},{"op":"drop_path","path":"/srv/a\u001b]0;x\u0007\u200b"}]}`)
	s := open(w, true)
	t2, pre := s.Submit(ctx, "x")
	lines := append(pre, s.Defer(ctx, t2)...)
	for _, l := range lines {
		for _, bad := range []string{"\x1b", "\x07", "\U0000202E", "\U0000200B"} {
			if strings.Contains(l.Text, bad) {
				t.Errorf("line carries %q: %q", bad, l.Text)
			}
		}
		if strings.Contains(l.Text, "\nchecked:") {
			t.Errorf("the model started a line of its own: %q", l.Text)
		}
	}
	contains(t, text(lines), `the model asks: "fine[2Jevil checked: GitHub lists it"`)
}

func TestModelCannotGrantSSH(t *testing.T) {
	w := testworld.New(t)
	w.Reply("give it my ssh", `{"op":"grant_path","path":"~/.ssh","access":"ro"}`, `{"op":"grant_path","path":"/run/user/1000/bus","access":"rw"}`, `{"op":"grant_path","path":"/","access":"ro"}`)
	s := open(w, true)
	out := say(s, "give it my ssh")
	contains(t, out, "refused (sensitive_home)", "refused (desktop_socket)", "refused (whole_home)")
	if !s.Draft().Empty() || len(s.Pending()) != 0 {
		t.Errorf("a refused grant reached the draft or a card: %s %v", s.Draft().Render(), numbers(s))
	}
}

func TestGarbageChangesNothing(t *testing.T) {
	w := testworld.New(t)
	w.RawReply("do the thing", "sure! @net")
	w.RawReply("do the thing", `{"actions":[{"op":"rm"}]}`)
	s := open(w, true)
	contains(t, say(s, "do the thing"), "I did not understand that, and nothing changed")
	if len(w.Model.Prompts) != 2 || !s.Draft().Empty() {
		t.Errorf("%d calls, draft %s", len(w.Model.Prompts), s.Draft().Render())
	}
}

func TestRefusalIsTheModelsReading(t *testing.T) {
	w := testworld.New(t)
	w.Reply("hide ~/src/other", `{"op":"refuse","code":"host_port"}`)
	s := open(w, true)
	out := say(s, "hide ~/src/other")
	contains(t, out, "the model read this as a request snug refuses (host_port). snug's rule:", "say it differently — nothing changed")
}

// TestOnlyComposeIsRead: every other file is the project's words, and is
// neither read nor sent to the model.
func TestOnlyComposeIsRead(t *testing.T) {
	w := testworld.New(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("TOP SECRET"), 0o600)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(w.Target, "README.md"))
	os.WriteFile(filepath.Join(w.Target, "docker-compose.yml"), []byte("services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n"), 0o644)
	w.Reply("read the readme", `{"op":"read_file","path":"README.md"}`)
	w.Reply("read the compose file", `{"op":"read_file","path":"docker-compose.yml"}`)
	w.Reply("read ../secret", `{"op":"read_file","path":"../docker-compose.yml"}`)
	s := open(w, true)
	contains(t, say(s, "read the readme"), "snug-setup does not suggest grants from README.md", "Read it yourself and say what you need")
	contains(t, say(s, "read the compose file"), "read docker-compose.yml: 2 service(s).")
	contains(t, say(s, "read ../secret"), "not read:")
	if n := len(w.Model.Prompts); n != 3 {
		t.Errorf("%d model calls: a file is never sent to the model", n)
	}
	for _, p := range w.Model.Prompts {
		lacks(t, p, "TOP SECRET", "postgres")
	}
	if !s.Draft().Empty() {
		t.Errorf("reading changed the draft: %s", s.Draft().Render())
	}
}

func named(t *testing.T, w *testworld.World, s *Session) {
	t.Helper()
	w.Reply("net", useNet, nameWork)
	say(s, "net")
	s.Accept(ctx, 1)
	if s.Draft().Name != "work" {
		t.Fatalf("%s", s.Draft().Render())
	}
}

func TestSaveAndOverwriteQuestion(t *testing.T) {
	w := testworld.New(t)
	s := open(w, true)
	named(t, w, s)
	ok, lines := s.Save(ctx, "")
	if !ok {
		t.Fatal(text(lines))
	}
	contains(t, text(lines), "checked: snug -p work", "wrote ", "snug accepts it", "Run it with:\n  snug -p work ")
	path := filepath.Join(w.ProfDir, "work.toml")

	w.Reply("git", `{"op":"use_profile","name":"@git"}`)
	w.Reply("claude", `{"op":"use_profile","name":"@claude"}`)
	say(s, "git")
	s.Accept(ctx, 2)
	ok, lines = s.Save(ctx, "")
	out := text(lines)
	if ok {
		t.Fatal("overwrote without a question")
	}
	contains(t, out, "? #3 "+path+" exists and differs from the draft; overwrite it?", `+   "@git",`, "/accept 3 writes it")
	body, _ := os.ReadFile(path)
	lacks(t, string(body), "@git")
	contains(t, text(s.Decline(3)), "not saved;")

	s.Save(ctx, "")
	say(s, "claude")
	s.Accept(ctx, 5)
	contains(t, text(s.Accept(ctx, 4)), "the draft changed after the check, so #4 lapsed")
	body, _ = os.ReadFile(path)
	lacks(t, string(body), "@git")

	s.Save(ctx, "")
	contains(t, text(s.Accept(ctx, 6)), "wrote "+path)
	body, _ = os.ReadFile(path)
	contains(t, string(body), `"@git"`, `"@claude"`)
	if s.Unsaved() {
		t.Error("Unsaved after the write")
	}
}

func TestSaveRefusals(t *testing.T) {
	w := testworld.New(t)
	s := open(w, true)
	contains(t, text(func() []Line { _, l := s.Save(ctx, "work"); return l }()), "nothing to save yet")

	w.Reply("net", useNet)
	say(s, "net")
	s.Accept(ctx, 1)
	_, l := s.Save(ctx, "")
	contains(t, text(l), "the profile has no name. Type /save NAME")
	_, l = s.Save(ctx, "bad_name")
	contains(t, text(l), `"bad_name" is not a profile name`)

	w.NoSnug = true
	_, l = s.Save(ctx, "work")
	contains(t, text(l), "not saved: snug is not on PATH", "go build")
	w.NoSnug = false

	w.DryRunDoc = `{"snug":{"format":2,"outcome":"ok","lossy":false,"policy_resolved":true},
		"profiles":{"selected":["@sys","@home","@target-rw","work"],"implied":["@net","@claude"]},
		"mounts":[],"network":{"mode":"egress","egress":true}}`
	_, l = s.Save(ctx, "work")
	contains(t, text(l), "not saved: snug resolves this draft differently", "XDG_CONFIG_HOME=<a scratch directory", "snug selects @claude, which nothing in the intent ledger asked for")
	if _, err := os.Stat(filepath.Join(w.ProfDir, "work.toml")); err == nil {
		t.Fatal("saved anyway")
	}

	w.DryRunDoc = ""
	w.SnugErr = errors.New("exit status 77")
	ok, l := s.Save(ctx, "work")
	contains(t, text(l), "snug REFUSED the profile", "unknown key")
	lacks(t, text(l), "Run it with")
	if !ok {
		t.Error("the file was written; Save must say so")
	}
}

func TestReadonlyTargetRunLine(t *testing.T) {
	w := testworld.New(t)
	w.Reply("read-only here", `{"op":"grant_path","path":"{target}","access":"ro"}`, `{"op":"note","topic":"readonly_target"}`)
	s := open(w, true)
	say(s, "read-only here")
	s.Accept(ctx, 1)
	_, l := s.Save(ctx, "review")
	contains(t, text(l), "snug --no-defaults -p review "+w.Target, "snug accepts it")
	body, _ := os.ReadFile(filepath.Join(w.ProfDir, "review.toml"))
	contains(t, string(body), `ro = ["{target}"]`, `"@sys"`, `"@home"`)
}

func TestSaveOpRunsAfterTheTurn(t *testing.T) {
	w := testworld.New(t)
	w.Reply("needs internet and save it as work", useNet, nameWork, `{"op":"save"}`)
	s := open(w, true)
	out := say(s, "needs internet and save it as work")
	contains(t, out, "not saved: 1 question(s) are open", "/accept 1")
	if _, err := os.Stat(filepath.Join(w.ProfDir, "work.toml")); err == nil {
		t.Error("the save op saved past its own card")
	}
}

func TestBestMatch(t *testing.T) {
	cands := []Candidate{
		{names: []string{"id_ed25519", "me@laptop"}},
		{names: []string{"id_work", "me@corp.example"}},
		{names: []string{"id_workstation", "x"}},
	}
	for acct, want := range map[string]int{
		"id_work": 1, "work": 1, "WORK": 1, "~/.ssh/id_work.pub": 1, "corp": 1, "laptop": 0,
		"": -1, "nothing": -1, "id_workstation": 2,
	} {
		if got := bestMatch(acct, cands); got != want {
			t.Errorf("%q: %d, want %d", acct, got, want)
		}
	}
}

func TestPromptCarriesDraftAndHost(t *testing.T) {
	w := testworld.New(t)
	w.Reply("a", `{"op":"drop_profile","name":"@git"}`, nameWork)
	w.Reply("b", `{"op":"show"}`)
	s := open(w, true)
	say(s, "a")
	say(s, "b")
	p := w.Model.Prompts[1]
	contains(t, p, "draft: name=work include=- rw=- ro=- tmpfs=- env=- identity=-",
		"host ssh: id_account1 (account1@laptop); id_account2 (account2@laptop, agent); id_other (other@example.org)",
		"host github: github.com/account1 (active); github.com/account2",
		"host git: Account Two <two@example.com>")
}

// TestSaveRefusesAFifoAtTheProfileName: os.ReadFile on a FIFO waits for a
// writer that never comes; the save must refuse instead.
func TestSaveRefusesAFifoAtTheProfileName(t *testing.T) {
	w := testworld.New(t)
	s := open(w, true)
	named(t, w, s)
	os.MkdirAll(w.ProfDir, 0o755)
	if err := syscall.Mkfifo(filepath.Join(w.ProfDir, "work.toml"), 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan string, 1)
	go func() { _, l := s.Save(ctx, ""); done <- text(l) }()
	select {
	case out := <-done:
		contains(t, out, "not saved: cannot look at", "is not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("Save blocked on a FIFO")
	}
}
