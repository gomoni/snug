package session

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/rules"
	"github.com/gomoni/snug/setup/internal/testworld"
)

func goProject(t *testing.T, w *testworld.World) {
	t.Helper()
	os.WriteFile(filepath.Join(w.Target, "go.mod"), []byte("module github.com/acme/app\n"), 0o644)
	os.Mkdir(filepath.Join(w.Target, ".git"), 0o755)
}

// startRules is start with the rules interpreter, snug-setup's default.
func startRules(w *testworld.World) (*Session, string) {
	s, lines := New(ctx, Config{Interpreter: rules.Interpreter{}, Run: w.Run, Host: w.Host(), LookPath: w.LookPath, Offline: true, ProfileDir: w.ProfDir, ProfileDirs: []string{w.ProfDir}})
	s.Shown(lines)
	return s, text(lines)
}

func start(w *testworld.World) (*Session, string) {
	s, lines := New(ctx, Config{Interpreter: llm.Interpreter{M: w.Model}, Run: w.Run, Host: w.Host(), LookPath: w.LookPath, Offline: true, ProfileDir: w.ProfDir, ProfileDirs: []string{w.ProfDir}})
	s.Shown(lines)
	return s, text(lines)
}

func TestOpeningProposalIsACardTheHumanAccepts(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, out := start(w)
	contains(t, out, "Go module github.com/acme/app (go.mod)", "a git work tree", "no Dockerfile, Containerfile or compose file",
		"? #1 what I found in the project", "add @git  (from .git)", "set GOMODCACHE={target}/.cache/go-mod  (from go.mod)",
		`Not proposed: @net (say "I need internet")`, "/why has the reasons")
	lacks(t, out, ".gitignore", "for go mod download")
	contains(t, text(s.Details(ctx)), "Not proposed: @net (for go mod download", ".gitignore")
	if !s.Draft().Empty() {
		t.Fatalf("applied before the answer: %s", s.Draft().Render())
	}
	text(s.Accept(ctx, 1))
	if !slices.Equal(s.Draft().Include, []string{"@git"}) {
		t.Errorf("include %v", s.Draft().Include)
	}
	contains(t, s.Draft().Render(), "# proposed from .git, accepted: @git", "# proposed from go.mod, accepted: env GOMODCACHE (set), env GOCACHE (set)",
		`GOMODCACHE = "{target}/.cache/go-mod"`)
}

// TestAnalyzeAgainIsShortAndDoesNotOpenASecondCard: the second ask says where
// the proposal is and what the draft pins, not the opening again, and /why
// still has the whole text.
func TestAnalyzeAgainIsShortAndDoesNotOpenASecondCard(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, opening := start(w)
	out := text(s.Analyze(ctx))
	contains(t, out, "The proposal is open as #1", "Open: #1", "/why prints the full analysis")
	lacks(t, out, "? #", "Go module github.com/acme/app", "Not proposed")
	if got, was := strings.Count(out, "\n"), strings.Count(opening, "\n"); got >= was/2 {
		t.Errorf("a repeat is %d lines, the opening %d", got, was)
	}
	text(s.Accept(ctx, 1))
	out = text(s.Analyze(ctx))
	contains(t, out, "Nothing to propose that the draft does not already have")
	lacks(t, out, "Open:")
	contains(t, text(s.Details(ctx)), "Go module github.com/acme/app", "Found on this host", "Each request stands alone", "Offline: GitHub is not asked")
}

func TestAnalyzeAfterDeclineOffersItAgain(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := start(w)
	text(s.Decline(1))
	if !s.Draft().Empty() {
		t.Fatal("declined proposal changed the draft")
	}
	contains(t, text(s.Analyze(ctx)), "? #2 what I found in the project")
}

// TestAnalyzeRequestIsTheAnalysis: "can you analyze the target dir" is
// answered from the project.
func TestAnalyzeRequestIsTheAnalysis(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := startRules(w)
	out := say(s, "can you analyze the target dir and suggest a setup?")
	contains(t, out, "The proposal is open as #1")
}

// TestHostileTargetProposesNothingFromItsText: a go.mod linked to a file
// outside the target, and a .snug directory, add no text to the screen and no
// grant, and the shipped profile is reported, not read.
func TestHostileTargetProposesNothingFromItsText(t *testing.T) {
	w := testworld.New(t)
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("module PRIVATE-KEY-BYTES\n"), 0o600)
	os.Symlink(outside, filepath.Join(w.Target, "go.mod"))
	os.Mkdir(filepath.Join(w.Target, ".snug"), 0o755)
	_, out := start(w)
	lacks(t, out, "PRIVATE-KEY-BYTES")
	contains(t, out, "Go project (go.mod)", "ships .snug or snug.toml", "does not read it")
}

// TestEveryProposedVariableIsAcceptedByTheDraft: a hint the draft refuses
// would silently vanish from the card, so the table is held against Apply.
func TestEveryProposedVariableIsAcceptedByTheDraft(t *testing.T) {
	w := testworld.New(t)
	p := ingest.Propose(ingest.TargetFacts{Languages: []ingest.Lang{
		{Name: "go", Marker: "go.mod"}, {Name: "node", Marker: "package.json"},
		{Name: "python", Marker: "uv.lock"}, {Name: "rust", Marker: "Cargo.toml"}}})
	s := open(w, true)
	turn := s.proposalTurn(ctx, p)
	if turn == nil || len(turn.Items) != len(p.Env) {
		t.Fatalf("%d of %d variables reach the card", len(turn.Items), len(p.Env))
	}
	_ = draft.SourceIngest
}

// TestCardAnswersInWords: "only 2" keeps the second item of the newest card
// and applies nothing else; "yes" takes a whole card.
func TestCardAnswersInWords(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, out := startRules(w)
	contains(t, out, "1. add @git", "2. set GOMODCACHE", `or say which to keep ("only 1 and 3")`)
	out = say(s, "only 2")
	if slices.Contains(s.Draft().Include, "@git") || !strings.Contains(s.Draft().Render(), "GOMODCACHE") || strings.Contains(s.Draft().Render(), "GOCACHE =") {
		t.Errorf("only 2 applied:\n%s\n%s", s.Draft().Render(), out)
	}
	contains(t, out, "not applied: add @git")
	contains(t, say(s, "yes"), "there is no open question")
	say(s, "needs internet")
	say(s, "yes")
	if !slices.Contains(s.Draft().Include, "@net") {
		t.Errorf("yes did not apply the card: %s", s.Draft().Render())
	}
}

// TestNotUnderstoodOffersChoices: a line the rules cannot read changes
// nothing. With one reading left it is a yes/no question, and yes submits it
// as a request whose card still waits; a line not understood at all offers
// three numbered readings.
func TestNotUnderstoodOffersChoices(t *testing.T) {
	w := testworld.New(t)
	s, _ := startRules(w)
	out := say(s, "needs internet and list them")
	contains(t, out, `I understood add @net, but not "list them". Nothing changed. Only add @net?`, "answer: yes or no")
	if !s.Draft().Empty() {
		t.Fatalf("an unclear line changed the draft: %s", s.Draft().Render())
	}
	out = say(s, "yes")
	contains(t, out, `your request "needs internet and list them" widens the sandbox`, "add @net")
	if !s.Draft().Empty() {
		t.Fatalf("a choice applied without its card: %s", s.Draft().Render())
	}
	out = say(s, "blorf frobnicate")
	contains(t, out, `I did not understand "blorf frobnicate"`, "1. ", "2. ", "3. ")
	say(s, "the usual")
	if n := slices.IndexFunc(s.Pending(), func(p Pending) bool { return p.Kind == Choice }); n < 0 || len(s.Pending()) != 2 {
		t.Errorf("a new line keeps one choice open beside the card: %v", s.Pending())
	}
}

// TestToolchainWordProposesTheAnalysisCaches: "needs internet and go" in a Go
// project puts the Go caches beside @net, or points at the opening card that
// already holds them; with no go.mod it says there is nothing to propose.
func TestToolchainWordProposesTheAnalysisCaches(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := startRules(w)
	s.Decline(1)
	contains(t, say(s, "needs internet and go"), "add @net", "set GOMODCACHE={target}/.cache/go-mod", "set GOCACHE={target}/.cache/go-build")
	w2 := testworld.New(t)
	s2, _ := startRules(w2)
	contains(t, say(s2, "it's a rust project"), "the target has no Cargo.toml, so there is no rust cache to propose")
}

// TestNoChangeIsNotACardItem: asking again for what the draft has says so
// and opens no card.
func TestNoChangeIsNotACardItem(t *testing.T) {
	w := testworld.New(t)
	s, _ := startRules(w)
	say(s, "needs internet")
	say(s, "yes")
	out := say(s, "needs internet and podman")
	contains(t, out, "@net is already in the draft.", "1. add @podman-socket")
	lacks(t, out, "2. ")
}

// TestBareYesOnlyAnswersLastPrinted: a bare answer applies to the question
// printed in answer to the line before it, says which it answered, and with
// none there applies nothing. The opening card is not reachable by a "yes"
// typed under a refusal.
func TestBareYesOnlyAnswersLastPrinted(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := startRules(w)
	if numbers(s)[0] != 1 {
		t.Fatalf("no opening card: %v", numbers(s))
	}
	contains(t, say(s, "give it my ~/.ssh"), "refuses (sensitive_home)")
	out := say(s, "yes")
	contains(t, out, "nothing changed", "#1: /accept 1")
	if !s.Draft().Empty() || len(s.Pending()) != 1 {
		t.Fatalf("a yes under a refusal applied the card printed above it:\n%s\n%s", out, s.Draft().Render())
	}
	contains(t, say(s, "I need internet"), "? #2")
	out = say(s, "yes")
	contains(t, out, "(answering #2)")
	if !slices.Contains(s.Draft().Include, "@net") || !slices.Equal(numbers(s), []int{1}) {
		t.Errorf("yes to #2: %v %s", numbers(s), s.Draft().Render())
	}
	// Only one question open, and it was printed last: the lead line is
	// still there.
	s2, _ := startRules(w)
	contains(t, say(s2, "no"), "(answering #1)", "not applied")
}

// TestNeverMindKeepsADeclinedCardClosed: words that take back the line just
// typed do not undo the decline before it, and a line holding a request and
// its own retraction applies neither.
func TestNeverMindKeepsADeclinedCardClosed(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := startRules(w)
	say(s, "no")
	if len(s.Pending()) != 0 {
		t.Fatalf("decline left %v", numbers(s))
	}
	out := say(s, "let it read ~/.ssh, no wait, never mind")
	contains(t, out, "nothing from it is applied and nothing earlier was undone")
	if len(s.Pending()) != 0 {
		t.Errorf("never mind beside a request reopened %v:\n%s", numbers(s), out)
	}
	out = say(s, "never mind")
	contains(t, out, "nothing was undone", "/undo reopens #1")
	if len(s.Pending()) != 0 {
		t.Errorf("never mind reopened %v:\n%s", numbers(s), out)
	}
	contains(t, text(s.Undo()), "#1 is open again")
	if !slices.Equal(numbers(s), []int{1}) || !s.Draft().Empty() {
		t.Errorf("/undo: %v %s", numbers(s), s.Draft().Render())
	}
}

// TestUnnamedProjectLabelsDoNotRepeatAWord fails if the opening text calls a
// project whose marker file names nothing "Python project project" (or "Node
// package project", "Rust crate project").
func TestUnnamedProjectLabelsDoNotRepeatAWord(t *testing.T) {
	for _, lang := range []string{"go", "node", "python", "rust"} {
		got := describeTarget("/t", ingest.TargetFacts{Languages: []ingest.Lang{{Name: lang, Marker: "marker"}}})
		if strings.Contains(got, "project project") || strings.Contains(got, "package project") || strings.Contains(got, "crate project") || !strings.Contains(got, " project (marker)") {
			t.Errorf("%s: %s", lang, got)
		}
	}
}
