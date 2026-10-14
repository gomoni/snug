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
	"github.com/gomoni/snug/setup/internal/testworld"
)

func goProject(t *testing.T, w *testworld.World) {
	t.Helper()
	os.WriteFile(filepath.Join(w.Target, "go.mod"), []byte("module github.com/acme/app\n"), 0o644)
	os.Mkdir(filepath.Join(w.Target, ".git"), 0o755)
}

func start(w *testworld.World) (*Session, string) {
	s, lines := New(ctx, Config{Interpreter: llm.Interpreter{M: w.Model}, Run: w.Run, Host: w.Host(), LookPath: w.LookPath, Offline: true, ProfileDir: w.ProfDir, ProfileDirs: []string{w.ProfDir}})
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

// TestAnalyzeRequestSkipsTheModel: "can you analyze the target dir" is
// answered from the project, not by the nearest action the model has.
func TestAnalyzeRequestSkipsTheModel(t *testing.T) {
	w := testworld.New(t)
	goProject(t, w)
	s, _ := start(w)
	out := say(s, "can you analyze the target dir and suggest a setup?")
	contains(t, out, "The proposal is open as #1")
	if len(w.Model.Prompts) != 0 {
		t.Errorf("the model was asked: %v", w.Model.Prompts)
	}
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
