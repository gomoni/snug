package plain

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/session"
	"github.com/gomoni/snug/setup/internal/testworld"
)

// run drives plain.Run end to end: the model is reached over HTTP through
// llm.Remote, gh, ssh-add, git and snug are the fake world's.
func run(t *testing.T, w *testworld.World, script string) (*session.Session, string) {
	t.Helper()
	var out bytes.Buffer
	s := Run(context.Background(), Config{
		Session: session.Config{
			Interpreter: llm.Interpreter{M: llm.Model{B: &llm.Remote{URL: w.LLMServer().URL}}},
			Run:         w.Run,
			Host:        w.Host(),
			LookPath:    w.LookPath,
			Offline:     true,
			ProfileDir:  w.ProfDir,
		},
		In:   strings.NewReader(script),
		Out:  &out,
		Echo: true,
	})
	return s, out.String()
}

func contains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, s := range wants {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

const outOfScope = `{"op":"refuse","code":"out_of_scope"}`

// TestPlainAnswersOnlyAWholeAnswerLine: a line that is yes, no or numbers
// answers the question just printed, and nothing else does. "y" does not name a
// login, so it pins none; "save" is a request even with a question open, and
// refuses naming it; "2" picks the second login listed; with nothing open, a
// bare answer says so.
func TestPlainAnswersOnlyAWholeAnswerLine(t *testing.T) {
	w := testworld.New(t)
	w.Reply("assign github account2", `{"op":"select_identity","kind":"github","account":"account2"}`)
	w.Reply("save", `{"op":"name_profile","name":"work"}`, `{"op":"save"}`)
	s, out := run(t, w, "assign github account2\ny\nsave\n2\nnone\n")
	if got, want := w.Model.Requests(), []string{"assign github account2", "save"}; !slices.Equal(got, want) {
		t.Errorf("requests the interpreter saw: %q, want %q", got, want)
	}
	if s.Draft().GH == nil || s.Draft().GH.User != "account2" {
		t.Errorf("pinned %+v, want account2", s.Draft().GH)
	}
	contains(t, out, "? #1 which GitHub login should the sandbox act as?", "2. github.com/account2",
		"#1 is answered with the number of one listed GitHub login", "not saved: 1 question(s) are open",
		"pinned GitHub login github.com/account2", "there is no open question to answer")
	if _, err := os.Stat(filepath.Join(w.ProfDir, "work.toml")); err == nil {
		t.Error("saved with an open question")
	}
}

func TestPlainScriptAnswersAndSaves(t *testing.T) {
	w := testworld.New(t)
	w.Reply("needs internet", `{"op":"use_profile","name":"@net"}`)
	w.Reply("assign github account2", `{"op":"select_identity","kind":"github","account":"account2"}`)
	s, out := run(t, w, "needs internet\n/pending\n/accept 1\nassign github account2\n/pick github account2\n/pending\n/save work\n")
	contains(t, out, "> needs internet", "? #1 your request \"needs internet\" widens the sandbox", "pinned GitHub login github.com/account2",
		"nothing is pending.", "checked: snug -p work", "wrote ", "snug accepts it")
	if strings.Contains(out, "The draft was not saved") {
		t.Errorf("%s", out)
	}
	body, err := os.ReadFile(filepath.Join(w.ProfDir, "work.toml"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	contains(t, string(body), `"@net",`, `user = "account2"`, `# intent (you, confirmed): "assign github account2" -> github identity account2`)
	if s.Unsaved() {
		t.Error("Unsaved after the save")
	}
}

// TestPlainAnswerLinesAreStrict: a malformed answer line is refused with its
// usage and never reaches the model.
func TestPlainAnswerLinesAreStrict(t *testing.T) {
	w := testworld.New(t)
	w.Reply("assign github account2", `{"op":"select_identity","kind":"github","account":"account2"}`)
	_, out := run(t, w, "/accept\n/accept x\n/accept 0\n/decline 1 2\n/accept 9\n/pick github\n/pick foo bar\n/pick github account2\n/save a b\n/frobnicate\n"+
		"assign github account2\n/pick github account2 extra\n/pick github Account2\n/accept 1\n/quit\nnever read\n")
	contains(t, out,
		"usage: /accept N, with N the number /pending shows.",
		"usage: /decline N",
		"there is no open question #9",
		"usage: /pick ssh STEM, /pick signing STEM, /pick github LOGIN or /pick git EMAIL",
		"there is no open github question",
		"usage: /save [NAME]",
		`unknown command "/frobnicate"`,
		`"Account2" is not a GitHub login on this host: one of account1, account2, or none`,
		"#1 is answered by naming the identity")
	if got := w.Model.Requests(); !slices.Equal(got, []string{"assign github account2"}) {
		t.Errorf("the model saw %q", got)
	}
	if strings.Contains(out, "never read") {
		t.Error("read past /quit")
	}
}

// TestPlainOutputCarriesNoTerminalControl: the model's text, a key comment
// and a refused path, each with escape sequences, bidi, zero-width and tag
// characters, reach the output stream with none of them.
func TestPlainOutputCarriesNoTerminalControl(t *testing.T) {
	w := testworld.New(t)
	w.Key("id_evil", "evil\x1b]0;pwned\x07\U0000202Ecomment\U0000200B", 9)
	w.RawReply("x", `{"actions":[{"op":"ask","question":"ok\u001b[2J\u202e\u2066\ufeff\udb40\udc41?"},{"op":"drop_path","path":"/srv/a\u001b]0;t\u0007\u200b"},{"op":"list_identities","kind":"ssh"}]}`)
	_, out := run(t, w, "x\n")
	for _, bad := range []string{"\x1b", "\x07", "\U0000202E", "\U00002066", "\U0000FEFF", "\U000E0041", "\U0000200B"} {
		if strings.Contains(out, bad) {
			t.Errorf("output carries %q:\n%q", bad, out)
		}
	}
	contains(t, out, "the model asks:", "id_evil", "refused (no_such_entry)")
}

func TestPlainSlashCommandsBypassTheModel(t *testing.T) {
	w := testworld.New(t)
	w.Reply("needs internet", `{"op":"use_profile","name":"@net"}`)
	s, out := run(t, w, "needs internet\n/accept 1\n/show\n/undo\n/undo\n/help\n")
	if !s.Draft().Empty() {
		t.Error("undo did not restore")
	}
	contains(t, out, `"@net"`, "undone: the answer to #1", "undone: your request", "/pick github LOGIN|none", "/show /save /undo /help /quit")
	if n := len(w.Model.Prompts); n != 1 {
		t.Errorf("%d model calls: slash commands must bypass the model", n)
	}
}

func TestPlainAnalyzeCommandBypassesTheModel(t *testing.T) {
	w := testworld.New(t)
	os.WriteFile(filepath.Join(w.Target, "go.mod"), []byte("module example.org/m\n"), 0o644)
	_, out := run(t, w, "/analyze\n/pending\n")
	contains(t, out, "Go module example.org/m (go.mod)", "? #1 what I found in the project", "/accept 1 applies all of it")
	if n := len(w.Model.Prompts); n != 0 {
		t.Errorf("%d model calls", n)
	}
}

// TestWhyAndKeysSkipTheModel: /why prints what the opening leaves out and
// /keys lists every key, neither asking the model.
func TestWhyAndKeysSkipTheModel(t *testing.T) {
	w := testworld.New(t)
	_, out := run(t, w, "/why\n/keys\n")
	contains(t, out, "Found on this host: 3 ssh public key(s)", "Each request stands alone", "id_account1", "id_other", "FINGERPRINT")
	if len(w.Model.Requests()) != 0 {
		t.Errorf("the model was asked: %v", w.Model.Requests())
	}
}
