package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/testworld"
)

func manyKeys(w *testworld.World) {
	for i := 0; i < 9; i++ {
		w.Key(fmt.Sprintf("spare_%d_ed25519", i), fmt.Sprintf("spare%d@host", i), byte(20+i))
	}
}

// TestIdentityQuestionListsFewKeysAndPointsAtAll: twelve keys do not make a
// twelve-row question; the suggestion is first, a footer says how many are
// left out, and a left-out key can still be picked.
func TestIdentityQuestionListsFewKeysAndPointsAtAll(t *testing.T) {
	w := testworld.New(t)
	manyKeys(w)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	os.WriteFile(filepath.Join(w.Home, ".ssh", "config"), []byte("Host github.com\n  IdentityFile ~/.ssh/id_account2\n"), 0o600)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	s, _ := start(w)
	out := say(s, "use my ssh key")
	rows := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "SHA256:") {
			rows++
		}
	}
	if rows > maxShown {
		t.Errorf("%d key rows listed, cap %d:\n%s", rows, maxShown, out)
	}
	contains(t, out, "and 9 more: /keys lists all 12", "<- suggested")
	lacks(t, out, "[held by the agent]")
	if i, j := strings.Index(out, "<- suggested"), strings.Index(out, "SHA256:"); i < j {
		t.Errorf("the suggestion is not the first row:\n%s", out)
	}
	if got := text(s.Pick(ctx, "ssh", "spare_7_ed25519")); !strings.Contains(got, "pinned ssh key spare_7_ed25519") {
		t.Errorf("a key left out of the list cannot be picked: %s", got)
	}
	table := text(s.ListIdentities("ssh"))
	if n := strings.Count(table, "SHA256:"); n != 12 {
		t.Errorf("/keys lists %d of 12:\n%s", n, table)
	}
}

// TestHintedKeyIsListedWhateverTheCap: "use my spare_5 key" must show spare_5
// even though twelve keys do not fit.
func TestHintedKeyIsListedWhateverTheCap(t *testing.T) {
	w := testworld.New(t)
	manyKeys(w)
	w.Reply("use my spare_5 key", `{"op":"select_identity","kind":"ssh","account":"spare_5_ed25519"}`)
	s, _ := start(w)
	contains(t, say(s, "use my spare_5 key"), "spare_5_ed25519  spare5@host", "more: /keys lists all 12")
}

// TestFewKeysAreAllListed: at the cap's edge nothing is cut and there is no footer.
func TestFewKeysAreAllListed(t *testing.T) {
	w := testworld.New(t)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	s, _ := start(w)
	out := say(s, "use my ssh key")
	contains(t, out, "id_account1", "id_account2", "id_other")
	lacks(t, out, "/keys lists")
}

// TestAdviceAgainIsShortAndSaysWhatIsPinned: asking for a recommendation a
// second time does not print the identity block twice.
func TestAdviceAgainIsShortAndSaysWhatIsPinned(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	s, _ := startRules(w)
	first := say(s, "should not AI reccomend identities?")
	again := say(s, "what identities do you recommend?")
	if first != again {
		t.Errorf("same facts, different answer:\n%s\n--\n%s", first, again)
	}
	if n := strings.Count(first, "\n"); n > 4 {
		t.Errorf("advice is %d lines:\n%s", n, first)
	}
	lacks(t, first, "Last 10 commits", "Remote origin")
	contains(t, first, "/why has the reasons")
	s.askIdentity("git", "", "my git author", 0)
	text(s.Pick(ctx, "git", "two@example.com"))
	contains(t, say(s, "recommend an identity"), "The draft pins git author two@example.com.")
}

// TestRefusedProfilesAreGroupedInTheOpening: two profiles refused for the same
// reason in the same file are one line, not two.
func TestRefusedProfilesAreGroupedInTheOpening(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml+strings.ReplaceAll(strings.ReplaceAll(acctToml, "acct", "acct2"), "account1", "account3"))
	const why = `profile includes "@cwd-rw": renamed`
	w.Refuse = map[string]string{"acct": why, "acct2": why}
	_, opening := start(w)
	if n := strings.Count(opening, "snug refuses your profile"); n != 1 {
		t.Errorf("%d refusal lines:\n%s", n, opening)
	}
	contains(t, opening, "snug refuses your profile acct, acct2 today: profile includes", "does not edit your profiles")
}
