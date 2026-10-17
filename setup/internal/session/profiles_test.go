package session

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/testworld"
)

const acctToml = `[profile.acct]
description = "GitHub account A: its ssh key, its gh token, its git author."
include = ["@sys", "@home", "@cwd-rw", "@net"]
  [profile.acct.identity.ssh]
  host = "github.com"
  key = "{home}/.ssh/id_account1.pub"
  [profile.acct.identity.git]
  name = "Account One"
  email = "one@example.com"
  signing_key = "{home}/.ssh/id_other.pub"
  [profile.acct.identity.gh]
  user = "account1"
`

const includeAcct = `{"op":"include_profile","name":"acct"}`

func TestIncludeProfileIsACardNamingWhatItPins(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	w.Reply("bring in acct please", includeAcct)
	s, opening := start(w)
	contains(t, text(s.Details(ctx)), "Your snug profiles: acct.")
	lacks(t, opening, "refuses")
	out := say(s, "bring in acct please")
	contains(t, out, "include your profile acct (GitHub account A", "cost: your profile acct includes @sys, @home, @cwd-rw, @net; pins GitHub login")
	if !s.Draft().Empty() {
		t.Fatalf("applied before the answer: %s", s.Draft().Render())
	}
	text(s.Accept(ctx, 1))
	if !slices.Equal(s.Draft().Include, []string{"acct"}) {
		t.Errorf("include %v", s.Draft().Include)
	}
	contains(t, s.Draft().Render(), "# acct: GitHub account A: its ssh key, its gh token, its git author.", `"acct",`, "# intent (you):")
	if got := w.Model.Prompts[0]; !strings.Contains(got, "\nhost profiles: acct\n") {
		t.Errorf("the prompt does not show the profile names:\n%s", got)
	}
}

// TestIncludeProfileThatSnugRefusesNamesTheFix: a profile that still says
// @cwd-rw (renamed @target-rw) is not offered, and snug's own message is the
// fix. The opening says so too, before the human tries it.
func TestIncludeProfileThatSnugRefusesNamesTheFix(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	w.Refuse = map[string]string{"acct": `profile "acct" includes "@cwd-rw", which is now "@target-rw"`}
	w.Reply("reuse acct", includeAcct)
	s, opening := start(w)
	contains(t, opening, `snug refuses your profile acct today: profile "acct" includes "@cwd-rw", which is now "@target-rw"`, "does not edit your profiles")
	out := say(s, "reuse acct")
	contains(t, out, "is there, but snug refuses it today", `which is now "@target-rw"`, "snug-setup does not edit your profiles", "accounts.toml")
	lacks(t, out, "? #")
	if !s.Draft().Empty() || len(s.Pending()) != 0 {
		t.Errorf("a refused profile reached the draft or a card")
	}
}

func TestIncludeProfileNotOneOfYours(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	w.Reply("use work", `{"op":"include_profile","name":"work"}`)
	s, _ := start(w)
	out := say(s, "use work")
	contains(t, out, `you have no snug profile called "work"`, "Yours: acct.")
	if len(s.Pending()) != 0 {
		t.Errorf("pending %v", numbers(s))
	}
}

// TestIncludedProfilePinsTheIdentity: once acct is in the draft, "use my
// github" says acct already pins one instead of opening a question that would
// end in two pins snug refuses.
func TestIncludedProfilePinsTheIdentity(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	s, _ := start(w)
	text(s.IncludeProfile(ctx, "acct"))
	text(s.Accept(ctx, 1))
	w.Reply("use my github", assignGH1)
	out := say(s, "use my github")
	contains(t, out, `your profile "acct", which the draft includes, already pins`, "another account needs a second profile")
	lacks(t, out, "? #")
}

func TestSlashIncludeSavesWithAnIncludedProfile(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	s, _ := start(w)
	contains(t, text(s.IncludeProfile(ctx, "acct")), "? #1 your request \"/include acct\" widens the sandbox")
	text(s.Accept(ctx, 1))
	ok, out := s.Save(ctx, "mine")
	if !ok {
		t.Fatalf("not saved:\n%s", text(out))
	}
}

// TestProfileNameCannotBeAnythingButAName: include_profile is looked up in the
// human's profiles, so a name from the model that is not one never reaches the
// draft, whatever it looks like.
func TestProfileNameCannotBeAnythingButAName(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	s, _ := start(w)
	for _, n := range []string{"@net", "../x", "acct\nrequest: x", "ACCT", "acc"} {
		out := text(s.IncludeProfile(ctx, n))
		lacks(t, out, "? #")
		if !s.Draft().Empty() {
			t.Fatalf("%q reached the draft: %s", n, s.Draft().Render())
		}
	}
}

// TestProfileRequestInWordsReachesTheCard: "reuse my acct profile" reaches
// the same card /include does, by looking the exact name up among the
// human's profiles; a near name includes nothing.
func TestProfileRequestInWordsReachesTheCard(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	s, _ := startRules(w)
	out := say(s, "I already have a profile called acct, just reuse it")
	contains(t, out, "? #1", "include your profile acct")
	s2, _ := startRules(w)
	out = say2(t, w, s2, "what is in my accts profile")
	lacks(t, out, "include your profile")
}

func say2(t *testing.T, w *testworld.World, s *Session, request string) string {
	t.Helper()
	return say(s, request)
}

// TestLongSnugMessageIsCutAtASentence: snug's refusal is shortened after a
// whole sentence, never in the middle of one.
func TestLongSnugMessageIsCutAtASentence(t *testing.T) {
	w := testworld.New(t)
	w.Profile("accounts.toml", acctToml)
	first := "profile includes \"@cwd-rw\": renamed to @target-rw. " + strings.Repeat("The grant was always the target directory. ", 4)
	w.Refuse = map[string]string{"acct": first + "Rewrite the selection as the new name and run again please"}
	s, _ := startRules(w)
	out := text(s.IncludeProfile(ctx, "acct"))
	lacks(t, out, "Rewrite the selection")
	contains(t, out, "directory. (`snug -p acct DIR` prints the rest)")
}

// TestIdenticalCostIsSaidOnce: two items with the same cost on one card
// print it once; the second points at the first.
func TestIdenticalCostIsSaidOnce(t *testing.T) {
	w := testworld.New(t)
	s := open(w, true)
	t1 := s.classify(ctx, 1, "x", nil)
	t1.Items = []Item{{Sentence: "a", Abuse: "same cost", Class: ClassGrant}, {Sentence: "b", Abuse: "same cost", Class: ClassGrant}}
	p := s.open(Pending{Kind: Card, turn: t1, held: []int{0, 1}, said: "x"})
	got := p.Line().Text
	if strings.Count(got, "same cost") != 1 || !strings.Contains(got, "cost: as 1.") {
		t.Errorf("%s", got)
	}
}

// TestPathGrantCardsStateTheirCost fails if a read-only or writable path
// grant is offered without a cost line, or if two of one access repeat it.
// The two cards use different words, so a rw cost cannot stand in for a ro one.
func TestPathGrantCardsStateTheirCost(t *testing.T) {
	w := testworld.New(t)
	s := openRules(w)
	out := say(s, "write to ~/Documents and ~/Notes")
	contains(t, out, "writable: "+w.Home+"/Documents (persists)", "cost: the sandbox can read, change and delete everything under this path")
	if n := strings.Count(out, "change and delete"); n != 1 {
		t.Errorf("rw cost said %d times, want once:\n%s", n, out)
	}
	out = say(s, "read-only ~/Downloads")
	contains(t, out, "read-only: "+w.Home+"/Downloads", "cost: the sandbox can read everything under this path")
	lacks(t, out, "change and delete")
}
