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
	w.Reply("I already have a profile called acct, just reuse it", includeAcct)
	s, opening := start(w)
	contains(t, opening, "Your snug profiles: acct.", "Your profile \"acct\"", "pins GitHub login github.com/account1, ssh key id_account1, signing key id_other, git author Account One <one@example.com>")
	lacks(t, opening, "refuses it")
	out := say(s, "I already have a profile called acct, just reuse it")
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
	contains(t, opening, `snug refuses it today: profile "acct" includes "@cwd-rw", which is now "@target-rw"`, "does not edit your profiles")
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
