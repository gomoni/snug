package draft

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func user(text string, a Action) Entry {
	return Entry{Source: SourceUser, Origin: text, Action: a}
}

func file(a Action) Entry { return Entry{Source: SourceFile, Origin: "README.md", Action: a} }

func picked(kind string, names ...string) Entry {
	return Entry{Source: SourceUser, Confirmed: true, Names: names, Action: Action{Op: OpSelectIdentity, Kind: kind, Account: names[0]}}
}

func TestContradicts(t *testing.T) {
	use := func(n string) Action { return act(OpUseProfile, "name", n) }
	drop := func(n string) Action { return act(OpDropProfile, "name", n) }
	grant := func(p, a string) Action { return act(OpGrantPath, "path", p, "access", a) }
	dropPath := func(p string) Action { return act(OpDropPath, "path", p) }
	env := func(verb, v string) Action {
		a := act(OpSetEnv, "name", "EDITOR", "verb", verb)
		if verb != "inherit" {
			a.Value, a.HasValue = v, true
		}
		return a
	}
	ident := func(kind, acct string) Action {
		return act(OpSelectIdentity, "kind", kind, "account", acct)
	}
	cases := []struct {
		name        string
		prior, next Entry
		want        bool
	}{
		{"use vs drop", user("x", drop("@net")), file(use("@net")), true},
		{"drop vs use", user("x", use("@net")), file(drop("@net")), true},
		{"drop a profile the next one includes", user("x", drop("@podman-socket")), file(use("@podman-build")), true},
		{"drop the includer, use the included", user("x", drop("@podman-build")), file(use("@podman-socket")), false},
		{"different profiles", user("x", drop("@net")), file(use("@git")), false},
		{"use twice", user("x", use("@net")), file(use("@net")), false},
		{"grant vs drop_path", user("x", grant("/srv/a", "rw")), file(dropPath("/srv/a")), true},
		{"drop_path vs grant", user("x", dropPath("/srv/a")), file(grant("/srv/a", "ro")), true},
		{"same path, two spellings", user("x", grant("~/data", "ro")), file(grant("/home/alice/data", "rw")), true},
		{"widening ro to rw", user("x", grant("/srv/a", "ro")), file(grant("/srv/a", "rw")), true},
		{"narrowing rw to ro", user("x", grant("/srv/a", "rw")), file(grant("/srv/a", "ro")), false},
		{"ro to tmpfs", user("x", grant("/srv/a", "ro")), file(grant("/srv/a", "tmpfs")), true},
		{"tmpfs to rw", user("x", grant("/srv/a", "tmpfs")), file(grant("/srv/a", "rw")), true},
		{"other path", user("x", grant("/srv/a", "ro")), file(grant("/srv/b", "rw")), false},
		{"sub path is layering", user("x", grant("/srv/a", "ro")), file(grant("/srv/a/out", "rw")), false},
		{"read-only target vs @target-rw", user("x", grant("{target}", "ro")), file(use("@target-rw")), true},
		{"@target-rw vs read-only target", user("x", use("@target-rw")), file(grant("here", "ro")), false},
		{"drop @target-rw vs @target-rw", user("x", drop("@target-rw")), file(use("@target-rw")), true},
		{"staged vs drop_path", user("x", act(OpStageBinary, "host", "/opt/x/bin/x", "name", "x")), file(dropPath("/opt/x/bin/x")), true},
		{"env set vs inherit", user("x", env("set", "vim")), file(env("inherit", "")), true},
		{"env set vs other value", user("x", env("set", "vim")), file(env("set", "nano")), true},
		{"env same value", user("x", env("set", "vim")), file(env("set", "vim")), false},
		{"identity, another account", picked("github", "account2", "github.com/account2"), file(ident("github", "account1")), true},
		{"identity, same account other spelling", picked("github", "account2", "github.com/account2"), file(ident("github", "GITHUB.COM/account2")), false},
		{"identity, no account named", picked("github", "account2"), file(ident("github", "")), false},
		{"identity, other kind", picked("github", "account2"), file(ident("ssh", "id_other")), false},
		{"identity, two picks", picked("ssh", "id_a"), picked("ssh", "id_b"), true},
		{"identity, unpicked prior", user("x", ident("github", "account2")), file(ident("github", "account1")), false},
		{"door vs door", user("x", act(OpOpenDoor, "name", "web")), file(act(OpOpenDoor, "name", "web")), false},
	}
	d := New(testHost())
	for _, c := range cases {
		if got := d.Contradicts(c.prior, c.next); got != c.want {
			t.Errorf("%s: Contradicts = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFileConflictIsAQuestionNotAnEdit(t *testing.T) {
	for _, accept := range []bool{false, true} {
		d := New(testHost())
		d.Propose(act(OpDropProfile, "name", "@net"), SourceUser, "keep it offline", 1)
		o, p := d.Propose(act(OpUseProfile, "name", "@net"), SourceFile, "README.md", 2)
		if p == nil {
			t.Fatalf("no question: %+v", o)
		}
		if slices.Contains(d.Include, "@net") {
			t.Fatal("applied before the human answered")
		}
		want := `README.md asks for @net, but you said "keep it offline" (drop @net) — add it?`
		if p.Question != want {
			t.Errorf("question\n got %s\nwant %s", p.Question, want)
		}
		d.Decide(*p, accept)
		if slices.Contains(d.Include, "@net") != accept {
			t.Errorf("accept=%v: include %v", accept, d.Include)
		}
		lines := strings.Join(d.IntentLines(), "\n")
		if accept {
			if !strings.Contains(lines, `# intent (README.md, accepted over "keep it offline"): -> @net`) {
				t.Error(lines)
			}
			// The accepted file action now carries the human's authority.
			if _, p := d.Propose(act(OpDropProfile, "name", "@net"), SourceFile, "compose.yml", 3); p == nil {
				t.Error("a file undid what the human accepted without asking")
			}
		} else if !strings.Contains(lines, `# intent (README.md, declined): @net — conflicts with "keep it offline"`) {
			t.Error(lines)
		}
	}
}

func TestNewestUserEntryWins(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpDropProfile, "name", "@net"), SourceUser, "keep it offline", 1)
	d.Propose(act(OpUseProfile, "name", "@net"), SourceUser, "actually it needs internet", 2)
	if !slices.Contains(d.Include, "@net") {
		t.Fatal("a user's later request was not applied")
	}
	if _, p := d.Propose(act(OpUseProfile, "name", "@net"), SourceFile, "README.md", 3); p != nil {
		t.Errorf("asked about what the human's newest request already says: %s", p.Question)
	}
	if _, p := d.Propose(act(OpDropProfile, "name", "@net"), SourceFile, "README.md", 3); p == nil {
		t.Error("a file dropped what the human's newest request asked for")
	}
	lines := d.IntentLines()
	if len(lines) != 3 || !strings.Contains(lines[0], "drop @net") || !strings.Contains(lines[1], "-> @net") {
		t.Errorf("the ledger must show both requests:\n%s", strings.Join(lines, "\n"))
	}
	eff := d.Effective()
	if len(eff) != 2 || eff[0].Action.Op != OpUseProfile || eff[0].Source != SourceUser {
		t.Errorf("effective: %+v", eff)
	}
}

func TestUserSourceIsNeverAsked(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpGrantPath, "path", "{target}", "access", "ro"), SourceUser, "read-only here", 1)
	if _, p := d.Propose(act(OpUseProfile, "name", "@target-rw"), SourceUser, "give me write access here", 2); p != nil {
		t.Fatal("the human was asked to confirm their own request")
	}
	if d.ReadOnlyTarget {
		t.Error("the later request did not win")
	}
}

func TestRefusedActionsAreNotRecorded(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpGrantPath, "path", "~/.ssh", "access", "ro"), SourceUser, "give it my ssh", 1)
	d.Propose(act(OpShow), SourceUser, "show", 2)
	d.Propose(act(OpNameProfile, "name", "work"), SourceUser, "call it work", 3)
	if l := d.Ledger(); len(l) != 0 {
		t.Errorf("%+v", l)
	}
}

func TestTargetRWIsAlreadyADefault(t *testing.T) {
	d := New(testHost())
	o := d.Apply(act(OpUseProfile, "name", "@target-rw"))
	if !o.Default || o.Changed || o.Msg != "" || !d.Empty() || strings.Contains(d.Render(), `"@target-rw"`) {
		t.Errorf("%+v\n%s", o, d.Render())
	}
	d.Apply(act(OpGrantPath, "path", "{target}", "access", "ro"))
	o = d.Apply(act(OpUseProfile, "name", "@target-rw"))
	if !o.Changed || d.ReadOnlyTarget || slices.Contains(d.Include, "@target-rw") || !d.Empty() {
		t.Errorf("%+v %+v", o, d)
	}
}

// TestLedgerDropsEveryFormatCharacter: a zero-width space, U+FEFF and the tag
// characters are Cf too, and are invisible in the profile a human reads.
func TestLedgerDropsEveryFormatCharacter(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpUseProfile, "name", "@git"), SourceUser, "use\u200bgit\ufeff \U000E0041\U000E0001now\u2066", 1)
	l := d.IntentLines()[0]
	for _, c := range l {
		if unicode.Is(unicode.Cf, c) {
			t.Errorf("format character %U in %q", c, l)
		}
	}
	if !strings.Contains(l, `"use git now"`) {
		t.Errorf("%q", l)
	}
}

// TestRequestTextCannotWriteTOML feeds the ledger request text that would end
// the comment, start a table and grant /, and forging runes.
func TestRequestTextCannotWriteTOML(t *testing.T) {
	evil := "keep it offline\n[profile.evil]\r\nrw = [\"/\"]\u2028x\u202ey\x1b[2J\x00\xff" + strings.Repeat("a", 200)
	d := New(testHost())
	d.Name = "work"
	d.Propose(act(OpDropProfile, "name", "@net"), SourceUser, evil, 1)
	d.Propose(act(OpUseProfile, "name", "@git"), SourceFile, "READ\nME\u202e.md", 2)
	out := d.Render()
	head, _, ok := strings.Cut(out, "[profile.work]")
	if !ok {
		t.Fatal(out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(head, "\n"), "\n") {
		if !strings.HasPrefix(l, "# ") {
			t.Errorf("header line is not a comment: %q", l)
		}
		if !utf8.ValidString(l) {
			t.Errorf("invalid UTF-8: %q", l)
		}
		for _, c := range l {
			if unicode.IsControl(c) || (c >= 0x2028 && c <= 0x202e) {
				t.Errorf("control or forging rune %U in %q", c, l)
			}
		}
	}
	tables := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[") {
			tables++
		}
	}
	if tables != 1 {
		t.Errorf("a second table appeared:\n%s", out)
	}
	line := d.IntentLines()[0]
	quoted := line[strings.Index(line, `"`)+1 : strings.LastIndex(line, `"`)]
	if n := utf8.RuneCountInString(quoted); n > commentMax {
		t.Errorf("request text is %d runes: %q", n, quoted)
	}
	if strings.Count(line, `"`) != 2 {
		t.Errorf("a quote in the request survived: %q", line)
	}
}

// TestBuiltinIncludesMatchBaseToml holds BuiltinIncludes equal to the include
// lines of base.toml, which writes them without the @.
func TestBuiltinIncludesMatchBaseToml(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}
	table := regexp.MustCompile(`^\[profile\.([a-z-]+)\]$`)
	include := regexp.MustCompile(`^include = \[(.*)\]$`)
	got := map[string][]string{}
	cur := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if m := table.FindStringSubmatch(l); m != nil {
			cur = "@" + m[1]
			got[cur] = nil
		} else if m := include.FindStringSubmatch(l); m != nil && cur != "" {
			for _, n := range strings.Split(m[1], ",") {
				got[cur] = append(got[cur], "@"+strings.Trim(strings.TrimSpace(n), `"`))
			}
		}
	}
	if len(got) != len(BuiltinIncludes) {
		t.Errorf("base.toml has %d profiles, BuiltinIncludes %d: %v", len(got), len(BuiltinIncludes), got)
	}
	for n, inc := range got {
		if want, ok := BuiltinIncludes[n]; !ok || !slices.Equal(want, inc) {
			t.Errorf("%s: base.toml includes %v, BuiltinIncludes says %v", n, inc, want)
		}
	}
}
