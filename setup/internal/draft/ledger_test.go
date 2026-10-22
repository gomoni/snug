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

func entry(a Action) Entry { return Entry{Origin: "test", Action: a} }

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
	cases := []struct {
		name        string
		prior, next Entry
		want        bool
	}{
		{"use vs drop", entry(drop("@net")), entry(use("@net")), true},
		{"drop vs use", entry(use("@net")), entry(drop("@net")), true},
		{"drop a profile the next one includes", entry(drop("@podman-socket")), entry(use("@podman-build")), true},
		{"drop the includer, use the included", entry(drop("@podman-build")), entry(use("@podman-socket")), false},
		{"different profiles", entry(drop("@net")), entry(use("@claude")), false},
		{"use twice", entry(use("@net")), entry(use("@net")), false},
		{"grant vs drop_path", entry(grant("/srv/a", "rw")), entry(dropPath("/srv/a")), true},
		{"drop_path vs grant", entry(dropPath("/srv/a")), entry(grant("/srv/a", "ro")), true},
		{"same path, two spellings", entry(grant("~/data", "ro")), entry(grant("/home/alice/data", "rw")), true},
		{"widening ro to rw", entry(grant("/srv/a", "ro")), entry(grant("/srv/a", "rw")), true},
		{"narrowing rw to ro", entry(grant("/srv/a", "rw")), entry(grant("/srv/a", "ro")), false},
		{"ro to tmpfs", entry(grant("/srv/a", "ro")), entry(grant("/srv/a", "tmpfs")), true},
		{"tmpfs to rw", entry(grant("/srv/a", "tmpfs")), entry(grant("/srv/a", "rw")), true},
		{"other path", entry(grant("/srv/a", "ro")), entry(grant("/srv/b", "rw")), false},
		{"sub path is layering", entry(grant("/srv/a", "ro")), entry(grant("/srv/a/out", "rw")), false},
		{"read-only target vs @target-rw", entry(grant("{target}", "ro")), entry(use("@target-rw")), true},
		{"@target-rw vs read-only target", entry(use("@target-rw")), entry(grant("here", "ro")), false},
		{"drop @target-rw vs @target-rw", entry(drop("@target-rw")), entry(use("@target-rw")), true},
		{"staged vs drop_path", entry(act(OpStageBinary, "host", "/opt/x/bin/x", "name", "x")), entry(dropPath("/opt/x/bin/x")), true},
		{"env set vs inherit", entry(env("set", "vim")), entry(env("inherit", "")), true},
		{"env set vs other value", entry(env("set", "vim")), entry(env("set", "nano")), true},
		{"env same value", entry(env("set", "vim")), entry(env("set", "vim")), false},
		{"door vs door", entry(act(OpOpenDoor, "name", "web")), entry(act(OpOpenDoor, "name", "web")), false},
	}
	d := New(testHost())
	for _, c := range cases {
		if got := d.Contradicts(c.prior, c.next); got != c.want {
			t.Errorf("%s: Contradicts = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRefusedActionsAreNotRecorded(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpGrantPath, "path", "~/.ssh", "access", "ro"), "x")
	d.Propose(act(OpShow), "x")
	d.Propose(act(OpNameProfile, "name", "work"), "x")
	if l := d.Ledger(); len(l) != 0 {
		t.Errorf("%+v", l)
	}
}

func TestLaterEntryAgainstEarlierIsEffective(t *testing.T) {
	d := New(testHost())
	d.Propose(act(OpDropProfile, "name", "@net"), "first")
	d.Propose(act(OpUseProfile, "name", "@net"), "second")
	eff := d.Effective()
	if len(eff) != 1 || eff[0].Action.Op != OpUseProfile {
		t.Errorf("effective: %+v", eff)
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

// TestOriginCannotWriteTOML feeds the description comment of an included
// profile text that would end the comment, start a table and grant /, and
// forging runes.
func TestOriginCannotWriteTOML(t *testing.T) {
	evil := "x\n[profile.evil]\r\nrw = [\"/\"]\u2028x\u202ey\x1b[2J\x00\xff" + strings.Repeat("a", 200)
	d := New(testHost())
	d.Name = "work"
	d.NoteProfile("acct", evil)
	d.Apply(act(OpIncludeProfile, "name", "acct"))
	out := d.Render()
	tables := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[") {
			tables++
		}
		if !utf8.ValidString(l) {
			t.Errorf("invalid UTF-8: %q", l)
		}
		for _, c := range l {
			if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == 0x2028 || c == 0x2029 {
				t.Errorf("control or forging rune %U in %q", c, l)
			}
		}
	}
	if tables != 1 {
		t.Errorf("a second table appeared:\n%s", out)
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

func TestRenderHasOneHeaderLine(t *testing.T) {
	d := New(testHost())
	d.Name = "work"
	d.Propose(act(OpUseProfile, "name", "@net"), "go mod download")
	head, _, ok := strings.Cut(d.Render(), "[profile.work]")
	if !ok || strings.Count(head, "\n") != 1 || !strings.HasPrefix(head, "# Generated by snug-setup") {
		t.Errorf("header is not one Generated line:\n%s", head)
	}
}
