package profile

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// Strict decoding is a security control, not a style choice. If a key snug does
// not understand were silently ignored, a profile could carry a `mask` or `deny`
// written for some other tool and the human would believe the sandbox is
// tighter than it is.
func TestUnknownKeysAreFatal(t *testing.T) {
	for _, key := range []string{"mask", "deny", "hide", "exclude", "allowlist_root"} {
		src := "[profile.x]\n" + key + " = [\"/etc\"]\n"
		if _, err := parse([]byte(src), "test.toml", true); err == nil {
			t.Errorf("key %q was accepted; the grant language must not silently absorb unknown keys", key)
		}
	}
}

// `publish_auto` was a shipped key that could never work: pasta's
// `-t 127.0.0.1/auto` scans the namespace for bound ports once, at ITS startup,
// which is before the payload exists. Measured refused at 3, 10, 20 and 30
// seconds after a listener came up inside, while --dry-run claimed "EVERY port
// the sandbox binds" — invariant 5, in the artifact a human trusts most.
//
// It is gone, and strict decoding is what makes that safe: anyone carrying it in
// their own profiles.d gets a fatal parse error naming the key, not a profile
// that silently does nothing. That is the whole reason DisallowUnknownFields is
// load-bearing, applied to snug's own retired key.
func TestRetiredPublishAutoIsAHardError(t *testing.T) {
	_, err := parse([]byte("[profile.x]\ninclude = [\"@net\"]\npublish_auto = true\n"),
		"/home/u/.config/snug/profiles.d/mine.toml", true)
	if err == nil {
		t.Fatal("publish_auto was accepted; a key that does nothing must not parse quietly")
	}
	if !strings.Contains(err.Error(), "publish_auto") {
		t.Errorf("the error must name the key so the fix is obvious: %v", err)
	}

	// CONTROL: naming the ports, which does work, still parses.
	if _, err := parse([]byte("[profile.x]\ninclude = [\"@net\"]\npublish = [3000]\n"),
		"mine.toml", true); err != nil {
		t.Fatalf("publish = [...] must still work, or the refusal above is a ban on "+
			"publishing rather than on the broken form: %v", err)
	}
}

// TestNoNullProfileShips pins the @null retirement's headline claim on its own, separate from
// TestBuiltinsLoad's broader sweep: @null must be absent from the builtin
// registry. The positive control matters — without it, a registry that failed
// to embed anything at all (a broken go:embed, say) would pass this trivially,
// the exact shape CLAUDE.md's pasta.avx2 lesson warns about: a check that
// cannot fail is worse than no check.
func TestNoNullProfileShips(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// CONTROL: if @sys is missing too, the registry did not load and the
	// assertion below is vacuous.
	if _, ok := reg["@sys"]; !ok {
		t.Fatal("@sys is missing; the registry failed to load, so the absence of @null below proves nothing")
	}
	if _, ok := reg["@null"]; ok {
		t.Error("@null ships as a builtin; a profile that grants nothing is a preference " +
			"(profile.BuiltinDefaults / --no-defaults), not a grant")
	}
}

func TestKnownKeysParse(t *testing.T) {
	src := `
[profile.x]
description = "d"
include = ["y"]
ro = ["/usr"]
rw = ["{target}"]
tmpfs = ["{home}"]
optional = ["/opt"]
symlink = [{ at = "/bin", target = "usr/bin" }]

[profile.x.environ.inherit]
EDITOR = true
`
	reg, err := parse([]byte(src), "test.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	p := reg["x"]
	if p == nil {
		t.Fatal("profile x missing")
	}
	if len(p.Symlink) != 1 || p.Symlink[0].At != "/bin" || p.Symlink[0].Target != "usr/bin" {
		t.Errorf("symlink parsed as %+v", p.Symlink)
	}
	if p.Description != "d" || len(p.RO) != 1 || len(p.Environ.Inherit) != 1 {
		t.Errorf("unexpected profile: %+v", p)
	}
}

// A later layer may add names but never redefine one. Shadowing a builtin would
// let a config file quietly change what `sys` grants.
func TestRedefinitionIsRejected(t *testing.T) {
	a, err := parse([]byte("[profile.sys]\nro = [\"/usr\"]\n"), "builtin:base.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parse([]byte("[profile.sys]\nro = [\"/\"]\n"), "/home/u/.config/snug/profiles.d/evil.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	err = a.merge(b)
	if err == nil {
		t.Fatal("redefining a builtin profile was allowed")
	}
	if !strings.Contains(err.Error(), "redefines") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// The builtin set must load, and must not contain a profile that grants the
// whole filesystem — the shipped defaults are the ones nobody reviews.
func TestBuiltinsLoad(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro"} {
		if _, ok := reg[want]; !ok {
			t.Errorf("builtin profile %q is missing", want)
		}
	}
	// There is deliberately no profile called `default`, and no profile
	// called `null` either — for the same reason: a default SELECTION is a
	// preference (profile.BuiltinDefaults), and the lattice floor is what
	// Resolve computes from an empty selection, not a grant either name would
	// have to be. Both kept appearing in SNUG_PROFILES and in every Mount's
	// provenance as though granting something were the point.
	if _, ok := reg["@default"]; ok {
		t.Error("a builtin profile named `@default` is back; the default SELECTION is a " +
			"preference (profile.BuiltinDefaults), not a profile")
	}
	if _, ok := reg["@null"]; ok {
		t.Error("a builtin profile named `@null` is back; the lattice floor is what Resolve " +
			"computes from an empty selection (--no-defaults), not a profile that has to name it")
	}
	for name, p := range reg {
		for _, g := range append(append([]string{}, p.RO...), p.RW...) {
			if g == "/" {
				t.Errorf("builtin profile %q grants /", name)
			}
		}
	}
}

// TestPodmanSocketDoesNotIncludeNet is the inverse of the deleted
// TestPodmanSocketIncludesNetAsAnInterimHonestyFix — that test's own failure
// message said deleting it was part of the milestone (issue #63, Tier B): the
// engine now runs in the SANDBOX's own network namespace, so `@podman-socket`
// no longer needs to include `@net` to tell the truth about egress.
// `@podman-socket` alone must resolve OFFLINE; the behavioural half of this
// claim (a container really has no egress) is
// TestPodmanSocketDoesNotImplyEgress in internal/cli, which resolves the real
// builtins through policy.Resolve rather than just inspecting the Include
// list.
func TestPodmanSocketDoesNotIncludeNet(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg["@podman-socket"]
	if !ok {
		t.Fatal("@podman-socket is missing")
	}
	for _, inc := range p.Include {
		if inc == "@net" {
			t.Errorf("@podman-socket still includes @net (includes: %v) — the engine now runs "+
				"in the sandbox's own netns (issue #63, Tier B), so offline must once again be "+
				"the ABSENCE of a profile rather than something @podman-socket switches back on",
				p.Include)
		}
	}
}

// No builtin sanitises, and the reason is that `sanitise` ADDS.
//
// It is easy to read the verb as hygiene — "clean the unwanted references out of
// PATH" — and in this codebase that reading is backwards. snug's floor is an
// empty environment (`cmd.Env = []string{}` plus bwrap's `--clearenv`), so
// nothing of the host's is inside to be cleaned. `sanitise` is the LIST
// counterpart of `inherit`: it copies the host's value and keeps the elements
// some grant covers. Its band sits alongside merge's in applyEnvClaims, which is
// the same statement in the resolver. A builtin that sanitised would therefore
// make every sandbox carry host-derived entries it does not carry today, on
// behalf of a human who never asked.
//
// So the bound is: the host's environment enters only where a human on this host
// wrote a profile saying so. What snug ships instead is the KNOWLEDGE, in two
// tables that are both stronger than a profile could be —
//
//   - policy.EnvNote's tables: the names whose value is code (ld.so(8)'s
//     secure-execution list, GIT_SSH, BASH_FUNC_*, RUBYOPT, …). They are
//     ANNOTATED rather than refused since the second pass over issue #44 — a
//     profile's author is a human on the trusted side of the boundary — so what
//     snug ships here is the SENTENCE, on --dry-run and on `snug profile show`.
//     Read alongside the roster rule, which is what stops a profile snug SHIPS
//     from writing one: none of those names has a roster row;
//   - envTypes' `sanitisable` column: which lists may be filtered at all. PATH,
//     GOPATH, CLASSPATH and friends yes; MANPATH illegal, because removing an
//     element there can ADD directories; PYTHONPATH and CDPATH no, because an
//     empty element is the current directory, which inside snug is the target.
//
// Adding a builtin that sanitises is a decision to hand every user host state by
// default, and this test is where that decision has to be made out loud.
func TestNoBuiltinSanitises(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]policy.ProfileName, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if got := reg[name].Environ.Sanitise; len(got) > 0 {
			t.Errorf("builtin profile %q sanitises %v.\n"+
				"`sanitise` imports the HOST's value for those variables, filtered by what "+
				"policy grants — it does not strip anything, because an unselected variable "+
				"was never there. A builtin doing it gives every sandbox host-derived entries "+
				"by default.\n"+
				"If that is genuinely intended, it belongs in an opt-in profile that is never "+
				"in `defaults`, with its own abuse sentence, and this test should be narrowed "+
				"to name it rather than deleted.", name, got)
		}
	}
}

// The built-in `defaults` are the selection a bare `snug <dir>` uses, so every
// name in them must resolve to a real builtin. A typo here is not a compile
// error and would surface as `unknown profile` on the user's first ever run.
func TestBuiltinDefaultsNameRealProfiles(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	names := BuiltinDefaults()
	if len(names) == 0 {
		t.Fatal("the built-in defaults are empty: a bare `snug <dir>` would grant nothing")
	}
	for _, n := range names {
		if _, ok := reg[n]; !ok {
			t.Errorf("built-in default %q is not a builtin profile", n)
		}
	}
	// A default that opens a network hole would contradict the guiding
	// principle, and offline-is-the-absence-of-a-profile is a property worth
	// keeping: it cannot then be switched back on by accident.
	for _, n := range names {
		if strings.HasPrefix(string(n), policy.Sigil+"net") {
			t.Errorf("built-in default %q opens the network; offline must stay the default", n)
		}
	}
}

// Load must never pick up config from beside the target: a hostile repository
// shipping its own profile would be granting itself permissions.
func TestLoadIgnoresRepoLocalConfig(t *testing.T) {
	dirs := ConfigDirs()
	for _, d := range dirs {
		if !strings.HasPrefix(d, "/etc/") && !strings.Contains(d, "/.config/") {
			t.Errorf("config dir %q is neither a system nor a user location; "+
				"repo-local config must never be auto-loaded", d)
		}
	}
}

// Redefinition is a HARD failure, and "hard" means every entry point — not just
// the ones that obviously need profiles.
//
// `snug config` and `snug doctor` are precisely what someone runs when snug will
// not start, and both used to report a tidy, healthy configuration while the
// profile set was unloadable. A diagnostic that gives a clean bill of health for
// a broken configuration is worse than no diagnostic.
//
// This is now about the layers a HUMAN controls — /etc/snug/profiles.d against
// their own ~/.config — because a user file can no longer collide with a builtin
// at all: see TestUserProfileCannotClaimTheSigil.
func TestRedefinitionIsRejectedRegardlessOfLayer(t *testing.T) {
	for _, name := range []string{"work", "build", "ci"} {
		t.Run(name, func(t *testing.T) {
			reg, err := Builtins()
			if err != nil {
				t.Fatal(err)
			}
			sys, err := parse([]byte("[profile."+name+"]\nro = [\"/usr\"]\n"),
				"/etc/snug/profiles.d/site.toml", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := reg.merge(sys); err != nil {
				t.Fatal(err)
			}
			user, err := parse([]byte("[profile."+name+"]\nro = [\"/\"]\n"),
				"/home/u/.config/snug/profiles.d/mine.toml", true)
			if err != nil {
				t.Fatal(err)
			}
			err = reg.merge(user)
			if err == nil {
				t.Fatalf("a user file redefining %q from a lower layer was accepted", name)
			}
			// The message must name BOTH files: the user knows what they wrote,
			// not what it collided with.
			for _, want := range []string{name, "mine.toml", "site.toml"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// ── the sigil ────────────────────────────────────────────────────────────────

// Every builtin wears the mark. This is the half of the invariant that says the
// namespace is not partially adopted: a profile shipped without one would be
// indistinguishable, in --dry-run and in SNUG_PROFILES, from a file someone
// wrote on this host.
func TestEveryBuiltinCarriesTheSigil(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if len(reg) == 0 {
		t.Fatal("no builtins loaded, so this test cannot fail — the embed is broken")
	}
	for name, p := range reg {
		if _, marked := name.CutMark(); !marked {
			t.Errorf("builtin %q does not carry %q", name, policy.Sigil)
		}
		if p.Name != name {
			t.Errorf("builtin registered as %q but names itself %q; provenance would lie", name, p.Name)
		}
		// An include is rewritten with the rest, or a builtin resolves against
		// whatever the user happens to have called `sys`.
		for _, inc := range p.Include {
			if _, marked := inc.CutMark(); !marked {
				t.Errorf("builtin %q includes %q, which is not a builtin name", name, inc)
			}
			if _, ok := reg[inc]; !ok {
				t.Errorf("builtin %q includes %q, which no builtin defines", name, inc)
			}
		}
	}
}

// And the other half: nobody else may wear it. The two together are what make
// "@ means snug shipped this" a fact rather than a convention — including for
// the builtin TOML itself, which writes bare names and is marked on load.
func TestUserProfileCannotClaimTheSigil(t *testing.T) {
	for _, name := range []string{"@sys", "@mine", "@"} {
		src := "[profile.\"" + name + "\"]\nro = [\"/\"]\n"
		_, err := parse([]byte(src), "/home/u/.config/snug/profiles.d/evil.toml", true)
		if err == nil {
			t.Errorf("a profile named %q was accepted; it would be indistinguishable "+
				"from one snug ships", name)
			continue
		}
		// The error has to say what to do about it, not just refuse.
		if !strings.Contains(err.Error(), "snug ships") {
			t.Errorf("unhelpful error for %q: %v", name, err)
		}
	}
}

// The sigil is what stops a user file from redefining a builtin — so a file
// defining `sys` must now LOAD, as a profile of the author's own, rather than
// collide. If this ever starts failing, the two namespaces have grown back
// together and the merge check is doing load-bearing work again.
func TestUserProfileMayReuseABuiltinsBareName(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg["@sys"]; !ok {
		t.Fatal("@sys is missing, so this test proves nothing")
	}
	user, err := parse([]byte("[profile.sys]\nro = [\"/usr\"]\n"),
		"/home/u/.config/snug/profiles.d/mine.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.merge(user); err != nil {
		t.Fatalf("a user profile named `sys` collided with the builtin `@sys`: %v", err)
	}
	if reg["@sys"].Source == reg["sys"].Source {
		t.Error("`sys` and `@sys` resolved to the same profile")
	}
	if len(reg["@sys"].RO) < 2 {
		t.Error("the builtin @sys lost its grants; the user file overwrote it after all")
	}
}

// No shipped profile may pass a long-lived credential through the environment.
//
// This is a regression test for a real one: `@claude` carried
// ANTHROPIC_API_KEY, so selecting the profile put an org key into
// /proc/self/environ — passively readable by every process in the sandbox and
// inherited by every child — and Claude Code PREFERS the key over the OAuth
// token when both are present, so the sandbox used the more dangerous of the
// two credentials it had.
//
// The check is by NAME rather than by value, deliberately: an `env` entry is a
// name and the value only exists on the invoking host, so a value-based check
// would pass on any machine where the variable happened to be unset. That is
// the same defect the old conditional forbidden-name guard had (see
// .claude/design/BRAINSTORM.md §4.4) and it is worth not repeating here.
//
// Matching is substring-based on purpose, so a NEW credential variable nobody
// has thought of yet — FOO_API_KEY, BAR_TOKEN — is caught the day it is added
// rather than the day someone reads the profile. If a legitimate name trips
// this, name it in the allowlist below with a comment saying why it is not a
// secret; do not soften the match.
func TestNoBuiltinPassesASecretThroughTheEnvironment(t *testing.T) {
	markers := []string{"API_KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL"}
	// Names that contain a marker and are demonstrably not credentials.
	allowed := map[string]bool{}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range reg {
		// EVERY verb, not just inherit. A `set` carries a literal value from
		// the file, which is a worse place for a credential than a name the
		// host supplies — so the sweep has to cover the names a profile writes
		// as well as the ones it re-admits.
		for _, e := range environNames(p.Environ) {
			if allowed[e] {
				continue
			}
			for _, m := range markers {
				if strings.Contains(strings.ToUpper(e), m) {
					t.Errorf("profile %s passes %q through the environment.\n"+
						"A variable is the worst place for a long-lived credential: "+
						"/proc/self/environ is passively readable by every process in the "+
						"sandbox and inherited by every child. CLAUDE.md's rule is 'put the "+
						"secret in a file, not the environment' — stage a file and point the "+
						"tool at it with its own config variable, as @claude does with "+
						"~/.claude/.credentials.json and as the identity code does with "+
						"GH_CONFIG_DIR.\n"+
						"If %q is genuinely not a credential, add it to the allowlist in this "+
						"test with a comment explaining why.", name, e, e)
					break
				}
			}
		}
	}
}

// environNames is every variable name a profile mentions, across all five
// verbs.
func environNames(g policy.EnvGrants) []string {
	var out []string
	for k := range g.Set {
		out = append(out, k)
	}
	for k := range g.Merge {
		out = append(out, k)
	}
	for k := range g.Prepend {
		out = append(out, k)
	}
	out = append(out, g.Inherit...)
	out = append(out, g.Sanitise...)
	sort.Strings(out)
	return out
}

// ── the environ block ────────────────────────────────────────────────────────
//
// The review artifact for the parser is this table, not a golden file: the
// legacy rewrite is value-identical, so nothing downstream moves. What has to
// be pinned is which SPELLINGS reach the resolver and which are refused before
// they get there.

func TestEnvironBlockParses(t *testing.T) {
	src := `
[profile.x]
ro = ["/usr"]

[profile.x.environ.set]
XDG_CONFIG_HOME = "{home}/.config"

[profile.x.environ.merge]
PATH            = ["{home}/.cargo/bin", "{home}/.local/bin"]
PKG_CONFIG_PATH = "/opt/x/lib/pkgconfig"

[profile.x.environ.prepend]
PATH = "/opt/first/bin"

[profile.x.environ.inherit]
EDITOR = true
PAGER  = true

[profile.x.environ.sanitise]
PERL5LIB = true
`
	reg, err := parse([]byte(src), "test.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	g := reg["x"].Environ

	if g.Set["XDG_CONFIG_HOME"] != "{home}/.config" {
		t.Errorf("set = %v", g.Set)
	}
	if len(g.Merge["PATH"]) != 2 || g.Merge["PATH"][0] != "{home}/.cargo/bin" {
		t.Errorf("merge PATH = %v; an array is its elements, in the order written", g.Merge["PATH"])
	}
	// A bare string is exactly ONE element, for merge as well as prepend
	// (CALL 1). snug never splits a value on a separator, so this must not
	// become two entries however it is written.
	if len(g.Merge["PKG_CONFIG_PATH"]) != 1 {
		t.Errorf("merge PKG_CONFIG_PATH = %v; a string is one element", g.Merge["PKG_CONFIG_PATH"])
	}
	if len(g.Prepend["PATH"]) != 1 || g.Prepend["PATH"][0] != "/opt/first/bin" {
		t.Errorf("prepend PATH = %v", g.Prepend["PATH"])
	}
	if strings.Join(g.Inherit, " ") != "EDITOR PAGER" {
		t.Errorf("inherit = %v; names are sorted so resolution cannot depend on map order", g.Inherit)
	}
	if strings.Join(g.Sanitise, " ") != "PERL5LIB" {
		t.Errorf("sanitise = %v", g.Sanitise)
	}
}

// `environ.deny` must be refused for free, by the same DisallowUnknownFields
// that refuses an unknown ROOT key. That is the load-bearing reason the verbs
// are nested under one key instead of being five root keys (§1.1b): "a negation
// key cannot be smuggled in" then applies one level down with no new code.
func TestUnknownEnvironVerbIsFatal(t *testing.T) {
	for _, verb := range []string{"deny", "unset", "remove", "filter", "append"} {
		src := "[profile.x]\n[profile.x.environ." + verb + "]\nPATH = \"/opt/bin\"\n"
		if _, err := parse([]byte(src), "test.toml", true); err == nil {
			t.Errorf("environ.%s was accepted; the environment must not grow a verb snug "+
				"does not understand any more than the grant language may grow a `deny`", verb)
		}
	}
}

// `NAME = false` is a negation key that would otherwise parse. There is no way
// to un-inherit, because nothing was inherited to begin with — the environment
// starts empty and everything in it was put there by name.
func TestInheritFalseIsRefusedByName(t *testing.T) {
	for _, verb := range []string{"inherit", "sanitise"} {
		src := "[profile.x]\n[profile.x.environ." + verb + "]\nEDITOR = false\n"
		_, err := parse([]byte(src), "mine.toml", true)
		if err == nil {
			t.Fatalf("environ.%s EDITOR = false was accepted; a stored false is a negation "+
				"key wearing a verb's clothes", verb)
		}
		for _, want := range []string{"EDITOR", "false", "Remove the line"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("environ.%s = false: error %q does not contain %q", verb, err, want)
			}
		}
		// CONTROL: `= true`, the spelling that means something, still parses.
		src = "[profile.x]\n[profile.x.environ." + verb + "]\n" +
			map[string]string{"inherit": "EDITOR", "sanitise": "PERL5LIB"}[verb] + " = true\n"
		if _, err := parse([]byte(src), "mine.toml", true); err != nil {
			t.Errorf("environ.%s = true must parse, or the refusal above reads as a ban on "+
				"the verb rather than on the spelling: %v", verb, err)
		}
	}
}

// go-toml's own decode error for a wrong value type names neither the profile
// nor the file nor the verb, and a profile author with several files gets no
// help from it.
func TestEnvironValueTypeErrorsNameTheProfile(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"a number in an array", "[profile.x.environ.merge]\nPATH = [1, 2]\n"},
		{"a bare boolean", "[profile.x.environ.merge]\nPATH = true\n"},
		{"a nested array", "[profile.x.environ.prepend]\nPATH = [[\"/opt/bin\"]]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte("[profile.x]\n"+tc.src), "/home/u/.config/snug/profiles.d/mine.toml", true)
			if err == nil {
				t.Fatal("accepted a value that is not a string or an array of strings")
			}
			for _, want := range []string{"mine.toml", `"x"`, "PATH"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// ── the retired keys ─────────────────────────────────────────────────────────
//
// `env` and `path` are gone, and the error names the replacement rather than
// letting DisallowUnknownFields say "unknown key". That is the difference
// between a key that should never have existed (publish_auto, deleted outright)
// and a key whose MEANING MOVED: `env = [...]` is still a thing a profile wants
// to say, and the reader needs the new spelling, not the news that a word does
// not exist.
//
// The prefix changed on purpose. A silently CHANGED meaning is worse than a
// removed key, so anyone whose muscle memory reaches for `env` gets an error
// naming `environ.inherit` instead of a subtly different grant that parses.

func TestRetiredEnvKeyNamesTheFix(t *testing.T) {
	_, err := parse([]byte("[profile.x]\nenv = [\"EDITOR\", \"PAGER\"]\n"), "mine.toml", true)
	if err == nil {
		t.Fatal("`env = [...]` is retired and must be refused")
	}
	for _, want := range []string{"mine.toml", `"x"`, "environ.inherit", "EDITOR = true", "PAGER = true"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q — the message has to be pasteable, or the\n"+
				"author has to go and read the design to find out what replaced the key", err, want)
		}
	}

	// POSITIVE CONTROL. Without it the refusal reads as a ban on the CAPABILITY
	// rather than on the retired spelling, which is the exact control
	// TestRetiredPublishAutoIsAHardError already carries.
	reg, err := parse([]byte("[profile.x.environ.inherit]\nEDITOR = true\nPAGER = true\n"), "mine.toml", true)
	if err != nil {
		t.Fatalf("the replacement spelling must parse: %v", err)
	}
	if got := strings.Join(reg["x"].Environ.Inherit, " "); got != "EDITOR PAGER" {
		t.Errorf("environ.inherit = %q, want both names", got)
	}
}

func TestRetiredPathKeyNamesTheFix(t *testing.T) {
	_, err := parse([]byte("[profile.x]\npath = [\"{home}/.local/bin\"]\n"), "mine.toml", true)
	if err == nil {
		t.Fatal("`path = [...]` is retired and must be refused")
	}
	for _, want := range []string{"mine.toml", `"x"`, "environ.merge", `PATH = ["{home}/.local/bin"]`,
		"environ.prepend", "GRANT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL, and one that says more than the env one: the replacement
	// spelling parses AND the message told the author about the new obligation
	// (the profile must grant what it names), which is the part that would
	// otherwise surface later as a refusal from a different file.
	reg, err := parse([]byte("[profile.x]\nro = [\"{home}/.local/bin\"]\n"+
		"[profile.x.environ.merge]\nPATH = [\"{home}/.local/bin\"]\n"), "mine.toml", true)
	if err != nil {
		t.Fatalf("the replacement spelling must parse: %v", err)
	}
	if got := strings.Join(reg["x"].Environ.Merge["PATH"], " "); got != "{home}/.local/bin" {
		t.Errorf("environ.merge PATH = %q", got)
	}
}

// The parse-time checks run in parse, beside checkName — so `snug profile show`
// reports them and the verdict on a profile never depends on the host reading
// it (§2.3).
func TestEnvironIsValidatedAtParseTime(t *testing.T) {
	bad := []struct {
		name string
		src  string
		want string
	}{
		{"a name snug owns", "[profile.x.environ.set]\nHOME = \"/tmp\"\n", "HOME"},
		{"a forbidden name", "[profile.x.environ.set]\nLD_PRELOAD = \"/tmp/x.so\"\n", "LD_PRELOAD"},
		{"a name with '='", "[profile.x.environ.set]\n\"A=B\" = \"c\"\n", "="},
		{"the wrong verb for the type", "[profile.x.environ.set]\nPATH = \"/opt/bin\"\n", "environ.merge"},
		{"a hand-written separator", "[profile.x.environ.merge]\nPATH = \"/a:/b\"\n", "separator"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte("[profile.x]\n"+tc.src), "/home/u/.config/snug/profiles.d/mine.toml", true)
			if err == nil {
				t.Fatal("accepted; this must not wait until a sandbox is resolved")
			}
			if !strings.Contains(err.Error(), "mine.toml") {
				t.Errorf("the error must name the file to edit: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// ── §4.6(b): one unparseable file must not take the registry down ────────────

// MEASURED ON MAIN, and the reason this is a prerequisite rather than a
// cleanup: Load() returned at the first bad file, so a single stale file in
// profiles.d made `snug --dry-run -p @sys .` fail AND made `snug profile list`
// — the one command that would have told the user what still works — fail with
// the same error. A file the user may not have edited disabled @sys.
func TestOneBadFileDoesNotDisableTheRegistry(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sorted first, so it is reached BEFORE the good one — otherwise the test
	// would pass on an implementation that merely finished the loop.
	write(t, filepath.Join(pd, "a-broken.toml"), "[profile.broken]\nnope = true\n")
	write(t, filepath.Join(pd, "b-fine.toml"), "[profile.mine]\nro = [\"/opt\"]\n")
	t.Setenv("XDG_CONFIG_HOME", dir)

	reg, bad, err := Load()
	if err != nil {
		t.Fatalf("Load returned a hard error for one unparseable file: %v", err)
	}

	// POSITIVE CONTROL, and it is the whole point: the builtins must still be
	// there. Without this assertion the test passes on a registry that loaded
	// nothing at all.
	if _, ok := reg["@sys"]; !ok {
		t.Error("@sys is missing: one bad file in profiles.d took down the builtins, which " +
			"is the outage this change exists to remove")
	}
	if _, ok := reg["mine"]; !ok {
		t.Error("the good file in the same directory did not load; the loop stopped at the bad one")
	}
	if _, ok := reg["broken"]; ok {
		t.Error("a profile from the file that did not parse is in the registry")
	}

	if len(bad) != 1 || !strings.HasSuffix(bad[0].Path, "a-broken.toml") {
		t.Fatalf("bad = %+v, want exactly the one file that did not parse — a file skipped "+
			"without being reported is a silent downgrade", bad)
	}
	if bad[0].Err == nil || !strings.Contains(bad[0].Err.Error(), "unknown key") {
		t.Errorf("the recorded error must say what was wrong with the file, got %v", bad[0].Err)
	}
}

// A REDEFINITION stays hard, because two files claiming one name is a question
// with no answer and continuing would mean picking one silently. That is a
// different failure from a file that will not parse, and the split must not
// blur.
func TestRedefinitionIsStillAHardError(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pd, "a.toml"), "[profile.mine]\nro = [\"/opt\"]\n")
	write(t, filepath.Join(pd, "b.toml"), "[profile.mine]\nro = [\"/usr\"]\n")
	t.Setenv("XDG_CONFIG_HOME", dir)

	if _, _, err := Load(); err == nil {
		t.Fatal("two files defining one profile name were accepted")
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestNoTOMLKeyProducesATopology is the other half of internal/policy's
// TestTopologyIsDerivedNotSettable, and it exists because that test guards the
// wrong type on its own.
//
// Topology is DERIVED — deriveTopology computes it from Net.Mode and Podman —
// and the whole point is that no file can set it. policy.Profile is what a
// parsed profile becomes, but rawProfile is what TOML actually decodes into,
// and internal/policy cannot import this package to check it without a cycle.
// So the guard has to be written twice, in two packages, over two types.
//
// The literal is UNKEYED on purpose: adding a field anywhere in rawProfile
// breaks this build, which a keyed literal would not. Combined with
// DisallowUnknownFields — an unknown key is already a fatal parse error — the
// pair means a `topology = ...` key cannot be introduced without someone
// deliberately editing this line.
func TestNoTOMLKeyProducesATopology(t *testing.T) {
	_ = rawProfile{
		"",  // Description
		nil, // Include
		nil, // RO
		nil, // RW
		nil, // Tmpfs
		nil, // Symlink
		nil, // Optional
		nil, // Environ
		nil, // Env (retired spelling)
		nil, // Path (retired spelling)
		"",  // Network
		false,
		nil, // Publish
		"",  // Address
		"",  // Gateway
		0,   // MTU
		"",  // Podman
		"",  // Git
		nil, // Identity
	}
}

// `@home`'s tmpfs list is quoted, by hand, in four documents: CLAUDE.md's
// "the writable surface is eight paths" bullet, VERIFY.md §3's table,
// .claude/design/INDEX.md §9, and .claude/agents/sandbox-policy.md's shadow-slot
// rule. When the list grew a fifth entry ({home}/.local/share, PR #10) all four
// kept saying seven, for a milestone, and nothing could fail — a count in prose
// is a copy of state held here, with no link back to its source.
//
// This is that link. It pins `@home`, and ONLY `@home`: /tmp, /dev and the
// target bind come from elsewhere, so a writable grant added to a different
// profile still slips past this test. It converts one silent drift into a
// failing test with an instruction attached; it does not verify the writable
// surface. VERIFY.md §3's probe does that, by enumeration, inside a live
// sandbox.
func TestHomeTmpfsListIsPinnedToTheDocumentsQuotingIt(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg["@home"]
	if !ok {
		t.Fatal("@home is missing")
	}
	want := []string{
		"{home}",
		"{home}/.cache",
		"{home}/.config",
		"{home}/.local/state",
		"{home}/.local/share",
	}
	if !slices.Equal(p.Tmpfs, want) {
		t.Errorf("@home's tmpfs list changed:\n got %q\nwant %q\n\n"+
			"That list is quoted by hand in CLAUDE.md (the writable-surface bullet), "+
			"VERIFY.md §3 (the table AND the expected output of the enumeration probe), "+
			".claude/design/INDEX.md §9, and .claude/agents/sandbox-policy.md. "+
			"Update all four and this test together, or the count in prose goes stale "+
			"again with nothing to catch it.", p.Tmpfs, want)
	}
}
