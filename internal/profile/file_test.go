package profile

import (
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

// TestNoNullProfileShips pins MVY0's headline claim on its own, separate from
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
			"(profile.BuiltinDefaults / --no-defaults), not a grant (MVY0)")
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
env = ["EDITOR"]
symlink = [{ at = "/bin", target = "usr/bin" }]
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
	for _, want := range []string{"@sys", "@home", "@cwd-rw", "@parent-ro"} {
		if _, ok := reg[want]; !ok {
			t.Errorf("builtin profile %q is missing", want)
		}
	}
	// There is deliberately no profile called `default`, and (MVY0) no profile
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

// The engine-netns finding (.claude/design/ENGINE-NETNS.md §0), pinned so its
// removal is deliberate rather than incidental.
//
// `@podman-socket` grants egress, because a container runs in the ENGINE's
// network namespace and therefore has the engine's network — measured, with the
// response read back out of `containers/{id}/logs`, while `--dry-run` printed
// "No egress. No host loopback." Including `net` does not narrow that hole; it
// stops snug asserting a guarantee it was not delivering (invariant 5).
//
// This test exists to make the eventual REMOVAL a conscious act. When the engine
// moves into the sandbox's netns (.claude/design/ENGINE-NETNS.md §5), container
// network becomes sandbox network, `@podman-socket` without `@net` is genuinely
// offline, and this include becomes actively wrong — because offline goes back
// to being the ABSENCE of a profile, which is the property that stops it being
// switched on by accident. Deleting this test is then part of the milestone, and
// the failure message is where the next person finds out why.
func TestPodmanSocketIncludesNetAsAnInterimHonestyFix(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg["@podman-socket"]
	if !ok {
		t.Fatal("@podman-socket is missing")
	}
	found := false
	for _, inc := range p.Include {
		if inc == "@net" {
			found = true
		}
	}
	if !found {
		t.Errorf("@podman-socket no longer includes @net (includes: %v).\n"+
			"If the engine now runs in the SANDBOX's netns, this is correct and this test "+
			"should be deleted along with the interim comment in base.toml — check that "+
			"`@podman-socket` without `@net` really is offline first, with a container "+
			"probe that has a positive control.\n"+
			"If the engine still runs on the host's network, this reopens the engine-netns "+
			"finding (.claude/design/ENGINE-NETNS.md §0): the "+
			"sandbox has egress through a container while --dry-run says it does not.",
			p.Include)
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
		if strings.HasPrefix(n, policy.Sigil+"net") {
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
		if !strings.HasPrefix(name, policy.Sigil) {
			t.Errorf("builtin %q does not carry %q", name, policy.Sigil)
		}
		if p.Name != name {
			t.Errorf("builtin registered as %q but names itself %q; provenance would lie", name, p.Name)
		}
		// An include is rewritten with the rest, or a builtin resolves against
		// whatever the user happens to have called `sys`.
		for _, inc := range p.Include {
			if !strings.HasPrefix(inc, policy.Sigil) {
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
// the same defect the conditional `forbiddenEnv` guard has (see
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

// The retired keys are REWRITTEN, not carried alongside: `env` is exactly
// `environ.inherit` and `path` is exactly `environ.merge` on PATH. Shipping
// both spellings would be two mechanisms for one idea.
func TestRetiredEnvAndPathAreRewritten(t *testing.T) {
	src := `
[profile.x]
env  = ["EDITOR", "PAGER"]
path = ["{home}/.local/bin"]
`
	reg, err := parse([]byte(src), "mine.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	g := reg["x"].Environ
	if strings.Join(g.Inherit, " ") != "EDITOR PAGER" {
		t.Errorf("env = [...] did not become environ.inherit: %v", g.Inherit)
	}
	if strings.Join(g.Merge["PATH"], " ") != "{home}/.local/bin" {
		t.Errorf("path = [...] did not become environ.merge on PATH: %v", g.Merge)
	}

	// And the two spellings coexist in one profile without one dropping the
	// other — the rewrite APPENDS to whatever the new spelling already said.
	src = `
[profile.y]
path = ["/opt/old/bin"]
[profile.y.environ.merge]
PATH = ["/opt/new/bin"]
`
	reg, err = parse([]byte(src), "mine.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := reg["y"].Environ.Merge["PATH"]; len(got) != 2 {
		t.Errorf("merge PATH = %v, want both spellings' entries; a rewrite that REPLACED "+
			"would silently drop a grant", got)
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
