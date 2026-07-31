package profile

import (
	"strings"
	"testing"

	"snug/internal/policy"
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
	if p.Description != "d" || len(p.RO) != 1 || len(p.Env) != 1 {
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
	reg, err := builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@null", "@sys", "@home", "@cwd-rw", "@parent-ro"} {
		if _, ok := reg[want]; !ok {
			t.Errorf("builtin profile %q is missing", want)
		}
	}
	// There is deliberately no profile called `default`. What a bare
	// `snug <dir>` selects is the `defaults` SETTING, not a grant — a profile
	// that grants nothing was still appearing in SNUG_PROFILES and in every
	// Mount's provenance as though it were a hole in the sandbox, and it
	// duplicated an idea config.toml already expressed. Reintroducing it would
	// bring back two mechanisms for one idea.
	if _, ok := reg["@default"]; ok {
		t.Error("a builtin profile named `@default` is back; the default SELECTION is a " +
			"preference (profile.BuiltinDefaults), not a profile")
	}
	if len(reg["@null"].RO)+len(reg["@null"].RW)+len(reg["@null"].Tmpfs) != 0 {
		t.Error("the @null profile must grant nothing; it is the floor of the lattice")
	}
	for name, p := range reg {
		for _, g := range append(append([]string{}, p.RO...), p.RW...) {
			if g == "/" {
				t.Errorf("builtin profile %q grants /", name)
			}
		}
	}
}

// The built-in `defaults` are the selection a bare `snug <dir>` uses, so every
// name in them must resolve to a real builtin. A typo here is not a compile
// error and would surface as `unknown profile` on the user's first ever run.
func TestBuiltinDefaultsNameRealProfiles(t *testing.T) {
	reg, err := builtins()
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
			reg, err := builtins()
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
	reg, err := builtins()
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
	reg, err := builtins()
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
