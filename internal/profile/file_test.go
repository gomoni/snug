package profile

import (
	"strings"
	"testing"
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
	for _, want := range []string{"null", "sys", "home", "cwd-rw", "parent-ro"} {
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
	if _, ok := reg["default"]; ok {
		t.Error("a builtin profile named `default` is back; the default SELECTION is a " +
			"preference (profile.BuiltinDefaults), not a profile")
	}
	if len(reg["null"].RO)+len(reg["null"].RW)+len(reg["null"].Tmpfs) != 0 {
		t.Error("the null profile must grant nothing; it is the floor of the lattice")
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
		if strings.HasPrefix(n, "net") {
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
func TestRedefinitionIsRejectedRegardlessOfLayer(t *testing.T) {
	builtin, err := builtins()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"sys", "net", "cwd-rw", "null"} {
		t.Run(name, func(t *testing.T) {
			if _, ok := builtin[name]; !ok {
				t.Skipf("%s is not a builtin", name)
			}
			reg, err := builtins()
			if err != nil {
				t.Fatal(err)
			}
			user, err := parse([]byte("[profile."+name+"]\nro = [\"/\"]\n"),
				"/home/u/.config/snug/profiles.d/mine.toml", true)
			if err != nil {
				t.Fatal(err)
			}
			err = reg.merge(user)
			if err == nil {
				t.Fatalf("a user file redefining the builtin %q was accepted", name)
			}
			// The message must name BOTH files: the user knows what they wrote,
			// not what it collided with.
			for _, want := range []string{name, "mine.toml", "builtin:"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}
