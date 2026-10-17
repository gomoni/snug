package policy

import (
	"strings"
	"testing"
)

// ── a writable grant reaching the trusted profile store ────────────────────
//
// MEASURED before this was written, on a scratch $HOME with the real binary:
//
//	$ snug --dry-run -p @target-rw $H/.config/snug/profiles.d
//	TARGET   …/.config/snug/profiles.d  (writable)
//	HOME     … (tmpfs, ephemeral; WRITABLE and PERSISTS below: …/profiles.d)
//
// So the payload could write a *.toml that a LATER run loads, which is the
// sandbox granting itself permissions — the one thing keeping the profile set
// outside the sandboxed material prevents. What hid it: `snug ~/.config/snug` is
// already refused ONE LEVEL UP, by the ephemeral-target rule and for an
// unrelated reason, so the obvious spellings all failed and the deeper one was
// never tried.
//
// The check is over writable GRANTS, not over the target, because the target's
// writability IS an rw grant (@target-rw grants {target}) — one rule then covers
// both that case and a hand-written profile granting rw over ~/.config.

func profileStoreCtx(target string, roots ...string) Context {
	c := testCtx()
	c.Target = target
	c.ConfigRoots = roots
	return c
}

// The configuration roots profile.TrustedConfigRoots yields on a host with no
// $XDG_CONFIG_HOME: both layers count.
var testConfigRoots = []string{"/etc/snug", "/home/u/.config/snug"}

func TestAWritableGrantCoveringTheProfileStoreIsRefused(t *testing.T) {
	for _, tc := range []struct{ grant, why string }{
		{"/home/u/.config/snug/profiles.d", "the measured case: the store IS the target"},
		{"/home/u/.config/snug/profiles.d/vendor", "inside the store — refused so the rule does not depend on loadDir staying non-recursive"},
		{"/home/u/.config", "a hand-written profile sharing the whole config directory"},
		{"/etc/snug/profiles.d", "the system layer, which Load reads first"},
	} {
		reg := testRegistry()
		reg["store"] = &Profile{Name: "store", RW: []string{tc.grant}}
		_, err := Resolve(reg, append(testDefaults, "store"),
			profileStoreCtx("/home/u/proj/sub", testConfigRoots...),
			envWith(tc.grant, "/home/u/proj/sub"))
		if err == nil {
			t.Errorf("ACCEPTED rw %s — %s", tc.grant, tc.why)
			continue
		}
		got := err.Error()
		for _, want := range []string{
			"refusing to grant WRITE access",
			"store",       // WHICH profile did it
			"LATER run",   // why it matters: the next run, not this one
			"on the host", // the fix, named
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal for rw %s does not contain %q:\n%s", tc.grant, want, got)
			}
		}
	}
}

// POSITIVE CONTROLS. A rule that refused everything would pass the test above
// and make snug useless.
func TestTheProfileStoreRuleIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name string
		prof *Profile
		why  string
		dirs []string
	}{
		{
			name: "ro over the store",
			prof: &Profile{Name: "p", RO: []string{"/home/u/.config/snug/profiles.d"}},
			why:  "read access is not the hole: a profile is not a secret, and @sys's /usr already carries snug's own builtins",
			dirs: testConfigRoots,
		},
		{
			name: "rw beside the store",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/snug-notes"}},
			why:  "a prefix that shares characters with the store but is not inside it — covers() must compare path segments, not strings",
			dirs: testConfigRoots,
		},
		{
			name: "rw over an unrelated config directory",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/nvim"}},
			why:  "the sibling case that makes ~/.config granular rather than forbidden",
			dirs: testConfigRoots,
		},
		{
			name: "no ConfigRoots injected",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/snug/profiles.d"}},
			why:  "an empty ConfigRoots disables the check, which is what a unit test resolving without a host store gets — and is why the CLI filling it from profile.TrustedConfigRoots is load-bearing",
			dirs: nil,
		},
	} {
		reg := testRegistry()
		reg["p"] = tc.prof
		paths := append(append([]string{}, tc.prof.RO...), tc.prof.RW...)
		_, err := Resolve(reg, append(testDefaults, "p"),
			profileStoreCtx("/home/u/proj/sub", tc.dirs...),
			envWith(append(paths, "/home/u/proj/sub")...))
		if err != nil {
			t.Errorf("%s was REFUSED — %s:\n%v", tc.name, tc.why, err)
		}
	}
}

// A grant naming a SYMLINK to the store is the same grant. The check
// canonicalises both sides through Environ.EvalSymlinks for this: comparing text
// would pass a link, and /home being a symlink is ordinary on several distros
// (this repo's own resolver comments cite /home -> /var/home). MEASURED with the
// real binary too, on a scratch store: `snug -p @target-rw $X/link-to-store` exits
// 77 and the message names the RESOLVED path.
func TestASymlinkToTheProfileStoreIsStillTheProfileStore(t *testing.T) {
	reg := testRegistry()
	reg["store"] = &Profile{Name: "store", RW: []string{"/home/u/link-to-store"}}
	env := envWith("/home/u/link-to-store", "/home/u/.config/snug/profiles.d", "/home/u/proj/sub")
	env.links["/home/u/link-to-store"] = "/home/u/.config/snug/profiles.d"
	_, err := Resolve(reg, append(testDefaults, "store"),
		profileStoreCtx("/home/u/proj/sub", testConfigRoots...), env)
	if err == nil {
		t.Fatal("accepted rw on a symlink whose target IS the profile store")
	}
	if !strings.Contains(err.Error(), "/home/u/.config/snug/profiles.d") {
		t.Errorf("the refusal names the link rather than what it resolves to, so a reader "+
			"cannot see why it fired:\n%v", err)
	}
}

// The refusal must beat the fold. Without this, `join` or Validate speaks first
// on some selections and the user gets a mount conflict instead of the sentence
// that names the actual problem — the same failure mode issue #179 was filed
// about for the ephemeral-target rule.
func TestTheProfileStoreRefusalBeatsTheFold(t *testing.T) {
	reg := testRegistry()
	reg["store"] = &Profile{
		Name:  "store",
		RW:    []string{"/home/u/.config/snug/profiles.d"},
		Tmpfs: []string{"/home/u/.config/snug/profiles.d"}, // a kind conflict at the same path
	}
	_, err := Resolve(reg, append(testDefaults, "store"),
		profileStoreCtx("/home/u/proj/sub", testConfigRoots...),
		envWith("/home/u/.config/snug/profiles.d", "/home/u/proj/sub"))
	if err == nil {
		t.Fatal("accepted a profile granting rw over the profile store")
	}
	if !strings.Contains(err.Error(), "refusing to grant WRITE access") {
		t.Errorf("the fold spoke first, so the user sees a mount conflict rather than the "+
			"reason the selection is refused:\n%v", err)
	}
}

// refusesConfigWrite resolves sel with reg under ctx and fails unless the
// configuration-root refusal is what speaks.
func refusesConfigWrite(t *testing.T, reg map[ProfileName]*Profile, sel []ProfileName, ctx Context, env Environ, what string) {
	t.Helper()
	_, err := Resolve(reg, sel, ctx, env)
	if err == nil {
		t.Fatalf("ACCEPTED %s", what)
	}
	for _, want := range []string{"refusing to grant WRITE access", "trusted configuration (profiles.d, config.toml)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal for %s does not contain %q:\n%v", what, want, err)
		}
	}
}

// TestWritableDefaultStoreRefusedWhenXDGPointsElsewhere: redteam setup r7
// R7-5. With XDG_CONFIG_HOME=$S/x the protected set used to be only
// $S/x/snug/profiles.d, so `rw = ["~/.config/snug/profiles.d"]` resolved — and
// a later run without that variable loads exactly that store. The roots here
// are what profile.TrustedConfigRoots yields under that variable.
func TestWritableDefaultStoreRefusedWhenXDGPointsElsewhere(t *testing.T) {
	reg := testRegistry()
	reg["store"] = &Profile{Name: "store", RW: []string{"/home/u/.config/snug/profiles.d"}}
	refusesConfigWrite(t, reg, append(testDefaults, "store"),
		profileStoreCtx("/home/u/proj/sub", "/etc/snug", "/s/x/snug", "/home/u/.config/snug"),
		envWith("/home/u/.config/snug/profiles.d", "/s/x/snug", "/home/u/proj/sub"),
		"rw ~/.config/snug/profiles.d under a custom XDG_CONFIG_HOME")
}

// TestWritableUserConfigTomlRefused: redteam setup r7 R7-5. config.toml was
// not covered, so `rw = ["$XDG_CONFIG_HOME/snug/config.toml"]` resolved and the
// payload could write `defaults = ["@net", ...]` for the next bare `snug DIR`.
func TestWritableUserConfigTomlRefused(t *testing.T) {
	for _, roots := range [][]string{
		testConfigRoots,
		{"/etc/snug", "/s/x/snug", "/home/u/.config/snug"},
	} {
		file := roots[1] + "/config.toml"
		reg := testRegistry()
		reg["store"] = &Profile{Name: "store", RW: []string{file}}
		env := envWith(roots[1], "/home/u/proj/sub")
		env.files[file] = true
		refusesConfigWrite(t, reg, append(testDefaults, "store"),
			profileStoreCtx("/home/u/proj/sub", roots...), env, "rw "+file)
	}
}

// TestWritableConfigRootAncestorRefused: redteam setup r7 R7-5. An ancestor of
// a configuration root is refused on its own — here with no default profiles
// selected (the --no-defaults shape), so nothing else in the selection can be
// what refuses it.
func TestWritableConfigRootAncestorRefused(t *testing.T) {
	reg := testRegistry()
	reg["store"] = &Profile{Name: "store", RW: []string{"/home/u/.config"}}
	refusesConfigWrite(t, reg, []ProfileName{"store"},
		profileStoreCtx("/home/u/proj/sub", testConfigRoots...),
		envWith("/home/u/.config/snug", "/home/u/proj/sub"),
		"rw /home/u/.config with no defaults")
}

// TestTargetRWInsideConfigRootRefused: redteam setup r7 R7-5. The target's
// writability is an rw grant, so a target inside a configuration root is
// refused by the same rule — profiles.d, and a sibling of it now that the
// whole root is covered rather than profiles.d alone.
func TestTargetRWInsideConfigRootRefused(t *testing.T) {
	for _, target := range []string{
		"/home/u/.config/snug/profiles.d",
		"/home/u/.config/snug/notes",
	} {
		refusesConfigWrite(t, testRegistry(), testDefaults,
			profileStoreCtx(target, testConfigRoots...),
			envWith(target), "@target-rw "+target)
	}
}

// TestReadOnlyConfigRootAllowed is the positive control for the widened
// scope: read access to the whole configuration root, config.toml included,
// is not the hole.
func TestReadOnlyConfigRootAllowed(t *testing.T) {
	reg := testRegistry()
	reg["p"] = &Profile{Name: "p", RO: []string{"/home/u/.config/snug", "/etc/snug"}}
	_, err := Resolve(reg, append(testDefaults, "p"),
		profileStoreCtx("/home/u/proj/sub", testConfigRoots...),
		envWith("/home/u/.config/snug", "/etc/snug", "/home/u/proj/sub"))
	if err != nil {
		t.Errorf("ro over the configuration roots was REFUSED:\n%v", err)
	}
}
