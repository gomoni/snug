package policy

import (
	"strings"
	"testing"
)

// ── a writable grant reaching the trusted profile store ────────────────────
//
// MEASURED before this was written, on a scratch $HOME with the real binary:
//
//	$ snug --dry-run -p @cwd-rw $H/.config/snug/profiles.d
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
// writability IS an rw grant (@cwd-rw grants {target}) — one rule then covers
// both that case and a hand-written profile granting rw over ~/.config.

func profileStoreCtx(target string, dirs ...string) Context {
	c := testCtx()
	c.Target = target
	c.ProfileDirs = dirs
	return c
}

// The store is a real directory on a real host, and both layers count.
var testProfileDirs = []string{"/etc/snug/profiles.d", "/home/u/.config/snug/profiles.d"}

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
			profileStoreCtx("/home/u/proj/sub", testProfileDirs...),
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
			dirs: testProfileDirs,
		},
		{
			name: "rw beside the store",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/snug-notes"}},
			why:  "a prefix that shares characters with the store but is not inside it — covers() must compare path segments, not strings",
			dirs: testProfileDirs,
		},
		{
			name: "rw over an unrelated config directory",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/nvim"}},
			why:  "the sibling case that makes ~/.config granular rather than forbidden",
			dirs: testProfileDirs,
		},
		{
			name: "no ProfileDirs injected",
			prof: &Profile{Name: "p", RW: []string{"/home/u/.config/snug/profiles.d"}},
			why:  "an empty ProfileDirs disables the check, which is what a unit test resolving without a host store gets — and is why the CLI filling it from profile.ConfigDirs is load-bearing",
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
// real binary too, on a scratch store: `snug -p @cwd-rw $X/link-to-store` exits
// 77 and the message names the RESOLVED path.
func TestASymlinkToTheProfileStoreIsStillTheProfileStore(t *testing.T) {
	reg := testRegistry()
	reg["store"] = &Profile{Name: "store", RW: []string{"/home/u/link-to-store"}}
	env := envWith("/home/u/link-to-store", "/home/u/.config/snug/profiles.d", "/home/u/proj/sub")
	env.links["/home/u/link-to-store"] = "/home/u/.config/snug/profiles.d"
	_, err := Resolve(reg, append(testDefaults, "store"),
		profileStoreCtx("/home/u/proj/sub", testProfileDirs...), env)
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
		profileStoreCtx("/home/u/proj/sub", testProfileDirs...),
		envWith("/home/u/.config/snug/profiles.d", "/home/u/proj/sub"))
	if err == nil {
		t.Fatal("accepted a profile granting rw over the profile store")
	}
	if !strings.Contains(err.Error(), "refusing to grant WRITE access") {
		t.Errorf("the fold spoke first, so the user sees a mount conflict rather than the "+
			"reason the selection is refused:\n%v", err)
	}
}
