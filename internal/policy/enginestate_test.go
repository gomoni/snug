package policy

import (
	"strings"
	"testing"
)

// The roots engine.DataRoots yields with XDG_DATA_HOME=/data/x and HOME=/home/u.
var testEngineDataRoots = []EngineDataRoot{
	{Path: "/data/x/snug"},
	{Path: "/home/u/.local/share/snug"},
}

func engineStateCtx(roots []EngineDataRoot, prefixes ...string) Context {
	c := testCtx()
	c.EngineDataRoots = roots
	c.EngineTmpPrefixes = prefixes
	return c
}

func withGrant(acc, path string) map[ProfileName]*Profile {
	p := &Profile{Name: "peek"}
	if acc == "ro" {
		p.RO = []string{path}
	} else {
		p.RW = []string{path}
	}
	reg := testRegistry()
	reg["peek"] = p
	return reg
}

// TestEngineDataRootGrantRefused: redteam setup r7 follow-up, engine state. A
// grant over snug's engine store resolved, rw and ro alike: rw lets a sandbox
// plant a tagged image a later container run on another target uses, or write
// libpod records so a later `start` skips the proxy's create-time decisions;
// ro leaks other targets' layers. Every coverage direction, a symlink to the
// root, and the $HOME default under a custom XDG_DATA_HOME are refused.
func TestEngineDataRootGrantRefused(t *testing.T) {
	for _, tc := range []struct{ name, grant, root string }{
		{"root", "/data/x/snug", "/data/x/snug"},
		{"inside", "/data/x/snug/engines", "/data/x/snug"},
		{"XDG_DATA_HOME parent", "/data/x", "/data/x/snug"},
		{"symlink to root", "/opt/link", "/data/x/snug"},
		{"$HOME default under custom XDG_DATA_HOME", "/home/u/.local/share/snug", "/home/u/.local/share/snug"},
	} {
		for _, acc := range []string{"ro", "rw"} {
			env := envWith(tc.grant, "/data/x/snug/engines", "/home/u/.local/share/snug", "/home/u/proj/sub")
			if tc.name == "symlink to root" {
				env.links["/opt/link"] = "/data/x/snug"
			}
			_, err := Resolve(withGrant(acc, tc.grant), append(testDefaults, "peek"),
				engineStateCtx(testEngineDataRoots), env)
			if err == nil {
				t.Errorf("ACCEPTED %s %s (%s)", acc, tc.grant, tc.name)
				continue
			}
			for _, want := range []string{"engine store " + tc.root, `"peek"`, "Grant a directory that does not contain it"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s %s (%s): refusal lacks %q:\n%v", acc, tc.grant, tc.name, want, err)
				}
			}
		}
	}
}

// TestEngineDataRootsEmptyDisables: redteam setup r7 follow-up, engine state.
// An empty EngineDataRoots disables the check — which is why the CLI filling it
// from engine.DataRoots is load-bearing — and a sibling of the store is not
// covered by it.
func TestEngineDataRootsEmptyDisables(t *testing.T) {
	for _, tc := range []struct {
		name, grant string
		roots       []EngineDataRoot
	}{
		{"no roots injected", "/data/x/snug", nil},
		{"sibling by prefix", "/data/x/snug-notes", testEngineDataRoots},
	} {
		env := envWith(tc.grant, "/home/u/proj/sub")
		_, err := Resolve(withGrant("rw", tc.grant), append(testDefaults, "peek"), engineStateCtx(tc.roots), env)
		if err != nil {
			t.Errorf("%s: rw %s refused:\n%v", tc.name, tc.grant, err)
		}
	}
}

// TestPerRunEngineTmpDirGrantRefused: redteam setup r7 follow-up, engine
// state. The per-run directories /tmp/snug-<uid>-<pid>/{sock,conf} and
// /tmp/snug-engines-<uid>-<key>/rr resolved rw, reaching another run's podman
// socket and its generated containers.conf and storage.conf. Refused by name
// prefix; "snug-1000x" shares characters but not the prefix and is accepted,
// which pins the boundary.
func TestPerRunEngineTmpDirGrantRefused(t *testing.T) {
	prefixes := []string{"/tmp/snug-1000-", "/tmp/snug-engines-1000-"}
	for _, tc := range []struct{ grant, entry string }{
		{"/tmp/snug-1000-123/conf", "/tmp/snug-1000-123"},
		{"/tmp/snug-1000-123", "/tmp/snug-1000-123"},
		{"/tmp/snug-engines-1000-k/rr", "/tmp/snug-engines-1000-k"},
		{"/tmp/x/link", "/tmp/snug-1000-123"},
	} {
		for _, acc := range []string{"ro", "rw"} {
			env := envWith(tc.grant, "/tmp/snug-1000-123/conf", "/home/u/proj/sub")
			env.links["/tmp/x/link"] = "/tmp/snug-1000-123"
			_, err := Resolve(withGrant(acc, tc.grant), append(testDefaults, "peek"),
				engineStateCtx(nil, prefixes...), env)
			if err == nil {
				t.Errorf("ACCEPTED %s %s", acc, tc.grant)
				continue
			}
			for _, want := range []string{"reaches " + tc.entry + ", a per-run directory", `"peek"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s %s: refusal lacks %q:\n%v", acc, tc.grant, want, err)
				}
			}
		}
	}

	env := envWith("/tmp/snug-1000x", "/home/u/proj/sub")
	if _, err := Resolve(withGrant("rw", "/tmp/snug-1000x"), append(testDefaults, "peek"),
		engineStateCtx(nil, prefixes...), env); err != nil {
		t.Errorf("rw /tmp/snug-1000x is not a per-run engine directory and was refused:\n%v", err)
	}
}

// TestToolchainRootRWRefusedROAllowed: redteam setup r7 follow-up, engine
// state. The toolchain root $SNUG_PODMAN_ROOT names holds the engine binaries
// a later container run executes on the host: rw is refused, in both coverage
// directions; ro is allowed, since reading program files is not the hole.
func TestToolchainRootRWRefusedROAllowed(t *testing.T) {
	roots := append([]EngineDataRoot{{Path: "/opt/podman", ReadAllowed: true}}, testEngineDataRoots...)
	for _, grant := range []string{"/opt/podman", "/opt/podman/usr/bin", "/opt"} {
		env := envWith("/opt/podman/usr/bin", "/home/u/proj/sub")
		_, err := Resolve(withGrant("rw", grant), append(testDefaults, "peek"), engineStateCtx(roots), env)
		if err == nil {
			t.Errorf("ACCEPTED rw %s over the toolchain root", grant)
		} else if !strings.Contains(err.Error(), "toolchain root /opt/podman ($SNUG_PODMAN_ROOT)") {
			t.Errorf("rw %s: refused for another reason:\n%v", grant, err)
		}

		_, err = Resolve(withGrant("ro", grant), append(testDefaults, "peek"), engineStateCtx(roots), env)
		if err != nil {
			t.Errorf("ro %s over the toolchain root was REFUSED:\n%v", grant, err)
		}
	}
}
