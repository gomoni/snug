package policy

import (
	"strings"
	"testing"
)

const (
	testRunDir = "/tmp/snug-1000"
	testXDGDir = "/run/user/1000/snug"
)

func runtimeDirCtx(target string, dirs ...string) Context {
	c := testCtx()
	c.Target = target
	c.RuntimeDirs = dirs
	return c
}

func runtimeDirEnv(extra ...string) *fakeEnv {
	return envWith(append([]string{"/tmp", testRunDir, "/run/user/1000", testXDGDir, "/tmp/x", "/tmp/proj"}, extra...)...)
}

func TestAGrantReachingTheRuntimeDirIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, grant string }{
		{"equal", testRunDir},
		{"containing", "/tmp"},
		{"inside", testRunDir + "/run-1"},
	} {
		for _, acc := range []string{"ro", "rw"} {
			p := &Profile{Name: "peek"}
			if acc == "ro" {
				p.RO = []string{tc.grant}
			} else {
				p.RW = []string{tc.grant}
			}
			reg := testRegistry()
			reg["peek"] = p
			env := runtimeDirEnv(tc.grant)
			_, err := Resolve(reg, append(testDefaults, "peek"), runtimeDirCtx("/home/u/proj/sub", testRunDir), env)
			if err == nil {
				t.Errorf("ACCEPTED %s %s (%s)", acc, tc.grant, tc.name)
				continue
			}
			for _, want := range []string{"runtime directory " + testRunDir, `"peek"`, "temp directory"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s %s: refusal lacks %q:\n%s", acc, tc.grant, want, err)
				}
			}
		}
	}
}

func TestATargetContainingTheRuntimeDirIsRefused(t *testing.T) {
	for _, tc := range []struct {
		profile ProfileName
		target  string
	}{
		{"@target-rw", "/tmp"},
		{"@target-rw", testRunDir},
		{"@parent-ro", "/tmp/x"},
	} {
		env := runtimeDirEnv()
		_, err := Resolve(testRegistry(), append(testDefaults, tc.profile), runtimeDirCtx(tc.target, testRunDir), env)
		if err == nil {
			t.Errorf("ACCEPTED %s with target %s", tc.profile, tc.target)
		}
	}
}

func TestTheRuntimeDirRuleIsNarrow(t *testing.T) {
	env := func() *fakeEnv {
		return runtimeDirEnv("/tmp/snug-10000", "/run/user/1000/pulse")
	}
	for _, tc := range []struct {
		name string
		prof *Profile
		ctx  Context
	}{
		{"sibling by prefix", &Profile{Name: "p", RW: []string{"/tmp/snug-10000"}}, runtimeDirCtx("/home/u/proj/sub", testRunDir)},
		{"sibling under /run/user", &Profile{Name: "p", RO: []string{"/run/user/1000/pulse"}}, runtimeDirCtx("/home/u/proj/sub", testXDGDir)},
		{"tmpfs at /tmp", &Profile{Name: "p", Tmpfs: []string{"/tmp"}}, runtimeDirCtx("/home/u/proj/sub", testRunDir)},
		{"empty RuntimeDirs", &Profile{Name: "p", RW: []string{"/tmp"}}, runtimeDirCtx("/home/u/proj/sub")},
	} {
		reg := testRegistry()
		reg["p"] = tc.prof
		_, err := Resolve(reg, append(testDefaults, "p"), tc.ctx, env())
		if err != nil && strings.Contains(err.Error(), "runtime directory") {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
	}
	_, err := Resolve(testRegistry(), append(testDefaults, "@target-rw"), runtimeDirCtx("/tmp/proj", testRunDir), env())
	if err != nil && strings.Contains(err.Error(), "runtime directory") {
		t.Errorf("target /tmp/proj refused: %v", err)
	}
}

func TestASymlinkToTheRuntimeDirIsStillTheRuntimeDir(t *testing.T) {
	env := runtimeDirEnv("/tmp/x/link")
	env.links["/tmp/x/link"] = testRunDir
	reg := testRegistry()
	reg["peek"] = &Profile{Name: "peek", RO: []string{"/tmp/x/link"}}
	if _, err := Resolve(reg, append(testDefaults, "peek"), runtimeDirCtx("/home/u/proj/sub", testRunDir), env); err == nil ||
		!strings.Contains(err.Error(), "runtime directory") {
		t.Errorf("a symlink to the runtime directory was accepted or refused for another reason: %v", err)
	}

	// The directory itself reached through a link: /var/tmp -> /tmp style.
	env = runtimeDirEnv("/tmp/x/real")
	env.links["/alias"] = "/tmp"
	reg = testRegistry()
	reg["peek"] = &Profile{Name: "peek", RO: []string{"/alias"}}
	env.dirs["/alias"] = true
	if _, err := Resolve(reg, append(testDefaults, "peek"), runtimeDirCtx("/home/u/proj/sub", "/alias/snug-1000"), env); err == nil ||
		!strings.Contains(err.Error(), "runtime directory") {
		t.Errorf("a runtime dir reached through a link was accepted: %v", err)
	}
}

func TestAnAbsentRuntimeDirIsCanonicalisedThroughItsParent(t *testing.T) {
	env := runtimeDirEnv()
	env.links["/alias"] = "/tmp"
	env.dirs["/alias"] = true
	got := canonExisting(env, "/alias/snug-1000/run-1")
	if got != "/tmp/snug-1000/run-1" {
		t.Errorf("canonExisting = %q, want /tmp/snug-1000/run-1", got)
	}
	reg := testRegistry()
	reg["peek"] = &Profile{Name: "peek", RO: []string{"/tmp"}}
	if _, err := Resolve(reg, append(testDefaults, "peek"), runtimeDirCtx("/home/u/proj/sub", "/alias/snug-2000"), env); err == nil {
		t.Errorf("an absent runtime dir under a symlinked parent was not matched against a grant of the real parent")
	}
}

func TestTheRuntimeDirRefusalIsOrderIndependent(t *testing.T) {
	env := runtimeDirEnv("/tmp/a", "/tmp/b")
	reg := testRegistry()
	reg["zeta"] = &Profile{Name: "zeta", RO: []string{"/tmp"}}
	reg["alpha"] = &Profile{Name: "alpha", RW: []string{"/tmp"}}
	var first string
	for i, order := range [][]ProfileName{
		append(append([]ProfileName{}, testDefaults...), "zeta", "alpha"),
		append(append([]ProfileName{}, testDefaults...), "alpha", "zeta"),
	} {
		for _, dirs := range [][]string{{testRunDir, testXDGDir}, {testXDGDir, testRunDir}} {
			_, err := Resolve(reg, order, runtimeDirCtx("/home/u/proj/sub", dirs...), env)
			if err == nil {
				t.Fatal("accepted")
			}
			if i == 0 && first == "" {
				first = err.Error()
			}
			if err.Error() != first {
				t.Errorf("verdict depends on order:\n%s\n--\n%s", first, err)
			}
		}
	}
}
