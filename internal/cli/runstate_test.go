package cli

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// openTestRoot and writeTestFile are the minimal *os.Root plumbing
// readRunStateFrom needs, kept local to this file rather than reused from
// runtimedir_test.go: those tests exercise runtimeDir's OWN
// ownership/symlink refusals, and duplicating a two-line helper here is
// cheaper than coupling this file's tests to that one's fixtures.
func openTestRoot(t *testing.T, dir string) (*os.Root, error) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return os.OpenRoot(dir)
}

func writeTestFile(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// TestStateFileCarriesNoCommandNoArgvAndNoExecutablePath is a mechanical
// sweep over the marshalled JSON keys, not an allowlist of the ones a human
// remembers — the design's own §6.2 demands exactly this shape of test
// rather than one that lists "command" and "argv" by name and stops.
func TestStateFileCarriesNoCommandNoArgvAndNoExecutablePath(t *testing.T) {
	st := runState{
		Schema: runStateSchema,
		Target: "/home/u/proj",
		Chdir:  "/home/u/proj",
		Sandbox: runStateSandbox{
			InitPID: 123, InitStarttime: 456,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		Seccomp: runStateSeccomp{State: "active", Digest: "sha256:aa"},
		Env:     [][2]string{{"HOME", "/home/u"}, {"SHELL", "/bin/bash"}},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"command", "argv", "argv0", "exe", "executable", "cmd"}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch vv := v.(type) {
		case map[string]any:
			for k, val := range vv {
				for _, f := range forbidden {
					if k == f {
						t.Errorf("state.json carries forbidden key %q at %s", k, path)
					}
				}
				walk(val, path+"."+k)
			}
		case []any:
			for i, val := range vv {
				walk(val, path)
				_ = i
			}
		}
	}
	walk(generic, "$")

	// The one bounded exception (§8.4): SHELL is allowed to appear as an
	// ordinary env pair, because it is data the run's OWN policy authored,
	// not a channel this file invents.
	found := false
	for _, kv := range st.Env {
		if kv[0] == "SHELL" {
			found = true
		}
	}
	if !found {
		t.Fatal("test setup is wrong: expected SHELL in Env")
	}
}

func TestReadRunStateFromRefusesUnknownSchema(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	write := func(name string, v any) {
		data, _ := json.Marshal(v)
		if err := writeTestFile(root, name, data); err != nil {
			t.Fatal(err)
		}
	}
	write("state.json", map[string]any{"schema": 99})

	if _, err := readRunStateFrom(root); err == nil {
		t.Fatal("expected a schema mismatch to be refused")
	}
}

func TestReadRunStateFromRefusesMissingNamespace(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	st := runState{
		Schema: runStateSchema,
		Sandbox: runStateSandbox{
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2}, // missing net/ipc/uts/cgroup
		},
	}
	data, _ := json.Marshal(st)
	if err := writeTestFile(root, "state.json", data); err != nil {
		t.Fatal(err)
	}

	if _, err := readRunStateFrom(root); err == nil {
		t.Fatal("expected a missing namespace id to be refused")
	}
}

func TestReadRunStateFromAcceptsAWellFormedFile(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	st := runState{
		Schema: runStateSchema,
		Target: "/x",
		Chdir:  "/x",
		Sandbox: runStateSandbox{
			InitPID: 1, InitStarttime: 2,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		Seccomp: runStateSeccomp{State: "none"},
	}
	data, _ := json.Marshal(st)
	if err := writeTestFile(root, "state.json", data); err != nil {
		t.Fatal(err)
	}

	got, err := readRunStateFrom(root)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got.Target != "/x" || got.Sandbox.InitPID != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestFilterDigestConsistent is the shape assertion for the sha256:<hex>
// convention shared between sandbox.FilterDigest and this package's reader.
func TestFilterDigestConsistent(t *testing.T) {
	if !filterDigestConsistent("sha256:" + zeros(64)) {
		t.Fatal("expected a well-formed digest to pass")
	}
	for _, bad := range []string{"", "sha256:", "md5:" + zeros(32), "sha256:zz"} {
		if filterDigestConsistent(bad) {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

func zeros(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

// TestSnugAuthoredEnvPairsExcludesAProfilePassedVariable is the test that
// keeps a token off disk: a profile-authored (non-VerbSnug) variable must
// never appear in state.json's env list, only names snug itself authored.
func TestSnugAuthoredEnvPairsExcludesAProfilePassedVariable(t *testing.T) {
	pol := &policy.Policy{
		Env: map[string]policy.EnvVar{},
	}
	pol.AuthorEnv("HOME", "/home/u")
	// Simulate a profile-authored variable the way the resolver would,
	// without needing a full Resolve: addEnvEntry is unexported, but a
	// profile-shaped entry has Verb != VerbSnug, and EnvValue/EnvPairs only
	// care about Present() — reach it through the public surface instead:
	// there is no public writer for a non-snug verb, which is exactly
	// invariant 2's point (a profile cannot write these names at all in the
	// wild), so this test constructs the struct directly to prove the FILTER
	// itself is verb-aware rather than name-aware.
	pol.Env["SOME_TOKEN"] = policy.EnvVar{
		Name:    "SOME_TOKEN",
		Entries: []policy.EnvEntry{{Value: "secret", Verb: policy.VerbSet, From: []string{"@some-profile"}}},
	}

	pairs := snugAuthoredEnvPairs(pol)
	for _, kv := range pairs {
		if kv[0] == "SOME_TOKEN" {
			t.Fatal("a profile-authored variable leaked into the snug-authored env record")
		}
	}
	foundHome := false
	for _, kv := range pairs {
		if kv[0] == "HOME" {
			foundHome = true
		}
	}
	if !foundHome {
		t.Fatal("expected the snug-authored HOME entry to be present")
	}
}
