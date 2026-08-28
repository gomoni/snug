package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// engineBindsPolicy is engineViewPolicy plus one USER profile declaring an
// `engine_binds` entry inside the target — the shape issue #376 exists for, and
// a shape no builtin can produce, because snug ships no profile that declares
// one. It is injected into the real builtin registry rather than hand-built, so
// the TOML grammar, Resolve and G1-G5 are all really on the path.
func engineBindsPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["work"] = &policy.Profile{
		Name:        "work",
		EngineBinds: []string{"{target}/data"},
		Source:      "(test)",
	}
	env := newEnvFakeEnv()
	env.dirs["/home/u/proj/sub/data"] = true

	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "work"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.EngineBinds) != 1 {
		t.Fatalf("the fixture resolved %d engine bind(s), want 1", len(p.EngineBinds))
	}
	return p
}

// TestGoldenEngineViewDeclaredBinds is the --dry-run half of issue #376, and it
// is the screen the ticket's own question 4 asks for: "a mount the payload asked
// for is a mount a human should be able to see before it exists."
//
// The row is produced by describeGrafts with no new rendering code at all — a
// declared bind is an ordinary KindGraft of a host path, so it renders as
// `graft-rw`, with its host path on the `from` line and its abuse sentence
// underneath. What the golden is here to catch is a change to any of those
// three: a declared bind that stops naming its source, stops naming the
// profile that declared it, or stops saying what a container could do with it.
func TestGoldenEngineViewDeclaredBinds(t *testing.T) {
	p := engineBindsPolicy(t)
	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatal(err)
	}
	if err := installEngineBindGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatal(err)
	}
	rep := Report{TmpfsSizeBytes: p.TmpfsSizeBytes, Grafts: sortedGrafts(p)}
	rep.GraftTmpfsSizeBytes = graftTmpfsSizeBytes(rep.Grafts, rep.TmpfsSizeBytes)
	got := captureFile(t, func(f io.Writer) { describeGrafts(f, rep, p) })

	path := filepath.Join("testdata", "engineview.enginebinds.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the ENGINE VIEW block for a declared engine bind changed — this row is the only "+
			"place a human learns, before the sandbox starts, that a container may mount one of "+
			"their host directories.\n--- got\n%s\n--- want\n%s", got, want)
	}

	// Asserted directly as well as pinned, because a golden regenerated
	// without being read would carry any of these away silently.
	for _, want := range []string{
		policy.EngineBindsDir + "/data", // the destination
		"/home/u/proj/sub/data",         // the host tree it clones
		"graft-rw",                      // the access, and which namespace it is in
		"work",                          // the profile that declared it, via the Why
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the ENGINE VIEW row for a declared bind does not contain %q:\n%s", want, got)
		}
	}
}

// TestDeclaredBindGraftIsInstalledBeforeTheDryRunBranch is the coupling that
// makes the golden above true of a real run rather than of this test.
//
// startContainers installs the engine's own mounts and then the declared binds,
// BOTH before it returns for a dry run — the gap issue #252 was filed for was
// exactly this, with the host-tree grafts recorded a hundred lines after the
// --dry-run return and therefore never printed. A sweep of the source is what
// catches the ordering being reversed, because a reversed version still passes
// every test that resolves a policy by hand.
func TestDeclaredBindGraftIsInstalledBeforeTheDryRunBranch(t *testing.T) {
	src, err := os.ReadFile("container.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	install := strings.Index(body, "installEngineBindGrafts(env, pol)")
	if install < 0 {
		t.Fatal("startContainers no longer calls installEngineBindGrafts, so a declared bind " +
			"never reaches p.Grafts and neither the engine nor --dry-run sees it")
	}
	branch := strings.Index(body, "if dryRun {")
	if branch < 0 {
		t.Fatal("startContainers' --dry-run branch is not where this test expects it; re-read " +
			"the function before trusting the position assertion below")
	}
	if install > branch {
		t.Error("installEngineBindGrafts runs AFTER the --dry-run branch, so --dry-run renders " +
			"fewer mounts than the run performs — the whole of issue #252, one grant later")
	}
}
