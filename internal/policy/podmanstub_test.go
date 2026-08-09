package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const podmanStubGuest = PodmanStubDir + "/podman"

// TestPodmanStubStagedOnlyForADetectedShim is the positive/negative pair for
// the trigger CONTAINER-CLIENT.md §8 specifies: staging follows detection,
// not mere selection of a podman profile.
func TestPodmanStubStagedOnlyForADetectedShim(t *testing.T) {
	sel := []string{"@sys", "@cwd-rw", "@podman-socket"}

	withShim, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := withShim.Mounts[podmanStubGuest]; !ok {
		t.Error("a detected shim + a podman profile must stage the stub, and did not")
	}

	withoutShim, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := withoutShim.Mounts[podmanStubGuest]; ok {
		t.Error("no shim was detected (ctx.HostShims is empty), but the stub was staged anyway")
	}
}

// TestPodmanStubStagedOnlyWhenPodmanIsSelected: a detected shim with no
// podman profile selected must not stage anything — the stub is gated on
// p.Podman, not merely on what the host looks like, so a sandbox that never
// asked for containers never sees a new executable on its PATH.
func TestPodmanStubStagedOnlyWhenPodmanIsSelected(t *testing.T) {
	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw"}, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Podman != PodmanOff {
		t.Fatalf("test fixture error: expected PodmanOff, got %s", p.Podman)
	}
	if _, ok := p.Mounts[podmanStubGuest]; ok {
		t.Error("stub staged despite no podman profile being selected")
	}
}

// TestPodmanStubBeatsUsrBinPodmanButLosesToProfilePath pins the ordering
// CONTAINER-CLIENT.md §8 calls load-bearing: profile-contributed PATH
// entries, then the stub's directory, then the base PATH (which is where
// /usr/bin lives). The stub's whole job is beating /usr/bin/podman; it must
// still lose to an explicit human grant.
func TestPodmanStubBeatsUsrBinPodmanButLosesToProfilePath(t *testing.T) {
	// "cwd-ro" carries a `path` entry in the fixture registry (see
	// testRegistry's comment on it) — reused here rather than inventing a new
	// fixture profile.
	sel := []string{"@sys", "@cwd-rw", "@podman-socket", "cwd-ro"}
	p, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	path := p.Env["PATH"]
	profileDir := "/home/u/.local/bin"
	iProfile := strings.Index(path, profileDir)
	iStub := strings.Index(path, PodmanStubDir)
	iBase := strings.Index(path, "/usr/bin")

	if iProfile < 0 || iStub < 0 || iBase < 0 {
		t.Fatalf("PATH is missing an expected entry: %q", path)
	}
	if !(iProfile < iStub && iStub < iBase) {
		t.Errorf("PATH order wrong: got %q, want profile dir, then %s, then the base PATH",
			path, PodmanStubDir)
	}
}

// TestPodmanStubIsReadOnlyAndExecutable pins the two load-bearing properties
// from CONTAINER-CLIENT.md §8's constraint 1 at the Mount level: Access must
// be AccessRO (so BwrapFlags emits --ro-bind-data, unwritable from inside —
// see bwrap.go), and Perms must carry an executable bit, or the sandbox
// cannot run it at all.
func TestPodmanStubIsReadOnlyAndExecutable(t *testing.T) {
	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "@podman-socket"},
		testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	m, ok := p.Mounts[podmanStubGuest]
	if !ok {
		t.Fatal("stub not staged")
	}
	if m.Access != AccessRO {
		t.Errorf("stub Access = %s, want ro", m.Access)
	}
	if m.Perms == nil || *m.Perms&0o111 == 0 {
		t.Errorf("stub Perms = %v, want an executable bit set", m.Perms)
	}
	if !m.Authored {
		t.Error("stub must be Authored (snug's own write), or rejectMasking would treat it as a profile grant")
	}
}

// TestPodmanStubScriptRefusesToEmbedAHostileShimPath is podmanStubScript's own
// fail-closed guard: the ONE host-derived string in the generated script
// (the shim's resolved path) is interpolated only inside a quoted heredoc,
// and staging is refused outright — never silently truncated or escaped —
// when the path could break out of it.
func TestPodmanStubScriptRefusesToEmbedAHostileShimPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolved string
	}{
		{"a newline", "/usr/bin/distrobox-host-exec\nrm -rf /"},
		{"a line equal to the delimiter", podmanStubDelim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := podmanStubScript(HostShim{Name: "podman", Resolved: tc.resolved})
			if err == nil {
				t.Fatalf("podmanStubScript(%q) succeeded; it must refuse to stage", tc.resolved)
			}
		})
	}
}

// TestPodmanStubScriptIsWellFormedForAnOrdinaryPath is the positive control
// for the guard above: an ordinary resolved path must still produce a script,
// or the guard would be indistinguishable from staging being broken outright.
func TestPodmanStubScriptIsWellFormedForAnOrdinaryPath(t *testing.T) {
	script, err := podmanStubScript(HostShim{Name: "podman", Resolved: "/usr/bin/distrobox-host-exec"})
	if err != nil {
		t.Fatalf("podmanStubScript: %v", err)
	}
	if !strings.HasPrefix(script, "#!/bin/sh") {
		t.Error("stub is not a POSIX sh script")
	}
	if !strings.Contains(script, "/usr/bin/distrobox-host-exec") {
		t.Error("stub does not mention the detected shim path")
	}
	// The header COMMENT is allowed to say "it never sets DOCKER_HOST" (and
	// does); what must never appear is an actual assignment or a `-H` flag
	// baked into the exec line.
	if strings.Contains(script, "DOCKER_HOST=") || strings.Contains(script, "exec docker -H") {
		t.Error("stub sets DOCKER_HOST or -H itself; the red team constraint is that it never does " +
			"(CONTAINER-CLIENT.md §9) — it must inherit whatever snug already set")
	}
	if !strings.Contains(script, "exec docker \"$@\"") {
		t.Error("stub does not forward argv byte-for-byte to docker")
	}
}

// TestPodmanStubScriptIsSyntacticallyValidSh runs the generated stub through
// `sh -n` (parse only, nothing executes). The template is built with
// fmt.Sprintf and four substitutions; a stray %s, an unbalanced quote in a
// generated case arm, or a heredoc delimiter typo would all be invisible to
// every other test here, which only greps the text.
func TestPodmanStubScriptIsSyntacticallyValidSh(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no `sh` on this host to check syntax with")
	}
	script, err := podmanStubScript(HostShim{Name: "podman", Resolved: "/usr/bin/distrobox-host-exec"})
	if err != nil {
		t.Fatalf("podmanStubScript: %v", err)
	}
	path := filepath.Join(t.TempDir(), "podman")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(sh, "-n", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n rejects the generated stub: %v\n%s", err, out)
	}
}

// TestPodmanStubScriptDispatchesAtRuntime actually RUNS the generated script
// against a fake `docker` on PATH — not merely a grep of the text, which
// TestPodmanStubScriptIsWellFormedForAnOrdinaryPath already is. This is the
// one test in the package that executes anything; it earns the exception by
// checking the property the whole mechanism exists for: an allowlisted
// subcommand reaches "docker" with argv intact, and a refused one exits 125
// with a message that says "snug" and "stub" and never reaches "docker" at
// all.
func TestPodmanStubScriptDispatchesAtRuntime(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no `sh` on this host to run the stub with")
	}
	script, err := podmanStubScript(HostShim{Name: "podman", Resolved: "/usr/bin/distrobox-host-exec"})
	if err != nil {
		t.Fatalf("podmanStubScript: %v", err)
	}

	bin := t.TempDir()
	stub := filepath.Join(bin, "podman")
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	// A fake `docker` that just echoes its argv, so a test can tell "reached
	// docker with argv X" from "the stub refused it" without a real engine.
	fakeDocker := filepath.Join(bin, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\necho DOCKER_REACHED \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (out string, exitCode int) {
		cmd := exec.Command(sh, append([]string{stub}, args...)...)
		cmd.Env = []string{"PATH=" + bin}
		b, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running the stub: %v", err)
		}
		return string(b), code
	}

	t.Run("an allowlisted subcommand reaches docker with argv intact", func(t *testing.T) {
		out, code := run("run", "--rm", "alpine", "echo", "hi")
		if code != 0 {
			t.Fatalf("exit %d, want 0: %s", code, out)
		}
		if !strings.Contains(out, "DOCKER_REACHED run --rm alpine echo hi") {
			t.Errorf("argv not forwarded intact: %s", out)
		}
	})

	t.Run("a podman-only subcommand is refused with a specific reason and never reaches docker", func(t *testing.T) {
		out, code := run("pod", "ps")
		if code != 125 {
			t.Errorf("exit %d, want 125: %s", code, out)
		}
		if strings.Contains(out, "DOCKER_REACHED") {
			t.Error("reached the fake docker; podman-only subcommands must never forward")
		}
		if !strings.Contains(out, "snug:") || !strings.Contains(out, "stub") {
			t.Errorf("refusal message does not identify itself as snug's stub: %s", out)
		}
	})

	t.Run("an unrecognised subcommand is refused generically and never reaches docker", func(t *testing.T) {
		out, code := run("totally-made-up-subcommand")
		if code != 125 {
			t.Errorf("exit %d, want 125: %s", code, out)
		}
		if strings.Contains(out, "DOCKER_REACHED") {
			t.Error("reached the fake docker for an unknown subcommand")
		}
		if !strings.Contains(out, "snug:") || !strings.Contains(out, "stub") {
			t.Errorf("refusal message does not identify itself as snug's stub: %s", out)
		}
	})

	t.Run("a connection-shaping flag is refused wherever it appears in argv", func(t *testing.T) {
		out, code := run("run", "--remote", "--rm", "alpine")
		if code != 125 {
			t.Errorf("exit %d, want 125: %s", code, out)
		}
		if strings.Contains(out, "DOCKER_REACHED") {
			t.Error("reached the fake docker with a connection-shaping flag present")
		}
	})

	t.Run("without docker on PATH, the no-client message names the shim and exits 125", func(t *testing.T) {
		// The stub's own heredoc needs `cat` on PATH (an external binary, not a
		// shell builtin) even to print the "no docker" message — this fixture
		// supplies exactly that and nothing named "docker", rather than reusing
		// the real host PATH, which could legitimately have a real docker
		// installed and make this case pass for the wrong reason.
		noDocker := t.TempDir()
		catPath, err := exec.LookPath("cat")
		if err != nil {
			t.Skip("no `cat` on this host to build the fixture with")
		}
		if err := os.Symlink(catPath, filepath.Join(noDocker, "cat")); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(sh, stub, "ps")
		cmd.Env = []string{"PATH=" + noDocker}
		b, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running the stub: %v", err)
		}
		out := string(b)
		if code != 125 {
			t.Errorf("exit %d, want 125: %s", code, out)
		}
		if !strings.Contains(out, "/usr/bin/distrobox-host-exec") {
			t.Errorf("message does not name the detected shim path: %s", out)
		}
		if !strings.Contains(out, "snug:") || !strings.Contains(out, "stub") {
			t.Errorf("message does not identify itself as snug's stub: %s", out)
		}
	})
}
