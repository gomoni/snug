//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakePodmanNoise strips fakepodman's own "FAKEPODMAN-LISTENING ..." line,
// which testdata/fakepodman's own doc comment names as a debugging aid for
// gate_test.go that nothing asserts on: it is written to the STAND-IN's own
// stderr, which — like a real engine's (internal/engine/reaper.go sets
// cmd.Stderr = os.Stderr for exactly this reason) — is inherited from P0's own
// stderr. It is the fake engine talking about itself, never snug, so a test
// about what SNUG writes has to read past it.
func fakePodmanNoise(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "FAKEPODMAN-LISTENING") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// runSplit runs snug with stdout and stderr captured SEPARATELY — cli() and
// run() deliberately use CombinedOutput, which cannot tell "snug said nothing
// on stderr" from "snug said something on stdout instead".
func runSplit(t *testing.T, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, args...)
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("snug %s did not finish within %s:\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), cmdTimeout, outBuf.String(), errBuf.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running snug %s: %v\nstdout:\n%s\nstderr:\n%s",
				strings.Join(args, " "), err, outBuf.String(), errBuf.String())
		}
		return outBuf.String(), errBuf.String(), ee.ExitCode()
	}
	return outBuf.String(), errBuf.String(), 0
}

// TestQuietRunsAreQuiet is the deleted VERIFY.md's "starts nothing" promise
// (§2a) read off stderr rather than off prose: an ordinary
// `snug -p @podman-socket <dir> -- /bin/true`, with no -v, writes NOTHING to
// stderr, and --dry-run -p @podman-socket renders no NOTES block at all while
// the same real run under -v does. notes.go's own doc comment states why the
// two disagree rather than one of them being a bug: startContainers returns
// at its --dry-run branch before warnAboutPodmanClient and before the
// /etc/resolv.conf probe, because those belong to an engine --dry-run never
// starts — so a note only the REAL path reaches has nothing to render on the
// dry-run screen, and "NOTES (these also print on a real run under -v)" would
// be a lie if it appeared there anyway.
func TestQuietRunsAreQuiet(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	fp := fakePodmanBin(t)
	writeFakePodmanConfig(t, fp, 0, 200)
	env := append(baseEnv(), "SNUG_PODMAN="+fp,
		// SNUG_PODMAN_ROOT is what the toolchain graft is built from since
		// Tier C: the engine's view is derived from the sandbox's, so a
		// binary in a temp directory reaches it only through a graft. The
		// fake engine is self-contained, so its own directory is the whole
		// toolchain.
		"SNUG_PODMAN_ROOT="+filepath.Dir(fp))

	// 1. THE NEGATIVE. No -v.
	_, stderr, code := runSplit(t, env, "-p", "@podman-socket", proj, "--", "/bin/true")
	if code != 0 {
		t.Fatalf("snug -p @podman-socket <dir> -- /bin/true exited %d, want 0:\nstderr:\n%s",
			code, stderr)
	}
	if got := strings.TrimSpace(fakePodmanNoise(stderr)); got != "" {
		t.Errorf("a quiet run without -v wrote to stderr:\n%s", got)
	}

	// 2. THE POSITIVE CONTROL for (1): the SAME run, differing only by -v,
	// really does have something to say — a run that is silent whether or not
	// -v is given would make (1) pass for a reason that has nothing to do
	// with quietness.
	_, vStderr, vCode := runSplit(t, env, "-v", "-p", "@podman-socket", proj, "--", "/bin/true")
	if vCode != 0 {
		t.Fatalf("snug -v -p @podman-socket <dir> -- /bin/true exited %d, want 0:\nstderr:\n%s",
			vCode, vStderr)
	}
	if got := strings.TrimSpace(fakePodmanNoise(vStderr)); got == "" {
		t.Fatalf("PRECONDITION: -v produced no output at all, so (1)'s silence proves nothing:\n"+
			"(raw stderr, before filtering the fake engine's own line: %q)", vStderr)
	}

	// 3. --dry-run renders no NOTES block for this same selection.
	dry, dryCode := cli(t, env, "--dry-run", "-p", "@podman-socket", proj, "--", "/bin/true")
	if dryCode != 0 {
		t.Fatalf("snug --dry-run -p @podman-socket <dir> exited %d, want 0:\n%s", dryCode, dry)
	}
	if strings.Contains(dry, "NOTES") {
		t.Errorf("--dry-run -p @podman-socket rendered a NOTES block; notes.go's own doc "+
			"comment says this selection should render none because the notes that fire "+
			"under -v belong to code startContainers's --dry-run branch never reaches:\n%s", dry)
	}
}
