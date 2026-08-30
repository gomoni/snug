//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDryRunLeavesNoRunDirectoryOrSocket is issue #21 end to end, on the real
// binary: `snug --dry-run -p <identity profile> <dir>` must leave
// $XDG_RUNTIME_DIR untouched — no snug/run-<pid>/ directory, no lock file, no
// ssh-agent.sock — while still SHOWING the socket path it would bind.
//
// Before the fix, startIdentity opened the run directory and bound the proxy
// socket for real, on a code path whose whole contract is that it starts
// nothing. The measurement in the issue is the piped case
// (`snug --dry-run ... | head`, SIGPIPE): the deferred cleanup never runs, so
// the directory and the socket are left on the host. This test runs the piped
// shape as well as the ordinary one, because they leak differently — the
// ordinary one leaked the directory, the piped one the socket too.
//
// THE POSITIVE CONTROL IS A REAL RUN, not an assertion about the fixture: a
// live sandbox with the same profile MUST produce the run directory and the
// socket under the same $XDG_RUNTIME_DIR. Without it, "nothing appeared" is
// equally true of a snug that ignored XDG_RUNTIME_DIR, a profile with no
// identity, and a binary that exited before reaching startIdentity at all.
func TestDryRunLeavesNoRunDirectoryOrSocket(t *testing.T) {
	budget(t, 90*time.Second)
	pub, agent := sshAgentAndKey(t)
	proj, _ := target(t)

	// A short path on purpose: this directory holds a unix socket in the
	// control below, and sun_path is 108 bytes. t.TempDir() names the
	// directory after the test, which alone is 40 of them.
	runtimeDir, err := os.MkdirTemp("", "snugrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })

	profile := "[profile.pinned]\n" +
		"description = \"one throwaway key\"\n" +
		"[profile.pinned.identity]\n" +
		"ssh_mode = \"agent-proxy\"\n" +
		"ssh_key = \"" + pub + "\"\n"
	env := writeProfile(t, profile, "SSH_AUTH_SOCK="+agent, "XDG_RUNTIME_DIR="+runtimeDir)

	out, code := cli(t, env, "--dry-run", "-p", "pinned", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	// CONTROL: the identity arm actually ran. A dry run that failed before
	// reaching it would leave the runtime directory empty too, and every
	// assertion below would pass on it.
	if !strings.Contains(out, "ssh-agent.sock") {
		t.Fatalf("--dry-run never named the agent socket, so it did not reach the identity "+
			"machinery this test is about:\n%s", out)
	}
	if left := entriesUnder(t, runtimeDir); len(left) != 0 {
		t.Errorf("`snug --dry-run` created %v under $XDG_RUNTIME_DIR (issue #21). A dry run "+
			"starts nothing:\n%s", left, out)
	}

	// The piped shape from the issue: SIGPIPE kills snug mid-screen, so no
	// deferred cleanup runs and whatever was created stays created.
	pipedOut := pipedThroughHead(t, env, "--dry-run", "-p", "pinned", proj)
	if left := entriesUnder(t, runtimeDir); len(left) != 0 {
		t.Errorf("`snug --dry-run ... | head` left %v under $XDG_RUNTIME_DIR — the SIGPIPE "+
			"case from issue #21, where no cleanup runs at all:\n%s", left, pipedOut)
	}

	// AND THE SAME TWO SHAPES FOR --explain (issue #541). It is a second
	// renderer of the same resolved policy and makes the same promise in its
	// own first line, so it reaches startIdentity by the same path and would
	// leak by the same mechanism. The arms live in THIS test rather than in
	// one of their own because the positive control below is what makes any of
	// these assertions mean anything, and it costs a real sandbox: a separate
	// test would either duplicate that cost or go without it and assert
	// "nothing appeared" about a binary that never looked.
	explainOut, code := cli(t, env, "--explain", "-p", "pinned", proj)
	if code != 0 {
		t.Fatalf("snug --explain exited %d:\n%s", code, explainOut)
	}
	// CONTROL for this arm: --explain does not name the agent socket (it says
	// what the sandbox IS, not which paths it binds), so the evidence that it
	// resolved a real policy is that it rendered the screen at all.
	if !strings.Contains(explainOut, "WHAT IS NOT IN HERE") {
		t.Fatalf("--explain did not render its screen, so the assertions below are about a "+
			"run that stopped early:\n%s", explainOut)
	}
	if left := entriesUnder(t, runtimeDir); len(left) != 0 {
		t.Errorf("`snug --explain` created %v under $XDG_RUNTIME_DIR. It promises the same "+
			"\"nothing was started\" --dry-run does (issue #541):\n%s", left, explainOut)
	}
	pipedExplain := pipedThroughHead(t, env, "--explain", "-p", "pinned", proj)
	if left := entriesUnder(t, runtimeDir); len(left) != 0 {
		t.Errorf("`snug --explain ... | head` left %v under $XDG_RUNTIME_DIR — the SIGPIPE "+
			"case, where no cleanup runs at all:\n%s", left, pipedExplain)
	}

	// POSITIVE CONTROL: the same profile on a REAL run does create both.
	requireSandbox(t)
	ready := filepath.Join(proj, "READY")
	bg := startBackgroundSnug(t, env, proj,
		"touch "+shQuote(ready)+"; while true; do sleep 1; done", "-p", "pinned")
	if err := waitForFile(ready, 60*time.Second); err != nil {
		t.Fatalf("control: the real run never signalled readiness (%v); its output so far:\n%s",
			err, bg.output())
	}
	live := entriesUnder(t, runtimeDir)
	if len(live) == 0 {
		t.Fatalf("control: a REAL run created nothing under $XDG_RUNTIME_DIR either, so the "+
			"assertions above cannot tell a dry run that starts nothing from a snug that "+
			"never looked at this directory:\n%s", bg.output())
	}
	if !containsSuffix(live, "ssh-agent.sock") {
		t.Errorf("control: a real run bound no ssh-agent.sock (entries: %v), so \"the dry run "+
			"bound none\" is not evidence of anything:\n%s", live, bg.output())
	}
}

// pipedThroughHead runs snug with its stdout on a pipe that closes after a few
// lines, which is what makes the SIGPIPE case reproducible: snug dies partway
// through the screen and none of its deferred cleanups run.
func pipedThroughHead(t *testing.T, env []string, args ...string) string {
	t.Helper()
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, shQuote(snugBin))
	for _, a := range args {
		quoted = append(quoted, shQuote(a))
	}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", strings.Join(quoted, " ")+" | head -3")
	cmd.Env = env
	out, _ := cmd.CombinedOutput() // a non-zero status IS the case under test
	return string(out)
}

func entriesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			out = append(out, strings.TrimPrefix(path, dir+"/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return out
}

func containsSuffix(entries []string, suffix string) bool {
	for _, e := range entries {
		if strings.HasSuffix(e, suffix) {
			return true
		}
	}
	return false
}
