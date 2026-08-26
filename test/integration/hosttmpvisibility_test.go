//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── issue #87: the session mesh's LOCAL half is closed by a structural fact ─
//
// Claude Code's cross-session messaging on one machine is unix sockets under
// the host's real /tmp/cc-socks/, not the API. Inside snug /tmp is always
// snug's own tmpfs (resolve.go yields a private KindTmpfs mount there
// unconditionally), and @tmp-shared does not reach the host's real /tmp
// either: prepareHostTmpDir (internal/cli/tmpdir.go) ALLOCATES a per-sandbox
// directory under os.TempDir() and binds THAT at /tmp — it never binds the
// host's /tmp itself. This test would catch either arm ever binding the
// host's real /tmp directly, which is the one change that would let a
// sandboxed payload reach another session's socket over the local channel
// #87 measured.
//
// The decoy is a plain file this test creates itself, directly in the host's
// real /tmp, named with this process's own pid plus a random suffix so it
// cannot collide with anything already there. It is never placed under, read
// from, or listed against /tmp/cc-socks/ — that directory holds LIVE Claude
// Code session sockets this test must not touch.
func TestHostsRealTmpIsNotVisibleInsideTheSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)

	// target() roots its project under os.TempDir(), which IS the host's
	// real /tmp in this suite's normal environment — and @tmp-shared grants
	// the whole of guest /tmp, so a target nested inside it would be
	// self-masking (rejectMasking refuses it) before this test ever reaches
	// the sandbox. Rooting outside /tmp sidesteps that and keeps the
	// assertion about the decoy, not about an unrelated grant conflict.
	proj := tmpVisibilityTarget(t)

	decoy, err := os.CreateTemp("/tmp", fmt.Sprintf("snug-87-decoy-%d-*", os.Getpid()))
	if err != nil {
		t.Fatalf("could not create the host-side decoy in the host's real /tmp: %v", err)
	}
	decoyPath := decoy.Name()
	decoy.Close()
	t.Cleanup(func() { _ = os.Remove(decoyPath) })
	decoyName := filepath.Base(decoyPath)

	// POSITIVE CONTROL, host side: the decoy really is sitting in the host's
	// real /tmp. Without this, "absent inside the sandbox" could just mean
	// the decoy was never created where this test claims.
	if _, err := os.Stat(decoyPath); err != nil {
		t.Fatalf("precondition: the decoy is not present on the host at %s (%v), so the "+
			"assertion below would prove nothing", decoyPath, err)
	}

	script := fmt.Sprintf(`
echo TMP_LS=$(ls -a /tmp | tr '\n' ',')
touch /tmp/sandbox-marker
echo WRITE_RC=$?
ls /tmp | grep -q '^sandbox-marker$' && echo MARKER_VISIBLE
if [ -e /tmp/%s ]; then echo DECOY_FOUND; else echo DECOY_ABSENT; fi
echo MARKER_DONE`, decoyName)

	for _, arm := range []struct {
		name string
		args []string
	}{
		// The plain-tmpfs case: no @tmp-shared, so /tmp is the base
		// topology's private KindTmpfs mount with nothing bound over it.
		{"no-tmp-shared", nil},
		// The arm the issue names explicitly: @tmp-shared replaces /tmp with
		// prepareHostTmpDir's ALLOCATED per-sandbox directory, which is the
		// one that would be a problem if it ever bound the host's real /tmp
		// instead.
		{"tmp-shared", []string{"-p", "@tmp-shared"}},
	} {
		t.Run(arm.name, func(t *testing.T) {
			r := run(t, arm.args, proj, script).mustRun(t)

			// POSITIVE CONTROL, inside the sandbox: /tmp is reachable,
			// listable and writable in THIS SAME run, so "decoy absent"
			// below cannot be explained by /tmp not existing, ls failing, or
			// the sandbox never actually mounting anything there.
			if !strings.Contains(r.out, "WRITE_RC=0") {
				t.Fatalf("control: writing to /tmp inside the sandbox failed, so the decoy "+
					"check below proves nothing:\n%s", r.out)
			}
			if !strings.Contains(r.out, "MARKER_VISIBLE") {
				t.Fatalf("control: a file this run wrote to /tmp is not visible via `ls /tmp` "+
					"in the same run, so the decoy check below proves nothing:\n%s", r.out)
			}

			if strings.Contains(r.out, "DECOY_FOUND") {
				t.Errorf("the host's real /tmp decoy is VISIBLE inside the sandbox's /tmp — "+
					"the host's real /tmp is no longer private, which is the local half of "+
					"issue #87 (Claude Code's cross-session unix sockets live in the host's "+
					"real /tmp/cc-socks/):\n%s", r.out)
			}
			if !strings.Contains(r.out, "DECOY_ABSENT") {
				t.Errorf("neither DECOY_FOUND nor DECOY_ABSENT appeared — the payload's probe "+
					"did not run as expected:\n%s", r.out)
			}
		})
	}
}

// tmpVisibilityTarget builds target()'s exact root/proj/{sibling,sub} shape,
// rooted OUTSIDE the host's /tmp (unlike target(), which sits under
// os.TempDir()). @tmp-shared grants the whole of guest /tmp, so a target
// nested inside it self-masks; this keeps the two independent.
//
// $HOME rather than "." because "." is this package's directory inside the
// repository: t.Cleanup covers a failure and a t.Fatal, but not a SIGKILL,
// and the residue of that would land in `git status` (issue #425's littering
// complaint). $HOME is not a path any arm here grants — @home is not selected
// — so it masks nothing either.
func tmpVisibilityTarget(t *testing.T) (proj string) {
	t.Helper()
	base := os.Getenv("HOME")
	if base == "" {
		t.Skip("no $HOME to root a target outside the host's /tmp under")
	}
	// $HOME is only usable here if it is OUTSIDE /tmp. A scratch HOME under
	// /tmp (mktemp's default, and a plausible CI shape) puts the target inside
	// the very tree @tmp-shared grants, and the run then aborts with exit 77 —
	// "@tmp-shared binds /tmp, which is an ancestor of your home" — which is
	// rejectMasking doing its job on an environment artifact, not this test
	// finding anything. Skip with the reason rather than fail: a red-team round
	// hit this by pinning HOME under /tmp and the exit 77 read as a defect.
	if abs, err := filepath.Abs(base); err == nil {
		if rel, err := filepath.Rel(os.TempDir(), abs); err == nil && !strings.HasPrefix(rel, "..") {
			t.Skipf("$HOME (%s) is inside %s, so a target rooted there would sit under "+
				"@tmp-shared's own /tmp grant; this test needs a HOME outside it", abs, os.TempDir())
		}
	}
	root, err := os.MkdirTemp(base, "snug-87-target-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}

	proj = filepath.Join(root, "proj", "sub")
	if err := os.MkdirAll(filepath.Join(root, "proj", "sibling"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	return proj
}
