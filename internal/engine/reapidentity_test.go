package engine

import (
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/gomoni/snug/internal/policy"
)

// TestEngineArgvNamesOnlyGuestPaths is what closes reap.go's wrapper case, and
// it is the half of that argument a test can hold.
//
// Since Tier C the engine is exec'd entirely in its DERIVED view: Spec resolves
// --root, --runroot and the socket through Engine.guestPath, which refuses a
// path no graft exposes. So every path in the argv is under /snug, and those
// paths resolve nowhere else — an engine that exec'd on the host could not open
// its store or bind its socket, so a host-forwarding wrapper cannot start one
// at all.
//
// If this ever fails, reap.go's opening paragraph is wrong again and the
// wrapper case is reachable: say so there, and #344's matcher has a second
// shape to handle.
func TestEngineArgvNamesOnlyGuestPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	// noSignaturePolicy is "this host configured none" — NOT nil, which Spec
	// refuses outright as a caller that skipped ProjectHostSignaturePolicy
	// (#307). It is the neutral input here rather than a claim this test
	// measures: the signature policy reaches the engine as a generated
	// policy.json under its own $HOME, and on podman 5.8.4 --signature-policy
	// is a hidden flag on `pull` and `push` only — absent from `system
	// service`, which is the subcommand this test sweeps — so no value of it
	// puts a path in this argv.
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}),
		"/usr/bin/podman", []string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t))
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}

	// POSITIVE CONTROL: the argv really carries paths. Without this the loop
	// below passes on an empty or path-free argv, which is the shape of a Spec
	// that stopped resolving anything.
	pathy := 0
	for _, a := range spec.Argv {
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "unix://") {
			pathy++
		}
	}
	if pathy < 3 {
		t.Fatalf("the argv carries %d path-shaped elements (%v), want at least three "+
			"(--root, --runroot, the socket) — this test measures nothing otherwise",
			pathy, spec.Argv)
	}

	for _, a := range spec.Argv {
		p := strings.TrimPrefix(a, "unix://")
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if !strings.HasPrefix(p, policy.SnugDir+"/") {
			t.Errorf("the engine's argv names %q, which is not under %s.\n"+
				"       Every path the engine is exec'd with must resolve in its DERIVED view "+
				"only. A host path here means an engine that exec'd outside that view could "+
				"start, which is the wrapper case reap.go's opening paragraph says is closed.",
				a, policy.SnugDir)
		}
	}

	// And the other side of the same fact, which is #344: Sock stays the HOST
	// path, because P1 waits for it and the proxy dials it. The two names for
	// one inode are the point of a graft.
	if strings.HasPrefix(spec.Sock, policy.SnugDir+"/") {
		t.Errorf("spec.Sock is %q, a guest path. P1's waitForSocket and the container proxy "+
			"both dial it from the HOST side, where /snug does not exist.", spec.Sock)
	}
	if spec.Sock != e.sock {
		t.Errorf("spec.Sock is %q, want the host socket %q", spec.Sock, e.sock)
	}
}

// TestDescribeSanitisesACommandLine is #344's other half, and the one that does
// not wait on a matcher decision.
//
// describe renders a matched process's command line onto the user's terminal.
// A command line is not snug's text — any process on the host can put anything
// in its own argv — so an ESC there forges or erases a line of snug's own
// output, which is the hazard TestNoSnugScreenEmitsARawControlCharacter exists
// for one package over. That sweep drives the --dry-run screen and does not
// reach internal/engine.
func TestDescribeSanitisesACommandLine(t *testing.T) {
	// The cursor-up-and-overwrite spelling: what a terminal does with this is
	// erase the line snug printed above it.
	const forged = "FORGED-BY-A-CMDLINE"
	// The argv goes in $0, and the -c string is MULTI-COMMAND on purpose: a
	// shell given a single command exec-optimises it and the crafted argv
	// disappears from the cmdline, so the decoy would prove nothing (#344's
	// own harness note). It must also STAY ALIVE — a decoy that exits is a
	// zombie whose cmdline reads back empty, which is what the first draft of
	// this test measured.
	cmd := exec.Command("/bin/sh", "-c", "sleep 30; :", "30\x1b[1A\r  "+forged)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a decoy process here: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// The cmdline reads back EMPTY for a window after execve — the kernel sets
	// mm->arg_start only once close-on-exec has fired, measured at 2965/3000
	// immediately after exec.Cmd.Start (#317/#318). This test's own positive
	// control caught exactly that on its first run, so wait for the argv to
	// exist rather than racing it.
	var out string
	deadline := time.Now().Add(3 * time.Second)
	for {
		out = describe([]int{cmd.Process.Pid})
		if strings.Contains(out, "sleep") || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// POSITIVE CONTROL: the decoy's argv really reached the rendering. Without
	// it, a describe that read nothing at all passes every assertion below.
	if !strings.Contains(out, "sleep") {
		t.Fatalf("the decoy's command line is not in the output, so this test measures "+
			"nothing:\n%s", out)
	}

	for _, r := range out {
		if r == '\n' || r == '\t' {
			continue // describe's own layout
		}
		if unicode.IsControl(r) || policy.IsForgingRune(r) {
			t.Errorf("describe emitted %q raw, from a command line snug does not own:\n%s",
				r, out)
			break
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("describe emitted a raw ESC:\n%q", out)
	}
}
