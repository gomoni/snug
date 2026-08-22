package engine

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// describeWhenVisible polls describe() until the probe's argv is readable.
//
// Not politeness: the kernel sets mm->arg_start only after close-on-exec fires,
// so for a real window after Start a live process reads back a ZERO-BYTE
// cmdline — measured empty 2965/3000 immediately after exec.Cmd.Start (issue
// #317), which is the same window ownedPIDs is deliberately blind to (#318).
// Without this wait the assertions below run against "" and pass while
// measuring nothing.
func describeWhenVisible(t *testing.T, pid int, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := describe([]int{pid})
		if strings.Contains(got, want) {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// THE TEARDOWN WARNING IS A SCREEN, AND SINCE THE MATCHER WAS FIXED IT RENDERS
// TEXT THE PAYLOAD CHOSE.
//
// internal/cli sweeps its own screens for this (TestNoSnugScreenEmitsARawControl-
// Character, screensinks_test.go) and that sweep does not reach this package —
// which is why describe() could print a raw command line for as long as it did.
// The assertion is the same one, made where the sink lives, so a message added
// to this file tomorrow is covered without either being touched.
//
// The match is on the GUEST socket path, a string a PAYLOAD can put in its own
// argv, and payload processes are visible in the host /proc. So the process
// whose command line lands in this warning may be one that WANTS the human to
// misread the line telling them what to kill -9.
func TestTheTeardownWarningEscapesTheCommandLinesItPrints(t *testing.T) {
	const marker = "OLR-DEGROF"

	// A real process with a real poisoned argv, read back through /proc the way
	// describe() reads it. Not a synthesised string: the bug is in what the
	// kernel hands back, and a fixture would prove nothing about that.
	//
	// ESC-[1A-CR erases the line above; U+009B is the 8-bit CSI, invisible to an
	// ASCII-only predicate; U+202E reverses the rest of the line, adding no row
	// and erasing none. All three are what internal/cli's sweep uses.
	poison := "\x1b[1A\r  1  (nothing to kill here)\u009b1A\u202e" + marker

	// The poison goes in ARGV[0], not in an operand, and that is the only
	// spelling that works here: `sleep 60 <poison>` makes sleep exit with
	// "invalid time interval" before anything can read its /proc entry, and
	// `sh -c 'sleep 60' <poison>` is exec-optimised by the shell, which
	// replaces the command line and silently loses the marker (the harness
	// caveat on issue #344). argv[0] is not parsed as an operand, so sleep
	// sees exactly one argument and lives.
	cmd := exec.Command("sleep")
	cmd.Args = []string{poison, "60"}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a probe process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	got := describeWhenVisible(t, cmd.Process.Pid, marker)

	// The control FIRST: a test that measures nothing looks exactly like a test
	// that passes. If the argv never reached the screen there is no sink here.
	if !strings.Contains(got, marker) {
		t.Fatalf("the probe's command line never reached describe(), so this test "+
			"measures nothing: %q", got)
	}
	if i := strings.IndexFunc(got, func(r rune) bool {
		return r != '\n' && policy.IsForgingRune(r)
	}); i >= 0 {
		t.Errorf("describe() rendered %q raw — a payload-chosen command line reached "+
			"the terminal unescaped: %q", []rune(got[i:])[0], got)
	}

	// CONTROL: an ordinary command line renders as itself. A describe() that
	// quoted everything would pass the assertion above and make the warning
	// unreadable, which is a worse failure than the raw escape — the whole point
	// of the line is that a human can act on it.
	plain := exec.Command("sleep")
	plain.Args = []string{"snug-plain-probe", "60"}
	if err := plain.Start(); err != nil {
		t.Skipf("cannot start a probe process: %v", err)
	}
	t.Cleanup(func() {
		_ = plain.Process.Kill()
		_, _ = plain.Process.Wait()
	})
	if out := describeWhenVisible(t, plain.Process.Pid, "snug-plain-probe"); !strings.Contains(out, "snug-plain-probe 60") {
		t.Errorf("an ordinary command line did not render as itself: %q", out)
	}
}
