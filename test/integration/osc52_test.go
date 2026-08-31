//go:build integration

package integration

// osc52_test.go pins issue #528 (R10 of the pseudo-filesystem audit): a payload
// writing terminal escape sequences — OSC 52 sets the operator's CLIPBOARD —
// to the terminal snug was launched from.
//
// TWO TESTS, AND THE SECOND IS THE MORE IMPORTANT ONE. The channel is closed
// in exactly one shape (nothing on snug's stdio is a terminal, so bwrap gets
// --new-session and /dev/tty is ENXIO inside) and is OPEN, permanently and by
// construction, in the other (the payload was handed the operator's pty on its
// own stdio). A test for the closure alone would let a later reader believe
// snug closes the channel, which is the misreading the ticket exists to
// prevent — so the residual is asserted too, and its name says it is known.
//
// NEITHER TEST USES snug's OWN TERMINAL. Both build a pty pair here, make it
// the child's controlling terminal via SysProcAttr, and read the master end:
// that is the operator's emulator, and what lands on it is what the operator
// would see.

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY allocates a pseudo-terminal pair. The master end is the operator's
// emulator for the purposes of these tests; the slave is what the child gets
// as a controlling terminal.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("opening /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Fatalf("TIOCSPTLCK: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Fatalf("TIOCGPTN: %v", err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Fatalf("opening the pty slave: %v", err)
	}
	// The caller closes the slave itself, right after starting the child (see
	// drainTerminal). These are the belt-and-braces closes for the paths that
	// fail before that.
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// drainTerminal reads what the operator's emulator received. It reads to EOF
// rather than for a duration, and the caller must have closed its own copy of
// the slave first: the last descriptor on the slave side going away is what
// turns the master's read into EIO, and the child's exit is what closes it.
//
// NOT SetReadDeadline, WHICH DOES NOT WORK HERE AND DOES NOT SAY SO. Measured:
// on a master opened with os.OpenFile("/dev/ptmx"), SetReadDeadline returns a
// nil error and the following Read then blocks indefinitely — the file is not
// registered with the runtime poller, so the deadline is accepted and never
// enforced. A first version of this test used it and hung for 375s until the
// suite was killed. The timeout below is the backstop for the case where
// something inside really does hold the slave open; the fd close in t.Cleanup
// releases the goroutine.
func drainTerminal(t *testing.T, master *os.File, d time.Duration) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(master)
		ch <- b
	}()
	select {
	case b := <-ch:
		return b
	case <-time.After(d):
		t.Fatalf("nothing closed the pty slave within %s, so the operator's end never "+
			"reached EOF — something inside the sandbox still holds the terminal", d)
		return nil
	}
}

const osc52Marker = "SNUG-528-OSC52-REACHED-THE-OPERATOR"

// TestNonInteractiveRunCannotWriteToTheOperatorTerminal is the fix for issue
// #528. snug is started the way a hook, a CI job or a piped invocation starts
// it — a controlling terminal inherited from the shell, but a pipe on stdout
// and /dev/null on stdin — and the payload's write to /dev/tty must fail.
//
// The assertion is on the OPERATOR's end, not on the payload's exit status: an
// implementation that let the open succeed and the write silently go nowhere
// would be indistinguishable from the fix by exit status alone, and would stop
// being a fix the moment the write went somewhere again.
func TestNonInteractiveRunCannotWriteToTheOperatorTerminal(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	master, slave := openPTY(t)

	script := `printf '%s' ` + osc52Marker + ` > /dev/tty 2>&1 && echo WROTE-TO-TTY || echo NO-TTY`
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, proj, "--", "/bin/sh", "-c", script)
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	var buf bytes.Buffer
	// A pipe on stdout/stderr and no stdin: this is the shape the fix keys on.
	cmd.Stdout, cmd.Stderr = &buf, &buf
	// The pty is the child's CONTROLLING terminal and nothing else — it is not
	// on any of its standard descriptors, exactly like `snug ... | tee log`
	// run from an interactive shell.
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting snug: %v", err)
	}
	// The parent's copy goes NOW: while it is open the master never sees EOF,
	// and a read of the operator's end would block forever whatever the
	// sandbox did.
	slave.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("snug: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, "WROTE-TO-TTY") {
		t.Errorf("the payload opened /dev/tty in a run with no terminal on snug's stdio: %s", out)
	}
	if seen := drainTerminal(t, master, cmdTimeout); bytes.Contains(seen, []byte(osc52Marker)) {
		t.Errorf("the marker reached the operator's terminal: %q\nsnug output:\n%s", seen, out)
	}
}

// TestKnownOpenResidualPayloadWritesToASharedTerminal asserts the channel that
// is NOT closed, and it is meant to keep passing: when the operator hands the
// payload their terminal, escape sequences the payload writes reach the
// emulator. --new-session cannot change that — the pty is on a descriptor the
// payload holds, and setsid only takes away the /dev/tty spelling.
//
// ONE DESCRIPTOR AT A TIME, WHICH IS THE HALF A REDTEAM ROUND FOUND MISSING.
// The first version of this test put the pty on all three and so never saw
// that the shapes differ: bwrap creates /dev/console only when snug's STDOUT
// is a terminal, while the channel is open in all three — `snug ... > log`
// keeps it on stderr. The screens used to assert /dev/console and "redirect
// snug's output" unconditionally, and both sentences were false for the stdin-
// and stderr-only shapes. The table is what makes that visible.
//
// If any arm stops reproducing, the residual has actually shrunk and the
// sentences in THREAT-MODEL.md §3.6, PSEUDOFS-AUDIT.md D1 and --dry-run's TTY
// block are the ones to correct.
func TestKnownOpenResidualPayloadWritesToASharedTerminal(t *testing.T) {
	requireSandbox(t)

	for _, tc := range []struct {
		name        string
		stdin       bool
		stdout      bool
		stderr      bool
		wantConsole bool
	}{
		{name: "stdin only", stdin: true},
		{name: "stdout only", stdout: true, wantConsole: true},
		{name: "stderr only", stderr: true},
		{name: "all three", stdin: true, stdout: true, stderr: true, wantConsole: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proj, _ := target(t)
			master, slave := openPTY(t)
			devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer devnull.Close()

			// The write goes to /dev/tty, which every shape here still has:
			// the run holds a terminal, so no reason for --new-session
			// applies. `ls` proves which shape this is from the inside.
			script := `ls /dev/console >/dev/tty 2>/dev/tty; printf '%s' ` + osc52Marker + ` > /dev/tty`
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, snugBin, proj, "--", "/bin/sh", "-c", script)
			cmd.Env = baseEnv()
			cmd.WaitDelay = waitDelay
			pick := func(isTTY bool) *os.File {
				if isTTY {
					return slave
				}
				return devnull
			}
			cmd.Stdin, cmd.Stdout, cmd.Stderr = pick(tc.stdin), pick(tc.stdout), pick(tc.stderr)
			// Ctty must name the descriptor that actually holds the pty:
			// TIOCSCTTY on /dev/null is ENOTTY ("inappropriate ioctl for
			// device"), which is what the stdout-only and stderr-only arms hit
			// while Ctty was left at its default of 0.
			ctty := 0
			switch {
			case tc.stdin:
				ctty = 0
			case tc.stdout:
				ctty = 1
			case tc.stderr:
				ctty = 2
			}
			cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true, Setctty: true, Ctty: ctty}

			if err := cmd.Start(); err != nil {
				t.Fatalf("starting snug: %v", err)
			}
			slave.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("snug: %v", err)
			}
			seen := drainTerminal(t, master, cmdTimeout)
			if !bytes.Contains(seen, []byte(osc52Marker)) {
				t.Errorf("KNOWN RESIDUAL NO LONGER REPRODUCES: the payload's write to /dev/tty "+
					"did not reach the operator's terminal (saw %q). If this is a real "+
					"improvement, the documents naming it as inherent are now wrong.", seen)
			}
			gotConsole := !bytes.Contains(seen, []byte("No such file or directory"))
			if gotConsole != tc.wantConsole {
				t.Errorf("/dev/console present=%v, want %v — bwrap keys it on snug's STDOUT "+
					"being a terminal, and --dry-run's TTY block says so per shape. "+
					"Terminal saw: %q", gotConsole, tc.wantConsole, seen)
			}
		})
	}
}
