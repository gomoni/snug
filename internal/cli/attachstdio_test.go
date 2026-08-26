package cli

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestCfmakerawClearsCanonicalModeAndEcho is the pure half of the raw-mode
// gap: cfmakeraw is termios(3)'s own function, reproduced here because
// golang.org/x/sys/unix does not wrap it (see cfmakeraw's own doc comment in
// attachstdio.go). This asserts the flags a raw pty session actually
// depends on: ICANON off (reads are not line-buffered — job control bytes
// like ^C reach the pty immediately rather than waiting for Enter), ECHO
// off (the client's own tty stops local-echoing what the remote shell is
// already echoing back over the pty), ISIG off (^C/^Z/^\ stop being turned
// into signals HERE, and become plain bytes 0x03/0x1a/0x1c that the
// attached shell's own controlling pty — see internal/attach/child.go's
// TIOCSCTTY — interprets instead).
func TestCfmakerawClearsCanonicalModeAndEcho(t *testing.T) {
	// A representative "cooked" termios: every flag cfmakeraw must clear is
	// set going in, so the test can tell a real clear from a bit that
	// happened to already be zero.
	term := unix.Termios{
		Iflag: unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
			unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON,
		Oflag: unix.OPOST,
		Lflag: unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN,
		Cflag: unix.CSIZE | unix.PARENB,
	}
	cfmakeraw(&term)

	if term.Iflag != 0 {
		t.Errorf("Iflag = %#x, want 0 (every input-processing flag cleared)", term.Iflag)
	}
	if term.Oflag&unix.OPOST != 0 {
		t.Errorf("Oflag has OPOST set: output post-processing must be off in raw mode")
	}
	for name, bit := range map[string]uint32{
		"ECHO": unix.ECHO, "ECHONL": unix.ECHONL, "ICANON": unix.ICANON,
		"ISIG": unix.ISIG, "IEXTEN": unix.IEXTEN,
	} {
		if term.Lflag&bit != 0 {
			t.Errorf("Lflag has %s set: raw mode requires it cleared", name)
		}
	}
	if term.Cflag&unix.CSIZE != unix.CS8 {
		t.Errorf("Cflag character size = %#x, want CS8", term.Cflag&unix.CSIZE)
	}
	if term.Cflag&unix.PARENB != 0 {
		t.Errorf("Cflag has PARENB set: raw mode requires parity disabled")
	}
	if term.Cc[unix.VMIN] != 1 || term.Cc[unix.VTIME] != 0 {
		t.Errorf("Cc[VMIN]=%d Cc[VTIME]=%d, want 1 and 0 (a read returns as soon as one byte "+
			"is available, no inter-byte timeout)", term.Cc[unix.VMIN], term.Cc[unix.VTIME])
	}
}

// TestCfmakerawPreservesFlagsItDoesNotOwn is the complement: cfmakeraw only
// touches the bits termios(3) documents it touches. A bit outside that set
// — modelled here with CREAD, which controls whether the receiver is
// enabled at all and has nothing to do with raw-vs-cooked mode — must
// survive untouched, or cfmakeraw is doing more than its name promises.
func TestCfmakerawPreservesFlagsItDoesNotOwn(t *testing.T) {
	term := unix.Termios{Cflag: unix.CREAD}
	cfmakeraw(&term)
	if term.Cflag&unix.CREAD == 0 {
		t.Errorf("cfmakeraw cleared CREAD, a flag it does not own")
	}
}

// TestRelayWaitDrainsEveryStreamWhenOneEndIsAlreadyClosed is the whole of
// the red team's F1 in a form that needs no sandbox: wait() arms a read
// deadline on each drain end, and on a two-stream payload the FIRST end is
// usually already finished and closed by the time wait() runs (measured 15
// of 20 runs), so arming it fails with "use of closed file". Returning on
// that error abandoned the other stream's copy goroutine mid-write and
// dropped what it was carrying — 4096 of 96000 bytes of a payload's own
// stderr, with a clean exit status and no message.
//
// The property asserted is that wait() still SERVES the live stream: it
// cannot return promptly, because a drain end whose far end is still held
// open has to go quiet for drainTimeout first. With the defect it returns in
// microseconds; that is the discriminator, not the byte comparison below,
// which a lucky schedule could satisfy either way.
func TestRelayWaitDrainsEveryStreamWhenOneEndIsAlreadyClosed(t *testing.T) {
	r := &stdioRelay{}

	// Stream one: finished. Its copy loop already returned and closed the
	// read end, exactly as drainCopy's callers do, so arming it will fail.
	finished, finishedW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	finishedW.Close()
	finished.Close()

	// Stream two: live, and its write end is never closed — the #221 shape,
	// something that outlived the attached command still holding it open.
	live, liveW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer liveW.Close()

	r.drainEnds = []*os.File{finished, live}
	var got safeBuffer
	r.outWG.Add(1)
	go func() {
		defer r.outWG.Done()
		r.drainCopy(&got, live)
		live.Close()
	}()
	if _, err := liveW.Write([]byte("trailing-output")); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		r.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("stdioRelay.wait() did not return at all, so the drain is unbounded again — " +
			"the drain deadline is not reaching the live stream's copy loop")
	}

	if el := time.Since(start); el < drainTimeout/2 {
		t.Errorf("stdioRelay.wait() returned after %s, far inside its own %s silence window: it "+
			"gave up on the live stream because arming the ALREADY-CLOSED first drain end "+
			"failed, which is the red team's F1 — a closed drain end is a finished one, not a "+
			"reason to abandon the others", el, drainTimeout)
	}
	if s := got.String(); s != "trailing-output" {
		t.Errorf("the live stream delivered %q, want %q: output the payload wrote before it "+
			"exited was dropped", s, "trailing-output")
	}
	if !r.cutOff.Load() {
		t.Error("cutOff is false after a drain that ended on its deadline rather than on EOF, " +
			"so wait() will not tell the user output was lost")
	}
}

// safeBuffer is a bytes.Buffer the drain goroutine writes and the test reads.
// wait() returns when the WaitGroup drains, which does order that goroutine's
// last write before the read below — the lock is here because the goroutine
// also writes on the paths where wait() does NOT wait for it, which is the
// very defect this test exists to catch.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
