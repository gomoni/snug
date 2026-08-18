package cli

import (
	"testing"

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
