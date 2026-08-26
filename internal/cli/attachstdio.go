package cli

// attachstdio.go implements §5.4/§17's stdio relay, in both shapes the
// maintainer settled on for this ticket: a fresh pty for an interactive
// session, and a pair of pipes for a redirected one. Either way, the host
// FILE DESCRIPTOR the attaching human's stdin/stdout/stderr point at never
// crosses into the sandbox — only a live stream this file itself owns does.
// See attach.go's package comment for the abuse sentence this narrows,
// and its own limit: M18/M24 in the design measured that the payload can
// still read and write the stream it was handed, only not the host inode
// behind a redirected one.
//
// Four interactive-UX gaps a fresh pty needs to actually behave like a
// terminal are closed here and in internal/attach/child.go, all four
// unrelated to the security property above (host inode never reaches the
// sandbox), which holds regardless: job control (the attached shell getting
// the pty as its controlling terminal, via setsid()+TIOCSCTTY in
// internal/attach/child.go on the pty path — see attach.Config.PTY, set
// from this file's own pty flag below), putting the CLIENT's own terminal
// into raw mode (clientRawMode), forwarding its window size into the pty
// both initially and on every SIGWINCH (watchWinsize), and restoring the
// client's termios and stopping the SIGWINCH watcher when the session ends
// (restoreTerminal) — deferred by runAttach right after newStdioRelay
// returns, so it runs on every exit path: normal return, the attached
// command dying, or an early error return.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// stdioRelay is what runAttach hands to attach.Config, plus the copy loops
// that keep bytes flowing between them and this process's own stdio for the
// life of the attached session.
type stdioRelay struct {
	childStdin, childStdout, childStderr *os.File

	// pty is true exactly when the interactive branch below was taken —
	// runAttach reads it to set attach.Config.PTY, which is what gates
	// child.go's setsid()+TIOCSCTTY to the pty path only.
	pty bool

	// origTermios is THIS PROCESS's own terminal's (os.Stdin's) termios
	// exactly as clientRawMode found it, before putting it in raw mode — the
	// value a later restore step puts back on exit. Nil on the pipe path,
	// where there is no terminal to touch.
	origTermios *unix.Termios

	// sigwinch and sigwinchDone belong to watchWinsize's background
	// goroutine: sigwinch is the channel signal.Notify delivers SIGWINCH on,
	// sigwinchDone stops the goroutine (closed by a later restore step, so
	// the goroutine and the signal registration do not outlive the
	// session). Both nil on the pipe path.
	sigwinch     chan os.Signal
	sigwinchDone chan struct{}

	// restoreOnce guards restoreTerminal against running twice — the caller
	// defers it once, but the same relay may also reach an error path that
	// wants to restore before returning.
	restoreOnce sync.Once

	closeOnce sync.Once
	childEnds []*os.File // deduplicated; closed once, right after Start()

	// draining is set by wait() for the rest of the process's life: the
	// copy loops read it to decide whether a successful read re-arms the
	// drain deadline. It cannot be armed earlier — an interactive session is
	// idle for minutes at a time and that is not a stream nobody will write
	// to again, it is a human thinking.
	draining atomic.Bool

	// cutOff records that a drain loop gave up on a deadline rather than an
	// EOF, i.e. output was dropped. wait() says so on stderr: a sandbox that
	// silently truncates its own transcript is the screen lying.
	cutOff atomic.Bool

	// drainEnds are the READ ends the outbound copy goroutines below are
	// blocked on — the pty master on the interactive path, the two pipe read
	// ends on the redirected one. They are held HERE and not only in those
	// goroutines' closures because wait() has to be able to bound them:
	// A's exit does NOT close them. A's fds 0/1/2 are dup3'd, and dup3
	// deliberately clears CLOEXEC (see runAttach's fdseal comment), so any
	// descendant A leaves behind inherits A's stdio and holds the far end
	// open. Without a bound, `snug attach` blocks in wait() forever with the
	// attached command already reaped and its exit status already in hand:
	// `snug attach dir -- bash -c '(sleep 60 &) ; exit 0'` returned only
	// when the sleep did.
	drainEnds []*os.File

	// outWG tracks only the OUTBOUND copy goroutines (A's stdout/stderr, or
	// the pty master read side, draining into this process's own stdout and
	// stderr). They end when the last write end they read from closes, which
	// is A's exit ONLY when A left nothing behind holding it — so wait()
	// bounds them rather than trusting that, see drainEnds above.
	//
	// The INBOUND copy goroutine (this process's stdin into A) is
	// deliberately NOT tracked here. It has no termination path of its own:
	// os.Stdin only closes when whatever feeds it (a pipe, a redirected
	// file) reaches EOF, which is a fact about the caller's stdin, not about
	// A's lifetime. A caller piping from a long-lived or never-closing
	// source (`sleep 30 | snug attach dir -- echo hi`) would otherwise wait
	// on that goroutine forever even though A exited immediately (#120). The
	// goroutine is left to be reclaimed when this process exits; it blocks
	// on nothing that outlives the process and holds no resource that needs
	// closing on this side.
	outWG sync.WaitGroup
}

// newStdioRelay decides pty-or-pipes ONCE, from whether this process's OWN
// stdin is a terminal — the same signal ssh, docker exec -t and kubectl exec
// -t all gate an interactive session on. A single shared pty is used for
// all three of A's stdio in that case, exactly as an ordinary interactive
// program's does when nothing has redirected it; otherwise each stream gets
// its own independent, unidirectional pipe.
func newStdioRelay() (*stdioRelay, error) {
	r := &stdioRelay{}

	if isTerminal(int(os.Stdin.Fd())) {
		master, slave, err := openPTY()
		if err != nil {
			return nil, err
		}
		r.pty = true
		r.childStdin, r.childStdout, r.childStderr = slave, slave, slave
		r.childEnds = []*os.File{slave}

		if err := r.clientRawMode(); err != nil {
			r.restoreTerminal()
			master.Close()
			slave.Close()
			return nil, err
		}
		if err := r.watchWinsize(master); err != nil {
			// clientRawMode above already succeeded — the client's terminal
			// IS raw at this point — so this path must restore it before
			// giving up, or a caller who only ever sees a non-nil relay
			// (and so only ever defers restoreTerminal on THAT) would leave
			// the real terminal raw on this specific failure.
			r.restoreTerminal()
			master.Close()
			slave.Close()
			return nil, err
		}

		// Inbound (stdin -> master): not tracked in outWG — see its comment.
		go func() {
			io.Copy(master, os.Stdin)
		}()
		r.drainEnds = []*os.File{master}
		r.outWG.Add(1)
		go func() {
			defer r.outWG.Done()
			r.drainCopy(os.Stdout, master)
			master.Close()
		}()
		return r, nil
	}

	stdin, err := r.relayIn(os.Stdin)
	if err != nil {
		return nil, err
	}
	r.childStdin = stdin

	stdout, err := r.relayOut(os.Stdout)
	if err != nil {
		return nil, err
	}
	r.childStdout = stdout

	stderr, err := r.relayOut(os.Stderr)
	if err != nil {
		return nil, err
	}
	r.childStderr = stderr

	r.childEnds = []*os.File{stdin, stdout, stderr}
	return r, nil
}

// relayIn is one direction of the pipe relay: A reads from the pipe's read
// end (handed to the child), this process copies FROM its own stdin INTO
// the write end it keeps. Deliberately not tracked in outWG: see its
// comment on the struct — this copy has no termination path tied to A's
// lifetime, only to when the caller's own stdin reaches EOF.
func (r *stdioRelay) relayIn(src *os.File) (childEnd *os.File, err error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		io.Copy(pw, src)
		pw.Close()
	}()
	return pr, nil
}

// relayOut is the other direction: A writes into the pipe's write end
// (handed to the child), this process copies FROM the read end it keeps
// INTO dst (this process's own stdout or stderr). Tracked in outWG: this
// copy DOES terminate on its own, once A exits and A's own copy of the
// write end closes.
func (r *stdioRelay) relayOut(dst *os.File) (childEnd *os.File, err error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.drainEnds = append(r.drainEnds, pr)
	r.outWG.Add(1)
	go func() {
		defer r.outWG.Done()
		r.drainCopy(dst, pr)
		pr.Close()
	}()
	return pw, nil
}

// closeChildEnds closes this process's copy of whatever A's own stdio
// descriptors are, once attach.Start has returned: A (via B, via fork) has
// its own copy of each already, fork having duplicated the whole descriptor
// table rather than curating it, so closing ours here does not affect A's —
// it only lets an EOF propagate on this side once A's copy is the last one
// standing.
func (r *stdioRelay) closeChildEnds() {
	r.closeOnce.Do(func() {
		seen := map[uintptr]bool{}
		for _, f := range r.childEnds {
			if f == nil || seen[f.Fd()] {
				continue
			}
			seen[f.Fd()] = true
			f.Close()
		}
	})
}

// wait blocks until every OUTBOUND copy goroutine has seen EOF — call after
// the attached process has exited, so trailing output is not dropped on a
// fast exit. It deliberately does NOT wait on the inbound (stdin) copy: that
// goroutine has no EOF to wait for unless the caller's own stdin happens to
// close, and blocking on it here is issue #120 — attach hanging until a
// pipe upstream of it closes, long after the attached command has exited
// and its exit status has already been read.
func (r *stdioRelay) wait() {
	// Arming can fail, and the ordinary reason is that this drain end's own
	// copy loop has ALREADY finished and closed it — measured 15 of 20 runs
	// on a two-stream payload. A closed drain end is a FINISHED one, so its
	// WaitGroup entry is already released and there is nothing to skip for:
	// the error is discarded rather than returned on, because returning here
	// abandoned the OTHER stream's goroutine mid-write and dropped what it
	// was carrying (measured: 4096 of 96000 bytes of the payload's own
	// stderr, with a clean exit status and no message). go1.27 reports it as
	// a bare *errors.errorString "use of closed file" — not an *os.PathError,
	// and errors.Is against os.ErrClosed is false — so there is nothing here
	// worth classifying either.
	r.draining.Store(true)
	deadline := time.Now().Add(drainTimeout)
	for _, f := range r.drainEnds {
		_ = f.SetReadDeadline(deadline)
	}
	r.outWG.Wait()
	if r.cutOff.Load() {
		fmt.Fprintf(os.Stderr, "snug: attach: the attached command exited, but something it left "+
			"behind still holds its stdio open; stopped draining after %s of silence and any "+
			"further output is lost\n", drainTimeout)
	}
}

// drainCopy is the outbound copy loop, and the one thing it does that
// io.Copy cannot is RE-ARM the drain deadline after every successful read.
//
// The bound wait() sets is on SILENCE, not on elapsed time, and the
// difference is not a nicety: an absolute deadline cut a benign payload's
// still-flowing output mid-stream (measured: 3572 bytes and the final line
// of a 20000-byte burst, with no descendant involved at all). Output that is
// actively arriving therefore gets the whole window again after every read,
// and only a stream that goes quiet for drainTimeout with its far end still
// held open — which is issue #221's actual shape — ends the drain.
//
// A copy parked in WRITE is deliberately not bounded by any of this. The
// deadline is a read deadline and does not touch a parked write, and that is
// correct rather than a gap: a write that has not completed means the
// CLIENT's own consumer (the human's terminal, a pipeline, a redirect) has
// not taken the bytes yet, which is the caller's business and ordinary Unix
// back-pressure. The sandbox side cannot reach it.
func (r *stdioRelay) drainCopy(dst io.Writer, src *os.File) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if r.draining.Load() {
				src.SetReadDeadline(time.Now().Add(drainTimeout))
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.cutOff.Store(true)
			}
			return
		}
	}
}

// drainTimeout is how long a stream may stay SILENT, after the attached
// command has been reaped, before the drain gives up on it — not a budget for
// the drain as a whole (see drainCopy) and not a performance target. It
// delays nothing on a healthy session: by then every descriptor snug itself
// holds on the far end is closed, so the drain ends on EOF/EIO at once. Two
// seconds is what a stream gets to produce its next byte when something that
// OUTLIVED the attached command is still holding it open, and after that the
// client returns with the exit status it already has, saying on stderr that
// it did.
const drainTimeout = 2 * time.Second

// isTerminal reports whether fd refers to a terminal, via TCGETS: it
// succeeds only on a tty-like device, so its error/success split IS the
// isatty(3) test, without needing a dependency for one ioctl.
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// openPTY allocates a fresh pseudo-terminal pair via /dev/ptmx — the
// standard three-ioctl sequence (unlock, get the slave's number, open it by
// path) rather than a dependency, on the same "small amount of our own code"
// reasoning CLAUDE.md states for why this project prefers the standard
// library first.
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := ctlFd(m, func(fd int) error {
		return unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)
	}); err != nil {
		m.Close()
		return nil, nil, err
	}
	var n int
	if err := ctlFd(m, func(fd int) (err error) {
		n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return err
	}); err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(ptsPath(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

func ptsPath(n int) string {
	return "/dev/pts/" + strconv.Itoa(n)
}

// clientRawMode puts THIS PROCESS's own terminal (os.Stdin, fd 0 — the real
// tty the attaching human is typing at, NOT the fresh pty the relay just
// allocated) into raw mode for the life of the session, saving the original
// termios in r.origTermios first so it can be put back later. Without this
// the client's real terminal stays in cooked/line mode: input would only
// reach the attached shell a whole line at a time, on Enter, doubly echoed
// (once by the client tty's own line discipline, once by the remote shell
// echoing over the pty) — and job control keystrokes like ^C, ^Z, ^\ would
// be intercepted and turned into signals HERE rather than reaching the
// attached shell as the bytes 0x03/0x1a/0x1c that its own (now-controlling,
// per internal/attach/child.go's TIOCSCTTY) pty is what should interpret
// them.
func (r *stdioRelay) clientRawMode() error {
	fd := int(os.Stdin.Fd())
	orig, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	r.origTermios = orig

	raw := *orig
	cfmakeraw(&raw)
	return unix.IoctlSetTermios(fd, unix.TCSETS, &raw)
}

// syncWinsize copies the CLIENT terminal's (clientFd, the attaching human's
// real tty) current window size onto master (the fresh pty the attached
// process's stdio lives on) — the same direction ssh and docker exec -t
// copy in, since master/slave share one size and setting it on either end
// updates what the other side's TIOCGWINSZ reads back.
func syncWinsize(clientFd int, master *os.File) error {
	ws, err := unix.IoctlGetWinsize(clientFd, unix.TIOCGWINSZ)
	if err != nil {
		return err
	}
	return ctlFd(master, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws)
	})
}

// ctlFd runs an ioctl on f's descriptor WITHOUT taking f out of the runtime
// poller, and every ioctl this file issues on the pty master goes through it.
//
// os.File.Fd() is the alternative and it is not equivalent: it puts a
// pollable file back into BLOCKING mode and dissociates it from the poller,
// permanently, which costs the file both its read deadlines and Close()'s
// ability to interrupt a read already in flight. Those two are exactly what
// wait()'s bound is built on, and openPTY did this to the master twice
// (TIOCSPTLCK, TIOCGPTN) before the master had ever been read from — so the
// master was blocking-mode from birth and no deadline on it could have
// worked. SyscallConn().Control gives the same descriptor for the duration
// of the call and leaves the file's mode alone.
func ctlFd(f *os.File, op func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if cerr := rc.Control(func(fd uintptr) { opErr = op(int(fd)) }); cerr != nil {
		return cerr
	}
	return opErr
}

// watchWinsize does the initial sync (so the attached process's very first
// TIOCGWINSZ — a shell drawing its prompt, `stty size`, an editor sizing
// its window — already sees the client's real size rather than whatever
// /dev/ptmx defaulted to) and then installs a SIGWINCH handler that repeats
// it for the rest of the session, so a client terminal resized mid-session
// propagates too. The background goroutine it starts is stopped by closing
// r.sigwinchDone, which a later restore-on-exit step owns; started
// goroutines that never see that channel closed exit only when this
// process does, holding nothing that needs closing.
func (r *stdioRelay) watchWinsize(master *os.File) error {
	fd := int(os.Stdin.Fd())
	if err := syncWinsize(fd, master); err != nil {
		return err
	}

	r.sigwinch = make(chan os.Signal, 1)
	signal.Notify(r.sigwinch, unix.SIGWINCH)
	r.sigwinchDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-r.sigwinch:
				syncWinsize(fd, master)
			case <-r.sigwinchDone:
				return
			}
		}
	}()
	return nil
}

// restoreTerminal undoes everything the pty branch of newStdioRelay changed
// on THIS PROCESS's own terminal: stops watchWinsize's SIGWINCH watcher
// (signal.Stop, then close its done channel so the goroutine exits) and
// puts back the termios clientRawMode saved before it put the terminal in
// raw mode. Idempotent via restoreOnce — safe to call more than once (an
// error path inside newStdioRelay calls it directly; the caller separately
// defers it once newStdioRelay returns) — and safe to call on a relay that
// never touched the terminal at all (the pipe path, or a pty attempt that
// failed before clientRawMode ran): both sigwinchDone and origTermios stay
// nil in that case, and this is then a no-op.
//
// The caller (runAttach) defers this immediately after newStdioRelay
// returns, so it runs on every exit path out of that function — normal
// return, the attached command dying (including by a signal — releaseGate
// still returns normally in that case, see ws.Signaled()), or an early
// error return — never only some of them.
func (r *stdioRelay) restoreTerminal() {
	r.restoreOnce.Do(func() {
		if r.sigwinchDone != nil {
			signal.Stop(r.sigwinch)
			close(r.sigwinchDone)
		}
		if r.origTermios != nil {
			unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, r.origTermios)
		}
	})
}

// cfmakeraw is termios(3)'s cfmakeraw — golang.org/x/sys/unix wraps the
// ioctl but not this convenience function, so it is reproduced here from
// the same flag list every termios(3) manual page documents: input is
// unprocessed and unbuffered (no signal generation, no canonical/line mode,
// no local echo, no special handling of BREAK/parity/CR/NL/flow-control
// bytes), output is unprocessed, 8-bit characters, and a read returns as
// soon as at least one byte (VMIN=1) is available with no inter-byte
// timeout (VTIME=0).
func cfmakeraw(t *unix.Termios) {
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
}
