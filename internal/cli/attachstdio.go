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
// What this file does NOT (yet) do: put the client's own terminal into raw
// mode, forward SIGWINCH/window-size changes into the pty, or restore
// terminal state on exit. Those are real interactive-UX gaps, being closed
// incrementally — the security property (host inode never reaches the
// sandbox) holds regardless of any of them. Job control (the attached shell
// getting the pty as its controlling terminal, via setsid()+TIOCSCTTY in
// internal/attach/child.go on the pty path) is now done; see
// attach.Config.PTY, set from this file's own pty flag below.

import (
	"io"
	"os"
	"strconv"
	"sync"

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

	closeOnce sync.Once
	childEnds []*os.File // deduplicated; closed once, right after Start()

	// outWG tracks only the OUTBOUND copy goroutines (A's stdout/stderr, or
	// the pty master read side, draining into this process's own stdout and
	// stderr). These terminate on their own once A exits and every write end
	// they read from is closed, which is exactly the point at which the last
	// of A's output has been drained — so wait() below can safely block on
	// this group without dropping trailing output.
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

		// Inbound (stdin -> master): not tracked in outWG — see its comment.
		go func() {
			io.Copy(master, os.Stdin)
		}()
		r.outWG.Add(1)
		go func() {
			defer r.outWG.Done()
			io.Copy(os.Stdout, master)
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
	r.outWG.Add(1)
	go func() {
		defer r.outWG.Done()
		io.Copy(dst, pr)
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
func (r *stdioRelay) wait() { r.outWG.Wait() }

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
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
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
