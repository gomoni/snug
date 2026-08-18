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
// What this file does NOT do: put the client's own terminal into raw mode,
// forward SIGWINCH/window-size changes into the pty, or restore terminal
// state on exit. Those are real interactive-UX gaps, left for a follow-up —
// the security property (host inode never reaches the sandbox) holds
// without them.

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

	closeOnce sync.Once
	childEnds []*os.File // deduplicated; closed once, right after Start()

	wg sync.WaitGroup
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
		r.childStdin, r.childStdout, r.childStderr = slave, slave, slave
		r.childEnds = []*os.File{slave}

		r.wg.Add(2)
		go func() {
			defer r.wg.Done()
			io.Copy(master, os.Stdin)
		}()
		go func() {
			defer r.wg.Done()
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
// the write end it keeps.
func (r *stdioRelay) relayIn(src *os.File) (childEnd *os.File, err error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		io.Copy(pw, src)
		pw.Close()
	}()
	return pr, nil
}

// relayOut is the other direction: A writes into the pipe's write end
// (handed to the child), this process copies FROM the read end it keeps
// INTO dst (this process's own stdout or stderr).
func (r *stdioRelay) relayOut(dst *os.File) (childEnd *os.File, err error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
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

// wait blocks until every copy goroutine has seen EOF — call after the
// attached process has exited, so trailing output is not dropped on a fast
// exit.
func (r *stdioRelay) wait() { r.wg.Wait() }

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
