// Package wrapper is what snug's own binary does when it runs INSIDE a
// sandbox, bound read-only at policy.WrapperGuest: the http door's descriptor
// handover and the login bridge's BROWSER. Both used to be /bin/sh scripts, and
// a feature that has nothing to do with a shell then required the selection to
// grant one (issue #669). snug is cgo-free (cmd/snug/nocgo.go), so this image
// runs with no libc and no loader granted.
//
// Neither mode is a boundary. Anything inside can set its own LISTEN_PID or
// write the FIFO directly; what the payload can reach is decided by the mounts
// and by internal/loginbridge on the host side of the FIFO.
package wrapper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Exit codes match what `exec` in the shell this replaces returned, so a
// payload that is not there fails the way it did under the script.
const (
	exitNotFound  = 127
	exitCannotRun = 126
	exitUsage     = 2
)

// pipeBuf is Linux's PIPE_BUF: a FIFO write of at most this many bytes is
// atomic, so a URL plus its newline under it cannot interleave with another
// writer's line.
const pipeBuf = 4096

// DoorExec sets LISTEN_PID to this process's own pid and replaces itself with
// argv. execve keeps the pid, so the pid it names IS the payload's — correct by
// construction, where predicting the payload's pid in a fresh pid namespace
// from outside would be correct only until bwrap adds a process.
//
// argv[0] is looked up on PATH the way the shell's `exec "$@"` did. It returns
// only on failure, with the exit code the caller should use.
func DoorExec(argv []string, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(stderr, "snug wrapper: __door-exec: no command to run")
		return exitUsage
	}
	path, err := exec.LookPath(argv[0])
	if errors.Is(err, exec.ErrDot) {
		// A PATH entry of "." is the payload's own choice; the shell ran the
		// match, and refusing here would be a policy the sandbox does not have.
		err = nil
	}
	if err != nil {
		fmt.Fprintf(stderr, "snug wrapper: %s: %v\n", argv[0], err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return exitNotFound
		}
		return exitCannotRun
	}
	if err := os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid())); err != nil {
		fmt.Fprintf(stderr, "snug wrapper: setting LISTEN_PID: %v\n", err)
		return exitCannotRun
	}
	err = syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(stderr, "snug wrapper: %s: %v\n", argv[0], err)
	if errors.Is(err, syscall.ENOENT) {
		return exitNotFound
	}
	return exitCannotRun
}

// Browser hands its one argument to snug over the FIFO at fifo, as one line.
// It opens nothing: whether the line is the login snug will open in the host's
// browser is decided by internal/loginbridge, which reads the other end and is
// the only side that can be the boundary — anything inside can write fifo
// without running this.
//
// A newline in the argument is refused because it would make one argument two
// lines; the host would judge both, but a BROWSER that sends something other
// than what it was handed is not this program's job.
func Browser(fifo string, args []string, stderr io.Writer) int {
	if len(args) != 1 || len(args[0]) >= pipeBuf ||
		strings.ContainsAny(args[0], "\n\x00") {
		fmt.Fprintln(stderr, "snug-browser: expected exactly one URL")
		return exitUsage
	}
	// HOSTREAD-EXEMPT: runs inside the sandbox, never on the host; fifo is
	// policy.BrowserFIFOGuest, and the open blocks until snug reads the other end.
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintf(stderr, "snug-browser: %v\n", err)
		return 1
	}
	_, werr := io.WriteString(f, args[0]+"\n")
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		fmt.Fprintf(stderr, "snug-browser: writing %s: %v\n", fifo, err)
		return 1
	}
	return 0
}
