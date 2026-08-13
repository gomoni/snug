package stage

import (
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
)

// EnterNetns is __innetns: the setns shim that is the only way a child of P1
// gets back into N. It runs between fork and exec in the only sense Go offers
// — a separate exec of this same binary, immediately re-execing the real
// program — and it must be annotated as hard as bwrap's `--` separator is:
//
//  1. lock the OS thread.
//  2. setns(fd, CLONE_NEWNET) — per-task exactly as unshare is, so the same
//     discipline applies. There is NO single-thread requirement here — that is
//     a CLONE_NEWUSER rule and does not reach setns(CLONE_NEWNET).
//  3. re-read and refuse if the namespace did not change.
//  4. CLOSE the descriptor — nothing downstream of this point (bwrap, the
//     payload, a container) ever holds a reference to N that it could setns
//     with if it somehow acquired CAP_SYS_ADMIN. 0b's measurement that nothing
//     downstream of bwrap holds a reference to N depends on this line.
//  5. seal everything except bwrap's own block, because THIS is the last exec
//     before the sandbox and syscall.Exec has no fd machinery of its own: what
//     is not CLOEXEC here is what the payload ends up holding.
//  6. exec the real program. Touch NOTHING else: every other inherited
//     descriptor is bwrap's and must pass through untouched.
func EnterNetns(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("__innetns: usage: __innetns FD CMD [ARGS...]")
	}
	fdStr, path, rest := argv[0], argv[1], argv[2:]
	fd := atoiOrZero(fdStr)
	if fd <= 0 {
		return fmt.Errorf("__innetns: bad fd %q", fdStr)
	}

	runtime.LockOSThread()
	before := threadNS("net")
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("__innetns: setns(net): %w", err)
	}
	after := threadNS("net")
	if before == after || after == "" {
		return fmt.Errorf("__innetns: setns reported success but the thread is still in %s", before)
	}

	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("__innetns: closing the netns fd: %w", err)
	}

	// bwrap's own descriptors are the contiguous block 3..fd-1 — P1 put them
	// there with ExtraFiles and the netns descriptor last, so the shim's own
	// argument bounds the block and the keep list is DERIVED from the request
	// rather than written down. Everything else this process holds is sealed:
	// syscall.Exec below installs no descriptors and clears no flags, so
	// whatever is not CLOEXEC at this instant is what bwrap inherits and, for
	// anything bwrap does not know to close, what the PAYLOAD ends up holding.
	// Go's runtime marks its own descriptors CLOEXEC, so today this seals
	// nothing at all — which is the point: it is the guard that keeps the next
	// edit to this function from being a leak, on the one exec in the whole
	// chain where nothing else would catch it.
	keep := make([]int, 0, fd-3)
	for i := 3; i < fd; i++ {
		keep = append(keep, i)
	}
	if err := fdseal.SealExcept(keep...); err != nil {
		return fmt.Errorf("__innetns: %w", err)
	}

	// path arrives already resolved: internal/sandbox.Run resolves bwrap with
	// exec.LookPath exactly once, before any of this exists, and that resolved
	// absolute path is what travels through the "start" request. __innetns does
	// not re-resolve it — a relative name reaching this point is a bug in the
	// caller, not something to paper over with a second LookPath.
	//
	// The environment is EMPTY, stated here rather than inherited. This exec
	// becomes bwrap, which becomes PID 1 of the sandbox's pid namespace — the
	// exact process whose /proc/1/environ once handed a payload 106 host
	// variables. os.Environ() is empty at this point only because runOneSandbox
	// set cmd.Env = []string{} two processes back, so passing it would make the
	// guarantee transitive across three generations instead of local to the
	// line that consumes it. Three independent reviews landed on this one word.
	return syscall.Exec(path, append([]string{path}, rest...), []string{})
}
