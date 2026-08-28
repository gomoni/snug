package sandbox

// inpidns.go is the `__inpidns` verb: the one process between snug and bwrap
// on the offline arm, and it is that process only until its own exec — it
// mounts a procfs and becomes bwrap, so the topology stays two processes.
//
// WHY IT EXISTS AT ALL, since the clone that starts it already made the
// namespaces. bwrap answers --info-fd by reading its CHILD's /proc entry:
// namespace_ids_read() does openat(proc_fd, "<child-pid>/ns", O_PATH), where
// proc_fd is the procfs bwrap opened before it unshared anything. With bwrap
// as pid 1 of NP (exec.go's clone), the child's number is 2 IN NP while
// proc_fd still belongs to the pid namespace above — so bwrap reads a
// stranger's /proc/2, or nobody's.
//
// MEASURED, same bwrap 0.11.2, same argv, one nesting level apart:
//
//	flat            {"child-pid": 10449, "cgroup-namespace": 4026532835, …six ids}
//	nested          {"child-pid": 2}                    <- every id gone
//	nested, no /proc/2   bwrap: open /proc/2/ns/ns failed: No such file or directory
//
// The middle line is this host, where outer pid 2 is kthreadd: the O_PATH open
// of a 0511 directory succeeds, every fstatat under it is EACCES because bwrap
// sits in a foreign user namespace, and bwrap silently reports no namespace
// ids at all. The third is a container, where pid 2 is whatever ran last and
// is usually gone — bwrap dies before the sandbox exists, and every test that
// needs a payload fails with it. That is CI run 33190731691's engine job.
//
// So the fix is not to translate the number, it is to make the number TRUE:
// give the intermediate its own mount namespace and mount a procfs of NP over
// /proc, and bwrap's /proc/2 is then genuinely its child. MEASURED after:
// bwrap reports all six ids and they match the payload's own readlinks.

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
)

// EnterPidNS is the whole body of `__inpidns NFDS BWRAP [ARGS...]`. NFDS is
// how many descriptors internal/sandbox.Run handed down with ExtraFiles, which
// are always the contiguous block 3..3+NFDS-1; BWRAP is already resolved by
// exec.LookPath one process back and is never re-resolved here, for the reason
// internal/stage's EnterNetns states.
//
// It refuses rather than continues when a step fails: a bwrap that runs with
// the WRONG /proc is exactly the state this verb exists to prevent, and
// invariant 5 says a capability that is not available is a refusal, not a
// quieter run.
func EnterPidNS(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("__inpidns: usage: __inpidns NFDS BWRAP [ARGS...]")
	}
	nfds, err := strconv.Atoi(argv[0])
	if err != nil || nfds < 0 {
		return fmt.Errorf("__inpidns: bad descriptor count %q", argv[0])
	}
	path, rest := argv[1], argv[2:]

	// A pid namespace of our own is the precondition, not an assumption: run
	// directly from a shell this verb would mount a procfs over the caller's
	// /proc in whatever mount namespace it inherited. os.Getpid() == 1 is what
	// the clone in exec.go produces and nothing else does.
	if os.Getpid() != 1 {
		return fmt.Errorf("__inpidns: this process is pid %d, not pid 1 — the verb is reachable "+
			"only through snug's own clone (CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNS) and refuses "+
			"to mount a procfs over an inherited /proc", os.Getpid())
	}

	// MS_REC|MS_PRIVATE first, and it is not a formality: on a systemd host /
	// is MS_SHARED, and a mount into a shared peer group PROPAGATES BACK — the
	// procfs below would appear on the host's own /proc. Measured on this host:
	// findmnt -o PROPAGATION / says "shared".
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("__inpidns: making the intermediate namespace's mounts private: %w "+
			"(snug forks bwrap into a mount namespace of its own; without this the procfs "+
			"below would propagate to the host's /proc)", err)
	}

	// The procfs bwrap will read its child out of. NOSUID|NODEV|NOEXEC are
	// what every /proc on the host already carries; nothing here needs more.
	if err := unix.Mount("proc", "/proc", "proc",
		unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("__inpidns: mounting a procfs for the intermediate pid namespace "+
			"on /proc: %w (bwrap resolves its own child's pid against this mount when it "+
			"answers --info-fd, so the run would either report a stranger's namespace ids or "+
			"die with \"open /proc/2/ns/ns failed\")", err)
	}

	// Everything outside the ExtraFiles block is sealed before the exec, for
	// the reason internal/stage's EnterNetns gives at the same point in the
	// chain: this is the last process that can decide what bwrap — and through
	// it, the payload — inherits.
	keep := make([]int, 0, nfds)
	for fd := 3; fd < 3+nfds; fd++ {
		keep = append(keep, fd)
	}
	if err := fdseal.SealExcept(keep...); err != nil {
		return fmt.Errorf("__inpidns: %w", err)
	}

	// Empty environment, stated rather than inherited — the same word, for the
	// same measured reason, as internal/stage's EnterNetns: this exec becomes
	// the bwrap whose /proc/1/environ a payload can read.
	return syscall.Exec(path, append([]string{path}, rest...), []string{})
}
