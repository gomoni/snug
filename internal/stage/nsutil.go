package stage

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// threadNS reads the namespace id of the CALLING THREAD, via
// /proc/thread-self — never /proc/self, which is the thread GROUP LEADER and,
// after a per-thread unshare(2) or setns(2), reports the namespace the calling
// thread just LEFT. Measured (SUPERVISOR-PHASE1-SPEC.md §1): reading the wrong
// one is how "the move worked" gets asserted about a process that never moved.
func threadNS(kind string) string {
	s, err := os.Readlink("/proc/thread-self/ns/" + kind)
	if err != nil {
		return ""
	}
	return s
}

// selfNS reads the namespace id of the process's OWN fd table entry, e.g. the
// pinned descriptor at fdNetnsN via /proc/self/fd/<n> — a stable reference that
// does not depend on which thread is asking, unlike threadNS.
func fdNS(fd int) string {
	s, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return s
}

// nsID reads the CURRENT thread group leader's namespace id — meaningful only
// where the caller is deliberately asking "what does /proc/self say", e.g. for
// the userns, which does not move over this process's lifetime.
func nsID(kind string) string {
	s, err := os.Readlink("/proc/self/ns/" + kind)
	if err != nil {
		return ""
	}
	return s
}

// checkFullCaps refuses to continue if CapEff is zero. /proc/<pid>/status
// renders uids and capabilities in the READER's own user namespace, so this
// check is only meaningful from inside — a process reading its OWN status.
func checkFullCaps() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("reading /proc/self/status: %w", err)
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(ln, "CapEff:"); ok {
			if strings.TrimSpace(v) == "0000000000000000" {
				return fmt.Errorf("CapEff is zero — the single-uid map did not land before this exec")
			}
			return nil
		}
	}
	return fmt.Errorf("no CapEff line in /proc/self/status")
}

// threadsInNamespace sweeps /proc/self/task/*/ns/net (NEVER /proc/self/ns/net,
// which reports only the thread group leader's namespace and, measured, lies
// about a per-thread move) and returns the tids whose network namespace equals
// pinned. An empty result is what stage2 requires before it will serve a
// request: it is the check that /proc/self/ns/net cannot make, because
// unshare(CLONE_NEWNET) is per-task and which threads moved is
// scheduler-dependent (SUPERVISOR-PHASE1-SPEC.md §1).
func threadsInNamespace(pinned string) ([]string, error) {
	if pinned == "" {
		return nil, fmt.Errorf("threadsInNamespace: pinned namespace id is empty")
	}
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/self/task: %w", err)
	}
	var stuck []string
	for _, e := range entries {
		tid := e.Name()
		s, err := os.Readlink("/proc/self/task/" + tid + "/ns/net")
		if err != nil {
			continue // the thread exited between ReadDir and Readlink; not stuck
		}
		if s == pinned {
			stuck = append(stuck, tid)
		}
	}
	return stuck, nil
}

func setCloexec(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
	return err
}

func clearCloexec(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags&^unix.FD_CLOEXEC)
	return err
}

// validateNetnsFD refuses fd unless NS_GET_NSTYPE reports CLONE_NEWNET —
// belt-and-braces against a descriptor that stopped meaning what its number
// says, before pasta or a review depends on it.
func validateNetnsFD(fd int) error {
	typ, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return fmt.Errorf("NS_GET_NSTYPE on fd %d: %w", fd, err)
	}
	if typ != unix.CLONE_NEWNET {
		return fmt.Errorf("fd %d is not a network namespace (NS_GET_NSTYPE=%d)", fd, typ)
	}
	return nil
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
