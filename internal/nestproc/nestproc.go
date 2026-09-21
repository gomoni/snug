// Package nestproc mounts the procfs that bwrap needs when snug has put it at
// the top of a pid namespace of snug's own making.
//
// WHY IT EXISTS, in one measurement. bwrap answers --info-fd by reading its
// CHILD's /proc entry: namespace_ids_read() does openat(proc_fd, "<child>/ns",
// O_PATH) against the procfs bwrap opened before it unshared anything. With
// bwrap as pid 1 of an intermediate namespace, the child is pid 2 THERE while
// that procfs still belongs to the namespace above — so bwrap reads a
// stranger's /proc/2, or nobody's. MEASURED, same bwrap 0.11.2, same argv, one
// nesting level apart:
//
//	flat                 {"child-pid": 10449, "cgroup-namespace": 4026532835, …six ids}
//	nested               {"child-pid": 2}                    <- every id gone
//	nested, no /proc/2   bwrap: open /proc/2/ns/ns failed: No such file or directory
//
// The middle line is a host where outer pid 2 is kthreadd: the O_PATH open of
// a 0511 directory succeeds, every fstatat under it is EACCES from a foreign
// user namespace, and bwrap silently reports no namespace ids at all. The
// third is a container, where pid 2 is whatever ran last and is usually gone.
//
// So the fix is not to translate the number, it is to make the number TRUE.
//
// ONE PACKAGE, TWO CALLERS, and that is the point rather than tidiness. Both
// arms of snug now fork bwrap into an intermediate pid namespace —
// internal/sandbox's __inpidns verb on the offline arm, internal/stage's
// __innetns verb on the staged one — and the two verbs are otherwise
// completely different (one has just been cloned, the other has just
// setns'd). A second copy of this sequence would be a second author of what
// bwrap can see of itself: invariant 6.
package nestproc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Mount makes this mount namespace private and puts a procfs of THIS pid
// namespace on /proc.
//
// It must run in a mount namespace of this process's own and with this process
// at pid 1 of a pid namespace of its own; both callers arrange exactly that,
// and Mount refuses rather than continuing if the second is not true. A bwrap
// that runs with the WRONG /proc is the state this package exists to prevent,
// and invariant 5 says an unavailable capability is a refusal, not a quieter
// run.
//
// verb is the caller's own name, used only to prefix the errors, so a failure
// says which of the two arms produced it.
func Mount(verb string) error {
	// A pid namespace of our own is the precondition, not an assumption: run
	// from an ordinary shell this would mount a procfs over the caller's own
	// /proc in whatever mount namespace it inherited.
	//
	// os.Getpid() == 1 is what both callers' clone produces, and it is NOT
	// unique to them — a redteam round reached the offline verb as pid 1 from
	// a host shell:
	//
	//	unshare -Urpf --mount-proc snug __inpidns 0 /bin/echo
	//
	// which is harmless and stays harmless for a reason worth stating,
	// because an earlier version of this comment claimed uniqueness and would
	// have been the thing a reader trusted: that caller ALREADY holds the
	// privilege to make the namespaces, so the verb hands it nothing, and the
	// procfs lands in the throwaway mount namespace `unshare` just made. What
	// the guard is for is the payload, which has an empty capability bounding
	// set (bwrap.go's --cap-drop ALL) and cannot create a pid namespace at all
	// — measured EPERM on unshare -U -r from inside the sandbox — and which
	// has no snug binary to run in the first place.
	if pid := os.Getpid(); pid != 1 {
		return fmt.Errorf("%s: this process is pid %d, not pid 1 — the verb is reachable "+
			"only through snug's own clone and refuses to mount a procfs over an "+
			"inherited /proc", verb, pid)
	}

	// MS_REC|MS_PRIVATE first, and it is not a formality: on a systemd host /
	// is MS_SHARED, and a mount into a shared peer group PROPAGATES BACK — the
	// procfs below would appear on the host's own /proc. Measured on this
	// host: findmnt -o PROPAGATION / says "shared".
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("%s: making the intermediate namespace's mounts private: %w "+
			"(snug forks bwrap into a mount namespace of its own; without this the procfs "+
			"below would propagate to the host's /proc)", verb, err)
	}

	// The procfs bwrap will read its child out of. NOSUID|NODEV|NOEXEC are
	// what every /proc on the host already carries; nothing here needs more.
	if err := unix.Mount("proc", "/proc", "proc",
		unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("%s: mounting a procfs for the intermediate pid namespace on "+
			"/proc: %w (bwrap resolves its own child's pid against this mount when it "+
			"answers --info-fd, so the run would either report a stranger's namespace ids "+
			"or die with \"open /proc/2/ns/ns failed\")", verb, err)
	}
	return nil
}
