package stage

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// engineCapBit maps the CAP_* names policy.EngineCapBounding renders to the
// kernel's own small integers (capability(7)). Kept HERE, not in
// internal/policy, deliberately: policy stays pure (no syscalls, no
// unix.CAP_* — those are Linux-specific values a portability-minded reviewer
// should never have to wade through to understand a grant), and this package
// is where every other raw namespace/capability syscall in the codebase
// already lives.
var engineCapBit = map[string]int{
	"CAP_CHOWN":            unix.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":     unix.CAP_DAC_OVERRIDE,
	"CAP_FOWNER":           unix.CAP_FOWNER,
	"CAP_FSETID":           unix.CAP_FSETID,
	"CAP_KILL":             unix.CAP_KILL,
	"CAP_SETGID":           unix.CAP_SETGID,
	"CAP_SETUID":           unix.CAP_SETUID,
	"CAP_SETPCAP":          unix.CAP_SETPCAP,
	"CAP_NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE,
	"CAP_SYS_CHROOT":       unix.CAP_SYS_CHROOT,
	"CAP_SETFCAP":          unix.CAP_SETFCAP,
	"CAP_SYS_ADMIN":        unix.CAP_SYS_ADMIN,
	// Named even though EngineCapBounding never includes them, so a caller
	// that DOES ask for one gets a clear "not implemented", never a
	// panic-shaped map miss — and so the standing gate (CAP_SYS_PTRACE) and
	// the settled exclusion (CAP_NET_ADMIN) both have a bit to refer to in
	// tests and error messages.
	"CAP_SYS_PTRACE": unix.CAP_SYS_PTRACE,
	"CAP_NET_ADMIN":  unix.CAP_NET_ADMIN,
}

// dropCapsToExactly reduces the CALLING PROCESS's own bounding, permitted,
// inheritable and effective capability sets to EXACTLY the named set —
// dropping everything else — and is the numeric half of
// policy.EngineCapBounding: the constant names WHAT the engine keeps: this
// function is HOW.
//
// Irreversible, on purpose: a process cannot ever regain a bounding-set
// capability it dropped (short of exec'ing a binary with file capabilities,
// which nothing here does). It must run AFTER whatever needs the full set —
// in the engine's case, after its own CLONE_NEWNS/CLONE_NEWCGROUP unshare and
// its private-tree mount, and immediately before the execve into podman —
// never before.
//
// Two mechanisms, because the kernel exposes two different interfaces for
// the two kinds of set: the bounding set can only be lowered ONE capability
// at a time (PR_CAPBSET_DROP has no bulk form, and DROPPING is the only
// direction it moves — there is no PR_CAPBSET_RAISE); permitted, effective
// and inheritable are set together in one capset(2) call. The bounding set is
// reduced FIRST, because capset(2) refuses a permitted set that is not a
// subset of the (already-reduced) bounding set — asking for the same set in
// both calls is what makes that ordering matter rather than merely being
// tidy.
//
// CAP_SETPCAP must be IN `keep`, or this function cannot even perform the
// PR_CAPBSET_DROP calls it needs to run (the man page: "The calling thread
// must have the CAP_SETPCAP capability"). policy.EngineCapBounding satisfies
// this; a caller that passes a set without it gets a clear refusal rather
// than a confusing EPERM on the very first drop.
func dropCapsToExactly(keep []string) error {
	keepBits := map[int]bool{}
	for _, name := range keep {
		bit, ok := engineCapBit[name]
		if !ok {
			return fmt.Errorf("dropCapsToExactly: %q is not a capability this package knows the "+
				"kernel bit for (see engineCapBit in internal/stage/capdrop.go)", name)
		}
		keepBits[bit] = true
	}
	if !keepBits[unix.CAP_SETPCAP] {
		return fmt.Errorf("dropCapsToExactly: CAP_SETPCAP is not in the kept set, so this call " +
			"could not perform the PR_CAPBSET_DROP calls it needs to run at all")
	}

	last, err := capLastCap()
	if err != nil {
		return fmt.Errorf("dropCapsToExactly: %w", err)
	}
	for cap := 0; cap <= last; cap++ {
		if keepBits[cap] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			if err == unix.EINVAL {
				// The kernel does not recognise this bit at all (a capability
				// added after this binary's cap_last_cap read, or a stale
				// value from a caller that skipped capLastCap) — nothing to
				// drop.
				continue
			}
			return fmt.Errorf("dropCapsToExactly: PR_CAPBSET_DROP(%d): %w", cap, err)
		}
	}

	var mask uint64
	for bit := range keepBits {
		mask |= 1 << uint(bit)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(mask), Permitted: uint32(mask)},
		{Effective: uint32(mask >> 32), Permitted: uint32(mask >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("dropCapsToExactly: capset: %w", err)
	}
	return nil
}

// dropFromBounding lowers the CALLING THREAD's bounding set by the named
// capabilities and nothing else — the subtractive counterpart to
// dropCapsToExactly, and the numeric half of policy.StageCapDrop.
//
// PER-THREAD, which is the whole reason its one caller sits on a locked thread
// immediately before an execve. MEASURED, from a 10-thread Go process: the
// prctl leaves /proc/self/status completely unchanged, because that file
// reports the group leader and not the caller — so a naive call reads as a
// no-op AND leaves every other thread privileged. It is the execve that makes
// it the process's: it kills every other thread, recomputes permitted and
// effective from the caller's bounding set, and hands the reduced set to
// everything forked afterwards. Measured after the exec: CapBnd
// 000001fffff7ffff and 0 of 9 threads holding anything wider.
//
// Called anywhere in this package OTHER than on a locked thread with an execve
// at the end of it, this is a no-op that looks like it worked. __stage-serve
// does not take that on trust — requireCapDropped sweeps every thread and
// refuses.
func dropFromBounding(names []string) error {
	for _, name := range names {
		bit, ok := engineCapBit[name]
		if !ok {
			return fmt.Errorf("dropFromBounding: %q is not a capability this package knows the "+
				"kernel bit for (see engineCapBit in internal/stage/capdrop.go)", name)
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(bit), 0, 0, 0); err != nil {
			return fmt.Errorf("dropFromBounding: PR_CAPBSET_DROP(%s=%d): %w", name, bit, err)
		}
	}
	return nil
}

// requireCapDropped refuses unless EVERY thread of this process has already
// lost the named capabilities from its bounding set, effective set and
// permitted set.
//
// It is the enforcement, and the prctl in __stage-setup is only the mechanism.
// Invariant 5: if the drop did not stick, the run refuses rather than
// proceeding with a guarantee it does not have. The sweep is over
// /proc/self/task/*/status and not /proc/self/status, for exactly the reason
// dropFromBounding's own comment gives — a per-task transition performed by
// the previous stage is verified in the next one, the same shape and the same
// place as threadsInNamespace directly above the caller.
//
// The task list is read ONCE and a thread could in principle appear after it.
// That is not a gap, and the reason is a kernel property rather than timing: a
// bounding set can only ever be LOWERED (there is no PR_CAPBSET_RAISE), and a
// new thread clones its credentials from the one that made it. So every thread
// this process will ever have descends from the leader whose set the execve
// already reduced, and none of them can hold more than it does. Re-reading the
// directory in a loop would buy nothing and would only look careful.
func requireCapDropped(names []string) error {
	tids, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return fmt.Errorf("reading /proc/self/task to verify the capability drop: %w", err)
	}
	if len(tids) == 0 {
		return fmt.Errorf("/proc/self/task is empty, so the capability drop cannot be verified")
	}
	for _, name := range names {
		bit, ok := engineCapBit[name]
		if !ok {
			return fmt.Errorf("requireCapDropped: %q is not a capability this package knows the "+
				"kernel bit for (see engineCapBit in internal/stage/capdrop.go)", name)
		}
		for _, tid := range tids {
			for _, field := range []string{"CapBnd", "CapPrm", "CapEff"} {
				set, err := readCapField("/proc/self/task/"+tid.Name()+"/status", field)
				if err != nil {
					return fmt.Errorf("verifying the capability drop: %w", err)
				}
				if set&(1<<uint(bit)) != 0 {
					return fmt.Errorf("the stage still holds %s (%s bit %d) on thread %s: the "+
						"PR_CAPBSET_DROP in __stage-setup did not survive the execve into "+
						"__stage-serve, so the gate issue #61 settled on — nothing snug puts in "+
						"the stage's user namespace may hold %s — does not hold for this run. "+
						"Refusing rather than running a sandbox whose supervisor can ptrace the "+
						"container engine. See policy.StageCapDrop",
						name, field, bit, tid.Name(), name)
				}
			}
		}
	}
	return nil
}

// readCapField parses one CapBnd/CapPrm/CapEff line out of a
// /proc/<pid>/status file. The value is a 16-digit hex mask with no 0x
// prefix.
func readCapField(path, field string) (uint64, error) {
	// HOSTREAD-EXEMPT: the only caller builds path as
	// "/proc/self/task/<tid>/status" from a directory entry this process just
	// read out of its OWN /proc/self/task. It is procfs, and it is this
	// process's own, so issue #337's hazard — a FIFO planted at a host path
	// turning ReadFile into an open(2) that never returns — has nothing to
	// plant on. path is a parameter only so the sweep can name each thread.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name != field {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing %s from %s (%q): %w", field, path, value, err)
		}
		return mask, nil
	}
	return 0, fmt.Errorf("%s names no %s line", path, field)
}

// capLastCap reads /proc/sys/kernel/cap_last_cap — the running kernel's own
// highest-numbered capability — rather than trusting unix.CAP_LAST_CAP, the
// value the x/sys/unix package this binary was BUILT against happened to
// know about. A kernel newer than the build (one more capability added) would
// otherwise leave that new bit in the bounding set undropped, silently, which
// is exactly the class of gap this whole file exists to close.
func capLastCap() (int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/sys/kernel/cap_last_cap: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing /proc/sys/kernel/cap_last_cap (%q): %w", data, err)
	}
	return n, nil
}
