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
