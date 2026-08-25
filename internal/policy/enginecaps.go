package policy

// EngineCapBounding is the capability bounding set the container engine
// process (podman) is reduced to after the stage forks it into U — the
// sandbox's own user namespace — as root-in-U (issue #63, Tier B). Root-in-U
// holds the FULL set in U by default, which is exactly what a peer-in-U reads
// with `process_vm_readv`/`/proc/<pid>/mem` (the standing gate, CLAUDE.md).
// This constant is what the engine's own process is bounded to instead.
//
// It is a fixed, exported constant — NOT a Profile field. A field would let a
// profile WIDEN the engine's authority (grant it ptrace, say), which is a
// negative-grant hazard facing the other way from every other grant in this
// package. There is no per-profile reason to vary it: like pasta's closing
// flag set, it is a mechanism, not a grant. internal/policy is the single
// author (invariant 6): both the stage (which performs the numeric drop,
// PR_CAPBSET_DROP + capset, after the raw fork) and --dry-run (which renders
// this named set on screen) read the SAME value, so the set the engine
// actually gets and the set on screen cannot diverge. Widening it is
// necessarily a golden diff (topology.podman-*.txt) — no profile author can
// touch it.
//
// MEASURED FLOOR (host-bridge, M-CAP, 2026-08-18): all 12 caps are required;
// none is droppable; CAP_SYS_PTRACE is never required at any cap count tried.
// A container engine op (podman run/pull/build) can exit 0 even when the
// container it started is cap-starved, because a container's DELIVERED
// capability set is its own default set INTERSECTED with the engine's
// bounding set — dropping a cap from this list does not fail podman's own
// exit code, it silently strips that capability from every container's
// default set. A naive peel of this list against "does `podman run alpine
// true` exit 0" finds a false 4-cap floor (DAC_OVERRIDE, SETGID, SETPCAP,
// SYS_ADMIN) that looks like a tighter bound and is not one: it under-grants
// every container. Do NOT re-derive this list from op-exit success; re-derive
// it, if ever, from the delivered container capability set
// (/proc/<pid>/status CapEff inside a running container), which is what
// M-CAP actually checked (12 caps in -> container receives the full
// M1 container set 0x800405fb; dropping CAP_NET_BIND_SERVICE from this list
// measurably drops exactly that bit from the container's own set).
//
// CAP_NET_ADMIN is deliberately EXCLUDED (maintainer decision, "NET_ADMIN
// decision", 2026-08-18): containers share the sandbox's network namespace N
// host-mode, with no per-container bridge and no `podman run -p N:80` port
// publishing. A compromised engine must not be able to reconfigure N — that
// is what dropping NET_ADMIN buys, and it is why port publishing is declined
// rather than paid for with a 13th cap.
//
// EXCLUDED, each a specific denial: CAP_SYS_PTRACE (the standing gate —
// cannot process_vm_readv or read /proc/<pid>/mem of a peer in U, and only on
// ptrace_scope>=1, which is why preflightPtraceScope refuses 0);
// CAP_NET_ADMIN (below); CAP_MKNOD (rootless crun bind-mounts devices rather
// than creating them); CAP_DAC_READ_SEARCH, CAP_SYS_MODULE, CAP_SYS_RAWIO,
// CAP_SYS_BOOT, CAP_SYS_TIME, CAP_BPF, CAP_PERFMON, CAP_AUDIT_*, CAP_MAC_*.
//
// SCOPE THAT SENTENCE (issue #412): what the exclusion denies is the engine's
// OWN process in U, and any descendant that stays in U. It is not a denial of
// the bit to everything the engine runs. A nested user namespace resets the
// bounding set to full — measured, CapBnd 000001ffffffffff with CAP_NET_ADMIN
// present after `unshare -U -r` from a container holding only podman's
// default 0x800405fb — and every cap in this file is subject to that, not
// only CAP_SYS_PTRACE. The decision survives it because the regained bit is
// namespace-relative and worthless against N: measured from root in a child
// userns U', SIOCSIFFLAGS(lo,DOWN) on N -> EPERM and setns(inherited netns
// fd, CLONE_NEWNET) -> EPERM, where the same fd and syscall from a process
// that stayed in U succeed. The constraint on N is OWNERSHIP of N, which this
// list cannot grant; the cap count is how the engine's own reach is bounded,
// not what makes N unreachable.
var EngineCapBounding = []string{
	// Each comment is "why podman needs it" then ABUSE: "a compromised engine
	// holding it in U can ___" (the working agreement's abuse sentence, which
	// belongs at the grant). Every one is bounded by U and by the engine's
	// DERIVED view — it can only ever name paths the resolved Policy granted.
	//
	// mount overlay/tmpfs/proc/bind, unshare/setns, pivot_root — the
	// irreducible reason the engine cannot take the container's own set.
	// SYS_ADMIN does NOT satisfy PTRACE_MODE_ATTACH, so excluding
	// CAP_SYS_PTRACE below still holds with this one present.
	// ABUSE: mount/remount and enter namespaces within U.
	"CAP_SYS_ADMIN",
	// pivot_root/chroot into a container rootfs.
	// ABUSE: chroot within U's mount tree.
	"CAP_SYS_CHROOT",
	// chown extracted image files across the delegated subuid range.
	// ABUSE: chown within the mapped range only — a uid outside the map is
	// unreachable.
	"CAP_CHOWN",
	// read/write/traverse extraction targets regardless of mode.
	// ABUSE: read/write any file its derived view names, ignoring mode. The
	// proxy's bind filter is what stops a CONTAINER naming more (belt and
	// braces: the view is structural, the filter is by name).
	"CAP_DAC_OVERRIDE",
	// chmod/utime/setxattr on extracted files.
	// ABUSE: bypass ownership checks on metadata ops within U.
	"CAP_FOWNER",
	// preserve setuid/setgid bits on extracted files.
	// ABUSE: keep suid bits on files it writes.
	"CAP_FSETID",
	// run a container process as its configured id; setgroups.
	// ABUSE: setuid/setgid within the mapped range only.
	"CAP_SETUID",
	"CAP_SETGID",
	// hand a container its own capability set from the bounding/inheritable
	// sets — this is the intersection mechanism above: a container's
	// delivered set is its default set ∩ this bounding set.
	// ABUSE: raise/drop caps in its own sets within U; cannot exceed the
	// bounding set it was given.
	"CAP_SETPCAP",
	// write file capabilities on extracted files (some images ship fcaps).
	// ABUSE: set fcaps on files it can write — and this is the cap that lets
	// a container unshare its own userns and regain a full bounding set (see
	// the scope note above), because verify_root_map wants it in the parent.
	"CAP_SETFCAP",
	// signal container processes it owns.
	// ABUSE: signal processes it owns.
	"CAP_KILL",
	// bind low ports in the shared netns N — the same reach the sandbox
	// already has, nothing wider.
	// ABUSE: bind a low port in N, which the sandbox can do anyway.
	"CAP_NET_BIND_SERVICE",
}
