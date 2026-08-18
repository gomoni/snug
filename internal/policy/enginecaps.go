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
var EngineCapBounding = []string{
	// mount overlay/tmpfs/proc/bind, unshare/setns, pivot_root — the
	// irreducible reason the engine cannot take the container's own set.
	// SYS_ADMIN does NOT satisfy PTRACE_MODE_ATTACH, so excluding
	// CAP_SYS_PTRACE below still holds with this one present.
	"CAP_SYS_ADMIN",
	// pivot_root/chroot into a container rootfs.
	"CAP_SYS_CHROOT",
	// chown extracted image files across the delegated subuid range.
	"CAP_CHOWN",
	// read/write/traverse extraction targets regardless of mode — the honest
	// gap the proxy bind filter (not the mount view) guards in Tier B; Tier C
	// makes it structural.
	"CAP_DAC_OVERRIDE",
	// chmod/utime/setxattr on extracted files.
	"CAP_FOWNER",
	// preserve setuid/setgid bits on extracted files.
	"CAP_FSETID",
	// run a container process as its configured id; setgroups.
	"CAP_SETUID",
	"CAP_SETGID",
	// hand a container its own capability set from the bounding/inheritable
	// sets — this is the intersection mechanism above: a container's
	// delivered set is its default set ∩ this bounding set.
	"CAP_SETPCAP",
	// write file capabilities on extracted files (some images ship fcaps).
	"CAP_SETFCAP",
	// signal container processes it owns.
	"CAP_KILL",
	// bind low ports in the shared netns N — the same reach the sandbox
	// already has, nothing wider.
	"CAP_NET_BIND_SERVICE",
}
