package policy

// StageCapDrop is what P1 — the stage — removes from its OWN capability
// bounding set at the `__stage-setup` -> `__stage-serve` execve, before it has
// forked anything.
//
// It is the one line issue #61's settlement measured as the gate that works.
// Case F of that review's matrix measured that hardening a TARGET — `CapEff` 0,
// `NoNewPrivs` 1, `dumpable` 0 — does not stop a full-capability peer in U from
// reading and writing it. Case G measured the gate that does: take
// `CAP_SYS_PTRACE` away from the PEERS.
//
// ABUSE: a process snug puts in U holding CAP_SYS_PTRACE can PTRACE_ATTACH,
// process_vm_readv and open /proc/<pid>/mem of every other process in U — the
// container engine, which holds the delegated subuid range and CAP_SYS_ADMIN,
// and the outer bwrap while it is still building the sandbox's mount tree — and
// so read their memory or rewrite what they are doing.
//
// # A drop list, not a keep set
//
// P1's set is "full minus this", deliberately. A keep set for P1 would be a
// second capability floor — bwrap's — and nobody has measured that one.
// EngineCapBounding IS a measured floor, and P1's bounding set is the CEILING
// over it: the engine's clone carries no CLONE_NEWUSER, so its permitted set is
// recomputed from this bounding set at its execve. The two must stay disjoint.
// If they ever are not, capset(2) refuses a permitted set outside the bounding
// set and the engine fails LOUDLY rather than running silently under-capped —
// and TestStageCapDropAndEngineCapBoundingAreDisjoint catches it at `go test`
// before that.
//
// # SCOPE THIS SENTENCE, the same way EngineCapBounding scopes issue #412
//
// What it denies is P1 and every descendant that STAYS in U: `__innetns`, the
// outer bwrap, the engine, conmon, and crun up to the moment crun makes the
// container's own user namespace.
//
// It does NOT reach bwrap's init, the payload, or any container. MEASURED:
// `unshare -Ur setpriv --bounding-set -sys_ptrace unshare -Ur cat
// /proc/self/status` reports `CapBnd = 000001ffffffffff` — create_user_ns sets
// cap_bset back to the full set. The regained bit holds only in the namespace
// that regained it and its descendants, never in an ancestor, so it reaches
// nothing in U. Write the claim the narrow way or a red team refutes it in one
// command.
//
// # And it is enforceable on the staged arm only
//
// On the offline, stage-less topology there is no P1: P0 forks bwrap directly
// with CLONE_NEWUSER, so the outer bwrap CREATES U and gets a full bounding set
// by the same measurement. It cannot be reduced from outside — Go's
// SysProcAttr can add ambient capabilities and cannot drop bounding ones — and
// doing it would need a re-exec shim snug does not have. "Nothing snug puts in
// U holds CAP_SYS_PTRACE" is a property of the STAGED arm.
//
// # What this closes, and what Yama closes
//
// The two routes to another process's memory — /proc/<pid>/mem and
// process_vm_readv, PTRACE_ATTACH besides — are all PTRACE_MODE_ATTACH, which
// is gated by BOTH the capability and Yama. So the honest split is: the
// capability drop closes the CROSS-UID route, which is the one SubuidFull
// opens by giving the engine a delegated range; Yama's ptrace_scope closes the
// same-uid sibling route, and at ptrace_scope 0 it closes nothing.
//
// That is why this is not theatre on a hardened-off host: preflight P6
// (internal/cli/containerpreflight.go, preflightPtraceScope) REFUSES a
// container run where ptrace_scope is 0 or Yama is absent, rather than running
// with an argument that no longer holds. The two mechanisms are checked
// separately and neither is allowed to stand in for the other.
//
// A fixed constant and NEVER a Profile field, for EngineCapBounding's reason
// facing the same way: a field would let a profile hand its own sandbox's
// supervisor back the bit this exists to remove.
//
// `snug attach` is already stricter than this from its own side: it drops the
// whole bounding set to zero before its execve (`CapBnd:
// 0000000000000000`, ATTACH.md §2 M11), which is what it must do — a
// full-capability process put back in U would undo this gate from outside.
var StageCapDrop = []string{"CAP_SYS_PTRACE"}
