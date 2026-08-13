package stage

import (
	"fmt"
	"syscall"
)

// stageCloneflags is the exact clone(2) flag set Start passes when it forks
// P1: a fresh user namespace (U, one uid mapped — SUPERVISOR-DESIGN.md §3.6),
// a fresh network namespace (N, pinned then left — §1), and a private mount
// namespace (§4 Step 4's `mount("", "/", "", MS_REC|MS_PRIVATE, "")` happens
// inside it). It is a named constant rather than an inline expression in Start
// so that TestGoldenStageSpec watches the SAME value Start uses instead of a
// re-typed copy of it — a golden that could drift from the code it describes
// would not be a golden.
//
// CLONE_NEWCGROUP is deliberately NOT here, and its absence is the point.
//
// It was taken originally because the engine will need a cgroup namespace when
// it moves into N. Nothing in Phase 1 uses one: the stage clones, pins, moves,
// forks once and then waits. Taking it early cost something real — clone(2)
// fails as a unit, so a kernel built without CONFIG_CGROUPS killed every `@net`
// run for a namespace no code read. That is the same "a capability with no
// consumer" argument this package already applies to subuid delegation, and it
// was being applied to one of its two halves.
//
// The phase that puts an engine in N adds it back, as a conscious edit with a
// consumer to point at and a golden line to review. TestGoldenStageSpec is what
// makes that edit visible rather than incidental.
const stageCloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET |
	syscall.CLONE_NEWNS

// Fixed descriptor numbers, and they are constants with names — nothing
// travels in the environment. /proc/self/environ is passively readable by
// every process in the sandbox and inherited by every child; a number in an
// env var is one --setenv away from being one, which is exactly the class of
// leak CLAUDE.md's "generate, don't bind" rule exists to close one layer up.
const (
	// fdControl is P1's end of the inherited SOCK_SEQPACKET socketpair.
	fdControl = 3
	// fdLife is the read end of the lifeline pipe. P0 holds the write end and
	// never writes to it; P1 sees EOF the instant P0 dies, however it dies —
	// including SIGKILL, which does not give P0 a chance to signal anyone.
	fdLife = 4

	// 5 .. 5+K-1, K = len(Config.Sandbox): the sandbox's own descriptors (the
	// generated-file memfds, the seccomp filter, the netns handshake pipes),
	// passed through from P0 in the exact order it built them. P1 never opens or
	// reads any of them; it only forwards the *os.File values.
	//
	// Who moves the numbers, since an earlier version of this comment named the
	// wrong party: Go's exec.Cmd machinery does, in runOneSandbox, by dup3'ing
	// ExtraFiles onto 3..3+K-1 — the numbers already baked into bwrap's args
	// memfd. __innetns renumbers NOTHING; it setns's, closes the netns fd, seals
	// and execs the block untouched. dup3 also leaves the SOURCES open in the
	// child, which is why the seal is not optional (see internal/fdseal).
	fdSandboxBase = 5

	// fdNetSock is an AF_INET datagram socket CREATED INSIDE N, kept for the
	// whole run so the stage can answer "is pasta's interface up in N?" after it
	// has left N.
	//
	// The mechanism, and it is the reason the parked window could be deleted: a
	// socket's network namespace is fixed when the socket is created and does
	// NOT follow the process. Measured, with both controls — after the move, a
	// freshly created socket sees lo DOWN in the stage's new empty namespace
	// while this one still sees lo UP in N.
	//
	// Readiness used to be answered by polling /proc/<pid>/net/dev of a process
	// inside N, which required a process inside N, which meant bwrap had to be
	// started BEFORE pasta and parked until pasta came up. That parking is what
	// a SIGKILL of snug could release early. One descriptor removes the whole
	// ordering constraint.
	fdNetSock = 62

	// fdNetnsN is the descriptor P1 pins on N before it leaves. Chosen high so
	// it never collides with the pass-through block above, whose size is
	// policy-dependent (as many data mounts as a resolved Policy has, plus one
	// for the seccomp filter, plus two for the netns handshake pipes when
	// networking is requested).
	//
	// "Chosen high so it never collides" is an assertion about a
	// policy-dependent quantity, and checkFDBudget is what turns it from a
	// comment into a check. Without one the symptom of a collision is not a
	// crash: P1 would hand bwrap the PINNED NETNS DESCRIPTOR as though it were
	// one of the sandbox's own, bwrap would read it as --args or --seccomp or
	// --block-fd, and the run would fail as an unexplained parse error one
	// process further in — which gets debugged in the wrong package.
	fdNetnsN = 63
)

// maxPassthrough is how many descriptors the pass-through block can hold before
// it reaches the LOWEST reserved descriptor above it. Derived, never written
// down twice: it follows fdNetSock, which is now the first thing the block
// would collide with — adding a second reserved fd above the block without
// moving this bound is exactly the collision checkFDBudget exists to refuse.
const maxPassthrough = fdNetSock - fdSandboxBase

// checkFDBudget refuses a pass-through block that would collide with the
// pinned netns descriptor, LOUDLY and by name, at the two points where the
// count is known: P0's stage.Start (where it comes from the resolved policy)
// and P1's __stage-serve (where it arrives over the control socket and is therefore
// input rather than a local fact).
func checkFDBudget(n int) error {
	if n < 0 {
		return fmt.Errorf("stage: negative pass-through descriptor count (%d)", n)
	}
	if n > maxPassthrough {
		return fmt.Errorf("stage: this policy needs %d pass-through descriptors, so the block "+
			"would run from fd %d to fd %d and swallow the pinned network namespace "+
			"descriptor at fd %d (the budget is %d).\n"+
			"      The fix is to RAISE fdNetnsN in internal/stage/fds.go above the block — it "+
			"is a free choice, not a kernel constant, and the descriptor is dup3'd to it "+
			"explicitly. Do not lower the descriptor count: it is what the resolved policy "+
			"actually needs (one per generated file, one for the seccomp filter, two for the "+
			"netns handshake, one for the args memfd)",
			n, fdSandboxBase, fdSandboxBase+n-1, fdNetnsN, maxPassthrough)
	}
	return nil
}
