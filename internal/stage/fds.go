package stage

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
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
// The phase that puts an engine in N (issue #63, Tier B) does not add it back
// HERE after all, and that is worth stating precisely: it belongs to the
// ENGINE's own fork, not P1's. P1 forks bwrap directly into ITS OWN mount
// view (so bwrap can still build the sandbox's tree); the engine instead gets
// a SEPARATE, later fork, with its own Cloneflags carrying CLONE_NEWNS AND
// CLONE_NEWCGROUP at that fork's own clone(2) — see enginefork.go's
// startEngine, which is the "conscious edit with a consumer to point at" this
// comment used to promise landing here. Nothing about P1's OWN namespace set
// changes: it still clones exactly these three, engine or no engine.
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

	// fdBwrapInfo is the READ end of bwrap's --info-fd pipe (issue #125, the C2
	// gate). The write end travels in the block below, as one of the sandbox's
	// own descriptors, exactly as it always did; what moved out of P0 is the
	// reading of it.
	//
	// It moved because P1 is the process that must be able to KILL bwrap's init
	// — measured: while the payload is parked on --block-fd, bwrap has NOT yet
	// armed --die-with-parent on that init, so killing the outer bwrap leaves it
	// alive and still releasable. P1 is bwrap's parent and the only process in
	// the chain that can own that kill, and it cannot kill a pid it was never
	// told. Learning the pid from bwrap's OWN answer, on a descriptor P1 holds,
	// about a process P1 is the grandparent of, is also what keeps the control
	// protocol free of a client-supplied pid the stage would have to trust
	// (proto.go's header).
	fdBwrapInfo = 5

	// 6 .. 6+K-1, K = len(Config.Sandbox): the sandbox's own descriptors (the
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
	fdSandboxBase = 6

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
	//
	// checkFDBudget covers the block growing INTO this number. requireFDFree
	// covers the other direction and is the half checkFDBudget cannot see:
	// this process's OWN descriptors, allocated above the block by the Go
	// runtime rather than by any policy, landing here first.
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
			"actually needs (one per generated file, one for the seccomp filter, one for "+
			"bwrap's --info-fd, two more for the --block-fd/--sync-fd gate on a container "+
			"run, and one for the args memfd)",
			n, fdSandboxBase, fdSandboxBase+n-1, fdNetnsN, maxPassthrough)
	}
	return nil
}

// requireFDFree refuses a dup3 TARGET that is already open. checkFDBudget
// bounds how far the pass-through block may grow; this checks the other half
// of the same fact, and it checks it rather than predicting it.
//
// Why both are needed. dup3(2) onto an occupied descriptor CLOSES it and
// reports success, so a collision here has no error to notice. Measured at the
// permitted maximum (K = maxPassthrough): the block ends at fd 61, this
// process's own descriptors then land immediately above it — the Go runtime's
// epoll and eventfd among them, allocated the first time anything in the
// process opens an *os.File — and `dup3(src, 62)` reports success while
// closing whatever was there. The symptom is not a crash: it is a Go runtime
// whose netpoller descriptor has silently gone, one process deep inside a
// namespace nothing has attached to yet.
//
// The number is snug's own free choice, not a kernel constant, so the fix this
// message names is the same one checkFDBudget names: raise the reserved
// descriptor above the block.
func requireFDFree(fd int, what string) error {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		if errors.Is(err, unix.EBADF) {
			return nil
		}
		return fmt.Errorf("stage: cannot tell whether fd %d (%s) is free: %w", fd, what, err)
	}
	// Best effort, and only for the message: an occupied descriptor is a
	// refusal whether or not procfs will say what is on it.
	occupant, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || occupant == "" {
		occupant = "unknown"
	}
	return fmt.Errorf("stage: fd %d, where %s must be parked, is ALREADY OPEN (%s), and dup3 "+
		"onto an occupied descriptor closes it and reports success — so this refuses instead "+
		"of taking a live descriptor out of this process with no error to notice.\n"+
		"      The pass-through block plus this process's own descriptors have reached the "+
		"reserved range. The fix is to RAISE fdNetSock and fdNetnsN in internal/stage/fds.go "+
		"above it, exactly as checkFDBudget's message says: both are a free choice, not "+
		"kernel constants",
		fd, what, occupant)
}
