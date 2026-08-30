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
	fdNetSock = 66

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
	fdNetnsN = 67
)

// fdPremainSlack is how many descriptor numbers are left free BETWEEN the top
// of the pass-through block and fdNetSock, for the descriptors the Go runtime
// opens BEFORE main and keeps for the life of the process.
//
// It exists because reserveParkingFDs cannot claim a number the runtime took
// first, and the runtime runs first by construction:
// runtime/cgroup_linux.go's own comment says defaultGOMAXPROCSInit reads
// /proc/self/cgroup and /proc/self/mountinfo "to find our current CPU cgroup
// and open its limit file(s), which remain open". internal/runtime/cgroup's
// CPU is {quotaFD, periodFD}: ONE descriptor under cgroup v2 (cpu.max), TWO
// under v1 (cpu.cfs_quota_us, cpu.cfs_period_us). Netpoll's epoll and eventfd
// are the other two, and they are pre-main as well whenever anything arms a
// timer that early — MEASURED on the author's host, a Go program's descriptor
// table at its first statement: 3=anon_inode:[eventpoll], 4=anon_inode:[eventfd].
//
// So four, and each one is named rather than rounded. The kernel hands out the
// LOWEST free descriptor, so all four land immediately above the inherited
// block; with the block at its maximum they land exactly on the reserved
// numbers, which is what CI measured (GitHub Actions run 33301432323, both the
// ubuntu and the Tumbleweed job, at exactly the budget): "fd 62, where the N
// socket must be parked, is ALREADY OPEN (/sys/fs/cgroup/cpu.max)". It was
// green on the author's machine because /proc/self/cgroup there reads
// `0::/../../app.slice/...` — a relative path from a namespaced cgroup view,
// so cgroup.OpenCPU fails with ErrNoCgroup and the runtime holds nothing.
//
// A future runtime that opens a FIFTH pre-main descriptor is not a silent
// failure: reserveParkingFDs refuses it loudly and requireFDFree's message
// names this constant.
const fdPremainSlack = 4

// maxPassthrough is how many descriptors the pass-through block can hold
// before it reaches the descriptors reserved above it. Derived, never written
// down twice: it follows fdNetSock, the first thing the block would collide
// with, less the slack the Go runtime's own pre-main descriptors need — adding
// a second reserved fd above the block without moving this bound is exactly
// the collision checkFDBudget exists to refuse.
//
// BOTH terms are load-bearing, and each was a separate defect.
//
// The subtraction of fdSandboxBase alone counts the BLOCK and nothing else,
// while __stage-setup goes on to allocate three more descriptors above the
// block before the second parking — the N socket, plus the Go runtime's
// netpoll epoll and eventfd. MEASURED at K = 53, 54, 55, 56 with the block
// inherited from P0: 53 ran, and 54/55/56 were refused at the parking with fd
// 62 already holding an eventfd, an eventpoll and the N socket respectively.
// reserveParkingFDs is what closes that, by claiming the numbers before any of
// those allocations happen.
//
// fdPremainSlack is the rest of it, and it is the part a reservation CANNOT
// close: the runtime opens the cgroup CPU limit file, and often netpoll's
// pair, before main runs at all, so those numbers are gone before P1 executes
// its first statement. MEASURED on CI, where the author's host holds no cgroup
// descriptor and so never saw it: at exactly the budget, "fd 62 ... is ALREADY
// OPEN (/sys/fs/cgroup/cpu.max)". See fdPremainSlack.
//
// Raising the reserved numbers alone fixes neither shape, because the kernel
// allocates the lowest free descriptor and every one of these allocations
// follows the block wherever it goes. Claiming the numbers first plus leaving
// slack below them is what makes this constant exact rather than approximately
// right.
const maxPassthrough = fdNetSock - fdSandboxBase - fdPremainSlack

// NetnsFD is fdNetnsN under an exported name, for the one caller outside this
// package that has to NAME the descriptor rather than hold it: `snug --dry-run`
// prints the pasta argv, and pasta is aimed at /proc/<stage>/fd/<n>. A number
// re-typed there is a copy of state that goes stale the instant this file
// moves it, and the screen it goes stale on is the one CLAUDE.md calls "the
// mechanism by which a human can trust snug at all".
const NetnsFD = fdNetnsN

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
			"would run from fd %d to fd %d and reach the numbers reserved above it: fd %d..%d, "+
			"the slack the Go runtime's pre-main descriptors need (fdPremainSlack), and then "+
			"the N socket at fd %d and the pinned network namespace descriptor at fd %d "+
			"(the budget is %d).\n"+
			"      The fix is to RAISE fdNetSock and fdNetnsN in internal/stage/fds.go above "+
			"the block — they are a free choice, not kernel constants, and each descriptor is "+
			"dup3'd to its number explicitly. Do not lower the descriptor count: it is what the resolved policy "+
			"actually needs (one per generated file, one for the seccomp filter, one for "+
			"bwrap's --info-fd, two more for the --block-fd/--sync-fd gate on a container "+
			"run, and one for the args memfd)",
			n, fdSandboxBase, fdSandboxBase+n-1, fdSandboxBase+maxPassthrough, fdNetSock-1,
			fdNetSock, fdNetnsN, maxPassthrough)
	}
	return nil
}

// requireFDFree refuses a dup3 TARGET that is already open. It guards
// reserveParkingFDs, which is the ONE place in this package that dup3s onto a
// number nothing has claimed yet. checkFDBudget bounds how far the
// pass-through block may grow from the count P0 resolved; this checks the same
// fact from the descriptor table, and it checks it rather than predicting it —
// two trust positions, neither a duplicate of the other.
//
// Why it matters. dup3(2) onto an occupied descriptor CLOSES it and reports
// success, so a collision here has no error to notice. Two things can occupy
// fdNetSock or fdNetnsN at P1's first instant. One is the inherited
// pass-through block, whose size is policy-dependent: a block one over the
// budget reaches fdNetSock. P0's checkFDBudget refuses that count first, and
// this refuses it again from the other side, because MainSetup does not have
// the count and is not entitled to assume P0 checked it. The other is a
// descriptor the Go runtime opened before main, which no reservation can
// preempt — that is what fdPremainSlack leaves room for, and this refusal is
// what a runtime opening more of them than the slack anticipates looks like.
//
// The numbers are snug's own free choice, not kernel constants, so the fix
// this message names is the same one checkFDBudget names: raise both reserved
// descriptors, and the slack below them, above the block.
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
		"      The pass-through block plus the descriptors this process did not open itself "+
		"have reached the reserved range. If the occupant above is one of the Go runtime's "+
		"(a cgroup cpu limit file, an eventpoll, an eventfd), it was opened before main and "+
		"no reservation can preempt it: RAISE fdPremainSlack in internal/stage/fds.go. "+
		"Otherwise RAISE fdNetSock and fdNetnsN above the block, exactly as checkFDBudget's "+
		"message says. All three are a free choice, not kernel constants",
		fd, what, occupant)
}

// reserveParkingFDs claims fdNetSock and fdNetnsN at P1's first instant, before
// this process has allocated a descriptor of its own, so that every later
// allocation avoids them BY CONSTRUCTION rather than by a check racing an
// allocator snug does not control.
//
// Why claiming beats checking. The descriptors that would collide are not
// snug's: the Go runtime creates its netpoll epoll and eventfd from a
// background goroutine the first time a timer is armed, so nothing orders them
// against a check, and `requireFDFree(62)` returning nil says nothing about fd
// 62 two lines later. MEASURED, the same tree at the same K with only the body
// of requireFDFree changed: one run laid out socket(61), epoll(62), eventfd(63)
// and the other socket(62), netns(63), epoll(61), eventfd(64) — the position of
// the runtime's pair relative to the parking is not a property snug decides.
// Claiming the numbers first removes the window; no check can.
//
// The placeholder is fdControl, dup3'd with O_CLOEXEC. CLOEXEC is what makes
// the SubuidFull re-exec work: the placeholder dies at that execve and the
// second __stage-setup re-reserves from a clean table, while the REAL
// descriptors parked onto these numbers later are dup3'd with flags 0 and so
// survive the execve into __stage-serve, which is the whole point of the
// numbers being fixed.
func reserveParkingFDs() error {
	for _, r := range []struct {
		fd   int
		what string
	}{
		{fdNetSock, "the N socket"},
		{fdNetnsN, "the pinned netns descriptor"},
	} {
		if err := requireFDFree(r.fd, r.what); err != nil {
			return err
		}
		if err := unix.Dup3(fdControl, r.fd, unix.O_CLOEXEC); err != nil {
			return fmt.Errorf("stage: reserving fd %d for %s: %w", r.fd, r.what, err)
		}
	}
	return nil
}

// requireFDReserved is the parking-site half of the same invariant, and it is
// the INVERSE check: by the time __stage-setup parks the N socket or the
// pinned netns descriptor, reserveParkingFDs has already claimed that number,
// so the target must be OPEN. An EBADF here means the reservation was closed
// by something in this process that did not own it, and the number may since
// have been handed to an allocation that a dup3 would silently destroy — the
// same failure requireFDFree exists to refuse, arriving from the other
// direction.
func requireFDReserved(fd int, what string) error {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return fmt.Errorf("stage: fd %d, where %s must be parked, is NOT the descriptor "+
			"reserveParkingFDs claimed at this process's first instant (%w). Something closed "+
			"a descriptor it does not own, so this number may now belong to another "+
			"allocation, and dup3 onto an occupied descriptor closes it and reports success",
			fd, what, err)
	}
	return nil
}
