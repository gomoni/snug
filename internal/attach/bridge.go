// Package attach performs the raw-fork syscall sequence that joins an
// already-running snug sandbox's namespaces and reproduces its confinement —
// no more, no less. It is issue #61 part (e): the "content of the feature is
// confinement, not entry" half. Namespace surgery lives in its own package,
// by analogy with internal/stage, because it is exactly as raw-syscall-heavy
// and exactly as unsafe to get casually wrong.
//
// # Why every step here is a raw syscall
//
// The calling process (`snug attach`, package internal/cli) is an ordinary
// multithreaded Go program. setns(CLONE_NEWUSER) and setns(CLONE_NEWNS) both
// refuse a multithreaded, multi-fs_struct caller with EINVAL — see
// .claude/design/NOCGO.md §2. A raw fork(2) (here: clone(SIGCHLD)) from a
// multithreaded Go program yields a child that is single-threaded and owns
// its own fs_struct, which is exactly the two states the kernel checks
// (NOCGO.md §3). That only holds until the child either execs or exits, so
// between the fork and its endpoint (execve for A, _exit for B) this whole
// package touches NOTHING that could allocate, lock, or otherwise re-enter
// the Go runtime's scheduler: no channels, no maps, no defer, no fmt, no
// interface boxing where it can be avoided. Everything the raw-fork children
// need is marshalled into flat, already-allocated memory by the caller
// BEFORE the fork (Config, built in internal/cli/attach.go).
//
// # Why RawSyscall and not the golang.org/x/sys/unix wrappers
//
// unix.Setns and unix.Prctl are implemented with Syscall/Syscall6, which call
// into the Go scheduler's entersyscall/exitsyscall around the trap — safe for
// an ordinary goroutine, not safe for a process that exists only because it
// skipped that scheduler entirely. unix.Capset happens to already use
// RawSyscall (verified against golang.org/x/sys@v0.47.0), so it is used
// as-is; everything else the sequence needs (prctl, setns, seccomp — which
// has no wrapper at all — dup3, chdir, execve, wait4, exit_group,
// rt_sigprocmask) is issued directly against unix.RawSyscall/RawSyscall6.
//
// # What this package does NOT do
//
// It does not resolve profiles, read TOML, or decide what the attached
// process may see — it reproduces a policy that has already been resolved
// and is already running. It does not gate entry: any same-uid process can
// join these namespaces with or without snug (issue #61's settlement). It
// does not harden the attached process against the sandboxed payload — M17
// in the design measured that PR_SET_DUMPABLE does not survive an execve, so
// there is no cheap instrument to add here, and none is added.
package attach

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SevenNamespaceFlags is the exact CLONE_NEW* set attach joins, in ONE
// setns(2) call — never several, because the kernel installs the set
// atomically and a sequence of six calls has six partial-membership states,
// any one of which is a topology nothing in snug describes.
//
// A golden test (internal/cli) asserts this literal value: a change to it is
// a change to the security boundary and must read as one.
//
// CLONE_NEWTIME is deliberately absent: bwrap creates no time namespace, so
// there is nothing to join, and — like CLONE_NEWPID — it would apply to
// children only, meaning a flag with no consumer.
const SevenNamespaceFlags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID |
	unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP

// Linux signal-mask syscall constants. Not exported by golang.org/x/sys/unix
// under these names; values are architecture-independent
// (linux/asm-generic/signal.h).
const (
	sigBlock   = 0
	sigSetmask = 2
)

// sigsetSize is sizeof(kernel_sigset_t) at the syscall ABI boundary: 64
// signals, 8 bytes. Not sizeof(C sigset_t) as libc defines it — the raw
// kernel one, which is what rt_sigprocmask(2) wants as its fourth argument.
const sigsetSize = 8

// Config is everything the raw-fork children (B, then A) need, marshalled by
// the caller into flat memory BEFORE the fork. Nothing in here is allocated,
// grown, or looked up again once Start is called — see the package comment
// for why.
type Config struct {
	// PidFD is a pidfd on the sandbox's init, opened and validated by the
	// caller (internal/cli/attach.go, §4.1 steps 1-5). This package neither
	// opens nor closes it.
	PidFD int

	// CapLastCap is /proc/sys/kernel/cap_last_cap, read by the caller — NEVER
	// hardcoded here, because a newer kernel with more capabilities would
	// otherwise leave the new ones in the bounding set silently.
	CapLastCap int

	// SeccompProg is the assembled BPF program (sandbox.BuildFilter's
	// output) to install in B before the namespace join. Nil means "install
	// nothing" — the run was started with --no-seccomp, and attach honours
	// that rather than adding a second weakening knob.
	SeccompProg []byte

	// Chdir, Argv0, Argv, Envp describe A's eventual execve. Argv0 is
	// resolved and validated by the caller (§8.4); Argv[0] conventionally
	// equals it but is not assumed to.
	Chdir string
	Argv0 string
	Argv  []string
	Envp  []string

	// PTY is true exactly when Stdin/Stdout/Stderr below are the same fresh
	// pty slave (internal/cli/attachstdio.go's interactive branch), never for
	// the pipe-relay branch. It gates ONE thing in child(): immediately
	// before A's execve, on the pty path only, A calls setsid() then
	// ioctl(0, TIOCSCTTY) — becomes a session leader and makes the pty its
	// controlling terminal, which is what an interactive shell needs for job
	// control (fg/bg/^Z) to work at all. False on the pipe path: a pipe has
	// no controlling-terminal concept, and calling TIOCSCTTY on fd 0 there
	// would be a syscall on a descriptor that was never a tty.
	PTY bool

	// Stdin, Stdout, Stderr are the fds A ends up with as 0/1/2, dup3'd into
	// place immediately before its execve. They may already BE 0/1/2 (a
	// terminal pass-through) or any other descriptor this process holds — the
	// caller decides which, per the design's stdio-relay rule.
	Stdin, Stdout, Stderr int

	// ReportW is B's end of the report pipe: B writes one byte to it once
	// confinement is fully applied (§4.2a). GateR is B's end of the gate
	// pipe: B blocks reading one byte from it before proceeding to chdir and
	// fork A. The caller holds the other ends and runs the verify-then-
	// release gate against /proc/<B>/status in between.
	ReportW, GateR int

	// SignalMask is the caller's OWN current signal mask
	// (rt_sigprocmask(SIG_SETMASK, nil, &old)), captured before the fork. B
	// blocks every signal for the whole of its raw-syscall sequence — a
	// signal delivered mid-sequence would run whatever handler this process
	// image has installed (Go's own, copied verbatim by fork), and those
	// handlers reach into scheduler state this single-threaded, doomed-to-
	// never-schedule-again child must not touch. A restores exactly this
	// mask immediately before its own execve, so the exec'd program's signal
	// behaviour is unremarkable.
	SignalMask [sigsetSize]byte
}

// Start forks the bridge (B). The calling goroutine MUST already be pinned
// with runtime.LockOSThread — Start does not call it, because the caller
// (internal/cli/attach.go) has to stay on that exact OS thread until it has
// wait4'd B to completion: PR_SET_PDEATHSIG fires on the death of the
// THREAD that created the child, not merely the process, so an unlocked
// forking goroutine whose thread the Go runtime later retires kills the
// attached session for no reason.
//
// It returns B's pid, in the CALLER's OWN pid namespace (the only one C ever
// has — C never calls setns itself). The caller uses it to run the release
// gate against /proc/<pid>/status (§4.2a) and, at the very end, to wait4 for
// B's exit status.
//
// Everything from here to the fork's return is safe, ordinary Go: it is the
// CHILD branch — the pid == 0 half of the raw clone's return — that must never
// come back out through this function. child's every path ends in a raw
// exit_group; there is no return statement in it that reaches Start's own
// return.
func Start(cfg *Config) (int, error) {
	// Everything child() dereferences is pre-marshalled into cfg's own
	// fields, which are ordinary Go values kept alive by the caller's own
	// stack frame for the life of the call — nothing is computed fresh here
	// that the child would need to allocate for.
	marshalled, err := marshal(cfg)
	if err != nil {
		return 0, err
	}

	// Block every signal on THIS thread across the fork, and put the mask
	// back the moment the clone has returned in the parent. Two different
	// windows need this, and child()'s own step 1 covers neither, because it
	// is already too late by the time it runs:
	//
	//   - A signal delivered to B between the clone returning and step 1
	//     runs whatever handler this process image has installed — Go's own,
	//     copied verbatim by fork — inside a process the Go runtime cannot
	//     schedule. ^C to a foreground process group is the everyday
	//     spelling. The child inherits this blocked mask, so the window
	//     closes; step 1 stays as the statement of the property for a reader
	//     of child(), and A restores cfg.SignalMask before its execve.
	//   - The parent's own mask is restored below on every path, including
	//     the clone-failed one.
	var blockAll, saved [sigsetSize]byte
	for i := range blockAll {
		blockAll[i] = 0xff
	}
	rtSigprocmaskRaw(sigSetmask, &blockAll, &saved)

	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		rtSigprocmaskRaw(sigSetmask, &saved, nil)
		return 0, fmt.Errorf("attach: clone(SIGCHLD): %w — this is the same raw fork "+
			"internal/stage relies on for the same reason (see .claude/design/NOCGO.md §3); "+
			"if it fails here it is a resource limit (RLIMIT_NPROC, pid_max), not a permission "+
			"problem", errno)
	}
	if pid == 0 {
		// CHILD (B). Never returns.
		//
		// This call is the FIRST instruction the fork child executes, and
		// issue #221 is what happens when it is an ordinary Go call: an
		// ordinary function's prologue compares SP against the goroutine's
		// stackguard0, and the runtime POISONS stackguard0 with stackPreempt
		// whenever it wants this goroutine preempted — every stop-the-world,
		// and sysmon's retake of any goroutine that has been running for
		// 10ms. The parent carries that poison into the child, whose
		// prologue then calls runtime.newstack, which asks the scheduler for
		// threads that the fork did not copy. Measured: futex_do_wait,
		// forever, with SigBlk=0 / NoNewPrivs=0 / Seccomp=0 / the caller's
		// own namespaces — B stopped before step 1, which is also before
		// step 2's PDEATHSIG, so it outlived a killed C by hours. C, for its
		// part, was still in its report-pipe read. 17 of 40 forks wedged
		// under stop-the-world pressure with a splittable first call, 0 of
		// 40 with a nosplit one.
		//
		// So child() and EVERY function it can reach carry //go:nosplit,
		// which removes the prologue that consults the poisoned value at
		// all. The linker enforces the budget for the whole chain, so a call
		// added here to something splittable is a BUILD failure and not a
		// rare hang — see TestEveryFunctionOnTheChildPathIsNosplit for the
		// half the linker does not check.
		child(marshalled)
		// Unreachable: child's every path is a raw exit_group. If control
		// somehow reaches here, the only safe thing left to do is the same —
		// anything else risks running Go runtime code this process must not
		// touch.
		exitGroupRaw(127)
	}
	rtSigprocmaskRaw(sigSetmask, &saved, nil)
	return int(pid), nil
}

// marshalled is Config, flattened into the exact pointers and NUL-terminated
// byte layouts execve(2), chdir(2) and seccomp(2) want. Built once, in the
// parent, before the fork — see the package comment.
type marshalled struct {
	pidfd      int
	capLastCap int
	sockFprog  unix.SockFprog // zero Len/nil Filter means "no filter"
	chdirC     []byte         // NUL-terminated
	argv0C     []byte         // NUL-terminated
	argvPtrs   []uintptr      // NUL-terminated array of pointers into argvC entries
	argvC      [][]byte       // keeps every argv element's backing array alive
	envpPtrs   []uintptr
	envpC      [][]byte
	stdin      int
	stdout     int
	stderr     int
	reportW    int
	gateR      int
	signalMask [sigsetSize]byte
	pty        bool
}

func marshal(cfg *Config) (*marshalled, error) {
	if cfg.Argv0 == "" || len(cfg.Argv) == 0 {
		return nil, fmt.Errorf("attach: empty argv")
	}

	m := &marshalled{
		pidfd:      cfg.PidFD,
		capLastCap: cfg.CapLastCap,
		chdirC:     cStringOrDot(cfg.Chdir),
		argv0C:     cString(cfg.Argv0),
		stdin:      cfg.Stdin,
		stdout:     cfg.Stdout,
		stderr:     cfg.Stderr,
		reportW:    cfg.ReportW,
		gateR:      cfg.GateR,
		signalMask: cfg.SignalMask,
		pty:        cfg.PTY,
	}

	if len(cfg.SeccompProg) > 0 {
		if len(cfg.SeccompProg)%8 != 0 {
			return nil, fmt.Errorf("attach: seccomp program length %d is not a multiple of 8 "+
				"(sizeof(struct sock_filter)) — this is a bug in sandbox.BuildFilter, not a "+
				"property of the running sandbox", len(cfg.SeccompProg))
		}
		prog := cfg.SeccompProg
		m.sockFprog = unix.SockFprog{
			Len:    uint16(len(prog) / 8),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0])),
		}
		// Keep the backing array reachable for the lifetime of m. It already
		// is, via cfg.SeccompProg staying alive in the caller — this
		// assignment is only about making the intent explicit for a reader.
	}

	m.argvC = make([][]byte, len(cfg.Argv))
	for i, a := range cfg.Argv {
		m.argvC[i] = cString(a)
	}
	m.argvPtrs = make([]uintptr, len(m.argvC)+1)
	for i, b := range m.argvC {
		m.argvPtrs[i] = uintptr(unsafe.Pointer(&b[0]))
	}
	// Trailing NULL, per execve(2).

	m.envpC = make([][]byte, len(cfg.Envp))
	for i, e := range cfg.Envp {
		m.envpC[i] = cString(e)
	}
	m.envpPtrs = make([]uintptr, len(m.envpC)+1)
	for i, b := range m.envpC {
		m.envpPtrs[i] = uintptr(unsafe.Pointer(&b[0]))
	}

	return m, nil
}

func cString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	// b[len(s)] is already 0.
	return b
}

func cStringOrDot(s string) []byte {
	if s == "" {
		s = "/"
	}
	return cString(s)
}
