// Package sigseal is fdseal's twin for signal state: the last thing an exec
// verb does before it BECOMES bwrap, so that what the payload can be told is a
// property of the policy rather than of whatever started snug.
//
// WHAT LEAKS, AND WHY IT IS ONLY THESE TWO. execve already resets every CAUGHT
// handler to SIG_DFL, so a handler snug or the Go runtime installed cannot
// reach the payload. Two things survive it, both by POSIX design:
//
//	SIG_IGN     an ignored signal stays ignored across execve
//	the mask    the calling thread's blocked set is inherited whole
//
// Either one silently removes a signal from the set the payload can act on. A
// payload's `trap … INT` is a no-op when SIGINT arrived as SIG_IGN — a
// non-interactive shell keeps a signal ignored on entry ignored — and `trap …
// USR1` never runs at all when SIGUSR1 is blocked. MEASURED on this host,
// snug at 655496a, before this package existed:
//
//	bash -c 'snug … &'              staged payload  SigIgn 0000000000000002
//	                                offline payload SigIgn 0000000000000000
//	python blocks USR1, execs snug  BOTH payloads   SigBlk 0000000000000200
//
// The SigIgn asymmetry is the sharper half, because nothing chose it. Go's
// runtime does not install a handler for a signal that was already SIG_IGN at
// startup, and os/exec only resets what the runtime handles — so the offline
// arm escaped only because armTeardown's signal.Notify runs before
// internal/sandbox's cmd.Start(), while the stage is forked before the guard
// is armed and passed SIG_IGN straight through. One policy, two behaviours,
// decided by the order of two lines 200 apart: invariant 6.
//
// HOW THE DISPOSITION IS RESET, since there is no arch-independent way to call
// rt_sigaction from Go without cgo (NOCGO.md) and x/sys/unix exports Sigaction
// on BSD only. signal.Notify installs a Go handler OVER the inherited SIG_IGN,
// and the execve that follows resets that handler to SIG_DFL — the two
// documented behaviours composed, with no struct layout to get wrong on arm64.
// MEASURED, a throwaway Go program exec'd under `trap "" INT`: SigIgn
// 0000000000000002 without the Notify, 0000000000000000 with it.
//
// Only the signals that are ACTUALLY ignored are touched, read from
// /proc/self/status rather than probed. Notify on the whole catchable range
// would install handlers over signals the Go runtime owns for its own reasons
// — SIGURG is preemption — to fix something that was not broken.
//
// THE RESIDUAL, stated rather than swept: a realtime signal (>= 32) is not
// reset here. signal.Notify's behaviour on the numbers the Go runtime reserves
// is not something to rely on, and nothing has been measured ignoring one. The
// MASK clear below covers every signal including those, so a blocked realtime
// signal is already handled; an IGNORED one is not.
package sigseal

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Seal clears this thread's signal mask and arranges for every currently
// ignored signal to reach the payload at its default disposition instead.
//
// It must be called on a thread that is LOCKED to this goroutine and
// immediately before syscall.Exec, because the mask execve preserves is the
// CALLING THREAD's: a Go scheduler migration between the clear and the exec
// would hand the payload some other thread's mask. Both callers already hold
// the lock for their own reasons — internal/stage's EnterNetns for setns,
// internal/sandbox's EnterPidNS as pid 1 of the namespace it was cloned into —
// and this takes it again rather than assuming, because LockOSThread nests and
// the assumption is the kind that stays true until someone reorders a file.
//
// A failure REFUSES the run, like every other step in those two verbs: a
// sandbox whose payload cannot be sent SIGTERM is not the sandbox the policy
// describes, and invariant 5 says that is a refusal rather than a quieter run.
func Seal() error {
	runtime.LockOSThread()

	ignored, err := ignoredSignals()
	if err != nil {
		return fmt.Errorf("reading this process's ignored-signal set: %w", err)
	}
	if len(ignored) > 0 {
		// Never read, and that is the whole design: the channel exists so
		// Notify has somewhere to put a signal, and the handler it installs is
		// what execve then resets to SIG_DFL. Buffered so a signal arriving in
		// the microseconds before the exec cannot block the runtime.
		//
		// It does mean a signal landing in that window is SWALLOWED rather
		// than acting on this verb. The window is between a fork and an exec,
		// the process holds nothing but descriptors it is about to hand over,
		// and P0's own teardown guard reaches it as a descendant regardless —
		// see internal/sandbox/teardown.go's confirmTeardown.
		signal.Notify(make(chan os.Signal, len(ignored)), ignored...)
	}

	var empty unix.Sigset_t
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, &empty, nil); err != nil {
		return fmt.Errorf("clearing this thread's signal mask: %w", err)
	}
	return nil
}

// ignoredSignals reads SigIgn from /proc/self/status and returns the signals
// it names, excluding the two that cannot be ignored in the first place.
//
// /proc rather than a probe loop: sigaction(sig, NULL, &old) for every number
// is 62 syscalls and the struct layout this package exists to avoid, and the
// kernel already publishes the answer as one hex word. The word is a bitmask
// with signal N at bit N-1 (proc(5)).
func ignoredSignals() ([]os.Signal, error) {
	mask, err := statusSigMask("SigIgn")
	if err != nil {
		return nil, err
	}
	var out []os.Signal
	// 1..31 only: see the package comment's residual on realtime signals.
	for n := 1; n <= 31; n++ {
		if mask&(1<<uint(n-1)) == 0 {
			continue
		}
		sig := syscall.Signal(n)
		if sig == syscall.SIGKILL || sig == syscall.SIGSTOP {
			continue
		}
		out = append(out, sig)
	}
	return out, nil
}

// statusSigMask pulls one of /proc/self/status's signal bitmask fields.
func statusSigMask(field string) (uint64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		v, cut := strings.CutPrefix(line, field+":")
		if !cut {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing %s %q: %w", field, strings.TrimSpace(v), err)
		}
		return mask, nil
	}
	// Absent rather than unparseable. Refuse: this package's whole job is to
	// know what is ignored, and "the file did not say" is not "nothing is".
	return 0, fmt.Errorf("no %s line in /proc/self/status", field)
}
