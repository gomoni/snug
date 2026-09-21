package sandbox

// inpidns.go is the `__inpidns` verb: the one process between snug and bwrap
// on the offline arm, and it is that process only until its own exec — it
// mounts a procfs and becomes bwrap, so the topology stays two processes.
//
// WHY IT EXISTS AT ALL, since the clone in exec.go already made the
// namespaces: bwrap must read its own child out of a procfs that belongs to
// the namespace it is pid 1 of. internal/nestproc carries that measurement and
// is the single author of the mount, because the staged verb now needs the
// identical sequence for the identical reason.

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/nestproc"
	"github.com/gomoni/snug/internal/sigseal"
)

// EnterPidNS is the whole body of `__inpidns NFDS BWRAP [ARGS...]`. NFDS is
// how many descriptors internal/sandbox.Run handed down with ExtraFiles, which
// are always the contiguous block 3..3+NFDS-1; BWRAP is already resolved by
// exec.LookPath one process back and is never re-resolved here, for the reason
// internal/stage's EnterNetns states.
//
// It refuses rather than continues when a step fails: a bwrap that runs with
// the WRONG /proc is exactly the state this verb exists to prevent, and
// invariant 5 says a capability that is not available is a refusal, not a
// quieter run.
func EnterPidNS(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("__inpidns: usage: __inpidns NFDS BWRAP [ARGS...]")
	}
	nfds, err := strconv.Atoi(argv[0])
	if err != nil || nfds < 0 {
		return fmt.Errorf("__inpidns: bad descriptor count %q", argv[0])
	}
	path, rest := argv[1], argv[2:]

	// The procfs bwrap reads its own child out of. See internal/nestproc for
	// the measurement and for why the staged verb calls the same function.
	if err := nestproc.Mount("__inpidns"); err != nil {
		return err
	}

	// Everything outside the ExtraFiles block is sealed before the exec, for
	// the reason internal/stage's EnterNetns gives at the same point in the
	// chain: this is the last process that can decide what bwrap — and through
	// it, the payload — inherits.
	keep := make([]int, 0, nfds)
	for fd := 3; fd < 3+nfds; fd++ {
		keep = append(keep, fd)
	}
	if err := fdseal.SealExcept(keep...); err != nil {
		return fmt.Errorf("__inpidns: %w", err)
	}

	// The same guard for SIGNAL state, on the same exec. This arm looked clean
	// only by accident — armTeardown's signal.Notify runs before exec.go's
	// cmd.Start(), so Go's own child-side reset covered the ignored
	// dispositions here while the staged arm leaked them. The MASK leaked on
	// both. See internal/sigseal for the measurements and for why one line in
	// two verbs beats two behaviours nobody chose.
	if err := sigseal.Seal(); err != nil {
		return fmt.Errorf("__inpidns: %w", err)
	}

	// Empty environment, stated rather than inherited — the same word, for the
	// same measured reason, as internal/stage's EnterNetns: this exec becomes
	// the bwrap whose /proc/1/environ a payload can read.
	return syscall.Exec(path, append([]string{path}, rest...), []string{})
}
