package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// Options are the run-time choices a human makes at the CLI. Nothing here is
// expressible in a profile — weakening is the human's prerogative (INDEX §2.5).
type Options struct {
	NoSeccomp bool
	Warn      func(string) // where degradation notices go; never silently dropped
}

// Run executes the policy and returns the payload's exit code verbatim, so
// `snug ... -- make test` is usable in a pipeline.
func Run(p *policy.Policy, uid, gid int, opts Options) (int, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return 0, fmt.Errorf("bubblewrap (bwrap) is not installed — snug cannot run without it")
	}

	var extra []*os.File
	defer func() {
		for _, f := range extra {
			f.Close()
		}
	}()

	// Child fd numbers: exec.Cmd maps ExtraFiles[i] to 3+i.
	nextFD := func() int { return 3 + len(extra) }

	// Generated files (resolv.conf today; hosts/passwd/group later) travel as
	// anonymous memfds, so nothing lands on disk.
	dataFDs := map[string]int{}
	for _, m := range p.SortedMounts() {
		if m.Kind != policy.KindData {
			continue
		}
		f, err := memfd("snug-data", m.Content)
		if err != nil {
			return 0, err
		}
		dataFDs[m.Guest] = nextFD()
		extra = append(extra, f)
	}

	flags := p.BwrapFlags(uid, gid, func(guest string) int { return dataFDs[guest] })

	if !opts.NoSeccomp {
		f, err := FilterFD()
		if err != nil {
			// The only subsystem permitted to degrade. Loudly: a user who
			// believes a guarantee that no longer holds is worse off than one
			// who got an error.
			opts.warn(fmt.Sprintf("seccomp filter unavailable (%v); continuing WITHOUT it.\n"+
				"      The namespace boundary is unaffected; ptrace/keyctl/TIOCSTI hardening is not active.", err))
		} else {
			flags = append(flags, "--seccomp", strconv.Itoa(nextFD()))
			extra = append(extra, f)
		}
	}

	// Networking needs a handshake with bwrap: it must create the netns before
	// pasta can join, and the payload must not run until pasta has attached.
	//
	// This block MUST come before the args memfd below. The memfd is a snapshot
	// of `flags`, so anything appended afterwards is silently dropped — which is
	// the same shape as the --seccomp-after-`--` bug: the flag exists in a
	// variable, bwrap never sees it, and everything reports success.
	var statusR, statusW, blockR, blockW *os.File
	needsNet := p.Net.Mode == policy.NetEgress
	if needsNet {
		statusR, statusW, err = os.Pipe()
		if err != nil {
			return 0, err
		}
		defer statusR.Close()
		defer statusW.Close()
		blockR, blockW, err = os.Pipe()
		if err != nil {
			return 0, err
		}
		defer blockR.Close()
		defer blockW.Close()

		flags = append(flags, "--json-status-fd", strconv.Itoa(nextFD()))
		extra = append(extra, statusW)
		flags = append(flags, "--block-fd", strconv.Itoa(nextFD()))
		extra = append(extra, blockR)
	}

	// The whole flag list travels through a memfd rather than real argv:
	//   - it sidesteps ARG_MAX for large policies
	//   - the sandbox's own /proc/<pid>/cmdline does not display the policy to
	//     the agent, so the agent cannot read its own boundary out of procfs
	//   - it removes every shell-quoting concern from what --dry-run prints
	//
	// Nothing may be appended to `flags` after this point.
	argsFile, err := memfd("snug-args", nulJoin(flags))
	if err != nil {
		return 0, err
	}
	argsFD := nextFD()
	extra = append(extra, argsFile)

	argv := []string{"--args", strconv.Itoa(argsFD), "--"}
	argv = append(argv, p.Command...)

	stdin, stdout, stderr, err := safeStdio()
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(bwrap, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.ExtraFiles = extra

	// bwrap runs with an EMPTY environment, and this line is load-bearing.
	//
	// exec.Cmd with a nil Env passes os.Environ() — the whole host environment.
	// bwrap then becomes PID 1 of the sandbox's PID namespace, running as the
	// same uid as the payload, so the payload can read every host variable out
	// of /proc/1/environ: SSH_AUTH_SOCK, cloud credentials, tokens. --clearenv
	// only clears the environment handed to the *spawned command*; it says
	// nothing about bwrap's own. Found by the redteam agent, which pulled 106
	// host variables out of a sandbox whose payload env was correctly clean.
	//
	// bwrap needs nothing from the host environment — the payload's environment
	// is rebuilt entirely through --setenv — so empty costs nothing.
	cmd.Env = []string{}

	// No Setpgid anywhere in this chain: the tree stays in the terminal's
	// foreground process group so Ctrl-C reaches the payload and job control
	// works for an interactive shell inside the sandbox.
	if err := sealInheritedFDs(extra); err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	if !needsNet {
		// Offline: bwrap made a netns with only loopback and there is no helper
		// to attach, so the payload is already running.
		return wait(cmd)
	}
	// Our copies of the child's ends must be closed or the reads never EOF.
	statusW.Close()
	blockR.Close()

	childPID, err := readChildPID(statusR)
	if err != nil {
		abort(cmd, 0)
		return 0, err
	}

	helper, err := startPasta(p, childPID)
	if err != nil {
		abort(cmd, childPID)
		return 0, err
	}
	defer helper.stop()
	helper.watch(opts.warn)

	// Release the payload.
	if _, err := blockW.Write([]byte{0}); err != nil {
		return 0, fmt.Errorf("releasing the sandbox: %w", err)
	}
	blockW.Close()

	return wait(cmd)
}

// abort tears down a sandbox whose network never came up, WITHOUT letting the
// parked payload run. Pass childPID 0 if it is not known yet.
//
// The subtlety, and it cost two wrong fixes to find: the payload is parked on
// bwrap's --block-fd, and that fd is released by EOF just as readily as by a
// byte. So the deferred blockW.Close() in Run is itself a release signal. It is
// not enough to "not write" — the child has to be dead before any close.
//
// Killing bwrap alone does not do it. --die-with-parent arms PR_SET_PDEATHSIG
// on the child, but the delivery races teardown, and measured here the parked
// child reliably survived long enough for the deferred close to release it: a
// stalled pasta produced a payload that ran 6 seconds later, during cleanup, on
// a run that reported exit 69. An earlier version closed the write end first and
// then killed, which released the payload and raced the kill — 1 abort in 15
// executed the payload and wrote to the target.
//
// So: SIGKILL the parked child by pid first, using the pid bwrap already told us
// through --json-status-fd, then reap bwrap. After this nothing is left to
// release and the deferred close is inert.
//
// Found by the redteam agent as "the abort path is not fail-closed".
func abort(cmd *exec.Cmd, childPID int) {
	if childPID > 0 {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func wait(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

func (o Options) warn(msg string) {
	if o.Warn != nil {
		o.Warn(msg)
		return
	}
	fmt.Fprintln(os.Stderr, "snug: "+msg)
}

// nulJoin renders the flag list in the NUL-separated form bwrap's --args reads.
func nulJoin(args []string) []byte {
	var b bytes.Buffer
	for _, a := range args {
		b.WriteString(a)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// safeStdio returns the three standard descriptors, with any that is a
// DIRECTORY replaced by /dev/null.
//
// sealInheritedFDs closes the door on inherited fds above 2, for a reason it
// states plainly: an open fd on a host directory is a complete bypass of the
// mount policy, because openat(2) walks from that descriptor's own vfsmount and
// never consults the sandbox's mount namespace. Fds 0/1/2 are exempt from that
// sweep because stdio has to pass through — which left exactly the same hole
// standing on three well-known descriptor numbers.
//
// The redteam agent walked through it:
//
//	snug proj -- sh -c 'cat /proc/self/fd/0/.bashrc'          < /home/user
//	snug proj -- sh -c 'echo x > /proc/self/fd/0/pwned'        0< ./ungranted-dir
//
// Both worked: arbitrary read AND write of a host subtree no profile granted.
// The sandboxed agent cannot set snug's descriptors, so the trigger is the
// launcher rather than the payload — but snug runs under wrappers and
// automation that rewire stdio as a matter of course, and the invariant is one
// the code already claims to enforce.
//
// A directory on stdio is never meaningful for a payload: read(2) on a dirfd
// returns EISDIR. So substituting /dev/null costs nothing real.
func safeStdio() (stdin, stdout, stderr *os.File, err error) {
	out := [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	names := [3]string{"stdin", "stdout", "stderr"}

	for i, f := range out {
		if f == nil {
			continue
		}
		fi, statErr := f.Stat()
		if statErr != nil || !fi.IsDir() {
			continue
		}
		devnull, openErr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if openErr != nil {
			return nil, nil, nil, fmt.Errorf("%s is a directory and /dev/null is unavailable: %w", names[i], openErr)
		}
		fmt.Fprintf(os.Stderr, "snug: %s is a directory; replacing it with /dev/null.\n"+
			"      A directory descriptor would let the sandbox reach the host filesystem "+
			"through /proc/self/fd/%d, bypassing every mount grant.\n", names[i], i)
		out[i] = devnull
	}
	return out[0], out[1], out[2], nil
}

// sealInheritedFDs marks every descriptor we did not deliberately open as
// close-on-exec, so nothing our own parent left lying around is inherited into
// the sandbox. bwrap does not close inherited fds, and an open fd on a host
// directory is a complete bypass of the mount policy — the sandbox can walk it
// with openat(2) regardless of what was mounted.
//
// It sets CLOEXEC rather than closing. Closing arbitrary descriptors in a Go
// process is how you break the runtime's netpoller; setting the flag is
// harmless on descriptors that already have it, which includes everything Go
// itself opens.
func sealInheritedFDs(keep []*os.File) error {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil // not fatal: Go already marks its own fds CLOEXEC
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}

	spare := map[int]bool{int(dir.Fd()): true}
	for _, f := range keep {
		spare[int(f.Fd())] = true
	}

	for _, n := range names {
		fd, err := strconv.Atoi(n)
		if err != nil || fd <= 2 || spare[fd] {
			continue
		}
		flags, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETFD, 0)
		if errno != 0 {
			continue
		}
		if flags&unix.FD_CLOEXEC != 0 {
			continue
		}
		unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
	}
	return nil
}
