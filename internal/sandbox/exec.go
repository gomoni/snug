package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
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
	joined, err := nulJoin(flags)
	if err != nil {
		return 0, err
	}
	argsFile, err := memfd("snug-args", joined)
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

	if p.Topology.NeedsStage() {
		return runStaged(p, bwrap, argv, extra, stdin, stdout, stderr, statusR, statusW, blockR, blockW, opts)
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
	if err := fdseal.SealFor(cmd); err != nil {
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
		// No pid, so there is nothing to kill by pid: fall back to reaping
		// bwrap, which is all the information available at this point.
		abort(cmd, 0)
		return 0, err
	}

	// From here until release there is a payload parked inside the sandbox and
	// snug's own death would run it. One deferred guard covers every return
	// path below, including the ones a later edit adds — see parked.go.
	pk := park(childPID, func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	defer pk.abort()

	helper, err := startPasta(p, policy.PastaTargetChild(childPID), childPID)
	if err != nil {
		return 0, err
	}
	defer helper.stop()
	helper.watch(opts.warn)

	if err := pk.release(blockW); err != nil {
		return 0, err
	}

	return wait(cmd)
}

// runStaged is the NetnsStage arm: a stage (P1) creates the sandbox's network
// namespace, pins it, leaves it, and forks bwrap back into it. Everything up
// to and including the args memfd is identical to the non-stage path — flags,
// extra, the "nothing may be appended after this point" comment, all of it.
// What changes is who forks bwrap: internal/stage.Start's *Stage, not
// exec.Command directly. See SUPERVISOR-PHASE1-SPEC.md §4 Step 5.
//
// statusR and blockW are the SAME kernel pipe objects the non-stage path uses
// — their other ends (statusW, blockR) travel to the final bwrap invocation
// inside `extra`/Config.Sandbox, threaded through P1 and __innetns unchanged.
// A pipe does not care how many process generations separate its two ends, so
// readChildPID and the block-release write below are BYTE FOR BYTE what the
// non-stage path does; only the fork itself moved.
//
// statusW and blockR are P0's OWN copies of the ends it handed off — needed
// here only so they can be closed the instant the hand-off is confirmed, the
// same immediate (non-deferred) close the non-stage path does right after
// cmd.Start(). Skipping that close is not cosmetic: readChildPID blocks on
// Decode(), which needs either DATA or EOF, and if bwrap fails before writing
// anything (the fake-binary case TestTheStageExitsWhenTheSandboxFailsToStart
// exercises), EOF never arrives while P0's own unused copy of statusW is still
// open — the read hangs forever instead of failing. Measured: this was a real
// hang, not a hypothetical one.
func runStaged(p *policy.Policy, bwrap string, argv []string, extra []*os.File,
	stdin, stdout, stderr, statusR, statusW, blockR, blockW *os.File, opts Options) (int, error) {
	st, err := stage.Start(stage.Config{
		Netns:   p.Topology.Netns,
		Sandbox: extra,
		Stdin:   stdin, Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		return 0, err
	}
	defer st.Close()

	// needsNet is always true on this arm today — NeedsStage() is only ever
	// true when Topology.Netns == NetnsStage, and deriveTopology only produces
	// that from NetEgress, which is exactly the case that needs the
	// status/block handshake. Asserting it explicitly here, rather than
	// assuming it silently, is what keeps that coupling from drifting apart
	// unnoticed if deriveTopology ever grows a second NetnsStage source.
	if statusR == nil || statusW == nil || blockR == nil || blockW == nil {
		return 0, fmt.Errorf("internal error: NetnsStage policy without a networking handshake")
	}

	if err := st.StartSandbox(bwrap, argv); err != nil {
		return 0, err
	}
	// Our copies of the child's ends must be closed or the reads never EOF —
	// see the doc comment above.
	statusW.Close()
	blockR.Close()

	childPID, err := readChildPID(statusR)
	if err != nil {
		// No pid to kill by, so take the stage down instead: P1 exiting drops
		// bwrap's parent, which is the only lever left. This is the same
		// weaker position abort(cmd, 0) occupies on the single-process path,
		// and for the same reason.
		_ = st.Close()
		return 0, err
	}

	// Same guard, same reason, same ordering as the single-process path — and
	// the reason this is a shared type rather than a repeated idiom is that
	// this arm is where the repetition was missed: one of its return paths
	// released the payload on a run that had already failed. See parked.go.
	pk := park(childPID, func() { _ = st.Close() })
	defer pk.abort()

	helper, err := startPasta(p, st.Target(), childPID)
	if err != nil {
		return 0, err
	}
	defer helper.stop()
	helper.watch(opts.warn)

	if err := pk.release(blockW); err != nil {
		return 0, err
	}

	ws, err := st.Wait()
	if err != nil {
		return 0, err
	}
	if ws.Exited() {
		return ws.ExitStatus(), nil
	}
	return -1, nil
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
//
// This function is now the DEGRADED case only — the one where readChildPID
// failed, so no pid exists to kill and reaping bwrap is all the information
// there is. Every path that knows the pid goes through parked.abort instead,
// which does the same thing in the same order but is registered as a defer the
// instant the pid is read, so no future return path can skip it. That
// distinction is the whole of what a red team found here a second time: the
// discipline was correct and was written out by hand, and a new arm did not
// repeat all of it.
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

// nulJoin renders the flag list in the NUL-separated form bwrap's --args reads,
// and refuses any element that contains the separator.
//
// This code OWNS the separator, so it is the one place entitled to say that no
// element may contain it — and it is the last place the whole argv exists as
// Go values, so a check here holds for every flag whatever authored it, not
// just for the ones whose author was remembered.
//
// It is deliberately the SECOND guard. `checkEnvValue` refuses a NUL in a
// profile-supplied environment value at parse time, where the error can name
// the profile, the verb and the variable; that is the one that will fire in
// practice and the one a human can act on. This one fires when something else
// puts a NUL into a flag — a path, a generated value, a future writer nobody
// has thought of — and it fails the run rather than handing bwrap a flag list
// that means something other than the policy.
//
// The reachable case, measured: an environ.set value carrying a NUL escape
// re-synced bwrap's --args parser onto its own remainder, so
// `--setenv EDITOR "vim\\u0000--ro-bind\\u0000/home/u/.ssh\\u0000/home/u/.ssh"`
// mounted ~/.ssh — a mount no Mount ever existed for, so Validate,
// rejectMasking and --dry-run were all blind to it.
func nulJoin(args []string) ([]byte, error) {
	var b bytes.Buffer
	for i, a := range args {
		if strings.ContainsRune(a, 0) {
			return nil, fmt.Errorf("refusing to run: flag %d of the bwrap argument list "+
				"contains a NUL byte, which is the separator the list is joined with — "+
				"everything after it would be read by bwrap as further flags, and no "+
				"such flag is in the resolved policy. This is a bug in snug unless a "+
				"profile put it there; run `snug --dry-run` and look at the ENVIRONMENT "+
				"block", i)
		}
		b.WriteString(a)
		b.WriteByte(0)
	}
	return b.Bytes(), nil
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

// sealInheritedFDs moved to internal/fdseal (SealFor) in Phase 1: the stage
// (P1) is a long-lived process that forks more than once, and a keep-list
// derived from the *exec.Cmd being forked is what stays correct as such a
// process's descriptor table drifts — see that package's doc comment.
