package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

	// Networking needs NO handshake with bwrap any more, and the absence is the
	// point.
	//
	// bwrap used to be started first and told to park its payload on --block-fd
	// until pasta had attached, because pasta needs a netns and only bwrap could
	// make one. Under the stage the netns exists BEFORE bwrap does, so pasta
	// attaches first and there is nothing to park. That deletes --block-fd,
	// --json-status-fd, the two pipes, readChildPID and the whole `parked` type
	// along with the SIGKILL window they carried: a payload that has not been
	// forked cannot be released early.
	//
	// Nothing here is conditional on networking any more, which is why this block
	// is gone rather than shortened. Note for anyone adding a flag near here: the
	// args memfd below is a SNAPSHOT of `flags`, so anything appended after it is
	// silently dropped — the same shape as the --seccomp-after-`--` bug.

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
		return runStaged(p, bwrap, argv, extra, stdin, stdout, stderr, opts)
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
	// This arm is the OFFLINE and host-network one: bwrap made its own namespace
	// (or was given the host's) and there is no helper to attach, so the payload
	// is already running. Every networked run goes through runStaged above —
	// NetEgress is the only mode deriveTopology maps to NetnsStage, and the only
	// mode that ever needed a helper.
	return wait(cmd)
}

// runStaged is the NetnsStage arm, and its ORDER is the security property.
//
//	stage.Start   -> N exists, pinned by a descriptor, with nobody in it
//	startPasta    -> pasta attaches to that empty N and configures snug0
//	WaitNetReady  -> the stage confirms snug0 is UP and RUNNING, from inside N
//	StartSandbox  -> only NOW does a payload exist
//
// The previous order was the reverse — bwrap first, its payload parked on
// --block-fd, released once pasta was up — because pasta needs a netns and
// only bwrap could create one. That parked interval was a real defect: bwrap
// releases a parked payload on EOF exactly as readily as on a byte, and snug's
// own death closes the write end, so a SIGKILL of snug inside the window ran
// the payload with no network and left an orphaned sandbox. Measured 5/5.
//
// Reordering does not narrow that window, it removes the thing that had a
// window: there is no payload to release, so there is nothing for a dying snug
// to release. --block-fd, --json-status-fd, readChildPID and the entire parked
// type are gone with it.
//
// BUT ONLY THE RELEASE HALF. F2 had two clauses — a killed snug released the
// payload AND left an orphaned sandbox — and this closes the first. The second
// is open on both topologies and predates this change: between bwrap forking
// the sandbox init and bwrap arming --die-with-parent on it, nothing in snug
// guarantees the sandbox dies, so a signal to snug in that interval leaves an
// init reparented to the subreaper, holding the payload and the netns, with
// write access to the target. Measured 3/3, all four signals. TODO.md carries
// it. Do not read the deletions above as covering it.
//
// What made the reorder possible, having previously been recorded as a blocker:
// confirming the interface is up needed a process inside N to read
// /proc/<pid>/net/dev, and before bwrap there is none. But a socket's network
// namespace is fixed when the SOCKET is created, not by where its owner later
// goes — so the socket the stage opens in N to bring lo up still answers for N
// after the stage has left, and the stage answers the question over the control
// socket. Both halves measured; see stage.WaitNetReady.
func runStaged(p *policy.Policy, bwrap string, argv []string, extra []*os.File,
	stdin, stdout, stderr *os.File, opts Options) (int, error) {
	st, err := stage.Start(stage.Config{
		Netns:   p.Topology.Netns,
		Sandbox: extra,
		Stdin:   stdin, Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		return 0, err
	}
	defer st.Close()

	// pasta attaches to a namespace with NO process in it. Measured: it starts,
	// stays up, and its interface is waiting when bwrap arrives.
	helper, err := startPasta(p, st.Target())
	if err != nil {
		return 0, err
	}
	defer helper.stop()
	helper.watch(opts.warn)

	// Fail here rather than run a payload that was promised a network it does not
	// have. This is invariant 5 at the exact point it used to be enforced by
	// parking a process that already existed.
	//
	// Raced against pasta dying, because the two failures need different
	// messages and very different latencies. A pasta that exits at once — the
	// crashing or OOM-killed shape — would otherwise be reported only when the
	// stage's interface timeout expired, turning a 300ms error into a ten-second
	// one that a human interrupts before reading.
	ready := make(chan error, 1)
	go func() { ready <- st.WaitNetReady(netReadyTimeout) }()
	select {
	case err := <-ready:
		if err != nil {
			return 0, err
		}
	case <-helper.died():
		return 0, fmt.Errorf("pasta exited before the network came up: %s", helper.failure())
	}

	if err := st.StartSandbox(bwrap, argv); err != nil {
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

// netReadyTimeout is P0's patience with the STAGE, not with pasta: the stage
// applies its own shorter bound to the interface itself, so exceeding this one
// means the stage is wedged rather than the network being slow.
const netReadyTimeout = 15 * time.Second

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
