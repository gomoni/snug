package cli

// attach.go is `snug attach`: every check in the design's §4.1, the
// verify-then-release gate (§4.2a), the stdio relay, and exit-code
// propagation. internal/attach owns the raw-fork syscall sequence itself
// (§4.2); this file is everything that can allocate, parse, and produce a
// good error message — which is deliberately everything BEFORE the fork.
//
// A hostile process inside the sandbox can use an attached session to reach
// whatever the attaching human's stdin, stdout and stderr point at — by
// listing /proc/<attached>/fd and reopening a descriptor there — and to read
// the attached process's environment. Measured: a reopened stdout still
// reaches whatever this file relays it to; a pipe relay keeps the HOST INODE
// out of reach (the payload cannot read what was already in a redirected
// file, cannot seek or truncate it), but not the live stream itself.
//
// A hostile process on the HOST with the same uid as the sandbox's owner can
// use `snug attach` to enter the sandbox — and could equally have used a
// dozen lines of C, because the kernel grants this on uid, not on anything
// snug controls. What it cannot do with snug attach is enter UNCONFINED: see
// internal/attach's package comment for the confinement this file always
// applies, unconditionally — there is no `snug attach --no-seccomp`.
import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/attach"
	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

func attachUsage() {
	fmt.Fprint(os.Stderr, `snug attach — run a command inside a sandbox that is already running

usage:
  snug attach [dir] [-- command ...]     join the live run on dir (default: .)

Joins the namespaces of the live snug run whose target is dir and runs command
inside it — the run's own seccomp filter, an empty capability set and bounding
set, no-new-privs, and the environment that run's policy authored. With no
command it runs that run's shell.

ATTACH IS NOT A PERMISSION. It gates nothing. Any process running as your uid
can join a sandbox's namespaces with or without snug — the kernel's rule is
"same uid as the owner of the sandbox's user namespace", and it was confirmed
five ways on both topologies. What snug attach adds is CONFINEMENT, not entry:
a plain nsenter joins with no seccomp filter, a full capability bounding set,
and your host environment, and everything it carries in is readable to the
payload out of /proc.

THE ATTACHED PROCESS IS INSIDE, AND THE PAYLOAD CAN ADDRESS IT. It appears in
the sandbox's /proc; the payload can read its environment and its open
descriptors, and on a host with kernel.yama.ptrace_scope=0 its memory (issue
#47 — not something a seccomp filter can reach). So whatever your stdin,
stdout and stderr point at, the payload can reach too. snug relays a
non-terminal descriptor through a pipe, so the payload reaches the stream but
not the file behind it; a terminal is relayed through a fresh pty allocated
only for this session, so the payload reaches a terminal that exists only for
attach rather than the one you are typing at directly. Do not attach with a
descriptor open on something the sandbox must not have.

It cannot run a DIFFERENT policy inside the same sandbox. Attach resolves no
profiles and reads no configuration; it reproduces the run's confinement and
nothing else. If you want different grants, start a different sandbox.
`)
}

// attachCmd is `snug attach`'s whole entry point.
func attachCmd(argv []string) int {
	target, command, err := parseAttachArgs(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n\n", err)
		attachUsage()
		return exitUsage
	}
	if target == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}

	// state.Target is the REALPATH: policy.Resolve canonicalises the target
	// with EvalSymlinks (internal/policy/resolve.go), and the per-target lock
	// issue #119 added keys its lock name on the same realpath
	// (targetlock.go's targetLockName). Matching against abs alone — a bare
	// filepath.Abs, never resolved through a symlink — meant `snug attach` on
	// a symlink to the target, a trailing slash, or any other non-canonical
	// spelling could never find the run its own lock had just refused a
	// second copy of. See CLAUDE.md's "One live sandbox per target
	// directory": "Same directory is realpath".
	real, exists, err := canonicalAttachTarget(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: resolving %s: %v\n", abs, err)
		return exitUsage
	}
	if !exists {
		// A target that does not exist cannot have a live run — report the
		// same "no live run" refusal selectLiveRun uses for zero matches,
		// rather than surfacing a raw EvalSymlinks error (which would read
		// as a filesystem problem, not "there is nothing to attach to") or
		// falling through to match a non-canonical path.
		fmt.Fprintf(os.Stderr, "snug: no live snug run found for %s — nothing is currently sandboxing "+
			"this directory (it does not exist)\n", abs)
		return exitPolicy
	}

	st, err := selectLiveRun(real)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

	code, err := runAttach(st, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUnavail
	}
	return code
}

func parseAttachArgs(argv []string) (target string, command []string, err error) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			command = argv[i+1:]
			return target, command, nil
		case a == "-h" || a == "--help":
			attachUsage()
			os.Exit(0)
		case strings.HasPrefix(a, "-"):
			return "", nil, fmt.Errorf("unknown flag %q (there is no `snug attach --list` yet; "+
				"a bare `snug attach [dir]` matches the live run on that target)", a)
		default:
			if target != "" {
				return "", nil, fmt.Errorf("more than one directory given (%q and %q)", target, a)
			}
			target = a
		}
	}
	return target, command, nil
}

// selectLiveRun is §4.1 step 1: find the run published for this target,
// confirm its lock is held, and validate what it published.
//
// Since issue #123 this is a LOOKUP, not a search. The state file is named
// from sha256(realpath) in the same uid-derived directory as the target lock
// (targetstate.go), so there is exactly one candidate and no listing to walk.
// Three things that used to be here went with the scan and are worth naming,
// because their absence is the point rather than an omission:
//
//   - the "more than one live run matches" branch. #119 made at most one run
//     live per directory, and the target-keyed name makes that structural: two
//     runs on one target cannot produce two state files, because they cannot
//     produce two names.
//   - the "live runs: ..." enumeration in the zero case. It listed other
//     people's targets to a user who asked about one directory, which was the
//     scan leaking into the message.
//   - a second liveness mechanism. Liveness is now the target lock — the same
//     fact `snug <dir>` consults when it refuses a second sandbox — rather
//     than a parallel per-run flock that could in principle disagree with it.
//
// real must already be canonicalised (filepath.EvalSymlinks, via
// canonicalAttachTarget), because the file name is a hash OF that canonical
// form: a symlink to the target, or any other spelling, hashes elsewhere and
// finds nothing. That is the same coherence issue #119 fixed for the lock.
func selectLiveRun(real string) (runState, error) {
	st, live, err := readTargetState(real)
	if err != nil {
		return runState{}, err
	}
	if !live {
		return runState{}, fmt.Errorf("no live snug run found for %s — nothing is currently sandboxing "+
			"this directory", real)
	}
	return st, nil
}

// canonicalAttachTarget resolves abs (already filepath.Abs'd) to the same
// realpath policy.Resolve and the target lock both use — see the comment
// above selectLiveRun. exists is false when abs, or a symlink it passes
// through, does not exist on disk: a directory with no on-disk presence
// cannot have a live run, so the caller reports that as "no live run"
// rather than surfacing a raw EvalSymlinks error. Any OTHER failure
// (permission denied on an intermediate component, a loop, ...) is
// returned as err with exists=false, and the caller must not treat that as
// "no live run" either — it is a different refusal with a different
// message.
func canonicalAttachTarget(abs string) (real string, exists bool, err error) {
	real, err = filepath.EvalSymlinks(abs)
	if err != nil {
		// errors.Is, not os.IsNotExist: the predicate must survive a %w wrap,
		// and the one place it did not was issue #124.
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return real, true, nil
}

// runAttach is §4.1 steps 2-10, the gate (§4.2a), and the wait. st has
// already been schema/shape validated by selectLiveRun; everything here is
// the LIVE-process-dependent half of the refusal table — the pid could have
// been reused, the namespaces could have been recreated, the binary could
// disagree with the run about its own filter — none of which a stale
// state.json alone can prove.
func runAttach(st runState, command []string) (int, error) {
	pidfd, err := unix.PidfdOpen(st.Sandbox.InitPID, 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return 0, fmt.Errorf("that sandbox is gone (pid %d no longer exists)", st.Sandbox.InitPID)
		}
		return 0, fmt.Errorf("opening a pidfd on pid %d: %w", st.Sandbox.InitPID, err)
	}
	defer unix.Close(pidfd)

	starttime, err := procStartTime(st.Sandbox.InitPID)
	if err != nil {
		return 0, fmt.Errorf("that sandbox is gone: %w", err)
	}
	if starttime != st.Sandbox.InitStarttime {
		return 0, fmt.Errorf("refusing to attach: pid %d has been reused since this run started "+
			"(recorded start time %d, actual %d) — the sandbox this state file described is gone",
			st.Sandbox.InitPID, st.Sandbox.InitStarttime, starttime)
	}

	nsIno, err := procNamespaceInodes(st.Sandbox.InitPID)
	if err != nil {
		return 0, fmt.Errorf("reading pid %d's namespaces: %w", st.Sandbox.InitPID, err)
	}
	for _, k := range runStateNamespaceKinds {
		if nsIno[k] != st.Sandbox.Namespaces[k] {
			return 0, fmt.Errorf("refusing to attach: pid %d's %q namespace does not match this run's "+
				"recorded one (a reused pid whose start time happened to collide, or the wrong sandbox)",
				st.Sandbox.InitPID, k)
		}
	}

	targetUserNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", st.Sandbox.InitPID))
	if err != nil {
		return 0, fmt.Errorf("reading pid %d's user namespace: %w", st.Sandbox.InitPID, err)
	}
	ourUserNS, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		return 0, fmt.Errorf("reading this process's own user namespace: %w", err)
	}
	if targetUserNS == ourUserNS {
		return 0, fmt.Errorf("refusing to attach: pid %d is not inside a sandbox — its user namespace "+
			"is your own. (A multithreaded caller gets EINVAL from the same setns this refusal replaces; "+
			"this message exists so that error is never what you see.)", st.Sandbox.InitPID)
	}

	seccompProg, err := attachSeccompProgram(st, sandbox.BuildFilter)
	if err != nil {
		return 0, err
	}

	capLastCap, err := readCapLastCap()
	if err != nil {
		return 0, fmt.Errorf("reading /proc/sys/kernel/cap_last_cap: %w", err)
	}

	argv0, argv, err := attachCommand(st, command)
	if err != nil {
		return 0, err
	}

	envp := attachEnviron(st)

	relay, err := newStdioRelay()
	if err != nil {
		return 0, err
	}
	// Restores the client's own terminal (raw-mode termios, SIGWINCH
	// watcher) on every path out of this function from here on — normal
	// return, the attached command dying, or any of the error returns
	// below. A no-op on the pipe path, where there was nothing to touch.
	defer relay.restoreTerminal()

	reportR, reportW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer reportR.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer gateW.Close()

	// Read (never change) this process's own current signal mask, so A can
	// restore exactly it right before its execve — the exec'd program's
	// signal behaviour should be unremarkable, not one born with every
	// signal blocked (attach.Config.SignalMask's own doc comment). Passing
	// set=NULL to rt_sigprocmask(2) means "read only"; `how` is then
	// ignored by the kernel.
	var mask [8]byte
	unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, 0, 0, uintptr(unsafe.Pointer(&mask)), 8, 0, 0)

	cfg := &attach.Config{
		PidFD:       pidfd,
		CapLastCap:  capLastCap,
		SeccompProg: seccompProg,
		Chdir:       st.Chdir,
		Argv0:       argv0,
		Argv:        argv,
		Envp:        envp,
		Stdin:       int(relay.childStdin.Fd()),
		Stdout:      int(relay.childStdout.Fd()),
		Stderr:      int(relay.childStderr.Fd()),
		ReportW:     int(reportW.Fd()),
		GateR:       int(gateR.Fd()),
		SignalMask:  mask,
		PTY:         relay.pty,
	}

	// Every descriptor this process holds — the pidfd, the state-file and
	// lock descriptors runtimeDir's own machinery is still holding open, the
	// report/gate pipes, everything — must be gone by the time A execve's,
	// per the design's §4.1 step 9. A's fork lineage (C -> B -> A) inherits
	// this process's ENTIRE fd table at each step, unlike Go's exec.Cmd
	// machinery, which curates one; fdseal.Seal is still the right tool,
	// because A's own dup3(relayFD, 0/1/2) creates BRAND NEW descriptors at
	// 0/1/2 (dup3 never copies CLOEXEC from its source), so those three
	// survive A's execve regardless of what this sweep marks on the numbers
	// they were dup3'd FROM.
	if err := fdseal.Seal(); err != nil {
		return 0, err
	}

	runtime.LockOSThread()
	// Deliberately NOT deferring UnlockOSThread: this goroutine stays
	// pinned to this OS thread until wait4 below returns, per
	// attach.Start's own doc comment on why (PR_SET_PDEATHSIG fires on the
	// death of the THREAD that created B, not merely the process).

	bpid, err := attach.Start(cfg)
	if err != nil {
		return 0, err
	}

	relay.closeChildEnds()
	reportW.Close()
	gateR.Close()

	code, gerr := releaseGate(bpid, st, reportR, gateW, relay)
	if gerr != nil {
		unix.Kill(bpid, unix.SIGKILL)
		var ws unix.WaitStatus
		unix.Wait4(bpid, &ws, 0, nil)
		return 0, gerr
	}
	return code, nil
}

// attachSeccompProgram implements §5.1's table. Rebuild, never carry: see
// sandbox.FilterDigest's own doc comment for why a file is never trusted for
// the program bytes themselves.
//
// buildFilter is sandbox.BuildFilter in production, injected here so a test
// can force the "cannot build a filter this run had" branch (§13.2 test 8)
// without needing an unsupported GOARCH to actually exist on the machine
// running the test — the same injected-dependency shape CLAUDE.md's working
// agreement already asks for host lookups in internal/policy.
func attachSeccompProgram(st runState, buildFilter func() ([]byte, bool, error)) ([]byte, error) {
	if st.Seccomp.State != "active" {
		fmt.Fprintln(os.Stderr, "snug: this run was started with --no-seccomp; the attached process "+
			"is unfiltered too.")
		return nil, nil
	}
	prog, ok, err := buildFilter()
	if err != nil || !ok {
		return nil, fmt.Errorf("refusing to attach: this binary cannot build the seccomp filter this "+
			"run recorded as active (%v) — attaching less filtered than the payload is the exact hole "+
			"this refusal exists to close", err)
	}
	digest := sandbox.FilterDigest(prog)
	if digest != st.Seccomp.Digest {
		rev := "an unknown build"
		if st.Revision != "" {
			rev = "revision " + st.Revision
		}
		return nil, fmt.Errorf("refusing to attach: this sandbox was started by %s of snug; its "+
			"seccomp filter (%s) is not the one this binary builds (%s). Attach from the same binary.",
			rev, st.Seccomp.Digest, digest)
	}
	return prog, nil
}

// attachCommand resolves the argv A will execve. With an explicit command it
// is the user's own words (§4.3's exec, "by path, of a path that came from
// the user's own command line"); with none, it is SHELL from the run's
// recorded environment — the one bounded exception named in §8.4.
//
// A bare (non-absolute) command name is not something a raw execve(2) can
// resolve — that is execvp's job, and it is bwrap's own execvp, running
// AFTER bwrap has entered the sandbox's mount namespace, that does this for
// an ordinary `snug -- bash` (internal/sandbox hands bwrap the argv verbatim
// and lets IT search $PATH from inside). attach has no bwrap in its chain,
// and resolving a bare name against THIS process's own (HOST) filesystem
// would be answering the wrong question — the sandbox's view of /usr/bin is
// not guaranteed to be this process's. So a bare name is handed to the run's
// own recorded SHELL as `sh -c 'exec "$0" "$@"' name args...`, which performs
// exactly the same $PATH search a user typing the same words at the attached
// shell would get, done by a program already running INSIDE the sandbox
// rather than guessed at from outside it. This is plumbing, not a new
// executable-path channel: SHELL is already §8.4's one bounded exception,
// and reusing it here rather than adding a second one is deliberate.
func attachCommand(st runState, command []string) (argv0 string, argv []string, err error) {
	shell, serr := attachRecordedShell(st)

	if len(command) == 0 {
		if serr != nil {
			return "", nil, serr
		}
		return shell, []string{shell}, nil
	}

	if filepath.IsAbs(command[0]) {
		return command[0], command, nil
	}
	if serr != nil {
		return "", nil, fmt.Errorf("%q is not an absolute path, and it cannot be resolved without "+
			"this run's SHELL: %w", command[0], serr)
	}
	argv = append([]string{shell, "-c", `exec "$0" "$@"`}, command...)
	return shell, argv, nil
}

// attachRecordedShell reads and validates SHELL from the run's recorded
// environment — §8.4's one bounded exception, and the only executable path
// this feature takes from a file rather than the user's own words.
func attachRecordedShell(st runState) (string, error) {
	shell := ""
	for _, kv := range st.Env {
		if kv[0] == "SHELL" {
			shell = kv[1]
		}
	}
	if shell == "" {
		return "", fmt.Errorf("this run's recorded environment has no SHELL")
	}
	if !filepath.IsAbs(shell) {
		return "", fmt.Errorf("this run's recorded SHELL (%q) is not an absolute path — refusing "+
			"to execute it", shell)
	}
	for _, r := range shell {
		if policy.IsForgingRune(r) {
			return "", fmt.Errorf("this run's recorded SHELL contains a control character — refusing")
		}
	}
	return shell, nil
}

// attachEnviron is §5.3: the recorded environment verbatim, with ONE
// deliberate exception — PS1 is replaced so the session reads as attached
// rather than as the payload's own. TERM is the RECORDED value, not this
// process's own (ATTACH.md §5.3): "the environment is authored by the run's
// policy" has no exception to remember.
func attachEnviron(st runState) []string {
	out := make([]string, 0, len(st.Env)+1)
	hasPS1 := false
	for _, kv := range st.Env {
		if kv[0] == "PS1" {
			hasPS1 = true
			out = append(out, "PS1="+attachPS1(kv[1]))
			continue
		}
		out = append(out, kv[0]+"="+kv[1])
	}
	if !hasPS1 {
		out = append(out, "PS1="+attachPS1(""))
	}
	return out
}

// attachPS1 marks an attached session distinctly from the payload's own
// prompt, on the same reasoning CLAUDE.md already states for the sandbox's
// PS1 in general: "am I inside?" and "am I the payload or a visitor?" are
// both questions where guessing wrong is expensive.
func attachPS1(base string) string {
	prefix := `\[\e[35m\][attached]\[\e[0m\] `
	if base == "" {
		return prefix + `\w \$ `
	}
	return prefix + base
}

// capLastCapPath is a var, not a literal inline in readCapLastCap, purely so
// a test can point it at a fake file (t.Setenv has no equivalent for a bare
// path) and prove the capability-bounding loop's upper bound really is READ
// at run time rather than a number someone typed in — see
// TestAttachCapBoundingLoopUsesCapLastCapFromProc. Never assigned anywhere
// outside a test.
var capLastCapPath = "/proc/sys/kernel/cap_last_cap"

func readCapLastCap() (int, error) {
	return readCapLastCapFrom(capLastCapPath)
}

func readCapLastCapFrom(path string) (int, error) {
	// HOSTREAD-EXEMPT: path is capLastCapPath, "/proc/sys/kernel/cap_last_cap",
	// made a parameter only so a test can point it at a fake file.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// procNamespaceInodes reads the six namespace ids by OPENING and FSTATing
// each /proc/<pid>/ns/<kind> descriptor — not readlink, which returns a
// string of the same form but is one syscall this function does not need to
// trust the kernel to have rendered consistently with what setns(2) will
// actually join. §4.1 step 4 says the same thing about the writer's side.
func procNamespaceInodes(pid int) (map[string]uint64, error) {
	out := make(map[string]uint64, len(runStateNamespaceKinds))
	for _, k := range runStateNamespaceKinds {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, k))
		if err != nil {
			return nil, err
		}
		var st unix.Stat_t
		ferr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if ferr != nil {
			return nil, ferr
		}
		out[k] = st.Ino
	}
	return out, nil
}

// releaseGate is §4.2a: block for B's report, then read /proc/<bpid>/status
// and independently verify all four confinement lines plus the recorded
// namespace ids, and ONLY THEN write the release byte. Any mismatch: kill B,
// A never exists.
// bridgeReportTimeout bounds releaseGate's wait for B's one report byte —
// see the comment at the read for why a bound exists at all and why this
// number is not a performance target.
const bridgeReportTimeout = 10 * time.Second

func releaseGate(bpid int, st runState, reportR, gateW *os.File, relay *stdioRelay) (int, error) {
	// The deadline is what makes the message below true. It read "before
	// this timed out waiting" for a milestone while the read had no
	// deadline at all, so the one failure it named — a B that never reports
	// — was the one failure it could not produce: `snug attach` blocked
	// here forever instead, which is issue #221's visible half. Ten seconds
	// is not a performance target: B's whole sequence is a handful of
	// syscalls and no I/O, so a B that has not reported in ten seconds is
	// not slow, it is stopped, and the caller SIGKILLs it (runAttach's error
	// path) rather than leaving it in the sandbox's namespaces.
	if err := reportR.SetReadDeadline(time.Now().Add(bridgeReportTimeout)); err != nil {
		return 0, fmt.Errorf("arming the deadline on the bridge's report pipe: %w", err)
	}
	buf := make([]byte, 1)
	if _, err := reportR.Read(buf); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, fmt.Errorf("the bridge process did not report confinement within %s and has "+
				"been killed. It was forked but never ran: if this is reproducible, it is the "+
				"class of bug issue #221 records (a fork child that entered the Go runtime and "+
				"stopped there), not a slow machine", bridgeReportTimeout)
		}
		return 0, fmt.Errorf("reading the bridge's confinement report: %w", err)
	}
	if buf[0] != 'C' {
		return 0, fmt.Errorf("the bridge process reported %q rather than confinement", buf[0])
	}

	if err := verifyBridgeConfined(bpid, st); err != nil {
		return 0, err
	}

	if _, err := gateW.Write([]byte{1}); err != nil {
		return 0, fmt.Errorf("releasing the bridge: %w", err)
	}
	// The relay's copy goroutines have been running since newStdioRelay
	// created them — there is nothing to start here, only to wait for once
	// A has exited, so trailing output is not dropped. relay.wait() blocks
	// only on the OUTBOUND (stdout/stderr) copies, which do terminate once A
	// exits; it does not wait on the inbound stdin copy, which has no EOF of
	// its own to reach when this process's stdin is a pipe/fd that outlives
	// A (#120) — see stdioRelay.wait's comment.

	var ws unix.WaitStatus
	if _, err := unix.Wait4(bpid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("waiting for the attached session: %w", err)
	}
	if relay != nil {
		relay.wait()
	}
	if ws.Exited() {
		return ws.ExitStatus(), nil
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return 1, nil
}

// verifyBridgeConfined is the "verify it is active, not merely requested"
// half. /proc/<bpid>/status renders absolute capability masks (not relative
// to the reader's own user namespace) and NoNewPrivs/Seccomp as plain
// integers, so this same-uid parent can read its own child's status file and
// know for certain what got installed — a security feature that was merely
// PASSED as a flag is the failure mode this exists to catch (the
// --seccomp-after-bwrap's-`--` history CLAUDE.md records).
func verifyBridgeConfined(bpid int, st runState) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", bpid))
	if err != nil {
		return fmt.Errorf("reading the bridge's own /proc/%d/status: %w", bpid, err)
	}
	got := map[string]string{}
	for _, ln := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(ln, ':'); i > 0 {
			got[ln[:i]] = strings.TrimSpace(ln[i+1:])
		}
	}
	if got["NoNewPrivs"] != "1" {
		return fmt.Errorf("refusing to release: the bridge does not have NoNewPrivs set")
	}
	if got["CapEff"] != "0000000000000000" || got["CapBnd"] != "0000000000000000" {
		return fmt.Errorf("refusing to release: the bridge does not have an empty capability set "+
			"(CapEff=%s CapBnd=%s)", got["CapEff"], got["CapBnd"])
	}
	wantSeccomp := "0"
	if st.Seccomp.State == "active" {
		wantSeccomp = "2"
	}
	if got["Seccomp"] != wantSeccomp {
		return fmt.Errorf("refusing to release: the bridge's Seccomp status (%s) does not match "+
			"what this run recorded (%s)", got["Seccomp"], wantSeccomp)
	}

	nsIno, err := procNamespaceInodes(bpid)
	if err != nil {
		return fmt.Errorf("reading the bridge's own namespaces: %w", err)
	}
	for _, k := range runStateNamespaceKinds {
		if k == "pid" {
			// The bridge (B) itself stays in the HOST's pid namespace by
			// design (§3.2: CLONE_NEWPID applies to children only) — the
			// namespace it has JOINED for children is ns/pid_for_children,
			// not ns/pid, and that is what must match the recorded one; only
			// A (B's own child) actually lands inside it.
			continue
		}
		if nsIno[k] != st.Sandbox.Namespaces[k] {
			return fmt.Errorf("refusing to release: the bridge's %q namespace does not match this "+
				"run's recorded one", k)
		}
	}

	pidForChildren, err := procNamespaceInode(bpid, "pid_for_children")
	if err != nil {
		return fmt.Errorf("reading the bridge's own pid_for_children namespace: %w", err)
	}
	if pidForChildren != st.Sandbox.Namespaces["pid"] {
		return fmt.Errorf("refusing to release: the bridge's pid_for_children namespace does not " +
			"match this run's recorded pid namespace")
	}
	return nil
}

// procNamespaceInode is procNamespaceInodes for a single, possibly
// non-standard entry under /proc/<pid>/ns/ — specifically
// "pid_for_children", which has no /proc/<pid>/ns/pid_for_children analogue
// in runStateNamespaceKinds because a state file never needs to record it: it
// only exists to be compared against the OWNING run's plain "pid" entry, at
// the one moment (the release gate) that distinction matters.
func procNamespaceInode(pid int, kind string) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
