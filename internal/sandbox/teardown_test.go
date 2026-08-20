package sandbox

import (
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// alive reports whether pid is a live, running process — NOT merely present
// in the process table. syscall.Kill(pid, 0) alone cannot tell the
// difference: a killed-but-unreaped child is still a valid pid (a zombie)
// until something calls wait() on it, and this file kills things without
// always reaping them immediately, exactly as confirmTeardown itself does in
// production (reaping is cmd.Wait's job, not the sweep's — see
// descendantsOf's comment on why it excludes zombies). Reusing readStatus
// keeps this test's notion of "gone" identical to the production code's.
func alive(pid int) bool {
	_, zombie, ok := readStatus(pid)
	return ok && !zombie
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBecomeSubreaperMakesAReparentedOrphanVisible is the mechanism issue #13's
// fix rests on, exercised with plain shell children — no bwrap, no root, no
// namespaces needed.
//
// Without becomeSubreaper, a process orphaned by its immediate parent's death
// reparents to the NEAREST subreaper further up the tree — on this host,
// measured, that escapes past this test binary entirely (issue #13's own
// reproduction shows exactly that: "ppid=6392", a container's own subreaper,
// not snug's pid). descendantsOf walks ancestry UP from every candidate, so an
// orphan that reparented somewhere outside this process's tree is invisible to
// it — which is the failure mode this positive control exists to catch: a
// descendantsOf that always returns empty would pass every negative test in
// this file for the wrong reason.
func TestBecomeSubreaperMakesAReparentedOrphanVisible(t *testing.T) {
	if err := becomeSubreaper(); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable on this host: %v", err)
	}

	// mid forks a background sleep and exits immediately WITHOUT waiting for
	// it — the shell equivalent of the orphaning issue #13 is about: an
	// intermediate process dying while its own child is still alive.
	mid := exec.Command("sh", "-c", "sleep 30 & exit 0")
	if err := mid.Start(); err != nil {
		t.Fatal(err)
	}
	if err := mid.Wait(); err != nil {
		t.Fatalf("the intermediate shell itself failed: %v", err)
	}

	root := os.Getpid()
	var orphan int
	found := waitUntil(t, 2*time.Second, func() bool {
		for _, pid := range descendantsOf(root, nil) {
			if commOf(pid) == "sleep" {
				orphan = pid
				return true
			}
		}
		return false
	})
	if !found {
		t.Fatal("a background child of an already-exited shell never became visible as this " +
			"process's descendant — becomeSubreaper is not doing what issue #13's fix needs " +
			"it to do")
	}
	// Positive control that `orphan` really is the process in question, not a
	// coincidence: it must actually be alive right now.
	if !alive(orphan) {
		t.Fatal("PRECONDITION: the discovered orphan pid is not actually alive")
	}
	_ = syscall.Kill(orphan, syscall.SIGKILL)
}

// TestTheTeardownGuardIsArmedBeforeEveryForkItProtects reads exec.go and
// asserts an ORDER, because the order is the property and nothing else can
// see it.
//
// A guard armed after the fork still passes every behavioural test in the
// suite: the offset sweep in test/integration cannot reliably aim at the
// sub-millisecond gap between a live bwrap and an uninstalled signal handler,
// and in that gap the default disposition applies and snug dies leaving the
// orphan issue #13 is about. This is the same shape as the two ordering bugs
// CLAUDE.md records — --seccomp landing after bwrap's `--`, and a flag
// appended after the args memfd snapshot — where the feature was present,
// requested, and inert.
//
// Deliberately source-scanning rather than clever: the assertion is about
// where a line sits, so a test that reads the lines is the honest spelling.
func TestTheTeardownGuardIsArmedBeforeEveryForkItProtects(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	// PRECONDITION: both the guard and both forks must actually be found, or
	// every "arms before" check below passes on an empty search.
	arms := indexesOf(text, "armTeardown(opts)")
	if len(arms) != 2 {
		t.Fatalf("PRECONDITION: expected exactly 2 armTeardown(opts) call sites in exec.go "+
			"(one per topology), found %d. If a topology was added, this test needs a case "+
			"for it — a fork with no guard is issue #13 reopened", len(arms))
	}

	// Per FUNCTION, not per file: Run is written above runStaged, so a
	// whole-file "some arm precedes this fork" check would be satisfied by
	// Run's arm even if runStaged's were deleted outright — which is the
	// staged topology losing its guard with a green test.
	for _, fn := range []struct{ name, fork string }{
		{"Run", "cmd.Start()"},
		{"runStaged", "st.StartSandbox(bwrap, argv, opts.EngineSpec, release != nil)"},
	} {
		body := funcBody(text, fn.name)
		if body == "" {
			t.Fatalf("PRECONDITION: no func %s in exec.go — this test is checking nothing", fn.name)
		}
		fork := strings.Index(body, fn.fork)
		if fork < 0 {
			t.Fatalf("PRECONDITION: %s does not contain %q, so the fork this test is named "+
				"for has moved elsewhere and is now unchecked", fn.name, fn.fork)
		}
		arm := strings.Index(body, "armTeardown(opts)")
		if arm < 0 {
			t.Errorf("%s forks the sandbox (%s) and never arms the teardown guard. A signal "+
				"there kills snug outright and leaves the sandbox behind — issue #13",
				fn.name, fn.fork)
			continue
		}
		if arm > fork {
			t.Errorf("%s arms the teardown guard AFTER %s. A signal landing between that "+
				"fork and signal.Notify takes the default disposition, killing snug outright "+
				"and leaving the sandbox behind — issue #13, with a guard present and inert",
				fn.name, fn.fork)
		}
	}
}

// funcBody returns the text of a top-level func, from its declaration to the
// next top-level declaration. Crude on purpose: this file asserts an order
// between two literal lines, and a parser would add a dependency without
// making the claim any truer.
func funcBody(text, name string) string {
	start := strings.Index(text, "\nfunc "+name+"(")
	if start < 0 {
		return ""
	}
	rest := text[start+1:]
	if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
		return rest[:end+1]
	}
	return rest
}

func indexesOf(s, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(sub)
	}
}

// pinPID is the test's own copy of what guard.wait does before it can be
// signalled: turn a pid into a descriptor that names a process rather than a
// number.
func pinPID(pid int) (*os.File, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "pidfd-test"), nil
}

// TestKillPinnedOnlySignalsARealDescendant is the negative half of the pid
// reuse defence: killPinned re-confirms ancestry AFTER pinning, so a pid that
// does not belong to the tree being torn down is left alone.
//
// The stand-in for "the number was recycled to a stranger" is a root that the
// live process is genuinely not a descendant of. That is the same code path a
// recycled pid takes — pin, re-read ancestry, decline — without this test
// having to win a race against the kernel's pid allocator to prove it.
//
// The positive control is the same process and the same call with the real
// root: without it, a killPinned that had simply stopped signalling anything
// would pass the negative half perfectly.
func TestKillPinnedOnlySignalsARealDescendant(t *testing.T) {
	if err := becomeSubreaper(); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable on this host: %v", err)
	}
	victim := exec.Command("sleep", "30")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	pid := victim.Process.Pid
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	})
	if !alive(pid) {
		t.Fatal("PRECONDITION: the child is not alive")
	}

	// A root nothing on this host descends from. strangerRoot is not a live
	// pid, so the ancestry walk cannot reach it from anywhere.
	const strangerRoot = 0x7fffffff
	killPinned(pid, strangerRoot, nil)
	time.Sleep(50 * time.Millisecond)
	if !alive(pid) {
		t.Fatalf("killPinned SIGKILLed pid %d even though it is not a descendant of the "+
			"root it was given. A sweep that kills what it has not confirmed is one "+
			"recycled pid away from killing a stranger", pid)
	}

	killPinned(pid, os.Getpid(), nil)
	if !waitUntil(t, 2*time.Second, func() bool { return !alive(pid) }) {
		t.Fatal("PRECONDITION: killPinned did NOT kill a genuine descendant, so the check " +
			"above passed for the wrong reason — it proves nothing about ancestry if this " +
			"function never signals anything")
	}
}

func commOf(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// TestConfirmTeardownKillsTheWholeTree is the regression for issue #13's
// production mechanism: kill the direct child, then do not trust any
// automatic cascade — sweep for and kill everything still alive underneath
// it, repeatedly, until the tree is empty or the budget runs out.
//
// The shape mirrors what bwrap does across the pdeathsig-arming gap: a
// process (directChild) that has already forked a child of its own (the
// background sleep) BEFORE it is killed. Merely killing directChild and
// trusting the kernel is exactly the experiment issue #13 measured failing
// 3/3 in production; confirmTeardown must not make the same mistake here.
func TestConfirmTeardownKillsTheWholeTree(t *testing.T) {
	if err := becomeSubreaper(); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable on this host: %v", err)
	}

	directChild := exec.Command("sh", "-c", "sleep 30 & exec sleep 30")
	if err := directChild.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = directChild.Process.Kill()
		_, _ = directChild.Process.Wait()
	})

	root := os.Getpid()
	// PRECONDITION: both the direct child (now itself "sleep", via exec) and
	// its own background sibling must be visible and alive before we try to
	// tear anything down, or a pass below proves nothing.
	var grandchild int
	ok := waitUntil(t, 2*time.Second, func() bool {
		for _, pid := range descendantsOf(root, nil) {
			if pid != directChild.Process.Pid && commOf(pid) == "sleep" {
				grandchild = pid
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("PRECONDITION: the background sleep never appeared as a descendant")
	}
	if !alive(directChild.Process.Pid) || !alive(grandchild) {
		t.Fatal("PRECONDITION: the tree to be torn down is not fully alive yet")
	}

	pinned, err := pinPID(directChild.Process.Pid)
	if err != nil {
		t.Fatalf("PRECONDITION: cannot pin a live child with pidfd_open: %v", err)
	}
	defer pinned.Close()

	warned := []string{}
	confirmTeardown(pinned, nil, func(msg string) { warned = append(warned, msg) })

	if alive(directChild.Process.Pid) {
		t.Errorf("the direct child (pid %d) survived confirmTeardown", directChild.Process.Pid)
	}
	if alive(grandchild) {
		t.Errorf("the grandchild (pid %d) survived confirmTeardown — this is exactly the "+
			"shape of issue #13: a descendant that outlives the process P0 knows how to kill "+
			"directly", grandchild)
	}
	if remaining := descendantsOf(root, nil); len(remaining) != 0 {
		t.Errorf("descendantsOf(root, nil) still reports %v after confirmTeardown returned", remaining)
	}
	if len(warned) != 0 {
		t.Errorf("confirmTeardown warned even though the tree it was given converges well "+
			"within budget: %v", warned)
	}
	_, _ = directChild.Process.Wait()
}

// ── issue #111: which signals the guard actually registers ────────────────

// orphaningSignals is the measured answer to "what kills P0 without running a
// handler, and therefore reproduces issue #13", plus the three the guard has
// always carried.
//
// The first three are the original set. The rest are issue #111's measurement:
// signalled one at a time, 50ms into startup, snug orphaned its sandbox on
// every one of them (all rc=2, the Go runtime's fatal-throw path) and did NOT
// orphan on USR1, USR2, PWR, XCPU, XFSZ or PIPE, which have harmless default
// dispositions or none at all.
//
// This table is deliberately written out here rather than derived from
// teardownSignals: a test that reads its expectations from the code it is
// testing cannot fail. Deleting a signal from teardownSignals must break
// something, and this is the something.
var orphaningSignals = []struct {
	name string
	sig  syscall.Signal
}{
	{"TERM", syscall.SIGTERM},
	{"INT", syscall.SIGINT},
	{"HUP", syscall.SIGHUP},
	{"QUIT", syscall.SIGQUIT},
	{"ABRT", syscall.SIGABRT},
	{"TRAP", syscall.SIGTRAP},
	{"SYS", syscall.SIGSYS},
	{"SEGV", syscall.SIGSEGV},
	{"BUS", syscall.SIGBUS},
	{"FPE", syscall.SIGFPE},
	{"ILL", syscall.SIGILL},
	{"STKFLT", syscall.SIGSTKFLT},
}

// TestTeardownSignalsCoversEveryMeasuredOrphaningSignal is the list half: a
// membership check against a table written independently of the production
// variable.
//
// It is the cheap guard, and it is not the real one. A signal can be present
// in teardownSignals and still not be delivered — os/signal is not obliged to
// notify for every number a caller passes — which is exactly the "documented
// but not implemented" shape CLAUDE.md warns about, and why
// TestTheTeardownGuardCatchesEverySignalItRegisters exists next to it.
func TestTeardownSignalsCoversEveryMeasuredOrphaningSignal(t *testing.T) {
	have := map[syscall.Signal]bool{}
	for _, s := range teardownSignals {
		sig, ok := s.(syscall.Signal)
		if !ok {
			t.Fatalf("teardownSignals contains %v, which is not a syscall.Signal — signal.Notify "+
				"would accept it and nothing would ever match it", s)
		}
		have[sig] = true
	}
	for _, want := range orphaningSignals {
		if !have[want.sig] {
			t.Errorf("SIG%s is not in teardownSignals. It was MEASURED to leave an orphaned "+
				"sandbox behind when sent to snug during startup (issue #111), and it is "+
				"catchable, so its absence reopens issue #13 for that signal — silently, with "+
				"every other test still green", want.name)
		}
	}
}

const (
	teardownHelperSig = "SNUG_TEST_TEARDOWN_HELPER_SIG"
	teardownHelperSet = "SNUG_TEST_TEARDOWN_HELPER_SET"
)

// TestTeardownSignalHelperProcess is not a test. It is the subprocess half of
// TestTheTeardownGuardCatchesEverySignalItRegisters, and it does nothing at
// all unless the parent asked for it through the environment.
//
// A subprocess, because the property under test is a PROCESS-WIDE signal
// disposition and the failure mode is "the process dies". Asserting it in the
// test binary itself would take the whole package's run down with it, and —
// worse — an unregistered SIGSEGV would look like a crashed test suite rather
// than like the specific thing that is wrong.
func TestTeardownSignalHelperProcess(t *testing.T) {
	name := os.Getenv(teardownHelperSig)
	if name == "" {
		return
	}
	var sig syscall.Signal
	for _, s := range orphaningSignals {
		if s.name == name {
			sig = s.sig
		}
	}
	if sig == 0 {
		os.Stdout.WriteString("BADSIGNAL\n")
		os.Exit(4)
	}

	ch := make(chan os.Signal, 1)
	switch os.Getenv(teardownHelperSet) {
	case "production":
		signal.Notify(ch, teardownSignals...)
	case "termonly":
		// The positive control's set: deliberately WRONG, and wrong in exactly
		// the way the code was before issue #111 — a short hand-written list.
		signal.Notify(ch, syscall.SIGTERM)
	default:
		os.Stdout.WriteString("BADSET\n")
		os.Exit(4)
	}

	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		os.Stdout.WriteString("KILLFAILED\n")
		os.Exit(4)
	}
	select {
	case got := <-ch:
		os.Stdout.WriteString("CAUGHT " + got.String() + "\n")
		os.Exit(0)
	case <-time.After(5 * time.Second):
		// Registered, accepted, and inert: the signal was delivered somewhere
		// else, or nowhere. Distinct from dying, and worth its own code.
		os.Stdout.WriteString("NOTDELIVERED\n")
		os.Exit(5)
	}
}

// runTeardownHelper starts the subprocess above and reports what happened to
// it: its first line of output and its exit code (-1 when a signal killed it,
// which is the whole point of the exercise).
func runTeardownHelper(t *testing.T, sigName, set string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestTeardownSignalHelperProcess", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), teardownHelperSig+"="+sigName, teardownHelperSet+"="+set)
	out, _ := cmd.CombinedOutput()

	first := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "CAUGHT") || strings.HasPrefix(line, "NOTDELIVERED") ||
			strings.HasPrefix(line, "BADSIGNAL") || strings.HasPrefix(line, "BADSET") ||
			strings.HasPrefix(line, "KILLFAILED") {
			first = line
			break
		}
	}

	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return first, code
}

// TestTheTeardownGuardCatchesEverySignalItRegisters is the behavioural half,
// and it is the one that would have caught issue #111.
//
// For every signal measured to orphan a sandbox, a subprocess registers the
// production teardownSignals set and then sends that signal to itself. If the
// handler runs, the guard's `select` in wait() would have run too, and
// confirmTeardown with it. If it does not, the process dies exactly as snug
// did — leaving the sandbox behind.
//
// The POSITIVE CONTROL is the second subtest and it is not optional: the same
// helper, same signal, registering only SIGTERM — the shape of the code before
// this fix — must die. Without it, a helper that always printed CAUGHT (or a
// harness that never actually delivered anything) would make every assertion
// above pass for the wrong reason.
func TestTheTeardownGuardCatchesEverySignalItRegisters(t *testing.T) {
	for _, s := range orphaningSignals {
		t.Run(s.name, func(t *testing.T) {
			line, code := runTeardownHelper(t, s.name, "production")
			if !strings.HasPrefix(line, "CAUGHT") || code != 0 {
				t.Errorf("a process registering teardownSignals did not survive SIG%s: got %q, "+
					"exit code %d. signal.Notify accepted the signal and it still did not reach "+
					"a handler, so snug would die here without tearing its sandbox down — issue "+
					"#13, through the door issue #111 found", s.name, line, code)
			}
		})
	}

	t.Run("positive-control/only-SIGTERM-registered", func(t *testing.T) {
		line, code := runTeardownHelper(t, "QUIT", "termonly")
		if strings.HasPrefix(line, "CAUGHT") {
			t.Fatalf("PRECONDITION: a process that registered ONLY SIGTERM reported catching "+
				"SIGQUIT (%q). Something other than signal.Notify is handling it, so the "+
				"subtests above prove nothing about the registered set", line)
		}
		if code == 0 {
			t.Fatalf("PRECONDITION: a process that registered ONLY SIGTERM exited 0 after "+
				"sending itself SIGQUIT. The harness cannot tell a caught signal from an "+
				"uncaught one, so every assertion above is vacuous (got %q)", line)
		}
	})
}

// ── issue #113: what the sweep must NOT kill ──────────────────────────────

// spawnTwoLevelTree starts `sh -c 'sleep 30 & exec sleep 30'` — a process that
// forks a child and then becomes a long-lived process itself, which is the
// shape both the sandbox (bwrap over its init) and the container reaper (a
// shell over the `podman stop` it forks on EOF) actually have.
//
// Returns the direct child and its own child. Both are alive on return.
func spawnTwoLevelTree(t *testing.T, others map[int]bool) (*exec.Cmd, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "sleep 30 & exec sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	var child int
	ok := waitUntil(t, 2*time.Second, func() bool {
		for _, pid := range descendantsOf(os.Getpid(), nil) {
			if pid == cmd.Process.Pid || others[pid] {
				continue
			}
			if ppid, _, ok := readStatus(pid); ok && ppid == cmd.Process.Pid {
				child = pid
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("PRECONDITION: the background child of the spawned tree never appeared")
	}
	if !alive(cmd.Process.Pid) || !alive(child) {
		t.Fatal("PRECONDITION: the spawned tree is not fully alive")
	}
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	return cmd, child
}

// TestConfirmTeardownSparesAnExcludedSubtree is issue #113's ratchet.
//
// The container reaper is the one helper snug starts that is MEANT to outlive
// it: no Pdeathsig, its own process group, and one job — stop this run's
// containers if snug died without cleaning up. It is also a direct child of
// snug, so the signalled-teardown sweep found it and SIGKILLed it. That was
// harmless only because internal/cli's `defer ctrCleanup()` still ran and did
// the teardown itself; an os.Exit anywhere on the signal path would have
// turned it into "a signalled @podman-socket run leaks its containers".
//
// Two properties, and the second is what makes the first mean anything:
//
//  1. an excluded pid AND ITS OWN CHILDREN survive a sweep that kills
//     everything else — the subtree, not the process, because a reaper spared
//     while its `podman stop` is killed has been spared uselessly;
//  2. the positive control: the identical tree, with a nil exclusion, is
//     killed. Without it, a confirmTeardown that had simply stopped reaching
//     that tree at all would pass part 1.
func TestConfirmTeardownSparesAnExcludedSubtree(t *testing.T) {
	if err := becomeSubreaper(); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable on this host: %v", err)
	}

	keeper, keeperChild := spawnTwoLevelTree(t, nil)
	victim, victimChild := spawnTwoLevelTree(t, map[int]bool{keeper.Process.Pid: true, keeperChild: true})

	pinned, err := pinPID(victim.Process.Pid)
	if err != nil {
		t.Fatalf("PRECONDITION: cannot pin a live child with pidfd_open: %v", err)
	}
	defer pinned.Close()

	var warned []string
	exclude := map[int]bool{keeper.Process.Pid: true}
	confirmTeardown(pinned, exclude, func(msg string) { warned = append(warned, msg) })

	if alive(victim.Process.Pid) || alive(victimChild) {
		t.Errorf("the un-excluded tree survived confirmTeardown (direct %d alive=%v, child %d "+
			"alive=%v) — the sweep is not doing its job at all",
			victim.Process.Pid, alive(victim.Process.Pid), victimChild, alive(victimChild))
	}
	if !alive(keeper.Process.Pid) {
		t.Errorf("the EXCLUDED pid %d was killed anyway. That pid is the container reaper in "+
			"production: the one process whose job is to outlive snug and clean up after it "+
			"(issue #113)", keeper.Process.Pid)
	}
	if !alive(keeperChild) {
		t.Errorf("pid %d, a CHILD of the excluded pid %d, was killed. The exclusion must cover "+
			"the subtree: the reaper forks `podman stop` when its pipe reports EOF, and sparing "+
			"the shell while killing the stop spares nothing that matters",
			keeperChild, keeper.Process.Pid)
	}
	if len(warned) != 0 {
		t.Errorf("confirmTeardown warned about processes it was told to spare: %v. An excluded "+
			"subtree is not an unconverged teardown, and reporting it as one would make every "+
			"signalled @podman-socket run print a false leak warning", warned)
	}

	// POSITIVE CONTROL. Everything above is consistent with a confirmTeardown
	// that had simply stopped finding this tree — a descendantsOf returning
	// nothing passes all four checks. So sweep the same tree again with no
	// exclusion at all and require that it dies.
	pinnedKeeper, err := pinPID(keeper.Process.Pid)
	if err != nil {
		t.Fatalf("PRECONDITION: cannot pin the keeper: %v", err)
	}
	defer pinnedKeeper.Close()
	confirmTeardown(pinnedKeeper, nil, func(string) {})

	if alive(keeper.Process.Pid) || alive(keeperChild) {
		t.Fatalf("PRECONDITION: with NO exclusion, the same tree (direct %d, child %d) still "+
			"survived confirmTeardown. The sweep cannot see it, so the exclusion above proved "+
			"nothing — it was spared by an absence, not by the exclusion",
			keeper.Process.Pid, keeperChild)
	}
	_, _ = keeper.Process.Wait()
	_, _ = victim.Process.Wait()
}

// TestExcludeSetDropsPidsThatCouldNotNameAProcess guards the conversion, not
// the sweep. A 0 or negative pid reaching kill(2) means the process GROUP, or
// every process the caller may signal — so an exclusion list that quietly
// carried one would be the opposite of a safety measure if anything downstream
// ever signalled through it instead of comparing against it.
func TestExcludeSetDropsPidsThatCouldNotNameAProcess(t *testing.T) {
	got := (Options{ExcludeFromTeardown: []int{0, -1, 1, 4242}}).excludeSet()
	if len(got) != 1 || !got[4242] {
		t.Errorf("excludeSet kept something it should have dropped: %v. Only genuine pids "+
			"(>1) may survive; 0 and negatives name process groups, and 1 is init", got)
	}
	if (Options{}).excludeSet() != nil {
		t.Error("excludeSet on an empty Options must be nil — the ordinary run has nothing to " +
			"spare, and an empty non-nil map is a different thing to read at the call site")
	}
}
