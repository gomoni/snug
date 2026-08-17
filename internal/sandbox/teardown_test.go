package sandbox

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
		for _, pid := range descendantsOf(root) {
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
		{"runStaged", "st.StartSandbox(bwrap, argv)"},
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
		for _, pid := range descendantsOf(root) {
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

	warned := []string{}
	confirmTeardown(directChild.Process.Pid, func(msg string) { warned = append(warned, msg) })

	if alive(directChild.Process.Pid) {
		t.Errorf("the direct child (pid %d) survived confirmTeardown", directChild.Process.Pid)
	}
	if alive(grandchild) {
		t.Errorf("the grandchild (pid %d) survived confirmTeardown — this is exactly the "+
			"shape of issue #13: a descendant that outlives the process P0 knows how to kill "+
			"directly", grandchild)
	}
	if remaining := descendantsOf(root); len(remaining) != 0 {
		t.Errorf("descendantsOf(root) still reports %v after confirmTeardown returned", remaining)
	}
	if len(warned) != 0 {
		t.Errorf("confirmTeardown warned even though the tree it was given converges well "+
			"within budget: %v", warned)
	}
	_, _ = directChild.Process.Wait()
}
