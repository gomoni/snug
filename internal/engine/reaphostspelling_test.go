package engine

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestSweepDoesNotMatchTheHostSocketSpelling is the last of the four #344
// regression tests that could be written, alongside reapmark_test.go,
// reapescalation_test.go and reapvacuity_test.go (plus test/guard's
// enginereapordering_test.go for the cross-package wiring). The review
// specified five; the fifth was an integration timing test, and
// test/integration/enginereapteardown_test.go carries the measurement showing
// it cannot exist on this architecture — read that file's package comment
// before concluding this set is short one.
//
// The other tests show that the sweep DOES match the spelling the engine's
// argv actually carries. This one shows the half that makes "guest-only" a
// FACT about the matcher rather than an implementation detail nobody
// exercises: a real, live process whose command line names the HOST socket
// spelling (e.Socket() / e.sock — /tmp/snug-<uid>-<pid>/sock/podman-<pid>.sock)
// must NOT be swept. That is precisely the string paths() used to return
// before #344's fix, and precisely why the sweep matched nothing on every
// run: no process on the machine ever carried it. A decoy that answers to
// that spelling and is correctly ignored is the difference between "the
// matcher is strict" and "the matcher is strict by accident, because nothing
// happened to collide".
func TestSweepDoesNotMatchTheHostSocketSpelling(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	// noSignaturePolicy is "this host configured none", NOT nil — Spec refuses
	// nil outright as a caller that skipped ProjectHostSignaturePolicy (#307).
	if _, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
		[]string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t)); err != nil {
		t.Fatalf("Spec: %v", err)
	}

	marks := e.paths()
	if len(marks) == 0 {
		t.Fatal("paths() is empty after Spec ran, so this test cannot tell a matched decoy " +
			"from an unmatched one — it would measure nothing")
	}

	host := e.Socket()
	guest := marks[0]
	// MANDATORY, and stated as its own assertion rather than folded into the
	// decoys below: if the host and guest spellings ever became the SAME
	// string (say, a future change that stops grafting engine directories and
	// exec's the engine against its host paths directly), every assertion in
	// this test would still pass — the "host decoy" and the "guest decoy"
	// would be indistinguishable and the negative below would hold for the
	// wrong reason. Fail loudly instead of silently degrading into a test
	// that cannot fail.
	if host == guest {
		t.Fatalf("e.Socket() (%q) and e.paths()[0] (%q) are identical — this test's host-spelling "+
			"negative and guest-spelling positive control would then be the same assertion twice, "+
			"which makes the whole test vacuous. Something about how the engine's directories are "+
			"grafted has changed; this test needs redesigning, not a green run", host, guest)
	}

	// The decoys. marker starts a real, non-forking process and does not
	// return until /proc/<pid>/cmdline is confirmed to actually contain the
	// mark (issue #317/#318's arg_start window) — see marker's own doc
	// comment in engine_test.go. Both are cleaned up by marker's own
	// t.Cleanup regardless of how this test ends.
	hostDecoy := marker(t, host)
	guestDecoy := marker(t, guest)

	// THE NEGATIVE: a decoy naming the HOST spelling must not be matched.
	if cmdlineNamesPath(hostDecoy.Process.Pid, marks) {
		t.Errorf("cmdlineNamesPath matched decoy pid %d, whose command line names the HOST "+
			"socket spelling %q — the engine is never exec'd with this string (its argv carries "+
			"the guest spelling %q instead), so matching it is issue #344 exactly: a matcher "+
			"that answers to a string nothing real ever carries", hostDecoy.Process.Pid, host, guest)
	}

	// THE MANDATORY POSITIVE CONTROL. Without this, "the host-spelling decoy
	// was not matched" is satisfied just as well by a matcher that matches
	// NOTHING AT ALL — which is the exact defect #344 was: paths() returning
	// a string no process carries makes every negative assertion trivially
	// true. This is the single most important assertion in this test.
	if !cmdlineNamesPath(guestDecoy.Process.Pid, marks) {
		t.Fatalf("cmdlineNamesPath did NOT match decoy pid %d, whose command line names the "+
			"real GUEST socket spelling %q — the matcher is matching nothing at all, which "+
			"means the negative assertion above passed for the wrong reason. This is the "+
			"vacuous-sweep shape issue #344 was", guestDecoy.Process.Pid, guest)
	}

	// The same two facts one level up, through ownedPIDs — the function
	// signalOwned and waitQuiet actually call, rather than the lower-level
	// predicate alone. exclude is empty: neither decoy is snug's own process.
	exclude := map[int]bool{}
	owned := ownedPIDs(marks, exclude)
	containsPID := func(pids []int, pid int) bool {
		for _, p := range pids {
			if p == pid {
				return true
			}
		}
		return false
	}
	if containsPID(owned, hostDecoy.Process.Pid) {
		t.Errorf("ownedPIDs(paths(), exclude) reports the host-spelling decoy pid %d as owned "+
			"by this run — ownedPIDs is what signalOwned and waitQuiet actually call, so this "+
			"is the production path, not just the predicate underneath it", hostDecoy.Process.Pid)
	}
	if !containsPID(owned, guestDecoy.Process.Pid) {
		t.Fatalf("POSITIVE CONTROL: ownedPIDs(paths(), exclude) does not report the "+
			"guest-spelling decoy pid %d as owned — ownedPIDs is matching nothing, which makes "+
			"the negative assertion above vacuous", guestDecoy.Process.Pid)
	}
}
