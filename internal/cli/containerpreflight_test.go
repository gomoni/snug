package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestMain exists for ONE reason: preflightResolvConfBind re-execs
// /proc/self/exe with the hidden `__probebind` verb, and under `go test`
// /proc/self/exe is the TEST binary, not snug. Without this dispatch the child
// ignores the verb and runs the whole test suite again — which re-enters this
// probe, which forks another suite. That is not a hypothetical: it was measured
// as a fork bomb that hung the run until the timeout killed the tree.
//
// So the test binary answers the verb exactly as internal/cli's Main does, and
// the probe under test is the real one rather than a stub.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__probebind" {
		if err := probeBindResolvConf(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestPreflightResolvConfBindAsksTheHostAndAnswersByName is preflight P7. It
// cannot assert an outcome — whether a file can be bound over
// /etc/resolv.conf is a property of the HOST, and both answers are legitimate
// (this development host says no, issue #128; CI says yes) — so it asserts
// that the probe actually got to ASK, and that whichever answer it gives is
// legible.
//
// CONTROL, and the reason this is not a test that cannot fail: the probe's own
// two failure modes are distinguishable by name. "making / private" means the
// child never reached the question — its user namespace was not created, the
// probe machinery is broken — and that is a FAILURE here. "mounting a file
// over /etc/resolv.conf" means the child asked and the host said no, which is
// the answer P7 exists to collect. A probe that silently returned the machinery
// error as the host's answer would warn every user on every host, and this
// assertion is what stops that shipping.
func TestPreflightResolvConfBindAsksTheHostAndAnswersByName(t *testing.T) {
	err := preflightResolvConfBind()
	if err == nil {
		t.Log("P7: this host CAN bind over /etc/resolv.conf")
		return
	}

	// THE THIRD OUTCOME, and it is not a failure of either the host or the
	// probe: some hosts cannot create the throwaway user namespace at all —
	// CI's unit-test container is one, where the child never starts and the
	// error is "fork/exec /proc/self/exe: permission denied". The probe did
	// not ASK, so there is no answer to grade. What IS graded is that snug
	// classified it that way rather than reporting it as the host's answer,
	// which is what the caller keys on to stay silent.
	var unavailable *probeUnavailableError
	if errors.As(err, &unavailable) {
		t.Skipf("SKIP: P7 cannot run its probe on this host (no throwaway user namespace): %v", err)
	}

	msg := err.Error()
	t.Logf("P7: this host CANNOT bind over /etc/resolv.conf: %s", msg)

	if strings.Contains(msg, "making / private") {
		t.Fatalf("the probe never reached its question: the child could not make its own tree "+
			"private, so one of the two namespaces it asked for was not created and this is the "+
			"probe machinery failing, not the host answering. P7 would then warn on every "+
			"host: %s", msg)
	}
	if !strings.Contains(msg, "/etc/resolv.conf") {
		t.Errorf("P7's answer does not name what stopped working — it reports an errno and "+
			"leaves the reader to guess (CLAUDE.md, 'errors name the fix'): %s", msg)
	}
}

// TestProbeBindRefusesWithoutAFile: the hidden verb is reachable from a shell,
// so it must refuse a malformed invocation rather than doing something
// undefined with whatever argv happens to hold.
func TestProbeBindRefusesWithoutAFile(t *testing.T) {
	for _, argv := range [][]string{nil, {}, {""}, {"a", "b"}} {
		if err := probeBindResolvConf(argv); err == nil {
			t.Errorf("__probebind accepted argv %q", argv)
		}
	}
}

// TestP7DoesNotDisturbTheHostsOwnResolvConf: the probe mounts inside a
// throwaway user + mount namespace whose tree it makes MS_PRIVATE first, so the
// host's own /etc/resolv.conf must read identically before and after — and the
// probe's temporary file must not survive it.
func TestP7DoesNotDisturbTheHostsOwnResolvConf(t *testing.T) {
	// The probe's own temporary file goes here, so the leftover check below
	// sees THIS probe's litter and not some other run's — os.CreateTemp("")
	// honours $TMPDIR.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	before, errBefore := os.ReadFile("/etc/resolv.conf")

	_ = preflightResolvConfBind()

	after, errAfter := os.ReadFile("/etc/resolv.conf")
	if (errBefore == nil) != (errAfter == nil) {
		t.Fatalf("the probe changed whether /etc/resolv.conf is readable: %v then %v", errBefore, errAfter)
	}
	if errBefore == nil && string(before) != string(after) {
		t.Errorf("the probe changed the HOST's /etc/resolv.conf — its mount escaped the throwaway "+
			"namespace:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "snug-resolvbind-probe-") {
			t.Errorf("the probe left %s behind in %s", e.Name(), tmp)
		}
	}
}
