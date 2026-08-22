package engine

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// THE MATCHER MUST NAME THE STRING THE ENGINE IS ACTUALLY EXEC'D WITH, and this
// is the ratchet for issue #344 — pure, cheap, and it fails on the code that
// shipped.
//
// reap.go identifies this run's engine by looking for a socket path in a
// host-visible command line. Since Tier C the engine is exec'd with an argv
// written in its DERIVED view ("unix://" + guestSock), while paths() returned
// the HOST spelling — so the sweep matched a string no process on the machine
// ever carried. Measured consequence: waitQuiet returned nil on its first poll
// on every run, signalOwned was never reached, and the "this sandbox's
// containers did not die with it" warning was unreachable.
//
// The general shape, which is why this test is worth more than the one-line fix
// under it: A PATH WRITTEN IN ONE NAMESPACE AND MATCHED IN ANOTHER. #167 was the
// same mistake for pids and was fixed by deleting the caller; nothing stopped it
// recurring for paths. This assertion is what stops the next one.
func TestTeardownMatchesTheArgvTheEngineIsStartedWith(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
		[]string{"PATH=/usr/bin"}, false, noSignaturePolicy(t))
	if err != nil {
		t.Fatal(err)
	}

	// What the engine's command line will read on the host: the binary plus its
	// arguments, exactly as the stage will exec them.
	argv := strings.Join(append([]string{spec.Podman}, spec.Argv...), " ")

	marks := e.paths()
	// CONTROL FIRST. An empty paths() would satisfy every assertion below while
	// meaning the sweep matches nothing at all — which is the defect this test
	// exists for, wearing a different hat.
	if len(marks) == 0 {
		t.Fatal("paths() is empty, so the teardown sweep can never match anything")
	}
	for _, m := range marks {
		if m == "" {
			t.Error("paths() contains an empty string, which cmdlineNamesPath skips")
			continue
		}
		if !strings.Contains(argv, m) {
			t.Errorf("teardown matches %q, which appears nowhere in the argv the engine "+
				"is started with.\n  argv: %s\n"+
				"A mark the engine never carries is a sweep that cannot fail (issue #344).",
				m, argv)
		}
	}

	// AND THE NEGATIVE, because "every mark is in the argv" is also satisfied by
	// marking something incidental. The HOST socket spelling is what shipped,
	// and it must not be a mark unless the derived view happens to give it the
	// same name — which it does not when the engine's directories are grafted.
	host := e.Socket()
	guest := strings.TrimPrefix(spec.Argv[len(spec.Argv)-1], "unix://")
	if guest == host {
		t.Skip("this fixture produced no derived view, so there is no second spelling to confuse")
	}
	for _, m := range marks {
		if m == host {
			t.Errorf("teardown still marks the HOST socket %q while the engine is exec'd "+
				"with %q — that is issue #344 exactly", host, guest)
		}
	}
}
