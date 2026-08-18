package stage

import (
	"os"
	"testing"
)

// TestMain gives THIS package's own test binary the exact hidden-verb
// dispatch internal/cli/main.go installs in the real `snug` binary, and nothing
// else. Start's clone re-execs /proc/self/exe with "__stage-setup" as argv[0]
// — which, under `go test`, IS this test binary — so without this dispatch a
// real end-to-end Start() can never reach "ready": the test runner would see
// "__stage-setup" as an unrecognised -test flag and fail immediately. This is
// the ONLY thing that lets TestStartDelegatesTheFullSubuidRange below exercise
// a real clone/newuidmap/exec chain instead of stopping at a Config the
// package refuses before creating anything.
//
// Mirrors internal/cli/main.go's own dispatch deliberately, not
// coincidentally: same three verbs, same "before anything else" placement,
// same exitOnStageError semantics (`os.Exit`, never returns) — so a change to
// the real dispatch that this copy misses is a change ONLY the real binary's
// own tests would catch, not this package's.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__stage-setup":
			exitOnStageErrorForTest(MainSetup())
		case "__stage-serve":
			exitOnStageErrorForTest(MainServe())
		case "__innetns":
			exitOnStageErrorForTest(EnterNetns(os.Args[2:]))
		case "__debug-dropcaps":
			// Test-only, for TestDropCapsToExactlyProducesTheEngineCapabilitySet:
			// wait for the parent's release byte on fd 3, drop to
			// policy.EngineCapBounding, and report /proc/self/status back over
			// a path named in the environment (the CHILD's environment here is
			// a test fixture, not a sandbox — CLAUDE.md's "generate, don't
			// bind" rule is about what a PROFILE hands the payload, not this
			// harness's own plumbing).
			buf := make([]byte, 1)
			os.NewFile(3, "release").Read(buf)
			exitOnStageErrorForTest(runDebugDropCaps())
		}
	}
	os.Exit(m.Run())
}

func exitOnStageErrorForTest(err error) {
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}
