package engine

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestEngineRunLabelIsNeverEmpty converts the container proxy's precondition
// from an assumption into an assertion.
//
// dockerproxy refuses every container removal when its run label is empty or is
// not `key=value` — a removal is judged by comparing the container's own
// snug.run label against this string, and a check that cannot be made is not a
// pass (issue #339). That refusal is the right behaviour for a misconfigured
// proxy and the WRONG behaviour to ship: if New ever produced an empty label,
// `docker rm` and `docker run --rm` would stop working inside every sandbox and
// the failure would read as a policy decision rather than as a bug here.
//
// So the guarantee is asserted where it is produced. The alternative — a
// "skip the check when there is no label" branch in the proxy — is a fail-open
// switch reachable from a constructor argument, which is the shape the finding
// was.
func TestEngineRunLabelIsNeverEmpty(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	got := e.RunLabel()
	if got == "" {
		t.Fatal("RunLabel() is empty; the proxy refuses every container removal on an " +
			"empty label, so `docker rm` and `docker run --rm` would be broken in every " +
			"sandbox and would look like a policy refusal")
	}
	key, value, ok := strings.Cut(got, "=")
	if !ok {
		t.Fatalf("RunLabel() = %q, which is not key=value; the proxy cannot split it into "+
			"a label name and the value it compares against", got)
	}
	if key != RunLabelKey {
		t.Errorf("RunLabel() key = %q, want %q — the proxy looks the container's label up "+
			"under the key it finds here, so the two cannot disagree", key, RunLabelKey)
	}
	if strings.TrimSpace(value) == "" {
		t.Errorf("RunLabel() = %q has an empty value; every container would carry a label "+
			"that identifies no run, and a removal check against it would pass for any "+
			"run's container", got)
	}
}
