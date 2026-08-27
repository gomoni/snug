//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
)

// TestTheUnsupportedEngineSkipNamesTheVersion pins issue #458's rule: a SKIP
// must name the ONE condition it excuses.
//
// The message this replaces excused 27 tests on run 33054984495 with "no usable
// real container engine in this environment ... this host's engine cannot
// really run one", while the actual condition — podman 5.8.4, already logged
// UNSUPPORTED by the same function — went unsaid. Two things make that
// message's failure mode reachable again, so both are asserted: the version has
// to be IN the text, and the false explanation has to be OUT of it.
func TestTheUnsupportedEngineSkipNamesTheVersion(t *testing.T) {
	r := engineResolution{
		versionLine: "podman version 5.8.4",
		path:        "/usr/local/bin/podman",
		unsupported: engine.UnsupportedPodmanReason("podman version 5.8.4"),
	}
	// CONTROL: the fixture really is an unsupported one. Without this the
	// assertions below would pass just as well on an empty reason.
	if r.unsupported == "" {
		t.Fatalf("control: engine.UnsupportedPodmanReason called podman 5.8.4 supported, so "+
			"this fixture cannot exercise the skip at all (SupportedPodmanSet = %s)",
			engine.SupportedPodmanSet)
	}

	msg := unsupportedEngineSkipReason(r)

	for _, want := range []string{
		"5.8.4",                   // WHICH engine
		engine.SupportedPodmanSet, // what it is being measured against
		"/usr/local/bin/podman",   // and where it came from
		"SNUG_REQUIRE_ENGINE",     // how to turn the skip into a failure
		"Tumbleweed",              // where the real coverage is
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the skip does not mention %q, so a reader cannot tell what was "+
				"excused or what to do:\n%s", want, msg)
		}
	}

	// The specific false sentence. It is not enough that the version appears —
	// the old message could have both, and a reader stops at the first
	// explanation offered.
	if strings.Contains(msg, "cannot really run one") {
		t.Errorf("the skip still blames the host for being unable to run a container, which "+
			"is the false condition issue #458 was filed on:\n%s", msg)
	}
}
