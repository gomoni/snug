package policy

import (
	"strings"
	"testing"
)

// TestSpecTextRoundTripsThroughSplitSpec would catch: a refusal suggesting
// `ro = ["<path>"]` for a host path holding ':' or '{', which splitSpec then
// reads as a different host at a different guest, or as an unknown variable.
func TestSpecTextRoundTripsThroughSplitSpec(t *testing.T) {
	for _, tc := range []struct{ host, guest string }{
		{"/h:/etc", "/opt/x"},
		{"/a{b}", "/c:d"},
		{"/x:y{z}:", "/{colon}"},
	} {
		host, guest, err := splitSpec(specText(tc.host), pathVars("/t", "/h"))
		if err != nil || host != tc.host || guest != tc.host {
			t.Errorf("specText(%q) reads back as %q at %q, %v", tc.host, host, guest, err)
		}
		host, guest, err = splitSpec(specText(tc.host)+":"+specText(tc.guest), pathVars("/t", "/h"))
		if err != nil || host != tc.host || guest != tc.guest {
			t.Errorf("%q:%q reads back as %q at %q, %v", tc.host, tc.guest, host, guest, err)
		}
	}
}

// TestEnvCouplingExpandsASymlinkTarget would catch: the coupling check
// resolving an env value through a symlink's RAW target while bwrap gets the
// expanded one, so a {var} in the target makes the verdict about a different
// link. /q{colon} is the link /q:, whatever the spelling, and nothing grants
// /q:/x.
func TestEnvCouplingExpandsASymlinkTarget(t *testing.T) {
	for _, target := range []string{"/q:", "/q{colon}"} {
		reg := testRegistry()
		reg["f"] = &Profile{Name: "f",
			Tmpfs:   []string{"/q{lbrace}colon}"},
			Symlink: []Symlink{{At: "/l", Target: target}},
			Environ: EnvGrants{Set: map[string]string{"PIP_CONFIG_FILE": "/l/x"}},
		}
		_, err := Resolve(reg, []ProfileName{"@sys", "@home", "f"}, testCtx(), newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), "which resolves to /q:/x through a symlink") {
			t.Errorf("target %q: err = %v, want the coupling refusal naming /q:/x", target, err)
		}
	}
}
