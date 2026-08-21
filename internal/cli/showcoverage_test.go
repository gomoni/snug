package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the guard that stops issue #195 recurring ───────────────────────────────
//
// `profile show` rendered every key that names a PATH and silently dropped every
// key that does not — network, dns, publish, address, gateway, mtu, podman, git,
// identity. A profile granting full internet egress and a host->sandbox port
// forward read as a profile with ZERO grants, on the screen a human uses to
// decide whether to select it.
//
// The defect is not that nine lines were missing. It is that NOTHING NOTICED,
// and nothing would have noticed the tenth: the renderer is a hand-written list
// of fields, so it falls one behind the struct once per feature. The goldens
// cannot catch it either — a key no fixture sets produces no diff when it is
// dropped.
//
// So this asserts the SET rather than the site, the same way CLAUDE.md's own
// rule about naming every sink does. It walks policy.Profile by reflection and
// requires each field to be either rendered or exempted WITH A REASON. A field
// added for a future feature fails this test until somebody decides which.
//
// It drives the real command through a real profiles.d file, so a key that
// parses but never reaches the renderer fails here rather than passing on a
// hand-built struct the loader would never have produced.

// probes maps a policy.Profile field to a string that must appear in
// `profile show` output for the fixture below. The value is chosen to be
// distinctive: matching on "egress" would pass on the word appearing in a
// description.
var probes = map[string]string{
	"Include":     "@sys",
	"RO":          "/probe-ro",
	"RW":          "/probe-rw",
	"Tmpfs":       "/probe-tmpfs",
	"Symlink":     "/probe-link",
	"Optional":    "/probe-optional",
	"Network":     "egress",
	"DNS":         "resolv.conf",
	"Publish":     "31415",
	"Plugins":     "probe-plugin",
	"Address":     "10.99.99.2/24",
	"Gateway":     "10.99.99.1",
	"Address6":    "fd00:99::2/64",
	"Gateway6":    "fd00:99::1",
	"MTU":         "1428",
	"Podman":      "socket",
	"Git":         "extract",
	"Identity":    "probe-key",
	"Environ":     "PROBE_ENV",
	"Description": "probe description",
}

// exempt names the fields `profile show` deliberately does not render as their
// own row, each with the reason. Adding a field here is a decision; leaving a
// new field out of both maps is a test failure, which is the point.
var exempt = map[string]string{
	"Name":   "rendered as the header, not as a row — the golden pins it there",
	"Source": "rendered as `defined in`, which is provenance rather than a grant",
	"Trusted": "not a grant and not read anywhere: CLAUDE.md records that " +
		"Profile.Trusted is set and never consulted, so rendering it would " +
		"assert a gate that does not exist (invariant 3's caveat)",
}

const probeProfile = `
[profile.probe]
description = "probe description"
include  = ["@sys"]
ro       = ["/probe-ro"]
rw       = ["/probe-rw"]
tmpfs    = ["/probe-tmpfs"]
optional = ["/probe-optional"]
symlink  = [{at = "/probe-link", target = "/probe-ro"}]
network  = "egress"
dns      = true
publish  = [31415]
plugins  = ["probe-plugin"]
address  = "10.99.99.2/24"
gateway  = "10.99.99.1"
address6 = "fd00:99::2/64"
gateway6 = "fd00:99::1"
mtu      = 1428
podman   = "socket"
git      = "extract"

[profile.probe.identity]
ssh_key   = "probe-key"
ssh_mode  = "agent-proxy"
git_name  = "Probe Person"
git_email = "probe@example.invalid"
gh_user   = "probeuser"

[profile.probe.environ.set]
PROBE_ENV = "probe-value"
`

// showProbe writes the fixture into a private profiles.d and renders it.
func showProbe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "probe.toml"), []byte(probeProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	orig := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "probe-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = f
	code := profileCmd([]string{"show", "probe"})
	os.Stdout = orig
	f.Close()
	if code != 0 {
		b, _ := os.ReadFile(f.Name())
		t.Fatalf("`profile show probe` exited %d — the fixture no longer parses, so every "+
			"assertion below would grade an empty screen:\n%s", code, b)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestProfileShowRendersEveryProfileField(t *testing.T) {
	got := showProbe(t)

	// The fixture has to actually have loaded, or every "not rendered" verdict
	// below would be true for the wrong reason.
	if !strings.Contains(got, "probe description") {
		t.Fatalf("PRECONDITION: the probe profile did not render at all:\n%s", got)
	}

	typ := reflect.TypeOf(policy.Profile{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		probe, wanted := probes[name]
		if !wanted {
			if why, ok := exempt[name]; ok {
				if why == "" {
					t.Errorf("policy.Profile.%s is exempt with no reason given", name)
				}
				continue
			}
			t.Errorf("policy.Profile.%s is in neither probes nor exempt. A field a profile "+
				"can set and `profile show` does not render is issue #195 happening again: "+
				"the screen a human reads to decide whether to trust a profile would not "+
				"name this grant. Render it in showCapabilities and add a probe, or exempt "+
				"it here with the reason", name)
			continue
		}
		if !strings.Contains(got, probe) {
			t.Errorf("policy.Profile.%s is set in the fixture but %q never reached the "+
				"screen:\n%s", name, probe, got)
		}
	}
}

// The consequence sentences are wrapped by hand (capRows), so the wrap width is
// a claim that can rot. A row running past 80 columns wraps wherever the
// terminal decides, in the middle of a sentence a human is being asked to weigh.
//
// SCOPED TO THE CAPABILITY ROWS, and that is a limit worth stating rather than
// hiding: the screen already emits longer lines elsewhere — `defined in` renders
// a full path, and an `environ.set` row carries the unchecked mark — and
// widening this test to the whole screen would either fail on those or force a
// number large enough to prove nothing. What is asserted is the part this change
// authors.
func TestProfileShowCapabilityRowsFitAnEightyColumnScreen(t *testing.T) {
	got := showProbe(t)

	const indent = "                   " // the blank label `show` prints, 19 columns
	inBlock, checked := false, 0
	for _, line := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(line, indent):
			// A continuation row belongs to whatever block opened above it.
		case strings.HasPrefix(line, "  "):
			label := strings.Fields(line)
			inBlock = len(label) > 0 && capabilityLabels[label[0]]
		default:
			inBlock = false
		}
		if !inBlock {
			continue
		}
		checked++
		if len(line) > 80 {
			t.Errorf("capability row is %d columns; showConsequenceWidth claims 80:\n%q",
				len(line), line)
		}
	}
	// Without this the loop could match nothing and pass on a screen that never
	// rendered a capability at all.
	if checked < len(capabilityLabels) {
		t.Fatalf("only %d capability rows were checked for a fixture that sets every "+
			"capability key — the block detection is wrong and this test is grading "+
			"almost nothing:\n%s", checked, got)
	}
}

var capabilityLabels = map[string]bool{
	"network": true, "dns": true, "publish": true, "address": true,
	"address6": true, "mtu": true, "podman": true, "git": true, "identity": true,
}

// A profile that grants nothing beyond paths must not grow an empty capability
// block. The renderer is all-conditional, and a stray unconditional row would
// show up here rather than only in a golden somebody regenerates.
func TestProfileShowRendersNoCapabilityRowsForAPathOnlyProfile(t *testing.T) {
	got, code := showGolden(t, "@sys")
	if code != 0 {
		t.Fatalf("`profile show @sys` exited %d", code)
	}
	for label := range capabilityLabels {
		if strings.Contains(got, "  "+label+" ") {
			t.Errorf("@sys grants no %s and must not render a %s row:\n%s", label, label, got)
		}
	}
}
