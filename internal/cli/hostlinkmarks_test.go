package cli

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── issue #604: the PATH marks for a HOST symlink walkLinks now follows ─────
//
// hostlinkMarksRegistry builds one profile exercising all three verdicts a
// human reads off the same screen:
//
//   - /opt/hostlink/bin: a HOST symlink under a read-only bind, planted by
//     whoever had earlier write access to the host tree /opt/hostlink names,
//     landing on this profile's own writable tmpfs (/opt/wtmp). ABUSE: a
//     payload that can also reach /opt/wtmp — snug's own grant, not the
//     host's — drops a file called `git` there and the PATH element the
//     profile spelled as read-only resolves to it.
//   - /opt/hostlink2/x: a host component the fixture cannot read at all
//     (hostlinkMarksEnv's lstatErrs), so snug never learns what is there.
//   - /opt/control: the bind's own mountpoint, no symlink on the way — the
//     unmarked control that proves the other two rows are not just how every
//     PATH element on this profile renders.
func hostlinkMarksRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["hostlinkmarks"] = &policy.Profile{
		Name:        "hostlinkmarks",
		Description: "three PATH elements: a host symlink onto writable ground, an unresolvable host read, and a plain control",
		Include:     []policy.ProfileName{"@sys", "@home", "@target-rw"},
		RO:          []string{"/opt/hostlink", "/opt/hostlink2", "/opt/control"},
		Tmpfs:       []string{"/opt/wtmp"},
		Environ: policy.EnvGrants{
			Merge: map[string][]string{
				"PATH": {"/opt/hostlink/bin", "/opt/hostlink2/x", "/opt/control"},
			},
		},
	}
	return m
}

// hostlinkMarksEnv is hostlinkMarksRegistry's matching HOST fixture: the
// three RO grants' own host paths (needed so Resolve's EvalSymlinks check on
// each `ro` entry succeeds at all), the host symlink for the writable-ground
// row, and the unreadable component for the unresolved row.
func hostlinkMarksEnv(env *envFakeEnv) {
	env.dirs["/opt/hostlink"] = true
	env.dirs["/opt/hostlink2"] = true
	env.dirs["/opt/control"] = true
	// SLOT: nobody's profile wrote this link; the host tree /opt/hostlink
	// names already contained it.
	env.hostSymlinks["/opt/hostlink/bin"] = "/opt/wtmp"
	// UNRESOLVED: a host Lstat failure other than not-exist.
	env.lstatErrs["/opt/hostlink2/x"] = &fs.PathError{
		Op: "lstat", Path: "/opt/hostlink2/x", Err: fs.ErrPermission,
	}
}

// TestDryRunJSONMarksAnUnresolvedGrant is the machine-format half of the
// hostlink-marks golden: the same fixture, read through buildReport and
// through the literal JSON text renderJSON writes, so both the Go field and
// the wire spelling are pinned rather than only the human screen.
func TestDryRunJSONMarksAnUnresolvedGrant(t *testing.T) {
	m := hostlinkMarksRegistry(t)
	env := newEnvFakeEnv()
	hostlinkMarksEnv(env)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "hostlinkmarks")

	p, err := policy.Resolve(m, sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}

	rep := buildReport(env, p, p.BwrapArgs(0, 0), config{json: true}, nil, pinnedSignaturePolicy)

	var entry *reportEnvEntry
	for i := range rep.Environment {
		if rep.Environment[i].Name != "PATH" {
			continue
		}
		for j := range rep.Environment[i].Entries {
			if rep.Environment[i].Entries[j].Value == "/opt/hostlink2/x" {
				entry = &rep.Environment[i].Entries[j]
			}
		}
	}
	if entry == nil {
		t.Fatal("/opt/hostlink2/x never reached rep.Environment, so this test measures nothing")
	}
	if entry.Grant != grantUnresolved {
		t.Errorf("Grant = %q, want %q — a host read that failed on the way must not read as "+
			"granted, not-granted, or a shadow slot; it is a fourth fact snug does not have "+
			"enough information to fold into any of the other three", entry.Grant, grantUnresolved)
	}

	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	// The literal wire spelling, not only the Go-side field: a consumer reads
	// the JSON text, and `grant` being "" by default (see jsonEnvEntry.Grant)
	// means a renderer that silently dropped the unresolved case would still
	// emit valid, plausible-looking JSON with the key simply missing its value.
	if !strings.Contains(buf.String(), `"value": "/opt/hostlink2/x"`) {
		t.Fatalf("/opt/hostlink2/x never reached the JSON document, so the assertion below "+
			"proves nothing:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"grant": "unresolved"`) {
		t.Errorf("the JSON document does not carry `\"grant\": \"unresolved\"` for "+
			"/opt/hostlink2/x:\n%s", buf.String())
	}
}
