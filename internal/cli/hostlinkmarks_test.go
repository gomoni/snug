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
// hostlinkMarksRegistry builds one profile exercising six verdicts a human
// reads off the same screen — issue #604's own reproduction plus the three
// conformance-round findings its follow-up fix closed:
//
//   - /opt/hl/b: a HOST symlink under a read-only bind, planted by
//     whoever had earlier write access to the host tree /opt/hl names,
//     landing on this profile's own writable tmpfs (/opt/wtmp). ABUSE: a
//     payload that can also reach /opt/wtmp — snug's own grant, not the
//     host's — drops a file called `git` there and the PATH element the
//     profile spelled as read-only resolves to it.
//   - /opt/hl2/x: a host component the fixture cannot read at all
//     (hostlinkMarksEnv's lstatErrs), so snug never learns what is there.
//   - /opt/f1/t: FINDING 1. f1/l2 is a host link into /opt/wtmp; f1/t is a
//     host link whose OWN TEXT is "l2/../bin" — a name followed by a "..".
//     The kernel resolves l2 FIRST (landing in /opt/wtmp) and only then
//     climbs the "..", landing inside the writable tmpfs; a lexical Clean
//     of the link text would instead cancel "l2/.." to nothing and land on
//     the real, read-only /opt/f1/bin next to it, unmarked.
//   - /opt/f2/a/../b: FINDING 2. The same shape one level up — the ".."
//     sits in the PATH ELEMENT ITSELF, after a host link (/opt/f2/a) that
//     lands in /opt/wtmp. A lexical Clean of the whole element treats "a"
//     as an ordinary directory name and cancels it against the following
//     "..", landing back inside the read-only /opt/f2 bind instead of
//     following the link the kernel actually follows first.
//   - /opt/f4: FINDING 4. A read-only bind whose HOST tree
//     (/home/u/proj/sub/realbin) sits inside @target-rw's writable host
//     root (/home/u/proj/sub) — no symlink anywhere on the way. The mount's
//     own Access says ro, but the payload writes through the target bind and
//     the content changes here too.
//   - /opt/control: the bind's own mountpoint, no symlink on the way and no
//     writable grant behind it — the unmarked control that proves the other
//     rows are not just how every PATH element on this profile renders.
func hostlinkMarksRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["hlmarks"] = &policy.Profile{
		Name: "hlmarks",
		Description: "six PATH elements: a host symlink onto writable ground, an unresolvable " +
			"host read, a link inside host-link text before a dotdot, a dotdot after a host link " +
			"in the element itself, a read-only bind aliased by the writable target, and a plain control",
		Include: []policy.ProfileName{"@sys", "@home", "@target-rw"},
		RO: []string{
			"/opt/hl", "/opt/hl2", "/opt/f1", "/opt/f2",
			// host:guest — a RELOCATED grant, host tree deliberately inside
			// @target-rw's writable {target} (finding 4).
			"/home/u/proj/sub/realbin:/opt/f4",
			"/opt/control",
		},
		Tmpfs: []string{"/opt/wtmp"},
		Environ: policy.EnvGrants{
			Merge: map[string][]string{
				"PATH": {
					"/opt/hl/b", "/opt/hl2/x",
					"/opt/f1/t", "/opt/f2/a/../b", "/opt/f4",
					"/opt/control",
				},
			},
		},
	}
	return m
}

// hostlinkMarksEnv is hostlinkMarksRegistry's matching HOST fixture: every
// RO grant's own host path (needed so Resolve's EvalSymlinks check on each
// `ro` entry succeeds at all), the host symlink for the writable-ground row,
// the unreadable component for the unresolved row, and the link chains
// findings 1 and 2 need.
func hostlinkMarksEnv(env *envFakeEnv) {
	env.dirs["/opt/hl"] = true
	env.dirs["/opt/hl2"] = true
	env.dirs["/opt/f1"] = true
	env.dirs["/opt/f2"] = true
	env.dirs["/home/u/proj/sub/realbin"] = true
	env.dirs["/opt/control"] = true
	// SLOT: nobody's profile wrote this link; the host tree /opt/hl
	// names already contained it.
	env.hostSymlinks["/opt/hl/b"] = "/opt/wtmp"
	// UNRESOLVED: a host Lstat failure other than not-exist.
	env.lstatErrs["/opt/hl2/x"] = &fs.PathError{
		Op: "lstat", Path: "/opt/hl2/x", Err: fs.ErrPermission,
	}
	// FINDING 1: l2 is a host link into the writable tmpfs; t's own TEXT
	// names l2 and then climbs out of wherever l2 lands, not out of t's
	// own directory — the kernel resolves l2 first.
	env.hostSymlinks["/opt/f1/l2"] = "/opt/wtmp/a/b"
	env.hostSymlinks["/opt/f1/t"] = "l2/../bin"
	env.dirs["/opt/f1/bin"] = true // the DECOY: a lexical Clean lands here instead
	// FINDING 2: abs is a host link into the writable tmpfs; the PATH
	// element itself (not any link's text) carries the ".." this time.
	env.hostSymlinks["/opt/f2/a"] = "/opt/wtmp/sx"
	env.dirs["/opt/f2/bin"] = true // the DECOY, same role as /opt/f1/bin above
}

// TestDryRunJSONMarksAnUnresolvedGrant is the machine-format half of the
// hostlink-marks golden: the same fixture, read through buildReport and
// through the literal JSON text renderJSON writes, so both the Go field and
// the wire spelling are pinned rather than only the human screen.
func TestDryRunJSONMarksAnUnresolvedGrant(t *testing.T) {
	m := hostlinkMarksRegistry(t)
	env := newEnvFakeEnv()
	hostlinkMarksEnv(env)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "hlmarks")

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
			if rep.Environment[i].Entries[j].Value == "/opt/hl2/x" {
				entry = &rep.Environment[i].Entries[j]
			}
		}
	}
	if entry == nil {
		t.Fatal("/opt/hl2/x never reached rep.Environment, so this test measures nothing")
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
	if !strings.Contains(buf.String(), `"value": "/opt/hl2/x"`) {
		t.Fatalf("/opt/hl2/x never reached the JSON document, so the assertion below "+
			"proves nothing:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"grant": "unresolved"`) {
		t.Errorf("the JSON document does not carry `\"grant\": \"unresolved\"` for "+
			"/opt/hl2/x:\n%s", buf.String())
	}
}

// TestDryRunJSONMarksTheAliasedGraftAShadowSlot is finding 4's machine-format
// half: /opt/f4 has no symlink on the way at all — its own mount says ro —
// and is still `shadow_slot`, because its HOST tree sits inside @target-rw's
// writable host root. A consumer scripting against the JSON document must see
// the SAME verdict grantMark spells on the human screen as "← writable from
// inside", or the two surfaces disagree about which paths are safe.
func TestDryRunJSONMarksTheAliasedGraftAShadowSlot(t *testing.T) {
	m := hostlinkMarksRegistry(t)
	env := newEnvFakeEnv()
	hostlinkMarksEnv(env)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "hlmarks")

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
			if rep.Environment[i].Entries[j].Value == "/opt/f4" {
				entry = &rep.Environment[i].Entries[j]
			}
		}
	}
	if entry == nil {
		t.Fatal("/opt/f4 never reached rep.Environment, so this test measures nothing")
	}
	if entry.Grant != grantShadowSlot {
		t.Errorf("Grant = %q, want %q — /opt/f4's own Access is ro, but a SEPARATE writable "+
			"grant's host root (@target-rw's {target}) contains its host tree, so the payload "+
			"reaches the same content through that other grant", entry.Grant, grantShadowSlot)
	}

	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"value": "/opt/f4"`) {
		t.Fatalf("/opt/f4 never reached the JSON document, so the assertion below proves "+
			"nothing:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"grant": "shadow_slot"`) {
		t.Errorf("the JSON document does not carry `\"grant\": \"shadow_slot\"` for /opt/f4:\n%s",
			buf.String())
	}
}
