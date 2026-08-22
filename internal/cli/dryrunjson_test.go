package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/sandbox"
)

// jsonGoldenSeccomp is the seccomp block every golden document carries,
// substituted for the real one before rendering.
//
// The real block is the only host-dependent thing in this document: Arch is
// runtime.GOARCH, Installed depends on whether sandbox.BuildFilter has a
// syscall table for it, and CompatArchGap is amd64-only. A golden containing
// any of the three would be an amd64 fixture nobody else's CI could pass —
// the same trap testdata/seccomp.active.txt already sidesteps with
// assertKnownGapParagraph.
//
// It is substituted rather than stripped so the KEYS stay in the golden: the
// field set is part of the format, and a renamed key must still show up as a
// diff here. TestSeccompFactsAreDerivedNotGolden asserts the real block on the
// host actually running the test.
var jsonGoldenSeccomp = reportSeccomp{
	Requested:     true,
	Installed:     true,
	Arch:          "GOARCH",
	Denied:        []string{"golden"},
	CompatArchGap: false,
}

// jsonGoldenReport resolves a selection against the same fixture host the
// environment goldens use and renders the machine format for it.
func jsonGoldenReport(t *testing.T, sel []policy.ProfileName, refused bool) string {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// $SNUG_PODMAN and $SNUG_PODMAN_ROOT reach the CONTAINERS block through
	// os.Getenv, so a developer with either exported would otherwise write
	// their own host into the golden.
	t.Setenv("SNUG_PODMAN", "")
	t.Setenv("SNUG_PODMAN_ROOT", "")

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	switch {
	case refused && err == nil:
		t.Fatalf("Resolve(%v) was expected to be refused; if this selection became runnable, "+
			"the case no longer shows what it was written for", sel)
	case !refused && err != nil:
		t.Fatalf("Resolve(%v): %v", sel, err)
	}

	rep := buildReport(p, p.BwrapArgs(0, 0), config{json: true}, err, pinnedSignaturePolicy)
	rep.Seccomp = jsonGoldenSeccomp

	var buf bytes.Buffer
	if rerr := renderJSON(&buf, rep); rerr != nil {
		t.Fatalf("renderJSON: %v", rerr)
	}
	return buf.String()
}

// TestGoldenDryRunJSON is the machine format's review artifact, and it is
// mandatory for the same reason the bwrap argv has one: a change to this
// document is a change to an interface other people's CI asserts on, and it
// must be readable as a diff.
//
// Issue #52's survey is the argument for not trusting the version field alone
// — five projects had drifted from their own documented format, terraform's
// docs disagree with its source, and cargo broke a consumer INSIDE
// --format-version=1. What actually held for git was v1 having its own
// renderer; a golden file buys the same guarantee more cheaply.
func TestGoldenDryRunJSON(t *testing.T) {
	cases := []struct {
		name    string
		sel     []policy.ProfileName
		refused bool
	}{
		// The document a bare `snug --dry-run --json <dir>` produces.
		{"defaults", profile.BuiltinDefaults(), false},
		// An engine run: the CONTAINERS block appears, the topology grows the
		// engine process and its capability bounding set, and the FILESYSTEM
		// block gains the staged podman stub — the one mount whose
		// "executable" is true, which is the fact behind the human column's
		// "exec" word.
		{"podman-socket", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, false},
		// A REFUSED policy still writes a complete document, and exits 77
		// separately. `snug --dry-run --json x > policy.json` yielding a
		// parseable file on a refusal is the property this format is designed
		// for; clang's SARIF does the opposite (0 bytes on redirect).
		{"refused", []policy.ProfileName{"@parent-ro"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonGoldenReport(t, tc.sel, tc.refused)

			path := filepath.Join("testdata", "json."+tc.name+".json")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/cli -update)", err)
			}
			if got != string(want) {
				t.Errorf("the machine format changed. This is an INTERFACE — read the diff as one:\n"+
					"--- want (%s)\n+++ got\n%s", path, diffLines(string(want), got))
			}
			// A golden that is not valid JSON would still compare equal to a
			// golden that is not valid JSON. Parse it.
			var doc map[string]any
			if err := json.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("the rendered document is not valid JSON: %v", err)
			}
		})
	}
}

// diffLines is a first-differing-line report. The documents are long and a
// full dump of both is not a diff anyone reads.
func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			fmt.Fprintf(&b, "line %d:\n-%s\n+%s\n", i+1, wl, gl)
			return b.String()
		}
	}
	return "(no line differs; a trailing-newline difference)"
}

// TestSeccompFactsAreDerivedNotGolden is the other half of the substitution
// jsonGoldenReport makes: the golden carries a placeholder seccomp block, so
// something has to assert the real one on the host running the test.
//
// The distinction it pins is CLAUDE.md's: requested is not installed. bwrap
// once accepted --seccomp after its own `--`, parsed nothing, and exited 0 —
// so a consumer asserting `seccomp.requested` would have been asking the
// question that looked the same and was not.
func TestSeccompFactsAreDerivedNotGolden(t *testing.T) {
	on := buildSeccompReport(config{})
	if on.Arch != runtime.GOARCH {
		t.Errorf("seccomp.arch is %q, want runtime.GOARCH %q", on.Arch, runtime.GOARCH)
	}
	if !on.Requested {
		t.Error("seccomp.requested is false without --no-seccomp")
	}
	_, ok, err := sandbox.BuildFilter()
	switch {
	case err != nil:
		if on.Installed || on.Reason != "assembly-error" {
			t.Errorf("BuildFilter failed to assemble but the report says installed=%v reason=%q",
				on.Installed, on.Reason)
		}
	case !ok:
		if on.Installed || on.Reason != "unsupported-arch" {
			t.Errorf("no syscall table for %s but the report says installed=%v reason=%q",
				runtime.GOARCH, on.Installed, on.Reason)
		}
	default:
		if !on.Installed || on.Reason != "" {
			t.Errorf("BuildFilter assembled but the report says installed=%v reason=%q",
				on.Installed, on.Reason)
		}
		if want := runtime.GOARCH == "amd64"; on.CompatArchGap != want {
			t.Errorf("compat_arch_gap is %v on GOARCH=%s, want %v",
				on.CompatArchGap, runtime.GOARCH, want)
		}
	}

	// The NEGATIVE control, and the one a consumer's gate depends on:
	// --no-seccomp must not produce a document claiming the filter is on.
	off := buildSeccompReport(config{noSeccomp: true})
	if off.Requested || off.Installed || off.Reason != "no-seccomp-flag" {
		t.Errorf("--no-seccomp reported as requested=%v installed=%v reason=%q",
			off.Requested, off.Installed, off.Reason)
	}
	if len(off.Denied) == 0 {
		t.Error("the denied list is empty under --no-seccomp — it is what those syscalls " +
			"are no longer protected from, and the human block prints it in that arm too")
	}
}

// TestSeccompBrokenBranchRenders reaches describeSeccomp's BROKEN arm, which
// seccompgolden_test.go's own doc comment records as unreachable before issue
// #52: it needed sandbox.BuildFilter to fail, and BuildFilter is a package
// function rather than a var. Splitting the facts out of the rendering removed
// the need for a seam — the arm is now selected by a field.
func TestSeccompBrokenBranchRenders(t *testing.T) {
	got := captureFile(t, func(f io.Writer) {
		describeSeccomp(f, reportSeccomp{
			Requested: true,
			Reason:    "assembly-error",
			Error:     "jump out of range",
			Arch:      "amd64",
			Denied:    []string{"ptrace"},
		})
	})
	if !strings.Contains(got, "SECCOMP  BROKEN — jump out of range") {
		t.Errorf("the BROKEN arm does not name the assembly error:\n%s", got)
	}
	if strings.Contains(got, "no syscall table") {
		t.Error("the BROKEN arm rendered the UNAVAILABLE sentence, which names the wrong fix: " +
			"there is nothing to fix on the host, the bug is in snug's own filter construction")
	}
	// POSITIVE CONTROL on the branch selection: the same helper on a report
	// that ASSEMBLED must not print BROKEN.
	fine := captureFile(t, func(f io.Writer) {
		describeSeccomp(f, reportSeccomp{Requested: true, Installed: true, Arch: "amd64", Denied: []string{"ptrace"}})
	})
	if strings.Contains(fine, "BROKEN") {
		t.Error("an installed filter rendered the BROKEN arm, so the branch is not selected by Reason")
	}
}

// TestHumanAndJSONFilesystemBlocksAgree is the check that makes "the two
// renderers cannot drift" a fact rather than a claim.
//
// It drives BOTH renderers for real — no re-derivation, no reading the policy
// a third time — and compares the SET of guest paths the FILESYSTEM block
// prints against the set in the JSON `mounts` array. Same shape as
// TestNoSnugScreenEmitsARawControlCharacter: assert the set, not the site.
func TestHumanAndJSONFilesystemBlocksAgree(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUG_PODMAN", "")
	t.Setenv("SNUG_PODMAN_ROOT", "")
	// The engine selection deliberately: it is the widest mount set any
	// shipped profile produces, and it is the one that carries a graft map as
	// well — which the FILESYSTEM block must NOT list and the `mounts` array
	// must not either.
	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	args := p.BwrapArgs(0, 0)

	human := dryRunText(p, args, config{}, nil)

	var jsonOut bytes.Buffer
	if err := dryRun(&jsonOut, p, args, config{json: true}, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}
	var doc struct {
		Mounts []struct {
			Guest string `json:"guest"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &doc); err != nil {
		t.Fatalf("the JSON renderer did not produce a parseable document: %v", err)
	}

	fromJSON := map[string]bool{}
	for _, m := range doc.Mounts {
		fromJSON[m.Guest] = true
	}
	fromHuman := humanFilesystemGuests(t, human)

	if len(fromJSON) == 0 || len(fromHuman) == 0 {
		t.Fatalf("one of the two renderers listed NO mounts (json %d, human %d) — a comparison "+
			"of two empty sets passes and tests nothing", len(fromJSON), len(fromHuman))
	}
	for g := range fromJSON {
		if !fromHuman[g] {
			t.Errorf("mount %q is in the JSON document and not in the FILESYSTEM block", g)
		}
	}
	for g := range fromHuman {
		if !fromJSON[g] {
			t.Errorf("mount %q is in the FILESYSTEM block and not in the JSON document", g)
		}
	}

	// POSITIVE CONTROL on the PARSER, which is the part of this test most able
	// to pass by accident: a guest path that is not in the policy must not be
	// found in the block it was never printed in.
	if fromHuman["/definitely-not-granted"] {
		t.Error("humanFilesystemGuests found a path the policy does not grant — the parser is " +
			"matching something other than a grant row")
	}
}

// humanFilesystemGuests pulls the guest paths out of the rendered FILESYSTEM
// block. It parses the SCREEN rather than the policy on purpose: reading the
// policy again would compare the JSON to the same source it came from, which
// is the drift this test exists to catch.
func humanFilesystemGuests(t *testing.T, screen string) map[string]bool {
	t.Helper()
	// The kind column's whole vocabulary: Kind.String(), plus the three
	// Access.String() words a bind renders instead, plus "exec" — the
	// dry-run-only word for a KindData file with an executable permission bit.
	// Anchoring on this SET rather than on indentation is what keeps a wrapped
	// prose line out: the block carries `←` marks and multi-line notes, and
	// their first word is never one of these.
	kinds := map[string]bool{
		"bind": true, "tmpfs": true, "link": true, "proc": true, "dev": true,
		"data": true, "graft": true, "cgroup2": true,
		"none": true, "ro": true, "rw": true, "exec": true,
	}
	out := map[string]bool{}
	in := false
	for _, line := range strings.Split(screen, "\n") {
		if strings.HasPrefix(line, "FILESYSTEM") {
			in = true
			continue
		}
		if !in {
			continue
		}
		fields := strings.Fields(line)
		// The block ends at its own summary row, which is not a grant.
		if len(fields) > 0 && fields[0] == "ro-/" {
			break
		}
		if len(fields) < 2 || !kinds[fields[0]] || !strings.HasPrefix(fields[1], "/") {
			continue
		}
		out[fields[1]] = true
	}
	return out
}

// TestJSONIsTheWholeOfStdoutOnARefusal pins stream discipline, which is the
// half of this format a consumer cannot work around.
func TestJSONIsTheWholeOfStdoutOnARefusal(t *testing.T) {
	out := jsonGoldenReport(t, []policy.ProfileName{"@parent-ro"}, true)

	var doc struct {
		Snug struct {
			Format  int    `json:"format"`
			Outcome string `json:"outcome"`
		} `json:"snug"`
		Refusal *struct {
			Message string `json:"message"`
		} `json:"refusal"`
		Mounts []any `json:"mounts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("a refused policy did not produce a parseable document: %v\n%s", err, out)
	}
	if doc.Snug.Outcome != "refused" {
		t.Errorf("outcome is %q on a refused policy, want \"refused\"", doc.Snug.Outcome)
	}
	if doc.Snug.Format != dryRunFormat {
		t.Errorf("format is %d, want %d", doc.Snug.Format, dryRunFormat)
	}
	if doc.Refusal == nil || doc.Refusal.Message == "" {
		t.Fatal("a refused policy carries no refusal.message — \"it was refused\" without the " +
			"reason is the half a consumer cannot act on")
	}
	if len(doc.Mounts) == 0 {
		t.Error("a refused policy rendered no mounts; --dry-run's whole job is showing what was " +
			"refused, not just that something was")
	}

	// The DISCRIMINATOR IS FIRST. A consumer streaming the document reads it
	// before anything else, which is why this is a struct tree and not a map
	// (encoding/json sorts map keys, and "snug" is not alphabetically first).
	if !strings.HasPrefix(out, "{\n  \"snug\": {") {
		t.Errorf("the document does not open with the snug discriminator:\n%.60s", out)
	}

	// POSITIVE CONTROL: the same renderer on a policy that is NOT refused must
	// say so, or "refused" is being reported unconditionally.
	ok := jsonGoldenReport(t, profile.BuiltinDefaults(), false)
	if !strings.Contains(ok, "\"outcome\": \"ok\"") {
		t.Error("a runnable policy did not render outcome \"ok\"")
	}
	if strings.Contains(ok, "\"refusal\"") {
		t.Error("a runnable policy carries a refusal object")
	}
}

// TestJSONNeverCarriesASecretsPlaintext is issue #51's guard, asserted from
// the sink that made it urgent rather than only on the type.
//
// #51 closed the hole — policy.Secret has MarshalJSON, so json.Marshal cannot
// render Content as base64 — but "the type is guarded" and "this document is
// clean" are two claims, and the second is the one a reviewer reading a golden
// diff is relying on.
func TestJSONNeverCarriesASecretsPlaintext(t *testing.T) {
	const needle = "ANTHROPIC_SUPER_SECRET_TOKEN_VALUE"

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUG_PODMAN", "")
	t.Setenv("SNUG_PODMAN_ROOT", "")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		profile.BuiltinDefaults(), envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	p.Replace(policy.Mount{
		Guest:   "/home/u/.secret",
		Kind:    policy.KindData,
		Content: policy.Secret(needle),
		From:    []string{"(snug)"},
	})

	// POSITIVE CONTROL: the needle really is in the policy this document is
	// rendered from. Without it, "the needle is absent" passes on a policy
	// that never carried one.
	found := false
	for _, m := range p.Mounts {
		if string(m.Content) == needle {
			found = true
		}
	}
	if !found {
		t.Fatal("the fixture policy does not carry the needle, so its absence below proves nothing")
	}

	rep := buildReport(p, p.BwrapArgs(0, 0), config{json: true}, nil, pinnedSignaturePolicy)
	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	if strings.Contains(buf.String(), needle) {
		t.Fatal("the machine-readable dry run contains a Secret's plaintext")
	}
	// And not base64 either, which is what json.Marshal does to a []byte and
	// is the exact spelling #51 was about — unrecognisable in a golden diff.
	if strings.Contains(buf.String(), "QU5USFJPUElD") {
		t.Fatal("the machine-readable dry run contains a Secret base64-encoded")
	}
}

// TestJSONPathsCarryTheirBytesWhenLossy is the safety property the format
// turns on: a CI gate saying "no mount grants anything under /etc" must not be
// bypassable by a path the string field cannot BE.
//
// The trigger is fidelity, not legibility. A value that is not valid UTF-8
// cannot be carried by a JSON string at all, so it gets a sibling and sets
// lossy. A value that is merely hard to look at is carried exactly, and the
// looking-at problem is solved in the SPELLING — see
// TestDryRunJSONEscapesTheRunesEncodingJSONLeavesRaw.
func TestJSONPathsCarryTheirBytesWhenLossy(t *testing.T) {
	bad := "/tmp/bad\xff\xfedir"

	var e lossyEncoder
	s, sib := e.text(bad)
	if !e.lossy {
		t.Fatal("encoding a non-UTF-8 path did not set lossy")
	}
	if sib == nil {
		t.Fatal("a non-UTF-8 path got no bytes sibling, so its real name is unrecoverable")
	}
	if string(sib) != bad {
		t.Errorf("the bytes sibling is %v, want the path's own bytes", []byte(sib))
	}
	if s != bad {
		t.Errorf("text() rewrote the string field (%q). It must hand json.Marshal the raw value "+
			"and let U+FFFD substitution be the documented loss — running a machine format "+
			"through policy.VisibleText, a TERMINAL-display transform, would make the field "+
			"not the value, so a consumer could not compare it without knowing snug's "+
			"escaping rules", s)
	}

	// A FORGING RUNE IS NOT A LOSS. The value is valid UTF-8 and is carried
	// exactly, so no sibling and no lossy — the document still round-trips.
	for _, forging := range []string{"/a\u009b1Ab", "/a\u0085b", "/a\u202eb", "/a\x1bb"} {
		var fe lossyEncoder
		v, fsib := fe.text(forging)
		if fe.lossy || fsib != nil {
			t.Errorf("a path carrying %q was reported lossy; it is valid UTF-8 and nothing "+
				"about it cannot be represented", forging)
		}
		if v != forging {
			t.Errorf("text() rewrote %q to %q — the string field must be the value", forging, v)
		}
	}

	// THE COLLISION VisibleText HAS AND THIS FORMAT AVOIDS BY NOT USING IT. A
	// path whose name literally contains the five ASCII characters \, x, f, f
	// renders identically to the non-UTF-8 one on screen — two different
	// files, one rendering. Here neither is transformed at all, and only one
	// carries a sibling.
	literal := `/tmp/bad\xff\xfedir`
	if policy.VisibleText(bad) != policy.VisibleText(literal) {
		t.Log("note: VisibleText no longer collides on these two; the argument for not reusing " +
			"it as the JSON encoding was measured against a version that did")
	}
	var e2 lossyEncoder
	if ls, lsib := e2.text(literal); lsib != nil || e2.lossy || ls != literal {
		t.Error("a valid-UTF-8 path was rewritten or got a bytes sibling, so the sibling no " +
			"longer distinguishes the two paths that collide on screen")
	}

	// The whole document's flag, which is the load-bearing part: one assertion
	// fails a gate closed, instead of auditing every field for a sibling it
	// may not know about.
	rep := Report{Outcome: "ok", Target: bad, Seccomp: jsonGoldenSeccomp}
	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\"lossy\": true") {
		t.Error("a document with a non-UTF-8 field does not carry snug.lossy: true")
	}
	if !strings.Contains(buf.String(), "\"target_bytes\": [") {
		t.Error("the target's bytes sibling is missing or is not an array of numbers")
	}

	// POSITIVE CONTROL: an all-UTF-8 document must be clean, or "lossy" is
	// simply always true.
	var clean bytes.Buffer
	if err := renderJSON(&clean, Report{Outcome: "ok", Target: "/tmp/fine", Seccomp: jsonGoldenSeccomp}); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	if !strings.Contains(clean.String(), "\"lossy\": false") {
		t.Error("an all-UTF-8 document reports lossy: true")
	}
	if strings.Contains(clean.String(), "_bytes") {
		t.Error("an all-UTF-8 document carries a bytes sibling")
	}
}

// TestDryRunJSONEscapesTheRunesEncodingJSONLeavesRaw is the display half, and
// it is a separate property from the lossy one on purpose: the value is
// unchanged, only its SPELLING is.
//
// Measured on this host, encoding/json escapes C0 for free and leaves the rest
// raw — U+009B (CSI), U+0085 (NEL) and U+202E (RLO) all reach the document as
// their own bytes. A dry-run document is read by humans in a golden diff,
// through jq and in a review UI, so that is the same lie visibleValue exists to
// stop on screen, in a new artifact.
func TestDryRunJSONEscapesTheRunesEncodingJSONLeavesRaw(t *testing.T) {
	const marker = "FORGED-BY-A-VALUE"
	hazards := map[string]string{
		"CSI (C1)":   "/a\u009b1Ab",
		"NEL (C1)":   "/a\u0085b",
		"RLO (bidi)": "/a\u202eb",
		"ESC (C0)":   "/a\x1bb",
	}
	for name, h := range hazards {
		t.Run(name, func(t *testing.T) {
			target := "/tmp/" + h + marker
			var buf bytes.Buffer
			if err := renderJSON(&buf, Report{Outcome: "ok", Target: target, Seccomp: jsonGoldenSeccomp}); err != nil {
				t.Fatalf("renderJSON: %v", err)
			}
			doc := buf.String()

			// POSITIVE CONTROL: the value really did reach the document. Without
			// it, "no raw rune" passes on a document that dropped the field.
			if !strings.Contains(doc, marker) {
				t.Fatalf("the fixture value never reached the document, so this measures "+
					"nothing:\n%s", doc)
			}
			// rawForgingRune is the sweep every screen in this package
			// shares (screensinks_test.go), used here unchanged: the
			// document is one more artifact a human reads, and it should
			// answer to the same predicate rather than to a copy of it. Its
			// '\n' exemption happens to be exactly right here too —
			// MarshalIndent's newlines are structure, and everything
			// encoding/json leaves raw INSIDE a string is >= U+0080.
			if r, ok := rawForgingRune(doc); ok {
				t.Errorf("the document carries a raw forging rune (%q):\n%s", r, doc)
			}

			// AND THE VALUE IS UNCHANGED, which is the whole argument for
			// spelling it this way rather than escaping it the way a screen
			// does: a decoder gives back the real rune, so a typed consumer
			// never sees the escape and `target == <the real path>` compares
			// equal.
			var back struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal([]byte(doc), &back); err != nil {
				t.Fatalf("the escaped document does not parse: %v", err)
			}
			if back.Target != target {
				t.Errorf("the document does not round-trip: got %q, want %q — the escaping "+
					"changed the VALUE, which is what VisibleText would have done and is "+
					"the reason this is JSON's own \\uXXXX instead", back.Target, target)
			}
			// snug.lossy stays FALSE: nothing was lost, only spelled.
			if strings.Contains(doc, "\"lossy\": true") {
				t.Error("escaping a forging rune set snug.lossy, which would make a gate " +
					"fail closed on a document that is byte-exact")
			}
		})
	}

	// NEGATIVE CONTROL on the escaper itself: an ordinary document must come
	// back byte-identical, or every golden in testdata/ is being rewritten by
	// a pass that is supposed to be a no-op.
	plain := []byte(`{"target":"/home/u/proj"}`)
	if got := escapeRawForgingRunes(plain); string(got) != string(plain) {
		t.Errorf("escapeRawForgingRunes rewrote a document with no hazard: %s", got)
	}
}

// TestKindAndAccessMarshalAsWords pins the enum spellings, which are part of
// the format. They are uint8 iota, so without MarshalJSON a document would
// carry "kind": 5 — a number whose meaning is the ORDER of the constants, and
// inserting one in the middle would silently renumber every document already
// written against format 1.
func TestKindAndAccessMarshalAsWords(t *testing.T) {
	for _, k := range []policy.Kind{
		policy.KindBind, policy.KindTmpfs, policy.KindSymlink, policy.KindProc,
		policy.KindDev, policy.KindData, policy.KindGraft, policy.KindCgroup2,
	} {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("json.Marshal(Kind(%d)): %v", k, err)
		}
		if want := `"` + k.String() + `"`; string(b) != want {
			t.Errorf("Kind(%d) marshals to %s, want %s", k, b, want)
		}
	}
	for _, a := range []policy.Access{policy.AccessNone, policy.AccessRO, policy.AccessRW} {
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("json.Marshal(Access(%d)): %v", a, err)
		}
		if want := `"` + a.String() + `"`; string(b) != want {
			t.Errorf("Access(%d) marshals to %s, want %s", a, b, want)
		}
	}
}

// TestJSONFlagNeedsDryRun holds the invocation rule: --json REPLACES the human
// dry-run screen, so without --dry-run it names nothing and is a usage error
// rather than a silent no-op.
func TestJSONFlagNeedsDryRun(t *testing.T) {
	for _, spelling := range []string{"-j", "--json"} {
		if _, err := parseArgs([]string{spelling, "/tmp"}); err == nil {
			t.Errorf("%s alone parsed cleanly; it must be a usage error", spelling)
		} else if !strings.Contains(err.Error(), "--dry-run") {
			t.Errorf("%s's error does not name the fix (%v)", spelling, err)
		}
		cfg, err := parseArgs([]string{spelling, "--dry-run", "/tmp"})
		if err != nil {
			t.Errorf("%s with --dry-run: %v", spelling, err)
		}
		if !cfg.json {
			t.Errorf("%s did not set the json flag", spelling)
		}
	}
	// The check must survive the EARLY return the `--` arm takes, which is a
	// second exit from parseArgs and exactly where a rule written once gets
	// applied to one of its two halves.
	if _, err := parseArgs([]string{"--json", "/tmp", "--", "sh"}); err == nil {
		t.Error("--json before a `--` command escaped the check, because that arm returns early")
	}

	// POSITIVE CONTROL: a plain dry run still parses.
	if _, err := parseArgs([]string{"--dry-run", "/tmp"}); err != nil {
		t.Errorf("--dry-run alone: %v", err)
	}
}

// TestSubcommandsRejectAFormatFlag closes the argv-drop trap. `snug doctor
// --json` and `snug profile list --json` exited 0 with the human report and
// the flag silently ignored — which hands PROSE to something about to
// json.Unmarshal, with a zero exit code saying it worked.
func TestSubcommandsRejectAFormatFlag(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	for _, argv := range [][]string{{"--json"}, {"-j"}, {"--format=json"}} {
		out := captureStdout(t, func() {
			if code := doctor(argv); code != exitUsage {
				t.Errorf("doctor(%v) returned %d, want %d (the flag was dropped)", argv, code, exitUsage)
			}
		})
		if strings.Contains(out, "🩺") {
			t.Errorf("doctor(%v) printed its human report before refusing", argv)
		}
	}
	for _, argv := range [][]string{{"list", "--json"}, {"--json"}, {"show", "@sys", "--json"}} {
		if code := profileCmd(argv); code != exitUsage {
			t.Errorf("profileCmd(%v) returned %d, want %d (the flag was dropped)", argv, code, exitUsage)
		}
	}

	// POSITIVE CONTROLS, both halves: the refusal must be about the FLAG, not
	// about the subcommand having stopped working.
	if code := profileCmd([]string{"list"}); code != 0 {
		t.Errorf("profileCmd(list) returned %d — the flag guard is refusing more than flags", code)
	}
	captureStdout(t, func() {
		if code := doctor(nil); code == exitUsage {
			t.Error("doctor with no arguments returned a usage error — the guard refuses every " +
				"invocation, not just the ones carrying a flag")
		}
	})
}

// pinnedSignaturePolicy is what every fixture in this package passes instead of
// reading the machine's own signature policy.
//
// It is the ordinary host: nothing configured. Without it json.podman-socket.json
// carries whatever /etc/containers/policy.json this runner happens to have —
// measured, and it is the difference between a green local gate and a red CI one.
func pinnedSignaturePolicy() engine.SignaturePolicySummary {
	return engine.SignaturePolicySummary{}
}
