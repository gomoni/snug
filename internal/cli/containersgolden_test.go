package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenContainers is the review artifact for describeContainers, which
// had none before issue #63, Tier B: a security statement with no golden is
// untested by "golden diffs are the review artifact" (CLAUDE.md). Mirrors
// TestGoldenTopology's shape.
//
// Two cases: @podman-socket offline (the closing claim of this ticket — a
// container really has no egress) and @podman-socket + @net (full egress,
// covered by the same pasta guarantees as the sandbox). PodmanOff renders
// nothing, so there is no third "no containers" case here — that emptiness
// is asserted directly in TestDescribeContainersIsSilentWhenPodmanIsOff.
func TestGoldenContainers(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"podman-offline", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}},
		{"podman-egress", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The PATH-case goldens must not depend on the developer's own shell:
			// describeEngineSource reads $SNUG_PODMAN/$SNUG_PODMAN_ROOT, and a dev
			// who exports one would otherwise regenerate a different golden. Clear
			// them so these two cases are the unpinned PATH branch by construction;
			// the pinned branch has its own test below (issue #278).
			t.Setenv("SNUG_PODMAN", "")
			t.Setenv("SNUG_PODMAN_ROOT", "")
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(p)) })

			path := filepath.Join("testdata", "containers."+tc.name+".txt")
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
				t.Errorf("the CONTAINERS block changed — this is what a human reads to learn whether\n"+
					"a container has egress and what it can mount.\n--- got\n%s\n--- want\n%s",
					got, want)
			}
		})
	}
}

// TestDescribeContainersIsSilentWhenPodmanIsOff is the negative control
// TestGoldenContainers above deliberately does not carry as a golden case: an
// empty file is easy to mistake for a missing fixture rather than an
// intentional silence.
func TestDescribeContainersIsSilentWhenPodmanIsOff(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(p)) })
	if got != "" {
		t.Errorf("describeContainers printed %q for a PodmanOff policy, want nothing", got)
	}
}

// TestGoldenContainersEnginePinned is the OTHER branch of describeEngineSource
// (issue #278): a run whose engine comes from $SNUG_PODMAN with a
// $SNUG_PODMAN_ROOT bundle root reads DIFFERENTLY from the PATH-case goldens
// above — a shim on PATH plus $SNUG_PODMAN exported is exactly the run whose
// engine binary a human could not tell from --dry-run before this. The env
// values are what the screen must name, so they are set here and asserted to
// appear.
func TestGoldenContainersEnginePinned(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUG_PODMAN", "/opt/snug-podman/bin/podman")
	t.Setenv("SNUG_PODMAN_ROOT", "/opt/snug-podman")

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(p)) })

	path := filepath.Join("testdata", "containers.podman-pinned.txt")
	if *update {
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
		t.Errorf("the pinned-engine CONTAINERS block changed — this names which binary the run "+
			"starts and that PATH was bypassed.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// containersFor builds the CONTAINERS/IMAGES facts for a golden, with the one
// host-dependent one PINNED.
//
// engine.SummariseSignaturePolicy reads this machine's own
// ~/.config/containers/policy.json, so a developer who enforces image
// signatures would otherwise regenerate different goldens from one who does
// not — the same trap $SNUG_PODMAN is, two lines above. The pinned value is the
// ordinary host: nothing configured. The other three renderings have a golden
// of their own, below.
func containersFor(p *policy.Policy) *reportContainers {
	return buildContainersReport(p, engine.SignaturePolicySummary{})
}

// TestGoldenSignatureLine is the review artifact for the one line in IMAGES
// that is a fact about the HOST rather than about snug (issue #307).
//
// Four states in one file, because the diff a reviewer needs is between them:
// snug projects the host's signature policy into the engine's rather than
// writing a permissive one over it, so "NOT verified" and "not verified because
// your host does not verify either" are different claims, and a run that will
// refuse must say so here rather than at the moment the engine starts.
func TestGoldenSignatureLine(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUG_PODMAN", "")
	t.Setenv("SNUG_PODMAN_ROOT", "")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	states := []struct {
		name string
		sig  engine.SignaturePolicySummary
	}{
		{"this host configured none", engine.SignaturePolicySummary{}},
		{"the host's own accepts anything", engine.SignaturePolicySummary{
			Source: "/home/u/.config/containers/policy.json"}},
		{"the host's own demands a signature", engine.SignaturePolicySummary{
			Source: "/etc/containers/policy.json", Verified: true}},
		{"the host's own cannot be reproduced", engine.SignaturePolicySummary{
			Source: "/etc/containers/policy.json",
			Refusal: errors.New("/etc/containers/policy.json: transport \"docker\", scope " +
				"\"registry.example.internal\" is \"sigstoreSigned\", which snug does not project.\n" +
				"       Fix: use a signedBy requirement for the scopes a sandbox needs.")}},
	}

	var b strings.Builder
	for _, st := range states {
		fmt.Fprintf(&b, "── %s\n", st.name)
		b.WriteString(captureFile(t, func(f io.Writer) {
			describeSignaturePolicy(f, buildContainersReport(p, st.sig))
		}))
	}
	got := b.String()

	path := filepath.Join("testdata", "images.signatures.txt")
	if *update {
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
		t.Errorf("the IMAGES signatures line changed — this is what a human reads to learn "+
			"whether the engine enforces what their host configured.\n--- got\n%s\n--- want\n%s",
			got, want)
	}
}

// TestTheSignatureLineCannotForgeALine is the sink assertion issue #58's third
// red-team finding earned for the credential refusal, applied to the two host-
// text fields issue #307 adds to a screen: a policy path out of $HOME and a
// decoder's rendering of the host's own file.
//
// A policy.json whose parse error carries ESC and CR would otherwise erase the
// lines a human just read and write a reassuring one over them. Not
// payload-reachable — it is the host user's file — so this is screen integrity
// rather than an escape, and it is asserted because the rule is to name every
// sink the value reaches.
//
// CONTROL: an ordinary refusal must still render readably. A guard that escaped
// everything, or printed nothing, would pass a check for "no ESC".
func TestTheSignatureLineCannotForgeALine(t *testing.T) {
	hostile := &reportContainers{
		SignaturePolicySource:  "/home/u/.config/containers/policy.json\x1b[2A\x1b[2K\r",
		SignaturePolicyRefusal: "snug: images ARE verified\r\x1b[1A",
	}
	got := captureFile(t, func(f io.Writer) { describeSignaturePolicy(f, hostile) })
	for _, forging := range []string{"\x1b", "\r"} {
		if strings.Contains(got, forging) {
			t.Errorf("the signatures line emitted a raw %q, so a crafted host policy.json can "+
				"move the cursor and rewrite the lines above it:\n%q", forging, got)
		}
	}

	plain := &reportContainers{
		SignaturePolicySource: "/etc/containers/policy.json",
		SignaturesVerified:    true,
	}
	readable := captureFile(t, func(f io.Writer) { describeSignaturePolicy(f, plain) })
	for _, want := range []string{"/etc/containers/policy.json", "requires"} {
		if !strings.Contains(readable, want) {
			t.Errorf("an ordinary signatures line lost %q in the escaping, so it no longer "+
				"tells the reader which file it means:\n%s", want, readable)
		}
	}
}
