package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// engineJudgeFixture resolves @sys, @cwd-rw, @podman-socket against
// envGoldenCtx (Target /home/u/proj/sub) over env — the same selection every
// other CONTAINERS-block golden in this package uses.
func engineJudgeFixture(t *testing.T, env *envFakeEnv) *policy.Policy {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestScreenRefusalAgreesWithTheRunForEverySpelling is issue #422 stated as an
// invariant rather than a single fixture: for any string a human could put in
// $SNUG_PODMAN or $SNUG_PODMAN_ROOT, the CONTAINERS block must carry a
// refusal if and only if the run's own judge — ResolveEngineBinary,
// JudgeEngineToolchain — returns one. The report used to re-implement a
// SUBSET of that judgement (CheckEngineBinary/CheckEngineToolchainTree on the
// raw value), which is how a resolving symlink could clear here and refuse
// there. Compared as EQUIVALENCE, not by wording, so a future reword of
// either message cannot fail this and a future divergence in verdict always
// will.
func TestScreenRefusalAgreesWithTheRunForEverySpelling(t *testing.T) {
	cases := []struct {
		name  string
		value string
		setup func(*envFakeEnv)
	}{
		{"clean, outside every grant", "/srv/clean-podman", nil},
		{"inside the rw target", "/home/u/proj/sub/bin/podman", nil},
		{"symlink outside every grant resolving into the rw target (#422)", "/srv/bundle-422",
			func(env *envFakeEnv) { env.links["/srv/bundle-422"] = "/home/u/proj/sub/tools" }},
		{"symlink whose NAME is inside the rw target, pointing at clean bytes",
			"/home/u/proj/sub/link",
			func(env *envFakeEnv) { env.links["/home/u/proj/sub/link"] = "/usr/bin/clean-podman" }},
		{"relative", "bin/podman", nil},
		{"a NUL byte", "/home/u/proj/sub/has\x00nul", nil},
		{"a newline", "/home/u/proj/sub/has\nnewline", nil},
		{"a directory where a binary is expected", "/usr", nil},
		{"nonexistent", "/srv/does-not-exist-422", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnvFakeEnv()
			if tc.setup != nil {
				tc.setup(env)
			}
			env.env["SNUG_PODMAN"] = tc.value
			env.env["SNUG_PODMAN_ROOT"] = tc.value
			p := engineJudgeFixture(t, env)

			_, binErr := p.ResolveEngineBinary(env, tc.value)
			_, rootErr := p.JudgeEngineToolchain(env, tc.value)
			rep := containersFor(env, p)

			if (rep.EngineBinaryRefusal != "") != (binErr != nil) {
				t.Errorf("EngineBinaryRefusal=%q, ResolveEngineBinary err=%v — the screen and the "+
					"run disagree about %q", rep.EngineBinaryRefusal, binErr, tc.value)
			}
			if (rep.ToolchainRootRefusal != "") != (rootErr != nil) {
				t.Errorf("ToolchainRootRefusal=%q, JudgeEngineToolchain err=%v — the screen and "+
					"the run disagree about %q", rep.ToolchainRootRefusal, rootErr, tc.value)
			}
		})
	}
}

// TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot is issue
// #422's own reproduction: $SNUG_PODMAN_ROOT names a path outside every
// grant, spelled through a symlink that resolves into the @cwd-rw target.
// The old screen called CheckEngineToolchainTree on the raw spelling, which
// is not covered by any grant lexically, so it printed the clearance
// sentence while the run — which resolves first — refused. Both sides are
// asserted in the SAME test body so the two cannot drift apart again.
func TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot(t *testing.T) {
	const spelling = "/srv/bundle"                // outside every grant, as spelled
	const resolvesInto = "/home/u/proj/sub/tools" // inside the rw target once resolved

	env := newEnvFakeEnv()
	env.env["SNUG_PODMAN_ROOT"] = spelling
	env.links[spelling] = resolvesInto

	p := engineJudgeFixture(t, env)

	// FIXTURE ASSERTION: if the target ever stops being write-visible, the
	// screen correctly clears the root and this test would pin a clearance
	// forever without ever exercising the refusal issue #422 is about.
	if !p.HostPathVisible(resolvesInto, true) {
		t.Fatalf("fixture: %s is not write-visible, so this test proves nothing about issue #422",
			resolvesInto)
	}

	got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
	if !strings.Contains(got, "THIS RUN WILL REFUSE") {
		t.Errorf("the screen cleared a toolchain root that resolves into the writable target:\n%s", got)
	}

	if err := p.EngineToolchain(env, spelling); err == nil {
		t.Error("the run's own EngineToolchain accepted the same spelling the screen just refused")
	}

	path := filepath.Join("testdata", "containers.podman-root-symlinked.txt")
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
		t.Errorf("the symlinked-toolchain-root CONTAINERS block changed — this is the screen "+
			"issue #422 is about.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// TestGoldenContainersEngineNotJudged is the OTHER new golden this issue
// adds: both fields NOT JUDGED at once, because neither has an object of the
// right kind on this host. A screen that quietly upgraded either of these to
// a clearance would be the "existence is a policy input" mistake report.go's
// own comment warns against.
func TestGoldenContainersEngineNotJudged(t *testing.T) {
	env := newEnvFakeEnv()
	env.env["SNUG_PODMAN"] = "/srv/a-directory" // exists, but is a directory
	env.dirs["/srv/a-directory"] = true
	env.env["SNUG_PODMAN_ROOT"] = "/srv/does-not-exist" // outside every grant, absent

	p := engineJudgeFixture(t, env)
	got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })

	if n := strings.Count(got, "NOT JUDGED"); n != 2 {
		t.Errorf("got %d NOT JUDGED line(s), want 2 (one per field):\n%s", n, got)
	}
	for _, clearance := range []string{"no grant of this sandbox makes that path", "no grant makes the root"} {
		if strings.Contains(got, clearance) {
			t.Errorf("an unjudged field rendered a clearance sentence (%q):\n%s", clearance, got)
		}
	}

	path := filepath.Join("testdata", "containers.podman-not-judged.txt")
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
		t.Errorf("the both-fields-NOT-JUDGED CONTAINERS block changed.\n--- got\n%s\n--- want\n%s",
			got, want)
	}
}

// TestContainersScreenDoesNotClearAnAbsentObject is issue #422's kind check as
// two negatives, one per field: a nonexistent toolchain root and a
// directory-valued engine binary, both outside every grant, must render NOT
// JUDGED rather than the "no grant" clearance — the check that fails if the
// kind gate is ever loosened to bare existence.
func TestContainersScreenDoesNotClearAnAbsentObject(t *testing.T) {
	t.Run("toolchain root: nonexistent", func(t *testing.T) {
		env := newEnvFakeEnv()
		env.env["SNUG_PODMAN_ROOT"] = "/srv/does-not-exist-422"
		p := engineJudgeFixture(t, env)
		got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
		if !strings.Contains(got, "NOT JUDGED") {
			t.Errorf("a nonexistent toolchain root did not render NOT JUDGED:\n%s", got)
		}
		if strings.Contains(got, "no grant makes the root") {
			t.Errorf("a nonexistent toolchain root rendered the clearance sentence:\n%s", got)
		}
	})

	t.Run("engine binary: directory-valued", func(t *testing.T) {
		env := newEnvFakeEnv()
		env.env["SNUG_PODMAN"] = "/srv/a-directory-422"
		env.dirs["/srv/a-directory-422"] = true
		p := engineJudgeFixture(t, env)
		got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
		if !strings.Contains(got, "NOT JUDGED") {
			t.Errorf("a directory-valued engine binary did not render NOT JUDGED:\n%s", got)
		}
		if strings.Contains(got, "no grant of this sandbox makes that path") {
			t.Errorf("a directory-valued engine binary rendered the clearance sentence:\n%s", got)
		}
	})
}

// TestContainersScreenDoesNotOverclaimAcrossAWritableMiddleHop is issue #417's
// F1: writableNameOnChain's own doc comment already states it never asks
// about a name strictly BETWEEN the first and last hop of a symlink chain,
// and a redteam round found the CONTAINERS block's clearance sentences
// asserting the opposite unqualified. The fixture puts a payload-writable
// NAME on exactly that middle hop:
//
//	rw grant    /base/proj
//	writable    /base/proj/toolchain -> /base/bundleA (the NAME sits inside the rw grant)
//	host-owned  /base/engine-root -> /base/bundleA     (outside every grant; models what a
//	                                                     real filesystem collapses a two-hop
//	                                                     chain through /base/proj/toolchain to)
//	clean       /base/bundleA/bin/podman                (outside every grant)
//
// Both JudgeEngineToolchain and ResolveEngineBinary clear $SNUG_PODMAN_ROOT
// and $SNUG_PODMAN here — the fixture assertions below are what prove this
// test is about the inversion rather than an ordinary refusal — because
// resolution collapses straight to the clean fixed point and never visits
// /base/proj/toolchain, exactly as ResolveEngineBinary's own NOTE THE LIMIT
// paragraph describes.
func TestContainersScreenDoesNotOverclaimAcrossAWritableMiddleHop(t *testing.T) {
	env := newEnvFakeEnv()
	env.dirs["/base/proj"] = true
	env.dirs["/base/bundleA"] = true
	env.dirs["/base/bundleA/bin"] = true
	env.files["/base/bundleA/bin/podman"] = true
	env.links["/base/proj/toolchain"] = "/base/bundleA"
	env.links["/base/engine-root"] = "/base/bundleA"
	// env.Stat does not itself follow env.links (unlike a real host's
	// os.Stat, which follows a symlink chain to the final inode) — these two
	// entries are what a real os.Stat through the chain above would report.
	env.dirs["/base/engine-root"] = true
	env.files["/base/engine-root/bin/podman"] = true
	env.env["SNUG_PODMAN"] = "/base/engine-root/bin/podman"
	env.env["SNUG_PODMAN_ROOT"] = "/base/engine-root"

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"},
		policy.Context{Target: "/base/proj", Home: "/home/u", Shell: "/usr/bin/bash", Command: []string{"/bin/sh"}},
		env)
	if err != nil {
		t.Fatal(err)
	}

	if !p.HostPathVisible("/base/proj/toolchain", true) {
		t.Fatalf("fixture: /base/proj/toolchain is not write-visible, so the fixture does not put a " +
			"writable name on the middle hop and this test proves nothing about the chain limit")
	}
	if _, err := p.ResolveEngineBinary(env, env.env["SNUG_PODMAN"]); err != nil {
		t.Fatalf("fixture: the run refuses the engine binary, so this test cannot be about a "+
			"clearance overclaiming: %v", err)
	}
	if _, err := p.JudgeEngineToolchain(env, env.env["SNUG_PODMAN_ROOT"]); err != nil {
		t.Fatalf("fixture: the run refuses the toolchain root, so this test cannot be about a "+
			"clearance overclaiming: %v", err)
	}

	got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
	// Joined on whitespace, not a raw Contains: the screen wraps this sentence
	// across two source lines ("...is not\npayload-controlled..."), and a
	// literal Contains of the joined phrase would never match either wording —
	// pinning nothing rather than pinning the inversion.
	normalized := strings.Join(strings.Fields(got), " ")
	if strings.Contains(normalized, "the engine is not payload-controlled") {
		t.Errorf("the CONTAINERS block clears the engine as \"not payload-controlled\" while "+
			"/base/proj/toolchain — a middle hop of the resolution chain — IS payload-writable; "+
			"this is the disclosure inversion issue #417 F1 exists to remove:\n%s", got)
	}
}

// TestContainersScreenExistenceOnlyDowngradesAClearance is the other
// direction from the test above: a path INSIDE a writable grant that does not
// exist on this host must still render THIS RUN WILL REFUSE, never NOT
// JUDGED — a payload must not be able to quiet the screen by deleting the
// file the engine would run.
func TestContainersScreenExistenceOnlyDowngradesAClearance(t *testing.T) {
	t.Run("engine binary", func(t *testing.T) {
		env := newEnvFakeEnv()
		env.env["SNUG_PODMAN"] = "/home/u/proj/sub/no-such-podman"
		p := engineJudgeFixture(t, env)
		got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
		if !strings.Contains(got, "THIS RUN WILL REFUSE") {
			t.Errorf("a nonexistent, writable-grant engine binary did not refuse:\n%s", got)
		}
		if strings.Contains(got, "NOT JUDGED") {
			t.Errorf("a nonexistent, writable-grant engine binary rendered NOT JUDGED, so "+
				"deleting the file would have quieted the screen:\n%s", got)
		}
	})

	t.Run("toolchain root", func(t *testing.T) {
		env := newEnvFakeEnv()
		env.env["SNUG_PODMAN_ROOT"] = "/home/u/proj/sub/no-such-root"
		p := engineJudgeFixture(t, env)
		got := captureFile(t, func(f io.Writer) { describeContainers(f, p, containersFor(env, p)) })
		if !strings.Contains(got, "THIS RUN WILL REFUSE") {
			t.Errorf("a nonexistent, writable-grant toolchain root did not refuse:\n%s", got)
		}
		if strings.Contains(got, "NOT JUDGED") {
			t.Errorf("a nonexistent, writable-grant toolchain root rendered NOT JUDGED, so "+
				"deleting the directory would have quieted the screen:\n%s", got)
		}
	})
}
