//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// TestDryRunNamesTheEnginesHostTreeGrafts is issue #252's second half, and the
// one that mattered: --dry-run rendered the engine's own four mounts and NONE
// of the host-tree grafts, because installEngineViewGrafts runs before the
// dry-run branch returns and eng.GraftInto ran a hundred lines after it.
//
// The store graft is the highest-value hand-over a container run makes —
// read-write, shared with every sandbox on the SAME TARGET DIRECTORY, whatever
// profiles it selected (issue #276), persistent across runs — and it had no
// abuse sentence on screen because it was never on screen.
//
// THE CONTROL IS A LIVE ENGINE, not a second reading of the same screen. The
// dry run claims the store lives at a host path; this test starts a real
// engine with the same profiles and the same target and reads
// /proc/<engine>/mountinfo to see where the store ACTUALLY came from. A screen
// that names a path the run does not use is the failure mode --dry-run exists
// to make impossible, and no amount of self-consistent output can detect it.
func TestDryRunNamesTheEnginesHostTreeGrafts(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	out, code := cli(t, env, "--dry-run", "-p", "@podman-socket", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}

	// CONTROL: the block is on the screen at all, and carries the engine's OWN
	// mounts. Those rendered before this fix too, so their presence is what
	// separates "the grafts are missing" from "the whole block is missing".
	if !strings.Contains(out, "ENGINE VIEW") {
		t.Fatalf("no ENGINE VIEW block on a @podman-socket dry run:\n%s", out)
	}
	if !strings.Contains(out, "proc-rw     /proc") {
		t.Fatalf("the ENGINE VIEW block does not carry the engine's own mounts, so this test "+
			"cannot tell a missing graft from a missing block:\n%s", out)
	}

	for _, want := range []struct{ guest, abuse string }{
		{"/snug/engine/store", "PERSISTS across runs"},
		{"/snug/engine/runroot", "keyed by"},
		{"/snug/engine/sock", "the socket the container proxy dials"},
		{"/snug/engine/conf", "read-only"},
	} {
		if !strings.Contains(out, want.guest) {
			t.Errorf("--dry-run does not name the %s graft (issue #252): the mount happens on "+
				"every container run and the screen a human reads to decide whether to trust "+
				"the run does not mention it:\n%s", want.guest, out)
			continue
		}
		// The row alone is not the point: the ABUSE SENTENCE is what a human
		// weighs, and it is what was missing along with the row.
		if !strings.Contains(out, want.abuse) {
			t.Errorf("the %s graft is named but its abuse sentence (%q) is not on screen",
				want.guest, want.abuse)
		}
	}

	dryStore := graftSourceFromScreen(t, out, "/snug/engine/store")
	dryRunroot := graftSourceFromScreen(t, out, "/snug/engine/runroot")
	t.Logf("--dry-run says store=%s runroot=%s", dryStore, dryRunroot)

	// A dry run must still have created none of them (issue #21). Reading the
	// paths off the screen and stat-ing them is the cheapest honest check that
	// PlannedPaths did not become engine.New.
	if fi, err := os.Stat(dryStore); err == nil && fi.IsDir() {
		// Not a failure by itself — a previous REAL run on this key may have
		// created it — so this only reports.
		t.Logf("note: %s already exists (an earlier real run on the same key)", dryStore)
	}

	// ── the control: what a live engine actually mounted ──────────────────
	bg := startBgSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 120`)
	bg.ready(t)
	bg.waitForState(t)
	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	mi, err := os.ReadFile(filepath.Join("/proc", itoa(enginePID), "mountinfo"))
	if err != nil {
		t.Fatalf("reading the engine's own mountinfo: %v", err)
	}
	liveStore := mountSourceFor(t, string(mi), "/snug/engine/store")
	liveRunroot := mountSourceFor(t, string(mi), "/snug/engine/runroot")
	t.Logf("the live engine mounted store=%s runroot=%s", liveStore, liveRunroot)

	// Only the KEY-DERIVED paths are compared, and by SUFFIX rather than by
	// equality. store and runroot are named from sha256(target) alone (issue
	// #276 removed the profile selection from the hash), so ANY selection on
	// the same target gives the same answer in both runs — that identity is
	// what makes this a check of the screen rather than of two unrelated
	// strings. sock and conf are named from the RUN's pid, so they
	// legitimately differ and are asserted by shape above.
	//
	// Equality is the wrong test for a reason worth writing down: mountinfo's
	// field 4 is the root WITHIN THE SOURCE FILESYSTEM, not the absolute host
	// path. Measured here — the store's host path is
	// /home/michal/.local/share/... and the engine's mountinfo says
	// /@/home/michal/... (a btrfs subvolume prefix), while the runroot under
	// /tmp reads /snug-engines-... because /tmp is its own tmpfs. The tail is
	// the part that carries the key, and the key is what decides WHICH store
	// this run writes into.
	for _, tc := range []struct{ what, screen, live string }{
		{"image store", dryStore, liveStore},
		{"runroot", dryRunroot, liveRunroot},
	} {
		tail := keyTail(tc.screen)
		if !strings.HasSuffix(tc.live, tail) {
			t.Errorf("--dry-run named the %s at %s; the live engine mounted %s, whose "+
				"filesystem-relative root does not end in %q. The screen is describing a "+
				"path this run does not use", tc.what, tc.screen, tc.live, tail)
		}
	}
}

// TestDryRunSaysTheEngineViewIsDerived is issue #252's first half: the
// TOPOLOGY text described the engine's mount namespace as "a private COPY of
// the host tree", which has been false since Tier C (#245) — and contradicted
// the ENGINE VIEW block twenty lines below it in the same output.
func TestDryRunSaysTheEngineViewIsDerived(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	out, code := cli(t, nil, "--dry-run", "-p", "@podman-socket", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	if strings.Contains(out, "private COPY of the host tree") ||
		strings.Contains(out, "private copy of the host tree") {
		t.Errorf("--dry-run still calls the engine's mount namespace a private copy of the host "+
			"tree; since Tier C it is derived from the sandbox's own view (issue #252):\n%s", out)
	}
	if !strings.Contains(out, "DERIVED from this sandbox's view") {
		t.Errorf("--dry-run does not say the engine's mount namespace is derived:\n%s", out)
	}
	// The two blocks must agree: the TOPOLOGY text points at ENGINE VIEW, so
	// ENGINE VIEW has to be there to be pointed at.
	if !strings.Contains(out, "ENGINE VIEW") {
		t.Errorf("the TOPOLOGY text refers to a block this screen does not print:\n%s", out)
	}
}

// TestDryRunStoreAbuseSentenceNamesTheTargetNotTheProfiles is issue #276's
// dry-run correction. Before this issue the store and runroot abuse sentences
// (paths.go's GraftPathsInto) said "profiles+target key" — true while
// engineKey hashed the sorted profile set alongside the target, and FALSE the
// moment part 1 removed the profile selection from the preimage. --dry-run is
// the artifact a human reads to decide whether to trust the run (CLAUDE.md),
// so a stale abuse sentence there is not a wording nit: it describes a key
// that no longer exists.
//
// This asserts the NEW text is on screen, not merely that the old text is
// gone — a screen with NEITHER sentence would pass a test that only checked
// absence, and "the abuse sentence is missing" is a different failure than
// "the abuse sentence is stale".
func TestDryRunStoreAbuseSentenceNamesTheTargetNotTheProfiles(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	out, code := cli(t, nil, "--dry-run", "-p", "@podman-socket", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "ENGINE VIEW") {
		t.Fatalf("no ENGINE VIEW block on a @podman-socket dry run:\n%s", out)
	}

	if strings.Contains(out, "profiles+target") {
		t.Errorf("--dry-run still says \"profiles+target\", describing a key issue #276 removed "+
			"from engineKey's preimage:\n%s", out)
	}

	// The abuse sentences are word-wrapped onto several screen lines, so the
	// comparison is done on WHITESPACE-COLLAPSED text: a substring check
	// against the raw output would fail on a wrap boundary that happens to
	// fall inside the phrase, which is a rendering fact and not the one this
	// test is about.
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"SAME TARGET DIRECTORY, whatever profiles it selected",
		"keyed by the TARGET DIRECTORY rather than by pid",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("--dry-run does not carry the corrected abuse sentence %q:\n%s", want, out)
		}
	}
}

// keyTail is the part of an engine path that carries the target-only key:
// the last two elements (…/<key>/storage, …/snug-engines-<uid>-<key>/rr). It
// is what survives mountinfo's filesystem-relative rendering, and it is the
// half that decides which store a run uses.
func keyTail(path string) string {
	dir, last := filepath.Split(strings.TrimSuffix(path, "/"))
	return filepath.Join(filepath.Base(strings.TrimSuffix(dir, "/")), last)
}

// graftSourceFromScreen reads the `from <host path>` line that follows a
// graft's row in the ENGINE VIEW block.
func graftSourceFromScreen(t *testing.T, out, guest string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.Contains(line, guest) || !strings.Contains(line, "graft-") {
			continue
		}
		for _, next := range lines[i+1:] {
			f := strings.Fields(next)
			if len(f) >= 2 && f[0] == "from" {
				return f[1]
			}
			if strings.Contains(next, "graft-") || strings.TrimSpace(next) == "" {
				break
			}
		}
	}
	t.Fatalf("no `from` line for the %s graft:\n%s", guest, out)
	return ""
}

// mountSourceFor reads the host-side source of a mount at guest out of a
// process's own mountinfo. Field 4 is the root within the source filesystem,
// which is the host path for a bind — the same field the issue's own
// measurement read.
func mountSourceFor(t *testing.T, mountinfo, guest string) string {
	t.Helper()
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[4] != guest {
			continue
		}
		return f[3]
	}
	t.Fatalf("the live engine has no mount at %s:\n%s", guest, mountinfo)
	return ""
}

// TestARealRunWithAnEngineOutsideEveryGrantMakesFiveGrafts is
// TestDryRunNamesTheEnginesHostTreeGrafts's other half, and the half
// TestGoldenEngineViewPlannedPaths (internal/cli/plannedgraft_test.go)
// deliberately does NOT cover: --dry-run runs no preflight, so it never
// resolves $SNUG_PODMAN_ROOT and always names four grafts — that test
// FATALS if its fixture policy ever carries a non-empty EngineToolchainRoot,
// precisely so nobody absorbs a fifth row into that golden by accident. A
// REAL run is different: when the engine binary sits outside every grant of
// the sandbox, $SNUG_PODMAN_ROOT (G4's third source) names a toolchain root,
// and the run mounts a FIFTH graft — policy.EngineToolchainGuest — so the
// engine can see its own binary at all.
//
// This drives that real run rather than trusting a screen, using the exact
// fixture containerengine_test.go's own engineWithHome helper builds for the
// same reason: a t.TempDir() wrapper is outside every grant this sandbox
// selects, so G4's first two disjuncts (an @sys-visible /usr/bin, a
// payload-writable root) cannot satisfy it and only $SNUG_PODMAN_ROOT can.
func TestARealRunWithAnEngineOutsideEveryGrantMakesFiveGrafts(t *testing.T) {
	budget(t, 90*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	wrapper, root := engineWithHome(t, t.TempDir())
	env = append(append([]string{}, env...), "SNUG_PODMAN="+wrapper, "SNUG_PODMAN_ROOT="+root)

	bg := startBgSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 60`)
	bg.ready(t)
	bg.waitForState(t)
	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	mi, err := os.ReadFile(filepath.Join("/proc", itoa(enginePID), "mountinfo"))
	if err != nil {
		t.Fatalf("reading the engine's own mountinfo: %v", err)
	}
	dump := string(mi)

	// The four grafts that are there either way, checked first as the
	// CONTROL: without them, "five grafts" could mean "one graft, mistakenly
	// counted five times" just as easily as the real claim.
	for _, guest := range []string{
		policy.EngineStoreGuest, policy.EngineRunrootGuest,
		policy.EngineSockGuest, policy.EngineConfGuest,
	} {
		if _, ok := mountSourceForOK(dump, guest); !ok {
			t.Fatalf("control: the live engine's own mountinfo has no mount at %s, so the "+
				"toolchain assertion below cannot mean \"five instead of four\":\n%s", guest, dump)
		}
	}

	// THE FIFTH GRAFT.
	toolchainSrc, ok := mountSourceForOK(dump, policy.EngineToolchainGuest)
	if !ok {
		t.Fatalf("the live engine's own mountinfo has no mount at %s (issue: a real run with "+
			"$SNUG_PODMAN_ROOT set must graft the toolchain root so the engine can see its own "+
			"binary), while it does have the other four:\n%s", policy.EngineToolchainGuest, dump)
	}
	tail := keyTail(root)
	if !strings.HasSuffix(toolchainSrc, tail) && toolchainSrc != root {
		t.Errorf("the toolchain graft at %s is sourced from %q; this run's own $SNUG_PODMAN_ROOT "+
			"is %q, and the live engine should be seeing THAT directory, not some other one",
			policy.EngineToolchainGuest, toolchainSrc, root)
	}
}

// mountSourceForOK is mountSourceFor without the t.Fatal — for a caller
// checking PRESENCE across several guests before deciding which failure to
// report, rather than aborting on the first miss.
func mountSourceForOK(mountinfo, guest string) (string, bool) {
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[4] != guest {
			continue
		}
		return f[3], true
	}
	return "", false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
