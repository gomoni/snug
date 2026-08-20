package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// engineMountRE finds the mount(2) calls __inengine makes with a LITERAL
// target — `unix.Mount("proc", "/proc", "proc", 0, "")` and its two siblings.
// The first argument is deliberately not captured: what this sweep compares is
// the DESTINATION, because that is what a graft is keyed by.
var engineMountRE = regexp.MustCompile(`unix\.Mount\(\s*"[^"]*"\s*,\s*"([^"]+)"`)

// engineMountExemptions are the mount(2) calls in __inengine that this sweep
// deliberately does not require a graft for, each with the reason — and the
// reason has to survive CLAUDE.md's own question about exemptions ("when you
// exempt something from a security sweep, ask what the exemption itself lets
// through"), so it is written out rather than listed.
//
//	/etc/resolv.conf — a BEST-EFFORT MS_BIND of snug's own generated
//	resolv.conf over the engine's, not a mount of a filesystem. It cannot be
//	modelled as a graft as the model stands: a graft may not be Optional (G5
//	refuses it outright, because "silently do less" is what the derived view
//	must never do), and this mount is allowed to fail — measured, issue #128,
//	on a host where /etc/resolv.conf is a bind over a deleted inode. It is
//	also the one __inengine step C2-view DELETES: once the engine's view is
//	derived from the sandbox's, the sandbox's own generated /etc/resolv.conf
//	is already there and there is nothing host-shaped left to shadow.
//
//	WHAT THE EXEMPTION LETS THROUGH: exactly one mount, of a file snug itself
//	generated, whose content the resolved Policy already authors (p.Net) and
//	whose failure is already printed. It is not a hole in the sense the other
//	three would be — it exposes no new host path — but it IS an unmodelled
//	mount in the engine's namespace for as long as it survives, which is the
//	thing this sweep exists to make visible rather than to permit.
//	/ — `unix.Mount("", "/", "", MS_REC|MS_PRIVATE, "")` is a PROPAGATION
//	change, not a mount: it adds no node to the engine's view and exposes
//	nothing. It is load-bearing for a different property (design pass §5:
//	without it the payload can see the engine's mounts, measured), which is a
//	fact about propagation flags rather than about the mount set this sweep
//	compares. Exempting it lets through nothing at all — there is no path to
//	model — and a sweep that demanded a graft for it would be demanding the
//	model describe a flag.
var engineMountExemptions = map[string]bool{
	"/etc/resolv.conf": true,
	"/":                true,
}

// TestEveryMountTheEngineMakesIsModelled is the §9.2 fix stated as a rule
// instead of as three call sites.
//
// The /run tmpfs was added to __inengine a milestone after issue #125 wrote
// "an unmodelled mount in the derived view is precisely #55's shape one layer
// further on" about /proc and /sys/fs/cgroup — and nothing noticed, because
// nothing was comparing the mounts the stage makes against the mounts the
// model describes. This is that comparison: the next mount the engine grows is
// modelled here or is visibly absent, on the day it is added.
func TestEveryMountTheEngineMakesIsModelled(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "stage", "inengine.go"))
	if err != nil {
		t.Fatal(err)
	}
	matches := engineMountRE.FindAllStringSubmatch(string(src), -1)

	// POSITIVE CONTROL on the sweep itself: __inengine makes at least the
	// three mounts this file models, so a regex that matched nothing (a
	// rewritten call, a helper extracted, a different quoting style) would
	// otherwise report "every mount is modelled" about a file it could not
	// read.
	if len(matches) < 3 {
		t.Fatalf("the sweep found %d literal unix.Mount call(s) in internal/stage/inengine.go and "+
			"the engine makes at least three (/proc, /sys/fs/cgroup, /run) — the pattern no longer "+
			"matches the source, so this test proves nothing. Repair the pattern; do not delete "+
			"the test.", len(matches))
	}

	modelled := modelledEngineViewGuests(t)
	for _, m := range matches {
		target := m[1]
		if engineMountExemptions[target] {
			continue
		}
		if !modelled[target] {
			t.Errorf("__inengine mounts %s in the engine's own namespace and nothing in "+
				"installEngineViewGrafts models it. An unmodelled mount in the derived view is "+
				"invisible to --dry-run, to Validate and to IsShadowSlot — three questions that "+
				"then all answer \"there is nothing there\" about a mount that is really there "+
				"(issue #125's design pass §9.2). Add it to engineview.go, or add it to "+
				"engineMountExemptions WITH the reason.", target)
		}
	}

	// And the other direction: a graft modelling a mount the engine does not
	// make is the same defect facing the other way — the screen would describe
	// a mount nobody performs.
	made := map[string]bool{}
	for _, m := range matches {
		made[m[1]] = true
	}
	for guest := range modelled {
		if !made[guest] {
			t.Errorf("installEngineViewGrafts models a mount at %s that __inengine does not make. "+
				"--dry-run would then describe the engine's view as holding something it does "+
				"not.", guest)
		}
	}
}

// modelledEngineViewGuests runs the real installer over a real resolved
// container policy and returns the destinations it recorded — read back from
// p.Grafts rather than from a list beside it, so this test cannot pass because
// two hand-kept lists agree with each other while the code does something
// else.
func modelledEngineViewGuests(t *testing.T) map[string]bool {
	t.Helper()
	p := engineViewPolicy(t)
	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatalf("installEngineViewGrafts refused a plain @podman-socket policy: %v", err)
	}
	if len(p.Grafts) == 0 {
		t.Fatal("installEngineViewGrafts recorded no grafts at all, so the comparison below " +
			"would be vacuous")
	}
	out := map[string]bool{}
	for guest := range p.Grafts {
		out[guest] = true
	}
	return out
}

func engineViewPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEngineViewGraftsCarryTheirOwnKindAndAccess pins the three properties a
// reader of --dry-run is entitled to: each of the engine's own mounts is the
// Kind that describes what it actually is, all three are writable (a
// read-only procfs, cgroup2 or /run would be a different engine), and none of
// them carries a host path — which is the whole distinction between "the stage
// mounts this" and "the stage clones this from the host".
func TestEngineViewGraftsCarryTheirOwnKindAndAccess(t *testing.T) {
	p := engineViewPolicy(t)
	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatal(err)
	}

	want := map[string]policy.Kind{
		"/proc":          policy.KindProc,
		"/sys/fs/cgroup": policy.KindCgroup2,
		"/run":           policy.KindTmpfs,
	}
	if len(p.Grafts) != len(want) {
		guests := make([]string, 0, len(p.Grafts))
		for g := range p.Grafts {
			guests = append(guests, g)
		}
		sort.Strings(guests)
		t.Fatalf("installEngineViewGrafts recorded %d graft(s) (%v), want exactly %d",
			len(p.Grafts), guests, len(want))
	}
	for guest, kind := range want {
		gr, ok := p.Grafts[guest]
		if !ok {
			t.Errorf("no graft at %s", guest)
			continue
		}
		if gr.Kind != kind {
			t.Errorf("graft at %s has Kind %v, want %v — the Kind is what says whether the stage "+
				"MOUNTS this or CLONES it from the host, and G4 is skipped for one and not the "+
				"other", guest, gr.Kind, kind)
		}
		if gr.Access != policy.AccessRW {
			t.Errorf("graft at %s is %v; all three of the engine's own mounts are writable — a "+
				"read-only one would be a different engine, and Access is enforced by "+
				"mount_setattr rather than being decorative", guest, gr.Access)
		}
		if gr.Host != "" {
			t.Errorf("graft at %s carries Host %q; a mount the stage makes itself has no source, "+
				"and --dry-run reads exactly this field to decide whether to print a `from` line "+
				"at all", guest, gr.Host)
		}
		if gr.Why == "" {
			t.Errorf("graft at %s has no abuse sentence", guest)
		}
	}
}

// TestGoldenEngineViewOwnMounts is the review artifact for this change: the
// ENGINE VIEW block a human really sees on a container run, rather than the
// hand-built Tier C fixture engineview.tierc.txt pins. A change to what the
// engine's own namespace holds is a change to the security boundary and shows
// up here as a diff.
func TestGoldenEngineViewOwnMounts(t *testing.T) {
	p := engineViewPolicy(t)
	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f *os.File) { describeGrafts(f, p) })

	path := filepath.Join("testdata", "engineview.enginemounts.txt")
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
		t.Errorf("the ENGINE VIEW block for the engine's OWN mounts changed — this is what a "+
			"human reads to learn what the container engine's namespace holds.\n--- got\n%s\n"+
			"--- want\n%s", got, want)
	}

	// The two render bugs this change fixed, asserted directly rather than
	// only pinned by the golden: a hostless graft printed `from ` with nothing
	// after it, and printed an `owned:` line claiming it "passed G4 only
	// because snug declared it its own for this run" — a check that never ran,
	// because G4 is skipped entirely for a mount with no source.
	if strings.Contains(got, "from \n") {
		t.Error("a graft with no host path still renders an empty `from` line")
	}
	if strings.Contains(got, "owned:") {
		t.Error("the ENGINE VIEW block claims G4's EngineOwnedHostPaths admitted one of the " +
			"engine's own mounts; G4 is skipped for a mount the stage makes itself, so that " +
			"sentence describes a check that did not run")
	}
}
