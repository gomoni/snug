package policy

import (
	"slices"
	"strings"
	"testing"
)

// ── issue #125, Tier C piece C1: the graft Kind table ─────────────────────────
//
// A graft is no longer only an open_tree(2) clone of a host path. The engine's
// derived view also needs two mounts the stage MAKES rather than clones — a
// fresh procfs bound to the engine's own pid namespace, and cgroup2 — and both
// must be in p.Grafts rather than made behind the model's back. EnterEngine
// made exactly those mounts for a whole tier with no Policy modelling them,
// which was harmless while there was no EngineView and is precisely issue #55's
// shape one layer on once EngineView becomes the enforcement model.
//
// So Graft.Kind became an allowlist (graftKindRules) instead of a flat
// `!= KindGraft`, and the tests below are about the thing an allowlist gets
// wrong: a kind added to the table without deciding, per rule, whether that
// rule applies to it. CLAUDE.md names this shape — "a rule written once and
// applied to one of its two halves" — and this package has paid for it twice
// (checkEnvName/checkEnvValue, hostPathVisible/resolveExisting).

// TestAFreshMountGraftMayNotCarryAHost is the assertion that makes
// graftKindRules a TABLE rather than a set of skips.
//
// hasHost=false must mean "this kind HAS no source", not "this kind's source
// goes unchecked". Gating alone was the first shape of the code: every Host
// rule is gated on rules.hasHost, so a KindProc graft carrying
// Host: "/home/u/.ssh" passed all of them, was stored verbatim, and
// describeGrafts printed `from /home/u/.ssh` for a mount the stage builds fresh
// and never opens that path for.
//
// Nothing was reachable — the stage ignores Host for KindProc — so this is not
// an escape. It is a LIE ON THE SCREEN, in the artifact CLAUDE.md calls "the
// mechanism by which a human can trust snug at all", about the one grant no
// profile can author and therefore the one a human can only check by reading
// --dry-run. Refuse the field rather than ignoring it.
func TestAFreshMountGraftMayNotCarryAHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind Kind
		set  func(*Graft)
	}{
		{"proc with a host", KindProc, func(g *Graft) { g.Host = "/home/u/.ssh" }},
		{"cgroup2 with a host", KindCgroup2, func(g *Graft) { g.Host = "/home/u/.ssh" }},
		// HostAsked reaches the screen too (issue #55, F6 §2c), so it is the
		// other half of the same field and must be refused by the same rule.
		// A guard written for one of two fields is this file's whole subject.
		{"proc with only a HostAsked", KindProc, func(g *Graft) { g.HostAsked = "/home/u/.ssh" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolveDefaults(t)
			g := freshMountGraft(tc.kind)
			tc.set(&g)
			err := p.Graft(newFakeEnv(), g)
			if err == nil {
				t.Fatalf("a %s graft carrying a host path was ACCEPTED. Every Host rule is gated "+
					"on graftKindRules[%v].hasHost, so nothing checked it and nothing will read "+
					"it — but --dry-run renders it, so the ENGINE VIEW block now names a host "+
					"path for a mount the stage builds fresh", tc.kind, tc.kind)
			}
			// The refusal must name the field, or it is indistinguishable from
			// the half-dozen other refusals this fixture could trip.
			if !strings.Contains(err.Error(), "Host") {
				t.Errorf("refusal does not name Host, so a reader cannot tell which field to "+
					"clear: %v", err)
			}
		})
	}
}

// TestAFreshMountGraftWithNoHostIsAccepted is the positive control for the test
// above: without it, "a fresh-mount graft was refused" would pass on a fixture
// that could never have been accepted for some unrelated reason.
func TestAFreshMountGraftWithNoHostIsAccepted(t *testing.T) {
	p := mustResolveDefaults(t)
	if err := p.Graft(newFakeEnv(), freshMountGraft(KindProc)); err != nil {
		t.Fatalf("control: the fresh-mount fixture was refused with no Host set, so every "+
			"refusal above may be refusing for a reason that has nothing to do with Host: %v", err)
	}
}

// freshMountGraft is the fixture for a mount the stage MAKES: /proc as the
// engine's own procfs. G1 admits exactly this (Guest, Kind) pair and nothing
// adjacent — see TestG1AdmitsExactlyProcAsKindProc.
func freshMountGraft(kind Kind) Graft {
	guest := "/proc"
	if kind == KindCgroup2 {
		guest = "/sys/fs/cgroup"
	}
	return Graft{
		Mount: Mount{Guest: guest, Kind: kind, Access: AccessRW, From: []string{"(snug)"}},
		Why: "a hostile process inside the sandbox that reaches code execution in the ENGINE can " +
			"read this mount, which describes the engine's own namespace and nothing of the host's",
	}
}

// TestG1AdmitsExactlyProcAsKindProc pins the one hard-coded hole in G1.
//
// /proc is in snugsOwn because a bind of the host's would hand the sandbox the
// host's process table. The engine's view legitimately REPLACES it with a fresh
// procfs bound to the engine's own pid namespace (C0, merged in 75eea68), so G1
// admits that one (Guest, Kind) pair — and the admission is an exact match on
// both, never a predicate over the graft's other fields.
//
// THE MUTATION THIS EXISTS FOR: rewrite the admission as `!g.Authored`. Every
// graft is Authored by construction, so that spelling makes G1 a permanent
// no-op — the exact trap validate.go's own comment warns about and that issue
// #55's TestGraftCoveringStagedBinDirIsRefused had to be strengthened to catch
// (its /run/snug/bin case first passed for the wrong reason, refused by G3).
// If this test survives that mutation, it is not testing G1.
func TestG1AdmitsExactlyProcAsKindProc(t *testing.T) {
	for _, tc := range []struct {
		name    string
		guest   string
		kind    Kind
		refused bool
	}{
		{"the admission itself", "/proc", KindProc, false},
		// A clone of a host subtree onto /proc is what snugsOwn is FOR. The
		// Kind is the whole difference, so this row is what proves the
		// admission keys on it.
		{"a host clone at the same path", "/proc", KindGraft, true},
		// Not an ancestor test and not a prefix test: exactly /proc.
		{"one level deeper", "/proc/sys", KindProc, true},
		{"snug's other own path", "/dev", KindProc, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolveDefaults(t)
			g := freshMountGraft(KindProc)
			g.Guest, g.Kind = tc.guest, tc.kind
			if tc.kind == KindGraft {
				// A KindGraft needs a source, and it must be one the sandbox
				// can see, or G4 refuses it before G1 is ever consulted — which
				// would make this row pass for the wrong reason.
				g.Host = p.Mounts[p.Target].Host
			}
			err := p.Graft(newFakeEnv(), g)
			if tc.refused && err == nil {
				t.Fatalf("(%s, %v) was ACCEPTED; G1's admission is wider than the one pair it is "+
					"documented to be", tc.guest, tc.kind)
			}
			if !tc.refused && err != nil {
				t.Fatalf("(%s, %v) was REFUSED, so the engine cannot mount the procfs its derived "+
					"view needs: %v", tc.guest, tc.kind, err)
			}
		})
	}
}

// TestEngineMountpointsTrackTheArgvThatCreatesThem asserts the coupling between
// G3's fourth disjunct and BwrapFlags's --dir emission.
//
// A graft's destination must already exist inside the sandbox: the derived root
// is read-only, so move_mount onto a path that is not there fails EROFS —
// measured for /etc/containers and /var/tmp in ENGINE-NETNS.md §5.1. /sys is
// granted by nothing, so bwrap has to pre-create /sys, /sys/fs and
// /sys/fs/cgroup, and it only does so when this run selects a container engine.
//
// Both sides are therefore written against the SAME p.Podman != PodmanOff
// boolean, and this test is why that is not merely tidy. If they diverged, one
// of exactly two things happens, and neither announces itself:
//
//   - G3 accepts a destination the argv never creates, so the policy layer
//     approves a graft that dies at move_mount inside the stage; or
//   - G3 refuses a destination the argv DID create, so a legitimate Tier C
//     graft is rejected for a reason nobody wrote down.
func TestEngineMountpointsTrackTheArgvThatCreatesThem(t *testing.T) {
	withEngine := mustResolve(t, append(slices.Clone(testDefaults), "@podman-socket")...)
	if withEngine.Podman == PodmanOff {
		t.Fatal("fixture: @podman-socket resolved to PodmanOff, so this test compares two " +
			"identical policies and cannot fail")
	}
	withoutEngine := mustResolveDefaults(t)
	if withoutEngine.Podman != PodmanOff {
		t.Fatal("fixture: the default selection already selects a container engine")
	}

	for _, mp := range EngineMountpoints {
		t.Run(mp, func(t *testing.T) {
			// A FRESH policy per subtest. EngineMountpoints are nested
			// (/sys contains /sys/fs contains /sys/fs/cgroup), so installing
			// them into one shared policy makes G2 refuse the second and third
			// for containment — a correct refusal, and one that would be read
			// here as G3 failing.
			withEngine := mustResolve(t, append(slices.Clone(testDefaults), "@podman-socket")...)
			withoutEngine := mustResolveDefaults(t)

			// The policy half.
			g := freshMountGraft(KindCgroup2)
			g.Guest = mp
			if err := withEngine.Graft(newFakeEnv(), g); err != nil {
				t.Fatalf("with a container engine, a graft at %s was refused, but BwrapFlags "+
					"creates that directory: %v", mp, err)
			}
			g2 := freshMountGraft(KindCgroup2)
			g2.Guest = mp
			if err := withoutEngine.Graft(newFakeEnv(), g2); err == nil {
				t.Fatalf("with NO container engine, a graft at %s was accepted — but nothing in "+
					"that policy creates the directory and the sandbox root is read-only, so the "+
					"stage's move_mount would fail EROFS at runtime (ENGINE-NETNS.md §5.1)", mp)
			}

			// The argv half, which is what makes the policy half true.
			if !argvCreatesDir(withEngine, mp) {
				t.Errorf("BwrapFlags does not create %s under a container profile, so G3's "+
					"acceptance above is a promise the argv does not keep", mp)
			}
			if argvCreatesDir(withoutEngine, mp) {
				t.Errorf("BwrapFlags creates %s with no container profile selected, so the --dir "+
					"emission is not gated and every offline sandbox carries a directory it has "+
					"no use for", mp)
			}
		})
	}
}

// argvCreatesDir reports whether the bwrap argv pre-creates guest with --dir.
//
// Matched as an adjacent (--dir, path) PAIR rather than by searching for the
// path anywhere in the argv: a bare Contains would also match the path as the
// operand of some other flag, which is how a sweep passes for the wrong reason.
func argvCreatesDir(p *Policy, guest string) bool {
	flags := p.BwrapFlags(1000, 1000, func(string) int { return -1 })
	for i := 0; i+1 < len(flags); i++ {
		if flags[i] == "--dir" && flags[i+1] == guest {
			return true
		}
	}
	return false
}

// TestKindCgroup2NeverReachesThePayload is KindGraft's rule applied to the kind
// that arrived beside it.
//
// The payload's mount namespace must never receive an engine-view mount, and
// there are two independent guards: Validate refuses the Kind in p.Mounts, and
// BwrapFlags has no case that can emit it (its default arm panics, added by
// issue #55 precisely because a Kind with no case is silently dropped from the
// argv — the --seccomp-after-`--` shape).
//
// KindGraft has had both since #55. This asserts KindCgroup2 does too, because
// "we added a Kind and gave it one of the two guards" is exactly what this file
// is about.
func TestKindCgroup2NeverReachesThePayload(t *testing.T) {
	p := mustResolveDefaults(t)
	p.Mounts["/sys/fs/cgroup"] = Mount{
		Guest: "/sys/fs/cgroup", Kind: KindCgroup2, Access: AccessRW,
		From: []string{"(snug)"}, Authored: true,
	}
	err := p.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("a KindCgroup2 mount in p.Mounts — the PAYLOAD's mount set — was accepted by " +
			"Validate. It is an engine-view mount: the payload must never receive one, and " +
			"BwrapFlags's default arm would panic on it, so this is the check that turns a " +
			"crash into a refusal that names the fix")
	}
	if !strings.Contains(err.Error(), "p.Mounts") {
		t.Errorf("refusal does not name p.Mounts, so a reader cannot tell which map is "+
			"wrong: %v", err)
	}
}

// TestKindCgroup2InMountsIsTheOnlyThingThatRefusesIt is the positive control
// for the test above: the same policy with no such mount must validate, or the
// refusal proves nothing about the Kind.
func TestKindCgroup2InMountsIsTheOnlyThingThatRefusesIt(t *testing.T) {
	p := mustResolveDefaults(t)
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("control: the default policy does not validate, so the refusal above cannot be "+
			"attributed to the KindCgroup2 mount: %v", err)
	}
}

// ── refusals.txt fixtures (issue #125, C1) ───────────────────────────────────
//
// These three are TestGoldenRefusals rows as well as tests. refusals.txt is the
// review artifact for a change to the security boundary, and the wording of a
// refusal is the half a human actually meets — a rule whose message does not
// name the fix costs an hour in an odd environment.

// refusalGraftKindNotInTheTable: a Kind the derived view does not build at all.
// KindBind is the one a caller reaches for by habit, because every other mount
// in the policy is one.
func refusalGraftKindNotInTheTable(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "kind-probe")
	g.Kind = KindBind
	return p.Graft(newFakeEnv(), g)
}

// refusalGraftFreshMountCarriesAHost: the field that would otherwise be
// silently ignored, and then rendered on the ENGINE VIEW block for a mount that
// never reads it.
func refusalGraftFreshMountCarriesAHost(t testing.TB) error {
	p := resolveDefaults(t)
	g := freshMountGraft(KindProc)
	g.Host = "/home/u/.ssh"
	return p.Graft(newFakeEnv(), g)
}

// refusalGraftKindProcAtTheWrongPath: G1's admission is an exact (Guest, Kind)
// pair. A fresh procfs anywhere but /proc is a caller bug, and the refusal has
// to say which of the two fields is wrong.
func refusalGraftKindProcAtTheWrongPath(t testing.TB) error {
	p := resolveDefaults(t)
	g := freshMountGraft(KindProc)
	g.Guest = "/dev"
	return p.Graft(newFakeEnv(), g)
}
