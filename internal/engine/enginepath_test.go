package engine

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// viewOf builds an engine view out of a mount set, through the real
// Policy.EngineView rather than by constructing a policy.View directly — the
// overlay it performs (a graft drops every mount beneath it) is part of what is
// under test, and a hand-built View would skip it.
//
// The graft is what makes EngineView answer at all: it returns ok=false for a
// policy with none, which is a case this file asserts separately.
func viewOf(t *testing.T, mounts map[string]policy.Mount, grafts map[string]policy.Mount) policy.View {
	t.Helper()
	p := &policy.Policy{Mounts: mounts, Grafts: map[string]policy.Graft{}}
	for guest, m := range grafts {
		p.Grafts[guest] = policy.Graft{Mount: m, Why: "fixture"}
	}
	view, ok := p.EngineView()
	if !ok {
		t.Fatal("fixture: EngineView() reported no view; every case here needs one")
	}
	return view
}

func roUsr() map[string]policy.Mount {
	return map[string]policy.Mount{
		"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind,
			Access: policy.AccessRO, From: []string{"@sys"}},
		"/bin":  {Guest: "/bin", Host: "usr/bin", Kind: policy.KindSymlink, From: []string{"@sys"}},
		"/sbin": {Guest: "/sbin", Host: "usr/sbin", Kind: policy.KindSymlink, From: []string{"@sys"}},
	}
}

// TestEveryElementOfTheEnginesPATHIsUnwritableInItsOwnView is issue #125's C3
// assertion for the PATH: not "snug pins the value" — Spec has done that since
// C2-path — but "the value it pins resolves to read-only ground in the
// namespace the engine really resolves it in".
//
// The two are different questions and only the second is about this run's
// policy. A graft landing on /usr, or a profile granting a writable tree there,
// puts a directory the payload can write ahead of crun for a process that is
// root-in-U with the full delegated subuid range — and the pinned literal would
// be completely unchanged.
func TestEveryElementOfTheEnginesPATHIsUnwritableInItsOwnView(t *testing.T) {
	view := viewOf(t, roUsr(), map[string]policy.Mount{
		policy.EngineStoreGuest: {Guest: policy.EngineStoreGuest, Host: "/run/user/1000/snug/store",
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"}},
	})

	// POSITIVE CONTROL on the fixture, not on the sweep: every element must
	// RESOLVE to something in this view. IsShadowSlot answers false for a path
	// that resolves to nothing (its own doc comment: "unresolved is false, and
	// that is truthful rather than optimistic"), so a fixture granting none of
	// these four would pass the assertion below while proving nothing at all.
	for _, elem := range strings.Split(PinnedPATH, ":") {
		if !view.GrantsGuestPath(elem) {
			t.Fatalf("fixture: nothing in this view covers %s, so IsShadowSlot would answer false "+
				"for it whatever the access — repair the fixture rather than the assertion", elem)
		}
	}

	if elem, bad := firstShadowSlot(view, PinnedPATH); bad {
		t.Errorf("PATH element %q is a shadow slot in the engine's own view", elem)
	}
}

// TestTheEnginePATHSweepCatchesAWritableElement is the sweep's own positive
// control, and it is the mutation the assertion above exists to catch: one
// graft, over one PATH element, everything else identical.
func TestTheEnginePATHSweepCatchesAWritableElement(t *testing.T) {
	view := viewOf(t, roUsr(), map[string]policy.Mount{
		"/usr/bin": {Guest: "/usr/bin", Kind: policy.KindTmpfs,
			Access: policy.AccessRW, From: []string{"(snug)"}},
	})
	elem, bad := firstShadowSlot(view, PinnedPATH)
	if !bad {
		t.Fatal("a writable tmpfs grafted over /usr/bin is not reported as a shadow slot; the " +
			"assertion in this file then passes on any policy at all")
	}
	if elem != "/usr/bin" {
		t.Errorf("the sweep names %q; a refusal that names the wrong element sends a reader to "+
			"the wrong grant", elem)
	}
}

// TestTheEnginePATHSweepCatchesTheHostsOwnPATH is the control issue #125 asked
// for by name: feed the sweep the shape of a real host PATH and assert it
// FAILS. Every element below was measured on the development host
// (Spec's own comment records the list), and each is under {home}, which @home
// makes a writable tmpfs — so under a DERIVED view they are the payload's, not
// the host's.
func TestTheEnginePATHSweepCatchesTheHostsOwnPATH(t *testing.T) {
	mounts := roUsr()
	mounts["/home/u"] = policy.Mount{Guest: "/home/u", Kind: policy.KindTmpfs,
		Access: policy.AccessRW, From: []string{"@home"}}
	view := viewOf(t, mounts, map[string]policy.Mount{
		policy.EngineStoreGuest: {Guest: policy.EngineStoreGuest, Host: "/run/user/1000/snug/store",
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"}},
	})

	for _, hostPATH := range []string{
		"/home/u/bin:/usr/bin:/bin",
		"/home/u/.local/bin:/usr/bin",
		"/home/u/.cargo/bin:/home/u/go/bin:/usr/bin",
		// The EMPTY element, which is the current directory and which no view
		// can resolve. A trailing colon and a doubled colon both produce one.
		"/usr/bin:",
		"/usr/bin::/sbin",
	} {
		if _, bad := firstShadowSlot(view, hostPATH); !bad {
			t.Errorf("the sweep found no shadow slot in %q, which is the shape of the PATH the "+
				"host really has — every element under {home} is the payload's own writable "+
				"tmpfs in the engine's derived view", hostPATH)
		}
	}

	// And the other direction, so the loop above is not passing because the
	// sweep says "slot" about everything: snug's own value, same view, clean.
	if elem, bad := firstShadowSlot(view, PinnedPATH); bad {
		t.Errorf("the same sweep reports %q a slot in snug's own PATH; the cases above then "+
			"prove nothing about the difference between the two values", elem)
	}
}

// TestNoEngineViewIsARefusalRatherThanAnEmptySweep pins the branch that would
// otherwise be a silent pass: a Policy with no grafts models no engine view, and
// answering "no shadow slots" about a view nobody modelled is the
// documented-but-not-implemented shape rather than an answer.
//
// It calls checkEnginePATH directly, and the reason is worth recording: this
// branch is NOT reachable through Spec. A graftless policy is refused several
// lines earlier by guestPath, which cannot map the runroot without a graft — so
// the ordering this branch guards against is already enforced upstream, and the
// branch is a backstop for whoever reorders those lines. The assertion below is
// the second half of that fact, so the two are read together.
func TestNoEngineViewIsARefusalRatherThanAnEmptySweep(t *testing.T) {
	p := &policy.Policy{Podman: policy.PodmanSocket, Mounts: roUsr()}
	if _, ok := p.EngineView(); ok {
		t.Fatal("fixture: this policy already has an engine view")
	}
	err := checkEnginePATH(p)
	if err == nil {
		t.Fatal("checkEnginePATH accepted a policy with no engine view: it then reports every " +
			"PATH element clean because there is nothing to resolve them in")
	}
	if !strings.Contains(err.Error(), "GraftInto") {
		t.Errorf("the refusal does not name the call that was skipped, so it reads as a policy "+
			"problem rather than as an ordering one:\n%v", err)
	}
}

// TestSpecRefusesAGraftlessPolicyBeforeItReachesThePATHCheck is the upstream
// half of the fact above, asserted rather than assumed. If this ever stops
// being true, the branch checkEnginePATH keeps becomes live rather than
// defensive — and a reader of either test finds the other.
func TestSpecRefusesAGraftlessPolicyBeforeItReachesThePATHCheck(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Podman: policy.PodmanSocket, Mounts: roUsr()}
	if _, err := e.Spec(p, "/usr/bin/podman", []string{"PATH=/usr/bin"}, false, noSignaturePolicy(t)); err == nil {
		t.Fatal("Spec accepted a policy with no grafts")
	} else if !strings.Contains(err.Error(), "cannot see") {
		t.Errorf("Spec refused a graftless policy for some reason other than an unmappable host "+
			"path; if the PATH check is now what refuses it, say so in both tests:\n%v", err)
	}
}
