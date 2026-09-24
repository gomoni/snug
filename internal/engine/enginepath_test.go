package engine

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// noHostLinks is the package-private stub the spec for issue #604 asks for:
// Lstat always fs.ErrNotExist, never an exported no-op reader a production
// call site could reach for real. Every fixture in this file builds its mounts
// by hand with no host symlink under a bind to find, so this is the same
// not-exist arm (walkLanded, judged by the bind) these tests asserted before
// host links were followed at all.
type noHostLinks struct{}

func (noHostLinks) Lstat(p string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (noHostLinks) Readlink(p string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}

// hostLinkStub is noHostLinks plus the one host name each case below plants:
// a symlink (Lstat reports ModeSymlink, Readlink returns the text) or a read
// failure other than not-exist. Everything else answers exactly like
// noHostLinks — fs.ErrNotExist — so a case only has to say what is DIFFERENT
// about the one path it is testing.
type hostLinkStub struct {
	symlinks map[string]string
	errs     map[string]error
}

func (h hostLinkStub) Lstat(p string) (fs.FileInfo, error) {
	if err, ok := h.errs[p]; ok {
		return nil, err
	}
	if _, ok := h.symlinks[p]; ok {
		return hostLinkInfo{}, nil
	}
	return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (h hostLinkStub) Readlink(p string) (string, error) {
	if t, ok := h.symlinks[p]; ok {
		return t, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}

type hostLinkInfo struct{}

func (hostLinkInfo) Name() string       { return "" }
func (hostLinkInfo) Size() int64        { return 0 }
func (hostLinkInfo) Mode() fs.FileMode  { return fs.ModeSymlink }
func (hostLinkInfo) ModTime() time.Time { return time.Time{} }
func (hostLinkInfo) IsDir() bool        { return false }
func (hostLinkInfo) Sys() any           { return nil }

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
		if !view.GrantsGuestPath(noHostLinks{}, elem) {
			t.Fatalf("fixture: nothing in this view covers %s, so IsShadowSlot would answer false "+
				"for it whatever the access — repair the fixture rather than the assertion", elem)
		}
	}

	if elem, verdict := firstShadowSlot(view, PinnedPATH, noHostLinks{}); verdict != policy.NotSlot {
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
	elem, verdict := firstShadowSlot(view, PinnedPATH, noHostLinks{})
	if verdict == policy.NotSlot {
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
		if _, verdict := firstShadowSlot(view, hostPATH, noHostLinks{}); verdict == policy.NotSlot {
			t.Errorf("the sweep found no shadow slot in %q, which is the shape of the PATH the "+
				"host really has — every element under {home} is the payload's own writable "+
				"tmpfs in the engine's derived view", hostPATH)
		}
	}

	// And the other direction, so the loop above is not passing because the
	// sweep says "slot" about everything: snug's own value, same view, clean.
	if elem, verdict := firstShadowSlot(view, PinnedPATH, noHostLinks{}); verdict != policy.NotSlot {
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
	err := checkEnginePATH(p, noHostLinks{})
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
	if _, err := e.Spec(p, "/usr/bin/podman", []string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t)); err == nil {
		t.Fatal("Spec accepted a policy with no grafts")
	} else if !strings.Contains(err.Error(), "cannot see") {
		t.Errorf("Spec refused a graftless policy for some reason other than an unmappable host "+
			"path; if the PATH check is now what refuses it, say so in both tests:\n%v", err)
	}
}

// engineGraft is the graft every fixture below needs so pol.EngineView() has
// something to derive — the identical EngineStoreGuest bind
// TestEveryElementOfTheEnginesPATHIsUnwritableInItsOwnView uses.
func engineGraft() map[string]policy.Graft {
	return map[string]policy.Graft{
		policy.EngineStoreGuest: {
			Mount: policy.Mount{Guest: policy.EngineStoreGuest, Host: "/run/user/1000/snug/store",
				Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"}},
			Why: "fixture",
		},
	}
}

// TestEnginePATHRefusesAHostLinkOutOfUsr is issue #604's fix reaching the
// ENGINE's own PATH check, not only the --dry-run screen: a HOST symlink
// nobody's profile wrote, sitting inside @sys's read-only /usr bind, is
// still followed by the kernel in the engine's namespace — checkEnginePATH
// must refuse it the same way it refuses a writable graft, and must refuse
// with the Unresolved wording (not "WRITABLE") when the reason is a host
// read it could not complete rather than ground it could see was writable.
func TestEnginePATHRefusesAHostLinkOutOfUsr(t *testing.T) {
	mounts := func() map[string]policy.Mount {
		m := roUsr()
		// Writable ground for the "writable ground" subtest's symlink to land
		// on — @home's shape, not /usr's.
		m["/tmp"] = policy.Mount{Guest: "/tmp", Kind: policy.KindTmpfs,
			Access: policy.AccessRW, From: []string{"(snug)"}}
		return m
	}

	t.Run("writable ground", func(t *testing.T) {
		p := &policy.Policy{Mounts: mounts(), Grafts: engineGraft()}
		host := hostLinkStub{symlinks: map[string]string{"/usr/sbin": "/tmp/x"}}

		err := checkEnginePATH(p, host)
		if err == nil {
			t.Fatal("a host symlink /usr/sbin -> /tmp/x (a writable tmpfs) was accepted; the " +
				"kernel follows it inside the engine's own namespace exactly as it follows " +
				"one of snug's own KindSymlink grants")
		}
		if !strings.Contains(err.Error(), "/usr/sbin") {
			t.Errorf("refusal does not name /usr/sbin: %v", err)
		}
		if !strings.Contains(err.Error(), "WRITABLE") {
			t.Errorf("refusal does not say WRITABLE for ground the walk actually confirmed is "+
				"writable: %v", err)
		}
	})

	t.Run("unresolved", func(t *testing.T) {
		p := &policy.Policy{Mounts: mounts(), Grafts: engineGraft()}
		host := hostLinkStub{errs: map[string]error{
			"/usr/sbin": &fs.PathError{Op: "lstat", Path: "/usr/sbin", Err: fs.ErrPermission},
		}}

		err := checkEnginePATH(p, host)
		if err == nil {
			t.Fatal("a host read that failed on the way to /usr/sbin was accepted; snug cannot " +
				"vouch for what the engine's PATH resolves to there")
		}
		if !strings.Contains(err.Error(), "/usr/sbin") {
			t.Errorf("refusal does not name /usr/sbin: %v", err)
		}
		if !strings.Contains(err.Error(), "cannot be resolved") {
			t.Errorf("refusal does not carry the Unresolved wording (\"cannot be resolved\"): %v", err)
		}
		if strings.Contains(err.Error(), "WRITABLE") {
			t.Errorf("refusal claims WRITABLE for a path the walk never actually confirmed "+
				"anything about: %v", err)
		}
	})
}

// TestEnginePATHRefusesAReadOnlyGraftAliasedByTheWritableTarget is issue
// #604's follow-up (finding 4) reaching the ENGINE's own PATH check: a
// READ-ONLY graft landing on /usr/bin — no symlink anywhere on the way — is
// still WRITABLE in the engine's derived view, because its host tree sits
// inside the SANDBOX's own writable target bind (@target-rw's shape). The
// payload writes through the target and the content changes at /usr/bin too,
// whatever this graft's own Access claims.
func TestEnginePATHRefusesAReadOnlyGraftAliasedByTheWritableTarget(t *testing.T) {
	mounts := roUsr()
	// The SANDBOX's own writable bind of the target, @target-rw's shape.
	mounts["/home/u/proj/sub"] = policy.Mount{Guest: "/home/u/proj/sub", Host: "/home/u/proj/sub",
		Kind: policy.KindBind, Access: policy.AccessRW, From: []string{"@target-rw"}}

	grafts := engineGraft()
	// A READ-ONLY graft over /usr/bin, one of the engine's own four PATH
	// elements, whose HOST tree sits inside the writable target's.
	grafts["/usr/bin"] = policy.Graft{
		Mount: policy.Mount{Guest: "/usr/bin", Host: "/home/u/proj/sub/realbin",
			Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"fixture"}},
		Why: "fixture",
	}

	p := &policy.Policy{Mounts: mounts, Grafts: grafts}
	err := checkEnginePATH(p, noHostLinks{})
	if err == nil {
		t.Fatal("a read-only graft over /usr/bin whose host tree sits inside the writable " +
			"target's was accepted; the payload writes through the target bind and the " +
			"content changes here too, whatever this graft's own Access says")
	}
	if !strings.Contains(err.Error(), "/usr/bin") {
		t.Errorf("refusal does not name /usr/bin: %v", err)
	}
	if !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("refusal does not say WRITABLE for a graft aliased by a writable grant: %v", err)
	}
}
