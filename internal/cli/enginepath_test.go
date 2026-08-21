package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestTheEnginesPATHIsUnwritableUnderTheREALBuiltins is issue #125's C3 PATH
// assertion at full fidelity — the same question internal/engine asks of a
// hand-built fixture, asked of the profile set snug actually ships.
//
// The two are not redundant, and the difference is the whole reason this file
// exists in internal/cli rather than beside the value. internal/engine cannot
// build this policy: the engine's OWN mounts (/proc, /sys/fs/cgroup, /var/tmp,
// /run) are recorded by installEngineViewGrafts, which lives here, and the four
// host-tree grafts by Engine.GraftInto — so only here is the engine view the
// COMPLETE one a run really has. A builtin profile that started granting a
// writable tree over /usr, or a graft destination that grew to cover one, is
// caught here and nowhere else.
func TestTheEnginesPATHIsUnwritableUnderTheREALBuiltins(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// The DEFAULT selection, not a curated one: @home and @cwd-rw are what put
	// writable tmpfs into a sandbox at all, so a sweep run without them would
	// be run against the one policy that has nothing writable to find.
	sel := append(profile.BuiltinDefaults(), "@podman-socket")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel,
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(sel, p.Target)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.GraftInto(policy.OSEnviron{}, p); err != nil {
		t.Fatal(err)
	}

	view, ok := p.EngineView()
	if !ok {
		t.Fatal("a resolved container policy with both graft sets installed still models no " +
			"engine view")
	}

	// CONTROL A — the fixture has something writable to find. IsShadowSlot
	// answers false for anything it cannot resolve, so a policy whose every
	// mount were read-only would pass the assertion below without the sweep
	// ever having had a decision to make.
	writable := 0
	for _, m := range view.Mounts {
		if m.Access == policy.AccessRW {
			writable++
		}
	}
	if writable == 0 {
		t.Fatal("no mount in the engine's view is writable, so this sweep is vacuous")
	}

	// CONTROL B — every element RESOLVES here. Four elements that nothing
	// grants would all answer "not a slot" for the wrong reason.
	elems := strings.Split(engine.PinnedPATH, ":")
	for _, elem := range elems {
		if !view.GrantsGuestPath(elem) {
			t.Fatalf("nothing in the engine's view covers %s — the assertion below would then be "+
				"true of a path that is not there", elem)
		}
	}

	for _, elem := range elems {
		if view.IsShadowSlot(elem) {
			t.Errorf("PATH element %s is WRITABLE in the engine's view under the profile set snug "+
				"ships. The engine is root-in-U with the full delegated subuid range, so this is "+
				"the payload choosing what it executes (issue #125, C3).", elem)
		}
	}

	// CONTROL C — the sweep still says "slot" about something, on this exact
	// view: the payload's own home is writable, and under a DERIVED view that
	// is the directory the host's real PATH leads with.
	if !view.IsShadowSlot(envGoldenCtx().Home + "/bin") {
		t.Errorf("%s/bin is not reported a shadow slot in a view where @home makes {home} a "+
			"writable tmpfs; the four assertions above then cannot be read as the sweep "+
			"discriminating", envGoldenCtx().Home)
	}
}
