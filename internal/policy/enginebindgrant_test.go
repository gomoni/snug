package policy

import (
	"strings"
	"testing"
)

// The `engine_binds` grant, issue #376. Every test here is over the RESOLVER
// and over G1-G5 — no filesystem beyond the fake host, no privileges — which is
// the property that lets the security-critical half of this feature be checked
// in CI (CLAUDE.md, "keep internal/policy pure").
//
// WHAT IS NOT TESTED HERE, and it is not an omission: an untrusted-source
// refusal. policy.Profile.Trusted is set by internal/profile and consulted by
// NOTHING in the resolver — internal/cli/showcoverage_test.go's own exempt map
// records that fact as the reason `profile show` does not render it — so
// `engine_binds` inherits exactly the trust boundary every other key has, which
// is the profile STORE (invariant 3, Load's three layers) rather than a per-key
// flag. A test asserting a refusal that no key in the language performs would
// be asserting a mechanism that does not exist.

func mustResolveEngineBinds(t *testing.T, sel ...ProfileName) *Policy {
	t.Helper()
	p := mustResolve(t, sel...)
	if len(p.EngineBinds) == 0 {
		t.Fatalf("Resolve(%v) produced no engine binds, so this test measures nothing", sel)
	}
	return p
}

// TestEngineBindsExpandVariablesAndUnion is the parse-and-fold half: a
// `{variable}` reaches expandVars exactly as an `ro`/`rw` entry's does, and two
// profiles' lists UNION into one sorted set rather than one shadowing the other.
func TestEngineBindsExpandVariablesAndUnion(t *testing.T) {
	p := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds", "engine-binds-two")

	// testCtx()'s target is /home/u/proj/sub, so {target}/data and
	// {target}/build must have become absolute host paths under it. An
	// unexpanded brace reaching p.EngineBinds is the failure this asserts
	// against, and it would be invisible in a golden: the argv would carry a
	// literal `{target}` and bwrap would happily --dir it.
	want := []string{"/home/u/proj/sub/build", "/home/u/proj/sub/data"}
	if len(p.EngineBinds) != len(want) {
		t.Fatalf("EngineBinds = %+v, want %d entries", p.EngineBinds, len(want))
	}
	for i, w := range want {
		if p.EngineBinds[i].Host != w {
			t.Errorf("EngineBinds[%d].Host = %q, want %q (sorted by Host)", i, p.EngineBinds[i].Host, w)
		}
	}
	if got := p.EngineBinds[1].Guest; got != EngineBindsDir+"/data" {
		t.Errorf("guest path = %q, want %q", got, EngineBindsDir+"/data")
	}
	if got := p.EngineBinds[1].From; len(got) != 1 || got[0] != "engine-binds" {
		t.Errorf("From = %v, want [engine-binds] — a refusal and the graft's Why both name it", got)
	}
}

// TestEngineBindsUnionIsOneEntryPerPath: two profiles naming ONE path resolve to
// one bind carrying both names, not two binds asking for one destination.
// Without this, the second would be refused by Policy.Graft for a duplicate
// Guest and the user would read "already grafted" about a profile they never
// wrote.
func TestEngineBindsUnionIsOneEntryPerPath(t *testing.T) {
	reg := testRegistry()
	reg["binds-a"] = &Profile{Name: "binds-a", Podman: "socket", EngineBinds: []string{"{target}/data"}}
	reg["binds-b"] = &Profile{Name: "binds-b", Podman: "socket", EngineBinds: []string{"{target}/data"}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binds-a", "binds-b"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(p.EngineBinds) != 1 {
		t.Fatalf("EngineBinds = %+v, want exactly one entry for one path", p.EngineBinds)
	}
	if got := strings.Join(p.EngineBinds[0].From, "+"); got != "binds-a+binds-b" {
		t.Errorf("From = %q, want both declaring profiles, sorted", got)
	}
}

// TestEngineBindAccessIsTheSandboxsOwn pins the one thing a profile does NOT
// choose. `engine_binds` adds a route, never a permission: the graft's access is
// Policy.HostPathVisible's answer for that host path, which is also the only
// access G4 would admit.
func TestEngineBindAccessIsTheSandboxsOwn(t *testing.T) {
	rw := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds")
	if rw.EngineBinds[0].Access != AccessRW {
		t.Errorf("a path inside @cwd-rw's rw bind of {target} resolved to %s, want rw",
			rw.EngineBinds[0].Access)
	}

	ro := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds-ro")
	if ro.EngineBinds[0].Access != AccessRO {
		t.Errorf("a path granted ro resolved to %s, want ro — a declared bind may not be wider "+
			"than the sandbox's own grant", ro.EngineBinds[0].Access)
	}
}

// TestEngineBindsRefusedWhenTheSandboxCannotSeeThePath is G4 asked early, so the
// refusal can name the profile that wrote the line. Reaching graft time instead
// would produce checkGraft's message, which knows only "(snug)".
func TestEngineBindsRefusedWhenTheSandboxCannotSeeThePath(t *testing.T) {
	_, err := Resolve(testRegistry(),
		[]ProfileName{"@sys", "@cwd-rw", "engine-binds-ungranted"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a declared bind of a path no grant exposes was accepted; the engine's view is " +
			"DERIVED from the sandbox's, so there would be nothing to clone")
	}
	for _, want := range []string{"engine-binds-ungranted", "/home/u/ungranted", "ro = ["} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not contain %q:\n%v", want, err)
		}
	}
}

// TestEngineBindsRefusesTwoEntriesSharingABaseName. The guest name is the base
// name, which is what makes it readable rather than a digest; two entries
// claiming one destination is therefore possible and must be a symmetric
// refusal naming both, never a silent winner.
func TestEngineBindsRefusesTwoEntriesSharingABaseName(t *testing.T) {
	_, err := Resolve(testRegistry(),
		[]ProfileName{"@sys", "@cwd-rw", "engine-binds-two", "engine-binds-collide"},
		testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("two declared binds with the base name \"build\" were accepted; they ask for one " +
			"destination and snug would have picked a winner between two grants nobody compared")
	}
	for _, want := range []string{
		"/home/u/proj/sub/build", "/home/u/proj/sub/nest/build",
		"engine-binds-two", "engine-binds-collide",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}
}

// TestEngineBindsRefusedWithNoContainerEngine. A declaration on a run with no
// engine grafts nothing, forwards nothing and appears nowhere — the silent
// no-op invariant 5 exists to prevent — so it refuses and names the fix.
func TestEngineBindsRefusedWithNoContainerEngine(t *testing.T) {
	_, err := Resolve(testRegistry(),
		[]ProfileName{"@sys", "@cwd-rw", "engine-binds-no-engine"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("engine_binds resolved with p.Podman == PodmanOff; there is no engine to bind " +
			"into, so the declaration would have done nothing at all")
	}
	for _, want := range []string{"engine-binds-no-engine", "podman = \"socket\""} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not contain %q:\n%v", want, err)
		}
	}
}

// TestEngineBindsRefusesBadEntries covers the three spellings that have no
// resolution: a relative path, "/" itself, and a path that is not there.
//
// The relative case is the ticket's own example spelled in the wrong place —
// `-v ./data:/data` is the REQUEST, and a profile writing `./data` has named
// nothing to resolve against. Absence is a refusal rather than a skip because
// checkGraft forbids Optional on a graft: a graft that silently did not happen
// leaves the engine confined differently from what --dry-run described.
func TestEngineBindsRefusesBadEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		want  string
	}{
		{"relative", "./data", "not an absolute path"},
		{"root", "/", "may not declare"},
		{"absent", "/home/u/proj/sub/nope", "does not exist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := testRegistry()
			reg["bad-binds"] = &Profile{Name: "bad-binds", Podman: "socket",
				EngineBinds: []string{tc.entry}}
			_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "bad-binds"},
				testCtx(), newFakeEnv())
			if err == nil {
				t.Fatalf("engine_binds = [%q] was accepted", tc.entry)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not contain %q:\n%v", tc.want, err)
			}
		})
	}
}

// TestEngineBindsResolveASymlinkTheWay284Requires is the anchored-source rule's
// own reasoning applied to the declaration, and it is asserted in both
// directions because only one of them is a refusal.
//
// A link INSIDE the target that points OUT of it is refused: the target is
// payload-writable and persists across runs, so an earlier run's payload could
// have planted it, and following it would let the sandboxed material choose
// what gets grafted. A link the host user planted outside the target is
// FOLLOWED and the resolved path is what is stored — which is what makes the
// string in p.EngineBinds the same string the proxy compares a client's own
// resolved source against, and the same string __inengine's
// openat2(RESOLVE_NO_SYMLINKS) re-walks. Storing the literal would leave that
// openat2 failing ELOOP on an ordinary host layout, or — worse — matching a
// client source it had not judged.
func TestEngineBindsResolveASymlinkTheWay284Requires(t *testing.T) {
	t.Run("redirect out of the target is refused", func(t *testing.T) {
		env := newFakeEnv()
		env.dirs["/home/u/proj/sub/link"] = true
		env.links["/home/u/proj/sub/link"] = "/home/u/secrets"
		reg := testRegistry()
		reg["linky"] = &Profile{Name: "linky", Podman: "socket",
			EngineBinds: []string{"{target}/link"}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "linky"}, testCtx(), env)
		if err == nil {
			t.Fatal("a declared bind inside the target that resolves OUT of it was accepted — a " +
				"previous run's payload can plant that link, and the target persists")
		}
		if !strings.Contains(err.Error(), "/home/u/secrets") {
			t.Errorf("refusal does not name what the link resolves to:\n%v", err)
		}
	})

	t.Run("a link outside the target is followed and stored resolved", func(t *testing.T) {
		env := newFakeEnv()
		env.dirs["/opt/link"] = true
		env.links["/opt/link"] = "/opt/tools/bin"
		reg := testRegistry()
		reg["linky-out"] = &Profile{Name: "linky-out", Podman: "socket",
			RO:          []string{"/opt/tools/bin"},
			EngineBinds: []string{"/opt/link"}}
		p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "linky-out"}, testCtx(), env)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(p.EngineBinds) != 1 || p.EngineBinds[0].Host != "/opt/tools/bin" {
			t.Fatalf("EngineBinds = %+v, want the RESOLVED host path /opt/tools/bin — the literal "+
				"would not match the client source the proxy compares, and openat2's "+
				"RESOLVE_NO_SYMLINKS would refuse it in the stage", p.EngineBinds)
		}
		// And the guest name comes from the resolved path, not the link's own
		// name: the destination has to be derivable from the string the graft
		// actually opens.
		if got := p.EngineBinds[0].Guest; got != EngineBindsDir+"/bin" {
			t.Errorf("guest = %q, want %q", got, EngineBindsDir+"/bin")
		}
	})
}

// TestDeclaredEngineBindPassesG1toG5 installs the graft the way Tier C does and
// requires every graft rule to accept it. It is the coupling between the
// resolver's half of #376 and the graft judgement's half: either could be
// changed without the other and this is what notices.
func TestDeclaredEngineBindPassesG1toG5(t *testing.T) {
	p := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds")
	b := p.EngineBinds[0]

	// G3 FIRST, on its own, because it is the disjunct this feature had to
	// extend and a whole-graft assertion would report the wrong rule as broken
	// if it regressed (the same conflation TestEngineMountpointsTrackTheArgv\
	// ThatCreatesThem's own comment records).
	if !existsInSandbox(p, b.Guest) {
		t.Fatalf("G3 says %s does not exist in the sandbox's view, but BwrapFlags --dirs it — "+
			"move_mount onto a path that is not there fails EROFS on the read-only root",
			b.Guest)
	}

	if err := p.Graft(newFakeEnv(), Graft{
		Mount: Mount{Guest: b.Guest, Host: b.Host, Kind: KindGraft, Access: b.Access,
			From: []string{"(snug)"}},
		Why: "bind this host tree into a container of its own choosing",
	}); err != nil {
		t.Fatalf("a declared engine bind was REFUSED by G1-G5, so the grant cannot be "+
			"installed at all: %v", err)
	}
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("Validate refused a policy carrying a declared engine bind's graft: %v", err)
	}
}

// TestEngineBindDestinationIsNotPreCreatedWithoutAnEngine is G3's fourth
// disjunct's other half: BwrapFlags emits the directory only when p.Podman !=
// PodmanOff, so G3 must refuse the destination on a run that creates nothing.
//
// It cannot be reached through a profile — Resolve refuses `engine_binds`
// without an engine — so the policy is built by hand, which is exactly the
// hand-built-Policy case checkGraft is the backstop for.
func TestEngineBindDestinationIsNotPreCreatedWithoutAnEngine(t *testing.T) {
	p := mustResolveDefaults(t)
	if p.Podman != PodmanOff {
		t.Fatal("fixture: the default selection already starts an engine")
	}
	p.EngineBinds = []EngineBind{{
		Host: "/home/u/proj/sub/data", Guest: EngineBindsDir + "/data", Access: AccessRW,
	}}
	if existsInSandbox(p, EngineBindsDir+"/data") {
		t.Fatal("with no container engine, G3 says the declared bind's destination exists — but " +
			"BwrapFlags emits no --dir for it, so nothing creates that directory and the graft " +
			"would die at move_mount inside the stage")
	}
}

// TestEngineBindForwardedIsExactAndNeverAPrefix is the clause the whole grant's
// safety rests on, and it is a NEGATIVE test: what must not be forwarded.
//
// Graft-root plus a request-supplied tail reopens #284 through the graft. crun
// re-resolves the whole forwarded string at container START, in the engine's
// namespace, so a relative symlink planted inside the grafted directory is
// followed there — open_tree(OPEN_TREE_CLONE) pins the inode at the graft's
// ROOT and says nothing about any name beneath it. Declaring the subdirectory
// is the answer; extending the match is not.
func TestEngineBindForwardedIsExactAndNeverAPrefix(t *testing.T) {
	p := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds")

	if guest, ok := p.EngineBindForwarded("/home/u/proj/sub/data", true); !ok ||
		guest != EngineBindsDir+"/data" {
		t.Fatalf("EngineBindForwarded(declared) = (%q, %v), want (%q, true)",
			guest, ok, EngineBindsDir+"/data")
	}

	for _, source := range []string{
		"/home/u/proj/sub/data/sub",  // a tail the request supplied
		"/home/u/proj/sub/data/../x", // the same, spelled to survive a naive prefix test
		"/home/u/proj/sub",           // an ANCESTOR of the declaration
		"/home/u/proj/sub/database",  // a sibling sharing a string prefix
	} {
		if guest, ok := p.EngineBindForwarded(source, true); ok {
			t.Errorf("EngineBindForwarded(%q) = (%q, true); a declared bind is forwarded at its "+
				"ROOT and never with a tail — the engine re-resolves the whole string at "+
				"container start (issue #284)", source, guest)
		}
	}

	// A read-only declaration does not satisfy a writable request. Unreachable
	// through checkOne today, because a declaration's Access IS
	// HostPathVisible's answer and checkOne asks that first — asserted anyway,
	// because "unreachable through today's one caller" is not a property of
	// this function.
	ro := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds-ro")
	if guest, ok := ro.EngineBindForwarded("/opt/tools/bin", true); ok {
		t.Errorf("a read-only declaration satisfied a writable request, forwarding %q", guest)
	}
	if _, ok := ro.EngineBindForwarded("/opt/tools/bin", false); !ok {
		t.Error("a read-only declaration did not satisfy a read-only request")
	}
}

// TestEngineBindDestinationsAreInSnugsOwnNamespace pins the two structural
// properties of the destination that keep it from being a shadow slot or a
// collision with snug's own wiring: it is under EngineDir (so G1b admits the
// graft at all) and under EngineBindsDir specifically (so a profile choosing to
// declare a directory called `store` cannot land on EngineStoreGuest).
func TestEngineBindDestinationsAreInSnugsOwnNamespace(t *testing.T) {
	if !strings.HasPrefix(EngineBindsDir+"/", EngineDir+"/") {
		t.Fatalf("EngineBindsDir %q is not inside EngineDir %q, so G1b refuses every graft "+
			"under it", EngineBindsDir, EngineDir)
	}
	for _, own := range []string{
		EngineStoreGuest, EngineRunrootGuest, EngineSockGuest, EngineConfGuest, EngineToolchainGuest,
	} {
		if EngineBindGuest("/x/"+strings.TrimPrefix(own, EngineDir+"/")) == own {
			t.Errorf("a declared bind whose base name is %q lands on snug's own %s",
				strings.TrimPrefix(own, EngineDir+"/"), own)
		}
	}
}

// TestValidateRefusesAHandBuiltEngineBindWithAForeignGuest is the backstop, and
// it is a hand-built Policy on purpose: Resolve cannot produce this row, and
// that is exactly why nothing else would catch it.
//
// The proxy forwards EngineBind.Guest verbatim, so a row pointing at one of
// snug's own engine destinations would hand a container the engine's image
// store under the name of a declared bind — the #251 shape, entered through the
// grant rather than through a symlink.
func TestValidateRefusesAHandBuiltEngineBindWithAForeignGuest(t *testing.T) {
	base := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds")
	if err := base.Validate(newFakeEnv()); err != nil {
		t.Fatalf("control: the resolved policy does not validate, so the refusals below are "+
			"unattributable: %v", err)
	}

	for _, tc := range []struct {
		name string
		bind EngineBind
		want string
	}{
		{
			name: "guest is one of snug's own engine paths",
			bind: EngineBind{Host: "/home/u/proj/sub/data", Guest: EngineStoreGuest, Access: AccessRW},
			want: "the only destination snug derives",
		},
		{
			name: "guest is the staging directory",
			bind: EngineBind{Host: "/home/u/proj/sub/data", Guest: StagedBinDir, Access: AccessRW},
			want: "the only destination snug derives",
		},
		{
			name: "access is neither ro nor rw",
			bind: EngineBind{Host: "/home/u/proj/sub/data", Guest: EngineBindsDir + "/data"},
			want: "describes nothing the stage can build",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolveEngineBinds(t, "@sys", "@cwd-rw", "engine-binds")
			p.EngineBinds = []EngineBind{tc.bind}
			err := p.Validate(newFakeEnv())
			if err == nil {
				t.Fatalf("Validate accepted a declared engine bind at guest %s", tc.bind.Guest)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not contain %q:\n%v", tc.want, err)
			}
		})
	}
}
