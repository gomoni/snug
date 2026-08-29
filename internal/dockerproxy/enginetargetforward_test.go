package dockerproxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// installTargetGraft mirrors internal/cli's installEngineTargetGraft: asks
// EngineTargetGraft for this policy's target-graft shape and records it via
// Policy.Graft, the same call the real Tier C installer makes. Duplicated
// here rather than exported from internal/cli, which this package must not
// import (layering: dockerproxy sits below cli).
func installTargetGraft(t *testing.T, pol *policy.Policy) {
	t.Helper()
	guest, access, ok := pol.EngineTargetGraft()
	if !ok {
		t.Fatalf("fixture: EngineTargetGraft() ok=false for target %s", pol.Target)
	}
	if err := pol.Graft(policy.OSEnviron{}, policy.Graft{
		Mount: policy.Mount{
			Guest: guest, Host: pol.Target,
			Kind: policy.KindGraft, Access: access, From: []string{"(snug)"},
		},
		Why: "test abuse sentence: a hostile process inside the sandbox can use this to test",
	}); err != nil {
		t.Fatalf("fixture: installing the target graft: %v", err)
	}
}

// TestATailUnderTheTargetIsNotForwardedAsTheGraft pins issue #376's own
// stated limit: the graft is a fixed root, exact match only, never a prefix —
// a name UNDERNEATH the target falls straight through to the ordinary
// anchored-source rule and is refused there, the same as before #376. A
// prefix match here would reopen #284 through the graft (open_tree pins the
// root inode and says nothing about names beneath it).
func TestATailUnderTheTargetIsNotForwardedAsTheGraft(t *testing.T) {
	var pol *policy.Policy
	var tail string
	sock, eng, _ := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		tail = filepath.Join(target, "data")
		if err := os.MkdirAll(tail, 0o755); err != nil {
			t.Fatal(err)
		}
		pol = &policy.Policy{
			Mounts: map[string]policy.Mount{
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			},
		}
		return pol
	})
	installTargetGraft(t, pol)

	if guest, ok := pol.EngineTargetForwarded(tail, true); ok {
		t.Fatalf("EngineTargetForwarded(%s) = (%q, true), want (\"\", false) — a tail under the "+
			"target must never match the graft's exact-match rewrite", tail, guest)
	}

	refuse(t, sock, eng, "/v1.41/containers/create",
		fmt.Sprintf(`{"HostConfig":{"Binds":["%s:/x"]}}`, tail), "this sandbox can write")
}

// TestASiblingOfTheTargetIsNotForwardedAsTheGraft pins the other half of
// "exact match, never a prefix": a directory next to the target, sharing
// nothing with it, must never reach the graft rewrite either — it is refused
// by the ordinary visibility check before checkOne ever asks about a graft.
func TestASiblingOfTheTargetIsNotForwardedAsTheGraft(t *testing.T) {
	var pol *policy.Policy
	var sibling string
	sock, eng, _ := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		sibling = filepath.Join(dir, "other")
		if err := os.MkdirAll(sibling, 0o755); err != nil {
			t.Fatal(err)
		}
		pol = &policy.Policy{
			Mounts: map[string]policy.Mount{
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			},
		}
		return pol
	})
	installTargetGraft(t, pol)

	if guest, ok := pol.EngineTargetForwarded(sibling, true); ok {
		t.Fatalf("EngineTargetForwarded(%s) = (%q, true), want (\"\", false) — a sibling of the "+
			"target shares no Host with the installed graft", sibling, guest)
	}

	refuse(t, sock, eng, "/v1.41/containers/create",
		fmt.Sprintf(`{"HostConfig":{"Binds":["%s:/x"]}}`, sibling), "cannot see "+sibling)
}

// TestAWritableRequestOnAReadOnlyTargetIsRefusedBeforeTheRewrite pins
// section 5's ordering claim: checkOne asks hostPathVisible BEFORE the
// target-graft rewrite, so a client's rw request against a target this
// sandbox can only see read-only is refused by hostPathVisible's own
// sentence, never reaching the graft arm at all — which matters because the
// graft arm's own mount would otherwise need to carry ReadOnly: false for a
// ro graft, a wrong mount section 5 names by name.
//
// MUTATION CHECK, empirically run and restored: EngineTargetForwarded's own
// `needWrite && g.Access != AccessRW` gate independently refuses this exact
// request, so removing EITHER that gate OR swapping the two blocks in
// checkOne, ALONE, leaves this test green — the two protections are
// redundant for this input. Removing BOTH at once is what actually lets the
// wrong mount through, and that combination turns this test red.
func TestAWritableRequestOnAReadOnlyTargetIsRefusedBeforeTheRewrite(t *testing.T) {
	var pol *policy.Policy
	sock, eng, target := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		pol = &policy.Policy{
			Mounts: map[string]policy.Mount{
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRO},
			},
		}
		return pol
	})
	installTargetGraft(t, pol) // installs AccessRO, the only access HostPathVisible grants here

	before := eng.reached.Load()
	code, resp := post(t, sock, "/v1.41/containers/create",
		fmt.Sprintf(`{"HostConfig":{"Binds":["%s:/x"]}}`, target))
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != before {
		t.Fatal("the request reached the engine; it should have been refused here")
	}
	msg := denyMessage(resp)
	if !strings.Contains(msg, "cannot see") || !strings.Contains(msg, "writable") {
		t.Errorf("refusal is not hostPathVisible's own sentence (\"cannot see ... as writable\"):\n%s", msg)
	}
	if strings.Contains(msg, "cannot be forwarded to the container engine") {
		t.Errorf("refusal came from CheckEngineForwardedPath/CheckEngineBindSource, not "+
			"hostPathVisible — the graft arm was reached before the visibility check:\n%s", msg)
	}
}

// TestNoTargetGraftWhenTheTargetIsNotVisibleInHostSpace pins section 2's
// "not-visible is reachable" case: a divergent host:guest grant satisfies
// Validate's GUEST-side target check but not HostPathVisible's HOST-side
// one, so EngineTargetGraft refuses to produce anything — silently, not as
// a refusal of the run — and the target still cannot be forwarded as a
// string, so nothing is lost.
func TestNoTargetGraftWhenTheTargetIsNotVisibleInHostSpace(t *testing.T) {
	var pol *policy.Policy
	sock, eng, target := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		pol = &policy.Policy{
			Mounts: map[string]policy.Mount{
				// The divergent grant: Guest is the target (satisfies
				// Resolve's own target-covering requirement), Host is a
				// different literal string HostPathVisible will never
				// match target against.
				target: {Guest: target, Host: "/srv/build", Kind: policy.KindBind, Access: policy.AccessRW},
			},
		}
		return pol
	})

	guest, access, ok := pol.EngineTargetGraft()
	if ok {
		t.Fatalf("EngineTargetGraft() = (%q, %v, true); want ok=false — HostPathVisible walks "+
			"Mount.Host, and nothing here has Host == %s", guest, access, target)
	}

	args := pol.BwrapArgs(1000, 1000)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--dir" && args[i+1] == policy.EngineBindsDir {
			t.Fatalf("bwrap argv creates %s despite no target graft being produced: %v",
				policy.EngineBindsDir, args)
		}
	}

	// checkOne's own message here is bindRefusalReason's FIRST arm, not the
	// plain "cannot see" sentence: the target's GUEST is granted
	// (GrantsGuestPath), so the more precise diagnosis fires — there is a
	// host directory in the sandbox's own view, snug just cannot resolve
	// this name to it. Either way the request never reaches the engine,
	// which is the property this test exists to pin.
	refuse(t, sock, eng, "/v1.41/containers/create",
		fmt.Sprintf(`{"HostConfig":{"Binds":["%s:/x"]}}`, target), "is not a bind of a host directory")
}
