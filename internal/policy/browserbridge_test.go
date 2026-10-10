package policy

import (
	"reflect"
	"strings"
	"testing"
)

// TestBrowserBridgeNeedsEgress: login = ["claude"] relays the callback
// into the sandbox's own network namespace, so a selection with no @net grant
// stages a BROWSER that can never complete a login — refused rather than
// granted-but-useless (issue #455).
func TestBrowserBridgeNeedsEgress(t *testing.T) {
	reg := testRegistry()
	reg["bridge"] = &Profile{Name: "bridge", Login: []string{"claude"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("login = [\"claude\"] without egress resolved")
	}
	for _, want := range []string{`"bridge"`, "-p @net"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %v", want, err)
		}
	}
}

// TestBrowserBridgeNeedsAShell: the shim BROWSER points at is a `/bin/sh`
// script, so a selection with no shell inside is refused at Resolve rather
// than failing later when Claude Code execs $BROWSER.
func TestBrowserBridgeNeedsAShell(t *testing.T) {
	reg := testRegistry()
	reg["bridge"] = &Profile{Name: "bridge", Login: []string{"claude"}, Network: "egress"}
	_, err := Resolve(reg, []ProfileName{"@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("login = [\"claude\"] with no shell resolved")
	}
	for _, want := range []string{"/bin/sh", "@sys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %v", want, err)
		}
	}
}

// TestBrowserBridgeStagesTheShimAndBROWSER pins the positive case: with both
// egress and a shell, Resolve stages the read-only shim and points BROWSER at
// it, and nothing else.
func TestBrowserBridgeStagesTheShimAndBROWSER(t *testing.T) {
	reg := testRegistry()
	reg["bridge"] = &Profile{Name: "bridge", Login: []string{"claude"}, Network: "egress"}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := (LoginSet(0)).With(LoginClaude); p.Login != want {
		t.Fatalf("p.Login = %v, want %v", p.Login, want)
	}
	m, ok := p.Mounts[BrowserShimGuest]
	if !ok || m.Kind != KindData || m.Access != AccessRO || !m.Authored {
		t.Fatalf("no authored read-only KindData mount at %s: %+v", BrowserShimGuest, m)
	}
	v, ok := p.Env["BROWSER"]
	if !ok || len(v.Entries) != 1 || v.Entries[0].Value != BrowserShimGuest || v.Entries[0].Verb != VerbSnug {
		t.Fatalf("BROWSER not authored to %s: %+v", BrowserShimGuest, v)
	}
}

// TestWithoutBrowserThereIsNoShimOrBROWSER: a selection with @net and @sys but
// no login key stages neither the shim nor BROWSER — the hole exists only
// where a profile spells the key itself.
func TestWithoutBrowserThereIsNoShimOrBROWSER(t *testing.T) {
	p := mustResolve(t, "@sys", "@target-rw", "netty")
	if _, ok := p.Mounts[BrowserShimGuest]; ok {
		t.Error("the shim is staged without login = [\"claude\"] anywhere in the selection")
	}
	if _, ok := p.Env["BROWSER"]; ok {
		t.Error("BROWSER is authored without login = [\"claude\"] anywhere in the selection")
	}
}

// TestLoginUnknownProviderRefuses: a `login` element outside the accepted set
// refuses at Resolve naming the profile and the set, never read as the nearest
// provider it resembles. "claude-login" is a mode spelling, not a provider.
func TestLoginUnknownProviderRefuses(t *testing.T) {
	for _, list := range [][]string{{"claude-login"}, {"x"}, {"claude", "x"}} {
		reg := testRegistry()
		reg["bridge"] = &Profile{Name: "bridge", Login: list, Network: "egress"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
		if err == nil {
			t.Errorf("login = %q resolved", list)
			continue
		}
		for _, want := range []string{`"bridge"`, "unknown login provider", "(want claude)"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("login = %q: refusal does not say %q: %v", list, want, err)
			}
		}
	}
}

// TestLoginIsAUnion: two profiles naming the same provider turn the bridge on
// once, and the resolved policy does not depend on which the fold reached
// first. An empty list is off and contributes nothing.
func TestLoginIsAUnion(t *testing.T) {
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Login: []string{"claude"}, Network: "egress"}
	reg["b"] = &Profile{Name: "b", Login: []string{"claude", "claude"}}
	reg["c"] = &Profile{Name: "c", Login: []string{}}
	ab, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "a", "b", "c"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve a b c: %v", err)
	}
	ba, err := Resolve(reg, []ProfileName{"c", "b", "a", "@target-rw", "@sys"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve c b a: %v", err)
	}
	want := LoginSet(0).With(LoginClaude)
	if ab.Login != want || ba.Login != want {
		t.Errorf("login = %v and %v, want %v in both orders", ab.Login, ba.Login, want)
	}
	if got := ab.Login.Names(); len(got) != 1 || got[0] != "claude" {
		t.Errorf("Names() = %q, want [claude]", got)
	}
	if !reflect.DeepEqual(ab.Mounts[BrowserShimGuest], ba.Mounts[BrowserShimGuest]) ||
		!reflect.DeepEqual(ab.Env["BROWSER"], ba.Env["BROWSER"]) {
		t.Error("the shim or BROWSER depends on fold order")
	}

	only := testRegistry()
	only["c"] = &Profile{Name: "c", Login: []string{}, Network: "egress"}
	p, err := Resolve(only, []ProfileName{"@sys", "@target-rw", "c"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve c: %v", err)
	}
	if p.Login != 0 {
		t.Errorf("login = [] resolved to %v, want empty", p.Login)
	}
	if _, ok := p.Mounts[BrowserShimGuest]; ok {
		t.Error("login = [] staged the shim")
	}
}
