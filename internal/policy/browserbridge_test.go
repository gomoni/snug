package policy

import (
	"strings"
	"testing"
)

// TestBrowserBridgeNeedsEgress: browser = "claude-login" relays the callback
// into the sandbox's own network namespace, so a selection with no @net grant
// stages a BROWSER that can never complete a login — refused rather than
// granted-but-useless (issue #455).
func TestBrowserBridgeNeedsEgress(t *testing.T) {
	reg := testRegistry()
	reg["bridge"] = &Profile{Name: "bridge", Browser: "claude-login"}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("browser = \"claude-login\" without egress resolved")
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
	reg["bridge"] = &Profile{Name: "bridge", Browser: "claude-login", Network: "egress"}
	_, err := Resolve(reg, []ProfileName{"@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("browser = \"claude-login\" with no shell resolved")
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
	reg["bridge"] = &Profile{Name: "bridge", Browser: "claude-login", Network: "egress"}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Browser != BrowserClaudeLogin {
		t.Fatalf("p.Browser = %v, want BrowserClaudeLogin", p.Browser)
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
// no browser key stages neither the shim nor BROWSER — the hole exists only
// where a profile spells the key itself.
func TestWithoutBrowserThereIsNoShimOrBROWSER(t *testing.T) {
	p := mustResolve(t, "@sys", "@target-rw", "netty")
	if _, ok := p.Mounts[BrowserShimGuest]; ok {
		t.Error("the shim is staged without browser = \"claude-login\" anywhere in the selection")
	}
	if _, ok := p.Env["BROWSER"]; ok {
		t.Error("BROWSER is authored without browser = \"claude-login\" anywhere in the selection")
	}
}
