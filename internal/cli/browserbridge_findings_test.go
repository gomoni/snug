package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestBrowserBridgeDryRunPlansTheFIFOOnce goes through dryRun after main's own
// planBrowserFIFO call, the order the binary runs them in, because the golden
// that bypasses dryRun is what let "(browser)+replaces:(browser)" ship.
func TestBrowserBridgeDryRunPlansTheFIFOOnce(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	env := newBridgeEnv(false)
	p := resolveBridge(t, env, true)
	if err := planBrowserFIFO(p, nil); err != nil {
		t.Fatal(err)
	}
	for _, json := range []bool{false, true} {
		var b bytes.Buffer
		if err := dryRun(env, &b, p, []string{"sh"}, config{json: json}, &notes{}, nil); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "replaces:") {
			t.Errorf("json=%v: the FIFO row displaced its own earlier row:\n%s", json, b.String())
		}
		if !strings.Contains(b.String(), policy.BrowserFIFOGuest) {
			t.Errorf("json=%v: no FIFO row at all", json)
		}
	}
}

// TestRefusedScreenNamesTheOffendingProfileAtTheFIFOPath: a profile that maps
// something at a path snug reserves is refused, and the refused screen's
// FILESYSTEM row must be that profile's, not a (browser) row written over it.
func TestRefusedScreenNamesTheOffendingProfileAtTheFIFOPath(t *testing.T) {
	const host = "/home/u/evil-host-file"
	for _, tc := range []struct {
		name string
		prof policy.Profile
	}{
		{"rw", policy.Profile{RW: []string{host + ":" + policy.BrowserFIFOGuest}}},
		{"ro", policy.Profile{RO: []string{host + ":" + policy.BrowserFIFOGuest}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newBridgeEnv(false)
			env.dirs[host] = true
			reg, err := profile.Builtins()
			if err != nil {
				t.Fatal(err)
			}
			m := map[policy.ProfileName]*policy.Profile(reg)
			evil := tc.prof
			evil.Name = "evil"
			evil.Login = []string{"claude"}
			m["evil"] = &evil
			p, rerr := policy.Resolve(m, []policy.ProfileName{"@sys", "@target-rw", "@net", "evil"}, envGoldenCtx(), env)
			if rerr == nil || p == nil {
				t.Fatalf("expected a refused policy, got p=%v err=%v", p, rerr)
			}
			var b bytes.Buffer
			if err := dryRun(env, &b, p, []string{"sh"}, config{}, &notes{}, rerr); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if strings.Contains(out, "(browser)") {
				t.Errorf("refused screen shows snug's (browser) row over the offending mount:\n%s", out)
			}
			if !strings.Contains(out, host) || !strings.Contains(out, "evil") {
				t.Errorf("refused screen does not name evil's host path:\n%s", out)
			}
		})
	}
}

// TestExplainSaysTheRunWouldRefuseWithoutAGraphicalSession reads the same
// preflight answer the --dry-run report does.
func TestExplainSaysTheRunWouldRefuseWithoutAGraphicalSession(t *testing.T) {
	env := newBridgeEnv(true)
	p := resolveBridge(t, env, true)
	var b bytes.Buffer
	if err := explain(env, &b, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "would REFUSE") || !strings.Contains(s, "xdg-utils") {
		t.Errorf("no opener: --explain does not say the run would refuse, naming the fix:\n%s", s)
	}
	if strings.Contains(s, "may ask snug to open") {
		t.Errorf("--explain promises a bridge a real run would not start:\n%s", s)
	}

	ok := newBridgeEnv(false)
	p = resolveBridge(t, ok, true)
	b.Reset()
	if err := explain(ok, &b, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "may ask snug to open") || strings.Contains(b.String(), "would REFUSE") {
		t.Errorf("working opener: --explain lost its normal paragraph:\n%s", b.String())
	}
}

// TestNetworkRowQualifiesHostToSandboxWhenTheBridgeIsOn: the bridge delivers
// one host-originated request into the sandbox, so an unqualified CLOSED is
// false with it on, and must stay byte-identical with it off.
func TestNetworkRowQualifiesHostToSandboxWhenTheBridgeIsOn(t *testing.T) {
	env := newBridgeEnv(false)
	var on, off bytes.Buffer
	describeNetwork(&on, resolveBridge(t, env, true))
	describeNetwork(&off, resolveBridge(t, env, false))
	if !strings.Contains(on.String(), "CLOSED — except the login bridge's one relayed") {
		t.Errorf("bridge on, row unqualified:\n%s", on.String())
	}
	if !strings.Contains(off.String(), "host -> sandbox CLOSED — nothing is forwarded into this\n") {
		t.Errorf("bridge off, row changed:\n%s", off.String())
	}
}

// TestTopologySaysOpenerMayOutliveTheRun: the wait is per login, and
// xdg-open itself, not only its browser, can outlive the run.
func TestTopologySaysOpenerMayOutliveTheRun(t *testing.T) {
	p := resolveBridge(t, newBridgeEnv(false), true)
	var b bytes.Buffer
	describeBrowserTopology(&b, p)
	s := strings.Join(strings.Fields(b.String()), " ")
	for _, want := range []string{"PER LOGIN", "only while snug is alive", "xdg-open itself"} {
		if !strings.Contains(s, want) {
			t.Errorf("topology row lacks %q: %s", want, s)
		}
	}
}
