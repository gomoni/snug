package cli

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// bridgeFakeEnv is the golden fake host with an xdg-open on PATH and a
// graphical session, so browserPreflight passes without reading this machine.
type bridgeFakeEnv struct {
	*envFakeEnv
	noOpener bool
}

func (f bridgeFakeEnv) LookPath(name string) (string, error) {
	if name == "xdg-open" && !f.noOpener {
		return "/usr/bin/xdg-open", nil
	}
	return "", &fs.PathError{Op: "lookpath", Path: name, Err: fs.ErrNotExist}
}

func newBridgeEnv(noOpener bool) bridgeFakeEnv {
	e := newEnvFakeEnv()
	e.env["WAYLAND_DISPLAY"] = "wayland-0"
	return bridgeFakeEnv{envFakeEnv: e, noOpener: noOpener}
}

// resolveBridge resolves @sys @target-rw @net plus a profile that sets the
// key, because no builtin does.
func resolveBridge(t *testing.T, env policy.Environ, on bool) *policy.Policy {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	sel := []policy.ProfileName{"@sys", "@target-rw", "@net"}
	if on {
		m["bridge"] = &policy.Profile{Name: "bridge", Login: []string{"claude"}}
		sel = append(sel, "bridge")
	}
	p, err := policy.Resolve(m, sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p
}

func goldenText(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -run Browser -update, then READ the diff)", err)
	}
	if got != string(want) {
		t.Errorf("%s changed — read it as the screen a human trusts.\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func bridgeHuman(t *testing.T, env policy.Environ, p *policy.Policy) string {
	t.Helper()
	if err := planBrowserFIFO(p, nil); err != nil {
		t.Fatal(err)
	}
	rep := buildReport(env, p, nil, config{}, nil, nil)
	var b bytes.Buffer
	renderHuman(&b, rep, p, nil, config{}, nil, env)
	return b.String()
}

func TestGoldenBrowserBridgeScreens(t *testing.T) {
	env := newBridgeEnv(false)
	p := resolveBridge(t, env, true)
	rep := buildReport(env, p, nil, config{}, nil, nil)

	goldenText(t, "network.browser-bridge.txt", captureFile(t, func(f io.Writer) {
		describeNetwork(f, p)
		renderBrowserBridge(f, rep.BrowserBridge)
	}))
	goldenText(t, "topology.browser-bridge.txt", captureFile(t, func(f io.Writer) { describeTopology(f, p) }))
	goldenText(t, "explain.browser-bridge.txt", captureFile(t, func(f io.Writer) {
		if err := explain(env, f, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}))
}

func TestGoldenBrowserBridgeJSON(t *testing.T) {
	// The FIFO's host path carries this process's pid and $XDG_RUNTIME_DIR;
	// both are pinned so the document is stable.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	env := newBridgeEnv(false)
	p := resolveBridge(t, env, true)
	if err := planBrowserFIFO(p, nil); err != nil {
		t.Fatal(err)
	}
	rep := buildReport(env, p, nil, config{}, nil, nil)
	var b bytes.Buffer
	if err := renderJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	goldenText(t, "json.browser-bridge.json", strings.ReplaceAll(b.String(), runDirName(), "run-PID"))
}

// TestBrowserBridgeRowsAreAbsentWhenTheKeyIsOff pins the negative: a
// selection without the key shows no bridge on any screen, and the document
// has no browser_bridge field.
func TestBrowserBridgeRowsAreAbsentWhenTheKeyIsOff(t *testing.T) {
	env := newBridgeEnv(false)
	p := resolveBridge(t, env, false)
	human := bridgeHuman(t, env, p)
	for _, bad := range []string{"browser bridge", "login opener", "snug-browser", "browser.fifo", "BROWSER"} {
		if strings.Contains(human, bad) {
			t.Errorf("key off, but --dry-run mentions %q", bad)
		}
	}
	rep := buildReport(env, p, nil, config{}, nil, nil)
	var j bytes.Buffer
	if err := renderJSON(&j, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(j.String(), "browser_bridge") {
		t.Error("key off, but the JSON document has browser_bridge")
	}
	var ex bytes.Buffer
	if err := explain(env, &ex, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if s := ex.String(); strings.Contains(s, "Login bridge") || strings.Contains(s, "except the browser") {
		t.Error("key off, but --explain mentions the bridge")
	}
}

// TestBrowserBridgeDryRunShowsTheFilesystemRowsAndEnv covers the rows that
// are not in the NETWORK block: the generated shim, the planned FIFO and
// BROWSER with snug provenance.
func TestBrowserBridgeDryRunShowsTheFilesystemRowsAndEnv(t *testing.T) {
	env := newBridgeEnv(false)
	p := resolveBridge(t, env, true)
	human := bridgeHuman(t, env, p)
	for _, want := range []string{
		policy.BrowserShimGuest, policy.BrowserFIFOGuest,
		"BROWSER", "browser bridge  login = [\"claude\"]", "opener          /usr/bin/xdg-open",
		"org:create_api_key", "login opener",
	} {
		if !strings.Contains(human, want) {
			t.Errorf("--dry-run lacks %q", want)
		}
	}
}

// TestBrowserBridgeScreenShowsARefusalTheRunWouldMake: without xdg-open the
// screen must not show an opener a real run would not have.
func TestBrowserBridgeScreenShowsARefusalTheRunWouldMake(t *testing.T) {
	env := newBridgeEnv(true)
	p := resolveBridge(t, env, true)
	human := bridgeHuman(t, env, p)
	if !strings.Contains(human, "NONE — a real run would REFUSE") {
		t.Errorf("no opener, but the screen does not say the run would refuse:\n%s", human)
	}
	rep := buildReport(env, p, nil, config{}, nil, nil)
	if rep.BrowserBridge.Opener != "" || rep.BrowserBridge.OpenerError == "" {
		t.Errorf("report = %+v, want empty opener and an error", rep.BrowserBridge)
	}
}
