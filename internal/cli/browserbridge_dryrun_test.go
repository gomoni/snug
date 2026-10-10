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

// TestGoldenBrowserBridgeJSON pins the machine document for the bridge as a
// DIFF against the same selection without it, not as a second whole document.
// It fails if turning the bridge on moves any line outside
// json.browser-bridge.diff — seccomp, topology, pasta and every unrelated
// mount and environment row included — and, through the base pin, if the
// bridge-off document under this fake host (WAYLAND_DISPLAY set, xdg-open on
// PATH) stops being exactly json.net.json. The two pins together determine
// every byte of the bridge-on document.
func TestGoldenBrowserBridgeJSON(t *testing.T) {
	// The FIFO's host path carries this process's pid and $XDG_RUNTIME_DIR;
	// both are pinned so the document is stable.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	env := newBridgeEnv(false)
	render := func(on bool, pinSeccomp bool) string {
		t.Helper()
		p := resolveBridge(t, env, on)
		if on {
			if err := planBrowserFIFO(p, nil); err != nil {
				t.Fatal(err)
			}
		}
		rep := buildReport(env, p, p.BwrapArgs(0, 0), config{json: true}, nil, nil)
		if pinSeccomp {
			rep.Seccomp = jsonGoldenSeccomp
		}
		var b bytes.Buffer
		if err := renderJSON(&b, rep); err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(b.String(), runDirName(), "run-PID")
	}

	// Base pin: without the key, this host renders json.net.json byte for
	// byte, so the context the diff below applies to is itself a golden.
	base, err := os.ReadFile(filepath.Join("testdata", "json.net.json"))
	if err != nil {
		t.Fatal(err)
	}
	if off := render(false, true); off != string(base) {
		t.Fatalf("with the key off, the bridge's fake host no longer renders json.net.json — "+
			"the diff golden would apply to an unpinned base.\n%s", unifiedLineDiff(string(base), off))
	}

	// The seccomp block is left REAL on both sides here: it cancels out of
	// the diff unless the bridge changes it, which is the property.
	delta := unifiedLineDiff(render(false, false), render(true, false))
	if !strings.Contains(delta, `"browser_bridge"`) {
		t.Fatalf("control: the diff has no browser_bridge object — the key never reached the document:\n%s", delta)
	}
	goldenText(t, "json.browser-bridge.diff", delta)
}

// unifiedLineDiff renders the line diff from a to b with two lines of context
// per hunk and no line numbers, so a hunk does not churn when an unrelated
// grant moves the lines above it. Equal inputs render "".
func unifiedLineDiff(a, b string) string {
	x, y := strings.SplitAfter(a, "\n"), strings.SplitAfter(b, "\n")
	// lcs[i][j] is the LCS length of x[i:] and y[j:].
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		tag  byte
		line string
	}
	var ops []op
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		switch {
		case i < len(x) && j < len(y) && x[i] == y[j]:
			ops = append(ops, op{' ', x[i]})
			i, j = i+1, j+1
		case i < len(x) && (j == len(y) || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', x[i]})
			i++
		default:
			ops = append(ops, op{'+', y[j]})
			j++
		}
	}
	const ctx = 2
	var out strings.Builder
	last := -1 // index of the last op written
	for k, o := range ops {
		if o.tag == ' ' {
			continue
		}
		start := max(k-ctx, last+1)
		if start > last+1 || last == -1 {
			out.WriteString("@@\n")
		}
		for c := start; c <= k; c++ {
			out.WriteByte(ops[c].tag)
			out.WriteString(strings.TrimSuffix(ops[c].line, "\n") + "\n")
		}
		last = k
		// Trailing context, stopping short of the next change so it is
		// written once.
		for c := k + 1; c < len(ops) && c <= k+ctx && ops[c].tag == ' '; c++ {
			out.WriteString(" " + strings.TrimSuffix(ops[c].line, "\n") + "\n")
			last = c
		}
	}
	return out.String()
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
