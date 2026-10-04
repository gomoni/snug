package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

type browserEnv struct {
	policy.Environ
	vars map[string]string
	xdg  bool
}

func (e browserEnv) Getenv(k string) string { return e.vars[k] }
func (e browserEnv) LookPath(f string) (string, error) {
	if f == "xdg-open" && e.xdg {
		return "/usr/bin/xdg-open", nil
	}
	return "", errors.New("not found")
}

func TestBrowserPreflightRefusals(t *testing.T) {
	_, err := browserPreflight(browserEnv{vars: map[string]string{"DISPLAY": ":0"}})
	if err == nil || !strings.Contains(err.Error(), "xdg-open") || !strings.Contains(err.Error(), "pasting the code") {
		t.Fatalf("no xdg-open: %v", err)
	}
	_, err = browserPreflight(browserEnv{xdg: true})
	if err == nil || !strings.Contains(err.Error(), "DISPLAY nor WAYLAND_DISPLAY") || !strings.Contains(err.Error(), "pasting the code") {
		t.Fatalf("no display: %v", err)
	}
	got, err := browserPreflight(browserEnv{xdg: true, vars: map[string]string{"WAYLAND_DISPLAY": "w0"}})
	if err != nil || got != "/usr/bin/xdg-open" {
		t.Fatalf("wayland only: %q %v", got, err)
	}
}

// The refusals leave through refuse with exitPolicy, the same funnel every
// other preflight uses.
func TestBrowserPreflightExitsPolicy(t *testing.T) {
	_, err := browserPreflight(browserEnv{})
	if err == nil {
		t.Fatal("expected refusal")
	}
	var buf bytes.Buffer
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	code := refuse(config{}, exitPolicy, err)
	w.Close()
	os.Stderr = old
	buf.ReadFrom(r)
	if code != 77 || !strings.HasPrefix(buf.String(), "snug: browser = \"claude-login\"") {
		t.Fatalf("code=%d out=%q", code, buf.String())
	}
}

const goodLoginURL = "https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e" +
	"&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A40123%2Fcallback" +
	"&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code" +
	"+user%3Amcp_servers+user%3Afile_upload+user%3Aplugins" +
	"&code_challenge=fD5xTDCwgf63U088pqhV0TFHbLf0emkJPI844Pfplvs" +
	"&code_challenge_method=S256&state=qUcPYbXlvfwBNYqnh52qhKs7Ac_7GNRvan-h3ihmgk8"

func TestLoginReaderRefusalsAreCappedAndSanitised(t *testing.T) {
	var out bytes.Buffer
	var in strings.Builder
	for range 8 {
		in.WriteString("https://evil.example/\x1b[31m\n")
	}
	handled := 0
	readLoginLines(strings.NewReader(in.String()), &out, func(loginbridge.Flow) { handled++ })
	s := out.String()
	if handled != 0 {
		t.Fatalf("a refused line reached the handler")
	}
	if n := strings.Count(s, "refused an open request from the sandbox"); n != 5 {
		t.Fatalf("printed %d refusals, want 5:\n%s", n, s)
	}
	if strings.Count(s, "further refusals suppressed") != 1 {
		t.Fatalf("want one suppression line:\n%s", s)
	}
	if strings.Contains(s, "\x1b") || !strings.Contains(s, "Nothing was opened.") {
		t.Fatalf("raw escape or missing tail:\n%q", s)
	}
}

func TestLoginReaderOverlongLineIsOneRefusalAndResyncs(t *testing.T) {
	var out bytes.Buffer
	in := strings.Repeat("a", 3*loginMaxLine) + "\n" + goodLoginURL + "\n"
	var got []loginbridge.Flow
	readLoginLines(strings.NewReader(in), &out, func(f loginbridge.Flow) { got = append(got, f) })
	if n := strings.Count(out.String(), "longer than 4096 bytes"); n != 1 {
		t.Fatalf("overlong refusals = %d:\n%s", n, out.String())
	}
	if len(got) != 1 || got[0].Port != 40123 {
		t.Fatalf("the line after the overlong one was not parsed: %+v", got)
	}
}

func TestLoginReaderAcceptedLineHitsHandOff(t *testing.T) {
	var out bytes.Buffer
	var got []loginbridge.Flow
	readLoginLines(strings.NewReader(goodLoginURL+"\n"), &out, func(f loginbridge.Flow) { got = append(got, f) })
	if len(got) != 1 || out.Len() != 0 {
		t.Fatalf("got %+v, stderr %q", got, out.String())
	}
	var o bytes.Buffer
	notYetBuiltHandler(&o)(got[0])
	if !strings.Contains(o.String(), "not implemented in this build") || !strings.Contains(o.String(), "NOTHING WAS OPENED") {
		t.Fatalf("stub handler: %q", o.String())
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestLoginBridgeFIFOIsPrivateBoundAndClosesCleanly(t *testing.T) {
	dir := t.TempDir()
	pol := &policy.Policy{Mounts: map[string]policy.Mount{}}
	var out lockedBuf
	flows := make(chan loginbridge.Flow, 1)
	b, err := startLoginBridge(pol, func(n string) (string, error) { return filepath.Join(dir, n), nil },
		&out, func(f loginbridge.Flow) { flows <- f })
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(dir, browserFIFOName))
	if err != nil || fi.Mode()&os.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("fifo: %v %v", fi, err)
	}
	m, ok := pol.Mounts[policy.BrowserFIFOGuest]
	if !ok || m.Host != filepath.Join(dir, browserFIFOName) || !m.RunScoped || m.Kind != policy.KindBind {
		t.Fatalf("mount: %+v ok=%v", m, ok)
	}
	w, err := os.OpenFile(filepath.Join(dir, browserFIFOName), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(goodLoginURL + "\n")
	w.Close()
	select {
	case f := <-flows:
		if f.Port != 40123 {
			t.Fatalf("port %d", f.Port)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader never delivered the line")
	}
	b.setRelay([]*os.File{mustTempFile(t)})
	done := make(chan struct{})
	go func() { b.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not stop the reader")
	}
	if b.relay != nil {
		t.Fatal("relay sockets not released")
	}
}

func mustTempFile(t *testing.T) *os.File {
	f, err := os.CreateTemp(t.TempDir(), "r")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRunWithoutTheKeyHasNoBridgeAndAsksForNoRelaySockets(t *testing.T) {
	if wantsLoginBridge(&policy.Policy{}, config{}) {
		t.Fatal("bridge wanted with the key off")
	}
	on := &policy.Policy{Browser: policy.BrowserClaudeLogin}
	if !wantsLoginBridge(on, config{}) {
		t.Fatal("bridge not wanted with the key on")
	}
	if wantsLoginBridge(on, config{dryRun: true}) {
		t.Fatal("--dry-run must start nothing")
	}
	var o sandbox.Options
	(*loginBridge)(nil).apply(&o)
	if o.RelaySockets != 0 || o.OnRelaySockets != nil {
		t.Fatalf("%+v", o)
	}
	(&loginBridge{}).apply(&o)
	if o.RelaySockets != 3 || o.OnRelaySockets == nil {
		t.Fatalf("%+v", o)
	}
}
