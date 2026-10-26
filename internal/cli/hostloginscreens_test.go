package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// hostLoginFakeEnv is the bridge's fake host plus the reads the host-mode
// preflight makes, answered from memory.
type hostLoginFakeEnv struct {
	bridgeFakeEnv
	state string
	creds fs.FileMode // 0: absent
}

type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return ".credentials.json" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func (e hostLoginFakeEnv) ReadClaudeState(string) ([]byte, string) {
	if e.state == "" {
		return nil, ""
	}
	return []byte(e.state), ""
}

func (e hostLoginFakeEnv) Lstat(path string) (fs.FileInfo, error) {
	if strings.HasSuffix(path, "/.claude/.credentials.json") {
		if e.creds == 0 {
			return nil, fs.ErrNotExist
		}
		return fakeInfo{e.creds}, nil
	}
	return e.bridgeFakeEnv.Lstat(path)
}

func (hostLoginFakeEnv) Writable(string) error { return nil }

const signedIn = `{"oauthAccount":{"accountUuid":"a","organizationUuid":"o","emailAddress":"x@example.com"}}`

func resolveHostBridge(t *testing.T, env policy.Environ) *policy.Policy {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["bridge"] = &policy.Profile{Name: "bridge",
		Login: map[policy.LoginProvider]policy.LoginMode{policy.LoginClaude: policy.LoginHost}}
	p, err := policy.Resolve(m, []policy.ProfileName{"@sys", "@target-rw", "@net", "bridge"}, envGoldenCtx(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p
}

// TestDryRunSaysTheHostFileWillBeRewritten: in host mode --dry-run states, in
// the browser bridge block and the JSON document, that a login the human
// approves rewrites the host's credential file; and it shows the preflight's
// refusal when the host has no login to renew, as a real run would refuse.
func TestDryRunSaysTheHostFileWillBeRewritten(t *testing.T) {
	ok := hostLoginFakeEnv{bridgeFakeEnv: newBridgeEnv(false), state: signedIn, creds: 0o600}
	p := resolveHostBridge(t, ok)
	human := bridgeHuman(t, ok, p)
	for _, w := range []string{
		`browser bridge  login.claude = "host"`,
		"A LOGIN YOU APPROVE REWRITES THIS HOST'S ~/.claude/.credentials.json",
		"At most 3 rewrites per run",
	} {
		if !strings.Contains(human, w) {
			t.Errorf("--dry-run lacks %q", w)
		}
	}
	if strings.Contains(human, "a real run would REFUSE") {
		t.Errorf("a signed-in host is shown as refused:\n%s", human)
	}
	var j bytes.Buffer
	if err := renderJSON(&j, buildReport(ok, p, nil, config{json: true}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"host_rewrite": true`, `"claude": "host"`} {
		if !strings.Contains(j.String(), w) {
			t.Errorf("the JSON document lacks %s", w)
		}
	}

	none := hostLoginFakeEnv{bridgeFakeEnv: newBridgeEnv(false), state: `{}`}
	p = resolveHostBridge(t, none)
	if human := bridgeHuman(t, none, p); !strings.Contains(human, "a real run would REFUSE to start") ||
		!strings.Contains(human, "names none") {
		t.Errorf("no pin: the screen does not show the refusal:\n%s", human)
	}
}

// TestDryRunNamesTheRunDirFileAndCreatesNothing: --dry-run binds the
// credential directory a real run would create, at the planned path,
// read-only and run-scoped, and creates no directory.
func TestDryRunNamesTheRunDirFileAndCreatesNothing(t *testing.T) {
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	env := hostLoginFakeEnv{bridgeFakeEnv: newBridgeEnv(false), state: signedIn, creds: 0o600}
	p := resolveHostBridge(t, env)
	if err := planBrowserFIFO(p, nil); err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts[policy.ClaudeCredentialDirGuest]
	if !ok || m.Kind != policy.KindBind || m.Access != policy.AccessRO || !m.RunScoped || !m.Authored ||
		m.Host != filepath.Join(rt, "snug", runDirName(), claudeRunDirName) {
		t.Fatalf("planned mount: %+v ok=%v", m, ok)
	}
	if _, err := os.Stat(filepath.Join(rt, "snug")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("--dry-run created something under the runtime directory: %v", err)
	}
	var b bytes.Buffer
	if err := dryRun(env, &b, p, []string{"sh"}, config{}, &notes{}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "/snug/claude (from ") || !strings.Contains(b.String(), `login.claude = "host"`) {
		t.Errorf("FILESYSTEM block lacks the credential directory row:\n%s", b.String())
	}
}

// TestExplainNamesTheHostWrite: --explain says, in host mode, that an
// approved login replaces the host's refresh token, how many times a run can,
// and that pasting a code inside hands the sandbox one.
func TestExplainNamesTheHostWrite(t *testing.T) {
	env := hostLoginFakeEnv{bridgeFakeEnv: newBridgeEnv(false), state: signedIn, creds: 0o600}
	p := resolveHostBridge(t, env)
	var b bytes.Buffer
	if err := explain(env, &b, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s := strings.Join(strings.Fields(b.String()), " ")
	for _, w := range []string{"REPLACES the refresh token", "at most 3 times per run", "If you paste a code"} {
		if !strings.Contains(s, w) {
			t.Errorf("--explain lacks %q:\n%s", w, b.String())
		}
	}
}
