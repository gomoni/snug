package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The review artifacts for login.claude = "host": the three screens a human
// reads to learn that approving a login in the browser REWRITES the host's
// ~/.claude/.credentials.json. They are goldens rather than substring checks
// because the wording IS the disclosure: a sentence that drifted to "may
// update" would pass every Contains in hostloginscreens_test.go and be a
// weaker promise to the person approving.
//
// What these cannot catch: they render against a fake host, so they say what
// the screens SAY, not that a real run does what they say. The behaviour is
// held by claudelogin_test.go and test/integration/hostlogin*_test.go.

// hostScreenIdentity matches what a host-mode screen must never carry: an
// email address, a UUID, or a token-shaped string. The fixtures below put an
// email, two uuids and a token in the fake host on purpose, so a screen that
// started echoing the pin or the credential would fail here.
var hostScreenIdentity = regexp.MustCompile(`(?i)[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]+|` +
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|sk-ant-|FIXTURE`)

// hostScreenFakeEnv is a signed-in fake host whose pin names an account the
// screens must not repeat.
func hostScreenFakeEnv() hostLoginFakeEnv {
	return hostLoginFakeEnv{bridgeFakeEnv: newBridgeEnv(false), creds: 0o600,
		state: `{"oauthAccount":{"accountUuid":"11111111-2222-3333-4444-555555555555",` +
			`"organizationUuid":"66666666-7777-8888-9999-000000000000","emailAddress":"pin-fixture@example.test"}}`}
}

func requireNoIdentity(t *testing.T, name, got string) {
	t.Helper()
	if m := hostScreenIdentity.FindString(got); m != "" {
		t.Errorf("%s carries %q, which looks like an email, uuid or token; a screen names fields, "+
			"never the values of the account it renews", name, m)
	}
}

// TestGoldenHostLoginClaudeBlock fails if the paragraph --dry-run's CLAUDE
// block prints for login.claude = "host" changes without a reviewed diff, or
// if it stops being the only difference to the sandbox-mode block, or if it
// names an account.
func TestGoldenHostLoginClaudeBlock(t *testing.T) {
	prev := screenNow
	screenNow = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { screenNow = prev })

	block := func(login *policy.Profile) string {
		p := resolveClaudeLogin(t, login)
		// The credentials arm: the paragraph is printed under the staged
		// projection, and /home/u does not exist, so claudeFiles staged none.
		projected, _, err := policy.ProjectClaudeCredentials([]byte(
			`{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE","refreshToken":"sk-ant-ort-FIXTURE",` +
				`"expiresAt":1767243600000,"refreshTokenExpiresAt":1767225600000,` +
				`"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"default"}}`))
		if err != nil {
			t.Fatalf("control: the real projection refused a host-shaped file: %v", err)
		}
		perm := uint32(0o600)
		p.Replace(policy.Mount{
			Guest: filepath.Join(envGoldenCtx().Home, ".claude", ".credentials.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: projected, Perms: &perm, From: []string{"@claude"},
		})
		if _, ok := claudeCredentialsMount(p); !ok {
			t.Fatal("control: no credentials mount, so the block would print its not-staged arm")
		}
		return captureFile(t, func(f io.Writer) { describeClaude(f, p) })
	}
	host := block(browserLoginHostProfile)
	sandbox := block(browserLoginProfile)

	// Controls: the paragraph is in the host block and only there, so the
	// golden is pinning the arm its name claims.
	if !strings.Contains(host, `login.claude = "host"`) || !strings.Contains(host, "REWRITES") {
		t.Fatalf("control: the host-mode block has no rewrite paragraph:\n%s", host)
	}
	if strings.Contains(sandbox, `login.claude = "host"`) {
		t.Fatalf("control: the sandbox-mode block names host mode:\n%s", sandbox)
	}
	var extra []string
	for _, l := range strings.Split(host, "\n") {
		if !strings.Contains(sandbox, l+"\n") {
			extra = append(extra, l)
		}
	}
	if len(extra) != len(hostLoginLines()) {
		t.Errorf("host mode adds %d lines to the CLAUDE block, want exactly the %d of hostLoginLines:\n%s",
			len(extra), len(hostLoginLines()), strings.Join(extra, "\n"))
	}
	requireNoIdentity(t, "the host-mode CLAUDE block", host)
	goldenText(t, "claude-block-login-host.txt", host)
}

// TestGoldenHostLoginJSON pins the machine document for host mode as a diff
// against the same selection in sandbox mode, the shape
// TestGoldenBrowserBridgeJSON uses against no key at all, so host_rewrite,
// the credential directory bind and CLAUDE_SECURESTORAGE_CONFIG_DIR are the
// review artifact and nothing else may move.
func TestGoldenHostLoginJSON(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	env := hostScreenFakeEnv()
	render := func(on bool) string {
		t.Helper()
		p := resolveBridge(t, env, true)
		if on {
			p = resolveHostBridge(t, env)
		}
		if err := planBrowserFIFO(p, nil); err != nil {
			t.Fatal(err)
		}
		rep := buildReport(env, p, p.BwrapArgs(0, 0), config{json: true}, nil, nil)
		var b bytes.Buffer
		if err := renderJSON(&b, rep); err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(b.String(), runDirName(), "run-PID")
	}
	delta := unifiedLineDiff(render(false), render(true))
	for _, w := range []string{`"host_rewrite": true`, `"claude": "host"`, `"guest": "/snug/claude"`,
		`"name": "CLAUDE_SECURESTORAGE_CONFIG_DIR"`} {
		if !strings.Contains(delta, w) {
			t.Fatalf("control: the host-mode document does not add %s:\n%s", w, delta)
		}
	}
	requireNoIdentity(t, "the host-mode --dry-run --json document", delta)
	goldenText(t, "json.login-host.diff", delta)
}

// TestGoldenProfileShowHostLogin pins `snug profile show` for a user profile
// that sets login.claude = "host", the screen read before selecting it.
func TestGoldenProfileShowHostLogin(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "login-host.toml"), []byte(
		"[profile.login-host]\ndescription = \"complete /login on the host\"\nlogin.claude = \"host\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "show-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = f
	code := profileCmd([]string{"show", "login-host"})
	os.Stdout = orig
	f.Close()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || len(b) == 0 {
		t.Fatalf("`profile show login-host` exited %d and printed %q", code, b)
	}
	got := strings.ReplaceAll(string(b), cfg, "{config}")
	if !strings.Contains(got, "REWRITES ~/.claude/.credentials.json") {
		t.Fatalf("control: the screen has no rewrite disclosure:\n%s", got)
	}
	requireNoIdentity(t, "profile show", got)
	goldenText(t, "show.login-host.txt", got)
}
