//go:build integration

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostLoginHome is a scratch account home signed in to a fixture account:
// ~/.claude.json naming it and a ~/.claude/.credentials.json with fixture
// tokens. The host-mode tests never touch the real home: a test that rewrote
// it would spend the human's refresh token.
func hostLoginHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		".claude.json": `{"oauthAccount":{"accountUuid":"acc-1","organizationUuid":"org-1",` +
			`"emailAddress":"fixture@example.com"}}`,
		".claude/.credentials.json": `{"claudeAiOauth":{"accessToken":"FIXTURE-AT-1","refreshToken":"FIXTURE-RT-1",` +
			`"expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"t"}}`,
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// TestHostModeRenewsTheSandboxFileLive fails if a process inside a host-mode
// sandbox does not see the credential snug renews on the host — the test
// renames a new file into this run's credential directory the way snug does —
// at /snug/claude/.credentials.json without a restart, or if it can write,
// rename or unlink anything there. Its first read is the control: the
// projection @claude staged, access token only.
func TestHostModeRenewsTheSandboxFileLive(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f, rt := newLoginFixtureRT(t, "hold")
	f.addProfile(t, "login-host", "[profile.login-host]\ndescription = \"host mode\"\nlogin.claude = \"host\"\n")
	home := hostLoginHome(t)
	env := append(append([]string{}, f.env...), fixtureHome(home)...)
	payload := `cat /snug/claude/.credentials.json > before.out
echo "$CLAUDE_SECURESTORAGE_CONFIG_DIR" > env.out
touch ready
while [ ! -e go ]; do sleep 0.1; done
cat /snug/claude/.credentials.json > after.out
{ touch /snug/claude/x; mv /snug/claude/.credentials.json /snug/claude/y; rm -f /snug/claude/.credentials.json;
  mkdir /snug/claude/.storage-write.lock; } > writes.out 2>&1
exit 0`
	cmd := exec.Command(snugFor(env), "-p", "@claude", "-p", "@net", "-p", "login-host", f.proj, "--",
		"/bin/sh", "-c", payload)
	cmd.Env = env
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill(); <-done })

	ready := filepath.Join(f.proj, "ready")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the payload never became ready:\n%s", log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	matches, _ := filepath.Glob(filepath.Join(rt, "snug", "run-*", "claude", ".credentials.json"))
	if len(matches) != 1 {
		t.Fatalf("want one run credential file under %s, found %v", rt, matches)
	}
	dir := filepath.Dir(matches[0])
	tmp := filepath.Join(dir, ".credentials.json.tmp.test")
	if err := os.WriteFile(tmp, []byte(`{"claudeAiOauth":{"accessToken":"RENEWED-AT"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, matches[0]); err != nil {
		t.Fatal(err)
	}
	handToPayload(t, f.proj, "go", "x")
	select {
	case err := <-done:
		done <- err
		if err != nil {
			t.Fatalf("snug: %v\n%s", err, log.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the payload did not finish:\n%s", log.String())
	}
	read := func(n string) string {
		b, _ := os.ReadFile(filepath.Join(f.proj, n))
		return string(b)
	}
	before := read("before.out")
	if !strings.Contains(before, "FIXTURE-AT-1") || strings.Contains(before, "FIXTURE-RT-1") {
		t.Errorf("control: the first read is not the projection (access token, no refresh token):\n%s", before)
	}
	if got := strings.TrimSpace(read("env.out")); got != "/snug/claude" {
		t.Errorf("CLAUDE_SECURESTORAGE_CONFIG_DIR = %q inside", got)
	}
	if after := read("after.out"); !strings.Contains(after, "RENEWED-AT") {
		t.Errorf("the running sandbox did not see the renewed file:\n%s", after)
	}
	if w := read("writes.out"); strings.Count(w, "Read-only file system") < 3 {
		t.Errorf("the credential directory was writable from inside:\n%s", w)
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json")); !strings.Contains(string(b), "FIXTURE-RT-1") {
		t.Error("the host's credential file changed in a run that completed no login")
	}
}
