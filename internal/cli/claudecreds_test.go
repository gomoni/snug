package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// writeHostCredential plants a ~/.claude/.credentials.json in a fake home and
// returns the home. Nothing here reads the developer's real one: a test that
// depended on a live token would pass or fail by accident of who ran it.
func writeHostCredential(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func stagedCredential(t *testing.T, home string) (policy.Mount, bool) {
	t.Helper()
	p := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: home}
	stageClaudeCredentials(p, home)
	m, ok := p.Mounts[filepath.Join(home, ".claude", ".credentials.json")]
	return m, ok
}

// TestAnUnreadableCredentialIsNotStagedVerbatim is the regression for the one
// failure mode that would silently undo issue #58.
//
// Before this change the staging path was "read the host file, mount its
// bytes". If a projection is ever added in front of that and then FAILS OPEN —
// falls through to the old path on a parse error, which is the natural way to
// write it — the sandbox gets the refresh token back with nothing on screen to
// say so. Nothing else in the tree would notice: the file would be present,
// Claude Code would work, and every other test would pass.
//
// POSITIVE CONTROL: the same function, same fake home, with a GOOD file must
// stage something. Otherwise "nothing was staged" passes on a
// stageClaudeCredentials that stopped working entirely.
func TestAnUnreadableCredentialIsNotStagedVerbatim(t *testing.T) {
	const marker = "sk-ant-ort-MUST-NOT-APPEAR"

	// CONTROL first, so a failure below cannot be "the function does nothing".
	good := writeHostCredential(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE",`+
		`"refreshToken":"`+marker+`"}}`)
	m, ok := stagedCredential(t, good)
	if !ok {
		t.Fatal("control: a well-formed host credential staged NOTHING, so the assertions " +
			"below would pass on a function that had stopped running")
	}
	if strings.Contains(string(m.Content), marker) {
		t.Errorf("the staged credential carries the host's refresh token (issue #58):\n%s", m.Content)
	}

	// Now the failure modes. Each is a file that EXISTS and does not project.
	for name, body := range map[string]string{
		"truncated":        `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIX`,
		"wrong envelope":   `{"anthropic":{"accessToken":"x","refreshToken":"` + marker + `"}}`,
		"no access token":  `{"claudeAiOauth":{"refreshToken":"` + marker + `"}}`,
		"not JSON at all":  marker,
		"array not object": `["` + marker + `"]`,
	} {
		t.Run(name, func(t *testing.T) {
			home := writeHostCredential(t, body)
			m, ok := stagedCredential(t, home)
			if ok {
				t.Fatalf("an unprojectable host credential was staged anyway. If those bytes "+
					"are the host's, the refresh token is back in the sandbox and nothing "+
					"says so (issue #58):\n%s", m.Content)
			}
		})
	}
}

// TestNoCredentialFileStagesNothingQuietly keeps the two silences apart, which
// is the distinction stageClaudeCredentials's doc comment turns on: "the host
// has nothing to stage" is an ordinary state and says nothing, while "the file
// is there and did not project" warns. This pins the first half; the test above
// pins that the second half does not stage. Both must leave the policy empty.
func TestNoCredentialFileStagesNothingQuietly(t *testing.T) {
	home := t.TempDir() // no ~/.claude at all
	if m, ok := stagedCredential(t, home); ok {
		t.Fatalf("a host with no credentials file got one anyway:\n%s", m.Content)
	}
}

// TestTheStagedCredentialIsWritableAndPrivate: Claude Code rewrites this file
// when it refreshes, so a read-only copy fails the same way gh's hosts.yml did
// (identity.go). It is a private tmpfs copy, so the write reaches nothing the
// host can see — and 0600 because the mode is what the file would have on the
// host, not something to relax because the tmpfs is private.
func TestTheStagedCredentialIsWritableAndPrivate(t *testing.T) {
	home := writeHostCredential(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE"}}`)
	m, ok := stagedCredential(t, home)
	if !ok {
		t.Fatal("nothing was staged")
	}
	if m.Access != policy.AccessRW {
		t.Errorf("the staged credential is %v, not writable — Claude Code rewrites this file "+
			"on refresh and a read-only copy fails the way gh's hosts.yml did", m.Access)
	}
	if m.Kind != policy.KindData {
		t.Errorf("the staged credential is %v, not KindData — it is generated content, not a "+
			"bind of a host path", m.Kind)
	}
	if m.Perms == nil || *m.Perms != 0o600 {
		t.Errorf("the staged credential's mode is %v, want 0600", m.Perms)
	}
}

// TestAnExpiredTokenIsNamedBeforeTheRun is the ergonomic regression this change
// introduces, made legible rather than left to be discovered.
//
// @claude + @net + a host token close to expiry is now a HARD failure where the
// refresh used to recover quietly, because nothing inside the sandbox can renew
// a credential any more. That is a real cost, and CLAUDE.md's rule is that
// errors name the fix — so it is said on the host, before the run, rather than
// surfacing as an auth error from inside a sandbox.
//
// The token is still staged. MEASURED (claude 2.1.232): an already-expired
// credential served a full session offline and expiry passing mid-run did
// nothing, so withholding it would break working sessions to prevent a failure
// that may not happen.
func TestAnExpiredTokenIsNamedBeforeTheRun(t *testing.T) {
	expired := writeHostCredential(t,
		`{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE","expiresAt":1000000000000}}`)

	var m policy.Mount
	var ok bool
	out := captureStderr(t, func() { m, ok = stagedCredential(t, expired) })

	if !ok {
		t.Fatal("an expired token was not staged. It must be: an expired credential still " +
			"serves an offline session, so withholding it breaks a working case to prevent " +
			"a failure that may not happen")
	}
	if !strings.Contains(string(m.Content), "sk-ant-oat-FIXTURE") {
		t.Errorf("the staged content is not the projected credential:\n%s", m.Content)
	}
	for _, want := range []string{"expired", "refresh token", "claude"} {
		if !strings.Contains(strings.ToLower(out), want) {
			t.Errorf("the expiry notice does not mention %q, so it does not name the fix:\n%s", want, out)
		}
	}

	// CONTROL: a token that has NOT expired says nothing. Without this the
	// assertions above would pass on a notice printed unconditionally, which
	// would train a reader to ignore it — the one outcome that makes the
	// warning worse than none.
	fresh := writeHostCredential(t,
		`{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE","expiresAt":4102444800000}}`)
	quiet := captureStderr(t, func() { stagedCredential(t, fresh) })
	if strings.Contains(strings.ToLower(quiet), "expired") {
		t.Errorf("a token with years left was reported as expired:\n%s", quiet)
	}
}
