package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

// TestTheCredsBlockNeverDeniesACredentialItStaged is the regression for the
// red-team finding that mattered most, because of the DIRECTION it failed in:
// --dry-run printed "creds NOT staged … LOGGED OUT" while the same screen's
// mount table and bwrap argv showed the access token being handed over. A trust
// artifact asserting the ABSENCE of a credential that is present is worse than
// one that says nothing.
//
// The cause was claudeCredentialsMount keying on an exact p.Home match with no
// Authored check and no fallback — four hundred lines below two siblings that
// both carry those guards under a comment stating the measured reason: Resolve
// canonicalises $HOME while claudeFiles is handed the raw os.UserHomeDir()
// value, so on a host whose home is a symlink (/home -> /var/home, the default
// on Silverblue-shaped systems) the key misses.
//
// CONTROL: a policy with NO credential mount must still reach the other arm.
// Otherwise "the block says PROJECTED" would pass on a lookup that had been
// made unconditionally true.
func TestTheCredsBlockNeverDeniesACredentialItStaged(t *testing.T) {
	home := writeHostCredential(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE"}}`)

	// The split the bug lived in: the policy's Home is the CANONICAL path,
	// while the staging ran against the path the user's $HOME actually named.
	canonical := filepath.Join(home, "canonical")
	if err := os.MkdirAll(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: canonical}
	stageClaudeCredentials(p, home) // staged under `home`, not `canonical`

	out := captureFile(t, func(f io.Writer) { describeCredsOnly(t, f, p) })
	if strings.Contains(out, "staged NOTHING") {
		t.Errorf("the CLAUDE block denies a credential that IS in the policy. On a host whose "+
			"$HOME is a symlink this screen tells the reader they are logged out while the "+
			"access token is handed over:\n%s", out)
	}
	if !strings.Contains(out, "PROJECTED") {
		t.Errorf("the block does not describe the staged credential at all:\n%s", out)
	}

	// CONTROL: nothing staged reaches the other arm.
	empty := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: canonical}
	quiet := captureFile(t, func(f io.Writer) { describeCredsOnly(t, f, empty) })
	if !strings.Contains(quiet, "staged NOTHING") {
		t.Errorf("control: a policy with no credential mount did not reach the NOT-staged "+
			"arm, so the assertion above cannot distinguish the two:\n%s", quiet)
	}
}

// describeCredsOnly renders just the two credential lines, by asking
// claudeCredentialsMount the same question describeClaude asks. describeClaude
// itself needs a ~/.claude.json mount to print anything at all, which this test
// is not about.
func describeCredsOnly(t *testing.T, f io.Writer, p *policy.Policy) {
	t.Helper()
	if m, ok := claudeCredentialsMount(p); ok {
		when, _ := claudeCredentialExpiry(m, time.Now())
		fmt.Fprintf(f, "PROJECTED %s\n", when)
		return
	}
	fmt.Fprintln(f, "staged NOTHING")
}

// TestTheCredentialRefusalCannotForgeALine: the refusal renders the host file's
// top-level KEY NAMES, and it goes to a terminal. A red-team pass planted a key
// carrying ESC[2A and a carriage return, and watched the real refusal line be
// ERASED and replaced by a fabricated "credentials projected normally;
// refreshToken dropped".
//
// Not payload-reachable — it is the host user's own file — so this is screen
// integrity rather than an escape. It is asserted anyway because the rule is to
// name every sink a value reaches and assert the SET rather than the site, and
// this sink sat outside the set: TestNoSnugScreenEmitsARawControlCharacter
// drives dryRun's STDOUT, while this message is stderr, written before dry-run
// renders anything.
//
// CONTROL: an ordinary key name must still appear readably. A guard that
// escaped everything, or printed nothing, would pass a check for "no ESC".
func TestTheCredentialRefusalCannotForgeALine(t *testing.T) {
	// The escapes are \u001b and \r AS JSON SOURCE, not raw bytes, and that
	// detail is the attack rather than a stylistic choice: Go's decoder REFUSES
	// a raw control character inside a string literal, so a fixture carrying
	// one never reaches the key list — it fails at the top-level parse and the
	// test proves nothing. The escaped form decodes to the same real ESC and CR
	// in the key NAME. (Written wrong the first time here, and the mutation
	// test is what said so: deleting the guard did not fail this test.)
	hostile := `{"x\u001b[2A\u001b[2K\rsnug: FORGED":1}`
	home := writeHostCredential(t, hostile)

	out := captureStderr(t, func() { stagedCredential(t, home) })

	for _, forging := range []string{"\x1b", "\r"} {
		// The message's own newlines are fine; a CR or ESC is not — those are
		// what move the cursor and erase what a human already read.
		if strings.Contains(out, forging) {
			t.Errorf("the refusal emitted a raw %q, so a crafted key name can move the cursor "+
				"and rewrite lines above it:\n%q", forging, out)
		}
	}
	if !strings.Contains(out, "not staging") {
		t.Fatalf("control: no refusal was printed at all, so the check above examined "+
			"nothing:\n%s", out)
	}

	// CONTROL: an ordinary name still renders.
	plain := writeHostCredential(t, `{"someOtherKey":1}`)
	readable := captureStderr(t, func() { stagedCredential(t, plain) })
	if !strings.Contains(readable, "someOtherKey") {
		t.Errorf("an ordinary key name did not survive the escaping, so the refusal no longer "+
			"tells the reader what it found:\n%s", readable)
	}
}

// TestAHostCredentialSnugCannotReadIsRefusedLoudly is the third red-team
// finding: the read was a bare os.ReadFile, while the settings loader 260 lines
// below already carried O_NONBLOCK, an IsRegular check and a LimitReader, each
// with the measurement that earned it. The same rule, applied to one of its two
// halves.
//
// Measured on the unfixed code: a FIFO at this path hung in open(2) FOREVER —
// no sandbox, no exit code, no line on any screen — and /dev/zero through a
// symlink reached 8.4 GB resident in six seconds. The FIFO case is the worse
// one: it produces no output and never returns, which is the opposite of the
// legibility this function's own doc comment promises.
//
// CONTROL: an ordinary regular file must still stage, so "refused" is not the
// answer to everything.
func TestAHostCredentialSnugCannotReadIsRefusedLoudly(t *testing.T) {
	t.Run("a FIFO is refused rather than opened", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".claude")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(dir, ".credentials.json"), 0o600); err != nil {
			t.Skipf("SKIP: cannot create a FIFO here: %v", err)
		}

		// The whole point is that this RETURNS. On the unfixed code the test
		// binary would hang here until the go test timeout killed it.
		done := make(chan string, 1)
		go func() {
			done <- captureStderr(t, func() { stagedCredential(t, home) })
		}()
		select {
		case out := <-done:
			if !strings.Contains(out, "not a regular file") {
				t.Errorf("a FIFO was refused for the wrong reason, or silently:\n%s", out)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("stageClaudeCredentials did not return on a FIFO at the credentials path: " +
				"it is blocked in open(2), which is the failure with no output and no exit")
		}
	})

	t.Run("an oversized file is refused rather than read", func(t *testing.T) {
		home := writeHostCredential(t, strings.Repeat("A", maxCredentialsBytes+1))
		out := captureStderr(t, func() {
			if m, ok := stagedCredential(t, home); ok {
				t.Errorf("an oversized credential file was staged:\n%d bytes", len(m.Content))
			}
		})
		if !strings.Contains(out, "cap") {
			t.Errorf("an oversized file was not refused by the cap:\n%s", out)
		}
	})

	t.Run("CONTROL: an ordinary file still stages", func(t *testing.T) {
		home := writeHostCredential(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE"}}`)
		if _, ok := stagedCredential(t, home); !ok {
			t.Fatal("control: an ordinary regular credential file was refused too, so the " +
				"refusals above are not discriminating anything")
		}
	})
}
