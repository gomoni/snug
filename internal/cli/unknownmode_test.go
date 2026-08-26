package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestAnUnknownModeInAProfileIsRefusedNotNarrowed drives `network` and
// `ssh_mode` through the REAL $XDG_CONFIG_HOME profile-load path and asserts
// that a value snug does not implement stops the run.
//
// The parsers have their own tests (policy.TestParseNetModeAcceptsTwoModesAndNothingElse,
// and the ssh arm below), and they assert the parser. This asserts that the
// refusal SURVIVES profile loading, include expansion and Resolve to reach a
// human — the only path a real profile takes, and the one a parser test says
// nothing about. A red-team round named this gap specifically.
//
// WHAT MUST NOT HAPPEN is a silent narrowing. An unrecognised value must be
// REFUSED, never quietly read as the nearest thing it resembles: a sandbox that
// does not match the profile describing it is invariant 5, and a user believing
// a guarantee that does not hold is worse than a failure. So this asserts the
// exit status AND that no policy was described, rather than exit != 0 alone.
//
// IN internal/cli, NOT test/integration, and that placement is the point: issue
// #411's complaint was that a security check could be deleted with `make gate`
// staying green, and a test under the `integration` build tag would leave that
// sentence true. None of this needs a sandbox — the refusal fires while the
// profile is read.
func TestAnUnknownModeInAProfileIsRefusedNotNarrowed(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// Public material only, and not the developer's: it is read and staged,
	// never parsed, so a literal line is enough and nothing here can touch a
	// real ~/.ssh. It exists so the ssh arms reach the MODE check rather than
	// failing earlier on a missing key.
	pub := filepath.Join(home, "decoy.pub")
	if err := os.WriteFile(pub, []byte("ssh-ed25519 AAAA-not-a-real-key decoy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	write := func(t *testing.T, body string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "snug", "profiles.d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "snug", "profiles.d", "p.toml"),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	run := func(t *testing.T) (stdout, stderr string, code int) {
		t.Helper()
		return captureRun(t, config{
			dryRun: true, target: proj, profiles: []policy.ProfileName{"p"},
		})
	}

	for _, tc := range []struct {
		name string
		body string
		// says are fragments the refusal must carry: the offending value, so a
		// reader knows which line of their file is wrong, and the accepted set,
		// so they know what to write instead (CLAUDE.md, "errors name the fix").
		says []string
	}{
		{
			name: "network",
			body: "[profile.p]\nnetwork = \"bridge\"\n",
			says: []string{"bridge", "isolated", "egress"},
		},
		{
			name: "ssh_mode",
			body: "[profile.p]\n[profile.p.identity]\nssh_mode = \"forward-everything\"\n" +
				"ssh_key = \"" + pub + "\"\n",
			says: []string{"forward-everything", "agent-proxy", "none"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(t, tc.body)
			stdout, stderr, code := run(t)
			if code != exitPolicy {
				t.Fatalf("an unknown %s resolved (exit %d, want %d):\n%s\n%s",
					tc.name, code, exitPolicy, stderr, stdout)
			}
			for _, says := range tc.says {
				if !strings.Contains(stderr, says) {
					t.Errorf("the refusal does not say %q by the time it reaches a human, "+
						"so the parser's message is being flattened on the way out:\n%s",
						says, stderr)
				}
			}
			// NO POLICY DESCRIBED. A --dry-run that printed one here would be
			// describing a sandbox the profile did not ask for.
			if strings.Contains(stdout, "FILESYSTEM") {
				t.Errorf("a policy was described for a refused profile:\n%s", stdout)
			}
		})
	}

	// POSITIVE CONTROL, and it is load-bearing: every other way these fixtures
	// can fail (a profile that does not parse, an unreadable ssh_key, a target
	// that does not exist) also exits 77 with a message, so without an arm that
	// RESOLVES the assertions above would pass on a profile that never reached
	// either parser.
	t.Run("the accepted spellings resolve", func(t *testing.T) {
		write(t, "[profile.p]\nnetwork = \"egress\"\n"+
			"[profile.p.identity]\nssh_mode = \"agent-proxy\"\nssh_key = \""+pub+"\"\n")
		stdout, stderr, code := run(t)
		if code != 0 {
			t.Fatalf("the accepted spellings should resolve (exit %d):\n%s", code, stderr)
		}
		if !strings.Contains(stdout, policy.AgentSocketGuest) {
			t.Errorf("agent-proxy resolved with no agent socket in the policy:\n%s", stdout)
		}
	})
}
