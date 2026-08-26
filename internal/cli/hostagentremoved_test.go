package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestHostAgentIsRefusedAndNamesAgentProxy pins the REMOVAL of `ssh_mode =
// "host-agent"` (issue #411).
//
// The ticket asked for a test of the `--i-know` gate that guarded the mode:
// the gate was implemented and had no test, so deleting the `if !iKnow` block
// left `make gate` green. The maintainer's answer was to delete the MODE
// instead, and the reason generalises past this one flag — a capability whose
// entire safety is a CLI flag is a capability people and agents will find and
// pass the flag to. host-agent carried nothing agent-proxy does not: both
// reach the host's already-unlocked agent, and only one bounds which key
// answers. See ParseSSHMode for the refusal's own account.
//
// WHAT MUST NOT HAPPEN is a silent downgrade. A profile still saying
// `host-agent` must be REFUSED, not quietly resolved as agent-proxy (no
// pinned key) or as none — CLAUDE.md invariant 5 binds a removal exactly as
// it binds an unavailable capability, and a user believing a guarantee that
// no longer holds is worse than a failure. So this asserts the exit status
// AND that the mode is named AND that nothing resolved, rather than exit != 0
// alone.
//
// IT LIVES IN internal/cli, NOT test/integration, and that placement is the
// point rather than a detail. #411's complaint was literally that `make gate`
// stays green when the enforcement is deleted; the same test under the
// `integration` build tag would leave that sentence true. The refusal needs no
// sandbox — it fires in ParseSSHMode, while the profile is being read.
func TestHostAgentIsRefusedAndNamesAgentProxy(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// Public material only, and not the developer's: the file is staged and
	// read, never parsed, so a literal line is enough and nothing here can
	// touch a real ~/.ssh. It exists so the positive control below reaches
	// agent-proxy's OWN requirements rather than failing on a missing key.
	pub := filepath.Join(home, "decoy.pub")
	if err := os.WriteFile(pub, []byte("ssh-ed25519 AAAA-not-a-real-key decoy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	profile := func(t *testing.T, mode string) {
		t.Helper()
		cfg := t.TempDir()
		if err := os.MkdirAll(filepath.Join(cfg, "snug", "profiles.d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg, "snug", "profiles.d", "p.toml"), []byte(
			"[profile.pinned]\n"+
				"description = \"one throwaway key\"\n"+
				"[profile.pinned.identity]\n"+
				"ssh_mode = \""+mode+"\"\n"+
				"ssh_key = \""+pub+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", cfg)
	}

	cfg := config{dryRun: true, target: proj, profiles: []policy.ProfileName{"pinned"}}

	t.Run("host-agent", func(t *testing.T) {
		profile(t, "host-agent")
		stdout, stderr, code := captureRun(t, cfg)
		if code != exitPolicy {
			t.Fatalf("ssh_mode = \"host-agent\" resolved (exit %d, want %d):\n%s\n%s",
				code, exitPolicy, stderr, stdout)
		}
		// Named, not "unknown ssh_mode": a profile written when the mode
		// existed deserves to be told what happened to it and what to write
		// instead, which is CLAUDE.md's "errors name the fix". Without this
		// the test passes on a typo'd mode.
		for _, says := range []string{"host-agent", "removed", "agent-proxy"} {
			if !strings.Contains(stderr, says) {
				t.Errorf("the refusal does not say %q, so it is not the removal talking:\n%s",
					says, stderr)
			}
		}
		// NO SILENT DOWNGRADE: nothing may have resolved. A --dry-run that
		// printed a policy here would be one describing a sandbox the profile
		// did not ask for.
		if strings.Contains(stdout, "FILESYSTEM") {
			t.Errorf("a policy was described for a refused mode:\n%s", stdout)
		}
		// And --i-know must not resurrect it. This is the assertion that
		// distinguishes "removed" from "gated", and it is the whole subject:
		// the flag still exists for @net-host, so a reader — or an agent —
		// reaching for it here must get the same refusal.
		known := cfg
		known.iKnow = true
		if _, stderr, code := captureRun(t, known); code != exitPolicy {
			t.Errorf("--i-know brought host-agent back (exit %d):\n%s", code, stderr)
		}
	})

	// POSITIVE CONTROL, and it is load-bearing: every other way this fixture
	// can fail (a profile that does not parse, an unreadable ssh_key, a target
	// that does not exist) also exits 77 with a message, so without an arm
	// that RESOLVES, the assertions above would pass on a profile that never
	// reached ParseSSHMode at all.
	t.Run("agent-proxy still resolves", func(t *testing.T) {
		profile(t, "agent-proxy")
		stdout, stderr, code := captureRun(t, cfg)
		if code != 0 {
			t.Fatalf("agent-proxy should resolve (exit %d):\n%s", code, stderr)
		}
		if !strings.Contains(stdout, policy.AgentSocketGuest) {
			t.Errorf("agent-proxy resolved with no agent socket in the policy:\n%s", stdout)
		}
	})
}
