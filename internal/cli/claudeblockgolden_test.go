package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// The review artifact for --dry-run's CLAUDE block.
//
// Why a golden of ONE block rather than of the whole screen: there is no
// full --dry-run golden in this package. testdata/env.*.txt covers the
// ENVIRONMENT block, topology.*.txt the TOPOLOGY block, seccomp.*.txt the
// SECCOMP block — each resolved against the REAL builtin profiles with a fake
// host, so the file is stable and reviewable. This follows that pattern rather
// than inventing a second one.
//
// What the diff is for: this block is the only place on the screen that says
// whether snug pre-answered Claude Code's "do you trust this folder" prompt. The
// FILESYSTEM row cannot say it — Mount.Content is a policy.Secret and renders
// redacted by design — so a change to the generated file's key list that did not
// change this text would be a change to what snug decides on the human's behalf
// with no artifact to read. CLAUDE.md: a security change that produces no golden
// diff is probably untested.
//
// TWO GOLDENS. ~/.claude.json's trust line is still conditional (one line, two
// arms — issue #19); ~/.claude/settings.json is UNCONDITIONAL now (issue #17:
// it is generated on every host, never bound), so what varies about it between
// the two goldens is no longer WHETHER it exists but WHAT IT CARRIED, and only
// the second case bothers to exercise that — the first is the plain "host had
// nothing to carry" shape stageClaudeSettings produces against a host with no
// file at all.
//
//	claude-block.txt          host has NOT trusted the target; no settings
//	                          were carried (nothing on the fake host to carry)
//	claude-block-trusted.txt  host HAS trusted this exact path, AND its
//	                          settings.json exercises the filter: some keys
//	                          carried, some (consequential) keys dropped
//
// Pairing the arms this way rather than writing four goldens keeps the review
// artifact to two files while leaving no rendered sentence unpinned; each arm's
// condition is also asserted directly below, so a swap cannot pass by accident.
func TestGoldenClaudeBlock(t *testing.T) {
	t.Run("untrusted target, nothing carried into settings.json", func(t *testing.T) {
		goldenClaudeBlock(t, "claude-block.txt", false, false)
	})
	t.Run("host-trusted target, settings.json filter exercised", func(t *testing.T) {
		goldenClaudeBlock(t, "claude-block-trusted.txt", true, true)
	})

	t.Run("no @claude, no block", func(t *testing.T) {
		// CONTROL: a block that always prints says nothing about the condition it
		// is gated on — and it would then appear on every sandbox, including the
		// ones where snug decided nothing.
		reg, err := profile.Builtins()
		if err != nil {
			t.Fatal(err)
		}
		ctx := envGoldenCtx()
		plain, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(), ctx, newEnvFakeEnv())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		claudeFiles(plain, ctx.Home, false)
		if got := captureFile(t, func(f *os.File) { describeClaude(f, plain) }); got != "" {
			t.Errorf("the CLAUDE block printed for a selection without @claude:\n%s", got)
		}
	})
}

func goldenClaudeBlock(t *testing.T, name string, hostTrusts, exerciseSettingsFilter bool) {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude")
	ctx := envGoldenCtx()
	fake := newEnvFakeEnv()
	// No `fake.dirs["/home/u/.claude/settings.json"]` any more, and its absence is
	// the point of issue #17 rather than a tidy-up: that line existed to make the
	// `optional` BIND appear in the policy, and there is no bind to make appear.
	// The mount is unconditional and authored, so the fake host needs to say
	// nothing about the path at all.
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, fake)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The real staging code, against the fake host's home. /home/u does not
	// exist, so the credentials copy is skipped, the ~/.claude.json trust entry
	// is absent, and stageClaudeSettings' own host read comes back "absent" too
	// — settings.json is staged with an empty allowlisted set ("{}\n"). That IS
	// the untrusted arm, reached the way a real host reaches it rather than by
	// poking the policy.
	claudeFiles(p, ctx.Home, false)

	if hostTrusts {
		// The trusted arm, produced by the REAL generator against a REAL host file
		// that records this exact path. Only the host home is faked out (the
		// golden's ctx.Home does not exist on any machine); the decision, the
		// lookup and the bytes are claudeStateJSON's own.
		hostHome := t.TempDir()
		body := []byte(`{"projects":{"` + ctx.Target + `":{"hasTrustDialogAccepted":true}}}`)
		if err := os.WriteFile(filepath.Join(hostHome, ".claude.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		gen := claudeStateJSON(p, hostHome)
		if !strings.Contains(string(gen), "hasTrustDialogAccepted") {
			t.Fatalf("control: the generator produced no trust entry for a host that trusts "+
				"%q, so this arm would silently golden the untrusted block:\n%s",
				ctx.Target, gen)
		}
		perm := uint32(0o600)
		p.Replace(policy.Mount{
			Guest: filepath.Join(ctx.Home, ".claude.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(gen),
			Perms: &perm, From: []string{"@claude"},
		})
	}

	if exerciseSettingsFilter {
		// The filter arm, produced by the REAL filter (policy.FilterClaudeSettings,
		// policy.ClaudeSettingsJSON) against a document shaped like a host's, built
		// in memory rather than written to ctx.Home (which does not exist on any
		// machine, same reason the trust arm above uses a separate temp directory
		// instead). One carried key, one dropped-and-catalogued key, one key on
		// NEITHER catalogue: enough to show all three lines of the disclosure
		// without turning the golden into a second copy of
		// TestClaudeSettingsFilterDropsEveryExecutingKey. The third is the
		// regression fixture for the defect this golden exists to pin: a
		// dropped key on no list was previously reported nowhere.
		raw := map[string]any{
			"theme": "dark", "apiKeyHelper": "/bin/cat /etc/passwd",
			"someFuturePreference": true,
		}
		carried, drops := policy.FilterClaudeSettings(raw)
		if _, ok := carried["theme"]; !ok {
			t.Fatal("control: the filter dropped `theme`, a positive control this fixture " +
				"depends on to show a non-empty `carried:` line")
		}
		if len(drops.Executing) == 0 {
			t.Fatal("control: the filter did not report `apiKeyHelper` as a dropped executing " +
				"key, so this arm would silently golden the same `carried: (none)` shape as " +
				"the untrusted case above")
		}
		if len(drops.Unknown) == 0 {
			t.Fatal("control: the filter did not report `someFuturePreference` as an unknown " +
				"key, so this arm would not exercise the class this golden exists to pin")
		}
		// stageClaudeSettings sets this on the Policy REGARDLESS of -v (see its
		// own comment); this fixture does the same rather than going through
		// stageClaudeSettings itself, for the same reason the trust arm above
		// builds its mount by hand instead of calling claudeFiles a second time.
		p.ClaudeSettingsUnknown = drops.Unknown
		perm := uint32(0o600)
		p.Replace(policy.Mount{
			Guest: filepath.Join(ctx.Home, ".claude", "settings.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(policy.ClaudeSettingsJSON(carried)),
			Perms: &perm, From: []string{"@claude"},
		})
	}

	// CONTROL: the block only means something if the mount it describes is
	// really in the policy. Without this the golden could be pinning the empty
	// string after a refactor silently stopped generating the file.
	m, ok := p.Mounts[filepath.Join(ctx.Home, ".claude.json")]
	if !ok {
		t.Fatal("control: nothing was staged at ~/.claude.json, so this golden pins nothing")
	}
	if _, ok := claudeSettingsMount(p); !ok {
		t.Fatal("control: nothing was staged at ~/.claude/settings.json — it is UNCONDITIONAL " +
			"now (issue #17), so its absence here means stageClaudeSettings silently stopped " +
			"running rather than that this arm has nothing to say")
	}
	// CONTROL: each arm is in the state it says it is. Otherwise a bug that made
	// claudeTrustCarried always answer the same way would leave two goldens
	// quietly pinning one arm twice.
	if got := claudeTrustCarried(p, m); got != hostTrusts {
		t.Fatalf("control: claudeTrustCarried = %v, want %v — this golden is not pinning "+
			"the arm it names", got, hostTrusts)
	}

	got := captureFile(t, func(f *os.File) { describeClaude(f, p) })
	if !strings.Contains(got, ctx.Target) {
		t.Fatalf("the block does not name the target, which is the ONE variable in the "+
			"generated file and the whole scope of the trust decision:\n%s", got)
	}

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the CLAUDE block changed. Read this diff as a change to what snug "+
			"pre-answers on the human's behalf, not as a wording tweak.\n--- got\n%s\n--- want\n%s",
			got, want)
	}
}
