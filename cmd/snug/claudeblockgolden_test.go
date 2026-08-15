package main

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
// TWO GOLDENS, because two lines of this block are conditional and each has two
// arms. Between them the pair pins all four:
//
//	claude-block.txt          host has NOT trusted the target, and
//	                          ~/.claude/settings.json is not bound (no host file)
//	claude-block-trusted.txt  host HAS trusted this exact path, and the
//	                          settings.json bind is present
//
// Pairing the arms this way rather than writing four goldens keeps the review
// artifact to two files while leaving no rendered sentence unpinned; each arm's
// condition is also asserted directly below, so a swap cannot pass by accident.
func TestGoldenClaudeBlock(t *testing.T) {
	t.Run("untrusted target, settings.json not bound", func(t *testing.T) {
		goldenClaudeBlock(t, "claude-block.txt", false, false)
	})
	t.Run("host-trusted target, settings.json bound read-only", func(t *testing.T) {
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
		plain, err := policy.Resolve(map[string]*policy.Profile(reg), profile.BuiltinDefaults(), ctx, newEnvFakeEnv())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		claudeFiles(plain, ctx.Home)
		if got := captureFile(t, func(f *os.File) { describeClaude(f, plain) }); got != "" {
			t.Errorf("the CLAUDE block printed for a selection without @claude:\n%s", got)
		}
	})
}

func goldenClaudeBlock(t *testing.T, name string, hostTrusts, bindSettings bool) {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := append(append([]string{}, profile.BuiltinDefaults()...), "@claude")
	ctx := envGoldenCtx()
	fake := newEnvFakeEnv()
	if bindSettings {
		// @claude marks this bind `optional`, so it is in the policy only on a
		// host that has the file. The fake host is mutated per call rather than in
		// newEnvFakeEnv: every other golden in this package shares that fixture,
		// and adding a path there would move goldens this change has no business
		// touching.
		fake.dirs["/home/u/.claude/settings.json"] = true
	}
	p, err := policy.Resolve(map[string]*policy.Profile(reg), sel, ctx, fake)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The real staging code, against the fake host's home. /home/u does not
	// exist, so the credentials copy is skipped and the generated file lands with
	// no trust entry — which IS the untrusted arm, reached the way a real host
	// reaches it rather than by poking the policy.
	claudeFiles(p, ctx.Home)

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

	// CONTROL: the block only means something if the mount it describes is
	// really in the policy. Without this the golden could be pinning the empty
	// string after a refactor silently stopped generating the file.
	m, ok := p.Mounts[filepath.Join(ctx.Home, ".claude.json")]
	if !ok {
		t.Fatal("control: nothing was staged at ~/.claude.json, so this golden pins nothing")
	}
	// CONTROL: each arm is in the state it says it is. Otherwise a bug that made
	// claudeTrustCarried or claudeSettingsBound always answer the same way would
	// leave two goldens quietly pinning one arm twice.
	if got := claudeTrustCarried(p, m); got != hostTrusts {
		t.Fatalf("control: claudeTrustCarried = %v, want %v — this golden is not pinning "+
			"the arm it names", got, hostTrusts)
	}
	if got := claudeSettingsBound(p); got != bindSettings {
		t.Fatalf("control: claudeSettingsBound = %v, want %v — this golden is not pinning "+
			"the arm it names", got, bindSettings)
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
		t.Fatalf("%v (run: go test ./cmd/snug -update)", err)
	}
	if got != string(want) {
		t.Errorf("the CLAUDE block changed. Read this diff as a change to what snug "+
			"pre-answers on the human's behalf, not as a wording tweak.\n--- got\n%s\n--- want\n%s",
			got, want)
	}
}
