package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// TestSnugsOwnSignaturePolicyIsNotStricterThanItself is the cross-check that
// keeps P8 honest, and it is the reason engine.SignaturePolicyJSON is
// exported at all.
//
// P8 exists to say "snug's generated policy is WEAKER than yours". If its
// notion of permissive ever stopped matching what engine.go actually writes,
// the notice would fire on every run (crying wolf about a downgrade that did
// not happen — the exact defect issue #112 was) or, worse, the comparison
// would drift the other way and stop firing when it should.
func TestSnugsOwnSignaturePolicyIsNotStricterThanItself(t *testing.T) {
	strict, err := signaturePolicyIsStricterThanSnugs([]byte(engine.SignaturePolicyJSON))
	if err != nil {
		t.Fatalf("P8 cannot parse the policy snug itself writes: %v", err)
	}
	if strict {
		t.Fatal("P8 reads snug's own generated policy as stricter than snug's own generated " +
			"policy, so every run with an engine would announce a downgrade that did not happen")
	}
}

// TestAStricterHostSignaturePolicyIsNoticed is invariant 5 applied to the one
// file snug took over by CONTENT rather than by pointing an environment
// variable at it (issue #137).
//
// The negative case is the one that carries the risk: a host file that
// already accepts anything must NOT produce a notice, because a warning that
// fires on every ordinary host is a warning nobody reads by the time it
// matters.
func TestAStricterHostSignaturePolicyIsNoticed(t *testing.T) {
	cases := []struct {
		name       string
		policy     string
		wantStrict bool
		wantErr    bool
	}{{
		name:   "podman's own default",
		policy: `{"default":[{"type":"insecureAcceptAnything"}]}`,
	}, {
		name:       "signatures required by default",
		policy:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/etc/pki/k.gpg"}]}`,
		wantStrict: true,
	}, {
		name:       "everything rejected by default",
		policy:     `{"default":[{"type":"reject"}]}`,
		wantStrict: true,
	}, {
		// The default is permissive and a TRANSPORT tightens it. Reading only
		// `default` would call this file permissive and stay silent about a
		// real downgrade.
		name: "a transport is stricter than the default",
		policy: `{"default":[{"type":"insecureAcceptAnything"}],
		          "transports":{"docker":{"registry.example.internal":[{"type":"sigstoreSigned"}]}}}`,
		wantStrict: true,
	}, {
		// A requirement type this code has never heard of is still not
		// insecureAcceptAnything, so it counts as stricter rather than being
		// silently ignored.
		name:       "a requirement type snug does not know",
		policy:     `{"default":[{"type":"someFutureRequirement"}]}`,
		wantStrict: true,
	}, {
		name:    "not JSON at all",
		policy:  `this is not a policy`,
		wantErr: true,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strict, err := signaturePolicyIsStricterThanSnugs([]byte(tc.policy))
			if tc.wantErr {
				if err == nil {
					t.Fatal("a policy.json snug cannot parse reported no error, so the run would " +
						"say nothing at all about a file it could not compare against")
				}
				if !strings.Contains(err.Error(), "could not parse") {
					t.Errorf("the error does not say what went wrong: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strict != tc.wantStrict {
				t.Errorf("stricter = %v, want %v", strict, tc.wantStrict)
			}
		})
	}
}

// TestTheInjectedGuidanceNamesTheImageProvenanceRules is the third site rule
// applied to issues #137 and #142: a fact that changes what an agent should do
// belongs in the file the agent reads, not only in --dry-run and a comment.
//
// Both consequences produce errors that look like breakage — a short name that
// resolves nowhere, a registry that refuses to authenticate — and an agent
// that has not been told will spend turns "fixing" them, which for the second
// one means trying to log in with credentials it should never be given.
//
// The negative arm is not a formality: the section must be absent when no
// engine is selected, or the guidance would describe a capability the run does
// not have, which is the same defect as claiming one it does.
func TestTheInjectedGuidanceNamesTheImageProvenanceRules(t *testing.T) {
	withEngine := string(claudeGuidance(resolveFor(t,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude", "@podman-socket"})))
	for _, want := range []string{"docker.io", "no registry credentials"} {
		if !strings.Contains(strings.ToLower(withEngine), strings.ToLower(want)) {
			t.Errorf("the injected guidance never says %q, so an agent meets an unresolvable "+
				"short name or an auth failure with no idea it is the design:\n%s", want, withEngine)
		}
	}

	withoutEngine := string(claudeGuidance(resolveFor(t,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"})))
	if strings.Contains(withoutEngine, "## Containers") {
		t.Errorf("the injected guidance has a Containers section on a run with no engine:\n%s",
			withoutEngine)
	}
}

// TestTheSignaturePolicyNoticeCannotForgeALine is the same assertion issue
// #58's third red-team finding earned for the credential refusal, applied to
// the sink P8 adds: a stderr message that renders a host file's own content.
//
// A policy.json whose parse error carries ESC and CR would otherwise erase the
// notice a human just read and write a reassuring one over it. Not
// payload-reachable — it is the host user's file — so this is screen integrity
// rather than an escape, and it is asserted because the rule is to name every
// sink the value reaches.
//
// CONTROL: an ordinary detail must still render readably. A guard that escaped
// everything, or printed nothing, would pass a check for "no ESC".
func TestTheSignaturePolicyNoticeCannotForgeALine(t *testing.T) {
	hostile := &signaturePolicyNotice{
		Path:   "/home/u/.config/containers/policy.json\x1b[2A\x1b[2K\r",
		Detail: "snug: images ARE verified\r\x1b[1A",
	}
	got := hostile.String()
	for _, forging := range []string{"\x1b", "\r"} {
		if strings.Contains(got, forging) {
			t.Errorf("the P8 notice emitted a raw %q, so a crafted host policy.json can move "+
				"the cursor and rewrite the lines above it:\n%q", forging, got)
		}
	}

	plain := &signaturePolicyNotice{
		Path:   "/etc/containers/policy.json",
		Detail: "it requires images to satisfy a signature policy, and snug's does not",
	}
	readable := plain.String()
	for _, want := range []string{"/etc/containers/policy.json", "signature policy"} {
		if !strings.Contains(readable, want) {
			t.Errorf("an ordinary notice lost %q in the escaping, so it no longer tells the "+
				"reader which file it means:\n%s", want, readable)
		}
	}
}

// TestP8DoesNotHangOnAFifoPolicyFile is the hardened-read half, and the reason
// P8 does not use os.ReadFile.
//
// Measured on the credential path (issue #58, third red-team finding): a FIFO
// blocks in open(2) forever — no sandbox, no exit code, nothing on any screen.
// A PREFLIGHT probe that can hang is worse than no probe, because it hangs
// before anything has started and with no output to explain itself.
//
// The timeout is the assertion: this test fails by TIMING OUT the whole
// package if the guard is removed, which is the only way to observe a hang.
// The notice is checked too, so "it returned" cannot pass by returning
// silence.
func TestP8DoesNotHangOnAFifoPolicyFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "policy.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("SKIP: cannot create a FIFO here: %v", err)
	}

	saved := hostSignaturePolicyPaths
	t.Cleanup(func() { hostSignaturePolicyPaths = saved })
	hostSignaturePolicyPaths = []string{fifo}

	done := make(chan *signaturePolicyNotice, 1)
	go func() { done <- preflightSignaturePolicy() }()

	select {
	case n := <-done:
		if n == nil {
			t.Fatal("a FIFO at the host's policy.json path produced no notice at all: P8 " +
				"cannot compare against it and must say so, not stay silent")
		}
		if !strings.Contains(n.Detail, "not a regular file") {
			t.Errorf("the notice does not say what was wrong with the file: %s", n.Detail)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("preflightSignaturePolicy blocked on a FIFO: the run would hang before " +
			"anything started, with nothing on any screen")
	}
}
