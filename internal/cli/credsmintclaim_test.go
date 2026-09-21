package cli

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// credsBlock renders --dry-run's CLAUDE block for a selection, with a staged
// credential put there the way TestGoldenClaudeBlock's credentials arm does:
// through the REAL projection against a literal fixture, never a host read. No
// golden may depend on the developer's own token, and nothing about a real one
// is needed to render a block that names FIELDS and never a value.
func credsBlock(t *testing.T, sel []policy.ProfileName) string {
	t.Helper()
	p := resolveFor(t, sel)
	// The block is gated on ~/.claude.json, which claudeFiles authors. The
	// temp home resolveFor builds holds no credential file, so this reaches
	// the "absent on this host" arm and the fixture below supplies the one
	// mount this test is about.
	if err := claudeFiles(p, p.Home, nil); err != nil {
		t.Fatalf("claudeFiles: %v", err)
	}
	host := []byte(`{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE",` +
		`"refreshToken":"sk-ant-ort-FIXTURE","expiresAt":1767243600000,` +
		`"refreshTokenExpiresAt":1767225600000,"scopes":["user:inference"],` +
		`"subscriptionType":"max","rateLimitTier":"default"}}`)
	projected, _, err := policy.ProjectClaudeCredentials(host)
	if err != nil {
		t.Fatalf("ProjectClaudeCredentials: %v", err)
	}
	perm := uint32(0o600)
	p.Replace(policy.Mount{
		Guest: filepath.Join(p.Home, ".claude", ".credentials.json"), Kind: policy.KindData,
		Access: policy.AccessRW, Content: projected, Perms: &perm, From: []string{"@claude"},
	})
	got := captureFile(t, func(f io.Writer) { describeClaude(f, p) })
	if !strings.Contains(got, "creds") {
		t.Fatalf("control: the creds block did not render for %v, so this test "+
			"would pass on an empty string:\n%s", sel, got)
	}
	return got
}

// TestTheCredsBlockDoesNotClaimTheTokenCannotMint holds the one sentence
// SECRETS.md §A2 refuses to let this screen say.
//
// The block printed "Nothing in here can mint a NEW token" while §A2 says the
// opposite in as many words: dropping refreshToken "removed renewal ... It did
// not remove minting: the client ships /api/oauth/claude_cli/create_api_key,
// and an API key minted there is durable and outlives the sandbox" — and
// whether THIS token is accepted at that endpoint is UNMEASURED, so the design
// treats it as true. Two documents in one repository said opposite things about
// the same token, and the one a human reads to decide whether to trust snug was
// the one that was wrong.
//
// The assertion is deliberately on the CLAIM and not on the wording: any
// sentence pairing "mint" with a negation is the defect, however it is spelled,
// because --dry-run's whole job is to replace trust with measurement and an
// unmeasured negative is the one thing it must not assert.
func TestTheCredsBlockDoesNotClaimTheTokenCannotMint(t *testing.T) {
	got := credsBlock(t, []policy.ProfileName{"@sys", "@home", "@target-rw", "@claude"})
	for _, line := range strings.Split(got, "\n") {
		if !strings.Contains(line, "mint") {
			continue
		}
		low := strings.ToLower(line)
		for _, neg := range []string{"nothing", "cannot", "can not", "can't", "no "} {
			if strings.Contains(low, neg) && !strings.Contains(line, "does not claim") {
				t.Errorf("the creds block denies minting, which SECRETS.md §A2 treats as "+
					"TRUE and unmeasured:\n%s", line)
			}
		}
	}
	// POSITIVE CONTROL. Without this the test above passes on a block that
	// stopped mentioning minting at all — which would be the same silence the
	// change replaced, just spelled differently.
	if !strings.Contains(got, "RENEWAL is not MINTING") {
		t.Errorf("the creds block no longer distinguishes renewal from minting at all, "+
			"so a reader is left with the expiry bound and nothing about the durable "+
			"key that bound does not cover:\n%s", got)
	}
}

// TestTheCredsBlockSaysWhetherThisRunStillHasTheNetworkBound pins the half that
// is a property of the SELECTION rather than of the token.
//
// SECRETS.md §A2's closing sentence — "Today what bounds it is that @claude does
// not include @net: a network defence, not a property of the token. That is
// worth stating in exactly those words, because a profile combination the user
// is free to write (-p @claude -p @net) removes it" — was stated in the design
// document and nowhere on the screen. A bound the reader has to go and check for
// themselves is one the artifact did not give them.
//
// Both arms are asserted, and each is the other's negative control: a block that
// printed the egress warning unconditionally would say nothing about the
// condition it names, which is the failure the @net-less arm exists to catch.
func TestTheCredsBlockSaysWhetherThisRunStillHasTheNetworkBound(t *testing.T) {
	const (
		bound   = "NO EGRESS"
		unbound = "NOTHING IN THIS RUN BOUNDS THAT"
	)

	offline := credsBlock(t, []policy.ProfileName{"@sys", "@home", "@target-rw", "@claude"})
	if !strings.Contains(offline, bound) {
		t.Errorf("a run with no egress does not say so is what bounds the mint path:\n%s", offline)
	}
	if strings.Contains(offline, unbound) {
		t.Errorf("a run with no egress claims the bound is gone:\n%s", offline)
	}

	egress := credsBlock(t, []policy.ProfileName{"@sys", "@home", "@target-rw", "@claude", "@net"})
	if !strings.Contains(egress, unbound) {
		t.Errorf("@claude and @net together, and the screen still describes the network "+
			"bound as though this run had it:\n%s", egress)
	}
	if strings.Contains(egress, bound) {
		t.Errorf("a run WITH egress says it has none:\n%s", egress)
	}
}
