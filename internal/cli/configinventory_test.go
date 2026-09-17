package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the ~/.config generated-file inventory INDEX.md §9.5 states in prose ────
//
// A red-team round on #582 caught INDEX.md §9.5 claiming snug generates
// exactly ONE file under ~/.config (.config/git/allowed_signers). It
// generates TWO: [identity.gh] stages a second one, .config/gh/hosts.yml,
// holding a GitHub OAuth token minted on the host by `gh auth token`
// (stageGhConfig below). Nothing failed when the prose said otherwise,
// because the count lived only in that paragraph — the same shape
// dryrun.go's authored() comment already names for the single-file case: a
// --dry-run sentence about ~/.config/gh was wrong for exactly this reason
// once identity started staging hosts.yml there.
//
// This test holds the count in code. It fails if stageGhConfig or
// startSSHIdentity ever start (or stop) writing a mount under ~/.config, so
// a future change to either has to walk over here and, if the count really
// changed, edit .claude/design/INDEX.md §9.5 to match rather than leave it
// describing a tree that no longer exists.

// mountsUnderConfig is every guest path staged under {home}/.config, sorted.
func mountsUnderConfig(pol *policy.Policy) []string {
	prefix := pol.Home + "/.config/"
	var out []string
	for guest := range pol.Mounts {
		if strings.HasPrefix(guest, prefix) {
			out = append(out, guest)
		}
	}
	sort.Strings(out)
	return out
}

func TestTheGeneratedConfigInventoryIsExactlyTwoFiles(t *testing.T) {
	pol := ghPolicy(t)
	id := &policy.Identity{Gh: policy.IdentityGh{Host: "gh.example", User: "some-one"}}
	mint := func(string, string) policy.Secret { return policy.Secret("t0ken") }

	if err := stageGhConfig(pol, id, false, mint); err != nil {
		t.Fatalf("stageGhConfig: %v", err)
	}

	got := mountsUnderConfig(pol)
	want := []string{"/home/u/.config/gh/hosts.yml"}
	if !equalStringSlices(got, want) {
		t.Fatalf("[identity.gh] alone staged %v under ~/.config, want exactly %v — if this changed "+
			"on purpose, .claude/design/INDEX.md §9.5's inventory has to be edited in the same change",
			got, want)
	}

	// Add [identity.git] with signing_key: a SECOND generated file joins the
	// set, which is the count this test exists to pin.
	authPath, _ := writePinnedPubKey(t, t.TempDir())
	signDir := t.TempDir()
	signPath := filepath.Join(signDir, "id_signing.pub")
	if err := os.WriteFile(signPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA signing@test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id.SSH = policy.IdentitySSH{Agent: policy.SSHAgentProxy, Key: authPath}
	id.Git = policy.IdentityGit{SigningKey: signPath, Email: "u@example.com"}

	cleanup, err := startSSHIdentity(pol, id, false, true)
	if err != nil {
		t.Fatalf("startSSHIdentity: %v", err)
	}
	defer cleanup()

	got = mountsUnderConfig(pol)
	want = []string{"/home/u/.config/gh/hosts.yml", "/home/u/.config/git/allowed_signers"}
	if !equalStringSlices(got, want) {
		t.Fatalf("with [identity.gh] and [identity.git] signing_key both set, ~/.config holds %v, "+
			"want exactly these TWO generated files: %v — the count INDEX.md §9.5 states in prose "+
			"because nothing else checks it, and this is the something else", got, want)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
