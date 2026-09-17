package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── #576: the generated verifier list for `git log --show-signature` ───────
//
// allowedSignersLine renders the ONE line snug authors; startSSHIdentity is
// what mounts it. These tests stay in internal/cli because both functions do:
// internal/policy's gitextract_test.go already covers the [gpg "ssh"] directive
// GitConfigFrom points at this file with.

// TestAllowedSignersLine is a table over the line format `PRINCIPAL
// namespaces="git" KEYTYPE BASE64`. namespaces="git" is asserted present in
// every non-error case: its absence would let the same key's signature over
// any other namespace (`ssh-keygen -Y sign -n file`, say) read as a good
// commit signature.
func TestAllowedSignersLine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pub     string
		wantErr bool
	}{
		{"ordinary .pub with a trailing comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host\n", false},
		{"no comment at all", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n", false},
		{"a comment containing spaces", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA a comment with spaces\n", false},
		{"one field is an error", "ssh-ed25519\n", true},
		{"empty is an error", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := allowedSignersLine("u@example.com", []byte(tc.pub))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("allowedSignersLine(%q) = %q, want an error naming it is not an ssh "+
						"public key", tc.pub, line)
				}
				if !strings.Contains(err.Error(), "not an ssh public key") {
					t.Errorf("error does not name what is wrong: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("allowedSignersLine(%q): %v", tc.pub, err)
			}
			fields := strings.Fields(string(line))
			if len(fields) != 4 {
				t.Fatalf("allowedSignersLine = %q, want exactly 4 fields (principal, options, "+
					"keytype, key), got %d: the .pub's comment must never survive into the line", line, len(fields))
			}
			if fields[0] != "u@example.com" {
				t.Errorf("principal = %q, want the pinned email", fields[0])
			}
			if fields[1] != `namespaces="git"` {
				t.Errorf(`option = %q, want namespaces="git"`, fields[1])
			}
			if fields[2] != "ssh-ed25519" {
				t.Errorf("keytype = %q, want the .pub's first field", fields[2])
			}
			if fields[3] != "AAAAC3NzaC1lZDI1NTE5AAAA" {
				t.Errorf("key = %q, want the .pub's second field with no comment attached", fields[3])
			}
		})
	}
}

// TestAllowedSignersLineRefusesAnUnprincipledEmail is the regression for the
// injection the red-team round measured on #576: an identity.git.email
// carrying more than one whitespace-separated field authored a line whose KEY
// was the attacker's and whose pinned key was swallowed as a trailing
// comment. THE ASSERTION THAT FAILED BEFORE THE FIX: strings.Fields of the
// returned line had length 6, not 4 — allowedSignersLine returned the
// six-field line rather than an error. This asserts the call now errors
// instead.
func TestAllowedSignersLineRefusesAnUnprincipledEmail(t *testing.T) {
	pub := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host\n")
	for _, tc := range []struct {
		name  string
		email string
	}{
		{"the measured six-field injection", "u@example.com,evil@example.com ssh-ed25519 AAAA"},
		{"empty", ""},
		{"whitespace only", " "},
		{"a leading #", "#u@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := allowedSignersLine(tc.email, pub)
			if err == nil {
				t.Fatalf("allowedSignersLine(%q) = %q (%d fields), want an error naming "+
					"identity.git.email", tc.email, line, len(strings.Fields(string(line))))
			}
			if !strings.Contains(err.Error(), "identity.git.email") {
				t.Errorf("error does not name identity.git.email: %v", err)
			}
		})
	}

	// POSITIVE CONTROL: an ordinary single address still produces the
	// four-field line. Without it every case above would pass equally on a
	// build that refuses every email outright.
	line, err := allowedSignersLine("u@example.com", pub)
	if err != nil {
		t.Fatalf("an ordinary single-address email was refused: %v", err)
	}
	if got := len(strings.Fields(string(line))); got != 4 {
		t.Errorf("allowedSignersLine = %q, want exactly 4 fields, got %d", line, got)
	}
}

// signingIdentityPolicy is the smallest policy that reaches the allowed_signers
// staging inside startSSHIdentity: an agent-proxy identity with both an auth key
// and a pinned signing_key plus the email the principal is authored from.
func signingIdentityPolicy(t *testing.T, authPath, signPath string) *policy.Policy {
	t.Helper()
	return &policy.Policy{
		Home:          "/home/u",
		Mounts:        map[string]policy.Mount{},
		Env:           map[string]policy.EnvVar{},
		IdentityOwner: "pinned",
		Identity: &policy.Identity{
			SSH: policy.IdentitySSH{Agent: policy.SSHAgentProxy, Key: authPath},
			Git: policy.IdentityGit{SigningKey: signPath, Email: "u@example.com"},
		},
	}
}

// TestAllowedSignersMountIsReadOnlyDataAtTheGuestPath is the mount-shape
// assertion the golden argv test cannot make: KindData (generated content, not
// a bind of a host path), AccessRO (nothing inside legitimately rewrites its
// own verifier list), the exact guest path, and the same identity provenance
// every other identity-staged file carries — the shape
// TestTheStagedCredentialIsWritableAndPrivate (claudecreds_test.go) and
// TestProjectSettingsProjectionDropsHooksWhereTheFileExists (claudeproject_test.go)
// assert their own KindData mounts with.
func TestAllowedSignersMountIsReadOnlyDataAtTheGuestPath(t *testing.T) {
	authPath, _ := writePinnedPubKey(t, t.TempDir())
	signDir := t.TempDir()
	signPath := filepath.Join(signDir, "id_signing.pub")
	if err := os.WriteFile(signPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA signing@test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := signingIdentityPolicy(t, authPath, signPath)
	cleanup, err := startSSHIdentity(pol, pol.Identity, false, true)
	if err != nil {
		t.Fatalf("startSSHIdentity: %v", err)
	}
	defer cleanup()

	guest := pol.Home + "/" + policy.AllowedSignersGuest
	m, ok := pol.Mounts[guest]
	if !ok {
		t.Fatalf("no mount at %s; mounts = %v", guest, pol.Mounts)
	}
	if m.Kind != policy.KindData {
		t.Errorf("Kind = %v, want KindData — this is generated content, not a bind of a host path", m.Kind)
	}
	if m.Access != policy.AccessRO {
		t.Errorf("Access = %v, want AccessRO — nothing inside legitimately rewrites its own "+
			"verifier list", m.Access)
	}
	want := "identity:pinned"
	if len(m.From) != 1 || m.From[0] != want {
		t.Errorf("From = %v, want [%q] — the same provenance every other identity-staged file carries",
			m.From, want)
	}
	if !strings.Contains(string(m.Content), "u@example.com") {
		t.Errorf("content does not name the pinned email:\n%s", m.Content)
	}
}

// TestAllowedSignersFileIsAuthoredNeverCarriedFromTheHost is the negative that
// matters most: the host's OWN ~/.config/git/allowed_signers — the verifier
// list of a developer who already trusts other people's keys — must
// contribute nothing to the one snug generates. It is planted at the real
// path HOME points at so a future change that "helpfully" merged the two
// would be caught here rather than in review: today nothing in startSSHIdentity
// reads that path at all, so this also pins that it stays that way.
func TestAllowedSignersFileIsAuthoredNeverCarriedFromTheHost(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	poison := `attacker@example.invalid namespaces="git" ssh-ed25519 AAAAPOISONPOISON attacker` + "\n"
	if err := os.WriteFile(filepath.Join(home, ".config", "git", "allowed_signers"),
		[]byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	authPath, _ := writePinnedPubKey(t, t.TempDir())
	signDir := t.TempDir()
	signPath := filepath.Join(signDir, "id_signing.pub")
	if err := os.WriteFile(signPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA signing@test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := signingIdentityPolicy(t, authPath, signPath)
	cleanup, err := startSSHIdentity(pol, pol.Identity, false, true)
	if err != nil {
		t.Fatalf("startSSHIdentity: %v", err)
	}
	defer cleanup()

	guest := pol.Home + "/" + policy.AllowedSignersGuest
	m, ok := pol.Mounts[guest]
	if !ok {
		t.Fatalf("no mount at %s", guest)
	}
	content := string(m.Content)
	if strings.Contains(content, "attacker") || strings.Contains(content, "AAAAPOISONPOISON") {
		t.Fatalf("the host's real allowed_signers leaked into the generated one:\n%s", content)
	}

	// POSITIVE CONTROL: the generated line does carry the profile's own pin, so
	// the negative above is not merely a check against a file staged empty.
	if !strings.Contains(content, "u@example.com") || !strings.Contains(content, "AAAAC3NzaC1lZDI1NTE5AAAA") {
		t.Fatalf("generated allowed_signers does not carry the pinned email/key:\n%s", content)
	}
}
