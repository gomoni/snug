package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/gpgproxy"
	"github.com/gomoni/snug/internal/policy"
)

// The real listing `gpg --with-colons --with-keygrip --list-secret-keys` prints
// for the measurement key: a primary ed25519 signing key and a cv25519
// encryption subkey. Two `grp:` records, in order.
const measuredListing = `sec:u:255:22:D4381E1CE2880244:1792588754:::u:::scESC:::+::ed25519:::0:
fpr:::::::::6732361300BBFDAE7F22972CD4381E1CE2880244:
grp:::::::::2761D2BF75F0095F0FEA0A9216F4114A3B0C20BA:
ssb:u:255:18:A53647A6FF8D6256:1792588754::::::e:::+::cv25519::
fpr:::::::::12BB70F3FB52237528EC3804A53647A6FF8D6256:
grp:::::::::80C95D6427C02FBB78C91DCEE6E12BD520EF66F0:
`

func TestParseKeygripsReadsPrimaryAndEncryptionSubkey(t *testing.T) {
	g, ok := parseKeygrips(measuredListing, "6732361300BBFDAE7F22972CD4381E1CE2880244")
	if !ok {
		t.Fatal("parseKeygrips found no primary key in a real listing")
	}
	if g.primary != "2761D2BF75F0095F0FEA0A9216F4114A3B0C20BA" {
		t.Errorf("primary = %q, want the measured primary grip", g.primary)
	}
	if g.encryptor != "80C95D6427C02FBB78C91DCEE6E12BD520EF66F0" {
		t.Errorf("encryptor = %q, want the measured encryption-subkey grip", g.encryptor)
	}
}

// A sign-only subkey must NOT be taken as the decryptor: the capability field
// is what distinguishes them, and a signing subkey handed to SETKEY would be a
// grip the agent refuses to decrypt with anyway.
func TestParseKeygripsIgnoresASignOnlySubkey(t *testing.T) {
	const signOnlySub = `sec:u:255:22:AAAAAAAAAAAAAAAA:1:::u:::scESC:::+::ed25519:::0:
grp:::::::::1111111111111111111111111111111111111111:
ssb:u:255:22:BBBBBBBBBBBBBBBB:1::::::s:::+::ed25519::
grp:::::::::2222222222222222222222222222222222222222:
`
	g, ok := parseKeygrips(signOnlySub, "9999999999999999999999999999999999999999")
	if !ok {
		t.Fatal("no primary found")
	}
	if g.encryptor != "" {
		t.Errorf("encryptor = %q, want empty: the subkey is sign-only", g.encryptor)
	}
}

// A key with no secret half: `--list-secret-keys` prints nothing (or only
// stderr), so the parser finds no primary and the caller refuses.
func TestParseKeygripsRefusesAnEmptyListing(t *testing.T) {
	if _, ok := parseKeygrips("", "6732361300BBFDAE7F22972CD4381E1CE2880244"); ok {
		t.Error("an empty listing reported a primary key")
	}
}

func TestGPGScopeForMapsBothSpellings(t *testing.T) {
	cases := []struct {
		scope string
		want  gpgproxy.Scope
	}{
		{"sign", gpgproxy.ScopeSign},
		{"decrypt", gpgproxy.ScopeDecrypt},
		{"decrypt,sign", gpgproxy.ScopeSign | gpgproxy.ScopeDecrypt},
	}
	for _, c := range cases {
		got, err := gpgScopeFor(c.scope)
		if err != nil {
			t.Errorf("gpgScopeFor(%q) refused: %v", c.scope, err)
			continue
		}
		if got != c.want {
			t.Errorf("gpgScopeFor(%q) = %v, want %v", c.scope, got, c.want)
		}
	}
	// A scope that maps to nothing is a refusal naming the profile field.
	for _, bad := range []string{"", "encrypt", "decrypt,encrypt"} {
		_, err := gpgScopeFor(bad)
		if err == nil {
			t.Errorf("gpgScopeFor(%q) accepted a grantless scope", bad)
			continue
		}
		if !strings.Contains(err.Error(), "identity.gpg.scope") {
			t.Errorf("refusal for %q does not name the field: %v", bad, err)
		}
	}
}

// gpgIdentityPolicy is the smallest policy that reaches startGPGIdentity's
// dry-run arm.
func gpgIdentityPolicy() *policy.Policy {
	return &policy.Policy{
		Home:           "/home/u",
		Mounts:         map[string]policy.Mount{},
		Env:            map[string]policy.EnvVar{},
		IdentityOwners: map[string][]policy.ProfileName{"gpg": {"pinned"}},
		Identity: &policy.Identity{
			GPG: policy.IdentityGPG{
				Fingerprint: "6732361300BBFDAE7F22972CD4381E1CE2880244",
				Scope:       "decrypt,sign",
			},
		},
	}
}

// TestGPGIdentityDryRunNamesTheSocketAndHomeAndStartsNothing is issue #21's
// rule applied to the gpg half: a dry run binds no socket, reads no host key,
// and creates no runtime directory — it NAMES the paths a real run would use.
// The socket must be named at exactly $GNUPGHOME/S.gpg-agent, because that is
// the only path gpg looks at (gpgconf --list-dirs agent-socket derives it from
// the CLIENT's GNUPGHOME).
func TestGPGIdentityDryRunNamesTheSocketAndHomeAndStartsNothing(t *testing.T) {
	pol := gpgIdentityPolicy()
	cleanup, err := startGPGIdentity(pol, pol.Identity, false, true)
	if err != nil {
		t.Fatalf("startGPGIdentity dry run: %v", err)
	}
	defer cleanup()

	// The socket is named at the guest path gpg actually reads.
	wantGuest := pol.Home + "/" + policy.GPGAgentSocketGuest
	bolt, ok := pol.Mounts[wantGuest]
	if !ok {
		t.Fatalf("no socket mount at %s; mounts = %v", wantGuest, pol.Mounts)
	}
	if bolt.Kind != policy.KindBind {
		t.Errorf("socket Kind = %v, want KindBind", bolt.Kind)
	}

	// GNUPGHOME points at the directory, not the socket.
	home, ok := pol.EnvValue("GNUPGHOME")
	if !ok {
		t.Fatal("GNUPGHOME was not set")
	}
	if home != pol.Home+"/"+policy.GPGHomeGuest {
		t.Errorf("GNUPGHOME = %q, want %q", home, pol.Home+"/"+policy.GPGHomeGuest)
	}

	// A dry run stages NO keyring: it read nothing from the host.
	if _, ok := pol.Mounts[pol.Home+"/"+policy.GPGKeyringGuest]; ok {
		t.Error("a dry run staged a public keyring; it must read nothing from the host")
	}
}

// TestGPGAgentSocketGuestIsWhereGPGLooks pins the spelling: gpg derives its
// agent socket as $GNUPGHOME/S.gpg-agent, so the guest path must be exactly
// that relative to GPGHomeGuest. A change here would make gpg talk to a socket
// that does not exist.
func TestGPGAgentSocketGuestIsWhereGPGLooks(t *testing.T) {
	if policy.GPGAgentSocketGuest != policy.GPGHomeGuest+"/S.gpg-agent" {
		t.Errorf("GPGAgentSocketGuest = %q, want %q/S.gpg-agent",
			policy.GPGAgentSocketGuest, policy.GPGHomeGuest)
	}
	if policy.GPGKeyringGuest != policy.GPGHomeGuest+"/pubring.kbx" {
		t.Errorf("GPGKeyringGuest = %q, want %q/pubring.kbx",
			policy.GPGKeyringGuest, policy.GPGHomeGuest)
	}
}
