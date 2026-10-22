package cli

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/gpgproxy"
	"github.com/gomoni/snug/internal/policy"
)

const (
	fprA = "6732361300BBFDAE7F22972CD4381E1CE2880244"
	fprB = "0E1D0C4D9A2B7E3B3F0B6D4F05B63E8E4E213D24"
	// Grips, distinct per role so a wrong pick shows in the diff.
	gripAPrimary = "2761D2BF75F0095F0FEA0A9216F4114A3B0C20BA"
	gripAEncr    = "80C95D6427C02FBB78C91DCEE6E12BD520EF66F0"
	gripASign    = "1111111111111111111111111111111111111111"
	gripBPrimary = "31ABBA59A26690C3264EAFC95372EDF59E25F3E4"
	gripBSign    = "2222222222222222222222222222222222222222"
	gripBEncr    = "3333333333333333333333333333333333333333"
)

// keyAListing is laid out like `gpg --with-colons --with-keygrip
// --list-secret-keys` for an ed25519 primary with a signing subkey and a
// cv25519 encryption subkey. The fingerprints and grips are fixtures in gpg's
// field order, not a capture; TestHostGPGEndToEnd parses a real one.
const keyAListing = `sec:u:255:22:D4381E1CE2880244:1792588754:::u:::cC:::+::ed25519:::0:
fpr:::::::::` + fprA + `:
grp:::::::::` + gripAPrimary + `:
ssb:u:255:22:BBBBBBBBBBBBBBBB:1792588754::::::s:::+::ed25519::
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
grp:::::::::` + gripASign + `:
ssb:u:255:18:A53647A6FF8D6256:1792588754::::::e:::+::cv25519::
fpr:::::::::12BB70F3FB52237528EC3804A53647A6FF8D6256:
grp:::::::::` + gripAEncr + `:
`

func TestParseKeygripsPinsSubkeysAndNeverThePrimary(t *testing.T) {
	g, ok := parseKeygrips(keyAListing, fprA)
	if !ok {
		t.Fatal("parseKeygrips found no key in a real-shaped listing")
	}
	if len(g.signers) != 1 || g.signers[0] != gripASign {
		t.Errorf("signers = %q, want [%s]", g.signers, gripASign)
	}
	if len(g.encryptors) != 1 || g.encryptors[0] != gripAEncr {
		t.Errorf("encryptors = %q, want [%s]", g.encryptors, gripAEncr)
	}
	// The primary certifies: through a pinned primary the sandbox could add a
	// user ID to the host key or bind a subkey it holds. It is in neither list.
	for _, list := range [][]string{g.signers, g.encryptors} {
		if slices.Contains(list, gripAPrimary) {
			t.Errorf("the primary's grip %s is pinned: %q", gripAPrimary, list)
		}
	}
}

// A listing holding a second key adds nothing to the first, in either
// direction, and a fingerprint absent from the listing reports so.
func TestParseKeygripsReadsOnlyTheAskedForKey(t *testing.T) {
	listing := keyAListing + `sec:u:255:22:05B63E8E4E213D24:1:::u:::cC:::+::ed25519:::0:
fpr:::::::::` + fprB + `:
grp:::::::::` + gripBPrimary + `:
ssb:u:255:22:CCCCCCCCCCCCCCCC:1::::::s:::+::ed25519::
grp:::::::::` + gripBSign + `:
ssb:u:255:18:DDDDDDDDDDDDDDDD:1::::::e:::+::cv25519::
grp:::::::::` + gripBEncr + `:
`
	a, ok := parseKeygrips(listing, fprA)
	if !ok || strings.Join(a.signers, ",") != gripASign || strings.Join(a.encryptors, ",") != gripAEncr {
		t.Errorf("key A = %+v (ok %v), want only its own subkeys", a, ok)
	}
	b, ok := parseKeygrips(listing, fprB)
	if !ok || strings.Join(b.signers, ",") != gripBSign || strings.Join(b.encryptors, ",") != gripBEncr {
		t.Errorf("key B = %+v (ok %v), want only its own subkeys", b, ok)
	}
	if g, ok := parseKeygrips(listing, "9999999999999999999999999999999999999999"); ok || len(g.signers)+len(g.encryptors) != 0 {
		t.Errorf("an absent fingerprint produced %+v (ok %v)", g, ok)
	}
	// gpg prints fingerprints upper-case; a profile may spell them either way.
	if _, ok := parseKeygrips(listing, strings.ToLower(fprB)); !ok {
		t.Error("a lower-case fingerprint did not match")
	}
}

// A revoked or expired signing subkey must not be pinned for signing: the
// agent would refuse it, and the startup probe would refuse the run for a key
// the user cannot use. An expired ENCRYPTION subkey is kept, because mail
// already addressed to it is the reason the key is wanted.
func TestParseKeygripsDropsDeadSigningSubkeys(t *testing.T) {
	const live = "4444444444444444444444444444444444444444"
	listing := `sec:u:255:22:AAAAAAAAAAAAAAAA:1:::u:::cC:::+::ed25519:::0:
fpr:::::::::` + fprA + `:
grp:::::::::` + gripAPrimary + `:
ssb:r:255:22:BBBBBBBBBBBBBBBB:1::::::s:::+::ed25519::
grp:::::::::` + gripASign + `:
ssb:e:255:22:CCCCCCCCCCCCCCCC:1::::::s:::+::ed25519::
grp:::::::::2222222222222222222222222222222222222222:
ssb:u:255:22:DDDDDDDDDDDDDDDD:1::::::s:::+::ed25519::
grp:::::::::` + live + `:
ssb:e:255:18:EEEEEEEEEEEEEEEE:1::::::e:::+::cv25519::
grp:::::::::` + gripAEncr + `:
`
	g, ok := parseKeygrips(listing, fprA)
	if !ok {
		t.Fatal("no key")
	}
	if len(g.signers) != 1 || g.signers[0] != live {
		t.Errorf("signers = %q, want only the live subkey %s", g.signers, live)
	}
	if len(g.encryptors) != 1 || g.encryptors[0] != gripAEncr {
		t.Errorf("encryptors = %q, want the expired encryption subkey kept", g.encryptors)
	}
}

// A subkey that is neither signing nor encrypting (authentication) pins nothing,
// and one that is both lands in both lists.
func TestParseKeygripsFollowsTheCapabilityField(t *testing.T) {
	listing := `sec:u:255:22:AAAAAAAAAAAAAAAA:1:::u:::cC:::+::ed25519:::0:
fpr:::::::::` + fprA + `:
grp:::::::::` + gripAPrimary + `:
ssb:u:255:22:BBBBBBBBBBBBBBBB:1::::::a:::+::ed25519::
grp:::::::::5555555555555555555555555555555555555555:
ssb:u:3072:1:CCCCCCCCCCCCCCCC:1::::::se:::+::rsa3072::
grp:::::::::6666666666666666666666666666666666666666:
`
	g, _ := parseKeygrips(listing, fprA)
	if strings.Join(g.signers, ",") != "6666666666666666666666666666666666666666" ||
		strings.Join(g.encryptors, ",") != "6666666666666666666666666666666666666666" {
		t.Errorf("got %+v, want the se subkey in both lists and the auth subkey in neither", g)
	}
}

// A gpg 2.5 post-quantum subkey is composite and its `grp:` line carries two
// grips, and decryption names both: `SETKEY <first>` then `SETKEY --another
// <second>`. The shape is gpg 2.5's; the grips here are fixtures.
func TestParseKeygripsSplitsACompositeSubkey(t *testing.T) {
	pqc := `sec:u:384:19:05B63E8E4E213D24:1792675586:::u:::scESC:::+::brainpoolP384r1:23::0:
fpr:::::::::` + fprB + `:
grp:::::::::` + gripBPrimary + `:
ssb:u:768:8:AE689B81586D7A5D:1792675586::::::e:::+::ky768_bp256:8 23:
grp:::::::::6BB91A8AD3741EF3E274773A21E79A14C7CC6A70,3B6B6986FE3B419F7FCCBE4721C56547A740F67E:
`
	g, ok := parseKeygrips(pqc, fprB)
	if !ok {
		t.Fatal("no key")
	}
	want := []string{"6BB91A8AD3741EF3E274773A21E79A14C7CC6A70", "3B6B6986FE3B419F7FCCBE4721C56547A740F67E"}
	if strings.Join(g.encryptors, ",") != strings.Join(want, ",") {
		t.Errorf("encryptors = %q, want %q", g.encryptors, want)
	}
	if len(g.signers) != 0 {
		t.Errorf("signers = %q, want none: the primary is not pinned and the subkey does not sign", g.signers)
	}
}

// Every encryption subkey is pinned, not the first: gpg encrypts to the newest,
// so a key with an old and a new subkey has its mail addressed to the second.
func TestParseKeygripsTakesEveryEncryptionSubkey(t *testing.T) {
	two := `sec:u:255:22:AAAAAAAAAAAAAAAA:1:::u:::cC:::+::ed25519:::0:
fpr:::::::::` + fprA + `:
grp:::::::::1111111111111111111111111111111111111111:
ssb:e:255:18:BBBBBBBBBBBBBBBB:1::::::e:::+::cv25519::
grp:::::::::2222222222222222222222222222222222222222:
ssb:u:255:18:CCCCCCCCCCCCCCCC:2::::::e:::+::cv25519::
grp:::::::::3333333333333333333333333333333333333333:
`
	g, _ := parseKeygrips(two, fprA)
	if len(g.encryptors) != 2 || g.encryptors[1] != "3333333333333333333333333333333333333333" {
		t.Errorf("encryptors = %q, want both subkeys' grips", g.encryptors)
	}
}

// A key with no secret half: `--list-secret-keys` prints nothing (or only
// stderr), so the parser finds no key and the caller refuses.
func TestParseKeygripsRefusesAnEmptyListing(t *testing.T) {
	if _, ok := parseKeygrips("", fprA); ok {
		t.Error("an empty listing reported a key")
	}
}

func scopeOf(pins []gpgproxy.PinnedGrip, grip string) gpgproxy.Scope {
	var s gpgproxy.Scope
	for _, p := range pins {
		if p.Grip == grip {
			s |= p.Scope
		}
	}
	return s
}

// TestGPGPinsFollowTheScope: sign pins the signing subkeys for signing, decrypt
// pins the encryption subkeys for decrypting, and neither pins the primary or
// crosses over. Under scope sign alone the encryption subkey is not pinned at
// all, so it is not even listed to the sandbox.
func TestGPGPinsFollowTheScope(t *testing.T) {
	g := gpgGrips{signers: []string{gripASign}, encryptors: []string{gripAEncr}}
	cases := []struct {
		scope             string
		wantSign, wantDec gpgproxy.Scope
	}{
		{"sign", gpgproxy.ScopeSign, 0},
		{"decrypt", 0, gpgproxy.ScopeDecrypt},
		{"decrypt,sign", gpgproxy.ScopeSign, gpgproxy.ScopeDecrypt},
	}
	for _, c := range cases {
		pins, err := gpgPins(fprA, c.scope, g)
		if err != nil {
			t.Errorf("scope %q: %v", c.scope, err)
			continue
		}
		if got := scopeOf(pins, gripASign); got != c.wantSign {
			t.Errorf("scope %q: signing subkey scope = %v, want %v", c.scope, got, c.wantSign)
		}
		if got := scopeOf(pins, gripAEncr); got != c.wantDec {
			t.Errorf("scope %q: encryption subkey scope = %v, want %v", c.scope, got, c.wantDec)
		}
		if got := scopeOf(pins, gripAPrimary); got != 0 {
			t.Errorf("scope %q: the primary is pinned with %v", c.scope, got)
		}
	}
}

// TestGPGPinsRefuseAScopeWithNothingToUse: a sign scope on a key without a
// signing subkey must not fall back to the primary, and a decrypt scope without
// an encryption subkey grants nothing. Each refusal names the key and the
// command that fixes it, because the alternative is a run where every commit
// fails with no cause on screen.
func TestGPGPinsRefuseAScopeWithNothingToUse(t *testing.T) {
	onlyEncr := gpgGrips{encryptors: []string{gripAEncr}}
	_, err := gpgPins(fprA, "sign", onlyEncr)
	if err == nil {
		t.Fatal("scope sign was accepted on a key with no signing subkey")
	}
	for _, want := range []string{fprA, "gpg --quick-add-key " + fprA + " ed25519 sign", "CERTIFIES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
	// decrypt,sign on the same key: the sign half still refuses.
	if _, err := gpgPins(fprA, "decrypt,sign", onlyEncr); err == nil {
		t.Error("decrypt,sign was accepted on a key with no signing subkey")
	}

	onlySign := gpgGrips{signers: []string{gripASign}}
	_, err = gpgPins(fprA, "decrypt", onlySign)
	if err == nil {
		t.Fatal("scope decrypt was accepted on a key with no encryption subkey")
	}
	for _, want := range []string{fprA, "gpg --quick-add-key " + fprA + " cv25519 encr", "identity.gpg.scope"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
	// Sign alone on that key is fine.
	if _, err := gpgPins(fprA, "sign", onlySign); err != nil {
		t.Errorf("scope sign on a signing key was refused: %v", err)
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

// TestGPGIdentityDryRunNamesTheSocketAndStartsNothing is issue #21's rule
// applied to the gpg half: a dry run binds no socket and creates no runtime
// directory — it NAMES the path a real run would use, at exactly
// $GNUPGHOME/S.gpg-agent, because that is the only path gpg looks at.
//
// GNUPGHOME and ~/.gnupg are Resolve's, not this function's (see
// policy's TestGPGIdentityOwnsItsHome), so this test does not look for them.
// The host gpg is pointed at an empty throwaway home, so the keyring row is
// absent for lack of the key rather than for what the machine running the
// suite happens to hold.
func TestGPGIdentityDryRunNamesTheSocketAndStartsNothing(t *testing.T) {
	t.Setenv("GNUPGHOME", shortGnupgHome(t))
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	pol := gpgIdentityPolicy()
	cleanup, err := startGPGIdentity(pol, pol.Identity, false, true)
	if err != nil {
		t.Fatalf("startGPGIdentity dry run: %v", err)
	}
	defer cleanup()

	wantGuest := pol.Home + "/" + policy.GPGAgentSocketGuest
	bolt, ok := pol.Mounts[wantGuest]
	if !ok {
		t.Fatalf("no socket mount at %s; mounts = %v", wantGuest, pol.Mounts)
	}
	if bolt.Kind != policy.KindBind {
		t.Errorf("socket Kind = %v, want KindBind", bolt.Kind)
	}
	if _, err := os.Stat(bolt.Host); err == nil {
		t.Errorf("a dry run created the socket %s", bolt.Host)
	}
	if entries, _ := os.ReadDir(rt); len(entries) != 0 {
		t.Errorf("a dry run created %d entries in the runtime directory", len(entries))
	}
	if _, ok := pol.Mounts[pol.Home+"/"+policy.GPGKeyringGuest]; ok {
		t.Error("a keyring was staged from a host gpg that does not know the key")
	}
}

// TestHostGPGToolsAreNamedWhenMissing: with no gpg or gpgconf on PATH each
// host touch refuses with a message naming the missing tool, not a bare exec
// error. PATH is an empty directory, so the result does not depend on what the
// machine running the suite has installed.
func TestHostGPGToolsAreNamedWhenMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := gpgKeyInfo(fprA); err == nil || !strings.Contains(err.Error(), "no gpg is on PATH") {
		t.Errorf("gpgKeyInfo without gpg: %v", err)
	}
	if _, err := gpgExportPublicKey(fprA); err == nil || !strings.Contains(err.Error(), "none is on PATH") {
		t.Errorf("gpgExportPublicKey without gpg: %v", err)
	}
	if _, err := gpgAgentSocket(); err == nil || !strings.Contains(err.Error(), "no gpgconf is on PATH") {
		t.Errorf("gpgAgentSocket without gpgconf: %v", err)
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
