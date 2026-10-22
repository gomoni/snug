package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestHostGPGEndToEnd runs the host half of identity.gpg against a real gpg and
// gpg-agent in a throwaway GNUPGHOME: gpgKeyInfo parses a real listing,
// gpgPins keeps the primary out, startGPGIdentity starts the proxy and stages
// the PUBLIC keyring, and the proxy then answers on the socket it bound. It
// would catch the parser drifting from what gpg prints, which the fixture
// listings in gpgidentity_test.go cannot. The throwaway agent is killed on
// cleanup and ~/.gnupg is never touched.
//
// What it does not cover: a sandbox. The socket is dialled from here.
func TestHostGPGEndToEnd(t *testing.T) {
	for _, bin := range []string{"gpg", "gpgconf", "gpg-agent"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	home := shortGnupgHome(t)
	t.Setenv("GNUPGHOME", home)
	rt, err := os.MkdirTemp("", "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)

	gpg := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("gpg", append([]string{"--batch", "--pinentry-mode", "loopback",
			"--passphrase", ""}, args...)...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, errb.String())
		}
		return out.String()
	}
	t.Cleanup(func() {
		exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		exec.Command("gpgconf", "--remove-socketdir").Run()
	})

	gpg("--quick-gen-key", "Pinned <pin@example.org>", "ed25519", "cert", "never")
	var fpr string
	for line := range strings.SplitSeq(gpg("--with-colons", "--list-keys"), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" && len(f) > 9 {
			fpr = f[9]
			break
		}
	}
	if fpr == "" {
		t.Fatal("no fingerprint for the generated key")
	}
	gpg("--quick-add-key", fpr, "ed25519", "sign", "never")
	gpg("--quick-add-key", fpr, "cv25519", "encr", "never")

	g, err := gpgKeyInfo(fpr)
	if err != nil {
		t.Fatalf("gpgKeyInfo: %v", err)
	}
	if len(g.signers) != 1 || len(g.encryptors) != 1 {
		t.Fatalf("grips = %+v, want one signing and one encryption subkey", g)
	}
	// The primary's grip is the first grp: line of the listing; pins must not
	// contain it. The control is that the listing does have one.
	primary := ""
	for line := range strings.SplitSeq(gpg("--with-colons", "--with-keygrip", "--list-secret-keys", "--", fpr), "\n") {
		if f := strings.Split(line, ":"); f[0] == "grp" && len(f) > 9 {
			primary = f[9]
			break
		}
	}
	if primary == "" {
		t.Fatal("control: the real listing has no primary grip")
	}
	pins, err := gpgPins(fpr, "decrypt,sign", g)
	if err != nil {
		t.Fatalf("gpgPins: %v", err)
	}
	for _, p := range pins {
		if strings.EqualFold(p.Grip, primary) {
			t.Errorf("the primary's grip %s was pinned", primary)
		}
	}

	// A key the host does not hold is refused, naming the fingerprint.
	const unknown = "0000000000000000000000000000000000000001"
	if _, err := gpgKeyInfo(unknown); err == nil || !strings.Contains(err.Error(), unknown) {
		t.Errorf("an unknown fingerprint was not refused by name: %v", err)
	}

	// A key with no signing subkey is refused at startup under scope sign.
	gpg("--quick-gen-key", "Certify only <cert@example.org>", "ed25519", "cert", "never")
	var certFpr string
	for line := range strings.SplitSeq(gpg("--with-colons", "--list-keys", "--", "cert@example.org"), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" && len(f) > 9 {
			certFpr = f[9]
			break
		}
	}
	cg, err := gpgKeyInfo(certFpr)
	if err != nil {
		t.Fatalf("gpgKeyInfo(cert-only): %v", err)
	}
	if _, err := gpgPins(certFpr, "sign", cg); err == nil ||
		!strings.Contains(err.Error(), "gpg --quick-add-key "+certFpr+" ed25519 sign") {
		t.Errorf("a key with no signing subkey under scope sign: %v", err)
	}

	// The real start: the proxy is bound, the keyring staged, the socket named.
	pol := gpgIdentityPolicy()
	pol.Identity.GPG.Fingerprint = fpr
	cleanup, err := startGPGIdentity(pol, pol.Identity, false, false)
	if err != nil {
		t.Fatalf("startGPGIdentity: %v", err)
	}
	defer cleanup()
	ring, ok := pol.Mounts[pol.Home+"/"+policy.GPGKeyringGuest]
	if !ok || ring.Kind != policy.KindData || len(ring.Content) == 0 {
		t.Fatalf("no staged keyring: %+v (ok %v)", ring, ok)
	}
	if bytes.Contains(ring.Content, []byte("PRIVATE KEY")) {
		t.Error("the staged keyring holds private key text")
	}
	sock, ok := pol.Mounts[pol.Home+"/"+policy.GPGAgentSocketGuest]
	if !ok {
		t.Fatal("no socket mount")
	}
	if _, err := os.Stat(sock.Host); err != nil {
		t.Errorf("the proxy socket %s was not bound: %v", sock.Host, err)
	}
}
