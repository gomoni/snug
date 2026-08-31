//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDirectoryBindOfALiveAgentSocketEnumeratesAndSignsWithTheDecoy pins
// issue #292(a): a plain directory GRANT that happens to hold a live
// ssh-agent socket — no ssh_mode, no [profile.*.identity] block, nothing
// snug-specific at all — is a complete bypass of everything @ssh-agent
// (ssh_mode = "agent-proxy") exists to bound. That mode's whole point is a
// filtering proxy exposing ONE pinned key with enumeration refused, and it
// still cannot restrict what gets SIGNED (CLAUDE.md, "Identity and
// credentials"). This test asserts BOTH halves for a specific reason, not a
// general one: a plausible future fix closes enumeration alone (teaches the
// sandbox's ssh-add nothing is there) and leaves signing reachable, because
// signing only needs the socket to answer a sign request, never a listing.
// An enumeration-only test would go green on that fix and report the sharper
// capability closed when it was not.
//
// This is measured, not fixed. The residual is the directory case of #219
// (CLAUDE.md: "A SOCKET is the third noun, and `ro` restrains it least of
// all" / "Half of the socket rule is checked now"), tracked open, and this
// test exists so the day someone believes it is closed, this fails instead
// of silently passing.
//
// Default profiles only (@parent-ro), no user profile at all: the socket and
// the copied public key sit under the target's PARENT, identity-mapped, the
// same selection every other test in this residual family uses and for the
// same reason — "reachable with no user profile at all, under the shipped
// defaults" is what makes #219's ratchet damning; "reachable through a
// one-line test profile" is one a reader can dismiss as self-inflicted.
// Getting there needed shortTarget() (sandbox_test.go) rather than target():
// AF_UNIX's sun_path is ~108 bytes and target()'s own t.TempDir() root
// already measures 80+ of them on this host, which is too little room once a
// socket filename is added — see shortTarget's doc comment for the
// measurement.
//
// Fixture discipline: a freshly generated ed25519 DECOY key and its OWN
// throwaway ssh-agent, scratch directories only. HOME is pinned to a scratch
// directory for every host-side ssh-agent/ssh-add invocation. Nothing here
// is the real host agent and nothing is read from this developer's actual
// ~/.ssh.
//
// TIE TO THE DECOY, NOT TO "A SIGNATURE HAPPENED": the payload's
// SSH_AUTH_SOCK is asserted EMPTY before it points at the mounted path (so a
// pass cannot mean "something reached a real host agent instead"), the
// enumerated fingerprint is compared against the decoy's own, and the
// resulting signature is verified with `ssh-keygen -Y verify` against the
// decoy's own public key — a signature that merely exists proves nothing
// about which agent produced it.
func TestDirectoryBindOfALiveAgentSocketEnumeratesAndSignsWithTheDecoy(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	requirePython(t)
	for _, bin := range []string{"ssh-keygen", "ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed; nothing to measure", bin)
		}
	}
	proj, _ := shortTarget(t)
	parent := filepath.Dir(proj)

	// The PRIVATE key lives in its OWN scratch directory, granted to the
	// sandbox by NOTHING — not @parent-ro, not any test profile, nothing.
	// That placement IS the mechanism this test measures, not incidental
	// tidiness: `ssh-keygen -Y sign -f <pubkey>` silently uses a co-located
	// PRIVATE key file instead of asking the agent, when one is present next
	// to the public key (measured while designing this fixture). With the
	// private key kept out of every granted tree, the sandbox has no local
	// key to fall back on, so a successful sign below can only have gone
	// through the agent protocol. Moving this key under the parent (or
	// anywhere else the sandbox can reach) would silently turn this into a
	// test of file exposure and make it pass even with the socket residual
	// fully closed — do not "clean up" this split without re-reading why it
	// is here.
	privDir, err := os.MkdirTemp("", "snug-decoy-priv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privDir) })

	// The exposed directory holds ONLY the agent socket and the copied
	// public key, and it sits under the target's PARENT — @parent-ro grants
	// it identity-mapped, so the guest path equals this host path exactly.
	exposedDir := filepath.Join(parent, "live-agent")
	if err := os.Mkdir(exposedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	privKey := filepath.Join(privDir, "decoy_id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
		"snug-292a-decoy", "-f", privKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	sock := filepath.Join(exposedDir, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	agent.Env = []string{"HOME=" + privDir, "PATH=" + os.Getenv("PATH")}
	if err := agent.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	})
	waitForSocket(t, sock)

	add := exec.Command("ssh-add", privKey)
	add.Env = []string{"HOME=" + privDir, "SSH_AUTH_SOCK=" + sock, "PATH=" + os.Getenv("PATH")}
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}

	pubBytes, err := os.ReadFile(privKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	exposedPub := filepath.Join(exposedDir, "decoy_id.pub")
	if err := os.WriteFile(exposedPub, pubBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	decoyFingerprint := fingerprintOf(t, exposedPub)

	const messageBody = "snug-292a-decoy-message\n"
	message := filepath.Join(proj, "message.txt")
	if err := os.WriteFile(message, []byte(messageBody), 0o644); err != nil {
		t.Fatal(err)
	}

	freshSock := filepath.Join(exposedDir, "payload-made-this.sock")
	const namespace = "snug-292a-test"
	script := fmt.Sprintf(`
echo "PRE-SOCK:[$SSH_AUTH_SOCK]"
export SSH_AUTH_SOCK=%[1]q
echo "ENUM:$(ssh-add -l 2>&1)"
ssh-keygen -Y sign -f %[2]q -n %[3]s %[4]q 2>&1
echo "SIGN-EXIT:$?"
python3 - <<'PY' 2>&1
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(%[5]q)
    print("UNEXPECTED-BIND-SUCCEEDED")
except OSError as e:
    print("BIND-REFUSED:", e)
PY
`, sock, exposedPub, namespace, message, freshSock)

	// The socket sits under the target's PARENT, which is @parent-ro's grant and
	// has not been a default since issue #550 — so the profile is named here.
	r := run(t, []string{"-p", "@parent-ro"}, proj, script).mustRun(t)

	// The load-bearing precondition: prove the payload had NOTHING before it
	// deliberately pointed itself at the mounted socket. Without this, a bug
	// that let the payload reach a REAL host agent (rather than the directory
	// bind under test) would make this test pass for the wrong reason.
	if !strings.Contains(r.out, "PRE-SOCK:[]") {
		t.Fatalf("SSH_AUTH_SOCK was not empty before the payload set it — this test can only "+
			"claim the directory-bind residual if the sandbox started with no agent reachable at "+
			"all:\n%s", r.out)
	}

	if !strings.Contains(r.out, "ENUM:") || !strings.Contains(r.out, decoyFingerprint) {
		t.Fatalf("ssh-add -l through the mounted directory did not enumerate the DECOY key "+
			"(want fingerprint %s) — enumeration is the half @ssh-agent (agent-proxy) exists to "+
			"refuse entirely:\n%s", decoyFingerprint, r.out)
	}
	if !strings.Contains(r.out, "SIGN-EXIT:0") {
		t.Fatalf("ssh-keygen -Y sign through the mounted agent socket did not succeed — signing "+
			"is the half @ssh-agent's own doc comment says it CANNOT restrain even when the proxy "+
			"is used as designed:\n%s", r.out)
	}
	if !strings.Contains(r.out, "BIND-REFUSED") {
		t.Errorf("creating a FRESH socket inside the read-only-granted directory did not report "+
			"a refusal — the residual is bounded to using an endpoint a host process already "+
			"made, never manufacturing a fresh one:\n%s", r.out)
	}
	if strings.Contains(r.out, "UNEXPECTED-BIND-SUCCEEDED") {
		t.Fatalf("the sandbox created a NEW socket inside a read-only bind:\n%s", r.out)
	}

	sigPath := message + ".sig"
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("no signature file was produced at %s: %v\n%s", sigPath, err, r.out)
	}

	// Tie the signature to the DECOY specifically, not merely to "some
	// signature exists": verify it against the decoy's own public key with
	// ssh-keygen's own verifier, entirely on the host, independent of
	// anything the sandbox reported about itself.
	principal := "decoy@" + namespace
	allowedSigners := filepath.Join(privDir, "allowed_signers")
	if err := os.WriteFile(allowedSigners,
		[]byte(principal+" "+strings.TrimSpace(string(pubBytes))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	verify := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowedSigners,
		"-I", principal, "-n", namespace, "-s", sigPath)
	verify.Stdin = strings.NewReader(messageBody)
	out, verr := verify.CombinedOutput()
	if verr != nil {
		t.Fatalf("the signature the sandbox produced does NOT verify against the DECOY's public "+
			"key — a signature merely existing proves nothing about which agent produced it, and "+
			"this is the assertion that ties it to the decoy specifically: %v\n%s", verr, out)
	}
	if !strings.Contains(string(out), principal) {
		t.Errorf("ssh-keygen -Y verify succeeded but did not name the decoy principal %q:\n%s",
			principal, out)
	}
}

// fingerprintOf runs ssh-keygen -lf on a public key file and returns its
// SHA256 fingerprint, so a test can tie an in-sandbox `ssh-add -l` listing to
// a SPECIFIC key rather than merely asserting that some key was listed.
func fingerprintOf(t *testing.T, pubPath string) string {
	t.Helper()
	out, err := exec.Command("ssh-keygen", "-lf", pubPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -lf %s: %v\n%s", pubPath, err, out)
	}
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "SHA256:") {
			return f
		}
	}
	t.Fatalf("no SHA256 fingerprint in ssh-keygen -lf output:\n%s", out)
	return ""
}
