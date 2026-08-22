package sshproxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/hostread"
)

// ── regression tests for issue #337: identity.ssh_key read with hostread ────
//
// New (via parsePublicKey) used to read id.SSHKey with a bare os.ReadFile.
// ssh_key is resolved under the target, which @cwd-rw makes writable, so a
// PREVIOUS run's own payload can leave `rm key.pub && mkfifo key.pub` behind
// for the next one: os.ReadFile then blocks in open(2) forever, before the
// sandbox exists, with no output and no exit code (exit=124 measured on
// f124dc7 by the redteam round on #295). A symlink to /dev/zero or a sparse
// file turned the same call into an unbounded host-side allocation.
//
// These are the three tests the issue owes: a FIFO must terminate with a
// NAMED refusal (not merely a non-zero exit — a test that waits on a hang and
// reads the timeout as a pass is the vacuous shape #337 warns against), an
// oversized file must be refused ON THE CAP, and a normal .pub must still
// stage the proxy socket in the same run as the refusals.

// TestNewRefusesFIFOKeyByName is the FIFO case. The deadline is load-bearing,
// not a nicety: without hostread's O_NONBLOCK open this blocks in open(2)
// forever, and a version of this test with no deadline would simply never
// finish — go test's own package timeout would eventually kill it, far from
// here and with no diagnostic naming the cause. That is exactly the shape
// this test exists to turn into a named, immediate failure instead.
func TestNewRefusesFIFOKeyByName(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pub")
	if err := syscall.Mkfifo(keyPath, 0o600); err != nil {
		t.Skipf("SKIP: cannot create a FIFO here: %v", err)
	}

	type result struct {
		p   *Proxy
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := New(keyPath, "/does/not/matter", filepath.Join(dir, "proxy.sock"), nil)
		done <- result{p, err}
	}()

	select {
	case r := <-done:
		if r.p != nil {
			r.p.Close()
			t.Fatal("New started a proxy pinned to a FIFO instead of refusing it")
		}
		if r.err == nil {
			t.Fatal("New accepted a FIFO at the ssh_key path with no error")
		}
		if !strings.Contains(r.err.Error(), keyPath) {
			t.Errorf("refusal does not name the path %q: %v", keyPath, r.err)
		}
		if !strings.Contains(r.err.Error(), "not a regular file") {
			t.Errorf("refusal does not name the node type (FIFO): %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("New did not return within 5s for a FIFO at the ssh_key path — this is the " +
			"exact hang issue #337 measured (exit=124, blocked in open(2), no sandbox created); " +
			"the O_NONBLOCK discipline in internal/hostread exists to prevent it")
	}
}

// TestNewRefusesOversizedKey is the cap case: a file that opens and stats
// fine but whose CONTENT exceeds hostread.MaxSSHPublicKeyBytes must be
// refused for exceeding the cap, not for some unrelated reason (a fixture
// that merely fails to parse as a key would pass this test for the wrong
// reason).
func TestNewRefusesOversizedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pub")

	// One line, well-formed up to the point of being absurdly long, so a
	// failure here is legibly about SIZE and not about "not a regular file"
	// or "does not parse as ssh-ed25519 <blob>".
	oversized := "ssh-ed25519 " + strings.Repeat("A", int(hostread.MaxSSHPublicKeyBytes)) + " way-over-cap\n"
	if len(oversized) <= int(hostread.MaxSSHPublicKeyBytes) {
		t.Fatalf("test fixture is %d bytes, not over the %d-byte cap", len(oversized), hostread.MaxSSHPublicKeyBytes)
	}
	writeKeyFile(t, keyPath, oversized)

	_, err := New(keyPath, "/does/not/matter", filepath.Join(dir, "proxy.sock"), nil)
	if err == nil {
		t.Fatal("New accepted a key file over the cap with no error")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("refusal does not say the file exceeded the cap: %v", err)
	}
}

// TestNewPositiveControlNormalKeyStagesSocket is the control the two refusals
// above depend on: without it, a New that refuses EVERY key — FIFO, oversized,
// or otherwise — would still pass both tests above. A normal .pub must still
// parse, and the proxy must still come up and answer on its socket.
func TestNewPositiveControlNormalKeyStagesSocket(t *testing.T) {
	dir := t.TempDir()
	blob := appendString(nil, []byte("ssh-ed25519"))
	blob = appendString(blob, make([]byte, 32))
	pub := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " control@test\n"
	keyPath := filepath.Join(dir, "key.pub")
	writeKeyFile(t, keyPath, pub)

	up := newFakeAgent(t)
	sock := filepath.Join(dir, "proxy.sock")
	p, err := New(keyPath, up.path, sock, nil)
	if err != nil {
		t.Fatalf("control: an ordinary .pub was refused: %v", err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	reply := ask(t, sock, []byte{requestIdentities})
	if reply[0] != identitiesAnswer {
		t.Fatalf("control: reply type %d, want IDENTITIES_ANSWER — the proxy did not stage "+
			"the socket at all, so the refusals above prove nothing", reply[0])
	}
	if got, _, ok := takeString(reply[5:]); !ok || string(got) != string(blob) {
		t.Error("control: the proxy answered, but not with the pinned key")
	}
}

func writeKeyFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
