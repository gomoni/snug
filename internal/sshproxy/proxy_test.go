package sshproxy

import (
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// fakeAgent stands in for the host's ssh-agent and records whether it was
// contacted at all. "The proxy refused" and "the proxy asked upstream and
// relayed a refusal" look identical to the client — only this distinguishes
// them, and the difference is the whole point of answering locally.
type fakeAgent struct {
	path     string
	contacts atomic.Int32
	ln       net.Listener
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{path: path, ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.contacts.Add(1)
			go func() {
				defer c.Close()
				for {
					msg, err := readMessage(c)
					if err != nil {
						return
					}
					if msg[0] == signRequest {
						writeMessage(c, []byte{signResponse, 0, 0, 0, 0})
					} else {
						writeMessage(c, []byte{agentFailure})
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return a
}

// startProxy wires a proxy over a fake agent with one pinned key.
func startProxy(t *testing.T) (client string, up *fakeAgent, pinned []byte) {
	t.Helper()
	dir := t.TempDir()

	// A real ed25519 public key blob: "ssh-ed25519" + 32 bytes.
	blob := appendString(nil, []byte("ssh-ed25519"))
	blob = appendString(blob, make([]byte, 32))
	pub := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " pinned@test\n"
	keyPath := filepath.Join(dir, "pinned.pub")
	if err := os.WriteFile(keyPath, []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	up = newFakeAgent(t)
	sock := filepath.Join(dir, "proxy.sock")
	p, err := New(keyPath, up.path, sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return sock, up, blob
}

func ask(t *testing.T, sock string, payload []byte) []byte {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := writeMessage(c, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// The sandbox must see exactly one key — and the host agent must not even be
// asked, so its other keys are never enumerated.
func TestIdentitiesAnswerIsLocalAndPinned(t *testing.T) {
	sock, up, pinned := startProxy(t)

	reply := ask(t, sock, []byte{requestIdentities})
	if reply[0] != identitiesAnswer {
		t.Fatalf("reply type %d, want IDENTITIES_ANSWER", reply[0])
	}
	if n := binary.BigEndian.Uint32(reply[1:5]); n != 1 {
		t.Fatalf("advertised %d keys, want exactly 1", n)
	}
	blob, _, ok := takeString(reply[5:])
	if !ok || string(blob) != string(pinned) {
		t.Error("the advertised key is not the pinned one")
	}
	if up.contacts.Load() != 0 {
		t.Error("the host agent was contacted; its other keys should never be enumerated")
	}
}

// Signing with the pinned key is the one thing that reaches the host agent.
func TestSignWithPinnedKeyIsForwarded(t *testing.T) {
	sock, up, pinned := startProxy(t)

	req := append([]byte{signRequest}, appendString(nil, pinned)...)
	req = appendString(req, []byte("data to sign"))
	req = binary.BigEndian.AppendUint32(req, 0)

	if reply := ask(t, sock, req); reply[0] != signResponse {
		t.Fatalf("reply type %d, want SIGN_RESPONSE", reply[0])
	}
	if up.contacts.Load() != 1 {
		t.Error("a pinned-key signature should reach the host agent")
	}
}

// THE test: any other key is refused, and the host agent is never asked. If the
// request were forwarded, a key the human has loaded would be usable by the
// sandbox purely because the agent holds it.
func TestSignWithOtherKeyIsRefusedWithoutAskingUpstream(t *testing.T) {
	sock, up, _ := startProxy(t)

	other := appendString(nil, []byte("ssh-ed25519"))
	other = appendString(other, []byte("ANOTHER KEY 32 bytes long .. xxx"))

	req := append([]byte{signRequest}, appendString(nil, other)...)
	req = appendString(req, []byte("data"))
	req = binary.BigEndian.AppendUint32(req, 0)

	if reply := ask(t, sock, req); reply[0] != agentFailure {
		t.Fatalf("reply type %d, want FAILURE for a non-pinned key", reply[0])
	}
	if up.contacts.Load() != 0 {
		t.Error("the host agent was asked to sign with a key the sandbox may not use")
	}
}

// Everything that mutates the human's agent is refused, and never forwarded.
func TestMutatingRequestsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  byte
	}{
		{"add a key to the host agent", addIdentity},
		{"add a constrained key", addIDConstrained},
		{"add a smartcard key", addSmartcardKey},
		{"remove one key", removeIdentity},
		{"remove ALL keys", removeAllIdentities},
		{"remove a smartcard key", removeSmartcardKey},
		{"lock the agent", lock},
		{"unlock the agent", unlock},
		{"an extension (incl. session-bind)", extension},
		{"an unknown message type", 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, up, _ := startProxy(t)
			if reply := ask(t, sock, []byte{tc.typ}); reply[0] != agentFailure {
				t.Errorf("reply type %d, want FAILURE", reply[0])
			}
			if up.contacts.Load() != 0 {
				t.Error("request reached the host agent; it should have been refused here")
			}
		})
	}
}

// A length prefix read from the sandbox is attacker-controlled. Unbounded, it
// is a memory-exhaustion primitive aimed at snug itself.
func TestOversizedMessageIsRejected(t *testing.T) {
	sock, _, _ := startProxy(t)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Claim 4 GiB without sending it.
	if _, err := c.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	if _, err := readMessage(c); err == nil {
		t.Error("proxy accepted an absurd message length instead of closing the connection")
	}
}

// The socket must not be usable by other users on the machine: anything that
// can connect can ask for a signature.
func TestSocketIsPrivate(t *testing.T) {
	sock, _, _ := startProxy(t)
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("agent socket is mode %#o; it must not be group- or world-accessible", perm)
	}
}

// No agent to proxy is an error, not a silent no-op that leaves the sandbox
// wondering why signing fails.
func TestMissingUpstreamIsAnError(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pub")
	blob := appendString(nil, []byte("ssh-ed25519"))
	blob = appendString(blob, make([]byte, 32))
	os.WriteFile(key, []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" c\n"), 0o600)

	if _, err := New(key, "", filepath.Join(dir, "s.sock"), nil); err == nil {
		t.Error("expected an error when the host has no ssh-agent")
	}
}
