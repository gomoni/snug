package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// A dry run must have started NOTHING. Issue #21: --dry-run created
// $XDG_RUNTIME_DIR/snug/run-<pid>/ and bound the ssh-agent proxy's listening
// socket inside it, then served it — and on a piped invocation killed by
// SIGPIPE (`snug --dry-run -p <identity> <dir> | head`) the deferred cleanup
// never ran, so the directory and the socket were left on the host.
//
// The rule is applied one indirection up too: main.go skips openRuntimeDir
// entirely on a dry run. startIdentity and startContainersScreen opened their
// own.
//
// THE POSITIVE CONTROL IS THE POINT OF THIS FILE. "No run-* directory
// appeared" is equally true of a test whose $XDG_RUNTIME_DIR was never
// consulted, of a policy that carried no identity, and of a startIdentity that
// returned at its first line. Each test below therefore does the same work
// twice — once with dryRun and once without — and requires the real run to
// produce exactly what the dry run must not.
func TestDryRunStartsNoSSHAgentProxy(t *testing.T) {
	base := shortRuntimeDir(t)
	// The fixtures live OUTSIDE the directory being measured: base is swept
	// for "did a dry run create anything", and a pinned key or a stand-in
	// agent socket sitting in it would answer that question for it.
	fixtures := shortTempDir(t)
	key, blob := writePinnedPubKey(t, fixtures)
	t.Setenv("SSH_AUTH_SOCK", fakeUpstreamAgent(t, fixtures, nil, blob))

	dry := identityPolicy(key)
	cleanup, err := startIdentity(dry, false, true)
	if err != nil {
		t.Fatalf("a dry run refused an identity profile: %v", err)
	}
	defer cleanup()

	// The screen must still NAME the socket, or the fix has traded a leak for
	// a --dry-run that stops describing what the real run mounts.
	sock := boundSocketPath(t, dry, policy.AgentSocketGuest)
	want, err := plannedSocket("ssh-agent.sock")
	if err != nil {
		t.Fatal(err)
	}
	if sock != want {
		t.Errorf("a dry run named the agent socket %q, want %q — the path a real run would "+
			"bind", sock, want)
	}
	if left := entriesUnder(t, base); len(left) != 0 {
		t.Errorf("a dry run created %v under $XDG_RUNTIME_DIR; it must start nothing and "+
			"leave nothing", left)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("a dry run bound the agent socket at %s (lstat err=%v)", sock, err)
	}

	// POSITIVE CONTROL: the identical call without dryRun creates the run
	// directory AND binds a socket a client can connect to. Without this the
	// assertions above pass on a build where startIdentity does nothing at
	// all — which is exactly the shape issue #21's own test note warns about.
	real := identityPolicy(key)
	realCleanup, err := startIdentity(real, false, false)
	if err != nil {
		t.Fatalf("control: a real run could not start the agent proxy: %v", err)
	}
	defer realCleanup()

	realSock := boundSocketPath(t, real, policy.AgentSocketGuest)
	if realSock != want {
		t.Errorf("control: a real run bound %q while the dry run named %q — the dry run is "+
			"describing a path the real run does not use", realSock, want)
	}
	fi, err := os.Lstat(realSock)
	if err != nil {
		t.Fatalf("control: a real run did not bind the agent socket at %s: %v", realSock, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control: %s exists but is not a socket (mode %v)", realSock, fi.Mode())
	}
	c, err := net.Dial("unix", realSock)
	if err != nil {
		t.Fatalf("control: nothing is listening on %s, so this test cannot tell a proxy that "+
			"was started from one that was not: %v", realSock, err)
	}
	c.Close()
}

// TestDryRunNeverAsksTheAgentToSign is the same "started nothing" rule
// applied to the sign probe specifically: a dry run must not send a
// SIGN_REQUEST to the host agent even when the profile pins a signing_key,
// because startIdentity returns before sshproxy.New (and therefore before
// probeUpstream's phase 2) on a dry run. TestDryRunStartsNoSSHAgentProxy above
// cannot tell this apart from a dry run that never even reaches the
// signing_key branch — REQUEST_IDENTITIES is the only message its fixture
// answers — so this one counts SIGN_REQUESTs specifically.
func TestDryRunNeverAsksTheAgentToSign(t *testing.T) {
	fixtures := shortTempDir(t)
	key, keyBlob := writePinnedPubKey(t, fixtures)
	signFixtures := shortTempDir(t) // a second directory: writePinnedPubKey always names its file id.pub
	signKey, signBlob := writePinnedPubKey(t, signFixtures)

	var signRequests atomic.Int32
	t.Setenv("SSH_AUTH_SOCK", fakeUpstreamAgent(t, fixtures, &signRequests, keyBlob, signBlob))

	dry := identityPolicyWithSigningKey(key, signKey)
	cleanup, err := startIdentity(dry, false, true)
	if err != nil {
		t.Fatalf("a dry run refused an identity profile with a signing key: %v", err)
	}
	defer cleanup()
	if n := signRequests.Load(); n != 0 {
		t.Errorf("a dry run sent %d SIGN_REQUESTs to the host agent; a dry run must start "+
			"nothing, including the startup sign probe", n)
	}

	// POSITIVE CONTROL, and it is the point of this test: without it, the zero
	// above passes equally on a startIdentity that silently does nothing at
	// all for identity.signing_key. The identical policy WITHOUT dryRun must
	// send exactly one SIGN_REQUEST — sshproxy.New's startup probe for the
	// one MustSign pin, identity.signing_key — over the one connection
	// probeUpstream already holds open for the identities list.
	real := identityPolicyWithSigningKey(key, signKey)
	realCleanup, err := startIdentity(real, false, false)
	if err != nil {
		t.Fatalf("control: a real run with a signing key could not start: %v", err)
	}
	defer realCleanup()
	if n := signRequests.Load(); n != 1 {
		t.Errorf("control: a real run sent %d SIGN_REQUESTs, want exactly 1 (the MustSign "+
			"startup probe for identity.signing_key)", n)
	}
}

// The container proxy's dry-run path is the same shape and was the same bug:
// startContainersScreen opened the runtime directory and bound podman.sock for
// real, purely so the MOUNTS section could show a path.
func TestDryRunStartsNoContainerProxy(t *testing.T) {
	base := shortRuntimeDir(t)

	dry := &policy.Policy{
		Mounts: map[string]policy.Mount{},
		Env:    map[string]policy.EnvVar{},
	}
	if _, err := startContainersScreen(dry); err != nil {
		t.Fatalf("the container dry-run screen failed: %v", err)
	}

	sock := boundSocketPath(t, dry, containerSocketGuest)
	want, err := plannedSocket("podman.sock")
	if err != nil {
		t.Fatal(err)
	}
	if sock != want {
		t.Errorf("the dry-run screen named the container socket %q, want %q", sock, want)
	}
	if left := entriesUnder(t, base); len(left) != 0 {
		t.Errorf("the container dry-run screen created %v under $XDG_RUNTIME_DIR", left)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("the container dry-run screen bound %s (lstat err=%v)", sock, err)
	}

	// POSITIVE CONTROL, and it is what makes the path assertion mean
	// something: the directory a REAL run opens produces the identical socket
	// path, so "the screen names where the socket would be" is checked rather
	// than asserted against a second copy of plannedSocket's own arithmetic.
	// It also proves $XDG_RUNTIME_DIR is the directory being measured — this
	// call is the one that creates something under it.
	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatalf("control: openRuntimeDir: %v", err)
	}
	got, err := rt.Socket("podman.sock")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("control: a real run's socket path is %q while the dry run showed %q", got, want)
	}
	if left := entriesUnder(t, base); len(left) == 0 {
		t.Error("control: a real run created nothing under $XDG_RUNTIME_DIR either, so the " +
			"assertions above cannot distinguish a dry run that starts nothing from a test " +
			"pointing at the wrong directory")
	}
}

// identityPolicy is the smallest policy that reaches the agent-proxy arm of
// startIdentity: an agent-proxy identity pinned to key.
func identityPolicy(key string) *policy.Policy {
	return &policy.Policy{
		Home:   "/home/u",
		Mounts: map[string]policy.Mount{},
		Env:    map[string]policy.EnvVar{},
		Identity: &policy.Identity{
			SSH: policy.IdentitySSH{Key: key, Agent: policy.SSHAgentProxy},
		},
	}
}

// identityPolicyWithSigningKey is identityPolicy plus a pinned signing_key,
// which is what makes sshproxy.New run the MustSign sign probe
// TestDryRunNeverAsksTheAgentToSign exists to check — identityPolicy alone
// never reaches it, since MustSign is set only for identity.git.signing_key.
func identityPolicyWithSigningKey(key, signKey string) *policy.Policy {
	p := identityPolicy(key)
	p.Identity.Git.SigningKey = signKey
	return p
}

// boundSocketPath is the HOST path of the mount at guest, which is where both
// proxies publish the socket they did — or did not — bind.
func boundSocketPath(t *testing.T, p *policy.Policy, guest string) string {
	t.Helper()
	for _, m := range p.Mounts {
		if m.Guest == guest {
			return m.Host
		}
	}
	t.Fatalf("no mount at %s, so nothing named a socket at all:\n%+v", guest, p.Mounts)
	return ""
}

func entriesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			out = append(out, strings.TrimPrefix(path, dir+"/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return out
}

// shortRuntimeDir points $XDG_RUNTIME_DIR at a directory whose NAME is short.
// t.TempDir() names the directory after the test, and a unix socket path is
// capped at 108 bytes (sun_path) — with this test's name in it, the control's
// net.Listen fails with "invalid argument" and the failure reads as a bug in
// the code under test rather than in the fixture. Measured while writing this.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "snugrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// writePinnedPubKey writes a real ed25519 public key in OpenSSH wire format:
// sshproxy.New parses it, so a placeholder string would make the control fail
// for the wrong reason. It returns the wire-format blob alongside the path so
// fakeUpstreamAgent can hold exactly this key — sshproxy.New now probes the
// upstream for it before binding its own socket (issue #453), and the
// control below needs that probe to succeed.
func writePinnedPubKey(t *testing.T, dir string) (path string, blob []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	blob = appendSSHString(blob, []byte("ssh-ed25519"))
	blob = appendSSHString(blob, pub)
	path = filepath.Join(dir, "id.pub")
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " pinned@test\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, blob
}

func appendSSHString(dst, s []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	return append(append(dst, n[:]...), s...)
}

// fakeUpstreamAgent is a listening unix socket standing in for the host's own
// ssh-agent. sshproxy.New refuses outright when SSH_AUTH_SOCK is unset, so
// without one the real-run control could not start at all — and a control that
// cannot run is not a control.
//
// It answers REQUEST_IDENTITIES with held, because sshproxy.New (issue #453)
// now probes the upstream for the pinned key before it will bind its own
// socket. Before this it only accepted and never replied, which is exactly
// the shape TestProbeNoAnswer (internal/sshproxy) exists to refuse: this
// file's own real-run control would have blocked for probeTimeout and then
// failed to start, which is the fixture breaking rather than the code under
// test.
//
// signRequests, if non-nil, is incremented on every SIGN_REQUEST this agent
// answers — TestDryRunNeverAsksTheAgentToSign is the one caller that needs to
// tell "a dry run started nothing" from "a dry run started something that
// never got asked to sign", which a REQUEST_IDENTITIES-only fixture cannot
// distinguish. Every SIGN_REQUEST for a held key gets a non-empty stub
// signature back: sshproxy's own probeSign treats a zero-length signature
// string as "not signed" (see internal/sshproxy/proxy_test.go's fakeAgent),
// and a fixture that failed the MustSign probe would make the positive
// control below fail for the wrong reason.
func fakeUpstreamAgent(t *testing.T, dir string, signRequests *atomic.Int32, held ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					msg, err := readAgentFrame(c)
					if err != nil {
						return
					}
					switch {
					case len(msg) > 0 && msg[0] == agentRequestIdentities:
						writeAgentFrame(c, identitiesAnswerFrame(held))
					case len(msg) > 0 && msg[0] == agentSignRequest:
						if signRequests != nil {
							signRequests.Add(1)
						}
						writeAgentFrame(c, signResponseFrame())
					default:
						writeAgentFrame(c, []byte{agentMsgFailure})
					}
				}
			}()
		}
	}()
	return path
}

// The constants and frame helpers below are a MINIMAL, local copy of the
// ssh-agent wire format sshproxy already implements — duplicated rather than
// imported so this fixture is not reaching into another package's unexported
// wire code for a handful of bytes. See internal/sshproxy/proxy.go for the
// real (and only security-relevant) implementation.
const (
	agentMsgFailure        = 5
	agentRequestIdentities = 11
	agentIdentitiesAnswer  = 12
	agentSignRequest       = 13
	agentSignResponse      = 14
)

// signResponseFrame is a SIGN_RESPONSE carrying a non-empty stub signature —
// only its presence is checked anywhere in this file, never its content.
func signResponseFrame() []byte {
	return appendSSHString([]byte{agentSignResponse}, []byte{0x01})
}

func identitiesAnswerFrame(held [][]byte) []byte {
	out := []byte{agentIdentitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, uint32(len(held)))
	for _, b := range held {
		out = appendSSHString(out, b)
		out = appendSSHString(out, []byte("pinned@test"))
	}
	return out
}

func readAgentFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeAgentFrame(w io.Writer, payload []byte) error {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	_, err := w.Write(append(out, payload...))
	return err
}
