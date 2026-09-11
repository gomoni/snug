package sshproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/hostread"
)

// signCall is one SIGN_REQUEST the fake agent answered, kept so a test can
// assert what the probe actually put on the wire — the payload it signed and
// the flags it asked for — rather than only whether the call happened.
type signCall struct {
	blob  []byte
	data  []byte
	flags uint32
}

// fakeAgent stands in for the host's ssh-agent and records whether it was
// contacted at all. "The proxy refused" and "the proxy asked upstream and
// relayed a refusal" look identical to the client — only this distinguishes
// them, and the difference is the whole point of answering locally.
//
// holds/holdComments are the SET of keys this fake agent has loaded, which is
// deliberately allowed to be WIDER than what the proxy pins — that is what
// makes the leak assertions in this file real assertions rather than ones that
// would pass against an agent with nothing to leak in the first place.
//
// refuseSign, signDelay and signMarker exist to give the sign-probe tests
// (TestListedButUnsignableKeyRefusesTheRun and its neighbours) an agent that
// LISTS a key and then behaves the way `ssh-add -c` or `ssh-add -h` measurably
// do: present at REQUEST_IDENTITIES, refused or slow at SIGN_REQUEST.
type fakeAgent struct {
	path     string
	contacts atomic.Int32
	ln       net.Listener

	mu           sync.Mutex
	holds        [][]byte
	holdComments []string
	refuseSign   map[string]bool // blob (as a string key) -> refuse every SIGN_REQUEST naming it
	signDelay    time.Duration   // sleep this long before answering any SIGN_REQUEST
	signMarker   []byte          // signature bytes returned on a successful sign; a fixed stub when nil
	signCalls    []signCall
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
					switch {
					case len(msg) > 0 && msg[0] == requestIdentities:
						writeMessage(c, a.identitiesAnswerBytes())
					case len(msg) > 0 && msg[0] == signRequest:
						blob, rest, ok := takeString(msg[1:])
						var data []byte
						var flags uint32
						if ok {
							data, rest, ok = takeString(rest)
						}
						if ok && len(rest) >= 4 {
							flags = binary.BigEndian.Uint32(rest[:4])
						}
						if ok {
							a.recordSign(blob, data, flags)
						}
						if d := a.getSignDelay(); d > 0 {
							time.Sleep(d)
						}
						if ok && a.holdsBlob(blob) && !a.refusesSign(blob) {
							sig := appendString([]byte{signResponse}, a.signature())
							writeMessage(c, sig)
						} else {
							writeMessage(c, []byte{agentFailure})
						}
					default:
						writeMessage(c, []byte{agentFailure})
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return a
}

// setHolds replaces the whole held set. Callers use it before the proxy under
// test has dialled in (construction has not happened yet, or has already
// finished and no client is connected), which is why a lock around the whole
// file is not needed here — removeHold is the one mutation made concurrently
// with a live connection, and it takes the same lock heldBlobs and
// holdsBlob do.
func (a *fakeAgent) setHolds(blobs [][]byte, comments []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.holds = blobs
	a.holdComments = comments
}

// removeHold drops one key from the held set, guarded by the same lock the
// connection handler uses — it is called WHILE a proxy built against this
// fixture may already be serving requests (TestSignPathConsultsTheLiveAgentNotTheProbe).
func (a *fakeAgent) removeHold(blob []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, b := range a.holds {
		if string(b) == string(blob) {
			a.holds = append(a.holds[:i], a.holds[i+1:]...)
			if i < len(a.holdComments) {
				a.holdComments = append(a.holdComments[:i], a.holdComments[i+1:]...)
			}
			return
		}
	}
}

func (a *fakeAgent) heldBlobs() ([][]byte, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]byte(nil), a.holds...), append([]string(nil), a.holdComments...)
}

func (a *fakeAgent) holdsBlob(b []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.holds {
		if string(k) == string(b) {
			return true
		}
	}
	return false
}

// setRefuseSign marks blob so every SIGN_REQUEST naming it gets
// SSH_AGENT_FAILURE even though holdsBlob still reports it present — the
// shape measured for `ssh-add -c` with no askpass and for `ssh-add -h`.
func (a *fakeAgent) setRefuseSign(blob []byte, refuse bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuseSign == nil {
		a.refuseSign = make(map[string]bool)
	}
	a.refuseSign[string(blob)] = refuse
}

func (a *fakeAgent) refusesSign(blob []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refuseSign[string(blob)]
}

// setSignDelay makes every subsequent SIGN_REQUEST block for d before this
// fake agent answers it, standing in for an askpass dialog or a slow
// confirmation on the host.
func (a *fakeAgent) setSignDelay(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signDelay = d
}

func (a *fakeAgent) getSignDelay() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signDelay
}

// setSignMarker fixes the bytes a successful SIGN_RESPONSE carries as its
// signature, so a test can look for them turning up somewhere they must not
// (TestSignProbeSignatureNeverLeavesNew).
func (a *fakeAgent) setSignMarker(marker []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signMarker = marker
}

func (a *fakeAgent) signature() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signMarker != nil {
		return a.signMarker
	}
	// Deliberately non-empty: an agent-format SIGN_RESPONSE with a
	// zero-length signature string is exactly what parses as "not signed" —
	// probeSign requires len(sig) > 0 — so a stub with nothing in it would
	// make every MustSign probe against a healthy fake agent fail.
	return []byte{0x01}
}

func (a *fakeAgent) recordSign(blob, data []byte, flags uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signCalls = append(a.signCalls, signCall{
		blob:  append([]byte(nil), blob...),
		data:  append([]byte(nil), data...),
		flags: flags,
	})
}

func (a *fakeAgent) sawSignCalls() []signCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]signCall(nil), a.signCalls...)
}

func (a *fakeAgent) identitiesAnswerBytes() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []byte{identitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, uint32(len(a.holds)))
	for i, b := range a.holds {
		out = appendString(out, b)
		c := ""
		if i < len(a.holdComments) {
			c = a.holdComments[i]
		}
		out = appendString(out, []byte(c))
	}
	return out
}

// ed25519Blob returns a syntactically valid, deterministically DISTINCT
// ed25519 wire-format blob: the marker byte repeated 32 times. Deterministic
// rather than crypto/rand so a failing assertion's diff is reproducible, and
// distinct markers so three keys in one test are never accidentally equal.
func ed25519Blob(marker byte) []byte {
	b := appendString(nil, []byte("ssh-ed25519"))
	key := make([]byte, 32)
	for i := range key {
		key[i] = marker
	}
	return appendString(b, key)
}

func writePubKeyBlob(t *testing.T, dir, name string, blob []byte, comment string) string {
	t.Helper()
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment + "\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startProxy wires a proxy pinned to TWO keys — ssh_key and signing_key,
// which is #453's whole point — over a fake agent that ALSO holds a third,
// unpinned key with a distinctive comment. The third key is what makes
// "absent from the reply" a real assertion in the tests below rather than one
// that would pass against an agent with nothing to leak in the first place.
func startProxy(t *testing.T) (sock string, up *fakeAgent, authBlob, signBlob []byte) {
	t.Helper()
	dir := t.TempDir()

	authBlob = ed25519Blob(0xA1)
	signBlob = ed25519Blob(0xB2)
	other := ed25519Blob(0xC3)
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	up = newFakeAgent(t)
	up.setHolds([][]byte{authBlob, signBlob, other},
		[]string{"auth@test", "signing@test", "the-third-key-nobody-pinned"})

	sockPath := filepath.Join(dir, "proxy.sock")
	p, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath},
	}, up.path, sockPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	// BASELINE, and the reason every `contacts != 0` assertion in this file
	// means "contacted AFTER New returned" rather than "contacted at all": New
	// itself now probes the upstream once at startup (see probeUpstream), so a
	// bare `contacts == 0` check right after construction would fail against a
	// CORRECT proxy. Confirmed once, here, then reset — the tests below keep
	// the meaning they had before the probe existed.
	if n := up.contacts.Load(); n != 1 {
		t.Fatalf("New's own startup probe contacted the upstream %d times, want exactly 1", n)
	}
	up.contacts.Store(0)

	go p.Serve()
	t.Cleanup(p.Close)
	return sockPath, up, authBlob, signBlob
}

// mustSignFixture builds the standard two-key pin set — identity.ssh_key and
// identity.signing_key — with signing_key marked MustSign, and a fake agent
// that holds and, by default, will sign for both. It does not call New: every
// test using it needs to inspect either New's error or its effect on the fake
// agent's own call log, so the call belongs at the call site and not hidden
// in here.
//
// Kept separate from startProxy rather than adding MustSign there: startProxy
// backs every pre-existing test in this file, and turning it MustSign by
// default would silently turn all of them into sign-probe tests too.
func mustSignFixture(t *testing.T) (keys []PinnedKey, sockPath string, up *fakeAgent, authBlob, signBlob []byte) {
	t.Helper()
	dir := t.TempDir()
	authBlob = ed25519Blob(0xA1)
	signBlob = ed25519Blob(0xB2)
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	up = newFakeAgent(t)
	up.setHolds([][]byte{authBlob, signBlob}, []string{"auth@test", "signing@test"})

	keys = []PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath, MustSign: true},
	}
	sockPath = filepath.Join(dir, "proxy.sock")
	return keys, sockPath, up, authBlob, signBlob
}

// rsaBlob returns a syntactically-shaped ssh-rsa wire blob: the algorithm
// name signFlagsFor actually inspects, with placeholder e/n fields. It does
// not need to be a mathematically valid RSA key — nothing in this package
// verifies key material, only the algorithm name that selects the flags word.
func rsaBlob(marker byte) []byte {
	b := appendString(nil, []byte("ssh-rsa"))
	b = appendString(b, []byte{marker})         // e
	b = appendString(b, []byte{marker, marker}) // n
	return b
}

// maximalPubKey writes the largest .pub file hostread.Required will still
// read — exactly hostread.MaxSSHPublicKeyBytes — shaped to also maximize its
// contribution to identitiesAnswerSize: a one-character type field and a
// 3-byte blob (the smallest multiple of three, so base64 adds no padding) put
// the rest of the budget into the comment, which identitiesAnswer carries in
// full and identitiesAnswerSize counts in full. No trailing newline, so every
// spare byte goes to the comment rather than to a separator New never reads.
func maximalPubKey(t *testing.T, dir, name string, marker byte) (path string, blob []byte, comment string) {
	t.Helper()
	blob = []byte{marker, marker ^ 0xff, marker + 1}
	b64 := base64.StdEncoding.EncodeToString(blob)
	if len(b64) != 4 {
		t.Fatalf("fixture bug: a 3-byte blob must base64-encode to 4 characters with no padding, got %d (%q)",
			len(b64), b64)
	}
	fixed := len("k") + len(" ") + len(b64) + len(" ")
	commentLen := hostread.MaxSSHPublicKeyBytes - fixed
	comment = strings.Repeat("c", commentLen)
	line := "k " + b64 + " " + comment
	if len(line) != hostread.MaxSSHPublicKeyBytes {
		t.Fatalf("fixture bug: constructed pub key is %d bytes, want exactly %d",
			len(line), hostread.MaxSSHPublicKeyBytes)
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, blob, comment
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

func signRequestFor(blob []byte) []byte {
	req := append([]byte{signRequest}, appendString(nil, blob)...)
	req = appendString(req, []byte("data to sign"))
	req = binary.BigEndian.AppendUint32(req, 0)
	return req
}

// The sandbox must see exactly the pinned SET, in the declared order, and the
// host agent must not even be asked — its other keys are never enumerated.
func TestIdentitiesAnswerIsLocalAndPinned(t *testing.T) {
	sock, up, authBlob, signBlob := startProxy(t)

	reply := ask(t, sock, []byte{requestIdentities})
	if reply[0] != identitiesAnswer {
		t.Fatalf("reply type %d, want IDENTITIES_ANSWER", reply[0])
	}
	if n := binary.BigEndian.Uint32(reply[1:5]); n != 2 {
		t.Fatalf("advertised %d keys, want exactly 2", n)
	}
	rest := reply[5:]
	b1, rest, ok := takeString(rest)
	if !ok {
		t.Fatal("could not parse the first advertised identity")
	}
	_, rest, ok = takeString(rest) // its comment
	if !ok {
		t.Fatal("could not parse the first identity's comment")
	}
	b2, _, ok := takeString(rest)
	if !ok {
		t.Fatal("could not parse the second advertised identity")
	}
	if string(b1) != string(authBlob) {
		t.Error("the first advertised key is not ssh_key's blob — declared order is ssh_key then signing_key")
	}
	if string(b2) != string(signBlob) {
		t.Error("the second advertised key is not signing_key's blob")
	}
	if up.contacts.Load() != 0 {
		t.Error("the host agent was contacted; its other keys should never be enumerated")
	}
}

// Both pinned keys sign — the proxy pins a SET, not a single blob, and either
// member of the set must reach the host agent.
func TestBothPinnedKeysCanSign(t *testing.T) {
	sock, up, authBlob, signBlob := startProxy(t)
	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"ssh_key", authBlob},
		{"signing_key", signBlob},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up.contacts.Store(0)
			if reply := ask(t, sock, signRequestFor(tc.blob)); reply[0] != signResponse {
				t.Fatalf("reply type %d, want SIGN_RESPONSE", reply[0])
			}
			if up.contacts.Load() != 1 {
				t.Error("a pinned-key signature should reach the host agent")
			}
		})
	}
}

// THE test: any key outside the pinned SET is refused, and the host agent is
// never asked. The refused key is the THIRD one — genuinely held upstream —
// so the refusal proves membership in the pinned set is the filter, not
// merely "a key the agent does not have either".
func TestSignWithOtherKeyIsRefusedWithoutAskingUpstream(t *testing.T) {
	sock, up, _, _ := startProxy(t)
	blobs, _ := up.heldBlobs()
	other := blobs[2]

	if reply := ask(t, sock, signRequestFor(other)); reply[0] != agentFailure {
		t.Fatalf("reply type %d, want FAILURE for a key that is not in the pinned set", reply[0])
	}
	if up.contacts.Load() != 0 {
		t.Error("the host agent was asked to sign with a key the sandbox may not use")
	}
}

// The leak negative: the upstream's third, unpinned key must appear NOWHERE
// in the IDENTITIES_ANSWER — neither its blob nor its comment — because the
// reply is built locally from the pin set and never from what the agent
// actually holds.
func TestIdentitiesAnswerNeverMentionsTheUnpinnedThirdKey(t *testing.T) {
	sock, up, _, _ := startProxy(t)
	blobs, comments := up.heldBlobs()
	other, otherComment := blobs[2], comments[2]

	reply := ask(t, sock, []byte{requestIdentities})
	if reply[0] != identitiesAnswer {
		t.Fatalf("reply type %d, want IDENTITIES_ANSWER", reply[0])
	}
	if strings.Contains(string(reply), string(other)) {
		t.Error("the reply carries the blob of a key nobody pinned")
	}
	if strings.Contains(string(reply), otherComment) {
		t.Error("the reply carries the comment of a key nobody pinned")
	}
}

// Naming the same file twice — ssh_key and signing_key both pointing at one
// key — advertises ONE entry, and signing with it still works.
func TestDuplicatePinAdvertisesOnce(t *testing.T) {
	dir := t.TempDir()
	blob := ed25519Blob(0xD4)
	path := writePubKeyBlob(t, dir, "dup.pub", blob, "dup@test")

	up := newFakeAgent(t)
	up.setHolds([][]byte{blob}, []string{"dup@test"})

	sock := filepath.Join(dir, "proxy.sock")
	p, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: path},
		{Field: "identity.signing_key", Path: path},
	}, up.path, sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	up.contacts.Store(0)
	go p.Serve()
	t.Cleanup(p.Close)

	reply := ask(t, sock, []byte{requestIdentities})
	if n := binary.BigEndian.Uint32(reply[1:5]); n != 1 {
		t.Fatalf("naming one file twice advertised %d identities, want 1", n)
	}
	if r := ask(t, sock, signRequestFor(blob)); r[0] != signResponse {
		t.Fatalf("signing with the duplicated key failed: reply type %d", r[0])
	}
}

// An empty pin set advertises nothing and refuses everything — a proxy that
// looks configured and is not — so New refuses to start one at all.
func TestNewRefusesAnEmptyPinSet(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(nil, "/does/not/matter", filepath.Join(dir, "s.sock"), nil); err == nil {
		t.Fatal("New accepted an empty pin set")
	}
}

// subtle.ConstantTimeCompare(nil, nil) reports a match, so an unguarded empty
// key blob on the wire would authenticate against nothing. This is the one
// reachable half of that trap: a SIGN_REQUEST whose key blob is zero-length
// must still be refused.
//
// The OTHER half — a .pub FILE that decodes to an empty blob — is not
// exercised here: parsePublicKey's own comment states strings.Fields never
// yields an empty field and a non-empty base64 string either decodes to at
// least one byte or errors, so there is no well-formed .pub content this test
// could write that reaches New's `len(blob) == 0` guard. That guard is
// defence in depth for a path this suite could not construct, and this
// comment says so rather than shipping a file-based test that would pass
// without ever exercising it.
func TestSignRequestWithAnEmptyKeyBlobIsRefused(t *testing.T) {
	sock, up, _, _ := startProxy(t)
	req := append([]byte{signRequest}, appendString(nil, nil)...) // zero-length key blob
	req = appendString(req, []byte("data"))
	req = binary.BigEndian.AppendUint32(req, 0)

	if reply := ask(t, sock, req); reply[0] != agentFailure {
		t.Fatalf("reply type %d, want FAILURE for an empty key blob", reply[0])
	}
	if up.contacts.Load() != 0 {
		t.Error("an empty key blob reached the host agent")
	}
}

// The startup probe, on a healthy host, contacts the upstream EXACTLY ONCE
// before New returns — never zero (a proxy with no idea whether it can sign
// is the failure invariant 5 exists to prevent) and never more than one
// (nothing here should retry or double-check).
//
// Renamed from TestProbeContactsUpstreamExactlyOnceWhenBothKeysAreHeld and
// given a MustSign signing key: the probe's phase 2 (a SIGN_REQUEST for every
// MustSign pin) runs on the SAME net.Dial as phase 1's REQUEST_IDENTITIES, so
// an implementation that opened a second connection for the sign probe would
// fail this test at exactly the assertion below — that is the pressure this
// rename exists to keep, now that a MustSign pin is part of the fixture.
func TestProbeContactsUpstreamExactlyOnceForListAndSign(t *testing.T) {
	dir := t.TempDir()
	authBlob := ed25519Blob(0xA1)
	signBlob := ed25519Blob(0xB2)
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	up := newFakeAgent(t)
	up.setHolds([][]byte{authBlob, signBlob}, []string{"auth@test", "signing@test"})

	p, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath, MustSign: true},
	}, up.path, filepath.Join(dir, "proxy.sock"), nil)
	if err != nil {
		t.Fatalf("New refused a run whose upstream holds and will sign with both pinned keys: %v", err)
	}
	t.Cleanup(p.Close)
	if n := up.contacts.Load(); n != 1 {
		t.Fatalf("upstream contacted %d times during New, want exactly 1", n)
	}
}

// The signing key is missing from the upstream: New must refuse, naming the
// field, the path and a fingerprint the human can match against `ssh-add -l`
// — and it must refuse BEFORE the listener is bound, or a refused run leaves
// a socket behind for the caller's cleanup to race.
func TestProbeRefusesWhenUpstreamLacksTheSigningKey(t *testing.T) {
	dir := t.TempDir()
	authBlob := ed25519Blob(0xA1)
	signBlob := ed25519Blob(0xB2) // never added to the agent's held set
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	up := newFakeAgent(t)
	up.setHolds([][]byte{authBlob}, []string{"auth@test"})

	sock := filepath.Join(dir, "proxy.sock")
	_, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath},
	}, up.path, sock, nil)
	if err == nil {
		t.Fatal("New started a proxy for a signing key the upstream does not hold")
	}
	if !strings.Contains(err.Error(), "identity.signing_key") {
		t.Errorf("error does not name identity.signing_key: %v", err)
	}
	if !strings.Contains(err.Error(), signPath) {
		t.Errorf("error does not name the path: %v", err)
	}
	if !strings.Contains(err.Error(), "SHA256:") {
		t.Errorf("error carries no fingerprint to match against `ssh-add -l`: %v", err)
	}
	// THE ORDERING CLAIM, MADE OBSERVABLE FROM OUTSIDE rather than trusted from
	// New's own doc comment: a probe failure that happened AFTER net.Listen
	// would leave a socket file on disk for nothing to ever clean up.
	if _, statErr := os.Stat(sock); !os.IsNotExist(statErr) {
		t.Errorf("a refused probe left a socket at %s (stat err=%v)", sock, statErr)
	}
}

// Same refusal, the other key: even with the signing key present and held,
// a missing AUTH key must still refuse, naming identity.ssh_key.
func TestProbeRefusesWhenUpstreamLacksTheAuthKeyEvenWithSigningKeyPresent(t *testing.T) {
	dir := t.TempDir()
	authBlob := ed25519Blob(0xA1) // never added to the agent's held set
	signBlob := ed25519Blob(0xB2)
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	up := newFakeAgent(t)
	up.setHolds([][]byte{signBlob}, []string{"signing@test"})

	_, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath},
	}, up.path, filepath.Join(dir, "proxy.sock"), nil)
	if err == nil {
		t.Fatal("New started a proxy for an auth key the upstream does not hold")
	}
	if !strings.Contains(err.Error(), "identity.ssh_key") {
		t.Errorf("error does not name identity.ssh_key even though the signing key IS held: %v", err)
	}
}

// The upstream never answers: a socket nothing is listening on, and a
// listener that accepts and then says nothing at all.
func TestProbeNoAnswer(t *testing.T) {
	dir := t.TempDir()
	blob := ed25519Blob(0xA1)
	path := writePubKeyBlob(t, dir, "k.pub", blob, "k@test")

	t.Run("nothing listening", func(t *testing.T) {
		_, err := New([]PinnedKey{{Field: "identity.ssh_key", Path: path}},
			filepath.Join(dir, "no-such.sock"), filepath.Join(dir, "s1.sock"), nil)
		if err == nil {
			t.Fatal("New succeeded dialling a socket nothing is listening on")
		}
	})

	// The deadline is the point, in the same shape TestOversizedMessageIsRejected
	// documents at length: without probeTimeout enforced, a silent upstream
	// blocks New forever, and that failure surfaces as go test's own package
	// timeout, far from here and naming nothing. Here it is a named, immediate
	// failure instead.
	t.Run("listener accepts and never replies", func(t *testing.T) {
		sockPath := filepath.Join(dir, "silent.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c // accepted, then never read from and never written to
			}
		}()

		start := time.Now()
		_, err = New([]PinnedKey{{Field: "identity.ssh_key", Path: path}},
			sockPath, filepath.Join(dir, "s2.sock"), nil)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("New succeeded against an upstream that never answers")
		}
		if elapsed > probeTimeout+2*time.Second {
			t.Fatalf("New took %s against a silent upstream; probeTimeout (%s) is not being "+
				"enforced — a removed deadline would hang instead of failing here", elapsed, probeTimeout)
		}
	})
}

// The upstream answers, but not with an identities list: New cannot tell
// from that whether it holds the pinned key, and must refuse rather than
// assume. The message must name both the type it got and the type it wanted.
func TestProbeRefusesWhenUpstreamAnswersTheWrongMessageType(t *testing.T) {
	dir := t.TempDir()
	blob := ed25519Blob(0xA1)
	path := writePubKeyBlob(t, dir, "k.pub", blob, "k@test")

	sockPath := filepath.Join(dir, "wrong.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readMessage(c)
		// 5 bytes so it clears the length floor probeUnparsable guards and is
		// read as a real, wrongly-typed reply rather than a truncated one.
		writeMessage(c, []byte{agentFailure, 0, 0, 0, 0}) // type 5, not IDENTITIES_ANSWER (12)
	}()

	_, err = New([]PinnedKey{{Field: "identity.ssh_key", Path: path}}, sockPath,
		filepath.Join(dir, "s.sock"), nil)
	if err == nil {
		t.Fatal("New accepted a probe reply that was not an identities list")
	}
	if !strings.Contains(err.Error(), "5") || !strings.Contains(err.Error(), "12") {
		t.Errorf("error does not name both message types (got 5, wanted 12): %v", err)
	}
}

// A malformed list — claiming 3 identities while carrying the bytes of only
// one — must be refused, and must not panic or allocate against the claimed
// count: the count is upstream-supplied, and maxMessage only bounds the
// bytes actually read.
func TestProbeRefusesAMalformedIdentitiesList(t *testing.T) {
	dir := t.TempDir()
	blob := ed25519Blob(0xA1)
	path := writePubKeyBlob(t, dir, "k.pub", blob, "k@test")

	sockPath := filepath.Join(dir, "malformed.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readMessage(c)
		out := []byte{identitiesAnswer}
		out = binary.BigEndian.AppendUint32(out, 3) // claims three...
		out = appendString(out, []byte("only one entry"))
		out = appendString(out, []byte("comment"))
		writeMessage(c, out) // ...carries one
	}()

	done := make(chan struct{})
	var perr error
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				perr = fmt.Errorf("New panicked on a malformed identities list: %v", r)
			}
		}()
		_, perr = New([]PinnedKey{{Field: "identity.ssh_key", Path: path}}, sockPath,
			filepath.Join(dir, "s.sock"), nil)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("New did not return for a malformed identities list")
	}
	if perr == nil {
		t.Fatal("New accepted a malformed identities list")
	}
}

// A probe that fails for a MISSING key must not describe what the agent DOES
// hold: neither another key's comment nor its base64 blob may appear in the
// refusal, because those belong to an identity the profile never named.
func TestProbeFailureDoesNotLeakTheUpstreamsOtherKeys(t *testing.T) {
	dir := t.TempDir()
	authBlob := ed25519Blob(0xA1)
	signBlob := ed25519Blob(0xB2) // never held
	authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
	signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

	other1, other2 := ed25519Blob(0xC3), ed25519Blob(0xD4)
	up := newFakeAgent(t)
	up.setHolds([][]byte{authBlob, other1, other2},
		[]string{"auth@test", "unrelated-work-key", "unrelated-personal-key"})

	_, err := New([]PinnedKey{
		{Field: "identity.ssh_key", Path: authPath},
		{Field: "identity.signing_key", Path: signPath},
	}, up.path, filepath.Join(dir, "s.sock"), nil)
	if err == nil {
		t.Fatal("New accepted a signing key the upstream does not hold")
	}
	msg := err.Error()
	for _, leaked := range []string{
		"unrelated-work-key", "unrelated-personal-key",
		base64.StdEncoding.EncodeToString(other1), base64.StdEncoding.EncodeToString(other2),
	} {
		if strings.Contains(msg, leaked) {
			t.Errorf("the refusal for a missing key leaks another key the agent holds: %q in %q", leaked, msg)
		}
	}
}

// The probe is a STARTUP check, not a cache: a key removed from the agent
// AFTER New succeeds must still be forwarded to the (now-refusing) live
// agent on a sign request, not answered from whatever the probe once saw.
func TestSignPathConsultsTheLiveAgentNotTheProbe(t *testing.T) {
	sock, up, _, signBlob := startProxy(t)

	up.removeHold(signBlob)

	reply := ask(t, sock, signRequestFor(signBlob))
	if reply[0] != agentFailure {
		t.Fatalf("reply type %d, want FAILURE relayed from the live agent", reply[0])
	}
	if up.contacts.Load() == 0 {
		t.Error("the sign request never reached the upstream; handleSign must consult the " +
			"live agent, not a cached probe result")
	}
}

// A broken profile is reported before a broken host: a garbage key path with
// NO upstream configured at all must still name the key, not the missing
// agent — the key is the thing the human wrote and can fix first.
func TestProfileErrorBeatsHostError(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "does-not-exist.pub")
	_, err := New([]PinnedKey{{Field: "identity.ssh_key", Path: garbage}}, "",
		filepath.Join(dir, "s.sock"), nil)
	if err == nil {
		t.Fatal("New accepted a nonexistent key path with no upstream at all")
	}
	if !strings.Contains(err.Error(), "identity.ssh_key") {
		t.Errorf("error does not name the key field: %v", err)
	}
	if strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("error names the missing agent instead of the unreadable key: %v", err)
	}
}

// Everything that mutates the human's agent is refused, and never forwarded —
// unchanged by pinning a second key: two pins must not widen the verb set.
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
			sock, up, _, _ := startProxy(t)
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
//
// The deadline is the point of this test, not a nicety. Without a bound, the
// proxy allocates the claimed size and then BLOCKS in ReadFull waiting for bytes
// the sandbox will never send — so the connection is neither answered nor
// closed, and `readMessage(c) != nil` was satisfied only by the whole test
// binary eventually dying on go test's ten-minute default timeout. Deleting the
// bound therefore "passed" for ten minutes and then failed anonymously. Here a
// hang is its own named failure, in two seconds.
func TestOversizedMessageIsRejected(t *testing.T) {
	sock, _, authBlob, _ := startProxy(t)

	// Two sizes, both refused for the same reason. maxMessage+1 is the boundary;
	// 4 GiB is the memory-exhaustion case, and a proxy that only bounded the
	// obviously-absurd value would still be a primitive at 256 KiB a connection.
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"one byte over the bound", []byte{0x00, 0x04, 0x00, 0x01}},
		{"4 GiB", []byte{0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			// Claim the size without sending it.
			if _, err := c.Write(tc.prefix); err != nil {
				t.Fatal(err)
			}
			if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err = readMessage(c)
			switch {
			case err == nil:
				t.Error("the proxy accepted an absurd message length instead of closing the connection")
			case errors.Is(err, os.ErrDeadlineExceeded):
				t.Error("the proxy neither answered nor closed the connection: it is sitting " +
					"on an unbounded read, having already allocated the size the sandbox " +
					"asked for. That is the memory-exhaustion primitive this test exists " +
					"to deny, and it looks identical to a pass unless the read is bounded.")
			}
		})
	}

	// POSITIVE CONTROL. The probe above concludes from a closed connection, and a
	// closed connection is equally what you get from a proxy that is broken, has
	// crashed, or never started. So show the same machinery getting a real answer
	// out of the same proxy afterwards.
	t.Run("control: a well-formed message on the same proxy is answered", func(t *testing.T) {
		reply := ask(t, sock, []byte{requestIdentities})
		if reply[0] != identitiesAnswer {
			t.Fatalf("control: reply type %d, want IDENTITIES_ANSWER — the proxy is not "+
				"answering anything, so the refusals above prove nothing", reply[0])
		}
		if blob, _, ok := takeString(reply[5:]); !ok || string(blob) != string(authBlob) {
			t.Error("control: the proxy answered, but not with the first pinned key")
		}
	})
}

// The socket must not be usable by other users on the machine: anything that
// can connect can ask for a signature.
//
// The umask is forced to 0 first, and that is what makes this an assertion
// rather than an observation about the developer's shell. bind(2) applies the
// umask, so under the common 0077 the socket comes out 0600 whether or not the
// code chmods it — the test would hold, and go on holding, with the chmod
// deleted. At umask 0 the only thing that can produce 0600 is snug doing it.
//
// Nothing in this package runs in parallel, and the umask is restored, so the
// process-wide change is contained.
func TestSocketIsPrivate(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	// Control: prove the umask really is permissive now, so a 0600 socket below
	// cannot be attributed to it.
	probe := filepath.Join(t.TempDir(), "umask-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o666 {
		t.Fatalf("could not clear the umask (a 0666 file came out %#o), so a private "+
			"socket below would prove nothing", fi.Mode().Perm())
	}

	sock, _, _, _ := startProxy(t)
	si, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := si.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("agent socket is mode %#o; it must not be group- or world-accessible", perm)
	}
}

// No agent to proxy is an error, not a silent no-op that leaves the sandbox
// wondering why signing fails — and it must fail with NO dial attempted:
// New refuses an empty upstream before probeUpstream is ever reached.
func TestMissingUpstreamIsAnError(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pub")
	blob := appendString(nil, []byte("ssh-ed25519"))
	blob = appendString(blob, make([]byte, 32))
	os.WriteFile(key, []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" c\n"), 0o600)

	start := time.Now()
	_, err := New([]PinnedKey{{Field: "identity.ssh_key", Path: key}}, "",
		filepath.Join(dir, "s.sock"), nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Error("expected an error when the host has no ssh-agent")
	}
	if !strings.Contains(err.Error(), "no ssh-agent is running") {
		t.Errorf("error is not the missing-agent message: %v", err)
	}
	// NO DIAL ATTEMPTED: a version that tried to dial the empty path before
	// checking it would still fail, but slowly (or not at all, and hang) — this
	// bound is what tells "refused immediately" from "attempted and failed".
	if elapsed > time.Second {
		t.Errorf("New took %s to refuse an empty upstream, which is long enough to have "+
			"attempted a dial first", elapsed)
	}
}

// ── the sign probe: a listed key is not a signable key ─────────────────────
//
// A red-team finding against ssh-signing-key: sshproxy.New checked only
// REQUEST_IDENTITIES membership before this fix, and a key can be listed
// there while refusing every SIGN_REQUEST. Measured on OpenSSH 10.5p1: a key
// added with `ssh-add -c` (confirm-before-use) and no askpass was listed by
// REQUEST_IDENTITIES and answered every SIGN_REQUEST with SSH_AGENT_FAILURE
// in 57 ms; a key added with `ssh-add -h <destination>` (destination-
// constrained) did the same and can NEVER sign through snug's proxy, because
// lifting the constraint needs the session-bind@openssh.com extension and
// handle's `case extension:` refuses agent extensions wholesale. Both then
// failed every commit inside once signing_key authored `commit.gpgsign =
// true`, with git printing "Couldn't sign message (signer): agent refused
// operation?" — naming no cause snug could have surfaced without asking the
// agent to actually sign.

// TestListedButUnsignableKeyRefusesTheRun pins the finding directly: an agent
// that lists both pinned keys and refuses every SIGN_REQUEST must make New
// fail, naming the signing field, a fingerprint, and both host-side causes —
// and it must fail before the listener is bound, or the refused run leaves a
// socket nothing ever cleans up.
func TestListedButUnsignableKeyRefusesTheRun(t *testing.T) {
	keys, sockPath, up, authBlob, signBlob := mustSignFixture(t)
	up.setRefuseSign(authBlob, true)
	up.setRefuseSign(signBlob, true)

	_, err := New(keys, up.path, sockPath, nil)
	if err == nil {
		t.Fatal("New accepted a signing key the upstream lists but refuses to sign with")
	}
	msg := err.Error()
	for _, want := range []string{
		"identity.signing_key", "SHA256:", "ssh-add -c", "ssh-add -h", "session-bind@openssh.com",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not contain %q: %v", want, msg)
		}
	}
	// THE ORDERING CLAIM, MADE OBSERVABLE FROM OUTSIDE rather than trusted from
	// New's own doc comment: a probe failure that happened after net.Listen
	// would leave a socket file on disk for nothing to ever clean up. Lstat,
	// not Stat, so a refusal that somehow left a dangling symlink still counts
	// as "left something behind" rather than being followed and reported clean.
	if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a refused sign probe left a socket at %s (lstat err=%v)", sockPath, statErr)
	}
}

// TestSignProbeCoversOnlyMustSignKeys pins the boundary of the fix: the probe
// is scoped to MustSign pins, not the whole pin set. The auth key is
// unsignable upstream and is never asked — probing it would turn a confirm
// dialog in front of every snug start, including ones that never touch
// git — while the signing key, which IS MustSign, gets probed and succeeds.
// A change that widened the probe to every pin would fail here on the count.
func TestSignProbeCoversOnlyMustSignKeys(t *testing.T) {
	keys, sockPath, up, authBlob, signBlob := mustSignFixture(t)
	up.setRefuseSign(authBlob, true)

	p, err := New(keys, up.path, sockPath, nil)
	if err != nil {
		t.Fatalf("New refused a run whose only unsignable key is not MustSign: %v", err)
	}
	t.Cleanup(p.Close)

	seen := up.sawSignCalls()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d SIGN_REQUESTs during New, want exactly 1 (the MustSign key only)", len(seen))
	}
	if string(seen[0].blob) != string(signBlob) {
		t.Error("the one sign probe was not for identity.signing_key's blob")
	}
}

// TestSignProbePayloadCannotBeReplayed asserts the security argument in
// signProbePrefix's doc comment rather than trusting it: the probe payload is
// 49 bytes, starts with the domain-separating prefix, cannot be mistaken for
// an SSHSIG namespace blob, cannot be mistaken for an SSH userauth signature
// (whose first four bytes are a session-id length that would have to exceed
// the whole payload to equal it), and is different on every run — so a
// signature captured from one probe cannot be replayed as an answer to the
// next one, let alone to a real SSHSIG or userauth request.
func TestSignProbePayloadCannotBeReplayed(t *testing.T) {
	keys1, sockPath1, up1, _, _ := mustSignFixture(t)
	p1, err := New(keys1, up1.path, sockPath1, nil)
	if err != nil {
		t.Fatalf("New refused a healthy fixture: %v", err)
	}
	t.Cleanup(p1.Close)
	seen1 := up1.sawSignCalls()
	if len(seen1) != 1 {
		t.Fatalf("want exactly 1 sign call, got %d", len(seen1))
	}
	data1 := seen1[0].data

	if len(data1) != 49 {
		t.Fatalf("probe payload is %d bytes, want 49 (17-byte prefix + 32-byte nonce)", len(data1))
	}
	if !bytes.HasPrefix(data1, []byte(signProbePrefix)) {
		t.Errorf("probe payload does not start with signProbePrefix: %x", data1)
	}
	if bytes.HasPrefix(data1, []byte("SSHSIG")) {
		t.Error("probe payload could be mistaken for an SSHSIG-namespaced blob")
	}
	if n := binary.BigEndian.Uint32(data1[:4]); n <= uint32(len(data1)) {
		t.Errorf("the first four bytes of the payload read as a length of %d, which fits inside "+
			"the 49-byte payload itself — an SSH userauth blob's session-id length prefix could "+
			"equal this and the domain separation argument would not hold", n)
	}

	keys2, sockPath2, up2, _, _ := mustSignFixture(t)
	p2, err := New(keys2, up2.path, sockPath2, nil)
	if err != nil {
		t.Fatalf("New refused a second healthy fixture: %v", err)
	}
	t.Cleanup(p2.Close)
	seen2 := up2.sawSignCalls()
	if len(seen2) != 1 {
		t.Fatalf("want exactly 1 sign call on the second run, got %d", len(seen2))
	}
	if bytes.Equal(data1, seen2[0].data) {
		t.Error("two New calls produced the identical probe payload; a signature over the first " +
			"could be replayed as an answer to the second")
	}
}

// TestSignProbeSendsTheFlagsGitSends pins signFlagsFor's own measurement:
// `ssh-keygen -Y sign -n git` sends flags 0x00000000 for an ed25519 key and
// 0x00000004 (SSH_AGENT_RSA_SHA2_512) for an RSA key, through a logging agent
// proxy on OpenSSH 10.5p1 / git 2.55.0. A probe that asked for flags git will
// not use would prove the wrong thing in both directions — succeeding with
// SHA-1 when git demands SHA-2, or failing with SHA-2 against an agent that
// only ever refuses SHA-1.
func TestSignProbeSendsTheFlagsGitSends(t *testing.T) {
	t.Run("ed25519 signing key: flags 0x0", func(t *testing.T) {
		keys, sockPath, up, _, signBlob := mustSignFixture(t)
		p, err := New(keys, up.path, sockPath, nil)
		if err != nil {
			t.Fatalf("New refused a healthy fixture: %v", err)
		}
		t.Cleanup(p.Close)
		seen := up.sawSignCalls()
		if len(seen) != 1 {
			t.Fatalf("want 1 sign call, got %d", len(seen))
		}
		if string(seen[0].blob) != string(signBlob) {
			t.Fatal("the recorded sign call is not for the signing key")
		}
		if seen[0].flags != 0 {
			t.Errorf("ed25519 signing probe sent flags %#x, want 0x0", seen[0].flags)
		}
	})

	t.Run("ssh-rsa signing key: flags 0x4 (SHA2-512)", func(t *testing.T) {
		dir := t.TempDir()
		authBlob := ed25519Blob(0xA1)
		signBlob := rsaBlob(0xB2)
		authPath := writePubKeyBlob(t, dir, "auth.pub", authBlob, "auth@test")
		signPath := writePubKeyBlob(t, dir, "signing.pub", signBlob, "signing@test")

		up := newFakeAgent(t)
		up.setHolds([][]byte{authBlob, signBlob}, []string{"auth@test", "signing@test"})

		p, err := New([]PinnedKey{
			{Field: "identity.ssh_key", Path: authPath},
			{Field: "identity.signing_key", Path: signPath, MustSign: true},
		}, up.path, filepath.Join(dir, "proxy.sock"), nil)
		if err != nil {
			t.Fatalf("New refused a healthy RSA fixture: %v", err)
		}
		t.Cleanup(p.Close)
		seen := up.sawSignCalls()
		if len(seen) != 1 {
			t.Fatalf("want 1 sign call, got %d", len(seen))
		}
		if string(seen[0].blob) != string(signBlob) {
			t.Fatal("the recorded sign call is not for the signing key")
		}
		if seen[0].flags != agentRSASHA2512 {
			t.Errorf("ssh-rsa signing probe sent flags %#x, want %#x (agentRSASHA2512)",
				seen[0].flags, agentRSASHA2512)
		}
	})
}

// TestSignProbeSignatureNeverLeavesNew is probeSign's own doc comment made an
// assertion: the signature the probe collects is inspected and dropped, never
// stored on the Proxy. A distinctive marker returned by the fake agent for
// EVERY successful sign must not turn up in the sandbox-visible identities
// list, and a later sandbox SIGN_REQUEST for the same key must still reach
// the live agent and get the marker back freshly — not a cached copy of the
// probe's own reply.
func TestSignProbeSignatureNeverLeavesNew(t *testing.T) {
	keys, sockPath, up, _, signBlob := mustSignFixture(t)
	marker := []byte("snug-test-signature-marker-must-not-leak")
	up.setSignMarker(marker)

	p, err := New(keys, up.path, sockPath, nil)
	if err != nil {
		t.Fatalf("New refused a healthy fixture: %v", err)
	}
	t.Cleanup(p.Close)
	go p.Serve()

	reply := ask(t, sockPath, []byte{requestIdentities})
	if bytes.Contains(reply, marker) {
		t.Error("the sandbox-visible identities list carries bytes from the startup sign probe's own reply")
	}

	signReply := ask(t, sockPath, signRequestFor(signBlob))
	if signReply[0] != signResponse {
		t.Fatalf("sandbox sign request reply type %d, want SIGN_RESPONSE", signReply[0])
	}
	if !bytes.Contains(signReply, marker) {
		t.Error("a sandbox sign request did not reach the live agent: its reply does not carry " +
			"the marker, so either the request never arrived or something answered on its behalf")
	}
}

// TestSignProbeDoesNotUseTheListDeadline proves probeSign's own deadline is
// signProbeTimeout (2 minutes), not probeTimeout (5 seconds): an agent that
// holds the delay past probeTimeout and then answers must still let New
// succeed. probeTimeout would abort exactly the case the sign probe exists to
// serve — a human being asked, on the host, to confirm — and turn a working
// setup into a refusal. The ~5.5s this test costs IS the assertion: the delay
// is derived from probeTimeout itself so it tracks the constant rather than a
// number written down once and left to drift.
func TestSignProbeDoesNotUseTheListDeadline(t *testing.T) {
	keys, sockPath, up, _, _ := mustSignFixture(t)
	delay := probeTimeout + 500*time.Millisecond
	up.setSignDelay(delay)

	start := time.Now()
	p, err := New(keys, up.path, sockPath, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New refused a signing agent that merely answered slowly (%s): %v", elapsed, err)
	}
	t.Cleanup(p.Close)
	if elapsed < delay {
		t.Errorf("New returned in %s, faster than the %s the fake agent held the sign reply — "+
			"the delay was not actually exercised", elapsed, delay)
	}
}

// TestPinSetTooLargeForOneIdentitiesAnswerIsRefused pins the size guard
// New's doc comment describes: hostread.MaxSSHPublicKeyBytes (65536) bounds
// one .pub file, and maxMessage (262144) bounds the one agent message
// identitiesAnswer writes. Three pins built at maximalPubKey's cap come to
// 196625 bytes of identities answer and New must accept them; a fourth,
// identical pin pushes the same message to 262165 bytes — over the bound —
// and New must refuse rather than write a message `ssh-add -l` inside would
// fail to parse.
func TestPinSetTooLargeForOneIdentitiesAnswerIsRefused(t *testing.T) {
	dir := t.TempDir()
	up := newFakeAgent(t)

	var keys []PinnedKey
	var blobs [][]byte
	var comments []string
	for i := 0; i < 4; i++ {
		path, blob, comment := maximalPubKey(t, dir, fmt.Sprintf("k%d.pub", i), byte(i))
		keys = append(keys, PinnedKey{Field: fmt.Sprintf("identity.field%d", i), Path: path})
		blobs = append(blobs, blob)
		comments = append(comments, comment)
	}
	// sizeOf mirrors identitiesAnswerSize's own arithmetic (5-byte header, then
	// 8+len(blob)+len(comment) per key) against the blobs and comments THIS
	// fixture actually wrote, independent of New — so a failure below points
	// at the fixture rather than at the code being tested.
	sizeOf := func(n int) int {
		sz := 5
		for i := 0; i < n; i++ {
			sz += 8 + len(blobs[i]) + len(comments[i])
		}
		return sz
	}
	if sz := sizeOf(3); sz != 196625 {
		t.Fatalf("fixture bug: three maximal pins come to %d bytes, want the measured 196625", sz)
	}
	if sz := sizeOf(4); sz != 262165 {
		t.Fatalf("fixture bug: four maximal pins come to %d bytes, want the measured 262165", sz)
	}

	// The fake agent must hold exactly the keys being pinned in each call: its
	// own REQUEST_IDENTITIES reply is not bounded by maxMessage the way New's
	// generated identitiesAnswer is, and holding all four for the three-pin
	// call would make readMessage reject the UPSTREAM's oversized reply
	// instead of exercising the size guard this test is about.
	three := keys[:3]
	up.setHolds(blobs[:3], comments[:3])
	p, err := New(three, up.path, filepath.Join(dir, "three.sock"), nil)
	if err != nil {
		t.Fatalf("New refused three maximal pins that fit under maxMessage: %v", err)
	}
	p.Close()

	four := keys
	up.setHolds(blobs, comments)
	_, err = New(four, up.path, filepath.Join(dir, "four.sock"), nil)
	if err == nil {
		t.Fatal("New accepted four maximal pins whose identities answer exceeds maxMessage")
	}
}

// TestIdentitiesAnswerSizeMatchesTheBytesWritten keeps identitiesAnswerSize
// (used by New to refuse an oversized pin set before Serve exists) from
// drifting out of step with identitiesAnswer (what Serve actually writes) —
// the size guard is worthless if it measures something other than the bytes
// that end up on the wire.
func TestIdentitiesAnswerSizeMatchesTheBytesWritten(t *testing.T) {
	dir := t.TempDir()
	up := newFakeAgent(t)

	blob1, blob2, blob3 := ed25519Blob(0xA1), ed25519Blob(0xB2), ed25519Blob(0xC3)
	path1 := writePubKeyBlob(t, dir, "k1.pub", blob1, "one")
	path2 := writePubKeyBlob(t, dir, "k2.pub", blob2, "two")
	path3 := writePubKeyBlob(t, dir, "k3.pub", blob3, "three")
	up.setHolds([][]byte{blob1, blob2, blob3}, []string{"one", "two", "three"})

	cases := []struct {
		name string
		keys []PinnedKey
	}{
		{"1 key", []PinnedKey{{Field: "f1", Path: path1}}},
		{"2 keys", []PinnedKey{{Field: "f1", Path: path1}, {Field: "f2", Path: path2}}},
		{"3 keys", []PinnedKey{
			{Field: "f1", Path: path1}, {Field: "f2", Path: path2}, {Field: "f3", Path: path3},
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.keys, up.path, filepath.Join(dir, fmt.Sprintf("s%d.sock", i)), nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer p.Close()
			got := len(p.identitiesAnswer())
			want := identitiesAnswerSize(p.pinned)
			if got != want {
				t.Errorf("identitiesAnswer wrote %d bytes, identitiesAnswerSize computed %d", got, want)
			}
		})
	}
}
