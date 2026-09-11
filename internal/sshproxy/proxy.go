// Package sshproxy is a filtering ssh-agent proxy: the sandbox sees exactly one
// key, and cannot enumerate, add, remove or lock anything else in your agent.
//
// Why a proxy rather than binding $SSH_AUTH_SOCK straight through: the agent
// protocol has verbs beyond "sign". A raw passthrough hands the sandbox every
// key you have loaded, plus the ability to plant a key in your agent and to
// delete the ones already there. Pinning to one key bounds the blast radius to
// one identity.
//
// WHAT THIS CANNOT DO, and it is inherent rather than a gap to close later: it
// cannot restrict WHAT is signed. A sign oracle for a key is authority to use
// that key for anything it can reach — push to any repository, authenticate to
// any host that trusts it. Every agent forwarder in existence has this property.
// Pinning bounds the identity, not the actions.
//
// Nor can it tell an AUTHENTICATION request from a SIGNING request, and that
// matters the moment a second key is pinned. SSH_AGENTC_SIGN_REQUEST carries a
// key blob, a byte string and a flags word — no purpose, no audience, no
// caller. `ssh` proving an identity to a host and `git` signing a commit send
// the same message shape. So with identity.ssh_key and identity.signing_key
// both pinned, EITHER key can be used for EITHER purpose by anything inside:
// the sandbox can authenticate with the signing key and sign with the auth key.
// The split between them is enforced by the host's authorized_keys and
// allowed_signers, not by this proxy. Do not add a filter that pretends
// otherwise — there is nothing on the wire to filter on.
//
// The protocol is implemented at the wire level rather than through a library
// because the filter IS the security control, and it should be readable as
// bytes-in, bytes-out with no framework in between.
package sshproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gomoni/snug/internal/hostread"
)

// Agent protocol message numbers (draft-miller-ssh-agent).
const (
	agentFailure         = 5
	agentSuccess         = 6
	requestIdentities    = 11
	identitiesAnswer     = 12
	signRequest          = 13
	signResponse         = 14
	addIdentity          = 17
	removeIdentity       = 18
	removeAllIdentities  = 19
	addIDConstrained     = 25
	addSmartcardKey      = 20
	removeSmartcardKey   = 21
	lock                 = 22
	unlock               = 23
	addSmartcardKeyConst = 26
	extension            = 27
)

// maxMessage bounds a single agent message. The real protocol has no useful
// upper bound, and an unbounded length prefix read from the sandbox is a memory
// exhaustion primitive pointed at snug itself.
const maxMessage = 256 * 1024

// PinnedKey is one public key the sandbox may use, and the profile field that
// named it. Field is a LABEL for error and audit text only — this package does
// not know the identity schema, and must not learn it. That ignorance is what
// keeps "a new identity field" from being a change in here: the caller names
// the field, the proxy holds blobs.
type PinnedKey struct {
	Field string // "identity.ssh_key", "identity.signing_key"
	Path  string // the PUBLIC key file on the host
}

// pin is a PinnedKey with the public half read and decoded.
type pin struct {
	field   string
	path    string
	blob    []byte
	comment string
}

type Proxy struct {
	// pinned is the SET of SSH wire-format public key blobs the sandbox may
	// use: identity.ssh_key, plus identity.signing_key when the profile sets
	// it. A request naming anything else is answered SSH_AGENT_FAILURE without
	// the host agent being contacted. Membership is the WHOLE filter; see the
	// package comment for why it cannot also be a filter on purpose.
	pinned []pin

	upstream string // the host's real SSH_AUTH_SOCK
	ln       net.Listener
	audit    func(string)

	wg   sync.WaitGroup
	once sync.Once
}

// New parses the PUBLIC key files and prepares a proxy pinned to all of them.
// Only the public halves are ever read: the private keys stay wherever they
// are, and the sandbox never sees key material of any kind.
//
// The host agent is asked ONCE here whether it holds each pinned key, and New
// refuses when it does not. See probeUpstream for why that check is not
// optional and what it does not promise. The purpose residual is in the
// package comment.
//
// Order is load-bearing: the keys are read before the upstream is checked, so
// a profile error beats a host-state error; and the probe runs before the
// listener is bound, so a refusal leaves no socket behind.
func New(keys []PinnedKey, upstream, socketPath string, audit func(string)) (*Proxy, error) {
	if len(keys) == 0 {
		return nil, errors.New("ssh-agent proxy: no key to pin. A proxy with an empty pin set " +
			"advertises nothing and refuses every signature, which is a sandbox that looks " +
			"configured and is not")
	}
	var pins []pin
	for _, k := range keys {
		blob, comment, err := parsePublicKey(k.Field, k.Path)
		if err != nil {
			return nil, err
		}
		// ConstantTimeCompare(nil, nil) returns 1, so an empty blob would match
		// an empty sign request. parsePublicKey cannot produce one today —
		// strings.Fields yields no empty field, and non-empty base64 either
		// decodes to at least one byte or errors — and the guard stays because
		// it costs one comparison and takes the hazard off the refactor's path.
		if len(blob) == 0 {
			return nil, fmt.Errorf("%s %q decodes to an empty key blob. An empty blob would "+
				"match an empty signature request, so it is refused here rather than pinned",
				k.Field, k.Path)
		}
		if containsBlob(blobsOf(pins), blob) {
			continue // the same key named twice advertises once
		}
		pins = append(pins, pin{field: k.Field, path: k.Path, blob: blob, comment: comment})
	}
	if upstream == "" {
		return nil, fmt.Errorf("no ssh-agent is running on the host (SSH_AUTH_SOCK is unset), " +
			"so there is nothing to proxy.\n" +
			"      Start one and load your key, or set ssh_mode = \"none\" in the profile")
	}
	if err := probeUpstream(upstream, pins); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent proxy socket: %w", err)
	}
	// The socket lives in a private per-run directory, but belt and braces:
	// anything that can connect can ask for a signature.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}

	if audit == nil {
		audit = func(string) {}
	}
	return &Proxy{pinned: pins, upstream: upstream, ln: ln, audit: audit}, nil
}

func (p *Proxy) Serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer c.Close()
			p.handle(c)
		}()
	}
}

func (p *Proxy) Close() {
	p.once.Do(func() {
		p.ln.Close()
		p.wg.Wait()
	})
}

// handle serves one client connection. Anything it does not positively
// understand is answered with SSH_AGENT_FAILURE — the protocol's own way of
// saying no, so a confused client degrades instead of hanging.
func (p *Proxy) handle(c net.Conn) {
	for {
		msg, err := readMessage(c)
		if err != nil {
			return
		}
		if len(msg) == 0 {
			writeMessage(c, []byte{agentFailure})
			continue
		}

		switch msg[0] {
		case requestIdentities:
			// Answered LOCALLY, never forwarded. The host agent is not even
			// asked, so its other keys are not merely filtered out of the
			// reply — they are never enumerated in the first place. The key is
			// advertised whether or not it is currently unlocked, so the
			// sandbox always has something to offer and the unlock prompt (if
			// any) happens at sign time, on the host, where the human is.
			writeMessage(c, p.identitiesAnswer())

		case signRequest:
			p.handleSign(c, msg)

		case addIdentity, addIDConstrained, addSmartcardKey, addSmartcardKeyConst:
			// The sandbox must not be able to plant a key in your agent.
			p.audit("refused: sandbox tried to add a key to the host agent")
			writeMessage(c, []byte{agentFailure})

		case removeIdentity, removeAllIdentities, removeSmartcardKey:
			// Denial of service against the human's own agent.
			p.audit("refused: sandbox tried to remove keys from the host agent")
			writeMessage(c, []byte{agentFailure})

		case lock, unlock:
			p.audit("refused: sandbox tried to lock/unlock the host agent")
			writeMessage(c, []byte{agentFailure})

		case extension:
			// Includes session-bind@openssh.com, which is how OpenSSH
			// implements agent-forwarding restrictions. Refusing extensions
			// wholesale means `ssh -A` from inside does not chain the agent
			// onward — which is the outcome we want — and keeps this filter
			// from having to track an open-ended surface.
			p.audit("refused: agent extension request")
			writeMessage(c, []byte{agentFailure})

		default:
			p.audit(fmt.Sprintf("refused: unknown agent message type %d", msg[0]))
			writeMessage(c, []byte{agentFailure})
		}
	}
}

// identitiesAnswer advertises the whole pin set, in the order the caller
// declared it (ssh_key, then signing_key). The order is for determinism in the
// tests and for a human reading `ssh-add -l` inside; it does NOT drive
// selection. ssh selects by file, because the generated ~/.ssh/config sets
// IdentitiesOnly with one IdentityFile, and git's ssh signing selects by the
// file user.signingkey names.
//
// The comment is the .pub file's own, verbatim, and it is visible to the
// sandbox. That is not an oversight and substituting a constant here would buy
// nothing: internal/cli stages the whole key file at ~/.ssh/id_snug.pub so ssh
// and ssh-keygen can name it, comment included. If the host-derived comment
// (commonly user@hostname) is ever to be stripped, it is stripped in BOTH
// places or in neither — one half is a fix that measures as a fix and is not
// one.
func (p *Proxy) identitiesAnswer() []byte {
	out := []byte{identitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, uint32(len(p.pinned)))
	for _, k := range p.pinned {
		out = appendString(out, k.blob)
		out = appendString(out, []byte(k.comment))
	}
	return out
}

func blobsOf(pins []pin) [][]byte {
	out := make([][]byte, 0, len(pins))
	for _, k := range pins {
		out = append(out, k.blob)
	}
	return out
}

// containsBlob reports whether b is one of set, with no early exit: every
// element is compared and the results are OR'd, so the time taken does not say
// WHICH element matched.
//
// The secrecy here is nil, and saying so is the point — the next reader will
// otherwise take this for a claim that it matters. Every element is a PUBLIC
// key, and identitiesAnswer hands the whole set to the sandbox on request one
// message earlier; there is nothing a timing oracle could learn that a single
// REQUEST_IDENTITIES does not simply give away. The loop is written this way
// for the reason the single-key compare already gave: a variable-time compare
// in a security filter invites the next reader to copy the pattern somewhere it
// does matter, and `break` on a match is that same invitation in a new shape.
func containsBlob(set [][]byte, b []byte) bool {
	if len(b) == 0 {
		return false // subtle.ConstantTimeCompare(nil, nil) returns 1
	}
	match := 0
	for _, k := range set {
		match |= subtle.ConstantTimeCompare(b, k)
	}
	return match == 1
}

// handleSign forwards a signature request if and only if it names one of the
// pinned keys, byte for byte.
func (p *Proxy) handleSign(c net.Conn, msg []byte) {
	blob, _, ok := takeString(msg[1:])
	if !ok {
		writeMessage(c, []byte{agentFailure})
		return
	}
	if !containsBlob(blobsOf(p.pinned), blob) {
		p.audit("refused: signature requested for a key that is not in the pinned set")
		writeMessage(c, []byte{agentFailure})
		return
	}
	field := "a pinned key"
	for _, k := range p.pinned {
		if subtle.ConstantTimeCompare(blob, k.blob) == 1 {
			field = k.field
		}
	}

	// A fresh upstream connection per request: the agent protocol is a
	// request/response stream with no message ids, so interleaving two clients
	// on one connection would mismatch replies.
	up, err := net.Dial("unix", p.upstream)
	if err != nil {
		p.audit(fmt.Sprintf("upstream agent unreachable: %v", err))
		writeMessage(c, []byte{agentFailure})
		return
	}
	defer up.Close()

	if err := writeMessage(up, msg); err != nil {
		writeMessage(c, []byte{agentFailure})
		return
	}
	reply, err := readMessage(up)
	if err != nil {
		writeMessage(c, []byte{agentFailure})
		return
	}
	if len(reply) > 0 && reply[0] == signResponse {
		// Names the KEY, never a purpose: the request carries none. See the
		// package comment.
		p.audit("signed with " + field)
	}
	writeMessage(c, reply)
}

// ── the startup probe ───────────────────────────────────────────────────────

// probeTimeout bounds the whole startup exchange — dial, write, read. On a live
// agent this is sub-millisecond over a unix socket; the value is loose because
// it exists to bound a hung or unresponsive socket, not to tune a fast path,
// and the cost is only ever paid on a host that is already broken.
const probeTimeout = 5 * time.Second

// probeUpstream asks the host agent ONCE, before the sandbox exists, whether it
// holds every pinned key, and refuses the run when it does not.
//
// WHY THIS IS NOT OPTIONAL. snug authors the thing that makes the failure
// fatal: with signing_key set it writes `commit.gpgsign = true` into the
// generated ~/.gitconfig, so a key the agent does not hold turns EVERY commit
// inside into a hard failure, and the error git prints at that point names
// libcrypto or a failed write — not a missing pin. The sandbox cannot see the
// host agent's contents, so the diagnosis is unavailable at the layer where the
// failure appears. It is available here. That is invariant 5 in its literal
// form, and it is why this lives in New rather than behind a method a caller
// can skip.
//
// WHAT IT DOES NOT PROMISE. It is liveness at startup, not a guarantee: a key
// removed from the agent, or an agent locked, after this returns will fail at
// sign time exactly as before. handleSign consults the live agent and nothing
// cached here.
//
// It contacts the upstream agent, which the sandbox-initiated REQUEST_IDENTITIES
// path deliberately never does. The distinction survives: that path answers
// locally so the agent's other keys are never enumerated FOR THE SANDBOX. This
// is snug asking on the human's behalf, before a sandbox exists, and nothing it
// learns reaches one — see the leak rules below.
//
// --dry-run never reaches here: startIdentity returns before sshproxy.New.
func probeUpstream(upstream string, pins []pin) error {
	deadline := time.Now().Add(probeTimeout)
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", upstream)
	if err != nil {
		return probeNoAnswer(upstream, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return probeNoAnswer(upstream, err)
	}
	if err := writeMessage(conn, []byte{requestIdentities}); err != nil {
		return probeNoAnswer(upstream, err)
	}
	reply, err := readMessage(conn)
	if err != nil {
		return probeNoAnswer(upstream, err)
	}

	if len(reply) < 5 {
		return probeUnparsable(upstream, len(reply), 0)
	}
	if reply[0] != identitiesAnswer {
		return fmt.Errorf("the host ssh-agent at %s answered a list request with message "+
			"type %d, not an identities list (%d).\n\n"+
			"      snug cannot tell from that whether the agent holds the pinned key, and it\n"+
			"      will not start a sandbox that claims an identity it could not verify.\n"+
			"      Check it answers:  ssh-add -l\n"+
			"      If the agent is locked, unlock it:  ssh-add -X\n"+
			"      Or set ssh_mode = \"none\" in the profile", upstream, reply[0], identitiesAnswer)
	}
	n := binary.BigEndian.Uint32(reply[1:5])
	// NOT preallocated against n: the count is upstream-supplied and maxMessage
	// bounds the BYTES, not the claim.
	var held [][]byte
	rest := reply[5:]
	for i := uint32(0); i < n; i++ {
		blob, r, ok := takeString(rest)
		if !ok {
			return probeUnparsable(upstream, len(reply), n)
		}
		_, r, ok = takeString(r) // the comment, which is not needed and not kept
		if !ok {
			return probeUnparsable(upstream, len(reply), n)
		}
		held = append(held, blob)
		rest = r
	}

	// Slice order, so the first missing key named is deterministic: auth before
	// signing.
	for _, k := range pins {
		if !containsBlob(held, k.blob) {
			return fmt.Errorf("the host ssh-agent does not hold %s %q (%s).\n\n"+
				"      That is the PUBLIC half of a key the sandbox is meant to use. The PRIVATE\n"+
				"      half must be loaded in the agent on the HOST, because no key material ever\n"+
				"      enters the sandbox. The agent answered with %s; this one is not among them.\n"+
				"      Load it:               ssh-add <the matching private key>\n"+
				"      Check what is loaded:  ssh-add -l\n"+
				"      Or remove %s from the profile.",
				k.field, k.path, fingerprint(k.blob), keysWord(len(held)), k.field)
		}
	}
	// held goes out of scope here. NOTHING derived from the upstream's answer is
	// stored on the Proxy, and no key the agent holds but the profile does not
	// pin may appear in any message above: the count is the only thing said
	// about the agent's contents, and the only fingerprint rendered belongs to a
	// key the human named in their own profile.
	return nil
}

func probeNoAnswer(upstream string, err error) error {
	return fmt.Errorf("the host ssh-agent at %s did not answer a list request: %w.\n\n"+
		"      snug asks the agent once, at startup, whether it holds the key the profile\n"+
		"      pins. A sandbox that believes it can sign and cannot fails later, INSIDE,\n"+
		"      as an error from git or ssh that names no cause.\n"+
		"      Check the agent is alive:  ssh-add -l\n"+
		"      Then re-run, or set ssh_mode = \"none\" in the profile", upstream, err)
}

func probeUnparsable(upstream string, got int, n uint32) error {
	return fmt.Errorf("the host ssh-agent at %s answered with an identities list snug could "+
		"not parse (%d bytes, claiming %d identities).\n\n"+
		"      snug cannot tell from that whether the agent holds the pinned key, and it\n"+
		"      will not start a sandbox that claims an identity it could not verify.\n"+
		"      Check it answers:  ssh-add -l\n"+
		"      Or set ssh_mode = \"none\" in the profile", upstream, got, n)
}

// fingerprint is OpenSSH's own `ssh-add -l` format, so the refusal above names a
// string the human can match against that command's output by eye.
func fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func keysWord(n int) string {
	switch n {
	case 0:
		return "no keys at all"
	case 1:
		return "one key"
	default:
		return fmt.Sprintf("%d keys", n)
	}
}

// ── wire format ─────────────────────────────────────────────────────────────

func readMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMessage {
		return nil, fmt.Errorf("agent message of %d bytes is out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeMessage(w io.Writer, payload []byte) error {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	_, err := w.Write(append(out, payload...))
	return err
}

func appendString(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

func takeString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// parsePublicKey reads an OpenSSH .pub file: "<type> <base64 blob> [comment]".
//
// hostread.Required, not os.ReadFile: this path is payload-reachable in the
// most direct sense a profile allows — ssh_key names a file under the
// target, which @cwd-rw makes rw, and `rm key.pub && mkfifo key.pub` from a
// PREVIOUS run turned a plain ReadFile into an open(2) that never returns,
// before the sandbox even exists (issue #337). "Required" because an
// unreadable pinned key must stay a hard error naming the path, exactly as
// os.ReadFile's did — a silent skip here would start a proxy with no key to
// pin against.
func parsePublicKey(field, path string) ([]byte, string, error) {
	data, err := hostread.Required(path, hostread.MaxSSHPublicKeyBytes)
	if err != nil {
		// Named by FIELD rather than the old "pinned ssh key": with two keys
		// pinned, that string cannot say which file is unreadable.
		return nil, "", fmt.Errorf("%s: %w", field, err)
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 2 {
		return nil, "", fmt.Errorf("%s is not an OpenSSH public key", path)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	comment := ""
	if len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	}
	return blob, comment, nil
}
