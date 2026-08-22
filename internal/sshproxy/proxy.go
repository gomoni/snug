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
// The protocol is implemented at the wire level rather than through a library
// because the filter IS the security control, and it should be readable as
// bytes-in, bytes-out with no framework in between.
package sshproxy

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

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

type Proxy struct {
	// pinned is the SSH wire-format public key blob the sandbox may use.
	pinned  []byte
	comment string

	upstream string // the host's real SSH_AUTH_SOCK
	ln       net.Listener
	audit    func(string)

	wg   sync.WaitGroup
	once sync.Once
}

// New parses a PUBLIC key file and prepares a proxy for it. Only the public
// half is ever read: the private key stays wherever it is, and the sandbox
// never sees key material of any kind.
func New(pubKeyPath, upstream, socketPath string, audit func(string)) (*Proxy, error) {
	blob, comment, err := parsePublicKey(pubKeyPath)
	if err != nil {
		return nil, err
	}
	if upstream == "" {
		return nil, fmt.Errorf("no ssh-agent is running on the host (SSH_AUTH_SOCK is unset), " +
			"so there is nothing to proxy.\n" +
			"      Start one and load your key, or set ssh_mode = \"none\" in the profile")
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
	return &Proxy{pinned: blob, comment: comment, upstream: upstream, ln: ln, audit: audit}, nil
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

func (p *Proxy) identitiesAnswer() []byte {
	out := []byte{identitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, 1)
	out = appendString(out, p.pinned)
	out = appendString(out, []byte(p.comment))
	return out
}

// handleSign forwards a signature request if and only if it names the pinned
// key, byte for byte.
func (p *Proxy) handleSign(c net.Conn, msg []byte) {
	blob, _, ok := takeString(msg[1:])
	if !ok {
		writeMessage(c, []byte{agentFailure})
		return
	}
	// Constant time: the comparison is against a public key, so this is
	// defence against nothing in particular, but a variable-time compare in a
	// security filter invites the next reader to copy the pattern somewhere it
	// does matter.
	if subtle.ConstantTimeCompare(blob, p.pinned) != 1 {
		p.audit("refused: signature requested for a key that is not the pinned one")
		writeMessage(c, []byte{agentFailure})
		return
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
		p.audit("signed with the pinned key")
	}
	writeMessage(c, reply)
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
func parsePublicKey(path string) ([]byte, string, error) {
	data, err := hostread.Required(path, hostread.MaxSSHPublicKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("pinned ssh key: %w", err)
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
