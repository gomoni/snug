// Package gpgproxy is a filtering gpg-agent proxy: the sandbox sees only the
// keygrips the profile's fingerprint resolves to, and cannot enumerate, export,
// delete or otherwise reach any other key in your agent.
//
// Why a proxy rather than binding $GNUPGHOME/S.gpg-agent straight through:
// gpg-agent's Assuan protocol has verbs beyond "sign" and "decrypt". Measured
// against gpg 2.4.8, a raw passthrough hands the sandbox:
//
//   - HAVEKEY --list=1000, KEYINFO and KEYINFO --list: every keygrip in your
//     agent, whether or not the profile named the key.
//   - EXPORT_KEY (with KEYWRAP_KEY --export and a preceding KEYINFO): the
//     PRIVATE KEY MATERIAL, transferred over the socket. `gpg --export-secret-keys`
//     drives exactly this, and it is the verb that makes a raw socket a
//     key-exfiltration primitive rather than a signing oracle.
//   - DELETEKEY, IMPORTKEYS, MKKEY, KEYTOOL, PASSPHRASE, CLEARPASSPHRASE,
//     CACHEDEC: mutation of, and denial of service against, the human's agent.
//   - PRESET_PASSPHRASE and the pinentry verbs: a way to have your agent ask
//     YOU for something the sandbox wrote.
//
// Pinning to one fingerprint's grips bounds the blast radius to one identity.
//
// WHAT THIS CANNOT DO, and it is inherent rather than a gap to close later: it
// cannot restrict WHAT is signed or decrypted. A signature oracle for a key is
// authority to use that key for anything it can reach. And for decryption the
// proxy is structurally blind in a second way too: PKDECRYPT takes the
// ciphertext as a server-driven INQUIRE, so the proxy relays a blob it cannot
// interpret, and it cannot tell you what was decrypted. Pinning bounds the
// identity, not the actions. Every agent forwarder in existence has this
// property.
//
// THIS PACKAGE HOLDS KEYGRIPS, NEVER KEYS. It reads no key file, executes no
// external program, and touches no filesystem path. The fingerprint -> keygrip
// resolution happens in internal/cli, which is the layer that already shells
// out; the proxy is handed grips the same way sshproxy.New is handed blobs.
// That is what keeps "what a profile pins" from being a concept this package
// has to learn — see PinnedGrip.
//
// The protocol is implemented at the wire level rather than through a library
// because the filter IS the security control, and it should be readable as
// bytes-in, bytes-out with no framework in between. Assuan is line-oriented:
// commands and replies are \n-terminated, replies are D (data), S (status) and
// # (comment) lines followed by OK or ERR <code> <description>.
package gpgproxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// maxLine bounds one Assuan line read from the sandbox. A command line names a
// keygrip or an option and is small; 64 KiB is far above anything a client
// legitimately sends. An unbounded ReadString from the sandbox is a memory
// exhaustion primitive pointed at snug itself.
const maxLine = 64 * 1024

// maxReply bounds how many bytes the proxy will copy from the agent for one
// command before it gives up. A PKDECRYPT reply and an EXPORT_KEY reply are the
// large ones; the former is bounded by the message it decrypts, the latter is
// refused outright. 1 MiB is generous and finite.
const maxReply = 1 << 20

// Scope is what a profile grants for one pinned key. It is a BIT SET rather
// than a string so the caller's parse is the only place that has to know the
// spelling, and so a union across profiles is an OR.
//
// There is deliberately no "encrypt" bit. Measured: encrypting to the pinned
// key produced an EMPTY agent log — gpg encrypts from the public key alone, the
// same way `gpg --export` needs no agent. A value that is accepted and grants
// nothing is the disease CLAUDE.md names ("podman = \"off\" is refused for
// precisely this"), so encryption is documented as arriving with either scope
// and is not spelled.
//
// There is deliberately no "auth" bit either: gpg-agent's ssh-emulation side is
// a different protocol on the same socket that snug has not measured, and a
// value whose verbs have not been read into this file would be a scope that
// cannot be enforced. It is left unbuilt rather than guessed, per
// .claude/agents/host-bridge.md.
type Scope uint8

const (
	// ScopeSign permits SIGKEY <primary grip>, SETKEYDESC, SETHASH and PKSIGN.
	ScopeSign Scope = 1 << iota
	// ScopeDecrypt permits SETKEY <primary or encryption-subkey grip>,
	// SETKEYDESC and PKDECRYPT. It deliberately does NOT permit SIGKEY: a
	// decryption-only grant must not double as a signing oracle.
	ScopeDecrypt
)

// String is for audit and error text only.
func (s Scope) String() string {
	switch s {
	case 0:
		return "nothing"
	case ScopeSign:
		return "sign"
	case ScopeDecrypt:
		return "decrypt"
	case ScopeSign | ScopeDecrypt:
		return "sign+decrypt"
	default:
		return fmt.Sprintf("scope(0x%x)", uint8(s))
	}
}

// PinnedGrip is one keygrip the sandbox may use, the scope the profile granted
// it, and the profile field that named it. Field is a LABEL for error and audit
// text only — this package does not know the identity schema, and must not
// learn it. The grip itself is a 40-hex-character string, the same one
// `gpg --with-keygrip` prints on a `grp:` line.
//
// The SCOPE travels with the grip rather than with the Proxy because one
// profile can pin a primary key for signing and its encryption subkey for
// decryption, and the two grips then carry different scopes. internal/cli
// derives both grips from a single fingerprint and sets Scope here; this
// package never sees the fingerprint.
type PinnedGrip struct {
	Field string // "identity.gpg.fingerprint"
	Grip  string // 40 hexadecimal characters
	Scope Scope  // what the sandbox may do with THIS grip
}

// grip is a PinnedGrip with the grip decoded to 20 bytes for constant-time
// comparison.
type grip struct {
	field   string
	grip    string
	raw     [20]byte
	sign    bool
	decrypt bool
}

type Proxy struct {
	// pinned is the SET of keygrips the sandbox may use. Membership is the
	// WHOLE filter; see the package comment for why it cannot also be a filter
	// on purpose. It is never empty — New refuses an empty set.
	pinned []grip

	upstream string // the host's real gpg-agent socket
	ln       net.Listener
	audit    func(string)

	// mu orders Serve's wg.Add against Close's wg.Wait: an Add that can run
	// concurrently with a Wait on a zero counter is a misuse of WaitGroup, and
	// the race detector reports it. Once closed is set, Serve adds nothing.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	once   sync.Once
}

// New prepares a proxy pinned to the given keygrips. No key material is read:
// the fingerprints were already resolved to grips by the caller, and the only
// thing this function does on the host is ask the agent, ON ONE CONNECTION
// before the listener is bound, whether it holds each grip and — for a grip
// carrying ScopeSign — whether it will actually sign with it. New refuses when
// either answer is no. See probeUpstream and probeSign for why neither check is
// optional and what they do not promise.
//
// Order is load-bearing: the grip set is checked before the upstream is, so a
// profile error beats a host-state error; and the probe runs before the listener
// is bound, so a refusal leaves no socket behind.
func New(grips []PinnedGrip, upstream, socketPath string, audit func(string)) (*Proxy, error) {
	if len(grips) == 0 {
		return nil, errors.New("gpg-agent proxy: no keygrip to pin. A proxy with an empty pin set " +
			"advertises nothing and refuses every signature, which is a sandbox that looks " +
			"configured and is not")
	}
	var pins []grip
	for _, g := range grips {
		if g.Scope == 0 {
			return nil, fmt.Errorf("%s pins keygrip %s with no scope: it would be "+
				"advertised by HAVEKEY and usable for nothing.\n\n"+
				"      A grip with an empty scope is a grant that grants nothing, which is the\n"+
				"      shape snug refuses rather than accepts. Set identity.gpg.scope in the\n"+
				"      profile (\"sign\", \"decrypt\", or both).", g.Field, truncate(g.Grip, 40))
		}
		raw, err := parseGrip(g.Field, g.Grip)
		if err != nil {
			return nil, err
		}
		if containsGrip(pins, raw) {
			continue // the same grip named twice advertises once
		}
		pins = append(pins, grip{
			field:   g.Field,
			grip:    strings.ToLower(g.Grip),
			raw:     raw,
			sign:    g.Scope&ScopeSign != 0,
			decrypt: g.Scope&ScopeDecrypt != 0,
		})
	}
	if upstream == "" {
		return nil, fmt.Errorf("no gpg-agent is running on the host (GNUPGHOME is unset, or " +
			"gpgconf reports no agent socket), so there is nothing to proxy.\n" +
			"      Start one with any gpg command, e.g.  gpg --list-keys")
	}
	if err := probeUpstream(upstream, pins); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("gpg-agent proxy socket: %w", err)
	}
	// The socket lives in a private per-run directory, but belt and braces:
	// anything that can connect can ask for a signature or a decryption.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("gpg-agent proxy: could not restrict %s to this user (%w); "+
			"anything else on this host that can connect to it could ask for a signature",
			socketPath, err)
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
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			c.Close()
			return
		}
		p.wg.Add(1)
		p.mu.Unlock()
		go func() {
			defer p.wg.Done()
			defer c.Close()
			p.handle(c)
		}()
	}
}

func (p *Proxy) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.ln.Close()
		p.wg.Wait()
	})
}

// handle serves one client connection.
//
// Every command is either answered LOCALLY (enumeration, GETINFO), REFUSED
// (mutation, export, anything unrecognised), or FORWARDED to the host agent
// after the grip and scope are checked.
//
// STATE IS PER CLIENT CONNECTION, AND SO IS THE UPSTREAM CONNECTION. Assuan is
// a stateful request/response stream: SIGKEY sets the key on the connection and
// PKSIGN uses it, so the two MUST reach the same agent connection. A fresh
// upstream connection per command (which sshproxy can afford, because its
// SIGN_REQUEST is self-contained) would lose the SIGKEY and make every PKSIGN
// fail with `No secret key`. So one upstream connection is opened lazily for
// the life of one client connection and reused; two clients never share one.
func (p *Proxy) handle(sandbox net.Conn) {
	s := &session{proxy: p, r: bufio.NewReaderSize(sandbox, 4096), w: bufio.NewWriter(sandbox)}
	defer s.close()

	// Greeting phrase. A client that reads the greeting is told the agent is
	// here; the wording is not gpg-agent's own verbatim, because the proxy is
	// not claiming to be the host agent.
	if err := writeLine(s.w, "OK Pleased to meet you, snug gpg-agent proxy"); err != nil {
		return
	}
	if err := s.w.Flush(); err != nil {
		return
	}

	for {
		line, err := readLine(s.r)
		if err != nil {
			return
		}
		if line == "" {
			continue
		}
		if !s.command(line) {
			s.w.Flush()
			return
		}
		if err := s.w.Flush(); err != nil {
			return
		}
	}
}

// session is one sandbox connection and its lazily-opened upstream.
type session struct {
	proxy *Proxy
	r     *bufio.Reader
	w     *bufio.Writer

	up     net.Conn
	upR    *bufio.Reader
	upW    *bufio.Writer
	upErr  error
	upOpen bool
}

func (s *session) close() {
	if s.up != nil {
		// BYE tells the agent this connection is done, so it does not wait on
		// a half-open socket. Best-effort: a dead agent needs no courtesy.
		_ = writeLine(s.upW, "BYE")
		_ = s.upW.Flush()
		s.up.Close()
	}
}

// upstream returns the shared upstream connection, opening it on first use.
// The error is sticky so a dead agent is reported once per connection rather
// than re-dialled per command.
func (s *session) upstream() (*bufio.Reader, *bufio.Writer, error) {
	if s.upOpen {
		return s.upR, s.upW, s.upErr
	}
	s.upOpen = true
	conn, err := net.Dial("unix", s.proxy.upstream)
	if err != nil {
		s.upErr = err
		return nil, nil, err
	}
	s.up = conn
	s.upR = bufio.NewReaderSize(conn, 4096)
	s.upW = bufio.NewWriter(conn)
	// Consume the agent's greeting.
	for {
		line, err := readLine(s.upR)
		if err != nil {
			s.upErr = err
			return nil, nil, err
		}
		if isTerminal(line) {
			break
		}
	}
	// Propagate TTY/display context to the agent so pinentry behaves like gpg
	// does. Without this, each new Assuan connection can spawn a different
	// pinentry program than the one that was primed by gpg-connect-agent.
	if err := probeSetOptions(s.upW, s.upR); err != nil {
		_ = err
	}
	return s.upR, s.upW, nil
}

// command dispatches one client line. It returns false to end the connection.
func (s *session) command(line string) bool {
	p := s.proxy
	name, args := splitCommand(line)

	switch strings.ToUpper(name) {
	// ── answered locally ────────────────────────────────────────────────
	case "HAVEKEY":
		p.handleHaveKey(s.w, args)
	case "KEYINFO":
		p.handleKeyInfo(s.w, args)
	case "GETINFO":
		p.handleGetInfo(s, args)

	// ── forwarded (grip + scope checked) ────────────────────────────────
	case "RESET", "OPTION", "SETKEYDESC", "SETHASH":
		s.forward(line)

	case "SIGKEY":
		s.handleSetKey(line, args, ScopeSign)
	case "SETKEY":
		s.handleSetKey(line, args, ScopeDecrypt)
	case "PKSIGN":
		s.forward("PKSIGN")
	case "PKDECRYPT":
		s.handlePKDECRYPT()

	case "BYE":
		writeLine(s.w, "OK closing connection")
		return false

	// ── refused ─────────────────────────────────────────────────────────
	case "KEYWRAP_KEY", "EXPORT_KEY", "IMPORT_KEYS", "IMPORTKEYS":
		// EXPORT_KEY is the verb that transfers PRIVATE KEY MATERIAL over the
		// socket; `gpg --export-secret-keys` drives it. This refusal is the
		// single most important line in the file.
		p.refuse(s.w, "refused: sandbox tried to export private key material from the host agent")
	case "DELETEKEY", "DELETE_KEY":
		p.refuse(s.w, "refused: sandbox tried to delete a key from the host agent")
	case "PASSPHRASE", "PRESET_PASSPHRASE", "CLEARPASSPHRASE", "GET_PASSPHRASE":
		p.refuse(s.w, "refused: sandbox tried to set or read a passphrase on the host agent")
	case "CACHEDEC", "CACHE_TTL":
		p.refuse(s.w, "refused: sandbox tried to change the host agent's cache policy")
	case "SETKEYDESC_DUMMY", "MKKEY", "KEYTOOL", "GENKEY":
		p.refuse(s.w, "refused: sandbox tried to create or manipulate keys in the host agent")
	case "SETINFO", "SETEVENTS", "SETPININFO", "GETPININFO", "UPDATESTARTUPTTY",
		"KILLAGENT", "RELOADAGENT", "GETEVENTCOUNTER":
		p.refuse(s.w, "refused: sandbox tried to reconfigure or control the host agent")

	case "SCD":
		// MEASURED, and it cost a live test to learn: `SCD SERIALNO` is part of
		// gpg's NORMAL path, not an attack. Every `gpg -d` sends it before
		// SETKEY, and gpg's key listing sends it too; the host agent answers
		// `ERR 67108983 No SmartCard daemon`. Refusing it wholesale broke
		// signing AND decryption with `problem with fast path key listing:
		// Invalid IPC response`.
		//
		// So only the read-only query is forwarded. Everything else SCD can do
		// — LEARN, APDU, the write verbs — is refused, because those drive card
		// operation and are not something a sandbox needs to reach.
		if strings.EqualFold(strings.TrimSpace(args), "SERIALNO") {
			s.forward(line)
		} else {
			p.refuse(s.w, "refused: sandbox tried to drive the smartcard layer (SCD "+
				truncate(strings.ToUpper(strings.TrimSpace(args)), 20)+")")
		}

	default:
		p.audit(fmt.Sprintf("refused: unknown gpg-agent command %q", truncate(name, 40)))
		writeLine(s.w, "ERR 0 refused by snug: unknown command")
	}
	return true
}

// refuse audits and answers an ERROR. The code 0 is gpg-agent's own generic
// failure; Assuan clients only need the ERR line to know to stop reading.
func (p *Proxy) refuse(w *bufio.Writer, what string) {
	p.audit(what)
	writeLine(w, "ERR 0 refused by snug")
}

// ── the local answers ───────────────────────────────────────────────────────

// handleHaveKey answers the two HAVEKEY forms the proxy must not forward.
//
// Measured against gpg 2.4.8:
//
//	HAVEKEY --list=N        -> D <N raw 20-byte grips concatenated> / OK
//	HAVEKEY <grip> [...]    -> OK when ALL are held, ERR when any is not
//
// Measured through this proxy, and it cost a live test to learn: the multi-grip
// form gpg sends is `HAVEKEY <primary> <subkey>` — BOTH grips on ONE line, and
// this is gpg's "fast path key listing", the shortcut it takes before any
// signing or decryption. The real agent answers OK for it, and so must the
// proxy: refusing (or narrowing it to sign-capable grips) makes gpg report
// `problem with fast path key listing: Invalid IPC response - ignored` and the
// operation fails with no cause. HAVEKEY asks "does this key EXIST here", not
// "may I use it for the operation I have not sent yet" — the scope is enforced
// at SIGKEY/SETKEY, which is the verb that names the capability.
//
// The answer comes from OUR pin set, not the agent's: a grip the agent holds
// but the profile did not pin must read as absent, exactly as sshproxy's
// identitiesAnswer never mentions an unpinned key.
func (p *Proxy) handleHaveKey(w *bufio.Writer, args string) {
	if rest, ok := strings.CutPrefix(args, "--list="); ok {
		// The client asks for N bytes worth; we answer with the pinned grips
		// that FIT, in declaration order. A grip is 20 bytes on the wire.
		raw := p.pinnedRaw()
		want := len(raw) * 20
		if n, err := atoiSafe(rest); err == nil && n < want {
			// Truncate to a whole number of grips, rounding DOWN: a partial
			// grip would be unparsable by the client.
			whole := n / 20
			if whole < len(raw) {
				raw = raw[:whole]
			}
		}
		if len(raw) > 0 {
			// MEASURED, and it cost a live test: the D payload is
			// PERCENT-ESCAPED. gpg's fast-path key listing failed with
			// `Invalid IPC response` because the pinned primary grip contains
			// a 0x0A byte, which the agent writes as the three characters
			// "%0A" and this proxy was writing raw. Assuan escapes %, \n and
			// \r in D lines; a grip is 20 arbitrary bytes, so roughly one grip
			// in ninety needs it.
			writeLine(w, "D "+assuanEscape(rawBytesToString(raw)))
		}
		writeLine(w, "OK")
		return
	}
	// HAVEKEY <grip> [<grip> ...]: the agent requires ALL named grips to be
	// pinned here.
	for _, name := range strings.Fields(args) {
		raw, err := parseGrip("HAVEKEY", name)
		if err != nil {
			writeLine(w, "ERR 67108881 No secret key")
			return
		}
		if !containsGrip(p.pinned, raw) {
			// The agent's own text for a grip it does not hold, so a client
			// sees the same thing it would see from a real agent.
			writeLine(w, "ERR 67108881 No secret key")
			return
		}
	}
	writeLine(w, "OK")
}

// handleKeyInfo answers KEYINFO <grip> and KEYINFO --list locally, for the
// pinned grips only. Measured reply shape:
//
//	S KEYINFO <grip> D - - - C - - -   /  OK
func (p *Proxy) handleKeyInfo(w *bufio.Writer, args string) {
	if strings.TrimSpace(args) == "--list" {
		for _, g := range p.pinned {
			writeLine(w, "S KEYINFO "+g.grip+" D - - - C - - -")
		}
		writeLine(w, "OK")
		return
	}
	for _, name := range strings.Fields(args) {
		raw, err := parseGrip("KEYINFO", name)
		if err != nil {
			writeLine(w, "ERR 67108891 Not found")
			return
		}
		g, ok := gripOf(p.pinned, raw)
		if !ok {
			writeLine(w, "ERR 67108891 Not found")
			return
		}
		writeLine(w, "S KEYINFO "+g.grip+" D - - - C - - -")
	}
	writeLine(w, "OK")
}

// handleGetInfo answers the GETINFO forms that describe the proxy rather than
// the host agent, and forwards none.
//
//   - version: a client that gates a feature on the agent version must not be
//     told the HOST agent's version, because the agent behind the proxy may be
//     a different one than snug measured against. Telling the truth here (a
//     fixed string) is better than a forwarded lie whose value changes with the
//     host. It is the one GETINFO that a gpg client reads on every connection.
//   - pid / socket_name / ssh_socket_name: these name HOST paths and a process
//     that is not inside the sandbox. Answering them would leak where the real
//     agent lives and invite a client to try the ssh socket directly.
//
// Anything else is forwarded, because it is a question about an OPTION the
// client is about to set (cmd_has_option) and the agent is the authority.
func (p *Proxy) handleGetInfo(s *session, args string) {
	switch strings.TrimSpace(args) {
	case "version":
		writeLine(s.w, "D 2.4.8")
		writeLine(s.w, "OK")
	default:
		s.forward("GETINFO " + strings.TrimSpace(args))
	}
}

// ── the checked forwards ────────────────────────────────────────────────────

// handleSetKey accepts SIGKEY <primary grip> under ScopeSign, or SETKEY <grip>
// under ScopeDecrypt, iff the grip is in the pin set AND carries the scope the
// verb needs, then forwards it upstream on the session's connection.
//
// Both verbs are handled here because they differ in exactly three ways: the
// verb name, the grip they may name, and the scope that admits them. Measured:
// signing uses `SIGKEY <primary grip>`, decryption uses
// `SETKEY <encryption-subkey grip>`. A decryption-only grant must not accept
// SIGKEY, and a signing-only grant must not accept SETKEY.
//
// The scope check is the whole reason SETKEY cannot simply be forwarded: gpg
// answers `OK` to SETKEY for ANY grip, including one it does not hold
// (measured: `SETKEY 0000…` → `OK`), and only fails later at PKDECRYPT with
// `No secret key`. So the guard must be here, at the verb that names the grip,
// or a decrypt scope would be enforceable only after the INQUIRE is in flight.
func (s *session) handleSetKey(line, args string, need Scope) {
	p := s.proxy
	verb := nameOf(line)
	gripArg := strings.TrimSpace(args)
	raw, err := parseGrip(strings.ToUpper(verb), gripArg)
	if err != nil {
		p.audit(fmt.Sprintf("refused: malformed keygrip %q", truncate(gripArg, 60)))
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
	g, ok := gripOf(p.pinned, raw)
	if !ok {
		p.audit("refused: " + strings.ToLower(verb) +
			" for a keygrip that is not in the pinned set")
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
	if need&ScopeSign != 0 && !g.sign {
		p.audit("refused: " + strings.ToLower(verb) + " for a grip without the sign scope")
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
	if need&ScopeDecrypt != 0 && !g.decrypt {
		// Unreachable today (every pinned grip carries decrypt), kept so the
		// two arms stay symmetric and a future sign-only grip cannot slip
		// through SETKEY.
		p.audit("refused: " + strings.ToLower(verb) + " for a grip without the decrypt scope")
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
	s.forward(line)
}

// forward relays one command to the session's upstream connection and copies
// the reply back verbatim, until OK or ERR. This is the arm for the commands
// that carry no grip of their own (RESET, OPTION, SETKEYDESC, SETHASH) and for
// the terminal PKSIGN.
//
// It is also the arm that reaches the agent with state from earlier commands on
// the same session: the SIGKEY a client sent two lines ago is on THIS
// connection, so PKSIGN finds it.
func (s *session) forward(line string) {
	p := s.proxy
	upR, upW, err := s.upstream()
	if err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	if err := writeLine(upW, line); err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	if err := upW.Flush(); err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	total := 0
	for {
		reply, err := readLine(upR)
		if err != nil {
			p.upstreamUnreachable(s.w, err)
			return
		}
		total += len(reply)
		if total > maxReply {
			writeLine(s.w, "ERR 0 refused by snug: reply exceeded limit")
			return
		}
		if err := writeLine(s.w, reply); err != nil {
			return
		}
		if isTerminal(reply) {
			return
		}
	}
}

// handlePKDECRYPT forwards a decryption request. This is the arm that is NOT a
// plain forwarding loop, and getting it wrong is a deadlock on every
// decryption.
//
// Measured against gpg 2.4.8, PKDECRYPT is SERVER-DRIVEN: after the client
// sends `PKDECRYPT`, the agent sends
//
//	S INQUIRE_MAXLEN 4096
//	INQUIRE CIPHERTEXT
//
// and WAITS for the client to answer with a D line and an END line before it
// produces its own `D (5:value33:...)` and `OK`. So the proxy cannot
// "copy upstream responses until OK"; it must relay the INQUIRE to the client,
// read exactly one D + END from the client, hand that to the agent, and only
// then resume copying.
//
// The proxy does not parse or interpret the ciphertext: it relays an opaque
// blob and an opaque value. It therefore cannot say WHAT was decrypted — that
// residual is in the package comment, not a gap this function can close.
func (s *session) handlePKDECRYPT() {
	p := s.proxy
	upR, upW, err := s.upstream()
	if err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	if err := writeLine(upW, "PKDECRYPT"); err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	if err := upW.Flush(); err != nil {
		p.upstreamUnreachable(s.w, err)
		return
	}
	total := 0
	for {
		line, err := readLine(upR)
		if err != nil {
			p.upstreamUnreachable(s.w, err)
			return
		}
		total += len(line)
		if total > maxReply {
			writeLine(s.w, "ERR 0 refused by snug: reply exceeded limit")
			return
		}
		switch {
		case isInquire(line):
			// Relay the INQUIRE line to the sandbox, then read its answer.
			if err := writeLine(s.w, line); err != nil {
				return
			}
			if err := s.w.Flush(); err != nil {
				return
			}
			if err := relayInquireAnswer(s.r, upW, s.w); err != nil {
				return
			}
		default:
			// A D, S, # or terminal OK/ERR line: pass it through unchanged.
			if err := writeLine(s.w, line); err != nil {
				return
			}
			if isTerminal(line) {
				return
			}
		}
	}
}

// relayInquireAnswer reads the sandbox's reply to an INQUIRE — the client
// writes one or more D lines carrying the data, then an END line — and hands it
// to the agent verbatim. Both directions are unbounded in principle, so both
// are bounded here: a client that never sends END must not pin a goroutine, and
// the total data must not exceed maxReply.
func relayInquireAnswer(r *bufio.Reader, upW *bufio.Writer, w *bufio.Writer) error {
	total := 0
	for {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		total += len(line)
		if total > maxReply {
			// Tell the agent to stop waiting, then the sandbox.
			_ = writeLine(upW, "END")
			_ = upW.Flush()
			return errors.New("inquire answer exceeded limit")
		}
		if err := writeLine(upW, line); err != nil {
			return err
		}
		if err := upW.Flush(); err != nil {
			return err
		}
		// END terminates the client's answer to the INQUIRE. CANCEL is the
		// protocol's own way of declining, and is relayed too.
		if strings.HasPrefix(line, "END") || strings.HasPrefix(line, "CANCEL") {
			return nil
		}
	}
}

// upstreamUnreachable audits and answers the agent's own failure for "no key
// available". A client that gets this retries or reports it as the agent being
// down, which is what happened.
func (p *Proxy) upstreamUnreachable(w *bufio.Writer, err error) {
	p.audit(fmt.Sprintf("upstream gpg-agent unreachable: %v", err))
	writeLine(w, "ERR 67108881 No secret key")
}

// ── pin-set helpers ─────────────────────────────────────────────────────────

func (p *Proxy) pinnedRaw() [][20]byte {
	out := make([][20]byte, 0, len(p.pinned))
	for _, g := range p.pinned {
		out = append(out, g.raw)
	}
	return out
}

// containsGrip reports whether raw is one of set, with no early exit: every
// element is compared and the results are OR'd, so the time taken does not say
// WHICH element matched. The secrecy here is nil — keygrips are public
// identifiers, and handleHaveKey hands the whole set to the sandbox on request
// — and the loop is written this way for the reason sshproxy.containsBlob is:
// a variable-time compare in a security filter invites the next reader to copy
// the pattern somewhere it does matter.
func containsGrip(set []grip, raw [20]byte) bool {
	match := 0
	for _, g := range set {
		match |= subtle.ConstantTimeCompare(raw[:], g.raw[:])
	}
	return match == 1
}

func gripOf(set []grip, raw [20]byte) (grip, bool) {
	var found grip
	ok := false
	for _, g := range set {
		if subtle.ConstantTimeCompare(raw[:], g.raw[:]) == 1 {
			found = g
			ok = true
		}
	}
	return found, ok
}

// parseGrip decodes a 40-hex-character keygrip into its 20 bytes. It is
// lenient about case, because gpg prints uppercase in some places and a client
// may too, and strict about length and alphabet, because a grip that is not 20
// bytes cannot be compared against the pin set.
func parseGrip(field, s string) ([20]byte, error) {
	var raw [20]byte
	s = strings.TrimSpace(s)
	if len(s) != 40 {
		return raw, fmt.Errorf("%s: %q is not a keygrip (want 40 hexadecimal characters)",
			field, truncate(s, 60))
	}
	for i := 0; i < 20; i++ {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return raw, fmt.Errorf("%s: %q is not a keygrip (want 40 hexadecimal characters)",
				field, truncate(s, 60))
		}
		raw[i] = hi<<4 | lo
	}
	return raw, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ── Assuan line helpers ─────────────────────────────────────────────────────

// assuanEscape percent-escapes a D-line payload: % becomes %25, LF becomes %0A
// and CR becomes %0D. Measured against gpg 2.4.8: the agent writes a keygrip
// containing the byte 0x0A as the three characters "%0A". A D line is
// newline-terminated, so an unescaped 0x0A would end the line early and the
// client would read a truncated payload.
//
// The escape SET is deliberately minimal — exactly the characters that would
// otherwise break the framing, plus '%' itself. Escaping anything else (for
// instance every non-printable byte) would still parse, but it would differ
// byte-for-byte from what the agent writes, and the D lines this proxy forwards
// from upstream are copied VERBATIM rather than re-escaped, so matching the
// agent's own habit is what keeps the two indistinguishable.
func assuanEscape(s []byte) string {
	if !needsEscape(s) {
		return string(s)
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, c := range s {
		switch c {
		case '%':
			b.WriteString("%25")
		case '\n':
			b.WriteString("%0A")
		case '\r':
			b.WriteString("%0D")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func needsEscape(s []byte) bool {
	for _, c := range s {
		if c == '%' || c == '\n' || c == '\r' {
			return true
		}
	}
	return false
}

// assuanUnescape is NOT used by the relay, and that is deliberate: the INQUIRE
// answer is forwarded byte-for-byte. The measurement that settled it: on a real
// decrypt, the client sent
//
//	D (7:enc-val(4:ecdh(1:s49:<49 raw bytes>)(1:e33:<33 raw bytes>)))
//
// with no percent-escapes at all, and the agent read it. Escaping in Assuan is
// applied by whoever WRITES a D line, and only the bytes that would break the
// framing need it; a payload with none of them travels raw. The proxy is a byte
// pipe in both directions, so it neither adds nor removes escaping on relayed
// lines — doing so would corrupt a ciphertext whose author chose not to escape.
//
// It is kept, unexported and exercised, because handleHaveKey GENERATES a D line
// and generation is the case that needs the inverse, and a test asserts the
// round trip so the pair cannot drift apart.
func assuanUnescape(s string) []byte {
	if !strings.ContainsRune(s, '%') {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// readLine reads one Assuan line (up to \n) and strips the terminator. It is
// bounded by maxLine so a sandbox that never sends a newline cannot exhaust
// snug's memory.
func readLine(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, more, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		sb.Write(chunk)
		if sb.Len() > maxLine {
			return "", errors.New("assuan line too long")
		}
		if !more {
			return sb.String(), nil
		}
	}
}

func writeLine(w *bufio.Writer, s string) error {
	if _, err := w.WriteString(s); err != nil {
		return err
	}
	return w.WriteByte('\n')
}

// isTerminal reports whether an Assuan reply line ends the server's response
// for the current command.
func isTerminal(line string) bool {
	return strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "ERR")
}

// isInquire reports whether a line from the agent is an INQUIRE the client must
// answer. The keyword is `INQUIRE `; `INQUIRE_MAXLEN` rides alongside it as an
// S line and is relayed like any other non-terminal line.
func isInquire(line string) bool {
	return strings.HasPrefix(line, "INQUIRE ") || line == "INQUIRE"
}

// splitCommand splits an Assuan line into the command keyword and the rest.
func splitCommand(line string) (name, args string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
}

func nameOf(line string) string {
	name, _ := splitCommand(line)
	return name
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// hexString renders bytes as lowercase hex, the form gpg prints and accepts.
func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// rawBytesToString converts a byte slice to a string without a copy being
// observable. Go strings are immutable, so a copy is made; this exists to name
// the conversion rather than hide it, and is only ever used on keygrips, which
// are public.
func rawBytesToString(b [][20]byte) []byte {
	out := make([]byte, 0, len(b)*20)
	for _, r := range b {
		out = append(out, r[:]...)
	}
	return out
}

func atoiSafe(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(s[i]-'0')
		if n > maxReply {
			return 0, errors.New("too large")
		}
	}
	return n, nil
}

func probeSetOptions(w *bufio.Writer, r *bufio.Reader) error {
	// Try to mirror gpg's behavior: tell the agent about the TTY and display
	// so it can spawn pinentry in the right context.
	setOption := func(opt string) {
		_ = writeLine(w, "OPTION "+opt)
		_ = w.Flush()
		// OPTION may return OK or ERR; consume the reply if present.
		line, err := readLine(r)
		if err != nil {
			return
		}
		_ = line
	}
	if v := os.Getenv("GPG_TTY"); v != "" {
		setOption("ttyname=" + v)
		setOption("ttytype=linux")
		setOption("putenv=GPG_TTY=" + v)
	} else if v := os.Getenv("TERM"); v != "" {
		setOption("ttytype=" + v)
	}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_CURRENT_DESKTOP", "GNOME_DESKTOP_SESSION_ID", "DESKTOP_SESSION"} {
		if v := os.Getenv(key); v != "" {
			setOption(key + "=" + v)
			setOption("putenv=" + key + "=" + v)
		}
	}
	// Some agents need this to actually use the options for the current session
	_ = writeLine(w, "UPDATESTARTUPTTY")
	_ = w.Flush()
	line, err := readLine(r)
	if err == nil {
		_ = line
	}
	return nil
}

// ── the startup probe ───────────────────────────────────────────────────────

// probeTimeout bounds the whole startup exchange — dial, write, read. On a
// live agent this is sub-millisecond over a unix socket; the value is loose
// because it exists to bound a hung or unresponsive socket, not to tune a fast
// path, and the cost is only ever paid on a host that is already broken.
const probeTimeout = 5 * time.Second

// probeUpstream asks the host agent ONCE, before the sandbox exists, whether it
// holds every pinned grip, and refuses the run when it does not.
//
// WHY THIS IS NOT OPTIONAL. snug authors the thing that makes the failure
// fatal: with identity.gpg it writes `gpg.format = openpgp` and
// `user.signingkey` into the generated ~/.gitconfig, so a grip the agent does
// not hold turns every signed commit inside into a hard failure whose error
// names libcrypto or a failed key lookup, not a missing pin. The sandbox cannot
// see the host agent's contents, so the diagnosis is unavailable at the layer
// where the failure appears. It is available here. That is invariant 5 in its
// literal form, and it is why this lives in New rather than behind a method a
// caller can skip.
//
// It contacts the upstream agent, which the sandbox-initiated HAVEKEY path
// deliberately never does. The distinction survives: that path answers locally
// so the agent's other grips are never enumerated FOR THE SANDBOX. This is snug
// asking on the human's behalf, before a sandbox exists, and nothing it learns
// reaches one — the only thing said about the agent's contents in any refusal
// is whether the PINNED grip is among them.
func probeUpstream(upstream string, pins []grip) error {
	deadline := time.Now().Add(probeTimeout)
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", upstream)
	if err != nil {
		return probeNoAnswer(upstream, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return probeNoAnswer(upstream, err)
	}
	r := bufio.NewReaderSize(conn, 4096)
	w := bufio.NewWriter(conn)
	// Greeting.
	for {
		line, err := readLine(r)
		if err != nil {
			return probeNoAnswer(upstream, err)
		}
		if isTerminal(line) {
			break
		}
	}
	// Set up TTY/display context so the agent can spawn pinentry correctly,
	// just like the gpg CLI does. The agent may ignore these, but without them
	// a new Assuan connection (from a process different from gpg) often fails to
	// start a GUI or tty pinentry with "Inappropriate ioctl for device".
	if err := probeSetOptions(w, r); err != nil {
		// Non-fatal: the agent might not support all options; continue and let
		// the actual sign probe report a clearer error if pinentry fails.
		_ = err
	}
	// Set up TTY/display context so the agent can spawn pinentry correctly,
	// just like the gpg CLI does. The agent may ignore these, but without them
	// a new Assuan connection (from a process different from gpg) often fails to
	// start a GUI or tty pinentry with "Inappropriate ioctl for device".
	if err := probeSetOptions(w, r); err != nil {
		// Non-fatal: the agent might not support all options; continue and let
		// the actual sign probe report a clearer error if pinentry fails.
		_ = err
	}
	// One HAVEKEY per grip: the multi-grip form answers a single ERR when ANY
	// is missing, which would not say WHICH pin the profile got wrong.
	for _, g := range pins {
		if err := writeLine(w, "HAVEKEY "+g.grip); err != nil {
			return probeNoAnswer(upstream, err)
		}
		if err := w.Flush(); err != nil {
			return probeNoAnswer(upstream, err)
		}
		line, err := readLine(r)
		if err != nil {
			return probeNoAnswer(upstream, err)
		}
		if strings.HasPrefix(line, "OK") {
			continue
		}
		return fmt.Errorf("the host gpg-agent does not hold the keygrip for %s (%s).\n\n"+
			"      That grip is derived from the fingerprint the profile pins. The PRIVATE\n"+
			"      half must be in the agent on the HOST, because no key material ever enters\n"+
			"      the sandbox. The agent answered:\n"+
			"        %s\n"+
			"      Load the key, or check it is not on a smartcard:\n"+
			"        gpg --list-secret-keys --with-keygrip <fingerprint>\n"+
			"      Or remove identity.gpg from the profile.",
			g.field, g.grip, strings.TrimSpace(line))
	}

	// Phase 2, on the SAME connection: membership was not enough for the keys
	// snug's own generated config makes mandatory. A grip the agent LISTS but
	// will not USE fails every commit inside with an error naming no cause. The
	// probe proves the agent ANSWERS for that grip, which is the failure
	// measured; it is startup state, not a guarantee.
	for _, g := range pins {
		if !g.sign {
			continue
		}
		if err := probeSign(conn, g); err != nil {
			return err
		}
	}
	return nil
}

// signProbePrefix domain-separates the probe digest so the signature snug gets
// back cannot be replayed as anything. The bytes hashed are this 17-byte prefix
// followed by 32 bytes from crypto/rand: fresh per key, per run, and not
// influenced by anything outside this function.
//
// A verifier of an OpenPGP signature does not PARSE the signed blob for the
// meaning of the signature; it hashes the payload it expects and checks the
// signature over that hash. So the property needed is that no payload a
// verifier constructs can EQUAL these bytes. The prefix is ASCII "snug-agent-probe"
// and a NUL, and an OpenPGP signature over a normal document (a git commit, an
// email) hashes that document verbatim — so the only way to construct a payload
// equal to this one is to already possess these exact 49 bytes, which no party
// outside this process does.
const signProbePrefix = "snug-agent-probe\x00"

const signProbeNonceBytes = 32

// signProbeTimeout bounds the SIGN phase, and it is deliberately not
// probeTimeout. A pinentry prompt on the host can block the client for as long
// as the human takes to answer; probeTimeout (5 s) would abort exactly the case
// the sign probe exists to serve — a human being asked, on the host, to confirm
// — and turn a working setup into a refusal. Two minutes bounds a hung agent;
// it does not pace a human, and nothing waits on it when the answer is no.
const signProbeTimeout = 2 * time.Minute

// probeSign asks the agent for one signature with a grip snug's generated
// config makes mandatory. The reply is INSPECTED AND DROPPED: nothing derived
// from it is stored, audited, written or sent to any client. The signature is
// over bytes that mean nothing to anyone, and the only thing snug wants is that
// it exists.
//
// It sends SIGKEY, SETKEYDESC, SETHASH and PKSIGN exactly as a client would
// (measured order), so a host that refuses the sequence refuses the probe for
// the same reason it would refuse the real thing.
func probeSign(conn net.Conn, g grip) error {
	nonce := make([]byte, signProbeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating the startup signature probe for %s: %w", g.field, err)
	}
	// SETHASH 10 <hex> takes the SHA-256 of the payload it is given; the agent
	// wants the DIGEST, not the payload. Send the digest of (prefix||nonce).
	digest := sha256Sum(append([]byte(signProbePrefix), nonce...))

	if err := conn.SetDeadline(time.Now().Add(signProbeTimeout)); err != nil {
		return probeSignNoAnswer(g, err)
	}
	r := bufio.NewReaderSize(conn, 4096)
	w := bufio.NewWriter(conn)
	expectOK := func(cmd string) error {
		if err := writeLine(w, cmd); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
		line, err := readLine(r)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "OK") {
			return fmt.Errorf("agent answered %q", strings.TrimSpace(line))
		}
		return nil
	}
	start := time.Now()
	if err := expectOK("RESET"); err != nil {
		return probeSignNoAnswer(g, err)
	}
	if err := expectOK("SIGKEY " + strings.ToUpper(g.grip)); err != nil {
		return probeSignSignRefused(g, err, time.Since(start))
	}
	if err := expectOK("SETKEYDESC snug-agent-probe"); err != nil {
		return probeSignNoAnswer(g, err)
	}
	if err := expectOK("SETHASH 10 " + strings.ToUpper(hexString(digest))); err != nil {
		return probeSignNoAnswer(g, err)
	}
	// PKSIGN: read until OK/ERR, then look for a D line carrying sig-val.
	if err := writeLine(w, "PKSIGN"); err != nil {
		return probeSignNoAnswer(g, err)
	}
	if err := w.Flush(); err != nil {
		return probeSignNoAnswer(g, err)
	}
	sawData := false
	for {
		line, err := readLine(r)
		if err != nil {
			return probeSignNoAnswer(g, err)
		}
		if strings.HasPrefix(line, "D ") {
			sawData = true
		}
		if strings.HasPrefix(line, "ERR") {
			return probeSignSignRefused(g, fmt.Errorf("agent answered %q", strings.TrimSpace(line)),
				time.Since(start))
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	if !sawData {
		return fmt.Errorf("the host gpg-agent answered PKSIGN for %s (%s) without a signature.\n\n"+
			"      snug asks for ONE signature at startup, over a probe digest of its own,\n"+
			"      because it authors `gpg.format = openpgp` and `commit.gpgsign = true` in the\n"+
			"      sandbox's ~/.gitconfig: a key the agent will not USE fails every commit inside.\n"+
			"      Reproduce by hand:  echo snug | gpg --detach-sign -u %s\n"+
			"      Or remove identity.gpg from the profile.",
			g.field, g.grip, g.field)
	}
	return nil
}

func probeSignSignRefused(g grip, cause error, elapsed time.Duration) error {
	return fmt.Errorf("the host gpg-agent holds %s (%s) but refused to sign with it: %v.\n\n"+
		"      snug asks for ONE signature at startup, over a probe digest of its own, because\n"+
		"      it authors `commit.gpgsign = true` inside. A key the agent LISTS but will not\n"+
		"      USE fails every signed commit inside with an error naming no cause.\n"+
		"      The agent answered after %s.\n"+
		"      Reproduce by hand:  echo snug | gpg --detach-sign -u %s\n"+
		"      Or remove identity.gpg from the profile.",
		g.field, g.grip, cause, elapsed.Round(time.Millisecond), g.field)
}

func probeSignNoAnswer(g grip, err error) error {
	return fmt.Errorf("the host gpg-agent did not answer a signature request for %s (%s) "+
		"within %s: %w.\n\n"+
		"      snug asks for one signature at startup because it authors `commit.gpgsign = true`\n"+
		"      inside, and a key that cannot sign fails every commit with an error naming no\n"+
		"      cause. If a pinentry dialog is open on the host, answer it and re-run.\n"+
		"      Check by hand:  echo snug | gpg --detach-sign -u %s\n"+
		"      Or remove identity.gpg from the profile.",
		g.field, g.grip, signProbeTimeout, err, g.field)
}

func probeNoAnswer(upstream string, err error) error {
	return fmt.Errorf("the host gpg-agent at %s did not answer: %w.\n\n"+
		"      snug asks the agent once, at startup, whether it holds the keygrip the profile\n"+
		"      pins. A sandbox that believes it can sign and cannot fails later, INSIDE, as an\n"+
		"      error from git or gpg that names no cause.\n"+
		"      Check the agent is alive:  gpg-connect-agent 'GETINFO version' /bye",
		upstream, err)
}
