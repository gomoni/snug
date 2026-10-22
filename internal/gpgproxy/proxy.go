// Package gpgproxy is a filtering gpg-agent proxy: the sandbox sees only the
// keygrips the profile's fingerprint resolves to, and cannot enumerate, export,
// delete or otherwise reach any other key in your agent.
//
// Why a proxy rather than binding $GNUPGHOME/S.gpg-agent straight through:
// gpg-agent's Assuan protocol has verbs beyond "sign" and "decrypt". A raw
// passthrough hands the sandbox (verbs from gpg-agent 2.5.24's HELP):
//
//   - HAVEKEY --list=1000, KEYINFO and KEYINFO --list: every keygrip in your
//     agent, whether or not the profile named the key.
//   - EXPORT_KEY (with KEYWRAP_KEY --export and a preceding KEYINFO): the
//     PRIVATE KEY MATERIAL, transferred over the socket. `gpg --export-secret-keys`
//     drives exactly this, and it is the verb that makes a raw socket a
//     key-exfiltration primitive rather than a signing oracle.
//   - DELETE_KEY, IMPORT_KEY, GENKEY, PASSWD, CLEAR_PASSPHRASE: mutation of,
//     and denial of service against, the human's agent.
//   - OPTION, SETKEYDESC and PRESET_PASSPHRASE: a way to choose where the
//     human's pinentry appears and what it says, so the agent asks YOU for
//     something the sandbox wrote.
//
// Every verb not named in session.command is refused. Pinning to one
// fingerprint's SUBKEY grips bounds the blast radius to one identity, minus
// certification.
//
// WHAT THIS CANNOT DO, and it is inherent rather than a gap to close later: it
// cannot restrict WHAT is signed or decrypted. A signature oracle for a key is
// authority to use that key for anything it can reach. And for decryption the
// proxy is structurally blind in a second way too: PKDECRYPT takes the
// ciphertext as a server-driven INQUIRE, so the proxy relays a blob it cannot
// interpret, and it cannot tell you what was decrypted. Pinning bounds the
// identity, not the actions. Every agent forwarder in existence has this
// property. What the proxy CAN hold is the verb: a key selected for decryption
// never reaches PKSIGN, and the only question the agent may ask the sandbox is
// INQUIRE CIPHERTEXT.
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
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/unixserve"
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
	// ScopeSign permits SIGKEY <grip>, SETHASH and a PKSIGN that follows it.
	ScopeSign Scope = 1 << iota
	// ScopeDecrypt permits SETKEY <grip> and a PKDECRYPT that follows it. It
	// deliberately does NOT permit SIGKEY, nor a PKSIGN after SETKEY: a
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
	audit    func(string)

	srv *unixserve.Server
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
//
// The startup probe's pinentry, if the key is locked, is pointed at the
// terminal and display in os.Getenv; NewEnv takes them from a caller instead.
func New(grips []PinnedGrip, upstream, socketPath string, audit func(string)) (*Proxy, error) {
	return NewEnv(grips, upstream, socketPath, audit, os.Getenv)
}

// NewEnv is New with the environment the startup probe's pinentry options are
// read from passed in.
func NewEnv(grips []PinnedGrip, upstream, socketPath string, audit func(string),
	getenv func(string) string) (*Proxy, error) {
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
	if err := probeUpstream(upstream, pins, getenv); err != nil {
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
	return &Proxy{pinned: pins, upstream: upstream, srv: unixserve.New(ln), audit: audit}, nil
}

func (p *Proxy) Serve() { p.srv.Serve(p.handle) }

// Close stops the proxy and ends every live sandbox connection.
func (p *Proxy) Close() { p.srv.Close() }

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
		if !s.command(line) || s.ended {
			_ = s.w.Flush()
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

	// ended is set when the session cannot continue in step with the agent —
	// a reply cut off at maxReply, an INQUIRE relay that failed — so the
	// connection is closed rather than left to read the rest of an old reply as
	// the answer to the next command.
	ended bool

	// selected is the scope of the verb that last chose this connection's key:
	// ScopeSign after an admitted SIGKEY, ScopeDecrypt after an admitted SETKEY,
	// zero after RESET or any refused selection. PKSIGN needs ScopeSign and
	// PKDECRYPT needs ScopeDecrypt.
	//
	// The grip check at SIGKEY/SETKEY is not enough on its own, because the
	// agent keeps ONE selected key for both verbs. Measured on gpg-agent 2.5.24
	// through this proxy under a decrypt-only profile: `SETKEY <primary grip>`,
	// `SETHASH`, `PKSIGN` returned a sig-val — a decryption grant was a signing
	// oracle.
	selected Scope
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
	// The dial, greeting and OPTION exchange are bounded; the commands after
	// them are not, because PKSIGN and PKDECRYPT may wait on a pinentry a
	// human answers.
	conn, err := net.DialTimeout("unix", s.proxy.upstream, probeTimeout)
	if err != nil {
		s.upErr = err
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		conn.Close()
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
	// No OPTION is sent here. A pinentry for a sandbox command takes the
	// agent's own startup environment, never a tty or display the sandbox or
	// snug's terminal names, because the sandbox shares that terminal and
	// could read what the human types into it.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.upErr = err
		return nil, nil, err
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
	case "RESET":
		s.selected = 0
		s.forward(line)
	case "OPTION":
		p.handleOption(s.w, args)
	case "SETKEYDESC":
		// The prompt text is the proxy's, written after an admitted
		// SIGKEY/SETKEY. Measured through this proxy: a sandbox-authored
		// SETKEYDESC ("system update needs your password") reached the host
		// pinentry verbatim.
		writeLine(s.w, "OK")
	case "SETHASH":
		s.forward(line)

	case "SIGKEY":
		s.handleSetKey(line, args, ScopeSign)
	case "SETKEY":
		s.handleSetKey(line, args, ScopeDecrypt)
	case "PKSIGN":
		if s.selected != ScopeSign {
			p.refuse(s.w, "refused: pksign without a key selected by sigkey")
			break
		}
		s.forward("PKSIGN")
	case "PKDECRYPT":
		if s.selected != ScopeDecrypt {
			p.refuse(s.w, "refused: pkdecrypt without a key selected by setkey")
			break
		}
		s.handlePKDECRYPT(line, args)

	case "BYE":
		_ = writeLine(s.w, "OK closing connection")
		return false

	// ── refused ─────────────────────────────────────────────────────────
	case "KEYWRAP_KEY", "EXPORT_KEY", "IMPORT_KEY":
		// EXPORT_KEY is the verb that transfers PRIVATE KEY MATERIAL over the
		// socket; `gpg --export-secret-keys` drives it. This refusal is the
		// single most important line in the file.
		p.refuse(s.w, "refused: sandbox tried to export private key material from the host agent")
	case "DELETE_KEY":
		p.refuse(s.w, "refused: sandbox tried to delete a key from the host agent")
	case "PASSWD", "PRESET_PASSPHRASE", "CLEAR_PASSPHRASE", "GET_PASSPHRASE":
		p.refuse(s.w, "refused: sandbox tried to set or read a passphrase on the host agent")
	case "GENKEY", "KEYTOCARD", "KEYTOTPM", "KEYATTR", "PUT_SECRET", "GET_SECRET":
		p.refuse(s.w, "refused: sandbox tried to create or manipulate keys in the host agent")
	case "UPDATESTARTUPTTY", "KILLAGENT", "RELOADAGENT", "GETEVENTCOUNTER":
		p.refuse(s.w, "refused: sandbox tried to reconfigure or control the host agent")

	case "SCD":
		// MEASURED, and it cost a live test to learn: `SCD SERIALNO` is part of
		// gpg's NORMAL path, not an attack. Every `gpg -d` sends it before
		// SETKEY, and gpg's key listing sends it too; with no card, gpg-agent
		// 2.4.4 and 2.5.24 answer `ERR 100696144 No such device <SCD>`
		// (measured; scdaemon installed). Refusing it wholesale broke
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
		writeLine(s.w, errForbidden)
	}
	return true
}

// errForbidden is the refusal the host agent itself gives on its restricted
// socket (agent-extra-socket), measured against gpg-agent 2.5.24 for
// EXPORT_KEY, DELETE_KEY and GETINFO socket_name: GPG_ERR_FORBIDDEN (251) from
// source GPG_ERR_SOURCE_GPGAGENT (4 << 24). Code 0 is GPG_ERR_NO_ERROR, so an
// `ERR 0` line reads to libgpg-error as a failure that is also a success.
const errForbidden = "ERR 67109115 Forbidden <snug>"

// refuse audits and answers the agent's own Forbidden.
func (p *Proxy) refuse(w *bufio.Writer, what string) {
	p.audit(what)
	writeLine(w, errForbidden)
}

// ── the local answers ───────────────────────────────────────────────────────

// handleOption answers OPTION locally and forwards none.
//
// OPTION sets the environment the host agent gives its pinentry, and every
// value of it measured through the proxy was a hole: `ttyname=<host path>`
// made pinentry-curses open that path on the HOST and overwrite it with the
// prompt (a 9-byte file became 17792 bytes), `pinentry-mode=loopback` turned
// the passphrase prompt into an INQUIRE the sandbox answers (unlimited
// guessing), and `allow-pinentry-notify` makes the agent report the host
// pinentry's pid and tty. The names gpg sends on every connection are
// answered OK so gpg proceeds; pinentry-mode and anything unlisted is
// refused.
func (p *Proxy) handleOption(w *bufio.Writer, args string) {
	name, _, _ := strings.Cut(strings.TrimSpace(args), "=")
	name, _, _ = strings.Cut(name, " ")
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ttyname", "ttytype", "display", "xauthority", "putenv", "lc-ctype",
		"lc-messages", "allow-pinentry-notify", "agent-awareness":
		writeLine(w, "OK")
	default:
		p.refuse(w, fmt.Sprintf("refused: OPTION %q", truncate(name, 40)))
	}
}

// handleHaveKey answers the two HAVEKEY forms the proxy must not forward.
//
// Measured against gpg-agent 2.4.4 and 2.5.24:
//
//	HAVEKEY --list=N        -> D <raw 20-byte grips concatenated> / OK
//	HAVEKEY <grip> [...]    -> OK when ANY is held, ERR when none is
//
// (`HAVEKEY <held> 0000…` answered OK on both.) The proxy answers the same
// question about its pin set. That matters with subkey-only pinning: gpg names
// the primary and its subkeys on one line, and the primary is never pinned.
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
			writeLine(w, "D "+assuanEscape(concatGrips(raw)))
		}
		writeLine(w, "OK")
		return
	}
	// HAVEKEY <grip> [<grip> ...]: OK when any named grip is pinned here.
	for _, name := range strings.Fields(args) {
		raw, err := parseGrip("HAVEKEY", name)
		if err != nil {
			continue
		}
		if containsGrip(p.pinned, raw) {
			writeLine(w, "OK")
			return
		}
	}
	// The agent's own text for a grip it does not hold, so a client sees the
	// same thing it would see from a real agent.
	writeLine(w, "ERR 67108881 No secret key")
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

// handleGetInfo forwards the GETINFO forms a client needs to talk to the agent
// and refuses the rest.
//
// Measured against gpg-agent 2.5.24, the refused forms answer with HOST state:
// `pid` and `connections` name the host process, `socket_name` and
// `ssh_socket_name` the host paths (an invitation to try the ssh socket
// directly), and `std_session_env`, `std_startup_env` and `getenv NAME` the
// agent's environment — GPG_TTY, DISPLAY, XAUTHORITY and anything else it was
// started with. The agent's own restricted socket forbids the same set.
//
// `version` is forwarded, not answered locally. gpg compares it against its own
// version and picks its protocol from the answer, so a fixed string is a lie
// the client acts on: answering 2.4.8 to gpg 2.5 printed "server 'gpg-agent' is
// older than us" on every call. The version names no path, process or secret.
// `cmd_has_option` is a question about the protocol the agent speaks, so the
// agent is the authority on it too.
func (p *Proxy) handleGetInfo(s *session, args string) {
	what := strings.TrimSpace(args)
	name, rest := splitCommand(what)
	switch name {
	case "cmd_has_option":
		// The one form that takes arguments: a command name and an option.
		s.forward("GETINFO " + what)
	case "version", "restricted", "s2k_count", "s2k_time", "s2k_count_cal",
		"scd_running", "jent_active":
		// No arguments, so none are passed on: a trailing word would reach a
		// future agent that gives it a meaning, unreviewed.
		if strings.TrimSpace(rest) != "" {
			p.refuse(s.w, fmt.Sprintf("refused: GETINFO %s takes no argument", name))
			return
		}
		s.forward("GETINFO " + name)
	default:
		p.refuse(s.w, fmt.Sprintf("refused: GETINFO %q describes the host agent", truncate(name, 40)))
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
//
// SETKEY may also carry `--another`: measured with gpg 2.5.24, a post-quantum
// (composite Kyber) subkey has two grips and decryption sends `SETKEY <first>`
// then `SETKEY --another <second>`. The second grip is checked exactly like the
// first; the option changes which slot it fills, not what is required of it.
//
// `--another` ADDS a grip to the key a plain SETKEY selected, so it is admitted
// only on a connection whose selection is already ScopeDecrypt: after a SIGKEY
// it would turn a sign-scoped selection into a decryption.
func (s *session) handleSetKey(line, args string, need Scope) {
	p := s.proxy
	verb := nameOf(line)
	gripArg := strings.TrimSpace(args)
	another := false
	if need == ScopeDecrypt {
		if rest, ok := strings.CutPrefix(gripArg, "--another "); ok {
			gripArg = strings.TrimSpace(rest)
			another = true
		}
	}
	prev := s.selected
	// Any refusal below leaves the agent holding whatever it held, so the
	// selection is cleared rather than kept: the next PKSIGN/PKDECRYPT must
	// not act on a key this connection did not just choose.
	s.selected = 0
	if another && prev != ScopeDecrypt {
		p.audit("refused: setkey --another without a key selected by setkey")
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
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
		// A sign-only profile pins the primary grip with ScopeSign alone, so
		// `SETKEY <primary>` lands here.
		p.audit("refused: " + strings.ToLower(verb) + " for a grip without the decrypt scope")
		writeLine(s.w, "ERR 67108881 No secret key")
		return
	}
	s.selected = need
	s.forward(line)
	if !another {
		what := "sign"
		if need == ScopeDecrypt {
			what = "decrypt"
		}
		s.tell("SETKEYDESC A+process+in+a+snug+sandbox+asks+to+" + what +
			"+with+your+OpenPGP+key%0Akeygrip+" + strings.ToUpper(g.grip))
	}
}

// forward relays one command to the session's upstream connection and copies
// the reply back verbatim, until OK or ERR. This is the arm for the commands
// that carry no grip of their own (RESET, SETHASH) and for the terminal PKSIGN.
//
// It is also the arm that reaches the agent with state from earlier commands on
// the same session: the SIGKEY a client sent two lines ago is on THIS
// connection, so PKSIGN finds it.
func (s *session) forward(line string) {
	s.exchange(line, false)
}

// handlePKDECRYPT forwards a decryption request.
//
// Measured against gpg-agent 2.4.4 and 2.5.24, PKDECRYPT is SERVER-DRIVEN: after the client
// sends `PKDECRYPT`, the agent sends
//
//	S INQUIRE_MAXLEN 4096
//	INQUIRE CIPHERTEXT
//
// and WAITS for the client to answer with a D line and an END line before it
// produces its own `D (5:value33:...)` and `OK`.
//
// The proxy does not parse or interpret the ciphertext: it relays an opaque
// blob and an opaque value. It therefore cannot say WHAT was decrypted — that
// residual is in the package comment, not a gap this function can close.
//
// The command line is forwarded WITH its option, because the option selects
// what the agent returns. Measured with `gpg --debug ipc`: gpg 2.5.24 sends
// `PKDECRYPT --kem=PGP` for a cv25519 subkey and expects the agent to finish
// the ECDH key derivation itself; gpg 2.4 sends a bare `PKDECRYPT` and does the
// derivation client-side. Dropping the option made every 2.5 decryption fail
// with `Wrong secret key used`. The proxy relays whichever form the client
// sends, so both versions keep the protocol they negotiated with the agent.
func (s *session) handlePKDECRYPT(line, args string) {
	if !pkdecryptOptionAllowed(args) {
		s.proxy.refuse(s.w, fmt.Sprintf("refused: PKDECRYPT option %q", truncate(args, 40)))
		return
	}
	s.exchange(line, true)
}

// exchange sends one command upstream and copies the reply to the sandbox
// until OK or ERR.
//
// An INQUIRE from the agent is a question the AGENT asks, and only one is
// relayed: `INQUIRE CIPHERTEXT` during PKDECRYPT, whose answer is the
// ciphertext the sandbox brought. Every other INQUIRE is answered here, never
// shown to the sandbox — PINENTRY_LAUNCHED with END (it names the host
// pinentry's pid and tty), anything else with CAN, which the agent turns into
// its own ERR.
func (s *session) exchange(line string, ciphertext bool) {
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
			s.abort("refused: agent reply exceeded the limit")
			return
		}
		if isInquire(reply) {
			if ciphertext && reply == "INQUIRE CIPHERTEXT" {
				if err := writeLine(s.w, reply); err != nil {
					return
				}
				if err := s.w.Flush(); err != nil {
					return
				}
				if err := relayInquireAnswer(s.r, upW); err != nil {
					s.abort("refused: inquire answer: " + err.Error())
					return
				}
				continue
			}
			answer := "CAN"
			if strings.HasPrefix(reply, "INQUIRE PINENTRY_LAUNCHED") {
				answer = "END"
			} else {
				p.audit(fmt.Sprintf("cancelled agent inquiry %q", truncate(reply, 60)))
			}
			if err := writeLine(upW, answer); err != nil {
				p.upstreamUnreachable(s.w, err)
				return
			}
			if err := upW.Flush(); err != nil {
				p.upstreamUnreachable(s.w, err)
				return
			}
			continue
		}
		if err := writeLine(s.w, reply); err != nil {
			return
		}
		if isTerminal(reply) {
			return
		}
	}
}

// tell sends a command of the PROXY's own upstream and discards the reply. It
// is for lines the sandbox did not write and must not see answered.
func (s *session) tell(line string) {
	upR, upW, err := s.upstream()
	if err != nil {
		return
	}
	if writeLine(upW, line) != nil || upW.Flush() != nil {
		return
	}
	for {
		reply, err := readLine(upR)
		if err != nil || isTerminal(reply) {
			return
		}
	}
}

// pkdecryptOptionAllowed is the option set PKDECRYPT may carry: the forms gpg
// sends, measured with `gpg --debug ipc` — bare (2.4), `--kem=PGP` (2.5, an
// ECDH subkey) and `--kem=PQC-PGP` (2.5, a composite Kyber subkey). Anything
// else is refused rather than forwarded. Measured against gpg-agent
// 2.5.24: it also accepts `--kem` and `--kem=CMS`, refuses `--kem=PQC` and
// `--kem=FOO` as "invalid KEM algorithm", and silently IGNORES an option it
// does not know (`PKDECRYPT --bogus` went on to INQUIRE CIPHERTEXT) — so a
// forwarded unknown option would reach a future agent that does know it,
// unreviewed.
func pkdecryptOptionAllowed(args string) bool {
	switch strings.TrimSpace(args) {
	case "", "--kem=PGP", "--kem=PQC-PGP":
		return true
	}
	return false
}

// isInquireEnd reports whether a client line ends an INQUIRE answer. Measured:
// gpg-agent 2.5.24 takes `CAN` as a cancel (`ERR 67109141 IPC call has been
// cancelled`), and gpg-connect-agent answers an INQUIRE it has no data for with
// `CANCEL`. A prefix test for "CANCEL" alone missed `CAN` and left the proxy
// waiting while the client waited for the agent.
func isInquireEnd(line string) bool {
	return line == "END" || line == "CAN" || line == "CANCEL"
}

// relayInquireAnswer reads the sandbox's reply to an INQUIRE — D lines, then
// END, or CAN to decline — and hands it to the agent verbatim, refusing any
// other line. The data is
// bounded by maxReply; the TIME is not, because the client is the one supplying
// the ciphertext, and a silent client holds only its own connection, which
// Close ends with the sandbox.
//
// The terminators are matched whole; see isInquireEnd.
func relayInquireAnswer(r *bufio.Reader, upW *bufio.Writer) error {
	total := 0
	for {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		total += len(line)
		if total > maxReply {
			return errors.New("exceeded the limit")
		}
		// Only data, END and CAN belong in an INQUIRE answer. Measured on
		// gpg-agent 2.5.24: any other line aborts the INQUIRE and every line
		// after it runs as an ordinary command — `PKDECRYPT`, `X`,
		// `KEYINFO --list`, `END` through this proxy returned the agent's
		// unpinned keygrips on the client's next command. So nothing else is
		// passed on, and the session ends.
		if !isInquireEnd(line) && !strings.HasPrefix(line, "D ") {
			_ = writeLine(upW, "CAN")
			_ = upW.Flush()
			return fmt.Errorf("line %q in an inquire answer", truncate(line, 20))
		}
		if err := writeLine(upW, line); err != nil {
			return err
		}
		if err := upW.Flush(); err != nil {
			return err
		}
		if isInquireEnd(line) {
			return nil
		}
	}
}

// abort ends a session that has lost step with the agent: the client gets a
// terminal ERR, the upstream connection is closed (sticky, so nothing reads the
// rest of its reply), and the sandbox connection is closed after this command.
func (s *session) abort(what string) {
	s.proxy.audit(what)
	writeLine(s.w, errForbidden)
	if s.up != nil {
		s.up.Close()
		s.up = nil
	}
	s.upErr = errors.New(what)
	s.ended = true
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
// and CR becomes %0D, as Assuan requires of every D line, and gpg's fast-path
// listing failed with `Invalid IPC response` through this proxy while it wrote
// a grip's 0x0A byte raw (the contributor's live test). A D line is
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
	return line == "OK" || strings.HasPrefix(line, "OK ") ||
		line == "ERR" || strings.HasPrefix(line, "ERR ")
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

// hexString renders bytes as lowercase hex, the form gpg prints and accepts.
func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// concatGrips joins raw keygrips into one byte string, the HAVEKEY --list
// payload before escaping.
func concatGrips(b [][20]byte) []byte {
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

func probeSetOptions(w *bufio.Writer, r *bufio.Reader, getenv func(string) string) {
	// The startup probe's pinentry, if the key is locked, belongs on snug's own
	// terminal or display: the sandbox does not exist yet. The options are
	// per-connection; nothing here changes the agent's startup environment.
	setOption := func(opt string) {
		_ = writeLine(w, "OPTION "+opt)
		_ = w.Flush()
		_, _ = readLine(r) // OK, or ERR for an option this agent lacks
	}
	if v := getenv("GPG_TTY"); v != "" {
		setOption("ttyname=" + v)
	}
	if v := getenv("TERM"); v != "" {
		setOption("ttytype=" + v)
	}
	if v := getenv("DISPLAY"); v != "" {
		setOption("display=" + v)
	}
	if v := getenv("XAUTHORITY"); v != "" {
		setOption("xauthority=" + v)
	}
	// Measured on gpg-agent 2.5.24, `OPTION DISPLAY=:9` is `Unknown option`;
	// the variables without an OPTION name of their own travel as putenv.
	for _, key := range []string{"WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"} {
		if v := getenv(key); v != "" {
			setOption("putenv=" + key + "=" + v)
		}
	}
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
func probeUpstream(upstream string, pins []grip, getenv func(string) string) error {
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
	// just like the gpg CLI does. Without it a new Assuan connection (from a
	// process other than gpg) can fail to start a GUI or tty pinentry with
	// "Inappropriate ioctl for device".
	probeSetOptions(w, r, getenv)
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
		if err := probeSign(conn, r, w, g); err != nil {
			return err
		}
	}
	return nil
}

// signProbePrefix domain-separates the probe digest so the signature snug gets
// back is not useful as a signature over anything else; snug also discards it.
// The bytes hashed are this 17-byte prefix
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
//
// It reads and writes through the probe's own r and w: a second bufio.Reader on
// the same conn would lose anything the first had already buffered.
func probeSign(conn net.Conn, r *bufio.Reader, w *bufio.Writer, g grip) error {
	nonce := make([]byte, signProbeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating the startup signature probe for %s: %w", g.field, err)
	}
	// SETHASH <algo> <hex> takes a DIGEST, and <algo> is the OpenPGP hash id:
	// 10 is SHA-512, so the digest must be 64 bytes. A 32-byte digest under id
	// 10 happened to sign with ed25519 and was refused by a brainpoolP384r1
	// key with `ERR 67109003 Invalid length` (measured, gpg-agent 2.5.24).
	// SHA-512 is long enough for every curve and RSA size gpg generates.
	sum := sha512.Sum512(append([]byte(signProbePrefix), nonce...))
	digest := sum[:]

	if err := conn.SetDeadline(time.Now().Add(signProbeTimeout)); err != nil {
		return probeSignNoAnswer(g, err)
	}
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
			"      Reproduce by hand:  echo snug | gpg --detach-sign -u <the key %s names>\n"+
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
		"      Reproduce by hand:  echo snug | gpg --detach-sign -u <the key %s names>\n"+
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
