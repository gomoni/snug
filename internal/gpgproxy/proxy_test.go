package gpgproxy

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Grip fixtures. Deterministic and DISTINCT so two grips in one test are never
// accidentally equal, and a failing assertion's diff is reproducible.
const (
	gripPrimary = "2761D2BF75F0095F0FEA0A9216F4114A3B0C20BA"
	gripSubkey  = "80C95D6427C02FBB78C91DCEE6E12BD520EF66F0"
	gripOther   = "0000000000000000000000000000000000000001"
)

// fakeAgent stands in for the host's gpg-agent and records whether it was
// contacted at all. "The proxy refused" and "the proxy asked upstream and
// relayed a refusal" look identical to the client — only this distinguishes
// them, and the difference is the whole point of answering locally.
//
// holds is deliberately allowed to be WIDER than what the proxy pins: that is
// what makes the leak assertions in this file real assertions rather than ones
// that would pass against an agent with nothing to leak.
type fakeAgent struct {
	path     string
	ln       net.Listener
	contacts atomic.Int32

	mu sync.Mutex
	// holds is the set of grips this fake agent has. Every command that
	// names a grip is checked against it, exactly as the real agent does.
	holds map[string]bool
	// signCalls and dekryptCalls record what actually crossed the wire.
	signCalls    []string
	decryptCalls []string
	// b64Marker is returned as the sig-val/value payload so a test can look
	// for it turning up somewhere it must not.
	sigMarker []byte
	// exported records every EXPORT_KEY the fake agent saw. A non-nil entry
	// is a test failure anywhere it appears: the proxy must never forward it.
	exported []string
	// scd records every SCD verb the fake agent saw. `SCD SERIALNO` is expected
	// on the normal path; other SCD verbs are not.
	scd []string
	// inquire records every line the fake agent read while waiting for an
	// INQUIRE answer — the client's D payload and its END.
	inquire []string
	// refuseSign marks a grip as held (HAVEKEY answers OK) but unsignable
	// (SIGKEY or PKSIGN answers ERR), standing in for a key the agent lists
	// and will not use — a smartcard-backed key with no card, a locked agent,
	// a passphrase prompt declined.
	refuseSign map[string]bool
}

// setRefuseSign marks grip as listed-but-unsignable.
func (a *fakeAgent) setRefuseSign(g string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuseSign == nil {
		a.refuseSign = map[string]bool{}
	}
	a.refuseSign[strings.ToUpper(g)] = true
}

func (a *fakeAgent) refusesSign(g string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refuseSign[strings.ToUpper(g)]
}

func newFakeAgent(t *testing.T, holds ...string) *fakeAgent {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{path: path, ln: ln, holds: map[string]bool{}}
	for _, g := range holds {
		a.holds[strings.ToUpper(g)] = true
	}
	a.sigMarker = []byte("sig-marker")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.contacts.Add(1)
			go a.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return a
}

// serve implements enough of the Assuan dialogue to exercise the proxy: the
// greeting, HAVEKEY, KEYINFO, SIGKEY, SETKEY, SETKEYDESC, SETHASH, PKSIGN,
// PKDECRYPT (with the server-driven INQUIRE) and RESET. Everything a real
// client sends that the proxy must never forward is recognized only so the fake
// can record it.
func (a *fakeAgent) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReaderSize(c, 4096)
	w := bufio.NewWriter(c)
	line := func(s string) { writeLine(w, s); w.Flush() }
	line("OK Pleased to meet you, process 0")
	// selected tracks the grip a SIGKEY/SETKEY set on THIS connection, which is
	// the whole reason the proxy must keep one upstream connection open.
	selected := ""
	for {
		req, err := readLine(r)
		if err != nil {
			return
		}
		name, args := splitCommand(req)
		switch strings.ToUpper(name) {
		case "RESET":
			selected = ""
			line("OK")
		case "OPTION":
			line("OK")
		case "GETINFO":
			if strings.TrimSpace(args) == "version" {
				line("D 2.4.8")
			}
			line("OK")
		case "HAVEKEY":
			a.handleHaveKey(line, args)
		case "KEYINFO":
			a.handleKeyInfo(line, args)
		case "SIGKEY", "SETKEY":
			g := strings.ToUpper(strings.TrimSpace(args))
			if !a.holdsGrip(g) {
				line("ERR 67108881 No secret key")
				continue
			}
			selected = g
			line("OK")
		case "SETKEYDESC":
			line("OK")
		case "SETHASH":
			line("OK")
		case "PKSIGN":
			if selected == "" {
				line("ERR 67108881 No secret key")
				continue
			}
			if a.refusesSign(selected) {
				line("ERR 67108881 No secret key")
				continue
			}
			a.recordSign(selected)
			line("D (7:sig-val(5:eddsa(1:r32:" + string(a.sigMarker) + ")(1:s32:x)))")
			line("OK")
		case "PKDECRYPT":
			if selected == "" {
				line("ERR 67108881 No secret key")
				continue
			}
			a.recordDecrypt(selected)
			// THE SERVER-DRIVEN INQUIRE, exactly as measured: the agent asks
			// the client for the ciphertext and waits.
			line("S INQUIRE_MAXLEN 4096")
			line("INQUIRE CIPHERTEXT")
			w.Flush()
			// Read the client's D ... / END.
			sawD, sawEnd := false, false
			for {
				reply, err := readLine(r)
				if err != nil {
					return
				}
				a.recordInquire(reply)
				if strings.HasPrefix(reply, "D ") {
					sawD = true
				}
				if strings.HasPrefix(reply, "END") {
					sawEnd = true
					break
				}
				if strings.HasPrefix(reply, "CANCEL") {
					break
				}
			}
			if !sawD || !sawEnd {
				line("ERR 67108881 No secret key")
				continue
			}
			line("D (5:value33:" + string(a.sigMarker) + ")")
			line("OK")
		case "SCD":
			// A real agent without a smartcard answers `SCD SERIALNO` with
			// `ERR 67108983 No SmartCard daemon`, and that answer is part of
			// gpg's normal path. Record it separately from the mutation verbs
			// so a test can tell the two apart.
			a.recordScd(req)
			line("ERR 67108983 No SmartCard daemon")
		case "EXPORT_KEY", "KEYWRAP_KEY", "IMPORTKEYS", "DELETEKEY", "PASSPHRASE",
			"SETEVENTS", "SETINFO":
			// Recorded so a test can prove these never arrived.
			a.recordExport(req)
			line("ERR 67108881 No secret key")
		case "BYE":
			line("OK closing connection")
			return
		default:
			line("ERR 0 unknown")
		}
	}
}

func (a *fakeAgent) handleHaveKey(line func(string), args string) {
	if rest, ok := strings.CutPrefix(args, "--list="); ok {
		var out []byte
		for g := range a.holds {
			out = append(out, []byte(g)...)
		}
		_ = rest
		if len(out) > 0 {
			// The count prefix the real agent uses: one decimal length then
			// raw bytes. A client that does not parse the count still gets the
			// grips.
			line(fmt.Sprintf("D %d%s", len(out), out))
		}
		line("OK")
		return
	}
	for _, g := range strings.Fields(args) {
		if !a.holdsGrip(strings.ToUpper(g)) {
			line("ERR 67108881 No secret key")
			return
		}
	}
	line("OK")
}

func (a *fakeAgent) handleKeyInfo(line func(string), args string) {
	if strings.TrimSpace(args) == "--list" {
		for g := range a.holds {
			line("S KEYINFO " + g + " D - - - C - - -")
		}
		line("OK")
		return
	}
	for _, g := range strings.Fields(args) {
		if !a.holdsGrip(strings.ToUpper(g)) {
			line("ERR 67108891 Not found")
			return
		}
		line("S KEYINFO " + strings.ToUpper(g) + " D - - - C - - -")
	}
	line("OK")
}

func (a *fakeAgent) holdsGrip(g string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.holds[g]
}

func (a *fakeAgent) recordSign(g string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signCalls = append(a.signCalls, g)
}

func (a *fakeAgent) recordDecrypt(g string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decryptCalls = append(a.decryptCalls, g)
}

func (a *fakeAgent) recordExport(req string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.exported = append(a.exported, req)
}

func (a *fakeAgent) recordScd(req string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scd = append(a.scd, req)
}

func (a *fakeAgent) recordInquire(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inquire = append(a.inquire, line)
}

func (a *fakeAgent) sawDecryptInquire() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.inquire...)
}

func (a *fakeAgent) sawScd() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.scd...)
}

func (a *fakeAgent) sawSign() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.signCalls...)
}

func (a *fakeAgent) sawDecrypt() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.decryptCalls...)
}

func (a *fakeAgent) sawExport() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.exported...)
}

func (a *fakeAgent) contactCount() int32 { return a.contacts.Load() }

// ── the test client ─────────────────────────────────────────────────────────

// client is a scripted Assuan client against the proxy. send writes one command
// and reads the reply up to OK/ERR; the reply is returned line by line.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func dial(t *testing.T, socketPath string) *client {
	t.Helper()
	c, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	cl := &client{t: t, conn: c, r: bufio.NewReaderSize(c, 4096), w: bufio.NewWriter(c)}
	// Greeting.
	line, err := readLine(cl.r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "OK") {
		t.Fatalf("greeting was %q, want OK", line)
	}
	return cl
}

// send writes one command and returns every reply line through the terminal
// OK/ERR, the terminal line included.
func (c *client) send(cmd string) []string {
	c.t.Helper()
	if err := writeLine(c.w, cmd); err != nil {
		c.t.Fatal(err)
	}
	if err := c.w.Flush(); err != nil {
		c.t.Fatal(err)
	}
	var out []string
	for {
		line, err := readLine(c.r)
		if err != nil {
			c.t.Fatalf("reading reply to %q: %v", cmd, err)
		}
		out = append(out, line)
		if isTerminal(line) {
			return out
		}
	}
}

// answerInquire reads an INQUIRE from the proxy and answers it with one D and
// an END, standing in for a real gpg client mid-PKDECRYPT.
func (c *client) answerInquire(data string) []string {
	c.t.Helper()
	var out []string
	sawInquire := false
	for {
		line, err := readLine(c.r)
		if err != nil {
			c.t.Fatalf("reading inquire: %v", err)
		}
		out = append(out, line)
		if isInquire(line) {
			sawInquire = true
			if err := writeLine(c.w, "D "+data); err != nil {
				c.t.Fatal(err)
			}
			if err := writeLine(c.w, "END"); err != nil {
				c.t.Fatal(err)
			}
			if err := c.w.Flush(); err != nil {
				c.t.Fatal(err)
			}
			continue
		}
		if isTerminal(line) {
			if !sawInquire {
				c.t.Fatalf("PKDECRYPT finished without an INQUIRE; got %v", out)
			}
			return out
		}
	}
}

func terminalOf(reply []string) string {
	if len(reply) == 0 {
		return ""
	}
	return reply[len(reply)-1]
}

// auditLog collects the proxy's audit strings for inspection.
type auditLog struct {
	mu     sync.Mutex
	audits []string
}

func (l *auditLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.audits = append(l.audits, s)
}

// contains reports whether any audit line contains sub.
func (l *auditLog) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.audits {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

func (l *auditLog) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.audits...)
}

// newTestProxy builds a proxy against a fake agent. grips are given as
// PinnedGrip values so a test can set a scope per grip.
func newTestProxy(t *testing.T, a *fakeAgent, grips []PinnedGrip) (*Proxy, string, *auditLog) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "S.gpg-agent")
	log := &auditLog{}
	p, err := New(grips, a.path, socketPath, log.add)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	go p.Serve()
	waitForSocket(t, socketPath)
	return p, socketPath, log
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("proxy socket %s never became dialable", path)
}
