package gpgproxy

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// This file holds the tests for what the proxy does between the sandbox and
// the agent that is NOT a plain forward: the INQUIRE relay, OPTION, SETKEYDESC,
// the reply bound and teardown. scope_test.go holds the verbs and the scopes.

// write sends one line without waiting for a reply.
func (c *client) write(line string) {
	c.t.Helper()
	if err := writeLine(c.w, line); err != nil {
		c.t.Fatal(err)
	}
	if err := c.w.Flush(); err != nil {
		c.t.Fatal(err)
	}
}

// drain reads until the connection ends and returns every line it saw. It fails
// the test if the connection is still open when the deadline passes, because
// "the session ended" is the property under test and a timeout is its absence.
func (c *client) drain() []string {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var out []string
	for {
		line, err := readLine(c.r)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.t.Fatalf("the proxy kept the connection open; saw %q", out)
			}
			return out
		}
		out = append(out, line)
	}
}

// startDecrypt selects the pinned decrypt grip, sends PKDECRYPT and reads up to
// and including `INQUIRE CIPHERTEXT`, so the caller holds a client the agent is
// waiting on. The INQUIRE arriving is the positive control for every test built
// on it: without it, "the bad line was not forwarded" would be equally true of
// a dialogue that never reached the inquiry.
func startDecrypt(t *testing.T, a *fakeAgent) (*Proxy, *client, *auditLog) {
	t.Helper()
	p, sock, log := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	if got := terminalOf(c.send("SETKEY " + gripSubkey)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SETKEY: %q", got)
	}
	c.write("PKDECRYPT")
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := readLine(c.r)
		if err != nil {
			t.Fatalf("waiting for the INQUIRE: %v", err)
		}
		if line == "INQUIRE CIPHERTEXT" {
			c.conn.SetReadDeadline(time.Time{})
			return p, c, log
		}
		if isTerminal(line) {
			t.Fatalf("PKDECRYPT ended without an INQUIRE: %q", line)
		}
	}
}

// directKeyInfo asks the fake agent itself, bypassing the proxy, which grips it
// lists. It is the positive control for every leak check below: the unpinned
// grip IS visible to anything that can reach the agent, so its absence from
// what the sandbox sees is the proxy's doing and not an empty agent's.
func directKeyInfo(t *testing.T, a *fakeAgent) string {
	t.Helper()
	conn, err := net.Dial("unix", a.path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := &client{t: t, conn: conn}
	cl.r = bufio.NewReaderSize(conn, 4096)
	cl.w = bufio.NewWriter(conn)
	if _, err := readLine(cl.r); err != nil {
		t.Fatal(err)
	}
	return strings.Join(cl.send("KEYINFO --list"), "\n")
}

// TestInquireInjectionEndsTheSession: after `INQUIRE CIPHERTEXT` the sandbox
// answers with command lines instead of data. Measured on gpg-agent 2.5.24, any
// line that is not D/END/CAN aborts the inquiry and every line after it runs
// as an ordinary command, so `PKDECRYPT`, `X`, `KEYINFO --list`, `END` came
// back with the agent's unpinned keygrips as the answer to the client's NEXT
// command. It would catch a proxy that forwards the inquiry answer verbatim.
//
// The positive control is directKeyInfo: the agent does list gripOther. What it
// does not cover is the real agent's parsing; the fake agent only records what
// it was sent.
func TestInquireInjectionEndsTheSession(t *testing.T) {
	attacks := map[string][]string{
		"the measured sequence": {"PKDECRYPT", "X", "KEYINFO --list", "GETINFO socket_name", "END", "RESET"},
		"data then a command":   {"D abc", "KEYINFO --list", "GETINFO socket_name", "END"},
		"option after inquire":  {"OPTION pinentry-mode=loopback", "KEYINFO --list", "END"},
	}
	for name, lines := range attacks {
		t.Run(name, func(t *testing.T) {
			a := newFakeAgent(t, gripSubkey, gripOther)
			if !strings.Contains(directKeyInfo(t, a), gripOther) {
				t.Fatal("control: the agent does not list the unpinned grip, so no leak could show")
			}
			_, c, log := startDecrypt(t, a)
			for _, l := range lines {
				// The proxy may close mid-way; a write error is the session ending.
				if writeLine(c.w, l) != nil {
					break
				}
			}
			c.w.Flush()
			seen := c.drain()
			joined := strings.Join(seen, "\n")
			if !strings.Contains(joined, errForbidden) {
				t.Errorf("the client was not told it was refused: %q", seen)
			}
			if strings.Contains(joined, gripOther) || strings.Contains(joined, a.path) ||
				strings.Contains(joined, "KEYINFO") {
				t.Errorf("the injected commands were answered by the agent: %q", seen)
			}
			// What the agent saw of the answer is a CAN from the proxy, never
			// the sandbox's command lines.
			for _, got := range a.waitDecryptInquire(t) {
				if got != "CAN" && got != "D abc" {
					t.Errorf("the agent received %q from an inquiry answer", got)
				}
			}
			if !log.contains("inquire answer") {
				t.Errorf("the abort was not audited: %v", log.lines())
			}
		})
	}
}

// TestInquireAnswerTerminatorsAreExact: END, CAN and CANCEL end the answer when
// they are the whole line. A prefix test lets `CANCELLED` or `END x` through to
// an agent that may read them as something else, and a missing CAN left the
// proxy waiting while the client waited for the agent.
func TestInquireAnswerTerminatorsAreExact(t *testing.T) {
	for _, bad := range []string{"ENDX", "END ", "CANCELLED", "CAN x", "end", "cancel", "",
		"D", "d abc", "# comment", "KEYINFO --list"} {
		t.Run("bad "+bad, func(t *testing.T) {
			a := newFakeAgent(t, gripSubkey, gripOther)
			_, c, _ := startDecrypt(t, a)
			c.write(bad)
			seen := c.drain()
			if !strings.Contains(strings.Join(seen, "\n"), errForbidden) {
				t.Errorf("%q in an inquire answer was not refused: %q", bad, seen)
			}
			got := a.waitDecryptInquire(t)
			if len(got) != 1 || got[0] != "CAN" {
				t.Errorf("the agent saw %q for %q, want exactly the proxy's [CAN]", got, bad)
			}
		})
	}
	for _, good := range []string{"CAN", "CANCEL"} {
		t.Run("good "+good, func(t *testing.T) {
			a := newFakeAgent(t, gripSubkey)
			_, c, _ := startDecrypt(t, a)
			c.write(good)
			conn := c.conn
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var term string
			for {
				line, err := readLine(c.r)
				if err != nil {
					t.Fatalf("after %s: %v", good, err)
				}
				if isTerminal(line) {
					term = line
					break
				}
			}
			if !strings.HasPrefix(term, "ERR") {
				t.Errorf("a cancelled PKDECRYPT answered %q, want the agent's ERR", term)
			}
			if got := a.sawDecryptInquire(); len(got) != 1 || got[0] != good {
				t.Errorf("the agent saw %q, want [%s] verbatim", got, good)
			}
			// A cancel is the client's decision, not an attack: the session lives.
			conn.SetReadDeadline(time.Time{})
			if got := terminalOf(c.send("RESET")); !strings.HasPrefix(got, "OK") {
				t.Errorf("RESET after %s answered %q, want OK", good, got)
			}
		})
	}
}

// TestOptionIsAnsweredLocallyAndNeverForwarded: OPTION sets the environment
// the host agent hands its pinentry. Measured through the proxy before it
// answered locally, `ttyname=<host path>` made pinentry-curses open that path
// on the HOST and overwrite it, and `pinentry-mode=loopback` turned the
// passphrase prompt into an INQUIRE the sandbox answers. It would catch any
// OPTION reaching the agent, including one sent after the upstream is open.
func TestOptionIsAnsweredLocallyAndNeverForwarded(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	allowed := []string{"ttyname=/dev/pts/9", "ttytype=xterm", "display=:0", "xauthority=/x",
		"putenv=FOO=bar", "lc-ctype=C", "lc-messages=C", "allow-pinentry-notify",
		"agent-awareness=2.1.0", "TTYNAME=/dev/pts/9", "ttyname /dev/pts/9"}
	refused := []string{"pinentry-mode=loopback", "pinentry-mode loopback", "debug=1",
		"no-grab", "ttyname2=x", "putenv-x=1", "", "pinentry-program=/bin/sh"}

	for _, opened := range []bool{false, true} {
		c := dial(t, sock)
		if opened {
			// RESET opens the upstream connection, so an OPTION after it could
			// be written onto a live agent session.
			c.send("RESET")
		}
		before := a.sawOptions()
		if len(before) == 0 {
			t.Fatal("control: the startup probe sent no OPTION, so a recorder that works would look the same")
		}
		for _, o := range allowed {
			if got := terminalOf(c.send("OPTION " + o)); !strings.HasPrefix(got, "OK") {
				t.Errorf("OPTION %s answered %q, want OK", o, got)
			}
		}
		for _, o := range refused {
			cmd := strings.TrimSpace("OPTION " + o)
			if got := terminalOf(c.send(cmd)); got != errForbidden {
				t.Errorf("%s answered %q, want %q", cmd, got, errForbidden)
			}
		}
		if after := a.sawOptions(); len(after) != len(before) {
			t.Errorf("upstream open=%v: OPTION reached the agent: %q", opened, after[len(before):])
		}
	}
	if !log.contains("OPTION") {
		t.Errorf("an OPTION refusal was not audited: %v", log.lines())
	}
}

// TestSetKeyDescIsTheProxysOwn: the pinentry prompt text is the proxy's. A
// sandbox-authored SETKEYDESC ("system update needs your password") reached the
// host pinentry verbatim before, which is a phishing line aimed at the human
// holding the passphrase. It would catch the client's text reaching the agent,
// and the proxy's own text going missing.
func TestSetKeyDescIsTheProxysOwn(t *testing.T) {
	cases := []struct {
		name, verb, grip, word string
		pins                   []PinnedGrip
		holds                  string
	}{
		{"sign", "SIGKEY", gripPrimary, "sign", pinnedSignOnly(), gripPrimary},
		{"decrypt", "SETKEY", gripSubkey, "decrypt", pinnedDecryptOnly(), gripSubkey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeAgent(t, tc.holds)
			_, sock, _ := newTestProxy(t, a, tc.pins)
			c := dial(t, sock)
			before := len(a.sawSetKeyDesc())

			// Before any selection the client's text is answered and dropped.
			if got := terminalOf(c.send("SETKEYDESC evil+first")); !strings.HasPrefix(got, "OK") {
				t.Fatalf("SETKEYDESC answered %q, want OK", got)
			}
			if got := terminalOf(c.send(tc.verb + " " + tc.grip)); !strings.HasPrefix(got, "OK") {
				t.Fatalf("%s: %q", tc.verb, got)
			}
			if got := terminalOf(c.send("SETKEYDESC system+update+needs+your+password")); !strings.HasPrefix(got, "OK") {
				t.Fatalf("SETKEYDESC answered %q, want OK", got)
			}
			// The proxy's own SETKEYDESC reply was consumed upstream. If it
			// leaked, this reply would be a stale OK instead of the version.
			if reply := c.send("GETINFO version"); !strings.Contains(strings.Join(reply, "\n"), "D 2.4.8") {
				t.Fatalf("the reply stream is out of step after SETKEYDESC: %q", reply)
			}

			descs := a.sawSetKeyDesc()[before:]
			if len(descs) != 1 {
				t.Fatalf("the agent saw %d SETKEYDESC lines, want exactly the proxy's one: %q", len(descs), descs)
			}
			if strings.Contains(strings.Join(descs, "\n"), "evil") ||
				strings.Contains(strings.Join(descs, "\n"), "password") {
				t.Errorf("the sandbox's SETKEYDESC text reached the agent: %q", descs)
			}
			want := "SETKEYDESC A+process+in+a+snug+sandbox+asks+to+" + tc.word
			if !strings.HasPrefix(descs[0], want) || !strings.Contains(descs[0], strings.ToUpper(tc.grip)) {
				t.Errorf("the proxy's SETKEYDESC = %q, want prefix %q naming the grip", descs[0], want)
			}
		})
	}

	t.Run("a refused selection sends none", func(t *testing.T) {
		a := newFakeAgent(t, gripPrimary, gripOther)
		_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
		c := dial(t, sock)
		before := len(a.sawSetKeyDesc())
		c.send("SIGKEY " + gripOther)
		c.send("SETKEYDESC x")
		if got := a.sawSetKeyDesc(); len(got) != before {
			t.Errorf("SETKEYDESC reached the agent after a refused SIGKEY: %q", got[before:])
		}
	})
	t.Run("--another adds no second prompt", func(t *testing.T) {
		a := newFakeAgent(t, gripSubkey)
		_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
		c := dial(t, sock)
		before := len(a.sawSetKeyDesc())
		c.send("SETKEY " + gripSubkey)
		c.send("SETKEY --another " + gripSubkey)
		if got := a.sawSetKeyDesc()[before:]; len(got) != 1 {
			t.Errorf("composite key sent %d SETKEYDESC lines, want one: %q", len(got), got)
		}
	})
}

// TestAgentInquiriesAreAnsweredUpstream: the agent asks the client questions
// while it works. Only the ciphertext during PKDECRYPT belongs to the sandbox.
// PINENTRY_LAUNCHED names the host pinentry's pid and tty, so it is answered
// END here and never shown; anything else (a PASSPHRASE prompt, a CIPHERTEXT
// outside a decryption) is cancelled. It would catch an INQUIRE reaching the
// sandbox, or an unanswered one stalling the agent.
func TestAgentInquiriesAreAnsweredUpstream(t *testing.T) {
	cases := []struct {
		keyword string
		answer  string
		signs   bool
	}{
		{"PINENTRY_LAUNCHED 4242 curses 1.3.1 /dev/pts/9 - - 1000", "END", true},
		{"PASSPHRASE", "CAN", false},
		{"CIPHERTEXT", "CAN", false}, // the decrypt inquiry, asked outside PKDECRYPT
	}
	for _, tc := range cases {
		t.Run(tc.keyword, func(t *testing.T) {
			a := newFakeAgent(t, gripPrimary)
			_, sock, log := newTestProxy(t, a, pinnedSignOnly())
			a.setPreInquire(tc.keyword) // after the startup probe has signed
			c := dial(t, sock)
			c.send("SIGKEY " + gripPrimary)
			c.send("SETHASH 10 " + strings.Repeat("ab", 64))
			reply := c.send("PKSIGN")
			joined := strings.Join(reply, "\n")

			if strings.Contains(joined, "INQUIRE") || strings.Contains(joined, "4242") ||
				strings.Contains(joined, "/dev/pts") {
				t.Errorf("the agent's inquiry reached the sandbox: %q", reply)
			}
			if got := a.sawInquireAnswers(); len(got) != 1 || got[0] != tc.answer {
				t.Errorf("the agent was answered %q, want [%s]", got, tc.answer)
			}
			if tc.signs {
				if !strings.Contains(joined, "sig-val") || !strings.HasPrefix(terminalOf(reply), "OK") {
					t.Errorf("a pinentry notification should not stop the signature: %q", reply)
				}
			} else {
				if strings.Contains(joined, "sig-val") || !strings.HasPrefix(terminalOf(reply), "ERR") {
					t.Errorf("a cancelled inquiry should end in the agent's ERR: %q", reply)
				}
				if !log.contains("cancelled agent inquiry") {
					t.Errorf("the cancel was not audited: %v", log.lines())
				}
			}
			// Either way the session is in step and usable.
			if got := terminalOf(c.send("RESET")); !strings.HasPrefix(got, "OK") {
				t.Errorf("RESET afterwards answered %q", got)
			}
		})
	}
}

// TestReplyOverflowEndsTheSession: an agent reply past maxReply cannot be
// relayed in step, so the proxy answers Forbidden, closes the upstream and
// ends the connection rather than leave the rest of the reply to be read as
// the answer to the next command. It would catch a bound that merely stops
// copying and keeps serving. The overflow is simulated by the fake agent; the
// real agent's replies are never that large.
func TestReplyOverflowEndsTheSession(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	a.setBigReply()
	c := dial(t, sock)
	c.send("SIGKEY " + gripPrimary)
	c.send("SETHASH 10 " + strings.Repeat("ab", 64))
	c.write("PKSIGN")
	seen := c.drain()
	if len(seen) == 0 || seen[len(seen)-1] != errForbidden {
		last := ""
		if len(seen) > 0 {
			last = truncate(seen[len(seen)-1], 60)
		}
		t.Fatalf("the overflow did not end in %q; %d lines, last %q", errForbidden, len(seen), last)
	}
	total := 0
	for _, l := range seen {
		total += len(l)
	}
	if total > maxReply+maxLine {
		t.Errorf("%d bytes reached the sandbox, over the %d bound", total, maxReply)
	}
	if !log.contains("exceeded the limit") {
		t.Errorf("the overflow was not audited: %v", log.lines())
	}
}

// TestCloseReturnsWithASilentClient: a sandbox connection that never sends a
// byte sits in a blocking read, and Close waits for its handler. Before Close
// ended the live connections, teardown hung for as long as the payload kept the
// socket open. The silent-mid-inquiry case is the same wait on a different
// read.
func TestCloseReturnsWithASilentClient(t *testing.T) {
	check := func(t *testing.T, p *Proxy, c *client) {
		done := make(chan struct{})
		go func() { p.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not return while a client was connected and silent")
		}
		// Positive control: the connection was live, and Close is what ended it.
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := readLine(c.r); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("the client connection survived Close (err=%v)", err)
		}
	}
	t.Run("idle", func(t *testing.T) {
		a := newFakeAgent(t, gripPrimary)
		p, sock, _ := newTestProxy(t, a, pinnedSignOnly())
		check(t, p, dial(t, sock))
	})
	t.Run("mid inquiry", func(t *testing.T) {
		a := newFakeAgent(t, gripSubkey)
		p, c, _ := startDecrypt(t, a)
		check(t, p, c)
	})
}

// TestSilentUpstreamIsBounded: an agent that accepts and never greets must not
// hold a sandbox command forever. The greeting is read under probeTimeout. It
// takes that long to run, so -short skips it.
func TestSilentUpstreamIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out probeTimeout")
	}
	a := newFakeAgent(t, gripPrimary)
	p, sock, _ := newTestProxy(t, a, pinnedSignOnly())

	path := shortDir(t) + "/mute.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			t.Cleanup(func() { c.Close() })
		}
	}()
	p.upstream = path

	c := dial(t, sock)
	start := time.Now()
	reply := c.send("RESET")
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("a mute upstream answered %q, want ERR", reply)
	}
	if took := time.Since(start); took > probeTimeout+3*time.Second {
		t.Errorf("answered after %s, over probeTimeout %s", took, probeTimeout)
	}
	select {
	case <-accepted:
	default:
		t.Error("control: the mute listener was never dialled, so the bound was not exercised")
	}
}

// TestSetKeyAnotherNeedsAPriorSetKey: `--another` adds a grip to the key a
// plain SETKEY chose, so as the first selection on a connection (or after a
// refused one) there is nothing to add to. It would catch the option being
// read as a way to select a key without the plain verb's checks.
func TestSetKeyAnotherNeedsAPriorSetKey(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	c.send("RESET")
	if got := terminalOf(c.send("SETKEY --another " + gripSubkey)); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("SETKEY --another as the first selection answered %q, want ERR", got)
	}
	if got := a.sawDecrypt(); len(got) != 0 {
		t.Errorf("decrypted: %v", got)
	}
}

// TestIsTerminalIsExact: a terminal line is OK or ERR as a whole word. A prefix
// test took `OKAY` and `ERROR` for the end of a reply and left the proxy out of
// step with the agent.
func TestIsTerminalIsExact(t *testing.T) {
	for line, want := range map[string]bool{
		"OK": true, "OK Pleased": true, "ERR": true, "ERR 67109115 Forbidden <snug>": true,
		"OKAY": false, "OKx": false, "ERROR": false, "ERRx": false, "": false,
		"D OK": false, "S OK": false, "ok": false, "INQUIRE CIPHERTEXT": false,
	} {
		if got := isTerminal(line); got != want {
			t.Errorf("isTerminal(%q) = %v, want %v", line, got, want)
		}
	}
}

// TestHaveKeyMultiGripIsOKWhenAnyIsPinned: gpg asks `HAVEKEY <primary>
// <subkey>` as its fast-path listing and the agent answers OK when any named
// grip is held. All-must-be-pinned made a profile pinning only the subkeys
// fail that probe. The agent holds the unpinned grip here, so a proxy that
// forwarded the question would answer OK for the unpinned-only line too.
func TestHaveKeyMultiGripIsOKWhenAnyIsPinned(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripOther)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	if got := terminalOf(c.send("HAVEKEY " + gripPrimary + " " + gripOther)); !strings.HasPrefix(got, "OK") {
		t.Errorf("HAVEKEY <pinned> <unpinned> answered %q, want OK", got)
	}
	if got := terminalOf(c.send("HAVEKEY " + gripOther + " " + gripPrimary)); !strings.HasPrefix(got, "OK") {
		t.Errorf("HAVEKEY <unpinned> <pinned> answered %q, want OK", got)
	}
	if got := terminalOf(c.send("HAVEKEY " + gripOther)); !strings.HasPrefix(got, "ERR") {
		t.Errorf("HAVEKEY <unpinned> answered %q, want ERR", got)
	}
	if got := terminalOf(c.send("HAVEKEY " + gripOther + " " + "0000000000000000000000000000000000000002")); !strings.HasPrefix(got, "ERR") {
		t.Errorf("HAVEKEY <unpinned> <unknown> answered %q, want ERR", got)
	}
	if a.contactCount() != before {
		t.Error("a HAVEKEY was forwarded to the agent")
	}
}
