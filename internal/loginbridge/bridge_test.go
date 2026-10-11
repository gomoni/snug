package loginbridge

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, t := range c.timers {
		if !t.stopped && !t.at.After(c.now) {
			t.stopped = true
			due = append(due, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

// fakeSandbox is the far end of a relay socket: it records each request it
// receives and answers with answer, after release is closed if set.
type fakeSandbox struct {
	mu       sync.Mutex
	left     int
	dials    int
	got      [][]byte
	answer   string
	release  chan struct{}
	received chan struct{}
}

func (s *fakeSandbox) Left() int { s.mu.Lock(); defer s.mu.Unlock(); return s.left }

func (s *fakeSandbox) Dial(port int) (net.Conn, error) {
	s.mu.Lock()
	if s.left == 0 {
		s.mu.Unlock()
		return nil, errors.New("no relay socket is left")
	}
	s.left--
	s.dials++
	s.mu.Unlock()
	ours, theirs := net.Pipe()
	go func() {
		defer theirs.Close()
		var req []byte
		buf := make([]byte, 512)
		for !bytes.Contains(req, []byte("\r\n\r\n")) {
			n, err := theirs.Read(buf)
			req = append(req, buf[:n]...)
			if err != nil {
				break
			}
		}
		s.mu.Lock()
		s.got = append(s.got, req)
		rel, rec := s.release, s.received
		s.mu.Unlock()
		if rec != nil {
			rec <- struct{}{}
		}
		if rel != nil {
			<-rel
		}
		io.WriteString(theirs, s.answer)
	}()
	return ours, nil
}

func (s *fakeSandbox) requests() [][]byte { s.mu.Lock(); defer s.mu.Unlock(); return s.got }

type fakeOpener struct {
	mu   sync.Mutex
	urls []string
	err  error
}

func (o *fakeOpener) Open(url string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.urls = append(o.urls, url)
	return o.err
}

func (o *fakeOpener) opened() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.urls...)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rig struct {
	b       *Bridge
	clock   *fakeClock
	sandbox *fakeSandbox
	opener  *fakeOpener
	stderr  *syncBuf
	peerUID int
	peerOK  bool
	mu      sync.Mutex
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		clock:   &fakeClock{now: time.Unix(1_000_000, 0)},
		sandbox: &fakeSandbox{left: MaxRelaysPerRun, answer: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		opener:  &fakeOpener{},
		stderr:  &syncBuf{},
		peerUID: os.Getuid(),
		peerOK:  true,
	}
	r.b = New(Deps{
		Clock:     r.clock,
		Relayer:   r.sandbox,
		Listening: func(int) (bool, error) { return true, nil },
		PeerUID: func(netip.AddrPort, netip.AddrPort) (int, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.peerUID, r.peerOK
		},
		UID:    os.Getuid(),
		Open:   r.opener.Open,
		Stderr: r.stderr,
	})
	t.Cleanup(r.b.Close)
	return r
}

// freePort returns a port nothing on 127.0.0.1 or ::1 holds right now.
func freePort(t *testing.T) int {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if l6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(p))); err == nil {
			l6.Close()
			return p
		} else if !errors.Is(err, syscall.EADDRINUSE) {
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

const testChallenge = "fD5xTDCwgf63U088pqhV0TFHbLf0emkJPI844Pfplvs"

func testFlow(t *testing.T) Flow {
	return Flow{Port: freePort(t), CodeChallenge: testChallenge, State: testState}
}

// browse sends req to 127.0.0.1:port and returns the whole answer.
func browse(t *testing.T, port int, req string) string {
	t.Helper()
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("browser could not connect: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, req)
	b, _ := io.ReadAll(c)
	return string(b)
}

// openFlow opens a flow on a free port through the rig's bridge, failing the
// test if Handle refuses it.
func (r *rig) openFlow(t *testing.T) Flow {
	t.Helper()
	f := testFlow(t)
	if err := r.b.Handle(f); err != nil {
		t.Fatal(err)
	}
	return f
}

// sendCallback is the browser's valid callback for f, and the whole answer.
func sendCallback(t *testing.T, f Flow) string {
	t.Helper()
	return browse(t, f.Port, callbackReq(f.Port, testState, ""))
}

func callbackReq(port int, state string, extra string) string {
	return "GET /callback?code=AbC-12.3_x~&state=" + state + " HTTP/1.1\r\n" +
		"Host: localhost:" + strconv.Itoa(port) + "\r\n" + extra + "\r\n"
}

func refuses(port int) bool {
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		c.Close()
		return false
	}
	return true
}

func TestTheRelayedRequestCarriesNoBrowserHeader(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	browse(t, f.Port, callbackReq(f.Port, testState,
		"Cookie: session=hostsecret\r\nReferer: https://claude.com/x\r\nAuthorization: Bearer hostsecret\r\n"+
			"User-Agent: Mozilla/5.0\r\nX-Forwarded-For: 10.0.0.1\r\n"))
	got := r.sandbox.requests()
	want := "GET /callback?code=AbC-12.3_x~&state=" + testState + " HTTP/1.1\r\n" +
		"Host: localhost:" + strconv.Itoa(f.Port) + "\r\n" +
		"Connection: close\r\n\r\n"
	if len(got) != 1 || string(got[0]) != want {
		t.Fatalf("relayed:\n%q\nwant:\n%q", got, want)
	}
	if !refuses(f.Port) {
		t.Fatal("the host listener is still open after the relay")
	}
}

func TestTheBrowserGetsSnugsPageNotTheSandboxs(t *testing.T) {
	r := newRig(t)
	r.sandbox.answer = "HTTP/1.1 302 Found\r\nSet-Cookie: pwn=1; Domain=localhost\r\n" +
		"Location: https://evil.example/\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"
	f := r.openFlow(t)
	resp := sendCallback(t, f)
	head, body, _ := strings.Cut(resp, "\r\n\r\n")
	for _, bad := range []string{"Set-Cookie", "Location", "evil.example", "<script", "pwn"} {
		if strings.Contains(resp, bad) {
			t.Errorf("browser saw %q:\n%s", bad, resp)
		}
	}
	for _, h := range []string{
		"HTTP/1.1 200 OK\r\n",
		"Content-Type: text/html; charset=utf-8\r\n",
		"Content-Security-Policy: default-src 'none'; form-action 'none'; frame-ancestors 'none'\r\n",
		"Cache-Control: no-store\r\n",
		"Referrer-Policy: no-referrer\r\n",
		"X-Content-Type-Options: nosniff\r\n",
		"Connection: close\r\n",
	} {
		if !strings.Contains(head+"\r\n", h) {
			t.Errorf("missing %q in:\n%s", h, head)
		}
	}
	if !strings.Contains(body, "snug delivered the login callback to the sandbox; it answered HTTP 302.") {
		t.Errorf("body: %s", body)
	}
}

func TestAnotherUIDIsRefused(t *testing.T) {
	r := newRig(t)
	r.peerUID = os.Getuid() + 1
	f := r.openFlow(t)
	resp := sendCallback(t, f)
	if !strings.HasPrefix(resp, "HTTP/1.1 403 ") || !strings.Contains(resp, "another user") {
		t.Fatalf("resp: %s", resp)
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("another uid's callback was relayed %d times", n)
	}
	if refuses(f.Port) {
		t.Fatal("another uid's connection ended the flow")
	}
	if !strings.Contains(r.stderr.String(), "only your uid") {
		t.Fatalf("stderr: %s", r.stderr.String())
	}
}

func TestAnUnresolvablePeerIsRefused(t *testing.T) {
	r := newRig(t)
	r.peerOK = false
	r.peerUID = os.Getuid()
	f := r.openFlow(t)
	resp := sendCallback(t, f)
	if !strings.HasPrefix(resp, "HTTP/1.1 403 ") {
		t.Fatalf("resp: %s", resp)
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("an unresolved peer's callback was relayed %d times", n)
	}
}

func TestBadHostHeaderIsRefused(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	p := strconv.Itoa(f.Port)
	cb := "GET /callback?code=x&state=" + testState + " HTTP/1.1\r\n"
	for name, req := range map[string]string{
		"rebinding host": cb + "Host: evil.example:" + p + "\r\n\r\n",
		"other port":     cb + "Host: localhost:1\r\n\r\n",
		"no port":        cb + "Host: localhost\r\n\r\n",
		"two hosts":      cb + "Host: localhost:" + p + "\r\nHost: evil.example\r\n\r\n",
		"no host":        cb + "\r\n",
		"lan address":    cb + "Host: 192.168.1.1:" + p + "\r\n\r\n",
	} {
		resp := browse(t, f.Port, req)
		if !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
			t.Errorf("%s: %s", name, resp)
		}
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("relayed %d times", n)
	}
	for _, host := range []string{"localhost:" + p, "127.0.0.1:" + p, "[::1]:" + p} {
		if !hostMatches(host, f.Port) {
			t.Errorf("%s refused", host)
		}
	}
}

func TestHostPortInUseOpensNothing(t *testing.T) {
	r := newRig(t)
	f := testFlow(t)
	squat, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.Port)))
	if err != nil {
		t.Fatal(err)
	}
	err = r.b.Handle(f)
	squat.Close()
	if err == nil || !strings.Contains(err.Error(), "localhost:"+strconv.Itoa(f.Port)+" is in use on this host") {
		t.Fatalf("err = %v", err)
	}

	// The v6 family squatted alone refuses too, and leaves v4 unbound.
	f2 := testFlow(t)
	squat6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(f2.Port)))
	if err == nil {
		err2 := r.b.Handle(f2)
		squat6.Close()
		if err2 == nil || !strings.Contains(err2.Error(), "is in use") {
			t.Fatalf("v6 squat: err = %v", err2)
		}
		if !refuses(f2.Port) {
			t.Fatal("v4 listener left bound after the v6 refusal")
		}
	} else {
		t.Logf("no IPv6 loopback here (%v); v6 squat half not exercised", err)
	}

	time.Sleep(100 * time.Millisecond)
	if got := r.opener.opened(); len(got) != 0 {
		t.Fatalf("opener ran: %v", got)
	}
}

func TestFlowLimits(t *testing.T) {
	t.Run("one live flow and the supersede rule", func(t *testing.T) {
		r := newRig(t)
		f1 := testFlow(t)
		if err := r.b.Handle(f1); err != nil {
			t.Fatal(err)
		}
		r.clock.Advance(SupersedeAfter - time.Second)
		f2 := testFlow(t)
		err := r.b.Handle(f2)
		if err == nil || err.Error() != "a login is pending (opened 29s ago)" {
			t.Fatalf("err = %v", err)
		}
		if !refuses(f2.Port) {
			t.Fatal("a refused open bound its port")
		}
		r.clock.Advance(time.Second)
		if err := r.b.Handle(f2); err != nil {
			t.Fatalf("supersede after %s: %v", SupersedeAfter, err)
		}
		if !refuses(f1.Port) {
			t.Fatal("the superseded flow still holds its port")
		}
		if refuses(f2.Port) {
			t.Fatal("the new flow is not listening")
		}
		waitFor(t, func() bool { return len(r.opener.opened()) == 2 })
		if got := r.opener.opened(); got[0] != f1.AuthorizeURL() || got[1] != f2.AuthorizeURL() {
			t.Fatalf("opener got %v", got)
		}
	})

	t.Run("a flow with a callback in flight is never superseded", func(t *testing.T) {
		r := newRig(t)
		r.sandbox.release = make(chan struct{})
		r.sandbox.received = make(chan struct{}, 1)
		f := r.openFlow(t)
		done := make(chan string)
		go func() { done <- sendCallback(t, f) }()
		<-r.sandbox.received
		r.clock.Advance(SupersedeAfter + time.Minute)
		if err := r.b.Handle(testFlow(t)); err == nil || !strings.Contains(err.Error(), "a login is pending") {
			t.Fatalf("superseded a relaying flow: %v", err)
		}
		close(r.sandbox.release)
		if resp := <-done; !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("resp: %s", resp)
		}
	})

	t.Run("a 404 does not end the flow", func(t *testing.T) {
		r := newRig(t)
		f := r.openFlow(t)
		p := strconv.Itoa(f.Port)
		for _, req := range []string{
			"GET / HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n",
			"GET /favicon.ico HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n",
			callbackReq(f.Port, testState[:42]+"X", ""),
			"POST /callback?code=x&state=" + testState + " HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n",
		} {
			if resp := browse(t, f.Port, req); !strings.HasPrefix(resp, "HTTP/1.1 404 ") {
				t.Fatalf("resp: %s", resp)
			}
		}
		if len(r.sandbox.requests()) != 0 {
			t.Fatal("a 404 relayed")
		}
		if resp := sendCallback(t, f); !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("the right callback after 404s: %s", resp)
		}
	})

	t.Run("five opens per run", func(t *testing.T) {
		r := newRig(t)
		for i := range MaxOpensPerRun {
			if err := r.b.Handle(testFlow(t)); err != nil {
				t.Fatalf("open %d: %v", i+1, err)
			}
			r.clock.Advance(SupersedeAfter)
		}
		err := r.b.Handle(testFlow(t))
		if err == nil || err.Error() != "this run has used its 5 login opens; restart snug" {
			t.Fatalf("sixth open: %v", err)
		}
	})

	t.Run("three relays per run", func(t *testing.T) {
		r := newRig(t)
		for i := range MaxRelaysPerRun {
			f := testFlow(t)
			if err := r.b.Handle(f); err != nil {
				t.Fatalf("open %d: %v", i+1, err)
			}
			if resp := sendCallback(t, f); !strings.Contains(resp, "answered HTTP 200") {
				t.Fatalf("relay %d: %s", i+1, resp)
			}
		}
		if err := r.b.Handle(testFlow(t)); err == nil || !strings.Contains(err.Error(), "relayed its 3 login callbacks") {
			t.Fatalf("fourth open: %v", err)
		}
		if r.sandbox.dials != MaxRelaysPerRun {
			t.Fatalf("dials = %d", r.sandbox.dials)
		}
	})

	t.Run("the TTL closes the listeners", func(t *testing.T) {
		r := newRig(t)
		f := r.openFlow(t)
		r.clock.Advance(FlowTTL - time.Second)
		if refuses(f.Port) {
			t.Fatal("closed before the TTL")
		}
		r.clock.Advance(time.Second)
		if !refuses(f.Port) {
			t.Fatal("still listening after the TTL")
		}
		if !strings.Contains(r.stderr.String(), "released the port") {
			t.Fatalf("stderr: %s", r.stderr.String())
		}
		if err := r.b.Handle(testFlow(t)); err != nil {
			t.Fatalf("open after TTL: %v", err)
		}
	})

	t.Run("a failing opener cancels the flow", func(t *testing.T) {
		r := newRig(t)
		r.opener.err = errors.New("xdg-open (/x) failed: exit status 3")
		f := r.openFlow(t)
		waitFor(t, func() bool { return refuses(f.Port) })
		waitFor(t, func() bool { return strings.Contains(r.stderr.String(), "The login was cancelled") })
	})

	t.Run("nothing listening inside refuses", func(t *testing.T) {
		r := newRig(t)
		r.b.d.Listening = func(int) (bool, error) { return false, nil }
		f := testFlow(t)
		err := r.b.Handle(f)
		if err == nil || err.Error() != "nothing inside listens on 127.0.0.1:"+strconv.Itoa(f.Port) {
			t.Fatalf("err = %v", err)
		}
		if !refuses(f.Port) {
			t.Fatal("bound a port for a refused open")
		}
	})

	t.Run("close ends the flow", func(t *testing.T) {
		r := newRig(t)
		f := r.openFlow(t)
		r.b.Close()
		if !refuses(f.Port) {
			t.Fatal("listening after Close")
		}
		if err := r.b.Handle(testFlow(t)); err == nil {
			t.Fatal("Handle after Close opened")
		}
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 200 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never held")
}

func TestOpenerGetsTheRebuiltURLAndHostEnv(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "rec")
	script := filepath.Join(dir, "xdg-open")
	os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" \"$SNUG_OPENER_PROBE\" > "+rec+"\n"), 0o700)
	t.Setenv("SNUG_OPENER_PROBE", "host-env")
	f := Flow{Port: 40123, CodeChallenge: testChallenge, State: testState}
	o := Opener{Path: script}
	cmd := o.openerCmd(f.AuthorizeURL())
	if cmd.Path != script || len(cmd.Args) != 2 || cmd.Args[1] != f.AuthorizeURL() {
		t.Fatalf("argv: %q", cmd.Args)
	}
	if !cmd.SysProcAttr.Setsid || cmd.SysProcAttr.Pdeathsig != 0 {
		t.Fatalf("SysProcAttr: %+v", cmd.SysProcAttr)
	}
	if err := o.Open(f.AuthorizeURL()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(rec)
	if want := "1\n" + f.AuthorizeURL() + "\nhost-env\n"; string(got) != want {
		t.Fatalf("opener saw:\n%q\nwant:\n%q", got, want)
	}

	fail := filepath.Join(dir, "fail")
	os.WriteFile(fail, []byte("#!/bin/sh\nprintf 'no browser\\033[2J' >&2\nexit 3\n"), 0o700)
	err := Opener{Path: fail}.Open(f.AuthorizeURL())
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), `no browser\x1b[2J`) {
		t.Fatalf("err = %v", err)
	}
}

func TestPeerUIDFindsTheClientRow(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer := s.RemoteAddr().(*net.TCPAddr).AddrPort()
	local := s.LocalAddr().(*net.TCPAddr).AddrPort()
	uid, ok := PeerUID(peer, local)
	if !ok || uid != os.Getuid() {
		t.Fatalf("uid=%d ok=%v", uid, ok)
	}
	if _, ok := PeerUID(netip.MustParseAddrPort("127.0.0.1:1"), local); ok {
		t.Fatal("a peer with no row resolved")
	}
	listening, err := ListeningOn("/proc/self/net/tcp", int(local.Port()))
	if err != nil || !listening {
		t.Fatalf("ListeningOn = %v, %v", listening, err)
	}
	if listening, _ := ListeningOn("/proc/self/net/tcp", int(peer.Port())); listening {
		t.Fatal("a client port reported as listening")
	}
}

func TestParseStatus(t *testing.T) {
	for line, want := range map[string]int{
		"HTTP/1.1 200 OK\r\n": 200, "HTTP/1.0 302 Found\r\n": 302, "HTTP/1.1 204\r\n": 204,
		"HTTP/2 200\r\n": 0, "HTTP/1.1 20 OK\r\n": 0, "HTTP/1.1 2000 OK\r\n": 0, "<html>\n": 0, "HTTP/1.1 099 x\r\n": 0,
	} {
		got, ok := parseStatus([]byte(line))
		if (want == 0 && ok) || (want != 0 && got != want) {
			t.Errorf("%q: %d %v", line, got, ok)
		}
	}
}
