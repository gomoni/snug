package loginbridge

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The listener's per-connection bounds (spec §5.3) and the relay's (§5.5).
const (
	headReadDeadline = 10 * time.Second
	maxHeadBytes     = 8 << 10
	maxConns         = 8
	relayDeadline    = 15 * time.Second
	maxStatusLine    = 8 << 10
	maxRelayDiscard  = 64 << 10
	// noticesPrinted bounds the stderr lines the listener prints for refused
	// connections, which anything on this host able to reach localhost can
	// cause.
	noticesPrinted = 5
)

// Clock is the time source a Bridge reads; tests inject a fake one.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine after d, unless stop is called
	// first; stop reports whether it prevented the call.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// RealClock is the wall clock.
type RealClock struct{}

// Now is time.Now.
func (RealClock) Now() time.Time { return time.Now() }

// AfterFunc is time.AfterFunc.
func (RealClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// Relayer hands out the sockets snug relays a callback through. Each one
// was created inside the sandbox's network namespace, and Dial only ever
// connects one to 127.0.0.1:port — the sandbox chooses the port and nothing
// else.
type Relayer interface {
	// Left is how many sockets Dial can still hand out.
	Left() int
	// Dial spends one socket connecting it to 127.0.0.1:port. A socket is
	// spent even when the connect fails.
	Dial(port int) (net.Conn, error)
}

// Deps is everything a Bridge does to the outside world, injected so the
// listener, relay and limits are testable without a sandbox.
type Deps struct {
	Clock   Clock
	Relayer Relayer
	// Listening reports whether something inside the sandbox listens on
	// 127.0.0.1:port.
	Listening func(port int) (bool, error)
	// PeerUID returns the uid owning the client end of an accepted
	// connection, ok false when it cannot be determined.
	PeerUID func(peer, local netip.AddrPort) (uid int, ok bool)
	// UID is the only uid whose connections the listener admits.
	UID int
	// Open opens url in the host browser and returns once the opener has
	// either exited or been waited on long enough. A non-nil error cancels
	// the flow.
	Open func(url string) error
	// Listen binds one host listener; nil means net.ListenConfig with
	// IPV6_V6ONLY set on the v6 one.
	Listen func(network, addr string) (net.Listener, error)
	Stderr io.Writer
}

// Bridge is the host half of the login bridge: at most one live flow at a
// time, a host listener on localhost:<port> while it lives, and the one-shot
// relay of its callback into the sandbox.
type Bridge struct {
	d Deps

	mu      sync.Mutex
	closed  bool
	opens   int
	relays  int
	live    *flow
	notices int
	wg      sync.WaitGroup
}

// flow is one live login: its listeners, its connections and whether its
// callback has been relayed.
type flow struct {
	f       Flow
	opened  time.Time
	lns     []net.Listener
	conns   map[net.Conn]bool
	stopTTL func() bool
	// relayed is set the moment a callback passes the predicate, before the
	// relay connects: a flow with a callback in flight is never superseded
	// and never relays a second one.
	relayed bool
	ended   bool
	slots   chan struct{}
}

// New returns a Bridge with no live flow.
func New(d Deps) *Bridge {
	if d.Listen == nil {
		d.Listen = listenLoopback
	}
	return &Bridge{d: d}
}

// Handle starts a flow for f: checks the limits and the port, binds the host
// listener, and opens the rebuilt authorize URL. A non-nil error is a
// refusal, worded as the reason a caller prints after "refused an open
// request from the sandbox — "; nothing was opened when it is returned.
func (b *Bridge) Handle(f Flow) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("snug is shutting down")
	}
	if b.opens >= MaxOpensPerRun {
		return fmt.Errorf("this run has used its %d login opens; restart snug", MaxOpensPerRun)
	}
	if b.relays >= MaxRelaysPerRun || b.d.Relayer.Left() == 0 {
		return fmt.Errorf("this run has relayed its %d login callbacks; restart snug", MaxRelaysPerRun)
	}
	now := b.d.Clock.Now()
	if l := b.live; l != nil {
		age := now.Sub(l.opened)
		if l.relayed || age < SupersedeAfter {
			return fmt.Errorf("a login is pending (opened %ds ago)", int(age/time.Second))
		}
	}
	ok, err := b.d.Listening(f.Port)
	if err != nil {
		return fmt.Errorf("could not check what the sandbox listens on: %v", err)
	}
	if !ok {
		return fmt.Errorf("nothing inside listens on 127.0.0.1:%d", f.Port)
	}
	if b.live != nil {
		b.endLocked(b.live)
	}

	lns, err := b.bind(f.Port)
	if err != nil {
		return err
	}
	fl := &flow{f: f, opened: now, lns: lns, conns: map[net.Conn]bool{}, slots: make(chan struct{}, maxConns)}
	fl.stopTTL = b.d.Clock.AfterFunc(FlowTTL, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.live == fl && !fl.relayed {
			b.endLocked(fl)
			fmt.Fprintf(b.d.Stderr, "snug: login bridge: no callback reached localhost:%d within %s; "+
				"the login was abandoned and snug released the port.\n", f.Port, FlowTTL)
		}
	})
	b.live = fl
	b.opens++
	for _, ln := range lns {
		b.wg.Add(1)
		go b.accept(fl, ln)
	}
	url := f.AuthorizeURL()
	go func() {
		if err := b.d.Open(url); err != nil {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.live == fl && !fl.relayed {
				b.endLocked(fl)
			}
			fmt.Fprintf(b.d.Stderr, "snug: login bridge: %v. The login was cancelled — open the URL "+
				"claude printed and paste the code.\n", err)
		}
	}()
	return nil
}

// bind takes 127.0.0.1:port and [::1]:port. Any failure on the v4 side, or
// EADDRINUSE on the v6 side, refuses the whole flow with nothing bound: a
// family snug skipped while it is in use could be held by another uid, and
// the browser may resolve localhost to it. A host with no v6 loopback
// (EADDRNOTAVAIL, EAFNOSUPPORT) gets v4 only — the browser cannot reach ::1
// there either.
func (b *Bridge) bind(port int) ([]net.Listener, error) {
	inUse := fmt.Errorf("localhost:%d is in use on this host; run /login again and claude picks another port", port)
	v4, err := b.d.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, inUse
		}
		return nil, fmt.Errorf("could not listen on 127.0.0.1:%d: %v", port, err)
	}
	v6, err := b.d.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	switch {
	case err == nil:
		return []net.Listener{v4, v6}, nil
	case errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.EAFNOSUPPORT):
		return []net.Listener{v4}, nil
	case errors.Is(err, syscall.EADDRINUSE):
		v4.Close()
		return nil, inUse
	default:
		v4.Close()
		return nil, fmt.Errorf("could not listen on [::1]:%d: %v", port, err)
	}
}

// listenLoopback binds network/addr with IPV6_V6ONLY set explicitly on a v6
// socket, so [::1]:port never also answers for a v4 address whatever the
// net.ipv6.bindv6only sysctl says.
func listenLoopback(network, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(nw, _ string, c syscall.RawConn) error {
		if nw != "tcp6" {
			return nil
		}
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), network, addr)
}

// endLocked closes fl's listeners and connections and stops its TTL. b.mu is
// held.
func (b *Bridge) endLocked(fl *flow) {
	if fl.ended {
		return
	}
	fl.ended = true
	if b.live == fl {
		b.live = nil
	}
	fl.stopTTL()
	for _, ln := range fl.lns {
		ln.Close()
	}
	for c := range fl.conns {
		c.Close()
	}
}

// Close ends any live flow, refuses every later Handle and waits for the
// listener goroutines. An opener already started is not waited for.
func (b *Bridge) Close() {
	b.mu.Lock()
	b.closed = true
	if b.live != nil {
		b.endLocked(b.live)
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// notice prints a listener-side line, the first noticesPrinted of them and
// then one suppression line.
func (b *Bridge) notice(format string, a ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.noticeLocked(format, a...)
}

func (b *Bridge) noticeLocked(format string, a ...any) {
	b.notices++
	switch {
	case b.notices <= noticesPrinted:
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: "+format+"\n", a...)
	case b.notices == noticesPrinted+1:
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: further connection refusals suppressed.\n")
	}
}

func (b *Bridge) accept(fl *flow, ln net.Listener) {
	defer b.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case fl.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		b.mu.Lock()
		if fl.ended {
			b.mu.Unlock()
			c.Close()
			<-fl.slots
			return
		}
		fl.conns[c] = true
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.serve(fl, c)
			b.mu.Lock()
			delete(fl.conns, c)
			b.mu.Unlock()
			c.Close()
			<-fl.slots
		}()
	}
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return t.AddrPort(), true
}

// serve answers one connection: one request, then close.
func (b *Bridge) serve(fl *flow, c net.Conn) {
	peer, ok1 := addrPort(c.RemoteAddr())
	local, ok2 := addrPort(c.LocalAddr())
	if !ok1 || !ok2 {
		writePage(c, 403, "snug refused this connection: its addresses are not TCP.")
		return
	}
	uid, ok := b.d.PeerUID(peer, local)
	if !ok {
		b.notice("refused a connection to localhost:%d — snug could not find which user owns it.", fl.f.Port)
		writePage(c, 403, "snug refused this connection: it could not tell which user on this machine made it.")
		return
	}
	if uid != b.d.UID {
		b.notice("refused a connection to localhost:%d from uid %d — only your uid (%d) may deliver a login callback.",
			fl.f.Port, uid, b.d.UID)
		writePage(c, 403, "snug refused this connection: it belongs to another user on this machine.")
		return
	}

	c.SetReadDeadline(time.Now().Add(headReadDeadline))
	method, target, host, err := readHead(c)
	if err != nil {
		b.notice("refused a request on localhost:%d — %s.", fl.f.Port, policy.VisibleText(err.Error()))
		writePage(c, 400, "snug could not read this request: "+err.Error()+".")
		return
	}
	if !hostMatches(host, fl.f.Port) {
		b.notice("refused a request on localhost:%d — Host header %s is not localhost:%d.",
			fl.f.Port, policy.VisibleText(host), fl.f.Port)
		writePage(c, 400, "snug answers only requests addressed to localhost.")
		return
	}
	cb, err := ParseCallback(method, target, fl.f.State)
	if err != nil {
		b.notice("answered 404 on localhost:%d — %s. The login is still pending.", fl.f.Port, err.Error())
		writePage(c, 404, "Not found. snug is waiting for a Claude login callback on this port; this was not it.")
		return
	}

	b.mu.Lock()
	if fl.ended || fl.relayed {
		b.mu.Unlock()
		writePage(c, 404, "Not found. This login's callback was already delivered or the login ended.")
		return
	}
	fl.relayed = true
	b.relays++
	b.mu.Unlock()

	status, rerr := b.relay(fl, cb)
	if rerr != nil {
		writePage(c, 502, "snug could not deliver the login callback to the sandbox: "+rerr.Error()+
			". Run /login again inside the sandbox.")
		b.notice("could not relay the login callback into the sandbox — %s.", policy.VisibleText(rerr.Error()))
	} else {
		writePage(c, 200, fmt.Sprintf("snug delivered the login callback to the sandbox; it answered HTTP %d. "+
			"You can close this tab.", status))
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: delivered the login callback to the sandbox; it answered HTTP %d.\n", status)
	}
	b.mu.Lock()
	b.endLocked(fl)
	b.mu.Unlock()
}

// relay writes the rebuilt callback into the sandbox and returns the status
// code of its answer. Nothing from the browser's request but cb.Code and the
// flow's own state crosses, and nothing of the answer but that integer comes
// back.
func (b *Bridge) relay(fl *flow, cb Callback) (int, error) {
	conn, err := b.d.Relayer.Dial(fl.f.Port)
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	if fl.ended {
		b.mu.Unlock()
		conn.Close()
		return 0, errors.New("the login ended before the relay connected")
	}
	fl.conns[conn] = true
	b.mu.Unlock()
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(relayDeadline))
	if _, err := conn.Write(RelayRequest(fl.f.Port, cb.Code, fl.f.State)); err != nil {
		return 0, fmt.Errorf("writing the callback: %v", err)
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, maxStatusLine+maxRelayDiscard), maxStatusLine)
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return 0, fmt.Errorf("the sandbox's status line is longer than %d bytes", maxStatusLine)
		}
		return 0, fmt.Errorf("reading the sandbox's answer: %v", err)
	}
	status, ok := parseStatus(line)
	if !ok {
		return 0, errors.New("the sandbox's answer is not an HTTP/1.x response")
	}
	io.Copy(io.Discard, br)
	return status, nil
}

// RelayRequest is the exact request snug writes into the sandbox for a
// callback: code raw as the browser sent it, the flow's own state, and no
// header but Host and Connection.
func RelayRequest(port int, code, state string) []byte {
	return []byte("GET /callback?code=" + code + "&state=" + state + " HTTP/1.1\r\n" +
		"Host: localhost:" + strconv.Itoa(port) + "\r\n" +
		"Connection: close\r\n\r\n")
}

// parseStatus reads the three-digit code of an HTTP/1.x status line.
func parseStatus(line []byte) (int, bool) {
	rest, ok := bytes.CutPrefix(line, []byte("HTTP/1."))
	if !ok || len(rest) < 6 || (rest[0] != '0' && rest[0] != '1') || rest[1] != ' ' {
		return 0, false
	}
	code := rest[2:5]
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	if rest[5] != ' ' && rest[5] != '\r' && rest[5] != '\n' {
		return 0, false
	}
	n, _ := strconv.Atoi(string(code))
	return n, n >= 100
}

// readHead reads one request head of at most maxHeadBytes and returns its
// method, request-target and the single Host header's value.
func readHead(r io.Reader) (method, target, host string, err error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		if len(buf) >= maxHeadBytes {
			return "", "", "", fmt.Errorf("the request head is longer than %d bytes", maxHeadBytes)
		}
		n, rerr := r.Read(tmp[:min(len(tmp), maxHeadBytes-len(buf))])
		buf = append(buf, tmp[:n]...)
		if rerr != nil && !bytes.Contains(buf, []byte("\r\n\r\n")) {
			return "", "", "", fmt.Errorf("the request head ended early: %v", rerr)
		}
	}
	head, _, _ := bytes.Cut(buf, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0" {
		return "", "", "", errors.New("the request line is not METHOD TARGET HTTP/1.x")
	}
	hosts := 0
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return "", "", "", errors.New("a header line is malformed")
		}
		if strings.EqualFold(k, "Host") {
			hosts++
			host = strings.Trim(v, " \t")
		}
	}
	if hosts != 1 {
		return "", "", "", fmt.Errorf("the request carries %d Host headers, want 1", hosts)
	}
	return parts[0], parts[1], host, nil
}

// hostMatches is the DNS-rebinding gate: the browser addressed localhost,
// 127.0.0.1 or [::1] on the flow's port, and nothing else.
func hostMatches(host string, port int) bool {
	p := strconv.Itoa(port)
	return host == "localhost:"+p || host == "127.0.0.1:"+p || host == "[::1]:"+p
}

// pageCSP forbids the page every subresource, form and frame: it is snug's
// static text and needs none.
const pageCSP = "default-src 'none'; form-action 'none'; frame-ancestors 'none'"

// writePage answers with snug's own page. The body is snug's text, HTML
// escaped; no byte of it comes from the sandbox.
func writePage(w io.Writer, status int, text string) {
	body := "<!doctype html>\n<meta charset=\"utf-8\">\n<title>snug login bridge</title>\n<p>" +
		htmlEscape(text) + "</p>\n"
	reason := map[int]string{200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 502: "Bad Gateway"}[status]
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Content-Security-Policy: %s\r\n"+
		"Cache-Control: no-store\r\n"+
		"Referrer-Policy: no-referrer\r\n"+
		"X-Content-Type-Options: nosniff\r\n"+
		"Connection: close\r\n\r\n%s", status, reason, len(body), pageCSP, body)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(s)
}
