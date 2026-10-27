package loginbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The listener's per-connection bounds (.claude/design/LOGIN-BRIDGE.md §6).
// They are the same in both modes: the consumer a callback is handed to is
// the only thing a mode changes.
const (
	headReadDeadline = 10 * time.Second
	maxHeadBytes     = 8 << 10
	maxConns         = 8
	// noticesPrinted bounds the stderr lines the listener prints for refused
	// connections, which anything on this host able to reach localhost can
	// cause.
	noticesPrinted = 5
)

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

// serve answers one connection: one request, then close. Every check before
// the claim is the listener's and is the same in both modes; the claimed
// callback goes to fl.deliver, a declined sign-in to relayDenial.
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
	cb, err := ParseCallback(method, target, fl.expect)
	denied := false
	if err != nil {
		if ParseDenial(method, target, fl.expect) != nil {
			b.notice("answered 404 on localhost:%d — %s. The login is still pending.", fl.f.Port, err.Error())
			writePage(c, 404, "Not found. snug is waiting for a Claude login callback on this port; this was not it.")
			return
		}
		denied = true
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

	// The browser waits on c while the consumer works, which in host mode is
	// two requests to the vendor; c's deadline is what bounds that wait from
	// the browser's side.
	c.SetDeadline(time.Now().Add(pageDeadline))
	if denied {
		b.relayDenial(fl, c)
	} else {
		fl.deliver(c, cb)
	}
	b.mu.Lock()
	b.endLocked(fl)
	b.mu.Unlock()
}

// pageDeadline bounds how long the browser's connection is held for its
// answer once a callback is claimed: in host mode the two vendor requests,
// the host write and the relay into the sandbox, run one after another, with
// room to write the page.
const pageDeadline = exchangeTimeout + profileTimeout + HostWriteBudget + relayDeadline + 5*time.Second

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
