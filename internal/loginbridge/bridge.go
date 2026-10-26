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
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The relay's bounds (.claude/design/LOGIN-BRIDGE.md §6).
const (
	relayDeadline   = 15 * time.Second
	maxStatusLine   = 8 << 10
	maxRelayDiscard = 64 << 10
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
	// Host, when set, completes every login on the host (login.claude =
	// "host") rather than relaying its code into the sandbox; nil is the
	// bridge of login.claude = "sandbox".
	Host *HostLogin
}

// Bridge is the host half of the login bridge: at most one live flow at a
// time, a host listener on localhost:<port> while it lives, and the one
// callback it accepts handed to the mode's consumer — relayed into the
// sandbox, or exchanged on the host.
type Bridge struct {
	d Deps
	// ctx is cancelled by Close, which is how an exchange in flight learns
	// that snug is shutting down and stops before it writes anything.
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	closed  bool
	opens   int
	relays  int
	live    *flow
	notices int
	wg      sync.WaitGroup
}

// flow is one live login: its listeners, its connections and whether its
// callback has been taken.
type flow struct {
	// f is the line the sandbox handed snug, as ParseAuthorize checked it.
	f Flow
	// expect is the state a callback must carry: the state of the URL snug
	// opened, which is f.State in sandbox mode and snug's own in host mode.
	expect string
	// deliver is the mode's consumer: it is handed the one callback that
	// passes every check, answers the browser, and returns.
	deliver func(c net.Conn, cb Callback)
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
	ctx, cancel := context.WithCancel(context.Background())
	return &Bridge{d: d, ctx: ctx, cancel: cancel}
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

	fl := &flow{f: f, expect: f.State, opened: now, conns: map[net.Conn]bool{}, slots: make(chan struct{}, maxConns)}
	url := f.AuthorizeURL()
	var announce string
	if h := b.d.Host; h != nil {
		hf, err := h.begin(f)
		if err != nil {
			return err
		}
		fl.expect = hf.State
		url = Flow{Port: f.Port, CodeChallenge: hf.Challenge, State: hf.State}.AuthorizeURL()
		fl.deliver = func(c net.Conn, cb Callback) { b.completeOnHost(fl, hf, c, cb) }
		announce = hf.announce()
	} else {
		fl.deliver = func(c net.Conn, cb Callback) { b.relayCode(fl, c, cb) }
	}

	if b.live != nil {
		b.endLocked(b.live)
	}
	lns, err := b.bind(f.Port)
	if err != nil {
		return err
	}
	fl.lns = lns
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
	if announce != "" {
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: %s\n", announce)
	}
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
	if fl.stopTTL != nil {
		fl.stopTTL()
	}
	for _, ln := range fl.lns {
		ln.Close()
	}
	for c := range fl.conns {
		c.Close()
	}
}

// Close ends any live flow, cancels an exchange in flight, refuses every
// later Handle and waits for the listener goroutines, the exchange's
// included. An opener already started is not waited for.
func (b *Bridge) Close() {
	b.mu.Lock()
	b.closed = true
	b.cancel()
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

// relayCode is sandbox mode's consumer: it writes the rebuilt callback into
// the sandbox and answers the browser with the status that came back.
func (b *Bridge) relayCode(fl *flow, c net.Conn, cb Callback) {
	status, rerr := b.relay(fl, RelayRequest(fl.f.Port, cb.Code, fl.f.State))
	if rerr != nil {
		writePage(c, 502, "snug could not deliver the login callback to the sandbox: "+rerr.Error()+
			". Run /login again inside the sandbox.")
		b.notice("could not relay the login callback into the sandbox — %s.", policy.VisibleText(rerr.Error()))
		return
	}
	writePage(c, 200, fmt.Sprintf("snug delivered the login callback to the sandbox; it answered HTTP %d. "+
		"You can close this tab.", status))
	fmt.Fprintf(b.d.Stderr, "snug: login bridge: delivered the login callback to the sandbox; it answered HTTP %d.\n", status)
}

// relayDenial is every mode's answer to a sign-in the browser declined: a
// constant error callback ends the client's wait, in place of the code
// there is none of.
func (b *Bridge) relayDenial(fl *flow, c net.Conn) {
	status, rerr := b.relay(fl, RelayErrorRequest(fl.f.Port, deniedError, deniedText, fl.f.State))
	if rerr != nil {
		writePage(c, 502, "You declined the Claude sign-in, and snug could not tell the sandbox: "+
			rerr.Error()+". Press Esc in claude inside the sandbox.")
		b.notice("the sign-in was declined, and relaying that into the sandbox failed — %s.",
			policy.VisibleText(rerr.Error()))
		return
	}
	writePage(c, 200, "You declined the Claude sign-in; snug ended the sandbox's /login. You can close this tab.")
	fmt.Fprintf(b.d.Stderr, "snug: login bridge: the sign-in was declined in the browser; snug ended "+
		"the sandbox's /login (it answered HTTP %d).\n", status)
}

// relay writes req into the sandbox and returns the status code of its
// answer. Nothing of the answer but that integer comes back.
func (b *Bridge) relay(fl *flow, req []byte) (int, error) {
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
	if _, err := conn.Write(req); err != nil {
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

// The error callbacks snug relays in place of a code. Each is snug's own
// constant: nothing the browser sent crosses but the fact the request
// reached the listener with the right state.
const (
	// deniedError and deniedText answer a sign-in declined in the browser.
	deniedError = "access_denied"
	deniedText  = "the sign-in was declined in the browser"
	// completedError and completedText end the client's wait after snug
	// completed the sign-in on the host and renewed the sandbox's token.
	completedError = "snug_completed_login"
	completedText  = "snug completed this sign-in on the host and renewed this sandbox's token; press Esc"
	// failedError and failedText end it after snug could not complete it.
	failedError = "snug_login_failed"
	failedText  = "snug could not complete this sign-in on the host; snug's terminal says why; press Esc"
)

// RelayErrorRequest is the request snug writes into the sandbox to end the
// client's /login wait without a code: error and error_description, the
// description percent-encoded, and the client's own state, which is what its
// listener checks before it gives up waiting.
func RelayErrorRequest(port int, errCode, description, state string) []byte {
	return []byte("GET /callback?error=" + errCode + "&error_description=" + percentEncode(description) +
		"&state=" + state + " HTTP/1.1\r\n" +
		"Host: localhost:" + strconv.Itoa(port) + "\r\n" +
		"Connection: close\r\n\r\n")
}

// percentEncode escapes every byte but RFC 3986's unreserved set, so the
// result is one query value whatever a later edit to a constant puts in it.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
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
