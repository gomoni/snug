package loginbridge

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// relayerFunc is a Relayer whose Dial is the test's own, so a test decides
// what the far end of the relay socket does and records what snug asked of it.
type relayerFunc struct {
	mu    sync.Mutex
	left  int
	ports []int
	dial  func(port int) (net.Conn, error)
}

func (r *relayerFunc) Left() int { r.mu.Lock(); defer r.mu.Unlock(); return r.left }

func (r *relayerFunc) Dial(port int) (net.Conn, error) {
	r.mu.Lock()
	r.left--
	r.ports = append(r.ports, port)
	r.mu.Unlock()
	return r.dial(port)
}

func (r *relayerFunc) dialled() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.ports...)
}

// answeringPipe returns a Dial whose far end reads the request head and then
// runs serve with the sandbox's side of the connection.
func answeringPipe(serve func(c net.Conn)) func(int) (net.Conn, error) {
	return func(int) (net.Conn, error) {
		ours, theirs := net.Pipe()
		go func() {
			defer theirs.Close()
			buf := make([]byte, 1)
			var seen []byte
			for !strings.HasSuffix(string(seen), "\r\n\r\n") {
				n, err := theirs.Read(buf)
				seen = append(seen, buf[:n]...)
				if err != nil {
					return
				}
			}
			serve(theirs)
		}()
		return ours, nil
	}
}

func wantRelay(port int, code string) string {
	return string(RelayRequest(port, code, testState))
}

// TestAPipelinedSecondRequestIsNeverProcessed fails if a second request on the
// connection that carried the first is read, answered or relayed: the listener
// answers one request and closes, so a browser-shaped first request cannot
// carry a second the checks never saw.
//
// Both orders: valid then valid must relay once, and a refused first request
// followed by a valid one must NOT be rescued by the pipelining (the flow
// stays open, shown by the relay a fresh connection then gets).
func TestAPipelinedSecondRequestIsNeverProcessed(t *testing.T) {
	t.Run("valid then valid relays once", func(t *testing.T) {
		r := newRig(t)
		f := r.openFlow(t)
		resp := browse(t, f.Port, callbackReq(f.Port, testState, "")+callbackReq(f.Port, testState, ""))
		if n := strings.Count(resp, "HTTP/1.1 "); n != 1 {
			t.Errorf("the connection carried %d responses, want 1:\n%s", n, resp)
		}
		got := r.sandbox.requests()
		if len(got) != 1 {
			t.Fatalf("the sandbox received %d requests, want 1: %q", len(got), got)
		}
		if string(got[0]) != wantRelay(f.Port, "AbC-12.3_x~") {
			t.Errorf("relayed %q", got[0])
		}
	})

	t.Run("refused then valid does not relay", func(t *testing.T) {
		r := newRig(t)
		f := r.openFlow(t)
		p := strconv.Itoa(f.Port)
		first := "GET /favicon.ico HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n"
		resp := browse(t, f.Port, first+callbackReq(f.Port, testState, ""))
		if !strings.HasPrefix(resp, "HTTP/1.1 404 ") || strings.Count(resp, "HTTP/1.1 ") != 1 {
			t.Fatalf("want exactly one 404 answer:\n%s", resp)
		}
		if n := len(r.sandbox.requests()); n != 0 {
			t.Fatalf("the pipelined second request was relayed (%d)", n)
		}
		// Control: the flow is alive, so the zero above is the pipelining
		// refusal and not a flow that had already ended.
		if resp := sendCallback(t, f); !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("the flow did not survive: %s", resp)
		}
	})
}

// TestFramingHeadersOnTheCallbackCannotSmuggleASecondRelay fails if a
// Content-Length, Transfer-Encoding or Expect header on a valid GET /callback
// makes snug read a body, forward a header, or relay the request carried
// inside it. Each case carries a second complete callback as the "body"; the
// sandbox must see exactly snug's one rebuilt request.
func TestFramingHeadersOnTheCallbackCannotSmuggleASecondRelay(t *testing.T) {
	second := callbackReq(0, testState, "")
	chunked := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(second), second)
	for name, hdr := range map[string]string{
		"content-length body":          "Content-Length: " + strconv.Itoa(len(second)) + "\r\n",
		"content-length zero":          "Content-Length: 0\r\n",
		"two content-lengths":          "Content-Length: 5\r\nContent-Length: 6\r\n",
		"chunked":                      "Transfer-Encoding: chunked\r\n",
		"chunked and content-length":   "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
		"expect continue":              "Expect: 100-continue\r\nContent-Length: 10\r\n",
		"connection keep-alive":        "Connection: keep-alive\r\n",
		"upgrade":                      "Connection: Upgrade\r\nUpgrade: websocket\r\n",
		"x-forwarded-host and proxies": "X-Forwarded-Host: evil.example\r\nForwarded: for=1.2.3.4\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			f := r.openFlow(t)
			body := second
			if strings.HasPrefix(hdr, "Transfer-Encoding") {
				body = chunked
			}
			resp := browse(t, f.Port, callbackReq(f.Port, testState, hdr)+body)
			got := r.sandbox.requests()
			if len(got) != 1 {
				t.Fatalf("the sandbox received %d requests, want exactly 1: %q\nanswer: %s", len(got), got, resp)
			}
			if string(got[0]) != wantRelay(f.Port, "AbC-12.3_x~") {
				t.Errorf("the relayed request is not snug's own:\n%q", got[0])
			}
			if n := r.sandbox.dials; n != 1 {
				t.Errorf("relay sockets spent: %d, want 1", n)
			}
			if !strings.HasPrefix(resp, "HTTP/1.1 200 ") || strings.Count(resp, "HTTP/1.1 ") != 1 {
				t.Errorf("want exactly one 200 page:\n%s", resp)
			}
		})
	}
}

// TestRequestFormsAndHostTricksAreRefused fails if an absolute-form target, a
// Host spelled to pass a prefix or a parser, or an odd request line reaches
// the relay. Every case is refused (400 or 404) with nothing relayed, and the
// flow is still open at the end: the closing valid callback relays, which is
// the control that the zero before it is the refusal's doing.
func TestRequestFormsAndHostTricksAreRefused(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	p := strconv.Itoa(f.Port)
	cb := "/callback?code=x&state=" + testState
	ok := "Host: localhost:" + p + "\r\n"
	type tc struct {
		name, req string
		status    string
	}
	cases := []tc{
		{"absolute-form, matching Host", "GET http://localhost:" + p + cb + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"absolute-form, other authority", "GET http://evil.example" + cb + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"asterisk-form", "GET * HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"authority-form CONNECT", "CONNECT localhost:" + p + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"lowercase method", "get " + cb + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"double slash path", "GET /" + cb + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"dot-dot path", "GET /x/..%2fcallback?code=x&state=" + testState + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"percent-encoded path", "GET /%63allback?code=x&state=" + testState + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"path parameter", "GET /callback;x=1?code=x&state=" + testState + " HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"fragment on the target", "GET " + cb + "#f HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"trailing ampersand", "GET " + cb + "& HTTP/1.1\r\n" + ok + "\r\n", "404"},
		{"HTTP/2 preface", "PRI * HTTP/2.0\r\n" + ok + "\r\n", "400"},
		{"HTTP/0.9", "GET " + cb + "\r\n" + ok + "\r\n", "400"},
		{"double space in the request line", "GET  " + cb + " HTTP/1.1\r\n" + ok + "\r\n", "400"},
		{"tab for space", "GET\t" + cb + "\tHTTP/1.1\r\n" + ok + "\r\n", "400"},
		{"obs-fold continuation", "GET " + cb + " HTTP/1.1\r\nHost: evil.example\r\n localhost:" + p + "\r\n\r\n", "400"},
		{"space before the colon", "GET " + cb + " HTTP/1.1\r\nHost : localhost:" + p + "\r\n\r\n", "400"},
		{"tab before the colon", "GET " + cb + " HTTP/1.1\r\nHost\t: localhost:" + p + "\r\n\r\n", "400"},
		{"empty Host", "GET " + cb + " HTTP/1.1\r\nHost:\r\n\r\n", "400"},
		{"userinfo in Host", "GET " + cb + " HTTP/1.1\r\nHost: localhost:" + p + "@evil.example\r\n\r\n", "400"},
		{"suffix on Host", "GET " + cb + " HTTP/1.1\r\nHost: localhost:" + p + ".evil.example\r\n\r\n", "400"},
		{"uppercase Host", "GET " + cb + " HTTP/1.1\r\nHost: LOCALHOST:" + p + "\r\n\r\n", "400"},
		{"trailing dot Host", "GET " + cb + " HTTP/1.1\r\nHost: localhost.:" + p + "\r\n\r\n", "400"},
		{"leading zero port", "GET " + cb + " HTTP/1.1\r\nHost: localhost:0" + p + "\r\n\r\n", "400"},
		{"list of Hosts", "GET " + cb + " HTTP/1.1\r\nHost: localhost:" + p + ", evil.example\r\n\r\n", "400"},
		{"NUL after Host", "GET " + cb + " HTTP/1.1\r\nHost: localhost:" + p + "\x00\r\n\r\n", "400"},
		{"URL in Host", "GET " + cb + " HTTP/1.1\r\nHost: http://localhost:" + p + "\r\n\r\n", "400"},
		{"slash in Host", "GET " + cb + " HTTP/1.1\r\nHost: localhost:" + p + "/\r\n\r\n", "400"},
		{"127.0.0.2", "GET " + cb + " HTTP/1.1\r\nHost: 127.0.0.2:" + p + "\r\n\r\n", "400"},
		{"0.0.0.0", "GET " + cb + " HTTP/1.1\r\nHost: 0.0.0.0:" + p + "\r\n\r\n", "400"},
		{"decimal address", "GET " + cb + " HTTP/1.1\r\nHost: 2130706433:" + p + "\r\n\r\n", "400"},
		{"v4-mapped v6", "GET " + cb + " HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:" + p + "\r\n\r\n", "400"},
		{"X-Forwarded-Host only", "GET " + cb + " HTTP/1.1\r\nX-Forwarded-Host: localhost:" + p + "\r\n\r\n", "400"},
		{"absolute-form with a bad Host", "GET http://localhost:" + p + cb + " HTTP/1.1\r\nHost: evil.example\r\n\r\n", "400"},
	}
	for _, c := range cases {
		resp := browse(t, f.Port, c.req)
		if !strings.HasPrefix(resp, "HTTP/1.1 "+c.status+" ") {
			t.Errorf("%s: want a %s, got:\n%s", c.name, c.status, firstLineOf(resp))
		}
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("%d refused request(s) were relayed: %q", n, r.sandbox.requests())
	}
	// The spellings a browser really uses are accepted, case-insensitive on the
	// header NAME, tolerant of surrounding blanks in the value.
	for _, host := range []string{"localhost:" + p, "127.0.0.1:" + p, "[::1]:" + p} {
		if !hostMatches(host, f.Port) {
			t.Errorf("control: Host %q is refused", host)
		}
	}
	resp := browse(t, f.Port, "GET "+cb+" HTTP/1.1\r\nhOsT:   localhost:"+p+"  \r\n\r\n")
	if !strings.Contains(resp, "answered HTTP 200") {
		t.Fatalf("control: the valid callback was not relayed after the refusals: %s", resp)
	}
}

// patientBrowse is browse with a client deadline longer than the relay's, for
// the cases whose point is the relay's own deadline.
func patientBrowse(t *testing.T, port int, req string) string {
	t.Helper()
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("browser could not connect: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(relayDeadline + 10*time.Second))
	io.WriteString(c, req)
	b, _ := io.ReadAll(c)
	return string(b)
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(s, "\r\n")
	return l
}

// TestSlowConnectionsDelayTheCallbackButNeverBlockItForever fails if eight
// slow connections hold the listener's connection slots past the head read
// deadline, or if a trickle keeps one alive past it. The real callback is
// dropped while the slots are full (the control that the saturation worked)
// and relays once they time out, within the deadline window.
//
// It takes the real headReadDeadline: the constant is not injectable. It
// shows one round of same-uid tricklers delays a login by about that window and
// no longer; it does not show a same-uid process cannot keep re-filling the
// slots every window until the flow's TTL, which nothing here rules out.
func TestSlowConnectionsDelayTheCallbackButNeverBlockItForever(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := r.openFlow(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.Port))
	start := time.Now()
	var conns []net.Conn
	for range maxConns {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		t.Cleanup(func() { c.Close() })
	}
	// Half stay silent, half trickle one byte of a header every 500ms: a
	// deadline that restarted on each byte would never fire on the second half.
	var stop atomic.Bool
	t.Cleanup(func() { stop.Store(true) })
	for i, c := range conns {
		if i%2 == 0 {
			continue
		}
		go func() {
			io.WriteString(c, "GET /callback")
			for !stop.Load() {
				if _, err := io.WriteString(c, "x"); err != nil {
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)

	dropped := sendCallback(t, f)
	if dropped != "" {
		t.Fatalf("control: the ninth connection was answered while eight slots were held: %q", dropped)
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("control: a callback was relayed while saturated")
	}

	var relayedAt time.Duration
	for time.Since(start) < headReadDeadline+4*time.Second {
		resp := sendCallback(t, f)
		if strings.Contains(resp, "answered HTTP 200") {
			relayedAt = time.Since(start)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if relayedAt == 0 {
		t.Fatalf("the callback was still not relayed %s after eight slow connections (deadline %s)",
			time.Since(start).Round(time.Second), headReadDeadline)
	}
	if relayedAt < headReadDeadline-time.Second {
		t.Errorf("relayed after %s, before the %s deadline could have freed a slot: the saturation "+
			"was not what delayed it", relayedAt.Round(time.Millisecond), headReadDeadline)
	}
	t.Logf("relayed %s after the eight slow connections opened", relayedAt.Round(100*time.Millisecond))
	if n := len(r.sandbox.requests()); n != 1 {
		t.Errorf("the sandbox received %d requests, want 1", n)
	}
	// The deadline answered the slow connections rather than dropping them
	// silently: evidence it, and not the test's own closes, freed the slots.
	answered := 0
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(time.Second))
		b, _ := io.ReadAll(c)
		if strings.HasPrefix(string(b), "HTTP/1.1 400 ") {
			answered++
		}
	}
	if answered == 0 {
		t.Errorf("no slow connection was answered 400: the head deadline did not fire")
	}
}

// TestAnotherUIDCannotHoldConnectionSlots fails if a connection from another
// uid keeps a slot while idle: the uid gate runs before the head read, so a
// stranger's connections are answered 403 at once and cannot slowloris the
// human out of a login. Thirty idle connections, each answered without sending
// a byte, and then the human's callback relays immediately.
func TestAnotherUIDCannotHoldConnectionSlots(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	r.mu.Lock()
	r.peerUID = os.Getuid() + 1
	r.mu.Unlock()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.Port))
	for i := range 30 {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(b), "HTTP/1.1 403 ") {
			t.Fatalf("idle connection %d from another uid was not answered 403 at once: %q", i, b)
		}
	}
	r.mu.Lock()
	r.peerUID = os.Getuid()
	r.mu.Unlock()
	if resp := sendCallback(t, f); !strings.Contains(resp, "answered HTTP 200") {
		t.Fatalf("the human's callback after the strangers: %s", resp)
	}
}

// TestRelayOnlyEverDialsTheFlowsOwnPort fails if the port handed to the
// relayer is ever anything but the one the flow was opened for — not the Host
// header's, not a port in the callback, not a stale flow's. The address half
// (always 127.0.0.1) is checked where the dial happens, in internal/cli.
func TestRelayOnlyEverDialsTheFlowsOwnPort(t *testing.T) {
	r := newRig(t)
	rel := &relayerFunc{left: MaxRelaysPerRun, dial: answeringPipe(func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	})}
	r.b.d.Relayer = rel
	var want []int
	for i, host := range []string{"localhost", "127.0.0.1", "[::1]"} {
		f := testFlow(t)
		if err := r.b.Handle(f); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		p := strconv.Itoa(f.Port)
		req := "GET /callback?code=x&state=" + testState + " HTTP/1.1\r\nHost: " + host + ":" + p + "\r\n\r\n"
		if resp := browse(t, f.Port, req); !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("flow %d: %s", i, resp)
		}
		want = append(want, f.Port)
	}
	got := rel.dialled()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the relayer was asked for ports %v, want exactly the flows' %v", got, want)
	}
	if rel.Left() != 0 {
		t.Fatalf("control: %d relay sockets left, want 0 after three relays", rel.Left())
	}
}

// TestARelayThatCouldSplitTheRequestIsRefusedOrStaysEncoded fails if a code
// with a raw CR, LF, tab, space, colon or other header-shaped byte reaches the
// relay, or if a percent-escaped CRLF is ever decoded on its way in. The
// escaped spelling IS accepted — it is 1-1024 bytes of the code alphabet — and
// must arrive byte-identical, still escaped: the sandbox's own server decodes
// it, snug never does.
func TestARelayThatCouldSplitTheRequestIsRefusedOrStaysEncoded(t *testing.T) {
	raw := []string{
		"a\rb", "a\nb", "a\r\nHost:evil", "a\tb", "a:b", "a;b", "a,b", "a\\b", "a\"b", "a<b", "a>b",
		"a|b", "a\x00b", "a\xc3\xa9b", "a%0", "a%g1", "a%", "a b", "a+b", "a=b", "a/b", "a?b", "a@b",
		"x\r\nX-Evil: 1", "",
	}
	for _, code := range raw {
		t.Run(fmt.Sprintf("refused/%q", code), func(t *testing.T) {
			r := newRig(t)
			f := r.openFlow(t)
			p := strconv.Itoa(f.Port)
			// A raw space would end the request-target, so it is sent as the
			// whole request line splitting; the others ride in the target.
			req := "GET /callback?code=" + code + "&state=" + testState + " HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n"
			resp := browse(t, f.Port, req)
			if !strings.HasPrefix(resp, "HTTP/1.1 404 ") && !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
				t.Errorf("want a refusal, got:\n%s", firstLineOf(resp))
			}
			if n := len(r.sandbox.requests()); n != 0 {
				t.Errorf("the code was relayed: %q", r.sandbox.requests())
			}
		})
	}
	for _, code := range []string{
		"a%0D%0AHost%3A%20evil.example%0D%0AX%3A%201",
		"a%0d%0aX-Evil%3a%201",
		"%00", "%2F%2e%2E", "a%20b",
	} {
		t.Run("encoded/"+code, func(t *testing.T) {
			r := newRig(t)
			f := r.openFlow(t)
			p := strconv.Itoa(f.Port)
			req := "GET /callback?code=" + code + "&state=" + testState + " HTTP/1.1\r\nHost: localhost:" + p + "\r\n\r\n"
			resp := browse(t, f.Port, req)
			if !strings.Contains(resp, "answered HTTP 200") {
				t.Fatalf("a well-formed escaped code was refused: %s", firstLineOf(resp))
			}
			got := r.sandbox.requests()
			if len(got) != 1 || string(got[0]) != wantRelay(f.Port, code) {
				t.Fatalf("relayed %q, want %q", got, wantRelay(f.Port, code))
			}
			if n := strings.Count(string(got[0]), "\r\n"); n != 4 {
				t.Errorf("the relayed request has %d CRLFs, want its own 4 (request line, Host, Connection, end of head)", n)
			}
		})
	}
}

// TestAFailedRelayEndsTheFlowAndAnswersOnlyWithSnugsText fails if a relay that
// cannot connect (the sandbox's listener is gone) leaves the flow open for a
// second try with the same spent socket, or leaks text from the failure into
// the page beyond snug's own wording.
func TestAFailedRelayEndsTheFlowAndAnswersOnlyWithSnugsText(t *testing.T) {
	r := newRig(t)
	rel := &relayerFunc{left: MaxRelaysPerRun, dial: func(int) (net.Conn, error) {
		return nil, errors.New("connecting to 127.0.0.1:1 inside the sandbox: connection refused")
	}}
	r.b.d.Relayer = rel
	f := r.openFlow(t)
	resp := sendCallback(t, f)
	if !strings.HasPrefix(resp, "HTTP/1.1 502 ") {
		t.Fatalf("want a 502:\n%s", resp)
	}
	if !refuses(f.Port) {
		t.Fatal("the flow is still open after a failed relay")
	}
	if got := rel.dialled(); len(got) != 1 {
		t.Fatalf("dialled %v, want one spent socket", got)
	}
}

// TestTheSandboxsAnswerNeverReachesTheBrowser fails if any byte the sandbox
// sends back, beyond the integer in its status line, reaches the browser; or
// if a hostile answer costs snug more than its stated read bounds. The
// existing TestTheBrowserGetsSnugsPageNotTheSandboxs covers the header set;
// these cover the shape of the answer.
//
// The slow cases run for the real relayDeadline in parallel, because it is a
// constant. They show the 15 s bound holds for a stalled status line and a
// stalled body; they do not show a sandbox that answers each of many relays
// slowly cannot spend three of them.
func TestTheSandboxsAnswerNeverReachesTheBrowser(t *testing.T) {
	t.Run("a huge body is read for at most the discard bound", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		var written atomic.Int64
		finished := make(chan struct{})
		r.b.d.Relayer = &relayerFunc{left: 1, dial: answeringPipe(func(c net.Conn) {
			defer close(finished)
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\n\r\n")
			written.Add(int64(len("HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\n\r\n")))
			chunk := []byte(strings.Repeat("A", 32<<10))
			for range 4000 {
				n, err := c.Write(chunk)
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
		})}
		f := r.openFlow(t)
		resp := sendCallback(t, f)
		if !strings.Contains(resp, "answered HTTP 200") || strings.Contains(resp, "AAAA") {
			t.Fatalf("browser answer:\n%.300s", resp)
		}
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("the sandbox's writer was never released: snug kept reading or kept the socket")
		}
		// 8 KiB of status line plus 64 KiB discarded, spelled as literals so
		// that raising either constant turns this red.
		const bound = 8<<10 + 64<<10
		if w := written.Load(); w > bound {
			t.Errorf("snug took %d bytes of the sandbox's answer, bound is %d", w, bound)
		} else if w < 1024 {
			t.Errorf("control: only %d bytes were written, so the bound was not exercised", w)
		}
	})

	t.Run("a response split in the body is not forwarded", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.sandbox.answer = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" +
			"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nSet-Cookie: a=b; Domain=localhost\r\n\r\n<script>1</script>"
		f := r.openFlow(t)
		resp := sendCallback(t, f)
		if n := strings.Count(resp, "HTTP/1.1 "); n != 1 {
			t.Errorf("the browser got %d responses, want 1:\n%s", n, resp)
		}
		if !strings.Contains(resp, "answered HTTP 200.") {
			t.Errorf("control: the page does not carry the first status:\n%s", resp)
		}
		for _, bad := range []string{"evil.example", "Set-Cookie: a=b", "<script", "302"} {
			if strings.Contains(resp, bad) {
				t.Errorf("browser saw %q:\n%s", bad, resp)
			}
		}
	})

	t.Run("a status line carrying markup shows only its integer", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.sandbox.answer = "HTTP/1.1 200 <script>alert(1)</script>\r\n\r\n"
		f := r.openFlow(t)
		resp := sendCallback(t, f)
		if !strings.Contains(resp, "answered HTTP 200.") || strings.Contains(resp, "script") {
			t.Errorf("browser answer:\n%s", resp)
		}
	})

	t.Run("a non-HTTP answer is a 502 carrying none of it", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.sandbox.answer = "SSH-2.0-EvilServer\r\nsecret-token\r\n"
		f := r.openFlow(t)
		resp := sendCallback(t, f)
		if !strings.HasPrefix(resp, "HTTP/1.1 502 ") || strings.Contains(resp, "EvilServer") || strings.Contains(resp, "secret-token") {
			t.Errorf("browser answer:\n%s", resp)
		}
	})

	t.Run("a status line over the cap is a 502", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.sandbox.answer = "HTTP/1.1 200 " + strings.Repeat("A", 2*maxStatusLine) + "\r\n\r\n"
		f := r.openFlow(t)
		resp := sendCallback(t, f)
		if !strings.HasPrefix(resp, "HTTP/1.1 502 ") || strings.Contains(resp, "AAAA") {
			t.Errorf("browser answer:\n%.300s", resp)
		}
	})

	t.Run("a stalled body ends at the relay deadline with the status", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		released := make(chan struct{})
		r.b.d.Relayer = &relayerFunc{left: 1, dial: answeringPipe(func(c net.Conn) {
			defer close(released)
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
			for {
				if _, err := c.Write([]byte("x")); err != nil {
					return
				}
				time.Sleep(time.Second)
			}
		})}
		f := r.openFlow(t)
		start := time.Now()
		resp := patientBrowse(t, f.Port, callbackReq(f.Port, testState, ""))
		took := time.Since(start)
		if !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("browser answer:\n%s", resp)
		}
		if took < relayDeadline-2*time.Second || took > relayDeadline+3*time.Second {
			t.Errorf("answered after %s, want about the %s relay deadline", took.Round(time.Millisecond), relayDeadline)
		}
		select {
		case <-released:
		case <-time.After(3 * time.Second):
			t.Error("the sandbox's trickling writer was never released after the answer")
		}
	})

	t.Run("a stalled status line is a 502 at the relay deadline", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.b.d.Relayer = &relayerFunc{left: 1, dial: answeringPipe(func(c net.Conn) {
			time.Sleep(relayDeadline + 5*time.Second)
		})}
		f := r.openFlow(t)
		start := time.Now()
		resp := patientBrowse(t, f.Port, callbackReq(f.Port, testState, ""))
		took := time.Since(start)
		if !strings.HasPrefix(resp, "HTTP/1.1 502 ") {
			t.Fatalf("browser answer:\n%s", resp)
		}
		if took < relayDeadline-2*time.Second || took > relayDeadline+3*time.Second {
			t.Errorf("answered after %s, want about the %s relay deadline", took.Round(time.Millisecond), relayDeadline)
		}
	})
}

// TestOpenBudgetHoldsAcrossEveryWayAFlowEnds fails if a flow that ended by
// relay, by TTL or by supersession hands back an open: five opens are five
// opens however each flow ended. The flows end in all three ways in turn, the
// sixth open is refused for the budget (named, not for a pending login), and
// refused opens in between did not spend any.
func TestOpenBudgetHoldsAcrossEveryWayAFlowEnds(t *testing.T) {
	r := newRig(t)
	open := func(i int) Flow {
		t.Helper()
		f := testFlow(t)
		if err := r.b.Handle(f); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		return f
	}
	relay := func(f Flow) {
		t.Helper()
		if resp := patientBrowse(t, f.Port, callbackReq(f.Port, testState, "")); !strings.Contains(resp, "answered HTTP 200") {
			t.Fatalf("relay: %s", resp)
		}
	}

	relay(open(1))
	r.b.d.Listening = func(int) (bool, error) { return false, nil }
	for range 10 {
		if err := r.b.Handle(testFlow(t)); err == nil {
			t.Fatal("a refused open succeeded")
		}
	}
	r.b.d.Listening = func(int) (bool, error) { return true, nil }

	open(2)
	r.clock.Advance(FlowTTL)
	open(3)
	r.clock.Advance(SupersedeAfter)
	open(4)
	r.clock.Advance(SupersedeAfter)
	relay(open(5))

	err := r.b.Handle(testFlow(t))
	if err == nil || err.Error() != "this run has used its 5 login opens; restart snug" {
		t.Fatalf("sixth open: %v", err)
	}
	waitFor(t, func() bool { return len(r.opener.opened()) == MaxOpensPerRun })
	time.Sleep(100 * time.Millisecond)
	if got := len(r.opener.opened()); got != MaxOpensPerRun {
		t.Fatalf("the opener ran %d times, want exactly %d", got, MaxOpensPerRun)
	}
}

// TestARefusedOpenLeavesTheLiveFlowAlone fails if an open that is refused for
// its port (nothing listens) tears down the pending flow it would have
// replaced: the sandbox could otherwise cancel the human's login by spamming
// opens once the supersede window has passed.
func TestARefusedOpenLeavesTheLiveFlowAlone(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	r.clock.Advance(SupersedeAfter + time.Second)
	r.b.d.Listening = func(int) (bool, error) { return false, nil }
	if err := r.b.Handle(testFlow(t)); err == nil {
		t.Fatal("the refused open succeeded")
	}
	if refuses(f.Port) {
		t.Fatal("a refused open closed the live flow's port")
	}
	if resp := patientBrowse(t, f.Port, callbackReq(f.Port, testState, "")); !strings.Contains(resp, "answered HTTP 200") {
		t.Fatalf("the live flow no longer relays: %s", resp)
	}
}

// TestAnExhaustedRelayerRefusesTheOpenEvenWithBudgetLeft fails if Handle opens
// a browser for a flow whose callback could not be relayed because the
// transport has no socket left, however many relays the run's own counter
// still allows.
func TestAnExhaustedRelayerRefusesTheOpenEvenWithBudgetLeft(t *testing.T) {
	r := newRig(t)
	r.sandbox.left = 0
	err := r.b.Handle(testFlow(t))
	if err == nil || !strings.Contains(err.Error(), "relayed its 3 login callbacks") {
		t.Fatalf("err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := r.opener.opened(); len(got) != 0 {
		t.Fatalf("opener ran: %v", got)
	}
}

// TestSandboxChosenTextIsEscapedOnEveryListenerNotice fails if text the
// browser connection or the sandbox chose reaches the run's stderr with a raw
// control or directional rune: ESC, C1 CSI (as UTF-8 and as a lone byte), RLO,
// RLI, DEL, NEL, LS. One rig per case because notices are capped at five;
// the control is that the notice WAS printed (it names the escaped form).
func TestSandboxChosenTextIsEscapedOnEveryListenerNotice(t *testing.T) {
	hostile := map[string]string{
		"ESC":         "\x1b[2J\x1b[31m",
		"CSI as rune": "\u009b2J",
		"lone CSI":    "\x9b2J",
		"RLO":         "\u202eevil",
		"RLI":         "\u2067evil",
		"NEL":         "\u0085",
		"LS":          "\u2028",
		"DEL":         "\x7f",
		"BEL":         "\a",
	}
	for name, h := range hostile {
		t.Run(name, func(t *testing.T) {
			p := func(f Flow) string { return strconv.Itoa(f.Port) }
			type tc struct{ where, req string }
			mk := func(f Flow) []tc {
				port := p(f)
				host := "Host: localhost:" + port + "\r\n"
				return []tc{
					{"method", h + " /callback?code=x&state=" + testState + " HTTP/1.1\r\n" + host + "\r\n"},
					{"path", "GET /" + h + " HTTP/1.1\r\n" + host + "\r\n"},
					{"query key", "GET /callback?" + h + "=1&code=x&state=" + testState + " HTTP/1.1\r\n" + host + "\r\n"},
					{"query segment without =", "GET /callback?" + h + " HTTP/1.1\r\n" + host + "\r\n"},
					{"code", "GET /callback?code=" + h + "&state=" + testState + " HTTP/1.1\r\n" + host + "\r\n"},
					{"duplicate key", "GET /callback?" + h + "=1&" + h + "=2 HTTP/1.1\r\n" + host + "\r\n"},
					{"empty name", "GET /callback?=" + h + " HTTP/1.1\r\n" + host + "\r\n"},
					{"Host header", "GET /callback?code=x&state=" + testState + " HTTP/1.1\r\nHost: " + h + "\r\n\r\n"},
					{"extra header name", "GET /callback?code=x&state=" + testState + " HTTP/1.1\r\n" + host + h + ": v\r\n\r\n"},
					{"request line", "GET /callback?code=x&state=" + testState + " HTTP/1.1 " + h + "\r\n" + host + "\r\n"},
				}
			}
			for i := range mk(Flow{}) {
				r := newRig(t)
				f := r.openFlow(t)
				c := mk(f)[i]
				browse(t, f.Port, c.req)
				out := r.stderr.String()
				if !strings.Contains(out, "snug: login bridge:") {
					t.Errorf("%s: control: no notice was printed, so nothing was checked:\n%q", c.where, out)
					continue
				}
				if rr, bad := forgingIn(out, true); bad {
					t.Errorf("%s: raw forging rune %U reached stderr: %q", c.where, rr, out)
				}
			}
		})
	}
}

// TestASecondCallbackWhileTheFirstIsInFlightIsNotRelayed fails if two
// connections that both pass the predicate can both be relayed: the flow is
// marked relayed before the relay connects, so the second, arriving while the
// first still waits on the sandbox, is answered 404 and spends no socket.
// This is the only test that reaches the flag; a pipelined or sequential
// second request never gets that far.
func TestASecondCallbackWhileTheFirstIsInFlightIsNotRelayed(t *testing.T) {
	r := newRig(t)
	r.sandbox.release = make(chan struct{})
	r.sandbox.received = make(chan struct{}, 2)
	f := r.openFlow(t)
	first := make(chan string)
	go func() { first <- sendCallback(t, f) }()
	<-r.sandbox.received
	second := sendCallback(t, f)
	if !strings.HasPrefix(second, "HTTP/1.1 404 ") || !strings.Contains(second, "already delivered") {
		t.Fatalf("the second callback was not refused as already delivered:\n%s", second)
	}
	close(r.sandbox.release)
	if resp := <-first; !strings.Contains(resp, "answered HTTP 200") {
		t.Fatalf("control: the first callback was not relayed: %s", resp)
	}
	if r.sandbox.dials != 1 || len(r.sandbox.requests()) != 1 {
		t.Fatalf("dials = %d, requests = %d, want 1 and 1", r.sandbox.dials, len(r.sandbox.requests()))
	}
}
