package httpdoor

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// echoBackend returns a Dial that always succeeds and answers with a fixed
// HTTP/1.1 response, counting how many times it was called.
func echoBackend(t *testing.T, raw string) (dial func(context.Context) (net.Conn, error), calls *int32) {
	t.Helper()
	calls = new(int32)
	dial = func(ctx context.Context) (net.Conn, error) {
		atomic.AddInt32(calls, 1)
		client, server := net.Pipe()
		go func() {
			// Drain and discard whatever the client writes so its Write
			// calls do not block on the unbuffered pipe.
			io.Copy(io.Discard, server)
		}()
		go func() {
			io.WriteString(server, raw)
			server.Close()
		}()
		return client, nil
	}
	return dial, calls
}

func testDoor(t *testing.T, dial func(context.Context) (net.Conn, error)) *Door {
	t.Helper()
	cfg := Config{
		Addr:     netip.MustParseAddrPort("127.64.1.2:8099"),
		Token:    "tok123",
		DoorName: "web",
		Dial:     dial,
		Log:      &bytes.Buffer{},
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestNewValidates(t *testing.T) {
	base := Config{
		Addr:     netip.MustParseAddrPort("127.64.1.2:8099"),
		Token:    "tok",
		DoorName: "web",
		Dial:     func(context.Context) (net.Conn, error) { return nil, nil },
		Log:      &bytes.Buffer{},
	}

	cases := []struct {
		name   string
		mutate func(Config) Config
	}{
		{"zero addr", func(c Config) Config { c.Addr = netip.AddrPort{}; return c }},
		{"zero port", func(c Config) Config { c.Addr = netip.MustParseAddrPort("127.64.1.2:0"); return c }},
		{"empty token", func(c Config) Config { c.Token = ""; return c }},
		{"empty door name", func(c Config) Config { c.DoorName = ""; return c }},
		{"nil dial", func(c Config) Config { c.Dial = nil; return c }},
		{"nil log", func(c Config) Config { c.Log = nil; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.mutate(base)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}

	if _, err := New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestSecFetchSite(t *testing.T) {
	cases := []struct {
		value string
		want  bool
		why   string
	}{
		{"", true, "curl and older browsers send no header at all; absence is not a lie"},
		{"none", true, "top-level navigation typed by the human"},
		{"same-origin", true, "a fetch from the door's own origin"},
		{"cross-site", false, "the one shape this check exists to catch"},
		{"same-site", false, "still a different origin than the door's own"},
		{"garbled", false, "an unrecognised value refuses; it is never read as the nearest known one"},
	}
	for _, tc := range cases {
		if got := secFetchSiteAllowed(tc.value); got != tc.want {
			t.Errorf("secFetchSiteAllowed(%q) = %v, want %v (%s)", tc.value, got, tc.want, tc.why)
		}
	}
}

func TestTheTokenParameterIsExactAndIsStrippedBeforeTheApp(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, tc := range []struct {
		name, query string
		want        int
		location    string
		why         string
	}{
		{"exact token at the root", "?snug-token=tok123", http.StatusSeeOther, "/",
			"the ordinary case: bootstrap, then the app owns /"},
		{"token beside another parameter", "?a=1&snug-token=tok123&b=2", http.StatusSeeOther, "/?a=1&b=2",
			"only the token is removed; the app's own query survives"},
		{"token on a sub-path", "/deep/page?snug-token=tok123", http.StatusSeeOther, "/deep/page",
			"a human may bookmark a deep link"},
		{"a prefix of the token", "?snug-token=tok12", http.StatusForbidden, "",
			"a near miss is a miss; comparison is exact"},
		{"the token with something appended", "?snug-token=tok123x", http.StatusForbidden, "",
			"prefix collision must not admit a longer value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := srv.URL + tc.query
			if strings.HasPrefix(tc.query, "/") {
				u = srv.URL + tc.query
			}
			req, _ := http.NewRequest(http.MethodGet, u, nil)
			req.Host = addr
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d (%s)", resp.StatusCode, tc.want, tc.why)
			}
			if tc.location != "" {
				if got := resp.Header.Get("Location"); got != tc.location {
					t.Errorf("Location = %q, want %q (%s)", got, tc.location, tc.why)
				}
			}
		})
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Error("a bootstrap or a refusal reached the backend; neither should")
	}
}

// doorServer starts a real listener via httptest, driven by the Door's
// Handler, so admission and connection-level behaviour (headers actually
// hitting the wire, connections actually closing) can be exercised for real
// rather than through ResponseRecorder.
func doorServer(t *testing.T, d *Door) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return srv
}

func TestAdmissionRefusals(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	d.origin = "http://127.64.1.2:8099"
	d.host = "127.64.1.2:8099"
	srv := doorServer(t, d)

	cases := []struct {
		name   string
		mutate func(*http.Request)
		why    string
	}{
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, "cross-site initiator"},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, "wrong origin"},
		{"wrong host", func(r *http.Request) { r.Host = "evil.example:8099" }, "DNS-rebinding defence"},
		{"no credential at all", func(r *http.Request) { r.Header.Del("Cookie") }, "neither token nor cookie"},
		{"wrong token in the cookie", func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: doorCookie, Value: "nottoken"})
		}, "the cookie is the credential after the bootstrap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			// The token is a bootstrap that plants a cookie; a request meant to reach
			// the BACKEND carries the cookie and lives at the app's own path.
			req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
			req.Host = "127.64.1.2:8099"
			tc.mutate(req)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403 (%s)", tc.name, resp.StatusCode, tc.why)
			}
		})
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Errorf("backend dialled %d times on refused requests, want 0", got)
	}
}

func TestConnectAndAbsoluteFormRefused(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	// Absolute-form request target: net/http's own client never issues one
	// against a plain (non-proxy) URL, so this is written directly to the
	// raw connection.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + addr + "/tok123/ HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("absolute-form target: status = %d, want 403", resp.StatusCode)
	}

	// CONNECT.
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn2.Close()
	req2 := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
	if _, err := conn2.Write([]byte(req2)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp2, err := http.ReadResponse(bufio.NewReader(conn2), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT: status = %d, want 403", resp2.StatusCode)
	}

	if got := atomic.LoadInt32(calls); got != 0 {
		t.Errorf("backend dialled %d times on refused requests, want 0", got)
	}
}

func TestUpgradeRefusedLoudly(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = addr
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "WebSocket and SSE are not proxied yet") {
		t.Errorf("body = %q, want it to name the limitation", body)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Errorf("backend dialled %d times for a refused upgrade, want 0", got)
	}
}

func TestCORSStrippedAndSecurityHeadersAdded(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Access-Control-Allow-Credentials: true\r\n" +
		"X-From-Backend: yes\r\n" +
		"Content-Length: 2\r\n\r\nhi"
	dial, _ := echoBackend(t, raw)
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = addr
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("Access-Control-Allow-Origin leaked through: %q", v)
	}
	if v := resp.Header.Get("Access-Control-Allow-Credentials"); v != "" {
		t.Errorf("Access-Control-Allow-Credentials leaked through: %q", v)
	}
	if v := resp.Header.Get("X-From-Backend"); v != "yes" {
		t.Errorf("ordinary backend header dropped: got %q", v)
	}
	if v := resp.Header.Get("Content-Security-Policy"); v != "frame-ancestors 'none'" {
		t.Errorf("Content-Security-Policy = %q", v)
	}
	if v := resp.Header.Get("Cross-Origin-Resource-Policy"); v != "same-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q", v)
	}
}

func TestOneRequestOneFreshBackendConnection(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	client := bootstrappedClient(t, srv, d, addr)
	// The bootstrap's own redirect is followed and reaches the backend, so the
	// count starts here rather than at zero-requests-ago.
	atomic.StoreInt32(calls, 0)
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		req.Host = addr
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := atomic.LoadInt32(calls); got != 5 {
		t.Errorf("backend dialled %d times for 5 client requests, want 5 (no pooling)", got)
	}
}

func TestECONNREFUSEDNamesTheFix(t *testing.T) {
	// Wrapped the way net.Dial reports a real ECONNREFUSED, so errors.Is
	// must see through the wrapping the way it would from a genuine
	// unix-socket Dial against a socket the sandbox shut down.
	dial := func(context.Context) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	client := bootstrappedClient(t, srv, d, addr)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Host = addr
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "shut this door") || !strings.Contains(string(body), "restart the run") {
		t.Errorf("body = %q, want it to name the fix, not \"backend not ready\"", body)
	}
	if strings.Contains(string(body), "backend not ready") {
		t.Errorf("body = %q, must not read as \"backend not ready\"", body)
	}
}

func TestBindRefusesOnCollision(t *testing.T) {
	addr := netip.MustParseAddrPort("127.64.9.9:0")
	ln, err := net.Listen("tcp", "127.64.9.9:0")
	if err != nil {
		t.Skipf("cannot bind 127.64.9.9 in this environment: %v", err)
	}
	defer ln.Close()
	addr = netip.MustParseAddrPort(ln.Addr().String())

	dial, _ := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	d, err := New(Config{Addr: addr, Token: "t", DoorName: "web", Dial: dial, Log: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = d.Serve(ctx)
	if err == nil {
		t.Fatal("Serve on a collided address succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), addr.String()) {
		t.Errorf("error %q does not name the address", err)
	}
}

func TestServeClosesListenerOnCtxDone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.64.9.10:0")
	if err != nil {
		t.Skipf("cannot bind 127.64.9.10 in this environment: %v", err)
	}
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()

	dial, _ := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	d, err := New(Config{Addr: addr, Token: "t", DoorName: "web", Dial: dial, Log: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- d.Serve(ctx) }()

	// Wait for the bind to happen: a second bind on the same address must
	// fail while the door is up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l, err := net.Listen("tcp", addr.String()); err != nil {
			break
		} else {
			l.Close()
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx was cancelled")
	}

	// Nothing left listening.
	l, err := net.Listen("tcp", addr.String())
	if err != nil {
		t.Fatalf("address still bound after Serve returned: %v", err)
	}
	l.Close()
}

// bootstrappedClient does what a browser does on the URL a human types: fetch
// the token path once, keep the cookie it sets, and follow the redirect. Every
// test that wants to reach the BACKEND needs it, because the token URL itself
// never reaches the backend — it is a redirect that plants the cookie.
//
// The token cannot stay in the path: measured through a real sandbox, a page
// served under /<token>/ makes the browser request /style.css at the origin
// ROOT for every absolute reference, which arrives with no token and is refused
// 403 before the backend sees it. That breaks every framework emitting absolute
// URLs, so the token bootstraps a cookie and the app owns "/".
func bootstrappedClient(t *testing.T, srv *httptest.Server, d *Door, addr string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/?"+tokenParam+"="+d.cfg.Token, nil)
	req.Host = addr
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return client
}

func TestTheTokenBootstrapsACookieAndRedirectsToTheRoot(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	// No redirect following: this asserts the bootstrap itself.
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app/page?"+tokenParam+"="+d.cfg.Token, nil)
	req.Host = addr
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303: the token URL must redirect rather than serve, or the "+
			"app ends up living under the token and every absolute URL it emits misses it",
			resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/app/page" {
		t.Errorf("Location = %q, want %q — the token is stripped and the rest of the path kept",
			got, "/app/page")
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Error("the bootstrap request reached the backend; it must not, it is snug's own redirect")
	}
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == doorCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatal("no cookie was set, so the next request carries no credential at all")
	}
	if found.Value != d.cfg.Token {
		t.Errorf("cookie value = %q, want the token", found.Value)
	}
	if !found.HttpOnly {
		t.Error("cookie is not HttpOnly: the page's own scripts can read the credential back out")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Error("cookie is not SameSite=Strict, which is what keeps a cross-site initiator from " +
			"carrying the credential at all")
	}
}

func TestAfterBootstrapTheAppOwnsTheWholePath(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	client := bootstrappedClient(t, srv, d, addr)
	// The request a browser really makes for <link href="/style.css">.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/style.css", nil)
	req.Host = addr
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an absolute asset path got %d after the bootstrap. This is the whole reason "+
			"the token is a cookie and not a path prefix", resp.StatusCode)
	}
	if atomic.LoadInt32(calls) == 0 {
		t.Error("the request never reached the backend")
	}
}

func TestWithoutTheCookieOrTheTokenNothingIsAdmitted(t *testing.T) {
	dial, calls := echoBackend(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	for _, tc := range []struct{ name, cookie string }{
		{"no cookie at all", ""},
		{"a wrong token in the cookie", "not-the-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/style.css", nil)
			req.Host = addr
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: doorCookie, Value: tc.cookie})
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Error("an unadmitted request reached the backend")
	}
}
