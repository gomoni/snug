package httpdoor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawBackend returns a Dial whose peer, on each accepted connection, drains
// whatever the client writes and then writes raw back verbatim — a
// hostile-backend stand-in that speaks exactly the bytes the test gives it,
// nothing more.
func rawBackend(raw string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			io.Copy(io.Discard, server)
		}()
		go func() {
			io.WriteString(server, raw)
			server.Close()
		}()
		return client, nil
	}
}

func doorClient(t *testing.T, raw string) (*httptest.Server, *Door) {
	t.Helper()
	d := testDoor(t, rawBackend(raw))
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr
	return srv, d
}

func TestFramingConflictClosesClientConnection(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nhi"
	srv, _ := doorClient(t, raw)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (framing conflict caught before any body was sent)", resp.StatusCode)
	}
	// net/http's own client consumes and strips "Connection: close" from
	// resp.Header while setting resp.Close — the field is the verified way
	// to observe it from the client side, not the header map.
	if !resp.Close {
		t.Error("resp.Close = false, want true so the client does not reuse this connection")
	}
}

func TestUnparseableChunkAbortsClientConnection(t *testing.T) {
	// "zzzz" is not a valid hex chunk-size.
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzzzz\r\ndata\r\n0\r\n\r\n"
	srv, _ := doorClient(t, raw)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := srv.Client().Do(req)
	if err != nil {
		// A malformed status/header phase can fail Do() outright, which is
		// an acceptable way to observe "refused".
		return
	}
	defer resp.Body.Close()
	_, readErr := io.ReadAll(resp.Body)
	if readErr == nil {
		t.Fatal("reading the body of an unparseable chunked response succeeded, want an error (aborted connection)")
	}
}

func TestLeftoverBytesAbortClientConnection(t *testing.T) {
	// A well-formed Content-Length response immediately followed by more
	// bytes on the SAME connection: a one-shot backend has no business
	// sending anything after its declared response. panic(http.ErrAbortHandler)
	// drops the connection outright — net/http's own server does not flush
	// buffered-but-unsent response bytes before closing on that panic — so
	// the observable failure is the connection dying, not a body trimmed to
	// exactly "hi": either Do() itself fails, or reading the body does, but
	// what must never happen is "hiEXTRA-UNEXPECTED-BYTES" reaching the
	// client as if it were a normal, complete response.
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA-UNEXPECTED-BYTES"
	srv, _ := doorClient(t, raw)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := srv.Client().Do(req)
	if err != nil {
		return // the connection died before headers arrived: acceptable
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr == nil && string(body) == "hiEXTRA-UNEXPECTED-BYTES" {
		t.Fatalf("leftover bytes were forwarded to the client as body: %q", body)
	}
	if readErr == nil && string(body) != "hi" {
		t.Fatalf("body = %q, want either the declared %q or a read error", body, "hi")
	}

	// The connection must not be silently kept alive and reused as if
	// nothing had happened: a second request on a fresh client connection
	// still works, proving the door detected and logged the anomaly rather
	// than wedging.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req2.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req2.Host = strings.TrimPrefix(srv.URL, "http://")
	resp2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close()
}

func TestChunkedResponseWithEmptyTrailerIsNotLeftover(t *testing.T) {
	// The well-formed minimal ending of a chunked message: the terminal
	// "0\r\n" chunk-size line plus the blank line closing an empty trailer
	// section. This must NOT be misread as leftover data.
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
	srv, _ := doorClient(t, raw)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading a well-formed chunked response failed: %v", err)
	}
	if string(body) != "hi" {
		t.Errorf("body = %q, want %q", body, "hi")
	}
}

func TestUnrequestedUpgradeResponseRefused(t *testing.T) {
	raw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	srv, _ := doorClient(t, raw)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	// The token is a bootstrap that plants a cookie; a request meant to reach
	// the BACKEND carries the cookie and lives at the app's own path.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502: a 101 answering a request with no Upgrade header is a protocol violation", resp.StatusCode)
	}
}

// TestBackendThatNeverReadsDoesNotHangTheDoor is the payload shape
// requirement 11 exists for: a backend that never reads the request, so a
// response-phase timeout alone would never even start counting.
func TestBackendThatNeverReadsDoesNotHangTheDoor(t *testing.T) {
	old := roundTripTimeout
	roundTripTimeout = 200 * time.Millisecond
	defer func() { roundTripTimeout = old }()

	dial := func(ctx context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		// The backend end never reads and never writes: any Write on the
		// client end blocks until the door's deadline fires, and the
		// subsequent Read for a response never gets anything either.
		go func() {
			<-ctx.Done()
			server.Close()
		}()
		return client, nil
	}
	d := testDoor(t, dial)
	srv := doorServer(t, d)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d.origin = "http://" + addr
	d.host = addr

	start := time.Now()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", bytes.NewReader(make([]byte, 1<<20)))
	// The cookie, not the token path: a POST carrying the token would be
	// answered by the bootstrap redirect and never reach the backend at all —
	// which is exactly what this test needs to reach.
	req.AddCookie(&http.Cookie{Name: doorCookie, Value: "tok123"})
	req.Host = addr
	req.ContentLength = 1 << 20
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("request took %v, want it bounded by roundTripTimeout (%v), not the client's own 5s timeout", elapsed, roundTripTimeout)
	}
	if err != nil {
		// The client observing a connection reset/EOF because the door
		// aborted is an acceptable way for this to surface too.
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want a refusal in the 5xx range", resp.StatusCode)
	}
}

func TestReadBoundedLineEnforcesMaxLineLen(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", maxLineLen+1)+"\r\n"), maxLineLen)
	if _, err := readBoundedLine(br); err == nil {
		t.Fatal("expected an error for a line exceeding maxLineLen")
	}
}

func TestReadHeaderBlockEnforcesCountAndByteBounds(t *testing.T) {
	var overCount strings.Builder
	for i := 0; i < maxHeaderCount+1; i++ {
		fmt.Fprintf(&overCount, "X-%d: v\r\n", i)
	}
	overCount.WriteString("\r\n")
	br := bufio.NewReaderSize(strings.NewReader(overCount.String()), maxLineLen)
	if _, err := readHeaderBlock(br); err == nil {
		t.Fatal("expected an error for more than maxHeaderCount header lines")
	}

	var overBytes strings.Builder
	// Individually-short lines whose sum exceeds maxHeaderBytes.
	line := "X-Pad: " + strings.Repeat("p", maxLineLen-16) + "\r\n"
	for i := 0; i*len(line) < maxHeaderBytes+len(line); i++ {
		overBytes.WriteString(line)
	}
	overBytes.WriteString("\r\n")
	br2 := bufio.NewReaderSize(strings.NewReader(overBytes.String()), maxLineLen)
	if _, err := readHeaderBlock(br2); err == nil {
		t.Fatal("expected an error for headers exceeding maxHeaderBytes total")
	}
}

func TestFramedBodyRejectsOversizedContentLength(t *testing.T) {
	h := http.Header{"Content-Length": {fmt.Sprintf("%d", int64(maxBodyBytes)+1)}}
	br := bufio.NewReader(strings.NewReader(""))
	if _, err := framedBody(br, h); err == nil {
		t.Fatal("expected a refusal for a Content-Length beyond the body cap")
	}
}

func TestOversizedBodyAbortsClientConnection(t *testing.T) {
	body := strings.Repeat("x", 1024)
	// No Content-Length: a close-delimited body, so the over-cap byte is
	// discovered only while streaming, not by the upfront Content-Length
	// check — this exercises the mid-stream abort path.
	raw := "HTTP/1.1 200 OK\r\n\r\n" + body
	d := testDoor(t, rawBackend(raw))
	// Shrink the cap so the test does not have to push real megabytes.
	oldCap := maxBodyBytes
	maxBodyBytes = int64(len(body) - 1)
	defer func() { maxBodyBytes = oldCap }()
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
		return
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("reading a body over the cap succeeded, want the connection aborted")
	}
}
