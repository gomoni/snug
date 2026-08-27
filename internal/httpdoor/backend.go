package httpdoor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// roundTripTimeout bounds dial, request write and response read as ONE
// absolute deadline, not one relative timer per phase. A backend that never
// reads the request must not hang the door: the payload controls consumption
// of the request, so a per-phase timer that only starts once the response
// begins never starts at all against a write that blocks forever. A variable,
// not a const, so tests can shrink it instead of waiting out 30s.
var roundTripTimeout = 30 * time.Second

const (
	// maxLineLen bounds one bufio line — the status line, or a single header
	// or trailer line. Far beyond any real status line ("HTTP/1.1 200 OK" is
	// 17 bytes) and small enough that a backend cannot stall the parser by
	// withholding the line terminator forever.
	maxLineLen = 8 * 1024

	// maxHeaderBytes matches net/http.DefaultMaxHeaderBytes (1<<20): a
	// compliant backend's headers already fit under the bound net/http's own
	// server would apply to them.
	maxHeaderBytes = 1 << 20

	// maxHeaderCount bounds header LINES independent of their size. Header
	// byte accounting alone does not stop a backend sending many tiny
	// headers, each of which costs a map entry to parse and hold.
	maxHeaderCount = 256
)

// maxBodyBytes bounds a single response body. Large enough for a dev
// server's built bundle, small enough that one hostile or wedged response
// cannot become an unbounded sink through the door. A variable, like
// roundTripTimeout, so a test can shrink it instead of pushing 256MiB.
var maxBodyBytes int64 = 256 << 20

var hopByHopResponse = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Content-Length":      true, // the door frames its own response to the client
}

var hopByHopRequest = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Connection":    true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true, // the door decides the request's own framing
	"Upgrade":             true, // ServeHTTP already refused any request carrying this
	"Content-Length":      true,
}

// forward dials one fresh backend connection, relays the request, and parses
// the response defensively before any of it reaches the client. It is the
// one place in this package where the client is trusted and the backend is
// not.
func (d *Door) forward(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(roundTripTimeout)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()

	conn, err := d.cfg.Dial(ctx)
	if err != nil {
		d.dialFailed(w, err)
		return
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		d.log("%s: backend connection ignores deadlines: %v", d.cfg.DoorName, err)
	}

	if err := writeRequest(conn, r); err != nil {
		d.deny(w, "the sandbox did not accept the request: %v", err)
		return
	}

	// Plain Read only, via bufio — never ReadMsgUnix. A payload can send
	// SCM_RIGHTS on this socket to hand a descriptor back out through the
	// door; a plain Read (which is all bufio.Reader ever issues) discards
	// ancillary data instead of installing it, where ReadMsgUnix would not.
	br := bufio.NewReaderSize(conn, maxLineLen)

	resp, err := readResponse(br)
	if err != nil {
		d.deny(w, "the sandbox sent a malformed response: %v", err)
		return
	}
	if resp.status == http.StatusSwitchingProtocols {
		// ServeHTTP refuses every request carrying Upgrade, so a 101 here
		// answers a request that never asked for one — a protocol violation,
		// not a feature this version declined to build.
		d.deny(w, "the sandbox sent an unrequested protocol upgrade")
		return
	}

	body, err := framedBody(br, resp.header)
	if err != nil {
		d.deny(w, "the sandbox response framing: %v", err)
		return
	}

	dst := w.Header()
	copyResponseHeaders(dst, resp.header)
	// Set, not merge: the door's own posture, unconditionally, regardless of
	// what the backend tried to send under the same names.
	dst.Set("Content-Security-Policy", "frame-ancestors 'none'")
	dst.Set("Cross-Origin-Resource-Policy", "same-origin")
	w.WriteHeader(resp.status)

	// From here the response is committed: a framing problem discovered now
	// can only be handled by aborting the client connection, not by sending
	// a clean error. http.ErrAbortHandler is net/http's own sentinel for
	// exactly that — a panic no other handler should ever produce.
	n, err := io.Copy(w, io.LimitReader(body, maxBodyBytes+1))
	if err != nil {
		d.log("%s: backend body: %v", d.cfg.DoorName, err)
		panic(http.ErrAbortHandler)
	}
	if n > maxBodyBytes {
		d.log("%s: backend response exceeded the %d-byte cap", d.cfg.DoorName, maxBodyBytes)
		panic(http.ErrAbortHandler)
	}
	if err := checkNoLeftover(br, resp.header); err != nil {
		d.log("%s: %v", d.cfg.DoorName, err)
		panic(http.ErrAbortHandler)
	}
}

// dialFailed distinguishes the one case the payload can cause on purpose —
// calling shutdown() on the socket the sandbox was handed, or simply never
// accepting on it again, both of which make a later connect() come back
// ECONNREFUSED even though the listening socket still exists — from every
// other reason the backend is unreachable. Conflating them would send a
// human "backend not ready" when the fix is to restart the run.
func (d *Door) dialFailed(w http.ResponseWriter, err error) {
	if errors.Is(err, syscall.ECONNREFUSED) {
		d.log("%s: refused: %v", d.cfg.DoorName, err)
		http.Error(w, d.cfg.DoorName+": the sandbox shut this door; restart the run", http.StatusServiceUnavailable)
		return
	}
	d.log("%s: cannot reach the sandbox: %v", d.cfg.DoorName, err)
	http.Error(w, d.cfg.DoorName+": cannot reach the sandbox (backend not ready): "+err.Error(), http.StatusBadGateway)
}

// deny is used only before any byte of the response has reached the client,
// so a clean status and body are still possible. Connection: close makes
// net/http drop the client connection after replying rather than keeping it
// alive on a door that just proved it cannot parse this backend.
func (d *Door) deny(w http.ResponseWriter, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	d.log("%s: %s", d.cfg.DoorName, msg)
	w.Header().Set("Connection", "close")
	http.Error(w, d.cfg.DoorName+": "+msg, http.StatusBadGateway)
}

// writeRequest relays the client's request line, headers and body to the
// backend. Hop-by-hop headers are dropped; framing is decided here, not
// copied from the client, because Content-Length and Transfer-Encoding must
// agree with whatever this function actually writes.
func writeRequest(conn io.Writer, r *http.Request) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	// Host EXPLICITLY, and it is not optional: net/http moves the inbound Host
	// header into r.Host and deletes it from r.Header, so a loop over r.Header
	// emits a request with no Host line at all — which any HTTP/1.1 backend is
	// entitled to reject. MEASURED against a Go http.Server inside the sandbox:
	// the backend answered "400 Bad Request: missing required Host header" and
	// the door forwarded that verbatim, so every request failed with the
	// backend's own error and the door looked like it was working.
	//
	// The value is r.Host, which ServeHTTP has already checked equals the door's
	// own address. Forwarding the value that was validated is what makes "the
	// inbound Host is allowlisted before any rewrite" true rather than a claim
	// about a header nobody sent.
	fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	for k, vs := range r.Header {
		if hopByHopRequest[k] || http.CanonicalHeaderKey(k) == "Host" {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	switch {
	case r.ContentLength > 0:
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", r.ContentLength)
	case r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody:
		buf.WriteString("Transfer-Encoding: chunked\r\n")
	}
	buf.WriteString("\r\n")
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}

	switch {
	case r.ContentLength > 0:
		_, err := io.CopyN(conn, r.Body, r.ContentLength)
		return err
	case r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody:
		cw := httputil.NewChunkedWriter(conn)
		if _, err := io.Copy(cw, r.Body); err != nil {
			return err
		}
		if err := cw.Close(); err != nil {
			return err
		}
		_, err := io.WriteString(conn, "\r\n")
		return err
	}
	return nil
}

type backendResponse struct {
	status int
	header http.Header
}

// readResponse parses the status line and headers of a response the door
// treats as hostile. It never delegates to net/http's own response reader:
// that reader deliberately RESOLVES a Content-Length/Transfer-Encoding
// conflict (RFC 7230 §3.3.3's "the Transfer-Encoding overrides the
// Content-Length" rule, applied by dropping Content-Length) rather than
// refusing it, which is the opposite of what this door needs from an
// adversarial backend.
func readResponse(br *bufio.Reader) (*backendResponse, error) {
	line, err := readBoundedLine(br)
	if err != nil {
		return nil, fmt.Errorf("status line: %w", err)
	}
	proto, rest, ok := strings.Cut(string(line), " ")
	if !ok || !strings.HasPrefix(proto, "HTTP/1.") {
		return nil, fmt.Errorf("malformed status line %q", line)
	}
	codeStr, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		return nil, fmt.Errorf("malformed status code in %q", line)
	}
	h, err := readHeaderBlock(br)
	if err != nil {
		return nil, err
	}
	return &backendResponse{status: code, header: h}, nil
}

// readBoundedLine reads one CRLF-terminated line, bounded to maxLineLen by
// the bufio.Reader's own buffer size. bufio.Reader.ReadString would keep
// growing an accumulator across fills until it found the delimiter or the
// connection died — it does NOT bound total line length by the buffer size —
// so this uses ReadSlice and treats ErrBufferFull as the refusal it is meant
// to be.
func readBoundedLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("line exceeds %d bytes", maxLineLen)
		}
		return nil, err
	}
	line = bytes.TrimRight(line, "\r\n")
	// ReadSlice's return value is only valid until the reader's next fill;
	// readHeaderBlock calls this in a loop, so it must be copied out.
	out := make([]byte, len(line))
	copy(out, line)
	return out, nil
}

// readHeaderBlock reads header (or trailer) lines up to a blank line,
// bounding both the number of lines and their total bytes (requirement 14).
// Obsolete header line-folding (a continuation line starting with whitespace)
// is not supported and is rejected as malformed rather than joined — folding
// is deprecated by RFC 7230 precisely because ambiguity in how it is
// unfolded is a request-smuggling vector, and refusing it outright removes
// the ambiguity rather than picking a resolution.
func readHeaderBlock(br *bufio.Reader) (http.Header, error) {
	h := make(http.Header)
	var total, count int
	for {
		line, err := readBoundedLine(br)
		if err != nil {
			return nil, fmt.Errorf("header line: %w", err)
		}
		total += len(line) + 2
		if total > maxHeaderBytes {
			return nil, fmt.Errorf("headers exceed %d bytes", maxHeaderBytes)
		}
		if len(line) == 0 {
			return h, nil
		}
		count++
		if count > maxHeaderCount {
			return nil, fmt.Errorf("more than %d header lines", maxHeaderCount)
		}
		key, val, ok := bytes.Cut(line, []byte(":"))
		if !ok || len(key) == 0 || bytes.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("malformed header line %q", line)
		}
		h.Add(string(key), strings.TrimSpace(string(val)))
	}
}

// framedBody picks the response body's framing and returns an UNCAPPED
// reader for it; forward() applies the body-size cap uniformly on top.
//
// Content-Length and Transfer-Encoding both present is refused outright
// (requirement 9) rather than resolved by preferring one, which is the
// choice net/http's own transfer.go makes and the one this door exists to
// not make on a hostile backend's say-so.
func framedBody(br *bufio.Reader, h http.Header) (io.Reader, error) {
	cl, hasCL := h["Content-Length"]
	te, hasTE := h["Transfer-Encoding"]
	if hasCL && hasTE {
		return nil, errors.New("response carries both Content-Length and Transfer-Encoding")
	}
	if hasTE {
		if len(te) != 1 || !strings.EqualFold(te[0], "chunked") {
			return nil, fmt.Errorf("unsupported Transfer-Encoding %q", te)
		}
		return httputil.NewChunkedReader(br), nil
	}
	if hasCL {
		if len(cl) != 1 {
			return nil, fmt.Errorf("multiple Content-Length headers %q", cl)
		}
		n, err := strconv.ParseInt(cl[0], 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid Content-Length %q", cl[0])
		}
		if n > maxBodyBytes {
			return nil, fmt.Errorf("Content-Length %d exceeds the %d-byte cap", n, maxBodyBytes)
		}
		return io.LimitReader(br, n), nil
	}
	// Neither header: a valid HTTP/1.0-style framing where the body runs
	// until the backend closes the connection. Since every backend
	// connection is one-shot and closed by forward()'s defer regardless,
	// there is nothing further to frame here.
	return br, nil
}

// checkNoLeftover reports whether the backend held back data beyond the
// response it declared. For a chunked response this first drains the
// trailer section httputil.NewChunkedReader deliberately does not consume
// (its own doc: it stops at the terminal 0-length chunk) — without draining
// it, a well-formed empty trailer would be misread as leftover on every
// chunked response. Buffered() is then checked without issuing a further
// Read, so a backend that never sends anything more is never blocked on.
func checkNoLeftover(br *bufio.Reader, h http.Header) error {
	if te, ok := h["Transfer-Encoding"]; ok && len(te) == 1 && strings.EqualFold(te[0], "chunked") {
		if _, err := readHeaderBlock(br); err != nil {
			return fmt.Errorf("malformed chunk trailer: %w", err)
		}
	}
	if n := br.Buffered(); n > 0 {
		return fmt.Errorf("backend sent %d bytes beyond the declared response", n)
	}
	return nil
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHopResponse[k] {
			continue
		}
		if strings.HasPrefix(k, "Access-Control-Allow-") {
			// A hostile backend cannot opt the browser into reading its own
			// response cross-origin; that decision is the door's alone.
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
