package dockerproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// stdoutMarker stands in for a container's stdout: the bytes the engine
// writes on the connection hijack() relays to the client.
const stdoutMarker = "regression-marker-hijack-halfclose"

// TestHijackDeliversStdoutAfterAnImmediateClientHalfClose is the permanent
// regression for the bug fixed in hijack(): waiting on `<-done` from two
// io.Copy goroutines racing to finish FIRST, rather than on the
// engine-to-client direction specifically.
//
// A client that has nothing to send half-closes its write side as soon as it
// has written its headers -- foreground `docker run` with no `-i`, and
// `docker run -i ... </dev/null` both do this. That makes
// io.Copy(up, client) return almost at once, and under the old code that
// alone made hijack() return and its deferred Close()s tear the connection to
// the engine down -- before the container's stdout had crossed it. Measured
// (`snug -p @podman-build -p @net`, image built in the same run):
//
//	docker run --rm localhost/probe:1 cat /marker            -> no output, exit 0
//	docker run --rm localhost/probe:1 cat /marker </dev/null -> no output, exit 0
//	(sleep 3; echo) | docker run --rm -i ... cat /marker     -> "hi"
//
// The fake engine here reproduces the same shape deliberately, delaying its
// write until well after it has observed the client's EOF, so that an old-code
// run has every opportunity to have already closed the connection by then.
func TestHijackDeliversStdoutAfterAnImmediateClientHalfClose(t *testing.T) {
	sawClientEOF := make(chan struct{})
	sock, _ := startRecordedWith(t, ownLabel, &recorder{
		inspect: inspectWithLabels(map[string]string{"snug.run": ownValue}),
		hijack:  fakeEngineStdoutAfterEOF(t, sawClientEOF),
	})

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodPost, "http://d/v1.41/containers/mine/start",
		strings.NewReader(""))
	req.Header.Set("Upgrade", "tcp")
	req.Header.Set("Connection", "Upgrade")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	// The shape measured above: nothing more to send, so the write side closes
	// right after the headers. The short wait first is a harness fact, not a
	// weakening of it: net/http's server watches the connection for an early
	// client close to cancel the request context, and a half-close that lands
	// before the ownership gate's own inspect call (which also runs on this
	// context, and precedes hijack() entirely) cancels that call instead of
	// exercising the race under test.
	time.Sleep(20 * time.Millisecond)
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("client half-close: %v", err)
	}

	// CONTROL: the engine must actually see the half-close, or a "fix" that
	// simply stopped closing anything would pass the marker assertion below
	// while hanging every container that reads its stdin to EOF.
	select {
	case <-sawClientEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("the fake engine never observed the client's write-side EOF, so the " +
			"assertion below proves nothing about the fix")
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(conn)
	if string(got) != stdoutMarker {
		t.Errorf("client received %q after half-closing immediately, want the engine's "+
			"stdout %q -- hijack() must wait on the engine-to-client copy, not on whichever "+
			"direction of the two finishes first", got, stdoutMarker)
	}
}

// fakeEngineStdoutAfterEOF is a recorder.hijack that plays the engine's side
// of an attach: it takes the raw connection over, reads the client's stream to
// EOF (closing sawClientEOF once it has), and only then writes stdoutMarker.
// The delay after EOF is what makes an old-code run fail deterministically
// rather than by luck of the scheduler -- by the time it fires, hijack() has
// long since returned if it woke on whichever copy finished first.
func fakeEngineStdoutAfterEOF(t *testing.T, sawClientEOF chan struct{}) func(w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/start") {
			return false
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("fake engine: ResponseWriter does not support Hijack")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatalf("fake engine: Hijack: %v", err)
		}
		go func() {
			defer conn.Close()
			// buf.Reader, not conn directly: net/http may already have
			// buffered bytes past the request headers that a raw conn.Read
			// would miss.
			_, _ = io.Copy(io.Discard, buf.Reader)
			close(sawClientEOF)
			time.Sleep(50 * time.Millisecond)
			_, _ = conn.Write([]byte(stdoutMarker))
		}()
		return true
	}
}
