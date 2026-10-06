package cli

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
)

// loginForgingIn is the first rune of s that could author, erase or reverse a
// line on a terminal. Spelled here and not asked of policy.IsForgingRune, so
// the tests below keep their meaning if that predicate moves.
func loginForgingIn(s string) (rune, bool) {
	if !utf8.ValidString(s) {
		return utf8.RuneError, true
	}
	for _, r := range s {
		switch {
		case r == '\n':
		case unicode.IsControl(r), r == '\u2028', r == '\u2029',
			r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069':
			return r, true
		}
	}
	return 0, false
}

func runReader(in string) (handled []loginbridge.Flow, stderr string) {
	var out bytes.Buffer
	readLoginLines(strings.NewReader(in), &out, func(f loginbridge.Flow) error {
		handled = append(handled, f)
		return nil
	})
	return handled, out.String()
}

// TestLoginReaderFramingNeverOpensWhatItShouldNot fails if the FIFO reader
// hands the handler anything but a complete, newline-terminated, in-bounds
// line that ParseAuthorize accepts. The cases are the framings a hostile
// writer controls: no newline, a joined second line, CR, NUL, a line at and
// over the 4096-byte cap, and an over-cap line whose tail is itself a valid
// URL (which must be discarded with the line, not parsed as its own).
//
// A valid URL followed by a newline and more text is TWO lines to the
// reader: the first is exactly what the shim writes and is handed on, the
// text after it is refused. The one-string form ("valid\nmore") is refused
// by ParseAuthorize itself, in internal/loginbridge.
func TestLoginReaderFramingNeverOpensWhatItShouldNot(t *testing.T) {
	pad := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		name       string
		in         string
		wantOpened int
		wantSay    string // substring of stderr, "" for silence
	}{
		{"valid, no newline, then EOF", goodLoginURL, 0, ""},
		{"valid, newline, more text", goodLoginURL + "\nhttps://evil.example/\n", 1, "not the Claude login URL"},
		{"valid, newline, more text, no final newline", goodLoginURL + "\nhttps://evil.example/", 1, ""},
		{"more text, newline, valid", "https://evil.example/\n" + goodLoginURL + "\n", 1, "not the Claude login URL"},
		{"valid then CRLF", goodLoginURL + "\r\n", 0, "0x0d"},
		{"valid then NUL", goodLoginURL + "\x00\n", 0, "0x00"},
		{"valid then space", goodLoginURL + " \n", 0, "0x20"},
		{"two valid URLs on one line", goodLoginURL + goodLoginURL + "\n", 0, "more than one"},
		{"valid after a leading space", " " + goodLoginURL + "\n", 0, "0x20"},
		{"empty line", "\n", 0, "empty line"},
		{"4096 bytes: in the cap, over the URL's own", pad(4096) + "\n", 0, "2048"},
		{"4097 bytes: over the cap", pad(4097) + "\n", 0, "longer than 4096"},
		{"over the cap, tail is a valid URL", pad(5000) + goodLoginURL + "\n", 0, "longer than 4096"},
		{"over the cap, valid line after", pad(9000) + "\n" + goodLoginURL + "\n", 1, "longer than 4096"},
		{"over the cap and no newline, EOF", pad(9000), 0, "longer than 4096"},
		{"valid URL padded past 2048", goodLoginURL + "&x=" + pad(2100) + "\n", 0, "2048"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handled, out := runReader(c.in)
			if len(handled) != c.wantOpened {
				t.Errorf("handed %d flows to the opener, want %d\nstderr: %s", len(handled), c.wantOpened, out)
			}
			if c.wantSay == "" && out != "" {
				t.Errorf("want silence, stderr: %s", out)
			}
			if !strings.Contains(out, c.wantSay) {
				t.Errorf("stderr does not say %q:\n%s", c.wantSay, out)
			}
			if r, bad := loginForgingIn(out); bad {
				t.Errorf("raw forging rune %U on stderr: %q", r, out)
			}
		})
	}
}

// TestLoginReaderWaitsForANewlineAndNeverOnEOFAlone fails if a partial line is
// acted on before its newline arrives, or if the reader dies on a pause
// instead of waiting. The FIFO is opened read-write in a real run, so it never
// reports EOF; a writer that stops mid-line leaves the line pending, and the
// next newline completes it — which is why nothing is opened for the first
// half and the first half joined with a later one is judged as one line.
//
// Control: the same bytes completed with "\n" are handed on, so the silence
// before it was the missing newline and not a dead reader.
func TestLoginReaderWaitsForANewlineAndNeverOnEOFAlone(t *testing.T) {
	pr, pw := io.Pipe()
	var out lockedBuf
	flows := make(chan loginbridge.Flow, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readLoginLines(pr, &out, func(f loginbridge.Flow) error { flows <- f; return nil })
	}()
	pw.Write([]byte(goodLoginURL))
	select {
	case f := <-flows:
		t.Fatalf("a line with no newline was acted on: %+v", f)
	case <-time.After(300 * time.Millisecond):
	}
	pw.Write([]byte("\n"))
	select {
	case <-flows:
	case <-time.After(5 * time.Second):
		t.Fatal("control: the completed line was never handed on")
	}

	// A half line followed by a different line is one garbled line: refused.
	pw.Write([]byte(goodLoginURL[:60]))
	pw.Write([]byte(goodLoginURL + "\n"))
	select {
	case f := <-flows:
		t.Fatalf("a half line joined with a full one was accepted: %+v", f)
	case <-time.After(300 * time.Millisecond):
	}
	if !strings.Contains(out.String(), "refused an open request") {
		t.Errorf("the garbled line was not refused aloud: %q", out.String())
	}
	pw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not stop at EOF")
	}
}

// TestLoginReaderScreensCarryNoRawForgingRune fails if text a sandbox writes
// to the FIFO reaches snug's stderr with a raw control or directional rune,
// through any refusal the predicate can produce: the prefix, a key, a value,
// the over-cap line, a lone invalid byte. Every line is refused, and the
// refusal is printed (the control that stderr was actually inspected).
func TestLoginReaderScreensCarryNoRawForgingRune(t *testing.T) {
	hostile := []string{"\x1b[2J", "\u009b2J", "\x9b2J", "\u202eevil", "\u2067evil", "\u0085", "\u2028", "\x7f", "\a", "\x00"}
	var lines []string
	for _, h := range hostile {
		lines = append(lines,
			h,
			"https://claude.com/cai/oauth/authorize?"+h,
			"https://claude.com/cai/oauth/authorize?"+h+"=1",
			"https://claude.com/cai/oauth/authorize?code="+h,
			"https://claude.com/cai/oauth/authorize?code=true&code=true"+h,
			goodLoginURL+h,
			"https://evil.example/"+h,
			strings.Repeat("a", 5000)+h,
		)
	}
	// Printable-ASCII keys and values: reach the %q and VisibleText arms
	// rather than the byte-range arm that refuses the controls above.
	lines = append(lines,
		goodLoginURL+"&%1b%5b2J=1",
		goodLoginURL+"&k\\x1b=1",
		"https://claude.com/cai/oauth/authorize?novalue",
		"https://claude.com/cai/oauth/authorize?=v",
		"https://claude.com/cai/oauth/authorize?a=b=c",
	)
	for _, l := range lines {
		handled, out := runReader(l + "\n")
		if len(handled) != 0 {
			t.Errorf("%q was handed to the opener", l)
		}
		if !strings.Contains(out, "Nothing was opened.") {
			t.Errorf("%q: control: no refusal was printed:\n%q", l, out)
		}
		if r, bad := loginForgingIn(out); bad {
			t.Errorf("%q: raw forging rune %U reached stderr: %q", l, r, out)
		}
	}
}

// TestASecondFIFOReaderAndAFloodCostOnlyTheBridge fails if a second process
// reading the FIFO, or a flood of lines into it, can hang close, crash the
// reader, or grow snug's heap by more than a small bound — and shows what a
// competing reader really does: it STEALS lines. The bridge then never sees
// them, which costs the sandbox its own login and nothing else; once the
// stealer is gone the next line is seen, so the stealer did not wedge the
// reader.
//
// The flood is 24 MiB of 100-byte garbage lines through the real FIFO: the
// writer can only finish once the reader has drained it past the 64 KiB pipe
// buffer, which is the control that the reader consumed it. The heap bound is
// HeapInuse after a GC, against a baseline taken the same way; it does not
// measure the Go runtime's RSS.
func TestASecondFIFOReaderAndAFloodCostOnlyTheBridge(t *testing.T) {
	dir := t.TempDir()
	pol := &policy.Policy{Mounts: map[string]policy.Mount{}}
	var out lockedBuf
	var handled atomic.Int64
	b, err := startLoginBridge(pol, func(n string) (string, error) { return filepath.Join(dir, n), nil },
		&out, func(*loginBridge) flowHandler {
			return func(loginbridge.Flow) error { handled.Add(1); return nil }
		})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, browserFIFOName)
	closed := false
	t.Cleanup(func() {
		if !closed {
			b.close()
		}
	})

	// The stealer: an O_RDONLY reader the sandbox could be.
	steal, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stolen atomic.Int64
	stealDone := make(chan struct{})
	go func() {
		defer close(stealDone)
		buf := make([]byte, 4096)
		for {
			n, err := steal.Read(buf)
			stolen.Add(int64(bytes.Count(buf[:n], []byte("\n"))))
			if err != nil {
				return
			}
		}
	}()
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	const lines = 200
	for range lines {
		w.WriteString(goodLoginURL + "\n")
	}
	// The writes above are 200 lines of about 330 bytes, more than the 64 KiB a
	// pipe holds, so having returned they were consumed by someone. The split is
	// logged and not asserted: a read can cut a line in two between the two
	// readers, so the counts do not add up to exactly lines.
	time.Sleep(200 * time.Millisecond)
	t.Logf("with a competing O_RDONLY reader, %d of %d lines reached the bridge intact and the stealer "+
		"counted %d newlines", handled.Load(), lines, stolen.Load())
	if handled.Load()+stolen.Load() == 0 {
		t.Fatal("control: nobody consumed any line")
	}
	steal.Close()
	<-stealDone
	// Three lines, not one: a stealer that took the tail of a line the bridge
	// had half of leaves that half pending, and the next line completes it
	// into one garbled line. The line after that is whole again.
	before := handled.Load()
	for range 3 {
		w.WriteString(goodLoginURL + "\n")
	}
	deadline := time.Now().Add(5 * time.Second)
	for handled.Load() < before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if handled.Load() < before+2 {
		t.Fatal("after the stealer went away the bridge saw fewer than two of three lines: the reader was wedged")
	}

	// The flood.
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	line := []byte(strings.Repeat("g", 99) + "\n")
	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		chunk := bytes.Repeat(line, 1000)
		for sent := 0; sent < 24<<20; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}()
	select {
	case <-floodDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the flood never finished being consumed: the reader stalled")
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if grew := int64(m1.HeapInuse) - int64(m0.HeapInuse); grew > 8<<20 {
		t.Errorf("the heap grew by %d bytes over a 24 MiB flood", grew)
	}
	if n := strings.Count(out.String(), "refused an open request"); n != loginRefusalsPrinted {
		t.Errorf("stderr carries %d refusal lines, want the cap of %d:\n%.400s", n, loginRefusalsPrinted, out.String())
	}
	if !strings.Contains(out.String(), "further refusals suppressed") {
		t.Errorf("no suppression line after the flood")
	}

	// close with the writer still holding the FIFO open must not hang.
	ch := make(chan struct{})
	go func() { b.close(); close(ch) }()
	select {
	case <-ch:
		closed = true
	case <-time.After(5 * time.Second):
		t.Fatal("close hung with a writer still open on the FIFO")
	}
}

func relaySocket(t *testing.T) *os.File {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fd), "relay")
}

func ephemeral(t *testing.T, network, host string) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s %s here: %v", network, host, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// TestLoginBridgeDialOnlyConnectsToLoopbackV4 fails if Dial ever connects a
// relay socket to anything but 127.0.0.1:<port>: a listener on 127.0.0.2 or on
// ::1 at the very port asked for must stay unreached, while one on 127.0.0.1
// is reached (the control that Dial connects at all).
//
// The test's own network namespace stands in for the sandbox's: it shows the
// address Dial passes to connect(2), not that the socket was created in the
// sandbox's namespace, which internal/stage and verifyRelaySockets own. Every
// Dial spends its socket whether or not it connects.
func TestLoginBridgeDialOnlyConnectsToLoopbackV4(t *testing.T) {
	b := &loginBridge{}
	good, goodPort := ephemeral(t, "tcp4", "127.0.0.1")
	b.setRelay([]*os.File{relaySocket(t)})
	accepted := make(chan net.Addr, 1)
	go func() {
		c, err := good.Accept()
		if err == nil {
			accepted <- c.LocalAddr()
			c.Close()
		}
	}()
	c, err := b.Dial(goodPort)
	if err != nil {
		t.Fatalf("control: Dial to a 127.0.0.1 listener failed: %v", err)
	}
	if ra := c.RemoteAddr().String(); ra != "127.0.0.1:"+strconv.Itoa(goodPort) {
		t.Errorf("Dial connected to %s", ra)
	}
	c.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("control: the 127.0.0.1 listener never accepted")
	}
	if b.Left() != 0 {
		t.Fatalf("Left() = %d after one Dial of one socket", b.Left())
	}

	// The same port number, on the other two spellings of loopback.
	for _, other := range []struct{ network, host string }{{"tcp4", "127.0.0.2"}, {"tcp6", "::1"}} {
		ln, port := ephemeral(t, other.network, other.host)
		// Nothing at 127.0.0.1:port, so a connect that lands there is refused
		// and one that ignored the address would show as an accept on ln.
		probe, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			probe.Close()
		}
		b.setRelay([]*os.File{relaySocket(t)})
		got := make(chan struct{}, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
				got <- struct{}{}
			}
		}()
		if c, err := b.Dial(port); err == nil {
			c.Close()
			t.Errorf("Dial(%d) connected although only %s %s listens on it", port, other.network, other.host)
		} else if !errors.Is(err, unix.ECONNREFUSED) {
			t.Errorf("Dial(%d) failed, but not with ECONNREFUSED: %v", port, err)
		}
		select {
		case <-got:
			t.Errorf("the %s listener on %s was reached", other.network, other.host)
		case <-time.After(300 * time.Millisecond):
		}
		if b.Left() != 0 {
			t.Errorf("a refused Dial did not spend its socket: Left() = %d", b.Left())
		}
	}
	if _, err := b.Dial(goodPort); err == nil {
		t.Error("Dial with no socket left succeeded")
	}
}

// TestLoginBridgeCloseReleasesEveryRelaySocket fails if a relay socket
// descriptor is still open in snug after close, or after the Dial that spent
// it: a spent socket's original descriptor is closed at once (the connection
// owns a duplicate), and close releases the unspent ones. Checked on the
// *os.File values, which report os.ErrClosed once closed.
func TestLoginBridgeCloseReleasesEveryRelaySocket(t *testing.T) {
	ln, port := ephemeral(t, "tcp4", "127.0.0.1")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	fs := []*os.File{relaySocket(t), relaySocket(t), relaySocket(t)}
	b := &loginBridge{fifo: mustTempFile(t), done: make(chan struct{})}
	close(b.done)
	b.setRelay(fs)
	for i, f := range fs {
		if _, err := f.Stat(); err != nil {
			t.Fatalf("control: socket %d is not open before the test: %v", i, err)
		}
	}
	c, err := b.Dial(port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := fs[0].Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the spent socket's descriptor is still open after Dial: %v", err)
	}
	for _, f := range fs[1:] {
		if _, err := f.Stat(); err != nil {
			t.Errorf("an unspent socket was closed by someone else's Dial: %v", err)
		}
	}
	b.close()
	for i, f := range fs {
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("socket %d is still open after close: %v", i, err)
		}
	}
	if b.Left() != 0 {
		t.Errorf("Left() = %d after close", b.Left())
	}
}
