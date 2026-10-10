// Command fakeopener stands in for xdg-open on the host's PATH and plays the
// human's browser.
//
// It records its own argv, then GETs the callback on localhost the way a real
// browser would after the login page redirected back: to the port named in the
// URL it was handed, with the state taken from that URL, AND with a Cookie and
// a User-Agent header of the kind a browser attaches to localhost requests.
// What the sandbox ends up seeing of those is what the tests measure.
//
// Environment (inherited from snug, which starts it with its own):
//
//	FAKEOPENER_DIR   directory the records go in; required
//	FAKEOPENER_MODE  "callback" (default), "hold" (record argv and exit, never
//	                 touching the callback), "wrongstate" (first send a callback
//	                 with a state that is not the URL's, then the right one) or
//	                 "dialonly" (record argv and report whether the callback
//	                 port accepts a TCP connection, then exit) or "linger"
//	                 (record argv and its own pid in "pid", then stay alive
//	                 for FAKEOPENER_LINGER, default 4s, never touching the
//	                 callback: a browser the opener started and left running)
//
// Files written, each created only when its step is reached, so a test can
// assert that this program never ran by the absence of "ran":
//
//	ran              empty marker, written first
//	runs             one byte appended per invocation, so a test can count them
//	argv             argc=N then one argv=... line per argument
//	response         the raw bytes the callback answered with
//	response-wrong   the same for the wrong-state request
//	dial             "v4 OK|REFUSED" and "v6 OK|REFUSED" lines
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	portRe  = regexp.MustCompile(`localhost%3A([0-9]+)%2Fcallback`)
	stateRe = regexp.MustCompile(`[&?]state=([A-Za-z0-9_-]+)`)
)

func main() {
	dir := os.Getenv("FAKEOPENER_DIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "fakeopener: FAKEOPENER_DIR is not set")
		os.Exit(2)
	}
	write := func(name, s string) {
		os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644)
	}
	write("ran", "")
	if f, err := os.OpenFile(filepath.Join(dir, "runs"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		f.WriteString("x")
		f.Close()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "argc=%d\n", len(os.Args)-1)
	for _, a := range os.Args[1:] {
		fmt.Fprintf(&b, "argv=%s\n", a)
	}
	write("argv", b.String())
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	pm := portRe.FindStringSubmatch(os.Args[1])
	sm := stateRe.FindStringSubmatch(os.Args[1])
	if pm == nil || sm == nil {
		write("response", "fakeopener: no port or state in the URL\n")
		os.Exit(3)
	}
	port, state := pm[1], sm[1]

	switch os.Getenv("FAKEOPENER_MODE") {
	case "hold":
		return
	case "linger":
		write("pid", fmt.Sprintf("%d\n", os.Getpid()))
		d := 4 * time.Second
		if v, err := time.ParseDuration(os.Getenv("FAKEOPENER_LINGER")); err == nil {
			d = v
		}
		time.Sleep(d)
		return
	case "dialonly":
		var d strings.Builder
		for _, f := range []struct{ label, network, addr string }{
			{"v4", "tcp4", "127.0.0.1:" + port}, {"v6", "tcp6", "[::1]:" + port},
		} {
			c, err := net.DialTimeout(f.network, f.addr, 2*time.Second)
			if err != nil {
				fmt.Fprintf(&d, "%s REFUSED %v\n", f.label, err)
				continue
			}
			c.Close()
			fmt.Fprintf(&d, "%s OK\n", f.label)
		}
		write("dial", d.String())
		return
	case "wrongstate":
		wrong := []byte(state)
		if wrong[0] == 'A' {
			wrong[0] = 'B'
		} else {
			wrong[0] = 'A'
		}
		write("response-wrong", callback(port, "WRONG-1", string(wrong)))
	}
	write("response", callback(port, "CODE-1_x", state))
}

// callback sends one browser-shaped request to the callback and returns the
// raw answer, or a line saying why there was none.
func callback(port, code, state string) string {
	c, err := net.DialTimeout("tcp4", "127.0.0.1:"+port, 10*time.Second)
	if err != nil {
		return "fakeopener: dial: " + err.Error() + "\n"
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "GET /callback?code=%s&state=%s HTTP/1.1\r\nHost: localhost:%s\r\n"+
		"Cookie: hostsession=SECRET\r\nUser-Agent: fakebrowser\r\n"+
		"Referer: http://localhost:%s/\r\n\r\n", code, state, port, port)
	resp, err := io.ReadAll(c)
	if err != nil && len(resp) == 0 {
		return "fakeopener: read: " + err.Error() + "\n"
	}
	return string(resp)
}
