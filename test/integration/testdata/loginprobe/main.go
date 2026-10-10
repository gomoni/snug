// Command loginprobe is the payload of the login-bridge integration tests: the
// part of Claude Code's /login that runs INSIDE the sandbox.
//
// It listens on 127.0.0.1:0 (so the port is one the sandbox's own kernel chose
// from its own range), asks $BROWSER to open a URL naming that port, and then
// prints, byte for byte, whatever connects. It answers with the three things a
// hostile sandbox would want a host browser to act on: a Set-Cookie, a Location
// to somewhere else and a script body.
//
// Usage: loginprobe key=value ...
//
//	url=RAW       hand $BROWSER this string instead of a valid pinned URL
//	state=S       the 43-character state to put in the valid URL
//	challenge=C   the 43-character code_challenge to put in the valid URL
//	nolisten=1    pick a port and release it before asking, so nothing listens
//	serve=0       do not wait for a callback at all
//	wait=DUR      how long to wait for the callback (default 20s)
//	accepts=N     how many connections to print before answering the last
//	              (default 1)
//	dial=L@N:H:P  after the open, and once the file named by go= exists, connect
//	              to H:P over network N (tcp or udp) and print the verdict under
//	              label L. H may be the word gw or gw6, resolved from /proc; P
//	              may be the word PORT, this probe's own callback port.
//	go=FILE       the file whose appearance releases the dial= probes
//	release=FILE  wait for FILE to appear before exiting
//	script=FILE   instead of calling $BROWSER itself, run /bin/sh FILE once the
//	              listener is up, with PORT, URL (a valid pinned URL for that
//	              port) and BROWSER in its environment and its output passed
//	              through, then SCRIPT-RC. The listener stays up until the
//	              script ends; nothing else (serve, dial) runs.
//	port=N        listen on 127.0.0.1:N instead of a kernel-chosen port, so two
//	              sandboxes can both name the same host port in their URL
//	second=FILE   after the first open, wait for FILE, then listen on a second
//	              kernel-chosen port, print it as PORT2, ask $BROWSER to open a
//	              URL naming it (SHIM2-RC) and serve that listener instead of
//	              the first. The state is the same
//	door=1        accept on descriptor 3 (the http door's LISTEN_FDS socket)
//	              and answer every request with DOOR-BODY, printing each one
//	              as DOOR-RECEIVED
//	token=T       ignored; it only puts T in this process's argv, where the
//	              host can find it
//
// Every line it prints starts with a marker word so a test can tell "the probe
// did not see X" from "the probe never ran".
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/loginbridge"
)

const (
	defaultState     = "qUcPYbXlvfwBNYqnh52qhKs7Ac_7GNRvan-h3ihmgk8"
	defaultChallenge = "fD5xTDCwgf63U088pqhV0TFHbLf0emkJPI844Pfplvs"
)

func main() {
	opt := map[string]string{}
	var dials []string
	for _, a := range os.Args[1:] {
		k, v, _ := strings.Cut(a, "=")
		if k == "dial" {
			dials = append(dials, v)
			continue
		}
		opt[k] = v
	}
	say("PROBE-START")

	listenAddr := "127.0.0.1:0"
	if opt["port"] != "" {
		listenAddr = "127.0.0.1:" + opt["port"]
	}
	if opt["door"] != "" {
		serveDoor()
	}
	ln, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		say("PROBE-ERROR listen: %v", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	say("PORT %d", port)
	if opt["nolisten"] != "" {
		ln.Close()
	}

	state, challenge := defaultState, defaultChallenge
	if opt["state"] != "" {
		state = opt["state"]
	}
	if opt["challenge"] != "" {
		challenge = opt["challenge"]
	}
	u := opt["url"]
	if u == "" {
		u = pinnedURL(port, state, challenge)
	}
	say("TARGET-URL %s", u)

	browser := os.Getenv("BROWSER")
	say("BROWSER %s", browser)
	if script := opt["script"]; script != "" {
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = append(os.Environ(), "PORT="+strconv.Itoa(port), "URL="+u)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			say("SCRIPT-RC %v", err)
		} else {
			say("SCRIPT-RC 0")
		}
		waitFor(opt["release"], 30*time.Second)
		say("PROBE-DONE")
		return
	}
	if browser == "" {
		say("PROBE-ERROR BROWSER is unset")
		os.Exit(1)
	}
	err = exec.Command(browser, u).Run()
	if err != nil {
		say("SHIM-RC %v", err)
	} else {
		say("SHIM-RC 0")
	}

	if opt["second"] != "" {
		waitFor(opt["second"], 30*time.Second)
		ln2, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			say("PROBE-ERROR listen2: %v", err)
			os.Exit(1)
		}
		port2 := ln2.Addr().(*net.TCPAddr).Port
		say("PORT2 %d", port2)
		u2 := pinnedURL(port2, state, challenge)
		if err := exec.Command(browser, u2).Run(); err != nil {
			say("SHIM2-RC %v", err)
		} else {
			say("SHIM2-RC 0")
		}
		serve(ln2, 1, 20*time.Second)
	} else if len(dials) > 0 {
		// The listener stays up until the go file appears, because snug checks
		// that something listens on the port when it handles the open, and that
		// is asynchronous. It is dropped before the dials: what they measure is
		// the sandbox's own loopback being empty and the host's being sealed,
		// and a listener of the probe's own on the open port would answer for it.
		waitFor(opt["go"], 30*time.Second)
		ln.Close()
		for _, d := range dials {
			dial(d, port)
		}
		say("DIALS-COMPLETE")
	} else if opt["nolisten"] == "" && opt["serve"] != "0" {
		wait := 20 * time.Second
		if opt["wait"] != "" {
			if d, err := time.ParseDuration(opt["wait"]); err == nil {
				wait = d
			}
		}
		accepts := 1
		if n, err := strconv.Atoi(opt["accepts"]); err == nil && n > 0 {
			accepts = n
		}
		serve(ln, accepts, wait)
	}
	waitFor(opt["release"], 30*time.Second)
	say("PROBE-DONE")
}

// serveDoor accepts on descriptor 3 until the process ends. It is the payload
// half of an http door: the host connects to the door's unix socket and what
// arrives here is what the host sent, byte for byte.
func serveDoor() {
	l, err := net.FileListener(os.NewFile(3, "door-fd-3"))
	if err != nil {
		say("PROBE-ERROR door: fd 3 is not a listener: %v", err)
		os.Exit(1)
	}
	say("DOOR-READY %s", os.Getenv("LISTEN_FDNAMES"))
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			var data []byte
			br := bufio.NewReader(c)
			for !strings.HasSuffix(string(data), "\r\n\r\n") {
				b, err := br.ReadByte()
				if err != nil {
					break
				}
				data = append(data, b)
			}
			say("DOOR-RECEIVED %q", string(data))
			body := "DOOR-BODY"
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			c.Close()
		}
	}()
}

func say(format string, a ...any) {
	fmt.Printf(format+"\n", a...)
}

func waitFor(file string, d time.Duration) {
	if file == "" {
		return
	}
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if _, err := os.Stat(file); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	say("PROBE-ERROR %s never appeared", file)
}

// pinnedURL builds a URL the bridge must admit, from the exported pinned
// constants, in a DIFFERENT parameter and scope order than the bridge writes
// its own. The bridge accepts those as sets and rebuilds in its measured
// order, so a test that sees the measured order at the opener has seen a
// rebuild rather than a copy.
func pinnedURL(port int, state, challenge string) string {
	scopes := loginbridge.PinnedScopes()
	var enc []string
	for i := len(scopes) - 1; i >= 0; i-- {
		enc = append(enc, url.QueryEscape(scopes[i]))
	}
	redirect := "http%3A%2F%2Flocalhost%3A" + strconv.Itoa(port) + "%2Fcallback"
	return loginbridge.PinnedAuthorizeBase() + "?" +
		"state=" + state +
		"&code_challenge_method=S256" +
		"&code_challenge=" + challenge +
		"&scope=" + strings.Join(enc, "+") +
		"&redirect_uri=" + redirect +
		"&response_type=code" +
		"&client_id=" + loginbridge.PinnedClientID() +
		"&code=true"
}

// serve prints the head of each of the first n connections and answers only
// the last, with the hostile reply.
func serve(ln net.Listener, n int, wait time.Duration) {
	for i := 1; i <= n; i++ {
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(wait))
		c, err := ln.Accept()
		if err != nil {
			say("PROBE-ERROR accept: %v", err)
			return
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var data []byte
		br := bufio.NewReader(c)
		for !strings.HasSuffix(string(data), "\r\n\r\n") {
			b, err := br.ReadByte()
			if err != nil {
				break
			}
			data = append(data, b)
		}
		say("RECEIVED %q", string(data))
		if i == n {
			c.Write([]byte("HTTP/1.1 302 Found\r\nSet-Cookie: pwn=1\r\n" +
				"Location: https://evil.example\r\nConnection: close\r\n\r\n" +
				"<script>alert(1)</script>"))
		}
		c.Close()
	}
}

func dial(spec string, ownPort int) {
	label, rest, _ := strings.Cut(spec, "@")
	network, hostport, _ := strings.Cut(rest, ":")
	i := strings.LastIndex(hostport, ":")
	host, port := hostport[:i], hostport[i+1:]
	if port == "PORT" {
		port = strconv.Itoa(ownPort)
	}
	switch host {
	case "gw":
		host = gateway4()
	case "gw6":
		host = gateway6()
	}
	if host == "" {
		say("DIAL %s NOADDR", label)
		return
	}
	addr := net.JoinHostPort(host, port)
	say("DIAL-TARGET %s %s %s", label, network, addr)
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		verdict := "ERROR"
		if strings.Contains(err.Error(), "refused") {
			verdict = "REFUSED"
		} else if strings.Contains(err.Error(), "timeout") {
			verdict = "TIMEDOUT"
		}
		say("DIAL %s %s %v", label, verdict, err)
		return
	}
	defer c.Close()
	if network == "udp" {
		c.Write([]byte("probe"))
	}
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n > 0 {
		say("DIAL %s REACHED %s", label, strings.TrimSpace(string(buf[:n])))
		return
	}
	if network == "udp" {
		// A connected UDP socket reports a refusal as an error on read.
		if strings.Contains(fmt.Sprint(err), "refused") {
			say("DIAL %s REFUSED %v", label, err)
		} else {
			say("DIAL %s TIMEDOUT %v", label, err)
		}
		return
	}
	// A TCP connect that completed IS a connection to something.
	say("DIAL %s REACHED (connected, no banner: %v)", label, err)
}

func gateway4() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == "00000000" {
			v, err := strconv.ParseUint(f[2], 16, 32)
			if err != nil {
				return ""
			}
			return fmt.Sprintf("%d.%d.%d.%d", v&0xff, v>>8&0xff, v>>16&0xff, v>>24&0xff)
		}
	}
	return ""
}

// gateway6 returns a default route's next hop with its scope, which a
// link-local gateway needs to be connectable.
func gateway6() string {
	b, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[4] != strings.Repeat("0", 32) {
			var parts []string
			for i := 0; i < 32; i += 4 {
				parts = append(parts, f[4][i:i+4])
			}
			return strings.Join(parts, ":") + "%" + f[len(f)-1]
		}
	}
	return ""
}
