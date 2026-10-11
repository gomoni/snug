// Command bridgedialprobe is the payload of the login-bridge container test: a
// static program that runs as a build RUN step and as a container's
// entrypoint, dials each target it is given and says what answered.
//
// Each argument is label@network:host:port; host may be the word gw, resolved
// from /proc/net/route. For every target it prints one line,
//
//	DIAL label VERDICT host:port (detail)
//
// with the address it actually dialled, so a test can compare it with the one
// it meant: a verdict whose reason is a parse error is not a network answer.
// VERDICT is CONNECTED-SILENT (the handshake completed and nothing answered a
// callback-shaped request), CONNECTED-ANSWER (something answered; the first
// bytes follow), REFUSED, TIMEDOUT, UNREACHABLE or ERROR.
//
// DIALER-START and DIALER-END bracket the output, and ARGS names how many
// targets it was given.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// state is the one the login probe puts in its URL by default, so a request
// that reached a live flow would carry the right one.
const state = "qUcPYbXlvfwBNYqnh52qhKs7Ac_7GNRvan-h3ihmgk8"

func gw() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) > 2 && x[1] == "00000000" {
			b, _ := hex.DecodeString(x[2])
			if len(b) == 4 {
				return net.IPv4(b[3], b[2], b[1], b[0]).String()
			}
		}
	}
	return ""
}

func main() {
	fmt.Println("DIALER-START")
	fmt.Printf("ARGS %d\n", len(os.Args)-1)
	for _, a := range os.Args[1:] {
		label, rest, _ := strings.Cut(a, "@")
		nw, hp, _ := strings.Cut(rest, ":")
		i := strings.LastIndex(hp, ":")
		if i < 0 {
			fmt.Printf("DIAL %s ERROR %s (not label@network:host:port)\n", label, a)
			continue
		}
		host, port := hp[:i], hp[i+1:]
		if host == "gw" {
			host = gw()
		}
		addr := net.JoinHostPort(host, port)
		c, err := net.DialTimeout(nw, addr, 3*time.Second)
		if err != nil {
			v := "ERROR"
			s := err.Error()
			switch {
			case strings.Contains(s, "refused"):
				v = "REFUSED"
			case strings.Contains(s, "timeout"):
				v = "TIMEDOUT"
			case strings.Contains(s, "unreachable"):
				v = "UNREACHABLE"
			}
			fmt.Printf("DIAL %s %s %s (%s)\n", label, v, addr, s)
			continue
		}
		fmt.Fprintf(c, "GET /callback?code=containercode&state=%s HTTP/1.1\r\nHost: localhost:%s\r\nConnection: close\r\n\r\n", state, port)
		c.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 400)
		n, err := c.Read(buf)
		c.Close()
		if n == 0 {
			fmt.Printf("DIAL %s CONNECTED-SILENT %s (%v)\n", label, addr, err)
			continue
		}
		fmt.Printf("DIAL %s CONNECTED-ANSWER %s %q\n", label, addr, string(buf[:n]))
	}
	fmt.Println("DIALER-END")
}
