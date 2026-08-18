// Command netprobe is a from-scratch container's own entrypoint: it has no
// shell, no libc and no /proc/net/route parser to borrow (CGO_ENABLED=0, a
// static binary with nothing else in the image), because the whole point of
// building it from `FROM scratch` is that the image needs no base layer and
// therefore no registry pull — see TestHostLoopbackClosedFromContainer and
// TestNoAbstractSocketsWithEngineInN in ../../containerengine_test.go for why
// that matters: a container in this suite must be constructible with the
// sandbox's egress CLOSED, which rules out alpine or anything else that has
// to be fetched.
//
// This directory is named testdata for the same reason
// test/integration/testdata/pidfdprobe is: the Go toolchain ignores it for
// `go build ./...` everywhere else, and only the integration test compiles it
// (for the HOST architecture, since it also has to run as the entrypoint of a
// container built and started through the very engine under test).
//
// Usage: netprobe PORT
//
// Prints one "RESULT <label> <verdict>" line per address tried:
//
//	v4-loop   127.0.0.1:PORT  — this netns's OWN loopback
//	v6-loop   [::1]:PORT      — same, IPv6
//	gw        <default-gw>:PORT — the address pasta's --map-host-loopback
//	                              actually controls (see
//	                              TestHostLoopbackIsUnreachable in
//	                              sandbox_test.go for the established
//	                              reasoning this borrows)
//
// A REACHED verdict includes whatever bytes the far end sent back, so a
// genuine escape shows the host's banner text on screen and not just
// "connected" — the same "read the banner, don't just check for a refusal"
// discipline the rest of this suite uses.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("RESULT usage ERROR missing-port")
		return
	}
	port := os.Args[1]

	probe("v4-loop", net.JoinHostPort("127.0.0.1", port))
	if _, err := net.ResolveTCPAddr("tcp6", "[::1]:0"); err == nil {
		probe("v6-loop", net.JoinHostPort("::1", port))
	}

	if gw := gateway4(); gw != "" {
		fmt.Println("GATEWAY", gw)
		probe("gw", net.JoinHostPort(gw, port))
	} else {
		fmt.Println("GATEWAY NONE")
	}
	fmt.Println("PROBE-COMPLETE")
}

// probe dials addr and prints a RESULT line. A refusal (RST, "connection
// refused") and a drop (deadline exceeded) are both reported distinctly —
// this file draws no conclusion about which is expected; the caller does,
// exactly as TestHostLoopbackIsUnreachable's own probe leaves that call to
// the Go test rather than to the payload.
func probe(label, addr string) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Printf("RESULT %s REFUSED %v\n", label, err)
		return
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	fmt.Printf("RESULT %s REACHED %s\n", label, strings.TrimSpace(string(buf[:n])))
}

// gateway4 reads /proc/net/route directly rather than shelling out to `ip`
// (not present in a from-scratch image at all) — the same fields the
// existing python probe in sandbox_test.go's TestHostLoopbackIsUnreachable
// reads, reimplemented here because this process cannot run python either.
func gateway4() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= 2 || fields[1] != "00000000" {
			continue
		}
		var raw uint32
		if _, err := fmt.Sscanf(fields[2], "%x", &raw); err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, raw)
		return ip.String()
	}
	return ""
}
