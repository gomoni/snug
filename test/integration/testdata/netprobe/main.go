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
// PORT must be a decimal port number. Anything else is a usage ERROR and no
// dial happens at all — issue #243, where the container was created with a
// Cmd that podman APPENDED to the image's own ENTRYPOINT, so this process ran
// as `/netprobe /netprobe <port>` and read the string "/netprobe" as its
// port. `net.DialTimeout` turned that into a port-NAME lookup, whose failure
// is spelled the same way a refusal is, and three security negatives passed
// for a milestone on a probe that never dialled anything.
//
// Prints one "RESULT <label> <addr> <verdict>" line per address tried. The
// address is in the line because a caller asserting a negative has to be able
// to tell "did not reach the target" from "never aimed at the target":
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
// discipline the rest of this suite uses. A REFUSED verdict means the kernel
// answered; a dial that never left this process (an unparseable address, a
// name lookup) is verdict ERROR instead, which is never a network answer and
// which callers treat as a broken probe rather than as a closed port.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("RESULT usage - ERROR missing-port")
		return
	}
	port := os.Args[1]
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		// Loud and early rather than one unparseable address per label: an
		// argv this process cannot make sense of means the caller's idea of
		// what is being dialled and this process's differ, and every RESULT
		// line after that point is about the wrong target.
		fmt.Printf("RESULT usage - ERROR bad-port %q\n", port)
		fmt.Println("PROBE-COMPLETE")
		return
	}

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
		// A parse or name-lookup failure is not a verdict about the network:
		// nothing was sent. Reporting it as REFUSED is what let issue #243
		// hide — "REFUSED" read as "the sandbox held".
		var ae *net.AddrError
		var de *net.DNSError
		if errors.As(err, &ae) || errors.As(err, &de) {
			fmt.Printf("RESULT %s %s ERROR %v\n", label, addr, err)
			return
		}
		fmt.Printf("RESULT %s %s REFUSED %v\n", label, addr, err)
		return
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	fmt.Printf("RESULT %s %s REACHED %s\n", label, addr, strings.TrimSpace(string(buf[:n])))
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
