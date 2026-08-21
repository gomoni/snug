// Command dhcpprobe asks pasta's own DHCP servers what they will hand a
// client, and prints the answer as one `KEY=VALUE` line per fact.
//
// Issue #196. The issue asserted that pasta's built-in DHCP/DHCPv6/RA server
// inside `@net-anon` still holds the host's router, resolver and search
// domains — and nobody had ever run a client to see. This is that client.
//
// IT NEEDS PRIVILEGE THE PAYLOAD DOES NOT HAVE, and that is the whole point of
// the issue: passt answers only source ports 67/68/546/547, and a snug payload
// runs with CapEff=0, so it cannot bind one to ask. This probe therefore runs
// where those capabilities exist — under `pasta … -- dhcpprobe`, which puts it
// in a namespace where it is root — to answer the question the payload cannot:
// what would the server say if something COULD ask.
//
// Output vocabulary, one per line, so the Go test parses rather than greps:
//
//	V4-REPLY-FROM=<ip>      the server that answered (empty line absent if none)
//	V4-YIADDR=<ip>          the offered address
//	V4-OPT-<n>=<value>      an option in the offer; 1 mask, 3 router, 6 DNS,
//	                        15 domain, 119 search list, rendered as text
//	V4-NO-REPLY             no DHCPOFFER arrived within the timeout
//	V6-IA-ADDR=<ip>         the address inside DHCPv6's IA_NA, if any
//	V6-OPT-<n>=<hex>        any other DHCPv6 option, hex, unparsed
//	V6-NO-REPLY             no DHCPv6 reply arrived
//	PROBE-DONE              reached the end; nothing below it was skipped
//
// Deliberately NOT probed: RA/NDP. A Router Solicitation drew no advertisement
// in either configuration when this was measured by hand, so an assertion here
// would be about a message nobody has seen arrive — see the test's own comment.
//
// This directory is named testdata for the same reason netprobe's is: the Go
// toolchain ignores it for `go build ./...`, and only the integration test
// compiles it.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

var magic = []byte{99, 130, 83, 99}

func main() {
	dhcpv4()
	dhcpv6()
	fmt.Println("PROBE-DONE")
}

func dhcpv4() {
	c, err := net.ListenPacket("udp4", ":68")
	if err != nil {
		// Not "no reply": a probe that could not ask must not be read as a
		// server that did not answer.
		fmt.Printf("V4-CANNOT-ASK=%v\n", err)
		return
	}
	defer c.Close()

	req := make([]byte, 0, 300)
	req = append(req, 1, 1, 6, 0) // BOOTREQUEST, ethernet, hlen 6
	req = append(req, 0x39, 0x03, 0xF3, 0x26)
	req = append(req, make([]byte, 8)...)  // secs, flags, ciaddr
	req = append(req, make([]byte, 12)...) // yiaddr, siaddr, giaddr
	req = append(req, 0x02, 0, 0, 0, 0, 1)
	req = append(req, make([]byte, 10)...)  // chaddr padding
	req = append(req, make([]byte, 192)...) // sname + file
	req = append(req, magic...)
	req = append(req, 53, 1, 1)                // DHCPDISCOVER
	req = append(req, 55, 5, 1, 3, 6, 15, 119) // ask for mask, router, DNS, domain, search
	req = append(req, 255)

	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	if _, err := c.WriteTo(req, dst); err != nil {
		fmt.Printf("V4-SEND-FAILED=%v\n", err)
		return
	}

	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		fmt.Println("V4-NO-REPLY")
		return
	}
	host, _, _ := net.SplitHostPort(from.String())
	fmt.Printf("V4-REPLY-FROM=%s\n", host)
	reply := buf[:n]
	if n >= 20 {
		fmt.Printf("V4-YIADDR=%s\n", net.IP(reply[16:20]).String())
	}
	i := indexOf(reply, magic)
	if i < 0 {
		return
	}
	for i += 4; i < len(reply); {
		code := reply[i]
		if code == 255 {
			return
		}
		if code == 0 {
			i++
			continue
		}
		if i+2 > len(reply) {
			return
		}
		ln := int(reply[i+1])
		if i+2+ln > len(reply) {
			return
		}
		fmt.Printf("V4-OPT-%d=%s\n", code, renderOption(code, reply[i+2:i+2+ln]))
		i += 2 + ln
	}
}

func renderOption(code byte, val []byte) string {
	switch code {
	case 1, 3, 6, 54: // mask, router, DNS list, server id
		var out []string
		for j := 0; j+4 <= len(val); j += 4 {
			out = append(out, net.IP(val[j:j+4]).String())
		}
		return strings.Join(out, " ")
	case 15: // domain name
		return string(val)
	case 119: // search list, RFC 1035 labels
		return decodeLabels(val)
	}
	return fmt.Sprintf("%x", val)
}

func decodeLabels(val []byte) string {
	var names []string
	var cur []string
	for i := 0; i < len(val); {
		ln := int(val[i])
		i++
		if ln == 0 {
			names = append(names, strings.Join(cur, "."))
			cur = nil
			continue
		}
		if i+ln > len(val) {
			break
		}
		cur = append(cur, string(val[i:i+ln]))
		i += ln
	}
	if len(cur) > 0 {
		names = append(names, strings.Join(cur, "."))
	}
	return strings.Join(names, " ")
}

// dhcpv6 sends an Information-Request and prints whatever comes back. The v6
// half is here because the measurement that prompted this test found the
// sharpest difference there: under plain @net the reply carried a GLOBAL,
// ISP-attributable address, and under @net-anon the synthetic ULA.
func dhcpv6() {
	c, err := net.ListenPacket("udp6", "[::]:546")
	if err != nil {
		fmt.Printf("V6-CANNOT-ASK=%v\n", err)
		return
	}
	defer c.Close()

	msg := []byte{11, 0x0a, 0x0b, 0x0c} // Information-Request, transaction id
	msg = append(msg, 0, 1, 0, 10)      // client id, DUID-LL
	msg = append(msg, 0, 3, 0, 0, 0, 0)
	msg = append(msg, 0x02, 0, 0, 0, 0, 1)
	msg = append(msg, 0, 6, 0, 4, 0, 23, 0, 24) // ask for DNS servers + search list

	dst := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547, Zone: "snug0"}
	if _, err := c.WriteTo(msg, dst); err != nil {
		fmt.Printf("V6-SEND-FAILED=%v\n", err)
		return
	}
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		fmt.Println("V6-NO-REPLY")
		return
	}
	reply := buf[:n]
	for i := 4; i+4 <= len(reply); {
		code := binary.BigEndian.Uint16(reply[i:])
		ln := int(binary.BigEndian.Uint16(reply[i+2:]))
		if i+4+ln > len(reply) {
			return
		}
		val := reply[i+4 : i+4+ln]
		switch code {
		case 3: // IA_NA, whose IAADDR sub-option carries the address
			if j := indexOfIAAddr(val); j >= 0 {
				fmt.Printf("V6-IA-ADDR=%s\n", net.IP(val[j:j+16]).String())
			}
		case 23:
			var out []string
			for j := 0; j+16 <= len(val); j += 16 {
				out = append(out, net.IP(val[j:j+16]).String())
			}
			fmt.Printf("V6-OPT-23=%s\n", strings.Join(out, " "))
		case 24:
			fmt.Printf("V6-OPT-24=%s\n", decodeLabels(val))
		default:
			fmt.Printf("V6-OPT-%d=%x\n", code, val)
		}
		i += 4 + ln
	}
}

// indexOfIAAddr finds the 16-byte address inside an IA_NA option's IAADDR
// sub-option (code 5), whose value begins with the address.
func indexOfIAAddr(ia []byte) int {
	for i := 12; i+4 <= len(ia); { // 12 = IAID + T1 + T2
		code := binary.BigEndian.Uint16(ia[i:])
		ln := int(binary.BigEndian.Uint16(ia[i+2:]))
		if i+4+ln > len(ia) {
			return -1
		}
		if code == 5 && ln >= 16 {
			return i + 4
		}
		i += 4 + ln
	}
	return -1
}

func indexOf(hay, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := range needle {
			if hay[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
