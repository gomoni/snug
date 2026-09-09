package stage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// openNetSocketInN creates an AF_INET datagram socket and brings lo up through
// it. It MUST be called while the caller is still inside N, because both of the
// things it produces are namespace-scoped at that moment:
//
//   - lo is configured in N. Today's offline sandbox has lo UP with 127.0.0.1/8
//     because bwrap configures the netns IT created (loopback_setup). Under the
//     stage bwrap does not create N, so nothing brings lo up unless the stage
//     does it here — TestSandboxHasItsOwnWorkingLoopback is the positive control
//     that catches the regression if this is skipped.
//   - the returned socket stays bound to N for its whole life, which is what
//     lets the stage answer readiness questions about N after it has left.
//
// Never by executing ip(8): that would add a host binary dependency snug does
// not otherwise have, on a path that must not depend on what is on $PATH.
//
// The caller owns the descriptor.
func openNetSocketInN() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, fmt.Errorf("opening a socket in N: %w", err)
	}
	if err := bringUp(fd, "lo"); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// bringUp sets IFF_UP on name. The kernel assigns 127.0.0.1/8 and ::1/128
// itself once lo is up, so no address code is needed.
func bringUp(fd int, name string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("bringing %s up: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing %s up: SIOCGIFFLAGS: %w", name, err)
	}
	flags := ifr.Uint16()
	if flags&unix.IFF_UP != 0 {
		return nil // already up
	}
	ifr.SetUint16(flags | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing %s up: SIOCSIFFLAGS: %w", name, err)
	}
	return nil
}

// ifaceIsUp reports whether name exists in the socket's network namespace and
// is both UP and RUNNING.
//
// Both flags, not just IFF_UP. pasta creates the tap interface and then
// configures it; IFF_UP alone can be true on an interface that is not yet
// carrying anything, and the whole point of this check is that the payload must
// not start before the network it was promised actually works. IFF_RUNNING is
// the kernel's own answer to "is the link operational".
//
// A missing interface is (false, nil), not an error: it is the ordinary state
// while pasta is still starting, and the caller polls.
func ifaceIsUp(fd int, name string) (bool, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return false, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		if err == unix.ENODEV {
			return false, nil // not there yet
		}
		return false, fmt.Errorf("SIOCGIFFLAGS on %s: %w", name, err)
	}
	flags := ifr.Uint16()
	return flags&unix.IFF_UP != 0 && flags&unix.IFF_RUNNING != 0, nil
}

// waitForIface polls until name is up in the socket's namespace, or the
// deadline passes. It is the stage's replacement for polling a sandbox
// process's /proc/<pid>/net/dev, and it needs no process in N at all.
//
// The timeout is the caller's business; this returns a plain error naming what
// it was waiting for, because that error reaches a human as "snug could not
// bring the network up" and a bare "timeout" would send them to the wrong
// place.
func waitForIface(fd int, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		up, err := ifaceIsUp(fd, name)
		if err != nil {
			return err
		}
		if up {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("interface %s did not come up in the sandbox's network namespace "+
				"within %s — pasta started but never configured it", name, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// openNetlinkSocketInN creates an AF_NETLINK/NETLINK_ROUTE socket. Same
// constraint as openNetSocketInN and the same reason: a socket's network
// namespace is fixed at creation, and this one is what lets __stage-serve
// assign addresses onto snug0 (sealHostAddresses) after it has left N.
//
// The caller owns the descriptor.
func openNetlinkSocketInN() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("opening a netlink socket in N: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("binding the netlink socket: %w", err)
	}
	return fd, nil
}

// ifaceIndex returns name's ifindex in the socket's network namespace, via
// SIOCGIFINDEX on the AF_INET socket already open there (fdNetSock) — no
// second socket needed just to learn a number ioctl already answers.
func ifaceIndex(fd int, name string) (uint32, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, fmt.Errorf("SIOCGIFINDEX on %s: %w", name, err)
	}
	return ifr.Uint32(), nil
}

// rtaAlign rounds n up to RTA_ALIGNTO (4), the padding every netlink
// attribute's payload is followed by so the next attribute starts aligned.
func rtaAlign(n int) int {
	return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
}

// writeRtAttr appends one netlink attribute (header + payload + alignment
// padding) to buf.
func writeRtAttr(buf *bytes.Buffer, t uint16, data []byte) {
	rta := unix.RtAttr{Len: uint16(unix.SizeofRtAttr + len(data)), Type: t}
	_ = binary.Write(buf, binary.NativeEndian, rta)
	buf.Write(data)
	if pad := rtaAlign(len(data)) - len(data); pad > 0 {
		buf.Write(make([]byte, pad))
	}
}

// sealHostAddresses assigns every address in addrs onto ifIndex, inside the
// network namespace fd (an AF_NETLINK/NETLINK_ROUTE socket opened by
// openNetlinkSocketInN) speaks for, as a /32 (v4) or /128 (v6) address.
//
// The kernel creates a `local` route for any address it holds on an
// interface, regardless of scope — so once assigned, a connect from inside
// the sandbox to one of these addresses short-circuits to local delivery and
// is refused (nothing listens) rather than reaching pasta and the host beyond
// it. This is what closes the addresses pasta does NOT copy onto snug0 itself
// (measured: the host's link-local, invisible to a route-blackhole approach
// because a scoped link-local's FIB6 lookup filters by output interface and
// skips a reject route on a different one) — a hostile process inside the
// sandbox that has learned the host's link-local address (from an ND
// neighbour advertisement, say) can otherwise reach whatever it binds
// there.
//
// EEXIST is swallowed rather than reported: the v4 primary and every v6
// global address pasta already copied onto snug0 collide with their own
// entry here, under the SAME address/prefixlen — a deliberate no-op, not a
// failure.
func sealHostAddresses(fd int, ifIndex uint32, addrs []netip.Addr) error {
	var seq uint32
	for _, a := range addrs {
		seq++
		if err := newAddr(fd, seq, ifIndex, a); err != nil {
			return fmt.Errorf("sealing host address %s as local on the sandbox's interface: %w", a, err)
		}
	}
	return nil
}

// newAddr sends one RTM_NEWADDR over fd and waits for its ack.
//
// IFA_F_NODAD on the v6 arm skips the tentative/DAD window — there is no
// duplicate to detect on an address the sandbox's own interface did not have
// a moment ago, and without it the address sits DADFAILED-pending rather than
// usable for the seal's own purpose. NEVER set on the v4 arm: it is an
// IPv6-only flag (in the kernel enum, but here the more relevant fact is that
// a v4 address is never tentative to begin with).
func newAddr(fd int, seq, ifIndex uint32, addr netip.Addr) error {
	family := uint8(unix.AF_INET)
	prefixlen := uint8(32)
	var flags uint8
	if addr.Is6() {
		family = unix.AF_INET6
		prefixlen = 128
		flags = unix.IFA_F_NODAD
	}
	payload := addr.AsSlice()

	ifa := unix.IfAddrmsg{Family: family, Prefixlen: prefixlen, Flags: flags, Index: ifIndex}
	var body bytes.Buffer
	if err := binary.Write(&body, binary.NativeEndian, ifa); err != nil {
		return err
	}
	// Both attributes set to the SAME value, matching what `ip addr add`
	// sends for a non-point-to-point address: the kernel's own newaddr path
	// falls back from IFA_LOCAL to IFA_ADDRESS (v4) or the reverse (v6)
	// depending on version, so sending both is what makes this correct on
	// either.
	writeRtAttr(&body, unix.IFA_LOCAL, payload)
	writeRtAttr(&body, unix.IFA_ADDRESS, payload)

	hdr := unix.NlMsghdr{
		Len:  uint32(unix.SizeofNlMsghdr) + uint32(body.Len()),
		Type: unix.RTM_NEWADDR,
		// NLM_F_EXCL, matching `ip addr add`'s own default (not `ip addr
		// change`): this is what makes assigning an address snug0 already
		// carries answer EEXIST rather than silently replacing it.
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
	}
	var msg bytes.Buffer
	if err := binary.Write(&msg, binary.NativeEndian, hdr); err != nil {
		return err
	}
	msg.Write(body.Bytes())

	if _, err := unix.Write(fd, msg.Bytes()); err != nil {
		return fmt.Errorf("RTM_NEWADDR: writing the request: %w", err)
	}
	return readNetlinkAck(fd)
}

// readNetlinkAck reads the one NLMSG_ERROR reply NLM_F_ACK guarantees and
// turns it into an error — nil for a zero error code AND for EEXIST, which
// sealHostAddresses' own doc comment explains is the expected outcome for an
// address pasta already copied.
func readNetlinkAck(fd int) error {
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("reading the netlink reply: %w", err)
	}
	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("netlink reply is %d bytes, shorter than its own header", n)
	}
	var hdr unix.NlMsghdr
	if err := binary.Read(bytes.NewReader(buf[:unix.SizeofNlMsghdr]), binary.NativeEndian, &hdr); err != nil {
		return err
	}
	if hdr.Type != unix.NLMSG_ERROR {
		return fmt.Errorf("expected a netlink ack (type %d), got type %d", unix.NLMSG_ERROR, hdr.Type)
	}
	if n < unix.SizeofNlMsghdr+4 {
		return fmt.Errorf("netlink ack carries no error code")
	}
	errno := int32(binary.NativeEndian.Uint32(buf[unix.SizeofNlMsghdr:]))
	if errno == 0 {
		return nil
	}
	if e := syscall.Errno(-errno); e == unix.EEXIST {
		return nil
	} else {
		return fmt.Errorf("RTM_NEWADDR: %w", e)
	}
}
