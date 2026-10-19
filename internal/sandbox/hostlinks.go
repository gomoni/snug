package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// HostNet is one prefix a host interface carries, with what snug makes of
// that interface. Prefix is the zero value when a HostNet describes an
// interface alone (RouteIface).
type HostNet struct {
	// Prefix is an address with the subnet it is attached to, unmapped and
	// without a zone; not masked, so Addr is the host's own address.
	Prefix netip.Prefix
	Iface  string
	// Kind is a display string: "physical", "wwan", "tun", "wireguard", or
	// the refused link's own kind ("bridge", "veth", "gre", ...), "tap",
	// "virtual", "enslaved physical" or "loopback".
	Kind string
	// Allowed is true only for an interface the allow list in classifyLink
	// names. Everything else is a network that runs on this host.
	Allowed bool
	// RouteBits and Default are set by RouteIface only: the prefix length of
	// the FIB entry that matched, and whether it is the default route
	// (length 0). Default is false in the zero value so a HostNet nobody
	// filled in keeps the route-egress refusal.
	RouteBits int
	Default   bool
}

// linkInfo is the part of a netlink link message classifyLink reads, plus the
// one sysfs fact.
type linkInfo struct {
	Name string
	// Kind is IFLA_INFO_KIND; "" for a link the kernel gives no kind, which
	// is every physical NIC and also a few out-of-tree virtual drivers.
	Kind   string
	Flags  uint32
	Master uint32
	// Device is /sys/class/net/<Name>/device existing: a bus device backs it.
	Device bool
}

// namedVirtualKinds are the refused kinds snug names in its messages and its
// docs. A kind outside the allow list is refused whether or not it is here;
// this set only chooses the wording.
var namedVirtualKinds = map[string]bool{
	"bridge": true, "veth": true, "tap": true, "macvlan": true, "macvtap": true,
	"ipvlan": true, "ipvtap": true, "vxlan": true, "geneve": true, "dummy": true,
	"vrf": true, "bond": true, "team": true, "vlan": true, "gre": true,
	"gretap": true, "ipip": true, "sit": true, "erspan": true,
}

// IsNamedVirtualKind reports whether kind is one of the refused link kinds
// snug names, as opposed to one it refuses only for not being on the allow
// list.
func IsNamedVirtualKind(kind string) bool { return namedVirtualKinds[kind] }

// classifyLink is the whole allow list: a physical NIC (no kind, a backing
// device, not loopback, not enslaved), a wwan modem, a layer-3 tun and
// wireguard. It returns the display kind and whether the link is allowed.
//
// A hostile process inside the sandbox can use a wrong "allowed" to act as
// the user on a cluster whose nodes run on this host, so a kind not named
// here is refused.
func classifyLink(l linkInfo) (kind string, allowed bool) {
	switch {
	case l.Flags&unix.IFF_LOOPBACK != 0:
		return "loopback", false
	case l.Kind == "":
		switch {
		case !l.Device:
			return "virtual", false
		case l.Master != 0:
			return "enslaved physical", false
		}
		return "physical", true
	case l.Kind == "tun":
		if l.Flags&unix.IFF_POINTOPOINT != 0 {
			return "tun", true
		}
		return "tap", false
	case l.Kind == "wwan", l.Kind == "wireguard":
		return l.Kind, true
	}
	return l.Kind, false
}

// HostLinks lists every prefix on every host interface, loopback included,
// each with its interface classified. identity.kubectl's dialer reads it on
// every dial. It fails when the kernel's answer could not be read whole: a
// partial list would read as a host with fewer networks.
func HostLinks() ([]HostNet, error) {
	links, err := readLinks()
	if err != nil {
		return nil, err
	}
	msgs, err := dump(unix.RTM_GETADDR)
	if err != nil {
		return nil, fmt.Errorf("listing host addresses: %w", err)
	}
	var recs []addrRec
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWADDR || len(m.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		at := attrs(m.Data[unix.SizeofIfAddrmsg:])
		raw, ok := at[unix.IFA_LOCAL]
		if !ok {
			raw = at[unix.IFA_ADDRESS]
		}
		recs = append(recs, addrRec{
			Index: binary.NativeEndian.Uint32(m.Data[4:8]),
			Bits:  int(m.Data[1]),
			Raw:   raw,
		})
	}
	return joinAddrs(links, recs)
}

// addrRec is one RTM_NEWADDR message as read.
type addrRec struct {
	Index uint32
	Bits  int
	Raw   []byte
}

// joinAddrs pairs each address with its link. An address that does not parse
// is an error, not a skip: dropping it would remove a host-owned address from
// the host-owned check. An address whose link is not in the map is kept as an
// "unknown", refused link, for the same reason.
func joinAddrs(links map[uint32]classifiedLink, recs []addrRec) ([]HostNet, error) {
	var out []HostNet
	for _, r := range recs {
		ip, ok := netip.AddrFromSlice(r.Raw)
		pfx := netip.PrefixFrom(ip, r.Bits)
		if !ok || !pfx.IsValid() {
			return nil, fmt.Errorf("interface %d carries an address snug cannot read (%d bytes, /%d)",
				r.Index, len(r.Raw), r.Bits)
		}
		n := HostNet{Prefix: pfx, Kind: "unknown"}
		if l, known := links[r.Index]; known {
			n.Iface, n.Kind, n.Allowed = l.Iface, l.Kind, l.Allowed
		} else {
			n.Iface = fmt.Sprintf("#%d", r.Index)
		}
		out = append(out, n)
	}
	return out, nil
}

// RouteIface asks the kernel which interface a packet to a would leave by
// (RTM_GETROUTE with RTA_DST) and classifies it. The answer is the routing
// table's, not netfilter's: an address DNAT'ed by the host's rules is routed
// as written. It fails when the kernel has no route, which reads as "refuse".
func RouteIface(a netip.Addr) (HostNet, error) {
	a = a.Unmap().WithZone("")
	oif, bits, err := routeOIF(a, unix.RTM_F_FIB_MATCH)
	if err != nil {
		return HostNet{}, fmt.Errorf("route lookup for %s: %w", a, err)
	}
	links, err := readLinks()
	if err != nil {
		return HostNet{}, err
	}
	l, ok := links[oif]
	if !ok {
		return HostNet{}, fmt.Errorf("route lookup for %s: output interface %d is not in the link list", a, oif)
	}
	return HostNet{Iface: l.Iface, Kind: l.Kind, Allowed: l.Allowed, RouteBits: bits, Default: bits == 0}, nil
}

type classifiedLink struct {
	Iface   string
	Kind    string
	Allowed bool
}

func readLinks() (map[uint32]classifiedLink, error) {
	msgs, err := dump(unix.RTM_GETLINK)
	if err != nil {
		return nil, fmt.Errorf("listing host interfaces: %w", err)
	}
	out := map[uint32]classifiedLink{}
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		idx := binary.NativeEndian.Uint32(m.Data[4:8])
		li := linkInfo{Flags: binary.NativeEndian.Uint32(m.Data[8:12])}
		at := attrs(m.Data[unix.SizeofIfInfomsg:])
		li.Name = cstring(at[unix.IFLA_IFNAME])
		if v := at[unix.IFLA_MASTER]; len(v) == 4 {
			li.Master = binary.NativeEndian.Uint32(v)
		}
		li.Kind = cstring(attrs(at[unix.IFLA_LINKINFO])[unix.IFLA_INFO_KIND])
		if li.Name == "" {
			return nil, fmt.Errorf("interface %d has no name in the kernel's answer", idx)
		}
		if li.Kind == "" {
			_, err := os.Stat("/sys/class/net/" + li.Name + "/device")
			switch {
			case err == nil:
				li.Device = true
			case errors.Is(err, os.ErrNotExist):
			default:
				return nil, fmt.Errorf("checking whether %s has a backing device: %w", li.Name, err)
			}
		}
		kind, ok := classifyLink(li)
		out[idx] = classifiedLink{Iface: li.Name, Kind: kind, Allowed: ok}
	}
	return out, nil
}

func dump(typ uint16) ([]syscall.NetlinkMessage, error) {
	rib, err := syscall.NetlinkRIB(int(typ), syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(rib)
}

// attrs indexes the rtattrs in b by type, nested and byte-order flags
// masked. A truncated attribute ends the walk.
func attrs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= unix.SizeofRtAttr {
		n := int(binary.NativeEndian.Uint16(b[0:2]))
		if n < unix.SizeofRtAttr || n > len(b) {
			break
		}
		t := binary.NativeEndian.Uint16(b[2:4]) &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)
		out[t] = b[unix.SizeofRtAttr:n]
		adv := (n + unix.NLA_ALIGNTO - 1) &^ (unix.NLA_ALIGNTO - 1)
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// routeOIF returns the output interface and the matched entry's rtm_dst_len.
// With RTM_F_FIB_MATCH the kernel answers with the FIB entry that matched;
// without it, the answer is the resolved route to the single address.
func routeOIF(a netip.Addr, flags uint32) (uint32, int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: 5}); err != nil {
		return 0, 0, err
	}
	fam := uint8(unix.AF_INET)
	if a.Is6() {
		fam = unix.AF_INET6
	}
	dst := a.AsSlice()
	attr := make([]byte, 4+len(dst))
	binary.NativeEndian.PutUint16(attr[0:], uint16(4+len(dst)))
	binary.NativeEndian.PutUint16(attr[2:], unix.RTA_DST)
	copy(attr[4:], dst)

	msg := make([]byte, unix.SizeofNlMsghdr+unix.SizeofRtMsg, unix.SizeofNlMsghdr+unix.SizeofRtMsg+len(attr))
	binary.NativeEndian.PutUint16(msg[4:], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg[unix.SizeofNlMsghdr] = fam
	msg[unix.SizeofNlMsghdr+1] = uint8(len(dst) * 8)
	binary.NativeEndian.PutUint32(msg[unix.SizeofNlMsghdr+8:], flags)
	msg = append(msg, attr...)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	if _, err := unix.Write(fd, msg); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 1<<16)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return 0, 0, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return 0, 0, err
	}
	for _, m := range msgs {
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			if len(m.Data) >= 4 {
				if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
					return 0, 0, syscall.Errno(-e)
				}
			}
		case unix.RTM_NEWROUTE:
			if len(m.Data) < unix.SizeofRtMsg {
				continue
			}
			if v := attrs(m.Data[unix.SizeofRtMsg:])[unix.RTA_OIF]; len(v) == 4 {
				return binary.NativeEndian.Uint32(v), int(m.Data[1]), nil
			}
		}
	}
	return 0, 0, errors.New("the kernel's answer names no output interface")
}
