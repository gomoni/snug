package loginbridge

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// tcpListen is the st column procfs prints for a socket in TCP_LISTEN.
const tcpListen = "0A"

// procAddr formats a in the address:port spelling of /proc/net/tcp{,6}: the
// address as the kernel's in-memory 32-bit words, each printed %08X in host
// byte order, and the port as %04X.
func procAddr(a netip.AddrPort) string {
	var raw []byte
	if a.Addr().Is4() {
		b := a.Addr().As4()
		raw = b[:]
	} else {
		b := a.Addr().As16()
		raw = b[:]
	}
	var s strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&s, "%08X", binary.NativeEndian.Uint32(raw[i:i+4]))
	}
	fmt.Fprintf(&s, ":%04X", a.Port())
	return s.String()
}

// procRows calls fn with the local, remote, state and uid columns of every
// socket row in a /proc/<pid>/net/tcp{,6} file.
func procRows(r io.Reader, fn func(local, remote, st, uid string)) error {
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		fn(f[1], f[2], f[3], f[7])
	}
	return sc.Err()
}

// ListeningOn reports whether the /proc/<pid>/net/tcp file at path has a
// socket in LISTEN on 127.0.0.1:port. It errors only when the file cannot be
// read.
//
// This is a consistency check and not a bound: the payload can listen on any
// port it likes. It turns "nothing is listening" into a refusal before a
// browser tab opens onto a dead callback.
func ListeningOn(path string, port int) (bool, error) {
	// HOSTREAD-EXEMPT: procfs, read-only, of a process snug itself started.
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	want := procAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)))
	found := false
	err = procRows(f, func(local, _, st, _ string) {
		if local == want && st == tcpListen {
			found = true
		}
	})
	return found, err
}

// PeerUID returns the uid owning the client end of a connection snug
// accepted, looked up in this process's own network namespace's
// /proc/self/net/tcp and tcp6. peer is the accepted connection's remote
// address and local its local one; the row wanted is the CLIENT's, whose
// local column is peer and whose remote column is local — the accepted
// socket's own row has the two swapped and is always snug's uid.
//
// ok is false when no row matches, when two matching rows disagree, or when
// a file cannot be read: the caller refuses on false, so every doubt fails
// closed. A client on a dual-stack AF_INET6 socket connecting to 127.0.0.1
// shows up in tcp6 under the v4-mapped address, so both spellings are tried.
func PeerUID(peer, local netip.AddrPort) (uid int, ok bool) {
	return peerUIDFrom("/proc/self/net/tcp", "/proc/self/net/tcp6", peer, local)
}

func peerUIDFrom(tcp, tcp6 string, peer, local netip.AddrPort) (int, bool) {
	type key struct{ l, r string }
	var want []key
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	want = append(want, key{procAddr(peer), procAddr(local)})
	if peer.Addr().Is4() && local.Addr().Is4() {
		m := func(a netip.AddrPort) netip.AddrPort {
			return netip.AddrPortFrom(netip.AddrFrom16(a.Addr().As16()), a.Port())
		}
		want = append(want, key{procAddr(m(peer)), procAddr(m(local))})
	}
	uid, matched := -1, false
	for _, path := range []string{tcp, tcp6} {
		// HOSTREAD-EXEMPT: procfs of snug's own process.
		f, err := os.Open(path)
		if err != nil {
			if path == tcp6 && errors.Is(err, fs.ErrNotExist) {
				// No IPv6 in this kernel: there is no row there to find.
				continue
			}
			return 0, false
		}
		disagree := false
		err = procRows(f, func(l, r, _, u string) {
			for _, k := range want {
				if l != k.l || r != k.r {
					continue
				}
				n, perr := strconv.Atoi(u)
				if perr != nil || (matched && n != uid) {
					disagree = true
					return
				}
				uid, matched = n, true
			}
		})
		f.Close()
		if err != nil || disagree {
			return 0, false
		}
	}
	return uid, matched
}
