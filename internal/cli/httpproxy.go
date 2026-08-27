package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// httpDoorTokenBytes is the per-run URL token's length in raw bytes, rendered as
// hex. 16 bytes is 128 bits: the token is the thing standing between a page the
// human did not open and the sandbox's own server, so it has to be
// unguessable rather than merely unique, and no shorter value buys anything
// except a prettier URL.
const httpDoorTokenBytes = 16

// httpDoorBasePort is the first door's port. Door i takes base+i, so a profile
// naming two doors can have BOTH open at once — they share the run's address,
// and without the offset the second `snug proxy` would die on EADDRINUSE
// against the first.
//
// Fixed rather than allocated, and it costs nothing to fix because each run gets
// its OWN address: two concurrent runs do not collide, so the only conflict left
// is a host service bound on 0.0.0.0, which is refused with a message rather
// than worked around. A memorable number is worth more here than an ephemeral
// one — the human types this URL.
//
// Sharing the address across a run's doors is deliberate: they are one trust
// domain (one sandbox), so one cookie jar between them is not a boundary anyone
// was relying on, and a second address per door would multiply what the human
// has to recognise for nothing.
const httpDoorBasePort = 8099

// httpDoorSubnet is the slice of loopback the door's per-run address is drawn
// from: 127.64.0.0/10, i.e. 127.64.0.0 through 127.127.255.255.
//
// NOT "127.0.0.0/8 avoiding 127.0.0.1". Measured on this host: 127.0.0.53
// (systemd-resolved's stub), 127.0.2.1 (the Debian /etc/hosts convention),
// 127.0.0.0 and 127.255.255.255 all bind successfully, so an exclusion set of
// one address is not an exclusion set. Everything conventional lives low in
// 127/8; this slice is chosen to sit above all of it.
//
// Why a distinct address at all, rather than 127.0.0.1 with a distinct port:
// cookies are not isolated by port (RFC 6265 §8.5 — web-platform spec), so a
// page served on 127.0.0.1 shares a cookie jar with every other service the
// human runs there. A different host STRING is a different cookie host, and
// §5.1.3's domain-matching requires the domain not be an IP, so two loopback
// literals cannot be made to match each other.
var httpDoorSubnet = netip.MustParsePrefix("127.64.0.0/10")

// httpDoor is one resolved door: what snug created, and what a human must type.
type httpDoor struct {
	Name       string
	SocketPath string
	Token      string
	Addr       netip.AddrPort
}

// URL is the exact string the human opens: the app's root plus the one-time
// token. The door answers it with a cookie and a redirect to "/", so this
// parameter is gone from the address bar as soon as the page loads — and the
// app never sees a path it does not own.
func (d httpDoor) URL() string {
	return fmt.Sprintf("http://%s/?snug-token=%s", d.Addr.String(), d.Token)
}

// planHTTPDoors decides every per-run value for the policy's doors.
//
// PER RUN, not per target, and that is the whole point of the nonce: the address
// and the token are what a browser keys its state on, so deriving them from the
// target path would give every run of a project the SAME origin — and a service
// worker, a cache entry or a permission grant left by one run would then be
// waiting for the next one, on a URL the human trusts. Nothing snug can sweep
// sees browser state, so the only defence is never reusing the origin.
//
// socketName is the door's socket file name and the reason door names have a
// narrow grammar: it becomes a single path element in the run's runtime
// directory, where AF_UNIX leaves 107 bytes for the whole path.
func planHTTPDoors(pol *policy.Policy, socketPath func(name string) (string, error)) ([]httpDoor, error) {
	if len(pol.ListenNames) == 0 {
		return nil, nil
	}
	nonce := make([]byte, httpDoorTokenBytes+4)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating this run's http door token: %w", err)
	}
	addr, err := httpDoorAddr(nonce[httpDoorTokenBytes:])
	if err != nil {
		return nil, err
	}
	token := hex.EncodeToString(nonce[:httpDoorTokenBytes])

	doors := make([]httpDoor, 0, len(pol.ListenNames))
	for i, name := range pol.ListenNames {
		path, err := socketPath("door-" + name + ".sock")
		if err != nil {
			return nil, fmt.Errorf("http door %q: %w", name, err)
		}
		doors = append(doors, httpDoor{
			Name:       name,
			SocketPath: path,
			Token:      token,
			Addr:       netip.AddrPortFrom(addr, uint16(httpDoorBasePort+i)),
		})
	}
	return doors, nil
}

// httpDoorAddr draws one address out of httpDoorSubnet.
//
// The host part is forced away from .0 and .255. Neither is reserved on
// loopback — both bind fine, measured — but a host part some future service or
// some client treats specially is a collision the human cannot move, because the
// address is derived rather than configured.
func httpDoorAddr(b []byte) (netip.Addr, error) {
	if len(b) < 4 {
		return netip.Addr{}, fmt.Errorf("http door address needs 4 random bytes, got %d", len(b))
	}
	octets := [4]byte{
		127,                // loopback; /10 constrains the SECOND octet, not this one
		64 + (b[0] & 0x3f), // 64..127 — the range 127.64.0.0/10 actually covers
		b[1],
		1 + (b[2] % 254), // 1..254, avoiding .0 and .255
	}
	addr := netip.AddrFrom4(octets)
	if !httpDoorSubnet.Contains(addr) {
		// NOT unreachable, measured: the first draft of the arithmetic above
		// masked the FIRST octet instead of the second and produced
		// 107.147.60.19 — a routable public address this check refused on the
		// first real run. The comment here used to call the branch unreachable,
		// which is why the wrong version is named rather than quietly fixed: the
		// constant and the arithmetic are two statements of one fact, and this is
		// the only thing that makes them disagree loudly.
		return netip.Addr{}, fmt.Errorf("derived http door address %s is outside %s", addr, httpDoorSubnet)
	}
	return addr, nil
}

// openHTTPDoorSockets binds and listens on every planned door, returning the
// descriptors in the SAME ORDER as doors — which is the order LISTEN_FDNAMES
// names them in, and the order internal/sandbox places them at fd 3...
//
// The socket is a pathname socket at 0600 and it is NOT unlinked after listen.
// Two tempting alternatives are both wrong. Unlinking would break the feature:
// `snug proxy` is a separate, later process that connects BY PATH, unlike this
// one which created the socket. The abstract namespace would connect — the
// creator and the door share the host netns, and the sandbox's own netns cannot
// reach an abstract name at all — but carries NO filesystem permissions, so any
// uid on the machine could connect, discarding one of the two reasons a socket
// beat a TCP port here.
//
// So the leak is stated rather than fixed: getsockname() from inside the sandbox
// returns this path, which discloses the runtime directory and the host uid. It
// is why the path carries no target key.
func openHTTPDoorSockets(doors []httpDoor) ([]*os.File, error) {
	files := make([]*os.File, 0, len(doors))
	cleanup := func() {
		for _, f := range files {
			f.Close()
		}
	}
	for _, d := range doors {
		// 0600 BEFORE the socket exists, via umask on the bind, is not
		// available; chmod after bind leaves a window in which the mode is the
		// process umask's. The window is inside a directory only this uid can
		// traverse (openRuntimeDir's guarantee), which is what makes it
		// acceptable rather than merely convenient.
		l, err := net.Listen("unix", d.SocketPath)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("http door %q: binding %s: %w", d.Name, d.SocketPath, err)
		}
		if err := os.Chmod(d.SocketPath, 0o600); err != nil {
			l.Close()
			cleanup()
			return nil, fmt.Errorf("http door %q: %w", d.Name, err)
		}
		ul, ok := l.(*net.UnixListener)
		if !ok {
			l.Close()
			cleanup()
			return nil, fmt.Errorf("http door %q: net.Listen(\"unix\") returned %T", d.Name, l)
		}
		// SetUnlinkOnClose(false): the payload holds this socket for the life of
		// the run, and THIS process closes its own copy as soon as bwrap is
		// forked. Letting the Go runtime unlink on that close would delete the
		// path `snug proxy` connects to, while the listening socket stayed alive
		// inside — a door that exists and cannot be reached.
		ul.SetUnlinkOnClose(false)
		f, err := ul.File()
		if err != nil {
			l.Close()
			cleanup()
			return nil, fmt.Errorf("http door %q: taking the listening descriptor: %w", d.Name, err)
		}
		// The *net.UnixListener's own descriptor is a DUPLICATE of the one File
		// returned; closing the listener now leaves the file valid and stops this
		// process holding two. The socket keeps listening because the descriptor
		// does, not because the listener object exists.
		l.Close()
		files = append(files, f)
	}
	return files, nil
}

// maxHTTPDoorStateBytes bounds the door file read. A door is a name, a socket
// path, a 32-character token and an address — a few hundred bytes each, and a
// policy naming a hundred doors would already have been refused for other
// reasons. 64 KiB is far beyond any legitimate file and still bounds what a
// planted one can make snug allocate.
const maxHTTPDoorStateBytes = 64 << 10

// httpDoorStateFile is where a run publishes its doors for `snug proxy` to find.
// Beside state.json in the run's own directory rather than inside it: state.json
// has a schema a version check refuses on mismatch, and a door is not something
// `snug attach` needs to understand.
const httpDoorStateFile = "http-doors.json"

// publishHTTPDoors writes this run's doors where `snug proxy` reads them.
//
// 0600, in the run directory only this uid can traverse. What it carries is not
// a secret in the credential sense — the socket path is guessable and the
// address is one of a million — but the TOKEN is exactly a secret: it is what
// stands between a page the human never opened and the sandbox's server.
func publishHTTPDoors(d *runtimeDir, doors []httpDoor) error {
	if d == nil {
		return fmt.Errorf("this run has no runtime directory, so its http doors cannot be " +
			"published and `snug proxy` could never find them")
	}
	path, err := d.Socket(httpDoorStateFile)
	if err != nil {
		return err
	}
	type wire struct {
		Name       string `json:"name"`
		SocketPath string `json:"socket_path"`
		Token      string `json:"token"`
		Addr       string `json:"addr"`
	}
	out := make([]wire, 0, len(doors))
	for _, dr := range doors {
		out = append(out, wire{dr.Name, dr.SocketPath, dr.Token, dr.Addr.String()})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("encoding this run's http doors: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("publishing this run's http doors: %w", err)
	}
	return nil
}

// readHTTPDoors is `snug proxy`'s side of publishHTTPDoors.
func readHTTPDoors(runPath string) ([]httpDoor, error) {
	// hostread.Required, not os.ReadFile: issue #337's shape applies here as
	// everywhere else snug reads a host path it did not just create. This one is
	// inside a run directory only this uid can traverse, so the FIFO route needs
	// that uid already — but "the attacker would have to be you" is an argument
	// about today's mode bits, and a bounded read costs nothing.
	body, err := hostread.Required(filepath.Join(runPath, httpDoorStateFile), maxHTTPDoorStateBytes)
	if err != nil {
		return nil, err
	}
	var wire []struct {
		Name       string `json:"name"`
		SocketPath string `json:"socket_path"`
		Token      string `json:"token"`
		Addr       string `json:"addr"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("reading this run's http doors: %w", err)
	}
	doors := make([]httpDoor, 0, len(wire))
	for _, w := range wire {
		ap, perr := netip.ParseAddrPort(w.Addr)
		if perr != nil {
			return nil, fmt.Errorf("this run's http door %q names address %q, which does not "+
				"parse: %w", w.Name, w.Addr, perr)
		}
		doors = append(doors, httpDoor{Name: w.Name, SocketPath: w.SocketPath, Token: w.Token, Addr: ap})
	}
	return doors, nil
}

// announceHTTPDoors is the escape sentence, on the HUMAN'S OWN TERMINAL.
//
// Not only in the generated CLAUDE.md preamble, and that is the point rather
// than belt-and-braces: the preamble lives in the project tree, which must be
// writable for work to happen, and snug's threat model has a payload that may be
// an agent following instructions planted in that tree. The party that would
// otherwise relay "this is a sandbox escape" is the party the model assumes is
// compromised. stderr is a channel it cannot reach.
func announceHTTPDoors(w io.Writer, doors []httpDoor) {
	for _, d := range doors {
		fmt.Fprintf(w, "snug: http door %q is declared. Nothing is reachable yet — run "+
			"`snug proxy` to open it.\n", d.Name)
	}
	fmt.Fprint(w, "      Opening one serves whatever the sandbox answers into YOUR browser, on an "+
		"origin\n"+
		"      your browser treats as local. THAT IS A SANDBOX ESCAPE and snug does not bound "+
		"it.\n"+
		"      The cost lands while the proxy runs, not only when you open the URL.\n")
}
