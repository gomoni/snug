package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

const (
	// browserFIFOName is the single path element runDir.Socket is asked for.
	browserFIFOName = "browser.fifo"
	// loginMaxLine is the longest URL line the reader accepts, newline
	// excluded. A longer one is discarded up to the next newline and counts
	// as one refusal.
	loginMaxLine = 4096
	// loginRefusalsPrinted bounds the stderr noise a sandbox can cause by
	// writing garbage to the FIFO.
	loginRefusalsPrinted = 5
	// loginRelaySockets is how many relay sockets the bridge asks the stage
	// for: one per callback it relays in a run.
	loginRelaySockets = 3
)

// browserOpener is the opener browserPreflight chose for a run: the desktop
// portal when it answered on the session bus, xdg-open otherwise. Exactly one
// field group is set, and the choice holds for the whole run: a portal that
// stops answering later fails that open, it does not fall back.
type browserOpener struct {
	portal  string // DBUS_SESSION_BUS_ADDRESS the portal answered on
	version uint32 // its OpenURI interface version
	xdg     string // xdg-open's absolute path, when no portal answered
	// noPortal is why the portal was not chosen, set with xdg, so a screen
	// naming xdg-open also says what the portal answered.
	noPortal string
}

// Kind names the opener for the JSON report: "portal" or "xdg-open".
func (o browserOpener) Kind() string {
	if o.portal != "" {
		return "portal"
	}
	return "xdg-open"
}

func (o browserOpener) String() string {
	if o.portal != "" {
		return fmt.Sprintf("desktop portal, org.freedesktop.portal.OpenURI version %d, on the session bus %s",
			o.version, o.portal)
	}
	return o.xdg
}

// open is the Deps.Open of the bridge's host half.
func (o browserOpener) open() func(string) error {
	if o.portal != "" {
		return loginbridge.PortalOpener{Addr: o.portal}.Open
	}
	return loginbridge.Opener{Path: o.xdg}.Open
}

// portalVersion is loginbridge.PortalVersion; a test replaces it.
var portalVersion = loginbridge.PortalVersion

// browserPreflight refuses a run whose profile turns the login bridge on in a
// host that cannot open a browser. It asks the desktop portal first, over the
// session bus in snug's own environment; when no portal answers, it resolves
// xdg-open once, so the opener never searches PATH a second time.
//
// The portal needs no DISPLAY: it runs in the desktop session and opens the
// browser there. xdg-open does — without DISPLAY or WAYLAND_DISPLAY it falls
// back to a text browser on snug's terminal, which the sandbox shares.
func browserPreflight(env policy.Environ) (browserOpener, error) {
	const fallback = "/login inside still works by opening the URL claude prints and pasting the code"
	addr := env.Getenv("DBUS_SESSION_BUS_ADDRESS")
	v, perr := portalVersion(addr)
	if perr == nil {
		return browserOpener{portal: addr, version: v}, nil
	}
	portal := "the desktop portal did not answer (" + perr.Error() + ")"
	xdg, err := env.LookPath("xdg-open")
	if err != nil {
		return browserOpener{}, fmt.Errorf("login.claude opens your browser with the desktop "+
			"portal or xdg-open: %s, and there is no xdg-open on PATH. Run snug in your desktop "+
			"session, or install xdg-utils — or drop login.claude from the profile that "+
			"sets it: %s", portal, fallback)
	}
	if env.Getenv("DISPLAY") == "" && env.Getenv("WAYLAND_DISPLAY") == "" {
		return browserOpener{}, fmt.Errorf("login.claude opens your browser with the desktop "+
			"portal or xdg-open: %s, and neither DISPLAY nor WAYLAND_DISPLAY is set in snug's "+
			"environment, without which xdg-open would start a text browser on this terminal. Run "+
			"snug from your desktop session — or drop login.claude from the profile that "+
			"sets it: %s", portal, fallback)
	}
	return browserOpener{xdg: xdg, noPortal: perr.Error()}, nil
}

// wantsLoginBridge is whether this run starts the bridge at all: the key is on
// and the run is real, since --dry-run and --explain start nothing.
func wantsLoginBridge(pol *policy.Policy, cfg config) bool {
	return pol.Login.Any() && !cfg.startsNothing()
}

// apply asks the stage for the relay sockets. A nil bridge — the key is off —
// asks for none, which is also what sandbox.Run requires of a topology with
// no network.
func (b *loginBridge) apply(o *sandbox.Options) {
	if b == nil {
		return
	}
	addRelaySockets(o, loginRelaySockets, b.setRelay)
}

// flowHandler receives a login flow the predicate accepted. A non-nil error
// is a refusal: the reader prints it, counted with its own, and nothing was
// opened.
type flowHandler func(f loginbridge.Flow) error

// loginBridge is P0's half of the transport: the FIFO descriptor, the reader
// goroutine, the relay sockets the stage hands back, the sandbox init's pid
// the port check reads, and the host half a real run hands flows to.
type loginBridge struct {
	fifoPath string
	fifo     *os.File
	done     chan struct{}
	initPID  atomic.Int64

	mu    sync.Mutex
	relay []*os.File
	host  *loginbridge.Bridge
}

// startLoginBridge creates the FIFO in the run directory, binds it into pol
// at policy.BrowserFIFOGuest and starts the reader, which hands every
// accepted flow to the handler newHandler builds for this bridge.
func startLoginBridge(pol *policy.Policy, socket func(string) (string, error), stderr io.Writer, newHandler func(*loginBridge) flowHandler) (*loginBridge, error) {
	path, err := socket(browserFIFOName)
	if err != nil {
		return nil, err
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		return nil, fmt.Errorf("could not create the login bridge's FIFO %s: %w (the run directory "+
			"must be writable by you; drop login.claude to run without the bridge)", path, err)
	}
	// HOSTREAD-EXEMPT: the FIFO was created two lines up, in this run's own
	// 0700 directory; O_RDWR never blocks the opener.
	// O_RDWR: a FIFO opened read-write never blocks the opener and never
	// reports EOF when the sandbox's writer exits.
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open the login bridge's FIFO %s: %w", path, err)
	}
	pol.BindSocket(path, policy.BrowserFIFOGuest, "(browser)")
	b := &loginBridge{fifoPath: path, fifo: f, done: make(chan struct{})}
	handle := newHandler(b)
	go func() {
		defer close(b.done)
		readLoginLines(f, stderr, handle)
	}()
	return b, nil
}

// hostHandler builds the host half — listener, relay or exchange, opener —
// over this bridge's relay sockets and the sandbox init's /proc, and returns
// its Handle. opener is what browserPreflight chose; files is
// login.claude = "host"'s host-file half, nil in sandbox mode.
func (b *loginBridge) hostHandler(opener browserOpener, files *claudeHostFiles, stderr io.Writer) flowHandler {
	d := loginbridge.Deps{
		Clock:     loginbridge.RealClock{},
		Relayer:   b,
		Listening: b.listening,
		PeerUID:   loginbridge.PeerUID,
		UID:       os.Getuid(),
		Open:      opener.open(),
		Stderr:    stderr,
	}
	if files != nil {
		d.Host = &loginbridge.HostLogin{Files: files}
	}
	h := loginbridge.New(d)
	b.mu.Lock()
	b.host = h
	b.mu.Unlock()
	return h.Handle
}

// setInitPID is fed from Options.OnInit: the pid whose /proc/<pid>/net/tcp
// lists the sockets of the sandbox's network namespace.
func (b *loginBridge) setInitPID(pid int) { b.initPID.Store(int64(pid)) }

func (b *loginBridge) listening(port int) (bool, error) {
	pid := b.initPID.Load()
	if pid == 0 {
		return false, errors.New("the sandbox has not started yet")
	}
	return loginbridge.ListeningOn(fmt.Sprintf("/proc/%d/net/tcp", pid), port)
}

// Left is loginbridge.Relayer's: the relay sockets not yet spent.
func (b *loginBridge) Left() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.relay)
}

// Dial spends one relay socket on connect(127.0.0.1:port). The socket was
// created in the sandbox's network namespace, so that address is the
// sandbox's loopback, not the host's.
func (b *loginBridge) Dial(port int) (net.Conn, error) {
	b.mu.Lock()
	if len(b.relay) == 0 {
		b.mu.Unlock()
		return nil, errors.New("no relay socket is left in this run")
	}
	f := b.relay[0]
	b.relay = b.relay[1:]
	b.mu.Unlock()
	defer f.Close()
	sa := &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Connect(int(f.Fd()), sa); err != nil {
		return nil, fmt.Errorf("connecting to 127.0.0.1:%d inside the sandbox: %w", port, err)
	}
	return net.FileConn(f)
}

// setRelay is Options.OnRelaySockets.
func (b *loginBridge) setRelay(fs []*os.File) error {
	b.mu.Lock()
	b.relay = fs
	b.mu.Unlock()
	return nil
}

// close stops the reader, ends any live flow (its listeners and
// connections), and closes the FIFO and the relay sockets. The FIFO file
// itself is removed with the run directory.
func (b *loginBridge) close() {
	b.fifo.Close()
	<-b.done
	b.mu.Lock()
	h := b.host
	b.mu.Unlock()
	if h != nil {
		h.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.relay {
		f.Close()
	}
	b.relay = nil
}

// readLoginLines reads newline-terminated lines from r until it errors,
// which is the descriptor closing. Nothing is ever written back.
func readLoginLines(r io.Reader, stderr io.Writer, handle flowHandler) {
	br := bufio.NewReaderSize(r, loginMaxLine+1)
	refusals := 0
	refuse := func(reason string) {
		refusals++
		switch {
		case refusals <= loginRefusalsPrinted:
			fmt.Fprintf(stderr, "snug: login bridge: refused an open request from the sandbox — %s. "+
				"Nothing was opened.\n", policy.VisibleText(reason))
		case refusals == loginRefusalsPrinted+1:
			fmt.Fprintf(stderr, "snug: login bridge: further refusals suppressed.\n")
		}
	}
	overlong := false
	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			if !overlong {
				overlong = true
				refuse(fmt.Sprintf("the request is longer than %d bytes", loginMaxLine))
			}
			continue
		case err != nil:
			return
		}
		if overlong {
			overlong = false
			continue
		}
		line := string(chunk[:len(chunk)-1])
		flow, perr := loginbridge.ParseAuthorize(line)
		if perr != nil {
			refuse(perr.Error())
			continue
		}
		if herr := handle(flow); herr != nil {
			refuse(herr.Error())
		}
	}
}
