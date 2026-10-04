package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
	"github.com/gomoni/snug/internal/stage"
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
	// loginRelaySockets is how many relay sockets the run asks the stage for:
	// the stage's own maximum.
	loginRelaySockets = stage.MaxRelaySockets
)

// browserPreflight refuses a run whose profile turns the login bridge on in a
// host that cannot open a browser. It returns xdg-open's absolute path,
// resolved once, so the opener never searches PATH a second time.
func browserPreflight(env policy.Environ) (string, error) {
	const fallback = "/login inside still works by opening the URL claude prints and pasting the code"
	xdg, err := env.LookPath("xdg-open")
	if err != nil {
		return "", fmt.Errorf("browser = \"claude-login\" opens your browser with xdg-open, and "+
			"there is none on PATH. Install xdg-utils — or drop browser = \"claude-login\" from "+
			"the profile that sets it: %s", fallback)
	}
	if env.Getenv("DISPLAY") == "" && env.Getenv("WAYLAND_DISPLAY") == "" {
		return "", fmt.Errorf("browser = \"claude-login\" needs a graphical session to open your "+
			"browser, and neither DISPLAY nor WAYLAND_DISPLAY is set in snug's environment. Run "+
			"snug from your desktop session — or drop browser = \"claude-login\" from the "+
			"profile that sets it: %s", fallback)
	}
	return xdg, nil
}

func announceLoginBridge(n *notes) {
	n.escape("snug: browser = \"claude-login\": the sandbox can ask snug to open a Claude " +
		"login page in your browser.\n" +
		"      snug opens only the one URL shape it pins, rebuilt from its own constants — " +
		"if you did not just type /login, close the page.\n")
}

// wantsLoginBridge is whether this run starts the bridge at all: the key is on
// and the run is real, since --dry-run and --explain start nothing.
func wantsLoginBridge(pol *policy.Policy, cfg config) bool {
	return pol.Browser != policy.BrowserOff && !cfg.startsNothing()
}

// apply asks the stage for the relay sockets. A nil bridge — the key is off —
// asks for none, which is also what sandbox.Run requires of a topology with
// no network.
func (b *loginBridge) apply(o *sandbox.Options) {
	if b == nil {
		return
	}
	o.RelaySockets = loginRelaySockets
	o.OnRelaySockets = b.setRelay
}

// flowHandler receives a login flow the predicate accepted. It is the one
// place the host half (listener, relay, opener) plugs in.
type flowHandler func(f loginbridge.Flow)

// loginBridge is P0's half of the transport: the FIFO descriptor, the reader
// goroutine and the relay sockets the stage hands back.
type loginBridge struct {
	fifoPath string
	fifo     *os.File
	done     chan struct{}

	mu    sync.Mutex
	relay []*os.File
}

// startLoginBridge creates the FIFO in the run directory, binds it into pol
// at policy.BrowserFIFOGuest and starts the reader.
func startLoginBridge(pol *policy.Policy, socket func(string) (string, error), stderr io.Writer, handle flowHandler) (*loginBridge, error) {
	path, err := socket(browserFIFOName)
	if err != nil {
		return nil, err
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		return nil, fmt.Errorf("could not create the login bridge's FIFO %s: %w (the run directory "+
			"must be writable by you; drop browser = \"claude-login\" to run without the bridge)", path, err)
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
	go func() {
		defer close(b.done)
		readLoginLines(f, stderr, handle)
	}()
	return b, nil
}

// setRelay is Options.OnRelaySockets.
func (b *loginBridge) setRelay(fs []*os.File) {
	b.mu.Lock()
	b.relay = fs
	b.mu.Unlock()
}

// close stops the reader and closes the FIFO and the relay sockets. The
// FIFO file itself is removed with the run directory.
func (b *loginBridge) close() {
	b.fifo.Close()
	<-b.done
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
		handle(flow)
	}
}

// notYetBuiltHandler stands in for the host listener, relay and opener.
func notYetBuiltHandler(stderr io.Writer) flowHandler {
	return func(f loginbridge.Flow) {
		fmt.Fprintf(stderr, "snug: login bridge: accepted a login URL for port %d, but the host "+
			"half (listener, relay, opener) is not implemented in this build. NOTHING WAS OPENED — "+
			"open the URL claude printed and paste the code.\n", f.Port)
	}
}
