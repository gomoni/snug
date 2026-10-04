package loginbridge

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
)

// openerOutputCap bounds the opener output snug keeps to show on failure.
const openerOutputCap = 4 << 10

// Opener runs xdg-open on the rebuilt authorize URL.
type Opener struct {
	// Path is xdg-open's absolute path, resolved once at preflight so no
	// PATH search happens at open time.
	Path string
	// Patience is how long Open waits for the opener to exit; zero means
	// OpenerPatience.
	Patience time.Duration
}

// openerCmd builds the opener's command. Its environment is snug's own,
// stated explicitly: this starts the host user's browser, and nothing in it
// comes from the sandbox.
func (o Opener) openerCmd(url string) *exec.Cmd {
	cmd := &exec.Cmd{Path: o.Path, Args: []string{o.Path, url}}
	cmd.Env = os.Environ()
	// Setsid and deliberately no Pdeathsig: when no browser is running yet,
	// the opener may become the user's browser, and killing it with the
	// sandbox would close the user's own windows. That process outliving the
	// run is the accepted cost.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// Open starts the opener and waits up to Patience for it. It returns an
// error naming the opener's exit status and its output (forging runes made
// visible) when it exits non-zero; an opener still running after Patience is
// left to a goroutine that reaps it whenever it exits, and Open returns nil.
//
// Output goes to a memfd rather than a pipe: a browser the opener starts
// inherits it, and a pipe snug stopped reading would kill that browser with
// SIGPIPE on its next write to stdout.
func (o Opener) Open(url string) error {
	patience := o.Patience
	if patience == 0 {
		patience = OpenerPatience
	}
	cmd := o.openerCmd(url)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("could not open %s for xdg-open's stdin: %v", os.DevNull, err)
	}
	defer devnull.Close()
	mfd, err := unix.MemfdCreate("snug-xdg-open", unix.MFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("could not create a buffer for xdg-open's output: %v", err)
	}
	out := os.NewFile(uintptr(mfd), "snug-xdg-open")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, out, out
	// The relay sockets and the FIFO are already close-on-exec; sealing every
	// descriptor makes that true of whatever else this process holds too.
	if err := fdseal.SealFor(cmd); err != nil {
		out.Close()
		return fmt.Errorf("xdg-open was not started: %v", err)
	}
	if err := cmd.Start(); err != nil {
		out.Close()
		return fmt.Errorf("xdg-open (%s) could not start: %v", o.Path, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case werr := <-done:
		defer out.Close()
		if werr == nil {
			return nil
		}
		buf := make([]byte, openerOutputCap)
		n, _ := out.ReadAt(buf, 0)
		msg := strings.TrimSpace(string(buf[:n]))
		if msg != "" {
			msg = "; it printed: " + policy.VisibleText(msg)
		}
		return fmt.Errorf("xdg-open (%s) failed: %v%s", o.Path, werr, msg)
	case <-time.After(patience):
		go func() {
			<-done
			out.Close()
		}()
		return nil
	}
}
