package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
)

// planBrowserFIFO is the --dry-run counterpart of startLoginBridge's
// BindSocket: it names the FIFO a real run would create, creating nothing, so
// the FILESYSTEM block and the mounts array carry the same row a run would.
// It is a no-op when the key is off. Replace is idempotent on a guest path,
// so calling it where a real run already bound the FIFO changes nothing.
func planBrowserFIFO(p *policy.Policy) error {
	if p.Browser == policy.BrowserOff {
		return nil
	}
	path, err := plannedSocket(browserFIFOName)
	if err != nil {
		return err
	}
	p.BindSocket(path, policy.BrowserFIFOGuest, "(browser)")
	return nil
}

// renderBrowserBridge prints the login bridge's rows inside the NETWORK
// block. Nothing when the key is off. The port is per-flow and so is not
// named: it exists only while a login is pending.
func renderBrowserBridge(out io.Writer, b *reportBrowserBridge) {
	if b == nil {
		return
	}
	scopes := loginbridge.PinnedScopes()
	fmt.Fprintf(out, "         browser bridge  %s — the sandbox may ask snug to open a Claude login page\n", b.Mode)
	fmt.Fprintf(out, "                         in YOUR browser, directly, one at a time. Accepted shape:\n")
	fmt.Fprintf(out, "                         %s\n", loginbridge.PinnedAuthorizeBase())
	fmt.Fprintf(out, "                         client %s, exactly %d scopes:\n", loginbridge.PinnedClientID(), len(scopes))
	fmt.Fprintf(out, "                         %s\n", strings.Join(scopes[:3], " "))
	fmt.Fprintf(out, "                         %s;\n", strings.Join(scopes[3:], " "))
	fmt.Fprintf(out, "                         anything else is REFUSED, and snug rebuilds the URL it opens\n")
	fmt.Fprintf(out, "                         from its own constants.\n")
	fmt.Fprintf(out, "                         callback: snug binds localhost:<port> (127.0.0.1 and ::1) on\n")
	fmt.Fprintf(out, "                         the host only while a login is pending (at most %s), admits\n", loginbridge.FlowTTL)
	fmt.Fprintf(out, "                         your uid only, relays ONE rebuilt GET /callback into the\n")
	fmt.Fprintf(out, "                         sandbox and answers your browser itself. Nothing is forwarded\n")
	fmt.Fprintf(out, "                         into the sandbox's namespace; host loopback stays unreachable\n")
	fmt.Fprintf(out, "                         from inside.\n")
	if b.OpenerError != "" {
		fmt.Fprintf(out, "         opener          NONE — a real run would REFUSE to start: %s\n", visibleValue(b.OpenerError))
	} else {
		fmt.Fprintf(out, "         opener          %s\n", visibleValue(b.Opener))
	}
	fmt.Fprintf(out, "         limits          %d opens and %d callbacks per run, %d login pending at a time\n",
		b.MaxOpens, b.MaxRelays, loginbridge.MaxLiveFlows)
}

// describeBrowserTopology prints the TOPOLOGY rows for the opener. It is not
// in longLivedProcesses: xdg-open is started per login, not per run, so
// counting it would make the process count a `ps` check cannot confirm.
func describeBrowserTopology(out io.Writer, p *policy.Policy) {
	if p.Browser == policy.BrowserOff {
		return
	}
	fmt.Fprintf(out, "  login opener    xdg-open, started by snug once per accepted login, detached;\n")
	fmt.Fprintf(out, "                  snug waits at most %s for it. The BROWSER it starts is YOURS —\n", loginbridge.OpenerPatience.Round(time.Second))
	fmt.Fprintf(out, "                  not a child of the sandbox — and may outlive this run.\n")
}
