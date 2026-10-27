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
//
// It writes nothing when the key is off, when refusedBy is set, or when the
// guest path is already mapped. Replace appends `replaces:<old From>` to a
// mount it displaces, so a second call over its own (browser) row would print
// "(browser)+replaces:(browser)"; and on a refused policy the mount at the
// guest path is the OFFENDING profile's, which a replacement would erase from
// the one screen that exists to name it.
func planBrowserFIFO(p *policy.Policy, refusedBy error) error {
	if !p.Login.Any() || refusedBy != nil {
		return nil
	}
	if p.Login.Mode(policy.LoginClaude) == policy.LoginHost {
		if _, mapped := p.Mounts[policy.ClaudeCredentialDirGuest]; !mapped {
			dir, err := plannedClaudeRunDir()
			if err != nil {
				return err
			}
			p.BindRunDir(dir, policy.ClaudeCredentialDirGuest, policy.LoginKey(policy.LoginClaude, policy.LoginHost))
		}
	}
	if _, mapped := p.Mounts[policy.BrowserFIFOGuest]; mapped {
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
	fmt.Fprintf(out, "         browser bridge  %s — the sandbox may ask snug to open a Claude login page\n",
		strings.Join(b.Keys, " "))
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
	if b.HostRewrite {
		fmt.Fprintf(out, "         host login      A LOGIN YOU APPROVE REWRITES THIS HOST'S ~/.claude/.credentials.json:\n")
		fmt.Fprintf(out, "                         snug opens the page with its own verifier and state, exchanges\n")
		fmt.Fprintf(out, "                         the code on the host, and replaces the host's refresh token for\n")
		fmt.Fprintf(out, "                         the account ~/.claude.json names, never another; the sandbox gets\n")
		fmt.Fprintf(out, "                         a fresh access token only, at %s.\n", policy.ClaudeCredentialDirGuest)
		fmt.Fprintf(out, "                         At most %d rewrites per run, each a click of yours.\n", b.MaxRelays)
		if b.HostError != "" {
			fmt.Fprintf(out, "                         a real run would REFUSE to start: %s\n", visibleValue(b.HostError))
		}
	}
	if b.OpenerError != "" {
		fmt.Fprintf(out, "         opener          NONE — a real run would REFUSE to start: %s\n", visibleValue(b.OpenerError))
	} else {
		fmt.Fprintf(out, "         opener          %s\n", visibleValue(b.Opener))
		if b.PortalError != "" {
			fmt.Fprintf(out, "                         not the desktop portal: %s\n", visibleValue(b.PortalError))
		}
	}
	fmt.Fprintf(out, "         limits          %d opens and %d callbacks per run, %d login pending at a time\n",
		b.MaxOpens, b.MaxRelays, loginbridge.MaxLiveFlows)
}

// describeBrowserTopology prints the TOPOLOGY rows for the opener. It is not
// in longLivedProcesses: xdg-open is started per login, not per run, and the
// portal starts nothing in snug's tree, so counting either would make the
// process count a `ps` check cannot confirm. NETWORK's opener row names which
// one this host gets; this block reads only the policy.
func describeBrowserTopology(out io.Writer, p *policy.Policy) {
	if !p.Login.Any() {
		return
	}
	fmt.Fprintf(out, "  login opener    once per accepted login: the desktop portal's OpenURI, or, where\n")
	fmt.Fprintf(out, "                  no portal answers, xdg-open started by snug, detached. snug waits\n")
	fmt.Fprintf(out, "                  at most %s PER LOGIN for the portal's answer or xdg-open's exit\n", loginbridge.OpenerPatience.Round(time.Second))
	fmt.Fprintf(out, "                  status, and reaps xdg-open only while snug is alive: xdg-open\n")
	fmt.Fprintf(out, "                  itself, and the BROWSER either one starts — YOURS, not a child\n")
	fmt.Fprintf(out, "                  of the sandbox — may outlive this run.\n")
}
