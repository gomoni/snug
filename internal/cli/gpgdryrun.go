package cli

import (
	"fmt"
	"io"

	"github.com/gomoni/snug/internal/policy"
)

// reportGPG is what identity.gpg grants, for both --dry-run screens. The
// FILESYSTEM rows show a socket and a keyring; neither says WHICH host key
// answers on that socket or what the sandbox may do with it, and a sign grant
// and a decrypt grant would otherwise read the same.
type reportGPG struct {
	Fingerprint string
	Scope       []string // "sign", "decrypt", in that order
	Proxy       string   // the socket's guest path
}

func buildGPGReport(p *policy.Policy) *reportGPG {
	if !p.Identity.Pinned("gpg") {
		return nil
	}
	r := &reportGPG{
		Fingerprint: p.Identity.GPG.Fingerprint,
		Proxy:       p.Home + "/" + policy.GPGAgentSocketGuest,
	}
	for _, s := range []string{policy.GPGScopeSign, policy.GPGScopeDecrypt} {
		if policy.GPGScopeHas(p.Identity.GPG.Scope, s) {
			r.Scope = append(r.Scope, s)
		}
	}
	return r
}

// jsonGPG is reportGPG.
type jsonGPG struct {
	Fingerprint string   `json:"fingerprint"`
	Scope       []string `json:"scope"`
	Proxy       string   `json:"proxy_guest"`
}

func describeGPG(out io.Writer, g *reportGPG) {
	if g == nil {
		return
	}
	fmt.Fprintf(out, "GPG      ~/.gnupg/S.gpg-agent is a filtering proxy to your host gpg-agent\n")
	fmt.Fprintf(out, "         key        %s, the only key listed or usable\n",
		policy.VisibleText(g.Fingerprint))
	for _, s := range g.Scope {
		switch s {
		case policy.GPGScopeSign:
			fmt.Fprintf(out, "         sign       anything, as you, while the run lasts\n")
		case policy.GPGScopeDecrypt:
			fmt.Fprintf(out, "         decrypt    anything addressed to the key that the sandbox can read\n")
		}
	}
}
