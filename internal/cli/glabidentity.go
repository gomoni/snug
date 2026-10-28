package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// glabAccount is what the host's glab holds for one host: the token, the login
// it belongs to, and whether it is an OAuth access token.
type glabAccount struct {
	User  string
	Token policy.Secret
	OAuth bool
}

// glabMinter and netrcReader are stageGlabConfig's two host touches, as
// parameters for the reason tokenMinter is one: the half that MOVES A
// CREDENTIAL sits behind an exec or a file read, and a package-level var a test
// swapped would be reachable from every other test in this package.
//
// A glabMinter returns an error for every way the host cannot answer — glab
// absent, no such host, no token — and never an account with an empty token.
type glabMinter func(host string) (glabAccount, error)

type netrcReader func() ([]byte, error)

// glabTokenVars are the environment names glab reads in place of the config it
// is asked about. A `glab config get token` run with one of them set can answer
// with THAT value rather than the account stored for the host, so snug would
// stage a token it never read from the pinned host's entry.
var glabTokenVars = []string{"GITLAB_TOKEN", "GITLAB_ACCESS_TOKEN", "OAUTH_TOKEN"}

// glabMinterEnv is environ without the names in glabTokenVars.
func glabMinterEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
next:
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		for _, v := range glabTokenVars {
			if name == v {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// glabToken asks the host's glab CLI for the account it holds for host, with
// the three token variables removed from its environment (glabMinterEnv).
// Shelling out rather than parsing ~/.config/glab-cli/config.yml: glab owns that
// format, and its token may live in the keyring rather than the file.
//
// glab's command and key names are from source v1.124.0, not measured: glab is
// not installed on the host this was written on.
func glabToken(host string) (glabAccount, error) {
	glab, err := exec.LookPath("glab")
	if err != nil {
		return glabAccount{}, errors.New("glab is not installed on the host (not found on PATH)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	get := func(key string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, glab, "config", "get", key, "--host", host)
		cmd.Env = glabMinterEnv(os.Environ())
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("`glab config get %s --host %s` failed (%v)", key, host, err)
		}
		return bytes.TrimSpace(out), nil
	}
	tok, err := get("token")
	if err != nil {
		return glabAccount{}, err
	}
	if len(tok) == 0 {
		return glabAccount{}, fmt.Errorf("glab holds no token for %s", host)
	}
	user, err := get("user")
	if err != nil {
		return glabAccount{}, err
	}
	oauth, err := get("is_oauth2")
	if err != nil {
		return glabAccount{}, err
	}
	return glabAccount{User: string(user), Token: policy.Secret(tok), OAuth: string(oauth) == "true"}, nil
}

// readHostNetrc reads {home}/.netrc: a fixed path with no profile key, opened
// without following a link, capped, and refused when another user can read it or
// it is owned by someone else. curl does not check the mode of a netrc, so this
// is the only place a world-readable credential file gets a say.
func readHostNetrc(home string) ([]byte, error) {
	data, err := hostread.RequiredNoLinksPrivate(home+"/.netrc", hostread.MaxNetrcBytes, os.Getuid())
	if errors.Is(err, hostread.ErrNotPrivate) {
		return nil, fmt.Errorf("~/.netrc is readable by others or not yours; chmod 600 ~/.netrc (%w)", err)
	}
	return data, err
}

// glabCredential returns the token for the pinned account, from the one source
// the block names. There is no fallback to the other source: a missing or
// unreadable entry in the chosen one is an error, because the profile said
// where the credential lives.
//
// The stored login must equal identity.glab.user: user verifies and never
// selects, since glab and netrc each hold one login per host. The token's shape
// is checked for both sources.
//
// RESIDUAL: a netrc entry records login and password and nothing else, so an
// OAuth access token kept there is indistinguishable from a personal access
// token; only the glab source can see is_oauth2.
func glabCredential(g policy.IdentityGlab, mint glabMinter, rd netrcReader) (policy.Secret, error) {
	var login string
	var tok policy.Secret
	switch g.TokenSource {
	case policy.GlabTokenFromNetrc:
		data, err := rd()
		if err != nil {
			return nil, fmt.Errorf("could not read the netrc entry: %w", err)
		}
		login, tok, err = policy.ParseNetrcEntry(data, g.Host)
		if err != nil {
			return nil, err
		}
	default:
		acct, err := mint(g.Host)
		if err != nil {
			return nil, err
		}
		if acct.OAuth {
			return nil, fmt.Errorf("glab's login for %s is an OAuth session, and snug stages only a "+
				"personal access token. Log in again with one: glab auth login --hostname %s",
				g.Host, g.Host)
		}
		login, tok = acct.User, acct.Token
	}
	if login != g.User {
		return nil, fmt.Errorf("the credential for %s belongs to %s, not %s. identity.glab.user "+
			"verifies the account and never selects one",
			g.Host, policy.VisibleText(strconv.Quote(login)), policy.VisibleText(strconv.Quote(g.User)))
	}
	if err := policy.CheckForgeToken(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// stageGlabConfig gives glab a private config directory and git a netrc entry,
// both generated, instead of a token in the environment (see stageGhConfig for
// why a file and not the environment).
//
// TWO FILES FROM ONE TOKEN, and both for either source. config.yml is what glab
// reads; ~/.netrc is what git over https reads, with no credential helper and no
// gitconfig line involved. The glab config's file is staged WRITABLE as gh's is,
// because glab may rewrite its config; it is a private copy on tmpfs. The netrc is
// read-only.
//
// THE GATE IS THE USER and is fail-closed like stageGhConfig's: Resolve refuses a
// half block, so an empty user here is unreachable for a profile that resolved,
// and deleting that refusal reverts to "no token" rather than to staging
// whichever account the host holds.
//
// git_protocol is ssh only when the ssh agent proxy is pinned for this very
// host, i.e. when git's insteadOf rule already sends that host over ssh.
//
// A dry run prints a refusal and continues, as stageGhConfig does, and the
// FILESYSTEM block it prints then has no config.yml or .netrc row.
func stageGlabConfig(pol *policy.Policy, id *policy.Identity, dryRun bool, mint glabMinter, rd netrcReader) error {
	if id.Glab.User == "" {
		return nil
	}
	host, user := id.Glab.Host, id.Glab.User
	tok, err := glabCredential(id.Glab, mint, rd)
	if err != nil {
		srcName, source := "glab", "glab auth login --hostname "+host
		if id.Glab.TokenSource == policy.GlabTokenFromNetrc {
			srcName = "netrc"
			source = "add `machine " + host + " login " + user + " password <token>` to ~/.netrc (chmod 600)"
		}
		who := strconv.Quote(user) + " on " + strconv.Quote(host)
		msg := fmt.Sprintf("no usable GitLab credential for %s: %s\n\n"+
			"      The profile pins a GitLab account, so snug will not start a sandbox\n"+
			"      that silently has no credential for it, and it does not fall back to the\n"+
			"      other token_source. Either:\n"+
			"        - fix the source the profile names (token_source = \"%s\"):  %s\n"+
			"        - or drop the [identity.glab] block if the sandbox does not need glab.",
			who, policy.VisibleText(err.Error()), srcName, source)
		if dryRun {
			fmt.Fprintln(os.Stderr, "snug: "+msg)
			fmt.Fprintln(os.Stderr, "      (dry run: continuing, and the FILESYSTEM block below "+
				"therefore has no config.yml or .netrc row)")
			return nil
		}
		return errors.New(msg)
	}

	gitProtocol := "https"
	if id.SSH.Agent != policy.SSHNone && id.SSHHost() == host {
		gitProtocol = "ssh"
	}
	dir := pol.Home + "/.config/glab-cli"
	// string(tok) at each Sprintf is the one explicit escape, as in stageGhConfig:
	// %s on a policy.Secret would render the redaction instead of the token.
	cfg := policy.Secret(fmt.Sprintf("# Generated by snug. The host's glab config is not mounted.\n"+
		"hosts:\n  %s:\n    api_host: %s\n    api_protocol: https\n    git_protocol: %s\n"+
		"    token: %s\n    user: %s\n", host, host, gitProtocol, string(tok), user))
	netrc := policy.Secret(fmt.Sprintf("machine %s login %s password %s\n", host, user, string(tok)))

	perm := uint32(0o600)
	from := []string{identityProvenance(pol, "glab")}
	pol.Replace(policy.Mount{
		Guest: dir + "/config.yml", Kind: policy.KindData, Access: policy.AccessRW,
		Content: cfg, Perms: &perm, From: from,
	})
	pol.Replace(policy.Mount{
		Guest: pol.Home + "/.netrc", Kind: policy.KindData, Access: policy.AccessRO,
		Content: netrc, Perms: &perm, From: from,
	})
	pol.AuthorEnv("GLAB_CONFIG_DIR", dir)
	pol.AuthorEnv("GITLAB_HOST", host)
	return nil
}
