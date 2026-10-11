package draft

import (
	"path/filepath"
	"strings"
)

// GitHubHost is the host identity blocks default to.
const GitHubHost = "github.com"

// SetSSH pins the public key at path (a *.pub file). The caller has already
// asked the human; Apply never calls this.
func (d *Draft) SetSSH(pubPath string) {
	home := filepath.Clean(d.Host.Home)
	key := pubPath
	if under(pubPath, home) && pubPath != home {
		key = "{home}/" + strings.TrimPrefix(pubPath, home+"/")
	}
	d.SSH = &SSHIdentity{Stem: strings.TrimSuffix(filepath.Base(pubPath), ".pub"), Key: key}
}

// SetGH pins the gh login user on host.
func (d *Draft) SetGH(host, user string) {
	d.GH = &GHIdentity{Host: host, User: user}
}

// SetGit pins the git author.
func (d *Draft) SetGit(name, email string) { d.Git = &GitIdentity{Name: name, Email: email} }

// ClearIdentity removes every identity block.
func (d *Draft) ClearIdentity() { d.SSH, d.GH, d.Git = nil, nil, nil }

// hosts returns the host written into identity.ssh and identity.gh, "" for the default. snug refuses naming one host
// block while the other is active, so a non-default gh host is written to both.
func (d *Draft) hosts() (ssh, gh string) {
	if d.GH != nil && d.GH.Host != GitHubHost {
		gh = d.GH.Host
		if d.SSH != nil {
			ssh = d.GH.Host
		}
	}
	return ssh, gh
}
