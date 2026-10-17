package draft

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
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

var authorEmail = regexp.MustCompile(`^[^\s@<>"\\]+@[^\s@<>"\\]+\.[A-Za-z]{2,}$`)

// ParseAuthor splits "Name <email>" at its last "<". It reports false for any
// other spelling; it does not validate either half (CheckAuthor does).
func ParseAuthor(s string) (name, email string, ok bool) {
	i := strings.LastIndex(s, "<")
	if i < 0 || !strings.HasSuffix(s, ">") {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1 : len(s)-1]), true
}

// CheckAuthor refuses a git author the human typed that cannot be written as
// identity.git: an empty or overlong name, a name or email holding a control
// or invisible formatting character, a quote, a backslash or an angle
// bracket, and an email that is not local@domain.tld.
func CheckAuthor(name, email string) error {
	switch {
	case name == "" || utf8.RuneCountInString(name) > 100:
		return errors.New("a git author needs a name of 1 to 100 characters")
	case hidden(name) || hidden(email):
		return errors.New("the name or email contains a control or invisible formatting character")
	case strings.ContainsAny(name, "\"<>\\"):
		return fmt.Errorf("the name %q contains a quote, backslash or angle bracket", name)
	case len(email) > 254 || !authorEmail.MatchString(email):
		return fmt.Errorf("%q is not an email address (local@domain.tld)", email)
	}
	return nil
}

// SetGit pins the git author.
func (d *Draft) SetGit(name, email string) { d.Git = &GitIdentity{Name: name, Email: email} }

// SetSigningKey pins the public key at pubPath for commit signing. snug needs
// the author it signs as and the ssh key whose agent proxy holds the private
// half, so it reports false, changing nothing, until both are pinned.
func (d *Draft) SetSigningKey(pubPath string) bool {
	if d.Git == nil || d.SSH == nil {
		return false
	}
	home := filepath.Clean(d.Host.Home)
	key := pubPath
	if under(pubPath, home) && pubPath != home {
		key = "{home}/" + strings.TrimPrefix(pubPath, home+"/")
	}
	d.Git.SigningKey = key
	d.Git.SigningStem = strings.TrimSuffix(filepath.Base(pubPath), ".pub")
	return true
}

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
