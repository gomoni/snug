package cli

import (
	"github.com/gomoni/snug/internal/getent"
)

// lookupHostAccount is the run path's account lookup (internal/getent's
// Account): outside a sandbox `getent passwd <uid>` and `getent group <gid>`
// from a root-owned getent, inside snug the generated /etc/passwd and
// /etc/group, run before the sandbox exists the way probeSSHConfig runs
// `ssh -G` before it. name and gname go into the generated /etc/passwd and
// /etc/group (policy.Context.HostUserName, HostGroupName); pwHome is the
// account's home directory, which policy.AccountHome checks $HOME against, and
// from names the source for the -v note.
//
// There is NO FALLBACK: a placeholder name or home here would be exactly the
// silent narrowing invariant 5 forbids, so a missing or failing source comes
// back as an error, naming the fix.
//
// A package variable so an in-process test can stub the account without
// depending on the CI host's own uid having an NSS entry.
var lookupHostAccount = hostAccount

func hostAccount() (name, pwHome, gname, from string, err error) {
	pw, gr, src, err := getent.Account()
	if err != nil {
		return "", "", "", "", err
	}
	return pw.Name, pw.Home, gr.Name, src.String(), nil
}
