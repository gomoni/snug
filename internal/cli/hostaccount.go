package cli

import (
	"os"

	"github.com/gomoni/snug/internal/getent"
)

// lookupHostAccount is the run path's host account lookup: `getent passwd
// <uid>` and `getent group <gid>` (internal/getent, snug's one entrypoint for
// host account data), run on the host before the sandbox exists, the same way
// probeSSHConfig runs `ssh -G` before it. name and gname go into the
// generated /etc/passwd and /etc/group (policy.Context.HostUserName,
// HostGroupName); pwHome is the host-side fact policy.Context.HostPasswdHome
// stays for (systemSSHConfigCandidates' own filtering).
//
// There is NO FALLBACK: a placeholder name here would be exactly the silent
// narrowing invariant 5 forbids, so getent missing, failing, or printing a
// line snug does not recognise all come back as an error, naming the fix.
//
// A package variable so an in-process test can stub the account without
// depending on the CI host's own uid having an NSS entry.
var lookupHostAccount = getentHostAccount

func getentHostAccount() (name, pwHome, gname string, err error) {
	pw, err := getent.PasswdByUID(os.Getuid())
	if err != nil {
		return "", "", "", err
	}
	gr, err := getent.GroupByGID(os.Getgid())
	if err != nil {
		return "", "", "", err
	}
	return pw.Name, pw.Home, gr.Name, nil
}
