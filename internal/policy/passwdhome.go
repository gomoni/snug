package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// refuseUnreadSSHConfig refuses a policy whose generated ~/.ssh/config the
// sandbox's ssh will never open (issue #599). OpenSSH locates the per-user
// config from getpwuid()->pw_dir, never from $HOME; @sys binds the host's
// /etc/passwd and the uid is unmapped, so inside the sandbox that is the
// HOST's pw_dir. The file is authored under p.Home, which is
// EvalSymlinks($HOME). When the two disagree, every directive in the generated
// config — IdentitiesOnly, StrictHostKeyChecking, UserKnownHostsFile — is lost
// with exit 0 while --dry-run shows the row as live: invariant 5.
//
// The question is asked of the MOUNT SET, the way ssh would ask it, rather than
// by comparing strings: on a /home -> /var/home host p.Home is /var/home/u for
// every $HOME naming that directory while pw_dir stays /home/u, so a raw
// comparison refuses forever, and a profile symlink /home/u -> /var/home/u
// makes the lookup land where a string comparison says it cannot.
//
// Gated on the ARTIFACT, not on why it exists: no generated config, nothing
// lost, no refusal.
func refuseUnreadSSHConfig(p *Policy, ctx Context, env Environ) error {
	want := p.Home + "/.ssh/config"
	if m, ok := p.Mounts[want]; !ok || m.Kind != KindData {
		return nil
	}
	owner := p.Mounts[want].From
	pw := ctx.HostPasswdHome
	if pw == "" || !filepath.IsAbs(pw) {
		return fmt.Errorf("the generated %s (%s) would never be read: ssh finds its "+
			"per-user config from the passwd entry's home directory, and uid %d has "+
			"no usable one (%s). Every directive in it would be lost silently, so "+
			"snug refuses. Give the uid a passwd entry with an absolute home, or "+
			"drop identity.ssh from the profile",
			VisibleText(want), VisibleText(strings.Join(owner, "+")), env.Uid(), passwdHomeShown(pw))
	}
	pw = filepath.Clean(pw)
	sshWill := filepath.Join(pw, ".ssh", "config")
	if sshWill == want {
		return nil
	}
	// The walk must END on want, not merely under a mount covering it: the
	// generated file covering want/config lexically is ENOTDIR to the kernel.
	// Only walkLanded is accepted — walkUnknown (a host path on the way could
	// not be read) and walkNowhere refuse exactly like every other unresolved
	// chain does here, because a host link this cannot vouch for is not
	// evidence that ssh will find the generated file.
	if final, at, _, end := p.SandboxView().walkLinks(env, sshWill); end == walkLanded && at == want && final.Guest == want && final.Kind == KindData {
		return nil
	}

	// Two ways out, and which one works depends on whether pw_dir is itself
	// canonical: setting HOME to it moves p.Home only if EvalSymlinks leaves
	// it alone. Otherwise no value of $HOME can help and the profile has to
	// make pw_dir resolve inside the sandbox.
	head := fmt.Sprintf("the generated %s (%s) would never be read: ssh opens %s, "+
		"because it takes the home directory from the passwd entry (%s), never from "+
		"$HOME (%s). Every directive in the generated config would be lost silently, "+
		"so snug refuses.",
		VisibleText(want), VisibleText(strings.Join(owner, "+")), VisibleText(sshWill),
		VisibleText(pw), VisibleText(ctx.Home))
	real, err := env.EvalSymlinks(pw)
	if err == nil && real == pw {
		return fmt.Errorf("%s Run with HOME=%s, or drop identity.ssh from the profile",
			head, VisibleText(pw))
	}
	why := "it does not exist on this host"
	if err == nil {
		why = "it resolves to " + VisibleText(real)
	}
	return fmt.Errorf("%s No value of HOME fixes that, because %s. Add to a selected "+
		"profile  symlink = [{ at = %q, target = %q }]  so %s resolves to the generated "+
		"file, or drop identity.ssh from the profile",
		head, why, pw, p.Home, VisibleText(sshWill))
}

func passwdHomeShown(pw string) string {
	if pw == "" {
		return "no passwd entry, or an empty home field"
	}
	return "home field " + VisibleText(pw) + " is not absolute"
}
