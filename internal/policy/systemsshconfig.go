package policy

import "strings"

// SystemSSHConfigPaths are the system-wide ssh_config locations snug may
// replace. Both spellings ship in the wild: the traditional /etc/ssh, and
// /usr/etc/ssh on distributions that moved the vendor copy out of /etc
// (openSUSE). A third spelling exists in the wild too
// (/usr/local/etc/ssh/ssh_config) and is deliberately NOT added here — see
// an unmeasured path in a security-relevant list is a claim with no
// evidence behind it (issue #40).
var SystemSSHConfigPaths = []string{
	"/etc/ssh/ssh_config",
	"/usr/etc/ssh/ssh_config",
}

// SystemSSHConfig is the generated replacement for the system-wide
// ssh_config. It is authored by snug in EVERY sandbox whose deepest covering
// grant actually supplies a host file at the path — see
// replaceSystemSSHConfig for the coverage rule that decides WHEN. This has
// NOTHING to do with a pinned identity: the failure it fixes is a
// configuration-chain problem, not a credential one, and it fires (or does
// not) the same way whether or not [identity] is set.
//
// WHY THIS EXISTS, measured rather than reasoned: the sandbox maps exactly
// one uid, so every root-owned file under a read-only bind reads as 65534
// inside it. OpenSSH refuses to use a configuration file owned by neither
// root nor the invoking user, and the refusal is fatal rather than a
// warning:
//
//	$ git clone git@github.com:owner/repo.git
//	Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf
//
// So ssh — and therefore git-over-ssh, scp, and rsync -e ssh — did not run
// inside snug at all on such a host, for every profile, identity pinned or
// not. `ssh -F <file>` always worked, because -F makes ssh skip the
// system-wide file entirely; this replacement is that same escape, applied
// once by snug instead of relying on every caller to remember a flag. git
// hits the identical root cause on a different file and takes the same
// SHAPE of fix (`safe.directory = *`) — the next tool with an ownership
// check on a root-owned file will need its own answer, but this is the
// pattern to look for.
//
// This is a REPLACEMENT, not masking: snug authors it, the sandbox still
// sees a file at that path, and no profile's grant is silently subtracted
// (CLAUDE.md, "PATH precedence, not overmounting"). It appears in --dry-run
// as a `data` row with `(snug)` provenance, plus a `replaces:<profile>`
// suffix when it displaced content a profile's bind supplied at that path —
// see Policy.Replace and replaceSystemSSHConfig.
//
// replaceSystemSSHConfig does not check who owns the host file it replaces —
// owner-gating was considered and rejected (issue #40:
// it makes emission depend on a mode bit and --dry-run host-state-dependent
// in a way a reader cannot check). So a human profile binding its OWN config
// at one of these paths is replaced too, disclosed by `replaces:` like any
// other displacement; their answer is `~/.ssh/config`, which snug does not
// author unless an identity is pinned.
//
// A second, independent reason to replace it: ssh_config is a COMMAND TABLE
// (ProxyCommand, LocalCommand, Match exec, KnownHostsCommand,
// PermitLocalCommand, PKCS11Provider, SecurityKeyProvider all name programs
// to run), and @sys's /usr bind supplies the host's copy of one
// unavoidably — /usr cannot be enumerated finely enough to leave it out.
// Replacing it means the sandbox's ssh obeys only bytes snug authored. Do
// NOT oversell this: the file is the host admin's, the payload cannot write
// it (a read-only data mount inside a read-only bind, under
// --remount-ro /), and anything it named would run inside the sandbox with
// the sandbox's own authority — no escalation is being closed here, this is
// legibility and robustness.
//
// ABUSE: a hostile process inside the sandbox can use this to run `ssh` —
// and therefore `git` over ssh, `scp` and `rsync -e ssh` — where it
// previously died parsing the host's root-owned config; it gains no
// credential by it, because without a pinned identity there is no key, no
// agent socket and no known_hosts inside, so it can only reach hosts that
// would accept it with no secret of yours, over egress @net already granted
// and with the same reach a plain TCP client already had. It cannot modify
// the file. What snug gives up on its behalf is the host's system-wide ssh
// defaults: the sandbox's ssh negotiates OpenSSH's compiled-in algorithm
// lists and RequiredRSASize 1024 instead of the host crypto policy's 2048,
// so a hostile remote can offer a weaker host key than the host's own ssh
// would have accepted.
//
// What it costs, stated plainly: the host's system-wide ssh defaults do not
// apply inside the sandbox — on a crypto-policy distro that is the policy's
// algorithm lists and RequiredRSASize (2048 -> OpenSSH's compiled-in 1024).
// Restoring that properly is extracting and generating the non-executable
// keys from the host's file, not implemented here (issue #40).
func SystemSSHConfig() []byte {
	return []byte("# Generated by snug, replacing this host's system-wide ssh_config.\n" +
		"#\n" +
		"# The sandbox maps exactly one uid, so a root-owned file under a\n" +
		"# read-only bind reads as 65534 inside it. OpenSSH refuses a\n" +
		"# configuration file owned by neither root nor the caller — fatally,\n" +
		"# not as a warning — so ssh, and therefore git-over-ssh, scp and\n" +
		"# rsync -e ssh, did not run inside the sandbox at all on a host whose\n" +
		"# system-wide ssh_config lives under a granted tree. This has nothing\n" +
		"# to do with pinning an identity; git hits the same root cause on a\n" +
		"# different file and takes the same shape of fix (safe.directory = *).\n" +
		"#\n" +
		"# It has no Include line for the same reason: every file it would pull\n" +
		"# in is root-owned too.\n" +
		"#\n" +
		"# If snug pinned an identity it also generated ~/.ssh/config; otherwise\n" +
		"# ssh's compiled-in defaults are all that apply.\n" +
		"#\n" +
		"# Cost: the host's system-wide ssh defaults do not apply inside — on a\n" +
		"# crypto-policy distro that includes RequiredRSASize (commonly 2048),\n" +
		"# which falls back to OpenSSH's compiled-in 1024 here.\n")
}

// replaceSystemSSHConfig emits SystemSSHConfig() at each guest path in
// SystemSSHConfigPaths whose deepest covering mount is a KindBind AND whose
// host side actually has a file there. See SystemSSHConfig for the WHY; this
// is the WHEN — decided in issue #40, restated here in full because the
// two halves of the condition each rule out a real, measured failure:
//
//   - Coverage (cov.Kind == KindBind) is the FAILURE CONDITION ITSELF: the
//     ownership refusal can only happen when the host's file is actually
//     inside the sandbox, which happens only when some bind supplies it.
//     Emitting unconditionally would create /etc/ssh in every sandbox on a
//     Debian/Fedora-shaped host, where @sys does not grant /etc/ssh at all
//     and ssh already works — a node nobody asked for, and (§1) it would also
//     have no covering mount to name after `replaces:`.
//   - The host env.Stat is load-bearing, not decorative: measured with bwrap,
//     `--ro-bind-data` at a path that does not exist inside a `--ro-bind`
//     fails the WHOLE SANDBOX with "Read-only file system", rc=1. Dropping
//     just the Stat would break every sandbox on a host that binds /etc but
//     has no ssh_config under it.
//
// Every other Kind fails closed: KindTmpfs covers with an empty directory (no
// host file, no refusal, nothing to fix — the same verdict keepHostElement
// gives a tmpfs); KindSymlink cannot be resolved without a second rule, so it
// is left alone; KindData/KindProc/KindDev cannot occur at these paths. A
// future Kind added to the enum skips here until someone decides — the
// sandbox is no worse off than today in every skipped case.
//
// Runs AFTER every profile mount is folded (so coverage sees the final set)
// and BEFORE applyEnvClaims (so sanitise sees the final mount set).
func replaceSystemSSHConfig(p *Policy, env Environ) {
	cfg := SystemSSHConfig()
	for _, guest := range SystemSSHConfigPaths {
		cov, ok := p.coveringMount(guest)
		if !ok || cov.Kind != KindBind {
			continue
		}
		// What the covering bind actually supplies at this exact path — the
		// honest spelling of "the file the sandbox will see here", which for
		// the case that occurs (@sys binds /usr at /usr) reduces to
		// env.Stat(guest).
		host := cov.Host + strings.TrimPrefix(guest, cov.Guest)
		if _, err := env.Stat(host); err != nil {
			continue
		}
		from := []string{"(snug)"}
		// Only annotate when the covering mount is an ANCESTOR, not an exact
		// match at this guest path: an exact match is handled by Replace
		// itself (it finds the existing p.Mounts[guest] and appends its own
		// replaces: note), and annotating both here and there would say it
		// twice.
		if cov.Guest != guest {
			from = append(from, "replaces:"+strings.Join(cov.From, "+"))
		}
		p.Replace(Mount{
			Guest:   guest,
			Kind:    KindData,
			Access:  AccessRO,
			Content: cfg,
			From:    from,
		})
	}
}
