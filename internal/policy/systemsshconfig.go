package policy

import (
	"path/filepath"
	"slices"
	"strings"
)

// SystemSSHConfigPaths is the FLOOR of system-wide ssh_config locations snug
// may replace, not the whole set. Both spellings here ship in the wild: the
// traditional /etc/ssh, and /usr/etc/ssh on distributions that moved the
// vendor copy out of /etc (openSUSE).
//
// A third, fourth and fifth spelling exist too — /usr/local/etc/ssh on
// FreeBSD and under a Homebrew-shaped prefix, a /nix/store/… path — and they
// are still deliberately NOT written down here. A list of platform spellings
// is a rule written somewhere it can be forgotten, and an entry nobody has a
// host to measure on is a claim with no evidence behind it (issue #40). What
// closed issue #42 instead is Context.HostSSHConfigs: the caller ASKS this
// host's ssh which files it reads, and whatever it names joins this list for
// the run.
//
// So this list is what remains when the question gets no usable answer —
// output the parser does not recognise — and a host in that state is exactly
// as well off as it was before #42, which is the fail-closed direction. A
// floor entry is authored only where a bind supplies a host file at it (see
// replaceSystemSSHConfig), and nothing is authored on a host with no ssh. See
// systemSSHConfigCandidates.
var SystemSSHConfigPaths = []string{
	"/etc/ssh/ssh_config",
	"/usr/etc/ssh/ssh_config",
}

// systemSSHConfigCandidates is every guest path this run may replace: the
// fixed floor, then whatever the host's own ssh named, in chain order.
//
// The filter on a discovered path is the load-bearing half, because these
// strings come from a HOST FILE the user's own ~/.ssh/config can Include, and
// they end up authoring a mount. Five conditions, each closing a measured
// shape rather than a hypothetical one:
//
//   - ABSOLUTE and CLEAN. A relative or unnormalised path cannot be reasoned
//     about against a mount's Guest, and Validate would refuse it later; being
//     refused here means a weird chain entry never becomes a policy at all.
//   - BASENAME ssh_config. `ssh -G -v` names every file in the chain,
//     INCLUDING the ones an Include pulls in
//     (/usr/etc/ssh/ssh_config.d/50-suse.conf,
//     /etc/crypto-policies/back-ends/openssh.config — both measured on this
//     host). Replacing an included file is pointless: snug replaces the
//     TOP-LEVEL file and the replacement carries no Include line, so nothing
//     under it is ever read. It is also how a chain entry chosen by a human's
//     own `Include /tmp/whatever.conf` stops being able to steer where snug
//     authors bytes.
//   - NOT UNDER Home NOR HostPasswdHome. The user's own ~/.ssh/config is in
//     the chain and is not a system file: snug generates that one only when an
//     identity is pinned (identity.go), and replacing it here would silently
//     displace a file the human wrote for themselves. Both are tested because
//     they are two spellings of one directory, and the chain comes from the
//     host's ssh, which found that file from pw_dir.
//   - NOR ANYWHERE INSIDE THE TARGET, and this one was found by attacking the
//     change rather than by writing it. A human's own `Include <some
//     repo>/ssh_config` puts a path from the SANDBOXED TREE into the chain,
//     and a KindData mount is assigned straight into p.Mounts — rejectMasking
//     exempts KindData by kind — so it would displace the repository's own
//     file with bytes snug wrote, read-only, inside the one tree the run
//     exists to let the payload write.
//   - NO CONTROL CHARACTER. Same rule as every other host string that reaches
//     a mount or a screen; Validate refuses one in a guest path anyway, and
//     this keeps it from getting that far.
//
// Duplicates are dropped so a chain that names the same file twice — the
// measured shape, ssh parses the whole chain twice per invocation — cannot
// produce two mounts at one guest path.
func systemSSHConfigCandidates(ctx Context) []string {
	out := slices.Clone(SystemSSHConfigPaths)
	for _, p := range ctx.HostSSHConfigs {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			continue
		}
		if filepath.Base(p) != "ssh_config" {
			continue
		}
		if ctx.Home != "" && underPath(ctx.Home, p) {
			continue
		}
		if ctx.HostPasswdHome != "" && underPath(ctx.HostPasswdHome, p) {
			continue
		}
		if ctx.Target != "" && underPath(ctx.Target, p) {
			continue
		}
		if strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		if slices.Contains(out, p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// underPath reports whether p is dir itself or anything beneath it. Written
// out rather than a strings.HasPrefix, which answers a different question:
// /home/us is not under /home/u.
func underPath(dir, p string) bool {
	dir = strings.TrimSuffix(filepath.Clean(dir), "/")
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// replaceSystemSSHConfig authors SystemSSHConfigFrom(ctx.HostSSHConfig, …) at
// the guest paths the sandbox's ssh reads. ctx.HostSSHBinary is that ssh, as
// the caller determined it from a previous Resolve's SandboxSSHHost (see its
// doc); the values are its `ssh -G`. See SystemSSHConfigFrom for the WHY;
// this is the WHEN.
//
// Two triggers, judged per candidate path by its deepest covering mount:
//
//   - KindBind whose host side env.Stat finds: author, whether or not the
//     sandbox has an ssh on its PATH. The host's root-owned file is inside, and
//     whatever ssh the sandbox runs would refuse it. This never creates a
//     node: the bind already put a file there. The Stat is load-bearing,
//     measured with bwrap: `--ro-bind-data` at a path that does not exist
//     inside a `--ro-bind` fails the WHOLE SANDBOX with "Read-only file
//     system", rc=1, so a host that binds /etc but has no ssh_config under it
//     would break. The binary is deliberately not required here: any ssh
//     run inside, from any source, would die on the host's file.
//   - KindTmpfs, or no cover at all (the root tmpfs): author only when
//     ctx.HostSSHBinary is set (the sandbox's PATH finds an ssh) and some
//     KindBind in the sandbox view supplies it, AND only at
//     ctx.HostSSHTopConfig, the top-level file that ssh opens itself. Never a
//     floor-only SystemSSHConfigPaths entry, and never another discovered
//     file named ssh_config: an Include'd one is read only through the
//     top-level file, whose replacement has no Include line, so nothing
//     inside would read a node written there. An ssh that is inside reads a
//     system-wide file, and with none it runs on its compiled-in defaults,
//     which on a crypto-policy host are weaker than the host's. bwrap creates the parent directories (the skeleton --dir pass on
//     the root tmpfs, auto-created inside a tmpfs). This is the Debian/Fedora
//     shape: @sys does not grant /etc/ssh, so /etc/ssh/ssh_config is on the
//     root tmpfs, and the sandbox's ssh, from the /usr bind, reads snug's
//     file there instead of nothing. NOT measured on a Debian or Fedora host.
//   - Anything else: skip. KindSymlink cannot be resolved without a second
//     rule; KindData/KindProc/KindDev cannot occur at these paths. A future
//     Kind added to the enum skips here until someone decides.
//
// When at least one file was authored and ctx.HostSSHRevoked is non-nil, the
// host's global RevokedHostKeys file is staged at SystemRevokedHostKeysGuest
// and every authored file names it. Which arm wrote each path is recorded
// (SystemSSHReplaced) for --dry-run.
//
// Runs AFTER every profile mount is folded (so coverage sees the final set)
// and BEFORE applyEnvClaims (so sanitise sees the final mount set).
func replaceSystemSSHConfig(p *Policy, ctx Context, env Environ) {
	// Runs before any graft can exist (Resolve, never Tier C's post-Resolve
	// Policy.Graft), and this is a question about the PAYLOAD's own view
	// either way — the sandbox's, explicitly.
	view := p.SandboxView()
	p.HostSSHBinary = ctx.HostSSHBinary
	p.HostSSHBinaryInside = sshBinaryInside(view, ctx.HostSSHBinary)
	revoked := ctx.HostSSHRevoked != nil
	cfg := SystemSSHConfigFrom(ctx.HostSSHConfig, revoked)
	for _, guest := range systemSSHConfigCandidates(ctx) {
		cov, ok := view.coveringMount(guest)
		from := []string{"(snug)"}
		replaced := true
		switch {
		case ok && cov.Kind == KindBind:
			// What the covering bind actually supplies at this exact path — the
			// honest spelling of "the file the sandbox will see here", which for
			// the case that occurs (@sys binds /usr at /usr) reduces to
			// env.Stat(guest).
			host := cov.Host + strings.TrimPrefix(guest, cov.Guest)
			if _, err := env.Stat(host); err != nil {
				continue
			}
			// Only annotate when the covering mount is an ANCESTOR, not an exact
			// match at this guest path: an exact match is handled by Replace
			// itself (it finds the existing p.Mounts[guest] and appends its own
			// replaces: note), and annotating both here and there would say it
			// twice.
			if cov.Guest != guest {
				from = append(from, "replaces:"+strings.Join(cov.From, "+"))
			}
		case !ok || cov.Kind == KindTmpfs:
			if ctx.HostSSHBinary == "" || !p.HostSSHBinaryInside || guest != ctx.HostSSHTopConfig {
				continue
			}
			replaced = false
		default:
			continue
		}
		p.Replace(Mount{
			Guest:   guest,
			Kind:    KindData,
			Access:  AccessRO,
			Content: cfg,
			From:    from,
		})
		// Recorded rather than re-derived: the screen reads what Resolve
		// DECIDED, because the set of paths is the floor plus whatever this
		// host's ssh named.
		p.SystemSSHConfigs = append(p.SystemSSHConfigs, guest)
		if replaced {
			p.SystemSSHReplaced = append(p.SystemSSHReplaced, guest)
		}
		p.SystemSSHCarried = carriedSSHKeys(ctx.HostSSHConfig)
	}
	if revoked && len(p.SystemSSHConfigs) > 0 {
		p.Replace(Mount{
			Guest:   SystemRevokedHostKeysGuest,
			Kind:    KindData,
			Access:  AccessRO,
			Content: ctx.HostSSHRevoked,
			From:    []string{"(snug)"},
		})
		// Replace keeps a profile's own mount here (it is inside SnugDir), and
		// Validate refuses that mount; only snug's copy is a staged KRL.
		p.SystemSSHRevoked = p.Mounts[SystemRevokedHostKeysGuest].Authored
		if p.SystemSSHRevoked {
			p.SystemSSHRevokedFrom = ctx.HostSSHRevokedPath
		}
	}
}

// SandboxBinary returns where the sandbox's PATH finds name: the guest path
// the lookup lands on, and the host file behind it with symlinks resolved.
// Both are empty when no PATH entry holds an executable regular file of that
// name. It reads the final PATH, so call it on a resolved Policy.
//
// Each PATH entry is resolved in the SANDBOX's view, following snug's own
// symlink grants (@sys's /bin -> usr/bin) and host symlinks under a bind the
// way the kernel will inside (walkLinks). A directory supplied by a bind is
// looked up through the host; anywhere else, only a bind AT dir/name can hold
// a file, because a tmpfs is empty and the root tmpfs holds only what snug
// put there. A file a payload writes into a writable PATH directory later is
// not seen: this answers what is there when the sandbox starts.
func (p *Policy) SandboxBinary(env Environ, name string) (guest, host string) {
	path, _ := p.EnvValue("PATH")
	view := p.SandboxView()
	for _, dir := range strings.Split(path, ":") {
		if !filepath.IsAbs(dir) {
			continue
		}
		cand := ""
		if m, at, _, end, hostAt := view.walkLinks(env, dir); end == walkLanded && at != "" && hostAt != "" &&
			m.Kind == KindBind {
			// at is the walk's link-free end, so the walk below has one
			// component left to resolve. A file standing where the directory
			// should be fails there (ENOTDIR) and the Stat below refuses it.
			cand = filepath.Join(at, name)
		}
		if cand == "" {
			cand = filepath.Join(filepath.Clean(dir), name)
			if m, ok := view.Mounts[cand]; !ok || m.Kind != KindBind {
				continue
			}
		}
		m, _, _, end, hostAt := view.walkLinks(env, cand)
		if end != walkLanded || m.Kind != KindBind || hostAt == "" {
			continue
		}
		fi, err := env.Stat(hostAt)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if real, err := env.EvalSymlinks(hostAt); err == nil {
			hostAt = real
		}
		return filepath.Join(filepath.Clean(dir), name), hostAt
	}
	return "", ""
}

// sshBinaryInside reports whether some KindBind in view supplies the host
// path bin, at any guest path. It does not ask whether a deeper mount shadows
// that part of the bind; SandboxBinary, which the caller checks bin against,
// does.
func sshBinaryInside(view View, bin string) bool {
	if bin == "" {
		return false
	}
	for _, m := range view.Mounts {
		if m.Kind == KindBind && m.Host != "" && underPath(m.Host, bin) {
			return true
		}
	}
	return false
}

// SandboxWritesHost reports whether host is at or under the host side of a
// writable bind in the sandbox's view: a file this run's payload can write.
func (p *Policy) SandboxWritesHost(host string) bool {
	for _, h := range writableBindHosts(p.Mounts) {
		if underPath(h, host) {
			return true
		}
	}
	return false
}
