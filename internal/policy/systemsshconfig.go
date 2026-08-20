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
// So this list is what remains when the question cannot be asked — no ssh on
// the host, a probe that times out, output the parser does not recognise —
// and a host in that state is exactly as well off as it was before #42, which
// is the fail-closed direction. See systemSSHConfigCandidates.
var SystemSSHConfigPaths = []string{
	"/etc/ssh/ssh_config",
	"/usr/etc/ssh/ssh_config",
}

// systemSSHConfigCandidates is every guest path this run may replace: the
// fixed floor, then whatever the host's own ssh named, in chain order.
//
// The filter on a discovered path is the load-bearing half, because these
// strings come from a HOST FILE the user's own ~/.ssh/config can Include, and
// they end up authoring a mount. Four conditions, each closing a measured
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
//   - NOT UNDER Home. The user's own ~/.ssh/config is in the chain and is not
//     a system file: snug generates that one only when an identity is pinned
//     (identity.go), and replacing it here would silently displace a file the
//     human wrote for themselves.
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
		// NOR ANYWHERE INSIDE THE TARGET. Found by attacking this change rather
		// than by writing it: the chain is host text, but a human's own
		// `Include <some repo>/ssh_config` line puts a path from the SANDBOXED
		// TREE into it, and a KindData mount is assigned straight into p.Mounts
		// — rejectMasking exempts KindData by kind, so it would displace the
		// repository's own file at that path with bytes snug wrote, read-only,
		// inside the one tree the run exists to let the payload write. Not an
		// escalation (the content is snug's own comment block), but it is snug
		// taking a file away from the thing it is supposed to be working on.
		if ctx.Target != "" && underPath(ctx.Target, p) {
			continue
		}
		// NOR ANYWHERE INSIDE THE TARGET. Found by attacking this change rather
		// than by writing it: the chain is host text, but a human's own
		// `Include <some repo>/ssh_config` line puts a path from the SANDBOXED
		// TREE into it, and a KindData mount is assigned straight into p.Mounts
		// — rejectMasking exempts KindData by kind, so it would displace the
		// repository's own file at that path with bytes snug wrote, read-only,
		// inside the one tree the run exists to let the payload write. Not an
		// escalation (the content is snug's own comment block), but it is snug
		// taking a file away from the thing it is supposed to be working on,
		// and the guest path is the target's.
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

// replaceSystemSSHConfig emits SystemSSHConfigFrom(ctx.HostSSHConfig) at each guest path in
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
func replaceSystemSSHConfig(p *Policy, ctx Context, env Environ) {
	cfg := SystemSSHConfigFrom(ctx.HostSSHConfig)
	for _, guest := range systemSSHConfigCandidates(ctx) {
		// Runs before any graft can exist (Resolve, never Tier C's post-Resolve
		// Policy.Graft), and this is a question about the PAYLOAD's own view
		// either way — the sandbox's, explicitly.
		cov, ok := p.SandboxView().coveringMount(guest)
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
		// Recorded rather than re-derived. --dry-run's SSH block used to walk
		// SystemSSHConfigPaths itself, which stopped being the whole set the
		// moment discovery landed: a run that replaced a discovered path would
		// have shown the reader nothing at all. The screen reads what Resolve
		// DECIDED (issue #42).
		p.SystemSSHConfigs = append(p.SystemSSHConfigs, guest)
		p.SystemSSHCarried = carriedSSHKeys(ctx.HostSSHConfig)
	}
}
