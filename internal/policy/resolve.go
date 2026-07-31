package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Resolve turns a selection of profiles into a Policy.
//
// It is commutative and idempotent in `selected`: Resolve([a,b]) == Resolve([b,a])
// and Resolve([a,a]) == Resolve([a]). Both properties are asserted by property
// tests in resolve_test.go, and both are load-bearing — if either fails, profile
// composition can tighten the sandbox and the whole model is void.
func Resolve(reg map[string]*Profile, selected []string, ctx Context, env Environ) (*Policy, error) {
	if len(selected) == 0 {
		return nil, fmt.Errorf("no profile selected: the empty policy grants nothing and cannot run a command")
	}

	// 1. Expand includes transitively into a SET. Because the result is a set,
	//    include is idempotent and diamond includes are harmless.
	set := map[string]*Profile{}
	for _, name := range selected {
		if err := expand(reg, name, set, nil); err != nil {
			return nil, err
		}
	}

	// 2. Canonicalise the target. Fail closed: no target means no policy.
	if ctx.Target == "" {
		return nil, fmt.Errorf("no target directory")
	}
	target, err := env.EvalSymlinks(ctx.Target)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", ctx.Target, err)
	}
	if fi, err := env.Stat(target); err != nil {
		return nil, fmt.Errorf("target %q: %w", target, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("target %q is not a directory", target)
	}

	// Canonicalise $HOME for the same reason the target is canonicalised: grants
	// are resolved against a real path, once, before the sandbox exists. Leaving
	// it verbatim meant the HOST side of a {home}/... grant was canonicalised by
	// add() while the GUEST side and anything derived from {home} were not.
	// Fails closed, like the target.
	if ctx.Home == "" {
		return nil, fmt.Errorf("cannot determine $HOME")
	}
	home, err := env.EvalSymlinks(ctx.Home)
	if err != nil {
		return nil, fmt.Errorf("$HOME %q: %w", ctx.Home, err)
	}

	vars := map[string]string{
		"target":        target,
		"target_parent": filepath.Dir(target),
		"home":          home,
		"host_tmpdir":   ctx.HostTmpDir,
	}

	p := &Policy{
		Target:     target,
		Home:       home,
		Hostname:   "snug",
		Chdir:      target,
		Command:    ctx.Command,
		Mounts:     map[string]Mount{},
		Env:        map[string]string{},
		Selected:   append([]string(nil), selected...),
		NewSession: ctx.LegacyTIOCSTI,
	}

	// 3. Fold every profile's grants into map[Guest]Mount. Iteration order over
	//    `set` is random by construction in Go, which is a feature here: if the
	//    fold were order-dependent, tests would flake and we would find out.
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	p.Profiles = names

	identityOwner := ""
	for _, name := range names {
		prof := set[name]
		optional := map[string]bool{}
		for _, o := range prof.Optional {
			e, err := expandVars(o, vars)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			optional[e] = true
		}

		add := func(spec string, kind Kind, access Access) error {
			host, guest, err := splitSpec(spec, vars)
			if err != nil {
				return fmt.Errorf("profile %q: %w", name, err)
			}
			m := Mount{
				Guest:    guest,
				Kind:     kind,
				Host:     host,
				Access:   access,
				Optional: optional[host] || optional[guest],
				From:     []string{name},
			}
			if kind == KindBind {
				// Canonicalise the host side now, while we still trust the
				// filesystem. A symlink planted inside the sandbox later cannot
				// retroactively widen a grant resolved here.
				real, err := env.EvalSymlinks(host)
				if err != nil {
					if m.Optional || os.IsNotExist(err) && m.Optional {
						return nil
					}
					if os.IsNotExist(err) {
						return fmt.Errorf("profile %q grants %q which does not exist (mark it optional if that is expected)", name, host)
					}
					return fmt.Errorf("profile %q: %s: %w", name, host, err)
				}
				if err := underTargetIsLiteral(target, host, real); err != nil {
					return fmt.Errorf("profile %q: %w", name, err)
				}
				m.Host = real
			}
			return p.join(m)
		}

		for _, s := range prof.RO {
			if err := add(s, KindBind, AccessRO); err != nil {
				return nil, err
			}
		}
		for _, s := range prof.RW {
			if err := add(s, KindBind, AccessRW); err != nil {
				return nil, err
			}
		}
		for _, s := range prof.Tmpfs {
			g, err := expandVars(s, vars)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			if err := p.join(Mount{Guest: filepath.Clean(g), Kind: KindTmpfs, Access: AccessRW, From: []string{name}}); err != nil {
				return nil, err
			}
		}
		for _, s := range prof.Symlink {
			at, err := expandVars(s.At, vars)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			if err := p.join(Mount{Guest: filepath.Clean(at), Kind: KindSymlink, Host: s.Target, Access: AccessRO, From: []string{name}}); err != nil {
				return nil, err
			}
		}
		// Identity does NOT join. Two profiles pinning different accounts is a
		// question with no safe answer — silently picking one would mean the
		// agent pushes as an identity the human did not choose — so it is a
		// conflict, reported with both names.
		if prof.Identity != nil {
			if p.Identity != nil && *p.Identity != *prof.Identity {
				return nil, fmt.Errorf("profiles %q and %q pin different identities; "+
					"select only one", identityOwner, name)
			}
			mode, err := ParseSSHMode(string(prof.Identity.SSHMode))
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			id := *prof.Identity
			id.SSHMode = mode
			if id.SSHKey != "" {
				expanded, err := expandVars(id.SSHKey, vars)
				if err != nil {
					return nil, fmt.Errorf("profile %q: %w", name, err)
				}
				id.SSHKey = expanded
			}
			p.Identity = &id
			identityOwner = name
		}

		// Network scalars, each joined permissive-ward. A profile can only ever
		// move the sandbox further open; there is no value that closes it.
		if prof.Network != "" {
			mode, err := ParseNetMode(prof.Network)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			p.Net.Mode = p.Net.Mode.Join(mode)
		}
		p.Net.DNS = p.Net.DNS || prof.DNS
		p.Net.PublishAuto = p.Net.PublishAuto || prof.PublishAuto
		p.Net.Publish = append(p.Net.Publish, prof.Publish...)
		if prof.Address != "" {
			p.Net.Address = prof.Address
		}
		if prof.Gateway != "" {
			p.Net.Gateway = prof.Gateway
		}
		if prof.MTU > 0 {
			p.Net.MTU = prof.MTU
		}

		for _, e := range prof.Env {
			if v := env.Getenv(e); v != "" {
				if forbiddenEnv[e] {
					return nil, fmt.Errorf("profile %q grants env %q, which is a code-injection vector into every process in the sandbox and is never passed", name, e)
				}
				p.Env[e] = v
			}
		}
	}

	// 4. Builtins that every sandbox gets. /proc needs the pid namespace to be
	//    meaningful; /dev is bwrap's synthetic minimal set, never a bind of the
	//    host's (which would hand over every block device and input device).
	p.mustJoin(Mount{Guest: "/proc", Kind: KindProc, Access: AccessRW, From: []string{"(builtin)"}})
	p.mustJoin(Mount{Guest: "/dev", Kind: KindDev, Access: AccessRW, From: []string{"(builtin)"}})
	if _, ok := p.Mounts["/tmp"]; !ok {
		p.mustJoin(Mount{Guest: "/tmp", Kind: KindTmpfs, Access: AccessRW, From: []string{"(builtin)"}})
	}

	if p.Net.DNS {
		p.Net.Nameservers = RoutableNameservers(ctx.HostNameservers)
	}

	// Identity files are GENERATED, never bound. ~/.ssh is not mounted at all,
	// so the sandbox learns nothing about which hosts or keys you have.
	if id := p.Identity; id != nil {
		if cfg := id.GitConfig(); len(cfg) > 0 {
			p.Mounts[home+"/.gitconfig"] = Mount{
				Guest: home + "/.gitconfig", Kind: KindData, Access: AccessRO,
				Content: cfg, From: []string{"identity:" + identityOwner},
			}
			// GIT_CONFIG_GLOBAL REPLACES the global config; without it git reads
			// ~/.gitconfig AND $XDG_CONFIG_HOME/git/config and merges them. So
			// with the git-ro profile also selected, the host's credential
			// helpers, insteadOf rules and user.email would sit alongside the
			// pinned identity — silently overriding what the human chose.
			// Verified: git merges both files; GIT_CONFIG_GLOBAL replaces both.
			p.Env["GIT_CONFIG_GLOBAL"] = home + "/.gitconfig"
		}
		if cfg := id.SSHConfig(home); len(cfg) > 0 {
			p.Mounts[home+"/.ssh/config"] = Mount{
				Guest: home + "/.ssh/config", Kind: KindData, Access: AccessRO,
				Content: cfg, From: []string{"identity:" + identityOwner},
			}
			// The pinned PUBLIC key, so IdentityFile above resolves. Public
			// material only; the private key never enters the sandbox.
			if len(ctx.PinnedPubKey) > 0 {
				p.Mounts[home+"/"+PubKeyGuest] = Mount{
					Guest: home + "/" + PubKeyGuest, Kind: KindData, Access: AccessRO,
					Content: ctx.PinnedPubKey, From: []string{"identity:" + identityOwner},
				}
			}
			p.Mounts[home+"/.ssh/known_hosts"] = Mount{
				Guest: home + "/.ssh/known_hosts", Kind: KindData, Access: AccessRO,
				Content: ctx.KnownHosts, From: []string{"identity:" + identityOwner},
			}
		}
	}

	// /etc/resolv.conf is GENERATED, never bound from the host. The host's may
	// name 127.0.0.53 (systemd-resolved), which the sandbox must not be able to
	// reach — and a tmpfs the agent could rewrite would be worse still.
	p.Mounts["/etc/resolv.conf"] = Mount{
		Guest:   "/etc/resolv.conf",
		Kind:    KindData,
		Access:  AccessRO,
		Content: p.Net.ResolvConf(),
		From:    []string{"(builtin)"},
	}

	// 5. The environment is reconstructed, not filtered. --clearenv discards the
	//    host's, and each variable below is set explicitly.
	p.Env["HOME"] = home
	p.Env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
	p.Env["USER"] = envOr(env, "USER", "user")
	p.Env["LOGNAME"] = p.Env["USER"]
	p.Env["SHELL"] = ctx.Shell
	p.Env["TMPDIR"] = "/tmp"
	if ctx.Term != "" {
		p.Env["TERM"] = ctx.Term
	}
	p.Env["SNUG"] = "1"
	p.Env["SNUG_PROFILES"] = strings.Join(names, ",")
	p.Env["SNUG_TARGET"] = target

	// A prompt that says where you are. This matters more than cosmetics: snug
	// does not curate /etc/bash.bashrc, so without this the shell falls back to
	// bash's built-in "bash-5.3$" and there is nothing on screen distinguishing
	// a sandboxed shell from a host one. Both humans and agents act on what the
	// prompt tells them, and "am I inside the sandbox?" is the one question
	// where guessing wrong is expensive.
	//
	// The escapes are bash/zsh syntax. A strict POSIX sh prints them literally,
	// which is ugly but harmless; the shells people actually get here expand them.
	p.Env["PS1"] = `🔒 snug:\w\$ `
	if ctx.Lang != "" {
		p.Env["LANG"] = ctx.Lang
	}
	if ctx.TZ != "" {
		p.Env["TZ"] = ctx.TZ
	}

	if err := p.Validate(env); err != nil {
		return nil, err
	}
	return p, nil
}

// underTargetIsLiteral refuses a grant whose resolution is diverted by a symlink
// living inside the sandbox's own writable area.
//
// Grants are canonicalised with EvalSymlinks at resolve time, which is what stops
// a symlink planted later from widening one. But a symlink planted EARLIER — by a
// previous sandbox run, which had write access to the target — is followed
// faithfully. A profile granting {target}/build, where build -> ~/.ssh, would
// bind ~/.ssh into the sandbox.
//
// The distinction that matters: symlinks ABOVE the target (/home -> /var/home on
// Silverblue-style hosts) are host configuration and must still be followed, or
// snug breaks on those machines. Symlinks at or below the target are attacker-
// controlled. So the comparison is against the LEXICAL JOIN under the canonical
// target, never against the requested path itself — the latter would reject
// every grant on a host whose /home is a symlink.
func underTargetIsLiteral(canonTarget, requested, real string) error {
	rel, ok := under(canonTarget, requested)
	if !ok {
		return nil
	}
	if want := filepath.Join(canonTarget, rel); real != want {
		return fmt.Errorf("grant %s resolves to %s: a symlink inside the sandbox's own "+
			"writable area redirects it, and snug will not follow that", requested, real)
	}
	return nil
}

// under reports whether p is canonTarget or below it, and the relative remainder.
func under(canonTarget, p string) (string, bool) {
	if p == canonTarget {
		return "", true
	}
	if rest, ok := strings.CutPrefix(p, canonTarget+"/"); ok {
		return rest, true
	}
	return "", false
}

// forbiddenEnv are code-injection vectors into every process the sandbox
// launches. This is the one place snug overrides an explicit grant, and it does
// so with a loud error rather than a silent drop so the human learns why.
var forbiddenEnv = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"BASH_ENV": true, "ENV": true, "PERL5OPT": true, "PYTHONSTARTUP": true,
	"GIT_SSH_COMMAND": true, "NODE_OPTIONS": true,
}

func envOr(e Environ, k, def string) string {
	if v := e.Getenv(k); v != "" {
		return v
	}
	return def
}

// join folds one grant into the policy. This is the whole of the monotonicity
// argument in code: every outcome is either a permissive-ward join or a
// symmetric error. There is no branch that lowers Access.
func (p *Policy) join(m Mount) error {
	old, ok := p.Mounts[m.Guest]
	if !ok {
		p.Mounts[m.Guest] = m
		return nil
	}
	if old.Kind != m.Kind {
		return fmt.Errorf("conflict at %s: %s (from %s) vs %s (from %s)",
			m.Guest, old.Kind, strings.Join(old.From, "+"), m.Kind, strings.Join(m.From, "+"))
	}
	if old.Kind == KindBind && old.Host != m.Host {
		return fmt.Errorf("conflict at %s: bound from %s (by %s) and from %s (by %s)",
			m.Guest, old.Host, strings.Join(old.From, "+"), m.Host, strings.Join(m.From, "+"))
	}
	old.Access = old.Access.Join(m.Access)
	old.Optional = old.Optional && m.Optional
	old.From = union(old.From, m.From)
	p.Mounts[m.Guest] = old
	return nil
}

func (p *Policy) mustJoin(m Mount) {
	if _, ok := p.Mounts[m.Guest]; !ok {
		p.Mounts[m.Guest] = m
	}
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Expand resolves a selection to the full transitive set of profiles it pulls
// in. Exported so a caller can inspect what it is about to run — the CLI uses
// it to discover whether any selected profile needs a host resource prepared
// before resolution can succeed.
func Expand(reg map[string]*Profile, selected []string) (map[string]*Profile, error) {
	out := map[string]*Profile{}
	for _, name := range selected {
		if err := expand(reg, name, out, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func expand(reg map[string]*Profile, name string, out map[string]*Profile, stack []string) error {
	for _, s := range stack {
		if s == name {
			return fmt.Errorf("include cycle: %s -> %s", strings.Join(stack, " -> "), name)
		}
	}
	if _, done := out[name]; done {
		return nil
	}
	prof, ok := reg[name]
	if !ok {
		return fmt.Errorf("unknown profile %q", name)
	}
	out[name] = prof
	for _, inc := range prof.Include {
		if err := expand(reg, inc, out, append(stack, name)); err != nil {
			return err
		}
	}
	return nil
}

// splitSpec parses "path" or "host:guest" and expands {variables} in both.
func splitSpec(spec string, vars map[string]string) (host, guest string, err error) {
	s, err := expandVars(spec, vars)
	if err != nil {
		return "", "", err
	}
	if i := strings.Index(s, ":"); i >= 0 {
		host, guest = s[:i], s[i+1:]
	} else {
		host, guest = s, s
	}
	if !filepath.IsAbs(host) || !filepath.IsAbs(guest) {
		return "", "", fmt.Errorf("grant %q: both sides must be absolute paths", spec)
	}
	return filepath.Clean(host), filepath.Clean(guest), nil
}

func expandVars(s string, vars map[string]string) (string, error) {
	if strings.HasPrefix(s, "~/") {
		s = vars["home"] + s[1:]
	}
	for {
		i := strings.Index(s, "{")
		if i < 0 {
			return s, nil
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			return "", fmt.Errorf("unterminated variable in %q", s)
		}
		key := s[i+1 : i+j]
		val, ok := vars[key]
		if !ok {
			return "", fmt.Errorf("unknown variable {%s} in %q", key, s)
		}
		s = s[:i] + val + s[i+j+1:]
	}
}
