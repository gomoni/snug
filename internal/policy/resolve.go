package policy

import (
	"bytes"
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
//
// An EMPTY selection is not special-cased: it resolves like any other, folding
// zero profiles' grants into the base topology (/proc, /dev, /tmp,
// /etc/resolv.conf), and is then refused by Validate as a policy nothing
// selected can run. Describing a policy is not the same act as admitting it —
// Validate is the only refuser, so --dry-run can show precisely what a refused
// selection would have been. This means Resolve's return contract is NOT the
// usual (nil, err) / (p, nil):
//
//   - Validate failure: returns (p, err) — the non-nil policy is EXACTLY what
//     was refused and why, for display. It must never be executed.
//   - every other failure (bad profile name, bad target, bad $HOME, ...):
//     returns (nil, err), because no policy was ever assembled to show.
//   - success: (p, nil).
//
// Callers must check err first and treat a non-nil err as "do not run this",
// regardless of whether p is nil.
func Resolve(reg map[string]*Profile, selected []string, ctx Context, env Environ) (*Policy, error) {
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
		Env:        map[string]EnvVar{},
		Selected:   append([]string(nil), selected...),
		NewSession: ctx.LegacyTIOCSTI,
	}

	// 3. Fold every profile's grants into map[Guest]Mount, in sorted name order.
	//
	//    THE FOLD ORDER MUST NOT BE OBSERVABLE. It is sorted, not randomised, and
	//    that is a deliberate choice against the obvious alternative: randomising
	//    it in production would make a resolver bug INTERMITTENT, and a security
	//    tool that is wrong occasionally is worse than one that is wrong
	//    reproducibly. Randomness belongs in the test suite, where a shuffle is a
	//    property test and a flake is a finding — see TestResolveIsCommutative,
	//    which shuffles 200 selections and compares the whole resolved policy.
	//
	//    So sorting here is a determinism device, NOT a tie-break: no resolved
	//    value may depend on which profile the fold reached first. Every scalar
	//    below is either a join or a symmetric error for exactly that reason.
	//    (This comment previously claimed map iteration order was "a feature
	//    here", three lines above the sort that removed it.)
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	p.Profiles = names

	// Which profile last set each non-lattice scalar, so a conflict can name both
	// sides rather than just reporting that there is one.
	identityOwner := ""
	addressOwner, gatewayOwner, mtuOwner := "", "", ""
	publish := map[int]bool{}
	// Environment claims are ACCUMULATED here and resolved after the fold — see
	// envresolve.go for why deciding during the fold cannot name every claimant.
	envClaims := newEnvClaims()
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
				// This path is READ, not mounted — sshproxy.New parses it for
				// the blob the proxy answers REQUEST_IDENTITIES with — so a
				// symlink AT it does not widen a grant, it selects WHICH host
				// key the sandbox can sign with. Under the target that is a
				// path the sandbox itself can write, and a previous run could
				// have planted the link, so it gets exactly what add() gives a
				// bind: resolve while the filesystem is still trusted, and
				// refuse a redirect out of the target.
				//
				// Outside the target it is deliberately NOT canonicalised, and
				// that is a narrower choice than add() makes. Two reasons: the
				// path carries the same trust as a grant's host side — the
				// human named it on their own filesystem — and canonicalising
				// would make resolution depend on the file existing, which
				// turns `snug profile show` and `--dry-run` into hard failures
				// for a profile whose key is merely absent. The hole being
				// closed here is the sandbox-writable one.
				if _, ok := under(target, expanded); ok {
					real, err := env.EvalSymlinks(expanded)
					if err != nil {
						return nil, fmt.Errorf("profile %q: ssh_key %s: %w", name, expanded, err)
					}
					if err := underTargetIsLiteral(target, expanded, real); err != nil {
						return nil, fmt.Errorf("profile %q: ssh_key: %w", name, err)
					}
					expanded = real
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
		if prof.Podman != "" {
			mode, err := ParsePodmanMode(prof.Podman)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			p.Podman = p.Podman.Join(mode)
		}
		p.Net.DNS = p.Net.DNS || prof.DNS

		// Publish is a SET, unioned — not a list appended to. Appending made
		// `publish = [3000]` in two profiles resolve to [3000 3000] and reach
		// pasta's -t as a duplicate, and it made the value depend on the fold
		// order, which the model does not have. INDEX §2.3 already said "union".
		for _, port := range prof.Publish {
			publish[port] = true
		}

		// address / gateway / mtu are NOT joins: there is no "more permissive"
		// IP address. They were last-writer-wins, which survived only because the
		// fold is sorted — the alphabetically later profile won, silently and
		// arbitrarily. No key in the model may be last-writer-wins, so two
		// profiles disagreeing is a symmetric error naming both, exactly as
		// `identity` already is. They are pasta cosmetics either way: they change
		// which address the sandbox SEES, never what it can reach.
		if prof.Address != "" {
			if p.Net.Address != "" && p.Net.Address != prof.Address {
				return nil, scalarConflict("network addresses", addressOwner, p.Net.Address, name, prof.Address)
			}
			p.Net.Address, addressOwner = prof.Address, name
		}
		if prof.Gateway != "" {
			if p.Net.Gateway != "" && p.Net.Gateway != prof.Gateway {
				return nil, scalarConflict("network gateways", gatewayOwner, p.Net.Gateway, name, prof.Gateway)
			}
			p.Net.Gateway, gatewayOwner = prof.Gateway, name
		}
		if prof.MTU > 0 {
			if p.Net.MTU > 0 && p.Net.MTU != prof.MTU {
				return nil, scalarConflict("MTUs", mtuOwner, p.Net.MTU, name, prof.MTU)
			}
			p.Net.MTU, mtuOwner = prof.MTU, name
		}

		// The environment grants. Every rule that is a property of the profile
		// TEXT runs at parse time (internal/profile calls ValidateEnvGrants), so
		// a profile's verdict does not depend on the host reading it — but a
		// Profile built in code never went through a parser, so the same check
		// runs here too. It is pure and cheap, and the alternative is a gate
		// that exists on one of two paths.
		if err := ValidateEnvGrants(prof.Environ); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		// The other half runs here and not at parse time, because it needs
		// {target} and {home} expanded — but it is still over profile TEXT, so
		// the verdict does not depend on which mounts survived. See
		// envcoupling.go, and read the first paragraph there before citing this
		// as a boundary: it stops a profile lying, not a profile reaching.
		if err := checkEnvCoupling(reg, name, prof.Environ, vars); err != nil {
			return nil, err
		}
		if err := collectEnv(envClaims, name, prof.Environ, vars, env); err != nil {
			return nil, err
		}
	}

	// A set has no order, so the one rendered here is sorted rather than the one
	// profiles happened to be folded in.
	if len(publish) > 0 {
		p.Net.Publish = sortedInts(publish)
	}

	// 3b. If podman resolves to a host-escape shim on this host AND a podman
	// profile is selected, stage a dispatcher stub ahead of it on PATH rather
	// than leave a binary that fails cryptically from inside. Gated on
	// p.Podman so a sandbox that never asked for containers never sees it.
	// See podmanstub.go and CONTAINER-CLIENT.md §8 for the abuse sentence and
	// the two load-bearing constraints (unwritable; every message says
	// "stub").
	//
	// It goes in StagedBinDir because EVERY executable snug puts in front of the
	// payload goes there, whether snug generated it (this stub) or a profile
	// bound it (@claude's binary). Nothing decides a directory locally.
	if p.Podman != PodmanOff {
		for _, shim := range ctx.HostShims {
			if shim.Name != "podman" {
				continue
			}
			content, err := podmanStubScript(shim)
			if err != nil {
				return nil, err
			}
			perm := uint32(0755)
			p.Replace(Mount{
				Guest: StagedBinDir + "/podman", Kind: KindData, Access: AccessRO,
				Perms: &perm, Content: []byte(content), From: []string{"(snug)"},
			})
			break
		}
	}

	// 4. Mounts snug authors ITSELF, in every sandbox. /proc needs the pid
	//    namespace to be meaningful; /dev is bwrap's synthetic minimal set,
	//    never a bind of the host's (which would hand over every block device
	//    and input device).
	//
	//    Their provenance reads "(snug)" rather than naming a profile, and they
	//    are Authored — the distinction the invariants turn on: a profile may not
	//    mount over another profile's grant, snug may replace a path with its own
	//    generated content. It used to read "(builtin)", which now collides with
	//    the @-marked builtin PROFILES (policy.Sigil) — two different things one
	//    word, on the same --dry-run screen.
	//
	//    /proc and /dev yield to a profile's grant only so Validate can refuse it
	//    by name (RULE 4); /tmp yields for real, which is how @tmp-shared works.
	p.yieldTo(Mount{Guest: "/proc", Kind: KindProc, Access: AccessRW, From: []string{"(snug)"}})
	p.yieldTo(Mount{Guest: "/dev", Kind: KindDev, Access: AccessRW, From: []string{"(snug)"}})
	p.yieldTo(Mount{Guest: "/tmp", Kind: KindTmpfs, Access: AccessRW, From: []string{"(snug)"}})

	if p.Net.DNS {
		p.Net.Nameservers = RoutableNameservers(ctx.HostNameservers)
	}

	// Identity files are GENERATED, never bound. ~/.ssh is not mounted at all,
	// so the sandbox learns nothing about which hosts or keys you have.
	if id := p.Identity; id != nil {
		if cfg := id.GitConfig(); len(cfg) > 0 {
			p.Replace(Mount{
				Guest: home + "/.gitconfig", Kind: KindData, Access: AccessRO,
				Content: cfg, From: []string{"identity:" + identityOwner},
			})
			// GIT_CONFIG_GLOBAL REPLACES the global config; without it git reads
			// ~/.gitconfig AND $XDG_CONFIG_HOME/git/config and merges them. So
			// with the git-ro profile also selected, the host's credential
			// helpers, insteadOf rules and user.email would sit alongside the
			// pinned identity — silently overriding what the human chose.
			// Verified: git merges both files; GIT_CONFIG_GLOBAL replaces both.
			p.AuthorEnv("GIT_CONFIG_GLOBAL", home+"/.gitconfig")
		}
		if cfg := id.SSHConfig(home); len(cfg) > 0 {
			p.Replace(Mount{
				Guest: home + "/.ssh/config", Kind: KindData, Access: AccessRO,
				Content: cfg, From: []string{"identity:" + identityOwner},
			})
			// The pinned PUBLIC key, so IdentityFile above resolves. Public
			// material only; the private key never enters the sandbox.
			if len(ctx.PinnedPubKey) > 0 {
				p.Replace(Mount{
					Guest: home + "/" + PubKeyGuest, Kind: KindData, Access: AccessRO,
					Content: ctx.PinnedPubKey, From: []string{"identity:" + identityOwner},
				})
			}
			p.Replace(Mount{
				Guest: home + "/.ssh/known_hosts", Kind: KindData, Access: AccessRO,
				Content: ctx.KnownHosts, From: []string{"identity:" + identityOwner},
			})
		}
	}

	// /etc/resolv.conf is GENERATED, never bound from the host. The host's may
	// name 127.0.0.53 (systemd-resolved), which the sandbox must not be able to
	// reach — and a tmpfs the agent could rewrite would be worse still.
	p.Replace(Mount{
		Guest:   "/etc/resolv.conf",
		Kind:    KindData,
		Access:  AccessRO,
		Content: p.Net.ResolvConf(),
		From:    []string{"(snug)"},
	})

	// 5. The environment is reconstructed, not filtered. --clearenv discards the
	//    host's, and each variable below is set explicitly.
	//
	//    The PROFILES' bands go in first, and this is the earliest point they
	//    can: `sanitise` asks "is this guest path granted", so it has to see the
	//    whole mount set — including the authored mounts and every Replace
	//    above. Conflicts are reported here rather than during the fold, so the
	//    message can name every claimant (envresolve.go).
	if err := p.applyEnvClaims(envClaims, env); err != nil {
		return nil, err
	}

	p.AuthorEnv("HOME", home)
	// PATH is the base plus whatever profiles asked for, profile entries FIRST
	// so a profile-provided tool wins over a distro one of the same name — that
	// is the point of asking. StagedBinDir goes NEXT, after every profile entry
	// and before the base: what is staged there must beat the distro's copy of
	// the same name, which is the whole reason it was staged, and must LOSE to a
	// profile entry, because a profile entry is an explicit human grant.
	//
	// The band appears IFF something was actually staged, computed from the
	// resolved mounts rather than tracked by whoever did the staging. That is
	// what lets a profile put a binary there — @claude binds its executable at
	// StagedBinDir/claude — without every such profile having to remember a
	// matching `environ.merge` line, and without the grant-coupling rule being
	// asked to reason about a directory no profile grants. The alternative,
	// letting each profile name its own directory, is how @claude came to merge
	// {home}/.local/bin, which is a WRITABLE tmpfs and therefore a shadow slot
	// snug itself installed (StagedBinDir's doc comment; CLAUDE.md).
	//
	// Each band is a separate write, in the order it is rendered: a profile's
	// directories are the profile's authorship, while the staged directory and
	// the base are snug's own and say so.
	if p.HasStagedBin() {
		p.AuthorEnvList("PATH", []string{StagedBinDir}, "staged bin")
	}
	p.AuthorEnvList("PATH", basePATH, "base")
	user := envOr(env, "USER", "user")
	p.AuthorEnv("USER", user)
	p.AuthorEnv("LOGNAME", user)
	p.AuthorEnv("SHELL", ctx.Shell)
	p.AuthorEnv("TMPDIR", "/tmp")
	if ctx.Term != "" {
		p.AuthorEnv("TERM", ctx.Term)
	}
	p.AuthorEnv("SNUG", "1")
	p.AuthorEnv("SNUG_PROFILES", strings.Join(names, ","))
	p.AuthorEnv("SNUG_TARGET", target)

	// A prompt that says where you are. This matters more than cosmetics: snug
	// does not curate /etc/bash.bashrc, so without this the shell falls back to
	// bash's built-in "bash-5.3$" and there is nothing on screen distinguishing
	// a sandboxed shell from a host one. Both humans and agents act on what the
	// prompt tells them, and "am I inside the sandbox?" is the one question
	// where guessing wrong is expensive.
	//
	// The escapes are bash/zsh syntax. A strict POSIX sh prints them literally,
	// which is ugly but harmless; the shells people actually get here expand them.
	p.AuthorEnv("PS1", `🔒 snug:\w\$ `)
	if ctx.Lang != "" {
		p.AuthorEnv("LANG", ctx.Lang)
	}
	if ctx.TZ != "" {
		p.AuthorEnv("TZ", ctx.TZ)
	}

	// LAST, after every band including snug's own: a repeated element collapses
	// to its earliest band, which is what makes prepend's guarantee literally
	// true and what stops a profile naming /bin producing it twice.
	p.dedupeEnvLists()

	// Topology is DERIVED, after p.Net and p.Podman are fully folded and before
	// Validate runs, so a hand-built *Policy that skips Resolve cannot carry a
	// Topology inconsistent with its own Net/Podman — Validate refuses exactly
	// that (see the rule below).
	p.Topology = deriveTopology(p.Net.Mode, p.Podman)

	if err := p.Validate(env); err != nil {
		return p, err
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

// The unexported `replace` that used to live here is now Policy.Replace
// (types.go), exported and marking Mount.Authored — because the same operation
// is needed by cmd/snug's staging layer, and three sites there were assigning
// p.Mounts[...] directly instead, bypassing both the provenance record and
// Validate.

// forbiddenEnv lives in envtypes.go now, split by verb: a value carried by a
// reviewed profile file and a value inherited from whoever launched snug are
// two different things, and one middle bucket is legal as the first and not the
// second (CALL 4).

// envOr keeps Getenv's "empty means absent" reading DELIBERATELY, and it is the
// one place that is right. Its callers want a value snug can fall back on —
// USER, and nothing else today — where an empty host value is no more useful
// than an unset one and "user" is a better answer than "". The presence
// distinction above exists for FLAG variables, where empty is a value; do not
// unify the two, because "right for one type, wrong for the other" is how this
// class of bug ships (§2.6).
func envOr(e Environ, k, def string) string {
	if v := e.Getenv(k); v != "" {
		return v
	}
	return def
}

// join folds one grant into the policy — RULE 1, the same-path rule.
//
// Two grants at one guest path join IFF they describe the IDENTICAL node: same
// Kind, same Host, same Perms, same Content. Then Access joins by max, Optional
// by AND, From unions. Anything else is a symmetric error naming both profiles
// and both values, because there is no join between two answers to "what node
// exists here" — only between two answers to "how much access to it".
//
// This is the whole of the monotonicity argument in code: every outcome is
// either a permissive-ward join or a symmetric error, and there is no branch
// that lowers Access. `ro` + `rw` STAYS a join for that reason and not for
// convenience: Access is the only field whose value domain is a semilattice, and
// INDEX §2.4's third leg (Resolve(A ∪ B) ⊒ Resolve(A)) is a statement about
// that lattice. Make differing access fatal and Resolve stops being a total
// join, at which point monotonicity is something we hope for rather than
// something the model IS.
//
// THE HOST COMPARISON IS NOT GUARDED BY KIND, and that guard was a real hole.
// For a KindSymlink, Host is the LINK TARGET; `old.Kind == KindBind &&` in front
// of the comparison meant two profiles pointing one symlink at two different
// targets silently kept whichever sorted first, and printed BOTH names as the
// provenance. A user profile called `0shadow` (a digit sorts before `@`) could
// therefore repoint `@sys`'s `/bin -> usr/bin` at `usr/sbin` while --dry-run
// read `0shadow+@sys`, as though the two agreed. That is a profile displacing
// another profile's grant — the thing invariant 1 says is structurally
// impossible. Host is "" for every kind that has no host side, so comparing it
// unconditionally is free.
func (p *Policy) join(m Mount) error {
	old, ok := p.Mounts[m.Guest]
	if !ok {
		p.Mounts[m.Guest] = m
		return nil
	}
	if old.Kind != m.Kind {
		return fmt.Errorf("conflict at %s: %s (from %s) vs %s (from %s).\n"+
			"       Two profiles ask for a different kind of node at one path. There is no join\n"+
			"       between them, so select one of the two, not both.",
			m.Guest, old.Kind, provenance(old), m.Kind, provenance(m))
	}
	if old.Host != m.Host {
		if m.Kind == KindSymlink {
			return fmt.Errorf("conflict at %s: symlink to %s (from %s) and to %s (from %s).\n"+
				"       A symlink has one target; profiles may only ever grant, so neither may\n"+
				"       silently repoint the other's. Select one of the two.",
				m.Guest, old.Host, provenance(old), m.Host, provenance(m))
		}
		return fmt.Errorf("conflict at %s: bound from %s (by %s) and from %s (by %s).\n"+
			"       One guest path, two host sources. Select one of the two profiles.",
			m.Guest, old.Host, provenance(old), m.Host, provenance(m))
	}
	if !samePerms(old.Perms, m.Perms) {
		return fmt.Errorf("conflict at %s: mode %s (from %s) and %s (from %s)",
			m.Guest, permString(old.Perms), provenance(old), permString(m.Perms), provenance(m))
	}
	if !bytes.Equal(old.Content, m.Content) {
		return fmt.Errorf("conflict at %s: two different generated contents (from %s and from %s)",
			m.Guest, provenance(old), provenance(m))
	}
	old.Access = old.Access.Join(m.Access)
	old.Optional = old.Optional && m.Optional
	old.From = union(old.From, m.From)
	p.Mounts[m.Guest] = old
	return nil
}

// yieldTo installs one of snug's base mounts only where no profile already
// claimed that guest path. It exists for /tmp, and ONLY /tmp is meant to be
// yielded: `@tmp-shared` replaces the private tmpfs with a host directory, and
// stepping aside is how that profile works.
//
// /proc and /dev go through it too, and there the yield is a diagnostic device
// rather than an intention: Validate refuses any non-authored mount at either
// path (RULE 4), and leaving the profile's grant in place is what lets the
// refusal NAME the profile that wrote it instead of silently discarding it.
// This used to be one function called mustJoin serving both intentions at once,
// which is how "ro = [\"/proc/sys\"]" and a bind at /proc came to be accepted.
func (p *Policy) yieldTo(m Mount) {
	m.Authored = true
	if _, ok := p.Mounts[m.Guest]; !ok {
		p.Mounts[m.Guest] = m
	}
}

func samePerms(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func permString(p *uint32) string {
	if p == nil {
		return "default"
	}
	return fmt.Sprintf("%04o", *p)
}

// provenance renders a mount's contributing profiles for an error message.
// Every refusal in this package names BOTH sides, so "it broke" becomes "I know
// which line to delete".
func provenance(m Mount) string { return strings.Join(m.From, "+") }

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

// retiredProfiles names builtins snug shipped and then removed on purpose,
// mapped to what replaces them. A retired name is not "unknown" — the mistake
// is not a typo, it is that the thing it asked for no longer exists as a
// profile — so it gets a specific error rather than the generic "see: snug
// profile list", the same shape TestRetiredPublishAutoIsAHardError already
// uses for a retired TOML key.
var retiredProfiles = map[string]string{
	"null": "there is no @null profile (MVY0): a profile that grants nothing " +
		"is a preference, not a grant. The lattice floor is what an empty " +
		"selection already resolves to — use --no-defaults, not -p @null",
}

// UnknownProfile is the error for a name nothing defines. It exists rather than
// a bare fmt.Errorf because the mistake people will actually make is the sigil:
// snug's own profiles are `@sys`, `@net`, `@claude`, and typing `sys` is the
// natural slip. An error that names the fix is worth the six lines — see the
// working agreement in CLAUDE.md.
//
// Every caller that looks a name up in a registry should route through here, so
// `snug -p sys`, `snug profile show sys` and `include = ["sys"]` inside a
// user's own file all say the same thing.
func UnknownProfile(reg map[string]*Profile, name string) error {
	// The user's OWN profiles are checked before the retired table, not after.
	// `null` is a perfectly legal name for a profile someone defines, and the
	// table used to preempt it: `snug profile show @null` told that user their
	// profile did not exist, pointing them at MVY0's reasoning about a builtin
	// they had never heard of. A retired name is only retired when nothing on
	// this host defines it.
	bare := strings.TrimPrefix(name, Sigil)
	_, mineBare := reg[bare]
	_, mineMarked := reg[name]
	if msg, retired := retiredProfiles[bare]; retired && !mineBare && !mineMarked {
		return fmt.Errorf("%s", msg)
	}
	if _, ok := reg[Sigil+name]; ok {
		return fmt.Errorf("unknown profile %q; snug's own profiles carry a leading %s, "+
			"so you probably meant %q (see: snug profile list)", name, Sigil, Sigil+name)
	}
	if bare, marked := strings.CutPrefix(name, Sigil); marked {
		if p, ok := reg[bare]; ok {
			return fmt.Errorf("unknown profile %q; %s marks a profile snug ships, and %q is "+
				"one of yours (defined in %s)", name, Sigil, bare, p.Source)
		}
		return fmt.Errorf("unknown profile %q; snug ships no profile by that name "+
			"(see: snug profile list)", name)
	}
	return fmt.Errorf("unknown profile %q (see: snug profile list)", name)
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
		return UnknownProfile(reg, name)
	}
	out[name] = prof
	for _, inc := range prof.Include {
		if err := expand(reg, inc, out, append(stack, name)); err != nil {
			return err
		}
	}
	return nil
}

// basePATH is what every sandbox gets. Profile `path` entries go in front.
var basePATH = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// scalarConflict is the refusal for a key whose value domain is not a
// semilattice. It names BOTH profiles and BOTH values, so "it broke" becomes "I
// know which line to delete".
func scalarConflict(key, ownerA string, a any, ownerB string, b any) error {
	return fmt.Errorf("profiles %q and %q set different %s (%v and %v); select only one.\n"+
		"       This key has no permissive direction — there is no \"more open\" address — so snug\n"+
		"       refuses rather than choosing. Picking one would make the answer depend on the order\n"+
		"       profiles are folded, and the model has no such order.",
		ownerA, ownerB, key, a, b)
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

// expandVars substitutes {name} from vars, in ONE PASS.
//
// The single pass is the substance, not an optimisation. The loop this replaced
// restarted `strings.Index(s, "{")` over the whole result after every
// substitution, so substituted text was itself scanned for placeholders — and
// the substituted text is a PATH, which the human running snug chose. Measured:
//
//	mkdir -p '/tmp/x/{home}' /tmp/x/home/michal
//	snug '/tmp/x/{home}'
//	  -> TARGET  /tmp/x/{home}   read-only, via @parent-ro
//	  -> rw      /tmp/x/home/michal   @cwd-rw    <- a DIFFERENT directory, writable
//
// The payload wrote to it and the write persisted to the host, while the
// directory the user actually named was read-only. "The target is the only
// writable thing that persists" was false for that input. A directory named
// `{target}` was worse: expansion fed its own result back in and the process
// spun at 224% CPU until killed — quadratic in TIME, not memory (RSS stayed at
// 18 MB), so it presents as a hang rather than an OOM.
//
// Neither needs a hostile profile — a directory with a brace in its name is
// enough — and both stop being expressible once the output is written once.
func expandVars(s string, vars map[string]string) (string, error) {
	if strings.HasPrefix(s, "~/") {
		s = vars["home"] + s[1:]
	}
	if !strings.Contains(s, "{") {
		return s, nil // the overwhelmingly common case, and no allocation
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "{")
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
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
		// The literal text before the placeholder and the substituted value are
		// both COMMITTED — appended to the builder and never looked at again.
		// Only the unexamined remainder continues round the loop.
		b.WriteString(s[:i])
		b.WriteString(val)
		s = s[i+j+1:]
	}
}
