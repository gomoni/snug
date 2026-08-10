package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Validate runs before any argv is emitted, so that a mistake surfaces as a
// readable error here rather than as a bwrap abort with no provenance.
func (p *Policy) Validate(env Environ) error {
	if p.Target == "" {
		return fmt.Errorf("no target")
	}

	// Report the whole picture at once. Someone who selected an empty or
	// near-empty profile set has a concept problem, not a missing flag, and
	// telling them one gap at a time makes them fix it one gap at a time.
	hasRuntime := false
	for g := range p.Mounts {
		if g == "/usr" || g == "/bin" {
			hasRuntime = true
		}
	}
	// The target must be REACHABLE, not necessarily writable. A read-only view
	// of a project is a legitimate sandbox — it is what `sys parent-ro` gives
	// you — so requiring rw here would forbid a perfectly good configuration.
	hasTarget := false
	for _, m := range p.Mounts {
		if m.Kind != KindBind {
			continue
		}
		if p.Target == m.Guest || strings.HasPrefix(p.Target, m.Guest+"/") {
			hasTarget = true
			break
		}
	}

	switch {
	case !hasRuntime && !hasTarget && len(p.Profiles) == 0:
		// Nothing was selected AT ALL — not "a profile that happens to grant
		// nothing", there is no such profile any more (see @null's removal,
		// MVY0). This is the lattice floor: /proc, /dev, /tmp and
		// /etc/resolv.conf, and no KindBind anywhere. It is the correct result
		// of resolving an empty selection, and it is also --no-defaults's exact
		// destination — say so, since that is the flag whoever got here typed
		// (or the one their config.toml's `defaults = []` reaches silently).
		return fmt.Errorf("no profile selected: this is the floor of the lattice — an empty tmpfs "+
			"root, no OS runtime, no target — and nothing can run in it.\n"+
			"       This is what --no-defaults selects.\n"+
			"       Try:  snug %s          (uses the default profile selection)\n"+
			"       See:  snug profile list", p.Target)
	case !hasRuntime && !hasTarget:
		return fmt.Errorf("the selected profiles (%s) grant nothing: no OS runtime to execute, "+
			"and no writable target.\n"+
			"       This is the empty sandbox — it is the correct floor of the model, but nothing can run in it.\n"+
			"       Try:  snug %s          (uses the default profile selection)\n"+
			"       See:  snug profile list",
			strings.Join(p.Profiles, " "), p.Target)
	case !hasRuntime:
		return fmt.Errorf("no OS runtime granted: neither /usr nor /bin is readable, so nothing can execute " +
			"(add the 'sys' profile)")
	case !hasTarget:
		return fmt.Errorf("target %s is not visible inside the sandbox: no profile grants it.\n"+
			"       Add 'cwd-rw' to make it writable, or 'parent-ro' to see it read-only.", p.Target)
	}

	// Build the sandbox's own symlink map so we can resolve guest paths through
	// the links snug itself creates.
	links := map[string]string{}
	for _, m := range p.Mounts {
		if m.Kind == KindSymlink {
			t := m.Host
			if !filepath.IsAbs(t) {
				t = filepath.Join(filepath.Dir(m.Guest), t)
			}
			links[m.Guest] = filepath.Clean(t)
		}
	}

	guests := make([]string, 0, len(p.Mounts))
	for g := range p.Mounts {
		guests = append(guests, g)
	}
	sort.Strings(guests)

	for _, g := range guests {
		m := p.Mounts[g]
		if !filepath.IsAbs(g) || filepath.Clean(g) != g {
			return fmt.Errorf("grant %q (from %s) is not an absolute clean path", g, provenance(m))
		}
		// The root is snug's, whatever the kind. This used to refuse only a BIND
		// at /, which left `tmpfs = ["/"]` accepted — and inert, but only by
		// accident: nearestCovering stops before / and never returns it, so the
		// masking rule cannot see anything nested under a root grant. What saved
		// it was SortedMounts emitting / first, so every sibling landed on top.
		// That makes the invariant depend on mount ORDER rather than on the
		// check, which is precisely the shape that breaks quietly the day the
		// ordering is tuned for an unrelated reason. Refuse the whole path
		// instead: bwrap's root is already a tmpfs, so a profile has nothing to
		// gain here, and an invariant with no exception can be checked by
		// grepping for one. (redteam, MVY1.)
		if g == "/" && !m.Authored {
			return fmt.Errorf("profile %s puts %s at /, but the sandbox root is snug's own:\n"+
				"       it is already an empty tmpfs, and the masking rule cannot see inside a grant\n"+
				"       at / — nothing above it can be judged. Grant the paths you meant instead.",
				provenance(m), describeNode(m))
		}
		// RULE 4: /proc and /dev belong to snug, and a profile may not take them.
		//
		// snug authors both AFTER the profile fold and yields to whatever is
		// already there (Resolve step 4), so a profile grant at either path
		// silently DISPLACED snug's — `ro = ["/proc"]` handed the sandbox the
		// host's procfs instead of one bound to its own pid namespace, and a bind
		// at /dev would substitute the host's device tree for bwrap's synthetic
		// minimal set. Neither is a hole a profile gets to open. The yield is what
		// lets this refusal name the profile that did it; /tmp yields for real,
		// because @tmp-shared replacing the private tmpfs is the intended use.
		if why, ours := snugsOwn[g]; ours && !m.Authored {
			return fmt.Errorf("profile %s puts %s at %s, but %s is snug's own: %s\n"+
				"       Whatever a profile puts there displaces it, so this is a hole no profile may\n"+
				"       open. Remove the grant at %s from profile %s.",
				provenance(m), describeNode(m), g, g, why, g, provenance(m))
		}
		// bwrap cannot create a mountpoint at a symlink destination. Catch the
		// case where a grant's guest path traverses a symlink snug itself
		// created — this is the failure that cost the previous generation a day
		// (.claude/design/INDEX.md §3.3).
		if m.Kind != KindSymlink {
			if via, resolved := resolveVia(links, g); via != "" {
				return fmt.Errorf("grant %s (from %s) resolves through the symlink %s -> %s, landing at %s; "+
					"bwrap cannot create a mountpoint at a symlink destination — grant %s instead",
					g, strings.Join(m.From, "+"), via, links[via], resolved, resolved)
			}
		}
	}

	return p.rejectMasking(env)
}

// snugsOwn are the paths only snug may put a node at, with the reason. /tmp is
// deliberately NOT here: @tmp-shared replacing the private tmpfs with a host
// directory is the intended use of the yield (Resolve step 4).
var snugsOwn = map[string]string{
	"/proc": "it must be a fresh procfs bound to the sandbox's OWN pid namespace, " +
		"or the sandbox reads the host's process table.",
	"/dev": "it must be bwrap's synthetic minimal device set, never a bind of the host's " +
		"(which hands over every block device and every input device).",
}

// rejectMasking closes the ways the grant language could still express
// subtraction. Anything mounted on top of a path a bind already exposes hides
// what was underneath, which is a `mask` rule wearing a different hat.
//
// It is tempting to allow, because hiding feels like the safe direction. Two
// reasons not to:
//
//   - It breaks the property that makes profiles composable: that adding one
//     never makes anything worse. Once a profile can hide, you cannot reason
//     about a profile set without reading every profile in it.
//   - Hiding is not reliably safe. Mask /etc/ssl and TLS clients lose their
//     trust store; mask /etc/nsswitch.conf and name lookup changes behaviour.
//     "More hidden" and "more secure" are not the same axis.
//
// The one nesting that is legitimate is re-granting the SAME underlying host
// tree at a stronger access — which is exactly what the default does, with
// `cwd-rw` laying rw {target} over `parent-ro`'s ro {target_parent}. That exposes a
// superset, not a subset. So a nested grant is allowed only when it is a bind
// whose host source is the corresponding subpath of the outer bind's host.
//
// An earlier version of this check looked only at KindTmpfs, and the redteam
// agent walked straight through it with a bind of an empty directory over
// /usr/share/misc: three entries became zero, with no error. Hence the check is
// now on every kind.
//
// When you want "X but not Y", the honest reading is that X was too coarse a
// grant. Grant the parts of X you meant — or grant X read-only and the parts
// you want to write separately, which the Access join already handles.
//
// RULE 2 — nesting is judged on the OUTER mount's content, because that is what
// decides whether there was anything to hide:
//
//	outer          inner allowed?
//	KindTmpfs      YES — a fresh tmpfs exposes nothing, so nothing can be hidden
//	KindBind of H  YES iff the inner is a bind of H/rel; otherwise it substitutes
//	KindProc/Dev   NO  — populated by the kernel and by bwrap, not snug's to carve
//	KindData       NO  — a grant beneath a FILE is meaningless
//	anything       YES if the inner is snug's own authored replacement (RULE 3)
//
// The KindTmpfs row is not a convenience. Every shipped profile that exposes a
// host file into the ephemeral $HOME is a bind inside @home's tmpfs — @git-ro's
// .gitconfig, @claude's settings.json, every generated identity file — so
// treating a tmpfs as maskable would break three profiles on the first
// invocation. The principled statement is the same one: masking requires the
// outer mount to HAVE content at the inner path.
func (p *Policy) rejectMasking(env Environ) error {
	for _, m := range p.SortedMounts() {
		// RULE 3 — authorship, as a field rather than a convention. These are
		// snug's own mounts: /etc/resolv.conf, the generated identity files, the
		// staged Claude credentials, the proxy sockets. They deliberately sit on
		// top of whatever a profile exposed, and that is a REPLACEMENT, not a
		// mask: the sandbox still sees a node at that path, just a truthful one,
		// and Policy.Replace records what it displaced so --dry-run says so.
		//
		// This used to exempt Kind == KindData, justified by "no TOML key
		// produces a KindData grant". True, but a proxy for the property that
		// actually matters — WHO WROTE IT — and one that a future TOML key would
		// have inherited for free. Mount.Authored is set only by Policy.Replace,
		// which nothing a profile can write reaches.
		if m.Authored {
			continue
		}
		outer, at, ok := p.nearestCovering(m.Guest)
		if !ok {
			continue
		}
		if err := checkNesting(env, outer, at, m); err != nil {
			return err
		}
	}
	return nil
}

// nearestCovering returns the deepest mount that strictly contains guest. The
// NEAREST one is the only one that decides: it is what actually supplies the
// content at that path, and anything further up was already judged when it was
// itself the inner mount (SortedMounts is depth-ascending, so an ancestor is
// always checked before its descendants).
func (p *Policy) nearestCovering(guest string) (Mount, string, bool) {
	for d := filepath.Dir(guest); d != "/" && d != "."; d = filepath.Dir(d) {
		if m, ok := p.Mounts[d]; ok {
			return m, d, true
		}
	}
	return Mount{}, "", false
}

func checkNesting(env Environ, outer Mount, at string, inner Mount) error {
	switch outer.Kind {
	case KindTmpfs:
		// A fresh tmpfs is empty. There is nothing underneath to hide.
		return nil

	case KindBind:
		if inner.Kind == KindBind && sameUnderlyingTree(env, outer, inner, at) {
			return nil // re-granting the same tree, e.g. cwd-rw over parent-ro
		}
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s from profile %s.\n"+
			"       That hides what %s already exposes there, and profiles may only ever grant.\n"+
			"       Grant the parts of %s you meant instead of masking the parts you did not.",
			provenance(inner), describeNode(inner), inner.Guest, at, provenance(outer), at, at)

	case KindProc, KindDev:
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s — a pseudo-filesystem the "+
			"kernel and bwrap populate, not a grant any profile made.\n"+
			"       That hides what %s already exposes there, and substitutes host content for kernel\n"+
			"       content: %s\n"+
			"       Remove the grant at %s.",
			provenance(inner), describeNode(inner), inner.Guest, at, at, snugsOwn[at], inner.Guest)

	case KindData:
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s — a generated FILE (from %s).\n"+
			"       A grant beneath a file is meaningless: nothing can be mounted inside a regular file.\n"+
			"       Remove the grant at %s.",
			provenance(inner), describeNode(inner), inner.Guest, at, provenance(outer), inner.Guest)
	}
	// KindSymlink: unreachable here — Validate already refuses any grant whose
	// guest path traverses one of snug's own symlinks, with a better message
	// (bwrap cannot create a mountpoint at a symlink destination, §3.3).
	return nil
}

// describeNode names what a grant puts at its guest path, for a refusal.
// The message used to read "an empty tmpfs" for every kind that was not a bind,
// so a symlink conflict was reported as a tmpfs.
func describeNode(m Mount) string {
	switch m.Kind {
	case KindBind:
		return fmt.Sprintf("a bind of %s", m.Host)
	case KindTmpfs:
		return "an empty tmpfs"
	case KindSymlink:
		return fmt.Sprintf("a symlink to %s", m.Host)
	case KindData:
		return "generated file content"
	case KindProc:
		return "a procfs"
	case KindDev:
		return "a device tree"
	}
	return m.Kind.String()
}

// sameUnderlyingTree reports whether inner re-grants the very subpath of outer
// that it sits on, rather than substituting unrelated content for it.
func sameUnderlyingTree(env Environ, outer, inner Mount, outerGuest string) bool {
	rel := strings.TrimPrefix(inner.Guest, outerGuest+"/")
	expected := filepath.Join(outer.Host, rel)
	if inner.Host == expected {
		return true
	}
	// The grant's host was canonicalised at resolve time; the path we just built
	// by joining may still contain symlinks. Compare canonical forms before
	// calling it a mask, so a symlinked /usr/share does not trip the check.
	if real, err := env.EvalSymlinks(expected); err == nil && real == inner.Host {
		return true
	}
	return false
}

// resolveVia reports whether guest path g passes through one of our own
// symlinks, and where it would actually land.
func resolveVia(links map[string]string, g string) (via, resolved string) {
	for link, target := range links {
		if g == link {
			continue
		}
		if strings.HasPrefix(g, link+"/") {
			return link, filepath.Join(target, strings.TrimPrefix(g, link+"/"))
		}
	}
	return "", ""
}
