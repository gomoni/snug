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
	// of a project is a legitimate sandbox — it is what `sys dotdot` gives you,
	// and what the --read-only clamp produces — so requiring rw here would
	// forbid a perfectly good configuration.
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
	case !hasRuntime && !hasTarget:
		return fmt.Errorf("the selected profiles (%s) grant nothing: no OS runtime to execute, "+
			"and no writable target.\n"+
			"       This is the empty sandbox — it is the correct floor of the model, but nothing can run in it.\n"+
			"       Try:  snug %s          (uses the 'default' profile)\n"+
			"       See:  snug profile list",
			strings.Join(p.Profiles, " "), p.Target)
	case !hasRuntime:
		return fmt.Errorf("no OS runtime granted: neither /usr nor /bin is readable, so nothing can execute " +
			"(add the 'sys' profile)")
	case !hasTarget:
		return fmt.Errorf("target %s is not visible inside the sandbox: no profile grants it.\n"+
			"       Add 'cwd-rw' to make it writable, or 'dotdot' to see it read-only.", p.Target)
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
			return fmt.Errorf("grant %q (from %s) is not an absolute clean path", g, strings.Join(m.From, "+"))
		}
		if g == "/" && m.Kind == KindBind {
			return fmt.Errorf("refusing to bind / (from %s)", strings.Join(m.From, "+"))
		}
		// bwrap cannot create a mountpoint at a symlink destination. Catch the
		// case where a grant's guest path traverses a symlink snug itself
		// created — this is the failure that cost the previous generation a day
		// (docs/DESIGN.md §3.3).
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
// `cwd-rw` laying rw {target} over `dotdot`'s ro {target_parent}. That exposes a
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
func (p *Policy) rejectMasking(env Environ) error {
	for _, m := range p.SortedMounts() {
		// KindData is snug's own generated content — /etc/resolv.conf today,
		// /etc/hosts and a synthetic /etc/passwd later. These deliberately sit on
		// top of whatever the host has there, and that is a REPLACEMENT, not a
		// mask: the sandbox still sees a file at that path, just a truthful one.
		//
		// Exempting the kind rather than the specific paths is safe because no
		// TOML key produces a KindData grant — only snug does. If a profile key
		// is ever added that can, this exemption must be narrowed to grants whose
		// provenance is "(builtin)" or the subtraction hole reopens.
		if m.Kind == KindData {
			continue
		}
		for d := filepath.Dir(m.Guest); d != "/" && d != "."; d = filepath.Dir(d) {
			outer, ok := p.Mounts[d]
			if !ok || outer.Kind != KindBind {
				continue
			}
			if m.Kind == KindBind && sameUnderlyingTree(env, outer, m, d) {
				break // re-granting the same tree, e.g. cwd-rw over dotdot
			}
			what := "an empty tmpfs"
			if m.Kind == KindBind {
				what = fmt.Sprintf("a bind of %s", m.Host)
			}
			return fmt.Errorf("profile %s puts %s at %s, which is inside %s from profile %s.\n"+
				"       That hides what %s already exposes there, and profiles may only ever grant.\n"+
				"       Grant the parts of %s you meant instead of masking the parts you did not.",
				strings.Join(m.From, "+"), what, m.Guest, d, strings.Join(outer.From, "+"), d, d)
		}
	}
	return nil
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
