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

	// Topology is derived, never set independently, so a policy whose Topology
	// disagrees with what its own Net/Podman would produce did not come through
	// Resolve. This closes the zero-value hazard on hand-built policies: several
	// unit tests construct &Policy{...} directly, and a zero Topology silently
	// read as NetnsSandbox/SubuidNone/AttachNone even for a policy whose Net.Mode
	// is NetHost.
	if want := deriveTopology(p.Net.Mode, p.Podman); p.Topology != want {
		return fmt.Errorf("policy.Topology (%s) does not match what Net.Mode=%s and Podman=%s derive "+
			"(%s): build the fixture through Resolve, or set Topology with deriveTopology",
			p.Topology, p.Net.Mode, p.Podman, want)
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
		// nothing", there is no such profile any more (see @null's removal).
		// This is the lattice floor: /proc, /dev, /tmp and
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
		// A control character in a GUEST path is refused next to the clean-path
		// check, because it is the same kind of rule — a property of the text —
		// and because filepath.Clean does not touch one.
		//
		// The reason is the screen, not the kernel. --dry-run renders one grant
		// per line in fixed columns, so a newline inside a guest path prints as
		// TWO rows, and the second can be spelled to look like a grant nobody
		// wrote:
		//
		//	tmpfs = ["/a\n  ro     /etc/shadow                          @sys"]
		//
		// The sandbox in that case really has one directory whose name contains a
		// newline, and /etc/shadow is not mounted at all — the line is a lie about
		// a policy, in the artifact CLAUDE.md calls the mechanism by which a human
		// can trust snug. The renderer escapes these too; this refusal is what
		// keeps a profile from putting one there in the first place.
		//
		// GUEST only. A HOST path is not snug's to refuse: a file on this machine
		// may legally be named with a newline, and refusing to bind it would be
		// snug inventing a rule about someone else's filesystem. The renderer
		// handles that half.
		if i := strings.IndexFunc(g, func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
			return fmt.Errorf("grant %q (from %s) has a control character (%q) in its path INSIDE "+
				"the sandbox.\n"+
				"       Every line of `snug --dry-run` is one grant, so a path that spans two lines "+
				"can forge\n"+
				"       a row for a grant that does not exist. No mountpoint needs one; write the "+
				"path you meant.",
				g, provenance(m), string(g[i]))
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
		// grepping for one. (redteam.)
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
			if via, resolved := resolveViaDeepest(links, g); via != "" {
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

	// StagedBinDir is here for a different reason from the other two, and the
	// difference is the point. /proc and /dev are refused because a profile grant
	// DISPLACES snug's own node. Nothing is mounted at StagedBinDir at all — it is
	// a plain directory on the root tmpfs, and that is precisely what makes it
	// unwritable, because `--remount-ro /` covers it. A profile mounting ANYTHING
	// there — a tmpfs, or a rw bind — is a separate mount, is not covered by that
	// remount, and turns the directory writable.
	//
	// What that buys the profile is not its own writable directory. It is
	// SNUG's PATH band: HasStagedBin sees the staged executable, snug puts
	// StagedBinDir first on PATH in `(snug)` provenance, and the payload then
	// writes `git` into a directory that runs ahead of /usr/bin. Measured, with
	// `tmpfs = ["/run/snug/bin"]` plus one staged bind: WROTE-OK, and the
	// shadowed git ran. The rw-bind spelling is worse — the shadowed command
	// persists to the host directory.
	//
	// This is the case the staging rule in CLAUDE.md says cannot happen ("a
	// profile cannot pick a writable directory by accident, because it does not
	// pick one at all"), and it is not the accepted residual class either: the
	// profile writes no PATH declaration, so no human ever read a line saying a
	// writable directory would go on PATH.
	//
	// Note what is NOT refused, and must not be: a grant at a path INSIDE the
	// directory. snugsOwn is keyed on the exact guest path, so @claude's
	// `{home}/.local/bin/claude:/run/snug/bin/claude` is untouched — staging one
	// executable is the whole purpose of the directory. Only the directory itself
	// is snug's.
	StagedBinDir: "it is a plain directory on the root tmpfs, which is what makes it " +
		"unwritable once / is remounted read-only, and snug puts it FIRST on PATH. " +
		"A mount there is not covered by that remount, so it would hand the payload a " +
		"writable directory ahead of /usr/bin. Stage the file itself — " +
		"`ro = [\"/host/path/tool:" + StagedBinDir + "/tool\"]` — never the directory.",
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

// One symlink map, TWO entry points, because two different questions are asked
// of it and a single function answering both would have to hide the difference
// behind a bool. They are deliberately not folded together: the comment on each
// has to be able to say which question it answers.
//
// Both pick the DEEPEST matching link. The single function these replace
// returned the first match Go's map iteration happened to produce, which is
// nondeterministic the moment one link prefixes another — /lib and /lib64 on a
// usr-merged host is the shipped case — and a security tool whose verdict flips
// between runs is worse than one that is wrong reproducibly.

// resolveViaDeepest reports whether guest path g passes THROUGH one of our own
// symlinks, and where a mountpoint at g would actually land.
//
// g == link is SKIPPED, and that is right for a MOUNTPOINT: a grant at the link
// path is the link itself, and there is nothing being diverted. bwrap's failure
// is about creating a mountpoint at a symlink DESTINATION (.claude/design/INDEX.md
// §3.3), which only arises for a path below the link.
func resolveViaDeepest(links map[string]string, g string) (via, resolved string) {
	for link, target := range links {
		if g == link || !strings.HasPrefix(g, link+"/") {
			continue
		}
		if len(link) <= len(via) {
			continue
		}
		via, resolved = link, filepath.Join(target, strings.TrimPrefix(g, link+"/"))
	}
	return via, resolved
}

// resolveLinkForEnv rewrites a guest path through one of our own symlinks, so a
// path a profile WROTE into the environment can be compared against the paths
// that profile granted.
//
// g == link is MATCHED, and that is the difference: an environment value can be
// literally /bin, and on a usr-merged host /bin is a symlink to usr/bin rather
// than a grant. Judging it unrewritten would refuse a profile that granted /usr
// and named the path the sandbox will actually see. It returns g unchanged when
// no link applies, so the caller has one path to compare either way.
func resolveLinkForEnv(links map[string]string, g string) string {
	via, resolved := "", g
	for link, target := range links {
		if g != link && !strings.HasPrefix(g, link+"/") {
			continue
		}
		if len(link) <= len(via) {
			continue
		}
		via = link
		if g == link {
			resolved = target
			continue
		}
		resolved = filepath.Join(target, strings.TrimPrefix(g, link+"/"))
	}
	return resolved
}
