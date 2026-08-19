package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Graft installs one mount into the ENGINE's derived view. It is the ONLY
// writer of p.Grafts — the same device as Policy.Replace for p.Mounts and
// deriveTopology for p.Topology (TestOnlyGraftWritesGrafts).
//
// A second graft at the same Guest is an ERROR, not a join: there is exactly
// one author, so two grafts at one destination is a bug in that author, and a
// join would silently pick a winner. Symmetric message naming both.
//
// It is NOT reached through join, and NOT the KindData late-assignment path
// either (Policy.Replace) — that distinction is load-bearing, not incidental.
// join merges two grants at one Guest IN ONE NAMESPACE; a graft and a bind at
// the same Guest are in TWO DIFFERENT mount namespaces, so joining them would
// compute an effective access no kernel ever computes. Replace is invariant 1's
// one carve-out because it displaces a profile's grant at the same path in the
// same namespace — the sandbox's view really changes and a profile's grant
// really vanishes. A graft does neither: it lands in a namespace no profile can
// name, no TOML key produces one so there is nothing to displace, and it is not
// in p.Mounts so it cannot overwrite an entry there. So grafts are OUTSIDE
// invariant 1 rather than an exception to it, and that stays true structurally
// — one writer, no TOML key — not by convention. Do not read "a graft is
// snug's own writing, like KindData" as license to fold it into Replace; that
// is the plausible-and-wrong reading that would widen the KindData carve-out
// by analogy (issue #55).
//
// Called by Tier C from internal/cli AFTER Resolve returns, for the same
// reason BindSocket is: the store and runroot paths are host artefacts snug
// creates for the run, and Resolve itself authors none. Runs the graft-specific
// rules (G1-G5) inline and returns the error, so a graft can never be installed
// unvalidated — this mirrors nothing existing on purpose: Replace is
// unvalidated today, and issue #55 is a report about an unchecked writer.
func (p *Policy) Graft(g Graft) error {
	if _, exists := p.Grafts[g.Guest]; exists {
		return fmt.Errorf("cannot graft %s: already grafted (from %s).\n"+
			"       Policy.Graft is the only writer of p.Grafts, so two attempts at the same\n"+
			"       destination is a bug in the caller, not a disagreement to resolve — a join\n"+
			"       here would silently pick a winner between two grafts nobody compared.",
			g.Guest, strings.Join(p.Grafts[g.Guest].From, "+"))
	}

	g.Authored = true
	if err := p.checkGraft(g); err != nil {
		return err
	}

	if p.Grafts == nil {
		p.Grafts = map[string]Graft{}
	}
	p.Grafts[g.Guest] = g
	return nil
}

// OwnEngineHostPath records one host path snug itself created for THIS run —
// the container store, the runroot, a socket directory — as visible to a
// graft under G4's second disjunct, without requiring the SANDBOX's own
// grants to expose it. It is the ONLY writer of p.EngineOwnedHostPaths, the
// same device Policy.Graft is for p.Grafts (TestOnlyOneWriterOfEngineOwnedHostPaths).
//
// Before this existed the map had no writer at all: a caller could set
// p.EngineOwnedHostPaths directly, with no hygiene check, and any string
// placed in it passed G4 unconditionally — the "a rule written once and
// applied to one of its two halves" shape (CLAUDE.md), on G4's own two
// disjuncts, found by the redteam (issue #55, finding F2). checkPathHygiene
// is the same check Policy.Graft runs on a graft's own Guest and Host; this
// is what brings the wider, unbounded-by-any-grant half of G4 up to the
// standard the narrower half (HostPathVisible) already met.
func (p *Policy) OwnEngineHostPath(path string) error {
	if err := checkPathHygiene("engine-owned host path", path, "(snug)", "the ENGINE VIEW block"); err != nil {
		return err
	}
	if p.EngineOwnedHostPaths == nil {
		p.EngineOwnedHostPaths = map[string]bool{}
	}
	p.EngineOwnedHostPaths[path] = true
	return nil
}

// checkGraft runs G1-G5 over one graft WITHOUT installing it, so Policy.Graft
// and Validate's re-check (issue #55) share exactly one implementation of the
// rules rather than the two that would otherwise drift.
//
// The exact-duplicate half of G2 ("two grafts at one Guest") is NOT checked
// here — it is checked by Policy.Graft before this runs, against the map
// lookup, because by the time Validate calls this over an ALREADY-INSTALLED
// graft, that graft IS the map entry at its own Guest, and comparing it to
// itself would refuse every graft that ever validated successfully. What this
// checks instead is a DIFFERENT graft covering or covered by this one, which a
// hand-built Policy can still produce and which the map's own uniqueness
// cannot catch.
func (p *Policy) checkGraft(g Graft) error {
	// G5, structural half — a bug in the caller, not a configuration choice, so
	// checked first and unconditionally.
	if g.Kind != KindGraft {
		return fmt.Errorf("cannot graft %s: Kind is %q, not graft — Policy.Graft only ever installs\n"+
			"       a KindGraft mount. A caller building a Graft with any other Kind is a bug in\n"+
			"       that caller, not a policy this can accept.", g.Guest, g.Kind)
	}
	if g.Access != AccessRO && g.Access != AccessRW {
		return fmt.Errorf("cannot graft %s: Access is %q, and a graft must be ro or rw — Access is a\n"+
			"       REQUIREMENT enforced by mount_setattr before move_mount (§5.1), and \"none\"\n"+
			"       describes nothing the stage can build. Set AccessRO or AccessRW.", g.Guest, g.Access)
	}
	if g.Optional {
		return fmt.Errorf("cannot graft %s: Optional is not permitted on a graft.\n"+
			"       -try semantics mean \"silently do less\", and under Tier C the derived view IS\n"+
			"       the enforcement boundary — a graft that silently did not happen would leave the\n"+
			"       engine with a different confinement from the one --dry-run described\n"+
			"       (invariant 5). Make the host path exist, or do not graft it.", g.Guest)
	}
	if g.Why == "" {
		return fmt.Errorf("cannot graft %s: Why is empty.\n"+
			"       Every graft carries the abuse sentence — \"a hostile process inside the sandbox\n"+
			"       can use this to ___\" — because a graft is the one grant a profile can never\n"+
			"       write, so a Graft literal is the only place left for a human to read it. Set Why\n"+
			"       before calling Policy.Graft.", g.Guest)
	}
	// G5 also requires From to be EXACTLY snug's own provenance — not merely
	// "not one of this run's resolved profiles". Comparing only against
	// p.Profiles let From: []string{"@podman-socket"} through on any
	// selection that did not happen to include @podman-socket: Validate
	// returned nil and the ENGINE VIEW block rendered the @ sigil next to a
	// row the block's own header says no profile could have authored — the
	// one guarantee the sigil exists to make (CLAUDE.md, "@ marks a profile
	// snug ships, and the mark is derived, not written"), forged by a Graft
	// literal (issue #55, finding F8). No profile — selected or not, builtin
	// or user-defined — may ever author a graft, so the only From this
	// accepts is the literal sentinel every other snug-generated mount
	// already uses for the same fact ("(snug)": /proc, /dev, /tmp, the
	// identity KindData mounts).
	if len(g.From) != 1 || g.From[0] != "(snug)" {
		return fmt.Errorf("cannot graft %s: From is %q, and a graft's From must be exactly\n"+
			"       []string{\"(snug)\"}.\n"+
			"       No profile may author a graft — there is no TOML key that produces one, and\n"+
			"       Policy.Graft is the only writer of p.Grafts — so any other From, including the\n"+
			"       name of a builtin this run never selected, means the caller copied provenance\n"+
			"       from somewhere else instead of writing the graft's own. Set From to\n"+
			"       []string{\"(snug)\"}.", g.Guest, g.From)
	}

	// Guest and Host go through the SAME two checks a mount's Guest already
	// does (validate.go), rather than a fourth hand-rolled copy.
	if err := checkPathHygiene("graft destination", g.Guest, strings.Join(g.From, "+"), "the ENGINE VIEW block"); err != nil {
		return err
	}
	if err := checkPathHygiene("graft source", g.Host, strings.Join(g.From, "+"), "the ENGINE VIEW block"); err != nil {
		return err
	}

	// G1 — a graft may not cover one of snug's own paths, in EITHER namespace.
	//
	// THE TRAP, stated so it cannot be copied wrong: validate.go's mount-level
	// check reads `if at, own, ours := snugsOwnCovered(g); ours && !m.Authored`.
	// Every graft is Authored by construction (set two lines above, in
	// Policy.Graft). Copying that clause here would make this check a
	// PERMANENT NO-OP. The `!Authored` clause exists on the mount-level check
	// because snug legitimately replaces /proc and /etc/resolv.conf in the
	// PAYLOAD's namespace; nothing legitimately covers StagedBinDir in ANY
	// namespace, so there is no analogous exemption to carry over here. It is
	// deliberately absent below. (TestGraftCoveringStagedBinDirIsRefused fails
	// if it is reintroduced.)
	//
	// No new relation is needed to find the /run-covers-StagedBinDir case —
	// covers/snugsOwnCovered is already a depth rule, asked of the SAME guest
	// path a mount-level grant would be asked of. It is not extended across
	// namespaces to do this: this is one graft's own Guest, judged on its own,
	// never compared against another namespace's containment.
	if at, own, ours := snugsOwnCovered(g.Guest); ours {
		if at == g.Guest {
			return fmt.Errorf("cannot graft %s into the engine's view: %s is snug's own: %s\n"+
				"       A graft at that path would displace it in the ENGINE's mount namespace\n"+
				"       exactly as a profile's grant would displace it in the sandbox's — this is a\n"+
				"       hole no graft may open, snug's own code included. Graft a destination that\n"+
				"       is neither %s nor an ancestor of it.",
				g.Guest, g.Guest, own.why, g.Guest)
		}
		return fmt.Errorf("cannot graft %s into the engine's view: it CONTAINS %s, and %s is snug's\n"+
			"       own: %s\n"+
			"       A graft at an ancestor takes the descendant with it in the engine's mount\n"+
			"       namespace, exactly as it would in the sandbox's — naming the parent is not a\n"+
			"       narrower graft than naming the child. Graft a destination that is neither %s\n"+
			"       nor an ancestor of it.",
			g.Guest, at, at, own.why, at)
	}

	// G2 — a graft may not cover, or be covered by, another graft. The
	// exact-Guest case is skipped here (see the doc comment above): it is
	// handled by Policy.Graft before this runs, and when Validate re-checks an
	// already-installed graft, "existing" at that exact Guest IS g itself.
	for _, existing := range p.Grafts {
		if existing.Guest == g.Guest {
			continue
		}
		if covers(g.Guest, existing.Guest) {
			return fmt.Errorf("cannot graft %s into the engine's view: it would CONTAIN the graft\n"+
				"       already at %s (from %s).\n"+
				"       A graft at an ancestor takes the descendant's destination with it in the\n"+
				"       engine's mount namespace — the same containment rule the sandbox's own\n"+
				"       grants follow. Graft a destination that neither is nor contains %s.",
				g.Guest, existing.Guest, strings.Join(existing.From, "+"), existing.Guest)
		}
		if covers(existing.Guest, g.Guest) {
			return fmt.Errorf("cannot graft %s into the engine's view: the graft already at %s\n"+
				"       (from %s) CONTAINS it.\n"+
				"       A graft at an ancestor takes the descendant's destination with it in the\n"+
				"       engine's mount namespace — the same containment rule the sandbox's own\n"+
				"       grants follow. Graft a destination that is not inside %s.",
				g.Guest, existing.Guest, strings.Join(existing.From, "+"), existing.Guest)
		}
	}

	// G3 — the destination must already exist in the SANDBOX's own view.
	// existsInSandbox names the fix and is measured against ENGINE-NETNS.md
	// §5.1's four rows; see its own doc comment for the soundness caveat on its
	// third disjunct.
	if !existsInSandbox(p, g.Guest) {
		return fmt.Errorf("snug cannot graft %s into the engine's view: nothing in this policy\n"+
			"       creates that directory inside the sandbox, and the sandbox root is read-only, so\n"+
			"       the mkdir that a graft needs fails with EROFS (measured, ENGINE-NETNS.md §5.1).\n"+
			"       Graft a destination that already exists — a path some grant mounts, an ancestor\n"+
			"       of one, or a path inside a writable grant.", g.Guest)
	}

	// G4 — the source must be something the sandbox can ALREADY see
	// (HostPathVisible), OR a host path snug itself created for this run
	// (EngineOwnedHostPaths, written only by OwnEngineHostPath). This is
	// invariant 6 expressed as a predicate: the engine's view is DERIVED from
	// the sandbox's, never a second, wider window onto the host.
	//
	// The two disjuncts are asking DIFFERENT questions and neither one alone
	// is "G4". HostPathVisible refuses /run/user/<uid> — the host's
	// ssh-agent, session D-Bus, Wayland and rootless podman socket — because
	// no grant exposes it: that is a fact about the FIRST disjunct only. It
	// is not a fact about EngineOwnedHostPaths, which is bounded by nothing
	// the sandbox's own policy granted — its only defence is that
	// OwnEngineHostPath is its one writer, called exclusively by snug's own
	// Tier C code for artefacts snug itself created (the container store,
	// the runroot, a socket directory), never by anything a profile or the
	// payload can reach. A doc comment claiming "/run/user/<uid> is refused
	// by G4, full stop" is true of HostPathVisible and silent about this
	// disjunct beside it — do not write that sentence again without naming
	// both halves (issue #55, finding F2).
	if !p.HostPathVisible(g.Host, g.Access == AccessRW) && !p.EngineOwnedHostPaths[g.Host] {
		needWrite := ""
		if g.Access == AccessRW {
			needWrite = ", writable"
		}
		return fmt.Errorf("cannot graft %s (host %s%s) into the engine's view: the sandbox's own\n"+
			"       policy does not expose this host path, and snug did not create it for this run.\n"+
			"       A graft may only reach a host path the sandbox's OWN grants already expose — the\n"+
			"       engine's view is DERIVED from the sandbox's, never a second, wider window onto\n"+
			"       the host — or a path snug itself created (the container store, the runroot, a\n"+
			"       socket directory). Grant it to the sandbox first, or graft a path snug owns.",
			g.Guest, g.Host, needWrite)
	}

	return nil
}

// existsInSandbox is G3: a graft's destination must already be a directory
// inside the SANDBOX's own mount namespace before move_mount(2) can land
// anything on it. ENGINE-NETNS.md §5.1 measured mkdir failing with EROFS on
// the read-only root tmpfs, and succeeding (EEXIST) wherever the directory
// already existed — so the discriminator is the directory, not the mount.
//
// Three ways a destination can already exist, only the THIRD of which is a
// guess:
//
//   - it is itself a mountpoint (a Guest key in p.Mounts);
//   - it is a strict ANCESTOR of one — bwrap auto-creates a mount's parent
//     directories (--dir), so the directory is there even though nothing is
//     mounted AT it;
//   - it sits inside a writable grant (KindBind rw, or KindTmpfs) — the STAGE
//     can mkdir it there before move_mount runs.
//
// THE THIRD DISJUNCT IS A SOUNDNESS APPROXIMATION, NOT A FACT, and must be
// read as one: "the stage can create this" is not the same claim as "this
// exists", and this function cannot run mkdir to find out (internal/policy
// stays pure — no filesystem, no exec). A destination this disjunct accepts
// that some unmodelled interaction has already turned into a file rather than
// a directory still fails at runtime — which is exactly why §6 makes the
// runtime open_tree/mount_setattr/mkdir/move_mount failure FATAL rather than
// treating this check as the last word. The two are not redundant: this is
// where an approximation that guessed wrong surfaces.
//
// Checked against ENGINE-NETNS.md §5.1's four measured rows: /etc/containers
// and /var/tmp match none of the three (@sys binds fourteen individual /etc
// entries, never /etc itself) -> refused, matching the measurement. /run is a
// strict ancestor of /run/snug/bin/claude under @claude -> passes this, then
// is refused by G1 — also matching. A destination inside an AccessRW bind ->
// accepted by the third disjunct, matching "onto a writable grant".
func existsInSandbox(p *Policy, guest string) bool {
	if _, ok := p.Mounts[guest]; ok {
		return true
	}
	for _, m := range p.Mounts {
		if m.Guest != guest && covers(guest, m.Guest) {
			return true
		}
	}
	if m, ok := p.SandboxView().coveringMount(guest); ok {
		if (m.Kind == KindBind || m.Kind == KindTmpfs) && m.Access == AccessRW {
			return true
		}
	}
	return false
}

// HostPathVisible reports whether the SANDBOX can itself see a host path at the
// given access — G4's first disjunct, and the same rule
// internal/dockerproxy's bind filter enforces for a container's own `-v`
// requests (invariant 6: one author of "can the sandbox see this host path",
// not two implementations that eventually disagree). Moved here from
// dockerproxy.hostPathVisible (issue #55) so a graft's source check and the
// proxy's bind filter share it rather than each carrying its own copy;
// dockerproxy.hostPathVisible is now a one-line call to this.
//
// It walks only KindBind mounts, matching a host path against a mount's Host
// by exact match or path-ancestor — never a string prefix — and, for a
// writable request, requiring AccessRW. A snug-GENERATED KindData grant (the
// identity files, /etc/resolv.conf) is invisible to this on purpose: it has no
// host path to match against, and inventing one would be a second, guessed
// answer to "what does this correspond to on the host".
func (p *Policy) HostPathVisible(host string, needWrite bool) bool {
	host = filepath.Clean(host)
	for _, m := range p.Mounts {
		if m.Kind != KindBind {
			continue
		}
		if host != m.Host && !strings.HasPrefix(host, m.Host+"/") {
			continue
		}
		if needWrite && m.Access != AccessRW {
			continue
		}
		return true
	}
	return false
}
