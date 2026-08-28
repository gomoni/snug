package policy

// enginebindgrant.go is the `engine_binds` GRANT: what a profile declares, what
// it resolves to, and the lookup the container proxy uses to honour it. Its
// neighbour enginebind.go is the anchored-source RULE (CheckEngineBindSource),
// which judges a path string the payload chose; these two are the two halves of
// issue #376 and are deliberately not one file — one is a grant, the other is a
// refusal, and only the grant has a TOML key.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// EngineBind is one resolved `engine_binds` entry.
//
// It is a DECLARATION from the trusted profile set (invariant 3), never
// anything the payload names, and that is what the whole grant rests on: the
// host path is fixed before the sandbox exists, so the guest path can be a
// readable name derived from it rather than a digest of a string somebody
// inside chose.
type EngineBind struct {
	// Host is the declared host directory, `{variable}`-expanded and
	// canonicalised by Resolve with the same env.EvalSymlinks pass an `ro`/`rw`
	// grant's host side gets — so the string here is the one the proxy compares
	// a client's own resolved source against, and the one __inengine's
	// openat2(RESOLVE_NO_SYMLINKS) re-walks.
	Host string

	// Guest is EngineBindGuest(Host): where the engine finds the clone, and the
	// source string the proxy forwards in place of Host.
	Guest string

	// Access is what the SANDBOX itself has at Host, decided by
	// Policy.HostPathVisible and never by the profile. A declared bind adds no
	// access: `ro = ["{home}/data"]` plus `engine_binds = ["{home}/data"]`
	// grafts read-only, and a container may then mount it read-only.
	Access Access

	// From is the profiles that declared this host path, sorted. It is
	// provenance for the graft's Why and for a refusal message; it is NOT the
	// graft's From, which G5 requires be exactly "(snug)" — no profile may
	// author a graft, and a profile name there would forge the @ sigil on the
	// ENGINE VIEW block (issue #55, finding F8).
	From []string
}

// EngineBindGuest returns the guest path a declared engine bind is grafted at:
// the entry's base name under EngineBindsDir.
//
// The name is READABLE rather than a digest, and that is a consequence of where
// the declaration comes from rather than a convenience. A digest is what you
// need when the string being named was chosen by the party you are defending
// against; an `engine_binds` entry is written by whoever writes the profile, so
// the only thing a name has to survive is collision — which Resolve refuses,
// naming both entries, rather than resolving by hashing.
//
// It is purely lexical and is the ONLY producer of a declared bind's guest
// path: EngineBind.Guest, the pre-created directory BwrapFlags emits, and G3's
// fourth disjunct are all this one function's output, so they cannot disagree
// about which directory the graft lands in.
//
// host must be absolute and already Clean; Resolve refuses "/" before calling,
// so the returned name is always a single path component.
func EngineBindGuest(host string) string {
	return EngineBindsDir + "/" + filepath.Base(host)
}

// EngineBindForwarded returns the guest path to forward in place of a client's
// bind source, when that source is EXACTLY a host path this run's profiles
// declared with `engine_binds` and the declaration covers the access asked for.
//
// The second return is false when nothing was declared at that path, which
// leaves the caller's ordinary refusals to speak — this function grants, it
// never refuses.
//
// EXACT MATCH, NEVER A PREFIX, and this is the clause the grant's safety rests
// on. What snug forwards is the GRAFT ROOT. Forwarding the graft root plus a
// tail the client supplied would reopen issue #284 through the graft: crun
// re-resolves the whole string at container START, in the engine's namespace,
// so a relative symlink planted inside the grafted directory is followed there
// — the graft pins the inode at its own root and says nothing about any name
// beneath it. A client asking for a subdirectory of a declared bind therefore
// falls through to CheckEngineBindSource and is refused; declaring that
// subdirectory is the answer, and it is one line of profile.
//
// needWrite is asked against the declaration's own Access rather than assumed
// satisfiable. The arm is unreachable through checkOne today — a declared
// bind's Access IS Policy.HostPathVisible's answer for its Host, and checkOne
// asks that same predicate about the same host path before it gets here — but
// "unreachable through today's one caller" is not a property of this function,
// and a second caller inheriting a silent widening is the shape invariant 5 is
// about.
func (p *Policy) EngineBindForwarded(source string, needWrite bool) (string, bool) {
	source = filepath.Clean(source)
	for _, b := range p.EngineBinds {
		if b.Host != source {
			continue
		}
		if needWrite && b.Access != AccessRW {
			return "", false
		}
		return b.Guest, true
	}
	return "", false
}

// resolveEngineBinds turns the declarations gathered during the fold into
// p.EngineBinds. decls maps an already-expanded, already-canonicalised host
// path to the profiles that declared it.
//
// Run AFTER the fold, and it has to be: every question here is asked of the
// WHOLE resolved mount set and of the joined p.Podman, neither of which exists
// part-way through. Asking during the fold would make the verdict depend on
// which profile came first, which is the one thing Resolve may never do.
func resolveEngineBinds(p *Policy, decls map[string][]string) ([]EngineBind, error) {
	hosts := make([]string, 0, len(decls))
	for h := range decls {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	if p.Podman == PodmanOff {
		return nil, fmt.Errorf("profile %s declares engine_binds = [%q] but no profile in this "+
			"selection starts a container engine, so there is nothing to bind into and the "+
			"declaration would silently do nothing.\n"+
			"       Select a profile with `podman = \"socket\"` (@podman-socket, @podman-build), or "+
			"remove the key",
			strings.Join(decls[hosts[0]], "+"), hosts[0])
	}

	out := make([]EngineBind, 0, len(hosts))
	byGuest := map[string]string{}
	for _, host := range hosts {
		// The access the SANDBOX has at this path, asked of the one author of
		// that question (invariant 6). A declared bind is a hand-over of a
		// path the sandbox already holds, at the access it already holds it
		// at: the graft would be refused by G4 for anything wider, and
		// deciding it here rather than at graft time is what lets the refusal
		// below name the profile that wrote the line.
		access := AccessRO
		switch {
		case p.HostPathVisible(host, true):
			access = AccessRW
		case p.HostPathVisible(host, false):
		default:
			return nil, fmt.Errorf("profile %s declares engine_binds = [%q], but this sandbox's own "+
				"grants do not expose that host path at all — so the engine's view, which is DERIVED "+
				"from the sandbox's, cannot hold it either (G4).\n"+
				"       Grant it to the sandbox as well: ro = [%q] or rw = [%q] in the same profile.\n"+
				"       A tmpfs is not enough — there is no host directory behind one, so there is "+
				"nothing to clone",
				strings.Join(decls[host], "+"), host, host, host)
		}

		guest := EngineBindGuest(host)
		if other, taken := byGuest[guest]; taken {
			return nil, fmt.Errorf("engine_binds declares both %q and %q, which share the base name "+
				"%q — the engine sees a declared bind at %s, one directory per base name, so these "+
				"two ask for one destination.\n"+
				"       Declared by %s and %s. Rename or move one of them; snug will not pick a "+
				"winner between two grants nobody compared",
				other, host, filepath.Base(host), guest,
				strings.Join(decls[other], "+"), strings.Join(decls[host], "+"))
		}
		byGuest[guest] = host

		out = append(out, EngineBind{
			Host:   host,
			Guest:  guest,
			Access: access,
			From:   decls[host],
		})
	}
	return out, nil
}

// checkEngineBinds is Validate's backstop over p.EngineBinds, and it is the
// same kind of check checkGraft is: Resolve is the only producer of these rows,
// but a hand-built Policy can hold any row at all, and EngineBindForwarded
// answers from this slice rather than from p.Grafts.
//
// The one thing that has to hold is that a row's Guest is EngineBindGuest of
// its own Host. Without it, a row could name any guest path — including one of
// snug's own five under EngineDir, or /snug/bin — and the proxy would forward
// THAT to the engine for a client that named the row's Host. The declaration's
// safety comes from the destination being on snug's read-only root inside a
// directory only snug writes; a row whose Guest was chosen elsewhere has none
// of it.
//
// It does NOT re-ask G4 (is the sandbox's own view exposing Host at Access).
// checkGraft does that, over the graft this row produces, and Validate runs it
// a few lines above — asking again here would be a second author of the
// question, which is the shape invariant 6 exists against.
func (p *Policy) checkEngineBinds() error {
	for _, b := range p.EngineBinds {
		if want := EngineBindGuest(b.Host); b.Guest != want {
			return fmt.Errorf("declared engine bind %s has guest path %s, but the only destination "+
				"snug derives for that host path is %s.\n"+
				"       EngineBindGuest is the single producer of a declared bind's destination, and\n"+
				"       the grant's safety is entirely that the destination sits in a directory only\n"+
				"       snug writes on the read-only root — a guest path chosen anywhere else could\n"+
				"       name one of snug's own engine paths, and the container proxy forwards this\n"+
				"       field verbatim. Build the policy through Resolve.",
				b.Host, b.Guest, want)
		}
		if b.Access != AccessRO && b.Access != AccessRW {
			return fmt.Errorf("declared engine bind %s has access %q; a declared bind is grafted "+
				"either read-only or read-write, and \"none\" describes nothing the stage can "+
				"build (checkGraft refuses it too, one layer down)", b.Host, b.Access)
		}
	}
	return nil
}
