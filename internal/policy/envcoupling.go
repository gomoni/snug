package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The grant-coupling rule (§2.5).
//
// IT IS A COUPLING RULE, NOT AN EXISTENCE CHECK, and the distinction is the
// whole of it. The profile that NAMES a path in the environment must be the
// profile that put a node on the chain to it, so a reviewer reading one profile
// sees both acts on one screen. It cannot prove the path exists: internal/policy
// may not touch the filesystem, a `tmpfs` grant creates an EMPTY directory, and
// a bind's contents are host state that changes under us.
//
// So do not cite this check as a boundary. IT IS NOT ONE. The value is inert —
// nothing in the environment grants access to anything — and the payload can set
// any variable it likes the moment it is running. It stops a profile LYING; it
// does not stop anything REACHING. A false positive here yields a variable
// naming an empty directory, which is a usability bug rather than a hole.
//
// Scope: values a profile WRITES (set/merge/prepend) at names the type table
// marks path-valued. `inherit` and `sanitise` are exempt because the value is
// the host's, not the profile's — sanitise has its own filter for exactly that
// (envresolve.go). EDITOR=vim is out of scope because EDITOR is not a path.
//
// The verdict is computed over profile TEXT, never over resolved mounts, and
// that is deliberate. @claude marks every one of its `ro` entries optional, so
// an absent grant produces no mount at all — checking mounts would make a
// profile's LEGALITY depend on the host reading it, which is precisely the
// defect §4.4 records for the old forbidden-name check, adopted there by
// accident and refused here on purpose.

// checkEnvCoupling refuses a profile whose environment names a path it does not
// grant.
//
// THE INCLUDE CLOSURE COUNTS; THE SELECTED SET DOES NOT. `include` is the
// profile's own text: static, host-independent, and rendered by `snug profile
// tree`. If the selected set counted, Resolve([a]) could refuse what
// Resolve([a,b]) admits — one profile would change another profile's verdict,
// which is not a visibility break but is one edit away from being one. See
// TestCouplingVerdictDoesNotDependOnTheSelectedSet, which exists because that
// edit is easy to make and impossible to notice.
func checkEnvCoupling(reg map[ProfileName]*Profile, name ProfileName, g EnvGrants, vars map[string]string) error {
	if !writesAnyPath(g) {
		return nil
	}
	guests, links, err := profileGuestGrants(reg, name, vars)
	if err != nil {
		return err
	}

	for _, k := range sortedMapKeys(g.Set) {
		if err := checkCoupled(name, VerbSet, k, g.Set[k], vars, guests, links); err != nil {
			return err
		}
	}
	for _, verb := range []EnvVerb{VerbMerge, VerbPrepend} {
		m := g.Merge
		if verb == VerbPrepend {
			m = g.Prepend
		}
		for _, k := range sortedListKeys(m) {
			for _, raw := range m[k] {
				if err := checkCoupled(name, verb, k, raw, vars, guests, links); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// writesAnyPath is the cheap gate, so a profile with no path-valued write never
// pays for the closure walk.
func writesAnyPath(g EnvGrants) bool {
	for _, m := range []map[string][]string{g.Merge, g.Prepend} {
		for k := range m {
			if isPathValued(k) {
				return true
			}
		}
	}
	for k := range g.Set {
		if isPathValued(k) {
			return true
		}
	}
	return false
}

// isPathValued is the coupling rule's scope, and an UNROSTERED name is outside
// it.
//
// That is not an oversight and it is the honest answer rather than the
// convenient one: `path` is a fact snug holds about a name, and for a name with
// no roster row snug holds no facts at all. The alternative is to decide a value
// is a path because it starts with a '/', which is precisely the shape-sniffing
// this file's header refuses ("the shape is the same for a search path, a URL, a
// template language bash performs command substitution on, and a set of
// delimiter characters"). So an unrostered value naming a path the profile does
// not grant is NOT refused, where the same value under a rostered path-valued
// name would be. What that costs is one profile-lying case going unreported —
// and --dry-run still marks that row `← unchecked`, and grantMark still says
// `← not granted` where the value is spelled like an absolute path nothing
// covers. What it would cost to close by guessing is a rule that refuses a
// correct value for every name whose value merely looks like a path —
// LESSOPEN's does, and it is a command line.
func isPathValued(name string) bool {
	t, known := typeOf(name)
	return known && t.path
}

// checkCoupled is the verdict on one written value.
func checkCoupled(profile ProfileName, verb EnvVerb, name, raw string, vars map[string]string, guests []string, links map[string]string) error {
	if !isPathValued(name) {
		return nil
	}
	value, err := expandVars(raw, vars)
	if err != nil {
		return fmt.Errorf("profile %q: %w", profile, err)
	}
	// A relative value can never be covered — there is nothing to compare it
	// against — but it has its own defect and its own message, so hand it to the
	// one function that owns that refusal rather than writing a second wording of
	// it here. This is also the only path by which a relative `set` is refused:
	// checkAbsoluteElement is called from the list verbs alone.
	if !filepath.IsAbs(value) {
		return checkAbsoluteElement(profile, name, verb, raw, value)
	}
	// Symlinks are RESOLVED FIRST and are never a grant themselves. On a
	// usr-merged host /bin is a symlink snug creates, so a profile granting /usr
	// and naming /bin/foo named the path the sandbox will actually see.
	resolved := resolveLinkForEnv(links, filepath.Clean(value))
	if coversGuest(guests, resolved) {
		return nil
	}
	via := ""
	if resolved != filepath.Clean(value) {
		via = fmt.Sprintf(" (which resolves to %s through a symlink the profile creates)", resolved)
	}
	return fmt.Errorf("profile %q %ss %s=%s%s, which it does not grant.\n"+
		"       Add the path to that profile's ro/rw/tmpfs — or to a profile it includes — or\n"+
		"       drop the variable: a variable naming a path that is not inside the sandbox is\n"+
		"       worse than an absent one, because every tool that reads it will believe it.\n"+
		"       snug is not checking that the path EXISTS (it cannot: a tmpfs grant creates an\n"+
		"       empty directory), only that the profile naming it is the profile that granted it.",
		profile, verb, name, value, via)
}

// coversGuest is lexical containment on `/` boundaries, DOWNWARD with no depth
// limit: a grant covers itself and everything under it.
//
// Coverage rather than an exact match, because SHELL=/usr/bin/bash against
// ro=["/usr"] must pass and there is no principled depth at which to stop. The
// accepted cost is that @home is a rubber stamp for all of $HOME, and that a
// profile including @sys+@home is checked vacuously under /usr and {home} — see
// @podman-socket. That is correct: the profile DID bring them, on an `include`
// line that --dry-run and $SNUG_PROFILES both render.
func coversGuest(guests []string, path string) bool {
	for _, g := range guests {
		if path == g || strings.HasPrefix(path, g+"/") {
			return true
		}
	}
	return false
}

// profileGuestGrants collects the GUEST side of every path grant a profile
// makes, over its own text plus its `include` closure, and the symlink map from
// the same closure.
//
// The guest side, because that is the path the environment value will name from
// inside; a `host:guest` spec's host side is irrelevant to what the payload sees.
//
// A spec that fails to expand or split is SKIPPED rather than reported here.
// That is not swallowing an error: every profile in the closure is also in the
// selected set (Resolve expands includes before folding), so the same spec is
// parsed again by the fold and refused there, with the right profile named.
// Skipping makes this set SMALLER, so the coupling check gets stricter, never
// laxer.
func profileGuestGrants(reg map[ProfileName]*Profile, name ProfileName, vars map[string]string) ([]string, map[string]string, error) {
	closure := map[ProfileName]*Profile{}
	if err := expand(reg, name, closure, nil); err != nil {
		return nil, nil, err
	}

	var guests []string
	links := map[string]string{}
	for _, n := range sortedProfileNames(closure) {
		prof := closure[n]
		for _, specs := range [][]string{prof.RO, prof.RW} {
			for _, s := range specs {
				_, guest, err := splitSpec(s, vars)
				if err != nil {
					continue
				}
				guests = append(guests, guest)
			}
		}
		for _, s := range prof.Tmpfs {
			g, err := expandVars(s, vars)
			if err != nil {
				continue
			}
			guests = append(guests, filepath.Clean(g))
		}
		for _, s := range prof.Symlink {
			at, err := expandVars(s.At, vars)
			if err != nil {
				continue
			}
			at = filepath.Clean(at)
			target := s.Target
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(at), target)
			}
			links[at] = filepath.Clean(target)
		}
	}
	return guests, links, nil
}

// sortedProfileNames is slices.Sort rather than sort.Strings for the same
// reason Resolve's fold is: ProfileName is a defined type over string, which
// cmp.Ordered admits and []string does not. The ordering is byte-wise either
// way, so nothing observable moves.
func sortedProfileNames(m map[ProfileName]*Profile) []ProfileName {
	out := make([]ProfileName, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
