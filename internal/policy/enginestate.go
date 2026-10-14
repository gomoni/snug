package policy

import (
	"fmt"
	"path/filepath"
	"sort"
)

// refuseEngineDataRootGrant refuses a selection whose grants reach any of
// roots (Context.EngineDataRoots): read-only and writable alike, except that a
// read-only grant passes an entry marked ReadAllowed.
//
// A hostile process that can write the engine store can plant a tagged image
// (a node:latest) that a later container run on ANOTHER target uses, or write
// podman's libpod database and container records so a later `start` runs a
// container the proxy never judged at create time — the one-policy-one-author
// guarantee, bypassed from below. Read access leaks every other target's
// layers. A writable toolchain root lets it replace the engine binaries a
// later container run executes on the host; reading program files is not the
// hole, so that entry is ReadAllowed.
//
// Both directions of coverage are refused, canonicalised on both sides, in the
// shape refuseRuntimeDirGrant uses. Tmpfs grants and guest paths are not
// scanned. snug's own engine grafts are not profile grants and never reach
// this check.
//
// Empty roots disables the check.
func refuseEngineDataRootGrant(set map[ProfileName]*Profile, names []ProfileName, vars map[string]string, roots []EngineDataRoot, env Environ) error {
	if len(roots) == 0 {
		return nil
	}
	sortedNames := append([]ProfileName(nil), names...)
	sort.Slice(sortedNames, func(i, j int) bool { return sortedNames[i] < sortedNames[j] })
	sortedRoots := append([]EngineDataRoot(nil), roots...)
	sort.Slice(sortedRoots, func(i, j int) bool { return sortedRoots[i].Path < sortedRoots[j].Path })

	for _, name := range sortedNames {
		prof := set[name]
		for _, acc := range []struct {
			specs []string
			ro    bool
		}{{prof.RO, true}, {prof.RW, false}} {
			for _, raw := range acc.specs {
				host, _, err := splitSpec(raw, vars)
				if err != nil {
					continue // the fold reports this properly a moment later
				}
				grants := []string{host, canonExisting(env, host)}
				for _, root := range sortedRoots {
					if acc.ro && root.ReadAllowed {
						continue
					}
					dir := filepath.Clean(root.Path)
					for _, g := range grants {
						for _, d := range []string{dir, canonExisting(env, dir)} {
							if covers(g, d) || covers(d, g) {
								return engineDataRootRefusal(name, host, root, acc.ro)
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func engineDataRootRefusal(profile ProfileName, grant string, root EngineDataRoot, ro bool) error {
	access := "WRITE"
	if ro {
		access = "READ"
	}
	if root.ReadAllowed {
		return fmt.Errorf("refusing to grant WRITE access to %s: profile %q grants it, and it overlaps the\n"+
			"       container engine toolchain root %s ($SNUG_PODMAN_ROOT). A process inside could\n"+
			"       replace the engine binaries a later container run executes on the host.\n"+
			"       Grant it read-only, or grant a directory that does not contain it.",
			VisibleText(grant), profile, VisibleText(filepath.Clean(root.Path)))
	}
	return fmt.Errorf("refusing to grant %s access to %s: profile %q grants it, and it overlaps snug's\n"+
		"       engine store %s, which holds every target's container images and podman's\n"+
		"       container records. Write access lets a sandbox plant an image a later container run\n"+
		"       on another directory uses, or edit records so a later `start` skips the container\n"+
		"       proxy's checks; read access exposes other projects' layers. A container profile\n"+
		"       already gives a run its own store. Grant a directory that does not contain it.",
		access, VisibleText(grant), profile, VisibleText(filepath.Clean(root.Path)))
}
