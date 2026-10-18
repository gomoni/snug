package policy

import (
	"fmt"
	"path/filepath"
	"sort"
)

// refuseIdentityKeyEngineState refuses an identity key path (key is the TOML
// key, path its expanded host spelling) that is at or inside snug's runtime
// directories, a per-run engine directory under the temp directory, or an
// engine data root.
//
// snug READS these paths and stages the bytes into $HOME as data, so a profile
// naming a file inside engine state turns that state into a readable file
// without a grant ever mentioning it: a hostile profile author points
// identity.ssh.key at a file in a peer run's directory or in the engine store
// and the sandbox reads it from $HOME. The ro/rw grant scans cover prof.RO and
// prof.RW only; this applies the READ half of the same refusals — the same
// canonicalisation, both spellings of both sides — to the key paths. An
// EngineDataRoot marked ReadAllowed is not skipped here: that mark excuses a
// read-only toolchain mount, and a key file there is not a program file.
//
// The paths are known at resolve, so this stays pure, with the same Context
// fields and Environ the grant scans use. Empty dirs, prefixes and roots
// disable it, as they do there. A path that reaches one of them only through a
// second mount of the same filesystem (mt, see aliasOverlap) is refused with
// the same text plus aliasNote; a nil or unusable mt disables that arm only.
func refuseIdentityKeyEngineState(name ProfileName, key, path string, ctx Context, env Environ, mt *mountTable) error {
	grants := []string{path, canonExisting(env, path)}

	dirs := append([]string(nil), ctx.RuntimeDirs...)
	sort.Strings(dirs)
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		for _, g := range grants {
			for _, d := range []string{dir, canonExisting(env, dir)} {
				if covers(g, d) || covers(d, g) {
					return identityKeyRefusal(name, key, path, "snug's runtime directory "+VisibleText(dir),
						"Every concurrent snug run keeps its host-side endpoints there")
				}
			}
		}
		if h, ok := mt.aliasOverlap(env, path, dir); ok {
			return fmt.Errorf("%w%s", identityKeyRefusal(name, key, path, "snug's runtime directory "+VisibleText(dir),
				"Every concurrent snug run keeps its host-side endpoints there"), aliasNote(h))
		}
	}

	prefixes := append([]string(nil), ctx.EngineTmpPrefixes...)
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		if entry, ok := underNamePrefix(env, grants, prefix); ok {
			return identityKeyRefusal(name, key, path, "a per-run engine directory "+VisibleText(entry),
				"It holds another run's podman socket and generated engine configuration")
		}
		if entry, h, ok := mt.aliasUnderNamePrefix(env, path, prefix); ok {
			return fmt.Errorf("%w%s", identityKeyRefusal(name, key, path, "a per-run engine directory "+VisibleText(entry),
				"It holds another run's podman socket and generated engine configuration"), aliasNote(h))
		}
	}

	if entry, ok := anyComponentNamePrefix(grants, prefixes); ok {
		return identityKeyRefusal(name, key, path, "a directory named like a per-run engine directory "+VisibleText(entry),
			"Another snug run's per-run state may live there")
	}

	roots := append([]EngineDataRoot(nil), ctx.EngineDataRoots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].Path < roots[j].Path })
	for _, root := range roots {
		dir := filepath.Clean(root.Path)
		for _, g := range grants {
			for _, d := range []string{dir, canonExisting(env, dir)} {
				if covers(g, d) || covers(d, g) {
					return identityKeyRefusal(name, key, path, "snug's engine store "+VisibleText(dir),
						"It holds every target's container images and podman's container records")
				}
			}
		}
		if h, ok := mt.aliasOverlap(env, path, dir); ok {
			return fmt.Errorf("%w%s", identityKeyRefusal(name, key, path, "snug's engine store "+VisibleText(dir),
				"It holds every target's container images and podman's container records"), aliasNote(h))
		}
	}
	return nil
}

func identityKeyRefusal(profile ProfileName, key, path, what, holds string) error {
	role := identityPathRoles[key]
	return fmt.Errorf("profile %q: refusing identity.%s %s: it is inside %s. %s, and %s.\n"+
		"       %s",
		profile, key, VisibleText(path), what, holds, role.reads, role.fix)
}
