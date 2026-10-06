package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// canonExisting canonicalises p through the longest ancestor that exists, then
// re-appends the part that does not. A path absent today is still a path a
// later run can create, and comparing it by text alone would let a symlinked
// parent hide it: `/tmp/link/snug-1000` where /tmp/link points at the real
// directory is the same directory the day it is created.
func canonExisting(env Environ, p string) string {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if r, err := env.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// refuseRuntimeDirGrant refuses a selection whose read-only or writable grants
// reach any of ctx.RuntimeDirs.
//
// A hostile process that can see snug's runtime directory reaches every
// concurrent run's host-side endpoints in it: the ssh-agent proxy socket (it
// can list and sign with another run's pinned key), the login-bridge FIFO, the
// container socket and `snug proxy` doors. Read-only does not help, because a
// read-only bind stops neither connect(2) on a socket nor opening a FIFO for
// writing, so both access levels are scanned.
//
// Both directions of coverage are refused: a grant containing the directory
// exposes it, and a grant inside it exposes a peer's endpoints that share it.
// Tmpfs grants and guest paths are not scanned — a tmpfs holds nothing of the
// host's, and only the host side of a bind is what is reached.
//
// Empty dirs disables the check.
func refuseRuntimeDirGrant(set map[ProfileName]*Profile, names []ProfileName, vars map[string]string, dirs []string, env Environ) error {
	if len(dirs) == 0 {
		return nil
	}
	sortedNames := append([]ProfileName(nil), names...)
	sort.Slice(sortedNames, func(i, j int) bool { return sortedNames[i] < sortedNames[j] })
	sortedDirs := append([]string(nil), dirs...)
	sort.Strings(sortedDirs)

	for _, name := range sortedNames {
		prof := set[name]
		for _, specs := range [][]string{prof.RO, prof.RW} {
			for _, raw := range specs {
				host, _, err := splitSpec(raw, vars)
				if err != nil {
					continue // the fold reports this properly a moment later
				}
				grants := []string{host, canonExisting(env, host)}
				for _, dir := range sortedDirs {
					dir = filepath.Clean(dir)
					forms := []string{dir, canonExisting(env, dir)}
					for _, g := range grants {
						for _, d := range forms {
							if !covers(g, d) && !covers(d, g) {
								continue
							}
							return runtimeDirRefusal(name, host, dir)
						}
					}
				}
			}
		}
	}
	return nil
}

func runtimeDirRefusal(profile ProfileName, grant, dir string) error {
	msg := fmt.Sprintf("refusing to grant %s: profile %q grants it, and it overlaps snug's runtime directory %s.\n"+
		"       Every concurrent snug run keeps its host-side endpoints there — the ssh-agent\n"+
		"       proxy socket, the login-bridge FIFO, the container socket, `snug proxy` doors —\n"+
		"       and a sandbox that can see it can use any of them. A read-only grant does not\n"+
		"       help: a read-only mount stops neither connect() nor opening a FIFO.\n"+
		"       Grant a directory that does not contain it.",
		VisibleText(grant), profile, VisibleText(dir))
	if strings.HasPrefix(filepath.Base(dir), "snug-") {
		msg += "\n       It is under the temp directory because that is where snug falls back when\n" +
			"       $XDG_RUNTIME_DIR is unset; pick a target inside /tmp, not /tmp itself."
	}
	return fmt.Errorf("%s", msg)
}
