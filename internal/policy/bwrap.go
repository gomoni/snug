package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
)

// BwrapArgs is the complete argument vector, flags followed by `-- command`.
// Used by --dry-run and the golden tests, where seeing the whole thing is the
// point.
func (p *Policy) BwrapArgs(uid, gid int) []string {
	// A deterministic stub allocator, so --dry-run and the golden files show
	// stable fd numbers. The real numbers come from the sandbox layer.
	n := 9
	a := p.BwrapFlags(uid, gid, func(string) int { n++; return n })
	a = append(a, "--")
	return append(a, p.Command...)
}

// BwrapFlags is everything up to but NOT including the `--` separator.
//
// The split matters: bwrap stops parsing flags at `--`, so anything the caller
// still needs to add (a --seccomp fd, say) has to go here. Appending it to the
// full BwrapArgs instead puts it after the separator, where bwrap silently
// treats it as an argument to the payload — a filter that is never installed
// and never complains.
//
// The result is a PURE function of the resolved policy, never of the order the
// profiles were named. Emission order comes from SortedMounts
// (depth-ascending), so `snug -p a -p b` and `snug -p b -p a` produce
// byte-identical output. The golden tests assert exactly that.
func (p *Policy) BwrapFlags(uid, gid int, dataFD func(guest string) int) []string {
	a := []string{
		// Unshare everything bwrap supports, rather than listing namespaces to
		// keep. A selective list is a denylist, and this design does not do
		// denylists. Networking is therefore a private netns with only lo —
		// offline, which is the correct floor until a net profile exists.
		"--unshare-all",

		// Same uid inside and outside. Mapping to 0 is tempting (chown works)
		// but then every file the agent creates is owned by a uid that maps
		// back to you while the agent believes it is root, and sudo-shaped
		// mistakes start to look plausible.
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),

		"--hostname", p.Hostname,

		// The payload dies with us even if we are SIGKILLed and cannot clean up.
		"--die-with-parent",
	}

	// In host-network mode the sandbox INHERITS the host netns rather than
	// getting its own. --share-net is the single documented exception to
	// --unshare-all, and it means every host loopback service and every abstract
	// AF_UNIX socket (X11, D-Bus) is reachable. The CLI demands --i-know.
	if p.Net.Mode == NetHost {
		a = append(a, "--share-net")
	}

	// Own TTY session, which blocks TIOCSTI input injection into the terminal
	// that launched snug — but also breaks job control for an interactive
	// shell. Only worth paying for where the kernel still allows TIOCSTI at all.
	if p.NewSession {
		a = append(a, "--new-session")
	}

	// Predictable ancestor directories, created 0755. bwrap auto-creates
	// mountpoint parents as 0700, which is fine when we own them but makes the
	// tree untraversable if uid/gid ever change.
	for _, d := range p.skeletonDirs() {
		a = append(a, "--perms", "0755", "--dir", d)
	}

	for _, m := range p.SortedMounts() {
		switch m.Kind {
		case KindBind:
			flag := "--ro-bind"
			if m.Access == AccessRW {
				flag = "--bind"
			}
			if m.Optional {
				flag += "-try"
			}
			a = append(a, flag, m.Host, m.Guest)
		case KindTmpfs:
			a = append(a, "--tmpfs", m.Guest)
		case KindSymlink:
			a = append(a, "--symlink", m.Host, m.Guest)
		case KindProc:
			a = append(a, "--proc", m.Guest)
		case KindDev:
			a = append(a, "--dev", m.Guest)
		case KindData:
			// Mounting over a path inside a read-only bind is fine: bwrap does
			// it in its own mount namespace before the payload ever runs.
			//
			// --file copies the content into the sandbox and leaves it
			// WRITABLE; --ro-bind-data binds it read-only. Staged credentials
			// need the former (Claude rewrites its own token file), generated
			// config the latter.
			if m.Perms != nil {
				a = append(a, "--perms", fmt.Sprintf("%04o", *m.Perms))
			}
			if m.Access == AccessRW {
				a = append(a, "--file", strconv.Itoa(dataFD(m.Guest)), m.Guest)
			} else {
				a = append(a, "--ro-bind-data", strconv.Itoa(dataFD(m.Guest)), m.Guest)
			}
		}
	}

	// LAST filesystem operation. The root tmpfs and its auto-created skeleton
	// directories are writable by default; this makes them read-only. It is
	// explicitly non-recursive, so /tmp, $HOME and the project bind keep their
	// own flags. Without it the agent can litter a shadow filesystem that looks
	// real and then confuses itself.
	a = append(a, "--remount-ro", "/")

	a = append(a, "--clearenv")
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "--setenv", k, p.Env[k])
	}

	return append(a, "--chdir", p.Chdir)
}

// coveredByGrant reports whether some proper ancestor of guest is itself a
// grant, i.e. whether a mount will land on top of this path.
func (p *Policy) coveredByGrant(guest string) bool {
	for d := filepath.Dir(guest); d != "/" && d != "."; d = filepath.Dir(d) {
		if _, ok := p.Mounts[d]; ok {
			return true
		}
	}
	return false
}

// skeletonDirs are the ancestor directories of every grant, so we can set their
// permissions rather than inheriting bwrap's 0700 default.
func (p *Policy) skeletonDirs() []string {
	seen := map[string]bool{}
	for g := range p.Mounts {
		for d := filepath.Dir(g); d != "/" && d != "."; d = filepath.Dir(d) {
			seen[d] = true
		}
	}
	// Drop any that is itself a grant, and any that sits under one: a --dir
	// created before its parent tmpfs or bind is mounted is immediately
	// shadowed by it, so emitting it is noise. bwrap auto-creates mountpoint
	// parents inside the covering mount anyway.
	out := []string{}
	for d := range seen {
		if _, isGrant := p.Mounts[d]; isGrant {
			continue
		}
		if p.coveredByGrant(d) {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if di, dj := depth(out[i]), depth(out[j]); di != dj {
			return di < dj
		}
		return out[i] < out[j]
	})
	return out
}
