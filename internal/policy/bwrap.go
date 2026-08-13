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
	a := []string{}

	if p.Topology.Netns == NetnsStage {
		// Enumerate every namespace EXCEPT net, rather than --unshare-all. Under
		// the stage, N already exists — the stage (P1) created it, pinned it,
		// and a setns shim put bwrap back into it before bwrap ever runs — so
		// bwrap must NOT make its own: --unshare-all would silently discard N
		// and replace it with a second, unpinned netns pasta was never aimed
		// at (measured: this is exactly what left pasta unable to bring up an
		// interface before this branch existed).
		//
		// A selective list is normally a denylist, and this design does not do
		// denylists — but TestBwrapUnshareSetIsExhaustive parses `bwrap --help`
		// for every --unshare-<name> and fails if this set does not cover all
		// of them except net, so a bwrap that grows a new namespace type goes
		// RED here rather than silently keeping it. See
		// SUPERVISOR-DESIGN.md §3.1.
		//
		// The -try spellings match what --unshare-all itself expands to, so
		// this path introduces no new failure mode on a host where user or
		// cgroup namespaces are unavailable — the strict spellings would be
		// better (a host with unprivileged userns disabled currently gets no
		// user namespace and no error, on EITHER path) but fixing that inside a
		// phase whose contract is "adds and removes nothing" would smuggle in a
		// user-visible change; see
		// https://github.com/gomoni/snug/issues/24.
		a = append(a,
			"--unshare-user-try", "--unshare-ipc", "--unshare-pid",
			"--unshare-uts", "--unshare-cgroup-try")
	} else {
		// Unshare everything bwrap supports, rather than listing namespaces to
		// keep. A selective list is a denylist, and this design does not do
		// denylists. Networking is therefore a private netns with only lo —
		// offline, which is the correct floor until a net profile exists.
		a = append(a, "--unshare-all")
	}

	a = append(a,
		// Same uid inside and outside. Mapping to 0 is tempting (chown works)
		// but then every file the agent creates is owned by a uid that maps
		// back to you while the agent believes it is root, and sudo-shaped
		// mistakes start to look plausible.
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),

		"--hostname", p.Hostname,

		// The payload dies with us even if we are SIGKILLed and cannot clean up.
		"--die-with-parent",

		// Empty the capability BOUNDING set, explicitly, on every topology.
		//
		// bwrap already does this on its own — but only when it decides it
		// needs to, and that decision is made from bwrap's view of its own
		// PARENT rather than from anything in this argv. MEASURED, bwrap
		// 0.11.2, same flags both times: started by an ordinary unprivileged
		// snug the payload comes out with CapBnd 0, and started by the stage
		// (P1, uid 0 in its own user namespace with a full capability set) the
		// same payload comes out with CapBnd 000001ffffffffff. Nothing in the
		// argv differed; nothing warned; --dry-run said the same thing on both
		// runs. That is invariant 5's silent downgrade, arriving through a
		// helper's inference rather than through a policy decision.
		//
		// The full bounding set is inert under NoNewPrivs=1 with every bwrap
		// mount carrying MS_NOSUID — the red team could not convert it into an
		// escalation on this host and said so — so what was lost is a layer of
		// defence in depth, not the boundary. It is restored here rather than
		// by a second cap-dropping code path in internal/stage for two
		// reasons: creating a user namespace RESETS the bounding set to full
		// (kernel: create_user_ns sets cap_bset = CAP_FULL_SET), so a drop in
		// P1 would be undone by bwrap's own --unshare-user a moment later and
		// could only ever be theatre; and the resolved policy is the single
		// author of the sandbox's confinement (invariant 6), which is where a
		// guarantee this load-bearing belongs.
		//
		// It is unconditional on purpose. "Never trust a helper's default, in
		// either direction — pass every security-relevant flag explicitly even
		// when it matches the current default" is the house rule, and this is
		// the case it was written for: relying on the default is what made the
		// downgrade invisible. MEASURED that it changes nothing on the paths
		// where bwrap was already dropping (CapBnd 0 before and after, both as
		// an unprivileged user and under the stage), and that unprivileged
		// bwrap accepts it without complaint despite --help describing it as
		// "when running as privileged user".
		"--cap-drop", "ALL",
	)

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

	// --clearenv first and unconditional: the environment is reconstructed by
	// name, never filtered. EnvPairs omits a variable that resolved to nothing,
	// and there is deliberately no --unsetenv anywhere — after --clearenv there
	// is nothing left to unset, and emitting one would put a subtraction into an
	// argv that has none.
	a = append(a, "--clearenv")
	for _, kv := range p.EnvPairs() {
		a = append(a, "--setenv", kv[0], kv[1])
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
