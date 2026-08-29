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
// UnshareFlags is the ONE enumeration of bwrap's namespace flags in this
// module. Everything that needs to know which namespaces snug creates —
// BwrapFlags below, internal/stage's golden, internal/cli/doctor's probe —
// reads it from here rather than re-typing it.
//
// It is a function, not an exported var: internal/policy holds no globals, and
// an exported []string is writable shared state a caller can append into.
//
// Issue #159 is why it exists at all. doctor's probe carried its own
// hand-typed copy, checked against nothing, forty lines below a comment in the
// same file saying a probe must call the real code path rather than re-type it
// — so an edit here would have reached the sandbox and silently not reached
// the diagnostic that claims the sandbox will work. That is issue #98
// re-opened through the screen instead of through the boundary.
//
// A selective list is normally a denylist, and this design does not do
// denylists — but TestBwrapUnshareSetIsExhaustive parses `bwrap --help` for
// every --unshare-<name> and fails if this set does not cover all of them
// except net, so a bwrap that grows a new namespace type goes RED rather than
// silently keeping the sandbox in it. That guard now covers every consumer
// instead of one branch. See SUPERVISOR-DESIGN.md §3.1.
//
// net is not "excluded from a list" under the stage. Its presence is decided by
// NetnsOwner — who CREATED the namespace — which is a first-class field of the
// resolved policy rather than a carve-out written here. Under the stage, N
// already exists: the stage (P1) created it, pinned it, and a setns shim put
// bwrap back into it before bwrap ever runs, so bwrap must NOT make its own.
// --unshare-all would silently discard N and replace it with a second,
// unpinned netns pasta was never aimed at — measured, and exactly what left
// pasta unable to bring up an interface before this was fixed. For
// NetnsSandbox, bwrap makes it, and net MUST stay in the list:
// dropping it would silently restore host networking, the worst possible
// outcome — verified by execution and pinned by TestOfflineHasOnlyLoopback
// (test/integration/sandbox_test.go).
//
// `net` in this list is unconditional: every topology gets a namespace of its
// own and nothing relaxes it afterwards, which is what
// TestEveryNonStageTopologyUnsharesNet asserts.
//
// user is the STRICT spelling, not -try. Measured (issue #24): for every
// unprivileged, non-root caller, bwrap's own DWIM (bubblewrap.c:2997, `if
// (!is_privileged && getuid() != 0 && opt_userns_fd == -1) opt_unshare_user =
// true;`) already forces this on before the -try heuristic runs, so strict
// costs that population nothing. What -try silently swallows is narrower and
// worse: a REAL uid-0 caller whose own namespace's max_user_namespaces reads
// "0" gets no user namespace and no error — and the stage's own topology (P1
// runs bwrap as uid 0 in its own user namespace) puts every @net run's bwrap
// in exactly that bucket, regardless of the human's uid. Strict makes that
// failure fatal, per invariant 5, with bwrap's own message naming the sysctl
// (kernel.unprivileged_userns_clone / max_user_namespaces).
//
// cgroup stays -try, deliberately, and the asymmetry is not an oversight:
// cgroup's -try is only a stat("/proc/self/ns/cgroup") kernel-support check,
// not a resource check, and any resource failure already takes the WHOLE
// clone() down loudly regardless of -try. Going strict here would trade a risk
// that measurement found to be non-existent for a real one — refusing a host
// built without CONFIG_CGROUPS. See the issue #24 comment for the measurement.
//
// Order is load-bearing only in that the golden argv files pin it: net last.
// A reordering is a golden diff, which is the review artifact.
func (t Topology) UnshareFlags() []string {
	f := []string{
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup-try",
	}
	if t.Netns != NetnsStage {
		f = append(f, "--unshare-net")
	}
	return f
}

func (p *Policy) BwrapFlags(uid, gid int, dataFD func(guest string) int) []string {
	a := []string{}

	// append, not `a := p.Topology.UnshareFlags()`, so the freshness of the
	// returned slice is not load-bearing at this call site.
	a = append(a, p.Topology.UnshareFlags()...)

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

	// p.engineMountpoints() — /sys, /sys/fs, /sys/fs/cgroup, plus the target
	// graft's own destination when there is one (issue #376) — ONLY when this
	// run selects a container engine. These are not grants: no profile
	// exposes /sys, and nothing here makes it visible to the PAYLOAD either
	// (the payload's own view is unaffected — these directories sit empty and
	// unremarked on the sandbox's root tmpfs, same as any other skeleton dir,
	// until --remount-ro / makes them permanently so). They exist so the
	// STAGE has somewhere to move_mount(2) the engine's own cgroup2 mount in
	// the DERIVED view (issue #125's design pass §1) — the sandbox's root is
	// read-only by the time the engine forks, so a destination not created
	// here never exists at all. existsInSandbox's fourth disjunct
	// (graft.go) is what makes G3 accept a graft at one of these paths, and
	// it is gated on the SAME p.Podman condition this is, on purpose: a
	// container-less run must not carry these directories in its argv (they
	// would be unexplained, ungranted paths on --dry-run's FILESYSTEM
	// picture) and a container run must not have G3 accept a destination
	// this loop did not actually create.
	if p.Podman != PodmanOff {
		for _, d := range p.engineMountpoints() {
			a = append(a, "--perms", "0755", "--dir", d)
		}
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
			// --size sets the size of the NEXT argument and bwrap refuses it in
			// front of anything but --tmpfs ("bwrap: --size must be followed by
			// --tmpfs", measured, exit 1). Emitted in the SAME append as the pair
			// it modifies for that reason: a separate pass appending sizes would be
			// one insertion away from a hard failure. bwrap fails closed here, which
			// is why this is a correctness note and not a security note — unlike
			// --seccomp after `--`, a misplaced --size cannot silently do nothing.
			a = append(a, "--size", strconv.FormatUint(p.TmpfsSizeBytes, 10), "--tmpfs", m.Guest)
		case KindSymlink:
			a = append(a, "--symlink", m.Host, m.Guest)
		case KindProc:
			a = append(a, "--proc", m.Guest)
		case KindDev:
			// MEASURED (bwrap 0.11.2): /dev/shm is NOT a mount under --dev /dev —
			// `findmnt -T /dev/shm -no TARGET,FSTYPE,SIZE` reports `/dev tmpfs
			// 27.3G`, i.e. shm is a plain directory on bwrap's own /dev tmpfs.
			// `dd if=/dev/zero of=/dev/shm/x bs=1M count=32` wrote 32 MiB and
			// /dev's AVAIL dropped by the same amount; the same superblock is
			// reachable at any other path under /dev too (e.g. /dev/big), so a
			// bound placed only at /dev/shm is a two-character path change away
			// from being defeated and is NOT done here (issue #281).
			//
			// bwrap's --dev takes no --size of its own (measured: `bwrap: --size
			// must be followed by --tmpfs`, exit 1, when --size precedes --dev).
			// The candidate fix — `--dev /dev … --remount-ro /dev --size <N>
			// --tmpfs /dev/shm` — was measured clean (/dev root EROFS, /dev/null
			// and /dev/urandom intact, pty allocation intact, /dev/shm bounded)
			// but REMOVES /dev from snug's documented writable surface: it is a
			// base-grant change with its own golden diff and abuse sentence, and
			// changes CLAUDE.md's "eight paths" count — a maintainer decision, not
			// this lane's.
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
		default:
			// Unreachable given Validate's rule that a KindGraft OR KindCgroup2
			// in p.Mounts is refused (internal/policy/validate.go) — neither
			// belongs in the PAYLOAD's mount set; both live only in p.Grafts,
			// installed by Policy.Graft — and every other Kind above is named
			// explicitly. So the only way here is a NEW Kind added to the enum
			// without a case in this switch. That is precisely the "--seccomp
			// after bwrap's --" shape CLAUDE.md warns about: the flag (here, the
			// mount) is silently OMITTED from the argv, with no error and no
			// --dry-run line to notice it by. Panicking is what turns a missing
			// capability into a build-time-adjacent failure instead of a
			// silently weaker sandbox. (KindProc is not in this list: it
			// legitimately appears in p.Mounts already, for the sandbox's own
			// /proc, and has its own case above — reusing it for the engine's
			// procfs graft does not change that.)
			panic(fmt.Sprintf("unhandled Kind — a Kind added without a case here is silently "+
				"omitted from the argv (Kind=%s, guest=%s)", m.Kind, m.Guest))
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
