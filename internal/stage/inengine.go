package stage

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
)

// EnterEngine is __inengine: the setns+confine shim that turns a freshly
// cloned child of the stage (CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWPID already
// applied by Cloneflags at fork time — see startEngine) into the per-sandbox
// container engine, running in THIS sandbox's own N, its OWN pid namespace,
// and bounded to policy.EngineCapBounding, and nothing else (issue #63, Tier
// B; the pid namespace and its procfs are issue #125's "C0" piece, tracked on
// the issue itself).
//
// THE ORDER IS THE SPECIFICATION (ENGINE-WIRING.md §2.4, extended by C0):
//
//  1. lock the OS thread — setns(CLONE_NEWNET) is per-task, exactly like
//     __innetns's own setns.
//
//  2. setns(fd, CLONE_NEWNET) into the sandbox's N; re-read and refuse if the
//     thread did not move — the __innetns check, verbatim, using the
//     DESCRIPTOR P1 pinned before it left N, never a /proc/<pid>/ns/net path
//     (the wrong-attach silent failure, SUPERVISOR-DESIGN.md §3.4).
//
//  3. close fd — nothing downstream of this point (podman, conmon, a
//     container) ever holds a reference to N it could setns with.
//
//  4. build the engine's view, DERIVED from the sandbox's. Four calls, in
//     this order, and the order is the whole of it:
//
//     4a. setns(mntFD, CLONE_NEWNS) — join the SANDBOX's own mount namespace.
//     The caller waited for bwrap to finish every mount snug asked for
//     (waitForSandboxMounts); joining earlier lands in a namespace still
//     holding the host tree at /oldroot, measured.
//     4b. unshare(CLONE_NEWNS) — the engine's OWN copy of that view, so
//     everything below is invisible to the payload. Without it the engine
//     would be mounting into the sandbox's namespace.
//     4c. mount("", "/", MS_REC|MS_PRIVATE) — load-bearing TWICE
//     (ENGINE-NETNS.md §1): overlay refuses to make its own mount private
//     without it, and it keeps podman's per-container nsfs binds out of the
//     host mount tree.
//     4d. move_mount each detached tree onto its guest path, then
//     MOUNT_ATTR_RDONLY where the graft is AccessRO. The trees come from
//     p.Grafts, so the resolved Policy is their author (invariant 6).
//
//     So the engine's starting point is the sandbox's view, not the host's,
//     and a host path reaches the engine only through a graft. What the view
//     does NOT do is decide what a CONTAINER may bind: that is the proxy's
//     bind filter, reading the same resolved Policy
//     (TestContainerBindFilterMatchesPolicyVisibility is the standing gate).
//     Two mechanisms over one model — do not read either as the other.
//
//  5. mount("proc", "/proc", "proc") — a FRESH procfs bound to THIS process's
//     own pid namespace (C0), replacing whatever /proc this process inherited
//     from the stage's private host-tree copy (step 4's mount, still the
//     HOST's real /proc up to this point). This process is already pid 1 of a
//     pid namespace created at clone time (CLONE_NEWPID, owned by U because
//     that clone carried no CLONE_NEWUSER of its own) — MEASURED that mounting
//     "proc" needs exactly that ownership: it returns EPERM with no owning
//     userns of the caller's own, and succeeds here. FATAL on failure
//     (invariant 5): no fallback to the inherited /proc, which would leave the
//     engine reading every host pid's cmdline, exe symlink and fd table while
//     TOPOLOGY on screen claimed it could not.
//
//  6. dropCapsToExactly(policy.EngineCapBounding) — runs AFTER the mounts that
//     need the full set and IMMEDIATELY BEFORE the exec, per capdrop.go's
//     own documented contract. No uid-map re-exec here, unlike
//     __stage-setup: this process forks from a P1 already uid-0-in-U with a
//     FULL effective set (it created no nested userns), so it inherits full
//     caps immediately and this single drop is enough — TIER-B.md §3 names
//     this distinction explicitly so nobody adds a spurious re-exec.
//
//  7. fdseal.SealExcept() with an EMPTY keep list — this is the last exec
//     before podman, and the whole point is that the engine talks to snug
//     ONLY through its own /tmp socket. The control socket and lifeline pipe
//     are never in this reach: cmd.Env is set to []string{} and no fd beyond
//     the netns descriptor (already closed at step 3) was ever added to this
//     process's ExtraFiles when it was forked.
//
//  8. execve podman with an EXPLICIT, MINIMAL argv AND env, both chosen
//     entirely by P0 and carried on THIS function's own argv — never
//     os.Environ() (the /proc/1/environ lesson, restated for a process whose
//     own /proc/<pid>/ is now worth asking about the moment it joins a
//     sandbox's namespaces). podman itself becomes pid 1 of the fresh
//     namespace by this exec (execve does not change pid); see the pid-1
//     note below.
//
// No /run graft (TIER-B.md §4's boundary table): podman's own forced tmpfs on /run gives
// the engine a working /run in its private mount-namespace copy, and the
// socket + runroot live on /tmp precisely to sit outside that masking
// (ENGINE-WIRING.md §3.1).
//
// # podman as pid 1
//
// The fresh pid namespace's init is whichever process holds pid 1 inside it —
// this process, from the CLONE_NEWPID clone onward, and podman itself from
// step 8's exec onward, since execve never changes pid. Two consequences,
// both read from user_namespaces(7)/pid_namespaces(7) rather than assumed:
// pid 1 gets the kernel's special signal disposition (a signal with no
// explicit handler is IGNORED, not defaulted — SIGKILL and SIGSTOP are the
// only exceptions), and when pid 1 exits or is killed the kernel tears the
// WHOLE namespace down, SIGKILLing everything still in it. The teardown path
// this project already runs (engine.Stop's clean-path `podman stop --filter
// label=...`, before the engine is killed — ENGINE-WIRING.md §6) still
// applies unchanged: it targets containers by socket/label while the socket
// is live, ahead of anything that would fell the namespace. What changes is
// only the WORST case — a killed engine with no clean stop — which used to
// leave conmon's double-forked grandchild reparented to the HOST's pid 1,
// outliving the engine entirely (ENGINE-WIRING.md §6's "containers outlive
// the engine and need an explicit stop"). Now that grandchild's own pid
// namespace is podman's, so podman's own death collapses it too — a stronger
// guarantee than before, not a weaker one. Since MEASURED, A/B against this
// change's own parent commit: the same isolated "SIGKILL the engine and touch
// nothing else" left the container running past a 10s deadline pre-C0 and
// killed it inside one 250ms poll tick after; the numbers are in
// internal/engine's package comment. Orthogonal to
// internal/engine/reap.go's host-pid sweep: that code runs OUTSIDE the
// engine's pid namespace (in P0, on the real host), and a pid namespace being
// a child of the host's does not hide its members from an ancestor's /proc —
// they are still enumerable there under their host-visible pids, so the sweep
// is unaffected by C0. Not separately reasoned about here: whether podman
// itself correctly reaps a reparented orphan before ITS OWN exit (a resource
// question, zombies under a live podman, not a confinement one) is unmeasured
// and out of C0's scope; the containment claim above holds regardless of
// whether podman reaps promptly, because it holds at podman's OWN exit, not
// before it.
//
// argv is [resolvConfPath, fd, nEnv, env0..envN-1, podman, podmanArgs...] —
// fd and the env count arrive as strings for the same reason __innetns's own
// fd argument does: syscall.Exec has no fd or env machinery of its own, so
// everything a raw exec needs has to be named on the command line of the shim
// that performs it. resolvConfPath is a HOST path, never the content itself
// (issue #126) — see the bind-mount step below.
// engineGraft is one entry of the derived view, as __inengine works with it:
// the flat triple P0 wrote down, plus the detached tree this process clones
// from it BEFORE joining the sandbox's namespace.
type engineGraft struct {
	host     string
	guest    string
	readOnly bool
	tree     int
}

func EnterEngine(argv []string) error {
	if len(argv) < 4 {
		return fmt.Errorf("__inengine: usage: __inengine NETNSFD MNTFD NENV [ENV...] " +
			"NGRAFTS [HOST GUEST ro|rw]... PODMAN [ARGS...]")
	}
	fd := atoiOrZero(argv[0])
	if fd <= 0 {
		return fmt.Errorf("__inengine: bad netns fd %q", argv[0])
	}
	mntFD := atoiOrZero(argv[1])
	if mntFD <= 0 {
		return fmt.Errorf("__inengine: bad sandbox-mount-namespace fd %q", argv[1])
	}
	nEnv, err := strconv.Atoi(argv[2])
	if err != nil || nEnv < 0 {
		return fmt.Errorf("__inengine: bad env count %q", argv[2])
	}
	rest := argv[3:]
	if len(rest) < nEnv+1 {
		return fmt.Errorf("__inengine: argv too short for %d env pair(s)", nEnv)
	}
	env := rest[:nEnv]
	rest = rest[nEnv:]

	nGrafts, err := strconv.Atoi(rest[0])
	if err != nil || nGrafts < 0 {
		return fmt.Errorf("__inengine: bad graft count %q", rest[0])
	}
	rest = rest[1:]
	if len(rest) < nGrafts*3+1 {
		return fmt.Errorf("__inengine: argv too short for %d graft(s) and a podman path", nGrafts)
	}
	grafts := make([]engineGraft, 0, nGrafts)
	for i := 0; i < nGrafts; i++ {
		host, guest, access := rest[i*3], rest[i*3+1], rest[i*3+2]
		if host == "" || guest == "" {
			return fmt.Errorf("__inengine: graft %d has an empty host or guest path", i)
		}
		switch access {
		case "ro", "rw":
		default:
			return fmt.Errorf("__inengine: graft %d (%s) has access %q, want ro or rw",
				i, guest, access)
		}
		grafts = append(grafts, engineGraft{host: host, guest: guest, readOnly: access == "ro"})
	}
	podmanArgv := rest[nGrafts*3:]
	podman := podmanArgv[0]

	runtime.LockOSThread()
	before := threadNS("net")
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("__inengine: setns(net): %w", err)
	}
	after := threadNS("net")
	if before == after || after == "" {
		return fmt.Errorf("__inengine: setns reported success but the thread is still in %s", before)
	}

	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("__inengine: closing the netns fd: %w", err)
	}

	// THE CLONE HAPPENS BEFORE THE JOIN, and the ordering is measured rather
	// than chosen. This process still holds the stage's private copy of the
	// HOST tree, so every graft's source resolves here; after the setns below
	// its root is the SANDBOX's and the identical path resolves inside the
	// sandbox — measured as ENOENT, not as a different tree, which is the only
	// mercy in it (issue #125's derived-view pass corrects the design's §4 on
	// exactly this point).
	//
	// It is also the only place with the AUTHORITY: open_tree(OPEN_TREE_CLONE)
	// needs CAP_SYS_ADMIN in the user namespace owning the mount namespace,
	// which this process has here (root-in-U) and P0 does not — the design's
	// own measurement of the P0 variant is EPERM, and reading that as
	// "invariant 4 working" rather than "the kernel refused our plumbing" is
	// what makes this the right place rather than a workaround.
	//
	// The detached trees survive the namespace change and attach on the far
	// side (measured). Each fd is CLOEXEC, so nothing here reaches podman.
	for i := range grafts {
		how := &unix.OpenHow{
			Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			// RESOLVE_NO_SYMLINKS, and ELOOP here is FATAL with no fallback to
			// the path form: Policy.Graft already resolved this source, so a
			// component that has BECOME a symlink since is the attack this
			// closing exists to catch, not a host layout to route around
			// (issue #55, F6; issue #125's G4 comment records the decision).
			// RESOLVE_NO_XDEV is deliberately absent: these sources plausibly
			// cross a mount boundary on an ordinary host, and AT_RECURSIVE
			// cloning the crossed submounts is the intent.
			Resolve: unix.RESOLVE_NO_SYMLINKS,
		}
		src, err := unix.Openat2(unix.AT_FDCWD, grafts[i].host, how)
		if err != nil {
			return fmt.Errorf("__inengine: opening the graft source %s (for %s): %w",
				grafts[i].host, grafts[i].guest, err)
		}
		tree, err := unix.OpenTree(src, "",
			unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.AT_RECURSIVE|unix.OPEN_TREE_CLOEXEC)
		unix.Close(src)
		if err != nil {
			return fmt.Errorf("__inengine: cloning the graft source %s (for %s): %w",
				grafts[i].host, grafts[i].guest, err)
		}
		grafts[i].tree = tree
	}

	// Step 3 of the design's sequence, and NOT the single-threaded requirement
	// the whole no-cgo decision is written around (NOCGO.md): setns(CLONE_NEWNS)
	// checks fs_struct SHARING, not thread count, and every Go runtime thread
	// shares one. One per-thread unshare satisfies it. Same symptom as
	// setns(CLONE_NEWUSER)'s check, different kernel test, and only one of them
	// costs a raw fork.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("__inengine: unshare(CLONE_FS) before joining the sandbox's mount "+
			"namespace: %w", err)
	}

	// Step 4: the sandbox's OWN view, which is what makes the engine's view
	// DERIVED rather than a second window onto the host. The caller waited for
	// bwrap to finish every mount snug asked for before opening this
	// descriptor (waitForSandboxMounts) — joining earlier lands in a namespace
	// that still holds the host tree at /oldroot, measured.
	if err := unix.Setns(mntFD, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("__inengine: setns into the sandbox's mount namespace: %w", err)
	}
	if err := unix.Close(mntFD); err != nil {
		return fmt.Errorf("__inengine: closing the sandbox mount-namespace fd: %w", err)
	}

	// Step 5: the engine's OWN copy of that view, so everything below — the
	// grafts, the fresh procfs, the cgroup2, the tmpfs on /run — is invisible
	// to the payload. Without this the engine would be mounting into the
	// SANDBOX's own namespace, which is the opposite of the ticket.
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("__inengine: unshare(CLONE_NEWNS) for the engine's own view: %w", err)
	}

	// Two reasons, both load-bearing, identical to __stage-setup's own copy
	// of this call: overlay refuses to make its own mount private without a
	// private tree to work in, and a private tree is what stops podman's
	// per-container nsfs binds propagating back to the host — the leak
	// ENGINE-NETNS.md §1 measured and #100's runtimeDir hardening pattern
	// exists to avoid a different flavour of.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("__inengine: making / private: %w", err)
	}

	// Step 10: attach each detached tree. MEASURED, and the two facts worth
	// carrying: move_mount onto a directory on the sandbox's READ-ONLY root
	// succeeds (a mountpoint needs no write access to the filesystem beneath
	// it), while mkdir there is EROFS — which is why G3 insists the
	// destination already exist and why BwrapFlags pre-creates every one of
	// them (policy.EngineMountpoints).
	//
	// Every failure is FATAL (invariant 5). G3's third disjunct is a soundness
	// approximation by its own doc comment; this is where an approximation
	// that guessed wrong has to surface rather than be papered over.
	for _, g := range grafts {
		if err := unix.MoveMount(g.tree, "", unix.AT_FDCWD, g.guest,
			unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
			return fmt.Errorf("__inengine: attaching %s at %s in the engine's view: %w",
				g.host, g.guest, err)
		}
		unix.Close(g.tree)
		if !g.readOnly {
			continue
		}
		// Read-only is a REQUIREMENT of the model, not a hint: the config
		// directory and the toolchain are grafted AccessRO precisely so an
		// engine that is talked into writing cannot rewrite what it was
		// started under. Applied after the attach, recursively, and measured
		// to refuse a write with EROFS afterwards.
		attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
		if err := unix.MountSetattr(unix.AT_FDCWD, g.guest, unix.AT_RECURSIVE, attr); err != nil {
			return fmt.Errorf("__inengine: making %s read-only in the engine's view: %w",
				g.guest, err)
		}
	}

	// A FRESH procfs, bound to THIS process's own pid namespace (issue #125's
	// "C0" piece: "the engine must hold its own pid namespace for the
	// derived-mount-view work to be buildable at all"). Mounted directly over
	// whatever /proc this process inherited from the stage's private
	// host-tree copy — which up to this line is still the HOST's real /proc,
	// exactly like /etc/resolv.conf below before its own bind. This process
	// is pid 1 of a pid namespace created at CLONE_NEWPID clone time
	// (startEngine), owned by U because that clone carried no CLONE_NEWUSER
	// of its own, and a procfs mount needs precisely that ownership —
	// MEASURED: mount(2) of "proc" in a pid namespace with no owning userns of
	// the caller's own returns EPERM; one created together with, or owned by,
	// the caller's own userns succeeds.
	//
	// FATAL on failure, no fallback (invariant 5): the alternative is the
	// engine silently keeping the host's whole process table — every host
	// pid's cmdline, exe symlink, environ and fd table — while snug's own
	// TOPOLOGY block on screen claims a pid namespace it does not have.
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("__inengine: mounting a fresh /proc for this engine's own pid namespace: %w", err)
	}

	// STEP 11 IS GONE, and its absence is the point rather than a tidy-up.
	// It used to bind snug's own generated /etc/resolv.conf over the engine's,
	// because the engine's view was a private copy of the HOST tree and
	// therefore carried the host's real resolver configuration (issue #126).
	// Under the derived view there is nothing host-shaped left to shadow: the
	// engine's /etc/resolv.conf IS the sandbox's, which snug generated. A bind
	// here would now be snug shadowing its own file with a second copy of
	// itself.
	//
	// What a CONTAINER gets is unchanged and was never this mount's job since
	// issue #126's second half: the generated containers.conf names DNS
	// explicitly, which needs no mount to take effect.

	// A bare tmpfs on /run, MEASURED necessary and NOT what ENGINE-WIRING.md
	// §7 assumed. That doc's "no /run graft" reasoning was "podman's own
	// forced tmpfs on /run gives the engine a working /run" — true for a
	// process podman considers ROOTLESS (a single mapped uid), false here:
	// this process is root-in-U with the FULL delegated subuid range
	// (SubuidFull), which podman reads as genuinely root-like (rootless=false)
	// and for which it does NOT self-mount anything — it just expects
	// /run/libpod to already be writable and fails outright
	// ("creating runtime temporary files directory: mkdir /run/libpod:
	// permission denied") when the host's own /run is read-only to this
	// mapped range, exactly as the earlier standalone measurement's own
	// snug-podman-ns wrapper already had to work around by hand. This is a
	// PLAIN tmpfs mount of a fresh, empty filesystem — not a graft in the
	// Tier C sense (no open_tree, no move_mount, nothing of the host tree
	// grafted in): TIER-B.md §4's "no grafts" still holds for what
	// it actually meant (no piece of the HOST's /run is exposed here), the
	// mechanism underneath it was simply wrong about needing no mount at
	// all. XDG_RUNTIME_DIR is recreated empty on it for the same reason
	// podman's own per-container netns bind-mount path looks there.
	if err := unix.Mount("tmpfs", "/run", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("__inengine: mounting a fresh tmpfs on /run: %w", err)
	}
	if err := unix.Mkdir("/run/lock", 0o1777); err != nil {
		return fmt.Errorf("__inengine: creating /run/lock: %w", err)
	}

	// /var/tmp, and it is a mount rather than a configuration key because the
	// consumer cannot be configured: containers/image hardcodes /var/tmp for
	// the scratch space it creates while COMMITTING a layer
	// (TemporaryDirectoryForBigFiles), which is why containers.conf's
	// image_copy_tmp_dir and $TMPDIR — both of which snug also sets — left
	// every build failing at the commit step. A fresh, empty tmpfs: nothing of
	// the host's /var/tmp is in it, and it dies with the engine.
	if err := unix.Mount("tmpfs", "/var/tmp", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("__inengine: mounting a fresh tmpfs on /var/tmp for the engine's own "+
			"image-commit scratch space: %w", err)
	}

	// A FRESH cgroup2 mount over /sys/fs/cgroup, MEASURED necessary and the
	// second correction to ENGINE-WIRING.md §2.2's assumption that
	// CLONE_NEWCGROUP alone is enough. A cgroup namespace changes what
	// /proc/self/cgroup REPORTS (the path becomes relative to the new
	// namespace's root) but does nothing on its own to the EXISTING
	// /sys/fs/cgroup mount this process's cloned mount namespace still
	// carries a copy of — that mount's contents stay rooted at the OLD
	// (host, or host-container) cgroup tree, unrestricted by the new
	// namespace, which is how crun failed with exactly the ENGINE-NETNS.md
	// §3 symptom this cgroup-namespace mechanism exists to avoid ("crun:
	// write to /sys/fs/cgroup/libpod_parent/.../cgroup.procs: No such file
	// or directory") even though CLONE_NEWCGROUP had already applied.
	// MS_PRIVATE above does not fix this either: it changes propagation, not
	// which namespace a mount's cgroup2 content is rooted at.
	//
	// A fresh mount of the cgroup2 FS TYPE (not a bind, not a remount) is
	// what the kernel roots at the CALLING PROCESS's own cgroup namespace
	// (cgroup_namespaces(7)) — mounted directly OVER the inherited one,
	// deliberately WITHOUT unmounting it first: an explicit unmount of the
	// inherited mount was measured to fail here (EINVAL) on at least one
	// tested host shape (nested container), while mounting straight over it
	// works on every host tried and is exactly what MS_PRIVATE on "/" above
	// exists to make safe (the shadowed mount cannot propagate anywhere, and
	// nothing downstream of this process ever looks past the new one).
	if err := unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, ""); err != nil {
		// EBUSY, measured on a nested-container host shape (a distrobox
		// itself running inside a container, several cgroup2 mounts already
		// stacked): the inherited mount has to come off first after all. Not
		// the FIRST thing tried (mounting straight over works, and is
		// simpler, on an un-nested host) — this is the fallback, not the
		// primary mechanism, so a host where either shape alone would have
		// worked still only pays for one mount(2) call.
		if unmountErr := unix.Unmount("/sys/fs/cgroup", unix.MNT_DETACH); unmountErr == nil {
			err = unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, "")
		}
		if err != nil {
			// NOT fatal. MEASURED on a host whose OWN /sys/fs/cgroup mount
			// root already needs ".." to express (visible in mountinfo as
			// "/../../app.slice/...") — a symptom of the container this
			// development host itself runs inside, ENGINE-NETNS.md §3's own
			// case, one level deeper. Refusing the whole engine over this
			// would be wrong: preflight P5 (containerpreflight.go) is what
			// is SUPPOSED to catch a host in this shape and select podman's
			// `cgroups = "disabled"` default, which needs no working
			// cgroup2 write path at all — so this failure is warned, not
			// fatal, and left for podman/crun to surface per-container if
			// P5 guessed wrong. What stays fatal is everything ABOVE this
			// point: the netns join and the mount-private call, which are
			// the actual confinement this tier exists to guarantee.
			fmt.Fprintf(os.Stderr, "snug: __inengine: could not remount /sys/fs/cgroup for this "+
				"engine's own cgroup namespace (%v) — continuing; a container that needs cgroup "+
				"management will fail with its own error rather than this one\n", err)
		}
	}

	// Runs AFTER the mount above (which needs the full set this process still
	// holds at this point) and IMMEDIATELY BEFORE the exec below — never
	// earlier, never later. See capdrop.go's own doc comment on why the
	// ordering is not merely tidy.
	if err := dropCapsToExactly(policy.EngineCapBounding); err != nil {
		return fmt.Errorf("__inengine: %w", err)
	}

	// Empty keep list: this is the last exec before podman, and the engine is
	// meant to hold nothing beyond its own stdio (0/1/2, exempt from the sweep
	// unconditionally — see fdseal.sealExcept) and the argv/env it was handed.
	if err := fdseal.SealExcept(); err != nil {
		return fmt.Errorf("__inengine: %w", err)
	}

	return syscall.Exec(podman, podmanArgv, env)
}
