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
// cloned child of the stage (CLONE_NEWNS|CLONE_NEWCGROUP already applied by
// Cloneflags at fork time — see startEngine) into the per-sandbox container
// engine, running in THIS sandbox's own N and bounded to
// policy.EngineCapBounding, and nothing else (issue #63, Tier B).
//
// THE ORDER IS THE SPECIFICATION (ENGINE-WIRING.md §2.4):
//
//  1. lock the OS thread — setns(CLONE_NEWNET) is per-task, exactly like
//     __innetns's own setns.
//  2. setns(fd, CLONE_NEWNET) into the sandbox's N; re-read and refuse if the
//     thread did not move — the __innetns check, verbatim, using the
//     DESCRIPTOR P1 pinned before it left N, never a /proc/<pid>/ns/net path
//     (the wrong-attach silent failure, SUPERVISOR-DESIGN.md §3.4).
//  3. close fd — nothing downstream of this point (podman, conmon, a
//     container) ever holds a reference to N it could setns with.
//  4. mount("", "/", MS_REC|MS_PRIVATE) — load-bearing TWICE
//     (ENGINE-NETNS.md §1): overlay refuses to make its own mount private
//     without it, and it keeps podman's per-container nsfs binds out of the
//     host mount tree. This is a plain private COPY of the host tree,
//     deliberately NOT derived from the resolved Policy — that is Tier C's
//     job (TIER-B.md §4: "if you find yourself writing open_tree,
//     move_mount, a graft… you have crossed into Tier C — stop"). What stops
//     the engine acting on an ungranted path is the proxy's bind filter,
//     which reads the SAME resolved Policy a container may not bypass
//     (TestContainerBindFilterMatchesPolicyVisibility is the standing gate);
//     this mount step is not that enforcement and must never be read as one.
//  5. dropCapsToExactly(policy.EngineCapBounding) — runs AFTER the mount that
//     needs the full set and IMMEDIATELY BEFORE the exec, per capdrop.go's
//     own documented contract. No uid-map re-exec here, unlike
//     __stage-setup: this process forks from a P1 already uid-0-in-U with a
//     FULL effective set (it created no nested userns), so it inherits full
//     caps immediately and this single drop is enough — TIER-B.md §3 names
//     this distinction explicitly so nobody adds a spurious re-exec.
//  6. fdseal.SealExcept() with an EMPTY keep list — this is the last exec
//     before podman, and the whole point is that the engine talks to snug
//     ONLY through its own /tmp socket. The control socket and lifeline pipe
//     are never in this reach: cmd.Env is set to []string{} and no fd beyond
//     the netns descriptor (already closed at step 3) was ever added to this
//     process's ExtraFiles when it was forked.
//  7. execve podman with an EXPLICIT, MINIMAL argv AND env, both chosen
//     entirely by P0 and carried on THIS function's own argv — never
//     os.Environ() (the /proc/1/environ lesson, restated for a process whose
//     own /proc/<pid>/ is now worth asking about the moment it joins a
//     sandbox's namespaces).
//
// No /run graft (TIER-B.md §4's boundary table): podman's own forced tmpfs on /run gives
// the engine a working /run in its private mount-namespace copy, and the
// socket + runroot live on /tmp precisely to sit outside that masking
// (ENGINE-WIRING.md §3.1).
//
// argv is [resolvConfPath, fd, nEnv, env0..envN-1, podman, podmanArgs...] —
// fd and the env count arrive as strings for the same reason __innetns's own
// fd argument does: syscall.Exec has no fd or env machinery of its own, so
// everything a raw exec needs has to be named on the command line of the shim
// that performs it. resolvConfPath is a HOST path, never the content itself
// (issue #126) — see the bind-mount step below.
func EnterEngine(argv []string) error {
	if len(argv) < 4 {
		return fmt.Errorf("__inengine: usage: __inengine RESOLVCONF FD NENV [ENV...] PODMAN [ARGS...]")
	}
	resolvConfPath := argv[0]
	if resolvConfPath == "" {
		return fmt.Errorf("__inengine: empty resolv.conf path")
	}
	fd := atoiOrZero(argv[1])
	if fd <= 0 {
		return fmt.Errorf("__inengine: bad fd %q", argv[1])
	}
	nEnv, err := strconv.Atoi(argv[2])
	if err != nil || nEnv < 0 {
		return fmt.Errorf("__inengine: bad env count %q", argv[2])
	}
	rest := argv[3:]
	if len(rest) < nEnv+1 {
		return fmt.Errorf("__inengine: argv too short for %d env pair(s) and a podman path", nEnv)
	}
	env := rest[:nEnv]
	podmanArgv := rest[nEnv:]
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

	// Two reasons, both load-bearing, identical to __stage-setup's own copy
	// of this call: overlay refuses to make its own mount private without a
	// private tree to work in, and a private tree is what stops podman's
	// per-container nsfs binds propagating back to the host — the leak
	// ENGINE-NETNS.md §1 measured and #100's runtimeDir hardening pattern
	// exists to avoid a different flavour of.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("__inengine: making / private: %w", err)
	}

	// Bind-mount snug's own generated /etc/resolv.conf (the SAME content the
	// sandbox payload gets, policy.NetPolicy.ResolvConf, threaded here as a
	// host path — never re-read from the host, never regenerated) OVER the
	// private tree's own /etc/resolv.conf, which up to this point is still
	// the HOST's real one (issue #126). Without this, podman generates every
	// container's /etc/resolv.conf FROM the engine's own — so an offline
	// sandbox's container would learn the host LAN's nameservers, the IPv6
	// ULA prefix and the search domain, a channel the proxy's bind filter
	// (internal/dockerproxy/create.go) never sees because it is not a
	// client-requested mount. MS_PRIVATE above is what makes this bind safe
	// to do at all: it is invisible to the host and to every other process —
	// the private tree copy is the only thing shadowed.
	//
	// A bind, not an overwrite of the file's own content: the target inode is
	// still the host's real /etc/resolv.conf (or, on a systemd-resolved host,
	// whatever it symlinks to) as far as the REST of the host mount tree
	// knows — MS_BIND only shadows the mountpoint inside THIS process's own
	// private namespace, so the host's file is never opened for writing here
	// at all.
	//
	// BEST-EFFORT, and deliberately so since issue #126's second half. This
	// mount is the ENGINE's own resolver configuration; what a CONTAINER gets
	// is now decided by the generated containers.conf (engine.writeContainersConf),
	// which needs no mount to take effect. So a host where this bind cannot
	// succeed — issue #128 measured one where /etc/resolv.conf is a bind over
	// a DELETED inode, on which mounting returns ENOENT while reading works
	// perfectly — costs the engine fast offline failure, not a container's DNS
	// isolation. Failing the whole run here would refuse to start an engine
	// that is not actually leaking anything. Preflight P7 says this on the
	// host before the run starts (internal/cli/containerpreflight.go); this
	// line is the backstop for a host where P7 and reality disagree, and it is
	// loud either way — never silent.
	if err := unix.Mount(resolvConfPath, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		// Terse on purpose: preflight P7 has already said this in full on the
		// host, before the run started. This line exists for the case where
		// P7 and reality disagree, so it must still be printed — but printing
		// the whole explanation twice is noise a reader learns to skip.
		fmt.Fprintf(os.Stderr, "snug: the container engine kept the host's /etc/resolv.conf "+
			"(%v) — containers are unaffected; see preflight P7's note above.\n", err)
	}

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
