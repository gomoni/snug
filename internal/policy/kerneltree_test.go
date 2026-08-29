package policy

import (
	"strings"
	"testing"
)

// RULE 5 (issue #527, R6 of the pseudo-filesystem audit): no profile may bind
// FROM /proc, /dev or /sys — at any access, under any guest name.
//
// ABUSE: a bind of the host's /proc reaches every host process of the same uid,
// and /proc/PID/root, /proc/PID/cwd and /proc/PID/fd/* leave the sandbox
// entirely; a bind of the host's /dev opens block and input devices whatever
// the access, because the kernel clears MAY_WRITE for a device node before it
// consults MNT_READONLY (issue #287); a bind of the host's /sys/fs/cgroup is
// cgroup delegation, and a delegated cgroup's cgroup.procs and cgroup.freeze
// reach processes OUTSIDE the sandbox.

func resolveWithGrant(t testing.TB, p *Profile) error {
	t.Helper()
	reg := testRegistry()
	reg[ProfileName(p.Name)] = p
	// The fake host must publish these paths: the existence check in Resolve
	// runs BEFORE Validate, so without them this file would be measuring "that
	// path does not exist" rather than the rule.
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", ProfileName(p.Name)}, testCtx(), envWithKernelTrees())
	return err
}

func envWithKernelTrees() *fakeEnv {
	env := newFakeEnv()
	for _, d := range []string{
		"/sys", "/sys/fs", "/sys/fs/cgroup", "/sys/fs/cgroup/user.slice",
		"/sys/kernel/debug", "/sys/class/net",
		"/proc", "/proc/sys", "/proc/1", "/proc/self", "/tmp",
		"/dev", "/dev/shm", "/dev/dri", "/dev/net",
		// The near-misses the precision case needs.
		"/system", "/sysroot", "/sysadmin", "/sysadmin/scratch",
		"/devel", "/procedures",
		"/mnt", "/mnt/cg", "/mnt/allsys", "/mnt/nics", "/mnt/dev", "/mnt/proc",
	} {
		env.dirs[d] = true
	}
	env.files["/dev/null"] = true
	env.files["/proc/cpuinfo"] = true
	return env
}

// The HOST end, which is the whole rule: the guest path says nothing about what
// a bind carries. A redteam round broke a guest-only version of this in one
// line of TOML — `rw = ["/sys/fs/cgroup:/mnt/cg"]` produced
// `--bind /sys/fs/cgroup /mnt/cg`, measured inside the sandbox as cgroup2 rw
// from the host's user.slice with `mkdir /mnt/cg/snugpwn_redteam` SUCCEEDING
// and cgroup.freeze and cgroup.kill both present.
func TestProfileCannotBindFromAKernelTree(t *testing.T) {
	specs := []struct{ spec, tree string }{
		{"/proc:/mnt/proc", "/proc"},
		{"/proc/1:/mnt/proc", "/proc"},
		{"/proc/cpuinfo:/mnt/proc", "/proc"},
		{"/dev:/mnt/dev", "/dev"},
		{"/dev/dri:/mnt/dev", "/dev"},
		{"/dev/null:/mnt/dev", "/dev"},
		{"/sys:/mnt/allsys", "/sys"},
		{"/sys/fs/cgroup:/mnt/cg", "/sys"},
		{"/sys/kernel/debug:/opt/tools/bin/dbg", "/sys"},
		{"/sys/class/net:/mnt/nics", "/sys"},
	}
	for _, s := range specs {
		for _, p := range []*Profile{
			{Name: "ktrw", RW: []string{s.spec}},
			{Name: "ktro", RO: []string{s.spec}},
		} {
			access := "rw"
			if len(p.RO) > 0 {
				access = "ro"
			}
			err := resolveWithGrant(t, p)
			if err == nil {
				t.Errorf("%s = [%q] resolved: the host end is %s, and no profile may bind from it",
					access, s.spec, s.tree)
				continue
			}
			// The message has to name the profile that did it and the host path
			// it named, or the author's next move is to widen something else.
			host := strings.SplitN(s.spec, ":", 2)[0]
			for _, want := range []string{string(p.Name), host, s.tree} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s = [%q] refused with %q, which does not name %q",
						access, s.spec, err, want)
				}
			}
		}
	}
}

// READ-ONLY IS NOT A BOUND, and this is the case the first version of the rule
// allowed. `ro` stops the sandbox REPLACING a node; it restrains neither a
// device node (the kernel clears MAY_WRITE for one before it consults
// MNT_READONLY, issue #287) nor a magic symlink under /proc, which resolves to
// the host filesystem regardless of every mount decision snug made.
func TestReadOnlyIsRefusedForAKernelTreeToo(t *testing.T) {
	for _, spec := range []string{"/sys", "/sys/class/net", "/proc", "/dev"} {
		err := resolveWithGrant(t, &Profile{Name: "ktro", RO: []string{spec + ":/mnt/allsys"}})
		if err == nil {
			t.Errorf("ro = [%q] resolved: read-only restrains neither a device node nor a "+
				"/proc magic symlink", spec)
			continue
		}
		if !strings.Contains(err.Error(), "Read-only is not a bound here") {
			t.Errorf("ro = [%q] refused with %q, which does not say why ro is refused too", spec, err)
		}
	}
}

// PRECISION. Each tree is a path COMPONENT, not a string prefix — a rule
// written with strings.HasPrefix alone would swallow these, and the author of a
// perfectly ordinary grant would get a lecture about cgroup delegation.
func TestTheKernelTreeRuleDoesNotCatchALookalikePath(t *testing.T) {
	for _, at := range []string{"/system", "/sysroot", "/sysadmin/scratch", "/devel", "/procedures"} {
		if err := resolveWithGrant(t, &Profile{Name: "notkt", RW: []string{at}}); err != nil {
			t.Errorf("rw = [%q] was refused (%v): each tree is a path component, not a prefix", at, err)
		}
	}
}

// snug's OWN mounts are Authored and must survive the rule. /proc/sys is the
// one that would break every run: procfs.go binds it read-only from the host to
// close the write side, and it goes through yieldTo, which sets Authored.
func TestTheKernelTreeRuleDoesNotRefuseSnugsOwnProcSysBind(t *testing.T) {
	pol, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw"}, testCtx(), envWithKernelTrees())
	if err != nil {
		t.Fatalf("an ordinary run stopped resolving: %v", err)
	}
	m, ok := pol.Mounts["/proc/sys"]
	if !ok {
		t.Fatal("snug's read-only /proc/sys bind is gone: it is the write-side closure procfs.go " +
			"exists for, and its absence is a hole this rule must not have caused")
	}
	if !m.Authored || m.Host != "/proc/sys" {
		t.Errorf("/proc/sys is %+v: the rule exempts it by Authored alone, so a non-Authored "+
			"writer of this mount would be refused at every run", m)
	}
}

// The engine's /sys is not caught and structurally cannot be: /sys, /sys/fs and
// /sys/fs/cgroup are bwrap --dir mountpoints (EngineMountpoints) and a
// KindCgroup2 in p.Grafts — never Mounts in p.Mounts, which is what Validate's
// loop reads. This is the control that says so, because a rule that broke every
// container run would otherwise be found by a user rather than here.
func TestTheKernelTreeRuleDoesNotRefuseTheEnginesOwnMountpoints(t *testing.T) {
	pol, err := Resolve(testRegistry(), []ProfileName{"@podman-socket", "@cwd-rw"},
		testCtxWithPodmanShim(), envWithKernelTrees())
	if err != nil {
		t.Fatalf("a container run stopped resolving: %v", err)
	}
	for _, at := range []string{"/sys", "/sys/fs", "/sys/fs/cgroup"} {
		if _, ok := pol.Mounts[at]; ok {
			t.Errorf("%s is in p.Mounts for a container run: the engine's /sys is a --dir "+
				"mountpoint and a graft, and if that ever changes RULE 5 needs a wider "+
				"exemption than Authored", at)
		}
	}
}

// The guest end keeps its OWN refusals, and they are better targeted than RULE
// 5's. This asserts the ordering rather than the messages: a grant AT /proc is
// RULE 4's ("snug's own"), and one strictly inside /dev is checkNesting's
// ("a pseudo-filesystem the kernel and bwrap populate").
func TestTheGuestEndOfProcAndDevIsStillRefusedByItsOwnRule(t *testing.T) {
	for _, c := range []struct {
		p    *Profile
		want string
	}{
		{&Profile{Name: "atproc", RO: []string{"/proc"}}, "snug's own"},
		{&Profile{Name: "atdev", RO: []string{"/dev"}}, "snug's own"},
		{&Profile{Name: "indev", RW: []string{"/tmp:/dev/shm"}}, "pseudo-filesystem"},
		{&Profile{Name: "inproc", RO: []string{"/tmp:/proc/1"}}, "pseudo-filesystem"},
	} {
		err := resolveWithGrant(t, c.p)
		if err == nil {
			t.Errorf("%s resolved: the guest end of /proc and /dev is closed at, above and inside",
				c.p.Name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s refused with %q, which is not the rule that should have caught it (%q)",
				c.p.Name, err, c.want)
		}
	}
}

// BY TYPE, NOT ONLY BY NAME, and this is the case a path rule alone loses. On a
// host running a toolbox container /run/host/proc is a procfs and /run/host/sys
// a sysfs — measured with findmnt on the maintainer's machine. With the path
// rule alone in place, `ro = ["/run/host/proc:/mnt/p"]` RESOLVED and the
// sandbox listed the host's process table at /mnt/p and the HOST ROOT at
// /mnt/p/self/root.
func TestProfileCannotBindFromAPseudoFilesystemAtAnOrdinaryPath(t *testing.T) {
	for _, c := range []struct {
		host   string
		fstype string
		tree   string
	}{
		{"/run/host/proc", "proc", "/proc"},
		{"/run/host/sys", "sysfs", "/sys"},
		{"/run/host/cg", "cgroup2", "/sys"},
		{"/mnt/dbg", "debugfs", "/sys"},
		{"/run/host/dev", "devtmpfs", "/dev"},
	} {
		env := envWithKernelTrees()
		env.dirs[c.host] = true
		env.mounts = []HostMount{{Path: c.host, FSType: c.fstype}}
		reg := testRegistry()
		reg["alt"] = &Profile{Name: "alt", RO: []string{c.host + ":/mnt/p"}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "alt"}, testCtx(), env)
		if err == nil {
			t.Errorf("ro = [%q] resolved: the path is ordinary, the FILESYSTEM is not", c.host)
			continue
		}
		if !strings.Contains(err.Error(), c.tree) {
			t.Errorf("ro = [%q] refused with %q, which does not name %q", c.host, err, c.tree)
		}
	}
}

// devtmpfs reports TMPFS_MAGIC, so no statfs distinguishes /dev from an
// ordinary tmpfs — which is why the path half of the rule cannot be dropped in
// favour of the type half.
func TestAnOrdinaryTmpfsIsNotAKernelTree(t *testing.T) {
	env := envWithKernelTrees()
	env.dirs["/run/user/1000"] = true
	env.mounts = []HostMount{{Path: "/run/user/1000", FSType: "tmpfs"}}
	reg := testRegistry()
	reg["rt"] = &Profile{Name: "rt", RW: []string{"/run/user/1000:/mnt/p"}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "rt"}, testCtx(), env); err != nil {
		t.Errorf("a bind from a tmpfs was refused (%v): tmpfs is where every socket snug "+
			"proxies lives, and refusing it would take @podman-socket and @ssh-agent with it", err)
	}
}

// THE KindBind GUARD. Mount.Host is the canonical host path for a bind and the
// LINK TARGET for a symlink (types.go). Without the guard a profile symlink
// pointing into the sandbox's OWN procfs is refused for naming a host path it
// does not name.
func TestAGuestSymlinkIntoTheSandboxsOwnProcIsNotAHostBind(t *testing.T) {
	reg := testRegistry()
	reg["sl"] = &Profile{Name: "sl", Symlink: []Symlink{{At: "/hostfd", Target: "/proc/self/fd"}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "sl"}, testCtx(), envWithKernelTrees()); err != nil {
		t.Errorf("a symlink to /proc/self/fd was refused (%v): its target is inside the "+
			"sandbox's own procfs, and Mount.Host is a link target here rather than a host path", err)
	}
}

// The refusal renders BOTH paths through VisibleText. m.Host never goes through
// checkPathHygiene — Validate checks the guest only — so a host path carrying an
// ESC is interpolated into a message a human reads.
func TestTheKernelTreeRefusalDoesNotForgeItsOwnScreen(t *testing.T) {
	env := envWithKernelTrees()
	host := "/sys/\x1b[2J"
	env.dirs[host] = true
	reg := testRegistry()
	reg["forge"] = &Profile{Name: "forge", RW: []string{host + ":/mnt/x"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "forge"}, testCtx(), env)
	if err == nil {
		t.Fatal("a host path under /sys resolved")
	}
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("the refusal carries a raw ESC: %q", err)
	}
}

// RULE 5b: the guest end of /sys. snug creates /sys, /sys/fs and /sys/fs/cgroup
// for an engine run and grafts a cgroup2 at the last of them; nothing judges a
// Mount against EngineMountpoints, so a profile mount there collides and argv
// order decides.
func TestProfileCannotMountAtOrUnderGuestSys(t *testing.T) {
	for _, p := range []*Profile{
		{Name: "gsys", RW: []string{"/tmp:/sys"}},
		{Name: "gsys", RO: []string{"/tmp:/sys/fs/cgroup"}},
		{Name: "gsys", Tmpfs: []string{"/sys/fs/cgroup"}},
	} {
		err := resolveWithGrant(t, p)
		if err == nil {
			t.Errorf("%+v resolved: /sys inside the sandbox is snug's own", p)
			continue
		}
		if !strings.Contains(err.Error(), "snug's own") {
			t.Errorf("%+v refused with %q, which is not RULE 5b", p, err)
		}
	}
}

// A REGULAR-FS ANCESTOR of a pseudo-filesystem, which is the whole reason the
// rule reads the mount table rather than the grant root alone. bwrap's bind is
// RECURSIVE, so a procfs mounted beneath a granted ordinary directory rides in
// as a submount and the grant names nothing suspicious.
//
// MEASURED with the grant-root check alone in place: `ro = ["/run/host:/host"]`
// resolved, --dry-run printed one innocuous `ro /host (from /run/host)` row,
// and inside the sandbox /host/proc came up type proc with the host's pid 1
// cmdline (/usr/lib/systemd/systemd), /host/sys type sysfs, and /host/dev/dm-0
// a real block device node. (redteam.)
func TestProfileCannotBindAnAncestorOfAPseudoFilesystem(t *testing.T) {
	for _, c := range []struct {
		grant, submount, fstype, tree string
	}{
		{"/run/host", "/run/host/proc", "proc", "/proc"},
		{"/run/host", "/run/host/sys", "sysfs", "/sys"},
		{"/run/host", "/run/host/dev", "devtmpfs", "/dev"},
		{"/run", "/run/host/proc", "proc", "/proc"},
	} {
		env := envWithKernelTrees()
		env.dirs[c.grant] = true
		env.mounts = []HostMount{
			{Path: "/", FSType: "btrfs"},
			{Path: c.submount, FSType: c.fstype},
		}
		reg := testRegistry()
		reg["anc"] = &Profile{Name: "anc", RO: []string{c.grant + ":/mnt/p"}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "anc"}, testCtx(), env)
		if err == nil {
			t.Errorf("ro = [%q] resolved with a %s at %s beneath it: bwrap's bind is recursive",
				c.grant, c.fstype, c.submount)
			continue
		}
		// The message has to name the submount, or the author reads a refusal
		// about a path their grant does not mention and deletes the wrong line.
		for _, want := range []string{c.submount, c.tree, "RECURSIVE"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ro = [%q] refused with %q, which does not name %q", c.grant, err, want)
			}
		}
	}
}

// The negative half: an ordinary directory with an ordinary submount is not a
// kernel tree, and a rule that refused any grant with a mount under it would
// take /home and /tmp with it.
func TestAnOrdinarySubmountIsNotAKernelTree(t *testing.T) {
	env := envWithKernelTrees()
	env.dirs["/mnt/data"] = true
	env.mounts = []HostMount{
		{Path: "/", FSType: "btrfs"},
		{Path: "/mnt/data/disk", FSType: "ext4"},
		{Path: "/mnt/data/scratch", FSType: "tmpfs"},
	}
	reg := testRegistry()
	reg["ord"] = &Profile{Name: "ord", RW: []string{"/mnt/data:/mnt/p"}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ord"}, testCtx(), env); err != nil {
		t.Errorf("a grant with an ext4 and a tmpfs beneath it was refused (%v)", err)
	}
}

// mountinfo's optional fields sit between the mount source and the type and are
// terminated by a lone "-", so the type is not at a fixed index; a mount point
// carries the space, tab, newline and backslash octal-escaped.
func TestParseMountinfo(t *testing.T) {
	const in = "36 35 98:0 / /proc rw,noatime shared:1 master:2 - proc proc rw\n" +
		"37 35 0:22 / /mnt/a\\040b rw - ext4 /dev/sda1 rw\n" +
		"bad line\n"
	got := parseMountinfo(in)
	want := []HostMount{{Path: "/proc", FSType: "proc"}, {Path: "/mnt/a b", FSType: "ext4"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d is %+v, want %+v", i, got[i], want[i])
		}
	}
}
