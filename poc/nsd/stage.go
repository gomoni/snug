package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Go's syscall package does not export SYS_SETNS on linux/amd64 (checked: it is
// absent from zsysnum_linux_amd64.go in go1.26.5), and this PoC has no
// golang.org/x/sys dependency. 308 is the x86_64 number; enterNetns refuses to
// run on any other GOARCH rather than issuing whatever 308 means there.
const sysSetns = 308

// The pasta closing set, copied verbatim from internal/policy/net.go. Any one of
// the last four missing re-opens host loopback.
//
// netnsPath is the ONLY part that is not a constant, and it is the whole of
// Phase 0b's question (c): once P1 has left N, `/proc/<P1>/ns/net` names the
// WRONG namespace. A pinned reference has to be passed instead.
func pastaArgs(stagePID int, netnsPath string) []string {
	return []string{
		"--config-net",
		"--map-host-loopback", "none",
		"-t", "none", "-u", "none",
		"-T", "none", "-U", "none",
		"--ns-ifname", "snug0",
		"--no-netns-quit",
		"--quiet",
		"--foreground",
		"--dns-forward", "10.0.2.3",
		"--netns", netnsPath,
		"--userns", fmt.Sprintf("/proc/%d/ns/user", stagePID),
	}
}

// cmdUp is P0: the host-side launcher. It exists only long enough to build P1
// and then supervises it.
func cmdUp(argv []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	runDir := fs.String("run", "", "run directory on the host filesystem (control socket lives here)")
	withNet := fs.Bool("net", false, "attach pasta to the stage's netns")
	bindDir := fs.String("bind", "", "directory to bind read-write into sandboxes")
	outsideN := fs.Bool("p1-outside-n", false, "P1 pins N then unshares out of it (Phase 0b)")
	pastaNaive := fs.Bool("pasta-naive", false, "aim pasta at /proc/<P1>/ns/net even after P1 has left N")
	singleUidMap := fs.Bool("single-uid-map", false,
		"write U's map as 0 <hostuid> 1 via SysProcAttr.UidMappings instead of "+
			"newuidmap's full subuid delegation, and skip the __stage0 privileged "+
			"re-exec entirely (SUPERVISOR-DESIGN.md §4 Step 0 / §3.6)")
	_ = fs.Parse(argv)
	if *runDir == "" {
		return fmt.Errorf("--run is required")
	}
	if err := os.MkdirAll(*runDir, 0o700); err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}

	// Two pipes, because the handshake runs in both directions:
	//   fd 3  P0 -> P1  "your uid map is written, you may re-exec"
	//   fd 4  P1 -> P0  "I am up, here is what I am"
	goR, goW, err := os.Pipe()
	if err != nil {
		return err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return err
	}
	// fd 5: the lifeline. P0 holds the write end and never writes to it; the
	// stage sees EOF the moment P0 dies, whatever killed it.
	//
	// This exists because Pdeathsig DOES NOT SURVIVE the stage's re-exec —
	// measured, see stage1. A supervisor that leaks its whole tree when the
	// launcher is SIGKILLed is worse than no supervisor.
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer lifeW.Close()

	// With --single-uid-map there is no privileged transition, so the __stage0
	// detour that exists ONLY to delay the real exec until newuidmap has run from
	// the parent is pointless: Go writes a single-entry uid_map itself, from
	// WITHIN the child, between clone and execve — which is unprivileged exactly
	// when the map's one entry is the calling process's own real uid — so the
	// child already has euid 0-in-U at the moment it execs __stage1 directly.
	stageVerb := "__stage0"
	if *singleUidMap {
		stageVerb = "__stage1"
	}
	cmd := exec.Command(self, stageVerb)
	cmd.Env = []string{
		"NSD_SELF=" + self,
		"NSD_RUN=" + *runDir,
		"NSD_BIND=" + *bindDir,
		"NSD_HOST_UID=" + strconv.Itoa(os.Getuid()),
		"NSD_HOST_GID=" + strconv.Itoa(os.Getgid()),
		"NSD_P1_OUTSIDE_N=" + boolArg(*outsideN),
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{goR, readyW, lifeR}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// One clone(2) creates all four. CLONE_NEWNET and CLONE_NEWCGROUP each
		// need CAP_SYS_ADMIN/CAP_NET_ADMIN, which the child gets *in the
		// namespace being created* precisely because CLONE_NEWUSER is in the
		// same call. Split into two steps and it fails.
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP,
		Pdeathsig: syscall.SIGKILL,
	}
	if *singleUidMap {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		}
		// Deny setgroups first — required before an unprivileged process may
		// write its gid_map at all (man 7 user_namespaces).
		cmd.SysProcAttr.GidMappingsEnableSetgroups = false
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting stage: %w", err)
	}
	goR.Close()
	readyW.Close()
	lifeR.Close()
	pid := cmd.Process.Pid

	// PIN N NOW, before P1 can move. The child is blocked reading the go pipe and
	// has not re-exec'd, so /proc/<pid>/ns/net is still N — this is the last
	// moment at which that path is guaranteed to name it. Captured whether or not
	// --p1-outside-n is set, so that the two topologies differ in one place only.
	pinnedN, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("pinning the stage's netns: %w", err)
	}
	defer pinnedN.Close()

	if !*singleUidMap {
		// Full subuid delegation. This is the step that needs newuidmap's file
		// capability; a process cannot write more than its own uid into its
		// child's uid_map by itself.
		if err := writeFullMaps(pid); err != nil {
			_ = cmd.Process.Kill()
			return err
		}
		if _, err := goW.Write([]byte("go\n")); err != nil {
			return err
		}
	}
	// --single-uid-map: the map was written by Go before __stage1 ever ran, so
	// there is nothing to signal — stage1() does not read fd 3 in this mode.

	line, err := bufio.NewReader(readyR).ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("stage never reported ready: %w", err)
	}
	fmt.Printf("P0: stage ready: %s", line)
	stageNetnsFD := readyField(line, "netns_fd")

	var pasta *exec.Cmd
	if *withNet {
		// Three cases, and the middle one is the bug this flag exists to show.
		//   not moving           /proc/<P1>/ns/net IS N. Unchanged.
		//   moving, naive        the same path, which now names N'. WRONG.
		//   moving, pinned       the descriptor captured above, handed to pasta
		//                        as fd 3 and named /proc/self/fd/3 in ITS process.
		netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
		aim := "P1's own /proc/<pid>/ns/net"
		if *outsideN && !*pastaNaive {
			// MEASURED, and this is the surprise: handing pasta the descriptor
			// itself (ExtraFiles + --netns /proc/self/fd/3) is REFUSED —
			// "Couldn't open network namespace /proc/self/fd/3: Permission
			// denied". pasta drops privileges before it opens the path, so the
			// reference has to be one it can open afterwards. P1's own fd table
			// is such a reference and is just as pinned: /proc/<P1>/fd/<n> names
			// the descriptor P1 captured before it moved, not P1's netns.
			if stageNetnsFD == "" {
				_ = cmd.Process.Kill()
				return fmt.Errorf("stage did not report netns_fd; cannot aim pasta at N")
			}
			netnsPath = fmt.Sprintf("/proc/%d/fd/%s", pid, stageNetnsFD)
			aim = "the descriptor P1 pinned before it moved"
		}
		fmt.Printf("P0: aiming pasta at %s (%s)\n", netnsPath, aim)
		pasta = exec.Command("pasta", pastaArgs(pid, netnsPath)...)
		pasta.Env = []string{}
		pasta.Stderr = os.Stderr
		pasta.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := pasta.Start(); err != nil {
			_ = cmd.Process.Kill()
			return fmt.Errorf("starting pasta: %w", err)
		}
		// Where to look for the interface has to follow where pasta was aimed —
		// /proc/<P1>/net/dev is P1's netns, which after the move is not N.
		waitErr := waitForNetDevice(pid)
		if *outsideN && !*pastaNaive {
			waitErr = waitForNetDeviceInN(*runDir)
		}
		if waitErr != nil {
			_ = cmd.Process.Kill()
			return waitErr
		}
		fmt.Printf("P0: pasta up (pid %d)\n", pasta.Process.Pid)
	}

	// Signal readiness to whoever is driving us.
	if err := os.WriteFile(filepath.Join(*runDir, "ready"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-sig:
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
		}
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "P0: stage exited: %v\n", err)
		}
	}
	if pasta != nil && pasta.Process != nil {
		_ = pasta.Process.Signal(syscall.SIGTERM)
	}
	return nil
}

// writeFullMaps delegates the whole subuid/subgid range to the stage's userns.
//
// Podman needs it: a single-uid map fails with "potentially insufficient UIDs or
// GIDs available in user namespace (requested 0:42 for /etc/shadow)".
func writeFullMaps(pid int) error {
	uid, gid := os.Getuid(), os.Getgid()
	subUID, err := subordinateRange("/etc/subuid")
	if err != nil {
		return err
	}
	subGID, err := subordinateRange("/etc/subgid")
	if err != nil {
		return err
	}
	p := strconv.Itoa(pid)
	// inside-id  outside-id  count
	uargs := []string{p, "0", strconv.Itoa(uid), "1", "1", strconv.Itoa(subUID.start), strconv.Itoa(subUID.count)}
	gargs := []string{p, "0", strconv.Itoa(gid), "1", "1", strconv.Itoa(subGID.start), strconv.Itoa(subGID.count)}
	if out, err := exec.Command("newuidmap", uargs...).CombinedOutput(); err != nil {
		return fmt.Errorf("newuidmap %v: %v: %s", uargs, err, out)
	}
	if out, err := exec.Command("newgidmap", gargs...).CombinedOutput(); err != nil {
		return fmt.Errorf("newgidmap %v: %v: %s", gargs, err, out)
	}
	return nil
}

type idRange struct{ start, count int }

func subordinateRange(file string) (idRange, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return idRange{}, err
	}
	me := currentUserNames()
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Split(strings.TrimSpace(ln), ":")
		if len(f) != 3 {
			continue
		}
		if !me[f[0]] {
			continue
		}
		start, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		return idRange{start, count}, nil
	}
	return idRange{}, fmt.Errorf("no entry for this user in %s — add one with usermod --add-subuids", file)
}

func currentUserNames() map[string]bool {
	m := map[string]bool{strconv.Itoa(os.Getuid()): true}
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		want := ":" + strconv.Itoa(os.Getuid()) + ":"
		for _, ln := range strings.Split(string(data), "\n") {
			if strings.Contains(ln, want) {
				m[strings.SplitN(ln, ":", 2)[0]] = true
			}
		}
	}
	if u := os.Getenv("USER"); u != "" {
		m[u] = true
	}
	return m
}

// stage0 is the first instant of P1's life: unmapped, uid 65534, and — this is
// the part that is easy to get wrong — with NO capabilities.
//
// clone(CLONE_NEWUSER) grants the child a full capability set in the new
// namespace, but Go cannot call clone without exec, and execve recalculates
// capabilities: euid is the overflow uid, the file has no file capabilities, so
// everything is dropped. The fix is to re-exec once the map exists, because by
// then euid is 0 and root's exec rules hand the caps back.
func stage0() error {
	goPipe := os.NewFile(3, "go")
	buf := make([]byte, 1)
	if _, err := goPipe.Read(buf); err != nil {
		return fmt.Errorf("stage0 handshake: %w", err)
	}
	goPipe.Close()

	// fds 4 and 5 must survive execve: Go marks ExtraFiles CLOEXEC-free for the
	// fork, but syscall.Exec is a different boundary.
	for _, fd := range []uintptr{4, 5} {
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0); errno != 0 {
			return fmt.Errorf("clearing CLOEXEC on fd %d: %v", fd, errno)
		}
	}
	self := os.Getenv("NSD_SELF")
	return syscall.Exec(self, []string{"nsd", "__stage1"}, os.Environ())
}

// stage1 is P1 proper.
func stage1() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("stage1: uid is %d, expected 0 — the uid map did not land", os.Getuid())
	}
	if err := checkCaps(); err != nil {
		return err
	}

	// Two reasons, both load-bearing: overlayfs refuses to work in a shared
	// tree, and the engine's per-container netns binds must not propagate to the
	// host, where they would pin namespaces with no process attached.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making / private: %w", err)
	}

	// lo comes up in N, while P1 is still in it. After the move this command
	// would configure the WRONG namespace.
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bringing lo up: %v: %s", err, out)
	}

	if os.Getenv("NSD_P1_OUTSIDE_N") == "1" {
		return moveOutOfN() // execs __stage2; does not return on success
	}
	return serveStage(nil, nsID("net"))
}

// moveOutOfN is Phase 0b, steps 2 and 3 — and the shape it has is forced by a
// fact the plan does not mention.
//
// MEASURED: unshare(CLONE_NEWNET) moves the CALLING THREAD, not the process.
// nsproxy is per-task, so in a Go program the goroutine's thread leaves N and
// every other runtime thread stays in it. A process split across two network
// namespaces is worse than one in N: it looks moved and is not, and which
// namespace a socket lands in then depends on the scheduler.
//
// The only join point where a multithreaded Go process can move as a whole is
// execve: it collapses the thread group onto the CALLING thread, so the new
// image is single-threaded in that thread's namespaces, and every thread the
// runtime starts afterwards inherits them. So the sequence is unshare-then-exec,
// on a locked thread, with nothing in between.
//
// Consequence for step 2 of the plan: the pinned descriptor must NOT be CLOEXEC
// here, because it has to survive the very exec that makes the move stick. It is
// re-marked CLOEXEC in stage2, which is the first moment CLOEXEC means what the
// plan intends.
func moveOutOfN() error {
	runtime.LockOSThread()

	// /proc/thread-self, not /proc/self: /proc/self is the thread GROUP leader,
	// and after a per-thread unshare it reports the namespace this thread just
	// left. Reading the wrong one is how "the move worked" gets asserted about a
	// process that never moved.
	before := threadNS("net")
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("pinning N: %w", err)
	}
	fd := f.Fd()
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0); errno != 0 {
		return fmt.Errorf("clearing CLOEXEC on the pinned netns fd: %v", errno)
	}

	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
	}
	after := threadNS("net")
	if before == after {
		return fmt.Errorf("unshare(CLONE_NEWNET) reported success but the calling thread is still in %s", before)
	}
	fmt.Fprintf(os.Stderr, "P1: left N: pinned=%s now(thread)=%s leader=%s\n", before, after, nsID("net"))

	env := append(os.Environ(),
		"NSD_NETNS_FD="+strconv.Itoa(int(fd)),
		"NSD_PINNED_NETNS="+before)
	return syscall.Exec(os.Getenv("NSD_SELF"), []string{"nsd", "__stage2"}, env)
}

// stage2 is P1 after the move: same pid, same mount/user/cgroup namespaces, a
// fresh empty netns of its own, and one descriptor on N.
func stage2() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("stage2: uid is %d, expected 0", os.Getuid())
	}
	if err := checkCaps(); err != nil {
		return fmt.Errorf("stage2: %w", err)
	}
	fd, err := strconv.Atoi(os.Getenv("NSD_NETNS_FD"))
	if err != nil {
		return fmt.Errorf("stage2: NSD_NETNS_FD: %w", err)
	}
	// NOW it is CLOEXEC: from here on the only way this descriptor reaches a
	// child is by being named in ExtraFiles, which is what inNetnsCmd does.
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
		return fmt.Errorf("stage2: marking the netns fd CLOEXEC: %v", errno)
	}
	n := os.NewFile(uintptr(fd), "netns-N")
	pinned := os.Getenv("NSD_PINNED_NETNS")
	if pinned == nsID("net") {
		return fmt.Errorf("stage2: P1 is still in the pinned namespace %s — the move did not survive the exec", pinned)
	}
	return serveStage(n, pinned)
}

// serveStage is everything both topologies do once P1 is where it belongs.
func serveStage(n *os.File, pinned string) error {
	netnsN = n
	pinnedNetnsID = pinned

	runDir := os.Getenv("NSD_RUN")
	srv, err := listenControl(filepath.Join(runDir, "control.sock"))
	if err != nil {
		return err
	}

	go watchLifeline(os.NewFile(5, "lifeline"), srv)

	netnsFD := -1
	if n != nil {
		netnsFD = int(n.Fd())
	}
	ready := os.NewFile(4, "ready")
	fmt.Fprintf(ready, "pid=%d uid=%d netns=%s pinned_netns=%s netns_fd=%d userns=%s cgroupns=%s mntns=%s\n",
		os.Getpid(), os.Getuid(), nsID("net"), pinned, netnsFD, nsID("user"), nsID("cgroup"), nsID("mnt"))
	ready.Close()

	return srv.serve()
}

// enterNetns is step 4: the only way a child of P1 gets back into N.
//
// It runs between fork and exec in the only sense Go offers — a separate exec of
// this same binary, which then setns's on a locked thread and execs the real
// program. setns(CLONE_NEWNET) is per-thread exactly as unshare is, so the same
// unshare-then-exec discipline applies; there is no single-thread requirement,
// which is a CLONE_NEWUSER rule and does not reach here.
//
// The descriptor is CLOSED before the exec, so nothing downstream of this point
// — bwrap, the payload, a container — ever holds a reference to N that it could
// setns with if it somehow acquired CAP_SYS_ADMIN.
func enterNetns(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("usage: __innetns FD CMD [ARGS...]")
	}
	fd, err := strconv.Atoi(argv[0])
	if err != nil {
		return fmt.Errorf("__innetns: bad fd %q: %w", argv[0], err)
	}
	runtime.LockOSThread()
	before := threadNS("net")
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("__innetns: sysSetns is the x86_64 number and this is %s", runtime.GOARCH)
	}
	if _, _, errno := syscall.RawSyscall(sysSetns, uintptr(fd), uintptr(syscall.CLONE_NEWNET), 0); errno != 0 {
		return fmt.Errorf("__innetns: setns(net): %v", errno)
	}
	after := threadNS("net")
	if before == after {
		return fmt.Errorf("__innetns: setns reported success but the thread is still in %s", before)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("__innetns: closing the netns fd: %w", err)
	}
	path := argv[1]
	if !strings.Contains(path, "/") {
		p, err := exec.LookPath(path)
		if err != nil {
			return fmt.Errorf("__innetns: %w", err)
		}
		path = p
	}
	return syscall.Exec(path, argv[1:], os.Environ())
}

// readyField pulls one key=value out of the stage's ready line.
func readyField(line, key string) string {
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func threadNS(kind string) string {
	s, err := os.Readlink("/proc/thread-self/ns/" + kind)
	if err != nil {
		return "?"
	}
	return s
}

func checkCaps() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, "CapEff:") {
			v := strings.TrimSpace(strings.TrimPrefix(ln, "CapEff:"))
			if v == "0000000000000000" {
				return fmt.Errorf("stage1: CapEff is zero — re-exec did not restore capabilities")
			}
			return nil
		}
	}
	return fmt.Errorf("stage1: no CapEff line in /proc/self/status")
}

func nsID(kind string) string {
	s, err := os.Readlink("/proc/self/ns/" + kind)
	if err != nil {
		return "?"
	}
	return s
}

func waitForNetDevice(pid int) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", pid))
		if err == nil {
			for i, ln := range strings.Split(string(data), "\n") {
				if i < 2 {
					continue
				}
				name, _, ok := strings.Cut(strings.TrimSpace(ln), ":")
				if ok && strings.TrimSpace(name) != "lo" {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pasta did not bring up an interface within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForNetDeviceInN asks P1 to look, because after the move P0 has no path
// that names N's procfs. This is the same class of change as aiming pasta: every
// reference to N that used to be spelled /proc/<P1>/... has to be re-sourced.
func waitForNetDeviceInN(runDir string) error {
	deadline := time.Now().Add(3 * time.Second)
	var last string
	for {
		resp, err := call(runDir, request{Op: "run", Argv: []string{"/usr/bin/cat", "/proc/self/net/dev"}})
		if err == nil && resp.OK {
			last = resp.Out
			for i, ln := range strings.Split(resp.Out, "\n") {
				if i < 2 {
					continue
				}
				name, _, ok := strings.Cut(strings.TrimSpace(ln), ":")
				if ok && strings.TrimSpace(name) != "lo" {
					return nil
				}
			}
		} else if err != nil {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pasta did not bring up an interface in N within 3s; /proc/self/net/dev in N was:\n%s", last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// watchLifeline is the teardown trigger.
//
// MEASURED, and it is the sharpest thing this proof of concept found: the stage
// re-exec that restores capabilities ALSO clears PR_SET_PDEATHSIG. execve sets
// bprm->secureexec whenever the new permitted capability set is not a subset of
// the old one, and secureexec zeroes pdeath_signal so that a parent cannot
// signal a process that just became more privileged. So `Pdeathsig: SIGKILL` on
// the stage is silently a no-op: SIGKILL the launcher and the entire tree —
// stage, bwrap, sandbox, every attached process — survives, reparented to init.
//
// (Pdeathsig is doubly unreliable from Go anyway: it fires when the parent
// THREAD exits, and the Go runtime does not promise which thread forked.)
//
// A pipe has none of those semantics to get wrong.
func watchLifeline(f *os.File, srv *server) {
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "P1: lifeline closed, tearing down")
	srv.dispatch(request{Op: "kill"})
	// Everything else in the sandbox is in its pid namespace, whose init is
	// bwrap's child; killing bwrap collapses it. The engine stage, when there is
	// one, is a direct child and gets the same treatment.
	os.Exit(1)
}
