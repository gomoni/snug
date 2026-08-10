package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The pasta closing set, copied verbatim from internal/policy/net.go. Any one of
// the last four missing re-opens host loopback.
func pastaArgs(stagePID int) []string {
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
		"--netns", fmt.Sprintf("/proc/%d/ns/net", stagePID),
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

	cmd := exec.Command(self, "__stage0")
	cmd.Env = []string{
		"NSD_SELF=" + self,
		"NSD_RUN=" + *runDir,
		"NSD_BIND=" + *bindDir,
		"NSD_HOST_UID=" + strconv.Itoa(os.Getuid()),
		"NSD_HOST_GID=" + strconv.Itoa(os.Getgid()),
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
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting stage: %w", err)
	}
	goR.Close()
	readyW.Close()
	lifeR.Close()
	pid := cmd.Process.Pid

	// Full subuid delegation. This is the step that needs newuidmap's file
	// capability; a process cannot write more than its own uid into its child's
	// uid_map by itself.
	if err := writeFullMaps(pid); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	if _, err := goW.Write([]byte("go\n")); err != nil {
		return err
	}

	line, err := bufio.NewReader(readyR).ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("stage never reported ready: %w", err)
	}
	fmt.Printf("P0: stage ready: %s", line)

	var pasta *exec.Cmd
	if *withNet {
		pasta = exec.Command("pasta", pastaArgs(pid)...)
		pasta.Env = []string{}
		pasta.Stderr = os.Stderr
		pasta.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := pasta.Start(); err != nil {
			_ = cmd.Process.Kill()
			return fmt.Errorf("starting pasta: %w", err)
		}
		if err := waitForNetDevice(pid); err != nil {
			_ = cmd.Process.Kill()
			return err
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

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bringing lo up: %v: %s", err, out)
	}

	runDir := os.Getenv("NSD_RUN")
	srv, err := listenControl(filepath.Join(runDir, "control.sock"))
	if err != nil {
		return err
	}

	go watchLifeline(os.NewFile(5, "lifeline"), srv)

	ready := os.NewFile(4, "ready")
	fmt.Fprintf(ready, "pid=%d uid=%d netns=%s userns=%s cgroupns=%s mntns=%s\n",
		os.Getpid(), os.Getuid(), nsID("net"), nsID("user"), nsID("cgroup"), nsID("mnt"))
	ready.Close()

	return srv.serve()
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
