package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The control protocol. Newline-delimited JSON, one request per connection.
//
// Deliberately NOT varlink, and the reason is worth recording: the attach path
// has to move file descriptors (a pty, or the client's stdio) between processes,
// and varlink has no notion of SCM_RIGHTS. A protocol that cannot carry an fd
// forces a byte-relay design anyway, at which point the IDL is buying nothing.
type request struct {
	Op       string   `json:"op"`
	Argv     []string `json:"argv,omitempty"`
	Target   int      `json:"target,omitempty"`
	DropCaps bool     `json:"drop_caps,omitempty"`
}

type response struct {
	OK   bool              `json:"ok"`
	Out  string            `json:"out,omitempty"`
	Err  string            `json:"err,omitempty"`
	Data map[string]string `json:"data,omitempty"`
}

type server struct {
	ln  net.Listener
	mu  sync.Mutex
	box *sandboxHandle
}

type sandboxHandle struct {
	cmd     *exec.Cmd // bwrap
	initPID int       // pid of the sandbox's init, in P1's pid namespace
}

func listenControl(path string) (*server, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return &server{ln: ln}, nil
}

func (s *server) serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	var req request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResp(conn, response{Err: "bad request: " + err.Error()})
		return
	}
	writeResp(conn, s.dispatch(req))
}

func writeResp(conn net.Conn, r response) {
	b, _ := json.Marshal(r)
	_, _ = conn.Write(append(b, '\n'))
}

func (s *server) dispatch(req request) response {
	switch req.Op {
	case "ping":
		return response{OK: true, Out: "pong"}
	case "info":
		s.mu.Lock()
		box := s.box
		s.mu.Unlock()
		d := map[string]string{
			"stage_pid": strconv.Itoa(os.Getpid()),
			"uid":       strconv.Itoa(os.Getuid()),
			"netns":     nsID("net"),
			"userns":    nsID("user"),
			"mntns":     nsID("mnt"),
			"cgroupns":  nsID("cgroup"),
		}
		if box != nil {
			d["sandbox_init_pid"] = strconv.Itoa(box.initPID)
		}
		return response{OK: true, Data: d}
	case "run":
		return runChild(req.Argv, false)
	case "runmnt":
		// Engine-shaped child: same U and N, but a private copy of the HOST
		// mount tree rather than the sandbox's.
		return runChild(req.Argv, true)
	case "sandbox":
		return s.startSandbox()
	case "attach":
		return s.attach(req)
	case "kill":
		return s.killSandbox()
	}
	return response{Err: "unknown op " + req.Op}
}

func runChild(argv []string, ownMountNS bool) response {
	if len(argv) == 0 {
		return response{Err: "empty argv"}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + os.Getenv("HOME")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if ownMountNS {
		// Go additionally remounts / as MS_REC|MS_PRIVATE when this is set,
		// which is exactly what overlayfs and the engine's netns binds need.
		cmd.SysProcAttr.Unshareflags = syscall.CLONE_NEWNS
	}
	out, err := cmd.CombinedOutput()
	r := response{OK: err == nil, Out: string(out)}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// startSandbox is P2. bwrap is a plain child of P1, so it inherits U and N by
// descent; it then builds the sandbox's mount, pid, ipc and uts namespaces on
// top. --unshare-net is deliberately absent.
func (s *server) startSandbox() response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.box != nil {
		return response{Err: "a sandbox is already running"}
	}

	statusR, statusW, err := os.Pipe()
	if err != nil {
		return response{Err: err.Error()}
	}
	defer statusR.Close()
	// bwrap announces the child pid as soon as the child EXISTS, which is well
	// before its mounts are in place. Attaching on the strength of that pid
	// lands a process in a half-built mount namespace, and the symptom is
	// execve returning ENOENT for a binary that stat() can see a moment later.
	// So the sandbox's own init reports readiness on its own pipe.
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return response{Err: err.Error()}
	}
	defer readyR.Close()

	self := os.Getenv("NSD_SELF")
	bind := os.Getenv("NSD_BIND")
	runDir := os.Getenv("NSD_RUN")
	hostUID := os.Getenv("NSD_HOST_UID")
	hostGID := os.Getenv("NSD_HOST_GID")

	args := []string{
		"--die-with-parent",
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		// N is inherited. This is the whole point of the topology.
		"--uid", hostUID, "--gid", hostGID,
		"--tmpfs", "/",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/sbin", "/sbin",
		"--ro-bind", "/etc", "/etc",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--ro-bind", self, "/nsd",
		"--json-status-fd", "3",
	}
	if bind != "" {
		args = append(args, "--bind", bind, "/work")
	}
	args = append(args, "--", "/nsd", "__sandbox-init")

	cmd := exec.Command("bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NSD_RUN=" + runDir}
	cmd.ExtraFiles = []*os.File{statusW, readyW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	logf, err := os.Create(filepath.Join(runDir, "sandbox.log"))
	if err != nil {
		return response{Err: err.Error()}
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return response{Err: "starting bwrap: " + err.Error()}
	}
	statusW.Close()
	readyW.Close()

	pid, err := readChildPID(statusR)
	if err != nil {
		_ = cmd.Process.Kill()
		return response{Err: err.Error()}
	}
	if err := waitReady(readyR); err != nil {
		_ = cmd.Process.Kill()
		return response{Err: err.Error()}
	}
	s.box = &sandboxHandle{cmd: cmd, initPID: pid}
	go func() { _ = cmd.Wait() }()

	return response{OK: true, Data: map[string]string{
		"sandbox_init_pid": strconv.Itoa(pid),
		"bwrap_pid":        strconv.Itoa(cmd.Process.Pid),
	}}
}

// waitReady blocks until the sandbox's init says its filesystem is real.
func waitReady(r *os.File) error {
	type res struct{ err error }
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := r.Read(buf)
		ch <- res{err}
	}()
	select {
	case v := <-ch:
		return v.err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("sandbox init never reported ready")
	}
}

func readChildPID(r *os.File) (int, error) {
	dec := json.NewDecoder(r)
	for {
		var st struct {
			ChildPID int `json:"child-pid"`
		}
		if err := dec.Decode(&st); err != nil {
			return 0, fmt.Errorf("reading bwrap status: %w", err)
		}
		if st.ChildPID != 0 {
			return st.ChildPID, nil
		}
	}
}

// attach is the tmux-shaped operation: put a NEW process into an ALREADY RUNNING
// sandbox's namespaces, from outside, without any socket inside the sandbox.
//
// It works — if it works — because of the ancestor rule in user_namespaces(7): a
// process has every capability in a child user namespace whose owner uid equals
// its own euid. P1 is uid 0 in U; bwrap ran as uid 0 in U, so U2's owner is 0;
// therefore P1 holds CAP_SYS_ADMIN in U2 and may setns into it.
//
// That same sentence is the danger: setns(CLONE_NEWUSER) hands the joiner a full
// capability set inside U2. Unless the joiner drops them it is a root-shaped
// process inside a sandbox that assumes nobody has capabilities. DropCaps=false
// exists so the experiment can measure that, not because it is ever right.
func (s *server) attach(req request) response {
	s.mu.Lock()
	box := s.box
	s.mu.Unlock()

	target := req.Target
	if target == 0 {
		if box == nil {
			return response{Err: "no sandbox running and no --target given"}
		}
		target = box.initPID
	}
	if len(req.Argv) == 0 {
		return response{Err: "empty argv"}
	}

	joiner := filepath.Join(filepath.Dir(os.Getenv("NSD_SELF")), "nsdjoin")
	argv := append([]string{strconv.Itoa(target), boolArg(req.DropCaps)}, req.Argv...)
	cmd := exec.Command(joiner, argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.CombinedOutput()
	r := response{OK: err == nil, Out: string(out)}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

func boolArg(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (s *server) killSandbox() response {
	s.mu.Lock()
	box := s.box
	s.box = nil
	s.mu.Unlock()
	if box == nil {
		return response{OK: true, Out: "no sandbox"}
	}
	_ = box.cmd.Process.Signal(syscall.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	_ = box.cmd.Process.Kill()
	return response{OK: true}
}

// sandboxInit is PID 1 inside the sandbox. It does nothing but exist, so that
// there is something to attach to.
func sandboxInit() error {
	fmt.Printf("SANDBOX-INIT pid=%d uid=%d netns=%s userns=%s mntns=%s pidns=%s\n",
		os.Getpid(), os.Getuid(), nsID("net"), nsID("user"), nsID("mnt"), nsID("pid"))
	if err := os.WriteFile("/tmp/marker-from-init", []byte("init was here\n"), 0o600); err != nil {
		fmt.Printf("SANDBOX-INIT tmp write failed: %v\n", err)
	}
	if err := os.WriteFile("/work/written-by-sandbox", []byte("payload wrote this\n"), 0o600); err != nil {
		fmt.Printf("SANDBOX-INIT work write failed: %v\n", err)
	}
	fmt.Println("SANDBOX-INIT ready")
	os.Stdout.Sync()
	ready := os.NewFile(4, "ready")
	if _, err := ready.Write([]byte("READY\n")); err != nil {
		fmt.Printf("SANDBOX-INIT could not report ready: %v\n", err)
	}
	ready.Close()
	select {}
}

// cmdProbe prints everything an experiment might want to assert about the
// process that runs it.
func cmdProbe(argv []string) error {
	fmt.Printf("pid=%d uid=%d gid=%d\n", os.Getpid(), os.Getuid(), os.Getgid())
	for _, k := range []string{"user", "net", "mnt", "pid", "ipc", "uts", "cgroup"} {
		fmt.Printf("ns.%s=%s\n", k, nsID(k))
	}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, ln := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(ln, "Cap") || strings.HasPrefix(ln, "Seccomp:") ||
				strings.HasPrefix(ln, "NoNewPrivs:") {
				fmt.Println(strings.Join(strings.Fields(ln), " "))
			}
		}
	}
	for _, a := range argv {
		if st, err := os.Stat(a); err == nil {
			fmt.Printf("stat %s ok mode=%v\n", a, st.Mode())
		} else {
			fmt.Printf("stat %s ERR %v\n", a, err)
		}
	}
	return nil
}

// cmdCtl is the client. In the real thing this is `snug attach`.
func cmdCtl(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("usage: nsd ctl RUNDIR OP [args...]")
	}
	runDir, op := argv[0], argv[1]
	req := request{Op: op}
	rest := argv[2:]
	// A couple of ops take a leading numeric target.
	if op == "attach" {
		if len(rest) < 2 {
			return fmt.Errorf("usage: nsd ctl DIR attach TARGETPID DROPCAPS cmd...")
		}
		t, err := strconv.Atoi(rest[0])
		if err != nil {
			return err
		}
		req.Target = t
		req.DropCaps = rest[1] == "1"
		rest = rest[2:]
	}
	req.Argv = rest

	conn, err := net.Dial("unix", filepath.Join(runDir, "control.sock"))
	if err != nil {
		return err
	}
	defer conn.Close()
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	var resp response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return err
	}
	if resp.Out != "" {
		fmt.Print(resp.Out)
		if !strings.HasSuffix(resp.Out, "\n") {
			fmt.Println()
		}
	}
	for k, v := range resp.Data {
		fmt.Printf("%s=%s\n", k, v)
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Err)
	}
	return nil
}
