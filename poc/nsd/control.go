package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	TTL      int      `json:"ttl,omitempty"` // sandbox init exits after this many seconds

	// ArgvFile is a host path to a NUL-separated bwrap argv, exactly as
	// policy.Policy.BwrapFlags would produce for a REAL Run() invocation — used
	// by "realbox" so Step 0 measures against snug's real code path rather than
	// the PoC's own hand-maintained bwrapBaseArgs(). A sibling
	// "<argvfile-dir>/manifest.json" names the --ro-bind-data/--file fds the argv
	// references and the plain host file holding each one's content. See
	// SUPERVISOR-PHASE1-SPEC.md §4 Step 0.
	ArgvFile string `json:"argv_file,omitempty"`
}

// netnsN is P1's only reference to N once it has left. nil means P1 never left —
// the topology run.sh measures — and every child is in N by descent, as before.
//
// pinnedNetnsID is the readlink form of N, reported over the control socket so a
// test can compare it against /proc/<sandbox>/ns/net without ever asking P1 for
// its own, which after the move is the wrong answer.
var (
	netnsN        *os.File
	pinnedNetnsID string
)

// inNetnsCmd builds a command that will run inside N.
//
// pre are descriptors the FINAL program must receive at fds 3, 4, …; the netns
// reference is appended after them, so their numbering is unchanged and the
// helper knows where to find it. When netnsN is nil this is exec.Command with
// its ExtraFiles set, byte for byte the old behaviour.
func inNetnsCmd(pre []*os.File, name string, args ...string) *exec.Cmd {
	if netnsN == nil {
		c := exec.Command(name, args...)
		c.ExtraFiles = pre
		return c
	}
	fd := 3 + len(pre)
	argv := append([]string{"__innetns", strconv.Itoa(fd), name}, args...)
	c := exec.Command(os.Getenv("NSD_SELF"), argv...)
	c.ExtraFiles = append(append([]*os.File{}, pre...), netnsN)
	return c
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

	// P1 IS NOT A DAEMON. It holds namespaces for as long as something is using
	// them and not one second longer: when the last payload exits, the stage
	// tears itself down. Nothing here restarts, re-listens or waits for the next
	// client — that is the line between a fork and a service.
	//
	// Only payloads count: a sandbox, and any process attached to one. The
	// experiment scaffolding (run/runmnt/graft) does not, because in the real
	// thing those are not user-visible processes.
	payloads int
	everRan  bool
}

// hold and release are the reference count. release is what ends the process.
func (s *server) hold() {
	s.mu.Lock()
	s.payloads++
	s.everRan = true
	s.mu.Unlock()
}

func (s *server) release() {
	s.mu.Lock()
	s.payloads--
	last := s.payloads <= 0 && s.everRan
	s.mu.Unlock()
	if last {
		fmt.Fprintln(os.Stderr, "P1: last payload exited, tearing down")
		s.dispatch(request{Op: "kill"})
		os.Exit(0)
	}
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
			"stage_pid":    strconv.Itoa(os.Getpid()),
			"uid":          strconv.Itoa(os.Getuid()),
			"netns":        nsID("net"),
			"pinned_netns": pinnedNetnsID,
			"userns":       nsID("user"),
			"mntns":        nsID("mnt"),
			"cgroupns":     nsID("cgroup"),
			"p1_outside_n": boolArg(netnsN != nil),
		}
		if box != nil {
			d["sandbox_init_pid"] = strconv.Itoa(box.initPID)
		}
		return response{OK: true, Data: d}
	case "run":
		return runChild(req.Argv, false, true)
	case "runmnt":
		// Engine-shaped child: same U and N, but a private copy of the HOST
		// mount tree rather than the sandbox's.
		return runChild(req.Argv, true, true)
	case "runstage":
		// The control for every "run" assertion: same everything, except that it
		// stays in P1's OWN network namespace instead of being put back into N.
		return runChild(req.Argv, false, false)
	case "boxcmd":
		return s.boxcmd(req.Argv)
	case "realbox":
		return s.realbox(req.ArgvFile)
	case "bindabstract":
		return s.bindAbstract(req.Argv)
	case "sandbox":
		return s.startSandbox(req.TTL)
	case "attach":
		return s.attach(req)
	case "graft":
		return s.graft(req)
	case "kill":
		return s.killSandbox()
	}
	return response{Err: "unknown op " + req.Op}
}

func runChild(argv []string, ownMountNS, inN bool) response {
	if len(argv) == 0 {
		return response{Err: "empty argv"}
	}
	var cmd *exec.Cmd
	if inN {
		cmd = inNetnsCmd(nil, argv[0], argv[1:]...)
	} else {
		cmd = exec.Command(argv[0], argv[1:]...)
	}
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

// bwrapBaseArgs is the sandbox's shape, shared by the long-lived sandbox and by
// boxcmd, so that a one-shot probe is not a differently-configured sandbox.
func bwrapBaseArgs() []string {
	self := os.Getenv("NSD_SELF")
	bind := os.Getenv("NSD_BIND")
	args := []string{
		"--die-with-parent",
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		// N is inherited. This is the whole point of the topology.
		"--uid", os.Getenv("NSD_HOST_UID"), "--gid", os.Getenv("NSD_HOST_GID"),
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
	}
	if bind != "" {
		args = append(args, "--bind", bind, "/work")
	}
	return args
}

// boxcmd runs one command in a sandbox built exactly like the long-lived one.
//
// It exists so that the network-namespace questions can be answered without
// depending on the setns joiner: everything asked here is a property of N, and a
// second bwrap child of P1 is in N by precisely the same mechanism as the first.
func (s *server) boxcmd(argv []string) response {
	if len(argv) == 0 {
		return response{Err: "empty argv"}
	}
	args := append(bwrapBaseArgs(), "--")
	args = append(args, argv...)
	cmd := inNetnsCmd(nil, "bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// Deliberately NOT hold()/release(): boxcmd is experiment scaffolding, and a
	// scaffolding process that takes the payload reference count from 0 to 1 and
	// back tears the whole stage down between two checks. MEASURED — the second
	// probe of a run got "EOF" from a P1 that had correctly decided its last
	// payload had exited.
	out, err := cmd.CombinedOutput()
	r := response{OK: err == nil, Out: string(out)}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// realbox runs bwrap with the EXACT argv snug's own BwrapFlags produced —
// dumped NUL-separated to argvFile by cmd/snug's Step 0 measurement helper —
// rather than the PoC's own hand-maintained bwrapBaseArgs(). This is the "have
// the PoC start it as the sandbox child rather than a hand-built bwrap" half of
// SUPERVISOR-PHASE1-SPEC.md §4 Step 0.
func (s *server) realbox(argvFile string) response {
	if argvFile == "" {
		return response{Err: "realbox: argv_file is required"}
	}
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		return response{Err: "realbox: reading argv file: " + err.Error()}
	}
	var args []string
	for _, a := range strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00") {
		args = append(args, a)
	}
	if len(args) == 0 {
		return response{Err: "realbox: argv file was empty"}
	}

	// The sibling manifest.json (data-fd -> content file), if present. The
	// entries must be dense from fd 3 upward — exec.Cmd.ExtraFiles has no other
	// way to place a descriptor at a specific child number — which is exactly
	// how internal/sandbox.Run() itself allocates them.
	var pre []*os.File
	manifestPath := filepath.Join(filepath.Dir(argvFile), "manifest.json")
	if mb, err := os.ReadFile(manifestPath); err == nil {
		var entries []struct {
			FD    int    `json:"fd"`
			Guest string `json:"guest"`
			Path  string `json:"path"`
		}
		if err := json.Unmarshal(mb, &entries); err != nil {
			return response{Err: "realbox: bad manifest: " + err.Error()}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].FD < entries[j].FD })
		for i, e := range entries {
			if want := 3 + i; e.FD != want {
				return response{Err: fmt.Sprintf(
					"realbox: manifest fd %d for %s is not contiguous from 3 (wanted %d)",
					e.FD, e.Guest, want)}
			}
			f, err := os.Open(e.Path)
			if err != nil {
				return response{Err: "realbox: opening " + e.Path + ": " + err.Error()}
			}
			pre = append(pre, f)
		}
	}

	cmd := inNetnsCmd(pre, "bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.CombinedOutput()
	for _, f := range pre {
		_ = f.Close()
	}
	r := response{OK: err == nil, Out: string(out)}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// bindAbstract makes P1 itself bind an abstract AF_UNIX name. Abstract names are
// scoped to the NETWORK namespace, so this is the direct test of what the move
// is for: with P1 in N the sandbox reaches it (SUPERVISOR §5, measured), with P1
// outside N it must not.
func (s *server) bindAbstract(argv []string) response {
	if len(argv) != 1 || argv[0] == "" {
		return response{Err: "usage: bindabstract NAME"}
	}
	ln, err := net.Listen("unix", "@"+argv[0])
	if err != nil {
		return response{Err: err.Error()}
	}
	heldMu.Lock()
	held = append(held, ln)
	heldMu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SECRET-FROM-P1"))
			_ = c.Close()
		}
	}()
	return response{OK: true, Out: "bound @" + argv[0] + " in " + nsID("net")}
}

var (
	heldMu sync.Mutex
	held   []net.Listener
)

// startSandbox is P2. bwrap is a plain child of P1, so it inherits U and N by
// descent; it then builds the sandbox's mount, pid, ipc and uts namespaces on
// top. --unshare-net is deliberately absent.
func (s *server) startSandbox(ttl int) response {
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

	runDir := os.Getenv("NSD_RUN")

	args := append(bwrapBaseArgs(), "--json-status-fd", "3", "--", "/nsd", "__sandbox-init")

	// bwrap is a plain child of P1 when P1 is in N, and goes through __innetns
	// when it is not. Either way the sandbox ends up in N — but note that the
	// bwrap ARGV is byte-identical in both cases, which is Phase 1's exit
	// criterion 2 arriving early: the argv no longer determines the netns.
	cmd := inNetnsCmd([]*os.File{statusW, readyW}, "bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NSD_RUN=" + runDir,
		"NSD_TTL=" + strconv.Itoa(ttl)}
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
	s.payloads++
	s.everRan = true
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		s.box = nil
		s.mu.Unlock()
		s.release()
	}()

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
	s.hold()
	defer s.release()
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

// graft runs a command in a mount namespace derived from the SANDBOX's, with one
// host path grafted in. See join/nsdmount.c — this is the engine-view experiment.
//
// Argv is [hostSrc, dest, cmd, args...].
func (s *server) graft(req request) response {
	s.mu.Lock()
	box := s.box
	s.mu.Unlock()
	target := req.Target
	if target == 0 {
		if box == nil {
			return response{Err: "no sandbox running"}
		}
		target = box.initPID
	}
	if len(req.Argv) < 3 {
		return response{Err: "graft needs SRC DEST CMD..."}
	}
	tool := filepath.Join(filepath.Dir(os.Getenv("NSD_SELF")), "nsdmount")
	cmd := exec.Command(tool, append([]string{strconv.Itoa(target)}, req.Argv...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.CombinedOutput()
	r := response{OK: err == nil, Out: string(out)}
	if err != nil {
		r.Err = err.Error()
	}
	return r
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

	if ttl, _ := strconv.Atoi(os.Getenv("NSD_TTL")); ttl > 0 {
		time.Sleep(time.Duration(ttl) * time.Second)
		fmt.Println("SANDBOX-INIT exiting")
		return nil
	}
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

// call is the whole client transport: one request, one response, one connection.
// P0 uses it too, because after the move it has no other way to look inside N.
func call(runDir string, req request) (response, error) {
	conn, err := net.Dial("unix", filepath.Join(runDir, "control.sock"))
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return response{}, err
	}
	var resp response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return response{}, err
	}
	return resp, nil
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
	if op == "realbox" {
		if len(rest) != 1 {
			return fmt.Errorf("usage: nsd ctl DIR realbox ARGVFILE")
		}
		req.ArgvFile = rest[0]
		rest = nil
	}
	if op == "sandbox" && len(rest) == 1 {
		t, err := strconv.Atoi(rest[0])
		if err != nil {
			return err
		}
		req.TTL = t
		rest = nil
	}
	req.Argv = rest

	resp, err := call(runDir, req)
	if err != nil {
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
