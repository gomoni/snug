package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

func TestKubePluginCmdEnvIsBuiltNotInherited(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "AWS_PROFILE", "KUBECONFIG", "AZURE_CONFIG_DIR", "KUBECACHEDIR"} {
		t.Setenv(k, "/from/the/repo/envrc")
	}
	argv := []string{"/usr/bin/kubelogin", "get-token"}
	env := (&policy.KubePlugin{}).KubePluginEnv("/h")
	cmd := kubeMintCmd(context.Background(), argv, env)
	if !slices.Equal(cmd.Env, env) || slices.ContainsFunc(cmd.Env, func(s string) bool { return strings.Contains(s, "envrc") }) {
		t.Errorf("Env = %q", cmd.Env)
	}
	if cmd.Dir != "/" {
		t.Errorf("Dir = %q, want /", cmd.Dir)
	}
	a := cmd.SysProcAttr
	if a == nil || a.Cloneflags&syscall.CLONE_NEWPID == 0 || a.Cloneflags&syscall.CLONE_NEWUSER == 0 ||
		a.Pdeathsig != syscall.SIGKILL {
		t.Errorf("SysProcAttr = %+v, want own user+pid namespace and Pdeathsig SIGKILL", a)
	}
}

func checkPluginIsABinary(path string) error {
	return checkHostBinaryIsELF("kube exec plugin", "kubelogin", path)
}

func TestKubePluginBinaryRefusesAScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "kubelogin")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec distrobox-enter -- kubelogin \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkPluginIsABinary(script); err == nil || !strings.Contains(err.Error(), "it is a script") {
		t.Errorf("a shim script: %v", err)
	}
}

func TestKubePluginBinaryFollowsSymlinkToELF(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "kubelogin")
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	if err := checkPluginIsABinary(link); err != nil {
		t.Errorf("a symlink to an ELF binary refused: %v", err)
	}
}

func writeStub(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubelogin")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The reason a plugin run gets its own pid namespace: cancelling it kills the
// plugin AND whatever it spawned, which a process group alone does not
// guarantee once the child setsid()s.
func TestKubePluginCancelLeavesNoGrandchild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	stub := writeStub(t, "setsid sleep 300 & echo $! > "+pidFile+"\nsleep 300\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runKubeCmd(kubeMintCmd(ctx, []string{stub}, []string{"PATH=/usr/bin:/bin"})); close(done) }()
	var pid []byte
	for range 100 {
		if pid, _ = os.ReadFile(pidFile); len(pid) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(pid) == 0 {
		t.Fatal("stub never started its grandchild")
	}
	cancel()
	<-done
	// The pid written is in the plugin's pid namespace; the grandchild is found
	// by its command line instead.
	for range 50 {
		if !sleepRunning(t, "300", os.Getpid()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a grandchild of the plugin survived its cancellation")
}

// sleepRunning reports whether a `sleep <arg>` owned by this user, started
// after this test process, is still alive.
func sleepRunning(t *testing.T, arg string, after int) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= after {
			continue
		}
		cl, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if string(cl) == "sleep\x00"+arg+"\x00" {
			return true
		}
	}
	return false
}

func TestKubeDryRunRunsNothing(t *testing.T) {
	rt := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	pol := &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{}, Env: map[string]policy.EnvVar{},
		Kube: &policy.KubeBinding{Context: "aks-dev", Credential: policy.KubeCredentialExec,
			Plugin: &policy.KubePlugin{Row: "kubelogin", Command: "snug-test-no-such-plugin"}}}
	run, err := startKubeIdentity(pol, policy.OSEnviron{}, false, true)
	if err != nil {
		t.Fatalf("a dry run refused for a missing plugin: %v", err)
	}
	if run != nil {
		t.Error("a dry run started a kube run")
	}
	ents, _ := os.ReadDir(rt)
	if len(ents) != 0 {
		t.Errorf("a dry run created %v under XDG_RUNTIME_DIR", ents)
	}
	if !strings.Contains(pol.KubePluginProblem, "not found on") {
		t.Errorf("KubePluginProblem = %q", pol.KubePluginProblem)
	}
	if _, err := startKubeIdentity(pol, policy.OSEnviron{}, false, false); err == nil {
		t.Error("a real run started with no plugin")
	}
}

// A certificate or token shape starts no process and writes nothing: the
// credential is a Go value handed to the proxy.
func TestKubeCredentialShapesStartNothingAndWriteNothing(t *testing.T) {
	rt := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	pol := &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{}, Env: map[string]policy.EnvVar{},
		Kube: &policy.KubeBinding{Context: "aks-dev", Credential: policy.KubeCredentialToken,
			HostUser: policy.KubeHostUser{Token: policy.Secret("tok")}, TokenLen: 3}}
	run, err := startKubeIdentity(pol, policy.OSEnviron{}, false, false)
	if err != nil || run == nil || run.token == nil || string(*run.token) != "tok" || run.src != nil || run.cert != nil {
		t.Fatalf("token shape: run %+v, %v", run, err)
	}
	run.close()
	if ents, _ := os.ReadDir(rt); len(ents) != 0 {
		t.Errorf("the token shape created %v under XDG_RUNTIME_DIR", ents)
	}
	expired := &policy.Policy{Home: "/home/u", Kube: &policy.KubeBinding{Context: "aks-dev",
		Credential: policy.KubeCredentialClientCert, CertSubject: "CN=x", CertNotAfter: time.Now().Add(-time.Hour)}}
	if _, err := startKubeIdentity(expired, policy.OSEnviron{}, false, false); err == nil ||
		!strings.Contains(err.Error(), "expired on") {
		t.Errorf("an expired client certificate started a run: %v", err)
	}
}

// A plugin run must not retire the OS thread it ran on: an earlier child of
// this process whose Pdeathsig is tied to that thread — the stage, in a real
// run — would be SIGKILLed with it. Measured as the stage dying partway
// through TestKubeBrokerBudgetRefuses before the run unlocked its thread.
func TestKubePluginDoesNotKillAnEarlierPdeathsigChild(t *testing.T) {
	// Forked from many goroutines, so their parent threads are spread over
	// the runtime's idle threads — the ones a plugin goroutine is handed.
	victims := make([]*exec.Cmd, 32)
	var wg sync.WaitGroup
	for i := range victims {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := exec.Command("sleep", "60")
			c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			if err := c.Start(); err == nil {
				victims[i] = c
			}
			time.Sleep(10 * time.Millisecond)
		}()
	}
	wg.Wait()
	for _, c := range victims {
		if c == nil {
			t.Fatal("could not start a victim")
		}
	}
	defer func() {
		for _, c := range victims {
			c.Process.Kill()
			c.Wait()
		}
	}()
	stub := writeStub(t, `echo '{"status":{"token":"t","expirationTimestamp":"2999-01-01T00:00:00Z"}}'`)
	for range 100 {
		if _, _, err := runKubeCmd(kubeMintCmd(context.Background(), []string{stub}, nil)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range victims {
		if err := c.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("a Pdeathsig child started before the plugin runs was killed: %v", err)
		}
		var ws syscall.WaitStatus
		if pid, _ := syscall.Wait4(c.Process.Pid, &ws, syscall.WNOHANG, nil); pid != 0 {
			t.Fatalf("a Pdeathsig child started before the plugin runs exited: %v", ws)
		}
	}
}

// Only the token and its expiry leave a plugin's answer; a certificate, a
// missing expiry or a version other than the file's refuses.
func TestKubeExecParsesAnExecCredential(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	run := func(body, api string) (string, error) {
		cmd := exec.Command("/bin/sh", "-c", `printf '%s' "$1"; echo noise >&2`, "sh", body)
		tok, _, err := runKubeExec(cmd, api)
		return string(tok.Value), err
	}
	const v1, v1b = "client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1"
	cred := func(api, status string) string {
		return `{"apiVersion":"` + api + `","kind":"ExecCredential","status":{` + status + `}}`
	}
	for _, api := range []string{v1, v1b} {
		got, err := run(cred(api, `"token":"tok-abc","expirationTimestamp":"`+exp+`","extra":"x"`), api)
		if err != nil || got != "tok-abc" {
			t.Errorf("%s: %q, %v", api, got, err)
		}
	}
	for name, c := range map[string]struct{ body, api, want string }{
		"no expiry":       {cred(v1, `"token":"tok-abc"`), v1, "expirationTimestamp"},
		"client cert":     {cred(v1, `"token":"tok","expirationTimestamp":"`+exp+`","clientCertificateData":"x","clientKeyData":"y"`), v1, "client certificate"},
		"version differs": {cred(v1b, `"token":"tok","expirationTimestamp":"`+exp+`"`), v1, "want ExecCredential"},
		"not a bearer":    {cred(v1, `"token":"a b","expirationTimestamp":"`+exp+`"`), v1, "not a bearer"},
		"not json":        {"hello", v1, "not an ExecCredential"},
	} {
		if _, err := run(c.body, c.api); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// A bare plugin command is looked up on KubePluginPATH only — never on the
// PATH snug inherited — and a script there refuses.
func TestKubePluginIsLookedUpOnTheMintPATHOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubelogin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got, err := lookPluginPATH(policy.OSEnviron{}, "kubelogin"); err == nil && strings.HasPrefix(got, dir) {
		t.Errorf("found %s on the inherited PATH", got)
	}
	// A name on no PATH entry is not found — the lookup once returned the
	// first entry for every name (red team KH-2) — and one that exists is
	// found where it is, not in /usr/local/bin.
	if got, err := lookPluginPATH(policy.OSEnviron{}, "snug-no-such-plugin-x9"); err == nil {
		t.Errorf("a missing plugin was found at %s", got)
	}
	if _, err := os.Stat("/usr/local/bin/sh"); err != nil {
		if got, err := lookPluginPATH(policy.OSEnviron{}, "sh"); err != nil || got == "/usr/local/bin/sh" {
			t.Errorf("sh found at %q, %v; want its real directory", got, err)
		}
	}
	if err := checkHostBinaryIsELF("kube exec plugin", "kubelogin", filepath.Join(dir, "kubelogin")); err == nil ||
		!strings.Contains(err.Error(), "it is a script") {
		t.Errorf("a script plugin: %v", err)
	}
}

// az, which kubelogin runs, is Python started without -s; the plugin's env
// must keep a .pth planted in the host home's user site from running (red
// team KH-1, measured against the azure-cli package's az).
func TestKubePluginEnvKeepsPythonUserSiteOff(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on this host")
	}
	home := t.TempDir()
	ver, err := exec.Command(py, "-c", "import sys; print('%d.%d' % sys.version_info[:2])").Output()
	if err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(home, ".local/lib/python"+strings.TrimSpace(string(ver))+"/site-packages")
	if err := os.MkdirAll(site, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "ran")
	if err := os.WriteFile(filepath.Join(site, "x.pth"), []byte("import os; open("+strconv.Quote(marker)+", 'w')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pl := &policy.KubePlugin{Row: "kubelogin"}
	run := func(env []string) bool {
		os.Remove(marker)
		cmd := exec.Command(py, "-c", "pass")
		cmd.Env = env
		_ = cmd.Run()
		_, err := os.Stat(marker)
		return err == nil
	}
	if !run([]string{"PATH=" + policy.KubePluginPATH, "HOME=" + home}) {
		t.Skip("this python3 does not load the user site even without the variable")
	}
	if run(pl.KubePluginEnv(home)) {
		t.Error("a .pth in the host home's user site ran under the plugin's environment")
	}
}

// Red-team F2: the plugin inherited a descriptor snug itself was started
// with (fd 7, a host key file), because its fork skipped fdseal. A
// descriptor this process holds without close-on-exec must not reach it.
func TestKubePluginInheritsNoDescriptorBeyondStdio(t *testing.T) {
	f, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	// /proc/self, not /proc/$$: the plugin is pid 1 of its own pid namespace,
	// and this /proc is the host's.
	stub := writeStub(t, `ls -1 /proc/self/fd | sed 's/^/FD /'`)
	out, _, err := runKubeCmd(kubeMintCmd(context.Background(), []string{stub}, []string{"PATH=/usr/bin:/bin"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "FD "+strconv.Itoa(fd)+"\n") {
		t.Errorf("the plugin inherited fd %d:\n%s", fd, out)
	}
	if !strings.Contains(string(out), "FD 0\n") {
		t.Fatalf("the stub listed no descriptors; the check would pass vacuously:\n%s", out)
	}
}

// Red-team F4: a failed host-address enumeration left the proxy's dialer
// with no host-owned refusal list. It refuses the run instead, before the
// socket is bound.
func TestKubeListenRefusesWhenHostAddressesFail(t *testing.T) {
	old := kubeHostAddresses
	kubeHostAddresses = func() ([]string, error) { return nil, errors.New("netlink: boom") }
	defer func() { kubeHostAddresses = old }()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &kubeRun{pol: &policy.Policy{Kube: &policy.KubeBinding{Server: "https://api.example"}}, audit: func(string) {}}
	err = r.listen([]*os.File{os.NewFile(uintptr(fd), "relay")})
	if err == nil || !strings.Contains(err.Error(), "listing this host's addresses") {
		t.Errorf("listen with no host addresses: %v", err)
	}
}
