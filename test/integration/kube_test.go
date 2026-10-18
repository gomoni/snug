//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// identity.kube end to end, with a stub host kubectl and an httptest TLS
// server standing in for the API server: kubectl inside reaches it only
// through snug's proxy, the bearer never enters the sandbox, the proxy refuses
// what would change who the sandbox is, and nothing snug started outlives it.
//
// The upstream listens on this host's loopback, which the real proxy refuses
// to dial by design; snugFixtureBin (-tags snugfixture) resolves the one name
// SNUG_FIXTURE_KUBE_UPSTREAM gives it to that address and dials it.

const (
	kubeStubToken  = "stub-token-0123"
	kubeServerName = "kube.example.invalid"
)

type kubeFixture struct {
	stubDir string
	probe   string
	env     []string
	proj    string
	server  string
	up      *kubeUpstream
}

// kubeUpstream records what reached the stand-in API server.
type kubeUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	auths []string
	paths []string
}

func (u *kubeUpstream) seen() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string{}, u.auths...), append([]string{}, u.paths...)
}

func newKubeUpstream(t *testing.T) *kubeUpstream {
	t.Helper()
	u := &kubeUpstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.paths = append(u.paths, r.URL.Path)
		u.mu.Unlock()
		if r.Header.Get("Upgrade") != "" {
			c, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", r.Header.Get("Upgrade"))
			brw.Flush()
			line, _ := brw.ReadString('\n')
			fmt.Fprintf(brw, "echo:%s", line)
			brw.Flush()
			return
		}
		fmt.Fprintf(w, "upstream path=%s", r.URL.Path)
	}))
	u.srv.EnableHTTP2 = true
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func buildKubeHelper(t *testing.T, dir, name, pkg string) string {
	t.Helper()
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v: %s", pkg, err, out)
	}
	return bin
}

func newKubeFixture(t *testing.T, mode string) kubeFixture { return newKubeFixtureNet(t, mode, true) }

func newKubeFixtureNet(t *testing.T, mode string, withNet bool) kubeFixture {
	t.Helper()
	stubDir := t.TempDir()
	buildKubeHelper(t, stubDir, "kubectl", "./testdata/stubkubectl")
	probe := buildKubeHelper(t, t.TempDir(), "kubeprobe", "./testdata/kubeprobe")
	if err := os.WriteFile(filepath.Join(stubDir, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	up := newKubeUpstream(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "https://"))
	server := "https://" + kubeServerName + ":" + port
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.srv.Certificate().Raw}))
	cfgDir := t.TempDir()
	kubeconfig := filepath.Join(cfgDir, "config")
	if err := os.WriteFile(kubeconfig, []byte(fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
    tls-server-name: example.com
  name: aks-dev
- cluster:
    server: https://127.0.0.1:38921
  name: kind-kind
contexts:
- context:
    cluster: aks-dev
    user: host-user
  name: aks-dev
- context:
    cluster: kind-kind
    user: host-user
  name: kind-kind
users:
- name: host-user
  user:
    token: HOSTSTATICTOKEN
`, ca, server)), 0o600); err != nil {
		t.Fatal(err)
	}
	proj, _ := target(t)
	include := ""
	if withNet {
		include = `include = ["@net"]`
	}
	env := writeProfile(t, fmt.Sprintf(`[profile.kubetest]
%s
ro = ["%s:/kubeprobe"]
  [profile.kubetest.identity.kube]
  context         = "aks-dev"
  server          = %q
  token           = "serviceaccount"
  service_account = "dev/snug-agent"
  kubeconfig      = %q
`, include, probe, server, kubeconfig), "PATH="+stubDir+":"+os.Getenv("PATH"),
		"SNUG_FIXTURE_KUBE_UPSTREAM="+kubeServerName+"=127.0.0.1")
	return kubeFixture{stubDir: stubDir, probe: probe, env: env, proj: proj, server: server, up: up}
}

func (f kubeFixture) run(t *testing.T, script string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugFixtureBin, "-p", "kubetest", f.proj, "--", "/bin/sh", "-c", script)
	cmd.Env = f.env
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running snug: %v\n%s", err, out)
	}
	return string(out), code
}

func (f kubeFixture) calls(t *testing.T) int {
	b, _ := os.ReadFile(filepath.Join(f.stubDir, "calls"))
	return strings.Count(string(b), "\n")
}

// The guest reaches the pinned server through the proxy, the server sees the
// minted bearer, and nothing the sandbox can read holds it: not the
// environment, not the home, not /snug, not any process's argv or environ.
func TestKubeGuestNeverSeesTheToken(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/kubeprobe get /api/v1/namespaces; /kubeprobe find `+hex.EncodeToString([]byte(kubeStubToken))+`;
		echo ==; cat ~/.kube/config; echo ==; ls -a ~/.azure 2>&1;
		grep -rl -e HOSTSTATICTOKEN -e kind-kind -e host-user "$HOME" 2>/dev/null; echo END`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "STATUS 200") || !strings.Contains(out, "upstream path=/api/v1/namespaces") {
		t.Errorf("the guest did not reach the pinned server through the proxy:\n%s", out)
	}
	auths, _ := f.up.seen()
	if len(auths) == 0 || auths[0] != "Bearer "+kubeStubToken {
		t.Errorf("the server saw Authorization %q, want the minted bearer", auths)
	}
	if !strings.Contains(out, "FIND DONE") || strings.Contains(out, "FOUND") {
		t.Errorf("the minted token is readable inside:\n%s", out)
	}
	for _, bad := range []string{"HOSTSTATICTOKEN", "kind-kind", "host-user", "client-key-data", "38921",
		kubeStubToken, "exec", "certificate-authority", kubeServerName} {
		if strings.Contains(strings.SplitN(out, "FIND DONE", 2)[1], bad) {
			t.Errorf("%q is visible inside:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, `"server": "http://127.0.0.1:6443"`) {
		t.Errorf("the generated kubeconfig does not name the proxy:\n%s", out)
	}
	if !strings.Contains(out, "No such file") {
		t.Errorf("~/.azure exists inside:\n%s", out)
	}
	args, _ := os.ReadFile(filepath.Join(f.stubDir, "calls"))
	if !strings.Contains(string(args), "--context=snug") || !strings.Contains(string(args), "kube-mint.json") {
		t.Errorf("the host mint was not run against snug's own file: %s", args)
	}
}

// kubectl --as and a bearer of the guest's own are refused, not stripped: the
// guest learns it cannot be anyone else, and the server never sees the try.
func TestKubeImpersonateIsRefusedInside(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/kubeprobe get /api Impersonate-User:admin; /kubeprobe get /api Impersonate_Group:system:masters;
		/kubeprobe get /api "Authorization:Bearer mine"; /kubeprobe get /k8s/../other/api; echo END`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Count(out, "STATUS 403") != 3 || strings.Count(out, "STATUS 400") != 1 {
		t.Errorf("want three 403 and one 400:\n%s", out)
	}
	if _, paths := f.up.seen(); len(paths) != 0 {
		t.Errorf("refused requests reached the server: %v", paths)
	}
}

// exec, attach and port-forward are upgrades; the tunnel works end to end.
func TestKubeUpgradeWorksInside(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/kubeprobe upgrade /api/v1/namespaces/d/pods/p/exec`)
	if code != 0 || !strings.Contains(out, "STATUS 101") || !strings.Contains(out, "TUNNEL echo:ping") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// The proxy's listener is a socket in the SANDBOX's netns: the host cannot
// reach it, and a payload cannot bind the port beside it.
func TestKubeProxyListenerIsInTheSandboxNetns(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	if c, err := net.DialTimeout("tcp", "127.0.0.1:6443", time.Second); err == nil {
		c.Close()
		t.Skip("something on this host already listens on 127.0.0.1:6443")
	}
	hostDial := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(cmdTimeout)
		for time.Now().Before(deadline) {
			if _, paths := f.up.seen(); len(paths) > 0 {
				c, err := net.DialTimeout("tcp", "127.0.0.1:6443", time.Second)
				if err == nil {
					c.Close()
				}
				hostDial <- err
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		hostDial <- errors.New("the run never reached the server")
	}()
	out, code := f.run(t, `/kubeprobe bind; /kubeprobe get /api; sleep 2; echo END`)
	if code != 0 || !strings.Contains(out, "STATUS 200") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Count(out, "address already in use") != 2 {
		t.Errorf("a payload bound the proxy's port:\n%s", out)
	}
	if err := <-hostDial; err == nil {
		t.Error("the host reached 127.0.0.1:6443 while the run lived: the listener is not in the sandbox's netns")
	}
}

// Without @net the sandbox has no egress of its own and still reaches the
// pinned server through the proxy: a kube profile is not an offline profile,
// and that is the one hole.
func TestKubeOfflineProfileReachesOnlyTheProxy(t *testing.T) {
	f := newKubeFixtureNet(t, "ok", false)
	budget(t)
	requireSandbox(t)
	out, code := f.run(t, `/kubeprobe get /api; /kubeprobe dial 1.1.1.1:443; echo END`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "STATUS 200") {
		t.Errorf("the offline kube profile did not reach the server through the proxy:\n%s", out)
	}
	if strings.Contains(out, "DIAL OK") {
		t.Errorf("an offline kube profile has egress of its own:\n%s", out)
	}
}

func TestKubeBrokerCachesWithinTTL(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/kubeprobe loop 3 /api`)
	if code != 0 || !strings.Contains(out, "ALL 3 OK") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if n := f.calls(t); n != 1 {
		t.Errorf("the host kubectl ran %d times for a preflight and three cached requests, want 1", n)
	}
}

func TestKubeBrokerBudgetRefuses(t *testing.T) {
	f := newKubeFixture(t, "short")
	budget(t, 60*time.Second)
	requireSandbox(t)
	requirePasta(t)
	out, _ := f.run(t, `/kubeprobe loop 70 /api`)
	if !strings.Contains(out, "STATUS 503") || !strings.Contains(out, "budget") {
		t.Errorf("70 requests against a 2s token never hit the mint budget:\n%s", out)
	}
	if n := f.calls(t); n > 64 {
		t.Errorf("the host kubectl ran %d times, past the budget of 64", n)
	}
}

func TestKubeBrokerStopsAtTeardown(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `echo RUNDIR`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	rt := os.Getenv("XDG_RUNTIME_DIR")
	for _, e := range f.env {
		if v, ok := strings.CutPrefix(e, "XDG_RUNTIME_DIR="); ok {
			rt = v
		}
	}
	matches, _ := filepath.Glob(filepath.Join(rt, "snug", "run-*", "kube-*"))
	for _, m := range matches {
		t.Errorf("%s survived the run", m)
	}
}

func TestKubeKubeconfigIsNotWritable(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, _ := f.run(t, `echo x >> ~/.kube/config 2>&1; echo END`)
	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("the generated kubeconfig is writable inside:\n%s", out)
	}
}

func TestKubeKubeconfigUnderTargetRefuses(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	inTarget := filepath.Join(f.proj, "kubeconfig")
	if err := os.WriteFile(inTarget, []byte("clusters: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := writeProfile(t, fmt.Sprintf(`[profile.kubetest]
  [profile.kubetest.identity.kube]
  context         = "aks-dev"
  server          = "https://kube.example.invalid:443"
  token           = "serviceaccount"
  service_account = "dev/snug-agent"
  kubeconfig      = %q
`, inTarget), "PATH="+f.stubDir+":"+os.Getenv("PATH"))
	f.env = env
	out, code := f.run(t, "echo RAN")
	if code != 77 || !strings.Contains(out, "inside the target") || strings.Contains(out, "RAN") {
		t.Errorf("exit %d, want 77 naming the target:\n%s", code, out)
	}
	if f.calls(t) != 0 {
		t.Error("the host kubectl ran for a refused selection")
	}
}

func TestKubeBrokerAHungMintTimesOut(t *testing.T) {
	f := newKubeFixture(t, "hang")
	budget(t, 50*time.Second)
	requireSandbox(t)
	requirePasta(t)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugFixtureBin, "-p", "kubetest", f.proj, "--", "/bin/true")
	cmd.Env = f.env
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	ee, _ := err.(*exec.ExitError)
	if ee == nil || ee.ExitCode() != 77 || !strings.Contains(string(out), "kube token mint failed") {
		t.Fatalf("a hung mint: err %v after %s:\n%s", err, time.Since(start), out)
	}
	if d := time.Since(start); d > 40*time.Second {
		t.Errorf("a hung mint held snug for %s; the mint timeout is 30s", d)
	}
}

func TestKubeMintLeavesNoProcessAfterSIGKILL(t *testing.T) {
	f := newKubeFixture(t, "grandchild")
	budget(t, 40*time.Second)
	requireSandbox(t)
	requirePasta(t)
	cmd := exec.Command(snugFixtureBin, "-p", "kubetest", f.proj, "--", "/bin/true")
	cmd.Env = f.env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(f.stubDir, "grandchild")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("the stub never started its grandchild")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	for range 100 {
		if !kubeSleepAlive("301") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the mint's grandchild survived SIGKILL of snug")
}

func kubeSleepAlive(arg string) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		cl, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && string(cl) == "sleep\x00"+arg+"\x00" {
			return true
		}
	}
	return false
}
