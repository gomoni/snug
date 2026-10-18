//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// identity.kube end to end, with a stub host kubectl: the shim inside gets the
// minted token and nothing else, the broker caches, budgets and times out, and
// nothing it started outlives snug.

type kubeFixture struct {
	stubDir string
	env     []string
	proj    string
}

func newKubeFixture(t *testing.T, mode string) kubeFixture {
	t.Helper()
	stubDir := t.TempDir()
	bin := filepath.Join(stubDir, "kubectl")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/stubkubectl")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building testdata/stubkubectl: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(stubDir, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgDir := t.TempDir()
	// A real self-signed certificate (snug-test-ca, no key kept): snug parses
	// every CA block as X.509 before re-encoding it.
	ca := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJUVENCOWFBREFnRUNBZ0VCTUFvR0NDcUdTTTQ5QkFNQ01CY3hGVEFUQmdOVkJBTVRESE51ZFdjdGRHVnoKZEMxallUQWVGdzB5TmpBeE1ERXdNREF3TURCYUZ3MHpOakF4TURFd01EQXdNREJhTUJjeEZUQVRCZ05WQkFNVApESE51ZFdjdGRHVnpkQzFqWVRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk1ZVld3NjVka2svCkZiYk0vTjJJbnc4ZU5CYzN3bi94RmFzekQwamdqdEFwUFp0em9Eam1lblVrbUQ1TEh1RTJnNjIzcXpTNmFnM2YKa0RsOGxjUzlwbGFqTWpBd01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZEN2FIT3l2Sm4rdAp1T2IrbUtleG1nOVI2Zk1NTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUdyd3dwaEFzV1Q2bWFVS0xsWXZ0VXpTCkVRUnZYN1k5T1N5NzJ4UVZDRm0vQWlBakNEYXRvQXIvNUd5YWFFUnkyNUpPSHQybmF5MXdjb0VDQ0psSUVNYUYKMnc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	kubeconfig := filepath.Join(cfgDir, "config")
	if err := os.WriteFile(kubeconfig, []byte(fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: https://kube.example.invalid:443
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
`, ca)), 0o600); err != nil {
		t.Fatal(err)
	}
	proj, _ := target(t)
	env := writeProfile(t, fmt.Sprintf(`[profile.kubetest]
include = ["@net"]
  [profile.kubetest.identity.kube]
  context         = "aks-dev"
  server          = "https://kube.example.invalid:443"
  token           = "serviceaccount"
  service_account = "dev/snug-agent"
  kubeconfig      = %q
`, kubeconfig), "PATH="+stubDir+":"+os.Getenv("PATH"))
	return kubeFixture{stubDir: stubDir, env: env, proj: proj}
}

func (f kubeFixture) run(t *testing.T, script string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, "-p", "kubetest", f.proj, "--", "/bin/sh", "-c", script)
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

func TestKubeBrokerHandsOutOnlyTheMintedToken(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/snug/bin/snug-kube-token; echo; echo ==; cat ~/.kube/config; echo ==;
		ls -a ~/.azure 2>&1; grep -rl -e HOSTSTATICTOKEN -e kind-kind -e host-user "$HOME" 2>/dev/null; echo END`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, `"token":"stub-token-0123"`) || !strings.Contains(out, "ExecCredential") {
		t.Errorf("the shim did not print the minted credential:\n%s", out)
	}
	for _, bad := range []string{"HOSTSTATICTOKEN", "kind-kind", "host-user", "client-key-data", "38921"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q is visible inside:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "No such file") {
		t.Errorf("~/.azure exists inside:\n%s", out)
	}
	if !strings.Contains(out, `"command": "/snug/bin/snug-kube-token"`) {
		t.Errorf("the generated kubeconfig does not name the shim:\n%s", out)
	}
	args, _ := os.ReadFile(filepath.Join(f.stubDir, "calls"))
	if !strings.Contains(string(args), "--context=snug") || strings.Contains(string(args), "config") &&
		!strings.Contains(string(args), "kube-mint.json") {
		t.Errorf("the host mint was not run against snug's own file: %s", args)
	}
}

func TestKubeBrokerCachesWithinTTL(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/snug/bin/snug-kube-token >/dev/null && /snug/bin/snug-kube-token >/dev/null && echo TWICE`)
	if code != 0 || !strings.Contains(out, "TWICE") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if n := f.calls(t); n != 1 {
		t.Errorf("the host kubectl ran %d times for a preflight and two cached asks, want 1", n)
	}
}

func TestKubeBrokerBudgetRefuses(t *testing.T) {
	f := newKubeFixture(t, "short")
	budget(t, 60*time.Second)
	requireSandbox(t)
	requirePasta(t)
	out, _ := f.run(t, `i=0; while [ $i -lt 70 ]; do /snug/bin/snug-kube-token >/dev/null 2>/tmp/e || { cat /tmp/e; break; }; i=$((i+1)); done; echo AFTER=$i`)
	if !strings.Contains(out, "budget") {
		t.Errorf("70 asks against a 2s token never hit the mint budget:\n%s", out)
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

func TestKubeShimIsNotWritable(t *testing.T) {
	f := newKubeFixture(t, "ok")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, _ := f.run(t, `echo x > /snug/bin/snug-kube-token 2>&1; echo x >> ~/.kube/config 2>&1; echo END`)
	if strings.Count(out, "Read-only file system") < 2 {
		t.Errorf("the shim or the generated kubeconfig is writable inside:\n%s", out)
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
include = ["@net"]
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
	cmd := exec.CommandContext(ctx, snugBin, "-p", "kubetest", f.proj, "--", "/bin/true")
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
	cmd := exec.Command(snugBin, "-p", "kubetest", f.proj, "--", "/bin/true")
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
