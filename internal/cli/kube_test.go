package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

func TestKubeMintEnvIsBuiltNotInherited(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "AWS_PROFILE", "KUBECONFIG", "AZURE_CONFIG_DIR", "KUBECACHEDIR"} {
		t.Setenv(k, "/from/the/repo/envrc")
	}
	argv := []string{"/usr/bin/kubectl", "create", "token", "a"}
	cmd := kubeMintCmd(context.Background(), argv, []string{"PATH=/usr/bin:/bin", "HOME=/h", "KUBERC=off"})
	if !slices.Equal(cmd.Env, []string{"PATH=/usr/bin:/bin", "HOME=/h", "KUBERC=off"}) {
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

func TestKubeMintBinaryRefusesAScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec distrobox-enter -- kubectl \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkKubectlIsABinary(script); err == nil || !strings.Contains(err.Error(), "it is a script") {
		t.Errorf("a shim script: %v", err)
	}
}

func TestKubeMintBinaryFollowsSymlinkToELF(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "kubectl")
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	if err := checkKubectlIsABinary(link); err != nil {
		t.Errorf("a symlink to an ELF binary refused: %v", err)
	}
}

func TestRuntimeDirCreateFileRefusesExistingAndLinks(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Remove()
	p, err := rt.CreateFile("kube-mint.json", []byte("x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi.Mode().Perm(), err)
	}
	if _, err := rt.CreateFile("kube-mint.json", []byte("y"), 0o600); err == nil {
		t.Error("CreateFile overwrote an existing entry")
	}
	if err := rt.RemoveFile("kube-mint.json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(rt.Path(), "planted")); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.CreateFile("planted", []byte("y"), 0o600); err == nil {
		t.Error("CreateFile followed a planted link")
	}
	if _, err := rt.CreateFile("../escape", nil, 0o600); err == nil {
		t.Error("CreateFile accepted a path")
	}
}

func writeStub(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubectl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKubeMintParsesATokenRequest(t *testing.T) {
	stub := writeStub(t, `echo '{"kind":"TokenRequest","status":{"token":"eyJ.abc-_9","expirationTimestamp":"2999-01-01T00:00:00Z"}}'`)
	tok, _, err := runKubeMint(kubeMintCmd(context.Background(), []string{stub}, []string{"PATH=/usr/bin:/bin"}))
	if err != nil {
		t.Fatal(err)
	}
	if string(tok.Value) != "eyJ.abc-_9" || tok.Expiry.Year() != 2999 {
		t.Errorf("token = %q, expiry %v", tok.Value, tok.Expiry)
	}
	for _, bad := range []string{
		`echo '{"status":{"token":"a b","expirationTimestamp":"2999-01-01T00:00:00Z"}}'`,
		`echo '{"status":{"token":"ok","expirationTimestamp":"2000-01-01T00:00:00Z"}}'`,
		`echo not-json`,
		`echo boom >&2; exit 3`,
	} {
		if _, _, err := runKubeMint(kubeMintCmd(context.Background(), []string{writeStub(t, bad)}, nil)); err == nil {
			t.Errorf("accepted the output of %q", bad)
		}
	}
}

// The reason the mint gets its own pid namespace: cancelling it kills kubectl
// AND whatever it spawned, which a process group alone does not guarantee once
// the child setsid()s.
func TestKubeMintCancelLeavesNoGrandchild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	stub := writeStub(t, "setsid sleep 300 & echo $! > "+pidFile+"\nsleep 300\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runKubeMint(kubeMintCmd(ctx, []string{stub}, []string{"PATH=/usr/bin:/bin"})); close(done) }()
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
	// The pid written is in the mint's pid namespace; the grandchild is found
	// by its command line instead.
	for range 50 {
		if !sleepRunning(t, "300", os.Getpid()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a grandchild of the mint survived its cancellation")
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

func TestKubeDryRunMintsNothing(t *testing.T) {
	rt := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("PATH", t.TempDir()) // no kubectl anywhere
	pol := &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{}, Env: map[string]policy.EnvVar{},
		Kube: &policy.KubeBinding{Context: "aks-dev", SANamespace: "dev", SAName: "snug-agent"}}
	cleanup, err := startKubeIdentity(pol, policy.OSEnviron{}, false, true)
	if err != nil {
		t.Fatalf("a dry run refused for a missing kubectl: %v", err)
	}
	cleanup()
	ents, _ := os.ReadDir(rt)
	if len(ents) != 0 {
		t.Errorf("a dry run created %v under XDG_RUNTIME_DIR", ents)
	}
	if m, ok := pol.Mounts[policy.KubeTokenSocketGuest]; !ok || !m.RunScoped {
		t.Errorf("the planned socket is not on the dry-run screen: %+v", m)
	}
	if !strings.Contains(pol.KubeMintProblem, "kubectl not found") {
		t.Errorf("KubeMintProblem = %q", pol.KubeMintProblem)
	}
	if _, err := startKubeIdentity(pol, policy.OSEnviron{}, false, false); err == nil {
		t.Error("a real run started with no host kubectl")
	}
}
