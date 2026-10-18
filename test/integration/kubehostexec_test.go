//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// token = "host-exec": snug runs the host context's own exec plugin (a stub
// built as kubelogin) on the host, with an argv it builds and an environment
// of its own, and the plugin's token is the proxy's bearer.

const kubePluginToken = "stub-plugin-token-4567"

type kubeExecFixture struct {
	kubeFixture
	pluginDir string
}

func newKubeExecFixture(t *testing.T, mode, token string) kubeExecFixture {
	t.Helper()
	pluginDir := t.TempDir()
	plugin := buildKubeHelper(t, pluginDir, "kubelogin", "./testdata/stubkubeplugin")
	if err := os.WriteFile(filepath.Join(pluginDir, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	stubDir := t.TempDir()
	buildKubeHelper(t, stubDir, "kubectl", "./testdata/stubkubectl")
	if err := os.WriteFile(filepath.Join(stubDir, "mode"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := buildKubeHelper(t, t.TempDir(), "kubeprobe", "./testdata/kubeprobe")
	up := newKubeUpstream(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "https://"))
	server := "https://" + kubeServerName + ":" + port
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.srv.Certificate().Raw}))
	kubeconfig := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfig, []byte(fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
    tls-server-name: example.com
  name: aks-entra
contexts:
- context:
    cluster: aks-entra
    user: clusterUser_rg_aks-entra
  name: aks-entra
users:
- name: clusterUser_rg_aks-entra
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - get-token
      - --environment
      - AzurePublicCloud
      - --server-id
      - 6dae42f8-4368-4678-94ff-3960e28e3630
      - --client-id
      - 80faf920-1908-4b52-b5ef-a8e7bedfc67a
      - --tenant-id
      - 00000000-0000-0000-0000-000000000000
      - --login
      - azurecli
      command: %s
      env: null
      installHint: |2

        kubelogin is not installed which is required to connect to AAD enabled cluster.
      interactiveMode: IfAvailable
      provideClusterInfo: false
`, ca, server, plugin)), 0o600); err != nil {
		t.Fatal(err)
	}
	sa := ""
	if token == "serviceaccount" {
		sa = `service_account = "dev/snug-agent"`
	}
	proj, _ := target(t)
	env := writeProfile(t, fmt.Sprintf(`[profile.kubetest]
ro = ["%s:/kubeprobe"]
  [profile.kubetest.identity.kube]
  context    = "aks-entra"
  server     = %q
  token      = %q
  kubeconfig = %q
  %s
`, probe, server, token, kubeconfig, sa), "PATH="+stubDir+":"+os.Getenv("PATH"),
		"SNUG_FIXTURE_KUBE_UPSTREAM="+kubeServerName+"=127.0.0.1")
	return kubeExecFixture{kubeFixture{stubDir: stubDir, probe: probe, env: env, proj: proj, server: server, up: up}, pluginDir}
}

func (f kubeExecFixture) pluginCalls(t *testing.T) string {
	b, _ := os.ReadFile(filepath.Join(f.pluginDir, "calls"))
	return string(b)
}

// The plugin's token reaches the pinned server as the bearer and nothing
// else of its answer — not the extra field, not the refresh-token-shaped
// value, not its stderr — reaches the sandbox. Its argv is snug's (no
// --client-id, flags in snug's order) and its environment is exactly PATH and
// HOME.
func TestKubeHostExecForwardsOnlyTheToken(t *testing.T) {
	f := newKubeExecFixture(t, "ok", "host-exec")
	budget(t)
	requireSandbox(t)
	out, code := f.run(t, `/kubeprobe get /api/v1/namespaces; /kubeprobe find `+hex.EncodeToString([]byte(kubePluginToken))+`;
		/kubeprobe find `+hex.EncodeToString([]byte("STUBREFRESHTOKEN"))+`; /kubeprobe find `+hex.EncodeToString([]byte("STUBSTDERR"))+`; echo END`)
	if code != 0 || !strings.Contains(out, "STATUS 200") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Count(out, "FIND DONE") != 3 || strings.Contains(out, "FOUND") {
		t.Errorf("part of the plugin's answer is readable inside:\n%s", out)
	}
	if auths, _ := f.up.seen(); len(auths) == 0 || auths[0] != "Bearer "+kubePluginToken {
		t.Errorf("the server saw Authorization %q, want the plugin's token", auths)
	}
	calls := f.pluginCalls(t)
	if !strings.Contains(calls, "ARGV get-token --login azurecli --server-id 6dae42f8-4368-4678-94ff-3960e28e3630 "+
		"--tenant-id 00000000-0000-0000-0000-000000000000 --environment AzurePublicCloud\n") {
		t.Errorf("the plugin did not run with snug's argv:\n%s", calls)
	}
	for _, line := range strings.Split(calls, "\n") {
		if env, ok := strings.CutPrefix(line, "ENV "); ok {
			for _, kv := range strings.Fields(env) {
				name, _, _ := strings.Cut(kv, "=")
				if name != "PATH" && name != "HOME" {
					t.Errorf("the plugin's environment carries %s", name)
				}
			}
		}
	}
}

// A plugin that answers with a client certificate refuses the run at start:
// the proxy carries a bearer only.
func TestKubeHostExecRefusesACertificateAnswer(t *testing.T) {
	f := newKubeExecFixture(t, "cert", "host-exec")
	budget(t)
	requireSandbox(t)
	out, code := f.run(t, "echo RAN")
	if code != 77 || !strings.Contains(out, "client certificate") || strings.Contains(out, "RAN") {
		t.Errorf("exit %d, want 77 naming the certificate:\n%s", code, out)
	}
	if strings.Contains(out, "STUBKEY") || strings.Contains(out, "STUBCERT") {
		t.Errorf("the refusal prints the plugin's certificate material:\n%s", out)
	}
}

// serviceaccount on an exec user: the plugin's token authenticates the
// host-side mint, and the sandbox acts as the ServiceAccount.
func TestKubeServiceAccountMintsThroughAnExecPlugin(t *testing.T) {
	f := newKubeExecFixture(t, "ok", "serviceaccount")
	budget(t)
	requireSandbox(t)
	out, code := f.run(t, `/kubeprobe get /api`)
	if code != 0 || !strings.Contains(out, "STATUS 200") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if auths, _ := f.up.seen(); len(auths) == 0 || auths[0] != "Bearer "+kubeStubToken {
		t.Errorf("the server saw Authorization %q, want the minted ServiceAccount token", auths)
	}
	b, _ := os.ReadFile(filepath.Join(f.stubDir, "calls"))
	if !strings.Contains(string(b), "MINTFILE-HAS-PLUGIN-TOKEN") || !strings.Contains(string(b), "create token snug-agent") {
		t.Errorf("the mint did not authenticate with the plugin's token:\n%s", b)
	}
}

func TestKubeHostExecLeavesNoGrandchildAfterSIGKILL(t *testing.T) {
	f := newKubeExecFixture(t, "grandchild", "host-exec")
	budget(t, 40*time.Second)
	requireSandbox(t)
	cmd := exec.Command(snugFixtureBin, "-p", "kubetest", f.proj, "--", "/bin/true")
	cmd.Env = f.env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(f.pluginDir, "grandchild")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("the stub plugin never started its grandchild")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	for range 100 {
		if !kubeSleepAlive("302") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the plugin's grandchild survived SIGKILL of snug")
}
