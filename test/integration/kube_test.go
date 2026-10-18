//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// identity.kubectl end to end, with an httptest TLS server standing in for
// the API server: kubectl inside reaches it only through snug's proxy, the
// proxy presents the host context's own credential — its client certificate
// or its static token, whichever the profile names — that credential never
// enters the sandbox and never touches disk, and the proxy forwards what the
// guest sends, impersonation included, to that one server.
//
// The upstream listens on this host's loopback, which the real proxy refuses
// to dial by design; snugFixtureBin (-tags snugfixture) resolves the one name
// SNUG_FIXTURE_KUBE_UPSTREAM gives it to that address and dials it.

const (
	kubeHostToken  = "HOSTSTATICTOKEN0123"
	kubeServerName = "kube.example.invalid"
)

type kubeFixture struct {
	probe  string
	env    []string
	proj   string
	server string
	up     *kubeUpstream
	keyB64 string // a slice of the host client key's base64, the leak needle
}

// kubeUpstream records what reached the stand-in API server.
type kubeUpstream struct {
	srv    *httptest.Server
	mu     sync.Mutex
	auths  []string
	paths  []string
	peers  []string
	imperb []string
}

func (u *kubeUpstream) seen() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string{}, u.auths...), append([]string{}, u.paths...)
}

func (u *kubeUpstream) seenPeers() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string{}, u.peers...), append([]string{}, u.imperb...)
}

// newKubeUpstream verifies a client certificate when one is offered, issued
// as clientCA, and records its subject.
func newKubeUpstream(t *testing.T, clientCA *x509.Certificate) *kubeUpstream {
	t.Helper()
	u := &kubeUpstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		u.mu.Lock()
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.paths = append(u.paths, r.URL.Path)
		u.peers = append(u.peers, peer)
		u.imperb = append(u.imperb, r.Header.Get("Impersonate-User"))
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
	if clientCA != nil {
		pool := x509.NewCertPool()
		pool.AddCert(clientCA)
		u.srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	}
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

// kubeClientCert is a self-signed client certificate standing in for an AKS
// local account's masterclient, PEM-encoded as a kubeconfig embeds it.
func kubeClientCert(t *testing.T) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9),
		Subject:   pkix.Name{CommonName: "masterclient", Organization: []string{"system:masters"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
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

func newKubeFixture(t *testing.T, cred string) kubeFixture { return newKubeFixtureNet(t, cred, true) }

// newKubeFixtureNet writes a host kubeconfig whose user entry holds a client
// certificate AND a static token — the AKS local-account shape — and a
// profile presenting the one cred names.
func newKubeFixtureNet(t *testing.T, cred string, withNet bool) kubeFixture {
	t.Helper()
	probe := buildKubeHelper(t, t.TempDir(), "kubeprobe", "./testdata/kubeprobe")
	leaf, certPEM, keyPEM := kubeClientCert(t)
	up := newKubeUpstream(t, leaf)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "https://"))
	server := "https://" + kubeServerName + ":" + port
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.srv.Certificate().Raw}))
	keyB64 := base64.StdEncoding.EncodeToString(keyPEM)
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
    client-certificate-data: %s
    client-key-data: %s
    token: %s
`, ca, server, base64.StdEncoding.EncodeToString(certPEM), keyB64, kubeHostToken)), 0o600); err != nil {
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
  [profile.kubetest.identity.kubectl]
  context    = "aks-dev"
  server     = %q
  credential = %q
  kubeconfig = %q
`, include, probe, server, cred, kubeconfig), "SNUG_FIXTURE_KUBE_UPSTREAM="+kubeServerName+"=127.0.0.1")
	return kubeFixture{probe: probe, env: env, proj: proj, server: server, up: up, keyB64: keyB64[len(keyB64)/2 : len(keyB64)/2+40]}
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

// The guest reaches the pinned server through the proxy, the server sees the
// ONE credential the profile names — the certificate's subject and no bearer,
// or the static token and no certificate — and nothing the sandbox can read
// holds either half of the host user entry: not the environment, not the
// home, not /snug, not any process's argv or environ.
func TestKubeGuestNeverSeesTheCredential(t *testing.T) {
	for _, cred := range []string{"client-certificate", "token"} {
		t.Run(cred, func(t *testing.T) {
			f := newKubeFixture(t, cred)
			budget(t)
			requireSandbox(t)
			requirePasta(t)
			out, code := f.run(t, `/kubeprobe get /api/v1/namespaces; /kubeprobe find `+hex.EncodeToString([]byte(kubeHostToken))+`;
				/kubeprobe find `+hex.EncodeToString([]byte(f.keyB64))+`;
				echo ==; cat ~/.kube/config; echo ==; ls -a ~/.azure 2>&1;
				grep -rl -e kind-kind -e host-user "$HOME" 2>/dev/null; echo END`)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if !strings.Contains(out, "STATUS 200") || !strings.Contains(out, "upstream path=/api/v1/namespaces") {
				t.Errorf("the guest did not reach the pinned server through the proxy:\n%s", out)
			}
			auths, _ := f.up.seen()
			peers, _ := f.up.seenPeers()
			switch cred {
			case "client-certificate":
				if len(peers) == 0 || peers[0] != "masterclient" || auths[0] != "" {
					t.Errorf("the server saw peer %q Authorization %q, want the certificate and no bearer", peers, auths)
				}
			case "token":
				if len(auths) == 0 || auths[0] != "Bearer "+kubeHostToken || peers[0] != "" {
					t.Errorf("the server saw Authorization %q peer %q, want the static token and no certificate", auths, peers)
				}
			}
			if strings.Count(out, "FIND DONE") != 2 || strings.Contains(out, "FOUND") {
				t.Errorf("the host credential is readable inside:\n%s", out)
			}
			after := strings.SplitN(out, "FIND DONE", 3)[2]
			for _, bad := range []string{kubeHostToken, f.keyB64, "kind-kind", "host-user", "client-key-data", "38921",
				"exec", "certificate-authority", kubeServerName} {
				if strings.Contains(after, bad) {
					t.Errorf("%q is visible inside:\n%s", bad, out)
				}
			}
			if !strings.Contains(out, `"server": "http://127.0.0.1:6443"`) {
				t.Errorf("the generated kubeconfig does not name the proxy:\n%s", out)
			}
			if !strings.Contains(out, "No such file") {
				t.Errorf("~/.azure exists inside:\n%s", out)
			}
		})
	}
}

// snug protects the host, not the cluster: impersonation and a guest's own
// Authorization are forwarded for the cluster to judge — under the token
// shape snug's bearer replaces the guest's — and only a path that would climb
// out of the pinned server is refused, before it reaches the server.
func TestKubeImpersonateReachesUpstreamInside(t *testing.T) {
	f := newKubeFixture(t, "token")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, code := f.run(t, `/kubeprobe get /api Impersonate-User:someone "Authorization:Bearer mine";
		/kubeprobe get /k8s/../other/api; echo END`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Count(out, "STATUS 200") != 1 || strings.Count(out, "STATUS 400") != 1 {
		t.Errorf("want one 200 and one 400:\n%s", out)
	}
	auths, paths := f.up.seen()
	_, imp := f.up.seenPeers()
	if len(paths) != 1 || imp[0] != "someone" || auths[0] != "Bearer "+kubeHostToken {
		t.Errorf("upstream saw paths %q Impersonate-User %q Authorization %q", paths, imp, auths)
	}
}

// The certificate and token shapes start no process of their own and write
// no file: while the run lives, every child of snug is snug or bwrap, and no
// file under snug's runtime directory holds a byte of the credential.
func TestKubeCredentialNeverTouchesDiskOrStartsAChild(t *testing.T) {
	for _, cred := range []string{"client-certificate", "token"} {
		t.Run(cred, func(t *testing.T) {
			f := newKubeFixture(t, cred)
			budget(t)
			requireSandbox(t)
			requirePasta(t)
			rt := ""
			for _, e := range f.env {
				if v, ok := strings.CutPrefix(e, "XDG_RUNTIME_DIR="); ok {
					rt = v
				}
			}
			if rt == "" {
				t.Fatal("the fixture environment names no XDG_RUNTIME_DIR")
			}
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, snugFixtureBin, "-p", "kubetest", f.proj, "--", "/bin/sh", "-c",
				"/kubeprobe get /api; sleep 3")
			cmd.Env = f.env
			cmd.WaitDelay = waitDelay
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(cmdTimeout)
			for {
				if _, paths := f.up.seen(); len(paths) > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			// comm, not exe: the stage's user namespace makes /proc/<pid>/exe
			// unreadable from here. The kernel truncates comm to 15 bytes; the
			// stage is snug re-executed through /proc/self/exe, so its comm is
			// "exe" (measured), and pasta's is its binary's, pasta.avx2 here.
			self := filepath.Base(snugFixtureBin)
			self = self[:min(len(self), 15)]
			kids := kubeChildren(cmd.Process.Pid)
			if len(kids) == 0 {
				t.Fatal("snug has no child while the run lives; the check would pass vacuously")
			}
			for _, kid := range kids {
				b, _ := os.ReadFile("/proc/" + kid + "/comm")
				if comm := strings.TrimSpace(string(b)); comm != self && comm != "exe" && comm != "bwrap" &&
					!strings.HasPrefix(comm, "pasta") {
					t.Errorf("snug started %q (pid %s) for credential = %s", comm, kid, cred)
				}
			}
			filepath.WalkDir(filepath.Join(rt, "snug"), func(p string, d fs.DirEntry, err error) error {
				if err != nil || !d.Type().IsRegular() {
					return nil
				}
				b, _ := os.ReadFile(p)
				if bytes.Contains(b, []byte(kubeHostToken)) || bytes.Contains(b, []byte(f.keyB64)) ||
					bytes.Contains(b, []byte("PRIVATE KEY")) {
					t.Errorf("%s holds the host credential", p)
				}
				return nil
			})
			if err := cmd.Wait(); err != nil {
				t.Fatalf("run: %v", err)
			}
		})
	}
}

// kubeChildren is every direct child of pid, from each task's children list.
func kubeChildren(pid int) []string {
	var kids []string
	tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	for _, task := range tasks {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, task.Name()))
		kids = append(kids, strings.Fields(string(b))...)
	}
	return kids
}

// exec, attach and port-forward are upgrades; the tunnel works end to end.
func TestKubeUpgradeWorksInside(t *testing.T) {
	f := newKubeFixture(t, "client-certificate")
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
	f := newKubeFixture(t, "token")
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
	f := newKubeFixtureNet(t, "token", false)
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

func TestKubeKubeconfigIsNotWritable(t *testing.T) {
	f := newKubeFixture(t, "token")
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	out, _ := f.run(t, `echo x >> ~/.kube/config 2>&1; echo END`)
	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("the generated kubeconfig is writable inside:\n%s", out)
	}
}

func TestKubeKubeconfigUnderTargetRefuses(t *testing.T) {
	f := newKubeFixture(t, "token")
	budget(t)
	requireSandbox(t)
	inTarget := filepath.Join(f.proj, "kubeconfig")
	if err := os.WriteFile(inTarget, []byte("clusters: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := writeProfile(t, fmt.Sprintf(`[profile.kubetest]
  [profile.kubetest.identity.kubectl]
  context    = "aks-dev"
  server     = "https://kube.example.invalid:443"
  credential = "token"
  kubeconfig = %q
`, inTarget))
	f.env = env
	out, code := f.run(t, "echo RAN")
	if code != 77 || !strings.Contains(out, "inside the target") || strings.Contains(out, "RAN") {
		t.Errorf("exit %d, want 77 naming the target:\n%s", code, out)
	}
	if _, paths := f.up.seen(); len(paths) != 0 {
		t.Error("a refused selection reached the server")
	}
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
