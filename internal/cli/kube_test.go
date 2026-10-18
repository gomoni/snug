package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/kubeproxy"
	"github.com/gomoni/snug/internal/policy"
)

func TestKubeDryRunRunsNothing(t *testing.T) {
	rt := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	// A server on loopback: a dry run neither resolves nor refuses it,
	// because it starts nothing.
	pol := &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{}, Env: map[string]policy.EnvVar{},
		Kube: &policy.KubeBinding{Context: "aks-dev", Server: "https://127.0.0.1:6443",
			Credential: policy.KubeCredentialToken, HostUser: policy.KubeHostUser{Token: policy.Secret("tok")}}}
	run, err := startKubeIdentity(pol, false, true)
	if err != nil {
		t.Fatalf("a dry run refused: %v", err)
	}
	if run != nil {
		t.Error("a dry run started a kube run")
	}
	ents, _ := os.ReadDir(rt)
	if len(ents) != 0 {
		t.Errorf("a dry run created %v under XDG_RUNTIME_DIR", ents)
	}
}

// A certificate or token shape starts no process and writes nothing: the
// credential is a Go value handed to the proxy.
func TestKubeCredentialShapesStartNothingAndWriteNothing(t *testing.T) {
	rt := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	old := kubePreflight
	kubePreflight = func(context.Context, kubeproxy.Config) error { return nil }
	defer func() { kubePreflight = old }()
	pol := &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{}, Env: map[string]policy.EnvVar{},
		Kube: &policy.KubeBinding{Context: "aks-dev", Server: "https://aks-dev.example.azmk8s.io:443", Credential: policy.KubeCredentialToken,
			HostUser: policy.KubeHostUser{Token: policy.Secret("tok")}, TokenLen: 3}}
	run, err := startKubeIdentity(pol, false, false)
	if err != nil || run == nil || run.token == nil || string(*run.token) != "tok" || run.cert != nil {
		t.Fatalf("token shape: run %+v, %v", run, err)
	}
	run.close()
	if ents, _ := os.ReadDir(rt); len(ents) != 0 {
		t.Errorf("the token shape created %v under XDG_RUNTIME_DIR", ents)
	}
	expired := &policy.Policy{Home: "/home/u", Kube: &policy.KubeBinding{Context: "aks-dev",
		Credential: policy.KubeCredentialClientCert, CertSubject: "CN=x", CertNotAfter: time.Now().Add(-time.Hour)}}
	if _, err := startKubeIdentity(expired, false, false); err == nil ||
		!strings.Contains(err.Error(), "expired on") {
		t.Errorf("an expired client certificate started a run: %v", err)
	}
}

// A server on this host — loopback, or an address this host owns — refuses
// the run before the sandbox exists, whatever credential the context holds.
func TestKubeRunRefusesAServerOnThisHost(t *testing.T) {
	old := kubeHostAddresses
	kubeHostAddresses = func() ([]string, error) { return []string{"192.0.2.10"}, nil }
	defer func() { kubeHostAddresses = old }()
	for _, server := range []string{"https://127.0.0.1:6443", "https://[::1]:6443", "https://192.0.2.10:6443"} {
		pol := &policy.Policy{Home: "/home/u", Kube: &policy.KubeBinding{Context: "kind-kind", Server: server,
			Credential: policy.KubeCredentialToken, HostUser: policy.KubeHostUser{Token: policy.Secret("tok")}}}
		run, err := startKubeIdentity(pol, false, false)
		if err == nil || run != nil || !strings.Contains(err.Error(), "cluster on this host") {
			t.Errorf("%s: run %v, err %v; want the on-this-host refusal", server, run, err)
		}
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
