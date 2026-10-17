package policy

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/hostread"
)

func TestKubeIdentityUnknownTokenValueRefuses(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"k": {Kube: IdentityKube{Context: "aks-dev", Token: "static", ServiceAccount: "dev/snug-agent"}},
	})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err == nil || p != nil || !strings.Contains(err.Error(), "(want serviceaccount)") ||
		!strings.Contains(err.Error(), `"k"`) {
		t.Fatalf("p = %v, err = %v; want a nil policy and the unknown-token refusal naming the profile", p, err)
	}
}

// An omitted kubeconfig takes the default before the path loop, so it is
// expanded and compared like an explicit spelling: three spellings of one path
// are one pin, not three.
func TestKubeKubeconfigSpellingsAreOneIdentity(t *testing.T) {
	block := func(kc string) Identity {
		return Identity{Kube: IdentityKube{Context: "aks-dev", Token: KubeTokenServiceAccount,
			ServiceAccount: "dev/snug-agent", Kubeconfig: kc}}
	}
	for _, pair := range [][2]string{{"", "{home}/.kube/config"}, {"", "~/.kube/config"}, {"{home}/.kube/config", "~/.kube/config"}} {
		reg, sel := identityProfiles(map[ProfileName]Identity{"ident-a": block(pair[0]), "ident-b": block(pair[1])})
		p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("kubeconfig %q and %q refused each other: %v", pair[0], pair[1], err)
		}
		if got := p.Identity.Kube.Kubeconfig; got != "/home/u/.kube/config" {
			t.Errorf("stored kubeconfig = %q, want the expanded default", got)
		}
	}
}

func TestOSEnvironKubeConfigRefusesALinkAndAnOversizedFile(t *testing.T) {
	dir := t.TempDir()
	good := dir + "/config"
	if err := os.WriteFile(good, []byte("clusters:\n- name: a\n  cluster:\n    server: https://a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OSEnviron{}.KubeConfig(good)
	if err != nil || len(f.Clusters) != 1 || f.Clusters[0].Fields["server"].Text != "https://a.example" {
		t.Fatalf("regular file: %+v, %v", f, err)
	}
	link := dir + "/link"
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSEnviron{}).KubeConfig(link); err == nil {
		t.Error("a symlinked kubeconfig was read; a planted link would choose the server")
	}
	big := dir + "/big"
	if err := os.WriteFile(big, bytes.Repeat([]byte("#\n"), hostread.MaxKubeconfigBytes/2+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSEnviron{}).KubeConfig(big); err == nil {
		t.Error("a kubeconfig over MaxKubeconfigBytes was read")
	}
	if _, err := (OSEnviron{}).KubeConfig(dir + "/absent"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent file: err = %v, want fs.ErrNotExist", err)
	}
}
