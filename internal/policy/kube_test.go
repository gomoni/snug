package policy

import (
	"strings"
	"testing"
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
