package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// kubePolicy resolves the builtin defaults plus @net and one kube identity
// against the policy package's fixture kubeconfig, and stages what a dry run
// stages.
func kubePolicy(t *testing.T) *policy.Policy { return kubePolicyNet(t, true) }

func kubePolicyNet(t *testing.T, withNet bool) *policy.Policy {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("PATH", t.TempDir()) // no host kubectl: the screen says so
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["aks-dev"] = &policy.Profile{Name: "aks-dev", Identity: &policy.Identity{Kube: policy.IdentityKube{
		Context: "aks-dev", Token: policy.KubeTokenServiceAccount, Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}}}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "aks-dev")
	if withNet {
		sel = append(sel, "@net")
	}
	fixture, err := os.ReadFile("../policy/testdata/kubeconfig.yaml")
	if err != nil {
		t.Fatal(err)
	}
	env := newEnvFakeEnv()
	env.kube = map[string][]byte{"/home/u/.kube/config": fixture}
	ctx := envGoldenCtx()
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := startKubeIdentity(p, env, false, true); err != nil {
		t.Fatal(err)
	}
	p.InstallAnchors()
	return p
}

func checkGolden(t *testing.T, name, got, why string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update, then READ the diff: %s)", err, why)
	}
	if got != string(want) {
		t.Errorf("%s changed — %s. Run with -update and read the diff.\n%s", name, why, got)
	}
}

func TestGoldenKubeArgv(t *testing.T) {
	p := kubePolicy(t)
	got := runDirPID.ReplaceAllString(goldenFormat(p.BwrapArgs(1000, 1000)), "run-N")
	for _, want := range []string{
		"/home/u/.kube/config", "KUBECONFIG",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("argv does not name %s", want)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "/home/u/.kube") && !strings.HasPrefix(line, "--ro-bind-data") &&
			!strings.Contains(line, "KUBECONFIG") && !strings.HasPrefix(line, "--dir") && !strings.HasPrefix(line, "--tmpfs") {
			t.Errorf("argv reaches the host ~/.kube other than through the generated file: %q", line)
		}
	}
	checkGolden(t, "identity-kube.bwrap.txt", got, "this is the argv for a sandbox behind a cluster credential proxy")
}

func TestGoldenKubeDryRunBlock(t *testing.T) {
	p := kubePolicy(t)
	var b bytes.Buffer
	describeKube(&b, buildKubeReport(p))
	got := runDirPID.ReplaceAllString(b.String(), "run-N")
	for _, want := range []string{"a real run would REFUSE", "static token is not used",
		"this pinned", "kind-kind", "~/.azure", "RoleBinding", "  --namespace=dev\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("KUBE block lacks %q:\n%s", want, got)
		}
	}
	checkGolden(t, "kube.dryrun.txt", got, "this is what a human reads before trusting a cluster credential proxy")
}

func TestProfileShowNamesTheKubeCapability(t *testing.T) {
	var got []string
	showIdentity(&policy.Identity{Kube: policy.IdentityKube{Context: "aks-dev", Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}},
		func(_ string, rows []string) { got = rows })
	all := strings.Join(got, "\n")
	for _, want := range []string{"kube aks-dev as dev/snug-agent", "ACT AS THIS SERVICEACCOUNT", "RoleBinding"} {
		if !strings.Contains(all, want) {
			t.Errorf("profile show lacks %q:\n%s", want, all)
		}
	}
}

func TestNotGrantedListsAzure(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".azure"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Home: home, Target: filepath.Join(home, "proj"), Mounts: map[string]policy.Mount{}}
	if got := strings.Join(notGranted(p), "\n"); !strings.Contains(got, ".azure") {
		t.Errorf("not-granted does not name ~/.azure, which holds a tenant-wide refresh token:\n%s", got)
	}
}

// Red-team finding: the absent row was a constant, so a grant onto ~/.azure
// was readable inside while the screen said absent.
func TestKubeDryRunSaysWhenAGrantShowsAzure(t *testing.T) {
	p := kubePolicy(t)
	p.Mounts["/home/u/.azure"] = policy.Mount{Guest: "/home/u/.azure", Host: "/srv/az", Kind: policy.KindBind, From: []string{"leaky"}}
	var b bytes.Buffer
	describeKube(&b, buildKubeReport(p))
	got := b.String()
	if !strings.Contains(got, "VISIBLE    ~/.azure (granted by leaky)") {
		t.Errorf("a granted ~/.azure is not called out:\n%s", got)
	}
	if strings.Contains(got, "~/.kube/cache, ~/.azure") {
		t.Errorf("~/.azure is still listed absent:\n%s", got)
	}
}

// A kube profile without @net resolves, gets a stage for the proxy's socket,
// and the NETWORK block says the one thing that makes "isolated" untrue.
func TestKubeOnlyProfileIsNotOffline(t *testing.T) {
	p := kubePolicyNet(t, false)
	if p.Net.Mode != policy.NetIsolated || !p.Topology.NeedsStage() {
		t.Fatalf("net %s, needs stage %v; want isolated with a stage", p.Net.Mode, p.Topology.NeedsStage())
	}
	var b strings.Builder
	describeNetwork(&b, p)
	for _, want := range []string{"NETWORK  isolated", "EXCEPT   127.0.0.1:6443", p.Kube.Server,
		"dialled from the HOST", "not an offline profile"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("NETWORK block lacks %q:\n%s", want, b.String())
		}
	}
}

// identity.kube with token = "host-exec" against the AKS kubelogin shape.
func kubeHostExecPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["aks-entra"] = &policy.Profile{Name: "aks-entra", Identity: &policy.Identity{Kube: policy.IdentityKube{
		Context: "aks-entra", Token: policy.KubeTokenHostExec, Server: "https://aks-entra.example.azmk8s.io:443"}}}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "aks-entra")
	fixture, err := os.ReadFile("../policy/testdata/kubeconfig-exec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	env := newEnvFakeEnv()
	env.kube = map[string][]byte{"/home/u/.kube/config": fixture}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := startKubeIdentity(p, env, false, true); err != nil {
		t.Fatal(err)
	}
	p.InstallAnchors()
	return p
}

func TestGoldenKubeHostExecDryRunBlock(t *testing.T) {
	p := kubeHostExecPolicy(t)
	var b bytes.Buffer
	describeKube(&b, buildKubeReport(p))
	got := b.String()
	for _, want := range []string{"YOU — the user of context aks-entra, through its kubelogin plugin",
		"--login azurecli", "valid as you at EVERY", "exec.env is never used",
		"env PATH=/usr/local/bin:/usr/bin:/bin\n", "env PYTHONNOUSERSITE=1\n", "it runs az off that PATH",
		"YOUR RBAC allows", "a real run would REFUSE", "not found on /usr/local/bin:/usr/bin:/bin"} {
		if !strings.Contains(got, want) {
			t.Errorf("KUBE block lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"host mint", "80faf920", "ServiceAccount"} {
		if strings.Contains(got, bad) {
			t.Errorf("KUBE block shows %q under host-exec:\n%s", bad, got)
		}
	}
	checkGolden(t, "kube-host-exec.dryrun.txt", got, "this is what a human reads before snug runs a plugin as them")
}
