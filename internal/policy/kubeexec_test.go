package policy

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func kubeExecFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kubeconfig-exec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hostExec(context, server string) IdentityKube {
	return IdentityKube{Context: context, Credential: KubeCredentialExec, Server: server}
}

const (
	aksEntraServer = "https://aks-entra.example.azmk8s.io:443"
	eksDemoServer  = "https://EKS0.gr7.eu-west-1.eks.amazonaws.com"
)

func execResolve(t *testing.T, k IdentityKube, file string, prof func(*Profile)) (*Policy, error) {
	t.Helper()
	if file == "" {
		file = kubeExecFixture(t)
	}
	return kubeResolve(t, kubeCase{kube: k, file: file, profile: prof})
}

func wantExecRefusal(t *testing.T, k IdentityKube, file string, prof func(*Profile), want ...string) {
	t.Helper()
	p, err := execResolve(t, k, file, prof)
	if err == nil || p != nil {
		t.Fatalf("resolved; want a refusal containing %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal does not contain %q:\n%v", w, err)
		}
	}
}

// The AKS shape after `kubelogin convert-kubeconfig -l azurecli`: the argv
// snug runs is BUILT from the parsed fields — --client-id dropped, flags in
// snug's order — and never the file's slice.
func TestKubeHostExecBuildsTheKubeloginArgv(t *testing.T) {
	p, err := execResolve(t, hostExec("aks-entra", aksEntraServer), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	pl := p.Kube.Plugin
	if pl == nil || pl.Row != "kubelogin" || pl.Command != "kubelogin" {
		t.Fatalf("plugin = %+v", pl)
	}
	want := []string{"get-token", "--login", "azurecli", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630",
		"--tenant-id", "00000000-0000-0000-0000-000000000000", "--environment", "AzurePublicCloud"}
	if !reflect.DeepEqual(pl.Args, want) {
		t.Errorf("args = %q\nwant  %q", pl.Args, want)
	}
	if !strings.Contains(pl.Reach, "EVERY AKS cluster in your tenant") {
		t.Errorf("reach = %q", pl.Reach)
	}
	if p.Kube.HostUser.Token != nil || p.Kube.HostUser.ClientKeyData != nil {
		t.Errorf("credential = exec carries a static host credential: %+v", p.Kube)
	}
	if !reflect.DeepEqual(pl.Helpers, []string{"az"}) {
		t.Errorf("helpers = %q, want az judged too", pl.Helpers)
	}
}

func TestKubeHostExecRefusesAnUnknownPlugin(t *testing.T) {
	file := strings.Replace(kubeExecFixture(t), "command: kubelogin", "command: kubelogin-fork", 1)
	wantExecRefusal(t, hostExec("aks-entra", aksEntraServer), file, nil, `"kubelogin-fork"`, "which snug does not run")
}

func TestKubeHostExecRefusesGKEPlugin(t *testing.T) {
	wantExecRefusal(t, hostExec("gke", "https://gke.example.com"), "", nil, "gke-gcloud-auth-plugin",
		"cloud-platform")
}

// A relative command would be looked up wherever the plugin's cwd is; the
// writable-binary half is internal/cli's (judgeKubePlugin), with a read.
func TestKubeHostExecRefusesARelativeCommand(t *testing.T) {
	file := strings.Replace(kubeExecFixture(t), "command: kubelogin", "command: bin/kubelogin", 1)
	wantExecRefusal(t, hostExec("aks-entra", aksEntraServer), file, nil, "relative path", KubePluginPATH)
}

func TestKubeHostExecRefusesArgvOutsideThePluginGrammar(t *testing.T) {
	base := kubeExecFixture(t)
	for _, c := range []struct{ name, old, new, want string }{
		{"unknown flag", "      - --login\n", "      - --legacy\n      - --login\n", `"--legacy"`},
		{"devicecode", "      - azurecli\n", "      - devicecode\n", "kubelogin convert-kubeconfig -l azurecli"},
		{"interactive", "      - azurecli\n", "      - interactive\n", "--login interactive"},
		{"repeated flag", "      - --login\n", "      - --environment\n      - AzureChinaCloud\n      - --login\n", "appears twice"},
		{"positional", "      - get-token\n", "      - get-token\n      - extra\n", "no positional"},
		{"bad uuid", "6dae42f8-4368-4678-94ff-3960e28e3630", "6dae42f8; rm -rf /", "not the shape"},
		{"wrong subcommand", "      - get-token\n", "      - convert-kubeconfig\n", "must start with get-token"},
		{"interactiveMode Always", "interactiveMode: IfAvailable", "interactiveMode: Always", "no terminal"},
		{"apiVersion", "apiVersion: client.authentication.k8s.io/v1beta1\n      args:\n      - get-token",
			"apiVersion: client.authentication.k8s.io/v1alpha1\n      args:\n      - get-token", "v1alpha1"},
		{"unknown exec key", "      provideClusterInfo: false\n", "      provideClusterInfo: false\n      extra: 1\n", `"extra"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := strings.Replace(base, c.old, c.new, 1)
			if file == base {
				t.Fatalf("fixture edit %q did not apply", c.old)
			}
			wantExecRefusal(t, hostExec("aks-entra", aksEntraServer), file, nil, c.want)
		})
	}
}

// The file's exec.env is never used: AWS_PROFILE there refuses until the
// profile names it, and any other name refuses outright. The built
// environment carries the profile's value, never the file's.
func TestKubeHostExecNeverUsesTheFileEnv(t *testing.T) {
	wantExecRefusal(t, hostExec("eks-demo", eksDemoServer), "", nil, "AWS_PROFILE", "identity.kubectl.aws_profile")
	k := hostExec("eks-demo", eksDemoServer)
	k.AWSProfile = "work"
	p, err := execResolve(t, k, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(p.Kube.Plugin.KubePluginEnv("/home/u"), "\n")
	if !strings.Contains(env, "AWS_PROFILE=work") || strings.Contains(env, "FIXTUREPROFILEVALUE") {
		t.Errorf("plugin env = %q", env)
	}
	want := []string{"eks", "get-token", "--cluster-name", "demo", "--region", "eu-west-1", "--output", "json"}
	if !reflect.DeepEqual(p.Kube.Plugin.Args, want) {
		t.Errorf("aws args = %q, want %q", p.Kube.Plugin.Args, want)
	}
	other := strings.Replace(kubeExecFixture(t), "- name: AWS_PROFILE", "- name: HTTPS_PROXY", 1)
	wantExecRefusal(t, k, other, nil, `"HTTPS_PROXY"`, "never uses")
}

// argv, env and cwd of the plugin are snug's: nothing in them names the
// target, so nothing the repository chose rides into a host process.
func TestKubeHostExecNeverSeesTheTarget(t *testing.T) {
	k := hostExec("eks-demo", eksDemoServer)
	k.AWSProfile = "work"
	p, err := execResolve(t, k, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(append(p.Kube.Plugin.KubeExecArgv("/usr/local/bin/aws"), p.Kube.Plugin.KubePluginEnv("/home/u")...), "\n")
	if strings.Contains(all, p.Target) {
		t.Errorf("the plugin's argv or env names the target %s:\n%s", p.Target, all)
	}
}

func TestKubeHostExecRefusesAWritableConfigDir(t *testing.T) {
	for _, c := range []struct {
		ctx, server, dir string
		k                func(*IdentityKube)
	}{
		{"aks-entra", aksEntraServer, "/home/u/.azure", nil},
		{"aks-entra", aksEntraServer, "/home/u/.kube/cache", nil},
		{"eks-demo", eksDemoServer, "/home/u/.aws", func(k *IdentityKube) { k.AWSProfile = "work" }},
	} {
		t.Run(c.dir, func(t *testing.T) {
			k := hostExec(c.ctx, c.server)
			if c.k != nil {
				c.k(&k)
			}
			wantKubeRefusal(t, kubeCase{kube: k, file: kubeExecFixture(t),
				profile: func(p *Profile) { p.RW = append(p.RW, c.dir) },
				env:     func(e *fakeEnv) { e.dirs[c.dir] = true },
			}, "WRITABLE", "runs on the host", c.dir)
		})
	}
}

func TestKubeAWSProfileRefusedWithoutAnAWSRow(t *testing.T) {
	k := hostExec("aks-entra", aksEntraServer)
	k.AWSProfile = "work"
	wantExecRefusal(t, k, "", nil, "aws_profile is set", "kubelogin")
	cert := IdentityKube{Context: "aks-dev", Credential: KubeCredentialClientCert,
		Server: "https://aks-dev.example.azmk8s.io:443", AWSProfile: "work"}
	wantKubeRefusal(t, kubeCase{kube: cert}, "aws_profile is set", "runs no aws plugin")
}

// Absent credential on an entry whose only credential is its exec plugin is
// that plugin: the only reading, printed on the dry run.
func TestKubeCredentialAbsentOnAnExecOnlyEntryIsExec(t *testing.T) {
	k := hostExec("aks-entra", aksEntraServer)
	k.Credential = ""
	p, err := execResolve(t, k, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kube.Credential != KubeCredentialExec || p.Kube.Plugin == nil {
		t.Errorf("Kube = %+v", p.Kube)
	}
}

func TestKubeHostExecAcceptsV1AndV1beta1(t *testing.T) {
	for _, file := range []string{"", strings.Replace(kubeExecFixture(t),
		"apiVersion: client.authentication.k8s.io/v1beta1\n      args:\n      - get-token",
		"apiVersion: client.authentication.k8s.io/v1\n      args:\n      - get-token", 1)} {
		p, err := execResolve(t, hostExec("aks-entra", aksEntraServer), file, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := p.Kube.Plugin.APIVersion; v != "client.authentication.k8s.io/v1beta1" && v != "client.authentication.k8s.io/v1" {
			t.Errorf("apiVersion = %q", v)
		}
	}
	p, err := execResolve(t, hostExec("eks-iam", "https://iam.example.com"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kube.Plugin.APIVersion != "client.authentication.k8s.io/v1" ||
		!reflect.DeepEqual(p.Kube.Plugin.Args, []string{"token", "--cluster-id", "demo"}) {
		t.Errorf("aws-iam-authenticator plugin = %+v", p.Kube.Plugin)
	}
}
