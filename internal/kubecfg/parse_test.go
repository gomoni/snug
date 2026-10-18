package kubecfg

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAcceptsWhatKubectlAndAzWrite(t *testing.T) {
	for _, name := range []string{"kubectl-written.yaml", "az-written.yaml", "json-written.json"} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(mustRead(t, name))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var aks *Cluster
			for i := range f.Clusters {
				if f.Clusters[i].Name == "aks-dev" {
					aks = &f.Clusters[i]
				}
			}
			if aks == nil {
				t.Fatalf("no aks-dev cluster in %+v", f.Clusters)
			}
			if got := aks.Fields["server"].Text; got != "https://aks-dev-dns-0000.hcp.example.azmk8s.io:443" {
				t.Errorf("server = %q", got)
			}
			if got := aks.Fields["certificate-authority-data"].Text; got != "RkFLRUNB" {
				t.Errorf("certificate-authority-data = %q", got)
			}
			var ctx *Context
			for i := range f.Contexts {
				if f.Contexts[i].Name == "aks-dev" {
					ctx = &f.Contexts[i]
				}
			}
			if ctx == nil || ctx.Cluster != "aks-dev" || ctx.User == "" {
				t.Fatalf("aks-dev context = %+v", ctx)
			}
			if len(f.Users) == 0 || f.Users[0].Fields["token"].Text == "" && f.Users[0].Fields["client-key-data"].Text == "" {
				t.Errorf("users carry no credential field: %+v", f.Users)
			}
		})
	}
}

func TestParseKeepsExecCommandAndContextExtras(t *testing.T) {
	f, err := Parse(mustRead(t, "kubectl-written.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var eks *User
	for i := range f.Users {
		if f.Users[i].Name == "eks" {
			eks = &f.Users[i]
		}
	}
	if eks == nil || eks.Exec == nil || eks.Exec.Command != "aws" {
		t.Fatalf("eks user exec = %+v", eks)
	}
	if v := eks.Fields["exec"]; v.Kind != Map || v.Len == 0 {
		t.Errorf("exec field = %+v, want a non-empty mapping", v)
	}
	f2, err := Parse([]byte("contexts:\n- name: c\n  context:\n    cluster: x\n    user: y\n    extensions: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f2.Contexts[0].Other; !reflect.DeepEqual(got, []string{"extensions"}) {
		t.Errorf("Other = %q, want [extensions]", got)
	}
}

func TestParseRecordsQuotingOfScalars(t *testing.T) {
	f, err := Parse([]byte("clusters:\n- name: a\n  cluster:\n    insecure-skip-tls-verify: false\n- name: b\n  cluster:\n    insecure-skip-tls-verify: \"false\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := f.Clusters[0].Fields["insecure-skip-tls-verify"]; v.Text != "false" || v.Quoted {
		t.Errorf("plain false = %+v", v)
	}
	if v := f.Clusters[1].Fields["insecure-skip-tls-verify"]; v.Text != "false" || !v.Quoted {
		t.Errorf("quoted false = %+v", v)
	}
}

func TestParseRefusesEachUnsupportedConstruct(t *testing.T) {
	const pre = "clusters:\n- name: a\n  cluster:\n"
	cases := []struct {
		name, doc, want string
	}{
		{"anchor", pre + "    server: &s https://x\n", "line 4: a YAML anchor"},
		{"alias", pre + "    server: *s\n", "line 4: a YAML alias"},
		{"tag", pre + "    server: !!str https://x\n", "line 4: a YAML tag"},
		{"literal block", pre + "    server: |\n      https://x\n", "line 4: block scalars"},
		{"folded block", pre + "    server: >\n      https://x\n", "line 4: block scalars"},
		{"multi-line plain", pre + "    server: https://x\n      continued\n", "line 5: a value continued"},
		{"multi-line quoted", pre + "    server: \"https://x\n      y\"\n", "line 4: a quoted scalar that continues"},
		{"complex key", pre + "    ? server\n    : https://x\n", "line 4: complex mapping keys"},
		{"merge key", pre + "    <<: {}\n", "line 4: the YAML merge key"},
		{"flow mapping", pre + "    extensions: {a: 1}\n", "line 4: flow mappings"},
		{"flow sequence", pre + "    extensions: [a]\n", "line 4: flow sequences"},
		{"second document", "kind: Config\n---\nkind: Config\n", "line 2: a second YAML document"},
		{"document end", "kind: Config\n...\n", "line 2: the YAML document end marker"},
		{"directive", "%YAML 1.2\nkind: Config\n", "line 1: YAML directives"},
		{"tab indent", pre + "\tserver: https://x\n", "line 4: a tab in indentation"},
		{"bad escape", pre + "    server: \"https://\\x41\"\n", "line 4: the escape \\x"},
		{"quoted key", pre + "    \"server\": https://x\n", "line 4: quoted mapping keys"},
		{"bad indent", pre + "    server: https://x\n   name: b\n", "line 5: indentation does not match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestParseRefusesDuplicateKeys(t *testing.T) {
	for name, doc := range map[string]string{
		"top level": "kind: Config\nkind: Config\n",
		"nested":    "clusters:\n- name: a\n  cluster:\n    server: https://x\n    server: https://y\n",
		"json":      `{"clusters":[{"name":"a","cluster":{"server":"https://x","server":"https://y"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), "appears twice") {
				t.Fatalf("Parse error = %v, want a duplicate-key refusal", err)
			}
		})
	}
}

func TestParseRefusesWhatIsNotAKubeconfig(t *testing.T) {
	for name, doc := range map[string]string{
		"scalar top":        "hello\n",
		"clusters not seq":  "clusters: x\n",
		"entry no name":     "clusters:\n- cluster:\n    server: https://x\n",
		"unknown entry key": "clusters:\n- name: a\n  cluster: {}\n  extra: 1\n",
		"not utf8":          "kind: \xff\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("Parse accepted it")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"kubectl-written.yaml", "az-written.yaml", "json-written.json"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, errA := Parse(data)
		b, errB := Parse(data)
		if (errA == nil) != (errB == nil) || !reflect.DeepEqual(a, b) {
			t.Fatalf("Parse is not deterministic on %q", data)
		}
	})
}

// The shape `az aks get-credentials` writes for an Entra-integrated cluster,
// after `kubelogin convert-kubeconfig -l azurecli`: block-sequence args, a null
// env, and an installHint block scalar — the one block scalar the decoder
// accepts, skipped rather than decoded.
func TestParseKeepsAnExecEntryAsData(t *testing.T) {
	f, err := Parse(mustRead(t, "aks-exec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	e := f.Users[0].Exec
	if e == nil {
		t.Fatal("no exec entry")
	}
	want := &Exec{
		APIVersion: "client.authentication.k8s.io/v1beta1", Command: "kubelogin",
		Args: []string{"get-token", "--environment", "AzurePublicCloud", "--server-id",
			"6dae42f8-4368-4678-94ff-3960e28e3630", "--client-id", "80faf920-1908-4b52-b5ef-a8e7bedfc67a",
			"--tenant-id", "00000000-0000-0000-0000-000000000000", "--login", "azurecli"},
		InteractiveMode: "IfAvailable", ProvideClusterInfo: "false",
	}
	if !reflect.DeepEqual(e, want) {
		t.Errorf("exec = %+v\nwant   %+v", e, want)
	}
	k, err := Parse(mustRead(t, "kubectl-written.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range k.Users {
		if u.Name == "eks" && !reflect.DeepEqual(u.Exec.EnvNames, []string{"AWS_PROFILE"}) {
			t.Errorf("eks env names = %q", u.Exec.EnvNames)
		}
	}
}

// installHint is the only key a block scalar may follow; under any other key,
// and as an arg, it still refuses.
func TestParseRefusesABlockScalarOutsideInstallHint(t *testing.T) {
	for _, doc := range []string{
		"users:\n- name: u\n  user:\n    token: |\n      abc\n",
		"users:\n- name: u\n  user:\n    exec:\n      command: |\n        kubelogin\n",
		"users:\n- name: u\n  user:\n    exec:\n      args:\n      - |\n        get-token\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "block scalar") {
			t.Errorf("%q: err = %v, want a block-scalar refusal", doc, err)
		}
	}
	if _, err := Parse([]byte("users:\n- name: u\n  user:\n    exec:\n      installHint: |\n        a: b\n        - c\n      command: kubelogin\n")); err != nil {
		t.Errorf("an installHint whose prose looks like YAML: %v", err)
	}
}
