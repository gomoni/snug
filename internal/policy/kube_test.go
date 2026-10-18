package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/hostread"
)

func TestKubeIdentityUnknownTokenValueRefuses(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"k": {Kube: IdentityKube{Context: "aks-dev", Token: "static", Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}},
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
			Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent", Kubeconfig: kc}}
	}
	for _, pair := range [][2]string{{"", "{home}/.kube/config"}, {"", "~/.kube/config"}, {"{home}/.kube/config", "~/.kube/config"}} {
		reg, sel := identityProfiles(map[ProfileName]Identity{"ident-a": block(pair[0]), "ident-b": block(pair[1])})
		reg, sel = withEgress(reg, sel)
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

// withEgress adds a profile granting the network, which identity.kube needs.
func withEgress(reg map[ProfileName]*Profile, sel []ProfileName) (map[ProfileName]*Profile, []ProfileName) {
	reg["egress"] = &Profile{Name: "egress", Network: "egress"}
	return reg, append(sel, "egress")
}

func kubeFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kubeconfig.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type kubeCase struct {
	kube    IdentityKube
	file    string // the host kubeconfig; "" leaves the fixture
	noNet   bool
	ctx     func(*Context)
	profile func(*Profile)
	env     func(*fakeEnv)
}

func kubeResolve(t *testing.T, c kubeCase) (*Policy, error) {
	t.Helper()
	k := IdentityKube{Context: "aks-dev", Token: KubeTokenServiceAccount, Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}
	if c.kube != (IdentityKube{}) {
		k = c.kube
	}
	prof := &Profile{Name: "kube", Identity: &Identity{Kube: k}}
	if !c.noNet {
		prof.Network = "egress"
	}
	if c.profile != nil {
		c.profile(prof)
	}
	reg := testRegistry()
	reg["kube"] = prof
	env := newFakeEnv()
	if c.file != "" {
		env.kube["/home/u/.kube/config"] = []byte(c.file)
	}
	if c.env != nil {
		c.env(env)
	}
	ctx := testCtx()
	if c.ctx != nil {
		c.ctx(&ctx)
	}
	return Resolve(reg, append(append([]ProfileName{}, testDefaults...), "kube"), ctx, env)
}

func wantKubeRefusal(t *testing.T, c kubeCase, want ...string) {
	t.Helper()
	p, err := kubeResolve(t, c)
	if err == nil || p != nil {
		t.Fatalf("resolved (p != nil: %v); want a refusal containing %q", p != nil, want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal does not contain %q:\n%v", w, err)
		}
	}
}

func TestKubeIdentityGeneratesOneClusterOneContextAndTheShim(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/home/u/.kube/config"]
	if !ok || m.Kind != KindData || m.Access != AccessRO {
		t.Fatalf("~/.kube/config = %+v, want a read-only generated file", m)
	}
	var got struct {
		Clusters []struct {
			Name    string
			Cluster map[string]any
		}
		Users []struct {
			Name string
			User struct{ Exec map[string]any }
		}
		Contexts []struct {
			Name    string
			Context map[string]string
		}
		CurrentContext string `json:"current-context"`
	}
	if err := json.Unmarshal(m.Content, &got); err != nil {
		t.Fatalf("generated kubeconfig is not JSON: %v", err)
	}
	if len(got.Clusters) != 1 || len(got.Users) != 1 || len(got.Contexts) != 1 {
		t.Fatalf("want one of each, got %+v", got)
	}
	if got.Clusters[0].Cluster["server"] != "https://aks-dev.example.azmk8s.io:443" {
		t.Errorf("server = %v", got.Clusters[0].Cluster["server"])
	}
	if got.Users[0].User.Exec["command"] != KubeTokenShimGuest {
		t.Errorf("exec command = %v, want %s", got.Users[0].User.Exec["command"], KubeTokenShimGuest)
	}
	if got.Contexts[0].Context["namespace"] != "dev" || got.CurrentContext != "aks-dev" {
		t.Errorf("context = %+v, current = %q", got.Contexts[0], got.CurrentContext)
	}
	shim, ok := p.Mounts[KubeTokenShimGuest]
	if !ok || shim.Kind != KindBind || shim.Access != AccessRO || shim.Host != "/usr/bin/snug" {
		t.Errorf("shim mount = %+v, want a read-only bind of snug's executable", shim)
	}
	if e := p.Env["KUBECONFIG"]; len(e.Entries) != 1 || e.Entries[0].Value != "/home/u/.kube/config" {
		t.Errorf("KUBECONFIG = %+v", e)
	}
	if p.Kube == nil || p.Kube.SAName != "snug-agent" || p.Kube.SANamespace != "dev" {
		t.Errorf("Kube = %+v", p.Kube)
	}
}

func TestKubeIdentityNeverCopiesAHostUserEntry(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	cert := base64.StdEncoding.EncodeToString([]byte("FIXTURECERT"))
	key := base64.StdEncoding.EncodeToString([]byte("FIXTUREKEYMATERIAL"))
	for guest, m := range p.Mounts {
		c := string(m.Content)
		for _, bad := range []string{"FIXTUREKEYMATERIAL", key, "FIXTURECERT", cert, "FIXTURETOKENVALUE",
			"clusterUser_rg_aks-dev", "kind-kind", "38921", "aws", "client-key-data", "\"token\""} {
			if strings.Contains(c, bad) {
				t.Errorf("%s carries %q from the host kubeconfig", guest, bad)
			}
		}
	}
	if got := strings.Join(p.Kube.OtherContexts, ","); got != "eks,kind-kind" {
		t.Errorf("OtherContexts = %q", got)
	}
}

func TestKubeHostUserPrefersCertificateOverToken(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Kube.HostUser.ClientKeyData) != "FIXTUREKEYMATERIAL" || len(p.Kube.HostUser.Token) != 0 {
		t.Errorf("HostUser keeps key %q and token %d bytes; want the key and no token",
			string(p.Kube.HostUser.ClientKeyData), len(p.Kube.HostUser.Token))
	}
	if !slices.Contains(p.Kube.HostUserShape, "static token") {
		t.Errorf("HostUserShape = %v, want it to say the static token stayed out", p.Kube.HostUserShape)
	}
}

func TestKubeIdentityAbsentAddsNothing(t *testing.T) {
	reg := testRegistry()
	p, err := Resolve(reg, testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if p.Kube != nil {
		t.Errorf("Kube = %+v with no kube block", p.Kube)
	}
	for _, g := range []string{"/home/u/.kube/config", KubeTokenShimGuest} {
		if _, ok := p.Mounts[g]; ok {
			t.Errorf("%s mounted with no kube block", g)
		}
	}
	if _, ok := p.Env["KUBECONFIG"]; ok {
		t.Error("KUBECONFIG set with no kube block")
	}
}

func TestKubeIdentityRefusesALoopbackServer(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "kind-kind", Token: KubeTokenServiceAccount,
		Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}}, "host's loopback", "THERE IS NO")
	for _, srv := range []string{"https://localhost:6443", "https://[::1]:6443", "https://api.localhost"} {
		wantKubeRefusal(t, kubeCase{file: strings.Replace(kubeFixture(t),
			"https://aks-dev.example.azmk8s.io:443", srv, 1)}, "host's loopback")
	}
}

func TestKubeIdentityRefusesAHostOwnedServer(t *testing.T) {
	wantKubeRefusal(t, kubeCase{
		file: strings.Replace(kubeFixture(t), "https://aks-dev.example.azmk8s.io:443", "https://192.0.2.10:6443", 1),
		ctx:  func(c *Context) { c.HostAddresses = []string{"192.0.2.10"} },
	}, "an address this host owns")
}

func TestKubeIdentityRefusesPlainHTTPServer(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: strings.Replace(kubeFixture(t),
		"https://aks-dev.example.azmk8s.io:443", "http://aks-dev.example.azmk8s.io", 1)}, "is not https")
}

func clusterField(t *testing.T, line string) string {
	return strings.Replace(kubeFixture(t), "    server: https://aks-dev.example.azmk8s.io:443\n",
		"    server: https://aks-dev.example.azmk8s.io:443\n    "+line+"\n", 1)
}

func TestKubeIdentityRefusesInsecureSkipTLSVerify(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "insecure-skip-tls-verify: true")}, "no TLS downgrade", "--embed-certs")
	wantKubeRefusal(t, kubeCase{file: clusterField(t, `insecure-skip-tls-verify: "false"`)}, "no TLS downgrade")
	if _, err := kubeResolve(t, kubeCase{file: clusterField(t, "insecure-skip-tls-verify: false")}); err != nil {
		t.Errorf("insecure-skip-tls-verify: false refused: %v", err)
	}
}

func TestKubeIdentityRefusesProxyURL(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "proxy-url: http://proxy.example:3128")}, "carries no proxy")
}

func TestKubeIdentityRefusesACertificateAuthorityPath(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "certificate-authority: /etc/ca.pem")}, "--embed-certs")
}

func TestKubeIdentityRefusesAnUnknownClusterField(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "disable-compression: true")}, "refused rather than dropped")
}

func TestKubeIdentityRequiresEgress(t *testing.T) {
	wantKubeRefusal(t, kubeCase{noNet: true}, "needs egress", "@net")
}

func TestKubeIdentityUnknownContextNamesTheKnownOnes(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-prod", Token: KubeTokenServiceAccount,
		Server: "https://aks-dev.example.azmk8s.io:443", ServiceAccount: "dev/snug-agent"}}, `"aks-prod"`, "contexts: aks-dev, eks, kind-kind")
}

func TestKubeServiceAccountRefusesAnExecUser(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "eks", Token: KubeTokenServiceAccount,
		Server: "https://eks.example.com", ServiceAccount: "dev/snug-agent"}}, "exec plugin (aws)", "#659")
	userField := func(line string) string {
		return strings.Replace(kubeFixture(t), "    token: FIXTURETOKENVALUE\n", "    token: FIXTURETOKENVALUE\n    "+line+"\n", 1)
	}
	for _, line := range []string{"auth-provider:\n      name: oidc", "client-certificate: /etc/c.pem",
		"tokenFile: /etc/t", "as: admin", "username: admin"} {
		wantKubeRefusal(t, kubeCase{file: userField(line)}, "user of context")
	}
}

func TestKubeIdentityRefusesAMalformedBlock(t *testing.T) {
	sa := func(s string) IdentityKube {
		return IdentityKube{Context: "aks-dev", Token: KubeTokenServiceAccount, ServiceAccount: s}
	}
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Token: KubeTokenServiceAccount, ServiceAccount: "dev/a"}}, "needs identity.kube.context")
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-dev", ServiceAccount: "dev/a"}}, "token is not set")
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-dev", Token: KubeTokenServiceAccount}}, "needs identity.kube.service_account")
	for _, bad := range []string{"nons", "Dev/a", "-x/a", "dev/-a", "dev/", "/a", "dev/a/b"} {
		wantKubeRefusal(t, kubeCase{kube: sa(bad)}, "is not \"namespace/name\"")
	}
}

func TestKubeIdentityRefusesAMissingOrUndecodableFile(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{profile: func(p *Profile) { p.Identity.Kube.Kubeconfig = "/home/u/.kube/absent" }})
	if err == nil || p != nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("absent kubeconfig: %v", err)
	}
	wantKubeRefusal(t, kubeCase{file: "clusters: &a []\n"}, "anchors, aliases")
	wantKubeRefusal(t, kubeCase{file: kubeFixture(t) + "- context:\n    cluster: eks\n    user: eks\n  name: eks\n"},
		"line") // a second `contexts:`-level sequence item after users is malformed, not silently merged
}

func TestKubeIdentityRefusesDuplicateNames(t *testing.T) {
	dupe := strings.Replace(kubeFixture(t), "  name: eks\ncontexts:", "  name: eks\n- cluster:\n    server: https://other.example\n  name: aks-dev\ncontexts:", 1)
	wantKubeRefusal(t, kubeCase{file: dupe}, "names cluster \"aks-dev\" twice")
}

func TestKubeIdentityRefusesAKubeconfigUnderTargetOrRW(t *testing.T) {
	wantKubeRefusal(t, kubeCase{
		profile: func(p *Profile) { p.Identity.Kube.Kubeconfig = "/home/u/proj/sub/.kube/config" },
		env:     func(e *fakeEnv) { e.files["/home/u/proj/sub/.kube/config"] = true },
	}, "inside the target")
	wantKubeRefusal(t, kubeCase{
		profile: func(p *Profile) { p.RW = []string{"/home/u/.kube"} },
		env:     func(e *fakeEnv) { e.dirs["/home/u/.kube"] = true },
	}, "WRITABLE")
	// The negative control: @home's tmpfs at {home} covers the default path
	// and writes nothing through to the host file, so it must resolve.
	if _, err := kubeResolve(t, kubeCase{profile: func(p *Profile) { p.Include = append(p.Include, "@home") }}); err != nil {
		t.Errorf("the default kubeconfig under @home's tmpfs refused: %v", err)
	}
}

// TestGoldenKubeGeneratedFiles is the review artifact for the bytes snug
// writes for identity.kube: a diff here is a change to what enters the sandbox.
func TestGoldenKubeGeneratedFiles(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	got := "# ~/.kube/config inside the sandbox\n" + string(p.Kube.SandboxKubeconfig()) +
		"# the host-side mint's kubeconfig (fixture credential)\n" + string(p.Kube.MintKubeconfig())
	const path = "testdata/identity-kube.txt"
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("generated kube files differ from %s (run with -update and read the diff):\n%s", path, got)
	}
}

func TestKubeIdentityPathRefusalsUseTheKubeconfigRole(t *testing.T) {
	err := identityKeyRefusal("p", "kube.kubeconfig", "/run/user/1000/snug/x", "snug's runtime directory /run/user/1000/snug", "It holds endpoints")
	for _, want := range []string{"decodes it on the host", "~/.kube"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "PUBLIC key") {
		t.Errorf("a kubeconfig refusal tells the human to copy a PUBLIC key: %v", err)
	}
}

func TestKubeHostMintNeverReadsTheHostFile(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	argv := p.Kube.MintArgv("/usr/bin/kubectl", "/run/snug/r/kube-mint.json", "/run/snug/r/kube-cache")
	want := []string{"/usr/bin/kubectl", "--kubeconfig=/run/snug/r/kube-mint.json", "--context=snug",
		"--cache-dir=/run/snug/r/kube-cache", "create", "token", "snug-agent", "--namespace=dev",
		"--duration=1h0m0s", "-o", "json"}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv = %q\nwant %q", argv, want)
	}
	for _, a := range argv {
		if strings.Contains(a, p.Kube.Kubeconfig) {
			t.Errorf("argv element %q names the host kubeconfig", a)
		}
	}
	env := KubeMintEnv("/run/snug/r/kube-home")
	if !slices.Equal(env, []string{"PATH=/usr/bin:/bin", "HOME=/run/snug/r/kube-home", "KUBERC=off"}) {
		t.Errorf("env = %q", env)
	}
}

func TestKubeMintKubeconfigCarriesOnlyTheAllowlist(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.Kube.MintKubeconfig())
	for _, bad := range []string{"FIXTURETOKENVALUE", "aws", "kind-kind", "clusterUser_rg_aks-dev", "exec"} {
		if strings.Contains(got, bad) {
			t.Errorf("mint kubeconfig carries %q", bad)
		}
	}
	key := base64.StdEncoding.EncodeToString([]byte("FIXTUREKEYMATERIAL"))
	if !strings.Contains(got, key) || !strings.Contains(got, `"name": "snug"`) {
		t.Errorf("mint kubeconfig lacks the client key or the snug names:\n%s", got)
	}
	tokenOnly := strings.Replace(kubeFixture(t),
		"    client-certificate-data: RklYVFVSRUNFUlQ=\n    client-key-data: RklYVFVSRUtFWU1BVEVSSUFM\n    token:",
		"    token:", 1)
	q, err := kubeResolve(t, kubeCase{file: tokenOnly})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(q.Kube.MintKubeconfig()), "FIXTURETOKENVALUE") {
		t.Error("a token-only user's mint kubeconfig lacks the token")
	}
}

func TestKubeMintBinaryRefusesWritableOrRelative(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()
	env.files["/usr/bin/kubectl"] = true
	if got, err := p.ResolveKubeMintBinary(env, "/usr/bin/kubectl"); err != nil || got != "/usr/bin/kubectl" {
		t.Errorf("an ordinary kubectl: %q, %v", got, err)
	}
	if _, err := p.ResolveKubeMintBinary(env, "kubectl"); err == nil {
		t.Error("a relative kubectl was accepted")
	}
	env.files["/home/u/proj/sub/bin/kubectl"] = true
	if _, err := p.ResolveKubeMintBinary(env, "/home/u/proj/sub/bin/kubectl"); err == nil ||
		!strings.Contains(err.Error(), "inside the target") {
		t.Errorf("a kubectl in the target: %v", err)
	}
	w, err := kubeResolve(t, kubeCase{
		profile: func(p *Profile) { p.RW = []string{"/opt/k"} },
		env:     func(e *fakeEnv) { e.dirs["/opt/k"] = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	env.files["/opt/k/kubectl"] = true
	if _, err := w.ResolveKubeMintBinary(env, "/opt/k/kubectl"); err == nil || !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("a kubectl under an rw grant: %v", err)
	}
}

func TestAzureFamilyIsInlineConfigAndItsPointersAreNot(t *testing.T) {
	for name, want := range map[string]bool{
		"AZURE_CORE_OUTPUT": true, "AZURE_CLIENT_SECRET": true,
		"AZURE_CONFIG_DIR": false, "KUBECONFIG": false,
	} {
		if got := IsInlineConfigEnv(name); got != want {
			t.Errorf("IsInlineConfigEnv(%q) = %v, want %v", name, got, want)
		}
	}
}

// Red-team findings on the identity.kube implementation, each a permanent test.

func TestConditionalEnvKubeconfigRefused(t *testing.T) {
	for name, side := range map[string]EnvGrants{
		"set":     {Set: map[string]string{"KUBECONFIG": "/home/u/proj/sub/kc"}},
		"inherit": {Inherit: []string{"KUBECONFIG"}},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := kubeResolve(t, kubeCase{profile: func(p *Profile) { p.Environ = side }})
			if err == nil || p != nil || !strings.Contains(err.Error(), "KUBECONFIG") {
				t.Fatalf("a profile's KUBECONFIG beside identity.kube resolved (%v); snug's value silently wins", err)
			}
		})
	}
}

func TestKubeCADataIsReencodedNotCopied(t *testing.T) {
	good, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	pemCA := string(good.Kube.CAData)
	withKey := pemCA + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	trailing := pemCA + "trailing bytes\n"
	notCert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	for name, bundle := range map[string]string{"private key after": withKey, "trailing bytes": trailing, "not x509": notCert} {
		file := strings.Replace(kubeFixture(t), base64.StdEncoding.EncodeToString(good.Kube.CAData),
			base64.StdEncoding.EncodeToString([]byte(bundle)), -1)
		if file == kubeFixture(t) {
			t.Fatal("fixture CA not found to replace; the test would pass vacuously")
		}
		if _, err := kubeResolve(t, kubeCase{file: file}); err == nil {
			t.Errorf("%s: a CA bundle that is not only certificates was carried into the sandbox", name)
		}
	}
}

func TestKubeLoopbackCheckFoldsCaseAndTrailingDot(t *testing.T) {
	for _, srv := range []string{"https://LOCALHOST:6443", "https://localhost.:6443", "https://Api.LocalHost"} {
		wantKubeRefusal(t, kubeCase{file: strings.Replace(kubeFixture(t),
			"https://aks-dev.example.azmk8s.io:443", srv, 1)}, "host's loopback")
	}
}

func TestOSEnvironKubeConfigRefusesAHardLink(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/config"
	if err := os.WriteFile(p, []byte("clusters: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, dir+"/second-name"); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSEnviron{}).KubeConfig(p); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("a kubeconfig with a second hard link was read: %v", err)
	}
}

// Red-team finding F2: an earlier run that could write the kubeconfig changed
// its server, and the next identity.kube run sent the host credential there.
// The profile pins the server; the file must agree.
func TestKubeServerIsPinnedByTheProfile(t *testing.T) {
	moved := strings.Replace(kubeFixture(t), "https://aks-dev.example.azmk8s.io:443", "https://attacker.example:443", 1)
	wantKubeRefusal(t, kubeCase{file: moved}, "identity.kube.server is", "attacker.example", "another run")
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-dev", Token: KubeTokenServiceAccount,
		ServiceAccount: "dev/snug-agent"}}, "needs identity.kube.server", `server = "https://aks-dev.example.azmk8s.io:443"`)
}
