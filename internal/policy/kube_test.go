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

func TestKubeUnknownCredentialValueNamesTheSet(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"k": {Kube: IdentityKube{Context: "aks-dev", Credential: "serviceaccount", Server: "https://aks-dev.example.azmk8s.io:443"}},
	})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err == nil || p != nil || !strings.Contains(err.Error(), "(want client-certificate, token or exec)") ||
		!strings.Contains(err.Error(), `"k"`) {
		t.Fatalf("p = %v, err = %v; want a nil policy and the unknown-token refusal naming the profile", p, err)
	}
}

// An omitted kubeconfig takes the default before the path loop, so it is
// expanded and compared like an explicit spelling: three spellings of one path
// are one pin, not three.
func TestKubeKubeconfigSpellingsAreOneIdentity(t *testing.T) {
	block := func(kc string) Identity {
		return Identity{Kube: IdentityKube{Context: "aks-dev", Credential: KubeCredentialClientCert, Server: "https://aks-dev.example.azmk8s.io:443", Kubeconfig: kc}}
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

// withEgress adds a profile granting the network, as most kube selections do.
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
	k := IdentityKube{Context: "aks-dev", Credential: KubeCredentialClientCert, Server: "https://aks-dev.example.azmk8s.io:443"}
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

func TestKubeIdentityGeneratesOneClusterOneContextPointingAtTheProxy(t *testing.T) {
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
			User map[string]any
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
	if got.Clusters[0].Cluster["server"] != KubeProxyGuest {
		t.Errorf("server = %v, want snug's proxy %s", got.Clusters[0].Cluster["server"], KubeProxyGuest)
	}
	if _, ok := got.Contexts[0].Context["namespace"]; ok || got.CurrentContext != "aks-dev" {
		t.Errorf("context = %+v, current = %q", got.Contexts[0], got.CurrentContext)
	}
	for g := range p.Mounts {
		if strings.HasPrefix(g, StagedBinDir+"/") && strings.Contains(g, "kube") {
			t.Errorf("%s is mounted: no kube helper runs inside", g)
		}
	}
	if e := p.Env["KUBECONFIG"]; len(e.Entries) != 1 || e.Entries[0].Value != "/home/u/.kube/config" {
		t.Errorf("KUBECONFIG = %+v", e)
	}
	if p.Kube == nil || p.Kube.Credential != KubeCredentialClientCert {
		t.Errorf("Kube = %+v", p.Kube)
	}
}

func fixtureUserData(t *testing.T) (cert, key string) {
	t.Helper()
	for _, l := range strings.Split(kubeFixture(t), "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "client-certificate-data: "); ok {
			cert = v
		}
		if v, ok := strings.CutPrefix(l, "client-key-data: "); ok {
			key = v
		}
	}
	return cert, key
}

func TestKubeIdentityNeverCopiesAHostUserEntry(t *testing.T) {
	cert, key := fixtureUserData(t)
	for _, c := range []IdentityKube{
		{Context: "aks-dev", Credential: KubeCredentialClientCert, Server: "https://aks-dev.example.azmk8s.io:443"},
		{Context: "aks-dev", Credential: KubeCredentialToken, Server: "https://aks-dev.example.azmk8s.io:443"},
	} {
		p, err := kubeResolve(t, kubeCase{kube: c})
		if err != nil {
			t.Fatal(err)
		}
		for guest, m := range p.Mounts {
			s := string(m.Content)
			for _, bad := range []string{key, key[40:80], cert, "FIXTURETOKENVALUE", "PRIVATE KEY",
				"clusterUser_rg_aks-dev", "kind-kind", "38921", "aws", "client-key-data", "\"token\""} {
				if strings.Contains(s, bad) {
					t.Errorf("credential %s: %s carries %q from the host kubeconfig", c.Credential, guest, bad)
				}
			}
		}
		if got := strings.Join(p.Kube.OtherContexts, ","); got != "aks-cert,aks-token,eks,kind-kind" {
			t.Errorf("OtherContexts = %q", got)
		}
	}
}

// One identity per profile: an entry holding a certificate AND a token (AKS
// local accounts: masterclient and clusterUser) refuses without the key.
func TestKubeCredentialRefusesAnAmbiguousEntryWithoutTheKey(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-dev", Server: "https://aks-dev.example.azmk8s.io:443"}},
		"holds a client certificate and a static token", "different identities", "will not choose",
		`identity.kubectl.credential = "client-certificate" or "token"`)
	execBeside := strings.Replace(kubeExecFixture(t), "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n",
		"    token: FIXTURETOKENVALUE\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n", 1)
	if execBeside == kubeExecFixture(t) {
		t.Fatal("fixture edit did not apply")
	}
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "eks-iam", Server: "https://iam.example.com"}, file: execBeside},
		"holds a static token and an exec plugin", `"token" or "exec"`)
}

func TestKubeCredentialRefusesAShapeTheEntryLacks(t *testing.T) {
	for _, c := range []struct {
		ctx  string
		cred KubeCredential
		want string
	}{
		{"aks-dev", KubeCredentialExec, "holds a client certificate and a static token"},
		{"aks-cert", KubeCredentialToken, "holds a client certificate"},
		{"aks-token", KubeCredentialClientCert, "holds a static token"},
	} {
		wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: c.ctx, Credential: c.cred,
			Server: "https://aks-dev.example.azmk8s.io:443"}}, `identity.kubectl.credential = "`+string(c.cred)+`"`, c.want)
	}
}

func TestKubeCredentialAbsentOnAnUnambiguousEntryIsThatOne(t *testing.T) {
	for ctx, want := range map[string]KubeCredential{"aks-cert": KubeCredentialClientCert, "aks-token": KubeCredentialToken} {
		p, err := kubeResolve(t, kubeCase{kube: IdentityKube{Context: ctx, Server: "https://aks-dev.example.azmk8s.io:443"}})
		if err != nil {
			t.Fatal(err)
		}
		if p.Kube.Credential != want || len(p.Kube.Unused) != 0 {
			t.Errorf("%s: credential %q unused %q, want %q and nothing unused", ctx, p.Kube.Credential, p.Kube.Unused, want)
		}
	}
}

// The binding holds the chosen shape only; the other is never decoded.
func TestKubeCredentialKeepsOnlyTheChosenShape(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	hu := p.Kube.HostUser
	if len(hu.ClientCertData) == 0 || len(hu.ClientKeyData) == 0 || len(hu.Token) != 0 {
		t.Errorf("client-certificate kept cert %d, key %d, token %d bytes; want no token",
			len(hu.ClientCertData), len(hu.ClientKeyData), len(hu.Token))
	}
	if p.Kube.CertSubject != "CN=fixture-master,O=system:masters" || p.Kube.CertNotAfter.Year() != 2099 {
		t.Errorf("subject %q notAfter %v", p.Kube.CertSubject, p.Kube.CertNotAfter)
	}
	if !slices.Equal(p.Kube.Unused, []string{"the entry's static token (not presented)"}) {
		t.Errorf("Unused = %q", p.Kube.Unused)
	}
	q, err := kubeResolve(t, kubeCase{kube: IdentityKube{Context: "aks-dev", Credential: KubeCredentialToken,
		Server: "https://aks-dev.example.azmk8s.io:443"}})
	if err != nil {
		t.Fatal(err)
	}
	hu = q.Kube.HostUser
	if string(hu.Token) != "FIXTURETOKENVALUE" || len(hu.ClientCertData) != 0 || len(hu.ClientKeyData) != 0 {
		t.Errorf("token kept cert %d, key %d bytes; want the token only", len(hu.ClientCertData), len(hu.ClientKeyData))
	}
	if q.Kube.TokenLen != len("FIXTURETOKENVALUE") || q.Kube.TokenJWT {
		t.Errorf("token shape %d jwt=%v", q.Kube.TokenLen, q.Kube.TokenJWT)
	}
	if !slices.Equal(q.Kube.Unused, []string{"the entry's client certificate (not presented)"}) {
		t.Errorf("Unused = %q", q.Kube.Unused)
	}
}

func TestKubeCredentialRefusesAnUnpairedOrMalformedCredential(t *testing.T) {
	_, key := fixtureUserData(t)
	f := kubeFixture(t)
	at := strings.Index(f, "- name: clusterUser_rg_aks-dev")
	notPair := f[:at] + strings.Replace(f[at:], "client-key-data: "+key, "client-key-data: "+
		base64.StdEncoding.EncodeToString([]byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")), 1)
	wantKubeRefusal(t, kubeCase{file: notPair}, "do not form a pair")
	badTok := strings.Replace(kubeFixture(t), "token: FIXTURETOKENVALUE\n", "token: \"a b\"\n", 1)
	wantKubeRefusal(t, kubeCase{file: badTok, kube: IdentityKube{Context: "aks-dev", Credential: KubeCredentialToken,
		Server: "https://aks-dev.example.azmk8s.io:443"}}, "not a bearer token")
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
	for _, g := range []string{"/home/u/.kube/config"} {
		if _, ok := p.Mounts[g]; ok {
			t.Errorf("%s mounted with no kube block", g)
		}
	}
	if _, ok := p.Env["KUBECONFIG"]; ok {
		t.Error("KUBECONFIG set with no kube block")
	}
}

func TestKubeIdentityRefusesALoopbackServer(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "kind-kind", Credential: KubeCredentialClientCert, Server: "https://aks-dev.example.azmk8s.io:443"}}, "host's loopback", "THERE IS NO")
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
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "proxy-url: http://proxy.example:3128")}, "never through a proxy the file names")
}

func TestKubeIdentityRefusesACertificateAuthorityPath(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "certificate-authority: /etc/ca.pem")}, "--embed-certs")
}

func TestKubeIdentityRefusesAnUnknownClusterField(t *testing.T) {
	wantKubeRefusal(t, kubeCase{file: clusterField(t, "disable-compression: true")}, "refused rather than dropped")
}

// The proxy dials the cluster from the host, so a kube profile needs no
// network grant — but its listener is a socket the stage creates in the
// sandbox's netns, so the run gets a stage. NOT an offline sandbox: the
// sandbox reaches one API server, and through it whatever the cluster reaches.
func TestKubeSelectsAStageWithoutNet(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{noNet: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Net.Mode == NetEgress {
		t.Fatalf("net mode = %s with no network grant", p.Net.Mode)
	}
	if p.Topology.Netns != NetnsStage {
		t.Errorf("topology netns = %s, want stage: the proxy's socket is made by the stage", p.Topology.Netns)
	}
}

// The generated kubeconfig holds nothing secret and nothing from the host
// user: no token, no exec plugin, no client certificate — and no CA, because
// the TLS hop is the proxy's, on the host.
func TestKubeSandboxKubeconfigCarriesNoCredentialAndNoCA(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	c := string(p.Mounts["/home/u/.kube/config"].Content)
	for _, bad := range []string{"exec", "token", "client-certificate", "client-key", "certificate-authority",
		"tls-server-name", "https://", "auth-provider", "username", "password"} {
		if strings.Contains(c, bad) {
			t.Errorf("generated kubeconfig carries %q:\n%s", bad, c)
		}
	}
	if !strings.Contains(c, `"user": {}`) {
		t.Errorf("user entry is not empty:\n%s", c)
	}
}

func TestKubeIdentityUnknownContextNamesTheKnownOnes(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-prod", Credential: KubeCredentialClientCert, Server: "https://aks-dev.example.azmk8s.io:443"}}, `"aks-prod"`, "contexts: aks-cert, aks-dev, aks-token, eks, kind-kind")
}

// The fixture's eks user runs `aws eks get-token` with no --cluster-name:
// outside the grammar, so refused before anything could run it.
func TestKubeExecUserOutsideTheGrammarRefuses(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "eks", Server: "https://eks.example.com"}}, "aws eks get-token without --cluster-name")
	userField := func(line string) string {
		return strings.Replace(kubeFixture(t), "    token: FIXTURETOKENVALUE\n", "    token: FIXTURETOKENVALUE\n    "+line+"\n", 1)
	}
	for _, line := range []string{"auth-provider:\n      name: oidc", "client-certificate: /etc/c.pem",
		"tokenFile: /etc/t", "as: admin", "username: admin"} {
		wantKubeRefusal(t, kubeCase{file: userField(line)}, "user of context")
	}
}

func TestKubeIdentityRefusesAMalformedBlock(t *testing.T) {
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Credential: KubeCredentialToken}}, "needs identity.kubectl.context")
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

// Red-team G1: a grant that shows the host kubeconfig inside — @parent-ro with
// it beside the target, an ro bind of ~/.kube — put every context's
// credential there while the screen said "never inside".
func TestKubeIdentityRefusesAReadableKubeconfig(t *testing.T) {
	wantKubeRefusal(t, kubeCase{
		profile: func(p *Profile) {
			p.Include = append(p.Include, "@parent-ro")
			p.Identity.Kube.Kubeconfig = "/home/u/proj/aks.kubeconfig"
		},
		env: func(e *fakeEnv) {
			e.files["/home/u/proj/aks.kubeconfig"] = true
			e.kube["/home/u/proj/aks.kubeconfig"] = []byte(kubeFixture(t))
		},
	}, "READABLE inside", "every other context's")
	wantKubeRefusal(t, kubeCase{
		profile: func(p *Profile) { p.RO = append(p.RO, "/home/u/.kube:/hostkube") },
		env:     func(e *fakeEnv) { e.dirs["/home/u/.kube"] = true },
	}, "READABLE inside")
}

// TestGoldenKubeGeneratedFiles is the review artifact for the bytes snug
// writes for identity.kubectl: a diff here is a change to what enters the sandbox.
func TestGoldenKubeGeneratedFiles(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	got := "# ~/.kube/config inside the sandbox\n" + string(p.Kube.SandboxKubeconfig())
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
	err := identityKeyRefusal("p", "kubectl.kubeconfig", "/run/user/1000/snug/x", "snug's runtime directory /run/user/1000/snug", "It holds endpoints")
	for _, want := range []string{"decodes it on the host", "~/.kube"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "PUBLIC key") {
		t.Errorf("a kubeconfig refusal tells the human to copy a PUBLIC key: %v", err)
	}
}

func TestKubeHostBinaryRefusesWritableOrRelative(t *testing.T) {
	p, err := kubeResolve(t, kubeCase{})
	if err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv()
	env.files["/usr/bin/kubelogin"] = true
	if got, err := p.ResolveKubeHostBinary(env, "plugin", "/usr/bin/kubelogin"); err != nil || got != "/usr/bin/kubelogin" {
		t.Errorf("an ordinary plugin: %q, %v", got, err)
	}
	if _, err := p.ResolveKubeHostBinary(env, "plugin", "kubelogin"); err == nil {
		t.Error("a relative plugin was accepted")
	}
	env.files["/home/u/proj/sub/bin/kubelogin"] = true
	if _, err := p.ResolveKubeHostBinary(env, "plugin", "/home/u/proj/sub/bin/kubelogin"); err == nil ||
		!strings.Contains(err.Error(), "inside the target") {
		t.Errorf("a plugin in the target: %v", err)
	}
	w, err := kubeResolve(t, kubeCase{
		profile: func(p *Profile) { p.RW = []string{"/opt/k"} },
		env:     func(e *fakeEnv) { e.dirs["/opt/k"] = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	env.files["/opt/k/kubelogin"] = true
	if _, err := w.ResolveKubeHostBinary(env, "plugin", "/opt/k/kubelogin"); err == nil || !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("a plugin under an rw grant: %v", err)
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

// Red-team findings on the identity.kubectl implementation, each a permanent test.

func TestConditionalEnvKubeconfigRefused(t *testing.T) {
	for name, side := range map[string]EnvGrants{
		"set":     {Set: map[string]string{"KUBECONFIG": "/home/u/proj/sub/kc"}},
		"inherit": {Inherit: []string{"KUBECONFIG"}},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := kubeResolve(t, kubeCase{profile: func(p *Profile) { p.Environ = side }})
			if err == nil || p != nil || !strings.Contains(err.Error(), "KUBECONFIG") {
				t.Fatalf("a profile's KUBECONFIG beside identity.kubectl resolved (%v); snug's value silently wins", err)
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
// its server, and the next identity.kubectl run sent the host credential there.
// The profile pins the server; the file must agree.
func TestKubeServerIsPinnedByTheProfile(t *testing.T) {
	moved := strings.Replace(kubeFixture(t), "https://aks-dev.example.azmk8s.io:443", "https://attacker.example:443", 1)
	wantKubeRefusal(t, kubeCase{file: moved}, "identity.kubectl.server is", "attacker.example", "another run")
	wantKubeRefusal(t, kubeCase{kube: IdentityKube{Context: "aks-dev", Credential: KubeCredentialClientCert}}, "needs identity.kubectl.server", `server = "https://aks-dev.example.azmk8s.io:443"`)
}
