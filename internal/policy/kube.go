package policy

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/kubecfg"
)

// KubeBinding is what Resolve made of a kube identity block: the one cluster
// snug's proxy forwards to, the one ServiceAccount the host-side mint asks a
// token for, and the host credential that mint authenticates with.
// It is resolver output, never profile text, and it is not inside Identity
// because Identity must stay a comparable value of profile leaves.
type KubeBinding struct {
	// Context is the profile's context name. It is also the cluster, user and
	// context name in the sandbox's file, so no host-side name reaches it.
	Context string
	// Kubeconfig is the host path that was decoded, link-free.
	Kubeconfig    string
	Server        string
	CAData        []byte // decoded PEM; nil means the system trust store
	TLSServerName string
	SANamespace   string
	SAName        string
	// HostUser is the mint's credential. It never enters the sandbox; it is
	// written, by internal/cli, only into the per-run host-side file the mint
	// reads.
	HostUser KubeHostUser
	// HostUserShape names what the host user entry holds, for the --dry-run
	// row saying what stayed out: "client certificate", "static token".
	HostUserShape []string
	// OtherContexts is every other context name in the host file, sorted.
	OtherContexts []string
}

// KubeHostUser is the host user entry's credential, re-decoded. When the entry
// holds both a client certificate and a static token, only the certificate is
// kept: the mint needs one credential, and a token that is never sent cannot be
// sent to the wrong server.
type KubeHostUser struct {
	ClientCertData, ClientKeyData, Token Secret
}

// kq renders a name from the host kubeconfig quoted and visible, so an empty
// or space-bearing name reads as one.
func kq(s string) string { return VisibleText(strconv.Quote(s)) }

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// resolveKube turns a pinned kube block into p.Kube, the generated sandbox
// kubeconfig and KUBECONFIG. It runs after the grants are final, because its
// location refusals read them. It needs no network grant: snug's proxy dials
// the cluster from the host, and deriveTopology gives the run the stage that
// creates the proxy's socket.
func resolveKube(p *Policy, ctx Context, env Environ, target, home string) error {
	if !p.Identity.Pinned("kube") {
		return nil
	}
	k := p.Identity.Kube
	owner := p.IdentityOwner("kube")
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{owner}, a...)...)
	}
	path := k.Kubeconfig

	if k.Context == "" {
		return refuse("[identity.kube] needs identity.kube.context: the name of one context in %s. "+
			"snug reads that context's cluster as data; its user entry never enters the sandbox.", VisibleText(path))
	}
	if k.Token == "" {
		return refuse("identity.kube.token is not set (want serviceaccount)")
	}
	if k.ServiceAccount == "" {
		return refuse("identity.kube.token = \"serviceaccount\" needs identity.kube.service_account " +
			"(\"namespace/name\"): the one ServiceAccount snug mints tokens for")
	}
	ns, sa, ok := strings.Cut(k.ServiceAccount, "/")
	if !ok || !dnsLabel.MatchString(ns) || len(sa) > 253 || !dnsSubdomain.MatchString(sa) {
		// The grammar also forbids a leading '-', so neither half can parse as
		// a flag in the mint's argv.
		return refuse("identity.kube.service_account %s is not \"namespace/name\" with both halves Kubernetes names",
			VisibleText(k.ServiceAccount))
	}

	// The host-side mint DECODES this file and authenticates with the
	// credential it names, so whoever can write it chooses which server that
	// credential is sent to. Under the target it is sandboxed material at any
	// access; anywhere a writable grant reaches, a payload rewrites it for the
	// next run. A tmpfs is not on this list: it is guest-only, and @home's
	// tmpfs at {home} writes nothing through to the host file.
	if _, under := under(target, path); under {
		return refuse("refusing identity.kube.kubeconfig %s: it is inside the target %s, the sandboxed material. "+
			"snug decodes this file on the host and mints with the credential it names, so a file the "+
			"repository or an earlier run wrote would choose which server receives that credential. "+
			"Keep your kubeconfig outside the target.", VisibleText(path), VisibleText(target))
	}
	const writable = "refusing identity.kube.kubeconfig %s: %s A payload that rewrites it chooses, " +
		"for the NEXT run, which server snug's host-side kubectl sends your credential to. Drop the " +
		"rw grant, or name a kubeconfig no rw grant covers.%s"
	if p.HostPathVisible(path, true) {
		return refuse(writable, VisibleText(path), "a grant of this sandbox makes it WRITABLE.", "")
	}
	if m, h, hit, err := p.writableAliasOf(env, path); err != nil {
		return err
	} else if hit {
		return refuse(writable, VisibleText(path), "the rw grant "+VisibleText(m.Host)+
			" reaches it through a second mount of the same filesystem.", aliasNote(h))
	}
	if name, asked, found := p.writableNameOnChain(env, path); found {
		return refuse(writable, VisibleText(path), selectionClause(name, asked), "")
	}

	f, err := env.KubeConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return refuse("identity.kube.kubeconfig %s: no such file. Name the kubeconfig holding context %s, "+
			"or create it with your cloud's get-credentials command.", VisibleText(path), kq(k.Context))
	}
	if err != nil {
		return refuse("identity.kube.kubeconfig %s: %s. snug reads the block-style YAML kubectl and az write; "+
			"anchors, aliases, tags, flow collections and multi-line scalars are refused rather than guessed at.",
			VisibleText(path), visibleErr(err))
	}

	cluster, user, others, err := kubePick(f, k.Context, path)
	if err != nil {
		return refuse("%s", err.Error())
	}
	b := &KubeBinding{
		Context: k.Context, Kubeconfig: path,
		SANamespace: ns, SAName: sa, OtherContexts: others,
	}
	if err := kubeCluster(b, cluster, ctx); err != nil {
		return refuse("%s", err.Error())
	}
	// The file names the server; the profile decides it. An earlier run that
	// could write the kubeconfig — through a target it was in, say — could
	// otherwise point the host-side mint, and the credential it sends, at a
	// server of its choosing (red team, measured across two runs).
	if k.Server == "" {
		return refuse("[identity.kube] needs identity.kube.server: the API server snug may send your host "+
			"credential to. Context %s in %s names %s today; if that is your cluster, write\n"+
			"         server = %s", kq(k.Context), VisibleText(path), VisibleText(b.Server), kq(b.Server))
	}
	if k.Server != b.Server {
		return refuse("identity.kube.server is %s, but context %s in %s names %s. Refusing: the kubeconfig "+
			"chooses where snug's host-side mint sends your credential only if it agrees with the profile, "+
			"and a file another run could have written is not the authority. If you changed the cluster, "+
			"update identity.kube.server.", kq(k.Server), kq(k.Context), VisibleText(path), kq(b.Server))
	}
	if err := kubeUser(b, user, k.Context); err != nil {
		return refuse("%s", err.Error())
	}

	p.Kube = b
	from := []string{p.IdentityProvenance("kube")}
	p.Replace(Mount{Guest: home + "/.kube/config", Kind: KindData, Access: AccessRO,
		Content: b.SandboxKubeconfig(), From: from})
	p.AuthorEnv("KUBECONFIG", home+"/.kube/config")
	return nil
}

// kubePick finds the pinned context and the cluster and user it names,
// refusing duplicates rather than choosing between them.
func kubePick(f kubecfg.File, name, path string) (kubecfg.Cluster, kubecfg.User, []string, error) {
	var zcl kubecfg.Cluster
	var zu kubecfg.User
	dup := func(kind, n string) error {
		return fmt.Errorf("%s names %s %s twice; kubectl and snug could disagree about which one is meant. "+
			"Remove the duplicate.", VisibleText(path), kind, kq(n))
	}
	seen := map[string]bool{}
	var found *kubecfg.Context
	var others []string
	for i, c := range f.Contexts {
		if seen[c.Name] {
			return zcl, zu, nil, dup("context", c.Name)
		}
		seen[c.Name] = true
		if c.Name == name {
			found = &f.Contexts[i]
		} else {
			others = append(others, c.Name)
		}
	}
	sort.Strings(others)
	if found == nil {
		list := make([]string, 0, len(others))
		for i, o := range others {
			if i == 20 {
				list = append(list, fmt.Sprintf("and %d more", len(others)-20))
				break
			}
			list = append(list, VisibleText(o))
		}
		return zcl, zu, nil, fmt.Errorf("identity.kube.context %s is not in %s (contexts: %s). "+
			"Name one of those, or set identity.kube.kubeconfig.",
			kq(name), VisibleText(path), strings.Join(list, ", "))
	}
	if len(found.Other) > 0 {
		return zcl, zu, nil, fmt.Errorf("context %s sets %s, which snug does not know; an unrecognised "+
			"field is refused rather than dropped", kq(name), kq(found.Other[0]))
	}
	var cl *kubecfg.Cluster
	seen = map[string]bool{}
	for i, c := range f.Clusters {
		if seen[c.Name] {
			return zcl, zu, nil, dup("cluster", c.Name)
		}
		seen[c.Name] = true
		if c.Name == found.Cluster {
			cl = &f.Clusters[i]
		}
	}
	var us *kubecfg.User
	seen = map[string]bool{}
	for i, u := range f.Users {
		if seen[u.Name] {
			return zcl, zu, nil, dup("user", u.Name)
		}
		seen[u.Name] = true
		if u.Name == found.User {
			us = &f.Users[i]
		}
	}
	if cl == nil {
		return zcl, zu, nil, fmt.Errorf("context %s names cluster %s, which %s does not define",
			kq(name), kq(found.Cluster), VisibleText(path))
	}
	if us == nil {
		return zcl, zu, nil, fmt.Errorf("context %s names user %s, which %s does not define",
			kq(name), kq(found.User), VisibleText(path))
	}
	return *cl, *us, others, nil
}

// kubeCluster checks the cluster entry against the allowlist and fills the
// public half of b.
func kubeCluster(b *KubeBinding, c kubecfg.Cluster, ctx Context) error {
	name := kq(c.Name)
	keys := make([]string, 0, len(c.Fields))
	for k := range c.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := c.Fields[k]
		switch k {
		case "server", "certificate-authority-data", "tls-server-name":
			if v.Kind != kubecfg.Scalar {
				return fmt.Errorf("cluster %s: %s is a %s, not a value", name, k, v.Kind)
			}
		case "insecure-skip-tls-verify":
			if v.Kind == kubecfg.Scalar && !v.Quoted && v.Text == "false" {
				continue
			}
			return fmt.Errorf("cluster %s sets insecure-skip-tls-verify; snug copies no TLS downgrade "+
				"into a sandbox. Fix the host entry (kubectl config set-cluster %s --embed-certs "+
				"--certificate-authority=<ca file>).", name, name)
		case "proxy-url":
			return fmt.Errorf("cluster %s sets proxy-url; snug carries no proxy into the sandbox or into "+
				"its host-side mint", name)
		case "certificate-authority":
			return fmt.Errorf("cluster %s names its CA by path (certificate-authority); snug reads no second "+
				"host file for it. Fix: kubectl config set-cluster %s --embed-certs --certificate-authority=<path>",
				name, name)
		case "extensions":
			if v.Len == 0 {
				continue
			}
			return fmt.Errorf("cluster %s sets extensions; snug does not interpret extensions", name)
		default:
			return fmt.Errorf("cluster %s sets %s, which snug does not know; an unrecognised field is "+
				"refused rather than dropped", name, VisibleText(k))
		}
	}

	server := c.Fields["server"].Text
	if server == "" {
		return fmt.Errorf("cluster %s has no server", name)
	}
	for _, s := range []string{server, c.Fields["tls-server-name"].Text} {
		for _, r := range s {
			if IsForgingRune(r) {
				return fmt.Errorf("cluster %s: %s contains %q, and it is written into the kubeconfig snug "+
					"generates and onto the --dry-run screen", name, VisibleText(s), r)
			}
		}
	}
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("cluster %s: server %s is not https; a bearer token over plain http is readable "+
			"on the path, and snug accepts only https://host[:port][/path]", name, VisibleText(server))
	}
	// The proxy and the host-side mint dial from the HOST, outside the seal
	// that keeps the sandbox off host loopback, so this refusal is what keeps
	// identity.kube from being a grant to one host port. It covers literals;
	// a name is not resolved here, because resolution stays pure, and the
	// proxy's dialer repeats the check on every address the name resolves to
	// at run time (internal/kubeproxy).
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return kubeLoopback(name, server)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() {
			return kubeLoopback(name, server)
		}
		for _, h := range ctx.HostAddresses {
			if ha, err := netip.ParseAddr(h); err == nil && ha.Unmap() == a {
				return fmt.Errorf("cluster %s: server %s names %s, an address this host owns; the stage seals "+
					"host-owned addresses from inside", name, VisibleText(server), a)
			}
		}
	}
	b.Server = server
	b.TLSServerName = c.Fields["tls-server-name"].Text
	if ca := c.Fields["certificate-authority-data"].Text; ca != "" {
		der, err := base64.StdEncoding.DecodeString(ca)
		if err != nil {
			return fmt.Errorf("cluster %s: certificate-authority-data is not base64: %v", name, err)
		}
		ca, err := reencodeCAs(der)
		if err != nil {
			return fmt.Errorf("cluster %s: certificate-authority-data %v", name, err)
		}
		b.CAData = ca
	}
	return nil
}

func kubeLoopback(name, server string) error {
	return fmt.Errorf("cluster %s: server %s is the host's loopback, which a sandbox cannot reach (host "+
		"loopback is sealed by design). There is no grant for one host port; see base.toml "+
		"\"THERE IS NO `network = \\\"host\\\"`\".", name, VisibleText(server))
}

// kubeUser checks the user entry's shape and keeps the one credential the
// mint will use.
func kubeUser(b *KubeBinding, u kubecfg.User, context string) error {
	if u.Exec != nil {
		return fmt.Errorf("context %s authenticates with an exec plugin (%s); token = \"serviceaccount\" "+
			"mints with your host credential through a kubeconfig snug writes, and carrying an exec entry "+
			"would be snug running that program on the host. Not supported: see #659 (host-exec).",
			kq(context), VisibleText(filepath.Base(u.Exec.Command)))
	}
	keys := make([]string, 0, len(u.Fields))
	for k := range u.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := u.Fields[k]
		switch k {
		case "client-certificate-data", "client-key-data", "token":
			if v.Kind != kubecfg.Scalar {
				return fmt.Errorf("user of context %s: %s is a %s, not a value", kq(context), k, v.Kind)
			}
		case "client-certificate", "client-key":
			return fmt.Errorf("user of context %s names %s by path; snug reads no second host file for it. "+
				"Fix: kubectl config set-credentials <user> --embed-certs --%s=<path>", kq(context), k, k)
		default:
			return fmt.Errorf("user of context %s sets %s, which token = \"serviceaccount\" does not "+
				"mint with; an unrecognised field is refused rather than dropped", kq(context), VisibleText(k))
		}
	}
	cert, key, tok := u.Fields["client-certificate-data"].Text, u.Fields["client-key-data"].Text, u.Fields["token"].Text
	if (cert == "") != (key == "") {
		return fmt.Errorf("user of context %s has a client certificate without its key, or a key without "+
			"its certificate", kq(context))
	}
	if cert != "" {
		c, err1 := base64.StdEncoding.DecodeString(cert)
		k, err2 := base64.StdEncoding.DecodeString(key)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("user of context %s: client-certificate-data or client-key-data is not base64",
				kq(context))
		}
		b.HostUser = KubeHostUser{ClientCertData: c, ClientKeyData: k}
		b.HostUserShape = append(b.HostUserShape, "client certificate", "client key")
		if tok != "" {
			b.HostUserShape = append(b.HostUserShape, "static token")
		}
		return nil
	}
	if tok == "" {
		return fmt.Errorf("user of context %s holds no credential snug can mint with", kq(context))
	}
	b.HostUser = KubeHostUser{Token: Secret(tok)}
	b.HostUserShape = []string{"static token"}
	return nil
}

type kubeconfigFile struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	Clusters       []kubeNamed       `json:"clusters"`
	Users          []kubeNamed       `json:"users"`
	Contexts       []kubeNamed       `json:"contexts"`
	CurrentContext string            `json:"current-context"`
	Preferences    map[string]string `json:"preferences"`
}

type kubeNamed struct {
	Name    string `json:"name"`
	Cluster any    `json:"cluster,omitempty"`
	User    any    `json:"user,omitempty"`
	Context any    `json:"context,omitempty"`
}

type kubeClusterOut struct {
	Server        string `json:"server"`
	CAData        []byte `json:"certificate-authority-data,omitempty"`
	TLSServerName string `json:"tls-server-name,omitempty"`
}

type kubeContextOut struct {
	Cluster   string `json:"cluster"`
	User      string `json:"user"`
	Namespace string `json:"namespace,omitempty"`
}

// SandboxKubeconfig is the ~/.kube/config generated inside: one cluster, which
// is snug's proxy on the sandbox's own loopback, one user with NO credential,
// one context. Plain http and no CA: both ends of that loopback are inside the
// sandbox, and the hop to the real server is the proxy's, over TLS, from the
// host. It is JSON, which is YAML, emitted from Go values — no host byte is
// copied, and no host cluster or user name appears in it.
func (k *KubeBinding) SandboxKubeconfig() []byte {
	return kubeconfig(k.Context, kubeClusterOut{Server: KubeProxyGuest}, struct{}{}, k.SANamespace)
}

func kubeconfig(name string, cluster kubeClusterOut, user any, namespace string) []byte {
	f := kubeconfigFile{
		APIVersion: "v1", Kind: "Config",
		Clusters:       []kubeNamed{{Name: name, Cluster: cluster}},
		Users:          []kubeNamed{{Name: name, User: user}},
		Contexts:       []kubeNamed{{Name: name, Context: kubeContextOut{Cluster: name, User: name, Namespace: namespace}}},
		CurrentContext: name,
		Preferences:    map[string]string{},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		panic(fmt.Sprintf("policy: encoding a generated kubeconfig: %v", err))
	}
	return buf.Bytes()
}

// KubeTokenDuration is the lifetime the mint REQUESTS. The cluster may cap or
// extend it; the token source reads the expiry the cluster returned. It is not
// a profile key: a knob on the credential's lifetime is precedent for every
// other knob. The token never enters the sandbox; an hour bounds what it is
// worth if it leaks from the host.
const KubeTokenDuration = "1h0m0s"

// KubeMintBudget is how many mints one run may make, the preflight included.
// The token source never mints before the cached token expires — not on a 401
// either — so this only binds when a cluster hands out very short tokens or
// the clock jumps.
const KubeMintBudget = 64

// KubeMintContext is the only cluster, user and context name in the host-side
// file the mint reads, so the mint's argv carries no text from the host file.
const KubeMintContext = "snug"

// MintKubeconfig is the per-run HOST-SIDE kubeconfig the mint reads: the same
// cluster as the sandbox's, all names "snug", and the host user's credential
// re-encoded — client certificate and key when the entry had them, else the
// static token. It is a Secret because it carries that credential, and the
// host kubectl never reads the host kubeconfig itself: what it would read
// there (other users, exec plugins, proxy settings) is not in this file.
func (k *KubeBinding) MintKubeconfig() Secret {
	type userOut struct {
		ClientCertificateData []byte `json:"client-certificate-data,omitempty"`
		ClientKeyData         []byte `json:"client-key-data,omitempty"`
		Token                 string `json:"token,omitempty"`
	}
	u := userOut{ClientCertificateData: k.HostUser.ClientCertData, ClientKeyData: k.HostUser.ClientKeyData}
	if len(u.ClientCertificateData) == 0 {
		u.Token = string(k.HostUser.Token)
	}
	return Secret(kubeconfig(KubeMintContext,
		kubeClusterOut{Server: k.Server, CAData: k.CAData, TLSServerName: k.TLSServerName}, u, ""))
}

// MintArgv is the host command that mints one token, exactly. Every element is
// snug's constant or a value Resolve validated: the ServiceAccount halves are
// Kubernetes names, which cannot start with '-'.
func (k *KubeBinding) MintArgv(kubectl, mintFile, cacheDir string) []string {
	return []string{kubectl,
		"--kubeconfig=" + mintFile, "--context=" + KubeMintContext, "--cache-dir=" + cacheDir,
		"create", "token", k.SAName, "--namespace=" + k.SANamespace,
		"--duration=" + KubeTokenDuration, "-o", "json"}
}

// KubeMintEnv is the mint's whole environment. Nothing is inherited: a proxy
// variable, KUBECONFIG, AWS_* or AZURE_* in snug's own environment — a repo's
// .envrc can put them there — would steer what the host kubectl does with the
// credential. HOME is an empty per-run directory and KUBERC=off, so no
// ~/.kube/kuberc alias or default flag applies.
func KubeMintEnv(kubeHome string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + kubeHome, "KUBERC=off"}
}

// KubeMintEnvNames is the names KubeMintEnv sets, for the screen.
func KubeMintEnvNames() []string { return []string{"PATH", "HOME", "KUBERC"} }

// ResolveKubeMintBinary judges the host kubectl the mint will run, named as
// exec.LookPath found it. It refuses a relative name, a binary inside the
// target, and one a writable grant reaches by bytes, by a second mount, or by
// a name on its resolution chain — the same three arms as ResolveEngineBinary,
// because the mint runs it with a cluster credential. Whether the file is an
// executable rather than a script is internal/cli's check: it needs a read.
func (p *Policy) ResolveKubeMintBinary(env Environ, asGiven string) (string, error) {
	if !filepath.IsAbs(asGiven) {
		return "", fmt.Errorf("host kubectl %s is not an absolute path; snug runs it on the host with your "+
			"cluster credential and judges it against this sandbox's grants, which a relative name matches "+
			"none of", VisibleText(asGiven))
	}
	asGiven = filepath.Clean(asGiven)
	resolved, err := ResolveExistingHostPath(env, asGiven)
	if err != nil {
		return "", fmt.Errorf("host kubectl %s: %s", VisibleText(asGiven), visibleErr(err))
	}
	const why = "snug runs it on the host with your cluster credential, so a kubectl the payload can " +
		"write or choose is the payload holding that credential. Install kubectl where no grant of " +
		"this sandbox reaches."
	if _, in := under(p.Target, resolved); in {
		return "", fmt.Errorf("host kubectl %s is inside the target %s. %s", VisibleText(resolved), VisibleText(p.Target), why)
	}
	if p.HostPathVisible(resolved, true) {
		return "", fmt.Errorf("host kubectl %s: a grant of this sandbox makes it WRITABLE. %s", VisibleText(resolved), why)
	}
	if m, h, hit, err := p.writableAliasOf(env, resolved); err != nil {
		return "", err
	} else if hit {
		return "", fmt.Errorf("host kubectl %s: the rw grant %s reaches it through a second mount of the same "+
			"filesystem.%s %s", VisibleText(resolved), VisibleText(m.Host), aliasNote(h), why)
	}
	if name, asked, found := p.writableNameOnChain(env, asGiven); found {
		return "", fmt.Errorf("host kubectl %s: %s %s", VisibleText(asGiven), selectionClause(name, asked), why)
	}
	return resolved, nil
}

// reencodeCAs parses every PEM block of a CA bundle as an X.509 certificate
// and re-encodes them, so what reaches the sandbox is snug's own encoding of
// certificates it parsed — never the host bytes. A block of another type, a
// block with headers, or anything but whitespace after the last block refuses:
// checking only the first block let a trailing PRIVATE KEY ride through into
// the sandbox's kubeconfig (red team, measured).
func reencodeCAs(der []byte) ([]byte, error) {
	var out []byte
	rest := der
	for {
		blk, next := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" || len(blk.Headers) > 0 {
			return nil, fmt.Errorf("holds a %q PEM block; only certificates are carried", blk.Type)
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return nil, fmt.Errorf("holds a certificate that does not parse: %v", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})...)
		rest = next
	}
	if len(out) == 0 {
		return nil, errors.New("is not a PEM CERTIFICATE")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("has bytes after its last certificate")
	}
	return out, nil
}
