package policy

import (
	"bytes"
	"crypto/tls"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/kubecfg"
)

// KubeBinding is what Resolve made of a kube identity block: the one cluster
// snug's proxy forwards to and the one credential of the context's user entry
// it presents there. It is resolver output, never profile text, and it is not
// inside Identity because Identity must stay a comparable value of profile
// leaves.
type KubeBinding struct {
	// Context is the profile's context name. It is also the cluster, user and
	// context name in the sandbox's file, so no host-side name reaches it.
	Context string
	// Credential is the credential the proxy presents: identity.kubectl.credential,
	// or the entry's only one when the key is absent. Never "".
	Credential KubeCredential
	// Plugin is the user entry's exec plugin when Credential is exec; its
	// token is the proxy's bearer. nil otherwise.
	Plugin *KubePlugin
	// Kubeconfig is the host path that was decoded, link-free.
	Kubeconfig    string
	Server        string
	CAData        []byte // decoded PEM; nil means the system trust store
	TLSServerName string
	// HostUser is the chosen credential, re-decoded: certificate and key, or
	// the static token, never both. It never enters the sandbox and is never
	// written: internal/cli hands it to the proxy in snug's own memory. Zero
	// when Credential is exec.
	HostUser KubeHostUser
	// CertSubject and CertNotAfter describe the chosen client certificate for
	// the screen and the -v line. The run refuses a certificate past
	// CertNotAfter; Resolve does not, because it reads no clock.
	CertSubject  string
	CertNotAfter time.Time
	// TokenLen and TokenJWT describe the chosen static token for the screen:
	// its length, and whether it has a JWT's three parts. Never its value.
	TokenLen int
	TokenJWT bool
	// Unused names the credentials the entry holds that the proxy does NOT
	// present, for the --dry-run row saying what stayed out.
	Unused []string
	// OtherContexts is every other context name in the host file, sorted.
	OtherContexts []string
}

// KubeHostUser is the chosen credential of the host user entry, re-decoded.
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
	if !p.Identity.Pinned("kubectl") {
		return nil
	}
	k := p.Identity.Kube
	owner := p.IdentityOwner("kubectl")
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{owner}, a...)...)
	}
	path := k.Kubeconfig

	if k.Context == "" {
		return refuse("[identity.kubectl] needs identity.kubectl.context: the name of one context in %s. "+
			"snug reads that context's cluster as data; its user entry never enters the sandbox.", VisibleText(path))
	}
	// snug DECODES this file and presents the credential it holds, so whoever
	// can write it chooses which server that credential is sent to. Under the target it is sandboxed material at any
	// access; anywhere a writable grant reaches, a payload rewrites it for the
	// next run. A tmpfs is not on this list: it is guest-only, and @home's
	// tmpfs at {home} writes nothing through to the host file.
	if _, under := under(target, path); under {
		return refuse("refusing identity.kubectl.kubeconfig %s: it is inside the target %s, the sandboxed material. "+
			"snug decodes this file on the host and presents the credential it holds, so a file the "+
			"repository or an earlier run wrote would choose which server receives that credential. "+
			"Keep your kubeconfig outside the target.", VisibleText(path), VisibleText(target))
	}
	const writable = "refusing identity.kubectl.kubeconfig %s: %s A payload that rewrites it chooses, " +
		"for the NEXT run, which server snug's proxy sends your credential to. Drop the " +
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
	// READABLE is refused too: the file holds the credential the proxy keeps
	// out — and every other context's — so a grant that shows it inside
	// (@parent-ro with the kubeconfig beside the target, an ro bind of
	// ~/.kube) puts it there while the screen says "never inside" (red team,
	// measured). @home's tmpfs at {home} is not a bind and does not count.
	const readable = "refusing identity.kubectl.kubeconfig %s: %s It holds the credential snug's proxy keeps " +
		"out of the sandbox, and every other context's. Drop the grant, or name a kubeconfig no grant shows.%s"
	if p.HostPathVisible(path, false) {
		return refuse(readable, VisibleText(path), "a grant of this sandbox makes it READABLE inside.", "")
	}
	if m, h, hit, err := p.visibleAliasOf(env, path); err != nil {
		return err
	} else if hit {
		return refuse(readable, VisibleText(path), "the grant "+VisibleText(m.Host)+
			" shows it inside through a second mount of the same filesystem.", aliasNote(h))
	}

	f, err := env.KubeConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return refuse("identity.kubectl.kubeconfig %s: no such file. Name the kubeconfig holding context %s, "+
			"or create it with your cloud's get-credentials command.", VisibleText(path), kq(k.Context))
	}
	if err != nil {
		return refuse("identity.kubectl.kubeconfig %s: %s. snug reads the block-style YAML kubectl and az write; "+
			"anchors, aliases, tags, flow collections and multi-line scalars are refused rather than guessed at.",
			VisibleText(path), visibleErr(err))
	}

	cluster, user, others, err := kubePick(f, k.Context, path)
	if err != nil {
		return refuse("%s", err.Error())
	}
	b := &KubeBinding{Context: k.Context, Kubeconfig: path, OtherContexts: others}
	if err := kubeCluster(b, cluster, ctx); err != nil {
		return refuse("%s", err.Error())
	}
	// The file names the server; the profile decides it. An earlier run that
	// could write the kubeconfig — through a target it was in, say — could
	// otherwise point snug, and the credential it sends, at a server of its
	// choosing (red team, measured across two runs).
	if k.Server == "" {
		return refuse("[identity.kubectl] needs identity.kubectl.server: the API server snug may send your host "+
			"credential to. Context %s in %s names %s today; if that is your cluster, write\n"+
			"         server = %s", kq(k.Context), VisibleText(path), VisibleText(b.Server), kq(b.Server))
	}
	if k.Server != b.Server {
		return refuse("identity.kubectl.server is %s, but context %s in %s names %s. Refusing: the kubeconfig "+
			"chooses where snug's proxy sends your credential only if it agrees with the profile, "+
			"and a file another run could have written is not the authority. If you changed the cluster, "+
			"update identity.kubectl.server.", kq(k.Server), kq(k.Context), VisibleText(path), kq(b.Server))
	}
	if err := kubeUser(b, user, k); err != nil {
		return refuse("%s", err.Error())
	}
	if b.Plugin != nil {
		// The plugin runs on the host as you and reads its own configuration
		// from your home: whoever can write ~/.aws/config chooses a
		// credential_process the host runs, and ~/.azure holds the session
		// kubelogin hands to az. Writable through this run's grants, that is
		// the payload choosing code that runs on the host.
		for _, dir := range b.Plugin.ConfigDirs {
			hp := home + "/" + dir
			const why = "refusing credential = %s for context %s: %s %s The %s plugin snug runs on the host " +
				"reads its configuration there, so a payload that writes it chooses what runs on the host as " +
				"you. Drop the rw grant over %s.%s"
			if p.HostPathVisible(hp, true) {
				return refuse(why, kq(string(b.Credential)), kq(k.Context), VisibleText(hp),
					"is WRITABLE through a grant of this sandbox.", b.Plugin.Row, VisibleText(hp), "")
			}
			if m, h, hit, err := p.writableAliasOf(env, hp); err != nil {
				return err
			} else if hit {
				return refuse(why, kq(string(b.Credential)), kq(k.Context), VisibleText(hp),
					"is reached by the rw grant "+VisibleText(m.Host)+" through a second mount.", b.Plugin.Row,
					VisibleText(hp), aliasNote(h))
			}
			if name, asked, found := p.writableNameOnChain(env, hp); found {
				return refuse(why, kq(string(b.Credential)), kq(k.Context), VisibleText(hp),
					selectionClause(name, asked), b.Plugin.Row, VisibleText(hp), "")
			}
		}
	}

	p.Kube = b
	from := []string{p.IdentityProvenance("kubectl")}
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
		return zcl, zu, nil, fmt.Errorf("identity.kubectl.context %s is not in %s (contexts: %s). "+
			"Name one of those, or set identity.kubectl.kubeconfig.",
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
			return fmt.Errorf("cluster %s sets proxy-url; snug's proxy sends your credential to the "+
				"pinned server only, never through a proxy the file names", name)
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
	// The proxy and the exec plugin dial from the HOST, outside the seal
	// that keeps the sandbox off host loopback, so this refusal is what keeps
	// identity.kubectl from being a grant to one host port. It covers literals;
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

// kubeTokenShape is a bearer token: the characters RFC 6750's b64token
// allows that a static token, a ServiceAccount JWT and an exec plugin's token
// use. Nothing else is written into an Authorization header.
var kubeTokenShape = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// KubeTokenOK reports whether tok is one snug's proxy will present.
func KubeTokenOK(tok string) bool { return len(tok) <= 16<<10 && kubeTokenShape.MatchString(tok) }

// kubeUser checks the user entry's shape and keeps the ONE credential the
// proxy presents: the one identity.kubectl.credential names, or the entry's only
// one. An entry holding two is refused when the key is absent, because a
// client certificate and a static token in one entry may be two identities
// (measured on AKS local accounts: the certificate is CN=masterclient in
// system:masters, the token is clusterUser), and kubectl's own choice — the
// certificate — is not one the profile wrote.
func kubeUser(b *KubeBinding, u kubecfg.User, k IdentityKube) error {
	context := k.Context
	keys := make([]string, 0, len(u.Fields))
	for key := range u.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := u.Fields[key]
		switch key {
		case "exec":
		case "client-certificate-data", "client-key-data", "token":
			if v.Kind != kubecfg.Scalar {
				return fmt.Errorf("user of context %s: %s is a %s, not a value", kq(context), key, v.Kind)
			}
		case "client-certificate", "client-key":
			return fmt.Errorf("user of context %s names %s by path; snug reads no second host file for it. "+
				"Fix: kubectl config set-credentials <user> --embed-certs --%s=<path>", kq(context), key, key)
		default:
			return fmt.Errorf("user of context %s sets %s, which snug does not present; an unrecognised "+
				"field is refused rather than dropped", kq(context), VisibleText(key))
		}
	}
	cert, key, tok := u.Fields["client-certificate-data"].Text, u.Fields["client-key-data"].Text, u.Fields["token"].Text
	if (cert == "") != (key == "") {
		return fmt.Errorf("user of context %s has a client certificate without its key, or a key without "+
			"its certificate", kq(context))
	}
	var holds []KubeCredential
	if cert != "" {
		holds = append(holds, KubeCredentialClientCert)
	}
	if tok != "" {
		holds = append(holds, KubeCredentialToken)
	}
	if u.Exec != nil {
		holds = append(holds, KubeCredentialExec)
	}
	names := map[KubeCredential]string{
		KubeCredentialClientCert: "a client certificate", KubeCredentialToken: "a static token",
		KubeCredentialExec: "an exec plugin",
	}
	list := func() string {
		s := make([]string, len(holds))
		for i, h := range holds {
			s[i] = names[h]
		}
		return strings.Join(s, " and ")
	}
	choice := k.Credential
	switch {
	case len(holds) == 0:
		return fmt.Errorf("user of context %s holds no credential snug can present (want "+
			"client-certificate-data and client-key-data, token, or exec)", kq(context))
	case choice == "" && len(holds) > 1:
		vals := make([]string, len(holds))
		for i, h := range holds {
			vals[i] = strconv.Quote(string(h))
		}
		return fmt.Errorf("the user of context %s holds %s; those may be different identities on the "+
			"cluster, and snug presents exactly one and will not choose for you. Write "+
			"identity.kubectl.credential = %s", kq(context), list(), strings.Join(vals, " or "))
	case choice == "":
		choice = holds[0]
	case !slices.Contains(holds, choice):
		return fmt.Errorf("identity.kubectl.credential = %s, but the user of context %s holds %s",
			kq(string(choice)), kq(context), list())
	}
	b.Credential = choice
	for _, h := range holds {
		if h != choice {
			b.Unused = append(b.Unused, "the entry's "+strings.TrimPrefix(strings.TrimPrefix(names[h], "a "), "an ")+
				" (not presented)")
		}
	}
	if choice != KubeCredentialExec && k.AWSProfile != "" {
		return fmt.Errorf("identity.kubectl.aws_profile is set, but credential = %s runs no aws plugin; "+
			"drop the key", kq(string(choice)))
	}
	switch choice {
	case KubeCredentialExec:
		pl, err := kubePluginOf(u.Exec, k, context)
		if err != nil {
			return err
		}
		b.Plugin = pl
	case KubeCredentialClientCert:
		c, err1 := base64.StdEncoding.DecodeString(cert)
		kd, err2 := base64.StdEncoding.DecodeString(key)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("user of context %s: client-certificate-data or client-key-data is not base64",
				kq(context))
		}
		pair, err := tls.X509KeyPair(c, kd)
		if err != nil {
			return fmt.Errorf("user of context %s: its client certificate and key do not form a pair snug "+
				"can present: %v", kq(context), err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return fmt.Errorf("user of context %s: its client certificate does not parse: %v", kq(context), err)
		}
		b.HostUser = KubeHostUser{ClientCertData: c, ClientKeyData: kd}
		b.CertSubject = VisibleText(leaf.Subject.String())
		b.CertNotAfter = leaf.NotAfter
	case KubeCredentialToken:
		if !KubeTokenOK(tok) {
			return fmt.Errorf("user of context %s: its token is over 16 KiB or not a bearer token "+
				"([A-Za-z0-9._-])", kq(context))
		}
		b.HostUser = KubeHostUser{Token: Secret(tok)}
		b.TokenLen = len(tok)
		b.TokenJWT = strings.Count(tok, ".") == 2
	}
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
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

// SandboxKubeconfig is the ~/.kube/config generated inside: one cluster, which
// is snug's proxy on the sandbox's own loopback, one user with NO credential,
// one context. Plain http and no CA: both ends of that loopback are inside the
// sandbox, and the hop to the real server is the proxy's, over TLS, from the
// host. It is JSON, which is YAML, emitted from Go values — no host byte is
// copied, and no host cluster or user name appears in it.
func (k *KubeBinding) SandboxKubeconfig() []byte {
	return kubeconfig(k.Context, kubeClusterOut{Server: KubeProxyGuest}, struct{}{})
}

func kubeconfig(name string, cluster kubeClusterOut, user any) []byte {
	f := kubeconfigFile{
		APIVersion: "v1", Kind: "Config",
		Clusters:       []kubeNamed{{Name: name, Cluster: cluster}},
		Users:          []kubeNamed{{Name: name, User: user}},
		Contexts:       []kubeNamed{{Name: name, Context: kubeContextOut{Cluster: name, User: name}}},
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

// KubeMintBudget is how many times one run may run the exec plugin, the one
// at start included. The token source never runs it before the cached token
// expires — not on a 401 either — so this only binds when a plugin hands out
// very short tokens or the clock jumps.
const KubeMintBudget = 64

// ResolveKubeHostBinary judges a host program identity.kubectl runs with your
// credential — an exec plugin or a helper the plugin runs — named by
// what in messages. It refuses a relative name, a binary inside the target,
// and one a writable grant reaches by bytes, by a second mount, or by a name
// on its resolution chain — the same three arms as ResolveEngineBinary.
// Whether the file is an executable rather than a script is internal/cli's
// check: it needs a read.
func (p *Policy) ResolveKubeHostBinary(env Environ, what, asGiven string) (string, error) {
	if !filepath.IsAbs(asGiven) {
		return "", fmt.Errorf("%s %s is not an absolute path; snug runs it on the host with your "+
			"cluster credential and judges it against this sandbox's grants, which a relative name matches "+
			"none of", what, VisibleText(asGiven))
	}
	asGiven = filepath.Clean(asGiven)
	resolved, err := ResolveExistingHostPath(env, asGiven)
	if err != nil {
		return "", fmt.Errorf("%s %s: %s", what, VisibleText(asGiven), visibleErr(err))
	}
	const why = "snug runs it on the host with your cluster credential, so a binary the payload can " +
		"write or choose is the payload holding that credential. Install it where no grant of " +
		"this sandbox reaches."
	if _, in := under(p.Target, resolved); in {
		return "", fmt.Errorf("%s %s is inside the target %s. %s", what, VisibleText(resolved), VisibleText(p.Target), why)
	}
	if p.HostPathVisible(resolved, true) {
		return "", fmt.Errorf("%s %s: a grant of this sandbox makes it WRITABLE. %s", what, VisibleText(resolved), why)
	}
	if m, h, hit, err := p.writableAliasOf(env, resolved); err != nil {
		return "", err
	} else if hit {
		return "", fmt.Errorf("%s %s: the rw grant %s reaches it through a second mount of the same "+
			"filesystem.%s %s", what, VisibleText(resolved), VisibleText(m.Host), aliasNote(h), why)
	}
	if name, asked, found := p.writableNameOnChain(env, asGiven); found {
		return "", fmt.Errorf("%s %s: %s %s", what, VisibleText(asGiven), selectionClause(name, asked), why)
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
