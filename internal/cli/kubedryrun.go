package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// reportKube is identity.kubectl as a fact about this run: where the
// sandbox's generated kubeconfig points, which credential of the context the
// proxy presents, what the proxy refuses, and what stays out. Every value is
// the one the run uses, from the same functions.
type reportKube struct {
	Context    string
	Server     string
	Credential string // identity.kubectl.credential as resolved
	// Chosen says how Credential was chosen: "" when the profile named it,
	// else why it is the only reading.
	Chosen     string
	Presented  string   // what the proxy presents, described, never a value
	Absent     []string // what the host file holds and the sandbox does not get
	Visible    []string // credential-bearing paths a grant makes visible anyway
	Proxy      string   // the guest URL kubectl talks to
	Refused    []string // what the proxy refuses from inside
	MintBudget int
	// The context's exec plugin, when Credential is exec.
	PluginRow     string
	Plugin        string // the judged binary, empty when there is none
	PluginProblem string // why there is none; a real run refuses on it
	PluginArgv    []string
	PluginEnv     []string // NAME=value, exactly what the plugin gets
	PluginHelpers []string // programs the plugin runs, judged for writability
	PluginReach   string
}

// kubeProxyRefuses is what the proxy refuses from inside, for the screen. It
// is the list internal/kubeproxy's admit and dialer enforce, named, not
// re-derived: everything that would change WHERE the credential goes.
var kubeProxyRefuses = []string{
	"CONNECT", "absolute URIs", "dot and escaped path segments",
	"loopback, host-owned and cloud-metadata addresses",
}

func buildKubeReport(p *policy.Policy) *reportKube {
	k := p.Kube
	if k == nil {
		return nil
	}
	r := &reportKube{Credential: string(k.Credential), MintBudget: policy.KubeMintBudget}
	if p.Identity.Kube.Credential == "" {
		r.Chosen = "the entry's only credential"
	}
	switch k.Credential {
	case policy.KubeCredentialClientCert:
		r.Presented = fmt.Sprintf("client certificate %s, expires %s, as the TLS client certificate",
			k.CertSubject, k.CertNotAfter.UTC().Format("2006-01-02"))
	case policy.KubeCredentialToken:
		shape := "not a JWT, so it carries no expiry"
		if k.TokenJWT {
			shape = "a JWT"
		}
		r.Presented = fmt.Sprintf("static token (%d chars, %s) as the bearer, replacing any the client sends",
			k.TokenLen, shape)
	case policy.KubeCredentialExec:
		r.Presented = fmt.Sprintf("the token the %s plugin returns, as the bearer, replacing any the client "+
			"sends; again on expiry, at most %d times", k.Plugin.Row, policy.KubeMintBudget)
	}
	if pl := k.Plugin; pl != nil {
		bin := p.KubePluginBinary
		if bin == "" {
			bin = pl.Command
		}
		r.PluginRow, r.Plugin, r.PluginProblem = pl.Row, p.KubePluginBinary, p.KubePluginProblem
		r.PluginArgv, r.PluginEnv, r.PluginReach = pl.KubeExecArgv(bin), pl.KubePluginEnv(p.Home), pl.Reach
		r.PluginHelpers = pl.Helpers
	}
	absent := append(append([]string{}, k.OtherContexts...), k.Unused...)
	var visible []string
	// Read off the policy, not asserted: a profile grant onto either path
	// makes it visible whatever identity.kubectl does (red team: a host:guest
	// bind onto ~/.azure was readable while this row said absent).
	for _, rel := range []string{".kube/cache", ".azure", ".aws"} {
		if from, ok := guestVisible(p, p.Home+"/"+rel); ok {
			visible = append(visible, "~/"+rel+" (granted by "+from+")")
		} else {
			absent = append(absent, "~/"+rel)
		}
	}
	r.Context, r.Server = k.Context, k.Server
	r.Absent, r.Visible = absent, visible
	r.Proxy, r.Refused = policy.KubeProxyGuest, kubeProxyRefuses
	return r
}

// flagLines breaks an argv at every flag, never by width: run-directory
// paths carry this process's pid, so a wrap by width would move with the
// pid's length.
func flagLines(argv []string) []string {
	var lines []string
	for _, a := range argv {
		a = visibleValue(a)
		if len(lines) == 0 || strings.HasPrefix(a, "-") {
			lines = append(lines, a)
		} else {
			lines[len(lines)-1] += " " + a
		}
	}
	return lines
}

// describeArgv prints argv under label, one flag per line.
func describeArgv(out io.Writer, label string, argv []string, problem bool) {
	for i, line := range flagLines(argv) {
		l := label
		if i > 0 || problem {
			l = strings.Repeat(" ", len(label))
		}
		if i > 0 {
			line = "  " + line
		}
		fmt.Fprintf(out, "         %s %s\n", l, line)
	}
}

// describeKube is the KUBE block of --dry-run. It reads only the report.
func describeKube(out io.Writer, k *reportKube) {
	if k == nil {
		return
	}
	fmt.Fprintf(out, "KUBECTL  context    %s -> %s\n", visibleValue(k.Context), visibleValue(k.Server))
	fmt.Fprintf(out, "                    server pinned by the profile; generated ~/.kube/config, read-only,\n")
	fmt.Fprintf(out, "                    with NO credential: kubectl talks to %s, snug's proxy\n", k.Proxy)
	fmt.Fprintf(out, "                    on the host presents your credential to that server only\n")
	fmt.Fprintf(out, "         as         YOU — the user of context %s\n", visibleValue(k.Context))
	cred := k.Credential
	if k.Chosen != "" {
		cred += " (" + k.Chosen + ")"
	}
	fmt.Fprintf(out, "         credential %s\n", cred)
	for _, line := range wrapWords(k.Presented+"; read from the host kubeconfig at start (this dry run "+
		"presented nothing), held in snug's memory for the run, never written, never inside", 62) {
		fmt.Fprintf(out, "                    %s\n", visibleValue(line))
	}
	if k.PluginRow != "" {
		if k.PluginProblem != "" {
			fmt.Fprintf(out, "         plugin     NONE — a real run would REFUSE to start: %s\n", visibleValue(k.PluginProblem))
		}
		describeArgv(out, "plugin    ", k.PluginArgv, k.PluginProblem != "")
		for _, e := range k.PluginEnv {
			fmt.Fprintf(out, "                    env %s\n", visibleValue(e))
		}
		fmt.Fprintf(out, "                    and nothing else; cwd /, own user+pid namespace, %s timeout.\n", kubeMintTimeout)
		fmt.Fprintf(out, "                    The file's exec.env is never used. Only the token and its expiry\n")
		fmt.Fprintf(out, "                    are read from its answer\n")
		if len(k.PluginHelpers) > 0 {
			fmt.Fprintf(out, "                    it runs %s off that PATH, judged unwritable like the plugin\n",
				strings.Join(k.PluginHelpers, ", "))
		}
		for i, line := range wrapWords(k.PluginReach+"; snug sends it to "+k.Server+" only", 62) {
			label := "plugin token"
			if i > 0 {
				label = "            "
			}
			fmt.Fprintf(out, "         %s %s\n", label, visibleValue(line))
		}
	}
	for i, line := range wrapList(k.Refused, 60) {
		label := "refused   "
		if i > 0 {
			label = "          "
		}
		fmt.Fprintf(out, "         %s %s\n", label, line)
	}
	for i, line := range wrapList(k.Absent, 60) {
		label := "absent    "
		if i > 0 {
			label = "          "
		}
		fmt.Fprintf(out, "         %s %s\n", label, visibleValue(line))
	}
	for _, v := range k.Visible {
		fmt.Fprintf(out, "         VISIBLE    %s — identity.kubectl does not keep it out\n", visibleValue(v))
	}
	fmt.Fprintf(out, "         reach      whatever YOUR RBAC allows, on this one server, while this run\n")
	fmt.Fprintf(out, "                    lives; snug cannot see RBAC and claims nothing. Impersonation,\n")
	fmt.Fprintf(out, "                    Secrets, TokenRequest and workloads are yours to use if the cluster\n")
	fmt.Fprintf(out, "                    allows, and what is read or minted outlives the run. No credential\n")
	fmt.Fprintf(out, "                    of yours is inside to carry away. pods/exec, pods/portforward and\n")
	fmt.Fprintf(out, "                    services/proxy reach the cluster's network through the API\n")
	fmt.Fprintf(out, "                    server, with or without @net\n")
}

// guestVisible reports whether guest is reachable inside through a grant: the
// deepest mount at or above it is a bind, graft or generated file rather than
// a tmpfs or snug's anchor. from is that mount's provenance.
func guestVisible(p *policy.Policy, guest string) (string, bool) {
	best := ""
	for g := range p.Mounts {
		if (g == guest || strings.HasPrefix(guest, g+"/")) && len(g) > len(best) {
			best = g
		}
	}
	if best == "" {
		return "", false
	}
	m := p.Mounts[best]
	if m.Anchor || m.Kind == policy.KindTmpfs {
		return "", false
	}
	return strings.Join(m.From, "+"), true
}
