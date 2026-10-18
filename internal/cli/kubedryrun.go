package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// reportKube is identity.kube as a fact about this run: where the sandbox's
// generated kubeconfig points, the exact host command that mints, what the
// proxy refuses, and what stays out. Every value is the one the run uses, from the same functions.
type reportKube struct {
	Context        string
	Server         string
	ServiceAccount string // namespace/name
	Namespace      string
	Kubectl        string // the host kubectl, empty when there is none
	KubectlProblem string // why there is none; a real run refuses on it
	MintArgv       []string
	MintEnv        []string // names only
	MintBudget     int
	Requested      string
	Credential     string // what the host-side mint authenticates with
	// StaticTokenUnused is true when the host user entry also holds a static
	// token, which the mint leaves out because a certificate is there.
	StaticTokenUnused bool
	Absent            []string // what the host file holds and the sandbox does not get
	Visible           []string // credential-bearing paths a grant makes visible anyway
	Proxy             string   // the guest URL kubectl talks to
	Refused           []string // what the proxy refuses from inside
	Mode              string   // identity.kube.token
	// The host context's exec plugin, when its user entry is one.
	PluginRow     string
	Plugin        string // the judged binary, empty when there is none
	PluginProblem string // why there is none; a real run refuses on it
	PluginArgv    []string
	PluginEnv     []string // NAME=value, exactly what the plugin gets
	PluginHelpers []string // programs the plugin runs, judged for writability
	PluginReach   string
}

// kubeProxyRefuses is what the proxy refuses from inside, for the screen. It
// is the list internal/kubeproxy's admit enforces, named, not re-derived.
var kubeProxyRefuses = []string{
	"Authorization", "Proxy-Authorization", "Impersonate-*", "X-Remote-*",
	"a websocket bearer", "trailers", "CONNECT", "absolute URIs", "dot segments",
}

func buildKubeReport(p *policy.Policy) *reportKube {
	k := p.Kube
	if k == nil {
		return nil
	}
	r := &reportKube{Mode: string(k.Mode)}
	if k.Mode == policy.KubeTokenServiceAccount {
		mintFile, _ := plannedSocket("kube-mint.json")
		cache, _ := plannedSocket("kube-cache")
		kubectl := p.KubeMintBinary
		if kubectl == "" {
			kubectl = "kubectl"
		}
		r.MintArgv = k.MintArgv(kubectl, mintFile, cache)
		r.MintEnv = policy.KubeMintEnvNames()
	}
	cred := "your client certificate"
	switch {
	case k.Plugin != nil:
		cred = "the token your " + k.Plugin.Row + " plugin returns"
	case len(k.HostUser.ClientCertData) == 0:
		cred = "your static token"
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
	absent := append(append([]string{}, k.OtherContexts...), "the host user entry ("+strings.Join(k.HostUserShape, ", ")+")")
	var visible []string
	// Read off the policy, not asserted: a profile grant onto either path
	// makes it visible whatever identity.kube does (red team: a host:guest
	// bind onto ~/.azure was readable while this row said absent).
	for _, rel := range []string{".kube/cache", ".azure", ".aws"} {
		if from, ok := guestVisible(p, p.Home+"/"+rel); ok {
			visible = append(visible, "~/"+rel+" (granted by "+from+")")
		} else {
			absent = append(absent, "~/"+rel)
		}
	}
	r.Context, r.Server, r.Namespace = k.Context, k.Server, k.SANamespace
	if k.SAName != "" {
		r.ServiceAccount = k.SANamespace + "/" + k.SAName
	}
	r.Kubectl, r.KubectlProblem = p.KubeMintBinary, p.KubeMintProblem
	r.MintBudget, r.Requested = policy.KubeMintBudget, policy.KubeTokenDuration
	r.Credential, r.Absent, r.Visible = cred, absent, visible
	r.StaticTokenUnused = len(k.HostUser.ClientCertData) > 0 && slices.Contains(k.HostUserShape, "static token")
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
	fmt.Fprintf(out, "KUBE     context    %s -> %s\n", visibleValue(k.Context), visibleValue(k.Server))
	fmt.Fprintf(out, "                    server pinned by the profile; generated ~/.kube/config, read-only,\n")
	fmt.Fprintf(out, "                    with NO credential: kubectl talks to %s, snug's proxy\n", k.Proxy)
	fmt.Fprintf(out, "                    on the host adds the bearer and forwards to that server only\n")
	if k.ServiceAccount != "" {
		fmt.Fprintf(out, "         as         ServiceAccount %s (namespace %s)\n", visibleValue(k.ServiceAccount), visibleValue(k.Namespace))
		fmt.Fprintf(out, "         token      minted on the host at start (this dry run minted nothing), again on\n")
		fmt.Fprintf(out, "                    expiry while this run lives, at most %d times; requested %s, the\n", k.MintBudget, k.Requested)
		fmt.Fprintf(out, "                    cluster may cap or extend it. It never enters the sandbox\n")
	} else {
		fmt.Fprintf(out, "         as         YOU — the user of context %s, through its %s plugin\n", visibleValue(k.Context), k.PluginRow)
		fmt.Fprintf(out, "         token      returned by the plugin on the host at start (this dry run ran\n")
		fmt.Fprintf(out, "                    nothing), again on expiry while this run lives, at most %d times;\n", k.MintBudget)
		fmt.Fprintf(out, "                    its issuer decides its lifetime. It never enters the sandbox\n")
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
	if len(k.MintArgv) > 0 {
		if k.KubectlProblem != "" {
			fmt.Fprintf(out, "         host mint  NONE — a real run would REFUSE to start: %s\n", visibleValue(k.KubectlProblem))
		}
		describeArgv(out, "host mint ", k.MintArgv, k.KubectlProblem != "")
		fmt.Fprintf(out, "                    env %s, cwd /, own user+pid namespace, %s timeout\n",
			strings.Join(k.MintEnv, " "), kubeMintTimeout)
		fmt.Fprintf(out, "                    authenticates on the HOST as the user of context %s,\n", visibleValue(k.Context))
		fmt.Fprintf(out, "                    with %s; that credential never enters the\n", k.Credential)
		fmt.Fprintf(out, "                    sandbox, and if the host user is cluster-admin this pinned\n")
		fmt.Fprintf(out, "                    argv is the whole bound on what the host mint does\n")
		if k.StaticTokenUnused {
			fmt.Fprintf(out, "                    the host user's static token is not used and not sent\n")
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
		fmt.Fprintf(out, "         VISIBLE    %s — identity.kube does not keep it out\n", visibleValue(v))
	}
	who := "YOUR RBAC allows"
	if k.ServiceAccount != "" {
		who = visibleValue(k.ServiceAccount) + "'s RoleBinding allows"
	}
	fmt.Fprintf(out, "         reach      whatever %s, on this one server,\n", who)
	fmt.Fprintf(out, "                    while this run lives; snug cannot see RBAC and claims nothing. No\n")
	fmt.Fprintf(out, "                    token of snug's is inside to carry away — but a Role that reads\n")
	fmt.Fprintf(out, "                    Secrets, creates tokens or creates pods hands out credentials\n")
	fmt.Fprintf(out, "                    that outlive the run. pods/exec, pods/portforward and\n")
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
