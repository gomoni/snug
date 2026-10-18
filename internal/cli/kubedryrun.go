package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// reportKube is identity.kube as a fact about this run: what the sandbox's
// generated kubeconfig names, the exact host command that mints, and what
// stays out. Every value is the one the run uses, from the same functions.
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
	Shim              string
	Socket            string
}

func buildKubeReport(p *policy.Policy) *reportKube {
	k := p.Kube
	if k == nil {
		return nil
	}
	mintFile, _ := plannedSocket("kube-mint.json")
	cache, _ := plannedSocket("kube-cache")
	kubectl := p.KubeMintBinary
	if kubectl == "" {
		kubectl = "kubectl"
	}
	cred := "your client certificate"
	if len(k.HostUser.ClientCertData) == 0 {
		cred = "your static token"
	}
	absent := append(append([]string{}, k.OtherContexts...), "the host user entry ("+strings.Join(k.HostUserShape, ", ")+")")
	var visible []string
	// Read off the policy, not asserted: a profile grant onto either path
	// makes it visible whatever identity.kube does (red team: a host:guest
	// bind onto ~/.azure was readable while this row said absent).
	for _, rel := range []string{".kube/cache", ".azure"} {
		if from, ok := guestVisible(p, p.Home+"/"+rel); ok {
			visible = append(visible, "~/"+rel+" (granted by "+from+")")
		} else {
			absent = append(absent, "~/"+rel)
		}
	}
	return &reportKube{
		Context: k.Context, Server: k.Server, ServiceAccount: k.SANamespace + "/" + k.SAName,
		Namespace: k.SANamespace, Kubectl: p.KubeMintBinary, KubectlProblem: p.KubeMintProblem,
		MintArgv: k.MintArgv(kubectl, mintFile, cache), MintEnv: policy.KubeMintEnvNames(),
		MintBudget: policy.KubeMintBudget, Requested: policy.KubeTokenDuration,
		Credential: cred, Absent: absent, Visible: visible,
		StaticTokenUnused: len(k.HostUser.ClientCertData) > 0 && slices.Contains(k.HostUserShape, "static token"),
		Shim:              policy.KubeTokenShimGuest, Socket: policy.KubeTokenSocketGuest,
	}
}

// describeKube is the KUBE block of --dry-run. It reads only the report.
func describeKube(out io.Writer, k *reportKube) {
	if k == nil {
		return
	}
	fmt.Fprintf(out, "KUBE     context    %s -> %s\n", visibleValue(k.Context), visibleValue(k.Server))
	fmt.Fprintf(out, "                    server pinned by the profile; generated ~/.kube/config, read-only\n")
	fmt.Fprintf(out, "         as         ServiceAccount %s (namespace %s)\n", visibleValue(k.ServiceAccount), visibleValue(k.Namespace))
	fmt.Fprintf(out, "         token      minted on the host at start (this dry run minted nothing), again on\n")
	fmt.Fprintf(out, "                    expiry while this run lives, at most %d times; requested %s, the\n", k.MintBudget, k.Requested)
	fmt.Fprintf(out, "                    cluster may cap or extend it\n")
	if k.KubectlProblem != "" {
		fmt.Fprintf(out, "         host mint  NONE — a real run would REFUSE to start: %s\n", visibleValue(k.KubectlProblem))
	}
	argv := make([]string, len(k.MintArgv))
	for i, a := range k.MintArgv {
		argv[i] = visibleValue(a)
	}
	// A new line at every flag, never by width: the run-directory paths carry
	// this process's pid, so a wrap by width would move with the pid's length.
	var lines []string
	for _, a := range argv {
		if len(lines) == 0 || strings.HasPrefix(a, "-") {
			lines = append(lines, a)
		} else {
			lines[len(lines)-1] += " " + a
		}
	}
	for i, line := range lines {
		label := "host mint "
		if i > 0 || k.KubectlProblem != "" {
			label = "          "
		}
		if i > 0 {
			line = "  " + line
		}
		fmt.Fprintf(out, "         %s %s\n", label, line)
	}
	fmt.Fprintf(out, "                    env %s, cwd /, own user+pid namespace, %s timeout\n",
		strings.Join(k.MintEnv, " "), kubeMintTimeout)
	fmt.Fprintf(out, "                    authenticates on the HOST as the user of context %s,\n", visibleValue(k.Context))
	fmt.Fprintf(out, "                    with %s; that credential never enters the\n", k.Credential)
	fmt.Fprintf(out, "                    sandbox, and if the host user is cluster-admin this pinned\n")
	fmt.Fprintf(out, "                    argv is the whole bound on what the host mint does\n")
	if k.StaticTokenUnused {
		fmt.Fprintf(out, "                    the host user's static token is not used and not sent\n")
	}
	fmt.Fprintf(out, "         inside     %s (exec plugin; snug's own binary)\n", k.Shim)
	fmt.Fprintf(out, "                    socket %s (0600, run-scoped)\n", k.Socket)
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
	fmt.Fprintf(out, "         reach      whatever %s's RoleBinding allows; snug cannot see RBAC and\n", visibleValue(k.ServiceAccount))
	fmt.Fprintf(out, "                    claims nothing. After the run, up to one token lifetime — and only\n")
	fmt.Fprintf(out, "                    if the Role grants no token/secret create or read, no workload\n")
	fmt.Fprintf(out, "                    create or patch, no nodes/proxy. pods/exec, pods/portforward and\n")
	fmt.Fprintf(out, "                    services/proxy reach the cluster's private network through the\n")
	fmt.Fprintf(out, "                    API server\n")
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
