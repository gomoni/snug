package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"snug/internal/policy"
)

// dryRun is not a debugging convenience. It is the mechanism by which a human
// can trust snug at all: a sandbox you cannot read is a sandbox you are
// guessing about. It starts no process and creates no file.
func dryRun(p *policy.Policy, args []string, cfg config) {
	out := os.Stdout
	fmt.Fprintln(out, "snug — dry run, nothing was started")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "TARGET   %s  (writable)\n", p.Target)
	fmt.Fprintf(out, "HOME     %s  (tmpfs, ephemeral)\n", p.Home)
	fmt.Fprintf(out, "PROFILES %s\n", strings.Join(p.Selected, " "))
	if implied := p.Implied(); len(implied) > 0 {
		fmt.Fprintf(out, "         + %s  (pulled in by include; see: snug profile tree)\n",
			strings.Join(implied, " "))
	}
	describeNetwork(out, p)
	if p.NewSession {
		fmt.Fprintf(out, "TTY      --new-session (this kernel allows TIOCSTI, so the sandbox is kept\n")
		fmt.Fprintf(out, "         out of your terminal — the cost is no job control inside)\n")
	} else {
		fmt.Fprintf(out, "TTY      shared session — job control works (TIOCSTI is disabled kernel-wide)\n")
	}
	if cfg.readOnly {
		fmt.Fprintln(out, "CLAMP    --read-only: every writable grant demoted to read-only")
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "FILESYSTEM  (deny-by-default; every line is a grant, there are no deny rules)")
	for _, m := range p.SortedMounts() {
		kind := m.Kind.String()
		if m.Kind == policy.KindBind {
			kind = m.Access.String()
		}
		opt := ""
		if m.Optional {
			opt = " (optional)"
		}
		detail := m.Guest
		if m.Kind == policy.KindSymlink {
			detail = fmt.Sprintf("%s -> %s", m.Guest, m.Host)
		} else if m.Kind == policy.KindBind && m.Host != m.Guest {
			detail = fmt.Sprintf("%s (from %s)", m.Guest, m.Host)
		}
		fmt.Fprintf(out, "  %-6s %-46s %s%s\n", kind, detail, strings.Join(m.From, "+"), opt)
	}
	fmt.Fprintf(out, "  %-6s %s\n", "ro-/", "everything else is a read-only skeleton (--remount-ro /)")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  NOT GRANTED (never mounted — these read as absent, they are not hidden):")
	for _, line := range notGranted(p) {
		fmt.Fprintf(out, "    %s\n", line)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "ENVIRONMENT  (--clearenv, then:)")
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "  %s=%s\n", k, p.Env[k])
	}

	if p.Net.Mode == policy.NetEgress {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "── pasta ─────────────────────────────────────────────────────────────────")
		fmt.Fprintln(out, "pasta "+strings.Join(p.PastaArgs(0), " "))
		fmt.Fprintln(out, "  (/proc/0/... is a placeholder; the real pid is bwrap's child)")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "── bwrap ─────────────────────────────────────────────────────────────────")
	fmt.Fprintln(out, formatArgs(args))
}

// describeNetwork spells out what the sandbox can and cannot reach. The
// negative half matters more than the positive half and is stated first.
func describeNetwork(out *os.File, p *policy.Policy) {
	switch p.Net.Mode {
	case policy.NetIsolated:
		fmt.Fprintf(out, "NETWORK  isolated — private netns, loopback only, no helper process.\n")
		fmt.Fprintf(out, "         No egress. No host loopback. No abstract sockets (X11/D-Bus are\n")
		fmt.Fprintf(out, "         netns-scoped, so they are out too). Add the 'net' profile for egress.\n")
	case policy.NetEgress:
		fmt.Fprintf(out, "NETWORK  egress — private netns (one per sandbox) with a pasta helper.\n")
		fmt.Fprintf(out, "         host loopback   UNREACHABLE (--map-host-loopback none, -T none, -U none)\n")
		fmt.Fprintf(out, "         abstract unix   UNREACHABLE (netns-scoped: X11, D-Bus)\n")
		fmt.Fprintf(out, "         egress          full, IPv4 + IPv6\n")
		if p.Net.DNS {
			fmt.Fprintf(out, "         dns             169.254.1.1 -> pasta -> host resolver\n")
		}
		switch {
		case p.Net.PublishAuto:
			fmt.Fprintf(out, "         host -> sandbox EVERY port the sandbox binds, on the host's 127.0.0.1\n")
		case len(p.Net.Publish) > 0:
			fmt.Fprintf(out, "         host -> sandbox ports %v, on the host's 127.0.0.1 only\n", p.Net.Publish)
		default:
			fmt.Fprintf(out, "         host -> sandbox CLOSED (add 'net-publish', or publish=[3000], to open)\n")
		}
		if p.Net.Address != "" {
			fmt.Fprintf(out, "         address         %s (synthetic; the host's LAN address is hidden)\n", p.Net.Address)
		} else {
			fmt.Fprintf(out, "         address         copied from the host — add 'net-anon' to hide it\n")
		}
	case policy.NetHost:
		fmt.Fprintf(out, "NETWORK  HOST — the sandbox SHARES your network namespace.\n")
		fmt.Fprintf(out, "         Every 127.0.0.1 service, every abstract socket (X11 keylogging and\n")
		fmt.Fprintf(out, "         screenshots included), and the LAN as you. Requires --i-know.\n")
	}
}

// notGranted probes for paths a reasonable person would expect to be there and
// confirms they are absent from the grant set. This is the only advisory part
// of explain — but it is what makes deny-by-default legible rather than
// something you take on faith.
func notGranted(p *policy.Policy) []string {
	var lines []string

	candidates := []string{
		".ssh", ".gnupg", ".aws", ".config/gh", ".kube", ".docker", ".netrc",
		".claude", ".mozilla", ".local/share/keyrings",
	}
	var absent []string
	for _, c := range candidates {
		full := filepath.Join(p.Home, c)
		if _, err := os.Stat(full); err != nil {
			continue // not on this host either; do not claim credit for it
		}
		if !covered(p, full) {
			absent = append(absent, "~/"+c)
		}
	}
	if len(absent) > 0 {
		lines = append(lines, strings.Join(absent, "  "))
	}

	// Siblings of the target, which is the property the dotdot profile is
	// really about: the parent is readable, its other children are not.
	parent := filepath.Dir(p.Target)
	if entries, err := os.ReadDir(parent); err == nil {
		n := 0
		for _, e := range entries {
			full := filepath.Join(parent, e.Name())
			if full != p.Target && !covered(p, full) {
				n++
			}
		}
		if n > 0 {
			lines = append(lines, fmt.Sprintf("%d sibling entries under %s", n, parent))
		}
	}

	lines = append(lines, "/sys  /tmp/.X11-unix  the Wayland socket  the session D-Bus socket")
	return lines
}

// covered reports whether a host path is reachable through some grant.
func covered(p *policy.Policy, host string) bool {
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind {
			continue
		}
		if host == m.Host || strings.HasPrefix(host, m.Host+"/") {
			return true
		}
	}
	return false
}

func formatArgs(args []string) string {
	var b strings.Builder
	b.WriteString("bwrap")
	for _, a := range args {
		if strings.HasPrefix(a, "--") || a == "--" {
			b.WriteString("\n  ")
		} else {
			b.WriteString(" ")
		}
		b.WriteString(a)
	}
	return b.String()
}
