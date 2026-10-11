package draft

import (
	"fmt"
	"slices"
	"strings"
)

func q(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func qlist(xs []string) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = q(x)
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// RunArgs are the arguments that select this profile, for the directory dir.
func (d *Draft) RunArgs(dir string) []string {
	var args []string
	if d.ReadOnlyTarget {
		args = append(args, "--no-defaults")
	}
	return append(args, "-p", d.profileName(), dir)
}

// RunLine is RunArgs as a shell command line.
func (d *Draft) RunLine(dir string) string {
	args := d.RunArgs(dir)
	args[len(args)-1] = shellQuote(dir)
	return "snug " + strings.Join(args, " ")
}

func (d *Draft) profileName() string {
	if d.Name == "" {
		return "NAME"
	}
	return d.Name
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-~") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Includes returns the include list as rendered: a read-only target adds @sys
// and @home, which the defaults would otherwise have supplied.
func (d *Draft) Includes() []string {
	inc := slices.Clone(d.Include)
	if d.ReadOnlyTarget {
		for _, n := range []string{"@home", "@sys"} {
			if !slices.Contains(inc, n) {
				inc = append([]string{n}, inc...)
			}
		}
	}
	return inc
}

// Render writes the draft as TOML: the intent ledger as comments, then one
// `[profile.NAME]` table, every built-in it includes followed by the ABUSE
// sentence snug ships for it. An unnamed
// draft renders as NAME. The output is a file like any other for snug to parse;
// nothing in it is trusted because snug-setup wrote it.
func (d *Draft) Render() string {
	var b strings.Builder
	n := d.profileName()
	b.WriteString("# Written by snug-setup. Nothing in this file is trusted because snug-setup wrote it:\n")
	b.WriteString("# snug parses it like any other profile. Read it before you select it.\n")
	if d.Name == "" {
		b.WriteString("# The profile has no name yet; NAME stands in for it.\n")
	}
	for _, l := range d.IntentLines() {
		b.WriteString(l + "\n")
	}
	fmt.Fprintf(&b, "[profile.%s]\n", n)

	if inc := d.Includes(); len(inc) > 0 {
		b.WriteString("include = [\n")
		for _, name := range inc {
			if s, ok := Abuse[name]; ok {
				fmt.Fprintf(&b, "  # ABUSE (%s): %s\n", name, s)
			}
			fmt.Fprintf(&b, "  %s,\n", q(name))
		}
		b.WriteString("]\n")
	}
	ro := slices.Clone(d.RO)
	if d.ReadOnlyTarget {
		ro = append([]string{"{target}"}, ro...)
	}
	for _, s := range d.Staged {
		ro = append(ro, s.K+":/snug/bin/"+s.V)
	}
	if len(ro) > 0 {
		fmt.Fprintf(&b, "ro = %s\n", qlist(ro))
	}
	if len(d.RW) > 0 {
		fmt.Fprintf(&b, "rw = %s\n", qlist(d.RW))
	}
	if len(d.Tmpfs) > 0 {
		fmt.Fprintf(&b, "tmpfs = %s\n", qlist(d.Tmpfs))
	}
	if len(d.Doors) > 0 {
		fmt.Fprintf(&b, "# ABUSE: %s\n", Abuse["listen_names"])
		fmt.Fprintf(&b, "listen_names = %s\n", qlist(d.Doors))
	}
	if len(d.EnvSet) > 0 {
		fmt.Fprintf(&b, "\n[profile.%s.environ.set]\n", n)
		for _, p := range d.EnvSet {
			fmt.Fprintf(&b, "%s = %s\n", p.K, q(p.V))
		}
	}
	if len(d.EnvInherit) > 0 {
		fmt.Fprintf(&b, "\n[profile.%s.environ.inherit]\n", n)
		for _, name := range d.EnvInherit {
			fmt.Fprintf(&b, "%s = true\n", name)
		}
	}
	if len(d.EnvPrepend) > 0 {
		fmt.Fprintf(&b, "\n[profile.%s.environ.prepend]\n", n)
		var order []string
		byName := map[string][]string{}
		for _, p := range d.EnvPrepend {
			if _, ok := byName[p.K]; !ok {
				order = append(order, p.K)
			}
			byName[p.K] = append(byName[p.K], p.V)
		}
		for _, name := range order {
			fmt.Fprintf(&b, "%s = %s\n", name, qlist(byName[name]))
		}
	}
	sshHost, ghHost := d.hosts()
	if d.SSH != nil || d.GH != nil {
		fmt.Fprintf(&b, "\n# ABUSE: %s.\n", Abuse["identity"])
		b.WriteString("# One identity per profile; two accounts are two profiles.\n")
	}
	if d.SSH != nil {
		fmt.Fprintf(&b, "[profile.%s.identity.ssh]\n", n)
		if sshHost != "" {
			fmt.Fprintf(&b, "host = %s\n", q(sshHost))
		}
		fmt.Fprintf(&b, "key = %s # the PUBLIC half\nagent = \"proxy\"\n", q(d.SSH.Key))
	}
	if d.Git != nil {
		fmt.Fprintf(&b, "[profile.%s.identity.git]\nname = %s\nemail = %s\n", n, q(d.Git.Name), q(d.Git.Email))
	}
	if d.GH != nil {
		fmt.Fprintf(&b, "[profile.%s.identity.gh]\n", n)
		if ghHost != "" {
			fmt.Fprintf(&b, "host = %s\n", q(ghHost))
		}
		fmt.Fprintf(&b, "user = %s\n", q(d.GH.User))
	}
	return b.String()
}
