package policy

import (
	"slices"
	"strings"
	"testing"
)

// The sandbox maps one uid, so every root-owned file under the read-only /usr
// bind reads as 65534 inside it. OpenSSH refuses a config file owned by neither
// root nor the caller, fatally, so on a host whose system-wide ssh_config lives
// under /usr (openSUSE) `git clone git@github.com:…` failed inside snug with
//
//	Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf
//
// for every account and every profile. Pinning an identity is *about* pushing as
// that account, so the feature did not work at all on this host and nothing said
// so. snug now replaces the system-wide file with one it authors.
//
// Measured, not reasoned: `ssh -F <file>` always worked, because -F makes ssh
// skip the system-wide file. The replacement is that escape applied once by snug
// instead of relying on every caller to pass a flag.

func systemSSHConfigMounts(p *Policy) []string {
	var got []string
	for _, m := range p.Mounts {
		if m.Kind == KindData && slices.Contains(SystemSSHConfigPaths, m.Guest) {
			got = append(got, m.Guest)
		}
	}
	slices.Sort(got)
	return got
}

func TestIdentityReplacesTheSystemSSHConfigWhereTheHostHasOne(t *testing.T) {
	env := newFakeEnv()
	// This host has the /usr spelling and not the /etc one, which is the shape
	// that produced the bug.
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	p, err := Resolve(identityRegistry("~/.ssh/id_ed25519.pub"),
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	got := systemSSHConfigMounts(p)
	want := []string{"/usr/etc/ssh/ssh_config"}
	if !slices.Equal(got, want) {
		t.Fatalf("system ssh_config mounts = %q, want %q — without this ssh does not "+
			"run inside the sandbox at all on such a host", got, want)
	}

	var content string
	for _, m := range p.Mounts {
		if m.Guest == "/usr/etc/ssh/ssh_config" {
			content = string(m.Content)
		}
	}
	// No Include, and that is the whole mechanism rather than tidiness: every
	// file an Include would pull in is root-owned too, so a replacement that
	// kept the Include line would reproduce the exact error it exists to fix.
	// Directives only — the prose in the file explains the absent Include and
	// must not be mistaken for one.
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.EqualFold(strings.Fields(line)[0], "Include") {
			t.Errorf("the generated system ssh_config has an Include directive; every "+
				"file it names is root-owned and reads as 65534 inside:\n%s", content)
		}
	}
	if content == "" {
		t.Error("the generated system ssh_config is empty; it must say why it exists, " +
			"because a reader finding it will otherwise assume the host's was lost")
	}
}

func TestSystemSSHConfigIsNotInventedWhereTheHostHasNone(t *testing.T) {
	// The control that keeps the rule honest in the other direction. snug
	// replaces a file this host's ssh actually reads; it does not author config
	// at a path that does not exist, because that is a grant nobody asked for
	// and it would make the two spellings differ from the host's reality.
	env := newFakeEnv()

	p, err := Resolve(identityRegistry("~/.ssh/id_ed25519.pub"),
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("invented a system ssh_config at %q on a host that has none", got)
	}
}

func TestNoIdentityMeansNoSystemSSHConfigReplacement(t *testing.T) {
	// The replacement rides on the identity, not on @sys: a sandbox that pins no
	// account gets the host's system config exactly as the /usr bind delivers it.
	// Broken for ssh on such a host, and deliberately so — snug does not rewrite
	// a file for a tool the human never asked it to configure.
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("a policy with no pinned identity replaced %q", got)
	}
}

func TestSystemSSHConfigIsNotProducedForSSHModeNone(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSHMode: SSHNone, GitName: "u", GitEmail: "u@example.com"},
	}
	p, err := Resolve(reg, append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("ssh_mode = none still replaced %q; an identity that pins no key "+
			"configures git and nothing else", got)
	}
}
