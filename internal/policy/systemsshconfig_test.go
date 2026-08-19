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
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
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
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("invented a system ssh_config at %q on a host that has none", got)
	}
}

// TestNoIdentityStillReplacesTheSystemSSHConfigWhereTheHostHasOne is the
// INVERSE of what this test asserted before issue #40: it used to pin the bug
// on purpose ("broken for ssh on such a host, and deliberately so"). That was
// wrong — pinning an identity is about pushing as one account, and the
// ownership refusal this replacement fixes has nothing to do with an account
// at all. It is a base fact about the sandbox (one uid mapped, root-owned file
// under a read-only bind reads as 65534, OpenSSH refuses it) that is exactly
// as true with no [identity] selected as with one. Gating the fix on identity
// left ssh — and git-over-ssh, scp, rsync -e ssh — broken in every unpinned
// sandbox on such a host, which is issue #40. The replacement now rides on
// COVERAGE (is the host's file actually visible inside?), computed in
// replaceSystemSSHConfig, not on p.Identity.
func TestNoIdentityStillReplacesTheSystemSSHConfigWhereTheHostHasOne(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	got := systemSSHConfigMounts(p)
	want := []string{"/usr/etc/ssh/ssh_config"}
	if !slices.Equal(got, want) {
		t.Fatalf("system ssh_config mounts = %q, want %q — a plain `snug <dir>` run "+
			"with no identity must still get a working ssh", got, want)
	}
	m := p.Mounts["/usr/etc/ssh/ssh_config"]
	if !m.Authored {
		t.Error("the replacement mount is not marked Authored")
	}
	// Provenance must read (snug), never identity:<profile> — nobody asked for
	// this by pinning an account, so nothing may say they did (issue #40).
	// And since @sys's /usr bind is the ancestor that actually supplies the
	// file at this path (not an exact-guest-path match), the row must also carry
	// replaces:@sys — the disclosure that a profile's content was displaced.
	if !slices.Contains(m.From, "(snug)") {
		t.Errorf("From = %q, want it to contain \"(snug)\"", m.From)
	}
	for _, f := range m.From {
		if strings.HasPrefix(f, "identity:") {
			t.Errorf("From = %q carries an identity provenance; nothing about "+
				"these bytes names an account", m.From)
		}
	}
	if !slices.ContainsFunc(m.From, func(s string) bool { return strings.HasPrefix(s, "replaces:") }) {
		t.Errorf("From = %q does not disclose what it displaced (expected a replaces: entry "+
			"naming @sys, whose /usr bind is what would otherwise deliver the host's file)", m.From)
	}
}

// TestSystemSSHConfigIsProducedRegardlessOfSSHMode is the INVERSE of
// TestSystemSSHConfigIsNotProducedForSSHModeNone: ssh_mode stopped being part
// of the condition entirely, because the replacement fixes the CONFIG CHAIN
// (a root-owned file OpenSSH refuses to read), not the credential. An identity
// with ssh_mode = "none" still configures git; it grants no key and no agent
// socket; but the system ssh_config would be exactly as unreadable to a bare
// `ssh` invocation whether or not this identity — or any identity — is
// selected, so the replacement fires all the same.
func TestSystemSSHConfigIsProducedRegardlessOfSSHMode(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSHMode: SSHNone, GitName: "u", GitEmail: "u@example.com"},
	}
	p, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 1 {
		t.Fatalf("ssh_mode = none dropped the system ssh_config replacement (got %q); "+
			"the replacement fixes the config chain, not the credential, so it must not "+
			"depend on ssh_mode at all", got)
	}
}

// TestSystemSSHConfigNeedsACoveringBind is the discriminator the design calls
// for: same fake host (the file genuinely exists at the /usr spelling), but a
// selection with no @sys — nothing at all covers /usr/etc/ssh/ssh_config, so
// there is no bind for the ownership refusal to ever occur through, and
// nothing must be authored. This is what proves the predicate is COVERAGE, not
// "the host has the file" — TestSystemSSHConfigIsNotInventedWhereTheHostHasNone
// already covers the other half (host has no file, @sys selected).
func TestSystemSSHConfigNeedsACoveringBind(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	// Validate refuses a policy with no OS runtime at all (a mount at exactly
	// /usr or /bin) before this predicate is ever reached, so the selection
	// needs SOME runtime grant to be a legal policy — testRegistry's
	// "runtime-bin" deliberately does NOT cover /usr, or the test would stop
	// discriminating anything.
	p, err := Resolve(testRegistry(), []ProfileName{"@home", "@cwd-rw", "@parent-ro", "runtime-bin"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("replaced %q with no profile covering /usr at all — nothing granted "+
			"the host's file, so nothing needed fixing", got)
	}
}

// TestSystemSSHConfigFailsClosedOnATmpfsCoveringMount is the Kind fail-closed
// arm issue #40 requires: a tmpfs covering the path grants an
// EMPTY directory, the same verdict keepHostElement gives a tmpfs elsewhere in
// this package. No host file is visible through it, so there is no ownership
// refusal to fix and nothing may be authored — only KindBind may trigger the
// replacement.
func TestSystemSSHConfigFailsClosedOnATmpfsCoveringMount(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true

	reg := testRegistry()
	// A profile granting a writable tmpfs at /usr instead of a bind — the same
	// shape @home grants at {home}, aimed at the path this test needs covered.
	reg["tmpfs-usr"] = &Profile{Name: "tmpfs-usr", Tmpfs: []string{"/usr"}}

	p, err := Resolve(reg, []ProfileName{"@home", "@cwd-rw", "@parent-ro", "tmpfs-usr"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 0 {
		t.Fatalf("replaced %q under a tmpfs covering mount; a tmpfs has no host content "+
			"to have an ownership problem with", got)
	}
}

// sysSSHProbeEnv is the golden trap fix (issue #40): newFakeEnv()
// has no ssh path in dirs at all, so before this fixture existed EVERY
// existing golden was byte-identical across this whole change, and an
// implementer could have shipped it with zero golden diff — a security change
// with no reviewable line. This is what gives the review artifact something
// to show: a fake host whose /usr genuinely has a system-wide ssh_config,
// mirroring the openSUSE shape that motivated the issue.
func sysSSHProbeEnv() *fakeEnv {
	env := newFakeEnv()
	env.dirs["/usr/etc/ssh/ssh_config"] = true
	return env
}
