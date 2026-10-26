package policy

import (
	"bytes"
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
	env.files["/usr/etc/ssh/ssh_config"] = true

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
	// replaces a file this host's ssh actually reads; under a bind it does not
	// author config at a path that does not exist, because that is a grant
	// nobody asked for and it would make the two spellings differ from the
	// host's reality.
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
// sandbox on such a host, which is issue #40. The replacement rides on the
// host's ssh binary and file being inside, computed in
// replaceSystemSSHConfig, not on p.Identity.
func TestNoIdentityStillReplacesTheSystemSSHConfigWhereTheHostHasOne(t *testing.T) {
	env := newFakeEnv()
	env.files["/usr/etc/ssh/ssh_config"] = true

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
// TestSystemSSHConfigIsNotProducedForSSHModeNone: the agent mode is not part
// of the condition entirely, because the replacement fixes the CONFIG CHAIN
// (a root-owned file OpenSSH refuses to read), not the credential. An identity
// with identity.ssh.agent = "none" still configures git; it grants no key and no agent
// socket; but the system ssh_config would be exactly as unreadable to a bare
// `ssh` invocation whether or not this identity — or any identity — is
// selected, so the replacement fires all the same.
func TestSystemSSHConfigIsProducedRegardlessOfSSHMode(t *testing.T) {
	env := newFakeEnv()
	env.files["/usr/etc/ssh/ssh_config"] = true

	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSH: IdentitySSH{Agent: SSHNone}, Git: IdentityGit{Name: "u", Email: "u@example.com"}},
	}
	p, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := systemSSHConfigMounts(p); len(got) != 1 {
		t.Fatalf("identity.ssh.agent = none dropped the system ssh_config replacement (got %q); "+
			"the replacement fixes the config chain, not the credential, so it must not "+
			"depend on the agent mode at all", got)
	}
}

// TestSystemSSHConfigNeedsACoveringBind holds the predicate for a path no
// grant supplies: the host's ssh BINARY must be inside, through a bind
// supplying its host path. Same fake host throughout (the host's ssh names
// /etc/ssh/ssh_config, on the root tmpfs under sys-usr), so the only thing
// varying is where the host's ssh is.
func TestSystemSSHConfigNeedsACoveringBind(t *testing.T) {
	for _, tc := range []struct {
		name, bin string
		want      bool
	}{
		{"the host has no ssh", "", false},
		{"the host's ssh is outside every grant", "/nix/store/x-openssh/bin/ssh", false},
		// POSITIVE CONTROL: without it every case above would also pass on a
		// replaceSystemSSHConfig that authors nothing at all.
		{"the host's ssh is inside the /usr bind", "/usr/bin/ssh", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			ctx.HostSSHConfigs = []string{"/etc/ssh/ssh_config"}
			ctx.HostSSHTopConfig = "/etc/ssh/ssh_config"
			ctx.HostSSHBinary = tc.bin
			ctx.HostSSHRevoked = []byte{}
			p, err := Resolve(testRegistry(), []ProfileName{"sys-usr", "@target-rw"}, ctx, newFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			got := systemSSHConfigMounts(p)
			if tc.want != (len(got) == 1) {
				t.Fatalf("HostSSHBinary = %q: system ssh_config mounts = %q, want authored = %v",
					tc.bin, got, tc.want)
			}
			if _, krl := p.Mounts[SystemRevokedHostKeysGuest]; krl != tc.want || p.SystemSSHRevoked != tc.want {
				t.Errorf("HostSSHBinary = %q: KRL staged = %v, recorded = %v, want %v — the KRL "+
					"rides on an authored system file", tc.bin, krl, p.SystemSSHRevoked, tc.want)
			}
		})
	}
}

// TestSystemSSHConfigFailsClosedOnATmpfsCoveringMount: where no grant
// supplies the file (a tmpfs over /etc, or nothing at all, the root tmpfs),
// snug authors only a path the host's ssh NAMED. A floor-only
// SystemSSHConfigPaths entry there is a file nothing reads.
func TestSystemSSHConfigFailsClosedOnATmpfsCoveringMount(t *testing.T) {
	reg := testRegistry()
	reg["tmpfs-etc"] = &Profile{Name: "tmpfs-etc", Tmpfs: []string{"/etc"}}
	for _, sel := range [][]ProfileName{
		{"sys-usr", "@target-rw", "tmpfs-etc"},
		{"sys-usr", "@target-rw"},
	} {
		for _, discovered := range []bool{false, true} {
			env := newFakeEnv()
			env.files["/etc/ssh/ssh_config"] = true
			ctx := testCtx()
			if discovered {
				ctx.HostSSHConfigs = []string{"/etc/ssh/ssh_config"}
				ctx.HostSSHTopConfig = "/etc/ssh/ssh_config"
			}
			p, err := Resolve(reg, sel, ctx, env)
			if err != nil {
				t.Fatal(err)
			}
			_, got := p.Mounts["/etc/ssh/ssh_config"]
			if got != discovered {
				t.Errorf("%v, discovered = %v: authored /etc/ssh/ssh_config = %v, want %v",
					sel, discovered, got, discovered)
			}
			if got && slices.ContainsFunc(p.Mounts["/etc/ssh/ssh_config"].From,
				func(f string) bool { return strings.HasPrefix(f, "replaces:") }) {
				t.Errorf("%v: From = %q; nothing was displaced", sel, p.Mounts["/etc/ssh/ssh_config"].From)
			}
		}
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
	env.files["/usr/etc/ssh/ssh_config"] = true
	return env
}

// TestDiscoveredSystemSSHConfigPathIsReplaced is issue #42's whole point: a
// host that spells the system-wide ssh_config a third way — FreeBSD's and
// Homebrew's /usr/local/etc/ssh, a /nix/store path — is not in
// SystemSSHConfigPaths and never will be, because a list of platform
// spellings is a rule written somewhere it can be forgotten. What the run has
// instead is the answer this host's own ssh gave when asked which files it
// reads (Context.HostSSHConfigs).
//
// Without this the failure is not just "unfixed", it is SILENT: ssh inside
// dies with `Bad owner or permissions` naming a root-owned file the human
// never wrote, and the SSH block on --dry-run says nothing, because it only
// speaks for a path that was actually replaced.
func TestDiscoveredSystemSSHConfigPathIsReplaced(t *testing.T) {
	env := newFakeEnv()
	// The FreeBSD/Homebrew spelling, and NOT either fixed one — so a run that
	// still consults only the fixed list authors nothing at all here.
	env.files["/usr/local/etc/ssh/ssh_config"] = true

	ctx := testCtx()
	ctx.HostSSHConfigs = []string{"/usr/local/etc/ssh/ssh_config"}

	p, err := Resolve(testRegistry(), testDefaults, ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/usr/local/etc/ssh/ssh_config"]
	if !ok {
		t.Fatalf("the path this host's ssh actually reads was not replaced; on such a host "+
			"ssh, git-over-ssh, scp and rsync -e ssh all die inside the sandbox with "+
			"`Bad owner or permissions` and nothing on screen explains it (mounts: %q)",
			sortedGuests(p.Mounts))
	}
	if m.Kind != KindData || !m.Authored {
		t.Errorf("mount at the discovered path is %v/authored=%v, want an authored data mount",
			m.Kind, m.Authored)
	}
	if !slices.Contains(p.SystemSSHConfigs, "/usr/local/etc/ssh/ssh_config") {
		t.Errorf("p.SystemSSHConfigs = %q does not record the discovered path; --dry-run's "+
			"SSH block reads that field, so the replacement would happen with nothing on screen",
			p.SystemSSHConfigs)
	}
}

// TestDiscoveredSSHConfigPathsAreFiltered is the half that matters for the
// threat model: the strings in HostSSHConfigs come out of `ssh -G -v`, which
// names every file in the chain — the user's own ~/.ssh/config, every file an
// Include pulls in, and therefore any path a line like
// `Include /tmp/whatever.conf` puts there. Each one would otherwise author a
// mount.
//
// It asserts against systemSSHConfigCandidates rather than against a resolved
// Policy, and that is a correction rather than a shortcut: a resolve-level
// version of this test passed with the HOME filter deleted, because @home
// covers $HOME with a TMPFS and the coverage condition already refuses to
// replace anything a tmpfs covers. The path never became a mount, so the
// assertion held while the filter it names was gone. Here the filter is the
// only thing under test.
//
// Every case is a real shape from the chain measured on this host, except the
// last three, which are path hygiene.
func TestDiscoveredSSHConfigPathsAreFiltered(t *testing.T) {
	cases := []struct {
		name string
		path string
		why  string
	}{
		{"the user's own config", "/home/u/.ssh/config",
			"~/.ssh/config is the human's own file; snug authors that one only when an identity is pinned"},
		{"a home path spelled like a system one", "/home/u/etc/ssh/ssh_config",
			"the basename rule passes this one, so the home filter is the only thing that stops it"},
		{"an Include'd fragment", "/usr/etc/ssh/ssh_config.d/50-suse.conf",
			"the replacement carries no Include line, so nothing under the top-level file is ever read"},
		{"a crypto-policy fragment", "/etc/crypto-policies/back-ends/openssh.config",
			"same: an included file, and not named ssh_config"},
		{"an arbitrary Include target", "/tmp/anything/ssh_config.conf",
			"a host config line must not choose where snug authors bytes"},
		{"a relative path", "usr/etc/ssh/ssh_config", "not absolute"},
		{"an unclean path", "/usr/etc/ssh/../ssh/ssh_config", "not clean"},
		{"a path carrying a newline", "/usr/etc/ssh\n/ssh_config", "control characters author lies and mounts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			ctx.HostSSHConfigs = []string{tc.path}
			if got := systemSSHConfigCandidates(ctx); slices.Contains(got, tc.path) {
				t.Fatalf("%q became a candidate for replacement: %s", tc.path, tc.why)
			}
			// POSITIVE CONTROL, per case rather than once: without it every
			// assertion above would also pass on a candidate list that dropped
			// EVERYTHING discovered, which is the failure this whole change
			// exists to fix.
			ctx.HostSSHConfigs = []string{tc.path, "/usr/local/etc/ssh/ssh_config"}
			if got := systemSSHConfigCandidates(ctx); !slices.Contains(got, "/usr/local/etc/ssh/ssh_config") {
				t.Fatalf("candidates = %q: the control path was dropped too, so this case "+
					"proves nothing about the filter it names", got)
			}
		})
	}
}

// TestADiscoveredPathInsideTheTargetIsRefused needs a target OUTSIDE $HOME to
// mean anything, which is why it is not a row in the table above: testCtx's
// target is /home/u/proj/sub, so the home filter refuses it there whether the
// target filter exists or not — measured by deleting the target filter and
// watching the table stay green.
//
// The shape it closes: the chain is host text, but a human's own
// `Include <some repo>/ssh_config` puts a path from the SANDBOXED TREE into
// it, and a KindData mount is assigned straight into p.Mounts (rejectMasking
// exempts KindData by kind), so snug would displace the repository's own file
// with a read-only file of its own, inside the one tree the run exists to let
// the payload write.
func TestADiscoveredPathInsideTheTargetIsRefused(t *testing.T) {
	ctx := testCtx()
	ctx.Target = "/srv/work"
	ctx.HostSSHConfigs = []string{"/srv/work/ssh_config", "/usr/local/etc/ssh/ssh_config"}

	got := systemSSHConfigCandidates(ctx)
	if slices.Contains(got, "/srv/work/ssh_config") {
		t.Errorf("a path inside the target became a candidate: %q", got)
	}
	// POSITIVE CONTROL: a discovered path outside it still gets through, so
	// this cannot pass on a filter that refuses everything.
	if !slices.Contains(got, "/usr/local/etc/ssh/ssh_config") {
		t.Errorf("candidates = %q: the control path was dropped too", got)
	}
}

// TestSystemSSHConfigCandidatesDeduplicates tests the candidate list DIRECTLY
// rather than through Resolve, and the reason is a mutation check: deleting
// the dedup and running the resolve-level test left it passing. Replace's own
// coverage condition makes a repeated candidate a no-op — the second time
// round, the covering mount at that guest path is the KindData file snug just
// authored, not a bind — so a resolve-level assertion cannot tell a working
// dedup from a missing one, and a test that cannot fail is worse than no test.
//
// The shapes are both measured: `ssh -G -v` prints the whole chain TWICE per
// invocation (it parses again after resolving the host name), and a discovered
// path may equally be one the fixed list already names.
func TestSystemSSHConfigCandidatesDeduplicates(t *testing.T) {
	ctx := testCtx()
	ctx.HostSSHConfigs = []string{
		"/usr/local/etc/ssh/ssh_config", "/usr/etc/ssh/ssh_config",
		"/usr/local/etc/ssh/ssh_config", "/usr/etc/ssh/ssh_config",
	}
	got := systemSSHConfigCandidates(ctx)
	want := append(slices.Clone(SystemSSHConfigPaths), "/usr/local/etc/ssh/ssh_config")
	if !slices.Equal(got, want) {
		t.Fatalf("systemSSHConfigCandidates = %q, want %q — the fixed floor in order, then\n"+
			"each discovered path once", got, want)
	}
}

// systemSSHEtcCtx is a host whose ssh reads /etc/ssh/ssh_config, a path no
// test profile grants, and names a global RevokedHostKeys file.
func systemSSHEtcCtx() Context {
	ctx := testCtx()
	ctx.HostSSHConfigs = []string{"/etc/ssh/ssh_config"}
	ctx.HostSSHTopConfig = "/etc/ssh/ssh_config"
	ctx.HostSSHRevoked = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIg==\n")
	return ctx
}

// TestSystemSSHConfigIsNotAuthoredForAnotherBinaryAtTheSSHPath would catch the
// "is the host's ssh inside" question being asked of the binary's GUEST path,
// i.e. of whatever is mounted where the host keeps ssh. A bind of /srv/other
// at /srv/bin puts /srv/other/ssh where the host's /srv/bin/ssh would be, and
// no bind supplies /srv/bin/ssh itself, so the ssh inside is not the binary
// whose `ssh -G` produced the carried values, and nothing may be written on
// its behalf at a path no grant supplies.
func TestSystemSSHConfigIsNotAuthoredForAnotherBinaryAtTheSSHPath(t *testing.T) {
	for _, tc := range []struct {
		name, ro string
		want     bool
	}{
		{"another host directory bound at the ssh's path", "/srv/other:/srv/bin", false},
		// POSITIVE CONTROL: the same selection with the ssh's own directory
		// at its own path authors the file, so the case above fails on the
		// host-path half and not on something else in the fixture.
		{"the ssh's own directory bound at its own path", "/srv/bin", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv()
			env.dirs["/srv/other"] = true
			reg := testRegistry()
			reg["sshdir"] = &Profile{Name: "sshdir", RO: []string{tc.ro}}
			// A path no grant supplies, so the binary is the whole trigger.
			ctx := systemSSHEtcCtx()
			ctx.HostSSHBinary = "/srv/bin/ssh"
			ctx.HostSSHRevoked = []byte("revoked\n")
			p, err := Resolve(reg, []ProfileName{"sys-usr", "@target-rw", "sshdir"}, ctx, env)
			if err != nil {
				t.Fatal(err)
			}
			got := systemSSHConfigMounts(p)
			if tc.want != (len(got) == 1) {
				t.Fatalf("ro = %q, HostSSHBinary = %q: system ssh_config mounts = %q, want authored = %v",
					tc.ro, ctx.HostSSHBinary, got, tc.want)
			}
			if _, krl := p.Mounts[SystemRevokedHostKeysGuest]; krl != tc.want {
				t.Errorf("ro = %q: KRL staged = %v, want %v", tc.ro, krl, tc.want)
			}
		})
	}
}

// systemSSHConfigContents is every authored system-wide ssh_config's bytes.
func systemSSHConfigContents(p *Policy) map[string]string {
	out := map[string]string{}
	for _, g := range p.SystemSSHConfigs {
		out[g] = string(p.Mounts[g].Content)
	}
	return out
}

// TestSystemRevokedHostKeysIsNotStagedWithoutAConfig would catch the KRL
// being staged on a run that authored no system ssh_config: the binary is
// inside and the host names a KRL, but no candidate path has a file to
// replace. A staged file nothing names is a mount nobody asked for, and
// p.SystemSSHRevoked would make --dry-run claim a revocation list is in force.
func TestSystemRevokedHostKeysIsNotStagedWithoutAConfig(t *testing.T) {
	for _, hostHasFile := range []bool{false, true} {
		env := newFakeEnv()
		if hostHasFile {
			env.files["/usr/etc/ssh/ssh_config"] = true
		}
		ctx := testCtx()
		ctx.HostSSHRevoked = []byte("revoked\n")
		p, err := Resolve(testRegistry(), testDefaults, ctx, env)
		if err != nil {
			t.Fatal(err)
		}
		_, staged := p.Mounts[SystemRevokedHostKeysGuest]
		// hostHasFile = true is the POSITIVE CONTROL: the same context stages
		// the KRL once a config is written, so the false case is not passing
		// on a fixture that never stages anything.
		if staged != hostHasFile || p.SystemSSHRevoked != hostHasFile {
			t.Errorf("host has /usr/etc/ssh/ssh_config = %v: KRL staged = %v, recorded = %v, want %v",
				hostHasFile, staged, p.SystemSSHRevoked, hostHasFile)
		}
		if hostHasFile {
			continue
		}
		for _, m := range p.Mounts {
			if strings.Contains(string(m.Content), SystemRevokedHostKeysGuest) {
				t.Errorf("%s names %s with no KRL staged", m.Guest, SystemRevokedHostKeysGuest)
			}
		}
	}
}

// TestSystemRevokedHostKeysStagesTheHostsBytes would catch three ways the
// staged KRL can differ from the host's: content rewritten, an empty file
// treated as "none" (an empty KRL is still a file the host's ssh opens, and
// the line naming it must survive), and nil treated as an empty file (a host
// naming no KRL getting a RevokedHostKeys line). It also holds that every
// authored config names the KRL exactly when one is staged.
func TestSystemRevokedHostKeysStagesTheHostsBytes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revoked []byte
	}{
		{"nil: the host names none", nil},
		{"empty: the host names an empty file", []byte{}},
		{"content", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIg==\n@not-a-key \x00\xff\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			ctx.HostSSHRevoked = tc.revoked
			p, err := Resolve(testRegistry(), testDefaults, ctx, sysSSHProbeEnv())
			if err != nil {
				t.Fatal(err)
			}
			configs := systemSSHConfigContents(p)
			if len(configs) == 0 {
				t.Fatal("no system ssh_config was authored, so nothing below is measured")
			}
			m, staged := p.Mounts[SystemRevokedHostKeysGuest]
			if want := tc.revoked != nil; staged != want || p.SystemSSHRevoked != want {
				t.Fatalf("KRL staged = %v, recorded = %v, want %v", staged, p.SystemSSHRevoked, want)
			}
			if staged {
				if m.Kind != KindData || m.Access != AccessRO || !m.Authored {
					t.Errorf("staged KRL is %v/%v/authored=%v, want an authored read-only data mount",
						m.Kind, m.Access, m.Authored)
				}
				if !bytes.Equal(m.Content, tc.revoked) {
					t.Errorf("staged KRL = %q, want the host's bytes %q", m.Content, tc.revoked)
				}
			}
			line := "\nRevokedHostKeys " + SystemRevokedHostKeysGuest + "\n"
			for g, c := range configs {
				if strings.Contains(c, line) != staged {
					t.Errorf("%s names the KRL = %v, KRL staged = %v:\n%s",
						g, strings.Contains(c, line), staged, c)
				}
			}
		})
	}
}

// TestSystemSSHConfigDisclosesTheHostBlocksItDoesNotCarry would catch the
// generated file dropping its statement that per-host Host and Match blocks
// are not carried. That residual is what a reader of the file inside the
// sandbox needs to explain why a host they configured narrowly negotiates
// with the global values instead. It holds the sentence only, as a comment:
// whether blocks are in fact not carried is TestUnpinnedHostBlockIsNotCarried
// in test/integration.
func TestSystemSSHConfigDisclosesTheHostBlocksItDoesNotCarry(t *testing.T) {
	const want = "# Host or Match pattern matches. Host blocks for other names are not\n" +
		"# carried, except a pinned host's, in ~/.ssh/config. A block with a\n" +
		"# negated pattern (Host * !x, Match !host x) matches that name, so\n" +
		"# here it applies to x too.\n"
	for _, revoked := range []bool{false, true} {
		if got := string(SystemSSHConfigFrom(sshValuesFixture(), revoked)); !strings.Contains(got, want) {
			t.Errorf("revoked = %v: the generated file lacks the Host/Match disclosure:\n%s", revoked, got)
		}
	}
}

// TestSystemSSHConfigIsWrittenForTheHostsSSHBoundElsewhere is the redteam's
// F2: the host's /usr/bin bound at /opt/sbin puts the host's own ssh inside,
// at another guest path, and a predicate that also required the guest path to
// match the host path left the sandbox's ssh reading no system file on a
// Debian-shaped host, where /etc/ssh is on the root tmpfs: compiled-in
// defaults, weaker than the host's. It would catch "inside" narrowing back to
// "inside at its own path".
func TestSystemSSHConfigIsWrittenForTheHostsSSHBoundElsewhere(t *testing.T) {
	for _, tc := range []struct {
		name string
		sel  []ProfileName
		want bool
	}{
		{"the host's /usr/bin bound at /opt/sbin", []ProfileName{"runtime-bin", "@target-rw", "sbin"}, true},
		// CONTROL: the same host without that bind has its ssh nowhere
		// inside (runtime-bin binds /opt, not /usr/bin), and nothing is
		// written, so the case above is decided by the bind.
		{"no bind supplies the host's ssh", []ProfileName{"runtime-bin", "@target-rw"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := testRegistry()
			reg["sbin"] = &Profile{Name: "sbin", RO: []string{"/usr/bin:/opt/sbin"}}
			ctx := systemSSHEtcCtx()
			ctx.HostSSHBinary = "/usr/bin/ssh"
			p, err := Resolve(reg, tc.sel, ctx, newFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			if p.HostSSHBinaryInside != tc.want {
				t.Errorf("HostSSHBinaryInside = %v, want %v", p.HostSSHBinaryInside, tc.want)
			}
			if _, got := p.Mounts["/etc/ssh/ssh_config"]; got != tc.want {
				t.Errorf("authored /etc/ssh/ssh_config = %v, want %v (mounts %q)", got, tc.want, sortedGuests(p.Mounts))
			}
		})
	}
}

// TestSystemSSHConfigReplacesABoundHostFileWhateverTheBinary is the
// redteam's F3, and the shape this suite's own ssh wrapper hit: the ssh on
// the host's PATH is a wrapper no grant supplies, while @sys's /usr bind
// supplies the host's root-owned /usr/etc/ssh/ssh_config. That file is inside
// whatever the binary does, it reads as 65534, and the /usr/bin/ssh inside
// dies on it ("Bad owner or permissions"). It would catch the bind branch
// being gated on the binary again.
func TestSystemSSHConfigReplacesABoundHostFileWhateverTheBinary(t *testing.T) {
	ctx := testCtx()
	ctx.HostSSHBinary = "/home/u/bin/ssh"
	p, err := Resolve(testRegistry(), testDefaults, ctx, sysSSHProbeEnv())
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is the shape it claims: the binary is not inside.
	if p.HostSSHBinaryInside {
		t.Fatalf("control: %s counts as inside, so this measures nothing about the bind branch", ctx.HostSSHBinary)
	}
	m, ok := p.Mounts["/usr/etc/ssh/ssh_config"]
	if !ok || m.Kind != KindData || !m.Authored {
		t.Fatalf("the bound host file was not replaced (mounts %q); /usr/bin/ssh inside dies on it",
			sortedGuests(p.Mounts))
	}
	if !slices.ContainsFunc(m.From, func(f string) bool { return strings.HasPrefix(f, "replaces:") }) {
		t.Errorf("From = %q: the replacement does not name the bind it displaced", m.From)
	}
}

// SandboxBinary finds the sandbox's ssh the way its PATH will: through @sys's
// /bin symlink, a profile path entry first, and only an executable file.
func TestSandboxBinaryFollowsTheSandboxPATH(t *testing.T) {
	env := newFakeEnv()
	env.execs["/usr/bin/ssh"] = true
	env.execs["/opt/tools/bin/ssh"] = true
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if g, h := p.SandboxBinary(env, "ssh"); g != "/usr/bin/ssh" || h != "/usr/bin/ssh" {
		t.Errorf("default selection: SandboxBinary = %q, %q; want /usr/bin/ssh twice", g, h)
	}
	if p.SandboxSSHGuest != "/usr/bin/ssh" || p.SandboxSSHHost != "/usr/bin/ssh" {
		t.Errorf("Resolve recorded %q, %q", p.SandboxSSHGuest, p.SandboxSSHHost)
	}
	// envy puts /opt/tools/bin on PATH ahead of the base.
	p, err = Resolve(testRegistry(), append(append([]ProfileName{}, testDefaults...), "envy"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if g, h := p.SandboxBinary(env, "ssh"); g != "/opt/tools/bin/ssh" || h != "/opt/tools/bin/ssh" {
		t.Errorf("with a profile path entry: SandboxBinary = %q, %q; want /opt/tools/bin/ssh", g, h)
	}
	// Not executable: a plain file is not what PATH runs.
	env = newFakeEnv()
	env.files["/usr/bin/ssh"] = true
	p, err = Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if g, h := p.SandboxBinary(env, "ssh"); g != "" || h != "" {
		t.Errorf("non-executable file: SandboxBinary = %q, %q; want none", g, h)
	}
}

// TestAnIncludedSSHConfigGetsNoNodeOnATmpfs is the redteam's F6. The chain
// `ssh -G -v` prints names every file read, Include'd ones among them, and a
// file Include'd from the top-level one may also be named ssh_config. Where
// no grant supplies it, a written copy is a node nothing reads: the generated
// top-level file has no Include line. It would catch the tmpfs arm writing
// every discovered path again instead of the top-level one alone.
func TestAnIncludedSSHConfigGetsNoNodeOnATmpfs(t *testing.T) {
	const top, inc = "/etc/ssh/ssh_config", "/etc/ssh/inc/ssh_config"
	for _, tc := range []struct {
		name          string
		topConfig     string
		wantTop, want bool
	}{
		{"the top-level file is the system one", top, true, false},
		// CONTROL: the same chain with the other file as top-level writes
		// that one, so the case above is decided by HostSSHTopConfig and not
		// by the second path being refused for some other reason.
		{"the top-level file is the other one", inc, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			ctx.HostSSHConfigs = []string{top, inc}
			ctx.HostSSHTopConfig = tc.topConfig
			p, err := Resolve(testRegistry(), []ProfileName{"sys-usr", "@target-rw"}, ctx, newFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			_, gotTop := p.Mounts[top]
			_, gotInc := p.Mounts[inc]
			if gotTop != tc.wantTop || gotInc != tc.want {
				t.Errorf("written: %s = %v, %s = %v; want %v, %v", top, gotTop, inc, gotInc, tc.wantTop, tc.want)
			}
		})
	}
}

// TestAProfileMountAtTheStagedRevokedHostKeysRefuses is the redteam's F8. A
// profile bind at /snug/revoked_host_keys was refused only on a run where
// snug staged nothing there; where the host named a KRL, snug's copy
// displaced the bind first and the refusal never saw it, so the verdict on a
// profile depended on the host's ssh configuration. It would catch that again
// for a read-only or writable bind, with or without a host KRL. The staged
// case must also say what the path is for.
func TestAProfileMountAtTheStagedRevokedHostKeysRefuses(t *testing.T) {
	for _, access := range []string{"ro", "rw"} {
		for _, staged := range []bool{false, true} {
			env := sysSSHProbeEnv()
			env.files["/srv/krl"] = true
			ctx := testCtx()
			if staged {
				ctx.HostSSHRevoked = []byte("revoked\n")
			}
			// POSITIVE CONTROL: without the bind this context stages the KRL
			// exactly when staged says so.
			p, err := Resolve(testRegistry(), testDefaults, ctx, env)
			if err != nil {
				t.Fatal(err)
			}
			if p.SystemSSHRevoked != staged {
				t.Fatalf("control: KRL staged = %v, want %v", p.SystemSSHRevoked, staged)
			}

			reg := testRegistry()
			bind := &Profile{Name: "intruder"}
			if access == "ro" {
				bind.RO = []string{"/srv/krl:" + SystemRevokedHostKeysGuest}
			} else {
				bind.RW = []string{"/srv/krl:" + SystemRevokedHostKeysGuest}
			}
			reg["intruder"] = bind
			_, err = Resolve(reg, append(append([]ProfileName{}, testDefaults...), "intruder"), ctx, env)
			if err == nil {
				t.Errorf("%s bind, host KRL = %v: a profile mount at %s was ACCEPTED",
					access, staged, SystemRevokedHostKeysGuest)
				continue
			}
			if !strings.Contains(err.Error(), SystemRevokedHostKeysGuest) ||
				!strings.Contains(err.Error(), "snug stages this host's RevokedHostKeys file here") {
				t.Errorf("%s bind, host KRL = %v: refusal does not name the path and what it is for: %v",
					access, staged, err)
			}
		}
	}
}
