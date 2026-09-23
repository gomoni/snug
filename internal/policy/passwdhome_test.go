package policy

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// Issue #599: ssh inside the sandbox takes its per-user config from pw_dir, and
// snug authors the generated one under EvalSymlinks($HOME). Measured on
// 43ba42d with HOME pointed elsewhere: the 247-byte config was mounted, `ssh -G`
// reported `identitiesonly no` and `stricthostkeychecking ask`, exit 0.

func pinnedSelection() []ProfileName {
	return append(append([]ProfileName{}, testDefaults...), "pinned")
}

func TestSSHConfigSkewIsRefusedAndNamesHOMEAsTheFix(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/srv/pw"] = true
	ctx := testCtx()
	ctx.HostPasswdHome = "/srv/pw"

	p, err := Resolve(identityRegistry("/etc/key.pub"), pinnedSelection(), ctx, env)
	if err == nil {
		t.Fatal("a generated ~/.ssh/config ssh will never open resolved; every directive in it is lost with exit 0")
	}
	// (p, err), not (nil, err): --dry-run renders the refused policy.
	if p == nil {
		t.Error("the refusal returned no policy, so --dry-run cannot show what was refused")
	}
	for _, says := range []string{"/srv/pw/.ssh/config", "/home/u/.ssh/config", "HOME=/srv/pw"} {
		if !strings.Contains(err.Error(), says) {
			t.Errorf("refusal does not say %q: %v", says, err)
		}
	}
}

// The Silverblue/MicroOS shape: /home -> /var/home. p.Home is /var/home/u for
// every $HOME naming it, pw_dir stays /home/u, so "set HOME" is a circle and
// the message must offer the profile symlink instead — and that symlink must
// then actually resolve, or the message sends the user in a different circle.
func TestSSHConfigSkewThroughAHostSymlinkOffersTheProfileSymlinkAndItWorks(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u"] = "/var/home/u"
	env.dirs["/var/home/u"] = true
	env.dirs["/var/home/u/proj"] = true
	env.dirs["/var/home/u/proj/sub"] = true
	ctx := testCtx()
	ctx.Target = "/var/home/u/proj/sub"
	ctx.HostPasswdHome = "/home/u"

	reg := identityRegistry("/etc/key.pub")
	_, err := Resolve(reg, pinnedSelection(), ctx, env)
	if err == nil {
		t.Fatal("pw_dir /home/u with the config generated at /var/home/u/.ssh/config resolved")
	}
	if strings.Contains(err.Error(), "Run with HOME=") {
		t.Errorf("offered HOME as the fix where no value of HOME can work: %v", err)
	}
	if !strings.Contains(err.Error(), `symlink = [{ at = "/home/u", target = "/var/home/u" }]`) {
		t.Errorf("refusal does not spell the symlink entry that fixes it: %v", err)
	}

	// Follow the message's own advice.
	reg["pinned"].Symlink = []Symlink{{At: "/home/u", Target: "/var/home/u"}}
	if _, err := Resolve(reg, pinnedSelection(), ctx, env); err != nil {
		t.Fatalf("the symlink the refusal told the user to add did not satisfy it: %v", err)
	}
}

func TestSSHConfigWithNoPasswdEntryIsRefused(t *testing.T) {
	for _, pw := range []string{"", "relative/home"} {
		ctx := testCtx()
		ctx.HostPasswdHome = pw
		_, err := Resolve(identityRegistry("/etc/key.pub"), pinnedSelection(), ctx, newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), "passwd") {
			t.Errorf("HostPasswdHome %q with a generated ~/.ssh/config: err = %v, want a refusal naming passwd", pw, err)
		}
	}
}

// Gated on the generated file, not on the passwd lookup: no identity, nothing
// for ssh to miss, and a host with no passwd entry still runs.
func TestNoGeneratedSSHConfigMeansNoPasswdRefusal(t *testing.T) {
	ctx := testCtx()
	ctx.HostPasswdHome = ""
	if _, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv()); err != nil {
		t.Fatalf("an unpinned run was refused over the passwd home: %v", err)
	}
	reg := identityRegistry("/etc/key.pub")
	reg["pinned"].Identity.SSH = IdentitySSH{Agent: SSHNone}
	reg["pinned"].Identity.Git = IdentityGit{Name: "Some One", Email: "one@example.com"}
	if _, err := Resolve(reg, pinnedSelection(), ctx, newFakeEnv()); err != nil {
		t.Fatalf("an identity with ssh.agent = none generates no ssh config, yet was refused: %v", err)
	}
}

// The chain systemSSHConfigCandidates filters came from the host's ssh, which
// found the user's own config from pw_dir. Filtering on Home alone let that
// file through as a "system" config whenever the two differ.
func TestSystemSSHConfigCandidatesDropThePasswdHomesOwnFile(t *testing.T) {
	ctx := testCtx()
	ctx.HostPasswdHome = "/srv/pw"
	own := "/srv/pw/etc/ssh/ssh_config"
	ctx.HostSSHConfigs = []string{own, "/usr/local/etc/ssh/ssh_config"}
	got := systemSSHConfigCandidates(ctx)
	if slices.Contains(got, own) {
		t.Errorf("a file under pw_dir became a system ssh_config candidate: %q", got)
	}
	if !slices.Contains(got, "/usr/local/etc/ssh/ssh_config") {
		t.Errorf("control path dropped too, so this proves nothing: %q", got)
	}
}

// Red-team finding against the first version of this check, measured with a
// real run: each shape below was ACCEPTED, and ssh inside printed
// `identitiesonly no` / `stricthostkeychecking ask`, exit 0 — #599's silent
// loss with snug's own check approving it. (a) coveringMount lets the generated
// FILE cover want/config, which the kernel answers ENOTDIR; (b)/(c) a lexically
// collapsed `..` the kernel resolves after a file or a missing name.
func TestSSHConfigSkewIsNotSatisfiedByALexicalLanding(t *testing.T) {
	cases := []struct{ name, at, target string }{
		{"a file covering its own descendant", "/home/pw/.ssh", "/home/u/.ssh/config"},
		{"dotdot after a file", "/home/pw", "/home/u/.ssh/config/../.."},
		{"dotdot after a missing name", "/home/pw", "/nonexistent/../home/u"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			ctx.HostPasswdHome = "/home/pw"
			reg := identityRegistry("/etc/key.pub")
			reg["pinned"].Symlink = []Symlink{{At: tc.at, Target: tc.target}}
			_, err := Resolve(reg, pinnedSelection(), ctx, newFakeEnv())
			if err == nil {
				t.Fatalf("symlink %s -> %s satisfied the check; the kernel does not reach "+
					"the generated config through it", tc.at, tc.target)
			}
		})
	}
}

// TestUnreadSSHConfigHostLinkFailsClosed is issue #604's fix applied to #599's
// own check: refuseUnreadSSHConfig's walk now follows a HOST symlink under a
// covering bind the same way IsShadowSlot does, so pw_dir can be reached
// through one and still satisfy the check — and a host read that fails on
// the way must still refuse, exactly as every other unresolved chain does.
func TestUnreadSSHConfigHostLinkFailsClosed(t *testing.T) {
	reg := identityRegistry("/etc/key.pub")
	reg["hostlink"] = &Profile{Name: "hostlink", RO: []string{"/mnt/otherhome"}}
	sel := append(append([]ProfileName{}, pinnedSelection()...), "hostlink")

	t.Run("accepted", func(t *testing.T) {
		env := newFakeEnv()
		env.dirs["/mnt/otherhome"] = true
		// The host symlink nobody in the profile wrote, redirecting pw_dir's
		// own .ssh directory onto the one snug actually generated the config
		// under ({home}/.ssh, from ctx.Home in testCtx()).
		env.links["/mnt/otherhome/.ssh"] = "/home/u/.ssh"
		ctx := testCtx()
		ctx.HostPasswdHome = "/mnt/otherhome"

		if _, err := Resolve(reg, sel, ctx, env); err != nil {
			t.Fatalf("a host symlink that truly leads pw_dir to the generated ~/.ssh/config "+
				"was refused: %v", err)
		}
	})

	t.Run("EACCES on the way refused", func(t *testing.T) {
		env := newFakeEnv()
		env.dirs["/mnt/otherhome"] = true
		env.statErrs["/mnt/otherhome/.ssh"] = &fs.PathError{
			Op: "lstat", Path: "/mnt/otherhome/.ssh", Err: fs.ErrPermission,
		}
		ctx := testCtx()
		ctx.HostPasswdHome = "/mnt/otherhome"

		if _, err := Resolve(reg, sel, ctx, env); err == nil {
			t.Fatal("a host read that failed on the way to pw_dir's ssh config was accepted; " +
				"snug cannot vouch for content it never actually read")
		}
	})
}

// The same lexical `..` lost the shadow-slot mark on PATH (red-team finding 2,
// live: the payload's git ran from /pbin). Refused at the fold, so no walk can
// disagree with the kernel about it.
func TestASymlinkTargetWithADotDotComponentIsRefused(t *testing.T) {
	for _, target := range []string{"/lnk/../../opt", "../usr/bin", "/usr//bin", "usr/bin/"} {
		reg := testRegistry()
		reg["dd"] = &Profile{Name: "dd", Symlink: []Symlink{{At: "/pbin", Target: target}}}
		_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "dd"), testCtx(), newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), "symlink target") {
			t.Errorf("symlink target %q: err = %v, want a refusal", target, err)
		}
	}
	// Control: the shipped usr-merge shape still resolves.
	reg := testRegistry()
	reg["dd"] = &Profile{Name: "dd", Symlink: []Symlink{{At: "/pbin", Target: "usr/bin"}}}
	if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "dd"), testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("a clean relative target was refused: %v", err)
	}
}
