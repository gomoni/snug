package policy

import (
	"errors"
	"io/fs"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// The ownership rule: a grant may follow a host symlink only if no sandbox
// could have written the link, which is to say it is owned by uid 0 and snug is
// not uid 0. These tests drive Resolve over an injected Environ whose links
// carry an owner (fakeEnv.linkOwners; the default 0 is the host's own
// configuration). A user-owned link is the stand-in for one a previous sandbox
// run planted: a sandbox can only create links owned by the invoking uid or a
// subuid.

const (
	hlUser   = uint32(1000)
	hlSubuid = uint32(100999)
)

// hlEnv is a fixture host with the directories the tests below grant, and no
// links yet.
func hlEnv() *fakeEnv {
	env := newFakeEnv()
	for _, d := range []string{"/s/cache", "/s/secret", "/s/old", "/s/d", "/s/cover",
		"/s/cover/inner", "/s/cache/real", "/secret"} {
		env.dirs[d] = true
	}
	return env
}

// hlLink plants a symlink with the given owner.
func (f *fakeEnv) hlLink(owner uint32, at, text string) {
	f.links[at] = text
	f.linkOwners[at] = owner
}

func hlRegistry(ps ...*Profile) map[ProfileName]*Profile {
	reg := testRegistry()
	for _, p := range ps {
		reg[p.Name] = p
	}
	return reg
}

func hlResolve(reg map[ProfileName]*Profile, env Environ, names ...ProfileName) (*Policy, error) {
	return Resolve(reg, append(slices.Clone(testDefaults), names...), testCtx(), env)
}

func hlWantRefusal(t *testing.T, err error, subs ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("resolved; the grant followed a link a sandbox could have planted")
	}
	for _, s := range subs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("refusal %q does not contain %q", err, s)
		}
	}
}

func hlMustResolve(t *testing.T, reg map[ProfileName]*Profile, env Environ, names ...ProfileName) *Policy {
	t.Helper()
	p, err := hlResolve(reg, env, names...)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	return p
}

func hlHost(t *testing.T, p *Policy, guest string) string {
	t.Helper()
	m, ok := p.Mounts[guest]
	if !ok {
		t.Fatalf("no mount at %s", guest)
	}
	return m.Host
}

func TestAuthorableLinksCatchesEveryHop(t *testing.T) {
	env := newFakeEnv()
	env.links["/opt/x"] = "/home/u/y"
	env.links["/home/u/y"] = "/"
	env.linkOwners["/home/u/y"] = 1000
	resolved, links, err := authorableLinks(env, 1000, "/opt/x/etc")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "/etc" {
		t.Errorf("resolved = %q, want /etc", resolved)
	}
	if len(links) != 1 || links[0].At != "/home/u/y" || links[0].Owner != 1000 {
		t.Errorf("links = %+v, want only the user-owned second hop", links)
	}
}

// TestRootOwnedLinkInADirectoryOthersCanWriteIsAuthorable fails if root
// ownership of the link alone is trusted: rename keeps the owner, so a
// root-owned link moved into a directory the user (or anyone) can write was
// placed by whoever could write there. The control is the same link in a
// directory only root can change.
func TestRootOwnedLinkInADirectoryOthersCanWriteIsAuthorable(t *testing.T) {
	cases := []struct {
		name  string
		owner uint32
		mode  fs.FileMode
		want  string
	}{
		{"parent owned by the user", 1000, 0o755, "a directory uid 1000 owns"},
		{"parent root-owned and world-writable sticky", 0, 0o1777, "group or other users can write (mode 0777)"},
		{"parent root-owned and group-writable", 0, 0o775, "group or other users can write (mode 0775)"},
		{"parent owned by another user", 4242, 0o755, "owned by uid 4242, not root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newFakeEnv()
			env.links["/opt/x"] = "/home/u"
			env.dirOwners["/opt"], env.dirModes["/opt"] = c.owner, c.mode
			_, links, err := authorableLinks(env, 1000, "/opt/x")
			if err != nil {
				t.Fatal(err)
			}
			if len(links) != 1 {
				t.Fatalf("links = %+v, want the root-owned link judged authorable", links)
			}
			if got := ownerPhrase(links[0], 1000); !strings.Contains(got, c.want) {
				t.Errorf("ownerPhrase = %q, want it to contain %q", got, c.want)
			}
		})
	}

	env := newFakeEnv()
	env.links["/opt/x"] = "/home/u"
	if _, links, err := authorableLinks(env, 1000, "/opt/x"); err != nil || len(links) != 0 {
		t.Errorf("control: a root-owned link in a root-owned 0755 directory: links=%+v err=%v", links, err)
	}
}

func TestAuthorableLinksLoopRefuses(t *testing.T) {
	env := newFakeEnv()
	env.links["/opt/a"] = "/opt/a"
	if _, _, err := authorableLinks(env, 1000, "/opt/a"); err == nil {
		t.Fatal("a link loop must be an error")
	}
}

// hlCache is the shape of the first finding: one profile holds the planted
// link's directory read-write and also names a path through the link.
func hlCache() *Profile {
	return &Profile{Name: "cache", RW: []string{"/s/cache"}, RO: []string{"/s/cache/bin:/mnt/x"}}
}

// TestGrantThroughUserLinkInsideRWGrantIsRefused fails if a path inside this
// run's own rw grant is followed through a link the sandbox could have planted
// there: run 1 writes `ln -s /s/secret /s/cache/bin`, run 2 binds the secret at
// /mnt/x. The control is the same profile over a real directory.
func TestGrantThroughUserLinkInsideRWGrantIsRefused(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlUser, "/s/cache/bin", "/s/secret")
	_, err := hlResolve(hlRegistry(hlCache()), env, "cache")
	hlWantRefusal(t, err, "/s/cache/bin", "/s/secret", "uid 1000", `"cache"`)

	ctl := hlEnv()
	ctl.dirs["/s/cache/bin"] = true
	p := hlMustResolve(t, hlRegistry(hlCache()), ctl, "cache")
	if got := hlHost(t, p, "/mnt/x"); got != "/s/cache/bin" {
		t.Errorf("control: /mnt/x binds %s, want the real directory", got)
	}
}

// TestGrantThroughUserLinkOutsideEveryGrantIsRefused fails if the rule is
// anchored on this run's rw grants or loaded profiles: the link was left by an
// earlier target, nothing in this run grants its directory, and the redirect is
// to a different place than any grant.
func TestGrantThroughUserLinkOutsideEveryGrantIsRefused(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlUser, "/s/old/bin", "/s/secret")
	past := &Profile{Name: "past", RO: []string{"/s/old/bin:/mnt/x"}}
	_, err := hlResolve(hlRegistry(past), env, "past")
	hlWantRefusal(t, err, "/s/old/bin", "/s/secret", "uid 1000")

	ctl := hlEnv()
	ctl.dirs["/s/old/bin"] = true
	hlMustResolve(t, hlRegistry(past), ctl, "past")
}

// TestGrantThroughSubuidOwnedLinkIsRefused fails if "not the invoking uid" were
// the test: a rootless container writes links owned by a subuid.
func TestGrantThroughSubuidOwnedLinkIsRefused(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlSubuid, "/s/old/bin", "/s/secret")
	past := &Profile{Name: "past", RO: []string{"/s/old/bin:/mnt/x"}}
	_, err := hlResolve(hlRegistry(past), env, "past")
	hlWantRefusal(t, err, "uid 100999")
}

// TestRootOwnedHostLinksAreFollowed is the negative of every refusal here: the
// links a distribution ships (/opt -> /var/opt, /home -> /var/home) are root's,
// and a rule that refused them would refuse every default selection on such a
// host.
func TestRootOwnedHostLinksAreFollowed(t *testing.T) {
	env := newFakeEnv()
	env.resolveParents = true
	env.links["/opt"] = "/var/opt"
	env.links["/home"] = "/var/home"
	for _, d := range []string{"/var/opt", "/var/home", "/var/home/u", "/var/home/u/proj", "/var/home/u/proj/sub"} {
		env.dirs[d] = true
	}
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatalf("a host whose /opt and /home are root-owned links was refused: %v", err)
	}
	if got := hlHost(t, p, "/opt"); got != "/var/opt" {
		t.Errorf("/opt binds %s, want /var/opt", got)
	}
	if p.Target != "/var/home/u/proj/sub" || p.TargetAsked != "/home/u/proj/sub" {
		t.Errorf("Target = %q, TargetAsked = %q; want the real path and the path that was asked",
			p.Target, p.TargetAsked)
	}
}

// TestRootOwnedLinkIsAuthorableWhenSnugRunsAsRoot fails if root ownership is
// trusted under uid 0: a root-run sandbox writes root-owned links, so the
// trace means nothing there.
func TestRootOwnedLinkIsAuthorableWhenSnugRunsAsRoot(t *testing.T) {
	past := &Profile{Name: "past", RO: []string{"/s/old/bin:/mnt/x"}}
	build := func(root bool) *fakeEnv {
		env := hlEnv()
		env.hlLink(0, "/s/old/bin", "/s/secret")
		env.asRoot = root
		return env
	}
	hlMustResolve(t, hlRegistry(past), build(false), "past") // control: uid 1000 follows it
	_, err := hlResolve(hlRegistry(past), build(true), "past")
	hlWantRefusal(t, err, "snug is running as root", "/s/old/bin")
}

// TestCoverMustItselfBeLiteral fails if a grant that was itself redirected can
// vouch for another: two links into one directory must not cover each other.
func TestCoverMustItselfBeLiteral(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlUser, "/s/a", "/s/d")
	env.hlLink(hlUser, "/s/b", "/s/d")
	both := &Profile{Name: "both", RO: []string{"/s/a", "/s/b:/mnt/b"}}
	_, err := hlResolve(hlRegistry(both), env, "both")
	hlWantRefusal(t, err, "/s/a")

	onlyB := &Profile{Name: "onlyb", RO: []string{"/s/b:/mnt/b"}}
	_, err = hlResolve(hlRegistry(onlyB), env, "onlyb")
	hlWantRefusal(t, err, "/s/b")

	cover := &Profile{Name: "cover", RO: []string{"/s/d"}}
	hlMustResolve(t, hlRegistry(both, cover), env, "both", "cover") // control: a literal grant of /s/d covers both
}

// TestCoverMustHaveAtLeastTheRedirectedAccess fails if a read-only grant of a
// tree covers a read-write redirect into it, which would turn a planted link
// into a writable view of something the profile only meant to read.
func TestCoverMustHaveAtLeastTheRedirectedAccess(t *testing.T) {
	env := hlEnv()
	env.dirs["/s/tree"] = true
	env.dirs["/s/tree/sub"] = true
	env.hlLink(hlUser, "/s/l", "/s/tree/sub")
	redirectRW := &Profile{Name: "redirect", RW: []string{"/s/l:/mnt/x"}}
	redirectRO := &Profile{Name: "redirect", RO: []string{"/s/l:/mnt/x"}}
	coverRO := &Profile{Name: "cover", RO: []string{"/s/tree"}}
	coverRW := &Profile{Name: "cover", RW: []string{"/s/tree"}}

	_, err := hlResolve(hlRegistry(redirectRW, coverRO), env, "redirect", "cover")
	hlWantRefusal(t, err, "/s/l", "/s/tree/sub")
	hlMustResolve(t, hlRegistry(redirectRW, coverRW), env, "redirect", "cover")
	hlMustResolve(t, hlRegistry(redirectRO, coverRO), env, "redirect", "cover")
	hlMustResolve(t, hlRegistry(redirectRO, coverRW), env, "redirect", "cover")
}

// hlCoverPair names the redirecting profile and the covering profile so that
// the fold reaches them in either order.
func hlCoverPair(redirect, cover ProfileName) map[ProfileName]*Profile {
	return hlRegistry(
		&Profile{Name: redirect, RO: []string{"/s/cache/bin:/mnt/x"}},
		&Profile{Name: cover, RW: []string{"/s/cache"}})
}

func hlCoverEnv() *fakeEnv {
	env := hlEnv()
	env.hlLink(hlUser, "/s/cache/bin", "/s/cache/real")
	return env
}

// TestCoverIsFoldOrderIndependent fails if whether a redirect is covered
// depends on which profile the fold reaches first. Cover and redirect swap
// names, and the selection order is shuffled; every variant must resolve to the
// same policy. (TestResolveIsCommutative runs over the shared fixture host,
// which has no planted link, so it cannot see this.)
func TestCoverIsFoldOrderIndependent(t *testing.T) {
	var want string
	rng := rand.New(rand.NewSource(1))
	for _, names := range [][2]ProfileName{{"aa", "zz"}, {"zz", "aa"}} {
		reg := hlCoverPair(names[0], names[1])
		for i := 0; i < 20; i++ {
			sel := []ProfileName{names[0], names[1]}
			rng.Shuffle(2, func(a, b int) { sel[a], sel[b] = sel[b], sel[a] })
			got := canon(hlMustResolve(t, reg, hlCoverEnv(), sel...))
			if want == "" {
				want = got
				if !strings.Contains(got, "/mnt/x") {
					t.Fatalf("control: the redirected grant is not in the policy:\n%s", got)
				}
			}
			if got != want {
				t.Fatalf("order or naming changed the result (redirect %s, cover %s, sel %v)\n--- got\n%s\n--- want\n%s",
					names[0], names[1], sel, got, want)
			}
		}
	}
}

// TestFailingRedirectsReportTheSameRefusalInEveryOrder fails if the refusal that
// is reported depends on fold order: two uncovered redirects, and two profiles
// naming the same redirected path.
func TestFailingRedirectsReportTheSameRefusalInEveryOrder(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlUser, "/s/x", "/s/secret")
	env.hlLink(hlUser, "/s/y", "/s/old")
	p1 := &Profile{Name: "p1", RO: []string{"/s/y:/mnt/1"}}
	p2 := &Profile{Name: "p2", RO: []string{"/s/x:/mnt/2"}}
	p3 := &Profile{Name: "p3", RO: []string{"/s/x:/mnt/3"}}
	reg := hlRegistry(p1, p2, p3)

	sels := [][]ProfileName{{"p1", "p2", "p3"}, {"p3", "p2", "p1"}, {"p2", "p1", "p3"}}
	var first string
	for _, sel := range sels {
		_, err := hlResolve(reg, env, sel...)
		if err == nil {
			t.Fatalf("%v resolved", sel)
		}
		if first == "" {
			first = err.Error()
			if !strings.Contains(first, "/s/x") || !strings.Contains(first, `"p2"`) {
				t.Fatalf("control: expected the first failure by (requested, profile), /s/x from p2: %v", err)
			}
		}
		if err.Error() != first {
			t.Errorf("selection %v reported a different refusal\n got: %v\nwant: %s", sel, err, first)
		}
	}
}

// TestMissingCoverRefusesNotDrops fails if a redirect whose cover is absent from
// this host is silently dropped or allowed. The cover below is optional and
// missing; the redirect still exists and still reaches a host path.
func TestMissingCoverRefusesNotDrops(t *testing.T) {
	redirect := &Profile{Name: "redirect", RO: []string{"/s/l:/mnt/x"}}
	cover := &Profile{Name: "cover", RO: []string{"/s/cover"}, Optional: []string{"/s/cover"}}
	build := func(coverPresent bool) *fakeEnv {
		env := hlEnv()
		if coverPresent {
			env.hlLink(hlUser, "/s/l", "/s/cover/inner")
		} else {
			env.hlLink(hlUser, "/s/l", "/s/secret")
			delete(env.dirs, "/s/cover")
			delete(env.dirs, "/s/cover/inner")
		}
		return env
	}
	hlMustResolve(t, hlRegistry(redirect, cover), build(true), "redirect", "cover") // control
	_, err := hlResolve(hlRegistry(redirect, cover), build(false), "redirect", "cover")
	hlWantRefusal(t, err, "/s/l", "/s/secret", "no other grant in this run exposes as")
}

// TestOptionalGrantThroughUserLinkStillRefuses fails if marking a grant optional
// waives the ownership rule: optional only forgives a path that does not exist,
// and this one does.
func TestOptionalGrantThroughUserLinkStillRefuses(t *testing.T) {
	env := hlEnv()
	env.hlLink(hlUser, "/s/old/bin", "/s/secret")
	past := &Profile{Name: "past", RO: []string{"/s/old/bin:/mnt/x"}, Optional: []string{"/s/old/bin"}}
	_, err := hlResolve(hlRegistry(past), env, "past")
	hlWantRefusal(t, err, "/s/old/bin", "uid 1000")

	// A dangling optional grant is still skipped, which is what optional means.
	delete(env.dirs, "/s/secret")
	delete(env.links, "/s/old/bin")
	hlMustResolve(t, hlRegistry(past), env, "past")
}

// TestEveryHopIsChecked fails if only the first or last link of a chain is
// looked at: a root-owned /opt/x leads to a user-owned link that leaves.
func TestEveryHopIsChecked(t *testing.T) {
	env := hlEnv()
	env.resolveParents = true
	env.hlLink(0, "/opt/x", "/home/u/y")
	env.hlLink(hlUser, "/home/u/y", "/secret")
	g := &Profile{Name: "g", RO: []string{"/opt/x:/mnt/x"}}
	_, err := hlResolve(hlRegistry(g), env, "g")
	hlWantRefusal(t, err, "/home/u/y", "uid 1000", "/secret")

	env.linkOwners["/home/u/y"] = 0 // control: all hops root-owned
	p := hlMustResolve(t, hlRegistry(g), env, "g")
	if got := hlHost(t, p, "/mnt/x"); got != "/secret" {
		t.Errorf("control: /mnt/x binds %s, want /secret", got)
	}
}

// TestRelativeUserLinkIsRefused fails if link text is judged only when it is
// absolute: ../../secret is resolved from the link's own directory.
func TestRelativeUserLinkIsRefused(t *testing.T) {
	g := &Profile{Name: "g", RO: []string{"/s/a/b/l:/mnt/x"}}
	build := func(owner uint32) *fakeEnv {
		env := hlEnv()
		env.dirs["/s/a/b"] = true
		env.hlLink(owner, "/s/a/b/l", "../../secret")
		return env
	}
	_, err := hlResolve(hlRegistry(g), build(hlUser), "g")
	hlWantRefusal(t, err, "/s/a/b/l", "../../secret", "/s/secret")
	p := hlMustResolve(t, hlRegistry(g), build(0), "g") // control: root's relative link is followed
	if got := hlHost(t, p, "/mnt/x"); got != "/s/secret" {
		t.Errorf("control: /mnt/x binds %s, want /s/secret", got)
	}
}

// TestUserLinkAboveTheGrantRootIsRefused fails if only the last component is
// examined: the user's ~/projects is a link, so a literal grant below it leaves
// the path the profile wrote. The same project named as {target} or
// {target_parent} is already canonical and still resolves.
func TestUserLinkAboveTheGrantRootIsRefused(t *testing.T) {
	env := newFakeEnv()
	env.resolveParents = true
	env.hlLink(hlUser, "/home/u/projects", "/data/projects")
	for _, d := range []string{"/data/projects", "/data/projects/lib", "/data/projects/app"} {
		env.dirs[d] = true
	}
	ctx := testCtx()
	ctx.Target = "/data/projects/app"
	sel := append(slices.Clone(testDefaults), "lit")

	lit := &Profile{Name: "lit", RO: []string{"/home/u/projects/lib"}}
	_, err := Resolve(hlRegistry(lit), sel, ctx, env)
	hlWantRefusal(t, err, "/home/u/projects/lib", "/home/u/projects", "uid 1000")

	viaTarget := &Profile{Name: "lit", RO: []string{"{target_parent}/lib"}}
	p, err := Resolve(hlRegistry(viaTarget), sel, ctx, env)
	if err != nil {
		t.Fatalf("the same project written as {target_parent} was refused: %v", err)
	}
	if p.Target != "/data/projects/app" {
		t.Errorf("Target = %q", p.Target)
	}
	if got := hlHost(t, p, "/data/projects/lib"); got != "/data/projects/lib" {
		t.Errorf("{target_parent}/lib binds %s", got)
	}
}

// TestIdentityKeyThroughUserLinkOutsideTargetIsRefused fails if a pinned key
// path outside {target} is trusted: a planted ~/.ssh link chooses which host
// key the proxy will sign with. Both key fields are covered. The control also
// holds that a trusted link is stored by its destination, because the key is
// opened without following links.
func TestIdentityKeyThroughUserLinkOutsideTargetIsRefused(t *testing.T) {
	env := newFakeEnv()
	env.hlLink(hlUser, "/home/u/.ssh", "/home/u/other-ssh")
	sel := append(slices.Clone(testDefaults), "pinned")

	_, err := Resolve(identityRegistry("~/.ssh/id.pub"), sel, testCtx(), env)
	hlWantRefusal(t, err, "ssh.key", "/home/u/.ssh", "uid 1000", "/home/u/other-ssh/id.pub")

	_, err = Resolve(identitySigningRegistry("~/id_auth.pub", "~/.ssh/sign.pub", SSHAgentProxy), sel, testCtx(), env)
	hlWantRefusal(t, err, "git.signing_key", "/home/u/.ssh", "uid 1000")

	env.linkOwners["/home/u/.ssh"] = 0 // control: root's link is the host's own
	p, err := Resolve(identityRegistry("~/.ssh/id.pub"), sel, testCtx(), env)
	if err != nil {
		t.Fatalf("control: a root-owned link on the key path was refused: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Key != "/home/u/other-ssh/id.pub" {
		t.Errorf("identity = %+v", p.Identity)
	}
}

// TestAbsentIdentityKeyStillResolves fails if the identity check refuses a key
// that merely does not exist, which would turn --dry-run and `snug profile
// show` into hard failures for a profile whose key is not yet created.
func TestAbsentIdentityKeyStillResolves(t *testing.T) {
	env := newFakeEnv()
	env.hlLink(0, "/home/u/.ssh", "/home/u/real-ssh")
	sel := append(slices.Clone(testDefaults), "pinned")
	p, err := Resolve(identityRegistry("~/.ssh/missing/deploy.pub"), sel, testCtx(), env)
	if err != nil {
		t.Fatalf("an absent key was refused: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Key != "/home/u/real-ssh/missing/deploy.pub" {
		t.Errorf("identity = %+v", p.Identity)
	}
}

// TestRootOwnedLinkUnderTargetStillRefused fails if the ownership rule loosened
// underTargetIsLiteral: under {target} even a root-owned link refuses, and the
// refusal is that function's own, not the new one.
func TestRootOwnedLinkUnderTargetStillRefused(t *testing.T) {
	env := hlEnv()
	env.hlLink(0, "/home/u/proj/sub/vendor", "/home/u/proj/sub/real")
	g := &Profile{Name: "g", RO: []string{"{target}/vendor"}}
	_, err := hlResolve(hlRegistry(g), env, "g")
	hlWantRefusal(t, err, "a symlink inside the sandbox's own writable area", "/home/u/proj/sub/real")
}

// hlLyingEnv lets a test make the host disagree with itself.
type hlLyingEnv struct {
	*fakeEnv
	evalAs  map[string]string
	noOwner map[string]bool
}

func (e hlLyingEnv) EvalSymlinks(p string) (string, error) {
	if r, ok := e.evalAs[p]; ok {
		return r, nil
	}
	return e.fakeEnv.EvalSymlinks(p)
}

func (e hlLyingEnv) Lstat(p string) (fs.FileInfo, error) {
	if e.noOwner[p] {
		return fakeInfo{name: p, mode: fs.ModeSymlink}, nil
	}
	return e.fakeEnv.Lstat(p)
}

// TestLinkWalkDisagreeingWithEvalSymlinksRefuses fails if snug's own walk and
// the host's resolution can diverge unnoticed: the ownership verdict is about
// the walk's path, the bind is of EvalSymlinks' path.
func TestLinkWalkDisagreeingWithEvalSymlinksRefuses(t *testing.T) {
	g := &Profile{Name: "g", RO: []string{"/s/g:/mnt/x"}}
	env := hlEnv()
	env.dirs["/s/g"] = true
	_, err := hlResolve(hlRegistry(g), hlLyingEnv{fakeEnv: env, evalAs: map[string]string{"/s/g": "/s/secret"}}, "g")
	hlWantRefusal(t, err, "link walk reached /s/g", "/s/secret")
	hlMustResolve(t, hlRegistry(g), hlLyingEnv{fakeEnv: env}, "g") // control: agreeing, it resolves
}

// TestUnreadableLinkOwnerFailsClosed fails if a link whose owner cannot be read
// (Sys() is not a *syscall.Stat_t) is trusted as root's.
func TestUnreadableLinkOwnerFailsClosed(t *testing.T) {
	g := &Profile{Name: "g", RO: []string{"/s/old/bin:/mnt/x"}}
	env := hlEnv()
	env.hlLink(0, "/s/old/bin", "/s/secret")
	hlMustResolve(t, hlRegistry(g), hlLyingEnv{fakeEnv: env}, "g") // control: readable root owner is followed
	_, err := hlResolve(hlRegistry(g), hlLyingEnv{fakeEnv: env, noOwner: map[string]bool{"/s/old/bin": true}}, "g")
	hlWantRefusal(t, err, "/s/old/bin")
	// Owner reads as 0 when there is none to read; the refusal must not then
	// call the link root-owned while refusing it for not being root-owned.
	if strings.Contains(err.Error(), "uid 0") || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("refusal misstates the owner: %v", err)
	}
}

// ── refusal producers, registered in TestGoldenRefusals ─────────────────────

func refusalGrantThroughAuthorableLinkUncovered(t testing.TB) error {
	env := hlEnv()
	env.hlLink(hlUser, "/s/cache/bin", "/s/secret")
	_, err := hlResolve(hlRegistry(hlCache()), env, "cache")
	return err
}

// refusalGrantThroughAuthorableLinkCarriesAForgingRune: the link's destination
// is chosen by whatever planted it and is printed in the refusal, so ESC and
// CSI in it must reach the screen escaped.
func refusalGrantThroughAuthorableLinkCarriesAForgingRune(t testing.TB) error {
	env := hlEnv()
	env.hlLink(hlUser, "/s/cache/bin", "/s/secret\x1b[2K\x1b[1Asnug: verified safe")
	_, err := hlResolve(hlRegistry(hlCache()), env, "cache")
	return err
}

func refusalIdentityKeyThroughAuthorableLinkCarriesAForgingRune(t testing.TB) error {
	env := newFakeEnv()
	env.hlLink(hlUser, "/home/u/.ssh", "/home/u/x\x1b[2K\x1b[1Asnug: verified safe")
	_, err := Resolve(identityRegistry("~/.ssh/id.pub"),
		append(slices.Clone(testDefaults), "pinned"), testCtx(), env)
	return err
}

func refusalIdentityKeyThroughAuthorableLink(t testing.TB) error {
	env := newFakeEnv()
	env.hlLink(hlUser, "/home/u/.ssh", "/home/u/other-ssh")
	_, err := Resolve(identityRegistry("~/.ssh/id.pub"),
		append(slices.Clone(testDefaults), "pinned"), testCtx(), env)
	return err
}

func TestAuthorableLinkRefusalsEscapeTheDestination(t *testing.T) {
	for name, run := range map[string]func(testing.TB) error{
		"grant":    refusalGrantThroughAuthorableLinkCarriesAForgingRune,
		"identity": refusalIdentityKeyThroughAuthorableLinkCarriesAForgingRune,
	} {
		err := run(t)
		if err == nil {
			t.Fatalf("%s: went unrefused", name)
		}
		if strings.ContainsRune(err.Error(), '\x1b') {
			t.Errorf("%s: the refusal rendered ESC raw: %q", name, err)
		}
		if !strings.Contains(err.Error(), "verified safe") || !strings.Contains(err.Error(), `\x1b`) {
			t.Errorf("%s: the destination is neither present nor escaped: %q", name, err)
		}
	}
}

// TestUserLinkOnTheTargetPathIsRefused fails if CanonicalTarget follows a link
// a sandbox could have planted. A root-owned link is the control.
func TestUserLinkOnTheTargetPathIsRefused(t *testing.T) {
	build := func(owner uint32) *fakeEnv {
		env := newFakeEnv()
		env.resolveParents = true
		env.hlLink(owner, "/home/u/projects", "/data/projects")
		env.dirs["/data/projects"] = true
		env.dirs["/data/projects/app"] = true
		return env
	}
	ctx := testCtx()
	ctx.Target = "/home/u/projects/app"
	_, err := Resolve(hlRegistry(), testDefaults, ctx, build(hlUser))
	if err == nil || errors.Is(err, ErrTargetUnusable) ||
		!strings.Contains(err.Error(), "/home/u/projects -> /data/projects") {
		t.Fatalf("a user-owned link above the target: err = %v", err)
	}
	if _, err := CanonicalTarget(build(hlUser), ctx); err == nil {
		t.Errorf("CanonicalTarget followed a user-owned link")
	}
	p, err := Resolve(hlRegistry(), testDefaults, ctx, build(0))
	if err != nil || p.Target != "/data/projects/app" || p.TargetAsked != ctx.Target {
		t.Errorf("control: root-owned link: p = %+v, err = %v", p, err)
	}
}

// TestUserLinkOnHomeIsRefused fails if a planted $HOME link is followed:
// {home} is the host side of every grant under it.
func TestUserLinkOnHomeIsRefused(t *testing.T) {
	env := newFakeEnv()
	env.resolveParents = true
	env.hlLink(hlUser, "/home/u", "/data/u")
	env.dirs["/data/u"] = true
	env.dirs["/data/u/proj/sub"] = true
	ctx := testCtx()
	ctx.Target = "/data/u/proj/sub"
	_, err := Resolve(hlRegistry(), testDefaults, ctx, env)
	if err == nil || !strings.HasPrefix(err.Error(), "$HOME /home/u resolves through the link") {
		t.Fatalf("err = %v", err)
	}
}

// targetEnv is a fixture host where links are followed on every component and
// the data directories a link can point at exist.
func targetEnv(dirs ...string) *fakeEnv {
	env := newFakeEnv()
	env.resolveParents = true
	for _, d := range dirs {
		env.dirs[d] = true
	}
	return env
}

func targetResolve(env *fakeEnv, target string) (*Policy, error) {
	ctx := testCtx()
	ctx.Target = target
	return Resolve(hlRegistry(), testDefaults, ctx, env)
}

// TestTargetLinkOneLevelBelowHomeIsRefused fails if the refusal is anchored on
// something that excludes the layout a sandbox with rw on ~/src would leave
// behind: a user-owned link one level below $HOME.
func TestTargetLinkOneLevelBelowHomeIsRefused(t *testing.T) {
	env := targetEnv("/data/work", "/data/work/app", "/home/u/src")
	env.hlLink(hlUser, "/home/u/src/work", "/data/work")
	_, err := targetResolve(env, "/home/u/src/work/app")
	if err == nil || errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("err = %v, want a policy refusal (not ErrTargetUnusable)", err)
	}
	for _, s := range []string{"/home/u/src/work -> /data/work", "snug /data/work/app", "cd -P"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("refusal does not contain %q: %v", s, err)
		}
	}
}

// TestTargetLinkDirectlyInHomeIsRefused pins the strict decision: the common
// ~/projects -> /data/projects layout is refused too, because a link there is
// indistinguishable from one a sandbox with rw on $HOME planted. The fix is to
// name /data/projects/app, and the refusal says so.
func TestTargetLinkDirectlyInHomeIsRefused(t *testing.T) {
	env := targetEnv("/data/projects", "/data/projects/app")
	env.hlLink(hlUser, "/home/u/projects", "/data/projects")
	_, err := targetResolve(env, "/home/u/projects/app")
	if err == nil || errors.Is(err, ErrTargetUnusable) ||
		!strings.Contains(err.Error(), "snug /data/projects/app") {
		t.Fatalf("err = %v", err)
	}
}

// TestTargetEveryHopIsJudged fails if only the first authorable link, or only
// the last hop, is checked: a root-owned link leads to a user-owned one and the
// refusal must name the second.
func TestTargetEveryHopIsJudged(t *testing.T) {
	env := targetEnv("/data/real", "/data/real/app", "/data/mid")
	env.hlLink(0, "/home/u/a", "/data/mid/b")
	env.hlLink(hlUser, "/data/mid/b", "/data/real")
	_, err := targetResolve(env, "/home/u/a/app")
	if err == nil {
		t.Fatal("a user-owned second hop was followed because the first was root-owned")
	}
	if !strings.Contains(err.Error(), "/data/mid/b -> /data/real") ||
		strings.Contains(err.Error(), "/home/u/a ->") {
		t.Errorf("refusal must name the second hop only: %v", err)
	}
}

// TestRootOwnedTargetLinkIsFollowed is the control for the refusals above: the
// same layout with a root-owned link resolves, with the asked path kept.
func TestRootOwnedTargetLinkIsFollowed(t *testing.T) {
	env := targetEnv("/data/projects", "/data/projects/app")
	env.hlLink(0, "/home/u/projects", "/data/projects")
	p, err := targetResolve(env, "/home/u/projects/app")
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != "/data/projects/app" || p.TargetAsked != "/home/u/projects/app" {
		t.Errorf("Target = %q, TargetAsked = %q", p.Target, p.TargetAsked)
	}
}

// TestTargetLinkRefusedAsRootToo fails if the root exemption (a root-owned
// link is trusted) is applied when snug itself is root: a root-owned link is
// then one the invoking user's sandbox could have planted.
func TestTargetLinkRefusedAsRootToo(t *testing.T) {
	env := targetEnv("/data/projects", "/data/projects/app")
	env.hlLink(0, "/home/u/projects", "/data/projects")
	env.asRoot = true
	_, err := targetResolve(env, "/home/u/projects/app")
	if err == nil || !strings.Contains(err.Error(), "running as root") {
		t.Fatalf("err = %v", err)
	}
}

const forgedTail = "\x1b[2K\x1b[1Asnug: verified safe\u202e"

// refusalTargetLinkCarriesAForgingRune puts the forging runes in the link name
// and in the link text, both of which whatever planted the link chooses.
func refusalTargetLinkCarriesAForgingRune(t testing.TB) error {
	env := targetEnv("/data/w"+forgedTail, "/data/w"+forgedTail+"/app")
	env.hlLink(hlUser, "/home/u/p"+forgedTail, "/data/w"+forgedTail)
	_, err := targetResolve(env, "/home/u/p"+forgedTail+"/app")
	return err
}

func refusalTargetThroughAuthorableLink(t testing.TB) error {
	env := targetEnv("/data/projects", "/data/projects/app")
	env.hlLink(hlUser, "/home/u/projects", "/data/projects")
	_, err := targetResolve(env, "/home/u/projects/app")
	return err
}

func refusalHomeCarriesAForgingRune(t testing.TB) error {
	env := targetEnv("/data/u"+forgedTail, "/data/u"+forgedTail+"/proj")
	env.hlLink(hlUser, "/home/h"+forgedTail, "/data/u"+forgedTail)
	ctx := testCtx()
	ctx.Home = "/home/h" + forgedTail
	ctx.Target = "/data/u" + forgedTail + "/proj"
	_, err := Resolve(hlRegistry(), testDefaults, ctx, env)
	return err
}

func refusalHomeThroughAuthorableLink(t testing.TB) error {
	env := targetEnv("/data/u", "/data/u/proj")
	env.hlLink(hlUser, "/home/h", "/data/u")
	ctx := testCtx()
	ctx.Home = "/home/h"
	ctx.Target = "/data/u/proj"
	_, err := Resolve(hlRegistry(), testDefaults, ctx, env)
	return err
}

// TestTargetLinkRefusalEscapesHostileSpelling fails if a refusal prints the
// planted link's name or text raw: a sandbox chose both, and the refusal is
// what the human reads before deciding what to delete.
func TestTargetLinkRefusalEscapesHostileSpelling(t *testing.T) {
	for name, run := range map[string]func(testing.TB) error{
		"target": refusalTargetLinkCarriesAForgingRune,
		"home":   refusalHomeCarriesAForgingRune,
	} {
		err := run(t)
		if err == nil {
			t.Fatalf("%s: went unrefused", name)
		}
		for _, r := range []string{"\x1b", "\u202e"} {
			if strings.Contains(err.Error(), r) {
				t.Errorf("%s: the refusal rendered %q raw: %q", name, r, err)
			}
		}
		if !strings.Contains(err.Error(), "verified safe") || !strings.Contains(err.Error(), `\x1b`) {
			t.Errorf("%s: the hostile spelling is neither present nor escaped: %q", name, err)
		}
	}
}

// TestHomeThroughUserLinkIsRefused fails if $HOME is canonicalised without the
// ownership rule while the target is not: here the target is clean and only
// $HOME crosses the link, and the refusal tells the human what to set.
func TestHomeThroughUserLinkIsRefused(t *testing.T) {
	err := refusalHomeThroughAuthorableLink(t)
	if err == nil || errors.Is(err, ErrTargetUnusable) ||
		!strings.Contains(err.Error(), "/home/h -> /data/u") ||
		!strings.Contains(err.Error(), "set HOME to /data/u") {
		t.Fatalf("err = %v", err)
	}
}
