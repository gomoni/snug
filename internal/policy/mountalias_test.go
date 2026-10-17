package policy

import (
	"errors"
	"strings"
	"testing"
)

// aliasMountinfo is a distrobox-shaped host: /home, /tmp and /run/user/1000
// each appear a second time under /run/host, the engine store is bound at
// /mnt/eng (a subdirectory of it) and /srv/box/s (the store itself, so a grant
// of /srv/box CONTAINS a second mount of it), and /mnt/tc is a bind of a
// toolchain directory on the root filesystem. The last five lines are
// structural: a stack at one mount point, a sibling mounted over a hidden one,
// and a nested pair.
const aliasMountinfo = `1 0 0:1 / / rw - rootfs rootfs rw
2 1 0:50 /@/home /home rw - btrfs /dev/vda rw
3 1 0:50 /@/home /run/host/home rw - btrfs /dev/vda rw
4 1 0:87 / /run/user/1000 rw - tmpfs tmpfs rw
5 1 0:87 / /run/host/run/user/1000 rw - tmpfs tmpfs rw
6 1 0:45 / /tmp rw - tmpfs tmpfs rw
7 1 0:45 / /run/host/tmp rw - tmpfs tmpfs rw
8 1 0:50 /@/home/u/.local/share/snug/engines /mnt/eng rw - btrfs /dev/vda rw
9 1 0:50 /@/home/u/.local/share/snug /srv/box/s rw - btrfs /dev/vda rw
10 1 0:50 /@/home/u/src /mnt/other rw - btrfs /dev/vda rw
11 1 0:1 /opt/podman /mnt/tc rw - rootfs rootfs rw
12 1 0:60 / /stack rw - tmpfs tmpfs rw
13 12 0:61 /x /stack rw - tmpfs tmpfs rw
14 1 0:70 / /sh/inner rw - tmpfs tmpfs rw
15 1 0:71 / /sh rw - tmpfs tmpfs rw
`

func aliasEnv(extra ...string) *fakeEnv {
	env := envWith(extra...)
	env.mounts = parseMountinfo(aliasMountinfo)
	return env
}

func TestParseMountinfoCarriesIdentity(t *testing.T) {
	const in = "37 35 0:22 /@/my\\040dir /mnt/a\\040b rw shared:1 master:2 - ext4 /dev/sda1 rw\n" +
		"x 35 0:22 / /bad rw - ext4 /dev/sda1 rw\n"
	got := parseMountinfo(in)
	want := HostMount{Path: "/mnt/a b", FSType: "ext4", ID: 37, Parent: 35, Dev: "0:22", Root: "/@/my dir"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("parsed %+v, want exactly [%+v] (a line whose id is not a number is skipped)", got, want)
	}
}

func TestMountTableLoc(t *testing.T) {
	mt, err := newMountTable(&fakeEnv{mounts: parseMountinfo(aliasMountinfo)})
	if err != nil || !mt.usable() {
		t.Fatalf("fixture table unusable: %v", err)
	}
	for _, tc := range []struct {
		name, path string
		want       fsLoc
	}{
		{"the root", "/", fsLoc{"0:1", "/"}},
		{"plain path on the root filesystem", "/srv/box", fsLoc{"0:1", "/srv/box"}},
		{"under a bind of a subvolume", "/home/u/proj", fsLoc{"0:50", "/@/home/u/proj"}},
		{"second mount of the same subvolume", "/run/host/home/u/proj", fsLoc{"0:50", "/@/home/u/proj"}},
		{"subdirectory bind", "/mnt/eng/k", fsLoc{"0:50", "/@/home/u/.local/share/snug/engines/k"}},
		{"under a submount of a grant's parent", "/srv/box/s/engines", fsLoc{"0:50", "/@/home/u/.local/share/snug/engines"}},
		{"nonexistent tail is the ancestor plus the tail", "/run/host/home/u/new/dir", fsLoc{"0:50", "/@/home/u/new/dir"}},
		{"stacked at one point: the top of the stack", "/stack/a", fsLoc{"0:61", "/x/a"}},
		{"shadowed sibling: the overmounting mount wins", "/sh/inner/f", fsLoc{"0:71", "/inner/f"}},
	} {
		got, ok := mt.loc(tc.path)
		if !ok || got != tc.want {
			t.Errorf("%s: loc(%s) = %+v, %v; want %+v", tc.name, tc.path, got, ok, tc.want)
		}
	}

	for name, tab := range map[string]*mountTable{
		"nil table": nil,
		"entries without mount identity": func() *mountTable {
			m, _ := newMountTable(&fakeEnv{mounts: []HostMount{{Path: "/", FSType: "ext4"}, {Path: "/proc", FSType: "proc"}}})
			return m
		}(),
		"no entry for /": func() *mountTable {
			m, _ := newMountTable(&fakeEnv{mounts: parseMountinfo("2 1 0:50 / /home rw - ext4 x rw\n")})
			return m
		}(),
	} {
		if tab.usable() {
			t.Errorf("%s: usable", name)
		}
		if _, ok := tab.loc("/home"); ok {
			t.Errorf("%s: loc answered", name)
		}
		if _, ok := tab.aliasOverlap(newFakeEnv(), "/a", "/a"); ok {
			t.Errorf("%s: aliasOverlap hit", name)
		}
	}
}

func TestRealMountTableIsUsable(t *testing.T) {
	mt, err := newMountTable(OSEnviron{})
	if err != nil {
		t.Fatalf("reading this host's mount table: %v", err)
	}
	if !mt.usable() {
		t.Fatalf("this host's mountinfo has no usable root mount (%d entries): the alias arm would silently do nothing", len(mt.ms))
	}
	if _, ok := mt.loc("/"); !ok {
		t.Error("loc(/) found no location")
	}
}

// aliasKind is one protected thing, with the Context field that names it and
// the sentence its refusal carries.
type aliasKind struct {
	ctx  func() Context
	want string
	dev  string
}

var aliasKinds = map[string]aliasKind{
	"config": {func() Context {
		c := testCtx()
		c.ConfigRoots = []string{"/home/u/.config/snug"}
		return c
	}, cfgSentence, "0:50"},
	"runtime": {func() Context {
		c := testCtx()
		c.RuntimeDirs = []string{"/run/user/1000/snug"}
		return c
	}, "runtime directory", "0:87"},
	"store": {func() Context {
		return engineStateCtx([]EngineDataRoot{{Path: "/home/u/.local/share/snug"}})
	}, "engine store", "0:50"},
	"toolchain": {func() Context {
		return engineStateCtx([]EngineDataRoot{{Path: "/opt/podman", ReadAllowed: true}})
	}, "container engine toolchain root", "0:1"},
	"tmp": {func() Context {
		return engineStateCtx(nil, "/tmp/snug-1000-")
	}, "a per-run directory", "0:45"},
}

// TestProtectedRootRefusedThroughAlias would catch a protected-root refusal
// that compares only spellings: every grant below is not under its root by
// name, and every one reaches it through a second mount of the same
// filesystem. The grant sits inside the root through an alias of an ancestor,
// contains the root (an ancestor alias, or a submount of the root under it),
// reaches it by a subdirectory bind, or names a path that does not exist yet.
//
// It does not reach the identity-key arm (TestIdentityKeyRefusedThroughAlias),
// nor overlayfs, where upperdir and lowerdir paths are not in mountinfo's
// fields 4 and 5.
func TestProtectedRootRefusedThroughAlias(t *testing.T) {
	type row struct {
		name, kind, grant string
		rwOnly            bool
	}
	rows := []row{
		{"config: alias of the root", "config", "/run/host/home/u/.config/snug", true},
		{"config: inside it via an ancestor alias", "config", "/run/host/home/u/.config/snug/profiles.d", true},
		{"config: contains it", "config", "/run/host/home/u", true},
		{"runtime: alias of the dir", "runtime", "/run/host/run/user/1000/snug", false},
		{"runtime: inside it", "runtime", "/run/host/run/user/1000/snug/x", false},
		{"runtime: contains it", "runtime", "/run/host/run/user/1000", false},
		{"store: alias of the root", "store", "/run/host/home/u/.local/share/snug", false},
		{"store: subdirectory bind", "store", "/mnt/eng", false},
		{"store: inside a subdirectory bind", "store", "/mnt/eng/k", false},
		{"store: contains a submount of the root", "store", "/srv/box", false},
		{"store: inside a submount of the root", "store", "/srv/box/s", false},
		{"store: nonexistent tail", "store", "/run/host/home/u/.local/share/snug/engines/new", false},
		{"store: contains it", "store", "/run/host/home/u", false},
		{"toolchain: bind of the root", "toolchain", "/mnt/tc", true},
		{"toolchain: inside the bind", "toolchain", "/mnt/tc/bin", true},
		{"tmp: alias of a per-run dir", "tmp", "/run/host/tmp/snug-1000-77", false},
		{"tmp: inside one", "tmp", "/run/host/tmp/snug-1000-77/x", false},
	}
	for _, r := range rows {
		k := aliasKinds[r.kind]
		for _, acc := range []string{"ro", "rw"} {
			if r.rwOnly && acc == "ro" {
				continue
			}
			for _, rootExists := range []bool{true, false} {
				state := "root-absent"
				if rootExists {
					state = "root-exists"
				}
				t.Run(r.name+"/"+acc+"/"+state, func(t *testing.T) {
					env := aliasEnv(r.grant, "/home/u/proj/sub")
					if rootExists {
						env = aliasEnv(r.grant, "/home/u/proj/sub", "/home/u/.config/snug",
							"/run/user/1000/snug", "/home/u/.local/share/snug", "/opt/podman", "/tmp/snug-1000-77")
					}
					_, err := Resolve(withGrant(acc, r.grant), append(testDefaults, "peek"), k.ctx(), env)
					if err == nil {
						t.Fatalf("ACCEPTED %s %s", acc, r.grant)
					}
					for _, w := range []string{k.want, "second mount", "device " + k.dev, r.grant, `"peek"`} {
						if !strings.Contains(err.Error(), w) {
							t.Errorf("refusal lacks %q:\n%v", w, err)
						}
					}

					env.mounts = nil
					_, err = Resolve(withGrant(acc, r.grant), append(testDefaults, "peek"), k.ctx(), env)
					if err != nil && strings.Contains(err.Error(), "second mount") {
						t.Errorf("a host with no mount identity still found an alias:\n%v", err)
					}
				})
			}
		}
	}

	for _, n := range []struct {
		name, kind, acc, grant string
	}{
		{"unrelated bind of the same filesystem", "store", "rw", "/mnt/other"},
		{"unrelated directory under an alias", "store", "rw", "/run/host/home/u/src"},
		{"name prefix is not a path ancestor: store", "store", "rw", "/run/host/home/u/.local/share/snugger"},
		{"name prefix is not a path ancestor: config", "config", "rw", "/run/host/home/u/.config/snugger"},
		{"unrelated bind next to the runtime dir", "runtime", "rw", "/run/host/run/user/1000/other"},
		{"read-only alias of the toolchain root", "toolchain", "ro", "/mnt/tc"},
		{"a name that is not a per-run prefix", "tmp", "rw", "/run/host/tmp/snug-other"},
		{"the temp directory itself is the runtime-dir rule's", "tmp", "rw", "/run/host/tmp"},
	} {
		t.Run("negative: "+n.name, func(t *testing.T) {
			env := aliasEnv(n.grant, "/home/u/proj/sub", "/home/u/.config/snug", "/run/user/1000/snug",
				"/home/u/.local/share/snug", "/opt/podman", "/tmp/snug-1000-77")
			if _, err := Resolve(withGrant(n.acc, n.grant), append(testDefaults, "peek"), aliasKinds[n.kind].ctx(), env); err != nil {
				t.Fatalf("%s %s refused:\n%v", n.acc, n.grant, err)
			}
		})
	}
}

// TestIdentityKeyRefusedThroughAlias would catch the identity-key arm
// comparing spellings only: snug reads the key on the host and stages its
// bytes, so a path that reaches engine state through a second mount hands that
// state over as a file.
func TestIdentityKeyRefusedThroughAlias(t *testing.T) {
	ctx := engineStateCtx(testEngineDataRoots, "/tmp/snug-1000-")
	ctx.RuntimeDirs = []string{"/run/user/1000/snug"}
	for _, tc := range []struct{ name, key, want string }{
		{"engine store", "/run/host/home/u/.local/share/snug/engines/k/x.pub", "engine store"},
		{"subdirectory bind of the store", "/mnt/eng/k/x.pub", "engine store"},
		{"inside a submount of the store", "/srv/box/s/engines/x.pub", "engine store"},
		{"runtime dir", "/run/host/run/user/1000/snug/agent.pub", "runtime directory"},
		{"per-run tmp", "/run/host/tmp/snug-1000-77/id.pub", "per-run engine directory"},
	} {
		for _, signing := range []bool{false, true} {
			ssh, sign, field := tc.key, "", "identity.ssh.key"
			env := aliasEnv(tc.key, "/home/u/proj/sub", "/home/u/.ssh/id.pub")
			if signing {
				ssh, sign, field = "/home/u/.ssh/id.pub", tc.key, "identity.git.signing_key"
			}
			_, err := Resolve(identityKeyProfile(ssh, sign), append(testDefaults, "peek"), ctx, env)
			if err == nil {
				t.Errorf("%s/%s: ACCEPTED %s", tc.name, field, tc.key)
				continue
			}
			for _, w := range []string{field, tc.key, tc.want, "second mount", "name that path instead"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%s/%s: refusal lacks %q:\n%v", tc.name, field, w, err)
				}
			}
		}
	}
	env := aliasEnv("/mnt/other/k.pub", "/run/host/home/u/src/k.pub", "/home/u/proj/sub")
	for _, ok := range []string{"/mnt/other/k.pub", "/run/host/home/u/src/k.pub"} {
		if _, err := Resolve(identityKeyProfile(ok, ""), append(testDefaults, "peek"), ctx, env); err != nil {
			t.Errorf("key %s refused:\n%v", ok, err)
		}
	}
}

// TestAliasRefusalIsOrderIndependent would catch the alias arms reporting
// whichever profile, root or configuration directory the caller listed first:
// the refusal a person reads must be the same on every run of the same
// selection.
func TestAliasRefusalIsOrderIndependent(t *testing.T) {
	mk := func() map[ProfileName]*Profile {
		reg := testRegistry()
		reg["a"] = &Profile{Name: "a", RW: []string{"/run/host/home/u"}}
		reg["b"] = &Profile{Name: "b", RW: []string{"/run/host/home/u/.local/share/snug"}}
		return reg
	}
	env := aliasEnv("/run/host/home/u", "/run/host/home/u/.local/share/snug", "/home/u/proj/sub")

	var first string
	for i, sel := range [][]ProfileName{{"a", "b"}, {"b", "a"}} {
		for j, cfg := range [][]string{
			{"/home/u/.config/snug", "/home/u/.cache/snug"},
			{"/home/u/.cache/snug", "/home/u/.config/snug"},
		} {
			ctx := testCtx()
			ctx.ConfigRoots = cfg
			_, err := Resolve(mk(), append(append([]ProfileName{}, testDefaults...), sel...), ctx, env)
			if err == nil {
				t.Fatal("ACCEPTED a grant containing two config roots through an alias")
			}
			if i == 0 && j == 0 {
				first = err.Error()
				if !strings.Contains(first, `"a"`) || !strings.Contains(first, "/home/u/.cache/snug") {
					t.Fatalf("expected the first profile and the first root in sorted order:\n%v", first)
				}
				continue
			}
			if err.Error() != first {
				t.Errorf("selection %v / roots %v changed the refusal:\n%v\nvs\n%v", sel, cfg, err, first)
			}
		}
	}
}

func rwTargetPolicy(t *testing.T, env Environ) *Policy {
	t.Helper()
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return p
}

type mountsErrEnv struct{ *fakeEnv }

func (mountsErrEnv) HostMounts() ([]HostMount, error) { return nil, errors.New("boom") }

// TestJudgeEngineToolchainRefusesWritableAlias would catch a toolchain root
// that no rw grant contains by name, but that the target's rw grant reaches
// through the /run/host copy of /home, being accepted: the payload would write
// the tree the engine executes as uid 0.
func TestJudgeEngineToolchainRefusesWritableAlias(t *testing.T) {
	const root = "/run/host/home/u/proj/sub/tc"
	env := aliasEnv("/home/u/proj/sub", root, "/run/host/home/u/src/tc")
	p := rwTargetPolicy(t, env)

	_, err := p.JudgeEngineToolchain(env, root)
	if err == nil {
		t.Fatalf("ACCEPTED %s as the toolchain root", root)
	}
	for _, w := range []string{root + " cannot be this run's engine toolchain root", "/home/u/proj/sub", "second mount", "device 0:50"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q:\n%v", w, err)
		}
	}

	if got, err := p.JudgeEngineToolchain(env, "/run/host/home/u/src/tc"); err != nil || got == "" {
		t.Errorf("control: a root on the same filesystem that no rw grant reaches was refused: %q, %v", got, err)
	}
	ro := &Policy{Mounts: map[string]Mount{"/home/u/proj/sub": {Guest: "/home/u/proj/sub", Kind: KindBind, Host: "/home/u/proj/sub", Access: AccessRO}}}
	if _, err := ro.JudgeEngineToolchain(env, root); err != nil {
		t.Errorf("control: a read-only grant reaching the root was refused: %v", err)
	}
	env.mounts = nil
	if _, err := p.JudgeEngineToolchain(env, root); err != nil {
		t.Errorf("a host with no mount identity refused (the lexical result is acceptance): %v", err)
	}
	if _, err := p.JudgeEngineToolchain(mountsErrEnv{env}, root); err == nil || !strings.Contains(err.Error(), "cannot read this host's mount table") {
		t.Errorf("an unreadable mount table must refuse, got %v", err)
	}
}

// TestResolveEngineBinaryRefusesWritableAlias is the engine-binary twin of
// TestJudgeEngineToolchainRefusesWritableAlias: the binary is writable through
// a second mount of the target.
func TestResolveEngineBinaryRefusesWritableAlias(t *testing.T) {
	const bin = "/run/host/home/u/proj/sub/podman"
	env := aliasEnv("/home/u/proj/sub")
	env.files[bin] = true
	env.files["/run/host/home/u/src/podman"] = true
	p := rwTargetPolicy(t, env)

	_, err := p.ResolveEngineBinary(env, bin)
	if err == nil {
		t.Fatalf("ACCEPTED %s as the container engine", bin)
	}
	for _, w := range []string{bin + " cannot be this run's container engine", "/home/u/proj/sub", "second mount", "device 0:50", "uid 0, pid 1"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q:\n%v", w, err)
		}
	}

	if _, err := p.ResolveEngineBinary(env, "/run/host/home/u/src/podman"); err != nil {
		t.Errorf("control: a binary no rw grant reaches was refused: %v", err)
	}
	ro := &Policy{Mounts: map[string]Mount{"/home/u/proj/sub": {Guest: "/home/u/proj/sub", Kind: KindBind, Host: "/home/u/proj/sub", Access: AccessRO}}}
	if _, err := ro.ResolveEngineBinary(env, bin); err != nil {
		t.Errorf("control: a read-only grant reaching the binary was refused: %v", err)
	}
	env.mounts = nil
	if _, err := p.ResolveEngineBinary(env, bin); err != nil {
		t.Errorf("a host with no mount identity refused (the lexical result is acceptance): %v", err)
	}
	if _, err := p.ResolveEngineBinary(mountsErrEnv{env}, bin); err == nil || !strings.Contains(err.Error(), "cannot read this host's mount table") {
		t.Errorf("an unreadable mount table must refuse, got %v", err)
	}
}

// TestUnusableMountTableRefuses would catch the alias arm reading a mount
// table it cannot walk as "no overlap": a table with entries but no root mount
// is not a host that has no aliases, it is a table snug cannot answer from, and
// accepting every grant on it is a silent downgrade. The table here is the
// aliasMountinfo with its root line removed. It reaches Resolve, JudgeEngineToolchain
// and ResolveEngineBinary; the nil table (a fake modelling no mount table) is
// the control that still passes.
func TestUnusableMountTableRefuses(t *testing.T) {
	var rootless []HostMount
	for _, m := range parseMountinfo(aliasMountinfo) {
		if m.Path != "/" {
			rootless = append(rootless, m)
		}
	}
	if len(rootless) == 0 {
		t.Fatal("fixture: no mounts left")
	}
	const grant = "/run/host/home/u/.local/share/snug"
	want := []string{"cannot read this host's mount table", "no root entry"}

	t.Run("Resolve", func(t *testing.T) {
		env := aliasEnv(grant, "/home/u/proj/sub", "/home/u/.local/share/snug")
		k := aliasKinds["store"]
		env.mounts = rootless
		_, err := Resolve(withGrant("ro", grant), append(testDefaults, "peek"), k.ctx(), env)
		if err == nil {
			t.Fatalf("ACCEPTED ro %s on a mount table with no root entry", grant)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal lacks %q:\n%v", w, err)
			}
		}
		env.mounts = nil
		if _, err := Resolve(withGrant("ro", grant), append(testDefaults, "peek"), k.ctx(), env); err != nil {
			t.Errorf("control: a fake with no mount table was refused: %v", err)
		}
	})
	t.Run("JudgeEngineToolchain", func(t *testing.T) {
		env := aliasEnv("/home/u/proj/sub", "/run/host/home/u/proj/sub/tc")
		p := rwTargetPolicy(t, env)
		env.mounts = rootless
		_, err := p.JudgeEngineToolchain(env, "/run/host/home/u/proj/sub/tc")
		if err == nil {
			t.Fatal("ACCEPTED a toolchain root on a mount table with no root entry")
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal lacks %q:\n%v", w, err)
			}
		}
	})
	t.Run("ResolveEngineBinary", func(t *testing.T) {
		const bin = "/run/host/home/u/proj/sub/podman"
		env := aliasEnv("/home/u/proj/sub")
		env.files[bin] = true
		p := rwTargetPolicy(t, env)
		env.mounts = rootless
		_, err := p.ResolveEngineBinary(env, bin)
		if err == nil {
			t.Fatal("ACCEPTED an engine binary on a mount table with no root entry")
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal lacks %q:\n%v", w, err)
			}
		}
	})
}

// TestProcSelfRootSpellingOfAnAliasIsRefused would catch a grant spelled
// through /proc/self/root, which the kernel resolves to "/" for the reading
// process, escaping the comparison if canonicalisation stopped at the /proc
// path. The fake models the link as /proc/self/root -> /. The integration row
// is the one that shows the real /proc magic link resolving; this one shows
// the refusal is the alias arm and not a lexical match.
func TestProcSelfRootSpellingOfAnAliasIsRefused(t *testing.T) {
	const grant = "/proc/self/root/run/host/home/u/.local/share/snug"
	env := aliasEnv("/home/u/proj/sub", "/home/u/.local/share/snug", "/run/host/home/u/.local/share/snug")
	env.links["/proc/self/root"] = "/"
	k := aliasKinds["store"]
	_, err := Resolve(withGrant("ro", grant), append(testDefaults, "peek"), k.ctx(), env)
	if err == nil {
		t.Fatalf("ACCEPTED ro %s", grant)
	}
	for _, w := range []string{"engine store", "second mount", "device 0:50"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q:\n%v", w, err)
		}
	}
}
