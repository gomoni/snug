package policy

import (
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAccountHome fails if AccountHome answers anything but the passwd
// entry's home, or lets an empty or relative one through. Nothing about the
// directory is looked up: whether it exists is Resolve's refusal.
func TestAccountHome(t *testing.T) {
	for _, tc := range []struct {
		name, pw      string
		want, wantErr string
	}{
		{"absolute", "/home/u", "/home/u", ""},
		{"a link spelling is kept", "/h", "/h", ""},
		{"not on this host", "/not/on/this/host", "/not/on/this/host", ""},
		{"empty", "", "", "gives this user no home directory"},
		{"relative", "home/u", "", "is not absolute"},
	} {
		got, err := AccountHome(tc.pw)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: got %q, %v, want error containing %q", tc.name, got, err, tc.wantErr)
			}
			if got != "" {
				t.Errorf("%s: refused but returned %q", tc.name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

// TestHostHOMEChangesNothing fails if the HOME snug was started with can move
// the sandbox's home or refuse a run. AccountHome takes no HOME, so this holds
// the property from the outside: with HOME set to another directory, to a
// relative path, to a missing one or to nothing, the policy resolved from the
// account's home is identical and nothing is refused. The control is that a
// different ACCOUNT home does change the policy, so the comparison can fail.
func TestHostHOMEChangesNothing(t *testing.T) {
	resolveWith := func(t *testing.T, pw string) *Policy {
		t.Helper()
		env := newFakeEnv()
		env.dirs["/home/u"] = true
		env.dirs["/srv/u"] = true
		home, err := AccountHome(pw)
		if err != nil {
			t.Fatalf("AccountHome(%q): %v", pw, err)
		}
		ctx := testCtx()
		ctx.Home, ctx.HostPasswdHome = home, home
		p, err := Resolve(testRegistry(), testDefaults, ctx, env)
		if err != nil {
			t.Fatalf("Resolve with home %q: %v", home, err)
		}
		return p
	}
	want := resolveWith(t, "/home/u")
	for _, hostHOME := range []string{"", "/srv/u", "/nowhere", "u", "relative/dir"} {
		t.Setenv("HOME", hostHOME)
		if got := resolveWith(t, "/home/u"); !reflect.DeepEqual(got, want) {
			t.Errorf("HOME=%q changed the resolved policy", hostHOME)
		}
	}
	if reflect.DeepEqual(resolveWith(t, "/srv/u"), want) {
		t.Error("control: a different account home resolved to the same policy")
	}
}

// TestUserLinkOnPasswdHomeRefusalText fails if the refusal for a home reached
// through a link a sandbox could have planted names a variable, or advises
// something that does not work. The account's home is a user-owned link;
// Resolve must call it the home directory, tell the human to change the
// account's home, and never mention HOME. Doing what it says (the real
// directory as the account's home) must then be accepted.
func TestUserLinkOnPasswdHomeRefusalText(t *testing.T) {
	env := newFakeEnv()
	env.hlLink(hlUser, "/h", "/home/u")

	ctx := testCtx()
	ctx.Home, ctx.HostPasswdHome = "/h", "/h"
	_, err := Resolve(testRegistry(), testDefaults, ctx, env)
	if err == nil {
		t.Fatal("a user-owned link on the account's home was accepted")
	}
	for _, want := range []string{
		"home directory /h resolves through the link /h -> /home/u",
		"make the account's home directory (getent passwd field 6) /home/u itself (usermod -d)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "HOME") {
		t.Errorf("refusal names HOME, which snug does not read: %v", err)
	}

	home, err := AccountHome("/home/u")
	if err != nil || home != "/home/u" {
		t.Fatalf("following the advice: AccountHome got %q, %v", home, err)
	}
	ctx.Home, ctx.HostPasswdHome = home, home
	if _, err := Resolve(testRegistry(), testDefaults, ctx, env); err != nil {
		t.Errorf("following the advice: Resolve still refuses: %v", err)
	}
}

// TestResolveRefusesAMissingPasswdHome fails if an account whose home does not
// exist on the host is let through: AccountHome looks nothing up, so Resolve
// must be the one to refuse.
func TestResolveRefusesAMissingPasswdHome(t *testing.T) {
	ctx := testCtx()
	ctx.Home, ctx.HostPasswdHome = "/nowhere", "/nowhere"
	_, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
	if err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("Resolve accepted a home directory that does not exist: %v", err)
	}
}

// TestHomeThatIsASystemTreeIsRefused fails if @home can be pointed at a
// directory every program reads (for /etc, ld.so.preload). The list is written
// out here and not read from systemTrees, so removing an entry from the
// variable fails this test instead of silently passing it. A home that merely
// resolves to one of them is refused too: the floor is on the canonical path.
// The controls are two homes that must stay legal, so a floor that refused
// everything would fail.
func TestHomeThatIsASystemTreeIsRefused(t *testing.T) {
	want := []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
		"/sbin", "/snug", "/sys", "/tmp", "/usr", "/var"}
	got := slices.Clone(systemTrees)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("systemTrees is %v, want exactly %v", got, want)
	}

	resolveHome := func(env *fakeEnv, home string) error {
		ctx := testCtx()
		ctx.Home = home
		ctx.HostPasswdHome = home
		_, err := Resolve(testRegistry(), testDefaults, ctx, env)
		return err
	}
	for _, h := range want {
		env := newFakeEnv()
		env.dirs[h] = true
		err := resolveHome(env, h)
		if err == nil || !strings.Contains(err.Error(), "is a system tree") {
			t.Errorf("home %q: got %v, want the system-tree refusal", h, err)
		}
	}

	env := newFakeEnv()
	env.dirs["/etc"] = true
	env.links["/h"] = "/etc"
	if err := resolveHome(env, "/h"); err == nil || !strings.Contains(err.Error(), "is a system tree") {
		t.Errorf("home /h, a root-owned link to /etc: got %v, want the system-tree refusal", err)
	}

	for _, ok := range []string{"/var/lib/svc", "/home/u"} {
		env := newFakeEnv()
		env.dirs[ok] = true
		if err := resolveHome(env, ok); err != nil {
			t.Errorf("control: home %q refused: %v", ok, err)
		}
	}
}

// texNode is one entry of texLinks.
type texNode struct {
	mode fs.FileMode // includes fs.ModeDir, fs.ModeSymlink or fs.ModeNamedPipe
	uid  uint32
	text string
}

// texLinks is a HostLinks over a map, with owners and modes, for
// TestTrustedExecutable: fakeEnv cannot give a regular file an owner.
type texLinks map[string]texNode

type texInfo struct {
	name string
	n    texNode
}

func (i texInfo) Name() string       { return i.name }
func (i texInfo) Size() int64        { return 0 }
func (i texInfo) Mode() fs.FileMode  { return i.n.mode }
func (i texInfo) ModTime() time.Time { return time.Time{} }
func (i texInfo) IsDir() bool        { return i.n.mode.IsDir() }
func (i texInfo) Sys() any           { return &syscall.Stat_t{Uid: i.n.uid} }

func (f texLinks) Lstat(p string) (fs.FileInfo, error) {
	n, ok := f[path.Clean(p)]
	if !ok {
		return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	return texInfo{path.Base(p), n}, nil
}

func (f texLinks) Readlink(p string) (string, error) {
	n, ok := f[path.Clean(p)]
	if !ok || n.mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
	}
	return n.text, nil
}

func texHost() texLinks {
	return texLinks{
		"/":               {mode: fs.ModeDir | 0o755},
		"/usr":            {mode: fs.ModeDir | 0o755},
		"/usr/bin":        {mode: fs.ModeDir | 0o755},
		"/usr/bin/getent": {mode: 0o755},
		"/bin":            {mode: fs.ModeSymlink | 0o777, text: "usr/bin"},
	}
}

// TestTrustedExecutable fails if snug would run, before any sandbox exists, a
// program a rootless user or a sandbox could have written or swapped: the
// file, every directory above it, and every link on the way must be root's.
// The overflow uid 65534 is how a root-owned file looks from inside a user
// namespace that does not map root; it is not root here. internal/getent's
// TestLocateRefusesWhatARootlessUserCouldHaveWritten drives the same predicate
// through Locate, and this table is the predicate's own.
func TestTrustedExecutable(t *testing.T) {
	const user = 1000
	for _, tc := range []struct {
		name   string
		uid    int
		path   string
		mutate func(texLinks)
		want   string // "" accepts
	}{
		{"root-owned file in root-owned dirs", user, "/usr/bin/getent", nil, ""},
		{"through a root-owned link in a root-owned dir", user, "/bin/getent", nil, ""},
		{"file owned by the user", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: 0o755, uid: user} }, "not owned by root"},
		{"file owned by the overflow uid", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: 0o755, uid: 65534} }, "not owned by root"},
		{"file group-writable", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: 0o775} }, "written by group or other"},
		{"file world-writable", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: 0o757} }, "written by group or other"},
		{"file not executable", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: 0o644} }, "not executable"},
		{"parent directory group-writable", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin"] = texNode{mode: fs.ModeDir | 0o775} }, "directory /usr/bin can be written by group or other (mode 0775)"},
		{"ancestor directory group-writable", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr"] = texNode{mode: fs.ModeDir | 0o775} }, "directory /usr can be written by group or other"},
		{"root directory group-writable", user, "/usr/bin/getent",
			func(f texLinks) { f["/"] = texNode{mode: fs.ModeDir | 0o775} }, "directory / can be written by group or other"},
		{"parent directory owned by the user", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin"] = texNode{mode: fs.ModeDir | 0o755, uid: user} }, "directory /usr/bin is owned by uid 1000, not root"},
		{"parent directory owned by the overflow uid", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin"] = texNode{mode: fs.ModeDir | 0o755, uid: 65534} }, "directory /usr/bin is owned by uid 65534, not root"},
		{"ancestor directory owned by the overflow uid", user, "/usr/bin/getent",
			func(f texLinks) { f["/"] = texNode{mode: fs.ModeDir | 0o755, uid: 65534} }, "directory / is owned by uid 65534, not root"},
		{"user-owned link on the path", user, "/bin/getent",
			func(f texLinks) { f["/bin"] = texNode{mode: fs.ModeSymlink | 0o777, uid: user, text: "usr/bin"} },
			"is a link"},
		{"root-owned link in a group-writable dir", user, "/bin/getent",
			func(f texLinks) { f["/"] = texNode{mode: fs.ModeDir | 0o775} }, "is a link"},
		{"any link when snug runs as root", 0, "/bin/getent", nil, "is a link"},
		{"a directory", user, "/usr/bin",
			nil, "not a regular file"},
		{"a named pipe", user, "/usr/bin/getent",
			func(f texLinks) { f["/usr/bin/getent"] = texNode{mode: fs.ModeNamedPipe | 0o755} }, "not a regular file"},
		{"missing", user, "/usr/bin/getent",
			func(f texLinks) { delete(f, "/usr/bin/getent") }, "does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := texHost()
			if tc.mutate != nil {
				tc.mutate(f)
			}
			err := TrustedExecutable(f, tc.uid, tc.path)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("got %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}
