package policy

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAccountHome(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/home/u"] = true
	env.dirs["/srv/u"] = true
	env.links["/h"] = "/home/u"

	for _, tc := range []struct {
		name, pw, home string
		want, wantErr  string
	}{
		{"HOME unset: the account's", "/home/u", "", "/home/u", ""},
		{"HOME the same", "/home/u", "/home/u", "/home/u", ""},
		{"HOME a link to the same directory keeps its spelling", "/home/u", "/h", "/h", ""},
		{"pw_dir a link, HOME its target", "/h", "/home/u", "/home/u", ""},
		{"HOME elsewhere", "/home/u", "/srv/u", "", `$HOME "/srv/u" is not this account's home directory "/home/u" (getent passwd); snug takes the home from the account. Unset HOME, or set HOME=/home/u`},
		{"empty pw_dir", "", "/home/u", "", "gives this user no home directory"},
		{"relative pw_dir", "home/u", "", "", "is not absolute"},
		{"relative HOME", "/home/u", "u", "", "$HOME \"u\" is not absolute; unset HOME, or set HOME=/home/u"},
		{"HOME missing", "/home/u", "/nowhere", "", "$HOME"},
	} {
		got, err := AccountHome(env, tc.pw, tc.home)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: got %q, %v, want error containing %q", tc.name, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

// TestAccountHome above is the table over AccountHome's whole contract; the
// tests below name the individual promises so a refactor that breaks one fails
// by that name.

// TestAccountHomeIsThePasswdHomeWhenHOMEIsUnset fails if an unset $HOME ever
// makes the run guess a home. The account's own spelling comes back unchanged,
// link and all, and nothing about it is looked up: the check that the
// directory exists is Resolve's.
func TestAccountHomeIsThePasswdHomeWhenHOMEIsUnset(t *testing.T) {
	env := newFakeEnv()
	env.links["/h"] = "/home/u"
	for _, pw := range []string{"/home/u", "/h", "/not/on/this/host"} {
		got, err := AccountHome(env, pw, "")
		if err != nil || got != pw {
			t.Errorf("pw_dir %q, HOME unset: got %q, %v, want %q", pw, got, err, pw)
		}
	}
}

// TestAccountHomeRefusesADivergentHOME fails if a $HOME naming a different
// directory than the account's is ever preferred, or quietly replaced, instead
// of refused. The refusal must name both directories and the fix, and must not
// hand back a home alongside the error.
func TestAccountHomeRefusesADivergentHOME(t *testing.T) {
	env := newFakeEnv()
	for _, d := range []string{"/srv/u", "/home", "/home/u2"} {
		env.dirs[d] = true
	}
	for _, home := range []string{"/srv/u", "/home", "/home/u2"} {
		got, err := AccountHome(env, "/home/u", home)
		if err == nil {
			t.Errorf("HOME %q accepted as %q for an account whose home is /home/u", home, got)
			continue
		}
		if got != "" {
			t.Errorf("HOME %q: refused but still returned %q", home, got)
		}
		for _, want := range []string{home, "/home/u", "Unset HOME, or set HOME=/home/u"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("HOME %q: refusal %q does not contain %q", home, err, want)
			}
		}
	}
}

// TestAccountHomeKeepsHOMEsSpellingOfTheSameDirectory fails if two spellings of
// one directory are refused as a mismatch (a Silverblue-shaped host has
// /home -> /var/home, and either spelling is what a login might export), or if
// the returned spelling is canonicalised: the human's own spelling is what a
// later refusal quotes when it tells them what to set HOME to.
func TestAccountHomeKeepsHOMEsSpellingOfTheSameDirectory(t *testing.T) {
	env := newFakeEnv()
	env.resolveParents = true
	env.links["/home"] = "/var/home"
	env.dirs["/var/home"] = true
	env.dirs["/var/home/u"] = true
	delete(env.dirs, "/home/u")
	// Control: the fixture really resolves the two spellings to one directory.
	a, errA := env.EvalSymlinks("/home/u")
	b, errB := env.EvalSymlinks("/var/home/u")
	if errA != nil || errB != nil || a != b || a != "/var/home/u" {
		t.Fatalf("control: fixture resolves /home/u to %q (%v) and /var/home/u to %q (%v)", a, errA, b, errB)
	}
	for _, tc := range []struct{ pw, home string }{
		{"/home/u", "/var/home/u"},
		{"/var/home/u", "/home/u"},
	} {
		got, err := AccountHome(env, tc.pw, tc.home)
		if err != nil || got != tc.home {
			t.Errorf("pw_dir %q, HOME %q: got %q, %v, want HOME's own spelling", tc.pw, tc.home, got, err)
		}
	}
}

// TestAccountHomeHasNoFallback fails if a missing, empty or unusable account
// home is ever answered from $HOME, or a broken $HOME from the account's
// home: invariant 5, in both directions.
func TestAccountHomeHasNoFallback(t *testing.T) {
	env := newFakeEnv()
	for _, tc := range []struct{ name, pw, home string }{
		{"empty pw_dir, HOME set", "", "/home/u"},
		{"empty pw_dir, HOME unset", "", ""},
		{"relative pw_dir, HOME set", "home/u", "/home/u"},
		{"HOME nonexistent, pw_dir fine", "/home/u", "/nowhere"},
		{"HOME relative, pw_dir fine", "/home/u", "u"},
	} {
		got, err := AccountHome(env, tc.pw, tc.home)
		if err == nil {
			t.Errorf("%s: answered %q instead of refusing", tc.name, got)
			continue
		}
		if got != "" {
			t.Errorf("%s: refused but returned %q", tc.name, got)
		}
	}
	_, err := AccountHome(env, "", "/home/u")
	if err == nil || !strings.Contains(err.Error(), "snug does not fall back to $HOME") {
		t.Errorf("the empty pw_dir refusal does not say it will not fall back: %v", err)
	}
}

// TestAccountHomeRefusesAMissingPasswdHome fails if an account whose home does
// not exist on the host is let through. With $HOME set, AccountHome cannot
// compare and refuses; with $HOME unset the comparison is skipped, so it is
// Resolve that must refuse, and this holds it to that.
func TestAccountHomeRefusesAMissingPasswdHome(t *testing.T) {
	env := newFakeEnv()
	_, err := AccountHome(env, "/nowhere", "/nowhere")
	if err == nil || !strings.Contains(err.Error(), "account database's home directory") {
		t.Errorf("HOME set: got %v, want a refusal naming the account database's home", err)
	}
	got, err := AccountHome(env, "/nowhere", "")
	if err != nil || got != "/nowhere" {
		t.Fatalf("control: with HOME unset the account's home comes back untouched: got %q, %v", got, err)
	}
	ctx := testCtx()
	ctx.Home = got
	ctx.HostPasswdHome = got
	_, err = Resolve(testRegistry(), testDefaults, ctx, env)
	if err == nil || !strings.Contains(err.Error(), "$HOME") {
		t.Errorf("Resolve accepted a home directory that does not exist: %v", err)
	}
}

// TestUserLinkOnPasswdHomeTheFixWorks fails if the refusal for a home reached
// through a link a sandbox could have planted advises something that does not
// work. The account's home is a user-owned link; Resolve refuses it and says to
// set HOME to the real directory; doing exactly that must then be accepted by
// both AccountHome (the account's home is a link to the same directory) and
// Resolve.
func TestUserLinkOnPasswdHomeTheFixWorks(t *testing.T) {
	env := newFakeEnv()
	env.hlLink(hlUser, "/h", "/home/u")

	ctx := testCtx()
	ctx.Home, ctx.HostPasswdHome = "/h", "/h"
	if got, err := AccountHome(env, "/h", ""); err != nil || got != "/h" {
		t.Fatalf("control: with HOME unset the account's own spelling comes back: %q, %v", got, err)
	}
	_, err := Resolve(testRegistry(), testDefaults, ctx, env)
	if err == nil || !strings.Contains(err.Error(), "set HOME to /home/u instead") {
		t.Fatalf("a user-owned link on the account's home: got %v, want the refusal advising HOME=/home/u", err)
	}

	home, err := AccountHome(env, "/h", "/home/u")
	if err != nil || home != "/home/u" {
		t.Fatalf("following the advice: AccountHome got %q, %v", home, err)
	}
	ctx.Home = home
	if _, err := Resolve(testRegistry(), testDefaults, ctx, env); err != nil {
		t.Errorf("following the advice: Resolve still refuses: %v", err)
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
