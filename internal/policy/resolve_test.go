package policy

import (
	"fmt"
	"io/fs"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

// ── a fake host, so these tests need no privileges and no real filesystem ────

type fakeInfo struct {
	name string
	dir  bool
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return fs.ModeDir }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.dir }
func (f fakeInfo) Sys() any           { return nil }

type fakeEnv struct {
	dirs  map[string]bool
	links map[string]string
	env   map[string]string
}

func newFakeEnv() *fakeEnv {
	return &fakeEnv{
		dirs: map[string]bool{
			"/usr": true, "/etc": true, "/opt": true,
			"/home/u": true, "/home/u/proj": true, "/home/u/proj/sub": true,
			"/home/u/proj/other": true, "/home/u/secrets": true,
		},
		links: map[string]string{},
		env:   map[string]string{"USER": "u"},
	}
}

func (f *fakeEnv) EvalSymlinks(p string) (string, error) {
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	if f.dirs[p] {
		return p, nil
	}
	return "", &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (f *fakeEnv) Stat(p string) (fs.FileInfo, error) {
	if f.dirs[p] {
		return fakeInfo{name: p, dir: true}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

func (f *fakeEnv) Getenv(k string) string { return f.env[k] }
func (f *fakeEnv) Uid() int               { return 1000 }
func (f *fakeEnv) Gid() int               { return 1000 }

func testRegistry() map[string]*Profile {
	return map[string]*Profile{
		"null": {Name: "null"},
		"sys": {Name: "sys",
			RO:       []string{"/usr", "/etc", "/opt"},
			Optional: []string{"/opt"},
			Symlink:  []Symlink{{At: "/bin", Target: "usr/bin"}},
		},
		"home":   {Name: "home", Tmpfs: []string{"{home}", "{home}/.cache"}},
		"cwd-rw": {Name: "cwd-rw", Include: []string{"home"}, RW: []string{"{target}"}},
		"dotdot": {Name: "dotdot", RO: []string{"{target_parent}"}},
		// Deliberately overlaps cwd-rw at the same guest path with weaker
		// access, to prove the join takes the max rather than the last writer.
		"cwd-ro":  {Name: "cwd-ro", RO: []string{"{target}"}},
		"default": {Name: "default", Include: []string{"sys", "cwd-rw", "dotdot"}},
	}
}

func testCtx() Context {
	return Context{Target: "/home/u/proj/sub", Home: "/home/u", Shell: "/bin/sh", Command: []string{"/bin/sh"}}
}

func mustResolve(t *testing.T, sel ...string) *Policy {
	t.Helper()
	p, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	return p
}

// canon renders the security-relevant content of a policy: the grants and their
// access. Provenance is excluded, exactly as it is from the join.
func canon(p *Policy) string {
	var b strings.Builder
	for _, m := range p.SortedMounts() {
		fmt.Fprintf(&b, "%s %s %s %s optional=%v\n", m.Guest, m.Kind, m.Access, m.Host, m.Optional)
	}
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "env %s=%s\n", k, p.Env[k])
	}
	return b.String()
}

// ── the invariants ───────────────────────────────────────────────────────────

// Resolve must be commutative. If it is not, the order profiles are named
// changes what the sandbox grants, and "profiles only relax" becomes unprovable.
func TestResolveIsCommutative(t *testing.T) {
	all := []string{"sys", "home", "cwd-rw", "dotdot", "cwd-ro"}
	want := canon(mustResolve(t, all...))

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		shuffled := append([]string(nil), all...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := canon(mustResolve(t, shuffled...)); got != want {
			t.Fatalf("order changed the result\norder: %v\n--- got\n%s\n--- want\n%s", shuffled, got, want)
		}
	}
}

// Selecting a profile twice must be identical to selecting it once.
func TestResolveIsIdempotent(t *testing.T) {
	for _, name := range []string{"sys", "cwd-rw", "dotdot", "default"} {
		once := canon(mustResolve(t, "sys", "cwd-rw", name))
		twice := canon(mustResolve(t, "sys", "cwd-rw", name, name))
		if once != twice {
			t.Errorf("%s: selecting twice differs from once\n--- once\n%s\n--- twice\n%s", name, once, twice)
		}
	}
}

// THE invariant: adding a profile may never remove or weaken a grant. This is
// the executable form of docs/DESIGN.md §2.4.
func TestResolveIsMonotone(t *testing.T) {
	base := []string{"sys", "cwd-rw"}
	basePol := mustResolve(t, base...)

	for name := range testRegistry() {
		with, err := Resolve(testRegistry(), append(append([]string{}, base...), name), testCtx(), newFakeEnv())
		if err != nil {
			continue // a conflict is a symmetric error, not a tightening
		}
		for guest, was := range basePol.Mounts {
			now, ok := with.Mounts[guest]
			if !ok {
				t.Errorf("adding %q REMOVED the grant at %s — profiles must only relax", name, guest)
				continue
			}
			if now.Access < was.Access {
				t.Errorf("adding %q WEAKENED %s from %s to %s — profiles must only relax",
					name, guest, was.Access, now.Access)
			}
		}
	}
}

// Pins the SCOPE of TestResolveIsMonotone, which is narrower than it looks.
//
// join is keyed by Guest, so it only fires at identical paths. Grants at
// different depths become two mounts, and effective access at a path is that of
// the deepest mount covering it. So a profile adding `ro {target}/.git` DOES
// reduce write access inside an otherwise writable target — verified by
// execution against a real sandbox, not inferred from the argv.
//
// That is deliberate: it is the same mechanism invariant 2 recommends for
// protecting .git, working in the other direction. Visibility stays monotone
// (rejectMasking); write access at a strict subpath does not. This test exists
// so nobody reads TestResolveIsMonotone as proving more than it does.
func TestDeeperGrantOverridesShallowerAccess(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/home/u/proj/sub/.git"] = true

	reg := testRegistry()
	reg["protect-git"] = &Profile{Name: "protect-git", RO: []string{"{target}/.git"}}

	p, err := Resolve(reg, []string{"sys", "cwd-rw", "protect-git"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Mounts["/home/u/proj/sub"].Access; got != AccessRW {
		t.Errorf("target access = %s, want rw", got)
	}
	if got := p.Mounts["/home/u/proj/sub/.git"].Access; got != AccessRO {
		t.Errorf(".git access = %s, want ro — the deeper grant should win", got)
	}
	// And the two must be separate mounts: if they had joined, .git would have
	// been folded up to rw and the protection would silently not exist.
	if len(p.Mounts["/home/u/proj/sub/.git"].From) == 0 {
		t.Error(".git has no grant of its own; it was folded into the target mount")
	}
}

// A symlink planted inside the target — by a previous sandbox run, which had
// write access there — must not divert a grant out of the sandbox.
func TestSymlinkInsideTargetCannotDivertAGrant(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/home/u/secrets"] = true
	env.links["/home/u/proj/sub/build"] = "/home/u/secrets" // the planted link

	reg := testRegistry()
	reg["build-rw"] = &Profile{Name: "build-rw", RW: []string{"{target}/build"}}

	_, err := Resolve(reg, []string{"sys", "cwd-rw", "build-rw"}, testCtx(), env)
	if err == nil {
		t.Fatal("a symlink inside the target diverted a grant to /home/u/secrets")
	}
	if !strings.Contains(err.Error(), "redirects it") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// But a symlink ABOVE the target is host configuration — /home -> /var/home on
// Silverblue-style hosts — and must still be followed, or snug is unusable
// there. Comparing against the lexical join under the canonical target rather
// than against the requested path is what keeps these two cases apart.
func TestSymlinkAboveTargetIsStillFollowed(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/var/home/u"] = true
	env.dirs["/var/home/u/proj"] = true
	env.dirs["/var/home/u/proj/sub"] = true
	env.links["/home/u"] = "/var/home/u"
	env.links["/home/u/proj"] = "/var/home/u/proj"
	env.links["/home/u/proj/sub"] = "/var/home/u/proj/sub"

	p, err := Resolve(testRegistry(), []string{"default"}, testCtx(), env)
	if err != nil {
		t.Fatalf("a host-level symlink above the target broke resolution: %v", err)
	}
	if p.Target != "/var/home/u/proj/sub" {
		t.Errorf("target = %s, want the canonicalised /var/home/u/proj/sub", p.Target)
	}
}

// A weaker grant at the same path must not win, no matter which order it
// arrives in. This is the join doing its job.
func TestAccessJoinTakesTheMaximum(t *testing.T) {
	for _, order := range [][]string{{"cwd-rw", "cwd-ro"}, {"cwd-ro", "cwd-rw"}} {
		p := mustResolve(t, append([]string{"sys"}, order...)...)
		if got := p.Mounts["/home/u/proj/sub"].Access; got != AccessRW {
			t.Errorf("order %v: target access = %s, want rw", order, got)
		}
	}
}

// ── fail-closed ──────────────────────────────────────────────────────────────

func TestFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		sel  []string
		ctx  func(Context) Context
		want string
	}{
		{"no profile", nil, nil, "no profile selected"},
		{"unknown profile", []string{"nope"}, nil, "unknown profile"},
		{"no runtime granted", []string{"cwd-rw"}, nil, "no OS runtime granted"},
		{"grants nothing", []string{"null"}, nil, "grant nothing"},
		{"target not visible", []string{"sys"}, nil, "is not visible"},
		{"missing target", []string{"default"}, func(c Context) Context {
			c.Target = "/home/u/nope"
			return c
		}, "does not exist"},
		{"empty target", []string{"default"}, func(c Context) Context {
			c.Target = ""
			return c
		}, "no target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			_, err := Resolve(testRegistry(), tc.sel, ctx, newFakeEnv())
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// The one remaining way to express subtraction was an overmount: an empty
// tmpfs on top of something a bind exposes. That is a mask rule in disguise and
// must be rejected, or "profiles only ever grant" stops being true.
func TestMaskingByOvermountIsRejected(t *testing.T) {
	reg := testRegistry()
	reg["etc-full"] = &Profile{Name: "etc-full", RO: []string{"/etc"}}
	reg["hide-profiled"] = &Profile{Name: "hide-profiled", Tmpfs: []string{"/etc/profile.d"}}

	_, err := Resolve(reg, []string{"sys", "etc-full", "cwd-rw", "hide-profiled"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a profile masked part of another profile's grant; the model has no subtraction")
	}
	if !strings.Contains(err.Error(), "hides what") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// REGRESSION, found by the redteam agent: rejectMasking originally inspected
// only KindTmpfs, so a BIND of an unrelated (e.g. empty) host directory over a
// path inside another grant hid it silently. /usr/share/misc went from three
// entries to zero with no error.
func TestMaskingByNestedBindIsRejected(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/share/misc"] = true
	env.dirs["/decoy"] = true

	reg := testRegistry()
	reg["mask-misc"] = &Profile{Name: "mask-misc", RO: []string{"/decoy:/usr/share/misc"}}

	_, err := Resolve(reg, []string{"sys", "cwd-rw", "mask-misc"}, testCtx(), env)
	if err == nil {
		t.Fatal("a bind of an unrelated host dir masked part of sys's /usr grant")
	}
	if !strings.Contains(err.Error(), "hides what") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// The legitimate nesting must keep working: cwd-rw lays rw {target} over
// dotdot's ro {target_parent}. That re-grants the SAME host tree at stronger
// access — a superset, not a mask — and the default profile depends on it.
func TestReGrantingTheSameTreeIsAllowed(t *testing.T) {
	p := mustResolve(t, "default")

	parent := p.Mounts["/home/u/proj"]
	target := p.Mounts["/home/u/proj/sub"]
	if parent.Access != AccessRO || target.Access != AccessRW {
		t.Fatalf("expected ro parent + rw target, got %s and %s", parent.Access, target.Access)
	}
	if target.Host != "/home/u/proj/sub" {
		t.Errorf("target should bind its own host path, got %s", target.Host)
	}
}

// The legitimate way to get "writable project except .git": grant the tree
// read-only and the parts you want to write separately. Purely additive, and
// the Access join gives the right answer at every path.
func TestNarrowerWriteIsExpressibleWithoutSubtraction(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/home/u/proj/sub/src"] = true
	env.dirs["/home/u/proj/sub/.git"] = true

	reg := testRegistry()
	reg["protect-git"] = &Profile{
		Name: "protect-git",
		RO:   []string{"{target}"},
		RW:   []string{"{target}/src"},
	}

	p, err := Resolve(reg, []string{"sys", "protect-git"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Mounts["/home/u/proj/sub/src"].Access; got != AccessRW {
		t.Errorf("src should be writable, got %s", got)
	}
	if got := p.Mounts["/home/u/proj/sub"].Access; got != AccessRO {
		t.Errorf("the tree itself should stay read-only, got %s", got)
	}
	if _, masked := p.Mounts["/home/u/proj/sub/.git"]; masked {
		t.Error(".git should need no grant of its own; it is simply covered by the read-only tree")
	}
}

// tmp-shared replaces the private /tmp with a host directory. The builtin
// tmpfs must step aside rather than colliding, and the result must be a bind —
// otherwise the whole point (the host can see it) is lost.
func TestSharedTmpReplacesThePrivateTmpfs(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/tmp/snug-1000-abc"] = true

	reg := testRegistry()
	reg["tmp-shared"] = &Profile{Name: "tmp-shared", RW: []string{"{host_tmpdir}:/tmp"}}

	ctx := testCtx()
	ctx.HostTmpDir = "/tmp/snug-1000-abc"

	p, err := Resolve(reg, []string{"sys", "cwd-rw", "tmp-shared"}, ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	m := p.Mounts["/tmp"]
	if m.Kind != KindBind {
		t.Errorf("/tmp is %s, want a bind of the host directory", m.Kind)
	}
	if m.Host != "/tmp/snug-1000-abc" || m.Access != AccessRW {
		t.Errorf("/tmp = %s %s, want /tmp/snug-1000-abc rw", m.Host, m.Access)
	}
}

// Without tmp-shared, /tmp must stay a private tmpfs — a sandbox whose /tmp
// leaked to the host by default would be a nasty surprise.
func TestTmpIsPrivateByDefault(t *testing.T) {
	if got := mustResolve(t, "default").Mounts["/tmp"].Kind; got != KindTmpfs {
		t.Errorf("/tmp is %s by default, want tmpfs", got)
	}
}

func TestIncludeCycleIsDetected(t *testing.T) {
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Include: []string{"b"}}
	reg["b"] = &Profile{Name: "b", Include: []string{"a"}}
	if _, err := Resolve(reg, []string{"a"}, testCtx(), newFakeEnv()); err == nil ||
		!strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected a cycle error, got %v", err)
	}
}

// Code-injection env vars are refused loudly rather than dropped silently, so
// the human learns why their profile did not do what it said.
func TestForbiddenEnvIsRefusedLoudly(t *testing.T) {
	reg := testRegistry()
	reg["bad"] = &Profile{Name: "bad", Env: []string{"LD_PRELOAD"}}
	env := newFakeEnv()
	env.env["LD_PRELOAD"] = "/tmp/evil.so"

	_, err := Resolve(reg, []string{"default", "bad"}, testCtx(), env)
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
		t.Fatalf("expected a refusal naming LD_PRELOAD, got %v", err)
	}
}

// bwrap cannot create a mountpoint at a symlink destination. Catch it at
// resolve time with provenance, not at runtime with a bare abort.
func TestSymlinkMountpointHazardIsRejected(t *testing.T) {
	reg := testRegistry()
	env := newFakeEnv()
	env.dirs["/usr/bin/tool"] = true
	reg["shim"] = &Profile{Name: "shim", RO: []string{"/usr/bin/tool:/bin/tool"}}

	_, err := Resolve(reg, []string{"sys", "cwd-rw", "shim"}, testCtx(), env)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink-mountpoint rejection, got %v", err)
	}
}

// ── what the sandbox must NOT contain ────────────────────────────────────────

// reachable reports whether a host path can be read from inside, through any
// grant. Used for negative assertions, which are the only ones that say
// anything about safety.
func reachable(p *Policy, host string) bool {
	for _, m := range p.Mounts {
		if m.Kind == KindBind && (m.Host == host || strings.HasPrefix(host, m.Host+"/")) {
			return true
		}
	}
	return false
}

// Deny-by-default is only real if unrelated host paths never appear.
func TestUngrantedPathsAreAbsent(t *testing.T) {
	p := mustResolve(t, "default")
	for _, absent := range []string{
		"/home/u/secrets", // a sibling of the project's ancestors
		"/sys",            // never granted
		"/tmp/.X11-unix",  // the GUI hole we do not open
		"/home/u/.ssh",    // the thing this whole project is about
	} {
		if reachable(p, absent) {
			t.Errorf("%s is reachable; it must never be mounted", absent)
		}
	}
}

// dotdot grants the target's PARENT, so the target's siblings are readable by
// design — that is the point of the profile (../other-package in a monorepo).
// What must stay out of reach is everything above the parent. Pinning this down
// means a future change to dotdot cannot quietly widen it by one level.
func TestDotdotGrantsTheParentAndNoHigher(t *testing.T) {
	p := mustResolve(t, "default")

	if !reachable(p, "/home/u/proj/other") {
		t.Error("a sibling of the target should be readable: dotdot grants the parent")
	}
	if reachable(p, "/home/u/secrets") {
		t.Error("dotdot leaked a level: the parent's siblings must stay unreachable")
	}

	// Without dotdot, the parent itself is gone.
	q := mustResolve(t, "sys", "cwd-rw")
	if reachable(q, "/home/u/proj/other") {
		t.Error("without dotdot the parent must not be granted at all")
	}
}

// The clamp is the only thing allowed to tighten, and it is applied by the
// human, never by a file.
func TestClampOnlyTightens(t *testing.T) {
	p := mustResolve(t, "default")
	if p.Mounts["/home/u/proj/sub"].Access != AccessRW {
		t.Fatal("precondition: target should start writable")
	}
	p.Apply(Clamp{ReadOnly: true})
	if got := p.Mounts["/home/u/proj/sub"].Access; got != AccessRO {
		t.Errorf("after --read-only clamp target access = %s, want ro", got)
	}
}
