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
			// The directories the environment fixtures NAME, so they can also
			// GRANT them — §2.5's coupling rule is why every one of these exists.
			// A fixture that named a path it did not grant used to resolve
			// happily, which is exactly the profile-side mistake the rule stops.
			"/home/u/.local/bin": true,
			"/usr/bin":           true, "/usr/share/pkgconfig": true,
			"/opt/tools/bin": true, "/opt/first/bin": true, "/opt/bin": true,
			"/opt/a": true, "/opt/b": true, "/opt/a/bin": true, "/opt/b/bin": true,
			"/srv/bin": true,
			// A directory whose NAME CONTAINS A SPACE. It is here so a fixture
			// can grant one, which is what
			// TestPrependsDifferingOnlyInElementBoundariesDisagree needs: the
			// space-joined key it exists to catch is only wrong when an element
			// legitimately contains a space, and the coupling rule refuses a
			// prepend of a path the profile has not granted.
			"/opt/a b": true,
			// A bind nested inside @home's tmpfs, mirroring @claude's real shape —
			// the sanitise-C fixtures (nested-bin) need this to exist so it can be
			// GRANTED as well as named (§2.5's coupling rule).
			"/home/u/.local/bin/tool": true,
		},
		links: map[string]string{},
		// EDITOR is here so a fixture profile can actually re-admit something
		// past --clearenv. Widening canon() to render the environment asserts
		// nothing unless a fixture exercises it — the same trap the canon
		// comment already records for the network scalars.
		env: map[string]string{
			"USER": "u", "EDITOR": "vim",
			// One granted element and one that is not, so `sanitise` has
			// something to keep AND something to drop. A filter fixture where
			// everything survives tests only half the filter.
			"PKG_CONFIG_PATH": "/usr/lib64/pkgconfig:/srv/pkgconfig",
		},
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

func (f *fakeEnv) LookupEnv(k string) (string, bool) {
	v, ok := f.env[k]
	return v, ok
}
func (f *fakeEnv) Uid() int { return 1000 }
func (f *fakeEnv) Gid() int { return 1000 }

// testRegistry is a fake standing in for the loaded profile set. The names
// mirror the real ones, sigil included (policy.Sigil): the resolver treats a
// name as opaque, but SNUG_PROFILES and every provenance string end up in the
// goldens, and a golden describing names no user ever types is a golden nobody
// can review. The unmarked entries (`nothing`, `cwd-ro`, `combo`) are
// deliberate — they play the part of a profile written in
// ~/.config/snug/profiles.d, which is exactly where a composition point like
// `combo`, or a fixture that grants nothing without being `@null`, belongs.
func testRegistry() map[string]*Profile {
	return map[string]*Profile{
		// Unmarked deliberately: there is no @null builtin — a profile
		// that grants nothing is a preference, not something snug ships. This
		// fixture plays the part of a hand-written profiles.d entry that
		// happens to grant nothing, which TestFailsClosed still needs to
		// exercise "profiles selected but nothing granted" separately from
		// "nothing selected at all".
		"nothing": {Name: "nothing"},
		"@sys": {Name: "@sys",
			RO:       []string{"/usr", "/etc", "/opt"},
			Optional: []string{"/opt"},
			Symlink:  []Symlink{{At: "/bin", Target: "usr/bin"}},
		},
		// Matches the real @home in base.toml, entry for entry, because the
		// .bwrap.txt goldens are built from this registry: a fake @home with
		// fewer grants than the shipped one makes those files describe a sandbox
		// no user gets. It had two of the five tmpfs directories and none of the
		// XDG block.
		"@home": {Name: "@home",
			Tmpfs: []string{"{home}", "{home}/.cache", "{home}/.config",
				"{home}/.local/state", "{home}/.local/share"},
			Environ: EnvGrants{Set: map[string]string{
				"XDG_CONFIG_HOME": "{home}/.config",
				"XDG_CACHE_HOME":  "{home}/.cache",
				"XDG_STATE_HOME":  "{home}/.local/state",
				"XDG_DATA_HOME":   "{home}/.local/share",
			}}},
		"@cwd-rw":    {Name: "@cwd-rw", Include: []string{"@home"}, RW: []string{"{target}"}},
		"@parent-ro": {Name: "@parent-ro", RO: []string{"{target_parent}"}},
		// Deliberately overlaps @cwd-rw at the same guest path with weaker
		// access, to prove the join takes the max rather than the last writer.
		//
		// It also carries the `path` entry, and that placement is deliberate:
		// canon() renders the environment, so the commutativity and idempotence
		// property tests cover PATH assembly for free — while keeping it OFF the
		// profiles in testDefaults, which the goldens are built from. A fake
		// @home with a grant the real one does not have would make the goldens
		// describe a sandbox no user gets.
		//
		// It GRANTS the directory it names on PATH, because §2.5's coupling rule
		// requires the profile that names a path to be the profile that put a
		// node on the chain to it. The real @claude satisfies the same rule a
		// different way — it includes @home, whose tmpfs covers all of $HOME —
		// and both spellings are legal; this one is the narrower.
		"cwd-ro": {Name: "cwd-ro", RO: []string{"{target}", "{home}/.local/bin"},
			Environ: EnvGrants{Merge: map[string][]string{"PATH": {"{home}/.local/bin"}}}},
		// Carries the environment grants, for the same reason `netty` carries
		// the network scalars: canon() renders them, so the commutativity and
		// idempotence tests only cover them if a fixture uses them. Two profiles
		// naming ONE variable and one directory is deliberate — that is the case
		// where provenance could come out fold-order-dependent.
		"envy": {Name: "envy", RO: []string{"/opt/tools/bin"}, Environ: EnvGrants{
			Inherit: []string{"EDITOR"},
			Merge:   map[string][]string{"PATH": {"/opt/tools/bin"}}}},
		"envy-too": {Name: "envy-too", RO: []string{"/opt/tools/bin"}, Environ: EnvGrants{
			Inherit: []string{"EDITOR"},
			Merge:   map[string][]string{"PATH": {"/opt/tools/bin"}}}},
		// `set` agreeing with `envy`'s `inherit` of the same name: equal claims
		// join rather than conflicting, and neither verb outranks the other
		// (CALL 2). The fake host has EDITOR=vim, which is what makes this an
		// agreement rather than a refusal.
		"setty": {Name: "setty", Environ: EnvGrants{
			Set: map[string]string{"EDITOR": "vim"}}},
		// The front of PATH. Exactly ONE profile in the commutativity set may
		// hold it — a second is a refusal, which is its own test.
		"firsty": {Name: "firsty", RO: []string{"/opt/first/bin"}, Environ: EnvGrants{
			Prepend: map[string][]string{"PATH": {"/opt/first/bin"}}}},
		// The filter, over the fake host's PKG_CONFIG_PATH.
		"sanity": {Name: "sanity", Environ: EnvGrants{
			Sanitise: []string{"PKG_CONFIG_PATH"}}},
		// Names a directory that is ALSO in the base PATH, so
		// dedup-to-the-earliest-band is exercised by the property tests rather
		// than only by the one test that names it.
		"dupe-path": {Name: "dupe-path", RO: []string{"/usr/bin"}, Environ: EnvGrants{
			Merge: map[string][]string{"PATH": {"/usr/bin"}}}},
		// Two profiles asking for the same git mode, so the commutativity and
		// idempotence sweeps actually exercise the scalar. Rendering it in canon
		// asserts nothing unless a fixture sets it — the same trap the canon
		// comment records for the network scalars.
		"gitty":     {Name: "gitty", Git: "extract"},
		"gitty-too": {Name: "gitty-too", Git: "extract"},
		// A pure composition point with a two-level include chain
		// (combo -> @cwd-rw -> @home). The builtin `default` used to be one of
		// these; it is now the `defaults` SETTING (internal/profile/defaults.go),
		// but the resolver must still handle include-only profiles, so the fake
		// registry keeps one.
		"combo": {Name: "combo", Include: []string{"@sys", "@cwd-rw", "@parent-ro"}},
		// Carries the SCALARS, so the commutativity and idempotence property
		// tests actually exercise them now that canon() renders them. Without a
		// fixture setting one, widening canon() would assert nothing: the
		// last-writer-wins bug in address/gateway/mtu was invisible to
		// TestResolveIsCommutative for exactly that reason. Kept off testDefaults
		// so the goldens still describe the sandbox a real user gets.
		"netty": {Name: "netty", Network: "egress", DNS: true, Publish: []int{4000, 3000},
			Address: "10.13.13.2/24", Gateway: "10.13.13.1", MTU: 1400, Podman: "socket"},
		// Same values, different name: two profiles agreeing on a scalar must
		// join, not conflict, whichever order they are folded in.
		"netty-too": {Name: "netty-too", Network: "egress", Publish: []int{3000},
			Address: "10.13.13.2/24"},
		// Sigil-marked and mirroring the real @podman-socket in base.toml
		// (include sys+home+net, podman=socket) rather than reusing `netty`,
		// which also carries scalars (address/gateway/mtu/publish) that would
		// make the podman-socket golden noisy with values unrelated to what
		// it is meant to review — the stub and the container proxy hole.
		"@podman-socket": {Name: "@podman-socket", Include: []string{"@sys", "@home"},
			Network: "egress", DNS: true, Podman: "socket"},
		// The sanitise-C regression fixtures (envresolve_test.go's
		// TestSanitiseXxx tests below TestSanitiseKeepsGrantedElementsInHostOrder).
		// PATH deliberately, not PKG_CONFIG_PATH — the band ordering that makes
		// the finding exploitable is PATH's, because it precedes /usr/bin.
		"sanity-path": {Name: "sanity-path", Environ: EnvGrants{Sanitise: []string{"PATH"}}},
		// A bind nested INSIDE @home's tmpfs, mirroring @claude's real shape
		// (base.toml: {home}/.local/bin/claude). Its own directory,
		// {home}/.local/bin, is NOT granted — only the file below it is — which
		// is exactly the shape TestSanitiseUsesTheDeepestCoveringMount needs.
		"nested-bin": {Name: "nested-bin", RO: []string{"{home}/.local/bin/tool"}},
		// A minimal OS-runtime grant that does NOT cover /usr — Validate refuses
		// any policy with no mount at exactly /usr or /bin ("no OS runtime
		// granted"), so a selection that deliberately excludes @sys (to test that
		// something ELSE covering /usr, or nothing at all, changes the verdict)
		// still needs SOME runtime grant to be legal. /opt exists in every
		// fakeEnv and is not /usr, which is the point.
		"runtime-bin": {Name: "runtime-bin", RO: []string{"/opt:/bin"}},
	}
}

// testDefaults mirrors profile.BuiltinDefaults() — what a bare `snug <dir>`
// selects. internal/policy cannot import internal/profile (that is the
// dependency the other way round), so the list is repeated here; if it ever
// diverges, the goldens are describing a sandbox no user gets.
var testDefaults = []string{"@sys", "@home", "@cwd-rw", "@parent-ro"}

func testCtx() Context {
	return Context{Target: "/home/u/proj/sub", Home: "/home/u", Shell: "/bin/sh", Command: []string{"/bin/sh"}}
}

// testCtxWithPodmanShim is testCtx plus a detected podman shim — the fixture
// for every test exercising podmanstub.go, so a fake distrobox-shaped host
// need not be reinvented per test.
func testCtxWithPodmanShim() Context {
	ctx := testCtx()
	ctx.HostShims = []HostShim{
		{Name: "podman", Path: "/usr/bin/podman", Resolved: "/usr/bin/distrobox-host-exec"},
	}
	return ctx
}

// mustResolveDefaults resolves what a bare `snug <dir>` produces.
func mustResolveDefaults(t *testing.T) *Policy {
	t.Helper()
	return mustResolve(t, testDefaults...)
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
//
// It covers the SCALARS as well, and that is not decoration. It used to render
// Mounts and Env only, so TestResolveIsCommutative could not see a break in
// Net.Address, Net.Publish, Identity or Podman — and three of those were
// last-writer-wins at the time, decided by which profile the sorted fold reached
// last. A commutativity test that does not render a field does not test it.
func canon(p *Policy) string {
	var b strings.Builder
	for _, m := range p.SortedMounts() {
		fmt.Fprintf(&b, "%s %s %s %s optional=%v authored=%v\n",
			m.Guest, m.Kind, m.Access, m.Host, m.Optional, m.Authored)
	}
	// The environment is rendered ENTRY BY ENTRY, not as its joined value, and
	// that is the same lesson as the paragraph above one level down. The joined
	// value hides which verb produced an entry, which profile got the credit,
	// and what a filter dropped — all three of which --dry-run prints as a trust
	// artifact (§2.8). If any of them depended on fold order, that screen would
	// lie and a commutativity test comparing only strings would stay green.
	for _, name := range p.EnvNames() {
		v := p.Env[name]
		shape := "scalar"
		if v.List {
			shape = fmt.Sprintf("list sep=%q", v.Sep)
		}
		fmt.Fprintf(&b, "env %s %s\n", name, shape)
		for i, e := range v.Entries {
			fmt.Fprintf(&b, "env %s [%d] %s %s %v %q\n", name, i, e.Value, e.Verb, e.From, e.Note)
		}
		for _, d := range v.Dropped {
			fmt.Fprintf(&b, "env %s drop %s %s %v\n", name, d.Value, d.Reason, d.From)
		}
	}
	fmt.Fprintf(&b, "net mode=%s dns=%v publish=%v nameservers=%v address=%s gateway=%s mtu=%d\n",
		p.Net.Mode, p.Net.DNS, p.Net.Publish, p.Net.Nameservers,
		p.Net.Address, p.Net.Gateway, p.Net.MTU)
	fmt.Fprintf(&b, "podman %s\n", p.Podman)
	// Git joins by max like every other scalar, and it was added without this
	// line — the exact omission this function's own comment warns about, three
	// scalars later. A commutativity test that does not render a field does not
	// test it.
	fmt.Fprintf(&b, "git %s owner=%s\n", p.Git, p.IdentityOwner)
	fmt.Fprintf(&b, "topology %s\n", p.Topology)
	fmt.Fprintf(&b, "identity %+v\n", p.Identity)
	fmt.Fprintf(&b, "profiles %v\n", p.Profiles)
	return b.String()
}

// ── the invariants ───────────────────────────────────────────────────────────

// Resolve must be commutative. If it is not, the order profiles are named
// changes what the sandbox grants, and "profiles only relax" becomes unprovable.
func TestResolveIsCommutative(t *testing.T) {
	all := []string{"@sys", "@home", "@cwd-rw", "@parent-ro", "cwd-ro", "netty", "netty-too",
		"envy", "envy-too", "setty", "firsty", "sanity", "dupe-path", "gitty", "gitty-too"}
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
	for _, name := range []string{"@sys", "@cwd-rw", "@parent-ro", "combo"} {
		once := canon(mustResolve(t, "@sys", "@cwd-rw", name))
		twice := canon(mustResolve(t, "@sys", "@cwd-rw", name, name))
		if once != twice {
			t.Errorf("%s: selecting twice differs from once\n--- once\n%s\n--- twice\n%s", name, once, twice)
		}
	}
}

// THE invariant: adding a profile may never remove or weaken a grant. This is
// the executable form of .claude/design/INDEX.md §2.4.
func TestResolveIsMonotone(t *testing.T) {
	base := []string{"@sys", "@cwd-rw"}
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

	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "protect-git"}, testCtx(), env)
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

	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "build-rw"}, testCtx(), env)
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

	p, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
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
	for _, order := range [][]string{{"@cwd-rw", "cwd-ro"}, {"cwd-ro", "@cwd-rw"}} {
		p := mustResolve(t, append([]string{"@sys"}, order...)...)
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
		{"no runtime granted", []string{"@cwd-rw"}, nil, "no OS runtime granted"},
		{"grants nothing", []string{"nothing"}, nil, "grant nothing"},
		{"target not visible", []string{"@sys"}, nil, "is not visible"},
		{"missing target", testDefaults, func(c Context) Context {
			c.Target = "/home/u/nope"
			return c
		}, "does not exist"},
		{"empty target", testDefaults, func(c Context) Context {
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

	_, err := Resolve(reg, []string{"@sys", "etc-full", "@cwd-rw", "hide-profiled"}, testCtx(), newFakeEnv())
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

	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "mask-misc"}, testCtx(), env)
	if err == nil {
		t.Fatal("a bind of an unrelated host dir masked part of sys's /usr grant")
	}
	if !strings.Contains(err.Error(), "hides what") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// sanitise-C's monotonicity argument (envresolve.go's keepHostElement doc
// comment, §2 of the design) rests entirely on rejectMasking: the one shape
// that would turn a KEPT element into a DROPPED one — a tmpfs appearing
// beneath an existing bind — is refused before Resolve ever returns. That
// coupling is invisible from keepHostElement's own code, so it is asserted
// here directly: relaxing rejectMasking must fail THIS test loudly, rather
// than quietly re-breaking TestEnvIsMonotoneAsASet's guarantee somewhere no
// one is looking.
func TestSanitiseMonotonicityRestsOnRejectMasking(t *testing.T) {
	reg := testRegistry()
	// A tmpfs installed beneath @sys's `ro /usr` bind is masking: it would
	// shadow /usr/bin, and if it were ever allowed, a profile adding it after
	// another profile's PATH entry survived sanitise as a bind could flip that
	// entry to a tmpfs-covered one — an element sanitise would then drop,
	// which is monotonicity failing from a totally unrelated profile choice.
	reg["mask-usr"] = &Profile{Name: "mask-usr", Tmpfs: []string{"/usr/local"}}
	if _, err := Resolve(reg, []string{"@sys", "@cwd-rw", "mask-usr"}, testCtx(), newFakeEnv()); err == nil {
		t.Fatal("a tmpfs installed beneath @sys's /usr bind was accepted; sanitise's " +
			"monotonicity depends on rejectMasking refusing exactly this arrangement")
	}

	// POSITIVE CONTROL: a tmpfs nested inside ANOTHER tmpfs is not masking —
	// there is nothing underneath a fresh tmpfs to hide — and must keep
	// resolving. Without this, the assertion above could be passing merely
	// because Resolve refuses every tmpfs nested inside anything, which would
	// prove nothing about the specific coupling this test exists to pin.
	reg["scratch"] = &Profile{Name: "scratch", Include: []string{"@home"}, Tmpfs: []string{"{home}/scratch"}}
	if _, err := Resolve(reg, []string{"@sys", "@cwd-rw", "scratch"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: a tmpfs nested inside another tmpfs must resolve fine, got %v", err)
	}
}

// The legitimate nesting must keep working: cwd-rw lays rw {target} over
// parent-ro's ro {target_parent}. That re-grants the SAME host tree at stronger
// access — a superset, not a mask — and the default selection depends on it.
func TestReGrantingTheSameTreeIsAllowed(t *testing.T) {
	p := mustResolveDefaults(t)

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

	p, err := Resolve(reg, []string{"@sys", "protect-git"}, testCtx(), env)
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

	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "tmp-shared"}, ctx, env)
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
	if got := mustResolveDefaults(t).Mounts["/tmp"].Kind; got != KindTmpfs {
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
	reg["bad"] = &Profile{Name: "bad", Environ: EnvGrants{Inherit: []string{"LD_PRELOAD"}}}
	env := newFakeEnv()
	env.env["LD_PRELOAD"] = "/tmp/evil.so"

	_, err := Resolve(reg, append(append([]string{}, testDefaults...), "bad"), testCtx(), env)
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
		t.Fatalf("expected a refusal naming LD_PRELOAD, got %v", err)
	}
}

// ...and it must fire on a host where the variable is not set at all.
//
// The refusal used to sit INSIDE the "is it set on the host" check, so the same
// profile passed review on a machine where LD_PRELOAD happened to be unset and
// failed on one where it was set. Whether a grant is legal is a property of the
// profile; it must not depend on who launched snug (§4.4).
func TestForbiddenEnvIsRefusedEvenWhenUnsetOnTheHost(t *testing.T) {
	env := newFakeEnv()
	if _, ok := env.LookupEnv("LD_PRELOAD"); ok {
		t.Fatal("control: this fixture host must NOT have LD_PRELOAD set, or the test " +
			"proves nothing about the unconditional refusal")
	}
	err := refusalForbiddenEnvUnsetOnHost(t)
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
		t.Fatalf("expected a refusal naming LD_PRELOAD on a host that does not have it, got %v", err)
	}
}

// A variable the host has set to the EMPTY STRING is set, and must reach the
// sandbox as a present, empty variable. NO_COLOR's specification is "set to any
// value, including empty", so dropping it means snug silently turns colour back
// on — and more generally, "empty means absent" is wrong for every flag (§3.2,
// §4.6a).
func TestSetButEmptyHostVariableReachesTheSandbox(t *testing.T) {
	reg := testRegistry()
	reg["flags"] = &Profile{Name: "flags", Environ: EnvGrants{Inherit: []string{"NO_COLOR", "PAGER"}}}
	env := newFakeEnv()
	env.env["NO_COLOR"] = ""

	p, err := Resolve(reg, append(append([]string{}, testDefaults...), "flags"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	v, ok := p.EnvValue("NO_COLOR")
	if !ok {
		t.Error("NO_COLOR was set to the empty string on the host and did not reach the " +
			"sandbox at all; set-but-empty is SET, and for a flag it is the whole meaning")
	}
	if v != "" {
		t.Errorf("NO_COLOR = %q, want the host's empty value verbatim", v)
	}
	// CONTROL: a name the host genuinely does not have must still be absent, or
	// the assertion above would pass on a resolver that invents every variable a
	// profile mentions.
	if _, ok := p.EnvValue("PAGER"); ok {
		t.Error("PAGER is unset on this host but reached the sandbox anyway")
	}

	// And it must survive all the way into the argv: bwrap delivers
	// `--setenv NO_COLOR ''` as a present, empty variable (measured, §0).
	args := p.BwrapFlags(1000, 1000, func(string) int { return 10 })
	found := false
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "NO_COLOR" && args[i+2] == "" {
			found = true
		}
	}
	if !found {
		t.Errorf("no `--setenv NO_COLOR ''` in the argv: %v", args)
	}
}

// bwrap cannot create a mountpoint at a symlink destination. Catch it at
// resolve time with provenance, not at runtime with a bare abort.
func TestSymlinkMountpointHazardIsRejected(t *testing.T) {
	reg := testRegistry()
	env := newFakeEnv()
	env.dirs["/usr/bin/tool"] = true
	reg["shim"] = &Profile{Name: "shim", RO: []string{"/usr/bin/tool:/bin/tool"}}

	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "shim"}, testCtx(), env)
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
	p := mustResolveDefaults(t)
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

// parent-ro grants the target's PARENT, so the target's siblings are readable by
// design — that is the point of the profile (../other-package in a monorepo).
// What must stay out of reach is everything above the parent. Pinning this down
// means a future change to parent-ro cannot quietly widen it by one level.
func TestParentRoGrantsTheParentAndNoHigher(t *testing.T) {
	p := mustResolveDefaults(t)

	if !reachable(p, "/home/u/proj/other") {
		t.Error("a sibling of the target should be readable: parent-ro grants the parent")
	}
	if reachable(p, "/home/u/secrets") {
		t.Error("parent-ro leaked a level: the parent's siblings must stay unreachable")
	}

	// Without parent-ro, the parent itself is gone.
	q := mustResolve(t, "@sys", "@cwd-rw")
	if reachable(q, "/home/u/proj/other") {
		t.Error("without parent-ro the parent must not be granted at all")
	}
}

// Nothing tightens. The clamp (`--read-only`) used to be the one exception —
// restriction applied by a human after resolution — and it is gone with the
// flag. A resolved policy now has exactly one way to grant less: fewer
// profiles. If a `Clamp`, an `Apply`, or any other demote appears here again,
// the model has grown a carve-out and every monotonicity argument in
// .claude/design/INDEX.md needs re-reading.
func TestPolicyHasNoRestrictionOperation(t *testing.T) {
	p := mustResolveDefaults(t)
	if got := p.Mounts["/home/u/proj/sub"].Access; got != AccessRW {
		t.Fatalf("target access = %s, want rw", got)
	}
	// Selecting a read-only view of the same tree does not demote the writable
	// grant: the join takes the maximum, in both directions.
	q := mustResolve(t, "@sys", "@cwd-rw", "cwd-ro")
	if got := q.Mounts["/home/u/proj/sub"].Access; got != AccessRW {
		t.Errorf("adding cwd-ro demoted the target to %s; profiles may only ever grant", got)
	}
}

// A profile may put a directory on PATH. It grants nothing by doing so — an
// unmounted directory on PATH is inert — but a profile that mounts a binary
// somewhere nothing looks is broken on its own terms, which is what `@claude`
// was: it bound ~/.local/bin/claude and `snug -p @claude . -- claude` answered
// "execvp claude: No such file or directory".
func TestProfilePathReachesPATH(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw", "cwd-ro")
	got, _ := p.EnvValue("PATH")

	if !strings.HasPrefix(got, "/home/u/.local/bin:") {
		t.Errorf("PATH = %q; a profile's directory must come FIRST, or a distro "+
			"binary of the same name wins over the one the profile provided", got)
	}
	for _, base := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(got, base) {
			t.Errorf("PATH = %q, missing the base entry %q", got, base)
		}
	}
}

// Two profiles contributing directories must produce the same PATH whichever
// order they were named in. PATH is the only env var assembled from several
// profiles, so it is the one place an order dependence could hide.
func TestPATHIsOrderIndependent(t *testing.T) {
	reg := testRegistry()
	reg["tools-a"] = &Profile{Name: "tools-a", RO: []string{"/opt/a/bin"},
		Environ: EnvGrants{Merge: map[string][]string{"PATH": {"/opt/a/bin"}}}}
	reg["tools-b"] = &Profile{Name: "tools-b", RO: []string{"/opt/b/bin"},
		Environ: EnvGrants{Merge: map[string][]string{"PATH": {"/opt/b/bin"}}}}

	one, err := Resolve(reg, []string{"@sys", "@cwd-rw", "tools-a", "tools-b"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	two, err := Resolve(reg, []string{"tools-b", "tools-a", "@cwd-rw", "@sys"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	onePath, _ := one.EnvValue("PATH")
	twoPath, _ := two.EnvValue("PATH")
	if onePath != twoPath {
		t.Errorf("naming the profiles in a different order changed PATH:\n  %s\n  %s",
			onePath, twoPath)
	}
	for _, want := range []string{"/opt/a/bin", "/opt/b/bin"} {
		if !strings.Contains(onePath, want) {
			t.Errorf("PATH = %q, missing %q", onePath, want)
		}
	}
}

// ── @null is retired, and the floor it used to name has no profile ──────────

// The lattice floor, asserted directly. Before this test, deny-by-default was
// only ever INFERRED — from the absence of a leak somewhere else. Resolve's
// "other" return contract (see its doc comment) applies here: an empty
// selection is refused by Validate, but the non-nil policy it returns
// alongside the error must be EXACTLY the four things Resolve authors itself,
// and nothing a profile could have granted.
func TestEmptySelectionResolvesToTheFloor(t *testing.T) {
	p, err := Resolve(testRegistry(), nil, testCtx(), newFakeEnv())
	if p == nil {
		t.Fatal("Resolve(nil selection) returned a nil policy; --dry-run would have nothing " +
			"to show for a refused selection")
	}
	if err == nil {
		t.Fatal("Resolve(nil selection) returned no error; the floor must still be refused by Validate")
	}

	want := map[string]bool{"/proc": true, "/dev": true, "/tmp": true, "/etc/resolv.conf": true}
	if len(p.Mounts) != len(want) {
		t.Fatalf("floor has %d mount(s), want exactly %d: %v", len(p.Mounts), len(want), mountGuests(p))
	}
	for g := range want {
		if _, ok := p.Mounts[g]; !ok {
			t.Errorf("floor is missing %s", g)
		}
	}
	for _, m := range p.Mounts {
		if m.Kind == KindBind {
			t.Errorf("floor contains a KindBind mount at %s (from %s); an empty selection "+
				"must grant nothing from the host — that is deny-by-default itself, not "+
				"something inferred from a leak test elsewhere", m.Guest, m.Host)
		}
	}
}

func mountGuests(p *Policy) []string {
	out := make([]string, 0, len(p.Mounts))
	for g := range p.Mounts {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// A profile name snug used to ship and deliberately removed is a different
// mistake from a typo: the fix is not "see: snug profile list", it is "here is
// what replaced it". Mirrors TestRetiredPublishAutoIsAHardError's shape
// (internal/profile/file_test.go), which does the same for a retired TOML key.
//
// Both routes that used to reach @null go through UnknownProfile: -p @null via
// Resolve -> expand, and `snug profile show @null` via a direct registry miss
// (cmd/snug/config.go). Exercising UnknownProfile itself, rather than only
// Resolve, is what actually pins the second route — see
// TestRetiredNullProfileIsANamedError in test/integration for the CLI-level
// (exit code) half of this.
func TestRetiredNullProfileNamesTheFix(t *testing.T) {
	_, err := Resolve(testRegistry(), append(append([]string{}, testDefaults...), "@null"), testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("-p @null was accepted; there is no @null profile any more")
	}
	if !strings.Contains(err.Error(), "--no-defaults") {
		t.Errorf("the error should point at --no-defaults, got: %v", err)
	}

	err = UnknownProfile(testRegistry(), "@null")
	if err == nil || !strings.Contains(err.Error(), "--no-defaults") {
		t.Errorf("UnknownProfile(@null), the route `snug profile show @null` takes, should "+
			"point at --no-defaults, got: %v", err)
	}

	// CONTROL: a name that is merely unknown — never shipped, never retired —
	// must get the ordinary "unknown profile" message, not the retired one.
	// Without this, retiredProfiles could swallow every miss and nothing here
	// would distinguish "retired" from "typo".
	err = UnknownProfile(testRegistry(), "@zzz-not-a-real-profile")
	if err == nil {
		t.Fatal("expected an error for a genuinely unknown profile")
	}
	if strings.Contains(err.Error(), "--no-defaults") {
		t.Errorf("a genuinely unknown profile must NOT get the retired-@null message: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("a genuinely unknown profile should say so plainly: %v", err)
	}
}

// ── Positive controls for the nesting rules ─────────────────────────────────
//
// The rules Validate now enforces (RULE 2, RULE 4) are permissive in three
// shipped arrangements, and a future tightening must not be able to break any
// of them silently. Each of these pins one arrangement directly, with a fake
// fixture shaped exactly like the real profile it stands in for — so it needs
// no host state and runs the same everywhere. See refusals_test.go for the
// negative side of the same rules.

// @git-ro and @claude both bind host FILES inside @home's writable tmpfs
// ({home}/.gitconfig, {home}/.claude/settings.json, ...). RULE 2 must keep
// allowing a bind nested inside a KindTmpfs mount, or every identity file and
// every @claude grant breaks on the first invocation. An earlier draft of the
// rule (R2 in the findings report) would have included KindTmpfs among the
// masking outer kinds; this is the test that draft would have failed.
func TestNestedBindInsideHomeTmpfsIsAllowed(t *testing.T) {
	reg := testRegistry()
	reg["id-file"] = &Profile{Name: "id-file", Include: []string{"@home"}, RO: []string{"/opt:{home}/.gitconfig"}}

	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "id-file"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("a bind INSIDE @home's tmpfs must stay legal — @git-ro and @claude depend on "+
			"it for every identity and credential file they expose: %v", err)
	}
	m, ok := p.Mounts["/home/u/.gitconfig"]
	if !ok || m.Kind != KindBind || m.Host != "/opt" {
		t.Fatalf("the nested grant did not survive resolution: %+v", p.Mounts["/home/u/.gitconfig"])
	}
}

// The real @sys profile (internal/profile/profiles/base.toml) binds
// /usr/share/ca-certificates a SECOND time, nested inside its own /usr bind —
// same profile, same underlying host tree, deeper guest path. RULE 2's
// KindBind row must keep allowing that: "yes iff the inner is a bind of
// H/rel". This mirrors the real shape with a fake host tree, so it does not
// depend on ca-certificates actually existing on the machine running the test.
func TestSysStyleNestedBindOfTheSameTreeIsAllowed(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/usr/share/ca-certificates"] = true

	reg := testRegistry()
	sys := *reg["@sys"]
	sys.RO = append(append([]string(nil), sys.RO...), "/usr/share/ca-certificates")
	reg["@sys"] = &sys

	p, err := Resolve(reg, []string{"@sys", "@cwd-rw"}, testCtx(), env)
	if err != nil {
		t.Fatalf("a bind nested inside another bind of the SAME host tree, from the SAME "+
			"profile, must stay legal — this is @sys's own shape: %v", err)
	}
	m, ok := p.Mounts["/usr/share/ca-certificates"]
	if !ok || m.Access != AccessRO {
		t.Fatalf("nested grant did not survive resolution: %+v", p.Mounts["/usr/share/ca-certificates"])
	}
}

// publish is a SET, unioned — not a list appended to. `publish = [3000]` in
// two profiles used to resolve to [3000 3000], reaching pasta's -t as a
// duplicate and depending on fold order for WHICH copy survived where. Two
// profiles agreeing on an address, and one repeating a port the other already
// named, must join cleanly rather than conflict or duplicate.
func TestPublishUnionsAndAddressesAgree(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw", "netty", "netty-too")

	if p.Net.Address != "10.13.13.2/24" {
		t.Errorf("address = %q, want 10.13.13.2/24 — two profiles agreeing on a scalar must join, not conflict", p.Net.Address)
	}

	want := []int{3000, 4000}
	if len(p.Net.Publish) != len(want) {
		t.Fatalf("publish = %v, want %v — repeating a port across profiles must not duplicate it", p.Net.Publish, want)
	}
	for i, v := range want {
		if p.Net.Publish[i] != v {
			t.Errorf("publish = %v, want %v", p.Net.Publish, want)
		}
	}
}

// BindSocket's provenance used to be hard-coded "(identity)" for every socket
// it granted, so the CONTAINER socket — a completely different hole, opened by
// @podman-socket — read in --dry-run as though the ssh identity machinery had
// granted it. `from` is now a parameter; this pins both call shapes.
func TestBindSocketProvenanceIsParameterized(t *testing.T) {
	p := mustResolveDefaults(t)
	p.BindSocket("/run/host/podman.sock", "/run/snug/containers.sock", "(containers)")

	m, ok := p.Mounts["/run/snug/containers.sock"]
	if !ok {
		t.Fatal("BindSocket did not install a mount")
	}
	if len(m.From) != 1 || m.From[0] != "(containers)" {
		t.Errorf("provenance = %v, want [(containers)] — a hard-coded \"(identity)\" would "+
			"misattribute the container hole to the ssh identity machinery", m.From)
	}
	if !m.Authored {
		t.Error("BindSocket must mark its mount Authored: it is snug's own socket, not a profile's grant")
	}
}

// A relative entry would be resolved against whatever the payload's cwd happens
// to be, which is a different directory per invocation.
func TestRelativeProfilePathIsRefused(t *testing.T) {
	reg := testRegistry()
	reg["bad"] = &Profile{Name: "bad", Environ: EnvGrants{Merge: map[string][]string{"PATH": {"bin"}}}}
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "bad"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a relative path entry was accepted")
	}
	if !strings.Contains(err.Error(), "must be an absolute path") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestAUserProfileNamedNullBeatsTheRetiredTable — red team. `null` is a
// perfectly legal name for a profile someone defines on their own host, and the
// retired table used to be consulted FIRST, so `snug profile show @null` told
// that user their profile did not exist and lectured them about a builtin they
// had never heard of. A name is only retired when nothing on this host defines
// it.
func TestAUserProfileNamedNullBeatsTheRetiredTable(t *testing.T) {
	reg := testRegistry()
	reg["null"] = &Profile{Name: "null", Source: "/home/u/.config/snug/profiles.d/mine.toml"}

	err := UnknownProfile(reg, "@null")
	if err == nil {
		t.Fatal("@null must still be an error — the sigil marks a profile snug ships")
	}
	if strings.Contains(err.Error(), "--no-defaults") {
		t.Errorf("with a user profile named null present, @null must point at THEIR profile, "+
			"not recite snug's reasoning about a builtin they never had: %v", err)
	}
	for _, want := range []string{"one of yours", "mine.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q so the user can find their own file: %v", want, err)
		}
	}

	// CONTROL: with NO user profile of that name, the retired message must
	// survive intact. Without this, the fix above could have deleted the retired
	// table's only reason to exist and this file would not notice.
	if err := UnknownProfile(testRegistry(), "@null"); err == nil ||
		!strings.Contains(err.Error(), "--no-defaults") {
		t.Errorf("control: with no user profile named null, @null must still name the fix: %v", err)
	}
}

// {variable} expansion is ONE PASS: substituted text is never re-scanned.
//
// The loop this replaced restarted the search over the whole result after each
// substitution, so a value that expanded to text containing braces was expanded
// again — and the values are paths the human running snug chose, not profile
// text. A directory literally named `{home}` therefore resolved to a DIFFERENT
// directory than the one on the command line, writable and persistent, while the
// one the user named was read-only.
func TestExpandVarsDoesNotRescanItsOwnOutput(t *testing.T) {
	vars := map[string]string{
		"home":   "/home/u",
		"target": "/proj/{target}", // pathological on purpose: expands to itself
		"brace":  "{home}",
	}

	cases := []struct{ in, want string }{
		// The live case: a path COMPONENT that looks like a placeholder is
		// literal text, because nothing in it was substituted.
		// The double slash is expansion's long-standing behaviour — {home} is
		// itself absolute — and splitSpec runs filepath.Clean afterwards. It is
		// spelled out rather than cleaned here so this test measures expansion
		// alone.
		{"/tmp/x/{home}/sub", "/tmp/x//home/u/sub"},
		// …and a substituted value that CONTAINS a placeholder is committed as
		// it stands. Re-scanning here is what made a real directory resolve to
		// somewhere else entirely.
		{"{brace}/bin", "{home}/bin"},
		// Ordinary cases, so a function that stopped expanding altogether would
		// not pass the three above.
		{"{home}/.config", "/home/u/.config"},
		{"~/.ssh", "/home/u/.ssh"},
		{"/usr/bin", "/usr/bin"},
		{"{home}:{home}/g", "/home/u:/home/u/g"},
	}
	for _, tc := range cases {
		got, err := expandVars(tc.in, vars)
		if err != nil {
			t.Errorf("expandVars(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("expandVars(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Self-reference must TERMINATE. Under the old loop this case did not
	// fail, it SPUN — 224% CPU, RSS flat at 18 MB, killed at 12 seconds — so it
	// is run with a deadline rather than inline: a regression here would
	// otherwise hang the whole package until go test's global timeout, and a
	// hang reads as infrastructure trouble rather than as this bug.
	done := make(chan string, 1)
	go func() {
		got, _ := expandVars("{target}/x", vars)
		done <- got
	}()
	select {
	case got := <-done:
		if got != "/proj/{target}/x" {
			t.Errorf("expandVars(\"{target}/x\") = %q, want %q — the substituted value "+
				"contains a placeholder and must be committed as it stands", got, "/proj/{target}/x")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expandVars did not terminate on a value that expands to itself; it is " +
			"re-scanning its own output")
	}

	// The errors still fire, and on the FIRST placeholder rather than on
	// whatever a second pass produced.
	if _, err := expandVars("/a/{nosuch}/b", vars); err == nil {
		t.Error("an unknown variable was accepted")
	}
	if _, err := expandVars("/a/{unterminated", vars); err == nil {
		t.Error("an unterminated variable was accepted")
	}
}
