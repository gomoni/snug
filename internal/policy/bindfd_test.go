package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestBindByPathIsComponentWise fails if the path-form exemption is a string
// prefix: "/procfoo" is an ordinary directory, and exempting it would hand a
// grant of it to bwrap as a path again, back inside the swap race the
// descriptor form closes.
func TestBindByPathIsComponentWise(t *testing.T) {
	for host, want := range map[string]bool{
		"/proc":            true,
		"/proc/sys":        true,
		"/proc/sys/kernel": true,
		"/procfoo":         false,
		"/procfoo/sys":     false,
		"/pro":             false,
		"/":                false,
		"/home/u/proc":     false,
		"/usr":             false,
	} {
		if got := BindByPath(host); got != want {
			t.Errorf("BindByPath(%q) = %v, want %v", host, got, want)
		}
	}
}

// pathBindFlags are every bwrap spelling that takes a host path as its source.
var pathBindFlags = []string{
	"--bind", "--bind-try", "--ro-bind", "--ro-bind-try", "--dev-bind", "--dev-bind-try",
}

// pathBindsOutsideProc returns the "flag source dest" triples in args whose
// source is a host path outside /proc.
func pathBindsOutsideProc(args []string) []string {
	var bad []string
	for i := 0; i+2 < len(args); i++ {
		if slices.Contains(pathBindFlags, args[i]) && !BindByPath(args[i+1]) {
			bad = append(bad, strings.Join(args[i:i+3], " "))
		}
	}
	return bad
}

// TestEveryBindCompilesToAnFDExceptProcfs fails if any selection in the golden
// table emits a bind with a host PATH outside /proc — the form bwrap opens
// itself, later, following whatever link a concurrent sandbox renamed into
// place — or if a --bind-fd line disagrees with the BindSources entry it
// stands for in guest, direction or number.
//
// Positive control: every case must emit at least one descriptor bind, so a
// BwrapArgs that emitted no binds at all would not pass as "no path binds".
// It reaches only policies the golden table resolves; selections outside it
// are covered by the sweep in internal/cli for the files that package pins.
func TestEveryBindCompilesToAnFDExceptProcfs(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv()
			if tc.env != nil {
				env = tc.env()
			}
			p, err := Resolve(testRegistry(), tc.sel, tc.ctx, env)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			args := p.BwrapArgs(1000, 1000)
			if bad := pathBindsOutsideProc(args); len(bad) > 0 {
				t.Errorf("path-form binds outside /proc, reachable by a swapped link:\n  %s", strings.Join(bad, "\n  "))
			}

			sources := p.BindSources()
			if len(sources) == 0 {
				t.Fatal("control: the policy has no bind sources, so the sweep measured nothing")
			}
			byGuest := map[string]Mount{}
			for _, m := range sources {
				byGuest[m.Guest] = m
			}
			seenFD := map[int]string{}
			seenGuest := map[string]int{}
			for i := 0; i+2 < len(args); i++ {
				if args[i] != "--ro-bind-fd" && args[i] != "--bind-fd" {
					continue
				}
				n, err := strconv.Atoi(args[i+1])
				if err != nil {
					t.Fatalf("%v: fd operand is not a number", args[i:i+3])
				}
				guest := args[i+2]
				m, ok := byGuest[guest]
				if !ok {
					t.Errorf("%v has no BindSources entry for %s", args[i:i+3], guest)
					continue
				}
				if want := (m.Access == AccessRW) == (args[i] == "--bind-fd"); !want {
					t.Errorf("%s: flag %s disagrees with access %v", guest, args[i], m.Access)
				}
				if stub := p.StubBindFDs()[guest]; stub != n {
					t.Errorf("%s: argv says fd %d, StubBindFDs says %d", guest, n, stub)
				}
				if prev, dup := seenFD[n]; dup {
					t.Errorf("fd %d used for both %s and %s", n, prev, guest)
				}
				seenFD[n] = guest
				seenGuest[guest]++
			}
			for _, m := range sources {
				if m.Optional {
					continue
				}
				if seenGuest[m.Guest] != 1 {
					t.Errorf("BindSources entry %s appears %d times in the argv, want exactly 1", m.Guest, seenGuest[m.Guest])
				}
			}
			if len(seenFD) != len(sources) {
				t.Errorf("argv has %d descriptor binds, BindSources has %d", len(seenFD), len(sources))
			}
		})
	}
}

// dataFDLines is every --file/--ro-bind-data operand pair, which is what the
// stub data numbering decides.
func dataFDLines(args []string) []string {
	var out []string
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--file" || args[i] == "--ro-bind-data" {
			out = append(out, strings.Join(args[i:i+3], " "))
		}
	}
	return out
}

// TestStubDataFDsDoNotShiftWhenBindsAreAdded fails if the bind descriptors are
// numbered ahead of the generated-file ones: every --file and --ro-bind-data
// line in every golden would then change whenever a grant is added, burying the
// one line a reviewer needs in noise. The control is that the bind numbers
// themselves do move (they come after).
func TestStubDataFDsDoNotShiftWhenBindsAreAdded(t *testing.T) {
	p := mustResolveDefaults(t)
	before := dataFDLines(p.BwrapArgs(1000, 1000))
	if len(before) == 0 {
		t.Fatal("control: no generated files in the argv, nothing to hold still")
	}
	bindBefore := p.StubBindFDs()["/zzz"]
	for _, guest := range []string{"/aaa", "/zzz"} {
		p.Mounts[guest] = Mount{Guest: guest, Host: guest, Kind: KindBind, Access: AccessRO}
	}
	after := dataFDLines(p.BwrapArgs(1000, 1000))
	if !slices.Equal(before, after) {
		t.Errorf("data fd lines moved when binds were added:\n%v\n%v", before, after)
	}
	if bindBefore != 0 || p.StubBindFDs()["/zzz"] == 0 {
		t.Errorf("control: the added bind did not get a stub number (%d -> %d)", bindBefore, p.StubBindFDs()["/zzz"])
	}
}

// canonLyingEnv answers EvalSymlinks truthfully until a path has been asked
// about lieAfter times, then reports lie[path]. Resolve's own checks see the
// honest answer and only the final canonical-host guard sees the lie, which is
// the state the guard exists for: a bind host that is not its own EvalSymlinks.
type canonLyingEnv struct {
	*fakeEnv
	lie      map[string]string
	lieAfter int
	asked    map[string]int
}

func (e *canonLyingEnv) EvalSymlinks(p string) (string, error) {
	e.asked[p]++
	if to, ok := e.lie[p]; ok && e.asked[p] > e.lieAfter {
		return to, nil
	}
	return e.fakeEnv.EvalSymlinks(p)
}

// TestResolveRefusesANonCanonicalBindHost fails if a bind whose host is not its
// own EvalSymlinks reaches the launcher: that open uses RESOLVE_NO_SYMLINKS
// and would refuse it with a message blaming a concurrent sandbox, when the
// cause is a snug bug and the refusal belongs at resolve time.
func TestResolveRefusesANonCanonicalBindHost(t *testing.T) {
	// Count how often an honest Resolve asks about /usr, so the lie starts
	// exactly at the guard's own call.
	probe := &canonLyingEnv{fakeEnv: newFakeEnv(), asked: map[string]int{}}
	if _, err := Resolve(testRegistry(), testDefaults, testCtx(), probe); err != nil {
		t.Fatalf("control: honest resolve failed: %v", err)
	}
	n := probe.asked["/usr"]
	if n == 0 {
		t.Fatal("control: /usr is never EvalSymlinks'd, so the guard has nothing to disagree with")
	}

	env := &canonLyingEnv{fakeEnv: newFakeEnv(), lie: map[string]string{"/usr": "/elsewhere/usr"},
		lieAfter: n - 1, asked: map[string]int{}}
	_, err := Resolve(testRegistry(), testDefaults, testCtx(), env)
	if err == nil {
		t.Fatal("resolved with a bind host that is not canonical")
	}
	for _, want := range []string{"snug bug", "not canonical", "/usr"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
}

// TestResolveStoresTheResolvedIdentityKeyPath fails if the pinned key path is
// stored as the human wrote it: it is opened with RESOLVE_NO_SYMLINKS, so
// /home -> /var/home (a root-owned link, as on an ostree host) would make
// every run fail with a swapped-link refusal for a path nobody swapped.
func TestResolveStoresTheResolvedIdentityKeyPath(t *testing.T) {
	env := newFakeEnv()
	// The fixture host mirrors /home under /var/home so every other grant
	// resolves through the link as well, as it would on such a host.
	for _, m := range []map[string]bool{env.dirs, env.files} {
		for k := range m {
			if strings.HasPrefix(k, "/home/") || k == "/home" {
				m["/var"+k] = true
			}
		}
	}
	env.dirs["/var"], env.dirs["/var/home"] = true, true
	env.links["/home"] = "/var/home"
	env.resolveParents = true
	sel := append(slices.Clone(testDefaults), "pinned")
	p, err := Resolve(identityRegistry("~/.ssh/id.pub"), sel, testCtx(), env)
	if err != nil {
		t.Fatalf("a root-owned /home link on the key path was refused: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Key != "/var/home/u/.ssh/id.pub" {
		t.Errorf("stored key = %+v, want /var/home/u/.ssh/id.pub (no link left to follow)", p.Identity)
	}
}

// TestRootOwnedLinkInARootOwnedDirStaysTrusted fails if the parent-directory
// rule over-reaches into refusing every host link: /home -> /var/home sits in
// a root-owned 0755 "/", exactly as a distribution writes it, and is followed.
func TestRootOwnedLinkInARootOwnedDirStaysTrusted(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o555} {
		env := newFakeEnv()
		env.links["/opt/x"] = "/home/u"
		env.dirModes["/opt"] = mode
		if _, links, err := authorableLinks(env, 1000, "/opt/x"); err != nil || len(links) != 0 {
			t.Errorf("mode %04o: links=%+v err=%v, want the link trusted", mode, links, err)
		}
	}
	env := newFakeEnv()
	env.links["/opt/x"] = "/home/u"
	env.dirModes["/opt"] = 0o755
	if _, links, _ := authorableLinks(env, 0, "/opt/x"); len(links) != 1 {
		t.Errorf("control: under uid 0 the same link must still be authorable, got %+v", links)
	}
}

// TestRootOwnedLinkParentRuleVariants fails if any one of the three ways a
// directory can be writable by a non-root actor stops making a root-owned link
// in it authorable. rename(2) keeps the link's owner, so root ownership of the
// link alone says nothing about who chose where it sits. Each variant has its
// own sibling control with the writable bit removed.
func TestRootOwnedLinkParentRuleVariants(t *testing.T) {
	for _, c := range []struct {
		name        string
		owner       uint32
		mode        os.FileMode
		authorable  bool
		controlMode os.FileMode
	}{
		{"sticky world-writable root dir (1777)", 0, os.ModeSticky | 0o777, true, os.ModeSticky | 0o755},
		{"group-writable root dir", 0, 0o775, true, 0o755},
		{"world-writable root dir", 0, 0o757, true, 0o755},
		{"user-owned dir", 1000, 0o755, true, 0o755},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := newFakeEnv()
			env.links["/opt/x"] = "/home/u"
			env.dirOwners["/opt"], env.dirModes["/opt"] = c.owner, c.mode
			_, links, err := authorableLinks(env, 1000, "/opt/x")
			if err != nil || len(links) != 1 {
				t.Fatalf("links=%+v err=%v, want authorable", links, err)
			}
			if c.owner == 0 {
				env.dirModes["/opt"] = c.controlMode
				if _, links, _ := authorableLinks(env, 1000, "/opt/x"); len(links) != 0 {
					t.Errorf("control: mode %04o was still judged authorable: %+v", c.controlMode, links)
				}
			}
		})
	}
}

// TestGoldenFilesHaveNoPathBindOutsideProc is the file-level form of the sweep
// above, over every committed bwrap golden in this package, including the
// floor, which no selection in goldenCases covers. It reads the artifact a
// human approves, so it also fails if the file was updated by hand.
func TestGoldenFilesHaveNoPathBindOutsideProc(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.bwrap.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("control: no golden files found (%v)", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && slices.Contains(pathBindFlags, fields[0]) && !BindByPath(fields[1]) {
				t.Errorf("%s:%d: %s", f, n+1, line)
			}
		}
	}
}
