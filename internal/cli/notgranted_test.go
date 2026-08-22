package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #59: a NOT GRANTED row that is wrong in the reassuring direction ──
//
// `covered` walked UPWARD only, so a bind BENEATH a candidate never marked that
// candidate covered. `--dry-run` printed
//
//	~/.claude (host's; snug generates its own here)
//
// under NOT GRANTED, twelve rows below a FILESYSTEM block binding
// `~/.claude/plugins` read-only. Both true about different things; together a
// false one — and what is actually under there was measured at 406 KB of plugin
// catalogue plus a third-party git repository whose `.git/config` is a command
// table.
//
// CLAUDE.md calls `--dry-run` the mechanism by which a human can trust snug at
// all. A row that is wrong in the reassuring direction is the worst kind of
// wrong on that screen, which is why this gets a test of its own rather than
// riding on a golden.
//
// WHY THERE WAS NO TEST BEFORE, and why this one builds a real tree: notGranted
// stats the candidate on the HOST and skips anything that is not there, so a
// policy with a synthetic Home exercises none of the candidate block. Every
// golden in this package has a synthetic Home, which is exactly why the fix
// moved no golden and why "the goldens are green" proved nothing here.

// homeWithDirs builds a real directory tree to serve as p.Home, so the
// os.Stat gate in notGranted actually passes.
func homeWithDirs(t *testing.T, rel ...string) string {
	t.Helper()
	home := t.TempDir()
	for _, r := range rel {
		if err := os.MkdirAll(filepath.Join(home, r), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// Mounts is keyed by guest path, so a fixture builds the map rather than a
// slice; the guest side is irrelevant to coverageOf, which walks Host.
func binds(hosts ...string) map[string]policy.Mount {
	m := map[string]policy.Mount{}
	for i, h := range hosts {
		guest := "/g/" + string(rune('a'+i))
		m[guest] = policy.Mount{Kind: policy.KindBind, Host: h, Guest: guest, From: []string{"@test"}}
	}
	return m
}

func TestNotGrantedDoesNotClaimAPathIsAbsentWhenSomethingBeneathItIsBound(t *testing.T) {
	home := homeWithDirs(t, ".claude/plugins", ".ssh")
	target := filepath.Join(home, "proj")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{
		Home:   home,
		Target: target,
		Mounts: binds(filepath.Join(home, ".claude", "plugins")),
	}

	got := strings.Join(notGranted(p), "\n")

	// THE BUG. Before the fix this row read as a bare name in the "none of
	// these" run, while a host path beneath it was bound read-only.
	for _, line := range strings.Split(got, "\n") {
		if !strings.Contains(line, "~/.claude") {
			continue
		}
		if strings.Contains(line, "PARTIAL") {
			continue
		}
		t.Errorf("NOT GRANTED lists ~/.claude as absent while %s is bound:\n%s\n"+
			"This is issue #59: `covered` walked upward only, so a mount BENEATH a candidate "+
			"never marked it covered. A row wrong in the REASSURING direction is the worst "+
			"kind of wrong on the screen CLAUDE.md calls the trust mechanism.",
			filepath.Join(home, ".claude", "plugins"), got)
	}

	// And it has to say the right thing, not merely stop saying the wrong one.
	// Asserted on the exact clause, including the singular verb: an earlier
	// draft read "1 host path BENEATH it are bound", which the loose assertion
	// this replaced did not notice.
	if !strings.Contains(got, "PARTIAL — 1 host path beneath it is bound") {
		t.Errorf("the PARTIAL row does not name what IS bound, or does not agree with "+
			"itself grammatically:\n%s", got)
	}
	if !strings.Contains(got, "the rest of it is not granted") {
		t.Errorf("the PARTIAL row does not say what is NOT granted, which makes it read as "+
			"\"granted\" — a lie in the other direction:\n%s", got)
	}

	// POSITIVE CONTROL. A candidate with nothing bound anywhere near it must
	// still appear as a plain absent name; without this, a fix that turned
	// every row into PARTIAL would pass every assertion above.
	if !strings.Contains(got, "~/.ssh") {
		t.Errorf("~/.ssh exists on this fixture and nothing is bound in it, so it must still "+
			"be listed as absent:\n%s", got)
	}
	if strings.Contains(got, "~/.ssh  PARTIAL") {
		t.Errorf("~/.ssh has nothing bound beneath it and must not be marked PARTIAL:\n%s", got)
	}
}

// The upward arm has to keep working: a bind AT or ABOVE a candidate means the
// host's copy is reachable, and the row must be suppressed entirely rather than
// downgraded to PARTIAL.
func TestNotGrantedStillSuppressesAFullyCoveredCandidate(t *testing.T) {
	home := homeWithDirs(t, ".ssh")
	p := &policy.Policy{
		Home:   home,
		Target: filepath.Join(home, "proj"),
		Mounts: binds(filepath.Join(home, ".ssh")),
	}
	got := strings.Join(notGranted(p), "\n")
	if strings.Contains(got, "~/.ssh") {
		t.Errorf("~/.ssh is bound outright and must not appear under NOT GRANTED at all:\n%s", got)
	}
}

// coverageOf is the predicate both call sites now share, so it is asserted
// directly as well: the rendering above could be right for one candidate and
// wrong for the sibling counter, which uses the same walk.
func TestCoverageOfWalksBothDirections(t *testing.T) {
	// /h/ab/c is the fixture that makes the downward arm's boundary
	// load-bearing. Without it, dropping the "/" from HasPrefix(m.Host, host+"/")
	// changed no test: every mount either matched both ways or neither.
	p := &policy.Policy{Mounts: binds("/h/a/b", "/h/c", "/h/ab/c")}
	for _, tc := range []struct {
		path string
		want coverage
		n    int
		why  string
	}{
		{"/h/a", coveragePartial, 1, "one bind is strictly beneath it — /h/ab/c is NOT, " +
			"and counting it would mean the downward arm lost its path boundary"},
		{"/h/a/b", coverageFull, 0, "the bind is exactly it"},
		{"/h/a/b/c", coverageFull, 0, "the bind is above it"},
		{"/h/c", coverageFull, 0, "exact"},
		{"/h/d", coverageNone, 0, "nothing at, above or below"},
		// The boundary that a naive HasPrefix gets wrong in both directions.
		{"/h/ab", coveragePartial, 1, "/h/ab/c is beneath it; /h/a/b is not"},
		{"/h/cc", coverageNone, 0, "/h/c must not match /h/cc"},
	} {
		got, n := coverageOf(p, tc.path)
		if got != tc.want || n != tc.n {
			t.Errorf("coverageOf(%q) = (%v, %d), want (%v, %d) — %s",
				tc.path, got, n, tc.want, tc.n, tc.why)
		}
	}
}

// The two STATIC host paths in the block went through no coverage check at all
// until issue #301's mechanical half: the whole line was appended
// unconditionally, so a run that bound the host's /tmp still printed
// /tmp/.X11-unix under NOT GRANTED. Same "wrong in the reassuring direction"
// shape as #59 above, on the same screen.
//
// A real host tree is NOT needed here, unlike the ~/ candidates: these two are
// absolute host paths and are deliberately not stat-gated, because a stat gate
// would make every golden in this package depend on whether the developer's box
// runs a display server.
func TestNotGrantedCoverageChecksTheStaticHostPaths(t *testing.T) {
	home := homeWithDirs(t)
	base := &policy.Policy{Home: home, Target: filepath.Join(home, "proj")}

	// POSITIVE CONTROL FIRST. With nothing bound, both names must be present —
	// otherwise every assertion below passes on a block that stopped printing
	// them for an unrelated reason.
	none := strings.Join(notGranted(base), "\n")
	for _, want := range []string{"/sys", "/tmp/.X11-unix"} {
		if !strings.Contains(none, want) {
			t.Fatalf("nothing is bound, so %s must be listed as not granted:\n%s", want, none)
		}
	}

	// THE BUG: bound outright and still listed.
	p := &policy.Policy{Home: home, Target: base.Target, Mounts: binds("/tmp")}
	got := strings.Join(notGranted(p), "\n")
	if strings.Contains(got, "/tmp/.X11-unix") {
		t.Errorf("the host's /tmp is bound, so /tmp/.X11-unix is reachable and must not be "+
			"listed as not granted (issue #301):\n%s", got)
	}
	// And the sibling must be unaffected — a fix that dropped the whole line
	// would pass the assertion above while deleting a true statement.
	if !strings.Contains(got, "/sys") {
		t.Errorf("/sys has nothing bound at or above it and must still be listed:\n%s", got)
	}

	// PARTIAL: a bind strictly beneath is neither "granted" nor "absent", and
	// saying either is a lie in one direction.
	deep := &policy.Policy{Home: home, Target: base.Target, Mounts: binds("/sys/fs/cgroup")}
	gotDeep := strings.Join(notGranted(deep), "\n")
	if !strings.Contains(gotDeep, "/sys  PARTIAL — 1 host path beneath it is bound") {
		t.Errorf("/sys has a bind strictly beneath it and must be marked PARTIAL:\n%s", gotDeep)
	}
	for _, line := range strings.Split(gotDeep, "\n") {
		if strings.HasPrefix(line, "/sys  /tmp") || line == "/sys" {
			t.Errorf("/sys is PARTIAL and must not also appear in the run of bare "+
				"absent names:\n%s", gotDeep)
		}
	}
}

// #301's ruling, asserted positively: the desktop-socket line is a claim about
// snug's MOUNT SET, and it is deliberately not derived from host environment
// and deliberately not coverage-checked.
//
// The residual it leaves is real and is stated on the screen in plain words:
// a profile granting the DIRECTORY one of those sockets sits in would make the
// claim false, and nothing here would notice. That is #292's shape (a grant of
// a directory is a grant of every socket in it) with #296 as its FIFO sibling
// — the issue numbers live here and in the source comment, never on the
// screen, because a human reading --dry-run has no tracker and a bare number
// leads nowhere.
//
// This test replaces the one that pinned the OLD shape ("the Wayland socket",
// "the session D-Bus socket" printed as bare names in the run of
// coverage-checked paths). It was changed, never deleted: the residual did not
// go away, it moved from a source comment nobody reading the screen ever sees
// onto the screen itself.
func TestTheDesktopSocketClaimIsAboutMountsNotAboutThisHost(t *testing.T) {
	home := homeWithDirs(t)

	// Distinctive host environment. If anyone ever derives the paths from it,
	// these strings land on the screen and the assertion below fails — which is
	// the whole point of setting them to something no real host would produce.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/DERIVED-FROM-ENV")
	t.Setenv("WAYLAND_DISPLAY", "wayland-DERIVED-FROM-ENV")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/DERIVED-FROM-ENV/bus,guid=deadbeef")

	// Bind the directory the session bus and the Wayland socket live in on this
	// host's spelling, AND /tmp. Under a coverage check both would be "granted"
	// and the claim would be silenced; it must not be, because the claim is
	// about what snug mounts and these binds are not snug mounting a desktop
	// socket.
	p := &policy.Policy{
		Home:   home,
		Target: filepath.Join(home, "proj"),
		Mounts: binds("/run/user/1000", "/tmp"),
	}
	got := strings.Join(notGranted(p), "\n")

	// Positive control: the claim is on screen at all. Without this, a run that
	// printed NOTHING under NOT GRANTED would satisfy every assertion below.
	if !strings.Contains(got, "snug mounts no desktop socket") {
		t.Fatalf("the desktop-socket claim is not on screen at all:\n%s", got)
	}

	// Not coverage-checked: the binds above did not silence it.
	if !strings.Contains(got, "no Wayland, no session D-Bus") {
		t.Errorf("binding /run/user/1000 and /tmp silenced the desktop-socket claim, so it "+
			"has acquired a coverage check. It is a claim about snug's MOUNT SET, not about "+
			"host paths, and a bind of the directory a socket sits in does not make it "+
			"false — it makes it UNCHECKED, which is the residual the next line states:\n%s", got)
	}

	// The residual is stated on the screen, in words, with no issue number.
	if !strings.Contains(got, "would make it false, and nothing") {
		t.Errorf("the residual is not stated on screen. It used to live only in a source "+
			"comment, which a human reading --dry-run never sees, and moving it here is what "+
			"#301 actually delivered:\n%s", got)
	}
	for _, n := range []string{"#292", "#296", "#301"} {
		if strings.Contains(got, n) {
			t.Errorf("%s appears on the --dry-run screen. A human reading it has no issue "+
				"tracker: a bare number leads nowhere and dates the artifact. Issue numbers "+
				"belong in the source comment and in this test:\n%s", n, got)
		}
	}

	// Not derived from host environment — the assertion that fails the day
	// someone reintroduces derivation.
	for _, leak := range []string{"DERIVED-FROM-ENV", "guid=", "unix:path="} {
		if strings.Contains(got, leak) {
			t.Errorf("%q reached the screen, so the desktop-socket line is being derived from "+
				"host environment. It must not be: that turns a true host-independent claim "+
				"into a host-dependent approximation of the same claim, and puts a "+
				"per-developer value into three golden fixtures and VERIFY.md:\n%s", leak, got)
		}
	}
}
