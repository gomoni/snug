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
