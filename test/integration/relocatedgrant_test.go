//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #588, end to end: bwrap resolves a mount's destination component by
// component INSIDE the sandbox, against whatever a covering bind already
// supplies there. A host symlink inside a bound tree can therefore divert a
// second profile's mountpoint onto a FIRST profile's own grant, changing that
// grant's access with no refusal and no line of --dry-run naming it — MEASURED
// (issue #588, bubblewrap 0.12.0): a writable grant, shadowed by a read-only
// one steered through exactly this shape, became read-only, snug exit 0.
//
// The unit half (internal/policy/relocatedgrant_test.go) exercises the walk
// directly against a fake host. This half is what the unit test cannot show:
// a real bwrap run against a real host symlink, and whether the canary a
// payload tries to write actually lands.
//
// relocatedGrantFixture builds the ticket's own reproduction: victim grants rw
// on w; evil grants ro on a translating cover (host/cover -> guest/G) plus a
// second mount whose host source is w/mnt — a subdirectory of victim's own
// tree — at guest G/sub/mnt. A real host symlink cover/sub -> w is what steers
// evil's second mount onto victim's grant when bwrap resolves it inside the
// sandbox.
func relocatedGrantFixture(t *testing.T) (env []string, proj, canary string) {
	t.Helper()

	root := t.TempDir()
	w := filepath.Join(root, "w")
	wmnt := filepath.Join(w, "mnt")
	cover := filepath.Join(root, "cover")
	for _, d := range []string{wmnt, cover} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(w, filepath.Join(cover, "sub")); err != nil {
		t.Fatal(err)
	}

	victim := "[profile.victim]\n" +
		"description = \"the reproduction: a writable grant a later profile's cover can steer into\"\n" +
		"rw = [\"" + w + "\"]\n"
	evil := "[profile.evil]\n" +
		"description = \"the reproduction: a translating cover whose host symlink lands on victim's grant\"\n" +
		"# ABUSE: without the fix this downgrades victim's rw grant to ro with no refusal.\n" +
		"ro = [\"" + cover + ":" + root + "/G\", \"" + wmnt + ":" + root + "/G/sub/mnt\"]\n"

	proj, _ = target(t)
	env = writeProfiles(t, map[string]string{"victim": victim, "evil": evil})
	canary = filepath.Join(wmnt, "canary")
	return env, proj, canary
}

// TestRelocatedGrantIsRefusedBeforeBwrapRuns is the ticket's own two-profile
// invocation. It must be refused during Validate, before bwrap ever runs — so
// the payload never starts (r.ran stays false, the same witness every
// negative in this suite uses) and the canary it would have written is never
// created on the host.
func TestRelocatedGrantIsRefusedBeforeBwrapRuns(t *testing.T) {
	budget(t)
	requireSandbox(t)

	env, proj, canary := relocatedGrantFixture(t)

	r := runEnv(t, env, []string{"--no-defaults", "-p", "@sys", "-p", "@target-rw", "-p", "victim", "-p", "evil"},
		proj, "touch "+canary+" && echo WRITABLE || echo READ-ONLY")

	if r.ran {
		t.Errorf("the payload ran at all — snug should have refused this policy before bwrap "+
			"started:\n%s", r.out)
	}
	if r.code == 0 {
		t.Errorf("snug ACCEPTED a policy where evil's cover steers a mount onto victim's own "+
			"grant through a host symlink:\n%s", r.out)
	}
	// "victim" is not named here: evil's own cover is what carries the
	// symlink, so both halves of the sentence are evil's — the refusal does
	// not have to identify who is shadowed, only that the mount evil wrote
	// does not land where evil wrote it.
	for _, want := range []string{"evil", "not where it lands", "Fix: grant"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, r.out)
		}
	}
	// THE ASSERTION: nothing touched the host. r.ran already says the payload
	// never started, but the filesystem is the witness that matters — bwrap
	// itself never ran either, so there is no process left to have raced this.
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatalf("the canary exists on the host (stat err=%v) even though the payload never "+
			"ran — something created it outside this refusal", err)
	}
}

// TestVictimGrantStaysWritableWithoutTheEvilProfile is the paired positive
// control: without it, a refusal that also broke the LEGITIMATE case would
// pass the test above and be worthless. victim's own rw grant, selected
// alone, must still let the payload write inside it.
func TestVictimGrantStaysWritableWithoutTheEvilProfile(t *testing.T) {
	budget(t)
	requireSandbox(t)

	env, proj, canary := relocatedGrantFixture(t)

	r := runEnv(t, env, []string{"--no-defaults", "-p", "@sys", "-p", "@target-rw", "-p", "victim"},
		proj, "touch "+canary+" && echo WRITABLE || echo READ-ONLY").mustRun(t)

	if !strings.Contains(r.out, "WRITABLE") {
		t.Fatalf("victim's own rw grant, selected without evil, should still be writable:\n%s", r.out)
	}
}
