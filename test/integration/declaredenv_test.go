//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeclaredPathListReachesThePayload is environ.types end to end: the
// profile loader decoding [profile.X.environ.types], the builtins, Resolve and
// the argv, through the real binary.
//
// It would catch: two declarers' merges not reaching the payload joined on ':'
// (the one thing the feature is for); the host's own GEM_PATH leaking past
// --clearenv because a declared name was treated as inherited; a profile that
// merges WITHOUT declaring being admitted because a profile selected beside it
// declared; and a declared list sharing its name with a scalar being resolved
// rather than refused.
func TestDeclaredPathListReachesThePayload(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	root := t.TempDir()
	gemsA := filepath.Join(root, "gems-a")
	gemsB := filepath.Join(root, "gems-b")
	for _, d := range []string{gemsA, gemsB} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// FIXTURE: a ':' in the temp root would make each path two elements and
	// the separator check refuse the profile for a reason this test is not
	// about.
	if strings.Contains(root, ":") {
		t.Fatalf("t.TempDir() %q contains ':'; the fixture cannot express it as one element", root)
	}

	good := "" +
		"[profile.gems-a]\nro = [\"" + gemsA + "\"]\n" +
		"[profile.gems-a.environ.types]\nGEM_PATH = \"path-list\"\n" +
		"[profile.gems-a.environ.merge]\nGEM_PATH = [\"" + gemsA + "\"]\n" +
		"[profile.gems-b]\nro = [\"" + gemsB + "\"]\n" +
		"[profile.gems-b.environ.types]\nGEM_PATH = \"path-list\"\n" +
		"[profile.gems-b.environ.merge]\nGEM_PATH = [\"" + gemsB + "\"]\n" +
		"[profile.gemset]\n" +
		"[profile.gemset.environ.set]\nGEM_PATH = \"/srv/one-value\"\n"
	// The host has a GEM_PATH of its own. Nothing selected inherits it.
	env := writeProfiles(t, map[string]string{"gems": good}, "GEM_PATH=/srv/host-gems")

	out, code := cli(t, env, "-p", "gems-a", "-p", "gems-b", proj, "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("snug -p gems-a -p gems-b exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "SNUG=1\n") {
		t.Fatalf("control: SNUG=1 absent, the payload did not run inside snug:\n%s", out)
	}
	want := "GEM_PATH=" + gemsA + ":" + gemsB + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("the payload's environment does not carry %q:\n%s", want, out)
	}
	if strings.Contains(out, "/srv/host-gems") {
		t.Errorf("the host's GEM_PATH reached the payload; nothing selected inherits it:\n%s", out)
	}

	// A declared list and a single value on one name: refused, naming both.
	out, code = cli(t, env, "-p", "gems-a", "-p", "gemset", proj, "--", "/usr/bin/env")
	if code != exitPolicyCode {
		t.Errorf("gems-a beside gemset exited %d, want %d:\n%s", code, exitPolicyCode, out)
	}
	for _, s := range []string{"GEM_PATH is typed two ways", "gems-a (environ.types)", "gemset (environ.set)"} {
		if !strings.Contains(out, s) {
			t.Errorf("the refusal does not say %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "SNUG=1") {
		t.Errorf("the refused selection ran the payload:\n%s", out)
	}

	// A profile merging GEM_PATH without declaring it, in the same FILE as two
	// that do. It is refused when the file loads — a profile's verbs are judged
	// against its own declarations only, so selecting gems-a beside it changes
	// nothing — and so it needs its own config directory: a file that does not
	// load is fatal to every run from that directory, the good selection above
	// included.
	bad := good + "" +
		"[profile.gems-c]\nro = [\"" + gemsB + "\"]\n" +
		"[profile.gems-c.environ.merge]\nGEM_PATH = [\"" + gemsB + "\"]\n"
	badEnv := writeProfiles(t, map[string]string{"gems": bad})
	out, code = cli(t, badEnv, "-p", "gems-a", "-p", "gems-c", proj, "--", "/usr/bin/env")
	if code != exitPolicyCode {
		t.Errorf("an undeclared merge beside a declarer exited %d, want %d:\n%s", code, exitPolicyCode, out)
	}
	for _, s := range []string{"gems-c", "environ.merge on GEM_PATH, which snug has no entry for"} {
		if !strings.Contains(out, s) {
			t.Errorf("the refusal does not say %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "SNUG=1") {
		t.Errorf("the refused selection ran the payload:\n%s", out)
	}
}
