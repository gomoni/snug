// Package guard tests bin/inside-snug from the HOST, where it must always
// refuse.
//
// It carries no build tag on purpose. The inside-the-sandbox half needs a real
// sandbox and lives in test/integration; this half needs nothing, so it runs in
// `make gate` on every machine and in CI. That asymmetry is deliberate: the
// expensive assertion is "it says yes inside", but the one that protects a
// $HOME is "it says no on the host", and that one must never be skippable.
package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The guard has to be IN the repository, not merely on the machine that wrote
// it. bin/ is gitignored — it is where build output lands — and that rule
// swallowed bin/inside-snug on the commit that introduced it: `git add -A`
// skipped the file, `git status` stayed clean, every test here passed locally,
// and CI was the first thing to observe that the file every agent instruction
// points at was not in the repository at all.
//
// Existence is not the same question as trackedness, and only the second one
// survives a clone.
func TestTheGuardIsTracked(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("SKIP: no git to ask")
	}
	cmd := exec.Command(git, "ls-files", "--error-unmatch", "bin/inside-snug")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bin/inside-snug is not tracked by git (%v: %s).\nIt is the file every agent "+
			"file tells an agent to guard destructive commands with, and a clone of this "+
			"repository would not have it — so `bin/inside-snug && rm -rf …` would fail at the "+
			"shell, or worse, be edited out as broken. bin/ is gitignored; the .gitignore "+
			"carries an explicit negation for this path.", err, out)
	}
}

func script(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "bin", "inside-snug"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("bin/inside-snug is missing (%v). Agents are told to guard destructive "+
			"commands with it in the same invocation; if it is gone, that instruction "+
			"silently becomes a no-op", err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Fatalf("bin/inside-snug is not executable (%v), so `bin/inside-snug && rm -rf …` "+
			"fails open at the shell rather than refusing", fi.Mode())
	}
	return p
}

// run executes the guard with an environment built from scratch, so a variable
// this test process happens to carry cannot decide the outcome.
func run(t *testing.T, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(script(t))
	cmd.Env = append([]string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s: %v", script(t), err)
	}
	return string(out), code
}

// THE ASSERTION THAT PROTECTS A HOME DIRECTORY. Everything else in this file is
// support for it.
func TestTheGuardRefusesOnTheHost(t *testing.T) {
	out, code := run(t)
	if code == 0 {
		t.Fatalf("bin/inside-snug exited 0 on the HOST. Every `inside-snug && rm -rf …` an "+
			"agent writes would then run its destructive half against the real home "+
			"directory — which is the failure issue #185 exists for:\n%s", out)
	}
	if !strings.Contains(out, "NOT inside a snug sandbox") {
		t.Errorf("the refusal does not say what it decided, so a human reading a failed "+
			"guarded command cannot tell the guard from the command:\n%s", out)
	}
}

// Family A is forgeable, and this is the test that says so out loud. snug
// authors SNUG and SNUG_PROFILES, and CLAUDE.md records that @sys binds /etc so
// /etc/profile.d/* can put variables back — so anything that trusts the
// environment alone is trusting a value the other side can write.
func TestForgingTheEnvironmentDoesNotSatisfyTheGuard(t *testing.T) {
	out, code := run(t, "SNUG=1", "SNUG_PROFILES=@sys,@home,@cwd-rw")
	if code == 0 {
		t.Fatalf("two environment variables were enough to convince the guard it was inside "+
			"a sandbox. Family A must be necessary and never sufficient:\n%s", out)
	}
	// And it must have got past family A to refuse — otherwise this test would
	// pass on a guard that refuses everything for an unrelated reason.
	if strings.Contains(out, "SNUG_PROFILES is unset") || strings.Contains(out, "SNUG is not 1") {
		t.Errorf("the forged environment did not even satisfy family A, so this test proves "+
			"nothing about whether A alone is sufficient:\n%s", out)
	}
}

// The canary is the one piece of evidence snug does not produce and a payload
// cannot manufacture. Installing it must be explicit and must land where the
// guard looks, or the check quietly becomes "a file nobody creates is absent" —
// true everywhere, including on the host.
func TestTheCanaryInstallsWhereTheGuardLooksForIt(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(script(t), "--install-canary")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--install-canary failed: %v\n%s", err, out)
	}
	canary := filepath.Join(home, ".snug-host-canary")
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("--install-canary did not create %s (%v), so the guard's strongest check "+
			"has nothing to find on the host", canary, err)
	}

	// With the canary present and HOME pointed at it, the guard must name that
	// reason specifically — the file is what identifies the host, and a refusal
	// for some other reason would leave the canary untested.
	cmd = exec.Command(script(t))
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"),
		"SNUG=1", "SNUG_PROFILES=@sys", "SNUG_HOST_CANARY=" + canary}
	out, _ = cmd.CombinedOutput()
	if !strings.Contains(string(out), "host canary") {
		t.Logf("guard output: %s", out)
		t.Log("the guard refused before reaching the canary check (/ is not tmpfs here, which " +
			"is itself correct). The canary's own positive control is the in-sandbox case in " +
			"test/integration, where / IS tmpfs and touching the file must flip the verdict.")
	}
}

// The root-filesystem check is the one family-B assertion that no other test
// isolates: on an ordinary host run the $HOME check refuses first, and in every
// counterfeit the root really is a tmpfs. So this builds the one case where / is
// the ONLY thing left to give the host away — family A forged, and HOME pointed
// at a directory that is itself a tmpfs.
//
// Found by mutation: deleting the root check changed no result anywhere.
func TestTheGuardRefusesWhenOnlyTheRootFilesystemGivesItAway(t *testing.T) {
	home := t.TempDir() // /tmp on this host, and /tmp is usually a tmpfs
	out, code := run(t, "HOME="+home, "SNUG=1", "SNUG_PROFILES=@sys,@home")
	if strings.Contains(out, "and the sandbox's home is a tmpfs") {
		t.Skipf("SKIP: %s is not a tmpfs on this host, so the home check refuses first and "+
			"the root check cannot be isolated here", home)
	}
	if code == 0 {
		t.Fatalf("the guard accepted a HOST shell whose HOME happened to be a tmpfs and whose "+
			"SNUG variables were forged. The root filesystem was the only remaining evidence "+
			"and it was not read:\n%s", out)
	}
	if !strings.Contains(out, "/ is ") {
		t.Errorf("refused, but not on the root filesystem — this test exists to prove that "+
			"check is read:\n%s", out)
	}
}
