//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ephemeralTargetHome builds a throwaway $HOME this test can freely create
// and delete inside — never the real developer machine's own home, which is
// exactly what a naive version of this test would touch given that issue
// #179's refusal is keyed on $HOME.
func ephemeralTargetHome(t *testing.T) (home string, env []string) {
	t.Helper()
	home = t.TempDir()
	env = baseEnv("HOME=" + home)
	return home, env
}

// TestTheEphemeralTargetRefusalReachesTheBinary is issue #179's refusal
// (internal/policy/validate.go's ephemeralTargetError), run against the real
// `snug` binary rather than against policy.Resolve in-process. Every existing
// arm of this rule (internal/policy/validate_test.go and friends) constructs
// a Policy directly; grepping test/integration and internal/cli for
// "refusing to sandbox" finds nothing, and nothing there asserts the exit
// code either. So the property under test is narrower than "the rule is
// correct" — internal/policy already owns that — and is instead "parseArgs's
// caller actually surfaces this refusal, unmodified, and exits 77" rather
// than, say, swallowing the error or mapping it to the wrong code on the way
// out of main.
func TestTheEphemeralTargetRefusalReachesTheBinary(t *testing.T) {
	budget(t)
	home, env := ephemeralTargetHome(t)

	// POSITIVE CONTROL FIRST: an ordinary project one level down must resolve
	// cleanly, on the SAME fake $HOME the refusals below use. Without this, a
	// refusal on every path below could mean "this $HOME is malformed" rather
	// than "this specific shape is refused".
	ordinary := filepath.Join(home, "src", "myproject")
	if err := os.MkdirAll(ordinary, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, code := cli(t, env, "--dry-run", ordinary); code != 0 {
		t.Fatalf("control: an ordinary project one level down was refused (exit %d):\n%s", code, out)
	}

	// A project directly in an ephemeral directory ($HOME itself).
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := cli(t, env, "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("a project directly in @home's tmpfs exited %d, want %d:\n%s", code, exitPolicyCode, out)
	}
	if !strings.Contains(out, "refusing to sandbox") {
		t.Errorf("no \"refusing to sandbox\" in the output:\n%s", out)
	}
	if !strings.Contains(out, "it sits directly in") {
		t.Errorf("the refusal does not name the \"sits directly in\" shape:\n%s", out)
	}
	if !strings.Contains(out, "This selection RESOLVES") {
		t.Errorf("the default selection resolves cleanly and is refused anyway — the message "+
			"must say RESOLVES, not imply a collision that is not there:\n%s", out)
	}

	// NOT KEYED ON $HOME ITSELF: any of @home's five ephemeral directories
	// triggers the same refusal, naming the directory that is actually
	// ephemeral rather than $HOME.
	cacheBuild := filepath.Join(home, ".cache", "build")
	if err := os.MkdirAll(cacheBuild, 0o755); err != nil {
		t.Fatal(err)
	}
	out2, code2 := cli(t, env, "--dry-run", cacheBuild)
	if code2 != exitPolicyCode {
		t.Errorf("a project directly in @home's .cache tmpfs exited %d, want %d:\n%s",
			code2, exitPolicyCode, out2)
	}
	if !strings.Contains(out2, filepath.Join(home, ".cache")) {
		t.Errorf("the refusal does not name %s as the ephemeral directory:\n%s",
			filepath.Join(home, ".cache"), out2)
	}

	// THE REFUSAL SURVIVES AN EXPLICIT SELECTION: this selection resolves
	// cleanly (no --dry-run collision report) and is refused anyway, which is
	// the ruling issue #179 is actually about.
	out3, code3 := cli(t, env, "--dry-run", "--no-defaults", "-p", "@sys", "-p", "@home",
		"-p", "@target-rw", proj)
	if code3 != exitPolicyCode {
		t.Errorf("an explicit -p @sys -p @home -p @target-rw selection on %s exited %d, want %d:\n%s",
			proj, code3, exitPolicyCode, out3)
	}
	if !strings.Contains(out3, "This selection RESOLVES") {
		t.Errorf("the explicit selection resolves and must say so:\n%s", out3)
	}

	// AND THE MESSAGE CHANGES for a selection that also collides:
	// @parent-ro's "the target's parent" and @home's tmpfs are the same path.
	out4, code4 := cli(t, env, "--dry-run", "-p", "@parent-ro", proj)
	if code4 != exitPolicyCode {
		t.Errorf("-p @parent-ro on %s exited %d, want %d:\n%s", proj, code4, exitPolicyCode, out4)
	}
	if !strings.Contains(out4, "This selection ALSO COLLIDES") {
		t.Errorf("-p @parent-ro's own grant collides with @home's tmpfs at the same path, so the "+
			"message must say COLLIDES rather than the plain RESOLVES text:\n%s", out4)
	}
}

// TestTheEphemeralTargetItselfIsRefused covers the second shape
// ephemeralTargetError has no working answer for: the target IS one of
// @home's ephemeral directories, not merely inside one. "Move the project one
// level down" is not advice a user pointing snug at $HOME itself can follow,
// so the message is a different one ("it IS a directory") with no `mv`
// suggested.
func TestTheEphemeralTargetItselfIsRefused(t *testing.T) {
	budget(t)
	home, env := ephemeralTargetHome(t)

	out, code := cli(t, env, "--dry-run", home)
	if code != exitPolicyCode {
		t.Errorf("snug --dry-run %s (a directory @home itself provides as a tmpfs) exited %d, "+
			"want %d:\n%s", home, code, exitPolicyCode, out)
	}
	if !strings.Contains(out, "refusing to sandbox") || !strings.Contains(out, "it IS a directory") {
		t.Errorf("the refusal does not say the target IS the ephemeral directory:\n%s", out)
	}
	if strings.Contains(out, "mv ") {
		t.Errorf("there is no level to move $HOME itself down to, so the refusal must not "+
			"suggest an `mv`:\n%s", out)
	}

	// POSITIVE CONTROL: /tmp targets still work — snug's own /tmp is a tmpfs
	// too, and only $HOME-rooted ones refuse. Without this, a change that made
	// EVERY path refuse (not just ephemeral ones) would still pass every
	// assertion above.
	tmpTarget := t.TempDir()
	if out5, code5 := cli(t, env, "--dry-run", tmpTarget); code5 != 0 {
		t.Errorf("control: an ordinary /tmp target was refused (exit %d):\n%s", code5, out5)
	}
}
