//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTargetThroughPlantedLinkRefuses reproduces the #636 escape end to end.
// Run 1 holds rw on a work directory and, from INSIDE the sandbox, plants
// `work/proj -> secret`. Run 2 names `work/proj` as the target; before the fix
// the target resolved to `secret`, which became writable, and the payload wrote
// into secret/creds. It fails if a link a sandbox could have planted is ever
// followed to choose the target, whether the human spelled the path out or sat
// in the link and typed `.` (the logical $PWD).
//
// Controls: the planted link is read back from the host and is ours, creds is
// writable from the host, and `snug <secret>` named directly runs and can write
// beside creds, so the refusals are attributable to the link rather than to a
// broken fixture. Not covered: a link planted by a different uid, which the
// policy unit tests drive through the injected owner.
func TestTargetThroughPlantedLinkRefuses(t *testing.T) {
	budget(t)
	requireSandbox(t)

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(root, "scratch")
	work := filepath.Join(root, "work")
	secret := filepath.Join(root, "secret")
	for _, d := range []string{scratch, work, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const orig = "ORIGINAL-CREDS-636\n"
	creds := filepath.Join(secret, "creds")
	if err := os.WriteFile(creds, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	unchanged := func(when string) {
		t.Helper()
		got, err := os.ReadFile(creds)
		if err != nil || string(got) != orig {
			t.Fatalf("%s: secret/creds = %q, %v; want it byte-identical to %q", when, got, err, orig)
		}
	}

	env := envProfileLayer(t, "targetlink.toml",
		fmt.Sprintf("[profile.workrw]\nrw = [%q]\n", work), os.Getenv("PATH"))

	// Run 1: the target is scratch, work is a separate rw grant, and the payload
	// plants the link.
	proj := filepath.Join(work, "proj")
	r1 := runEnv(t, env, []string{"-p", "workrw"}, scratch,
		fmt.Sprintf(`ln -s %s %s && echo LINK-PLANTED`, secret, proj)).mustRun(t)
	if !strings.Contains(r1.out, "LINK-PLANTED") {
		t.Fatalf("run 1 did not plant the link:\n%s", r1.out)
	}
	assertLinkIsOurs(t, proj, secret)

	assertRefused := func(what string, r sandboxRun) {
		t.Helper()
		if r.ran {
			t.Errorf("%s: the payload ran through a planted target link:\n%s", what, r.out)
		}
		if r.code != exitPolicyCode {
			t.Errorf("%s: exit %d, want %d (exitPolicy, not usage):\n%s", what, r.code, exitPolicyCode, r.out)
		}
		for _, want := range []string{"resolves through the link", proj + " -> " + secret, "cd -P"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("%s: refusal does not contain %q:\n%s", what, want, r.out)
			}
		}
		unchanged(what)
	}

	// Run 2, the path spelled out.
	r2 := runEnv(t, env, []string{"-p", "@target-rw"}, proj, `echo PWNED > creds`)
	assertRefused("named target", r2)

	// Run 2, `snug .` from inside the link with the logical $PWD. cmd.Dir is the
	// link and PWD is set explicitly, because that is the only way the logical
	// path survives into filepath.Abs.
	cmd := exec.Command(snugBin, "-p", "@target-rw", ".", "--", "/bin/sh", "-c",
		"printf '%s\\n' "+payloadMarker+"; echo PWNED > creds")
	cmd.Dir = proj
	cmd.Env = append(baseEnv(), "PWD="+proj)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	assertRefused("snug . from the link", sandboxRun{out: string(out), code: code,
		ran: strings.Contains(string(out), payloadMarker)})

	// CONTROL: the real directory runs, and writes where the payload is allowed.
	ctl := runEnv(t, env, []string{"-p", "@target-rw"}, secret, `echo CONTROL > ctl && echo CONTROL-WROTE`).mustRun(t)
	if ctl.code != 0 || !strings.Contains(ctl.out, "CONTROL-WROTE") {
		t.Fatalf("control: snug <secret> exited %d:\n%s", ctl.code, ctl.out)
	}
	if b, err := os.ReadFile(filepath.Join(secret, "ctl")); err != nil || strings.TrimSpace(string(b)) != "CONTROL" {
		t.Errorf("control: the real target was not writable: %q, %v", b, err)
	}
	unchanged("after the control")
}
