//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// plantedLinkFixture builds the host the two tests below share: a project, a
// cache directory a profile may hold read-write, and a directory standing for
// something no profile grants, with a file in it whose content is unique.
func plantedLinkFixture(t *testing.T) (proj, cache, secretDir, secretText string) {
	t.Helper()
	proj, secret := target(t)
	base := filepath.Dir(secret)
	cache = filepath.Join(base, "cache")
	secretDir = filepath.Join(base, "secretdir")
	for _, d := range []string{cache, secretDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secretText = "PLANTED-LINK-SECRET-" + filepath.Base(base)
	if err := os.WriteFile(filepath.Join(secretDir, "id_rsa"), []byte(secretText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return proj, cache, secretDir, secretText
}

// assertLinkIsOurs checks from the host that the link the sandbox planted is
// really there, points where the payload said, and is owned by the invoking
// uid: the premise the ownership rule rests on, measured rather than assumed.
func assertLinkIsOurs(t *testing.T, link, dest string) {
	t.Helper()
	got, err := os.Readlink(link)
	if err != nil || got != dest {
		t.Fatalf("control: Readlink(%s) = %q, %v; want %s. The sandbox did not plant the link, "+
			"so the refusal below would prove nothing", link, got, err, dest)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		t.Fatalf("control: the planted link is owned by %+v, want uid %d", fi.Sys(), os.Getuid())
	}
}

// TestPlantedLinkFromEarlierRunIsRefused is the first finding of the nested
// grant symlink issue, end to end. Run 1 holds `cache` read-write and plants
// `cache/bin -> secretdir` from INSIDE the sandbox; run 2 names `cache/bin` as
// a read-only grant to /mnt/x beside the same rw `cache`. Before the ownership
// rule, run 2 bound secretdir at /mnt/x and `cat /mnt/x/id_rsa` printed the
// host file no profile had granted. It fails if that path opens again.
//
// What it does not reach: the dry-run and the run are asserted to refuse, not
// that the refusal is the ONLY thing standing between the payload and the
// file; the unit tests in internal/policy hold the rule's edges.
func TestPlantedLinkFromEarlierRunIsRefused(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, cache, secretDir, secretText := plantedLinkFixture(t)

	toml := fmt.Sprintf("[profile.plant]\nrw = [%q]\n\n[profile.cache]\nrw = [%q]\nro = [%q]\n",
		cache, cache, cache+"/bin:/mnt/x")
	env := envProfileLayer(t, "plantedlink.toml", toml, os.Getenv("PATH"))

	// CONTROL, before anything is planted: `bin` is a real directory, the same
	// profile resolves, runs, and the payload reads a file through /mnt/x. This
	// is what makes "run 2 refused" attributable to the link.
	if err := os.MkdirAll(filepath.Join(cache, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "bin", "ok"), []byte("REAL-DIR-CONTENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctl := runEnv(t, env, []string{"-p", "cache"}, proj, `cat /mnt/x/ok`).mustRun(t)
	if ctl.code != 0 || !strings.Contains(ctl.out, "REAL-DIR-CONTENT") {
		t.Fatalf("control: the profile over a real directory exited %d:\n%s", ctl.code, ctl.out)
	}
	if err := os.RemoveAll(filepath.Join(cache, "bin")); err != nil {
		t.Fatal(err)
	}

	// Run 1: the sandbox plants the link.
	r1 := runEnv(t, env, []string{"-p", "plant"}, proj,
		fmt.Sprintf(`ln -sfn %s %s/bin && echo LINK-PLANTED`, secretDir, cache)).mustRun(t)
	if !strings.Contains(r1.out, "LINK-PLANTED") {
		t.Fatalf("run 1 did not plant the link:\n%s", r1.out)
	}
	assertLinkIsOurs(t, filepath.Join(cache, "bin"), secretDir)

	// Run 2: refused, and the payload never starts.
	r2 := runEnv(t, env, []string{"-p", "cache"}, proj, `cat /mnt/x/id_rsa`)
	if r2.ran {
		t.Errorf("the payload ran under a profile whose grant goes through a planted link:\n%s", r2.out)
	}
	if r2.code != exitPolicyCode {
		t.Errorf("exit %d, want %d (exitPolicy):\n%s", r2.code, exitPolicyCode, r2.out)
	}
	if strings.Contains(r2.out, secretText) {
		t.Errorf("the host secret reached the output:\n%s", r2.out)
	}

	// --dry-run is the screen a human reads; it must refuse the same way.
	out, code := cli(t, env, "--dry-run", "-p", "cache", proj)
	if code != exitPolicyCode {
		t.Errorf("--dry-run exited %d, want %d:\n%s", code, exitPolicyCode, out)
	}
	for _, want := range []string{filepath.Join(cache, "bin"), secretDir, "uid"} {
		if !strings.Contains(out, want) {
			t.Errorf("--dry-run refusal does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secretText) {
		t.Errorf("the host secret reached --dry-run output:\n%s", out)
	}
}

// TestPlantedLinkFromAPastTargetIsRefused is the second finding: the link was
// left by a run whose TARGET was another directory, no rw grant of this run
// covers it, and no profile that planted it is loaded. Only the link's owner
// remains of that earlier run. It fails if the rule is ever anchored on this
// run's rw grants or on loaded profiles.
func TestPlantedLinkFromAPastTargetIsRefused(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _, secretDir, secretText := plantedLinkFixture(t)
	old := filepath.Join(filepath.Dir(filepath.Dir(proj)), "old")
	if err := os.MkdirAll(filepath.Join(old, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := envProfileLayer(t, "pastlink.toml",
		fmt.Sprintf("[profile.past]\nro = [%q]\n", old+"/bin:/mnt/x"), os.Getenv("PATH"))

	// CONTROL: with `bin` a real directory the profile runs.
	ctl := runEnv(t, env, []string{"-p", "past"}, proj, `echo CONTROL-RAN`).mustRun(t)
	if ctl.code != 0 {
		t.Fatalf("control: the profile over a real directory exited %d:\n%s", ctl.code, ctl.out)
	}
	if err := os.RemoveAll(filepath.Join(old, "bin")); err != nil {
		t.Fatal(err)
	}

	// Run 1: `old` is the TARGET, so the default @target-rw lets the payload plant.
	r1 := runEnv(t, nil, nil, old, fmt.Sprintf(`ln -sfn %s bin && echo LINK-PLANTED`, secretDir)).mustRun(t)
	if !strings.Contains(r1.out, "LINK-PLANTED") {
		t.Fatalf("run 1 did not plant the link:\n%s", r1.out)
	}
	assertLinkIsOurs(t, filepath.Join(old, "bin"), secretDir)

	r2 := runEnv(t, env, []string{"-p", "past"}, proj, `cat /mnt/x/id_rsa`)
	if r2.ran || r2.code != exitPolicyCode {
		t.Errorf("ran=%v exit %d, want a refusal with exit %d:\n%s", r2.ran, r2.code, exitPolicyCode, r2.out)
	}
	if strings.Contains(r2.out, secretText) {
		t.Errorf("the host secret reached the output:\n%s", r2.out)
	}
}
