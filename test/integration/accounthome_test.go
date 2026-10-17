//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The account's home directory comes from the account database (a root-owned
// getent outside a sandbox, snug's own generated /etc/passwd inside one), and a
// $HOME that names another directory is refused. These tests hold that end to
// end: through the binary a user runs, through the fixture binary the suite
// uses to name a scratch home, and through snug run inside snug.

// hostAccountHome is field 6 of this uid's getent passwd line, read by the test
// the way a human would. It is the control that the refusal below names a real
// directory and not an empty one.
func hostAccountHome(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("getent", "passwd", strconv.Itoa(os.Getuid())).Output()
	if err != nil {
		skipOrFail(t, "getent passwd %d fails here (%v), so there is no account home to compare against", os.Getuid(), err)
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) != 7 || f[5] == "" {
		skipOrFail(t, "getent passwd %d printed %q, which has no home field", os.Getuid(), out)
	}
	return f[5]
}

// TestHOMEDifferentFromTheAccountHomeChangesNothing runs the binary a user
// installs with $HOME pointing at a scratch directory, and again with a
// relative one. It fails if either is refused or if the scratch directory
// reaches the policy: the dry-run must be byte-identical to the one under the
// account's own HOME and must not mention the scratch directory. --dry-run, so
// nothing is started against the developer's real home.
func TestHOMEDifferentFromTheAccountHomeChangesNothing(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	acct := hostAccountHome(t)
	scratch := t.TempDir()
	if scratch == acct {
		t.Fatal("control: the scratch HOME is the account's home")
	}

	want, code := cli(t, baseEnv("HOME="+acct), "--dry-run", proj, "--", "/bin/true")
	if code != 0 {
		t.Fatalf("control: HOME equal to the account's home was refused (exit %d):\n%s", code, want)
	}
	for _, host := range []string{scratch, "relative/home"} {
		out, code := cli(t, baseEnv("HOME="+host), "--dry-run", proj, "--", "/bin/true")
		if code != 0 {
			t.Errorf("HOME=%q was refused (exit %d):\n%s", host, code, out)
			continue
		}
		if out != want {
			t.Errorf("HOME=%q changed the dry-run:\n%s", host, out)
		}
		if strings.Contains(out, scratch) {
			t.Errorf("HOME=%q reached the policy:\n%s", host, out)
		}
	}
}

// TestHomeFollowsTheAccountWithHOMEUnset fails if an unset $HOME leaves the run
// guessing, or leaves the sandbox with a $HOME other than the account's. The
// fixture binary reports a scratch directory as the account's home; inside, $HOME
// and the generated passwd's field 6 must both be that directory's canonical
// path. Control: the environment really has no HOME when snug starts, shown by
// the env this test passes, and the payload ran.
func TestHomeFollowsTheAccountWithHOMEUnset(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	home := t.TempDir()
	canon, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvDropping([]string{"HOME"}, "SNUG_FIXTURE_ACCOUNT_HOME="+home)
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			t.Fatalf("control: HOME is set in the environment: %s", kv)
		}
	}
	r := runEnv(t, env, nil, proj, `echo "HOME=$HOME"; getent passwd "$(id -u)"`).mustRun(t)
	if !strings.Contains(r.out, "HOME="+canon+"\n") {
		t.Errorf("$HOME inside is not the account's home %q:\n%s", canon, r.out)
	}
	var pwHome string
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Split(line, ":"); len(f) == 7 {
			pwHome = f[5]
		}
	}
	if pwHome != canon {
		t.Errorf("getent passwd field 6 inside is %q, want %q:\n%s", pwHome, canon, r.out)
	}
}

// TestSystemTreeAccountHomeIsRefused fails if an account whose home is a system
// tree is let through: @home would put a writable tmpfs over /etc, and every
// program reads what a payload writes there. The fixture binary names /etc as
// the account's home. Control: the same fixture with an ordinary scratch home
// runs, so the refusal is the home's.
func TestSystemTreeAccountHomeIsRefused(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := runEnv(t, baseEnv(fixtureHome("/etc")...), nil, proj, `echo SHOULD-NOT-RUN`)
	if r.ran || strings.Contains(r.out, "SHOULD-NOT-RUN") {
		t.Fatalf("the payload ran with /etc as its home:\n%s", r.out)
	}
	if r.code != exitPolicyCode || !strings.Contains(r.out, "is a system tree") {
		t.Errorf("exit %d, want %d and the system-tree refusal:\n%s", r.code, exitPolicyCode, r.out)
	}
	assertNoStageStarted(t, proj)

	ok := runEnv(t, baseEnv(fixtureHome(t.TempDir())...), nil, proj, `echo fine`).mustRun(t)
	if ok.code != 0 {
		t.Errorf("control: an ordinary home was refused (exit %d):\n%s", ok.code, ok.out)
	}
}

// nested is an outer snug run whose payload is another snug, for the tests of
// where the inner one reads its account from. The inner binary is the shipped
// one, copied under the target because that is the only place the outer
// sandbox sees.
type nested struct {
	env        []string
	proj, home string
	canonical  string
	outerArgs  []string
}

func newNested(t *testing.T, outerArgs ...string) nested {
	t.Helper()
	requireSandbox(t)
	proj, _ := target(t)
	home := t.TempDir()
	canon, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(snugBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "snug"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	return nested{env: baseEnv(fixtureHome(home)...), proj: proj, home: home, canonical: canon,
		outerArgs: outerArgs}
}

func (n nested) run(t *testing.T, script string) sandboxRun {
	t.Helper()
	return runEnv(t, n.env, n.outerArgs, n.proj, script)
}

// TestNestedSnugDryRunUsesTheOuterHome fails if a snug started inside snug
// takes any home but the outer sandbox's. The inner process cannot ask getent
// (the host's root-owned files are not root's in here) and reads the generated
// passwd instead; --dry-run prints which. Controls: the inner run says it read
// the generated passwd, names the outer home, and the developer's real home
// is a different directory that does not appear in it.
func TestNestedSnugDryRunUsesTheOuterHome(t *testing.T) {
	budget(t)
	n := newNested(t)
	real := hostAccountHome(t)
	if real == n.canonical {
		t.Fatal("control: the outer home is the developer's real home")
	}
	r := n.run(t, `./snug --dry-run "$PWD" -- true; echo "inner-exit=$?"`).mustRun(t)
	if !strings.Contains(r.out, "inner-exit=0") {
		t.Fatalf("the inner dry-run failed:\n%s", r.out)
	}
	if !strings.Contains(r.out, "home "+n.canonical+" "+fromSnugAuthoredSource) {
		t.Errorf("the inner snug's home is not the outer sandbox's %q:\n%s", n.canonical, r.out)
	}
	if strings.Contains(r.out, real) {
		t.Errorf("the developer's real home %q appears in the inner snug's screen:\n%s", real, r.out)
	}
}

// TestNestedSnugUnsetHOMETakesTheAuthoredHome is the unset-HOME arm of the same
// thing: the inner snug is started without HOME and must take the generated
// passwd's home, not refuse and not guess.
func TestNestedSnugUnsetHOMETakesTheAuthoredHome(t *testing.T) {
	budget(t)
	n := newNested(t)
	r := n.run(t, `env -u HOME ./snug --dry-run "$PWD" -- true; echo "inner-exit=$?"`).mustRun(t)
	if !strings.Contains(r.out, "inner-exit=0") {
		t.Fatalf("the inner dry-run without HOME failed:\n%s", r.out)
	}
	if !strings.Contains(r.out, "home "+n.canonical+" "+fromSnugAuthoredSource) {
		t.Errorf("without HOME the inner snug did not take the authored home %q:\n%s", n.canonical, r.out)
	}
}

// TestNestedSnugIgnoresAChangedHOME fails if the inner snug lets a HOME the
// payload changed move anything. The payload controls its own environment, so
// HOME=/tmp is the payload's choice and must not matter: the inner snug takes
// the generated passwd's home, as it does with HOME unchanged.
func TestNestedSnugIgnoresAChangedHOME(t *testing.T) {
	budget(t)
	n := newNested(t)
	r := n.run(t, `./snug --dry-run "$PWD" -- true; echo "unchanged-exit=$?"
HOME=/tmp ./snug --dry-run "$PWD" -- true; echo "changed-exit=$?"`).mustRun(t)
	if !strings.Contains(r.out, "unchanged-exit=0") {
		t.Fatalf("control: the unchanged HOME was refused:\n%s", r.out)
	}
	if !strings.Contains(r.out, "changed-exit=0") {
		t.Errorf("the inner snug did not exit 0 for HOME=/tmp:\n%s", r.out)
	}
	if got := strings.Count(r.out, "home "+n.canonical+" "+fromSnugAuthoredSource); got != 2 {
		t.Errorf("want both inner runs to take the authored home %q, got %d:\n%s", n.canonical, got, r.out)
	}
}

// TestNestedSnugWithoutNSSRefuses fails if the inner snug, finding no generated
// passwd because the outer selection had no nss profile, falls back to anything
// else, or refuses without saying how to fix it. The outer selection is a
// profile that grants /usr and nothing named nss. Controls: /etc/passwd is
// really absent inside, and the same outer selection plus @sys, which has nss,
// lets the inner snug resolve.
func TestNestedSnugWithoutNSSRefuses(t *testing.T) {
	budget(t)
	cfgEnv := func(n nested) []string {
		cfg := t.TempDir()
		pd := filepath.Join(cfg, "snug", "profiles.d")
		if err := os.MkdirAll(pd, 0o755); err != nil {
			t.Fatal(err)
		}
		toml := "[profile.runtime]\ndescription = \"/usr and the dynamic linker, no nss\"\n" +
			"ro = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc/ld.so.cache\", \"/etc/ld.so.conf\", \"/etc/ld.so.conf.d\"]\n"
		if err := os.WriteFile(filepath.Join(pd, "runtime.toml"), []byte(toml), 0o644); err != nil {
			t.Fatal(err)
		}
		return append(append([]string{}, n.env...), "XDG_CONFIG_HOME="+cfg)
	}

	n := newNested(t, "--no-defaults", "-p", "@target-rw", "-p", "runtime")
	n.env = cfgEnv(n)
	r := n.run(t, `test -e /etc/passwd && echo PASSWD-PRESENT || echo PASSWD-ABSENT
./snug --dry-run "$PWD" -- true; echo "inner-exit=$?"`).mustRun(t)
	if !strings.Contains(r.out, "PASSWD-ABSENT") {
		t.Fatalf("control: /etc/passwd exists inside, so this is not the no-nss case:\n%s", r.out)
	}
	if strings.Contains(r.out, "exec format") || strings.Contains(r.out, "not found") {
		t.Fatalf("control: the inner snug did not start (%s):\n%s", "no runtime", r.out)
	}
	if !strings.Contains(r.out, "inner-exit="+strconv.Itoa(exitPolicyCode)) ||
		!strings.Contains(r.out, "select a profile with nss = true") {
		t.Errorf("the inner snug did not refuse with the nss fix (want exit %d):\n%s", exitPolicyCode, r.out)
	}
	if strings.Contains(r.out, "account: ") {
		t.Errorf("the inner snug reported an account despite no generated passwd:\n%s", r.out)
	}

	with := newNested(t, "--no-defaults", "-p", "@target-rw", "-p", "@sys")
	rw := with.run(t, `./snug --dry-run "$PWD" -- true; echo "inner-exit=$?"`).mustRun(t)
	if !strings.Contains(rw.out, "inner-exit=0") {
		t.Errorf("control: the same outer selection with @sys did not let the inner snug resolve:\n%s", rw.out)
	}
}

// TestPlainUserNamespaceRefuses fails if snug accepts the account of a user
// namespace that is not a snug sandbox. A bwrap with the host's filesystem
// bound back in has the same one-line uid map as a sandbox, but its /etc/passwd
// is the host's, which anyone with such a namespace could have replaced. The
// refusal names both sources snug trusts. Control: the same wrapper with the
// root authoredAccount builds, which has the shape of a snug sandbox, is
// accepted and says it read the generated passwd.
func TestPlainUserNamespaceRefuses(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	bare := func(args ...string) (string, int) {
		t.Helper()
		full := append([]string{"--unshare-user", "--die-with-parent", "--dev-bind", "/", "/", "--", snugBin}, args...)
		return runBwrap(t, nil, full)
	}
	out, code := bare(proj, "--", "/bin/echo", "SHOULD-NOT-RUN")
	if strings.Contains(out, "SHOULD-NOT-RUN") {
		t.Fatalf("the payload ran in a plain user namespace:\n%s", out)
	}
	if code != exitPolicyCode || !strings.Contains(out, "this is a user namespace but not a snug sandbox") {
		t.Errorf("exit %d, want %d and the not-a-snug-sandbox refusal:\n%s", code, exitPolicyCode, out)
	}
	assertNoStageStarted(t, proj)

	acct := newAuthoredAccount(t)
	full := append([]string{"--unshare-user", "--die-with-parent"}, acct.Root...)
	full = append(full, "--dev-bind", "/dev", "/dev", "--bind", "/proc", "/proc")
	full = append(full, acct.Account...)
	full = append(full, "--", snugBin, "--dry-run", proj, "--", "/bin/true")
	out, code = runBwrap(t, acct.Files(t), full)
	if code != 0 {
		t.Fatalf("control: the snug-shaped wrapper was refused (exit %d):\n%s", code, out)
	}
	wantAuthoredSource(t, out)
}

// runBwrap runs bwrap with args and the given extra descriptors and returns its
// combined output and exit code.
func runBwrap(t *testing.T, files []*os.File, args []string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	cmd.Env = baseEnv()
	cmd.ExtraFiles = files
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bwrap did not finish within %s:\n%s", cmdTimeout, out)
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running bwrap: %v\n%s", err, out)
		}
		return string(out), ee.ExitCode()
	}
	return string(out), 0
}

// TestShadowedAuthoredPasswdIsRefused is the forged-passwd attempt, written the
// way a payload would do it. With seccomp off in the OUTER sandbox, the payload
// makes a user namespace and a mount namespace of its own, binds a directory it
// wrote over /etc whose passwd names a directory of its own as the account's home, and runs
// the shipped snug as the same uid. That snug sees a one-line uid map and a
// one-line /etc/passwd for its uid, exactly the shape it trusts inside a real
// sandbox, except that the file is on a writable mount the payload made. It must
// refuse. Controls: the forged file is really what getent reads there
// (the forged home), and in the same sandbox, without the bind, the same snug resolves
// and reports the real generated passwd. What this does not show: a forged
// file on a read-only tmpfs mount of the root's own device, which only the
// bwrap that builds a sandbox can create.
func TestShadowedAuthoredPasswdIsRefused(t *testing.T) {
	budget(t)
	requireNestedUserNamespace(t)
	n := newNested(t, "--no-seccomp")
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())

	// --no-defaults, a profile with /usr and no nss, so the inner resolve needs nothing from /etc
	// beyond the account: over the forged /etc, a snug that believed the forged
	// file would otherwise stop for want of /etc/ld.so.cache, and its refusal
	// would look the same as the right one.
	//
	// The forged home is a directory that exists in the outer sandbox, so a
	// snug that believed the forged file would go on to resolve it rather than
	// stop for some other reason; the inner snug is started without HOME so
	// the account's home is the only home it has.
	script := `
set -u
H="$HOME/fakehome"
mkdir -p "$H" "$PWD/fake" "$HOME/xdg/snug/profiles.d"
printf '[profile.runtime]\ndescription = "usr only, no nss"\nro = ["/usr", "/bin", "/lib", "/lib64"]\n' > "$HOME/xdg/snug/profiles.d/runtime.toml"
export XDG_CONFIG_HOME="$HOME/xdg"
printf 'forger:x:` + uid + `:` + gid + `::%s:/bin/sh\n' "$H" > "$PWD/fake/passwd"
printf 'forger:x:` + gid + `:\n' > "$PWD/fake/group"
echo "--- unshadowed"
./snug --dry-run --no-defaults -p @target-rw -p runtime "$PWD" -- true; echo "plain-exit=$?"
echo "--- shadowed"
unshare -U -m --map-user=` + uid + ` --map-group=` + gid + ` --keep-caps -- /bin/sh -c '
  mount --bind "$1/fake" /etc || { echo BIND-FAILED; exit 0; }
  echo "forged-passwd: $(getent passwd ` + uid + `)"
  env -u HOME "$1/snug" --dry-run --no-defaults -p @target-rw -p runtime "$1" -- true; echo "shadowed-exit=$?"
' sh "$PWD"
`
	r := n.run(t, script).mustRun(t)
	if strings.Contains(r.out, "BIND-FAILED") || !strings.Contains(r.out, "shadowed-exit=") {
		t.Skipf("the payload could not build the forged /etc here (nested user namespace or "+
			"mount refused), so nothing below can be said:\n%s", r.out)
	}
	if !strings.Contains(r.out, "plain-exit=0") {
		t.Fatalf("control: the same snug did not resolve before the bind:\n%s", r.out)
	}
	if !strings.Contains(r.out, "forged-passwd: forger:x:"+uid+":"+gid+"::"+n.canonical+"/fakehome:/bin/sh") {
		t.Fatalf("control: getent does not read the forged file after the bind, so it was not "+
			"shadowed:\n%s", r.out)
	}
	shadowed := r.out[strings.Index(r.out, "--- shadowed"):]
	t.Logf("the inner snug over the forged /etc:\n%s", shadowed)
	if !strings.Contains(shadowed, "shadowed-exit="+strconv.Itoa(exitPolicyCode)) {
		t.Errorf("the inner snug did not refuse (want exit %d) over a forged /etc/passwd:\n%s",
			exitPolicyCode, shadowed)
	}
	// Which of the mount rule's tests fires first depends on what backs the
	// forger's directory: a writable tmpfs here, ext4 on the CI runner. Any
	// of them is the rule refusing; a refusal for some other reason is not.
	mountRule := false
	for _, why := range []string{"/etc/passwd: its mount is not read-only",
		"/etc/passwd: it is on a ", "/etc/passwd: it is on device "} {
		if strings.Contains(shadowed, why) {
			mountRule = true
		}
	}
	if !mountRule {
		t.Errorf("the refusal is not the mount rule's:\n%s", shadowed)
	}
	if !strings.Contains(shadowed, "the file there now is not it") ||
		strings.Contains(shadowed, "generate none") {
		t.Errorf("the refusal names the missing-file fix (nss) for a file that is there but forged:\n%s", shadowed)
	}
	if strings.Contains(shadowed, "account: forger") {
		t.Errorf("the inner snug took the forged account:\n%s", shadowed)
	}
}

// TestNestedRunNeedsNoSeccompOff pins what a nested RUN costs, so nobody
// mistakes the nested --dry-run tests above for proof that snug runs under the
// default filter. A real snug run inside a sandbox with the default seccomp
// filter fails at the namespace creation the filter refuses; fails if the
// default filter ever lets that run start, which would mean it no longer
// blocks a payload making user namespaces. The control is the same inner run
// under --no-seccomp on the outer run: it must not fail with that message, so
// the message is the filter's and not something else's.
//
// What this does NOT show: that the inner run then completes. On the
// development host it stops later, at the procfs mount for the intermediate pid
// namespace ("__inpidns: mounting a procfs ... operation not permitted"), and
// the same stop was measured on a build of 60ed78c, before the account
// changes, so it is not new; this test deliberately asserts nothing about it.
func TestNestedRunNeedsNoSeccompOff(t *testing.T) {
	budget(t)
	requireNestedUserNamespace(t)
	const refusal = "fork/exec /proc/self/exe: operation not permitted"

	n := newNested(t)
	r := n.run(t, `./snug "$PWD" -- /bin/echo INNER-RAN; echo "inner-exit=$?"`).mustRun(t)
	if strings.Contains(r.out, "INNER-RAN") {
		t.Errorf("a nested snug run started under the default seccomp filter:\n%s", r.out)
	}
	if !strings.Contains(r.out, refusal) {
		t.Errorf("the nested run did not fail with %q:\n%s", refusal, r.out)
	}

	off := newNested(t, "--no-seccomp")
	ro := off.run(t, `./snug "$PWD" -- /bin/echo INNER-RAN; echo "inner-exit=$?"`).mustRun(t)
	if !strings.Contains(ro.out, "inner-exit=") {
		t.Fatalf("control: the inner snug never reported an exit, so it did not run:\n%s", ro.out)
	}
	if strings.Contains(ro.out, refusal) {
		t.Errorf("control: with --no-seccomp the inner run still fails with %q, so that message "+
			"is not the filter's:\n%s", refusal, ro.out)
	}
}
