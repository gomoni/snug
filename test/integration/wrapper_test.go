//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snug's own binary is the http door's entry and the login bridge's BROWSER
// (internal/wrapper), bound read-only at /snug/lib/snug/wrapper. These tests
// run the real binary and assert what the payload finds there. The two things
// that make a negative here worth anything: every payload prints a marker, and
// the runtime in the "no shell" selections is a directory that contains only
// the probe, with the same selection shown to have no /bin/sh.

// bareRuntime returns a host directory holding copies of the given files, to be
// granted as the sandbox's /usr: a runtime with no shell, no libc and no
// loader, so only a static binary runs in it.
func bareRuntime(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// bareDoorEnv writes the user profile "barerun" (the bare runtime as /usr, one
// http door) and returns the environment and the selection that uses nothing
// else: --no-defaults, so @sys is not there.
func bareDoorEnv(t *testing.T, rt string) (env, sel []string) {
	t.Helper()
	env = envProfileLayer(t, "bare.toml", fmt.Sprintf(`[profile.barerun]
description = "a runtime with only a static probe in it, and one http door"
ro = ["%s:/usr"]
listen_names = ["web"]
`, rt), os.Getenv("PATH"))
	return env, []string{"--no-defaults", "-p", "@target-rw", "-p", "barerun"}
}

// TestTheHTTPDoorWorksWithoutASystemProfile fails if a door needs anything of
// the sandbox's runtime: a shell, a libc, a loader. The only thing granted as
// /usr is a directory holding a static probe. The probe must receive
// LISTEN_PID equal to its own pid, accept on fd 3, and answer a host request.
//
// Controls: the same selection cannot run /bin/sh at all (so "no shell" is a
// fact of this run, not an assumption), and the probe's own report is read
// before anything is asserted about it. It does not run a dynamically linked
// payload; that is every other door test.
func TestTheHTTPDoorWorksWithoutASystemProfile(t *testing.T) {
	probe := buildDoorProbe(t) // before budget(t), as the sibling tests
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	rt := bareRuntime(t, map[string]string{"doorprobe": probe})
	env, sel := bareDoorEnv(t, rt)

	// Control: no shell in this selection. The wrapper reports 127 for a
	// command it cannot find; the marker below is the probe's, so a refusal
	// that happened before the sandbox started would not satisfy it.
	out, code := cli(t, env, append(append([]string{}, sel...), proj, "--", "/bin/sh", "-c", "echo SHELL-RAN")...)
	if code != 127 || strings.Contains(out, "SHELL-RAN") || !strings.Contains(out, "snug wrapper") {
		t.Fatalf("control: /bin/sh in the bare selection exited %d, want 127 from the wrapper with no shell output:\n%s", code, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, append(append([]string{}, sel...), proj, "--", "/usr/doorprobe")...)
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	var log strings.Builder
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting snug: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	found := awaitDoorProbe(t, proj)
	pid, mine := found["LISTEN-PID"], found["MY-PID"]
	if pid == "" || mine == "" || pid != mine {
		t.Errorf("LISTEN_PID = %q, the payload's own pid = %q: want both present and equal", pid, mine)
	}
	if found["LISTEN-FDS"] != "1" || found["LISTEN-FDNAMES"] != "web" {
		t.Errorf("LISTEN_FDS=%q LISTEN_FDNAMES=%q, want 1 and web", found["LISTEN-FDS"], found["LISTEN-FDNAMES"])
	}
	sock := found["SOCKET"]
	if sock == "" {
		t.Fatalf("the payload reported no socket; it did not get a listener on fd 3:\n%s", log.String())
	}
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		t.Fatalf("the host cannot reach the door socket %s: %v", sock, err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: doortest\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "served-by-the-payload") {
		t.Errorf("the door carried no answer from the payload:\n%s", body)
	}
}

// TestTheDoorEntryExitCodes fails if the wrapper changes what the payload's
// exit status looks like from outside: 127 for a command that is not there, 126
// for one that cannot be run, and the payload's own code otherwise. These are
// what the /bin/sh `exec` it replaced returned. The passthrough case prints a
// marker, so a 7 that came from the wrapper rather than the payload would not
// pass; the bare runtime is the same as above, so no shell is in the way.
func TestTheDoorEntryExitCodes(t *testing.T) {
	probe := buildDoorProbe(t)
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	rt := bareRuntime(t, map[string]string{"doorprobe": probe})
	env, sel := bareDoorEnv(t, rt)

	run := func(cmd ...string) (string, int) {
		return cli(t, env, append(append(append([]string{}, sel...), proj, "--"), cmd...)...)
	}

	out, code := run("/usr/doorprobe", "exit", "7")
	if code != 7 || !strings.Contains(out, "EXIT-PROBE-RAN") {
		t.Errorf("a payload exiting 7 gave snug exit %d (marker present: %v):\n%s",
			code, strings.Contains(out, "EXIT-PROBE-RAN"), out)
	}
	// And the marker carries the pid the wrapper handed over, equal to the
	// payload's own: the same property as the test above, on a second payload.
	var pid, lpid int
	if _, err := fmt.Sscanf(out[strings.Index(out, "pid="):], "pid=%d listen_pid=%d", &pid, &lpid); err != nil || pid == 0 || pid != lpid {
		t.Errorf("pid and LISTEN_PID in the marker are %d and %d (%v):\n%s", pid, lpid, err, out)
	}

	out, code = run("/usr/doorprobe", "exit", "0")
	if code != 0 || !strings.Contains(out, "EXIT-PROBE-RAN") {
		t.Errorf("a payload exiting 0 gave snug exit %d:\n%s", code, out)
	}

	out, code = run("/usr/not-there")
	if code != 127 || strings.Contains(out, "EXIT-PROBE-RAN") || !strings.Contains(out, "snug wrapper: /usr/not-there") {
		t.Errorf("a missing command gave exit %d, want 127 with the wrapper's message:\n%s", code, out)
	}

	out, code = run("/usr")
	if code != 126 || !strings.Contains(out, "snug wrapper: /usr") {
		t.Errorf("a directory as the command gave exit %d, want 126 with the wrapper's message:\n%s", code, out)
	}
}

// TestTheWrapperInsideIsReadOnlyNosuidAndOffPATH fails if the payload can
// modify, replace, remove or add to what is at /snug/lib/snug, if the mount
// is not read-only and nosuid, or if /snug/lib is on the payload's PATH. The
// payload is bash under the default profiles (the door is not the subject, the
// wrapper's mount is). Controls: the wrapper is there and executable, the same
// writes succeed in /tmp, and the first bytes of the wrapper are still an ELF
// header afterwards.
func TestTheWrapperInsideIsReadOnlyNosuidAndOffPATH(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "door.toml", `[profile.doortest]
description = "one http door"
listen_names = ["web"]
`, os.Getenv("PATH"))

	out, code := cli(t, env, "-p", "doortest", proj, "--", "/bin/bash", "-c", `
echo "MARK-PAYLOAD-RAN"
[ -x /snug/lib/snug/wrapper ] && echo CTL-WRAPPER-EXEC
touch /tmp/ctl && echo CTL-TMP-WRITE
awk '$5 == "/snug/lib/snug/wrapper" {print "WRAPPER-OPTS " $6}' /proc/self/mountinfo
echo "PATH-IS $PATH"
(touch /snug/lib/snug/x) 2>&1;                echo "TOUCH-RC $?"
(touch /snug/lib/x) 2>&1;                     echo "TOUCH-LIB-RC $?"
(printf x >> /snug/lib/snug/wrapper) 2>&1;    echo "APPEND-RC $?"
(rm -f /snug/lib/snug/wrapper) 2>&1;          echo "RM-RC $?"
(mv /snug/lib /snug/lib2) 2>&1;               echo "MV-RC $?"
(ln -s /tmp /snug/lib/snug/browser) 2>&1;     echo "LN-RC $?"
(mkdir /snug/lib/snug/d) 2>&1;                echo "MKDIR-RC $?"
echo "MAGIC $(head -c 4 /snug/lib/snug/wrapper | tail -c 3)"
`)
	if code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, out)
	}
	for _, m := range []string{"MARK-PAYLOAD-RAN", "CTL-WRAPPER-EXEC", "CTL-TMP-WRITE"} {
		if !strings.Contains(out, m) {
			t.Fatalf("control %s missing, so the refusals below measure nothing:\n%s", m, out)
		}
	}
	for _, rc := range []string{"TOUCH", "TOUCH-LIB", "APPEND", "RM", "MV", "LN", "MKDIR"} {
		if v := fieldOf(out, rc+"-RC"); v == "" || v == "0" {
			t.Errorf("%s inside succeeded or never ran (rc %q):\n%s", rc, v, out)
		}
	}
	if opts := fieldOf(out, "WRAPPER-OPTS"); !strings.HasPrefix(opts, "ro,") || !strings.Contains(opts, "nosuid") {
		t.Errorf("the wrapper mount options are %q, want read-only and nosuid", opts)
	}
	if fieldOf(out, "MAGIC") != "ELF" {
		t.Errorf("the wrapper is no longer an ELF after the attempts:\n%s", out)
	}
	path := fieldOf(out, "PATH-IS")
	if path == "" {
		t.Fatalf("control: PATH was not printed:\n%s", out)
	}
	for _, d := range strings.Split(path, ":") {
		if d == "/snug/lib" || d == "/snug/lib/snug" {
			t.Errorf("PATH %q has %s on it", path, d)
		}
	}
}

// TestTheWrapperRefusesEveryVerbButTheDoorEntry fails if the in-sandbox copy of
// snug does anything but its door entry when run by the payload: the hidden
// re-exec verbs, a bare invocation, and the BROWSER-less case must all exit 2
// with no payload-visible effect. It does not show those verbs are harmless
// when run from a copy at another path; a copy the payload writes itself runs
// them all the same, and that is why the wrapper is not a boundary.
func TestTheWrapperRefusesEveryVerbButTheDoorEntry(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "door.toml", `[profile.doortest]
description = "one http door"
listen_names = ["web"]
`, os.Getenv("PATH"))

	out, code := cli(t, env, "-p", "doortest", proj, "--", "/bin/bash", "-c", `
echo "MARK-PAYLOAD-RAN"
W=/snug/lib/snug/wrapper
$W >/dev/null 2>&1;                       echo "BARE-RC $?"
$W __stage-setup >/dev/null 2>&1;         echo "STAGE-RC $?"
$W __innetns /bin/true >/dev/null 2>&1;   echo "INNETNS-RC $?"
$W --version >/dev/null 2>&1;             echo "VERSION-RC $?"
$W /tmp >/dev/null 2>&1;                  echo "TARGET-RC $?"
$W __door-exec >/dev/null 2>&1;           echo "NOCMD-RC $?"
$W __door-exec /bin/echo CTL-DOOR-EXEC-RAN 2>&1
$W --help 2>&1 | head -3
`)
	if code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "MARK-PAYLOAD-RAN") || !strings.Contains(out, "CTL-DOOR-EXEC-RAN") {
		t.Fatalf("controls missing: the payload or the one verb the wrapper does run did not:\n%s", out)
	}
	for _, rc := range []string{"BARE", "STAGE", "INNETNS", "VERSION", "TARGET", "NOCMD"} {
		if v := fieldOf(out, rc+"-RC"); v != "2" {
			t.Errorf("%s: wrapper exited %q, want 2:\n%s", rc, v, out)
		}
	}
	if strings.Contains(out, "usage:") || strings.Contains(out, "Usage:") {
		t.Errorf("the wrapper printed snug's CLI usage:\n%s", out)
	}
}

// fieldOf returns the rest of the first line of out that starts with key and a
// space, or "" if none does.
func fieldOf(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(l, key+" "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// TestTheBrowserBridgeWorksWithoutASystemProfile fails if login.claude
// needs a shell or a loader in the sandbox again. The runtime is a directory
// holding nothing (granted as /usr), the payload is the static loginprobe
// from the target, and BROWSER leads to snug's own binary. The host's fake
// opener must receive the rebuilt URL: that is the bridge reaching the host
// through the FIFO, which a wrapper that exited 0 without writing would not
// do.
//
// Control: the same selection cannot run /bin/sh (bwrap cannot exec it, so the
// run exits non-zero without the marker). It does not show the login
// completes; scripts/ owns that.
func TestTheBrowserBridgeWorksWithoutASystemProfile(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")
	rt := bareRuntime(t, nil)
	f.addProfile(t, "barerun", fmt.Sprintf("[profile.barerun]\ndescription = \"a /usr with nothing in it\"\nro = [\"%s:/usr\"]\n", rt))
	args := []string{"--no-defaults", "-p", "@target-rw", "-p", "barerun", "-p", "@net", "-p", "login"}

	out, code := cli(t, f.env, append(append([]string{}, args...), f.proj, "--", "/bin/sh", "-c", "echo SHELL-RAN")...)
	if code == 0 || strings.Contains(out, "SHELL-RAN") {
		t.Fatalf("control: a shell ran in the bare selection (exit %d):\n%s", code, out)
	}

	out, code = cli(t, f.env, append(append([]string{}, args...), f.proj, "--", "./loginprobe",
		"state="+loginState, "challenge="+loginChallenge)...)
	if code != 0 || !strings.Contains(out, "PROBE-DONE") {
		t.Fatalf("the probe did not finish in the bare selection (exit %d):\n%s", code, out)
	}
	if v, _ := loginField(out, "BROWSER"); v != "/snug/lib/snug/browser" {
		t.Errorf("BROWSER inside is %q, want /snug/lib/snug/browser:\n%s", v, out)
	}
	if v, _ := loginField(out, "SHIM-RC"); v != "0" {
		t.Errorf("BROWSER exited %q, want 0:\n%s", v, out)
	}
	port := loginPort(t, out)
	argv, ok := loginRec(t, f.rec, "argv")
	if !ok {
		t.Fatalf("the host's opener never ran: the URL did not cross the FIFO:\n%s", out)
	}
	if want := "argc=1\nargv=" + fmt.Sprintf(loginRebuiltFmt, port, loginChallenge, loginState) + "\n"; argv != want {
		t.Errorf("the opener's argv was\n%q\nwant\n%q", argv, want)
	}
}

// TestTheBrowserLinkRefusesAnythingButOneLine fails if BROWSER hands the host
// anything other than exactly one URL: two arguments, none, or an argument with
// a newline in it all exit 2 and the host's opener does not run. Control: a
// single well-formed argument exits 0 in the same script (the host refuses it
// as not the Claude login URL, which is the host side's verdict and the
// reason the opener still has not run), so the FIFO was open and writable and
// the 2s are the wrapper's own.
func TestTheBrowserLinkRefusesAnythingButOneLine(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")

	r := runEnv(t, f.env, loginBridgeArgs, f.proj, `
"$BROWSER" https://example.com/ ; echo "ONE-RC $?"
"$BROWSER" https://example.com/ https://example.org/ ; echo "TWO-RC $?"
"$BROWSER" ; echo "NONE-RC $?"
"$BROWSER" $'https://example.com/\nhttps://example.org/' ; echo "NEWLINE-RC $?"
"$BROWSER" "$(head -c 5000 /dev/zero | tr '\0' a)" ; echo "LONG-RC $?"
`).mustRun(t)
	if v := fieldOf(r.out, "ONE-RC"); v != "0" {
		t.Fatalf("control: one well-formed argument exited %q, want 0:\n%s", v, r.out)
	}
	for _, rc := range []string{"TWO", "NONE", "NEWLINE", "LONG"} {
		if v := fieldOf(r.out, rc+"-RC"); v != "2" {
			t.Errorf("%s: snug-browser exited %q, want 2:\n%s", rc, v, r.out)
		}
	}
	if !strings.Contains(r.out, "snug-browser: expected exactly one URL") {
		t.Errorf("the usage message is missing:\n%s", r.out)
	}
	if n := loginRunCount(t, f.rec); n != 0 {
		t.Errorf("the host's opener ran %d times, want 0", n)
	}
}
