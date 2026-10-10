//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// oPathFlag is O_PATH as /proc/<pid>/fdinfo prints it: the octal "flags:"
// value of a descriptor opened with O_PATH carries 010000000.
const oPathFlag = 0o10000000

// oPathFDs lists the descriptors of pid that were opened with O_PATH, as
// "fd->target". ok is false when the process or its fd table could not be read
// at all, which is not the same as "has none" and callers must not treat it so.
func oPathFDs(pid int) (found []string, ok bool) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	for _, e := range ents {
		info, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/fdinfo/" + e.Name())
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(info), "\n") {
			v, isFlags := strings.CutPrefix(line, "flags:")
			if !isFlags {
				continue
			}
			flags, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
			if err == nil && flags&oPathFlag != 0 {
				target, _ := os.Readlink(dir + "/" + e.Name())
				found = append(found, e.Name()+"->"+target)
			}
		}
	}
	return found, true
}

// bindGrantProfiles writes a profile granting n distinct directories, each
// with a marker file, read-only at /mnt/gN, and returns the env and the host
// directories.
func bindGrantProfiles(t *testing.T, n int) (env []string, dirs []string) {
	t.Helper()
	root := t.TempDir()
	var ro []string
	for i := 0; i < n; i++ {
		d := filepath.Join(root, fmt.Sprintf("g%d", i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte(fmt.Sprintf("GRANT-%d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
		ro = append(ro, fmt.Sprintf("%q", fmt.Sprintf("%s:/mnt/g%d", d, i)))
	}
	toml := "[profile.binds]\ndescription = \"several read-only grants, to count the descriptors they cost\"\n" +
		"# ABUSE: none; the grants are the test's own temp directories.\n" +
		"ro = [" + strings.Join(ro, ", ") + "]\n"
	return writeProfiles(t, map[string]string{"binds": toml}), dirs
}

// payloadFDListing prints the payload shell's own descriptor numbers, one per
// line, after opening nothing. `ls` lists /proc/$$/fd of the shell, so its own
// directory descriptor is not in the answer.
const payloadFDListing = `ls -1 /proc/$$/fd | sort -n | tr '\n' ' '; echo`

// TestPayloadInheritsNoBindSourceFD fails if any of the descriptors snug opens
// for the grants reaches the payload: an O_PATH fd on a granted directory is a
// handle the payload could use with openat(2)-relative walks, and one on a
// directory above the payload's view would be a way out. Both topologies are
// run, because the unstaged and the @net arm pass the descriptors through
// different processes.
//
// The positive controls are two: the payload really holds a descriptor it
// opened itself (7) when it lists them, so the listing can see numbers beyond
// 0-2, and the grants really are bound (GRANT-n read back), so the run had
// binds whose sources could have leaked. What this does not reach is a leak
// into some process other than the payload; TestBindSourceFDsDoNotOutliveBwrapSetup
// scans the rest of the tree.
func TestPayloadInheritsNoBindSourceFD(t *testing.T) {
	budget(t)
	requireSandbox(t)
	env, _ := bindGrantProfiles(t, 6)
	proj, _ := target(t)

	read := `for i in 0 1 2 3 4 5; do cat /mnt/g$i/f; done`
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"unstaged", []string{"-p", "binds"}},
		{"net", []string{"-p", "binds", "-p", "@net"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "net" {
				requirePasta(t)
			}
			r := runEnv(t, env, tc.args, proj, read+"\n"+payloadFDListing+"\nexec 7</dev/null; "+payloadFDListing).mustRun(t)
			for i := 0; i < 6; i++ {
				if !strings.Contains(r.out, fmt.Sprintf("GRANT-%d", i)) {
					t.Fatalf("control: grant %d is not readable inside, so there were no live binds to leak:\n%s", i, r.out)
				}
			}
			lines := strings.Split(strings.TrimSpace(r.out), "\n")
			if len(lines) < 2 {
				t.Fatalf("control: expected two fd listings at the end of the output:\n%s", r.out)
			}
			before, with7 := strings.TrimSpace(lines[len(lines)-2]), strings.TrimSpace(lines[len(lines)-1])
			if with7 != "0 1 2 7" {
				t.Fatalf("control: after opening fd 7 the listing is %q, so it cannot see extra descriptors", with7)
			}
			if before != "0 1 2" {
				t.Errorf("the payload's descriptors are %q, want exactly 0 1 2; the extras are bind sources or other leaks:\n%s",
					before, r.out)
			}
		})
	}
}

// TestBindSourceFDsDoNotOutliveBwrapSetup fails if a descriptor snug opened
// for a grant is still held, once the payload is running, by any process under
// snug other than snug itself: the stage, bwrap, the sandbox init and pasta
// were all handed the block at some point, and anything that kept an O_PATH
// handle on a granted directory keeps it for the life of the sandbox and is
// reachable through /proc/<pid>/fd by anything that can ptrace it.
//
// The positive control is snug's own process, which MUST show at least one
// O_PATH descriptor per grant: if the scan cannot see those it cannot see a
// leak either. Processes whose fd table is unreadable are counted and logged,
// never read as clean: on the @net arm that is pasta, measured here as the one
// process whose table this uid cannot read, so a leak into pasta is the part
// this does not reach.
func TestBindSourceFDsDoNotOutliveBwrapSetup(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	env, _ := bindGrantProfiles(t, 6)
	proj, _ := target(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"unstaged", []string{"-p", "binds"}},
		{"net", []string{"-p", "binds", "-p", "@net"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "net" {
				requirePasta(t)
			}
			s := startBgSandbox(t, env, tc.args, proj, "sleep 30")
			s.ready(t)

			root, ok := oPathFDs(s.pid())
			if !ok || len(root) < 6 {
				t.Fatalf("control: snug itself shows %v (readable=%v), want an O_PATH descriptor per grant", root, ok)
			}
			unreadable, scanned := 0, 0
			for _, pid := range descendantsOf(s.pid()) {
				got, readable := oPathFDs(pid)
				if !readable {
					unreadable++
					t.Logf("pid %d (%s) has an fd table this uid cannot read; not scanned", pid, commOf(pid))
					continue
				}
				scanned++
				if len(got) > 0 {
					t.Errorf("pid %d (%s) still holds O_PATH descriptors on the grants: %v", pid, commOf(pid), got)
				}
			}
			t.Logf("scanned %d descendants, %d unreadable", scanned, unreadable)
			if scanned == 0 {
				t.Fatal("control: no descendant of snug could be scanned, so nothing was measured")
			}
		})
	}
}

// TestConcurrentSandboxCannotSwapAGrantSourceBetweenResolveAndBind is the
// reproduction from the ticket that made every bind descriptor-based, written
// to fail loudly on the old behaviour.
//
// A sandbox with rw on a directory (swap) renames a symlink to a secret
// directory into the place a second invocation (reader) has granted, in a loop;
// the reader runs 200 times and each run reads /mnt/x/f. With the grant passed
// to bwrap as a path, a fraction of those runs read the secret instead of the
// directory that was granted; with the grant opened by snug before bwrap
// starts, a swapped component is refused (policy exit, or bwrap finding the
// source missing mid-rename) and nothing may print the secret.
//
// What it does not do is prove the race window was hit on any given run: the
// host side of the test samples the granted path while the loop runs and
// requires to have seen the symlink at least once, so a swap sandbox that
// never swapped cannot pass, but the reader's own open and the swap are not
// aligned. The old behaviour is the mutation check, not a control in the test.
func TestConcurrentSandboxCannotSwapAGrantSourceBetweenResolveAndBind(t *testing.T) {
	budget(t, 4*time.Minute)
	requireSandbox(t)

	s := t.TempDir()
	for _, d := range []string{"work/d", "secret", "proj"} {
		if err := os.MkdirAll(filepath.Join(s, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(s, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("work/d/f", "BENIGN\n")
	write("secret/f", "RACE-SECRET\n")
	if err := os.Symlink(filepath.Join(s, "secret"), filepath.Join(s, "work/evil")); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(s, "proj")

	env := writeProfiles(t, map[string]string{
		"swap": "[profile.swap]\ndescription = \"the attacker: rw on the directory the reader grants a child of\"\n" +
			"rw = [\"" + filepath.Join(s, "work") + "\"]\n",
		"reader": "[profile.reader]\ndescription = \"the victim: a read-only grant of a directory the attacker can rename\"\n" +
			"ro = [\"" + filepath.Join(s, "work/d") + ":/mnt/x\"]\n",
	})

	// Control, before any swapping: the reader's grant shows the benign file.
	out, code := cli(t, env, "-p", "reader", proj, "--", "/bin/cat", "/mnt/x/f")
	if code != 0 || strings.TrimSpace(out) != "BENIGN" {
		t.Fatalf("control: the unraced reader printed %q (exit %d), want BENIGN", out, code)
	}

	// The swap loop, the ticket's four renames. It stops when work/stop
	// appears or after a bound, so a test that dies leaves nothing spinning. The
	// 0-3ms sleep is random so the granted path is a real directory often enough
	// for a run to resolve it cleanly and then meet the swap at bwrap's open; with
	// no sleep almost every run met a link at resolve and was refused before bwrap
	// was involved. Measured with the path form of the bind put back: 10 of 200
	// runs printed the secret (2 of 200 with no sleep). With RESOLVE_NO_SYMLINKS
	// dropped from the opener instead: 11 of 200.
	w := filepath.Join(s, "work")
	swapper := startBgSandbox(t, env, []string{"-p", "swap"}, proj, fmt.Sprintf(
		`cd %[1]s; i=0
while [ ! -e %[1]s/stop ] && [ $i -lt 200000 ]; do
  mv -T d tmpd 2>/dev/null; mv -T evil d 2>/dev/null; mv -T d evil 2>/dev/null; mv -T tmpd d 2>/dev/null
  i=$((i+1)); echo $i > %[1]s/count
  sleep 0.00$((RANDOM %% 4))
done`, w))
	swapper.ready(t)
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(w, "stop"), nil, 0o644) })

	// Sample the host's view of the granted path: the symlink must be seen at
	// least once, or the loop never did what the test says it does.
	var sawLink atomic.Int64
	stopSample := make(chan struct{})
	var sampled sync.WaitGroup
	sampled.Add(1)
	go func() {
		defer sampled.Done()
		for {
			select {
			case <-stopSample:
				return
			default:
			}
			if fi, err := os.Lstat(filepath.Join(w, "d")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				sawLink.Add(1)
			}
		}
	}()

	const attempts = 200
	var secret, benign, refused, other int
	var otherSample string
	for i := 0; i < attempts; i++ {
		out, code := cli(t, env, "-p", "reader", proj, "--", "/bin/cat", "/mnt/x/f")
		switch {
		case strings.Contains(out, "RACE-SECRET"):
			secret++
		case strings.TrimSpace(out) == "BENIGN" && code == 0:
			benign++
		case code == 77:
			refused++
		default:
			other++
			otherSample = out
		}
	}
	close(stopSample)
	sampled.Wait()
	cnt, _ := os.ReadFile(filepath.Join(w, "count"))
	t.Logf("attempts=%d secret=%d benign=%d refused77=%d other=%d; swap loop iterations=%s; host saw the symlink %d times",
		attempts, secret, benign, refused, other, strings.TrimSpace(string(cnt)), sawLink.Load())
	if other > 0 {
		t.Logf("last 'other' output (bwrap saying the source is gone mid-rename is expected):\n%s", otherSample)
	}

	if secret > 0 {
		t.Errorf("%d of %d runs read RACE-SECRET, a file the reader never granted: the grant source was re-resolved by path after snug resolved it", secret, attempts)
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(cnt))); n < 10 {
		t.Errorf("control: the swap loop completed %d iterations; the attacker sandbox did not run the race", n)
	}
	if sawLink.Load() == 0 {
		t.Error("control: the host never saw the granted path as a symlink, so no swap was in flight while the readers ran")
	}
	if benign+refused+other != attempts {
		t.Errorf("accounting: %d+%d+%d != %d", benign, refused, other, attempts)
	}
}

// fakeBwrapOnPath returns an env whose PATH starts with a directory holding a
// `bwrap` that forwards everything to the real one, except that --help is
// answered with the real help minus the descriptor-bind lines when
// withoutFDBinds is set.
func fakeBwrapOnPath(t *testing.T, base []string, withoutFDBinds bool) []string {
	t.Helper()
	real, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	filter := "cat"
	if withoutFDBinds {
		filter = "grep -v -e '--ro-bind-fd' -e '--bind-fd'"
	}
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --help ]; then %q --help 2>&1 | %s; exit 0; fi\nexec %q \"$@\"\n", real, filter, real)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return append(append([]string{}, base...), "PATH="+dir+":"+os.Getenv("PATH"))
}

// TestMissingBindFDSupportRefusesTheRun fails if a bubblewrap that does not
// list --ro-bind-fd/--bind-fd is allowed to start a sandbox: the failure would
// then arrive as an option-parse error from inside bwrap, or worse as a
// fallback to path binds. The control is the same wrapper forwarding the real
// --help, which must run the payload, so the refusal is the missing flag's and
// not the wrapper's.
func TestMissingBindFDSupportRefusesTheRun(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := runEnv(t, fakeBwrapOnPath(t, baseEnv(), false), nil, proj, "echo CONTROL-RAN").mustRun(t)
	if !strings.Contains(r.out, "CONTROL-RAN") || r.code != 0 {
		t.Fatalf("control: the forwarding wrapper broke the run (exit %d):\n%s", r.code, r.out)
	}

	r = runEnv(t, fakeBwrapOnPath(t, baseEnv(), true), nil, proj, "echo SHOULD-NOT-RUN")
	if r.ran || r.code == 0 {
		t.Errorf("a bwrap without --ro-bind-fd started the sandbox (ran=%v exit=%d):\n%s", r.ran, r.code, r.out)
	}
	for _, want := range []string{"--ro-bind-fd", "upgrade bubblewrap"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, r.out)
		}
	}
}

// TestEngineInheritsNoBindSourceFD fails if the container engine snug forks
// into the sandbox's network namespace (and anything it starts) holds one of
// the O_PATH descriptors opened for the grants: the engine runs with more
// capability than the payload, outside its pid namespace, and a handle on a
// granted directory would outlive the mount it was meant for.
//
// Positive controls: snug itself shows an O_PATH descriptor per grant, and an
// engine process (one whose command line names podman or __inengine) is among
// the scanned descendants, so "no leak" is not true of a run that never started
// an engine. Skips like the other engine tests when no usable engine exists
// here, and says so; SNUG_REQUIRE_ENGINE makes that a failure.
func TestEngineInheritsNoBindSourceFD(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := bindGrantProfiles(t, 6)
	requireRealEngine(t, env)
	proj, _ := target(t)

	s := startBgSandbox(t, env, []string{"-p", "binds", "-p", "@podman-socket", "-p", "@net"}, proj, "sleep 60")
	s.ready(t)

	root, ok := oPathFDs(s.pid())
	if !ok || len(root) < 6 {
		t.Fatalf("control: snug itself shows %v (readable=%v), want an O_PATH descriptor per grant", root, ok)
	}
	engines, scanned, unreadable := 0, 0, 0
	for _, pid := range descendantsOf(s.pid()) {
		cmdline, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if c := string(cmdline); strings.Contains(c, "podman") || strings.Contains(c, "__inengine") {
			engines++
		}
		got, readable := oPathFDs(pid)
		if !readable {
			unreadable++
			t.Logf("pid %d (%s) has an fd table this uid cannot read; not scanned", pid, commOf(pid))
			continue
		}
		scanned++
		if len(got) > 0 {
			t.Errorf("pid %d (%s) holds O_PATH descriptors on the grants: %v", pid, commOf(pid), got)
		}
	}
	t.Logf("scanned %d descendants (%d engine processes), %d unreadable", scanned, engines, unreadable)
	if engines == 0 {
		t.Fatal("control: no engine process under snug, so an engine's descriptors were not looked at")
	}
}
