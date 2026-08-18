package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The store key is what teardown uses as identity, so two different sandboxes
// must never share one, and the same sandbox must get the same one twice.
func TestStoreKeyIdentifiesTheSandbox(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	a, err := New([]policy.ProfileName{"@sys", "@podman-socket"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]policy.ProfileName{"@podman-socket", "@sys"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New([]policy.ProfileName{"@sys", "@podman-socket"}, "/proj/two")
	if err != nil {
		t.Fatal(err)
	}
	if a.store != b.store {
		t.Errorf("profile order changed the store: %s vs %s", a.store, b.store)
	}
	if a.store == c.store {
		t.Errorf("two targets share a store: %s", a.store)
	}
	if !strings.Contains(a.store, "/snug/engines/") {
		t.Errorf("store %q is not under snug's own engine directory", a.store)
	}

	// The socket and runroot (issue #63, Tier B) live under this RUN's own
	// /tmp directory — never under $XDG_DATA_HOME's store tree, which is
	// shared across runs on purpose, and never under $XDG_RUNTIME_DIR, which
	// a root-in-userns podman masks with its own tmpfs on /run.
	if strings.Contains(a.sock, "/snug/engines/") || strings.Contains(a.runroot, "/snug/engines/") {
		t.Errorf("socket %q / runroot %q must NOT be under the shared store tree", a.sock, a.runroot)
	}

	// The socket is the teardown identity and must name THIS run, not the
	// store — otherwise teardown reaches into a concurrent sandbox that
	// resolved to the same key.
	if a.sock == c.sock {
		t.Errorf("two sandboxes share a socket: %s", a.sock)
	}
	if !strings.Contains(a.sock, "podman-"+strconv.Itoa(os.Getpid())+".sock") {
		t.Errorf("socket %q does not identify this run", a.sock)
	}
	// The socket lives in THIS run's own hardened directory (createRunDir),
	// unique per pid. The runroot, MEASURED, deliberately does NOT: podman's
	// own libpod database (inside the persisted store) records the runroot a
	// run used and refuses a LATER run against the same store with a
	// different one, so runroot is keyed by the same profiles+target key the
	// store already is, shared across runs the way the store is (Spec's own
	// doc comment). The two are therefore in DIFFERENT directories now,
	// which is the corrected shape, not a regression of the earlier "both in
	// one run directory" assertion this replaces.
	if filepath.Dir(a.sock) == filepath.Dir(a.runroot) {
		t.Errorf("socket %q and runroot %q are in the same directory; the runroot must be keyed "+
			"by the store's own key so it stays stable across runs sharing that store, not by "+
			"this run's own pid", a.sock, a.runroot)
	}
	if !strings.Contains(a.runroot, "snug-engines-") {
		t.Errorf("runroot %q is not under the shared, store-keyed engines directory", a.runroot)
	}
}

// The engine's run directory is hardened, not a blind MkdirAll into
// world-writable /tmp: it must be owned by this uid and mode exactly 0700,
// and a second claim of the identical name (this test's own re-derivation of
// runDirName with the SAME sequence number New already consumed) must be
// refused rather than silently reused.
func TestEngineRunDirIsHardenedAndNotReused(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", e.runDir)
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		t.Errorf("run directory mode is %#o, want 0700", mode)
	}

	if err := createRunDir(e.runDir); err == nil {
		t.Fatal("createRunDir silently reused an existing directory; it must refuse")
	}
}

// ownedPIDs is what reaps an engine that is not snug's child. It has to find
// the real thing (positive control) and it must never claim a process that
// merely looks like podman.
func TestOwnedPIDsMatchesOnlyThisEnginesPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: a process whose command line names our socket. Without
	// this assertion the negative ones below could pass on a sweep that never
	// matches anything at all.
	mine := marker(t, "unix://"+e.sock)

	// Two things that must NEVER match: the user's own rootless podman, and a
	// CONCURRENT snug sandbox that resolved to the same store. The store is
	// shared on purpose (warm start), so it is not an identity.
	home, _ := os.UserHomeDir()
	theirs := marker(t, "podman --root "+filepath.Join(home, ".local/share/containers/storage")+
		" --runroot /run/user/1000/containers system service")

	sibling := marker(t, "podman --root "+e.store+" --runroot "+e.runroot+
		" system service --time 10 unix://"+filepath.Join(filepath.Dir(e.sock), "podman-999999.sock"))

	var pids []int
	for i := 0; i < 100; i++ {
		pids = ownedPIDs(e.paths(), map[int]bool{os.Getpid(): true})
		if len(pids) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	found := false
	for _, p := range pids {
		if p == mine.Process.Pid {
			found = true
		}
		if p == theirs.Process.Pid {
			t.Fatalf("the sweep claimed the host's own podman (pid %d); it must only ever "+
				"match this run's own socket", p)
		}
		if p == sibling.Process.Pid {
			t.Fatalf("the sweep claimed a concurrent sandbox's engine on the same store "+
				"(pid %d); teardown would kill a sibling that is still working", p)
		}
	}
	if !found {
		t.Fatalf("the sweep did not find pid %d, which names %s — it cannot reap what it "+
			"cannot see", mine.Process.Pid, e.store)
	}

	// Exclusion is honoured: the pid named in `exclude` is not returned, and
	// nothing else under test has crept in.
	//
	// It asserts about THESE pids rather than demanding the result be empty,
	// and the difference is what a CI failure taught. `len(excl) != 0` is a
	// claim about the whole machine — that no other process anywhere names our
	// socket — which is not what this test is named for and not something the
	// code under test controls. It failed once on a GitHub runner with one
	// unexplained pid, and the message said only "still got [4381]", so the
	// cause is not known and this comment will not pretend otherwise: the
	// helpers below no longer fork (one candidate removed) and anything
	// unexpected is now logged WITH ITS COMMAND LINE, so a recurrence explains
	// itself instead of costing another round trip.
	excl := ownedPIDs(e.paths(), map[int]bool{os.Getpid(): true, mine.Process.Pid: true})
	for _, p := range excl {
		switch p {
		case mine.Process.Pid:
			t.Errorf("exclusion is not honoured: pid %d was named in exclude and returned anyway", p)
		case theirs.Process.Pid, sibling.Process.Pid:
			t.Errorf("the sweep claimed pid %d, which does not own this engine's socket:\n%s",
				p, describe([]int{p}))
		}
	}
	if len(excl) > 0 {
		t.Logf("note: %d process(es) other than the ones under test name %s:\n%s",
			len(excl), e.sock, describe(excl))
	}
}

// marker starts a process whose command line contains arg and which NEVER
// FORKS, then blocks until the test ends.
//
// The non-forking part is deliberate. The helper used to be
// `sh -c "sleep 30; true" ARG`, and sh forks to run sleep — between the fork
// and the exec the child is a copy of sh, command line and marker included, so
// a /proc sweep can see a second pid carrying our socket. That was the leading
// theory for the CI failure above and it is NOT confirmed: 40 trials of a tight
// scan immediately after Start never caught the window on this developer's box.
// Removing the fork is still right (fewer processes, and one fewer thing the
// test depends on), it is simply not known to be the cause.
//
// `read` is a shell builtin, so this sh runs it in-process and never has a
// child at all; closing stdin is what ends it.
func marker(t *testing.T, arg string) *exec.Cmd {
	t.Helper()
	c := exec.Command("/bin/sh", "-c", "read x", arg)
	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	})
	return c
}

// The reaper is the only thing that runs after snug is SIGKILLed, and it is
// triggered by EOF on a pipe. Assert both edges: it fires on EOF, and it does
// nothing when snug cleaned up and said so.
func TestReaperFiresOnEOFAndStandsDown(t *testing.T) {
	run := func(t *testing.T, standDown bool) bool {
		dir := t.TempDir()
		marker := filepath.Join(dir, "reaped")
		fake := filepath.Join(dir, "podman")
		script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + marker + "\n"
		if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}

		sock := filepath.Join(dir, "podman-1.sock")
		r, err := startReaper(fake, filepath.Join(dir, "storage"), filepath.Join(dir, "rr"), sock, RunLabelKey+"=test")
		if err != nil {
			t.Fatal(err)
		}
		// The reaper must not name the socket in its own command line, or the
		// /proc sweep would find snug's own cleanup and report it as a leak.
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(r.cmd.Process.Pid) + "/cmdline")
		if err == nil && strings.Contains(string(cmdline), sock) {
			t.Errorf("the reaper's command line names the socket; the sweep will match itself")
		}

		if standDown {
			r.standDown()
		} else {
			r.w.Close() // exactly what the kernel does when snug is SIGKILLed
			_, _ = r.cmd.Process.Wait()
		}

		for i := 0; i < 200; i++ {
			if _, err := os.Stat(marker); err == nil {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}

	if !run(t, false) {
		t.Error("snug died and the reaper did not stop the sandbox's containers")
	}
	if run(t, true) {
		t.Error("snug cleaned up and told the reaper to stand down, but it ran anyway")
	}
}
