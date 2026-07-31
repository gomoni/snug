package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The store key is what teardown uses as identity, so two different sandboxes
// must never share one, and the same sandbox must get the same one twice.
func TestStoreKeyIdentifiesTheSandbox(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	a, err := New([]string{"@sys", "@podman-socket"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]string{"@podman-socket", "@sys"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New([]string{"@sys", "@podman-socket"}, "/proj/two")
	if err != nil {
		t.Fatal(err)
	}
	if a.store != b.store {
		t.Errorf("profile order changed the store: %s vs %s", a.store, b.store)
	}
	if a.store == c.store {
		t.Errorf("two targets share a store: %s", a.store)
	}
	if !strings.Contains(a.store, "/snug/engines/") || !strings.Contains(a.runroot, "/snug/engines/") {
		t.Errorf("store %q / runroot %q are not under snug's own engine directory", a.store, a.runroot)
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
	if filepath.Dir(a.sock) != filepath.Dir(a.runroot) {
		t.Errorf("socket %q is not in this engine's own runtime directory", a.sock)
	}
}

// ownedPIDs is what reaps an engine that is not snug's child. It has to find
// the real thing (positive control) and it must never claim a process that
// merely looks like podman.
func TestOwnedPIDsMatchesOnlyThisEnginesPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	e, err := New([]string{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: a process whose command line names our socket. Without
	// this assertion the negative ones below could pass on a sweep that never
	// matches anything at all.
	mine := exec.Command("/bin/sh", "-c", "sleep 30; true", "unix://"+e.sock)
	if err := mine.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mine.Process.Kill(); _, _ = mine.Process.Wait() }()

	// Two things that must NEVER match: the user's own rootless podman, and a
	// CONCURRENT snug sandbox that resolved to the same store. The store is
	// shared on purpose (warm start), so it is not an identity.
	home, _ := os.UserHomeDir()
	theirs := exec.Command("/bin/sh", "-c", "sleep 30; true",
		"podman --root "+filepath.Join(home, ".local/share/containers/storage")+
			" --runroot /run/user/1000/containers system service")
	if err := theirs.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = theirs.Process.Kill(); _, _ = theirs.Process.Wait() }()

	sibling := exec.Command("/bin/sh", "-c", "sleep 30; true",
		"podman --root "+e.store+" --runroot "+e.runroot+
			" system service --time 10 unix://"+filepath.Join(filepath.Dir(e.sock), "podman-999999.sock"))
	if err := sibling.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sibling.Process.Kill(); _, _ = sibling.Process.Wait() }()

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

	if excl := ownedPIDs(e.paths(), map[int]bool{os.Getpid(): true, mine.Process.Pid: true}); len(excl) != 0 {
		t.Errorf("exclusion is not honoured: still got %v", excl)
	}
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
		r, err := startReaper(fake, filepath.Join(dir, "storage"), filepath.Join(dir, "rr"), sock)
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
