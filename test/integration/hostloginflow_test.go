//go:build integration

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests drive the real snug binary through a host-mode login against
// hostVendor, with a fake browser (the test) and a scratch home. What is NOT
// real: Claude's servers, the browser, and Claude Code inside. What the
// binary does with the answers, to the files, is.

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// waitGone polls until path no longer exists.
func waitPathGone(path string, d time.Duration) bool {
	for end := time.Now().Add(d); ; time.Sleep(25 * time.Millisecond) {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// waitFileHas polls until the file at path holds want.
func waitFileHas(path, want string, d time.Duration) bool {
	for end := time.Now().Add(d); ; time.Sleep(25 * time.Millisecond) {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), want) {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// requireHostLoginUntouched fails unless the host credential file is
// byte-identical, with its mtime and mode, to what the test recorded before
// the run.
func requireHostLoginUntouched(t *testing.T, path string, before []byte, mtime time.Time, why string) {
	t.Helper()
	after := mustRead(t, path)
	if !bytes.Equal(after, before) {
		t.Errorf("%s: the host's ~/.claude/.credentials.json changed (%d bytes before, %d after)", why, len(before), len(after))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(mtime) || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: the host credential file's mtime/mode moved (mtime %v -> %v, mode %v)", why, mtime, fi.ModTime(), fi.Mode().Perm())
	}
}

// hostMidExchange starts a host-mode run whose token endpoint holds its
// answer, plays the browser's callback, waits until the exchange is in flight
// against the vendor, and signals snug with sig. It returns the run and the
// vendor after snug is gone.
func hostMidExchange(t *testing.T, sig syscall.Signal, name string) (*hostRun, *hostVendor, []byte, time.Time) {
	t.Helper()
	requireLoginBridgeEnv(t)
	v := newHostVendor(t, "a")
	v.holdToken()
	f, rt := newLoginFixtureRT(t, "hold")
	home := hostLoginAccount(t, "a")
	before := mustRead(t, filepath.Join(home, ".claude", ".credentials.json"))
	fi, err := os.Stat(filepath.Join(home, ".claude", ".credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := startHostRun(t, f, rt, home, v, "")
	if !waitFileHas(filepath.Join(r.runDir(), "claude", ".credentials.json"), "FIXTURE-AT-a", 5*time.Second) {
		t.Fatalf("precondition: the run directory's credential is not the projection of the host's:\n%s", r.s.log())
	}
	r.callback(t)
	v.waitToken(t, 15*time.Second)
	if err := r.s.proc.cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	code := loginWaitExit(t, r.s, 20*time.Second)
	t.Logf("snug exited %d after %s mid-exchange", code, name)
	return r, v, before, fi.ModTime()
}

// checkMidExchangeHost holds the assertions both signals share: nothing was
// written to the host, nothing was created beside the file, the token request
// went to the pinned host and only it, and the listener's port is closed.
func checkMidExchangeHost(t *testing.T, r *hostRun, v *hostVendor, before []byte, mtime time.Time, sig string) {
	t.Helper()
	requireHostLoginUntouched(t, r.hostCred(), before, mtime, "after "+sig+" mid-exchange")
	if got := dirNames(t, filepath.Join(r.home, ".claude")); !slices.Equal(got, []string{".credentials.json"}) {
		t.Errorf("after %s mid-exchange ~/.claude holds %v, want only .credentials.json: no lock, no temp file", sig, got)
	}
	connects, tokens, profiles := v.seen()
	if !slices.Equal(connects, []string{"platform.claude.com:443"}) || len(tokens) != 1 || len(profiles) != 0 {
		t.Errorf("control: the exchange was not the one in flight against platform.claude.com "+
			"(connects %v, token requests %d, profile requests %d)", connects, len(tokens), len(profiles))
	}
	for _, leak := range []string{"NEW-AT", "NEW-RT", "FAKE-CODE"} {
		if strings.Contains(r.s.log(), leak) {
			t.Errorf("snug's output carries %q after %s", leak, sig)
		}
	}
	requireLoginPortClosed(t, r.port, "after "+sig+" of snug mid-exchange")
}

// TestSIGTERMMidExchangeLeavesTheHostLoginUntouched fails if a SIGTERM that
// arrives while snug waits on the token endpoint leaves the host's
// ~/.claude/.credentials.json changed, a .storage-write.lock or a temp file
// beside it, the run directory behind, or the callback port held. The
// exchange is held open by the vendor, which is also the positive control:
// the token request reached platform.claude.com and nothing else was asked.
//
// It does not reach SIGTERM inside the host write itself; that window is
// milliseconds wide and the binary offers no seam to stop in it.
// TestSIGTERMWhileWaitingForTheStorageLockKeepsAnotherProgramsLock is the
// nearest, and internal/cli's TestHostWriteKilledAtAnyInstantNeverTearsTheFile
// covers the write.
func TestSIGTERMMidExchangeLeavesTheHostLoginUntouched(t *testing.T) {
	budget(t, 90*time.Second)
	r, v, before, mtime := hostMidExchange(t, syscall.SIGTERM, "SIGTERM")
	checkMidExchangeHost(t, r, v, before, mtime, "SIGTERM")
	if !waitPathGone(r.runDir(), 5*time.Second) {
		t.Errorf("the run directory %s survived a SIGTERM exit: %v", r.runDir(), dirNames(t, r.runDir()))
	}
}

// TestSIGKILLMidExchangeLeavesTheHostLoginUntouched fails if a SIGKILL of
// snug mid-exchange changes the host's credential file, leaves anything
// beside it, or leaves the port held; and if the dead run's directory, which
// SIGKILL cannot clean and may leave holding the sandbox's access token,
// survives the NEXT snug start.
//
// What is guaranteed is only that: the host file and the port, immediately,
// and the run directory at the next start. That the directory is present
// between the kill and the next start is not asserted either way.
func TestSIGKILLMidExchangeLeavesTheHostLoginUntouched(t *testing.T) {
	budget(t, 90*time.Second)
	r, v, before, mtime := hostMidExchange(t, syscall.SIGKILL, "SIGKILL")
	checkMidExchangeHost(t, r, v, before, mtime, "SIGKILL")

	env := append(append([]string{}, r.f.env...), fixtureHome(r.home)...)
	out, err := runSnugOnce(t, env, r.f.proj)
	if err != nil {
		t.Fatalf("the next snug start failed: %v\n%s", err, out)
	}
	if !waitPathGone(r.runDir(), 5*time.Second) {
		t.Errorf("the next snug start did not sweep the dead run's directory %s: %v", r.runDir(), dirNames(t, r.runDir()))
	}
}

// runSnugOnce runs a default-profile snug on proj with a true payload, the
// "next start" that sweeps dead run directories.
func runSnugOnce(t *testing.T, env []string, proj string) (string, error) {
	t.Helper()
	cmd := exec.Command(snugFor(env), proj, "--", "/bin/true")
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// TestSIGTERMWhileWaitingForTheStorageLockKeepsAnotherProgramsLock fails if
// snug, signalled while it waits for ~/.claude/.storage-write.lock held by
// another program, removes that lock, writes the host file anyway, or
// leaves a temp file. The test plays the other program by creating the lock
// directory itself; the control that snug reached the host write is the
// sandbox's own credential already renewed (RenewSandbox runs just before
// WriteHost) while the browser's connection is still unanswered.
//
// It does not show that a lock snug itself took is removed on SIGTERM:
// the window is the milliseconds of one write.
func TestSIGTERMWhileWaitingForTheStorageLockKeepsAnotherProgramsLock(t *testing.T) {
	budget(t, 90*time.Second)
	requireLoginBridgeEnv(t)
	v := newHostVendor(t, "b")
	f, rt := newLoginFixtureRT(t, "hold")
	home := hostLoginAccount(t, "b")
	cred := filepath.Join(home, ".claude", ".credentials.json")
	before := mustRead(t, cred)
	fi, err := os.Stat(cred)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(home, ".claude", ".storage-write.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	lockBefore, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}

	r := startHostRun(t, f, rt, home, v, "")
	answer := r.callback(t)
	if !waitFileHas(filepath.Join(r.runDir(), "claude", ".credentials.json"), "NEW-AT-b", 20*time.Second) {
		t.Fatalf("control: the sandbox's credential was never renewed, so snug never reached the host write:\n%s", r.s.log())
	}
	select {
	case a := <-answer:
		t.Fatalf("control: the browser was answered while the lock was still held, so snug was not waiting on it:\n%s", a)
	case <-time.After(500 * time.Millisecond):
	}
	if err := r.s.proc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	code := loginWaitExit(t, r.s, 20*time.Second)
	t.Logf("snug exited %d after SIGTERM in the lock wait", code)

	requireHostLoginUntouched(t, cred, before, fi.ModTime(), "after SIGTERM in the lock wait")
	if got := dirNames(t, filepath.Join(home, ".claude")); !slices.Equal(got, []string{".credentials.json", ".storage-write.lock"}) {
		t.Errorf("~/.claude holds %v, want the credential file and the OTHER program's lock, no temp file", got)
	}
	lockAfter, err := os.Stat(lock)
	if err != nil {
		t.Fatalf("snug removed a lock it did not take: %v", err)
	}
	if !os.SameFile(lockBefore, lockAfter) || !lockAfter.ModTime().Equal(lockBefore.ModTime()) {
		t.Error("the lock directory was replaced or touched by snug")
	}
	if !waitPathGone(r.runDir(), 5*time.Second) {
		t.Errorf("the run directory %s survived a SIGTERM exit", r.runDir())
	}
	requireLoginPortClosed(t, r.port, "after SIGTERM in the lock wait")
}

// TestTwoHostModeRunsNeverShareACredentialDirectoryOrFile fails if two
// concurrent host-mode runs share a per-run /snug/claude directory or
// credential file, or if a login completed in one changes anything the other
// holds: its sandbox file, its host file, or what its payload reads at
// /snug/claude. Run A completes a login against the vendor (the control that
// a renewal really happened: its own run file and host file change); run B,
// started first on a different account in a different home, is pending
// throughout and must be byte-identical.
//
// It does not cover two logins completing at the same instant; the
// compare-and-swap for that is TestHostModeLeavesTheHostFileOnACASMismatch.
func TestTwoHostModeRunsNeverShareACredentialDirectoryOrFile(t *testing.T) {
	budget(t, 120*time.Second)
	requireLoginBridgeEnv(t)
	rt := loginRuntimeDir(t)
	vA, vB := newHostVendor(t, "a"), newHostVendor(t, "b")
	fB := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	fA := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	homeB, homeA := hostLoginAccount(t, "b"), hostLoginAccount(t, "a")

	view := "( while [ ! -e go ]; do sleep 0.1; done; cat /snug/claude/.credentials.json > seen.out; touch seen.done ) &"
	rB := startHostRun(t, fB, rt, homeB, vB, view)
	rA := startHostRun(t, fA, rt, homeA, vA, view)

	dirA, dirB := filepath.Join(rA.runDir(), "claude"), filepath.Join(rB.runDir(), "claude")
	if dirA == dirB {
		t.Fatalf("both runs have the credential directory %s", dirA)
	}
	fiA, errA := os.Stat(dirA)
	fiB, errB := os.Stat(dirB)
	if errA != nil || errB != nil {
		t.Fatalf("control: a run's credential directory is missing: %v, %v", errA, errB)
	}
	if os.SameFile(fiA, fiB) || fiA.Mode().Perm() != 0o700 || fiB.Mode().Perm() != 0o700 {
		t.Errorf("the directories are the same inode or not 0700 (%v, %v)", fiA.Mode(), fiB.Mode())
	}
	runA, runB := filepath.Join(dirA, ".credentials.json"), filepath.Join(dirB, ".credentials.json")
	if !strings.Contains(string(mustRead(t, runA)), "FIXTURE-AT-a") || !strings.Contains(string(mustRead(t, runB)), "FIXTURE-AT-b") {
		t.Fatalf("control: the two run files are not each their own host's projection:\nA %s\nB %s", mustRead(t, runA), mustRead(t, runB))
	}
	runBBefore, hostBBefore, hostABefore := mustRead(t, runB), mustRead(t, rB.hostCred()), mustRead(t, rA.hostCred())

	answer := <-rA.callback(t)
	if !strings.HasPrefix(answer, "HTTP/1.1 200 ") || !strings.Contains(answer, "renewed the sandbox") {
		t.Fatalf("control: run A's login did not complete:\n%s\n%s", answer, rA.s.log())
	}
	if !strings.Contains(string(mustRead(t, runA)), "NEW-AT-a") || !strings.Contains(string(mustRead(t, rA.hostCred())), "NEW-RT-a") ||
		bytes.Equal(mustRead(t, rA.hostCred()), hostABefore) {
		t.Fatalf("control: run A's own files were not renewed:\nrun %s\nhost %s", mustRead(t, runA), mustRead(t, rA.hostCred()))
	}

	if !bytes.Equal(mustRead(t, runB), runBBefore) || !bytes.Equal(mustRead(t, rB.hostCred()), hostBBefore) {
		t.Error("run B's sandbox file or host file changed when run A's login completed")
	}
	for _, p := range []string{runB, rB.hostCred()} {
		if strings.Contains(string(mustRead(t, p)), "-a") {
			t.Errorf("%s names account a", p)
		}
	}
	if c, tokens, _ := vB.seen(); len(c) != 0 || len(tokens) != 0 {
		t.Errorf("run B reached the vendor (%v), though only run A completed a login", c)
	}
	if _, tokens, _ := vA.seen(); len(tokens) != 1 {
		t.Errorf("control: run A's vendor saw %d token requests, want 1", len(tokens))
	}

	// From inside: each payload reads its own file at the same guest path.
	handToPayload(t, fA.proj, "go", "x")
	handToPayload(t, fB.proj, "go", "x")
	for _, r := range []*hostRun{rA, rB} {
		for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(r.f.proj, "seen.done")); err == nil {
				break
			}
			if time.Now().After(end) {
				t.Fatalf("a payload never read /snug/claude:\n%s", r.s.log())
			}
		}
	}
	if seen := string(mustRead(t, filepath.Join(fA.proj, "seen.out"))); !strings.Contains(seen, "NEW-AT-a") || strings.Contains(seen, "-b") {
		t.Errorf("run A inside reads %q at /snug/claude", seen)
	}
	if seen := mustRead(t, filepath.Join(fB.proj, "seen.out")); !bytes.Equal(seen, runBBefore) {
		t.Errorf("run B inside reads %q at /snug/claude, not its own unchanged file", seen)
	}
}
