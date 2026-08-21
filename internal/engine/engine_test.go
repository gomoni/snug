package engine

import (
	"fmt"
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

	// The no-reuse rule, asserted through the same door production uses: a
	// second openRunDirs at this exact name must refuse, because the name
	// carries a pid and an entry already at it is either a leftover from a
	// reused pid or something planted first. /tmp is world-writable, which is
	// what makes the second case real.
	if _, err := openRunDirs(filepath.Dir(e.runDir), filepath.Base(e.runDir)); err == nil {
		t.Fatal("openRunDirs silently reused an existing directory; it must refuse")
	}
}

// TestEngineRunDirSplitsByWritability is issue #125's C2b: the run directory is
// divided by what the ENGINE does with each file, not by topic. conf/ holds
// only files snug generated and the engine reads; sock/ holds the one thing
// the engine creates.
//
// It matters because Tier C grafts each of these into the engine's own mount
// namespace WITH AN ACCESS. Without the split there is no directory that can be
// read-only, so the AccessRO arm of the graft model would ship with nothing
// exercising it — and a model whose stricter half is never used is a model
// whose stricter half is untested.
//
// The generated-file list is asserted EXHAUSTIVELY rather than by spot check —
// and "exhaustively" is a claim this list has already failed once: storage.conf
// was added to the engine one commit after this comment was written and did not
// arrive here until a review caught it. The negative below is what makes the
// claim self-enforcing rather than aspirational, since a file in neither
// directory fails whether or not anyone remembers this line.
// A new generated file landing in sock/ instead of conf/ would be silently
// writable inside the engine under Tier C, which is the failure this test is
// the only warning for: nothing else notices where a file was written.
func TestEngineRunDirSplitsByWritability(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	// Both halves get the SAME hardening the parent got — /tmp is commonly
	// world-writable and that reasoning does not weaken one directory down.
	for _, d := range []string{e.sockDir, e.confDir} {
		fi, statErr := os.Stat(d)
		if statErr != nil {
			t.Fatalf("%s: %v", d, statErr)
		}
		if !fi.IsDir() {
			t.Fatalf("%s is not a directory", d)
		}
		if mode := fi.Mode().Perm(); mode != 0o700 {
			t.Errorf("%s mode is %#o, want 0700", d, mode)
		}
		if _, err := openRunDirs(filepath.Dir(d), filepath.Base(d)); err == nil {
			t.Errorf("a second create reused the existing %s; it must refuse here exactly as "+
				"it does for the parent", d)
		}
	}

	// The socket is the ONLY thing under sock/, because it is the only thing
	// the engine itself creates.
	if got := filepath.Dir(e.sock); got != e.sockDir {
		t.Errorf("the engine socket is in %s, want %s — a socket the engine must create cannot "+
			"live in the half Tier C grafts read-only", got, e.sockDir)
	}

	// Every generated file, written through the real writers rather than
	// re-derived here, so a writer that starts choosing its own directory is
	// caught rather than mirrored.
	if _, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman", []string{"PATH=/usr/bin"}, false); err != nil {
		t.Fatalf("Spec: %v", err)
	}
	// resolv.conf is NOT in this list any more, and its absence is the point:
	// Tier C deleted the bind that put snug's generated resolver config over
	// the engine's, because the engine's view is now derived from the
	// sandbox's and already carries that exact file. A generator with no
	// consumer would be the "documented but not implemented" shape in reverse.
	generated := []string{"containers.conf", "registries.conf", "storage.conf", "auth.json",
		filepath.Join("home", ".config", "containers", "policy.json")}
	for _, name := range generated {
		path := filepath.Join(e.confDir, name)
		if _, statErr := os.Stat(path); statErr != nil {
			t.Errorf("%s is not under conf/ (%v) — a generated file outside conf/ is one Tier C "+
				"cannot graft read-only, and nothing else notices where it was written", name, statErr)
		}
	}

	// NEGATIVE: nothing generated may sit at the top of the run directory any
	// more. Without this the test passes on an engine that writes each file
	// TWICE, once in each place.
	entries, err := os.ReadDir(e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if ent.Name() != "sock" && ent.Name() != "conf" {
			t.Errorf("%s sits at the top of the run directory; everything belongs in sock/ or "+
				"conf/, and a file in neither is one the split does not classify", ent.Name())
		}
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
//
// REWRITTEN for issue #167: the reaper no longer forks `podman stop` at all
// (stopLocked's own doc comment says why — the recorded pids are numbered in
// the ENGINE's pid namespace, meaningless on the host, and by the time this
// helper's EOF fires the namespace has already collapsed and taken the
// containers with it). What is left to observe is the one thing nothing else
// removes on the SIGKILL path: this run's stale socket FILE. A pre-#167
// version of this test asserted a fake podman binary got exec'd with the
// stop argv; that assertion is retired along with the mechanism it watched,
// not narrowed — a passing "podman was invoked" test on THIS script would be
// proof of the exact regression #167 exists to prevent.
// TestReaperFiresOnEOFAndRemovesTheWholeRunDirectoryAndStandsDownWithoutTouchingIt
// is issue #167's own reaper test, extended for red team F4: the reaper used
// to remove only the socket FILE (`rm -f "$SNUG_REAP_SOCK"`), leaving the
// rest of the run directory — containers.conf, registries.conf, auth.json,
// resolv.conf, the generated home/ — behind on the SIGKILL path, because
// stopLocked's own `os.RemoveAll(e.runDir)` (step 4) does not run when no Go
// code runs at all. Measured consequence: a leftover entry at that path
// (empty or not) permanently poisons the pid it is named after —
// `engine.New`'s own existence check refuses with "file exists" the next
// time this uid+pid combination is reused. The fixture below populates the
// directory the way a real run does (several files AND a subdirectory), not
// just the one file the old test checked, so a fix that only widened the
// glob would still be caught.
func TestReaperFiresOnEOFAndRemovesTheWholeRunDirectoryAndStandsDownWithoutTouchingIt(t *testing.T) {
	run := func(t *testing.T, standDown bool) (dirGone bool) {
		// The real shape runDirName authors, not a bare t.TempDir(): the
		// reaper refuses to remove anything that does not look like this
		// run's own directory (see reaperScript), so a test using an
		// arbitrary temp path would exercise the refusal branch and prove
		// nothing about the removal.
		dir := filepath.Join(t.TempDir(), fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "podman-1.sock")
		if err := os.WriteFile(sock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		// The rest of the run directory's real shape (engine.go's Spec):
		// containers.conf, registries.conf, auth.json, resolv.conf, and a
		// generated home/ subdirectory with content of its own — `rmdir`
		// would refuse a directory this populated; only `rm -rf` clears it.
		for _, f := range []string{"containers.conf", "registries.conf", "auth.json", "resolv.conf"} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(dir, "home", ".config"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "home", ".config", "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		r, err := startReaper(sock, dir)
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
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}

	// POSITIVE CONTROL for the "stand down" arm below: without first proving
	// EOF removes the whole directory, "it wasn't removed" on stand-down
	// could equally mean the reaper never removes anything at all.
	if !run(t, false) {
		t.Error("snug died (EOF on the pipe) and the reaper did not remove this run's " +
			"whole run directory — a leftover entry there poisons this pid for the next " +
			"run at the same path (issue #167, red team F4)")
	}
	if run(t, true) {
		t.Error("snug cleaned up and told the reaper to stand down, but the run directory " +
			"was removed anyway")
	}
}

// The reaper's removal is an `rm -rf` running as the host user, in a process
// that by design outlives snug and therefore has nobody left to supervise it.
// Its target must be STATED, never DERIVED.
//
// The first cut of issue #167's run-directory removal derived it —
// `rm -rf "$(dirname "$SNUG_REAP_SOCK")"` — which is one property weaker than
// it looks: `rm -f` on an empty value is a harmless no-op, but `dirname`
// follows the socket wherever a later refactor puts it. Measured: point the
// socket at some other directory (a plausible move, since snug's other
// runtime state lives under $XDG_RUNTIME_DIR) and the reaper silently removes
// THAT directory instead, unrelated contents included — `rm` does not refuse
// it, the way it happens to refuse ".".
//
// So the script pins the target to the shape runDirName authors. This test
// owns that pin. Every case is a path an `rm -rf` must never be handed, plus
// the positive control that the pin has not simply disabled the removal.
func TestTheReaperRefusesToRemoveAnythingButItsOwnRunDirectory(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	victim := t.TempDir()
	canary := filepath.Join(victim, "canary.txt")
	if err := os.WriteFile(canary, []byte("must survive"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Everything the reaper must refuse. The empty value is what an
	// unset/zeroed field yields; the rest are what a relocation or a
	// mis-joined path yields.
	for _, dir := range []string{"", ".", "..", "/", "/home", victim, filepath.Base(victim), "relative/snug-1-1"} {
		cmd := exec.Command("/bin/sh", "-c", reaperScript)
		cmd.Dir = victim // the reaper sets no Dir either: it inherits snug's cwd
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SNUG_REAP_DIR=" + dir}
		cmd.Stdin = strings.NewReader("die\n")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "refusing to remove") {
			t.Errorf("SNUG_REAP_DIR=%q: the reaper did not refuse it; output was %q", dir, out)
		}
		if _, err := os.Stat(canary); err != nil {
			t.Fatalf("SNUG_REAP_DIR=%q: the reaper removed a directory that is not a run "+
				"directory (the canary is gone): %v", dir, err)
		}
	}

	// POSITIVE CONTROL. Without this, every assertion above passes on a
	// script that removes nothing at all.
	own := filepath.Join(victim, fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()))
	if err := os.MkdirAll(filepath.Join(own, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", reaperScript)
	cmd.Dir = victim
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SNUG_REAP_DIR=" + own}
	cmd.Stdin = strings.NewReader("die\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("control: %v: %s", err, out)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Errorf("control: the reaper did not remove its OWN run directory %q, so the "+
			"refusals above prove nothing", own)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("control: removing the run directory took the canary with it: %v", err)
	}
}

// specConf runs Spec against a throwaway Engine and returns the generated
// containers.conf's content together with the environment the engine will be
// started with. It is the shared setup for every #126/#132 assertion below.
func specConf(t *testing.T, net policy.NetPolicy, cgroupsDisabled bool) (conf string, env []string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(specPolicy(t, e, "", net), "/usr/bin/podman", []string{"PATH=/usr/bin"}, cgroupsDisabled)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range spec.Env {
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF="); ok {
			path = rest
		}
	}
	if path == "" {
		t.Fatal("Spec set no CONTAINERS_CONF at all — the engine reads the HOST's containers.conf")
	}
	path = hostSideOf(t, e, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), spec.Env
}

// TestTheEngineReadsOnlySnugsOwnContainersConf is issue #132's structural half.
// Both variables must name snug's generated file: CONTAINERS_CONF is what
// REPLACES the host's /etc/containers/containers.conf and
// ~/.config/containers/containers.conf, and CONTAINERS_CONF_OVERRIDE is what
// still wins if something between here and the engine exports CONTAINERS_CONF
// of its own (issue #133 is exactly that, in the test wrapper).
//
// CONTROL: the file the variables name must EXIST and be non-empty — otherwise
// this test passes on a Spec that names a path it never wrote.
func TestTheEngineReadsOnlySnugsOwnContainersConf(t *testing.T) {
	conf, env := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"192.0.2.53"}}, false)
	if strings.TrimSpace(conf) == "" {
		t.Fatal("CONTAINERS_CONF names an empty file")
	}

	var confPath, overridePath string
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF="); ok {
			confPath = rest
		}
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF_OVERRIDE="); ok {
			overridePath = rest
		}
	}
	if overridePath == "" {
		t.Error("Spec set no CONTAINERS_CONF_OVERRIDE: an export of CONTAINERS_CONF anywhere " +
			"between here and the engine silently restores the host's configuration (issue #133)")
	}
	if confPath != overridePath {
		t.Errorf("the two variables name different files (%q vs %q): the engine's configuration "+
			"then depends on which one podman happens to load", confPath, overridePath)
	}
}

// TestGeneratedContainersConfClosesTheHostInjectionKeys is issue #132's
// enumerated half — the keys a host containers.conf would otherwise have
// supplied on EVERY container, none of them client-requested and none of them
// visible to the proxy's bind filter or to --dry-run. CONTAINERS_CONF already
// stops those files being read; naming the keys is "never trust a helper's
// default, in either direction", and it is what still holds if a future podman
// changes CONTAINERS_CONF from "replaces" to "merges".
func TestGeneratedContainersConfClosesTheHostInjectionKeys(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"192.0.2.53"}}, false)
	for _, want := range []string{
		"mounts = []",
		"volumes = []",
		"devices = []",
		"env = []",
		"env_host = false",
		"http_proxy = false",
		"hooks_dir = []",
		"annotations = []",
		"privileged = false",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated containers.conf does not close %q:\n%s", want, conf)
		}
	}
}

// TestTheInjectionKeyListSaysWhatItDoesNotClose is the honesty half, and it
// exists because the first version of this list was PRESENTED as complete and
// was not — a red-team pass measured a bare `env` key injecting into every
// container while the doc comment said the keys a host config "would otherwise
// have supplied" were closed.
//
// default_capabilities, default_sysctls, default_ulimits, seccomp_profile and
// userns are deliberately NOT closed: emptying or pinning any of them
// overrides podman's own default for every container, a policy decision
// writeContainersConf must not make silently. For those the guarantee is
// CONTAINERS_CONF's replacement alone (issue #136).
//
// This test fails if one of them is added WITHOUT the comment being updated,
// which is the drift it exists to catch — a list whose prose and content
// disagree is how the finding happened in the first place.
func TestTheInjectionKeyListSaysWhatItDoesNotClose(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"192.0.2.53"}}, false)
	for _, notClosed := range []string{
		"default_capabilities",
		"default_sysctls",
		"default_ulimits",
		"seccomp_profile",
		"userns",
	} {
		if strings.Contains(conf, notClosed) {
			t.Errorf("generated containers.conf now names %q, which writeContainersConf's own "+
				"comment lists as deliberately NOT closed. Either the comment and issue #136 "+
				"are stale, or a value was chosen on podman's behalf without deciding to:\n%s",
				notClosed, conf)
		}
	}
}

// TestGeneratedContainersConfTakesDNSFromTheResolvedPolicy is issue #126's
// container half: podman generates every container's /etc/resolv.conf from the
// ENGINE's own unless containers.conf names DNS, and its /etc/hosts from the
// host's unless base_hosts_file says otherwise.
//
// The assertion is that the file carries the POLICY's nameserver, not the
// host's — with a nameserver no host has, so a pass cannot be an accident of
// this machine's own resolver configuration.
func TestGeneratedContainersConfTakesDNSFromTheResolvedPolicy(t *testing.T) {
	// DNS: true is not decoration. Resolve populates Nameservers only when a
	// profile asked for DNS, so a fixture with Nameservers and no DNS is a
	// state no run can produce — and since Resolver became mode-and-DNS-aware
	// (issue #164) it correctly yields no resolver at all, which made this
	// test fail against a policy that was never valid rather than against a
	// defect.
	net := policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"192.0.2.53"}}
	conf, _ := specConf(t, net, false)

	for _, want := range []string{
		`dns_servers = ["192.0.2.53"]`,
		`dns_searches = ["."]`, // dns_servers ALONE still leaked the host's search domain
		`dns_options = ["edns0"]`,
		`base_hosts_file = "none"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated containers.conf is missing %s:\n%s", want, conf)
		}
	}
}

// TestGeneratedContainersConfNeverLeavesDNSUNSETOffline is the sharp edge of
// the above: podman reads dns_servers = [] as "not configured" and falls back
// to the engine's own /etc/resolv.conf — so an EMPTY list would reopen exactly
// the leak this closes, on the one configuration (offline) where it matters
// most. Offline must therefore name a server that resolves nothing rather than
// naming none.
//
// CONTROL: the egress case above proves a real nameserver does reach the file,
// so "non-empty offline" is not passing because the key is hardcoded.
func TestGeneratedContainersConfNeverLeavesDNSUnsetOffline(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetIsolated}, false)
	if strings.Contains(conf, "dns_servers = []") {
		t.Errorf("offline containers.conf leaves dns_servers EMPTY, which podman reads as "+
			"'not configured' and answers from the engine's own /etc/resolv.conf:\n%s", conf)
	}
	if !strings.Contains(conf, "dns_servers = [") {
		t.Errorf("offline containers.conf names no dns_servers at all:\n%s", conf)
	}
	if !strings.Contains(conf, `base_hosts_file = "none"`) {
		t.Errorf("offline containers.conf still copies the host's /etc/hosts:\n%s", conf)
	}
}

// TestTheEnginesTwoDNSRenderingsCannotDiverge is invariant 6 ("one Policy, one
// author") applied to the one fact that now has two renderings: the engine's
// /etc/resolv.conf and the containers.conf keys. Both must come from the SAME
// policy.NetPolicy — this test fails if a future change re-derives either one.
func TestTheEnginesTwoDNSRenderingsCannotDiverge(t *testing.T) {
	net := policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"198.51.100.7"}}
	conf, _ := specConf(t, net, false)
	resolv := string(net.ResolvConf())

	if !strings.Contains(resolv, "nameserver 198.51.100.7") {
		t.Fatalf("control: the policy's own resolv.conf does not name the policy's nameserver:\n%s", resolv)
	}
	if !strings.Contains(conf, `"198.51.100.7"`) {
		t.Errorf("containers.conf and /etc/resolv.conf disagree about the nameserver:\n%s\n%s", conf, resolv)
	}
}

// TestCgroupsDisabledStillReachesTheEngine guards the job this file had BEFORE
// #126 gave it two more: preflight P5's selection is a containers.conf setting,
// and it must survive the file gaining other content.
//
// CONTROL: the same Spec with cgroupsDisabled=false must NOT carry it, so this
// is not asserting a constant.
func TestCgroupsDisabledStillReachesTheEngine(t *testing.T) {
	net := policy.NetPolicy{Mode: policy.NetEgress, DNS: true, Nameservers: []string{"192.0.2.53"}}
	with, _ := specConf(t, net, true)
	if !strings.Contains(with, `cgroups = "disabled"`) {
		t.Errorf("preflight P5's selection did not reach the engine:\n%s", with)
	}
	without, _ := specConf(t, net, false)
	if strings.Contains(without, `cgroups = "disabled"`) {
		t.Errorf("cgroups was disabled without P5 selecting it:\n%s", without)
	}
}

// TestNoHostSidePodmanReadsARecordedPid is issue #167's regression: neither
// engine.go's stopLocked nor reaper.go's reaperScript may invoke the podman
// CLI to `stop` a container, because the pids libpod records in the runroot
// are numbered in the ENGINE's pid namespace (issue #125, C0) and a HOST-side
// reader is reading numbers meaningless in its own numbering.
//
// A source-level sweep rather than a behavioural one: the failure mode this
// guards is a REINTRODUCTION of the exact invocation that was deleted, which
// is easiest to catch by name before it ever runs.
//
// Guarded against CLAUDE.md's own named trap ("a grep that cannot fail is
// worse than no test"): the sweep is run FIRST against a fixture holding the
// pre-#167 text, and must fail there, before it is trusted to pass against
// the real source.
func TestNoHostSidePodmanReadsARecordedPid(t *testing.T) {
	needles := []string{
		`"stop", "--all"`,             // engine.go's old stopLocked invocation
		"SNUG_REAP_PODMAN",            // reaper.go's env var carrying the binary path
		`stop --all --filter "label=`, // reaperScript's old shell line
		"e.podman",                    // the field that carried it, now removed
	}

	preChangeFixture := `
		if e.podman != "" {
			stop := exec.Command(e.podman, "--root", e.store, "--runroot", e.runroot,
				"stop", "--all", "--filter", "label="+e.runLabel, "--time", "5")
			stop.Env = e.env
			_ = stop.Run()
		}
	` + `"$SNUG_REAP_PODMAN" --root "$SNUG_REAP_STORE" --runroot "$SNUG_REAP_RUNROOT" ` +
		`stop --all --filter "label=$SNUG_REAP_LABEL" --time 5`

	sweep := func(src string) []string {
		var found []string
		for _, n := range needles {
			if strings.Contains(src, n) {
				found = append(found, n)
			}
		}
		return found
	}

	// The sweep-can-fail control: every needle must be found in the OLD text,
	// or the sweep itself is written wrong and "clean" proves nothing.
	if got := sweep(preChangeFixture); len(got) != len(needles) {
		t.Fatalf("PRECONDITION: the sweep did not match its own pre-#167 fixture (found %v, "+
			"want all %d needles) — the sweep below cannot be trusted to catch a real "+
			"regression if it cannot catch a synthetic one", got, len(needles))
	}

	// The design docs are swept too (red team F7): INDEX.md §8.2 and
	// ENGINE-WIRING.md §6 both described the pre-#167 teardown in the
	// PRESENT tense for a while after the code stopped matching, and a
	// future implementer reading either would reintroduce exactly what
	// #167 removed with nothing here to notice. Both now describe the old
	// mechanism only in the past tense, without ever spelling the literal
	// env var, Go snippet or shell line the needles look for — verified by
	// this sweep passing on the corrected text, not merely asserted.
	for _, f := range []string{
		"engine.go", "reaper.go",
		"../../.claude/design/INDEX.md",
		"../../.claude/design/ENGINE-WIRING.md",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if got := sweep(string(b)); len(got) > 0 {
			t.Errorf("%s still contains %v: a host-side podman stop reads a pid recorded in "+
				"the engine's OWN pid namespace, meaningless in the host's (issue #167)", f, got)
		}
	}
}

// specPolicy is the fixture every Spec test needs since Tier C (issue #125):
// a resolved-enough Policy that GRAFTS this engine's own four directories, plus
// the /usr bind @sys makes on a real run.
//
// Spec maps every path it hands the engine through those grafts and REFUSES one
// it cannot see, so a test that built a Spec against an empty Policy would now
// be testing the refusal rather than the spec. Built by calling the engine's own
// GraftInto — never by hand-listing the four paths — so this fixture cannot
// drift from what a real run installs.
func specPolicy(t *testing.T, e *Engine, toolchainRoot string, net policy.NetPolicy) *policy.Policy {
	t.Helper()
	p := &policy.Policy{
		Podman: policy.PodmanSocket,
		Net:    net,
		Mounts: map[string]policy.Mount{
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind,
				Access: policy.AccessRO, From: []string{"@sys"}},
		},
	}
	if toolchainRoot != "" {
		if err := p.EngineToolchain(policy.OSEnviron{}, toolchainRoot); err != nil {
			t.Fatalf("fixture: recording the toolchain root: %v", err)
		}
	}
	if err := e.GraftInto(policy.OSEnviron{}, p); err != nil {
		t.Fatalf("fixture: grafting the engine's own directories: %v", err)
	}
	return p
}

// hostSideOf maps a path the SPEC handed the engine back to where snug actually
// wrote it.
//
// Since Tier C (issue #125) every path in the spec is a GUEST path — what the
// engine sees inside its derived view — while the file itself lives in this
// run's own host directory under conf/. A test that opens the spec's value
// directly is opening /snug/engine/conf/..., which exists in no namespace this
// process is in.
//
// It ALSO asserts the property rather than merely working around it: a config
// path that is not under the config graft is one Tier C cannot attach
// read-only, and this fails naming it.
func hostSideOf(t *testing.T, e *Engine, guest string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(guest, policy.EngineConfGuest+"/")
	if !ok {
		t.Fatalf("the spec names %q, which is not under the engine's config graft (%s). Every "+
			"generated file the engine reads must be, or it is a file Tier C cannot attach "+
			"read-only and the engine could rewrite what it was started under.",
			guest, policy.EngineConfGuest)
	}
	return filepath.Join(e.ConfDir(), rest)
}
