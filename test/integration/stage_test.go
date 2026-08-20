//go:build integration

package integration

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── /proc process-tree helpers, shared by every test in this file ───────────

// ppidOf reads a process's parent pid from /proc/<pid>/status, which is far
// easier to parse reliably than /proc/<pid>/stat (comm can contain spaces and
// parens, which shift every fixed-position field after it).
func ppidOf(pid int) (int, bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ppid, ok := strings.CutPrefix(sc.Text(), "PPid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(ppid))
			return n, err == nil
		}
	}
	return 0, false
}

func commOf(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// cmdlineOf reads a process's argv out of /proc/<pid>/cmdline, NUL-separated.
func cmdlineOf(pid int) []string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(b) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
	return parts
}

// isStageProcess identifies P1 by its ARGV, never by comm: the kernel sets
// /proc/<pid>/comm from the FILENAME actually exec'd (here, always
// /proc/self/exe, whose basename is "exe"), not from argv[0] — measured, ps
// and /proc/<pid>/comm both show "exe" for the stage even though its own
// Args[0] is set to "snug". cmdline reflects the argv array as given, which is
// where "snug __stage-setup" / "snug __stage-serve" actually shows up.
func isStageProcess(pid int) bool {
	argv := cmdlineOf(pid)
	if len(argv) < 2 {
		return false
	}
	return argv[0] == "snug" && strings.HasPrefix(argv[1], "__stage")
}

func isComm(name string) func(int) bool {
	return func(pid int) bool { return commOf(pid) == name }
}

// allPIDs lists every pid currently in /proc, owned by this uid — the sweep
// base for findDescendant and threadNetnsOf below.
func allPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	uid := uint32(os.Getuid())
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fi, err := os.Stat("/proc/" + e.Name())
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != uid {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// findDescendant polls /proc for a process satisfying `match` whose ancestry
// (by PPid, walking up) reaches `root` within a few hops — bounded so an
// unrelated matching process elsewhere on the host cannot match. Returns
// 0, false if none appears before the deadline.
func findDescendant(root int, match func(int) bool, timeout time.Duration) (int, bool) {
	deadline := time.Now().Add(timeout)
	for {
		for _, pid := range allPIDs() {
			if !match(pid) {
				continue
			}
			p := pid
			for hop := 0; hop < 8; hop++ {
				parent, ok := ppidOf(p)
				if !ok {
					break
				}
				if parent == root {
					return pid, true
				}
				p = parent
			}
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// threadNetnsIDs returns the DISTINCT net namespace ids across every thread of
// pid, read from /proc/<pid>/task/*/ns/net — never /proc/<pid>/ns/net, which
// reports only the thread GROUP LEADER and, measured
// (SUPERVISOR-DESIGN.md §1), lies about a per-thread unshare/setns: it
// keeps reporting the OLD namespace while the calling thread has already moved.
func threadNetnsIDs(pid int) map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		return out
	}
	for _, e := range entries {
		s, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/task/" + e.Name() + "/ns/net")
		if err != nil {
			continue
		}
		out[s]++
	}
	return out
}

// sweepNetnsAcrossAllProcesses returns, for every readable process on the
// host, the set of net namespace ids any of its THREADS currently reports —
// the same sweep TestOnlyBwrapAndTheSandboxAreInN and
// TestTheStageLeavesNoNamespaceObjectAfterSIGKILL both need, so pids sharing
// one namespace id (in EITHER direction) can be found.
func sweepNetnsAcrossAllProcesses() map[string][]int {
	byNS := map[string][]int{}
	for _, pid := range allPIDs() {
		for ns := range threadNetnsIDs(pid) {
			byNS[ns] = append(byNS[ns], pid)
		}
	}
	return byNS
}

// mountinfoHasNsfsFor reports whether ANY readable process's mountinfo carries
// an nsfs entry naming id — the check for a netns pinned by a BIND MOUNT with
// no process attached, which a process sweep alone cannot see (this is exactly
// the shape a future engine's per-container netns binds will produce).
func mountinfoHasNsfsFor(id string) bool {
	for _, pid := range allPIDs() {
		f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mountinfo")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "nsfs") && strings.Contains(line, id) {
				f.Close()
				return true
			}
		}
		f.Close()
	}
	return false
}

// netnsIDFromReadlink normalises "net:[4026532924]" forms so a comparison
// against readlink output from two different sources is a plain string
// compare.
func netnsIDFromReadlink(s string) string { return strings.TrimSpace(s) }

// ── the tests ────────────────────────────────────────────────────────────

// unshareNamesFromHelp parses `bwrap --help` for every --unshare-<name> flag
// this bwrap build supports, normalising away the -try suffix (name alone,
// not name+try, is what both branches in internal/policy/bwrap.go decide
// coverage by) and the --unshare-all umbrella flag itself.
func unshareNamesFromHelp(t *testing.T) map[string]bool {
	t.Helper()
	help, err := exec.Command("bwrap", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("bwrap --help: %v", err)
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(help), "\n") {
		line = strings.TrimSpace(line)
		name, ok := strings.CutPrefix(line, "--unshare-")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, " ")
		name = strings.TrimSuffix(name, "-try")
		if name == "all" {
			continue
		}
		found[name] = true
	}
	if len(found) == 0 {
		t.Fatal("parsed zero --unshare-<name> flags out of bwrap --help; the parser is broken")
	}
	return found
}

// TestBwrapUnshareSetIsExhaustive is the guard that makes §3.1's enumerated
// --unshare-* set (used under the stage, instead of --unshare-all) an
// acceptable exception to "no selective lists" (CLAUDE.md invariant 2): it
// parses `bwrap --help` for every --unshare-<name> this bwrap supports and
// fails if the stage's own set does not cover all of them except net. A build
// against a bwrap that grows a new namespace type goes red here rather than
// silently keeping the sandbox in it.
//
// What it guards is now policy.Topology.UnshareFlags, the single authority
// every consumer reads (issue #159) — so this one guard covers BwrapFlags,
// internal/stage's golden and internal/cli/doctor's probe, where it used to
// cover one branch of an if.
//
// requireBwrapBinary, not requireSandbox: this test parses --help and creates
// no namespace, and gating it on namespace creation meant it silently did not
// run on the hosts least able to notice a namespace being inherited (#159).
func TestBwrapUnshareSetIsExhaustive(t *testing.T) {
	budget(t)
	requireBwrapBinary(t)

	found := unshareNamesFromHelp(t)
	// The set policy.Topology.UnshareFlags returns for Netns == NetnsStage.
	// Kept here as a literal, not imported, because this package deliberately
	// drives the built binary rather than linking against internal/policy (see
	// the package doc in sandbox_test.go) — a change to the set is a change
	// this test must be edited to see, which is the point. After #159 this is
	// the ONLY copy of the set not derived from the authority, which is what
	// makes it a guard rather than a duplicate: it is checked against an
	// independent oracle (`bwrap --help`) that internal/policy cannot consult,
	// because it may not exec.
	stageSet := map[string]bool{
		"user": true, "ipc": true, "pid": true, "uts": true, "cgroup": true,
	}
	for name := range found {
		if name == "net" {
			continue // the one namespace the stage topology must NOT unshare
		}
		if !stageSet[name] {
			t.Errorf("bwrap --help advertises --unshare-%s, which the stage's enumerated set "+
				"(internal/policy/bwrap.go) does not cover — a sandbox running under the "+
				"stage would silently inherit this namespace from the stage rather than "+
				"getting its own", name)
		}
	}
	for name := range stageSet {
		if !found[name] {
			t.Errorf("the stage's enumerated set names --unshare-%s, which this bwrap's "+
				"--help does not advertise at all", name)
		}
	}
}

// TestBwrapOfflineUnshareSetIsExhaustive is TestBwrapUnshareSetIsExhaustive's
// sibling for the offline topology (issue #24): since that branch converted
// from the single --unshare-all flag to an explicit list (internal/policy/
// bwrap.go, the `else` branch), it needs the same coverage guard the stage
// branch already had, or the two could silently drift apart the same way a
// hand-rolled --unshare-all could silently drop a namespace bwrap grows in a
// future release. Unlike the stage set, net belongs HERE — the offline
// sandbox creates and keeps its own empty network namespace — so every name
// bwrap advertises must be covered, with none excluded.
func TestBwrapOfflineUnshareSetIsExhaustive(t *testing.T) {
	budget(t)
	requireBwrapBinary(t)

	found := unshareNamesFromHelp(t)
	// The set policy.Topology.UnshareFlags returns for every non-stage
	// topology — the explicit expansion of --unshare-all, literal here for the
	// same reason as stageSet above. There is no `else` branch any more: net's
	// presence follows from NetnsOwner, which records who CREATED the
	// namespace (#159).
	offlineSet := map[string]bool{
		"user": true, "ipc": true, "pid": true, "uts": true, "cgroup": true, "net": true,
	}
	for name := range found {
		if !offlineSet[name] {
			t.Errorf("bwrap --help advertises --unshare-%s, which the offline topology's "+
				"enumerated set (internal/policy/bwrap.go) does not cover — an offline "+
				"sandbox would silently inherit this namespace from whatever started snug", name)
		}
	}
	for name := range offlineSet {
		if !found[name] {
			t.Errorf("the offline topology's enumerated set names --unshare-%s, which this "+
				"bwrap's --help does not advertise at all", name)
		}
	}
}

// requireNestedUserNamespace gates on this host permitting a user namespace to
// be created FROM INSIDE another one it created itself — administering a
// namespace you already own, which is what "unprivileged user namespaces
// work" means and needs no elevated privilege beyond what requireSandbox
// already demanded. A positive control, not an assumption: the exhaustion
// test below constructs its "unavailable" case by writing to a sysctl inside a
// self-owned nested namespace, and that construction is worthless if nesting
// itself does not work here, so it is verified with the exact same shape
// (one level of unshare --user --map-root-user, unmodified) before the
// modified case runs.
func requireNestedUserNamespace(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		skipOrFail(t, "unshare (util-linux) is not installed")
	}
	probe := exec.Command("unshare", "--user", "--map-root-user", "--",
		"unshare", "--user", "--map-root-user", "--", "/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		skipOrFail(t, "cannot nest a second user namespace inside a self-created one "+
			"here: %s", strings.TrimSpace(string(out)))
	}
}

// TestStrictUnshareUserFailsLoudlyWhenNamespacesAreExhausted pins issue #24's
// fix: internal/policy/bwrap.go now emits strict --unshare-user rather than
// --unshare-user-try, on both topologies. This is the exact scenario
// the issue's measurement identified as the silent-downgrade case — a REAL
// uid-0 caller (which is what the stage's P1-runs-bwrap-as-uid-0 shape makes
// every `@net` bwrap invocation, regardless of the human's uid) whose own
// user namespace's max_user_namespaces reads "0" — reconstructed here without
// any genuine host privilege: administering a user namespace this test
// created itself, via `unshare --user --map-root-user`, is what "unprivileged
// user namespaces work" means, so requireSandbox (transitively, through
// requireNestedUserNamespace) is the only gate this needs.
//
// The bwrap flags below are the STAGE topology's literal set, post-fix,
// copied rather than derived from internal/policy the same way stageSet is in
// TestBwrapUnshareSetIsExhaustive: a change to what bwrap.go emits is a
// change this test must be edited to see.
//
// The UNCAPPED run is the positive control this test ships in the same
// function, per the project's "a test that cannot fail is worse than no
// test" rule: without it, a nested-namespace harness that is broken for some
// unrelated reason (bwrap missing inside the nest, a mount failure, anything)
// would make the capped run fail for the WRONG reason and this test would
// still go green on a check that proves nothing.
func TestStrictUnshareUserFailsLoudlyWhenNamespacesAreExhausted(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requireNestedUserNamespace(t)

	// internal/policy/bwrap.go, Topology.Netns == NetnsStage, after issue #24.
	stageFlags := "--unshare-user --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try"
	mountFlags := "--ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib " +
		"--symlink usr/lib64 /lib64 --proc /proc --dev /dev --die-with-parent"

	// POSITIVE CONTROL: the identical bwrap invocation, run inside the same
	// kind of self-created nested namespace, with max_user_namespaces left at
	// its default (uncapped). Must succeed, or the capped case below proves
	// nothing about the sysctl.
	okCmd := exec.Command("unshare", "--user", "--map-root-user", "--",
		"sh", "-c", "exec bwrap "+stageFlags+" "+mountFlags+" -- /bin/true")
	if out, err := okCmd.CombinedOutput(); err != nil {
		t.Fatalf("control: strict --unshare-user bwrap failed in an UNCAPPED nested "+
			"namespace, which should succeed — the harness itself is broken, not the "+
			"sysctl this test means to exercise: %v\n%s", err, out)
	}

	// THE CASE: same invocation, same kind of namespace, but this run first
	// writes "0" to max_user_namespaces INSIDE that namespace — exactly the
	// construction the issue #24 measurement used, mirroring a host with
	// unprivileged user namespaces exhausted or disabled at the level bwrap's
	// clone() actually observes. Before the fix (--unshare-user-try) this
	// exited 0 with no user namespace created at all (verified by hand:
	// /proc/self/uid_map inside came back byte-identical to the caller's).
	// Strict must make it fail, non-zero, with bwrap's own message naming the
	// sysctl — invariant 5, "no silent downgrade, ever".
	capScript := "echo 0 > /proc/sys/user/max_user_namespaces && exec bwrap " +
		stageFlags + " " + mountFlags + " -- /bin/true"
	capCmd := exec.Command("unshare", "--user", "--map-root-user", "--", "sh", "-c", capScript)
	out, err := capCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict --unshare-user silently succeeded with max_user_namespaces=0 "+
			"in bwrap's own namespace — invariant 5 violated, exactly the case issue #24 "+
			"measured as a silent downgrade under -try. Output:\n%s", out)
	}
	if !strings.Contains(string(out), "max_") || !strings.Contains(string(out), "namespaces") {
		t.Errorf("strict --unshare-user failed (good, exit=%v) but the message does not "+
			"name the sysctl the way \"errors name the fix\" requires:\n%s", err, out)
	}
}

// TestOfflineStartsNoStage is exit criterion... the deny-by-default check on
// snug's OWN process tree: a bare `snug <dir>` with no net profile must start
// bwrap directly, with NO second long-lived process ahead of it. Positive
// control: a @net run DOES start one (findDescendant would otherwise pass
// vacuously on a topology that never creates a stage at all).
func TestOfflineStartsNoStage(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, proj, "--", "/bin/sleep", "2")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	// Positive control: bwrap itself must appear as a child of snug, or this
	// offline run never really started and the absence of a stage proves
	// nothing.
	if _, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: bwrap never appeared as a child of snug; the offline run " +
			"did not really start")
	}
	if pid, ok := findDescendant(cmd.Process.Pid, isStageProcess, 500*time.Millisecond); ok {
		t.Errorf("a second 'snug' process (pid %d) exists as a descendant of an OFFLINE run; "+
			"NeedsStage() must be false here", pid)
	}

	cmd.Process.Kill()
	cmd.Wait()
	killed = true
}

// TestSandboxNetnsIsTheStagesPinnedNetns is exit criterion 2: the payload's
// OWN network namespace must equal the id the stage reported at readiness, and
// must differ from the top-level snug (P0) process's. Both sides are refused
// if empty, per SUPERVISOR-DESIGN.md's review §3.2 — an empty string is
// != every real namespace id, which is how a sandbox that never started would
// otherwise read as PASS.
//
// TestNoStageThreadRemainsInTheSandboxNetns rides along in the same run: once
// the stage (P1) is found, its own thread sweep must show NO thread left in
// the namespace it handed to the sandbox — reading /proc/<P1>/ns/net instead
// would answer a different, misleading question (measured,
// SUPERVISOR-DESIGN.md §1: it reports the OLD namespace,
// scheduler-dependently).
func TestSandboxNetnsIsTheStagesPinnedNetns(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	netnsFile := proj + "/netns.txt"
	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sh", "-c",
		"readlink /proc/self/ns/net > "+netnsFile+"; sleep 5")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: no stage ('snug') process appeared as a descendant of a @net run")
	}
	// Positive control for the thread-count claim below: a freshly started Go
	// program has more than one OS thread to be wrong about.
	//
	// POLLED, not sampled once, and that is a real bug this test had rather
	// than defensive padding: "a Go program has several threads" is only
	// EVENTUALLY true — the runtime starts them as it needs them — and
	// findDescendant returns the instant the stage appears in /proc, which can
	// be microseconds after its exec. Whether this precondition held was
	// therefore decided by how long P0 took to get to the fork relative to the
	// poll loop above, and anything that changes snug's startup cost by a few
	// tens of milliseconds flips it. Measured: adding the `ssh -G` probe
	// (issue #42, ~70ms before the stage is forked) made this fail every time
	// on this host, in isolation, while main passed every time — a false
	// failure about thread counts, in a test about namespaces.
	var before map[string]int
	total := 0
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		before = threadNetnsIDs(stagePID)
		total = 0
		for _, n := range before {
			total += n
		}
		if total > 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if total <= 1 {
		t.Fatalf("PRECONDITION: the stage (pid %d) still reports only %d thread(s) after two "+
			"seconds; this test needs more than one to be a meaningful sweep", stagePID, total)
	}

	// The stage's OWN netns (a fresh one it left N for) must be present among
	// its threads, and N must NOT be.
	p0Net, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net")
	if err != nil {
		t.Fatalf("reading P0's own netns: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var payloadNet string
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(netnsFile)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			payloadNet = netnsIDFromReadlink(string(b))
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if payloadNet == "" {
		t.Fatal("the payload never reported its own netns; the sandbox probably did not start")
	}

	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	if payloadNet == p0Net {
		t.Errorf("the sandbox's netns (%s) equals P0's own — the stage granted no isolation at all",
			payloadNet)
	}

	// Nothing about the stage's OWN thread set may still carry the namespace it
	// handed to the sandbox — reading it back here, after the kill, is still
	// meaningful only if the sweep was taken WHILE the stage was alive, which
	// `before` was.
	if n := before[payloadNet]; n > 0 {
		t.Errorf("%d of the stage's own threads were still in the sandbox's namespace %s "+
			"while the sandbox was running — the move did not survive", n, payloadNet)
	}
}

// TestOnlyBwrapAndTheSandboxAreInN sweeps EVERY readable process's threads for
// the sandbox's own namespace id while a sandbox is running, and asserts the
// only pids present are the ones bwrap itself created — no stray snug helper
// process. Positive control: the sweep must find at least bwrap itself.
//
// pasta is NOT covered: it sets itself non-dumpable, so its own
// /proc/<pasta>/ns/net is EACCES to us and no sweep can see it. That pasta's
// forwarding side is outside N stays INFERRED, not measured, and this test's
// doc comment is where that limitation is recorded rather than implied.
func TestOnlyBwrapAndTheSandboxAreInN(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "5")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	bwrapPID, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: bwrap never appeared")
	}
	sandboxNet, err := os.Readlink("/proc/" + strconv.Itoa(bwrapPID) + "/ns/net")
	if err != nil {
		t.Fatalf("reading bwrap's own netns: %v", err)
	}

	byNS := sweepNetnsAcrossAllProcesses()
	inN := byNS[sandboxNet]
	if len(inN) == 0 {
		t.Fatal("PRECONDITION: the sweep found NOTHING in the sandbox's own namespace, " +
			"including bwrap itself — the sweep is broken")
	}

	// Classify BEFORE the kill, not after. Ancestry is only readable while the
	// ancestors are alive: killing snug collapses the tree, and a payload that
	// outlives its parent by a few milliseconds is reparented to the nearest
	// reaper — at which point walking its PPid can no longer reach bwrap and it
	// reads as "an unexpected process in N". MEASURED on a loaded CI runner,
	// where `sleep` was reported as neither bwrap nor a descendant of it; the
	// sandbox was correct and the test was asking its question too late.
	type member struct {
		pid       int
		comm      string
		descended bool
	}
	members := make([]member, 0, len(inN))
	for _, pid := range inN {
		members = append(members, member{
			pid: pid, comm: commOf(pid), descended: isDescendantOf(pid, bwrapPID),
		})
	}

	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	for _, m := range members {
		if m.comm == "" {
			// The process was already gone by the time we read its comm — a
			// transient helper bwrap itself forks and reaps during setup/teardown
			// (measured: this raced the sweep at least once). A pid that cannot
			// even be identified any more is not a finding; it is the sweep
			// catching something mid-exit.
			continue
		}
		if m.comm != "bwrap" && !m.descended {
			t.Errorf("pid %d (comm %q) is in the sandbox's netns %s but is neither bwrap "+
				"nor a descendant of it — an unexpected process reaches N", m.pid, m.comm, sandboxNet)
		}
	}
}

// isDescendantOf walks PPid upward from pid, bounded, looking for root.
func isDescendantOf(pid, root int) bool {
	p := pid
	for hop := 0; hop < 10; hop++ {
		parent, ok := ppidOf(p)
		if !ok {
			return false
		}
		if parent == root {
			return true
		}
		p = parent
	}
	return false
}

// TestTheStageClosesTheSandboxsDescriptorsAtTheFork asserts the PROPERTY rather
// than a process-wide descriptor count, and the rename is a finding of its own.
//
// It used to be called ...HoldsFourDescriptorsAtTheFork, say "four" in its name,
// and assert `n > 10` — a number measured once, with zero margin in either
// direction. A host-integration audit flagged that the count was decoration
// wearing the test's name, and it was proved right the next time a descriptor
// was legitimately added: parking the N-socket at fd 62 took the stage from 10
// to 11 and turned a correct change into a red build, on CI only, because the
// Go runtime's own bookkeeping fds differ between hosts.
//
// What actually matters is that the stage does not keep the SANDBOX's
// descriptors after handing them to bwrap — the args memfd above all, which a
// red team once read out of a payload. That is a statement about identity, not
// arity, so this greps link targets and ignores how many there are.
//
// Positive control: the two descriptors the stage MUST still hold at this point
// are asserted present, so "no memfd found" cannot pass on a stage whose
// descriptor table could not be read at all.
func TestTheStageClosesTheSandboxsDescriptorsAtTheFork(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "5")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: no stage process appeared")
	}
	if _, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: bwrap never appeared; the fork this test is about never happened")
	}

	stageTargets := fdTargets(stagePID)

	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	// POSITIVE CONTROL. The stage keeps exactly two namespace-bearing things: the
	// pinned netns, and the socket it created inside that netns to answer
	// readiness. If neither is visible the sweep read nothing and the negative
	// below would pass vacuously.
	sawNetns := false
	for target := range stageTargets {
		if strings.HasPrefix(target, "net:[") {
			sawNetns = true
		}
	}
	if !sawNetns {
		t.Fatalf("PRECONDITION: the stage's descriptor table shows no pinned network namespace, "+
			"so this sweep saw nothing and proves nothing. Targets: %v", stageTargets)
	}

	for target := range stageTargets {
		if strings.Contains(target, "memfd:snug-") {
			t.Errorf("the stage still has %q open once bwrap was running — it must close "+
				"the sandbox's own descriptors the instant the fork returns. Targets: %v",
				target, stageTargets)
		}
	}
}

// TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage is exit
// criterion 3 (review finding F1, stated as a class rather than as fd 5): a
// payload's open descriptor table must not resolve, via /proc/<pid>/fd/N's
// link target, to anything the stage ALSO has open. Comparing link targets
// rather than fd numbers is deliberate — two different processes' fd 5 naming
// the same file would be exactly the class of collision this test exists to
// catch, and fd numbers alone cannot distinguish that from coincidence.
//
// Positive controls: the payload has descriptors at all (every process does —
// stdio if nothing else), and the stage holds at least four (asserted by
// TestTheStageClosesTheSandboxsDescriptorsAtTheFork; this test does not re-derive that
// count, only that both sides are non-empty).
func TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "5")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: no stage process appeared")
	}
	// The payload IS bwrap's own child, several hops down; "sleep" is what the
	// payload actually execs into.
	payloadPID, ok := findDescendant(cmd.Process.Pid, isComm("sleep"), 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: the payload ('sleep') never appeared")
	}

	stageTargets := fdTargets(stagePID)
	payloadTargets := fdTargets(payloadPID)

	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	if len(payloadTargets) == 0 {
		t.Fatal("PRECONDITION: the payload has NO open descriptors at all — even stdio — " +
			"so this comparison would pass vacuously")
	}
	if len(stageTargets) == 0 {
		t.Fatal("PRECONDITION: the stage has NO open descriptors at all, which contradicts " +
			"TestTheStageClosesTheSandboxsDescriptorsAtTheFork and means this run did not really use one")
	}

	for target := range payloadTargets {
		// /dev/null is excluded: it grants nothing (no data, no capability),
		// every sandbox and the stage both legitimately open it for stdio
		// substitution (safeStdio) or as an /dev entry, and — unlike a pipe or
		// socket inode, which is unique per kernel object — "/dev/null" as a
		// STRING is identical for any two independent opens of the same device
		// node in two different mount namespaces. A match here is expected and
		// meaningless; it is not evidence of a shared descriptor.
		//
		// pipe:/socket: targets are NOT excluded, deliberately: bwrap's own
		// --json-status-fd/--block-fd pipes and the args memfd are internal
		// plumbing the payload has no business seeing by fd number, and every
		// anonymous pipe/socket target string IS unique per kernel object, so a
		// collision there is exactly the finding this test exists to catch.
		if target == "/dev/null" {
			continue
		}
		if _, ok := stageTargets[target]; ok {
			t.Errorf("descriptor target %q is open in BOTH the payload and the stage — "+
				"the stage did not seal something it should have", target)
		}
	}
}

// TestFdTargetProbeDetectsARealSharedDescriptor is the positive control for
// TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage's whole METHOD,
// not just its preconditions. That test's "the payload and the stage share
// no descriptor" result is only meaningful if the string-comparison technique
// it uses (matching /proc/<pid>/fd/N's link target) can actually SEE a
// shared descriptor when one genuinely exists — otherwise an empty
// intersection proves nothing, the exact "pasta.avx2" shape CLAUDE.md warns
// about (a check that was always vacuously true).
//
// Needs no sandbox, no namespaces, no privilege at all: two ordinary
// processes are handed the SAME *os.File via exec.Cmd.ExtraFiles — precisely
// the mechanism P0/P1/bwrap use to pass descriptors down this whole chain —
// and the probe must report their fd tables intersecting on that pipe. A
// second, unrelated pipe held by only one of the two processes is the
// negative half of the same control: the probe must NOT report it as shared.
func TestFdTargetProbeDetectsARealSharedDescriptor(t *testing.T) {
	budget(t)

	sharedR, sharedW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer sharedR.Close()
	defer sharedW.Close()

	onlyAR, onlyAW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer onlyAR.Close()
	defer onlyAW.Close()

	a := exec.Command("/bin/sleep", "5")
	a.ExtraFiles = []*os.File{sharedR, onlyAR}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Process.Kill(); a.Wait() })

	b := exec.Command("/bin/sleep", "5")
	b.ExtraFiles = []*os.File{sharedR}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Process.Kill(); b.Wait() })

	// Give /proc a moment to reflect two freshly forked children rather than
	// racing the fork.
	var aTargets, bTargets map[string]bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		aTargets = fdTargets(a.Process.Pid)
		bTargets = fdTargets(b.Process.Pid)
		if len(aTargets) > 0 && len(bTargets) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(aTargets) == 0 || len(bTargets) == 0 {
		t.Fatal("PRECONDITION: could not read one or both children's fd tables at all")
	}

	var sharedFound []string
	for target := range aTargets {
		if target == "/dev/null" {
			continue
		}
		if bTargets[target] {
			sharedFound = append(sharedFound, target)
		}
	}
	if len(sharedFound) == 0 {
		t.Fatalf("the probe found NO shared descriptor between two processes DELIBERATELY "+
			"handed the same pipe — the comparison technique itself is broken, which means "+
			"TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage's 'nothing shared' "+
			"result proves nothing rather than proving containment.\na=%v\nb=%v", aTargets, bTargets)
	}
	// The DELIBERATELY shared pipe must be among the matches. Note what is NOT
	// asserted: that every match is a pipe.
	//
	// That stronger form was here and it was wrong — it went red on CI with
	// "/usr/lib/x86_64-linux-gnu/libc.so.6 reported as shared". Two children
	// caught between fork and the end of exec both have the dynamic loader's
	// libc open, and an identical file target legitimately appears in both fd
	// tables. Nothing was leaking; the probe was right and the assertion was
	// too strong, which made a timing difference between hosts look like a
	// finding.
	//
	// What this test exists to prove is that the intersection technique CAN see
	// a shared descriptor, so that the containment test's "nothing shared"
	// result means something. A pipe among the matches proves exactly that.
	sawPipe := false
	for _, target := range sharedFound {
		if strings.Contains(target, "pipe:") {
			sawPipe = true
		}
	}
	if !sawPipe {
		t.Errorf("the probe found shared targets %v but none of them is the pipe both "+
			"children were deliberately handed — it is matching on something incidental "+
			"rather than on the descriptor under test", sharedFound)
	}

	// The negative half: onlyAR/onlyAW were never given to b at all, so NOTHING
	// in a's fd table beyond the deliberately shared pipe and stdio may show up
	// as an intersection. sharedFound is exactly aTargets ∩ bTargets (minus
	// /dev/null) by construction, so this just re-states that as an explicit
	// assertion rather than trusting the loop above never had a bug: anything
	// a holds that b does NOT hold (onlyAR/onlyAW's pipe: target, in
	// particular) must be absent from sharedFound.
	for target := range aTargets {
		if bTargets[target] {
			continue // genuinely shared — already accounted for in sharedFound
		}
		for _, s := range sharedFound {
			if s == target {
				t.Errorf("%q is in sharedFound but b does not actually hold it — "+
					"the intersection computation itself is broken", target)
			}
		}
	}
}

// fdTargets reads every /proc/<pid>/fd/N symlink target for pid, ignoring
// entries that vanish mid-read (racing the process's own churn).
func fdTargets(pid int) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		return out
	}
	for _, e := range entries {
		s, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + e.Name())
		if err != nil {
			continue
		}
		out[s] = true
	}
	return out
}

// TestTheStageExitsWhenTheSandboxFailsToStart is exit criterion 4: the stage
// is ONE-SHOT. Force a bwrap failure by putting a failing "bwrap" first on
// snug's own PATH, and assert the stage process is gone within the test's
// budget. Positive control: something claiming to be the stage existed at
// all (a "snug" pid was reachable to poll on) — this is checked implicitly by
// requiring cli() to report the run failed, which only happens once the stage
// itself decided the fork did not succeed.
func TestTheStageExitsWhenTheSandboxFailsToStart(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	fakeBin := t.TempDir()
	failing := fakeBin + "/bwrap"
	if err := os.WriteFile(failing, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath := os.Getenv("PATH")
	if realPath == "" {
		realPath = "/usr/bin:/bin"
	}

	before := allPIDs()
	_, code := cli(t, baseEnv("PATH="+fakeBin+":"+realPath), "-p", "@net", proj, "--", "/bin/true")
	if code == 0 {
		t.Fatal("PRECONDITION: snug reported success with a bwrap that always exits 7")
	}

	// Nothing new and still alive should be a stage: cli() already waited for
	// the whole tree to exit (CombinedOutput blocks until the pipes close), so
	// this is really asserting that wait actually reaped everything rather than
	// leaving an orphaned stage behind it.
	//
	// isStageProcess, NOT commOf(pid) == "snug". This loop used to compare comm
	// against the literal "snug" and could therefore never fire: the kernel sets
	// comm from the basename of the file exec'd, which is always "exe" here
	// because the stage is started as /proc/self/exe. Setting cmd.Args[0] moves
	// cmdline, not comm. Measured on a live run: comm=exe cmdline="snug
	// __stage-serve". The helper 700 lines above says exactly this and this loop
	// did not use it — the pasta.avx2 shape, in a file that already knew.
	for _, pid := range newPIDs(pidSet(before), pidSet(allPIDs())) {
		if isStageProcess(pid) {
			t.Errorf("pid %d is a leftover stage (%v) after a run whose bwrap always fails; "+
				"the stage is supposed to exit after exactly one start request, whatever the "+
				"outcome", pid, cmdlineOf(pid))
		}
	}
}

func pidSet(pids []int) map[int]bool {
	m := make(map[int]bool, len(pids))
	for _, p := range pids {
		m[p] = true
	}
	return m
}

// TestTheStageLeavesNoNamespaceObjectAfterSIGKILL is exit criterion 5.
// Asserted on the NAMESPACE OBJECT, never a process count: after SIGKILL on
// snug, the pinned netns id must appear in NO process's thread sweep and in NO
// readable mountinfo nsfs entry — a netns pinned by a bind mount with no
// process attached is invisible to a process sweep alone, and that is
// precisely the failure shape a future engine's per-container netns binds
// would produce. Positive control: the id WAS present (via a process) before
// the kill.
func TestTheStageLeavesNoNamespaceObjectAfterSIGKILL(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "30")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	bwrapPID, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: bwrap never appeared")
	}
	// Wait for the PAYLOAD, not just bwrap, before killing anything. Killing
	// the instant bwrap's pid appears — which findDescendant's poll can do
	// within a millisecond of the fork — reliably left an orphan reparented to
	// this container's init, indistinguishable from a genuine teardown failure.
	//
	// The mechanism, stated correctly because the earlier version of this
	// comment did not: it is NOT that bwrap arms its own --die-with-parent
	// somewhere in its startup sequence and this races that arming. MEASURED
	// with a matched pair: bwrap does not arm --die-with-parent on the sandbox's
	// INIT until the --block-fd read returns, so the init is unprotected for the
	// whole parked window. Waiting for the payload waits past the release, which
	// is the point at which the protection actually exists. That is also why
	// this bar cannot be widened to fix the underlying defect — see
	// https://github.com/gomoni/snug/issues/13.
	//
	// Waiting for "sleep" (the payload bwrap execs once its setup is done) is
	// the same readiness bar every other test in this suite uses via
	// payloadMarker, applied here because this test cannot use run()/mustRun
	// (it needs the raw pids mid-flight).
	if _, ok := findDescendant(cmd.Process.Pid, isComm("sleep"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: the payload ('sleep') never appeared")
	}
	sandboxNet, err := os.Readlink("/proc/" + strconv.Itoa(bwrapPID) + "/ns/net")
	if err != nil {
		t.Fatalf("reading the sandbox's netns: %v", err)
	}

	before := sweepNetnsAcrossAllProcesses()[sandboxNet]
	if len(before) == 0 {
		t.Fatal("PRECONDITION: the sandbox's namespace does not appear in the sweep before " +
			"the kill; the positive control failed")
	}
	// The exact set of pids in N right before the kill — not just the count.
	// This host runs a great many OTHER sandboxes (flatpak/bwrap) that create
	// and destroy their OWN private netns constantly, and netns ids are nsfs
	// inode numbers: the kernel is free to reuse one the instant every
	// reference to it drops. So "the id is present in the sweep" is not itself
	// proof of survival — a DIFFERENT, unrelated bwrap starting an instant
	// after ours dies could coincidentally be handed the same freed inode. Only
	// a pid that was ALSO here immediately before the kill (same process,
	// genuinely still alive) counts as a survivor; the same id appearing under
	// a NEW pid afterwards is exactly what reuse looks like, not a finding.
	beforeSet := pidSet(before)

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	killed = true

	// 10s, not 5: bwrap's own --die-with-parent (PR_SET_PDEATHSIG on ITSELF,
	// targeting the process that forked it) is a KERNEL SIGNAL DELIVERY, not a
	// synchronous teardown, and CLAUDE.md already documents this exact class of
	// race for the non-stage abort() path ("the parked child reliably survived
	// long enough for the deferred close to release it... 6 seconds later").
	// Measured here: 8 back-to-back manual kills all cleaned up in ~2ms, but
	// under the load of the full suite running back to back a single run took
	// long enough to trip a 5s bound once. This is the same shape as
	// TestNoLeakedHelpersAfterSIGKILL's pasta wait — a bound, not the
	// measurement — just a more generous one for a signal whose delivery this
	// project has already found reason to distrust.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var survivors []int
		for _, pid := range sweepNetnsAcrossAllProcesses()[sandboxNet] {
			if beforeSet[pid] {
				survivors = append(survivors, pid)
			}
		}
		byMount := mountinfoHasNsfsFor(sandboxNet)
		if len(survivors) == 0 && !byMount {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("namespace %s survived SIGKILL: pid(s) %v (present both before and after "+
				"the kill) still report it, nsfs mountinfo entry present=%v",
				sandboxNet, survivors, byMount)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// ── regressions for the four findings the second red team confirmed ─────────
//
// One test per finding, each named after the property rather than the bug, and
// each with a positive control that answers "would this probe have seen the
// hole while it was open?" — because every one of these WAS open, on this
// host, measured, a few hours before the test was written.

// TestThePayloadInheritsNothingButStdio is the regression for F1.
//
// The payload used to hold the snug-args memfd at fd 9, READ-WRITE, on the
// stage path: its own complete resolved boundary — every host path bound and
// at what access, every --ro-bind-try that was attempted and found absent,
// every --setenv name and value, the uid/gid, and the fd numbers of the
// seccomp filter and the handshake pipes — readable out of /proc/self/fd, plus
// a writable descriptor on a snug-internal kernel object. That contradicts
// both the stated reason the memfd exists (internal/sandbox/exec.go) and the
// abuse sentence --dry-run's TOPOLOGY block PRINTS ("holds no descriptor it
// can open"). It was found independently by two red teams.
//
// The cause was not fd 9 and the fix is not fd 9: Go's fork/exec installs a
// child's descriptors with dup3 and does NOT close the SOURCE descriptor, so
// every descriptor P1 handed down that landed on a LOWER number survived at
// its original number as a second copy. Sealing the sources is what makes this
// hold for descriptor blocks of any size and any future shape, which is why
// this test asserts the WHOLE table rather than the absence of one name.
//
// Positive controls, both needed:
//   - the payload really enumerated its own descriptors (it must find stdio);
//   - the judgement applied to that table flags a planted line, so an empty
//     finding is a fact about the sandbox rather than about the classifier.
func TestThePayloadInheritsNothingButStdio(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)

	for _, tc := range []struct {
		name  string
		args  []string
		stage bool
	}{
		{"offline", nil, false},
		{"stage", []string{"-p", "@net"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proj, _ := target(t)
			// ls -l, not a shell loop: the link TARGET is what identifies a
			// descriptor, and the payload must print it for anything the host
			// side cannot see (a memfd has no path).
			args := append(append([]string{}, tc.args...), proj, "--",
				"/bin/sh", "-c", "echo "+payloadMarker+"; ls -l /proc/self/fd/")
			out, code := cli(t, baseEnv(), args...)
			if code != 0 {
				t.Fatalf("PRECONDITION: the run failed (exit %d):\n%s", code, out)
			}
			if !strings.Contains(out, payloadMarker) {
				t.Fatalf("PRECONDITION: no payload marker, so the payload never ran:\n%s", out)
			}

			var stdio, suspicious []string
			for _, ln := range strings.Split(out, "\n") {
				fd, tgt, ok := parseFdLine(ln)
				if !ok {
					continue
				}
				if fd <= 2 {
					stdio = append(stdio, ln)
					continue
				}
				// fd 3 belongs to `ls` itself: it is the open directory
				// handle on /proc/self/fd that produced this listing, and it
				// necessarily names that same path.
				if fd == 3 && strings.HasSuffix(tgt, "/fd") {
					continue
				}
				suspicious = append(suspicious, ln)
			}

			if len(stdio) == 0 {
				t.Fatalf("PRECONDITION: the payload listed no stdio descriptors at all, so "+
					"this listing is not a descriptor table and the test would pass "+
					"vacuously:\n%s", out)
			}
			if len(suspicious) > 0 {
				t.Errorf("the payload holds %d descriptor(s) beyond stdio and its own:\n%s\n"+
					"Anything here is inherited from snug's side of the boundary; the whole "+
					"point of the args memfd is that the payload cannot read its own policy.",
					len(suspicious), strings.Join(suspicious, "\n"))
			}
		})
	}

	// The classifier's own positive control: the exact line the hole used to
	// produce must be judged suspicious by the code above.
	planted := "lrwx------. 1 u u 64 Aug 13 10:32 9 -> /memfd:snug-args (deleted)"
	fd, _, ok := parseFdLine(planted)
	if !ok || fd != 9 {
		t.Fatalf("the fd-line parser does not recognise the line this hole actually produced "+
			"(%q), so the negative result above proves nothing", planted)
	}
}

// parseFdLine pulls the descriptor number and its link target out of one line
// of `ls -l /proc/self/fd`. It returns ok=false for anything that is not such
// a line (the "total 0" header, the payload marker, snug's own warnings), so a
// caller cannot mistake noise for an empty table.
func parseFdLine(ln string) (fd int, target string, ok bool) {
	name, tgt, found := strings.Cut(ln, " -> ")
	if !found {
		return 0, "", false
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0, "", false
	}
	return n, strings.TrimSpace(tgt), true
}

// TestAStalledPastaNeitherHangsNorRunsThePayload is the regression for F2's
// first half: a pasta that STARTS and then DIES.
//
// TestAbortedNetworkNeverRunsThePayload covers the case where pasta is missing
// entirely, which fails at exec.LookPath before anything is parked. This one
// covers the case that deadlocked snug: netHelper's wait result was a value in
// a buffered channel with three readers, waitForNetDevice took it, and stop()
// then blocked forever on a receive that could never arrive — with the payload
// parked on bwrap's --block-fd the whole time. MEASURED as a real hang, from a
// goroutine dump of a hung snug.
//
// The hang is what made it dangerous rather than annoying: the human's only
// available response is to kill snug, and that used to run the payload.
//
// Positive control: the same payload, the same target, with the REAL pasta,
// must produce the marker file — otherwise "no marker" would be evidence about
// the payload rather than about the abort.
func TestAStalledPastaNeitherHangsNorRunsThePayload(t *testing.T) {
	// Deliberately above cli()'s own 30s cmdTimeout: the hang this test exists
	// to catch should be reported by cli as "a hang is a finding", naming the
	// invocation, rather than as a budget overrun that names nothing. The
	// passing case runs in about two seconds.
	budget(t, 45*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	marker := proj + "/PWNED"
	payload := `echo pwned > "$SNUG_TARGET/PWNED"`

	// Positive control FIRST: with the real pasta this payload does write the
	// marker, so the negative below is about the abort path.
	out, code := cli(t, baseEnv(), "-p", "@net", proj, "--", "/bin/sh", "-c", payload)
	if code != 0 {
		t.Fatalf("PRECONDITION: an ordinary @net run failed (exit %d):\n%s", code, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("PRECONDITION: the payload did not write %s on a run that succeeded, so "+
			"its absence below would prove nothing: %v", marker, err)
	}

	// A pasta that starts, lives briefly, and dies — the shape a crashing or
	// OOM-killed helper has, and the one a missing binary does NOT have.
	fakeBin := t.TempDir()
	if err := os.WriteFile(fakeBin+"/pasta", []byte("#!/bin/sh\nsleep 0.3\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath := os.Getenv("PATH")
	if realPath == "" {
		realPath = "/usr/bin:/bin"
	}

	for i := range 5 {
		// Only the first iteration has a marker to clear — the control run's.
		// Every later one is preceded by an abort, which is the whole point.
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		// cli() fails the test itself if snug does not finish within
		// cmdTimeout, so the hang half of this finding is asserted here.
		out, code := cli(t, baseEnv("PATH="+fakeBin+":"+realPath), "-p", "@net", proj,
			"--", "/bin/sh", "-c", payload)
		if code == 0 {
			t.Fatalf("iteration %d: snug reported success with a pasta that dies:\n%s", i, out)
		}
		if !strings.Contains(out, "pasta exited before the network came up") {
			t.Fatalf("iteration %d: snug failed for some other reason than the dead pasta, "+
				"so this iteration exercised something else:\n%s", i, out)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("iteration %d: the payload executed and wrote to the target on a run "+
				"snug reported as aborted (exit %d):\n%s", i, code, out)
		}
	}
}

// TestKillingSnugDuringStartupNeverRunsThePayload is what the old
// TestKillingSnugWhileThePayloadIsParkedDoesNotRunIt became when the parked
// window was deleted, and the rename is the finding.
//
// The old test could not assert SIGKILL and said so in its own doc comment:
// bwrap releases a payload parked on --block-fd on EOF exactly as readily as
// on a byte, snug's death closes the write end, and SIGKILL gives snug no
// chance to intervene. Measured 5/5 with the payload running and an orphaned
// sandbox left behind. Three review rounds also reported SIGTERM as open; that
// was a measurement error — they killed after the release point — but the
// SIGKILL half was real and unfixable by any guard, because a guard catches
// signals and that is the one signal that cannot be caught.
//
// It is fixed by ordering rather than by defending: pasta now attaches to the
// namespace BEFORE bwrap is forked, so during startup there is no payload in
// existence to release. SIGKILL is therefore asserted here alongside the
// catchable signals — the assertion the previous version had to exclude.
//
// The fake pasta hangs without ever configuring an interface, which holds snug
// in exactly the phase this is about: helper started, network not up, sandbox
// deliberately not forked yet.
//
// Positive control: an identical run with the real pasta writes the marker.
func TestKillingSnugDuringStartupNeverRunsThePayload(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	marker := proj + "/PWNED"
	payload := `echo pwned > "$SNUG_TARGET/PWNED"`

	out, code := cli(t, baseEnv(), "-p", "@net", proj, "--", "/bin/sh", "-c", payload)
	if code != 0 {
		t.Fatalf("PRECONDITION: an ordinary @net run failed (exit %d):\n%s", code, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("PRECONDITION: the payload did not write %s on a run that succeeded: %v", marker, err)
	}

	fakeBin := t.TempDir()
	if err := os.WriteFile(fakeBin+"/pasta", []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath := os.Getenv("PATH")
	if realPath == "" {
		realPath = "/usr/bin:/bin"
	}

	for _, sig := range []syscall.Signal{
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGKILL,
	} {
		t.Run(sig.String(), func(t *testing.T) {
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sh", "-c", payload)
			cmd.Env = baseEnv("PATH=" + fakeBin + ":" + realPath)
			cmd.WaitDelay = waitDelay
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}

			// PRECONDITION, and it is the one that makes the whole test mean
			// something: wait until the STAGE exists and pasta has been started,
			// so the signal lands in the interval this test is named for. Under
			// the old ordering the bar was "bwrap exists"; there is deliberately
			// no bwrap here yet, and asserting on its absence is the point.
			if _, ok := findDescendant(cmd.Process.Pid, isStageProcess, 10*time.Second); !ok {
				cmd.Process.Kill()
				cmd.Wait()
				t.Fatal("PRECONDITION: the stage never appeared, so nothing was exercised")
			}
			if pid, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 500*time.Millisecond); ok {
				cmd.Process.Kill()
				cmd.Wait()
				t.Fatalf("PRECONDITION FAILED, and this is a REGRESSION rather than a flake: "+
					"bwrap (pid %d) exists while the network is not up. The ordering that "+
					"closes this window is pasta-first; if bwrap is being forked before the "+
					"stage confirms the interface, the parked window is back", pid)
			}

			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()

			// Give a released payload every chance to run before looking: a
			// check made too early would pass for the wrong reason.
			time.Sleep(700 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Errorf("%s to a starting snug ran the payload and wrote to the target. "+
					"With pasta-first ordering no payload exists during startup, so this "+
					"means bwrap was forked before the network was confirmed", sig)
			}
		})
	}
}

// TestTheCapabilityBoundingSetIsEmptyOnEveryTopology is the regression for F3.
//
// CapBnd went from 0 to the FULL set on the stage path alone, with no error,
// no warning, no golden diff and no --dry-run line — invariant 5's silent
// downgrade. The cause was not in snug's argv at all: MEASURED, bwrap drops
// the bounding set on its own only when it judges its PARENT unprivileged, and
// under the stage its parent is uid 0 in a user namespace with a full
// capability set. The fix routes the guarantee back through the resolved
// policy (an explicit --cap-drop ALL for every topology) rather than through
// bwrap's inference, which is also why this test runs on both.
//
// Positive control: the CapBnd line must actually be found and parsed. A test
// that greps for a value and finds no line at all would otherwise pass.
func TestTheCapabilityBoundingSetIsEmptyOnEveryTopology(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"offline", nil},
		{"stage", []string{"-p", "@net"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proj, _ := target(t)
			args := append(append([]string{}, tc.args...), proj, "--",
				"/bin/sh", "-c", "echo "+payloadMarker+"; grep -E '^(CapBnd|CapEff|NoNewPrivs):' /proc/self/status")
			out, code := cli(t, baseEnv(), args...)
			if code != 0 {
				t.Fatalf("PRECONDITION: the run failed (exit %d):\n%s", code, out)
			}
			if !strings.Contains(out, payloadMarker) {
				t.Fatalf("PRECONDITION: no payload marker:\n%s", out)
			}

			seen := map[string]string{}
			for _, ln := range strings.Split(out, "\n") {
				k, v, ok := strings.Cut(ln, ":")
				if !ok {
					continue
				}
				seen[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
			for _, k := range []string{"CapBnd", "CapEff", "NoNewPrivs"} {
				if _, ok := seen[k]; !ok {
					t.Fatalf("PRECONDITION: no %s line in the payload's own /proc/self/status, "+
						"so nothing below was actually measured:\n%s", k, out)
				}
			}
			if seen["CapBnd"] != "0000000000000000" {
				t.Errorf("the payload's capability BOUNDING set is %s, not empty. It is inert "+
					"under NoNewPrivs=1 with MS_NOSUID mounts, so this is a lost layer of "+
					"defence in depth rather than an escalation — but it disappeared silently "+
					"once and must not again", seen["CapBnd"])
			}
			if seen["CapEff"] != "0000000000000000" {
				t.Errorf("the payload's effective capability set is %s, not empty", seen["CapEff"])
			}
			if seen["NoNewPrivs"] != "1" {
				t.Errorf("NoNewPrivs is %q, not 1", seen["NoNewPrivs"])
			}
		})
	}
}

// stateOf reads a process's scheduling state letter from /proc/<pid>/status —
// 'T' for stopped, 'R'/'S'/'D' for variously running. Used to PROVE the
// SIGSTOP below actually landed, because a test that freezes nothing and then
// observes a clean teardown observes only that the ordinary path works.
func stateOf(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "State:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// descendantsOf returns every readable pid whose ancestry reaches root within a
// few hops, root excluded — the whole sandbox tree, including pasta, which is a
// child of snug rather than of the stage.
func descendantsOf(root int) []int {
	var out []int
	for _, pid := range allPIDs() {
		if pid == root {
			continue
		}
		p := pid
		for hop := 0; hop < 8; hop++ {
			parent, ok := ppidOf(p)
			if !ok {
				break
			}
			if parent == root {
				out = append(out, pid)
				break
			}
			p = parent
		}
	}
	return out
}

// TestAFrozenStageTreeStillDiesWithSnug is the regression for a finding that
// runs the opposite way to the usual one: the code was SAFER than its comments
// claimed, and the comments invited the edit that would break it.
//
// Two mechanisms tear the stage down, and they cover different failures. The
// lifeline pipe needs the stage to RUN A GOROUTINE to notice EOF. PR_SET_PDEATHSIG
// needs nothing — the kernel delivers it. Two comments in internal/stage
// asserted, as measured fact, that Pdeathsig does not survive the
// __stage-setup → __stage-serve re-exec (a secureexec transition zeroing
// pdeath_signal) and concluded that "the lifeline is the mechanism that
// actually holds; this cannot be relied on alone". That was measured FALSE:
// capabilities do not widen at that exec, because the stage already holds a
// full set in U from the moment it creates the user namespace, so there is no
// secureexec.
//
// The distinction is not academic. A process in state 'T' executes no user
// code at all, so a SIGSTOPped stage can never see the lifeline's EOF. If
// someone deletes the Pdeathsig line as the dead weight the old comment
// described, this case becomes an orphaned sandbox holding a network namespace
// with nothing left to tear it down.
//
// The positive control is the freeze itself: every member of the tree is
// asserted to be in state 'T' BEFORE snug is killed. Without it a green result
// would only prove that the lifeline works, which no longer answers anything.
func TestAFrozenStageTreeStillDiesWithSnug(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "30")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	frozen := []int{}
	killed := false
	t.Cleanup(func() {
		// Un-freeze before anything else, or a failed run leaves stopped
		// processes on the host that nothing will ever reap.
		for _, pid := range frozen {
			_ = syscall.Kill(pid, syscall.SIGCONT)
		}
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	bwrapPID, ok := findDescendant(cmd.Process.Pid, isComm("bwrap"), 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: bwrap never appeared")
	}
	if _, ok := findDescendant(cmd.Process.Pid, isComm("sleep"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: the payload ('sleep') never appeared")
	}
	sandboxNet, err := os.Readlink("/proc/" + strconv.Itoa(bwrapPID) + "/ns/net")
	if err != nil {
		t.Fatalf("reading the sandbox's netns: %v", err)
	}

	tree := descendantsOf(cmd.Process.Pid)
	if len(tree) < 3 {
		t.Fatalf("PRECONDITION: expected at least a stage, a pasta and a bwrap below snug, got %v", tree)
	}
	sawStage := false
	for _, pid := range tree {
		if isStageProcess(pid) {
			sawStage = true
		}
	}
	if !sawStage {
		t.Fatalf("PRECONDITION: no stage process in snug's tree %v; this test is not exercising "+
			"the stage topology at all", tree)
	}

	// Freeze the whole tree. SIGSTOP is not deliverable to a process that has
	// already exited, so ignore ESRCH and let the state check below decide.
	for _, pid := range tree {
		if err := syscall.Kill(pid, syscall.SIGSTOP); err == nil {
			frozen = append(frozen, pid)
		}
	}

	// POSITIVE CONTROL: every frozen member really is stopped. If this does not
	// hold, a clean teardown below proves nothing, because the lifeline would
	// have been free to do the work.
	stoppedDeadline := time.Now().Add(3 * time.Second)
	for {
		var awake []int
		for _, pid := range frozen {
			if s := stateOf(pid); s != "" && s != "T" {
				awake = append(awake, pid)
			}
		}
		if len(awake) == 0 {
			break
		}
		if time.Now().After(stoppedDeadline) {
			t.Fatalf("PRECONDITION: pid(s) %v never reached state T; the freeze did not land, so "+
				"this run cannot distinguish Pdeathsig from the lifeline", awake)
		}
		time.Sleep(25 * time.Millisecond)
	}

	beforeSet := pidSet(sweepNetnsAcrossAllProcesses()[sandboxNet])
	if len(beforeSet) == 0 {
		t.Fatal("PRECONDITION: the sandbox's namespace does not appear in the sweep before the kill")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	killed = true

	// No SIGCONT here on purpose: nothing in the tree is ever allowed to run
	// again. Whatever tears it down has to be the kernel.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var survivors []int
		for _, pid := range frozen {
			// An exited-but-unreaped process still has a /proc entry; state 'Z'
			// means it is gone in every sense that matters here.
			if s := stateOf(pid); s != "" && s != "Z" {
				survivors = append(survivors, pid)
			}
		}
		var inNS []int
		for _, pid := range sweepNetnsAcrossAllProcesses()[sandboxNet] {
			if beforeSet[pid] {
				inNS = append(inNS, pid)
			}
		}
		if len(survivors) == 0 && len(inNS) == 0 && !mountinfoHasNsfsFor(sandboxNet) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a FROZEN stage tree survived SIGKILL of snug: pid(s) %v still exist, %v still "+
				"report namespace %s. The lifeline cannot fire in a stopped process, so this is "+
				"what PR_SET_PDEATHSIG in internal/stage/stage.go is for — check it is still there",
				survivors, inNS, sandboxNet)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
