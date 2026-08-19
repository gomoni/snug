package stage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

func TestLookupIDRangeMatchesByUidWhenNameUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	if err := os.WriteFile(path, []byte("999999999:100000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupIDRange(path, 999999999); err != nil {
		t.Fatalf("lookupIDRange: %v", err)
	}
}

func TestLookupIDRangeSkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	content := "# a comment\n\n999999999:100000:65536\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := lookupIDRange(path, 999999999)
	if err != nil {
		t.Fatalf("lookupIDRange: %v", err)
	}
	if r.base != 100000 || r.size != 65536 {
		t.Errorf("got %+v, want base=100000 size=65536", r)
	}
}

// TestLookupIDRangeRefusesNamesTheFix is invariant "errors name the fix":
// asking for an id with no entry must name the id AND a concrete example
// line, not just "not found".
func TestLookupIDRangeRefusesNamesTheFix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	if err := os.WriteFile(path, []byte("someoneelse:100000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := lookupIDRange(path, 999999999)
	if err == nil {
		t.Fatal("lookupIDRange accepted an id with no matching entry")
	}
	if !strings.Contains(err.Error(), "999999999:100000:65536") {
		t.Errorf("error %q does not name a concrete fix line", err)
	}
}

func TestLookupIDRangeRefusesMissingFile(t *testing.T) {
	if _, err := lookupIDRange("/does/not/exist/subuid", 0); err == nil {
		t.Fatal("lookupIDRange accepted a missing file")
	}
}

// TestFindIDMapToolRefusesAnUnknownName pins the "errors name the fix" shape
// for the tool-not-found case, without depending on newuidmap being ABSENT
// from this host (it is present in the dev environment).
func TestFindIDMapToolRefusesAnUnknownName(t *testing.T) {
	_, err := findIDMapTool("snug-definitely-not-a-real-binary")
	if err == nil {
		t.Fatal("findIDMapTool accepted a binary that does not exist")
	}
	if !strings.Contains(err.Error(), "shadow-utils") {
		t.Errorf("error %q does not name the fix", err)
	}
}

// TestDelegateSubuidWritesBothRanges is the real-execution check for the
// mechanism the whole file exists to provide: fork a plain child into a
// FRESH, unmapped user namespace (mirroring exactly what Start leaves for
// SubuidFull — no SysProcAttr.UidMappings/GidMappings), call delegateSubuid
// against its pid while it blocks with an unmapped uid_map, and read back
// what landed. This is the positive control for
// TestPodmanDelegatesFullSubuid's policy-layer claim: here is proof the
// MECHANISM the policy now demands actually produces the two-range map on a
// real kernel, not just that the Topology struct says SubuidFull.
//
// Skipped, not failed, when this host cannot support it (no newuidmap, no
// /etc/subuid entry, no unprivileged userns) — sandbox-tester's brief is the
// full privileged integration suite; this is the one case worth checking here
// because it is new, low-level, security-relevant code this pass introduces.
func TestDelegateSubuidWritesBothRanges(t *testing.T) {
	if _, err := findIDMapTool("newuidmap"); err != nil {
		t.Skipf("newuidmap not available: %v", err)
	}
	if _, err := findIDMapTool("newgidmap"); err != nil {
		t.Skipf("newgidmap not available: %v", err)
	}
	hostUID, hostGID := os.Getuid(), os.Getgid()
	uRange, err := lookupIDRange("/etc/subuid", hostUID)
	if err != nil {
		t.Skipf("no /etc/subuid range for this user: %v", err)
	}
	gRange, err := lookupIDRange("/etc/subgid", hostGID)
	if err != nil {
		t.Skipf("no /etc/subgid range for this user: %v", err)
	}

	cmd := exec.Command("/bin/sleep", "5")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		// Deliberately nil: this is the exact shape Start uses for SubuidFull
		// — leaving the map unwritten so delegateSubuid, not Go, writes it.
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot create a user namespace on this host: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Give the child a moment to reach its blocking sleep before the maps are
	// written — there is no synchronization needed for correctness (the
	// kernel lets the map be written at any point before the namespace is
	// destroyed), but reading /proc/<pid>/uid_map moments after Start can
	// race the exec transition on a loaded machine.
	time.Sleep(50 * time.Millisecond)

	if err := delegateSubuid(cmd.Process.Pid, hostUID, hostGID); err != nil {
		t.Fatalf("delegateSubuid: %v", err)
	}

	uidMap, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/uid_map")
	if err != nil {
		t.Fatalf("reading uid_map: %v", err)
	}
	wantUID := "0" + spaces + strconv.Itoa(hostUID) + spaces + "1"
	if !strings.Contains(normalizeMapLine(string(uidMap)), wantUID) {
		t.Errorf("uid_map = %q, does not contain the self-map line %q", uidMap, wantUID)
	}
	wantUIDRange := "1" + spaces + strconv.Itoa(int(uRange.base)) + spaces + strconv.Itoa(int(uRange.size))
	if !strings.Contains(normalizeMapLine(string(uidMap)), wantUIDRange) {
		t.Errorf("uid_map = %q, does not contain the delegated range %q", uidMap, wantUIDRange)
	}

	gidMap, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/gid_map")
	if err != nil {
		t.Fatalf("reading gid_map: %v", err)
	}
	wantGIDRange := "1" + spaces + strconv.Itoa(int(gRange.base)) + spaces + strconv.Itoa(int(gRange.size))
	if !strings.Contains(normalizeMapLine(string(gidMap)), wantGIDRange) {
		t.Errorf("gid_map = %q, does not contain the delegated range %q", gidMap, wantGIDRange)
	}
}

const spaces = " "

// normalizeMapLine collapses the kernel's column-aligned whitespace
// (/proc/<pid>/uid_map right-justifies each field with variable padding) down
// to single spaces, so a Contains check does not have to guess the exact
// column widths the kernel chose.
func normalizeMapLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// TestStartDelegatesTheFullSubuidRange is the end-to-end proof for the whole
// mechanism this file adds: not just that delegateSubuid can write a map
// against an arbitrary forked child (TestDelegateSubuidWritesBothRanges
// above), but that stage.Start ITSELF, driven exactly the way
// internal/sandbox drives it, reaches "ready" with the map already landed —
// walking the real needmap/mapped handshake (stage.go, setup.go) end to end.
// Made possible by TestMain in mainprocess_test.go, without which Start's
// re-exec of /proc/self/exe ("__stage-setup") would be this test binary's own
// unrecognised argv[1] rather than a real hidden-verb dispatch.
//
// Skipped, not failed, under the same preconditions as
// TestDelegateSubuidWritesBothRanges — this is new capability this pass adds,
// worth a real positive-path check here; the fuller integration suite
// (teardown on SIGKILL, nsfs leak checks, the container itself) is
// sandbox-tester's brief.
func TestStartDelegatesTheFullSubuidRange(t *testing.T) {
	if _, err := findIDMapTool("newuidmap"); err != nil {
		t.Skipf("newuidmap not available: %v", err)
	}
	if _, err := findIDMapTool("newgidmap"); err != nil {
		t.Skipf("newgidmap not available: %v", err)
	}
	hostUID, hostGID := os.Getuid(), os.Getgid()
	uRange, err := lookupIDRange("/etc/subuid", hostUID)
	if err != nil {
		t.Skipf("no /etc/subuid range for this user: %v", err)
	}
	gRange, err := lookupIDRange("/etc/subgid", hostGID)
	if err != nil {
		t.Skipf("no /etc/subgid range for this user: %v", err)
	}

	st, err := Start(Config{
		Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidFull},
		// Required since issue #125's gate: the stage reads bwrap's --info-fd
		// answer itself. This test never gets as far as a "start" request, so
		// any open descriptor satisfies it.
		BwrapInfo: devNullFile(t),
		Stdin:     devNullFile(t), Stdout: devNullFile(t), Stderr: devNullFile(t),
	})
	if err != nil {
		if isUnprivilegedUsernsRefusal(err) {
			// The plain `gate` CI lane runs on Ubuntu 24.04's default
			// kernel.apparmor_restrict_unprivileged_userns=1, which refuses
			// the clone outright — only the `integration` lane's workflow
			// step relaxes that sysctl. Skipping here, not failing, matches
			// this file's OWN precondition skips above and the project-wide
			// convention (ci.yml's own comment: "the harness SKIPS where the
			// host cannot create namespaces"). A host that genuinely cannot
			// create user namespaces at all was never going to be able to
			// run snug regardless of this change.
			t.Skipf("this host refuses unprivileged user namespaces: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	defer st.Close()

	uidMap, err := os.ReadFile("/proc/" + strconv.Itoa(st.Pid()) + "/uid_map")
	if err != nil {
		t.Fatalf("reading the stage's own uid_map: %v", err)
	}
	got := normalizeMapLine(string(uidMap))
	wantSelf := "0" + spaces + strconv.Itoa(hostUID) + spaces + "1"
	if !strings.Contains(got, wantSelf) {
		t.Errorf("stage uid_map = %q, missing the self-map line %q", uidMap, wantSelf)
	}
	wantRange := "1" + spaces + strconv.Itoa(int(uRange.base)) + spaces + strconv.Itoa(int(uRange.size))
	if !strings.Contains(got, wantRange) {
		t.Errorf("stage uid_map = %q, missing the delegated range %q", uidMap, wantRange)
	}

	gidMap, err := os.ReadFile("/proc/" + strconv.Itoa(st.Pid()) + "/gid_map")
	if err != nil {
		t.Fatalf("reading the stage's own gid_map: %v", err)
	}
	wantGRange := "1" + spaces + strconv.Itoa(int(gRange.base)) + spaces + strconv.Itoa(int(gRange.size))
	if !strings.Contains(normalizeMapLine(string(gidMap)), wantGRange) {
		t.Errorf("stage gid_map = %q, missing the delegated range %q", gidMap, wantGRange)
	}
}

func devNullFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
