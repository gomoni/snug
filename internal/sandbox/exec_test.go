package sandbox

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// REGRESSION, found by the redteam agent: sealInheritedFDs marks inherited fds
// above 2 close-on-exec precisely because an open directory descriptor bypasses
// the mount policy — openat(2) walks from that descriptor's own vfsmount and
// never consults the sandbox's mount namespace. Fds 0/1/2 were exempt so stdio
// could pass through, which left the identical hole on three well-known
// numbers:
//
//	snug proj -- sh -c 'cat /proc/self/fd/0/.bashrc'   < /home/user
//	snug proj -- sh -c 'echo x > /proc/self/fd/0/pwned' 0< ./ungranted
//
// Both worked — arbitrary read and write of a host subtree no profile granted.
func TestDirectoryOnStdioIsReplaced(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()
	os.Stdin = dir

	stdin, _, _, err := safeStdio()
	if err != nil {
		t.Fatal(err)
	}
	if stdin == dir {
		t.Fatal("a directory was passed through as stdin; the sandbox could reach the host " +
			"filesystem through /proc/self/fd/0")
	}

	fi, err := stdin.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.IsDir() {
		t.Error("stdin is still a directory after substitution")
	}
}

// Ordinary stdio must pass through untouched, or every pipeline breaks.
func TestNonDirectoryStdioIsUntouched(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()
	os.Stdin = f

	stdin, stdout, stderr, err := safeStdio()
	if err != nil {
		t.Fatal(err)
	}
	if stdin != f {
		t.Error("a regular file on stdin was replaced; it should pass through")
	}
	if stdout != os.Stdout || stderr != os.Stderr {
		t.Error("stdout/stderr were replaced without cause")
	}
}

// nulJoin owns the separator, so it is the one place that can say no element may
// contain it — and it is the last point at which the whole bwrap argv exists as
// Go values, so the check holds for every flag whatever authored it.
//
// The reachable case was an environ value: `--setenv NAME VALUE` is three
// elements, the list is NUL-joined into the args memfd, and bwrap's --args splits
// on NUL, so a NUL inside VALUE re-synced the parser onto the remainder and
// mounted a host directory that no Mount, no Validate pass and no --dry-run line
// ever knew about. checkEnvValue refuses that at parse time, where the error can
// name the profile; this is the backstop for every other writer.
func TestNulJoinRefusesAnElementContainingTheSeparator(t *testing.T) {
	// The positive control first: the ordinary argv must still join, or the
	// refusal below is indistinguishable from a function that always errors.
	got, err := nulJoin([]string{"--ro-bind", "/usr", "/usr"})
	if err != nil {
		t.Fatalf("nulJoin refused an ordinary flag list: %v", err)
	}
	if string(got) != "--ro-bind\x00/usr\x00/usr\x00" {
		t.Errorf("nulJoin produced %q; --args reads a NUL-TERMINATED list, so every element "+
			"including the last one carries a trailing separator", got)
	}

	if _, err := nulJoin([]string{"--setenv", "EDITOR", "vim\x00--ro-bind\x00/etc\x00/etc"}); err == nil {
		t.Error("nulJoin accepted a value containing a NUL. bwrap would read everything after " +
			"it as further flags — a mount the policy model never saw and --dry-run never " +
			"printed")
	}
	// The index is in the message because a failure here is a bug hunt, and
	// "which flag" is the first question.
	_, err = nulJoin([]string{"--dev", "/dev", "x\x00y"})
	if err == nil || !strings.Contains(err.Error(), "flag 2") {
		t.Errorf("want the offending element's index in the error, got %v", err)
	}
}

// TestFillMissingNamespaceIDsRecoversAnOmittedKey is the regression this
// session found: bwrap's --info-fd JSON OMITS a "<kind>-namespace" key
// entirely for any namespace it did not itself unshare — measured directly
// against this host's bwrap (with --unshare-net the key is present and
// correct; without it, because the process merely inherited an
// already-created netns exactly as runStaged's own stage does, the key is
// absent and json.Decoder silently zero-values it). Every @net (staged) run
// therefore recorded "net": 0 in state.json, and since attach's own live
// check treats ANY mismatch as a refusal (0 is never a real inode), every
// @net sandbox was permanently unattachable. This test proves the fallback:
// a 0 left by the decoder is replaced with the REAL inode read from
// /proc/<pid>/ns/<kind>, for THIS process's own namespaces (which this test
// can read without any privilege).
func TestFillMissingNamespaceIDsRecoversAnOmittedKey(t *testing.T) {
	namespaces := map[string]uint64{
		"mnt": 111, "pid": 0 /* simulates an omitted key */, "net": 222,
		"ipc": 0 /* simulates an omitted key */, "uts": 333, "cgroup": 444,
	}
	fillMissingNamespaceIDs(os.Getpid(), namespaces)

	// The two that were already non-zero (bwrap DID report them) must be
	// left EXACTLY alone — this fallback is for the omitted case only, never
	// a second, competing source of truth for a value bwrap already gave.
	if namespaces["mnt"] != 111 || namespaces["net"] != 222 || namespaces["uts"] != 333 || namespaces["cgroup"] != 444 {
		t.Fatalf("a non-zero value was overwritten: %+v", namespaces)
	}

	// The two that were 0 must now be real (non-zero, and — since this is
	// THIS TEST PROCESS's own pid — verifiably equal to what a fresh read of
	// the same file returns right now).
	for _, k := range []string{"pid", "ipc"} {
		if namespaces[k] == 0 {
			t.Errorf("%q is still 0 — the fallback did not fire", k)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		t.Fatal(err)
	}
	if namespaces["pid"] != st.Ino {
		t.Errorf("fillMissingNamespaceIDs recovered %d for \"pid\", but this process's own "+
			"/proc/self/ns/pid is %d", namespaces["pid"], st.Ino)
	}
}

// TestFillMissingNamespaceIDsLeavesAGoneProcessAtZero is the control for the
// test above: for a pid that does not exist, the fallback cannot recover
// anything and must leave the value at 0 rather than guessing — the caller
// (writeRunState) is what turns a persisting 0 into a refusal.
func TestFillMissingNamespaceIDsLeavesAGoneProcessAtZero(t *testing.T) {
	namespaces := map[string]uint64{"mnt": 0}
	// pid 1 is never THIS test's own process and /proc/1/ns/mnt is refused
	// with EACCES for a non-root, non-matching-uid caller on every host this
	// suite runs on — the point is just that it is NOT this process's own
	// namespace, so the fallback (whatever it does) must not silently invent
	// a value. A pid that is outright impossible (a huge number, guaranteed
	// ESRCH) is a cleaner control than relying on a permission edge case.
	const impossiblePID = 1 << 30
	fillMissingNamespaceIDs(impossiblePID, namespaces)
	if namespaces["mnt"] != 0 {
		t.Errorf("a nonexistent pid's namespace read %d instead of staying 0", namespaces["mnt"])
	}
}
