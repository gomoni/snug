package sandbox

import (
	"os"
	"testing"
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
