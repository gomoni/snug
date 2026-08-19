package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr replaced by a pipe and returns what it
// wrote. The notices under test go to os.Stderr directly — deliberately, since
// they are terminal output rather than data — so intercepting the file is the
// only honest way to assert on them.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	os.Stderr = prev
	w.Close()
	out := <-done
	r.Close()
	return out
}

// seedStaleRunDir plants what an abnormally-terminated run leaves behind: a
// run directory with a lock file nobody holds. That is exactly the shape
// sweepStaleRunDirs is looking for — a held lock means a live run and is left
// alone, so an unheld one is the corpse.
func seedStaleRunDir(t *testing.T, xdg, name string) string {
	t.Helper()
	dir := filepath.Join(xdg, "snug", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(xdg, "snug"), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return dir
}

// TestStaleRunDirectoryNoticeIsQuietByDefault is issue #118.
//
// snug swept a stale run directory on the way in — the #85/#100 sweep — and
// announced it on stderr every time. That fires on the everyday path after any
// abnormal termination, reports work that SUCCEEDED, and describes a directory
// the user never knew existed and cannot act on. Correct information in the
// wrong register: it reads like a warning for snug working as designed.
//
// The positive control is not optional and it is the interesting half:
// "printed nothing" is also exactly what a sweep that never ran would produce.
// So both subtests assert that the stale directory was actually REMOVED — the
// silence has to be the silence of work done, not of work skipped.
func TestStaleRunDirectoryNoticeIsQuietByDefault(t *testing.T) {
	t.Run("default-is-silent-but-still-sweeps", func(t *testing.T) {
		xdg := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", xdg)
		stale := seedStaleRunDir(t, xdg, "run-999999")

		var runPath string
		out := captureStderr(t, func() {
			var err error
			runPath, err = runtimeDir()
			if err != nil {
				t.Errorf("runtimeDir: %v", err)
			}
		})
		t.Cleanup(func() { os.RemoveAll(runPath) })

		if strings.Contains(out, "stale run directory") {
			t.Errorf("a routine sweep announced itself on stderr with no --verbose asked for: %q", out)
		}
		// POSITIVE CONTROL: the sweep really ran.
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatalf("PRECONDITION: the stale run directory %s was not removed (err=%v), so the "+
				"silence above is the silence of a sweep that did nothing — this test would pass "+
				"on a build that had lost the sweep entirely", stale, err)
		}
	})

	t.Run("verbose-says-what-it-did", func(t *testing.T) {
		xdg := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", xdg)
		stale := seedStaleRunDir(t, xdg, "run-999998")

		prev := housekeepingVerbose
		setHousekeepingVerbose(true)
		t.Cleanup(func() { setHousekeepingVerbose(prev) })

		var runPath string
		out := captureStderr(t, func() {
			var err error
			runPath, err = runtimeDir()
			if err != nil {
				t.Errorf("runtimeDir: %v", err)
			}
		})
		t.Cleanup(func() { os.RemoveAll(runPath) })

		if !strings.Contains(out, "removed stale run directory") {
			t.Errorf("--verbose did not report the sweep it performed: %q", out)
		}
		if !strings.Contains(out, stale) {
			t.Errorf("the notice does not name the directory it removed, which is the only part "+
				"a user could act on: %q", out)
		}
	})
}

// TestAFailedStaleRunDirRemovalIsAlwaysReported is the other half of #118's
// "decide per-line rather than blanket".
//
// A stale directory snug could NOT remove is state that outlives the user, and
// snug promised to clean it up. Silence there would be failing quietly at
// housekeeping, so that line stays unconditional — and this test is what stops
// a later tidy-up from sweeping both lines behind the same flag.
//
// Source-scanning rather than behavioural, because provoking a RemoveAll
// failure needs an unwritable parent, and a test that chmods its way there is
// testing the kernel more than it is testing snug. The assertion is about
// which sink each line reaches, and reading the lines is the honest spelling —
// the same argument TestTheTeardownGuardIsArmedBeforeEveryForkItProtects makes
// for asserting an ORDER by reading source.
func TestAFailedStaleRunDirRemovalIsAlwaysReported(t *testing.T) {
	src, err := os.ReadFile("runtimedir.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	const failure = "could not remove stale run directory"
	i := strings.Index(text, failure)
	if i < 0 {
		t.Fatalf("PRECONDITION: %q is no longer in runtimedir.go — this test is checking nothing", failure)
	}
	// The whole statement it sits in, back to the start of its line.
	start := strings.LastIndex(text[:i], "\n")
	stmt := text[start+1 : i]
	if !strings.Contains(stmt, "os.Stderr") {
		t.Errorf("the FAILED-removal notice no longer goes straight to stderr. A stale directory "+
			"snug could not remove is state that outlives the user; hiding it behind --verbose "+
			"means snug failing quietly at housekeeping it promised to do (issue #118 asked for "+
			"this decision to be made per line). Statement was: %q", stmt)
	}
	if strings.Contains(stmt, "verboseHousekeeping") {
		t.Error("the FAILED-removal notice was moved behind --verbose along with the success line")
	}
}
