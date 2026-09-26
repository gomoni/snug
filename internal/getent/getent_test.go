package getent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeGetent points LookPath at a shell script that prints out and exits with
// code, for the duration of one test: parsing is judged on bytes this test
// chose, not on whatever accounts the machine running it happens to have.
//
// out is written into the script as a `\NNN` octal escape per byte, passed as
// printf's FORMAT argument (no separate %s data argument), so the script file
// on disk never carries out's bytes directly — only ASCII digits and
// backslashes — and printf reconstitutes them exactly at run time. That is
// what lets a fixture carry a NUL: a NUL byte sitting in the script's own text
// confuses the shell reading the file (measured: `cannot execute binary
// file`), where an escape sequence producing one at print time does not.
func fakeGetent(t *testing.T, out string, code int) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "getent")
	var escaped strings.Builder
	for i := 0; i < len(out); i++ {
		fmt.Fprintf(&escaped, `\%03o`, out[i])
	}
	body := "#!/bin/sh\nprintf '" + escaped.String() + "'\nexit " +
		strconv.Itoa(code) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := LookPath
	LookPath = func() (string, error) { return script, nil }
	t.Cleanup(func() { LookPath = orig })
}

func TestPasswdByUIDParsesTheEntry(t *testing.T) {
	fakeGetent(t, "alice@example.com:*:1000:100:Alice:/home/alice:/bin/zsh\n", 0)
	pw, err := PasswdByUID(1000)
	if err != nil {
		t.Fatal(err)
	}
	want := Passwd{Name: "alice@example.com", UID: 1000, GID: 100, Gecos: "Alice",
		Home: "/home/alice", Shell: "/bin/zsh"}
	if pw != want {
		t.Fatalf("got %+v, want %+v", pw, want)
	}
}

func TestGroupByGIDParsesTheEntry(t *testing.T) {
	fakeGetent(t, "users:x:100:\n", 0)
	gr, err := GroupByGID(100)
	if err != nil {
		t.Fatal(err)
	}
	if gr != (Group{Name: "users", GID: 100}) {
		t.Fatalf("got %+v", gr)
	}
}

func TestExitTwoIsErrNoEntry(t *testing.T) {
	fakeGetent(t, "", 2)
	_, err := PasswdByUID(4242)
	if !errors.Is(err, ErrNoEntry) {
		t.Fatalf("got %v, want an error wrapping ErrNoEntry", err)
	}
}

// Every other failure is a refusal a caller must NOT read as "no entry":
// that is the difference between a uid with no name and a host whose NSS is
// broken, and only the first is an answer.
func TestRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		code      int
		call      func() error
		want      string
	}{
		{"another exit code", "", 1, func() error { _, err := PasswdByUID(1000); return err }, "failed"},
		{"a second line", "a:x:1000:1000::/h:/bin/sh\nb:x:1000:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "exactly one line"},
		{"no trailing newline", "a:x:1000:1000::/h:/bin/sh", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "exactly one line"},
		{"a carriage return", "a:x:1000:1000::/h:/bin/sh\r\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "'\\r'"},
		{"six fields", "a:x:1000:1000::/h\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "want exactly 7"},
		{"another uid", "a:x:1001:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "not 1000"},
		{"an empty name", ":x:1000:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "empty account name"},
		{"another name", "bob:x:1000:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByName("alice"); return err }, `not "alice"`},
		{"a numeric name", "", 0,
			func() error { _, err := PasswdByName("1000"); return err }, "read as a uid"},
		{"another gid", "users:x:101:\n", 0,
			func() error { _, err := GroupByGID(100); return err }, "not 100"},
		{"a NUL byte in the name", "a\x00b:x:1000:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "control byte"},
		{"a DEL byte in the name", "a\x7fb:x:1000:1000::/h:/bin/sh\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "control byte"},
		{"a C0 control byte in the shell field", "a:x:1000:1000::/h:/bin/sh\x01\n", 0,
			func() error { _, err := PasswdByUID(1000); return err }, "control byte"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeGetent(t, tc.out, tc.code)
			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal containing %q", err, tc.want)
			}
			if errors.Is(err, ErrNoEntry) {
				t.Fatalf("%v wraps ErrNoEntry; only exit 2 may", err)
			}
		})
	}
}

// TestWaitDelayBoundsAChildHoldingThePipe reproduces the shape from issue
// #612's redteam round: getent backgrounds a child before exec'ing its own
// replacement, and that child inherits the stdout/stderr pipe fds. The
// context kill at Timeout only reaches the direct child (the exec'd `sleep`),
// so without WaitDelay forcibly closing the pipes, Run blocks on the
// backgrounded child until IT exits — 30s here, unbounded in the reproduction
// that used `sleep infinity &`.
func TestWaitDelayBoundsAChildHoldingThePipe(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "getent")
	body := "#!/bin/sh\nsleep 30 &\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := LookPath
	LookPath = func() (string, error) { return script, nil }
	t.Cleanup(func() { LookPath = orig })

	start := time.Now()
	_, err := PasswdByUID(1000)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v, want a timeout refusal", err)
	}
	if want := Timeout + 2*time.Second; elapsed > want {
		t.Fatalf("Run took %s to return, want at most %s: WaitDelay is not bounding "+
			"the wait for a child holding the pipe", elapsed, want)
	}
}

// TestStderrIsEscaped reproduces the #612 reproduction where a getent stderr
// carrying an ESC + cursor-control sequence overwrote the start of snug's own
// refusal on the terminal ("boom" then a clear-line and cursor-up landed
// "snug: all good" over it). Run must pass stderr through policy.VisibleText
// before it reaches the error, so the escape sequence renders as text rather
// than executing as one.
func TestStderrIsEscaped(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "getent")
	body := "#!/bin/sh\nprintf 'boom\\033[2K\\033[1Asnug: all good\\n' >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := LookPath
	LookPath = func() (string, error) { return script, nil }
	t.Cleanup(func() { LookPath = orig })

	_, err := PasswdByUID(1000)
	if err == nil {
		t.Fatal("got nil error, want a refusal carrying getent's stderr")
	}
	if strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("error contains a raw ESC byte, not escaped: %q", err.Error())
	}
	if !strings.Contains(err.Error(), `\x1b[2K`) {
		t.Fatalf("error = %q, want the ESC sequence escaped as \\x1b[2K", err.Error())
	}
}

// TestStderrIsBounded reproduces the #612 measurement of 400 MB written to
// stderr costing 1.8 GiB of peak RSS to hold and re-quote: Run must cap what
// it captures rather than growing without limit.
func TestStderrIsBounded(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "getent")
	// 10 MiB of 'A', well past maxCapturedOutput, written in one shot so a
	// short write loop cannot hide a missing cap.
	body := "#!/bin/sh\nyes A | tr -d '\\n' | head -c 10000000 >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := LookPath
	LookPath = func() (string, error) { return script, nil }
	t.Cleanup(func() { LookPath = orig })

	_, err := PasswdByUID(1000)
	if err == nil {
		t.Fatal("got nil error, want a refusal")
	}
	if got := len(err.Error()); got > 2*maxCapturedOutput {
		t.Fatalf("error is %d bytes, want at most roughly %d (maxCapturedOutput): "+
			"stderr was not capped", got, maxCapturedOutput)
	}
}

func TestMissingGetentNamesTheFix(t *testing.T) {
	orig := LookPath
	LookPath = func() (string, error) { return "", errors.New(`exec: "getent": executable file not found in $PATH`) }
	t.Cleanup(func() { LookPath = orig })
	_, err := PasswdByUID(1000)
	if err == nil || !strings.Contains(err.Error(), "libc-bin") {
		t.Fatalf("got %v, want a refusal naming the package", err)
	}
}
