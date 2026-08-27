// doorprobe is the payload for the @http-proxy integration tests.
//
// It exists because the whole design rests on one claim nothing asserted end to
// end: that a listening descriptor snug creates on the HOST reaches the payload
// inside the sandbox, at the number LISTEN_FDS names, still listening. A
// red-team round measured that through a bwrap invocation mirroring snug's
// flags; this measures it through snug.
//
// It writes its findings to a FILE in the working directory — the target, which
// is bound rw, so the same file is visible on the host — and then serves exactly
// one HTTP response, so a test can prove the socket carries traffic rather than
// merely existing.
//
// A file and not stdout, deliberately: reading the payload's stdout through an
// os/exec pipe made the test hang intermittently before the first line arrived,
// on a run that behaved perfectly by hand. The file removes the pipe from the
// test, and it is also the thing a human debugging a door would go and look at.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const reportName = "doorprobe-report.txt"

func main() {
	var report []string
	say := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		report = append(report, line)
		fmt.Println(line) // also stdout, for a human running this by hand
	}
	// Written after every step rather than once at the end: a test waiting for
	// READY must never be waiting for a process that has already blocked.
	flush := func() {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		tmp := filepath.Join(wd, reportName+".part")
		if err := os.WriteFile(tmp, []byte(strings.Join(report, "\n")+"\n"), 0o644); err != nil {
			return
		}
		// Rename, so a reader never sees a half-written report and mistakes a
		// truncated file for a payload that stopped early.
		_ = os.Rename(tmp, filepath.Join(wd, reportName))
	}

	// LISTEN_FDS says how many descriptors start at fd 3; LISTEN_PID must equal
	// this process's own pid or a conforming client ignores them, which is the
	// failure snug's staged `exec` handover exists to prevent.
	say("LISTEN-FDS=%s", os.Getenv("LISTEN_FDS"))
	say("LISTEN-FDNAMES=%s", os.Getenv("LISTEN_FDNAMES"))
	say("LISTEN-PID=%s", os.Getenv("LISTEN_PID"))
	say("MY-PID=%d", os.Getpid())
	flush()

	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		say("FAIL=no usable LISTEN_FDS (%q)", os.Getenv("LISTEN_FDS"))
		flush()
		os.Exit(1)
	}

	l, err := net.FileListener(os.NewFile(3, "listen-fd-3"))
	if err != nil {
		say("FAIL=fd 3 is not a listener: %v", err)
		flush()
		os.Exit(1)
	}
	// The path getsockname reports from INSIDE. The design states this as a
	// deliberate leak rather than fixing it: the socket cannot be unlinked,
	// because `snug proxy` connects to it by path.
	say("SOCKET=%s", l.Addr().String())
	say("READY")
	flush()

	c, err := l.Accept()
	if err != nil {
		say("FAIL=accept: %v", err)
		flush()
		os.Exit(1)
	}
	buf := make([]byte, 4096)
	if _, err := c.Read(buf); err != nil {
		say("FAIL=read: %v", err)
		flush()
		os.Exit(1)
	}
	body := "served-by-the-payload\n"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	c.Close()
	say("SERVED")
	flush()
}
