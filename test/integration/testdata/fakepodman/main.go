// Command fakepodman stands in for a real `podman system service` in
// test/integration/gate_test.go's issue #125 (Tier C, "C2-gate") regressions.
//
// It never touches a container. It does the ONE thing internal/stage's gate
// actually depends on podman for at the point these tests care about:
// creating a listening socket at the path snug's own `system service … unix://
// SOCK` argv names, at a time and with a first-request behaviour the TEST
// controls — never a real engine's, which starts in an uncontrollable 1-2s and
// always answers 200.
//
// It is exec'd as $SNUG_PODMAN (internal/cli/containerpreflight.go's
// preflightPodmanBinary trusts that path outright, never re-resolving it
// through PATH), so it runs with EXACTLY the argv and environment
// internal/engine.Engine.Spec built — "--root", store, "--runroot", runroot,
// "system", "service", "--time", N, "unix://"+sock — inside the engine's own
// derived mount/pid/cgroup namespaces (internal/stage/inengine.go). Finding
// the socket path is therefore "the last argument beginning with unix://",
// never a fixed index: this binary does not need to understand the rest.
//
// Behaviour is read from a sidecar CONFIG FILE next to this binary's own
// path (os.Args[0] + ".cfg"), not from flags: the argv this process is
// exec'd with is entirely engine.Spec's, and this binary has no say in it.
// The test writes that file before each snug invocation, so ONE compiled
// binary — built once — serves every scenario. Two "key=value" lines,
// missing file or missing key defaulting to "no delay, answer 200":
//
//	delay=DURATION   sleep this long before creating the socket, so a caller
//	                 can hold snug's payload parked on --block-fd for a
//	                 controlled window (M4's harness, in-tree).
//	status=CODE      the HTTP status line this process writes on the FIRST
//	                 request of every connection. 200 leaves the connection
//	                 open afterwards, exactly as internal/engine/lifeline.go's
//	                 dialLifeline expects from a real engine's kept-open
//	                 /events stream; anything else closes the connection at
//	                 once, so dialLifeline's own status check fails FAST
//	                 rather than waiting out its own 10s read deadline (M5's
//	                 abort path).
//
// This is not a channel a sandboxed payload could ever reach: the config file
// lives on the HOST, at a path this binary's own argv0 names, never bound
// into any sandbox or engine mount view snug builds.
//
// It prints one line per phase to its OWN stderr — which, across every hop in
// this chain (__inengine's cmd.Stderr = os.Stderr, stage.Config.Stderr =
// P0's own inherited stderr), lands in the same combined output the test
// harness already captures for snug itself. That is a debugging aid only:
// nothing in gate_test.go asserts on these lines, because the point of the
// tests they support is what snug's OWN process tree and screen say, not what
// this stand-in says about itself.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func readConfig() (delay time.Duration, status int) {
	status = 200
	b, err := os.ReadFile(os.Args[0] + ".cfg")
	if err != nil {
		return delay, status
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "delay":
			if d, err := time.ParseDuration(v); err == nil {
				delay = d
			}
		case "status":
			if n, err := strconv.Atoi(v); err == nil {
				status = n
			}
		}
	}
	return delay, status
}

func main() {
	delay, status := readConfig()

	sock := ""
	for _, a := range os.Args[1:] {
		if s, ok := strings.CutPrefix(a, "unix://"); ok {
			sock = s
		}
	}
	if sock == "" {
		fmt.Fprintln(os.Stderr, "fakepodman: no unix:// argument in", os.Args[1:])
		os.Exit(2)
	}

	if delay > 0 {
		fmt.Fprintf(os.Stderr, "fakepodman: delaying %s before creating %s\n", delay, sock)
		time.Sleep(delay)
	}

	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "fakepodman: mkdir:", err)
		os.Exit(2)
	}
	// A stale socket from an earlier, killed run of this same binary would
	// otherwise make Listen fail EADDRINUSE — harmless to remove, since a
	// listening AF_UNIX socket's backing inode has no content of its own.
	_ = os.Remove(sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakepodman: listen:", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "FAKEPODMAN-LISTENING %s status=%d\n", sock, status)

	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", status, http.StatusText(status))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, status, statusLine)
		}
	}()

	// Block forever — a real `system service` stays up until its idle timeout
	// or its process tree dies with the engine's Pdeathsig, and this stands
	// in for exactly that: it is torn down by the SAME mechanism (the
	// engine's Cloneflags carries Pdeathsig: SIGKILL, cascading from the
	// stage), never by exiting on its own.
	select {}
}

func serve(conn net.Conn, status int, statusLine string) {
	defer func() {
		if status != 200 {
			conn.Close()
		}
	}()
	// Read (a bound is enough — the request line and headers dialLifeline
	// sends fit comfortably under it) BEFORE writing or closing. This is not
	// a nicety: closing a socket that still has the PEER's own unread bytes
	// sitting in its receive buffer sends RST rather than a graceful FIN
	// (ordinary POSIX socket behaviour, and it applies to AF_UNIX
	// SOCK_STREAM exactly as it does to TCP) — measured here, by hand,
	// racing snug's own dialLifeline against a version of this function that
	// wrote-then-closed without reading first: dialLifeline's own write of
	// its request occasionally raced the close and came back "broken pipe"
	// instead of the intended "status line said 503", a different, equally
	// legitimate failure but not the one a caller matching on the STATUS
	// TEXT should have to allow for. Reading first removes the race rather
	// than widening what callers must tolerate.
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})

	if _, err := conn.Write([]byte(statusLine)); err != nil {
		return
	}
	if status != 200 {
		// dialLifeline's own open() reads exactly one status line and returns
		// an error the instant it does not contain " 200 " — it never reads
		// again, so there is nothing further to send and closing promptly is
		// what makes the caller's failure fast rather than a 10s read-deadline
		// timeout.
		return
	}
	// 200: hold the connection open and simply discard whatever the caller
	// sends, exactly as a real engine's kept-open /events stream would — the
	// lifeline's own hold() goroutine drains this with io.Copy and never
	// expects a reply.
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
