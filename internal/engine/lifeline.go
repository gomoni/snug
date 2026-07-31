package engine

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// A lifeline is "die with the sandbox", carried by the SOCKET instead of by the
// process tree.
//
// The problem it solves: Pdeathsig and a process-group kill both assume the
// engine is snug's child. When /usr/bin/podman is a wrapper — distrobox's
// symlink to distrobox-host-exec, which forwards over D-Bus to the real podman
// on the host — snug's child is the shim and the engine is in an unrelated
// process tree. Neither mechanism reaches it, so a hard-killed snug left the
// engine, its pasta and its containers running. Verified, not theorised.
//
// podman already has a mechanism for "my client went away": `system service`
// takes an idle timeout and exits when the session expires. snug's engine used
// `--time 0`, which disables it and turns the engine into exactly the daemon
// this project says it does not run. So instead:
//
//   - the engine is started with a FINITE idle timeout, and
//   - snug holds one streaming request (`GET /events`, which never completes)
//     open for as long as the sandbox lives.
//
// While that request is in flight podman counts the session as active and the
// timeout never fires. The moment snug's process dies — exit, panic, SIGKILL,
// the machine's OOM killer — the kernel closes the socket, the session goes
// idle, and the engine exits by itself within the timeout. No supervision, no
// daemon, and it does not care whether the engine is a child, a grandchild
// through a shim, or on the other side of a D-Bus call.
//
// Verified by execution against podman 5.8.3: with `--time 5` and no
// connection, the service is gone in under 12s; with this stream held open it
// was still up after 25s; within 2s of the holder being SIGKILLed it was gone.
// A bare open connection that never sends a request does NOT hold it — podman
// logs "IdleTracker: StateClosed transition by connection marked un-managed"
// and expires anyway. The request is the point, not the connection.
type lifeline struct {
	sock string

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	done   chan struct{}
}

// eventsRequest is the one request in flight for the life of the sandbox.
// /events is the docker-compat endpoint and streams until the client leaves.
const eventsRequest = "GET /v1.41/events HTTP/1.1\r\nHost: snug\r\nAccept: application/json\r\n\r\n"

// dialLifeline opens the stream and confirms the engine accepted it. A failure
// here is fatal to Start: without the lifeline a hard-killed snug would leave
// the engine running forever, and snug does not silently downgrade a guarantee.
func dialLifeline(sock string) (*lifeline, error) {
	l := &lifeline{sock: sock, done: make(chan struct{})}
	conn, br, err := l.open()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conn = conn
	l.mu.Unlock()
	go l.hold(br)
	return l, nil
}

func (l *lifeline) open() (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("unix", l.sock, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.WriteString(conn, eventsRequest); err != nil {
		conn.Close()
		return nil, nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if !strings.Contains(status, " 200 ") {
		conn.Close()
		return nil, nil, fmt.Errorf("engine refused the keepalive stream: %s", strings.TrimSpace(status))
	}
	// No deadline from here on: the stream is meant to sit open forever.
	_ = conn.SetReadDeadline(time.Time{})
	return conn, br, nil
}

// hold drains the stream and re-establishes it if it breaks. Re-dialling
// matters: a lifeline that quietly stayed down would let the engine idle out
// mid-run and take the sandbox's containers with it.
func (l *lifeline) hold(br *bufio.Reader) {
	defer close(l.done)
	for {
		_, _ = io.Copy(io.Discard, br)

		l.mu.Lock()
		stop := l.closed
		l.mu.Unlock()
		if stop {
			return
		}
		time.Sleep(200 * time.Millisecond)

		conn, next, err := l.open()
		if err != nil {
			// The engine is gone. Nothing to keep alive, and restarting it is
			// not this goroutine's decision.
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			conn.Close()
			return
		}
		l.conn = conn
		l.mu.Unlock()
		br = next
	}
}

// Close drops the stream, which arms the engine's idle timeout.
func (l *lifeline) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	conn := l.conn
	l.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
	}
}
