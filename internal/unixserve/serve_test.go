package unixserve

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestCloseEndsASilentClient: a client that connects and never writes holds its
// handler in a read with no deadline. Close must end that connection rather
// than wait for it, or snug's teardown hangs for as long as the sandbox
// process keeps the socket open.
func TestCloseEndsASilentClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(ln)
	entered := make(chan struct{})
	go s.Serve(func(c net.Conn) {
		close(entered)
		buf := make([]byte, 1)
		c.Read(buf) // blocks until Close ends the connection
	})
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-entered

	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while a silent client was connected")
	}
}
