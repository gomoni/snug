package dbus

import (
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// hostileBus accepts one connection and runs serve on it.
func hostileBus(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bus")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		serve(c)
	}()
	return "unix:path=" + path
}

// boundedDial dials addr with a 2 s deadline and fails the test if Dial
// succeeds, takes past the deadline plus slack, or grows the heap by more
// than 16 MiB. The red team measured both floods at over 5 GB of RSS and the
// SASL one at 9.6 s against a 5 s bound before the fix.
func boundedDial(t *testing.T, addr, want string) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	c, err := Dial(addr, 1000, start.Add(2*time.Second))
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	if err == nil {
		c.Close()
		t.Fatal("Dial succeeded against a flooding peer")
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q, want it to name %q", err, want)
	}
	if took > 3*time.Second {
		t.Errorf("Dial took %s with a 2s deadline", took)
	}
	if grew := int64(after.TotalAlloc - before.TotalAlloc); grew > 16<<20 {
		t.Errorf("Dial allocated %d MiB against a flooding peer", grew>>20)
	}
}

func TestDialBoundsASASLLineWithNoNewline(t *testing.T) {
	addr := hostileBus(t, func(c net.Conn) {
		buf := make([]byte, 1)
		c.Read(buf)
		junk := []byte(strings.Repeat("A", 64<<10))
		for {
			if _, err := c.Write(junk); err != nil {
				return
			}
		}
	})
	boundedDial(t, addr, "SASL line longer than")
}

func TestCallBoundsSignalsBeforeItsReply(t *testing.T) {
	addr := hostileBus(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.Read(buf)
		c.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
		var e Encoder
		e.String(strings.Repeat("x", 1<<19))
		body, _ := e.Bytes()
		sig := Message{Type: TypeSignal, Serial: 1, Path: "/a", Interface: "b.c", Member: "D", Signature: "s", Body: body}
		b, _ := sig.Marshal()
		for {
			if _, err := c.Write(b); err != nil {
				return
			}
		}
	})
	boundedDial(t, addr, "signals arrived before its reply")
}
