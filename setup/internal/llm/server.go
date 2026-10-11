package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// FindServer returns the llama-server to run: explicit if non-empty, else the
// first on PATH, else the newest under ~/.cache/snug-setup/llama.cpp/*/*/.
func FindServer(explicit, home string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if p, err := exec.LookPath("llama-server"); err == nil {
		return p, nil
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".cache", "snug-setup", "llama.cpp", "*", "*", "llama-server"))
	if len(matches) > 0 {
		sort.Strings(matches)
		return matches[len(matches)-1], nil
	}
	return "", errors.New("no llama-server found: it is not on PATH and not under ~/.cache/snug-setup/llama.cpp/; pass --llama-server PATH, or --llm-url of a server that is already running")
}

// tail keeps the last bytes written, for error messages.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 4096

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = t.buf[len(t.buf)-tailMax:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(bytes.TrimSpace(t.buf))
}

// Server is a llama-server child bound to 127.0.0.1.
type Server struct {
	URL string

	cmd  *exec.Cmd
	done chan struct{}
	logs *tail
	err  error
}

// FreePort returns a TCP port on 127.0.0.1 that was free a moment ago. The
// server binds it later, so another process can in principle take it first;
// the health wait then fails with the server's own output rather than hanging.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("cannot find a free local port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// StartServer runs bin on model, listening on 127.0.0.1 at a random free port,
// and returns once /health answers 200 or timeout passes. The child gets
// SIGKILL if snug-setup dies (Pdeathsig) and is killed by Close.
//
// Pdeathsig is tied to the OS THREAD that forked the child, not to the process,
// so the goroutine that starts it locks its thread and keeps it until the
// child is reaped; otherwise the Go runtime retiring that thread would kill
// the model server mid-session.
func StartServer(ctx context.Context, bin, model string, timeout time.Duration) (*Server, error) {
	if _, err := os.Stat(model); err != nil {
		return nil, fmt.Errorf("model file %s: %w", model, err)
	}
	port, err := FreePort()
	if err != nil {
		return nil, err
	}
	s := &Server{
		URL:  "http://127.0.0.1:" + strconv.Itoa(port),
		done: make(chan struct{}),
		logs: &tail{},
	}
	s.cmd = exec.Command(bin, "--model", model, "--host", "127.0.0.1", "--port", strconv.Itoa(port), "-c", "4096", "-np", "1")
	s.cmd.Stdout, s.cmd.Stderr = s.logs, s.logs
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}

	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(s.done)
		if err := s.cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		s.err = s.cmd.Wait()
	}()
	if err := <-started; err != nil {
		return nil, fmt.Errorf("cannot start %s: %w", bin, err)
	}
	if err := s.waitHealthy(ctx, timeout); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) waitHealthy(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	hc := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-s.done:
			return fmt.Errorf("llama-server exited before it was ready (%v):\n%s", s.err, s.logs.String())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if resp, err := hc.Get(s.URL + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("llama-server did not become ready within %s:\n%s", timeout, s.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Close kills the server and waits for it to be reaped. It is safe to call
// twice.
func (s *Server) Close() {
	// Process.Kill on our own child is safe even though Wait runs in another
	// goroutine: until Wait returns the child is a zombie that still holds its
	// pid, so the signal cannot reach a stranger.
	_ = s.cmd.Process.Kill()
	<-s.done
}
