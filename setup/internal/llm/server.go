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
	return "", errors.New("no llama-server found: it is not on PATH and not under ~/.cache/snug-setup/llama.cpp/; pass --llama-server PATH, give --llm-url of a server that is already running, or use --model FILE.gguf to run the model in-process")
}

// Tail keeps the last bytes written, for error messages. The zero value is
// ready to use.
type Tail struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 4096

func (t *Tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = t.buf[len(t.buf)-tailMax:]
	}
	return len(p), nil
}

func (t *Tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(bytes.TrimSpace(t.buf))
}

// Server is a llama-server child listening on a unix socket. It is a Remote
// whose URL is a placeholder and whose HTTP dials the socket for it, whatever
// host URL names; llama-server turns the request's schema into a grammar, so
// its Caps say constrained.
type Server struct {
	Remote

	dir  string
	cmd  *exec.Cmd
	done chan struct{}
	logs *Tail
	err  error
}

// sunPathMax is the room for a socket path in sockaddr_un on Linux, less its
// terminating NUL.
const sunPathMax = 107

// StartServer runs bin on model, listening on a unix socket in a fresh 0700
// directory, and returns once /health answers 200 or timeout passes. Not a
// 127.0.0.1 port: a port found free and bound later can be taken first by
// another local user, who then receives the prompts, and any local user can
// query a loopback server. The directory's mode keeps both out. The child
// gets SIGKILL if snug-setup dies (Pdeathsig) and is killed by Close, which
// removes the directory.
//
// Pdeathsig is tied to the OS THREAD that forked the child, not to the process,
// so the goroutine that starts it locks its thread and keeps it until the
// child is reaped; otherwise the Go runtime retiring that thread would kill
// the model server mid-session.
func StartServer(ctx context.Context, bin, model string, timeout time.Duration) (*Server, error) {
	if _, err := os.Stat(model); err != nil {
		return nil, fmt.Errorf("model file %s: %w", model, err)
	}
	dir, err := os.MkdirTemp("", "snug-setup-")
	if err != nil {
		return nil, fmt.Errorf("cannot make a directory for the model server's socket: %w", err)
	}
	sock := filepath.Join(dir, "llama.sock")
	if len(sock) > sunPathMax {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("socket path %s is longer than the %d bytes a unix socket address holds; set TMPDIR to a shorter directory", sock, sunPathMax)
	}
	s := &Server{
		Remote: Remote{
			URL: "http://llama-server",
			HTTP: &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sock)
				},
			}},
		},
		dir:  dir,
		done: make(chan struct{}),
		logs: &Tail{},
	}
	// --host takes a unix socket path when it ends in .sock.
	s.cmd = exec.Command(bin, "--model", model, "--host", sock, "-c", "4096", "-np", "1")
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
		os.RemoveAll(dir)
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
	hc := &http.Client{Timeout: 2 * time.Second, Transport: s.HTTP.Transport}
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

// Caps reports a local, constrained backend.
func (s *Server) Caps() Caps {
	return Caps{Constrained: true, Local: true, Where: "llama-server on " + filepath.Join(s.dir, "llama.sock")}
}

// Close kills the server and waits for it to be reaped. It is safe to call
// twice, and never fails: the error is there for Backend.
func (s *Server) Close() error {
	// Process.Kill on our own child is safe even though Wait runs in another
	// goroutine: until Wait returns the child is a zombie that still holds its
	// pid, so the signal cannot reach a stranger.
	_ = s.cmd.Process.Kill()
	<-s.done
	os.RemoveAll(s.dir)
	return nil
}
