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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gomoni/snug/setup/internal/safe"
)

// ServerBin is a llama-server FindServer chose. Cached marks the one snug-setup
// fetched itself: StartServer checks it against the manifest and runs a copy.
type ServerBin struct {
	Path   string
	Cached bool
}

// FindServer returns the llama-server to run: explicit if non-empty, else the
// first on PATH, else exactly
// ~/.cache/snug-setup/llama.cpp/<PinnedTag>/llama-<PinnedTag>/llama-server,
// which scripts/fetch-llama-server.sh unpacks. No other directory under
// llama.cpp is looked at: nothing is globbed or sorted, so a directory planted
// beside the pinned one cannot win.
//
// explicit and a PATH hit are the user's own choice and are run as they are,
// unchecked. Only the cache candidate, a path anyone with write access to the
// cache could have filled, is Cached and gets verified.
func FindServer(explicit, home string) (ServerBin, error) {
	if explicit != "" {
		return ServerBin{Path: explicit}, nil
	}
	if p, err := exec.LookPath("llama-server"); err == nil {
		return ServerBin{Path: p}, nil
	}
	p := filepath.Join(home, ".cache", "snug-setup", "llama.cpp", PinnedTag, "llama-"+PinnedTag, "llama-server")
	if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
		return ServerBin{Path: p, Cached: true}, nil
	}
	return ServerBin{}, errors.New("no llama-server found: it is not on PATH and not at ~/.cache/snug-setup/llama.cpp/" + PinnedTag + "/llama-" + PinnedTag + "/llama-server. Run scripts/fetch-llama-server.sh from the snug repository (it downloads the release snug-setup is tested against, checks its sha256 and unpacks it there), install llama.cpp yourself and put llama-server on PATH, pass --llama-server PATH, or give --openai-url of a server that is already running")
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

// StartServer runs sb on model, listening on a unix socket in a fresh 0700
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
//
// A Cached sb is not run where it lies: its files are copied into the same
// private directory, hashed on the way against the manifest embedded from
// llama-server.manifest, and the copy is run, so the cache can change after the
// check without effect. Any other sb is run as given.
func StartServer(ctx context.Context, sb ServerBin, model string, timeout time.Duration) (*Server, error) {
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
	bin := sb.Path
	if sb.Cached {
		m, err := parseManifest(pinnedManifest)
		if err == nil && m.tag != PinnedTag {
			err = fmt.Errorf("llama-server.manifest is for %s, snug-setup for %s", m.tag, PinnedTag)
		}
		if err == nil {
			staged := filepath.Join(dir, "llama-server.d")
			if err = os.Mkdir(staged, 0o700); err == nil {
				err = m.stage(filepath.Dir(sb.Path), staged)
			}
			bin = filepath.Join(staged, "llama-server")
		}
		if err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("not running the llama-server under ~/.cache/snug-setup: %w", err)
		}
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
			return fmt.Errorf("llama-server exited before it was ready (%v):\n%s", s.err, logTail(s.logs.String()))
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
			return fmt.Errorf("llama-server did not become ready within %s:\n%s", timeout, logTail(s.logs.String()))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

const (
	logTailLines = 20
	logLineRunes = 300
)

// logTail renders what llama-server printed for an error message. The model
// file is untrusted input that llama.cpp echoes, so each line goes through
// safe.Inline and is indented: a newline from the log can then never start a
// line that reads as one of snug-setup's. Only the last logTailLines lines of
// at most logLineRunes runes are kept.
func logTail(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r", "\n"), "\n")
	if len(lines) > logTailLines {
		lines = lines[len(lines)-logTailLines:]
	}
	var b strings.Builder
	for _, l := range lines {
		l = safe.Inline(l)
		if r := []rune(l); len(r) > logLineRunes {
			l = string(r[:logLineRunes]) + "..."
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		b.WriteString("    | " + l + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
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
