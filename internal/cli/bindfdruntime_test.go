package cli

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// TestBindSocketWorksUnderASymlinkedXDGRuntimeDir fails if the socket snug
// binds by descriptor is spelled through $XDG_RUNTIME_DIR as the user wrote it:
// the launcher opens every grant with RESOLVE_NO_SYMLINKS, so a runtime
// directory reached through a link (a /run -> /var/run host) would refuse
// every run that has an agent proxy or a container socket. The control is the
// uncanonicalised spelling of the same socket, which really is refused with
// ELOOP; without it "the canonical path opens" would be equally true of a
// fixture with no link in it.
//
// It checks the open with openat2 directly rather than through
// internal/sandbox, whose opener is unexported; the flags are the opener's.
func TestBindSocketWorksUnderASymlinkedXDGRuntimeDir(t *testing.T) {
	real := shortTempDir(t)
	linkParent := shortTempDir(t)
	link := filepath.Join(linkParent, "run")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", link)

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	sock, err := rt.Socket("agent.sock")
	if err != nil {
		t.Fatal(err)
	}
	planned, err := plannedSocket("agent.sock")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(rt.Path(), "agent.sock"); planned != want {
		t.Errorf("plannedSocket (what --dry-run shows) = %q, openRuntimeDir spells it %q", planned, want)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("control: cannot listen at %s: %v", sock, err)
	}
	defer ln.Close()

	p := &policy.Policy{Mounts: map[string]policy.Mount{}}
	p.BindSocket(sock, policy.AgentSocketGuest, "(identity)")
	sources := p.BindSources()
	if len(sources) != 1 || sources[0].Host != sock {
		t.Fatalf("BindSources = %+v, want the socket", sources)
	}

	open := func(path string) error {
		fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
			Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
		if err == nil {
			unix.Close(fd)
		}
		return err
	}
	if err := open(sock); err != nil {
		t.Errorf("the canonical socket path %s was refused: %v", sock, err)
	}
	asWritten := filepath.Join(link, "snug", filepath.Base(rt.Path()), "agent.sock")
	if _, err := os.Stat(asWritten); err != nil {
		t.Fatalf("control: the uncanonical spelling %s does not reach the socket: %v", asWritten, err)
	}
	if err := open(asWritten); !errors.Is(err, unix.ELOOP) {
		t.Errorf("control: the spelling through the link opened with err=%v, want ELOOP", err)
	}
}

// TestCLIGoldensHaveNoPathBindOutsideProc is the sweep of internal/policy's
// golden files over the ones this package pins: a path-form bind in a --dry-run
// golden is a grant bwrap opens itself, later, following whatever a concurrent
// sandbox renamed into place. The control is that the same files do contain
// descriptor binds, so an empty or renamed glob cannot pass.
func TestCLIGoldensHaveNoPathBindOutsideProc(t *testing.T) {
	// bwrap-note.*.txt are excluded: they render a hand-written argv through the
	// note, so a path-form bind in them is the fixture's input, not snug's output.
	files, err := filepath.Glob(filepath.Join("testdata", "bwrap.*.txt"))
	more, _ := filepath.Glob(filepath.Join("testdata", "*.bwrap.txt"))
	files = append(files, more...)
	if err != nil || len(files) == 0 {
		t.Fatalf("control: no bwrap golden files found (%v)", err)
	}
	pathFlags := []string{"--bind", "--bind-try", "--ro-bind", "--ro-bind-try", "--dev-bind", "--dev-bind-try"}
	fdBinds := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			if fields[0] == "--bind-fd" || fields[0] == "--ro-bind-fd" {
				fdBinds++
			}
			if slices.Contains(pathFlags, fields[0]) && !policy.BindByPath(fields[1]) {
				t.Errorf("%s:%d: path-form bind outside /proc: %s", f, n+1, line)
			}
		}
	}
	if fdBinds == 0 {
		t.Error("control: no descriptor binds in any golden, so the sweep above measured nothing")
	}
}
