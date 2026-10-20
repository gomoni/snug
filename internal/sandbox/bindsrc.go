package sandbox

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/bwrapinfo"
	"github.com/gomoni/snug/internal/policy"
)

// openat2 is unix.Openat2, a variable only so a test can answer ENOSYS the way
// a kernel older than 5.6 or a seccomp filter around snug does.
var openat2 = unix.Openat2

// ErrGrantRefused marks a launch-time refusal that is a statement about the
// policy and not about the machine: the grant's host path was redirected after
// snug resolved it. The CLI maps it to the policy exit code.
var ErrGrantRefused = errors.New("grant refused")

// openBindSource opens the host side of one KindBind mount for bwrap's
// --ro-bind-fd/--bind-fd. m.Host is canonical (Resolve refuses anything else),
// so a link anywhere on it means something was written after snug resolved it.
//
// RESOLVE_NO_SYMLINKS refuses a link at any component, final one included.
// O_DIRECTORY is absent because grants may be files and sockets; so is
// RESOLVE_NO_XDEV, because a grant may legitimately sit under a mount point.
// The descriptor is O_PATH: it names the inode and grants no access of its own.
//
// ok=false with a nil error means m is Optional and the path is absent, which
// is the -try semantics the path form had: omit the mount.
func openBindSource(m policy.Mount) (f *os.File, ok bool, err error) {
	if m.Host == policy.SelfExeHost {
		return openSelfExe()
	}
	fd, err := openat2(unix.AT_FDCWD, m.Host, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	switch {
	case err == nil:
		return os.NewFile(uintptr(fd), m.Host), true, nil
	case errors.Is(err, unix.ELOOP):
		return nil, false, fmt.Errorf("%w: %s (granted at %s): a component became a symlink after snug "+
			"resolved it; another process with write access to a parent directory (e.g. a "+
			"concurrent sandbox) may be redirecting this grant",
			ErrGrantRefused, policy.VisibleText(m.Host), policy.VisibleText(m.Guest))
	case errors.Is(err, unix.ENOENT) && m.Optional:
		return nil, false, nil
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM):
		return nil, false, fmt.Errorf("snug needs openat2(2) (Linux 5.6+) to open grant sources "+
			"race-free; opening %s (granted at %s) failed: %w — a seccomp filter around snug may "+
			"be blocking it, and there is no fallback to opening by path",
			policy.VisibleText(m.Host), policy.VisibleText(m.Guest), err)
	default:
		return nil, false, fmt.Errorf("opening the grant source %s (granted at %s): %w",
			policy.VisibleText(m.Host), policy.VisibleText(m.Guest), err)
	}
}

// openSelfExe opens the executable this snug is running, for
// policy.WrapperGuest. A plain open FOLLOWS the magic link, which is the point:
// openat2's RESOLVE_NO_SYMLINKS would refuse it with ELOOP, and nothing can
// write /proc/self/exe, so the swap that rule closes does not exist here. Every
// bind source is opened in the snug the user ran, before either topology
// forks, so this is that image in both.
//
// An image replaced or removed on disk since this snug started (an upgrade) has
// no links left, and bwrap refuses to bind it with "Can't find source path
// /proc/self/fd/N". Refused here instead, with the cause.
func openSelfExe() (*os.File, bool, error) {
	fd, err := unix.Open(policy.SelfExeHost, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, fmt.Errorf("opening snug's own executable for %s: %w", policy.WrapperGuest, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, false, fmt.Errorf("stat of snug's own executable: %w", err)
	}
	if st.Nlink == 0 {
		unix.Close(fd)
		return nil, false, fmt.Errorf("snug's own executable was replaced or removed on disk after this " +
			"snug started (an upgrade in progress?), and bwrap cannot bind a deleted file for " +
			policy.WrapperGuest + "; run snug again")
	}
	return os.NewFile(uintptr(fd), policy.SelfExeHost), true, nil
}

var (
	bindFDOnce sync.Once
	bindFDErr  error
)

// requireBindFD runs bwrapinfo.RequireBindFD once per process: every Run in
// one process resolves the same bwrap.
func requireBindFD(bwrap string) error {
	bindFDOnce.Do(func() { bindFDErr = bwrapinfo.RequireBindFD(bwrap) })
	return bindFDErr
}

// openBindSources opens every policy.BindSources entry and appends the files to
// *extra, returning the guest -> child descriptor number map for FDs.Bind. The
// numbers follow the 3+index rule exec.Cmd applies to ExtraFiles, so the caller
// passes the next free number as base and the files in extra are appended in
// that order. Optional mounts whose source is absent get no entry.
//
// Callers own closing *extra; a descriptor is appended before the next open can
// fail, so an error return leaves nothing leaked.
func openBindSources(p *policy.Policy, extra *[]*os.File, base func() int) (map[string]int, error) {
	fds := map[string]int{}
	for _, m := range p.BindSources() {
		f, ok, err := openBindSource(m)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		fds[m.Guest] = base()
		*extra = append(*extra, f)
	}
	return fds, nil
}
