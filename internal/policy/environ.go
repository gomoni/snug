package policy

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Environ is every host lookup the resolver needs. It exists so that Resolve is
// a pure function of its inputs: tests inject a fake host layout and assert on
// the result without touching the real filesystem or needing privileges.
type Environ interface {
	// EvalSymlinks canonicalises a host path. Grants are canonicalised at
	// resolve time so a symlink planted later inside the writable project
	// cannot widen one.
	EvalSymlinks(path string) (string, error)
	Stat(path string) (fs.FileInfo, error)
	Getenv(key string) string

	// LookupEnv distinguishes SET-BUT-EMPTY from UNSET, which Getenv cannot.
	//
	// That difference is not pedantry. NO_COLOR's specification is "set to any
	// value, INCLUDING empty", so `NO_COLOR=` means disable colour — and a
	// resolver that reads the host with `v != ""` silently re-enables it. The
	// same collapse is wrong for every flag-shaped variable (§3.2), and it is
	// the difference between a variable reaching the sandbox and not reaching
	// it at all.
	LookupEnv(key string) (string, bool)

	Uid() int
	Gid() int
}

// OSEnviron is the real host.
type OSEnviron struct{}

func (OSEnviron) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }
func (OSEnviron) Stat(p string) (fs.FileInfo, error)    { return os.Stat(p) }
func (OSEnviron) Getenv(k string) string                { return os.Getenv(k) }
func (OSEnviron) LookupEnv(k string) (string, bool)     { return os.LookupEnv(k) }
func (OSEnviron) Uid() int                              { return os.Getuid() }
func (OSEnviron) Gid() int                              { return os.Getgid() }

// Context is the per-invocation input to resolution: what the human asked for,
// plus the host facts the variables expand against.
type Context struct {
	Target  string // the directory the sandbox is for, as given
	Home    string
	Shell   string
	Term    string
	Lang    string
	TZ      string
	Command []string

	// HostNameservers is the host's /etc/resolv.conf nameserver list, read by the
	// caller. Resolve keeps only the routable ones; see NetPolicy.ResolvConf.
	HostNameservers []string

	// KnownHosts is the subset of the host's known_hosts for the pinned host,
	// filtered by the caller. Binding the whole file would tell the sandbox
	// every host you have ever connected to.
	KnownHosts []byte

	// HostTmpDir backs the {host_tmpdir} variable used by the tmp-shared
	// profile. The caller allocates and safety-checks it, because creating
	// directories is not something a pure resolver may do.
	HostTmpDir string

	// LegacyTIOCSTI reports whether this kernel still allows the TIOCSTI ioctl,
	// read from /proc/sys/dev/tty/legacy_tiocsti. When it does, a process in the
	// sandbox could push characters into the terminal that launched snug, and we
	// pay for --new-session (losing job control) to stop it. Modern kernels
	// default this off, so most hosts get working job control for free.
	//
	// It lives in Context rather than being read inside Resolve so that argv
	// generation stays a pure function and the golden tests stay deterministic.
	LegacyTIOCSTI bool

	// HostShims records commands snug looked up on PATH that resolve to a
	// host-escape helper (distrobox-host-exec, host-spawn, flatpak-spawn)
	// rather than the genuine binary — detected by cmd/snug via
	// exec.LookPath + filepath.EvalSymlinks. When podman is one of these AND
	// a podman profile is selected, Resolve stages a dispatcher stub ahead of
	// it on PATH (see podmanstub.go and CONTAINER-CLIENT.md §8) rather than
	// leaving a binary that fails with a message naming neither cause.
	//
	// It lives in Context, exactly like LegacyTIOCSTI and for the same
	// reason: the lookup is impure (PATH search, symlink resolution), and
	// Resolve must stay a pure function of its inputs so the golden tests
	// stay deterministic.
	HostShims []HostShim
}

// HostShim is one command snug found on PATH that resolves to a host-escape
// helper rather than a genuine binary. The trigger is resolving to one of a
// short, named list of helpers — NOT "is a symlink": ordinary symlinks
// (/bin -> usr/bin, vi -> vim) are common and harmless, while a host-escape
// helper cannot work from inside a sandbox at all (it forwards to a socket
// or bus the sandbox correctly cannot see).
//
// Detection is impure and lives in cmd/snug (exec.LookPath +
// filepath.EvalSymlinks); this is the value it carries into Context so
// Resolve can stay pure. See CONTAINER-CLIENT.md §8.
type HostShim struct {
	Name     string // the command snug looked up, e.g. "podman"
	Path     string // exec.LookPath's answer
	Resolved string // Path after filepath.EvalSymlinks
}
