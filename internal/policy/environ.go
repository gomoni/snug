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
	Uid() int
	Gid() int
}

// OSEnviron is the real host.
type OSEnviron struct{}

func (OSEnviron) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }
func (OSEnviron) Stat(p string) (fs.FileInfo, error)    { return os.Stat(p) }
func (OSEnviron) Getenv(k string) string                { return os.Getenv(k) }
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

	// PinnedPubKey is the public half of the identity's ssh key, read by the
	// caller so the resolver stays pure.
	PinnedPubKey []byte

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
}
