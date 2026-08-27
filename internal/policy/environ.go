package policy

import (
	"io/fs"
	"os"
	"os/exec"
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

	// LookPath resolves a bare command name against $PATH the way the host
	// shell would, so a PATH search is as injectable as every other host fact
	// this interface carries — see OSEnviron.LookPath and exec.LookPath for
	// what "the way the host shell would" means precisely.
	LookPath(file string) (string, error)

	Uid() int
	Gid() int
}

// OSEnviron is the real host.
type OSEnviron struct{}

func (OSEnviron) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }
func (OSEnviron) Stat(p string) (fs.FileInfo, error)    { return os.Stat(p) }
func (OSEnviron) Getenv(k string) string                { return os.Getenv(k) }
func (OSEnviron) LookupEnv(k string) (string, bool)     { return os.LookupEnv(k) }
func (OSEnviron) LookPath(f string) (string, error)     { return exec.LookPath(f) }
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

	// TmpfsSizeBytes is the caller's preference, in bytes, from
	// tmpfs_size_mib in ~/.config/snug/config.toml. 0 means the caller
	// expressed none, and Resolve substitutes DefaultTmpfsSize.
	TmpfsSizeBytes uint64

	// ProfileDirs are the directories the trusted profile set was READ from,
	// passed in rather than derived here so profile.ConfigDirs stays the single
	// author of that path — a resolver recomputing it would be a second copy
	// that drifts. Resolve refuses a writable grant covering any of them:
	// invariant 3 says the trusted profile set comes from outside the sandboxed
	// material, and a payload that can write a profile grants itself
	// permissions for the NEXT run. Empty disables the check, which is what a
	// unit test wanting to resolve without a host profile store gets.
	ProfileDirs []string

	// HostNameservers is the host's /etc/resolv.conf nameserver list, read by the
	// caller. Resolve keeps only the routable ones; see NetPolicy.ResolvConf.
	HostNameservers []string

	// HostGit is the whitelisted subset of the host's RESOLVED git config,
	// extracted by the caller because reading files is not the resolver's job.
	// Only keys in GitKeyWhitelist ever appear here; nothing in it names a
	// program, a file or a credential. Empty unless a profile asks for
	// `git = "extract"`.
	HostGit GitValues

	// HostSSHConfigs are the system-wide ssh_config paths this host's ssh
	// actually reads, discovered by the caller by asking ssh itself
	// (`ssh -G -v`, whose debug output names every file in the chain) rather
	// than by snug guessing spellings. It is ADDITIVE to
	// SystemSSHConfigPaths, never a replacement for it: a host with no ssh
	// binary, a probe that times out, or output in a shape the parser does
	// not recognise all leave this empty and the fixed list is what remains
	// (issue #42).
	//
	// Reading it is impure — it runs a host binary — so it lives here for the
	// same reason HostGit and HostShims do, and Resolve stays a pure function
	// of its inputs.
	//
	// Every entry is re-checked by systemSSHConfigCandidates before it can
	// author anything: absolute, clean, named ssh_config, and not under Home.
	// The caller filters too. That is deliberate belt-and-braces, exactly as
	// GitConfigFrom re-drops control characters the extractor already dropped
	// — this is the last place a path from a host file can be stopped before
	// it becomes a mount.
	HostSSHConfigs []string

	// HostSSHConfig is the whitelisted subset of this host's RESOLVED
	// system-wide ssh configuration — algorithm lists and RequiredRSASize,
	// nothing that names a program, a file or a socket — extracted by the
	// caller with `ssh -G` because running a host binary is not the
	// resolver's job. Only keys in SSHKeyWhitelist ever appear here, and only
	// where the host's value DIFFERS from OpenSSH's compiled-in default.
	//
	// Empty is the ordinary case and costs nothing: the generated file then
	// carries no directives and the sandbox's ssh uses the same compiled-in
	// defaults the host's does (issue #43).
	HostSSHConfig SSHValues

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
	// rather than the genuine binary — detected by internal/cli via
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
// Detection is impure and lives in internal/cli (exec.LookPath +
// filepath.EvalSymlinks); this is the value it carries into Context so
// Resolve can stay pure. See CONTAINER-CLIENT.md §8.
type HostShim struct {
	Name     string // the command snug looked up, e.g. "podman"
	Path     string // exec.LookPath's answer
	Resolved string // Path after filepath.EvalSymlinks
}
