package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// runtimeDir is a private per-run directory for sockets: the ssh-agent
// proxy's and the container proxy's. Both are named things a same-uid
// process reaching them can use as a signing oracle or a container-creation
// oracle, so the directory holding them has to resist being redirected
// before snug gets there, not just after.
//
// Two guards, both load-bearing (issue #61 part (c), which promoted this
// from #31's low-severity list once it became the prerequisite for `snug
// attach`):
//
//   - Every directory this function creates or reuses — the shared "snug"
//     directory and this run's own subdirectory — is opened with
//     openat2(RESOLVE_NO_SYMLINKS), which refuses a symlink ANYWHERE in the
//     resolution rather than checking the final component and racing the
//     kernel to it. os.MkdirAll, what this function used to call, has
//     neither property: it follows a pre-planted symlink-to-directory and
//     never inspects an existing directory's owner or mode at all.
//   - Every directory this function touches — even one it just created,
//     because a hostile umask can weaken the mode Mkdirat asked for — has
//     its owner and mode checked afterwards, and a mismatch is refused
//     rather than repaired. Invariant 5: a chmod here would be a silent
//     downgrade of whatever guarantee the wrong mode already broke.
//
// The fallback when $XDG_RUNTIME_DIR is unset changes shape along with this
// fix: it used to be the fixed name "snug" directly under os.TempDir(),
// which is commonly /tmp — world-writable, so any user on a shared host
// could pre-create that exact path before the real owner's first run and
// would then own every socket placed under it. The directory name is now
// uid-scoped ("snug-<uid>"), so a squatter cannot pass the ownership check
// even if they win the race to create it first.
//
// On its way in, runtimeDir also sweeps run-* directories left behind by a
// run that ended abnormally (issue #85): SIGKILL cannot be caught, so
// nothing this process does on the way OUT can remove its own directory,
// and self-healing on the way IN is the only shape that reaches that case.
// See sweepStaleRunDirs for how a directory is told apart from a live run
// rather than merely an old one.
func runtimeDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	snugName := "snug"
	if base == "" {
		// os.TempDir() is frequently mode 1777 (world-writable, sticky)
		// rather than private to us, and it is provided by the OS the same
		// way $XDG_RUNTIME_DIR is — this function does not own it and does
		// not second-guess its mode. What it owns, and therefore verifies,
		// starts one level down: the "snug"/"snug-<uid>" directory and
		// everything under it.
		base = os.TempDir()
		snugName = fmt.Sprintf("snug-%d", os.Getuid())
	}

	// The base directory itself ($XDG_RUNTIME_DIR or os.TempDir()) is not
	// ours to own or to police the mode of — it is handed to every process
	// on the host the same way. It still gets the symlink refusal: a
	// symlinked XDG_RUNTIME_DIR would be bizarre, but refusing to resolve
	// through it costs nothing and openat2 is already in hand.
	rootFd, err := openNoFollow(unix.AT_FDCWD, base)
	if err != nil {
		return "", fmt.Errorf("runtime directory: opening %s: %w", base, describeOpenErr(err, base))
	}
	defer unix.Close(rootFd)

	snugFd, created, err := secureSubdir(rootFd, base, snugName)
	if err != nil {
		return "", fmt.Errorf("runtime directory: %w", err)
	}
	defer unix.Close(snugFd)
	snugPath := filepath.Join(base, snugName)

	if !created {
		// A freshly-created directory has nothing in it; sweeping one is a
		// correct no-op, so this is an optimisation, not a correctness call.
		sweepStaleRunDirs(snugPath)
	}

	pid := os.Getpid()
	start, err := pidStartTime(pid)
	if err != nil {
		return "", fmt.Errorf("runtime directory: reading this process's own start time "+
			"out of /proc/%d/stat: %w (this is how a stale run-* directory left by an "+
			"earlier process that reused this pid gets told apart from this run)", pid, err)
	}
	runName := runDirName(pid, start)

	runFd, _, err := secureSubdir(snugFd, snugPath, runName)
	if err != nil {
		return "", fmt.Errorf("runtime directory: %w", err)
	}
	unix.Close(runFd)

	return filepath.Join(snugPath, runName), nil
}

// runDirName encodes both the pid and its start time, not the pid alone. A
// pid is reused across the lifetime of a long-running host, and the sweep in
// sweepStaleRunDirs needs to tell "this pid is still the same process" apart
// from "this pid was recycled by something else" — which a bare run-<pid>
// name cannot express. Field 22 of /proc/<pid>/stat (start time in clock
// ticks since boot) is what the kernel itself effectively uses for exactly
// this distinction.
func runDirName(pid int, startTime uint64) string {
	return fmt.Sprintf("run-%d-%d", pid, startTime)
}

// parseRunDirName is runDirName's inverse, used only by the sweep.
func parseRunDirName(name string) (pid int, startTime uint64, ok bool) {
	rest, ok := strings.CutPrefix(name, "run-")
	if !ok {
		return 0, 0, false
	}
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	p, err := strconv.Atoi(parts[0])
	if err != nil || p <= 0 {
		return 0, 0, false
	}
	s, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return p, s, true
}

// sweepStaleRunDirs removes run-* directories whose owning process is gone —
// invariant 4 says helpers "leave nothing behind", and that was false the
// moment a run ended in a SIGKILL rather than a clean exit: nothing that
// process does on its way out can run, so the only place left to remove its
// directory is the next run's way in (issue #85).
//
// A directory is swept only when /proc/<pid> either does not exist, or
// exists but belongs to a DIFFERENT process than the one that made the
// directory — the pid was reused, field 22 of /proc/<pid>/stat has
// therefore changed, and the entry names a process that is not the one
// running now. An mtime check cannot make this distinction (an old but
// genuinely still-running sandbox is legitimate and must not be swept),
// which is why the directory name carries the start time instead of relying
// on age.
//
// This reads snugPath by NAME rather than through the fd runtimeDir already
// holds open. That is a narrower guarantee than the fd-based creation path
// above: by this point the "snug" directory's existence and ownership have
// already been verified, its identity cannot be redirected by anything other
// than the same uid this process runs as, and same-uid tampering is outside
// what this guard — or #61's threat notes — cover.
//
// Errors reading an individual entry are not fatal to the run — a directory
// this function cannot classify is left alone rather than guessed at, since
// leaving one extra stale directory costs nothing and removing a live one
// would not.
func sweepStaleRunDirs(snugPath string) {
	entries, err := os.ReadDir(snugPath)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, start, ok := parseRunDirName(e.Name())
		if !ok {
			continue
		}
		if pid == os.Getpid() {
			// Can never be stale: it would name the process running this
			// sweep, which by definition still exists.
			continue
		}
		if live, err := pidStartTime(pid); err == nil && live == start {
			continue // a genuinely still-running sandbox; not this function's business
		}
		full := filepath.Join(snugPath, e.Name())
		if rmErr := os.RemoveAll(full); rmErr != nil {
			fmt.Fprintf(os.Stderr, "snug: could not remove stale run directory %s: %v\n", full, rmErr)
			continue
		}
		fmt.Fprintf(os.Stderr, "snug: removed stale run directory %s (pid %d is gone; "+
			"left behind by a run that did not exit cleanly)\n", full, pid)
	}
}

// pidStartTime returns field 22 of /proc/<pid>/stat, in clock ticks since
// boot. comm (field 2) is parenthesized and may itself contain spaces and
// close-parens, so fields are only reliably counted starting after its own
// closing paren — the same hazard test/integration/stage_test.go documents
// for the same file.
func pidStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 || i+2 > len(data) {
		return 0, fmt.Errorf("unexpected /proc/%d/stat contents", pid)
	}
	fields := strings.Fields(string(data[i+2:]))
	// state is field 3, so the first entry above is field 3, and starttime
	// (field 22) is nineteen further along.
	const starttimeOffset = 22 - 3
	if len(fields) <= starttimeOffset {
		return 0, fmt.Errorf("unexpected /proc/%d/stat contents: too few fields after comm", pid)
	}
	return strconv.ParseUint(fields[starttimeOffset], 10, 64)
}

// openNoFollow opens an existing directory, refusing to resolve through a
// symlink anywhere along the way.
//
// RESOLVE_NO_SYMLINKS covers the trailing component as well as every
// intermediate one, so O_NOFOLLOW would be redundant — and worse than
// redundant: O_NOFOLLOW combined with O_DIRECTORY reports a symlink as
// ENOTDIR rather than ELOOP, which is the same refusal wearing an error
// that says "not a directory" instead of "somebody planted a symlink
// here". The guard held either way; the message did not, and the message is
// the half a human acts on. Measured — the two symlink tests failed on the
// errno alone, with the directory correctly refused in both.
func openNoFollow(dirFd int, path string) (int, error) {
	how := unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	return unix.Openat2(dirFd, path, &how)
}

// secureSubdir opens (creating it if absent) a directory named `name` inside
// the already-verified directory `parentFd`. It never trusts an existing
// entry: found means checked, and — per invariant 5 — a check that fails is
// refused rather than repaired.
//
// parentDesc is the human-readable path to parentFd, used only in messages —
// secureSubdir itself never resolves a path STRING for anything but display,
// precisely so nothing it does can be redirected by a symlink planted after
// parentFd was opened.
func secureSubdir(parentFd int, parentDesc, name string) (fd int, created bool, err error) {
	mkErr := unix.Mkdirat(parentFd, name, 0o700)
	created = mkErr == nil
	if mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
		return -1, false, fmt.Errorf("creating %s: %w", filepath.Join(parentDesc, name), mkErr)
	}

	full := filepath.Join(parentDesc, name)
	fd, err = openNoFollow(parentFd, name)
	if err != nil {
		return -1, false, fmt.Errorf("opening %s: %w", full, describeOpenErr(err, full))
	}

	if verr := verifyOwnedAndPrivate(fd, full); verr != nil {
		unix.Close(fd)
		return -1, false, verr
	}
	return fd, created, nil
}

// verifyOwnedAndPrivate refuses a directory that is not ours, or that is
// readable, writable or searchable by anyone else — the two properties that
// make it safe to place a unix socket inside without asking who else could
// already be watching that path.
func verifyOwnedAndPrivate(fd int, desc string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("checking %s: %w", desc, err)
	}
	if uid := int(st.Uid); uid != os.Getuid() {
		return fmt.Errorf("refusing %s: owned by uid %d, not you (uid %d) — "+
			"something else on this host created it; remove it by hand if you are sure "+
			"it is not in use — snug will not use a directory it does not own for sockets",
			desc, uid, os.Getuid())
	}
	if mode := st.Mode & 0o777; mode != 0o700 {
		return fmt.Errorf("refusing %s: mode is %#o, must be exactly 0700 — "+
			"check the umask that created it and fix the permissions by hand; "+
			"snug will not repair it silently", desc, mode)
	}
	return nil
}

// describeOpenErr turns ENOSYS and ELOOP from openNoFollow into a message
// that names the fix rather than the errno. ENOSYS means the kernel predates
// openat2 (Linux 5.6); there is no fallback, because the fallback IS the bug
// this function exists to close — a path lookup with no defence against a
// symlink planted in the middle of it. ELOOP means openat2 refused exactly
// that: a symlink somewhere in the resolution.
func describeOpenErr(err error, path string) error {
	switch {
	case errors.Is(err, unix.ENOSYS):
		return fmt.Errorf("this kernel has no openat2(2), which needs Linux 5.6 or newer. "+
			"snug refuses to fall back to an unguarded path lookup for a directory that will "+
			"hold live sockets — upgrade the kernel, or point XDG_RUNTIME_DIR at a host that "+
			"can run this (original error: %w)", err)
	case errors.Is(err, unix.ELOOP):
		return fmt.Errorf("%s is a symlink, or resolves through one somewhere along its "+
			"path — refusing to follow it. Something on this host planted it before snug "+
			"got here; remove it by hand and re-run snug", path)
	case errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%s exists but is not a directory — refusing to use it. Remove "+
			"it by hand and re-run snug", path)
	default:
		return err
	}
}
