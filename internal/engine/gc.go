package engine

// gc.go is issue #308's removal primitive: the low-level operations
// `snug engine gc` (internal/cli/enginegc.go) drives. Liveness — the
// question of whether a store is safe to touch at all — is NOT this file's
// job and nothing here knows what a lock is; internal/cli owns
// targetLockBase and the run-state identity check, and calls into this file
// only once it has already decided a key is not live.
//
// # Why removal is two-phase, measured against a real busybox store
//
// Removing the layer directory but leaving podman's inventory intact: the
// engine still LISTS the image and a re-pull FAILS ("Stat …/vfs/dir/…: no
// such file or directory") — and does not repair it. Removing the inventory
// but leaving the layer data: the engine warns "Top layer … not found in
// layer tree", lists nothing, and the bytes stay on disk with no record of
// them at all — an invisible leak, #308 making its own problem worse. A
// store that is wholly ABSENT is clean and re-initialises normally. So a
// store must go from "wholly present" to "wholly absent" in one step, not
// two: phase 1 is a single renameat moving the whole key directory to a
// name nothing else looks up; phase 2 is the (possibly slow) recursive
// delete of whatever phase 1 disconnected. From the engine's point of view —
// anything that might look the key up again — there is no window where the
// store is PARTIALLY there.
//
// # Why the recursive delete needs its own walk, measured against overlayfs
//
// os.RemoveAll on a real overlayfs work/work directory (mode 0000, non-empty,
// owned by the caller's own uid) fails outright: "permission denied", whole
// tree left. openat(2) on that directory, even confined through an already-
// opened parent descriptor, returns EACCES — a descriptor buys nothing here,
// because the kernel gate is the target's OWN mode, checked at open time,
// not anything about how it was reached. unlinkat(parentfd, "work",
// AT_REMOVEDIR) on the EMPTY directory succeeds; on the non-empty one it is
// ENOTEMPTY. chmod 0700 (which only needs OWNERSHIP, not the current mode)
// then lets it open, and only then can its contents be listed and removed.
// Purge below does exactly that ordering — rmdir first, chmod only the
// directories that actually block it — because chmod -R would additionally
// rewrite the mode of every FILE in the tree for no reason: the walk already
// proves only directories can block a removal this way.
//
// EACCES and EPERM are kept apart everywhere in this file, in code and in
// messages, because they mean opposite fixes. EACCES from unlinkat/openat on
// something OWNED means a mode this process itself can repair — chmod, then
// retry. EPERM from a chmod means the target belongs to someone else — no
// retry, no repair, refuse and name the uid. Measured against a directory
// planted with a foreign uid: chmod -> EPERM, unlink of a child -> EACCES,
// rmdir -> EACCES, `rm -rf` exits 1 with the subtree left, `mv` aside
// succeeds (rename needs only WRITE+EXEC on the parent). Confusing the two
// turns "refuse and name the uid" into a retry loop against a directory that
// will never open.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/vdir"
)

// leftoverPrefix names a directory phase 2 stopped on partway through, under
// engines/ — renamed aside by phase 1, never renamed back. Its own doc
// comment on ListEngineEntries says what makes it self-describing.
const leftoverPrefix = ".gc-"

// storeKeyPattern is exactly what internal/targetkey.Hash produces: a full,
// lowercase hex sha256 digest, 64 characters. Used to tell an engine store's
// own directory apart from a leftover (leftoverPrefix) or from something
// under engines/ that snug's own naming never produced and is therefore left
// alone rather than guessed at.
var storeKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StoreKey reports whether s is shaped like an engine store key — the same
// shape KeyForTarget produces. Used to validate a key a human names on the
// `snug engine gc` command line before this package tries to open anything
// by that name.
func StoreKey(s string) bool { return storeKeyPattern.MatchString(s) }

// EnginesRoot opens $XDG_DATA_HOME/snug/engines for a caller that means to
// LIST or REMOVE stores rather than create one — `snug engine gc`. Nothing
// here is ever created: ok=false with a nil error means there is nothing to
// garbage collect (a fresh machine, or one that has never started a
// container profile), which is not a fault and must not become one — a GC
// command that fails on a machine that never needed one would be its own
// small violation of invariant 5's "no silent downgrade" read backwards.
//
// It walks through the same two names verifyEngineStore's SecureSubdir walk
// creates — "snug" then "engines" — refusing a symlink or a foreign owner at
// either exactly as hard, through vdir.OpenExistingSubdir, which is
// SecureSubdir without the Mkdir: it is exactly as strict and creates
// nothing.
func EnginesRoot() (root *os.Root, path string, ok bool, err error) {
	dataHome, err := dataHomeDir()
	if err != nil {
		return nil, "", false, err
	}
	base, err := os.OpenRoot(dataHome)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("engine gc: opening %s: %w", dataHome, err)
	}
	defer base.Close()

	snug, err := vdir.OpenExistingSubdir(base, dataHome, "snug")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("engine gc: %w", err)
	}
	defer snug.Close()
	snugPath := filepath.Join(dataHome, "snug")

	engines, err := vdir.OpenExistingSubdir(snug, snugPath, "engines")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("engine gc: %w", err)
	}
	enginesPath := filepath.Join(snugPath, "engines")
	return engines, enginesPath, true, nil
}

// EngineEntry is one directory GC found under engines/.
type EngineEntry struct {
	// Name is the directory's own name on disk.
	Name string
	// Key is the store key this entry is about: Name itself for a live
	// store, or the key parsed back out of Name for a leftover. Empty for a
	// directory under engines/ that matches neither shape — never removed,
	// never reported, left alone rather than guessed at.
	Key string
	// Leftover marks a directory a previous GC's phase 2 renamed aside and
	// then stopped on (a foreign-owned subtree — see PreflightOwnership).
	// Its own store.json travelled with the rename, so it is still
	// attributable exactly as a live store's is.
	Leftover bool
}

// leftoverName renders the ".gc-<key>-<pid>-<ts>" a phase-1 rename produces.
// pid and ts are for humans reading `ls`, not for this package's own logic:
// nothing here parses them back out, only the key.
func leftoverName(key string) string {
	return fmt.Sprintf("%s%s-%d-%d", leftoverPrefix, key, os.Getpid(), time.Now().UnixNano())
}

// leftoverKey recovers the key a leftover name carries, or "" if name is not
// shaped like one this package produced (leftoverPrefix followed by
// something that is not a valid store key at all — never guessed at).
func leftoverKey(name string) string {
	rest := strings.TrimPrefix(name, leftoverPrefix)
	if rest == name {
		return ""
	}
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) == 0 || !StoreKey(parts[0]) {
		return ""
	}
	return parts[0]
}

// ListEngineEntries enumerates engines/, classifying every directory as a
// live store, a leftover, or neither (skipped). It reads no breadcrumb and
// checks no ownership — a directory listing only — so it never fails on a
// store this process cannot fully open, which is exactly the store a report
// most needs to be able to name.
func ListEngineEntries(root *os.Root) ([]EngineEntry, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("engine gc: reading engines directory: %w", err)
	}
	out := make([]EngineEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue // engines/ holds only per-key directories; anything else was not put there by snug
		}
		name := e.Name()
		switch {
		case StoreKey(name):
			out = append(out, EngineEntry{Name: name, Key: name})
		case strings.HasPrefix(name, leftoverPrefix):
			if key := leftoverKey(name); key != "" {
				out = append(out, EngineEntry{Name: name, Key: key, Leftover: true})
			}
			// A ".gc-" name this package cannot parse a key back out of was
			// not produced by this package's own leftoverName and is left
			// alone rather than guessed at.
		}
	}
	return out, nil
}

// OpenStore opens engines/<name> (a live store's own key, or a leftover's
// full ".gc-..." name) for reading or removal. The TOP-LEVEL per-key
// directory is always created by verifyEngineStore's SecureSubdir at exactly
// 0700, and a rename preserves that mode, so this stays the strict,
// creation-refusing vdir.OpenExistingSubdir rather than OpenForRemoval — the
// mode-not-required predicate is for what PURGE finds descending into
// storage/, an engine-authored tree, not for a directory snug itself always
// creates at a fixed mode.
func OpenStore(root *os.Root, rootPath, name string) (*os.Root, string, error) {
	child, err := vdir.OpenExistingSubdir(root, rootPath, name)
	if err != nil {
		return nil, "", fmt.Errorf("engine gc: %w", err)
	}
	return child, filepath.Join(rootPath, name), nil
}

// RenameAside is phase 1: a single renameat moving name (already open
// through root) to a ".gc-" name nothing else will ever look up. See this
// file's package comment for why this is what turns "partially removed"
// into an impossible state rather than a rare one — the engine only ever
// looks up a store by its ORIGINAL key, so the instant this call returns,
// nothing can find it under that key again, and the (possibly slow) delete
// below can run with no lock held at all.
//
// The caller is responsible for having already proven name is not a live
// run's store — this function does not know what a lock is and does not
// take one. It reports fs.ErrNotExist, unwrapped, when name is not there at
// all (nothing to remove, not a fault).
func RenameAside(root *os.Root, name string) (renamed string, err error) {
	renamed = leftoverName(name)
	if rerr := root.Rename(name, renamed); rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return "", fs.ErrNotExist
		}
		return "", fmt.Errorf("engine gc: renaming %s aside: %w", name, rerr)
	}
	return renamed, nil
}

// StoreScan is a NO-MUTATION walk's result: a LOWER BOUND on size, and
// whatever the walk could learn about what it could not read. It is used
// both for the pre-flight ownership sweep (PreflightOwnership refuses the
// whole store on ForeignUID != "") and for --dry-run's honest size report,
// which must never claim a number chmod would be needed to produce.
type StoreScan struct {
	// SizeBytes is the sum of every regular file this walk could actually
	// read the size of. It excludes anything inside a directory the walk
	// could not open.
	SizeBytes int64
	// UnreadableDirs counts directories this process OWNS but could not
	// open — overlayfs's own work/work shape. Real removal chmods and
	// retries; this walk never does.
	UnreadableDirs int
	// UnreadableSubdirs is a LOWER BOUND on the subdirectories hidden inside
	// UnreadableDirs, read from each one's own st_nlink via Lstat — which
	// needs no permission on the target itself, only on its parent — rather
	// than by opening it. POSIX: every subdirectory's own ".." entry adds
	// one link to its parent, so nlink-2 is a floor on how many there are,
	// never a ceiling and never their size.
	UnreadableSubdirs int
	// ForeignUID and ForeignPath are set when this walk finds an entry NOT
	// owned by this process. Non-empty ForeignPath means the whole store
	// this scan covers must be refused, not merely the one subtree — see
	// PreflightOwnership.
	ForeignUID  int
	ForeignPath string
}

// ForeignOwner reports whether this scan found a directory or file this
// process does not own.
func (s StoreScan) ForeignOwner() bool { return s.ForeignPath != "" }

// ScanStore walks dir READ-ONLY — no chmod, no rename, nothing removed — and
// is what PreflightOwnership and --dry-run's size report both are.
//
// THE PRE-FLIGHT IS INCOMPLETE BY CONSTRUCTION, and this is the one place to
// say so: it cannot see inside a directory it owns but cannot open (mode
// denies traversal), so a foreign-uid subtree HIDDEN inside one is invisible
// to this walk. This is payload-reachable, not hypothetical: any container
// image can ship a directory whose content is owned by a non-root UID inside
// the image (nginx, postgres, most language runtimes all do), which lands on
// disk owned by whatever HOST uid this host's subuid map delegates that
// namespace uid to — commonly NOT this process's own uid, per
// internal/stage/subuid.go's ns 0 -> host uid (size 1), ns 1..N -> host
// uid+1.. delegation. If such a subtree sits inside a mode-0000 directory
// this process itself owns, this walk cannot open that directory to find it,
// and phase 1 (RenameAside) proceeds having seen nothing wrong. The landing
// branch is not silent: phase 2 (Purge) reaches the same directory, gets the
// SAME EACCES, chmods it open (ownership already confirmed at THAT level),
// and only then meets the foreign-owned child — where it stops with a
// ForeignOwnerError, leaving a named, self-describing ".gc-<key>-..."
// directory that still carries its own store.json, so the NEXT `snug engine
// gc` describes it by name and by target rather than silently retrying
// forever.
func ScanStore(dir *os.Root, dirPath string) (StoreScan, error) {
	var scan StoreScan
	if err := scanInto(dir, dirPath, &scan); err != nil {
		return scan, err
	}
	return scan, nil
}

func scanInto(dir *os.Root, dirPath string, scan *StoreScan) error {
	entries, err := fs.ReadDir(dir.FS(), ".")
	if err != nil {
		return fmt.Errorf("engine gc: reading %s: %w", dirPath, err)
	}
	for _, e := range entries {
		if scan.ForeignOwner() {
			return nil // already refusing the whole store; no point measuring more
		}
		name := e.Name()
		full := filepath.Join(dirPath, name)

		fi, lerr := dir.Lstat(name)
		if lerr != nil {
			continue // gone between ReadDir and Lstat: not this walk's problem
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue // never followed; its own size is negligible and not counted
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if ok && int(st.Uid) != os.Getuid() {
			scan.ForeignUID = int(st.Uid)
			scan.ForeignPath = full
			return nil
		}
		if !fi.IsDir() {
			scan.SizeBytes += fi.Size()
			continue
		}

		sub, oerr := dir.OpenRoot(name)
		if oerr != nil {
			// Owned (checked above) but this walk cannot enter it — the
			// mode-0000 shape this package's doc comment describes. Lstat
			// already told us its nlink without needing to open it.
			scan.UnreadableDirs++
			if ok && st.Nlink >= 2 {
				scan.UnreadableSubdirs += int(st.Nlink) - 2
			}
			continue
		}
		serr := scanInto(sub, full, scan)
		sub.Close()
		if serr != nil {
			return serr
		}
	}
	return nil
}

// Purge removes name from parent, recursively, tolerating the one shape a
// container engine's overlayfs leaves behind — see this file's package
// comment for the measurements that force this shape and the rmdir-first
// ordering.
//
// A ForeignOwnerError (from vdir.OpenForRemoval or from Chmod's own EPERM)
// stops the walk immediately and is returned as-is: the caller is expected
// to leave everything ABOVE the refusal exactly where phase 1 put it — a
// named ".gc-<key>-..." directory, still carrying its own store.json, that a
// later `snug engine gc` will find and describe rather than silently retry.
func Purge(parent *os.Root, parentDesc, name string) error {
	full := filepath.Join(parentDesc, name)

	err := parent.Remove(name)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EACCES) {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // already gone: not this call's problem
		}
		return fmt.Errorf("engine gc: removing %s: %w", full, err)
	}

	child, _, operr := vdir.OpenForRemoval(parent, parentDesc, name)
	if operr != nil {
		var foreign *vdir.ForeignOwnerError
		if errors.As(operr, &foreign) {
			return operr
		}
		if !errors.Is(operr, syscall.EACCES) {
			return fmt.Errorf("engine gc: opening %s: %w", full, operr)
		}
		// Owned by us (OpenForRemoval already confirmed that — a foreign
		// owner returns ForeignOwnerError above, not EACCES here) but its
		// OWN mode denies traversal: overlayfs's work/work, measured at
		// mode 0000. Chmod is authorised by OWNERSHIP, not by the current
		// mode, so this succeeds; EPERM here would mean the ownership check
		// a moment ago somehow did not hold between then and now — treated
		// as a hard failure rather than retried, and NOT reported as
		// vdir.ForeignOwnerError: that type's own doc comment promises the
		// UID it names came from a stat, and this branch has none to offer.
		if cerr := parent.Chmod(name, 0o700); cerr != nil {
			if errors.Is(cerr, syscall.EPERM) {
				return fmt.Errorf("engine gc: refusing %s: chmod returned EPERM after an ownership "+
					"check a moment ago said this uid owns it — ownership changed underneath this "+
					"walk; re-run rather than trusting a stale check: %w", full, cerr)
			}
			return fmt.Errorf("engine gc: chmod %s: %w", full, cerr)
		}
		child, _, operr = vdir.OpenForRemoval(parent, parentDesc, name)
		if operr != nil {
			return fmt.Errorf("engine gc: opening %s after chmod: %w", full, operr)
		}
	}
	defer child.Close()

	entries, rerr := fs.ReadDir(child.FS(), ".")
	if rerr != nil {
		return fmt.Errorf("engine gc: reading %s: %w", full, rerr)
	}
	for _, e := range entries {
		if perr := Purge(child, full, e.Name()); perr != nil {
			return perr
		}
	}
	return parent.Remove(name)
}

// RunrootBaseName is the runroot's own top-level name under os.TempDir() —
// see verifyEngineRunroot, which creates it at exactly this name. `snug
// engine gc` removes it alongside the store, same key, same two phases:
// leaving it behind is invariant 4's "state that survives them", and a fresh
// store beside a stale runroot of the same key is untested and unwanted.
func RunrootBaseName(key string) string {
	return fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key)
}
