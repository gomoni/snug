// Package vdir is snug's one implementation of "a directory this process has
// verified it owns", and it exists because there were about to be three.
//
// internal/cli grew these checks for the $XDG_RUNTIME_DIR run directory
// (#61, #85, #103); internal/engine hand-rolled an equivalent for its own
// run directory under /tmp — mkdir-that-refuses-to-reuse, then
// O_DIRECTORY|O_NOFOLLOW, then fstat on the descriptor — and
// prepareHostTmpDir had a third, weaker spelling that checked by path and
// held no descriptor at all (#233). Three copies of a security check is the
// shape CLAUDE.md warns about under a different name: a rule written once
// and applied to one of its halves. Two of those copies were already
// drifting — only one of the three refused a symlink at the name it creates.
//
// What every caller gets from these functions:
//
//   - an *os.Root, so nothing opened through it can name anything outside
//     the directory it was opened on — structurally, not by convention;
//   - a refusal, never a repair, when the owner or mode is wrong
//     (invariant 5: a silent chmod would downgrade whatever guarantee the
//     wrong mode already broke);
//   - an Lstat refusal at exactly the name being opened, because os.Root's
//     documented contract is to FOLLOW an in-root symlink, which is one
//     degree more permissive than any of these callers wants at a name it
//     created itself.
//
// What it does not give anyone: protection for what happens to the NAME
// afterwards. A descriptor names an inode; a later open by path — bwrap
// binding a directory, a helper re-deriving a route — walks the name again.
// Each caller states that limit where it applies rather than assuming the
// type covers it.
package vdir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// secureSubroot opens (creating it if absent) a directory named `name`
// inside the already-verified root `parent`, and returns it as its own
// *os.Root so nothing opened through it can walk back out or past it.
//
// It never trusts an existing entry: found means checked, and — per
// invariant 5 — a check that fails is refused rather than repaired.
//
// The Lstat immediately below is the deliberate narrowing described on
// this package: os.Root's documented behaviour is to follow an in-root
// symlink, and this is one of the two names ("snug"/"snug-<uid>", and the
// per-run directory) where that is one degree more permissive than this
// function wants. It runs AFTER Mkdir, not before: Mkdir is the atomic
// step — either it creates a fresh directory (nothing could have raced a
// symlink into that exact name in between, because the parent directory
// this create just happened in has already passed the ownership+mode 0700
// check below, and 0700 owned by this uid is the only thing that can write
// there), or it reports EEXIST, in which case the Lstat is what tells apart
// "a directory left by an earlier run" from "a symlink something planted
// before snug got here".
func SecureSubdir(parent *os.Root, parentDesc, name string) (child *os.Root, created bool, err error) {
	mkErr := parent.Mkdir(name, 0o700)
	created = mkErr == nil
	if mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
		return nil, false, fmt.Errorf("creating %s: %w - snug needs this directory; check "+
			"free space, inodes and write permission on the parent", filepath.Join(parentDesc, name), mkErr)
	}

	full := filepath.Join(parentDesc, name)

	if fi, lerr := parent.Lstat(name); lerr != nil {
		return nil, false, fmt.Errorf("checking %s: %w - snug verifies what it is about to open "+
			"before opening it, and refuses rather than trusting it", full, lerr)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing %s: it is a symlink — something on this host "+
			"planted it before snug got here; remove it by hand and re-run snug", full)
	}

	child, err = parent.OpenRoot(name)
	if err != nil {
		return nil, false, fmt.Errorf("opening %s: %w - it passed the symlink and ownership "+
			"checks a moment ago, so something changed underneath: re-run, and if it repeats, "+
			"something else on this host is writing where snug keeps its state", full, err)
	}

	if verr := VerifyOwnedAndPrivate(child, full); verr != nil {
		child.Close()
		return nil, false, verr
	}
	return child, created, nil
}

// MustCreateSubdir is SecureSubdir with reuse REFUSED rather than reported:
// the caller's name is unique per run, so an entry already at it is
// suspicious by construction — a leftover from a run whose pid was reused, or
// something planted there before snug arrived. internal/engine's run
// directory lives under /tmp, commonly world-writable, which is exactly where
// a same-uid process on a shared host can get there first.
//
// Whether reuse is legitimate is the caller's question, not this package's:
// internal/cli's runtime directory reuses the shared "snug" directory between
// runs by design, so it calls SecureSubdir and reads the created flag.
func MustCreateSubdir(parent *os.Root, parentDesc, name string) (*os.Root, error) {
	child, created, err := SecureSubdir(parent, parentDesc, name)
	if err != nil {
		return nil, err
	}
	if !created {
		child.Close()
		return nil, fmt.Errorf("refusing %s: it already exists — this name is unique to this "+
			"run, so nothing should have been at it; remove it by hand if you are sure "+
			"nothing is using it, and re-run snug", filepath.Join(parentDesc, name))
	}
	return child, nil
}

// OpenExistingSubdir is SecureSubdir without the Mkdir: it opens a
// directory that is expected to already exist (another run's directory,
// being read rather than claimed) and refuses it exactly as hard —
// ownership, mode, and no symlink at this name — without creating anything
// if it is absent. Used by `snug attach`'s run discovery, which must never
// bring a directory into existence just by looking for one.
func OpenExistingSubdir(parent *os.Root, parentDesc, name string) (*os.Root, error) {
	full := filepath.Join(parentDesc, name)

	if fi, lerr := parent.Lstat(name); lerr != nil {
		return nil, fmt.Errorf("checking %s: %w - snug verifies what it is about to open before "+
			"opening it, and refuses rather than trusting it", full, lerr)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing %s: it is a symlink — something on this host "+
			"planted it before snug got here; remove it by hand and re-run snug", full)
	}

	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w - it passed the symlink and ownership checks a "+
			"moment ago, so something changed underneath: re-run, and if it repeats, something "+
			"else on this host is writing into snug's runtime directory", full, err)
	}
	if verr := VerifyOwnedAndPrivate(child, full); verr != nil {
		child.Close()
		return nil, verr
	}
	return child, nil
}

// ForeignOwnerError is OpenForRemoval's refusal when a directory belongs to a
// uid other than the caller's own. It is a distinct type — not a plain
// fmt.Errorf — because the caller (Purge in internal/engine's `snug engine
// gc`) has to tell this apart from an EACCES it can fix with a chmod: EPERM
// from a chmod attempt and this error both mean "not yours", and the fix in
// both cases is the same word, "refuse", never "retry as root".
type ForeignOwnerError struct {
	Path string // the full, human-facing path this was checked at
	UID  int    // the directory's actual owner
}

func (e *ForeignOwnerError) Error() string {
	return fmt.Sprintf("refusing %s: owned by uid %d, not you — this needs a userns carrying "+
		"the same delegated uid map to remove; snug will not chmod or delete something it does "+
		"not own", e.Path, e.UID)
}

// OpenForRemoval is SecureSubdir's sibling for a directory about to be
// DELETED rather than used: it refuses exactly what every other predicate in
// this package refuses — an in-root symlink, and an entry this process does
// not own — but it neither creates the entry nor requires any particular
// mode, and it reports whatever mode it finds instead.
//
// Every other predicate here assumes a directory snug created for its own
// use, where 0700 is the FLOOR of what counts as safe and a caller checking
// it means to KEEP using the directory afterwards (VerifyOwnedAndPrivate:
// "found means checked", refused rather than repaired). Removal inverts
// that: the caller means to make the entry go away regardless of how
// permissive or restrictive its CURRENT mode is. A container engine's own
// overlayfs leaves a work/work directory at mode 0000, non-empty, and still
// owned by the same uid that ran the engine (measured — see
// internal/engine's Purge, the caller this exists for) — requiring 0700 here
// would make `snug engine gc` refuse to open the exact directories it exists
// to remove.
//
// Ownership and the symlink refusal are both checked from Lstat alone,
// deliberately BEFORE any attempt to open the entry: Lstat needs only search
// permission on the already-verified PARENT, not on the target itself, so a
// foreign-owned or mode-0000 entry is fully classifiable without ever trying
// to enter it. A foreign owner is refused outright — OpenForRemoval never
// attempts to open something it does not own, matching ForeignOwnerError's
// own message. Only once ownership is confirmed does this attempt OpenRoot,
// whose failure past that point is a MODE question (measured: a 0000
// directory a process owns still refuses openat(2) with EACCES) rather than
// an ownership one, and the caller is expected to chmod and retry — this
// function does not chmod anything itself, staying a predicate rather than a
// mutation.
func OpenForRemoval(parent *os.Root, parentDesc, name string) (child *os.Root, mode os.FileMode, err error) {
	full := filepath.Join(parentDesc, name)

	fi, lerr := parent.Lstat(name)
	if lerr != nil {
		return nil, 0, fmt.Errorf("checking %s: %w - snug verifies what it is about to remove "+
			"before touching it, and refuses rather than trusting it", full, lerr)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("refusing %s: it is a symlink — something planted it; "+
			"remove it by hand", full)
	}
	if !fi.IsDir() {
		return nil, 0, fmt.Errorf("refusing %s: not a directory", full)
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, fmt.Errorf("checking %s: could not read its owner on this platform - snug "+
			"needs POSIX stat to confirm the directory is yours before removing it", full)
	}
	mode = fi.Mode().Perm()
	if uid := int(st.Uid); uid != os.Getuid() {
		return nil, mode, &ForeignOwnerError{Path: full, UID: uid}
	}

	child, oerr := parent.OpenRoot(name)
	if oerr != nil {
		return nil, mode, fmt.Errorf("opening %s: %w - ownership is already confirmed at this "+
			"point, so EACCES here means the directory's OWN mode denies traversal (measured: an "+
			"overlayfs work directory at mode 0000); a caller meaning to remove it chmods the name "+
			"and retries (internal/engine.Purge does exactly this) rather than treating this as fatal",
			full, oerr)
	}
	return child, mode, nil
}

// verifyOwnedAndPrivate refuses a directory that is not ours, or that is
// readable, writable or searchable by anyone else — the two properties that
// make it safe to place a unix socket inside without asking who else could
// already be watching that path.
//
// It checks the open HANDLE (root.Stat(".")), not a path string, so what
// gets checked is exactly the directory that was just opened — os.Root
// prevents this handle from having been redirected out of the tree it was
// opened on, but says nothing on its own about who owns what is inside it.
func VerifyOwnedAndPrivate(root *os.Root, desc string) error {
	fi, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("checking %s: %w - snug must confirm it owns this directory before "+
			"using it, and refuses rather than assuming", desc, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checking %s: could not read its owner on this platform - snug needs POSIX "+
			"stat to confirm the directory is yours, so it cannot run here at all", desc)
	}
	if uid := int(st.Uid); uid != os.Getuid() {
		return fmt.Errorf("refusing %s: owned by uid %d, not you (uid %d) — "+
			"something else on this host created it; remove it by hand if you are sure "+
			"it is not in use — snug will not use a directory it does not own",
			desc, uid, os.Getuid())
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		return fmt.Errorf("refusing %s: mode is %#o, must be exactly 0700 — "+
			"check the umask that created it and fix the permissions by hand; "+
			"snug will not repair it silently", desc, mode)
	}
	return nil
}
