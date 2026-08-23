package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/targetkey"
	"github.com/gomoni/snug/internal/vdir"
)

// needsHostTmpDir reports whether any selected profile refers to the
// {host_tmpdir} variable. Looking for the variable rather than for the profile
// named "tmp-shared" keeps the CLI from hard-coding a profile name: a
// user-written profile that uses the variable works the same way.
func needsHostTmpDir(reg profile.Registry, selected []policy.ProfileName) (bool, error) {
	set, err := policy.Expand(map[policy.ProfileName]*policy.Profile(reg), selected)
	if err != nil {
		return false, err
	}
	for _, p := range set {
		for _, g := range [][]string{p.RO, p.RW, p.Tmpfs} {
			for _, s := range g {
				if strings.Contains(s, "{host_tmpdir}") {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// prepareHostTmpDir allocates the per-sandbox directory that the tmp-shared
// profile mounts as the sandbox's /tmp.
//
// The name is derived from the target, so a given project gets the same
// directory across runs and a build cache stays warm — and two different
// projects never share one.
//
// Everything below the MkdirAll is defence against the classic /tmp races: a
// path someone else can replace with a symlink, or that is group/other-writable,
// is a way to get the sandbox to write somewhere it was never granted. Refuse
// rather than repair, because a surprising directory here means something on
// the host is already wrong.
// hostTmpDirPath is the name alone, with no side effect. Split out so --dry-run
// can render the exact path it WOULD use without creating it: `--dry-run` says
// "It starts no process and creates no file", and this was the one place that
// was false — `--dry-run -p @tmp-shared` left a /tmp/snug-* behind.
//
// The key is internal/targetkey's Hash, full and untruncated — see that
// package's doc comment. This directory used to carry a 12-character
// truncation of its own, a third length alongside engineKey's 16 and
// targetKeyPrefix's full form; standardising on the full form means a reader
// holding the target can verify this name against it without knowing this
// site used to cut it short. This directory lives under os.TempDir(), not
// $XDG_DATA_HOME, so unlike the engine store, an orphan left by the rename
// (an old-format "snug-<uid>-<hex12>" directory nothing names any more)
// needs no GC: /tmp clears it at the next reboot. The store persists across
// reboots by design and does not get that for free — that asymmetry is why
// only the store needed `snug engine gc` (issue #308) and this directory did
// not.
func hostTmpDirPath(target string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("snug-%d-%s", os.Getuid(), targetkey.Hash(target)))
}

func prepareHostTmpDir(target string) (string, error) {
	path := hostTmpDirPath(target)
	base, name := filepath.Dir(path), filepath.Base(path)

	root, err := os.OpenRoot(base)
	if err != nil {
		return "", fmt.Errorf("shared tmp: opening %s: %w - the sandbox's /tmp is a directory "+
			"under it; check that it exists and is a directory you can write to", base, err)
	}
	defer root.Close()

	// vdir.SecureSubdir, not the Lstat-then-check this function used to do.
	// The old version asked its questions of a PATH — Lstat it, refuse a
	// symlink, check owner and mode on that FileInfo — and never held a
	// descriptor at all, so every answer was about a name at a moment. This
	// creates through a handle that cannot name anything outside `base`,
	// refuses a symlink at exactly the name it is about to open, and checks
	// owner and mode on the opened directory itself (issue #233).
	//
	// Reuse is expected here, unlike the engine's run directory: the name is
	// derived from the target, so a project gets the same directory across
	// runs and a build cache stays warm. Hence SecureSubdir with the created
	// flag ignored, rather than MustCreateSubdir.
	//
	// One behaviour change worth stating: the old check refused a mode with
	// ANY group or other bits (perm&0o077); vdir requires exactly 0700. A
	// directory that was 0500 or 0000 passed before and is refused now. That
	// is the stricter direction, it is the same rule the runtime directory has
	// always had, and a shared /tmp snug cannot write to is not usable as one
	// anyway.
	child, _, err := vdir.SecureSubdir(root, base, name)
	if err != nil {
		return "", fmt.Errorf("shared tmp: %w", err)
	}
	child.Close()

	// THE LIMIT, inherent rather than an omission: bwrap binds this directory
	// BY PATH, in a process snug forks later, and there is no way to hand it a
	// descriptor. So the handle above establishes that the directory snug
	// created and checked is the one it opened — not that the name still leads
	// there when bwrap walks it. Holding the descriptor open would not close
	// that window either: a rename or replace of the NAME is what the window
	// is. What changed is that the check is now about the thing rather than
	// about the string, and that creation cannot follow a symlink planted
	// first.
	return path, nil
}
