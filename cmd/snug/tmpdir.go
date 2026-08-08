package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"snug/internal/policy"
	"snug/internal/profile"
)

// needsHostTmpDir reports whether any selected profile refers to the
// {host_tmpdir} variable. Looking for the variable rather than for the profile
// named "tmp-shared" keeps the CLI from hard-coding a profile name: a
// user-written profile that uses the variable works the same way.
func needsHostTmpDir(reg profile.Registry, selected []string) (bool, error) {
	set, err := policy.Expand(map[string]*policy.Profile(reg), selected)
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
func hostTmpDirPath(target string) string {
	sum := sha256.Sum256([]byte(target))
	return filepath.Join(os.TempDir(), fmt.Sprintf("snug-%d-%s", os.Getuid(), hex.EncodeToString(sum[:])[:12]))
}

func prepareHostTmpDir(target string) (string, error) {
	path := hostTmpDirPath(target)

	fi, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", fmt.Errorf("shared tmp: %w", err)
		}
		return path, nil
	case err != nil:
		return "", fmt.Errorf("shared tmp: %w", err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("shared tmp: %s is a symlink; refusing to follow it", path)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("shared tmp: %s exists and is not a directory", path)
	}
	if err := ownedByUsAndPrivate(path, fi); err != nil {
		return "", err
	}
	return path, nil
}

func ownedByUsAndPrivate(path string, fi os.FileInfo) error {
	if uid, ok := fileUID(fi); ok && uid != os.Getuid() {
		return fmt.Errorf("shared tmp: %s is owned by uid %d, not you; refusing to use it", path, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("shared tmp: %s is mode %#o; it must not be group- or world-accessible", path, perm)
	}
	return nil
}

func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
