package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/gomoni/snug/internal/vdir"
)

// runSeq disambiguates the run directory name when New is called more than
// once in the same process: a real snug invocation creates exactly one
// Engine per run, so the FIRST call gets the plain, spec-shaped name
// (ENGINE-WIRING.md §3.2: "/tmp/snug-<uid>-<runid>/", runid = this process's
// own pid) and every call after it — which only ever happens in this
// package's own tests — gets a numbered suffix so it does not collide with
// (and get refused by createRunDir's own no-reuse rule against) a directory
// an earlier call in the same test binary already claimed.
var runSeq atomic.Int64

func runDirName(uid, pid int) string {
	n := runSeq.Add(1)
	if n == 1 {
		return fmt.Sprintf("snug-%d-%d", uid, pid)
	}
	return fmt.Sprintf("snug-%d-%d-%d", uid, pid, n)
}

// runDirs is this engine's own run directory: the verified handle, its
// verified parent, and the path string podman's argv still needs.
//
// It replaces createRunDir, which hand-rolled what internal/vdir now does for
// everyone — mkdir-that-refuses-to-reuse, then O_DIRECTORY|O_NOFOLLOW, then
// fstat on the descriptor rather than a second walk of the path. That code was
// right, and #233 is about what happened NEXT: the descriptor was closed, the
// path became a string, and every later operation on the most exposed
// directory snug creates re-derived it by name.
//
// /tmp is why this matters more here than for the $XDG_RUNTIME_DIR directory:
// it is commonly world-writable and sticky, so a same-uid process on a shared
// host can plant an entry at a guessable path before this one gets there
// (ENGINE-WIRING.md §3.2).
//
// THE LIMIT, stated rather than left to be discovered: podman is a separate
// process taking --root and --runroot as ARGV, and the paths in this struct
// are handed to it as strings. A descriptor cannot be passed there. What the
// handles buy is everything on THIS side — creation that cannot follow a
// planted symlink, verification of the thing actually opened, and a removal
// that finds this run's directory by inode rather than by a route that may no
// longer lead there.
type runDirs struct {
	parent *os.Root // os.TempDir(), held open for the life of the engine
	root   *os.Root // the run directory itself
	name   string
	path   string
}

// openRunDirs creates and verifies the run directory, and keeps both handles.
//
// The name carries this process's own pid, so an entry already at it is
// suspicious by construction — vdir.MustCreateSubdir refuses reuse, which is
// the rule the old createRunDir enforced with a bare unix.Mkdir and the
// reason it never called MkdirAll.
func openRunDirs(base, name string) (*runDirs, error) {
	parent, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("engine run directory: opening %s: %w — snug puts this run's "+
			"engine socket and generated config under it; check that it exists and is a "+
			"directory you can write to", base, err)
	}
	root, err := vdir.MustCreateSubdir(parent, base, name)
	if err != nil {
		parent.Close()
		return nil, fmt.Errorf("engine run directory: %w", err)
	}
	return &runDirs{parent: parent, root: root, name: name, path: filepath.Join(base, name)}, nil
}

// sub creates one of the run directory's own children — sock/ and conf/,
// which #125's C2b split by writability — through the already-verified
// handle, and verifies it the same way.
func (d *runDirs) sub(name string) (*os.Root, string, error) {
	child, err := vdir.MustCreateSubdir(d.root, d.path, name)
	if err != nil {
		return nil, "", fmt.Errorf("engine run directory: %w", err)
	}
	return child, filepath.Join(d.path, name), nil
}

// remove takes the run directory away through the verified parent handle.
//
// The difference from os.RemoveAll(d.path) is not stylistic and is measured
// the same way #103's was: a descriptor names an inode, a path names a route,
// and os.RemoveAll on a route that no longer leads here reports success having
// removed nothing — which would leave this run's engine socket and generated
// config on disk while snug reported a clean teardown.
func (d *runDirs) remove() error {
	if d == nil {
		return nil
	}
	return d.parent.RemoveAll(d.name)
}

// close releases the handles without removing anything. The engine holds them
// for its whole life, so this runs only on a construction path that fails
// after they were opened.
func (d *runDirs) close() {
	if d == nil {
		return
	}
	d.root.Close()
	d.parent.Close()
}
