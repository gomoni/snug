// Package modroot finds the directory holding this module's go.mod, for the
// source sweeps under test/ and the *_test.go packages that walk the module's
// own tree.
//
// It walks UP from the working directory, never by counting ".." segments —
// a hardcoded subroot is how a sweep once came to walk a subdirectory of the
// module and miss cmd/snug entirely (issue #291).
//
// This was three identical copies (internal/dockerproxy, internal/policy,
// test/guard) before it was a package. The alternative to a shared package
// was three copies each carrying its own positive control on the walk, which
// fails for the same reason the duplication itself does: the control would
// be triplicated too, so the #291 lesson would live correctly in one copy out
// of three and nobody could tell which. It now lives in the one place that
// exists.
//
// No "testing" import: this is a non-test file so it can be imported, and
// each caller does its own t.Fatal(err).
package modroot

import (
	"errors"
	"os"
	"path/filepath"
)

// Find returns the directory holding go.mod, found by walking up from the
// current directory.
func Find() (string, error) {
	dir, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("modroot: no go.mod above the working directory")
		}
		dir = parent
	}
}
