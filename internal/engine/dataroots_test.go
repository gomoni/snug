package engine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDataRootsIncludesHomeDefaultUnderCustomXDG: redteam setup r7 follow-up,
// engine state. Under a custom $XDG_DATA_HOME the set still holds
// $HOME/.local/share/snug, because a later run without the variable keeps its
// store there; an XDG_DATA_HOME equal to the default lists it once.
func TestDataRootsIncludesHomeDefaultUnderCustomXDG(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_DATA_HOME", "/s/x")
	if got, want := DataRoots(), []string{"/s/x/snug", "/home/u/.local/share/snug"}; !slices.Equal(got, want) {
		t.Errorf("DataRoots() = %v, want %v", got, want)
	}
	t.Setenv("XDG_DATA_HOME", "/home/u/.local/share")
	if got, want := DataRoots(), []string{"/home/u/.local/share/snug"}; !slices.Equal(got, want) {
		t.Errorf("DataRoots() = %v, want %v", got, want)
	}
}

// TestTmpDirPrefixesMatchTheNamesTheEngineCreates: redteam setup r7 follow-up,
// engine state. The resolver refuses grants by these prefixes, so each name
// the engine authors under the temp directory must start with one of them.
func TestTmpDirPrefixesMatchTheNamesTheEngineCreates(t *testing.T) {
	prefixes := TmpDirPrefixes()
	for _, name := range []string{runDirName(os.Getuid(), 123), runDirName(os.Getuid(), 123), RunrootBaseName("k")} {
		path := filepath.Join(os.TempDir(), name)
		if !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(path, p) }) {
			t.Errorf("%s matches none of TmpDirPrefixes() %v", path, prefixes)
		}
	}
}
