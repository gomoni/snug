package engine

import (
	"slices"
	"testing"
)

// TestRelativeXDGDataHomeIsIgnored holds the XDG Base Directory rule that a
// relative $XDG_DATA_HOME is invalid. Honoured, the engine store lands under
// the working directory while DataRoots names a relative path no absolute
// grant can match, so a grant over the store in use resolved.
func TestRelativeXDGDataHomeIsIgnored(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_DATA_HOME", "rel")
	d, err := dataHomeDir()
	if err != nil || d != "/home/u/.local/share" {
		t.Errorf("dataHomeDir = %q, %v; want /home/u/.local/share", d, err)
	}
	if got, want := DataRoots(), []string{"/home/u/.local/share/snug"}; !slices.Equal(got, want) {
		t.Errorf("DataRoots = %v, want %v", got, want)
	}
}
