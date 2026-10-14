package profile

import (
	"slices"
	"testing"
)

// TestRelativeXDGConfigHomeIsIgnored holds the XDG Base Directory rule that a
// relative $XDG_CONFIG_HOME is invalid. Honoured, it roots the trusted profile
// store at the working directory, a checkout can ship that directory, and
// TrustedConfigRoots then names a relative path no absolute grant can match,
// so rw over the store it loads from resolved (--dry-run exit 0).
func TestRelativeXDGConfigHomeIsIgnored(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_CONFIG_HOME", "rel")
	if got, want := ConfigDirs(), []string{"/etc/snug/profiles.d", "/home/u/.config/snug/profiles.d"}; !slices.Equal(got, want) {
		t.Errorf("ConfigDirs = %v, want %v", got, want)
	}
	if got, want := ConfigFile(), "/home/u/.config/snug/config.toml"; got != want {
		t.Errorf("ConfigFile = %q, want %q", got, want)
	}
	if got, want := TrustedConfigRoots(), []string{"/etc/snug", "/home/u/.config/snug"}; !slices.Equal(got, want) {
		t.Errorf("TrustedConfigRoots = %v, want %v", got, want)
	}
}
