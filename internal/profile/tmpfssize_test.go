package profile

import (
	"strings"
	"testing"
)

// TestProfileCannotSetATmpfsSize is the structural half of issue #281's
// scoping decision: tmpfs_size_mib is a PREFERENCE (internal/cli/config.go's
// userConfig, ~/.config/snug/config.toml) and must never become a grant-
// language key. DisallowUnknownFields is what makes that a hard parse error
// rather than a silently-ignored key — the same mechanism
// TestUnknownKeysAreFatal above asserts for `mask`/`deny`/`hide` — so this
// pins the specific spelling an author porting a preference into a profile by
// habit would reach for.
func TestProfileCannotSetATmpfsSize(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		// `size` beside a `tmpfs` grant, the shape the bwrap flag itself uses.
		{"size", `[profile.x]
tmpfs = ["{home}"]
size = 1024
`},
		// The config key's own name, at profile scope instead of config scope.
		{"tmpfs_size_mib", `[profile.x]
tmpfs = ["{home}"]
tmpfs_size_mib = 16
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte(tc.src), "test.toml", true)
			if err == nil {
				t.Fatalf("%q was accepted as a profile key; a tmpfs bound must only ever be a "+
					"preference in ~/.config/snug/config.toml, never something a profile — trusted "+
					"or not — can name", tc.name)
			}
			if !strings.Contains(err.Error(), "unknown") {
				t.Errorf("error %q does not say the key is unknown", err)
			}
		})
	}

	// CONTROL: the identical `tmpfs` grant without the extra key still parses,
	// or the refusal above is not attributable to the extra key at all.
	if _, err := parse([]byte("[profile.x]\ntmpfs = [\"{home}\"]\n"), "test.toml", true); err != nil {
		t.Fatalf("control: a plain tmpfs grant must still parse: %v", err)
	}
}
