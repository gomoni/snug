package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenFilesystemDefaults is the FILESYSTEM block of --dry-run for the
// shipped `defaults` selection, resolved against profile.Builtins() the same
// way TestGoldenTopology and TestGoldenEnvironment are — the review artifact
// for issue #553: every anchor row this change adds, its provenance
// ("(snug anchor)"), and the AnchorNote trailer that explains the kind once
// per screen.
//
// It replaces testdata/filesystem.defaults.txt rather than adding a new file:
// that golden existed since issue #169/#170 but was read by NOTHING (only two
// comments cited it, dryrun.go and topologygraft_test.go) and had already
// drifted — it showed `ro /home/u/proj @parent-ro`, which issue #550 made
// false for the default selection, with no anchor row at all.
func TestGoldenFilesystemDefaults(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(), envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	screen := captureFile(t, func(f io.Writer) {
		dryRun(newEnvFakeEnv(), f, p, []string{"/bin/sh"}, config{}, nil, nil)
	})
	// blockBetween cuts at the literal text "NOT GRANTED", which sits two
	// columns in on its own line — so the raw slice carries that trailing
	// indent with no newline after it. Trimmed and given a single trailing
	// newline, matching every other golden format in this package.
	got := strings.TrimRight(blockBetween(t, screen, "FILESYSTEM", "NOT GRANTED"), " \n") + "\n"

	path := filepath.Join("testdata", "filesystem.defaults.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the FILESYSTEM block changed — a diff here is a diff in the sandbox's\n"+
			"boundary, or in its provenance.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
