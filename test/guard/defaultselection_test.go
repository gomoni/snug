package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/test/modroot"
)

// ── the default selection is written down twice, and the copies must agree ──
//
// internal/policy cannot import internal/profile — the dependency runs the
// other way — so internal/policy/resolve_test.go keeps `testDefaults`, a hand
// copy of profile.BuiltinDefaults(). Its own comment states the risk: "if it
// ever diverges, the goldens are describing a sandbox no user gets", and every
// golden in that package resolves that list.
//
// A comment is not a check. When issue #550 dropped @parent-ro from the shipped
// defaults, the mirror kept it, and the goldens went on pinning a read-only
// bind of the target's parent that no user was getting any more. The mismatch
// was found by a test that happened to fail for another reason.
//
// This sweep is the check: it reads the literal out of the test source and
// compares it against the shipped list. Source-level, like sourcesweep_test.go
// beside it, because the value it guards lives in a _test.go file that nothing
// can import.
func TestTheMirroredDefaultSelectionMatchesTheShippedOne(t *testing.T) {
	const rel = "internal/policy/resolve_test.go"
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`var testDefaults = \[\]ProfileName\{([^}]*)\}`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("%s no longer declares `var testDefaults = []ProfileName{...}` on one line. "+
			"If the mirror moved, move this sweep with it — the two copies of the default "+
			"selection are what it exists to keep equal", rel)
	}

	var mirrored []string
	for _, f := range strings.Split(string(m[1]), ",") {
		if f = strings.TrimSpace(f); f != "" {
			mirrored = append(mirrored, strings.Trim(f, `"`))
		}
	}

	var shipped []string
	for _, n := range profile.BuiltinDefaults() {
		shipped = append(shipped, string(n))
	}

	if strings.Join(mirrored, " ") != strings.Join(shipped, " ") {
		t.Errorf("the default selection disagrees with itself:\n"+
			"  profile.BuiltinDefaults() = %v\n"+
			"  %s testDefaults = %v\n"+
			"Every golden in internal/policy resolves the mirror, so while these differ "+
			"those files pin a sandbox nobody gets. Fix the mirror and regenerate with "+
			"`go test ./internal/policy -update`.",
			shipped, rel, mirrored)
	}
}
