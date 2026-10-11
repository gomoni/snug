package guard

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureEnvName is the variable internal/cli/accountfixture.go reads. A binary
// that reads it reports whatever home directory the caller names as the
// account's, which is the check a real snug makes against the account
// database, so no binary a user runs may contain it.
const fixtureEnvName = "SNUG_FIXTURE_ACCOUNT_HOME"

func buildSnug(t *testing.T, tags string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "snug")
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./cmd/snug")
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join("..", "..")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestShippedBinaryHasNoAccountFixture fails if the account-home override of the
// integration suite's fixture binary can end up in the binary snug ships. The
// override lets a caller name the account's home, which would defeat the check
// that $HOME is the account's. The positive control is the tagged build, which
// must contain the name: a binary compiled without the file would otherwise pass
// for the wrong reason. The Makefile half asserts that nothing a user installs
// is built with the tag: only the `fixture` target and the type-check in `gate`
// may mention it.
func TestShippedBinaryHasNoAccountFixture(t *testing.T) {
	if !bytes.Contains(buildSnug(t, "snugfixture"), []byte(fixtureEnvName)) {
		t.Fatal("control: the snugfixture build does not contain " + fixtureEnvName +
			", so the absence below proves nothing")
	}
	if bytes.Contains(buildSnug(t, ""), []byte(fixtureEnvName)) {
		t.Errorf("the untagged ./cmd/snug binary contains %s", fixtureEnvName)
	}

	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	target := ""
	seen := false
	for _, line := range strings.Split(string(mk), "\n") {
		if trim := strings.TrimSpace(line); trim != "" && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trim, "#") &&
			strings.Contains(line, ":") && !strings.Contains(line, ":=") && !strings.Contains(line, "?=") {
			target = strings.SplitN(line, ":", 2)[0]
		}
		if !strings.Contains(line, "snugfixture") || !strings.HasPrefix(line, "\t") {
			continue
		}
		seen = true
		switch target {
		case "fixture", "gate":
		default:
			t.Errorf("Makefile target %q passes snugfixture: %s", target, strings.TrimSpace(line))
		}
	}
	if !seen {
		t.Error("control: no Makefile recipe line mentions snugfixture, so the target check ran over nothing")
	}
}
