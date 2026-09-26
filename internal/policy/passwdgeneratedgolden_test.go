package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenGeneratedPasswdAndGroup is the review artifact for issue #612: no
// prior golden ever rendered the BYTES of the generated /etc/passwd or
// /etc/group, so a change to field order, gecos, or which name feeds which
// file would produce zero diff anywhere else — the *.bwrap.txt goldens carry
// only a --ro-bind-data row naming the guest path and an fd, never the
// content behind it.
func TestGoldenGeneratedPasswdAndGroup(t *testing.T) {
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	content := func(guest string) string {
		t.Helper()
		m, ok := p.Mounts[guest]
		if !ok {
			t.Fatalf("no generated mount at %s", guest)
		}
		return string(m.Content)
	}

	got := fmt.Sprintf("── /etc/passwd ──\n%s\n── /etc/group ──\n%s",
		content("/etc/passwd"), content("/etc/group"))

	path := filepath.Join("testdata", "passwd-generated.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/policy -run TestGoldenGeneratedPasswdAndGroup "+
			"-update, then READ the diff)", err)
	}
	if got != string(want) {
		t.Errorf("the generated /etc/passwd or /etc/group changed:\n--- got\n%s\n--- want\n%s", got, string(want))
	}
}
