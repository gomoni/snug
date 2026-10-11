package hostread

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRequiredNoLinksRefusesALinkSwappedInAfterResolve fails if a pinned key
// path that was a regular file when the policy was resolved is read through a
// link planted afterwards, at the last component or at a parent: the key a
// sandbox can sign with would then be chosen by whoever could write there. The
// controls are the unswapped read, which must succeed, and the following
// Required reading the secret through the very same link, which shows the link
// leads somewhere readable and that ELOOP is the no-links open's doing.
func TestRequiredNoLinksRefusesALinkSwappedInAfterResolve(t *testing.T) {
	root := t.TempDir()
	keyDir := filepath.Join(root, "ssh")
	secretDir := filepath.Join(root, "secret")
	for _, d := range []string{keyDir, secretDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(keyDir, "id.pub")
	if err := os.WriteFile(key, []byte("ssh-ed25519 BENIGN\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "id.pub"), []byte("ssh-ed25519 SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := RequiredNoLinks(key, MaxSSHPublicKeyBytes)
	if err != nil || !strings.Contains(string(got), "BENIGN") {
		t.Fatalf("control: the unswapped key was not read: %q, %v", got, err)
	}

	check := func(t *testing.T, path string) {
		t.Helper()
		if data, err := Required(path, MaxSSHPublicKeyBytes); err != nil || !strings.Contains(string(data), "SECRET") {
			t.Fatalf("control: Required does not reach the secret through the link (%q, %v)", data, err)
		}
		data, err := RequiredNoLinks(path, MaxSSHPublicKeyBytes)
		if data != nil || !errors.Is(err, unix.ELOOP) {
			t.Fatalf("RequiredNoLinks(%s) = %q, %v; want no data and ELOOP", path, data, err)
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("refusal %q does not name the path", err)
		}
	}

	t.Run("last component", func(t *testing.T) {
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(secretDir, "id.pub"), key); err != nil {
			t.Fatal(err)
		}
		check(t, key)
	})

	t.Run("parent component", func(t *testing.T) {
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, []byte("ssh-ed25519 BENIGN\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(root, "ssh-moved")
		if err := os.Rename(keyDir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(secretDir, keyDir); err != nil {
			t.Fatal(err)
		}
		check(t, key)
	})
}
