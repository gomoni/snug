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

// TestRequiredNoLinksPrivateRefusesOtherReadableAndLinks fails if a credential
// file with a group or other bit set, or reached through a link, is returned.
// The control is the 0600 regular file, which must read. Ownership by another
// uid is the third refusal and is not exercised here: it needs a file this
// user does not own.
func TestRequiredNoLinksPrivateRefusesOtherReadableAndLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := RequiredNoLinksPrivate(path, 64, os.Getuid()); err != nil || string(got) != "secret\n" {
		t.Fatalf("control: %q, %v", got, err)
	}
	if _, err := RequiredNoLinksPrivate(path, 64, os.Getuid()+1); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("a file owned by another uid: err = %v, want ErrNotPrivate", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := RequiredNoLinksPrivate(path, 64, os.Getuid()); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("mode %04o: err = %v, want ErrNotPrivate", mode, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := RequiredNoLinksPrivate(link, 64, os.Getuid()); err == nil {
		t.Error("a symlink was followed")
	}
	if _, err := RequiredNoLinksPrivate(path, 3, os.Getuid()); err == nil {
		t.Error("a file over the cap was read")
	}
}
