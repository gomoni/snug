package compose

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// allowlist is matched case-insensitively against the name the model asked for.
var allowlist = []string{
	"readme*", "docker-compose*.y*ml", "compose*.y*ml", "dockerfile*", "containerfile*",
	"makefile", "package.json", "pyproject.toml", "go.mod", "cargo.toml", "contributing*", ".env.example",
}

// maxRead bounds what is read from disk; compose files longer than this are
// digested from their first maxRead bytes only if that still parses.
const maxRead = 256 << 10

// Allowed reports whether name may be read: a single path element matching the
// allowlist.
func Allowed(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	l := strings.ToLower(name)
	for _, pat := range allowlist {
		if ok, _ := path.Match(pat, l); ok {
			return true
		}
	}
	return false
}

// ErrRefused is wrapped by every ReadTarget refusal the model or the file can
// provoke (as opposed to I/O failures).
var ErrRefused = errors.New("read refused")

// ReadTarget reads the file name from the target directory and returns its
// digest. name must be a bare allowlisted file name; a path with a separator,
// a name outside the allowlist, a symlink at that name (even one pointing
// inside the target) and anything that is not a regular file are refused with
// an error wrapping ErrRefused. os.Root follows symlinks that stay inside the
// root, which is one degree too permissive here, hence the Lstat at the name;
// a symlink swapped in after that check still cannot lead out of the target.
func ReadTarget(target, name string) (string, error) {
	if !Allowed(name) {
		return "", fmt.Errorf("%w: %q is not a file snug-setup reads (only README*, compose files, Dockerfile*, Makefile, package.json, pyproject.toml, go.mod, Cargo.toml, CONTRIBUTING*, .env.example in the target directory)", ErrRefused, name)
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return "", fmt.Errorf("cannot open the target directory %s: %w", target, err)
	}
	defer root.Close()
	li, err := root.Lstat(name)
	if err != nil {
		return "", fmt.Errorf("cannot read %s in %s: %w", name, target, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s is a symlink; snug-setup does not follow links", ErrRefused, name)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("cannot read %s in %s: %w", name, target, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", ErrRefused, name)
	}
	body, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", name, err)
	}
	return Digest(name, body), nil
}
