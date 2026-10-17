// Package write reads, diffs and writes profile files.
package write

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gomoni/snug/setup/internal/safe"
)

// maxProfile bounds what ReadProfile reads; a profile is a few hundred bytes.
const maxProfile = 1 << 20

// ReadProfile returns the file at path and whether it exists. A missing file
// is not an error; anything at path that is not a regular file is, and so is
// a file larger than maxProfile.
func ReadProfile(path string) (body string, exists bool, err error) {
	// HOSTREAD-EXEMPT: opened O_NONBLOCK and refused below unless fstat says
	// regular file, so a FIFO at the name cannot block the open or the read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", true, err
	}
	if !fi.Mode().IsRegular() {
		return "", true, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfile+1))
	if err == nil && len(b) > maxProfile {
		err = fmt.Errorf("%s is larger than %d bytes, which no profile snug-setup writes is", path, maxProfile)
	}
	return string(b), true, err
}

// WriteProfile writes body to path: O_EXCL for a new file, so a file that
// appeared since the check is not replaced, and a rename over the old one
// for an overwrite, so a crash leaves either file whole.
func WriteProfile(path, body string, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if !overwrite {
		// HOSTREAD-EXEMPT: O_CREATE|O_EXCL fails on any existing name, FIFO
		// included, so this never opens a file it did not create.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(body); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snug-setup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LineDiff marks the lines only in old with "- " and the lines only in new
// with "+ ", in new's order after old's. It is a summary for a human, not a patch.
func LineDiff(old, new string) string {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			m[l] = true
		}
		return m
	}
	oldSet, newSet := set(old), set(new)
	var out []string
	for _, l := range strings.Split(strings.TrimRight(old, "\n"), "\n") {
		if old != "" && !newSet[l] {
			out = append(out, "- "+safe.Inline(l))
		}
	}
	for _, l := range strings.Split(strings.TrimRight(new, "\n"), "\n") {
		if !oldSet[l] {
			out = append(out, "+ "+l)
		}
	}
	if len(out) == 0 {
		return "(no line changes)"
	}
	return strings.Join(out, "\n")
}
