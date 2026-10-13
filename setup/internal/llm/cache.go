package llm

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PinnedTag is the llama.cpp release snug-setup is tested against and the only
// one it runs from the cache. scripts/fetch-llama-server.sh pins the same tag
// and a test reads the script to keep the two equal.
const PinnedTag = "b11541"

//go:embed llama-server.manifest
var pinnedManifest string

// manifest is the files of the pinned release that llama-server is or loads.
type manifest struct {
	tag   string
	files []manifestFile
	links []manifestLink
}

type manifestFile struct{ name, sha256 string }
type manifestLink struct{ name, target string }

// parseManifest reads the format of llama-server.manifest: "tag NAME",
// "sha256 HEX NAME" and "link NAME TARGET" lines, '#' comments. Names are
// single path elements; anything else is an error, so a manifest can never
// name a path outside the directory it is applied to.
func parseManifest(s string) (manifest, error) {
	var m manifest
	sc := bufio.NewScanner(strings.NewReader(s))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		bad := func() (manifest, error) {
			return manifest{}, fmt.Errorf("llama-server.manifest line %d: %q is not tag, sha256 or link with a plain file name", n, line)
		}
		switch {
		case f[0] == "tag" && len(f) == 2:
			m.tag = f[1]
		case f[0] == "sha256" && len(f) == 3 && len(f[1]) == 64 && plainName(f[2]):
			m.files = append(m.files, manifestFile{name: f[2], sha256: f[1]})
		case f[0] == "link" && len(f) == 3 && plainName(f[1]) && plainName(f[2]):
			m.links = append(m.links, manifestLink{name: f[1], target: f[2]})
		default:
			return bad()
		}
	}
	if m.tag == "" || len(m.files) == 0 {
		return manifest{}, errors.New("llama-server.manifest has no tag or no files")
	}
	return m, nil
}

func plainName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

func (m manifest) has(name string) bool {
	for _, f := range m.files {
		if f.name == name {
			return true
		}
	}
	for _, l := range m.links {
		if l.name == name {
			return true
		}
	}
	return false
}

// stage copies the files of m from src into dst, hashing each as it is copied,
// and recreates its links. dst must exist and belong to the caller alone. It
// refuses a file that is missing, is not a regular file, or hashes differently,
// and a libggml-*.so in src that m does not name: ggml loads every such
// library it finds beside the binary. The caller runs the copy, never src, so
// nothing can change a file between the check and the exec.
func (m manifest) stage(src, dst string) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", src, err)
	}
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, "libggml-") && strings.Contains(n, ".so") && !m.has(n) {
			return fmt.Errorf("%s holds %s, which is not part of llama.cpp %s; delete %s and run scripts/fetch-llama-server.sh again", src, n, m.tag, filepath.Dir(src))
		}
	}
	for _, f := range m.files {
		if err := copyHashed(filepath.Join(src, f.name), filepath.Join(dst, f.name), f.sha256); err != nil {
			return fmt.Errorf("%w; delete %s and run scripts/fetch-llama-server.sh again", err, filepath.Dir(src))
		}
	}
	for _, l := range m.links {
		if err := os.Symlink(l.target, filepath.Join(dst, l.name)); err != nil {
			return fmt.Errorf("cannot stage %s: %w", l.name, err)
		}
	}
	return nil
}

func copyHashed(from, to, want string) error {
	// HOSTREAD-EXEMPT: O_NONBLOCK makes open(2) on a FIFO planted at from return, and the fstat below refuses anything that is not a regular file.
	in, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("llama.cpp file %s is missing or is a link: %w", from, err)
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", from)
	}
	// HOSTREAD-EXEMPT: to is a new name (O_EXCL) in a directory only the caller can reach, never a host path.
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return fmt.Errorf("cannot stage %s: %w", from, err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("cannot stage %s: %w", from, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(to)
		return fmt.Errorf("%s has sha256 %s, not the %s of llama.cpp's own file; refusing to run it", from, got, want)
	}
	return nil
}
