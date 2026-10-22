package hostfacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
)

// SSHKey is one public key file under ~/.ssh.
type SSHKey struct {
	Stem        string // file name without .pub
	Path        string // absolute path of the .pub file
	Type        string // ssh-ed25519, ssh-rsa, ...
	Comment     string // the trailing comment, control characters removed
	Blob        string // base64 key blob, the identity the agent is matched on
	Fingerprint string // SHA256:... as ssh-keygen -l prints it
	InAgent     bool   // ssh-add -L lists this blob
}

const maxPubSize = 16 << 10

// FingerprintOf returns the SHA256:... fingerprint of a base64 key blob, or an
// error when the blob is not valid base64.
func FingerprintOf(blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("not a base64 key blob")
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}

// parsePub parses the first line of an OpenSSH public key file.
func parsePub(line string) (typ, blob, comment string, err error) {
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") && !strings.HasPrefix(f[0], "sk-") {
		return "", "", "", errors.New("not an OpenSSH public key line")
	}
	if _, err := FingerprintOf(f[1]); err != nil {
		return "", "", "", err
	}
	return f[0], f[1], cleanText(strings.Join(f[2:], " ")), nil
}

// SSHKeys lists ~/.ssh/*.pub under home, sorted by stem, and marks the ones the
// ssh-agent holds. Only *.pub files are opened. Problems that leave the list
// usable (an unreadable or malformed .pub, an agent that cannot be reached)
// come back as warnings; a missing ~/.ssh is an empty list, not a warning.
func SSHKeys(ctx context.Context, home string, run Runner) (keys []SSHKey, warnings []string) {
	matches, _ := filepath.Glob(filepath.Join(home, ".ssh", "*.pub"))
	sort.Strings(matches)
	for _, p := range matches {
		// HOSTREAD-EXEMPT: opened O_NONBLOCK and skipped unless fstat says
		// regular file, so a FIFO named *.pub cannot block the open or the read.
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", p, err))
			continue
		}
		if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
			f.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxPubSize))
		f.Close()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", p, err))
			continue
		}
		line, _, _ := bytes.Cut(data, []byte("\n"))
		typ, blob, comment, err := parsePub(string(line))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s skipped: %v", p, err))
			continue
		}
		fp, _ := FingerprintOf(blob)
		keys = append(keys, SSHKey{
			Stem: strings.TrimSuffix(filepath.Base(p), ".pub"), Path: p, Type: typ,
			Comment: comment, Blob: blob, Fingerprint: fp,
		})
	}
	if len(keys) == 0 {
		return keys, warnings
	}
	res, err := run(ctx, nil, "ssh-add", "-L")
	var ee *exec.ExitError
	switch {
	case errors.Is(err, exec.ErrNotFound):
		warnings = append(warnings, "ssh-add not found: no key is marked as held by the agent")
	case errors.As(err, &ee) && ee.ExitCode() == 1:
		// the agent answered and holds nothing
	case err != nil:
		warnings = append(warnings, fmt.Sprintf("ssh-agent not reachable (ssh-add -L: %v): no key is marked as held by the agent", err))
	}
	held := map[string]bool{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			held[f[1]] = true
		}
	}
	for i := range keys {
		keys[i].InAgent = held[keys[i].Blob]
	}
	return keys, warnings
}
