package getent

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// Candidates are the only places snug looks for getent, in order. $PATH is
// never consulted: a getent found there is a program the invoking user's
// environment chose, and snug would run it before any sandbox exists, with
// the user's full authority.
var Candidates = []string{"/usr/bin/getent", "/bin/getent"}

// Locate returns the path of the first Candidates entry that
// policy.TrustedExecutable accepts, or an error naming each candidate and why
// it was refused, and the package that provides getent. It is the ONE answer,
// shared by every lookup and by `snug doctor`, so a doctor report and an
// actual run's refusal cannot disagree about whether getent is there.
// A variable so a test can simulate a host with any getent, or none.
var Locate = func() (string, error) {
	return locate(osLinks{}, os.Getuid(), Candidates)
}

type osLinks struct{}

func (osLinks) Lstat(p string) (fs.FileInfo, error) { return os.Lstat(p) }
func (osLinks) Readlink(p string) (string, error)   { return os.Readlink(p) }

func locate(h policy.HostLinks, uid int, candidates []string) (string, error) {
	var reasons []string
	for _, c := range candidates {
		err := policy.TrustedExecutable(h, uid, c)
		if err == nil {
			return c, nil
		}
		reasons = append(reasons, c+": "+err.Error())
	}
	return "", fmt.Errorf("snug reads this account's name and home directory only from getent at a "+
		"root-owned path, and none is usable: %s. Install getent there (glibc: glibc / libc-bin / "+
		"glibc-common; musl: musl-utils). snug does not search $PATH for it.",
		strings.Join(reasons, "; "))
}
