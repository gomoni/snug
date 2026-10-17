package policy

import (
	"fmt"
	"path/filepath"
)

// AccountHome returns the home directory snug uses: the account database's
// (pwDir, field 6 of the passwd entry), unchanged.
//
// The environment the invoking shell exported has no say: a different HOME
// would not move the sandbox's home, which is always this one, and reading it
// would only give the account database a second, weaker voice. An empty pwDir
// is refused rather than answered from anywhere else, and so is a relative
// one. Every error names what to change.
func AccountHome(pwDir string) (string, error) {
	if pwDir == "" {
		return "", fmt.Errorf("the account database gives this user no home directory (getent passwd " +
			"field 6 is empty); give the account one (usermod -d <dir>). snug has no fallback for it")
	}
	if !filepath.IsAbs(pwDir) {
		return "", fmt.Errorf("the account database's home directory %q is not absolute; give the "+
			"account an absolute one (usermod -d <dir>)", VisibleText(pwDir))
	}
	return pwDir, nil
}

// systemTrees are the directories a home directory must not be, by canonical
// path. @home puts a writable tmpfs at the home, so a home of one of these
// would let a payload write files every program reads (for /etc, ld.so.preload).
// Exact match only: a home beneath one is an ordinary, if odd, home.
var systemTrees = []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
	"/sbin", "/snug", "/sys", "/tmp", "/usr", "/var"}
