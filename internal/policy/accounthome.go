package policy

import (
	"fmt"
	"path/filepath"
)

// AccountHome returns the home directory snug uses: the account database's
// (pwDir, field 6 of the passwd entry), after checking that $HOME (homeEnv),
// when set, names the same directory.
//
// $HOME is whatever the invoking environment exported, so it is not a source
// of the home directory: a $HOME of another directory would make `@home`
// and `{home}/...` grants point somewhere the account database does not, and
// the generated /etc/passwd would then vouch for it. A set $HOME that differs
// is refused, never preferred and never silently replaced. An empty pwDir is
// refused rather than answered from $HOME, and so is a relative one.
//
// The two are compared by realpath, and the returned value is homeEnv when it is
// set so the spelling the human used survives into a refusal that tells them
// what to set instead. It returns pwDir when homeEnv is empty. Every error
// names what to change.
func AccountHome(env Environ, pwDir, homeEnv string) (string, error) {
	if pwDir == "" {
		return "", fmt.Errorf("the account database gives this user no home directory (getent passwd " +
			"field 6 is empty); give the account one (usermod -d <dir>). snug does not fall back to $HOME")
	}
	if !filepath.IsAbs(pwDir) {
		return "", fmt.Errorf("the account database's home directory %q is not absolute; give the "+
			"account an absolute one (usermod -d <dir>)", VisibleText(pwDir))
	}
	if homeEnv == "" {
		return pwDir, nil
	}
	if !filepath.IsAbs(homeEnv) {
		return "", fmt.Errorf("$HOME %q is not absolute; unset HOME, or set HOME=%s",
			VisibleText(homeEnv), VisibleText(pwDir))
	}
	realPw, err := env.EvalSymlinks(pwDir)
	if err != nil {
		return "", fmt.Errorf("the account database's home directory %q: %w", VisibleText(pwDir), err)
	}
	realEnv, err := env.EvalSymlinks(homeEnv)
	if err != nil {
		return "", fmt.Errorf("$HOME %q: %w", VisibleText(homeEnv), err)
	}
	if realPw != realEnv {
		return "", fmt.Errorf("$HOME %q is not this account's home directory %q (getent passwd); snug "+
			"takes the home from the account. Unset HOME, or set HOME=%s",
			VisibleText(homeEnv), VisibleText(pwDir), VisibleText(pwDir))
	}
	return homeEnv, nil
}

// systemTrees are the directories a home directory must not be, by canonical
// path. @home puts a writable tmpfs at the home, so a home of one of these
// would let a payload write files every program reads (for /etc, ld.so.preload).
// Exact match only: a home beneath one is an ordinary, if odd, home.
var systemTrees = []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
	"/sbin", "/snug", "/sys", "/tmp", "/usr", "/var"}
