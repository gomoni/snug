//go:build snugfixture

package cli

import "os"

// fixtureAccountHomeEnv names the directory this binary reports as the
// account's home. Only a binary built with -tags snugfixture reads it: the
// integration suite uses a scratch directory as the home, which the real
// account database does not know. Name and group still come from the real source, so
// only the home is replaced. No install or release target passes the tag.
const fixtureAccountHomeEnv = "SNUG_FIXTURE_ACCOUNT_HOME"

func init() {
	home := os.Getenv(fixtureAccountHomeEnv)
	if home == "" {
		return
	}
	real := lookupHostAccount
	lookupHostAccount = func() (name, pwHome, gname, from string, err error) {
		name, _, gname, from, err = real()
		return name, home, gname, from + " with the home replaced by " + fixtureAccountHomeEnv, err
	}
}
