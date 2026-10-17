package cli

import (
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/sandbox"
)

// snugExecutable is the running snug binary, canonical, for the
// exec-credential shim identity.kube binds into the sandbox. "" when it cannot
// be named, which Resolve refuses for a kube identity and ignores otherwise.
func snugExecutable() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return real
}

// hostAddressesForResolve feeds identity.kube's host-owned-server refusal. It
// is a usability check, not the seal, so an interface enumeration that fails
// leaves it empty rather than refusing the run; the stage enumerates again and
// does refuse.
func hostAddressesForResolve() []string {
	a, err := sandbox.HostAddresses()
	if err != nil {
		return nil
	}
	return a
}
