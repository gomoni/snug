package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both branches, because the failing one is the reason this check exists and a
// test cannot create /dev/net/tun without root. The path is a parameter for
// exactly this.
func TestTunDeviceUsableReportsAnUnopenableNodeWithItsErrno(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "net", "tun")
	detail, ok := tunDeviceUsable(missing)
	if ok {
		t.Fatalf("tunDeviceUsable(%q) said yes for a path that does not exist", missing)
	}
	// The errno is the half a reader acts on: "no such file or directory" sends
	// them to --device or modprobe, "operation not permitted" does not. This is
	// the string pasta itself printed in the CI container that produced this
	// check: "Failed to open() /dev/net/tun: No such file or directory".
	if !strings.Contains(detail, "no such file or directory") {
		t.Errorf("detail = %q, want it to carry the open(2) errno", detail)
	}

	// Positive control: a node that DOES open read-write must pass, or the
	// negative above proves nothing about the check and only that everything
	// fails. /dev/null is the one such node every host in this project's
	// support set has.
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("no /dev/null on this host, so the positive control cannot run")
	}
	if detail, ok := tunDeviceUsable("/dev/null"); !ok {
		t.Errorf("tunDeviceUsable(/dev/null) = %q, want it usable — without this the negative above is vacuous", detail)
	}
}

// The constant the check uses is the path pasta opens. One spelling, so a
// future edit cannot make doctor probe a node pasta does not use.
func TestTheTunPathIsTheOnePastaOpens(t *testing.T) {
	if tunClonePath != "/dev/net/tun" {
		t.Errorf("tunClonePath = %q, want /dev/net/tun — pasta opens the tun clone device by that name", tunClonePath)
	}
}
