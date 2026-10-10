package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestBindFDPinsTheOpenedInodeNotThePath fails if bwrap, given a grant source
// by descriptor, re-resolves anything by path: after the source is opened the
// granted directory is renamed away and a symlink to a secret directory takes
// its name, and the sandbox must still show the directory that was opened.
// This is the ticket's race made deterministic: the swap happens at the one
// point the real run is exposed (sources opened, bwrap not yet started) instead
// of being waited for.
//
// It drives openBindSources and a hand-written bwrap argv, not sandbox.Run,
// because Run re-execs /proc/self/exe as a hidden verb that a test binary does
// not carry. What it therefore does NOT show is that Run opens the sources
// before it starts bwrap; that ordering is exercised by the concurrent-swap
// integration test, which runs the real binary.
//
// The control is the same run without the swap: it must print BENIGN, so a
// sandbox that cannot show the directory at all does not pass as "did not show
// the secret".
func TestBindFDPinsTheOpenedInodeNotThePath(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipOrFailSandbox(t, "bubblewrap is not installed")
	}
	if err := requireBindFD(bwrap); err != nil {
		skipOrFailSandbox(t, err.Error())
	}

	launch := func(t *testing.T, swap bool) string {
		root := t.TempDir()
		granted := filepath.Join(root, "work", "d")
		secretDir := filepath.Join(root, "secret")
		for _, d := range []string{granted, secretDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		write := func(path, s string) {
			if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write(filepath.Join(granted, "f"), "BENIGN\n")
		write(filepath.Join(secretDir, "f"), "RACE-SECRET\n")

		p := &policy.Policy{Mounts: map[string]policy.Mount{
			"/mnt/x": {Guest: "/mnt/x", Host: granted, Kind: policy.KindBind},
		}}
		var extra []*os.File
		defer func() {
			for _, f := range extra {
				f.Close()
			}
		}()
		fds, err := openBindSources(p, &extra, func() int { return 3 + len(extra) })
		if err != nil {
			t.Fatal(err)
		}

		if swap {
			moved := filepath.Join(root, "work", "moved")
			if err := os.Rename(granted, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(secretDir, granted); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(filepath.Join(granted, "f")); err != nil || string(got) != "RACE-SECRET\n" {
				t.Fatalf("control: the swapped path does not lead to the secret on the host (%q, %v)", got, err)
			}
		}

		args := []string{"--unshare-user", "--unshare-pid", "--die-with-parent",
			"--ro-bind", "/usr", "/usr",
			"--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
			"--ro-bind-fd", strconv.Itoa(fds["/mnt/x"]), "/mnt/x",
			"--", "/usr/bin/cat", "/mnt/x/f"}
		cmd := exec.Command(bwrap, args...)
		cmd.Env = []string{}
		cmd.ExtraFiles = extra
		out, err := cmd.CombinedOutput()
		if err != nil {
			skipOrFailSandbox(t, "bwrap would not start here, so nothing was measured: "+err.Error()+": "+string(out))
		}
		return string(out)
	}

	if got := launch(t, false); got != "BENIGN\n" {
		t.Fatalf("control: unraced run printed %q, want BENIGN", got)
	}
	got := launch(t, true)
	if strings.Contains(got, "RACE-SECRET") {
		t.Fatalf("bwrap followed the swapped path instead of the opened inode: %q", got)
	}
	if got != "BENIGN\n" {
		t.Errorf("raced run printed %q, want the opened directory's BENIGN", got)
	}
}

// skipOrFailSandbox mirrors the integration suite's rule: SNUG_REQUIRE_SANDBOX=1
// turns "this host cannot run this" into a failure, so a CI run that silently
// measured nothing is not green.
func skipOrFailSandbox(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("SNUG_REQUIRE_SANDBOX") == "1" {
		t.Fatalf("SNUG_REQUIRE_SANDBOX=1 and this host cannot run the test: %s", reason)
	}
	t.Skipf("SKIPPED, not run: %s", reason)
}
