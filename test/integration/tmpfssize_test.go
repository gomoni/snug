//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ── issue #281: config.toml's tmpfs_size, fatal-path coverage ───────────
//
// loadUserConfig (internal/cli/config.go) calls os.Exit directly on a bad
// value, exactly like the unreadable-config and unknown-profile-key paths
// this suite already covers (TestOnlyAMissingConfigIsANonEvent,
// TestAnUnknownProfileKeyIsFatal). Those establish the mechanism: os.Exit
// inside internal/cli has no seam a unit test can intercept, so the only
// thing that actually observes the exit is a subprocess — this suite's own
// `cli` helper, which runs the real built binary. --dry-run is enough to
// reach loadUserConfig without needing a real sandbox, so none of these five
// tests calls requireSandbox.
//
// A value the parser refuses (a sign, a bare number, a unit that is not a
// unit) exits on the same path: policy.ParseSize's error reaches the screen
// through configDecodeMessage, and loadUserConfig exits 77 for it exactly as
// it does for a value the parser accepts and loadUserConfig then rejects.

func writeTmpfsConfig(t *testing.T, body string) string {
	t.Helper()
	cfg := t.TempDir()
	dir := filepath.Join(cfg, "snug")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// tmpfsConfigControl is the shared positive control for the four fatal cases
// below: the identical invocation with NO config file at all must succeed.
// Without it, "exit 77" could be true of --dry-run itself, or of the target
// fixture, rather than of the specific bad value under test.
func tmpfsConfigControl(t *testing.T, proj string) {
	t.Helper()
	if out, code := cli(t, baseEnv(), "--dry-run", proj); code != 0 {
		t.Fatalf("control: --dry-run with no config file at all must succeed, got %d:\n%s", code, out)
	}
}

func TestConfigTmpfsSizeZeroIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"0 B\"\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size = \"0 B\" should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := `tmpfs_size = "0 B" would mean an unbounded tmpfs; omit the key for the 1 GiB default`
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

func TestConfigTmpfsSizeNegativeIsRefusedByTheParser(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"-1 MiB\"\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size = \"-1 MiB\" should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := `"-1 MiB" does not begin with a number`
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

func TestConfigTmpfsSizeAboveOneTiBIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"2 TiB\"\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size = \"2 TiB\" should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := `tmpfs_size = "2 TiB" is too large; it must be between "1 B" and "1 TiB"`
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

// TestConfigTmpfsSizeAbsentUsesTheBuiltInDefault is the positive half
// pinned as its own test rather than left implicit in the other three's
// control: an absent key must resolve to exactly DefaultTmpfsSize (1 GiB),
// visible in the actual argv --dry-run renders, not just "did not exit 77".
func TestConfigTmpfsSizeAbsentUsesTheBuiltInDefault(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	cfg := writeTmpfsConfig(t, "# no tmpfs_size key\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != 0 {
		t.Fatalf("an absent tmpfs_size should not be fatal, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "--size 1073741824") {
		t.Errorf("the rendered argv does not carry the 1 GiB default (--size 1073741824):\n%s", out)
	}
}

// TestConfigTmpfsSizeMiBNamesItsReplacement is the migration path. The key was
// tmpfs_size_mib and is not any more; a file still carrying it must exit
// rather than start a sandbox with the built-in default, and the message must
// carry the line that replaces it rather than only "unknown key".
func TestConfigTmpfsSizeMiBNamesItsReplacement(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = 512\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size_mib = 512 should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	for _, want := range []string{"tmpfs_size_mib is gone", `tmpfs_size = "512 MiB"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// TestConfigTmpfsSizeBareIntegerIsFatal is the same reader one keystroke
// further along: they deleted `_mib` and left the 512. 512 BYTES is a valid
// byte count and a catastrophic tmpfs, so a bare number is refused rather than
// read — and the refusal has to survive at THIS tier, because the thing that
// would silently accept it is go-toml writing a TOML integer into a
// uint64-kinded field without calling its UnmarshalText.
func TestConfigTmpfsSizeBareIntegerIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size = 512\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size = 512 should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	if strings.Contains(out, "--size 512 ") {
		t.Errorf("a bare 512 was read as 512 BYTES and reached the argv:\n%s", out)
	}
	for _, want := range []string{`"512" has no unit`, `as in "512 MiB"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// TestConfigTmpfsSizeAcceptsBothUnitFamilies is the positive counterpart: the
// bound a user writes is the bound bwrap gets, and `mb` is not `MiB`. 128 MB
// is 128000000 bytes and 128 MiB is 134217728; a parser that quietly read one
// as the other would be invisible in every test that only asserts "some
// --size arrived".
func TestConfigTmpfsSizeAcceptsBothUnitFamilies(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	for _, tc := range []struct {
		value string
		size  string
	}{
		{`"128 MiB"`, "--size 134217728"},
		{`"128 mb"`, "--size 128000000"},
		{`"1 GiB"`, "--size 1073741824"},
	} {
		cfg := writeTmpfsConfig(t, "tmpfs_size = "+tc.value+"\n")
		out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
		if code != 0 {
			t.Fatalf("tmpfs_size = %s should be accepted, got %d:\n%s", tc.value, code, out)
		}
		if !strings.Contains(out, tc.size) {
			t.Errorf("tmpfs_size = %s did not reach the argv as %q:\n%s", tc.value, tc.size, out)
		}
	}
}

// TestConfigTmpfsSizeTableIsFatal: a TOML table at tmpfs_size decodes clean
// and calls no UnmarshalText, so it reaches loadUserConfig as a non-nil zero.
// The refusal must name what tmpfs_size actually takes rather than quote back
// a `"0 B"` the file does not contain.
func TestConfigTmpfsSizeTableIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	for _, body := range []string{"[tmpfs_size]\n", "tmpfs_size = {}\n"} {
		cfg := writeTmpfsConfig(t, body)
		out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
		if code != exitPolicyCode {
			t.Errorf("%q should exit %d, got %d:\n%s", body, exitPolicyCode, code, out)
		}
		if !strings.Contains(out, "tmpfs_size is a quoted size, not a table") {
			t.Errorf("%q: refusal does not say what tmpfs_size takes:\n%s", body, out)
		}
		if strings.Contains(out, `tmpfs_size = "0 B"`) {
			t.Errorf("%q: refusal quotes a value the file does not contain:\n%s", body, out)
		}
	}
}

// TestTmpfsSizeOnScreenIsTheSizeInsideTheSandbox is the honesty of --dry-run
// as a measurement rather than as an intention. tmpfs rounds its size up to a
// whole page, so `tmpfs_size = "1 B"` mounts 4096 bytes; before the rounding
// moved to the config boundary, three separate screens (`snug config`,
// --dry-run's `(max …)`, the JSON facts' size_bytes) and the bwrap argv all
// published 1. Not reachable while the key was tmpfs_size_mib — every value
// was a whole number of MiB and so already aligned.
//
// The assertion is agreement, not a constant: the page size is the host's, so
// the test reads what snug published and compares it with what the kernel
// delivered rather than pinning 4096.
func TestTmpfsSizeOnScreenIsTheSizeInsideTheSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"1 B\"\n")
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	out, code := cli(t, env, "--dry-run", proj)
	if code != 0 {
		t.Fatalf("--dry-run with tmpfs_size = \"1 B\" should succeed, got %d:\n%s", code, out)
	}
	m := regexp.MustCompile(`--size ([0-9]+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no --size in the rendered argv:\n%s", out)
	}
	published := m[1]
	if published == "1" {
		t.Fatalf("--dry-run published --size 1, which no tmpfs can be:\n%s", out)
	}
	if !strings.Contains(out, "(max "+published+" B)") &&
		!strings.Contains(out, "(max 4 KiB)") {
		t.Logf("note: the human column renders the same number in units:\n%s", out)
	}

	// What the kernel actually gave the mount, read from inside.
	res := runEnv(t, env, nil, proj, `stat -f -c %s\ %b /tmp
echo MARKER`).mustRun(t)
	if !strings.Contains(res.out, "MARKER") {
		t.Fatalf("the payload did not reach its own marker:\n%s", res.out)
	}
	var bsize, blocks uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(res.out), "%d %d", &bsize, &blocks); err != nil {
		t.Fatalf("could not read the mount's size from %q: %v", res.out, err)
	}
	delivered := fmt.Sprintf("%d", bsize*blocks)
	if delivered != published {
		t.Errorf("snug published --size %s and the kernel delivered %s bytes on /tmp; "+
			"--dry-run is the mechanism by which a human can trust snug at all",
			published, delivered)
	}
}

// TestConfigCmdNamesTheTmpfsBoundSource pins `snug config`'s own disclosure of
// the bound, in both directions: the built-in default with its origin, and an
// explicit config.toml value with the FILE named as the source rather than
// "(built-in)".
func TestConfigCmdNamesTheTmpfsBoundSource(t *testing.T) {
	budget(t)

	// POSITIVE CONTROL: the built-in default, unset.
	out, code := cli(t, baseEnv(), "config")
	if code != 0 {
		t.Fatalf("control: `snug config` with no config file should succeed, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "tmpfs size       1 GiB      (built-in)") {
		t.Errorf("`snug config` does not name the built-in 1 GiB default:\n%s", out)
	}

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"64 MiB\"\n")
	out, code = cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "config")
	if code != 0 {
		t.Fatalf("`snug config` with tmpfs_size = \"64 MiB\" should succeed, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "tmpfs size       64 MiB") {
		t.Errorf("`snug config` does not report the configured 64 MiB bound:\n%s", out)
	}
	if !strings.Contains(out, filepath.Join(cfg, "snug", "config.toml")) {
		t.Errorf("`snug config` does not name the config FILE as the source of the bound:\n%s", out)
	}
	if strings.Contains(out, "tmpfs size       64 MiB     (built-in)") {
		t.Errorf("`snug config` reports a file-set value as built-in:\n%s", out)
	}
}

// ── issue #281: the bound is enforced INSIDE a real sandbox ─────────────────

// TestTmpfsGrantsAreBoundedInsideTheSandbox is the real-sandbox half of #281:
// a SMALL configured bound (16 MiB, so the test is fast and the negative arm
// does not need to fill anything close to the 1 GiB default) actually caps
// what a payload can write into every KindTmpfs mount, at both $HOME/.cache
// (an @home tmpfs) and /tmp (the base topology's).
//
// Each arm carries its own MARKER (CLAUDE.md: "a test that cannot fail is
// worse than no test" — a payload that never reaches its own marker proves
// nothing about a write that "failed").
func TestTmpfsGrantsAreBoundedInsideTheSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"16 MiB\"\n")
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	for _, tc := range []struct {
		name string
		path string
	}{
		{"tmp", "/tmp/probe"},
		{"home-cache", "$HOME/.cache/probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// POSITIVE CONTROL: a 1 MiB write to the SAME path succeeds. This is
			// what makes the failure below a fact about the 16 MiB bound rather
			// than about a sandbox that never launched, a config that was not
			// read, or a path that does not exist.
			small := runEnv(t, env, nil, proj, fmt.Sprintf(
				`dd if=/dev/zero of=%s bs=1M count=1 2>&1
echo SMALL_RC=$?
rm -f %s
echo MARKER_SMALL`, tc.path, tc.path)).mustRun(t)
			if !strings.Contains(small.out, "MARKER_SMALL") {
				t.Fatalf("the small-write payload did not reach its own marker:\n%s", small.out)
			}
			if !strings.Contains(small.out, "SMALL_RC=0") {
				t.Fatalf("control: a 1 MiB write to %s failed, so the failure below cannot be "+
					"attributed to the 16 MiB bound:\n%s", tc.path, small.out)
			}

			// NEGATIVE: a fresh sandbox, so the mount starts empty — 32 MiB into
			// a 16 MiB tmpfs must fail, and what actually landed must be exactly
			// the bound: 16777216 bytes, not zero (which would mean the write
			// never started) and not some other size (which would mean it is not
			// the configured bound doing the capping).
			big := runEnv(t, env, nil, proj, fmt.Sprintf(
				`dd if=/dev/zero of=%s bs=1M count=32 2>&1
echo BIG_RC=$?
echo BIG_BYTES=$(stat -c %%s %s)
echo BIG_MOUNT_SIZE=$(findmnt -no SIZE -T %s | tr -d " ")
echo MARKER_BIG`, tc.path, tc.path, tc.path)).mustRun(t)
			if !strings.Contains(big.out, "MARKER_BIG") {
				t.Fatalf("the big-write payload did not reach its own marker:\n%s", big.out)
			}
			if strings.Contains(big.out, "BIG_RC=0") {
				t.Errorf("a 32 MiB write into a 16 MiB tmpfs at %s SUCCEEDED:\n%s", tc.path, big.out)
			}
			if !strings.Contains(big.out, "BIG_BYTES=16777216") {
				t.Errorf("the file at %s is not exactly the 16 MiB bound after the failed write:\n%s",
					tc.path, big.out)
			}
			if !strings.Contains(big.out, "BIG_MOUNT_SIZE=16M") {
				t.Errorf("findmnt does not report the mount at %s as 16M:\n%s", tc.path, big.out)
			}
		})
	}
}

// A bound on /dev/shm alone is a two-character path change from defeat, so
// this asserts both halves: shm capped at the configured size, and every
// other path under /dev not writable at all.
//
// MEASURED (bwrap 0.11.2, this host): `touch /dev/escape` and `dd of=/dev/big`
// both fail "Read-only file system"; `findmnt -T /dev/shm -no SIZE` reports
// the configured bound, not host RAM. Issue #281.
func TestDevShmIsBoundedAndDevRootIsReadOnly(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	cfg := writeTmpfsConfig(t, "tmpfs_size = \"16 MiB\"\n")
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	r := runEnv(t, env, nil, proj, `dd if=/dev/zero of=/dev/shm/x bs=1M count=32 2>&1
echo SHM_RC=$?
echo SHM_BYTES=$(stat -c %s /dev/shm/x)
echo SHM_SIZE=$(findmnt -no SIZE -T /dev/shm | tr -d " ")
touch /dev/escape 2>&1
echo TOUCH_RC=$?
dd if=/dev/zero of=/dev/big bs=1M count=32 2>&1
echo BIG_RC=$?
echo MARKER_DONE`).mustRun(t)
	if !strings.Contains(r.out, "MARKER_DONE") {
		t.Fatalf("the payload did not reach its own marker:\n%s", r.out)
	}

	// /dev/shm is bounded at the configured 16 MiB, the same shape as every
	// other snug tmpfs: capped, not merely slow or refused outright.
	if strings.Contains(r.out, "SHM_RC=0") {
		t.Errorf("a 32 MiB write into /dev/shm with a 16 MiB bound configured SUCCEEDED:\n%s", r.out)
	}
	if !strings.Contains(r.out, "SHM_BYTES=16777216") {
		t.Errorf("the file at /dev/shm/x is not exactly the 16 MiB bound after the capped write:\n%s",
			r.out)
	}
	if !strings.Contains(r.out, "SHM_SIZE=16M") {
		t.Errorf("findmnt does not report /dev/shm as its own 16M mount:\n%s", r.out)
	}

	// /dev's root is read-only, so the bound above cannot be sidestepped by
	// writing to a path that is not /dev/shm.
	if strings.Contains(r.out, "TOUCH_RC=0") {
		t.Errorf("touch /dev/escape SUCCEEDED — /dev's root is not read-only, so the /dev/shm "+
			"bound above can be defeated at any other path under /dev:\n%s", r.out)
	}
	if strings.Contains(r.out, "BIG_RC=0") {
		t.Errorf("a 32 MiB write to /dev/big SUCCEEDED — /dev/shm's bound is sidesteppable:\n%s",
			r.out)
	}
}
