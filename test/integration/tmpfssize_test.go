//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── issue #281: config.toml's tmpfs_size_mib, fatal-path coverage ───────────
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

func TestConfigTmpfsSizeMiBZeroIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = 0\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size_mib = 0 should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := "tmpfs_size_mib = 0 would mean an unbounded tmpfs; omit the key for the 1 GiB default"
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

func TestConfigTmpfsSizeMiBNegativeIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = -1\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size_mib = -1 should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := "tmpfs_size_mib = -1 is negative; it must be between 1 and 1048576"
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

func TestConfigTmpfsSizeMiBAboveOneTiBIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	tmpfsConfigControl(t, proj)

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = 1048577\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != exitPolicyCode {
		t.Errorf("tmpfs_size_mib = 1048577 should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	want := "tmpfs_size_mib = 1048577 is too large; it must be between 1 and 1048576 (1 TiB)"
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain the exact message %q:\n%s", want, out)
	}
}

// TestConfigTmpfsSizeMiBAbsentUsesTheBuiltInDefault is the positive half
// pinned as its own test rather than left implicit in the other three's
// control: an absent key must resolve to exactly DefaultTmpfsSize (1 GiB),
// visible in the actual argv --dry-run renders, not just "did not exit 77".
func TestConfigTmpfsSizeMiBAbsentUsesTheBuiltInDefault(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	cfg := writeTmpfsConfig(t, "# no tmpfs_size_mib key\n")
	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", proj)
	if code != 0 {
		t.Fatalf("an absent tmpfs_size_mib should not be fatal, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "--size 1073741824") {
		t.Errorf("the rendered argv does not carry the 1 GiB default (--size 1073741824):\n%s", out)
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
	if !strings.Contains(out, "tmpfs size       1 GiB    (built-in)") {
		t.Errorf("`snug config` does not name the built-in 1 GiB default:\n%s", out)
	}

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = 64\n")
	out, code = cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "config")
	if code != 0 {
		t.Fatalf("`snug config` with tmpfs_size_mib = 64 should succeed, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "tmpfs size       64 MiB") {
		t.Errorf("`snug config` does not report the configured 64 MiB bound:\n%s", out)
	}
	if !strings.Contains(out, filepath.Join(cfg, "snug", "config.toml")) {
		t.Errorf("`snug config` does not name the config FILE as the source of the bound:\n%s", out)
	}
	if strings.Contains(out, "tmpfs size       64 MiB   (built-in)") {
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

	cfg := writeTmpfsConfig(t, "tmpfs_size_mib = 16\n")
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

// TestDevTmpfsIsUnboundedResidual is the HONEST test for the deliberate
// non-fix documented at bwrap.go's KindDev arm: /dev/shm is a directory on
// bwrap's own /dev tmpfs, not a mount of its own, so `--size` — which snug
// applies only to the KindTmpfs mounts it emits — never reaches it.
//
// MEASURED (bwrap 0.11.2, this host): under `--dev /dev`, `findmnt -T
// /dev/shm -no TARGET,FSTYPE,SIZE` reports `/dev tmpfs 27.3G` — i.e. shm is
// plain space on /dev's own superblock, sized from host RAM like every
// unsized tmpfs bwrap creates. `dd if=/dev/zero of=/dev/shm/x bs=1M count=32`
// wrote the full 32 MiB with exit 0.
//
// This test does not assert a bug — it asserts the LIMIT of this lane's fix,
// on purpose, so the follow-up (fixing it costs `/dev` from snug's documented
// eight-path writable surface, per bwrap.go's own comment — a maintainer
// decision, not this lane's) has a test to FLIP rather than a paragraph to
// rediscover. Issue #281.
func TestDevTmpfsIsUnboundedResidual(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `echo TMP_SIZE=$(findmnt -no SIZE -T /tmp | tr -d " ")
dd if=/dev/zero of=/dev/shm/x bs=1M count=32 2>&1
echo SHM_RC=$?
echo SHM_BYTES=$(stat -c %s /dev/shm/x)
echo SHM_SIZE=$(findmnt -no SIZE -T /dev/shm | tr -d " ")
echo MARKER_DONE`).mustRun(t)
	if !strings.Contains(r.out, "MARKER_DONE") {
		t.Fatalf("the payload did not reach its own marker:\n%s", r.out)
	}

	// POSITIVE CONTROL: /tmp IS bounded at the default 1 GiB in this same
	// sandbox, so the /dev/shm finding below cannot be explained by a sandbox
	// that applies no bound anywhere, or one that never started.
	if !strings.Contains(r.out, "TMP_SIZE=1G") {
		t.Fatalf("control: /tmp is not reported as bounded (want TMP_SIZE=1G) in this same "+
			"run, so the /dev/shm assertions below prove nothing:\n%s", r.out)
	}

	if !strings.Contains(r.out, "SHM_RC=0") {
		t.Errorf("a 32 MiB write to /dev/shm did NOT succeed — if this /dev/shm has become "+
			"bounded, the abuse sentence at bwrap.go's KindDev arm needs updating and this test "+
			"should be flipped to a negative assertion:\n%s", r.out)
	}
	if !strings.Contains(r.out, "SHM_BYTES=33554432") {
		t.Errorf("the file at /dev/shm/x is not the full 32 MiB written, which is a different "+
			"finding than this test documents:\n%s", r.out)
	}
	// /dev/shm's reported size must NOT equal /tmp's 1G bound — it comes from
	// the host's RAM via bwrap's own --dev default, not from anything snug set.
	if strings.Contains(r.out, "SHM_SIZE=1G") {
		t.Errorf("findmnt reports /dev/shm at 1G, the same as /tmp's configured bound — this "+
			"would mean /dev/shm has started being sized by snug, contradicting this test's own "+
			"premise:\n%s", r.out)
	}
}
