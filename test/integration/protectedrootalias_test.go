//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtectedRootRefusedThroughBindAlias fails if a grant that reaches one of
// snug's own state directories through a second mount of it (a bind, which is
// what a distrobox /run/host/... copy of /home is) is accepted while the same
// directory spelled directly is refused. Redteam r9 got every row below to
// exit 0 on such a host, and the toolchain row to plant a file in the tree the
// engine executes crun from.
//
// The test makes the alias itself: it runs the shipped snug under a bwrap whose
// root is the host's with the scratch directories bound a second time under
// S/alias, so the refusal must come from the mount table, since no string
// comparison relates alias/data/snug to xdgdata/snug. Each row asserts exit 77,
// the refusal's own words, the "second mount" sentence and the alias spelling;
// the control row (a bind of an unrelated directory) must resolve, which also
// shows the wrapper and the environment are sound.
//
// What it does not show: the per-run row is placed by the name prefix
// snug-<uid>- under $TMPDIR, which is how the engine finds per-run
// directories; a run directory registered anywhere else is not covered here.
// The toolchain row stops at the dry-run's refusal and does not run an engine.
func TestProtectedRootRefusedThroughBindAlias(t *testing.T) {
	budget(t)
	requireSandbox(t)

	s, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	perRun := filepath.Join(s, fmt.Sprintf("snug-%d-42", uid))
	for _, d := range []string{
		"xdgdata/snug/engines/k", "xdgrt/snug", "xdgcfg/snug/profiles.d", "clean/usr/local/bin",
		"unrelated", "proj",
		"alias/data", "alias/eng", "alias/rt", "alias/cfg", "alias/clean", "alias/perrun", "alias/other",
	} {
		if err := os.MkdirAll(filepath.Join(s, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(perRun, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s, "xdgdata/snug/engines/k/x.pub"),
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA throwaway\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	al := func(n string) string { return filepath.Join(s, "alias", n) }
	profiles := `
[profile.rt-ro]
description = "reads the runtime directory through an alias"
ro = ["` + al("rt") + `/snug"]
[profile.store-ro]
description = "reads the engine store through an alias"
ro = ["` + al("data") + `/snug"]
[profile.procroot-ro]
description = "reads the engine store spelled through /proc/self/root"
ro = ["/proc/self/root` + al("data") + `/snug"]
[profile.store-new-rw]
description = "writes under the engine store through an alias"
rw = ["` + al("data") + `/snug/engines/new"]
[profile.sub-ro]
description = "reads a subdirectory bind of the engine store"
ro = ["` + al("eng") + `/k"]
[profile.submounts-ro]
description = "reads a directory that carries the other binds as submounts"
ro = ["` + filepath.Join(s, "alias") + `"]
[profile.cfg-rw]
description = "writes the configuration through an alias"
rw = ["` + al("cfg") + `/snug"]
[profile.key]
description = "pins a key from the engine store through an alias"
[profile.key.identity.ssh]
agent = "proxy"
key = "` + al("data") + `/snug/engines/k/x.pub"
[profile.toolchain-rw]
description = "writes the engine toolchain through an alias"
rw = ["` + al("clean") + `/usr/local/bin"]
[profile.perrun-ro]
description = "reads a per-run engine directory through an alias"
ro = ["` + al("perrun") + `"]
[profile.other-ro]
description = "reads an unrelated directory"
ro = ["` + al("other") + `"]
`
	if err := os.WriteFile(filepath.Join(s, "xdgcfg/snug/profiles.d/p.toml"), []byte(profiles), 0o644); err != nil {
		t.Fatal(err)
	}

	acct := newAuthoredAccount(t)
	wrap := func(args ...string) []string {
		full := append([]string{"--unshare-user", "--die-with-parent"}, acct.Root...)
		full = append(full, "--dev-bind", "/dev", "/dev", "--bind", "/proc", "/proc")
		for _, b := range [][2]string{
			{"xdgdata", "data"}, {"xdgdata/snug/engines", "eng"}, {"xdgrt", "rt"}, {"xdgcfg", "cfg"},
			{"clean", "clean"}, {filepath.Base(perRun), "perrun"}, {"unrelated", "other"},
		} {
			full = append(full, "--bind", filepath.Join(s, b[0]), al(b[1]))
		}
		full = append(full, acct.Account...)
		return append(full, "--", snugBin)
	}
	env := baseEnv(
		"XDG_DATA_HOME="+filepath.Join(s, "xdgdata"),
		"XDG_RUNTIME_DIR="+filepath.Join(s, "xdgrt"),
		"XDG_CONFIG_HOME="+filepath.Join(s, "xdgcfg"),
		"TMPDIR="+s,
		"SNUG_PODMAN_ROOT="+filepath.Join(s, "clean"),
	)
	proj := filepath.Join(s, "proj")
	run := func(args ...string) (string, int) {
		t.Helper()
		full := append(wrap(), append([]string{"--dry-run"}, args...)...)
		full = append(full, proj, "--", "/bin/true")
		return runBwrapEnv(t, env, acct.Files(t), full)
	}

	out, code := run("-p", "other-ro")
	if code != 0 {
		if strings.Contains(out, "bwrap:") {
			t.Skipf("the alias wrapper could not be built here:\n%s", out)
		}
		t.Fatalf("control: an unrelated alias was refused (exit %d), so the wrapper or environment is wrong:\n%s", code, out)
	}

	for _, tc := range []struct {
		name  string
		args  []string
		want  string
		alias string
	}{
		{"runtime dir ro", []string{"-p", "rt-ro"}, "runtime directory", al("rt") + "/snug"},
		{"engine store ro", []string{"-p", "store-ro"}, "engine store", al("data") + "/snug"},
		{"engine store via /proc/self/root", []string{"-p", "procroot-ro"}, "", "/proc/self/root" + al("data") + "/snug"},
		{"engine store rw new subdir", []string{"-p", "store-new-rw"}, "engine store", al("data") + "/snug/engines/new"},
		{"subdirectory bind of the store", []string{"-p", "sub-ro"}, "engine store", al("eng") + "/k"},
		{"grant carrying the binds as submounts", []string{"-p", "submounts-ro"}, "runtime directory", filepath.Join(s, "alias")},
		{"config rw", []string{"-p", "cfg-rw"}, "trusted configuration", al("cfg") + "/snug"},
		{"identity key in the store", []string{"-p", "key"}, "inside snug's engine store", al("data") + "/snug/engines/k/x.pub"},
		{"toolchain tree rw", []string{"-p", "@podman-socket", "-p", "toolchain-rw"}, "container engine toolchain root", al("clean") + "/usr/local/bin"},
		{"per-run dir ro", []string{"-p", "perrun-ro"}, "per-run", al("perrun")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run(tc.args...)
			if code != exitPolicyCode {
				t.Fatalf("exit %d, want %d:\n%s", code, exitPolicyCode, out)
			}
			for _, w := range []string{tc.want, "second mount", tc.alias} {
				if !strings.Contains(out, w) {
					t.Errorf("refusal does not contain %q:\n%s", w, out)
				}
			}
		})
	}
}

// runBwrapEnv is runBwrap with an environment of the caller's choosing.
func runBwrapEnv(t *testing.T, env []string, files []*os.File, args []string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	cmd.Env = env
	cmd.ExtraFiles = files
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bwrap did not finish within %s:\n%s", cmdTimeout, out)
	}
	var ee *exec.ExitError
	if err != nil {
		if !errors.As(err, &ee) {
			t.Fatalf("running bwrap: %v\n%s", err, out)
		}
		return string(out), ee.ExitCode()
	}
	return string(out), 0
}
