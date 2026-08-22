//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDryRunJSONIsTheWholeOfStdout is issue #52 end to end, on the real binary,
// and it asserts the one property a unit test cannot: that the DOCUMENT is
// alone on stdout, on every exit code, with the human prose on stderr.
//
// `snug --dry-run --json <dir> > policy.json` yielding a parseable file even
// when the policy is REFUSED is the failure mode this format was designed
// against — clang's SARIF writes 0 bytes on redirect, and a consumer then
// cannot tell "refused" from "the tool died".
func TestDryRunJSONIsTheWholeOfStdout(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	cases := []struct {
		name    string
		args    []string
		code    int
		outcome string
	}{
		// A runnable policy.
		{"ok", []string{"--dry-run", "--json", proj}, 0, "ok"},
		// A refused one. --no-defaults selects nothing, which is the floor of
		// the lattice: no OS runtime, nothing can run in it.
		{"refused", []string{"--dry-run", "--json", "--no-defaults", proj}, 77, "refused"},
		// The short spelling, on the refusal, because a flag that works in one
		// arm and not the other is this project's most-repeated shape.
		{"refused-short", []string{"-n", "-j", "--no-defaults", proj}, 77, "refused"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := split(t, baseEnv(), tc.args...)

			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, stdout, stderr)
			}

			var doc struct {
				Snug struct {
					Format  int    `json:"format"`
					Outcome string `json:"outcome"`
					Lossy   bool   `json:"lossy"`
				} `json:"snug"`
				Refusal *struct {
					Message string `json:"message"`
				} `json:"refusal"`
				Mounts []struct {
					Guest string `json:"guest"`
				} `json:"mounts"`
			}
			if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
				t.Fatalf("stdout is not one parseable JSON document: %v\nstdout:\n%s", err, stdout)
			}
			if doc.Snug.Format != 1 {
				t.Errorf("snug.format is %d, want 1", doc.Snug.Format)
			}
			if doc.Snug.Outcome != tc.outcome {
				t.Errorf("snug.outcome is %q, want %q", doc.Snug.Outcome, tc.outcome)
			}
			if doc.Snug.Lossy {
				t.Errorf("snug.lossy is true for an all-UTF-8 fixture, so a gate asserting it " +
					"would fail closed on an ordinary run")
			}
			// A refused policy is still fully described. "It was refused"
			// without the policy is the half a human cannot act on, and
			// --dry-run's whole job is showing what snug decided.
			if len(doc.Mounts) == 0 {
				t.Errorf("the document lists no mounts")
			}
			if tc.outcome == "refused" {
				if doc.Refusal == nil || doc.Refusal.Message == "" {
					t.Error("a refused policy carries no refusal.message")
				}
				// The human refusal is still on stderr, where every other
				// snug error already goes.
				if !strings.Contains(stderr, "snug:") {
					t.Errorf("the refusal did not reach stderr:\n%s", stderr)
				}
			}

			// --json REPLACES the human screen. Never both: prose interleaved
			// with a document is what makes a consumer parse by luck.
			for _, prose := range []string{"snug — dry run", "FILESYSTEM", "NOT GRANTED", "SECCOMP"} {
				if strings.Contains(stdout, prose) {
					t.Errorf("stdout carries the human screen's %q as well as the document", prose)
				}
			}
		})
	}
}

// TestDryRunJSONAgreesWithTheHumanScreen is the drift check on the REAL binary.
// internal/cli's TestHumanAndJSONFilesystemBlocksAgree drives both renderers in
// process; this one runs snug twice and compares what a person and a program
// are actually told about the same directory.
func TestDryRunJSONAgreesWithTheHumanScreen(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	human, _, code := split(t, baseEnv(), "--dry-run", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, human)
	}
	machine, _, code := split(t, baseEnv(), "--dry-run", "--json", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run --json exited %d:\n%s", code, machine)
	}

	var doc struct {
		Mounts []struct {
			Guest string `json:"guest"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal([]byte(machine), &doc); err != nil {
		t.Fatalf("the machine form is not parseable: %v", err)
	}

	kinds := map[string]bool{
		"bind": true, "tmpfs": true, "link": true, "proc": true, "dev": true,
		"data": true, "graft": true, "cgroup2": true,
		"none": true, "ro": true, "rw": true, "exec": true,
	}
	onScreen := map[string]bool{}
	in := false
	for _, line := range strings.Split(human, "\n") {
		if strings.HasPrefix(line, "FILESYSTEM") {
			in = true
			continue
		}
		if !in {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "ro-/" {
			break
		}
		if len(f) >= 2 && kinds[f[0]] && strings.HasPrefix(f[1], "/") {
			onScreen[f[1]] = true
		}
	}

	if len(onScreen) == 0 || len(doc.Mounts) == 0 {
		t.Fatalf("one of the two renderers listed NO mounts (screen %d, document %d) — a "+
			"comparison of two empty sets passes and tests nothing",
			len(onScreen), len(doc.Mounts))
	}
	inDoc := map[string]bool{}
	for _, m := range doc.Mounts {
		inDoc[m.Guest] = true
	}
	for g := range inDoc {
		if !onScreen[g] {
			t.Errorf("%q is in the document and not on the screen", g)
		}
	}
	for g := range onScreen {
		if !inDoc[g] {
			t.Errorf("%q is on the screen and not in the document", g)
		}
	}
}

// TestFormatFlagIsRefusedWhereThereIsNoFormat closes the argv-drop trap. Each
// of these exited 0 with the human report and the flag silently ignored, which
// hands PROSE to something about to json.Unmarshal under a success code.
//
// stdout must be EMPTY in every case: a usage error's text belongs on stderr,
// and a consumer redirecting stdout must get zero bytes rather than half a
// message it will try to parse.
func TestFormatFlagIsRefusedWhereThereIsNoFormat(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	cases := []struct {
		name string
		args []string
	}{
		// --json names nothing without --dry-run: there is no
		// machine-readable form of an actual run.
		{"no-dry-run", []string{"--json", proj}},
		{"no-dry-run-short", []string{"-j", proj}},
		// …including when it precedes a `--` command, which is a SECOND early
		// return out of parseArgs.
		{"before-command", []string{"--json", proj, "--", "true"}},
		{"doctor", []string{"doctor", "--json"}},
		{"profile-list", []string{"profile", "list", "--json"}},
		{"profile-show", []string{"profile", "show", "@sys", "--json"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := split(t, baseEnv(), tc.args...)
			if code != 64 {
				t.Errorf("exit %d, want 64 (a usage error)\nstdout:\n%s\nstderr:\n%s",
					code, stdout, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout is not empty on a usage error:\n%s", stdout)
			}
			if !strings.Contains(stderr, "snug:") {
				t.Errorf("stderr carries no snug error:\n%s", stderr)
			}
		})
	}

	// POSITIVE CONTROLS. Without them, "every one of those is refused" is
	// equally true of a snug that refuses everything.
	if _, _, code := split(t, baseEnv(), "--dry-run", "--json", proj); code != 0 {
		t.Errorf("--json WITH --dry-run exited %d — the guard refuses more than the "+
			"combination it was written for", code)
	}
	if _, _, code := split(t, baseEnv(), "profile", "list"); code != 0 {
		t.Errorf("`snug profile list` exited %d — the flag guard is refusing arguments that "+
			"are not flags", code)
	}
}

// TestDryRunJSONStartsNothing is issue #21's property for the second renderer.
// The human form is covered by TestDryRunLeavesNoRunDirectoryOrSocket; this is
// the same assertion for the path that did not exist when that test was
// written.
func TestDryRunJSONStartsNothing(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	runtimeDir, err := os.MkdirTemp("", "snugrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })

	stdout, stderr, code := split(t, baseEnv("XDG_RUNTIME_DIR="+runtimeDir),
		"--dry-run", "--json", "-p", "@podman-socket", proj)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	// CONTROL: the container machinery really did run. A dry run that failed
	// before reaching it would leave the runtime directory empty too.
	if !strings.Contains(stdout, "podman.sock") {
		t.Fatalf("the document never names the proxy socket, so it did not reach the "+
			"machinery this test is about:\n%s", stdout)
	}
	if left := entriesUnder(t, runtimeDir); len(left) != 0 {
		t.Errorf("`snug --dry-run --json` created %v under $XDG_RUNTIME_DIR. A dry run "+
			"starts nothing, whichever renderer it uses", left)
	}
}

// split runs snug and returns stdout and stderr SEPARATELY, which cli() cannot:
// it combines them, and every assertion in this file is about which stream a
// byte landed on.
func split(t *testing.T, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	var out, errb strings.Builder
	cmd := exec.CommandContext(ctx, snugBin, args...)
	cmd.Env = env
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.WaitDelay = waitDelay
	err := cmd.Run()

	if ctx.Err() != nil {
		t.Fatalf("snug %s did not finish within %s (a hang is a finding):\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), cmdTimeout, out.String(), errb.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running snug %s: %v", strings.Join(args, " "), err)
		}
		return out.String(), errb.String(), ee.ExitCode()
	}
	return out.String(), errb.String(), 0
}
