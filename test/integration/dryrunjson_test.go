//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDryRunJSONIsTheWholeOfStdout is issue #52 end to end, on the real binary,
// and it asserts the one property a unit test cannot: that the DOCUMENT is
// alone on stdout, on every exit code run produces, with the human prose on
// stderr. That qualification is issue #334's: this sentence read "every exit
// code" while five refusal classes wrote nothing at all, and the one exit that
// is still not a document — a flag that does not parse — is named at
// renderJSON rather than left for a redirect to find.
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

// TestDryRunJSONRedirectIsNeverZeroBytes is issue #334 on the real binary, with
// a real file redirect — which is the exact shape the failure is named after.
//
// The unit-level enumeration (internal/cli's
// TestEveryRefusalClassProducesAParseableDocument) drives run() and captures two
// in-process buffers. That is the right place for the class table, and it cannot
// observe the one thing this test is for: that the FILE a shell leaves behind
// parses. clang's SARIF writes zero bytes on redirect, a consumer opens the file
// and cannot tell "refused" from "the tool died", and the two are the same
// number of bytes.
//
// Measured before the fix, `snug --dry-run --json ... > f` for the classes here:
// 0 bytes each, exit 77, with the human diagnostic on stderr as usual. So the
// file said nothing at all and the exit code said only "policy".
func TestDryRunJSONRedirectIsNeverZeroBytes(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	badCfg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(badCfg, "snug", "profiles.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badCfg, "snug", "profiles.d", "bad.toml"),
		[]byte("this is not toml {{{\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		env  []string
		args []string
		// resolved is snug.policy_resolved: a refusal ahead of policy.Resolve
		// has no policy, so its document carries no mounts and must not
		// pretend to by carrying an empty array.
		resolved bool
		// says is a distinctive fragment of the refusal. Without it a case
		// that started hitting a different refusal would still pass every
		// assertion below, which is the "test that cannot fail" shape.
		says string
	}{
		{
			name: "unparseable profile file",
			env:  append(os.Environ(), "XDG_CONFIG_HOME="+badCfg, "SNUG_TEST=1"),
			args: []string{"--dry-run", "--json", proj},
			says: "did not load",
		},
		{
			name: "unknown profile",
			env:  baseEnv(),
			args: []string{"--dry-run", "--json", "-p", "@nosuchprofile", proj},
			says: "unknown profile",
		},
		{
			name: "target does not exist",
			env:  baseEnv(),
			args: []string{"--dry-run", "--json", filepath.Join(proj, "nope")},
			says: "no such file",
		},
		{
			name:     "net-host without --i-know",
			env:      baseEnv(),
			args:     []string{"--dry-run", "--json", "-p", "@net-host", proj},
			resolved: true,
			says:     "--i-know",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			var errb strings.Builder
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, snugBin, tc.args...)
			cmd.Env = tc.env
			cmd.Stdout = f
			cmd.Stderr = &errb
			cmd.WaitDelay = waitDelay
			runErr := cmd.Run()
			f.Close()
			if ctx.Err() != nil {
				t.Fatalf("snug did not finish within %s (a hang is a finding)", cmdTimeout)
			}
			code := 0
			if runErr != nil {
				var ee *exec.ExitError
				if !errors.As(runErr, &ee) {
					t.Fatalf("running snug: %v", runErr)
				}
				code = ee.ExitCode()
			}
			if code != 77 {
				t.Fatalf("exit %d, want 77 — this case is meant to be a refusal\nstderr:\n%s",
					code, errb.String())
			}

			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) == 0 {
				t.Fatalf("the redirected file is ZERO BYTES — a consumer opening it cannot "+
					"tell a refusal from snug having died (issue #334)\nstderr:\n%s", errb.String())
			}

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatalf("the redirected file is not one parseable document: %v\n%s", err, b)
			}
			var meta struct {
				Format         int    `json:"format"`
				Outcome        string `json:"outcome"`
				ExitCode       int    `json:"exit_code"`
				PolicyResolved bool   `json:"policy_resolved"`
			}
			if err := json.Unmarshal(raw["snug"], &meta); err != nil {
				t.Fatalf("no snug block: %v\n%s", err, b)
			}
			if meta.Format != 1 {
				t.Errorf("snug.format is %d, want 1", meta.Format)
			}
			if meta.Outcome != "refused" {
				t.Errorf("snug.outcome is %q, want %q", meta.Outcome, "refused")
			}
			// Against the code the PROCESS returned, not against a constant:
			// a consumer holding only this file must be told what the shell
			// saw.
			if meta.ExitCode != code {
				t.Errorf("snug.exit_code is %d and snug exited %d", meta.ExitCode, code)
			}
			if meta.PolicyResolved != tc.resolved {
				t.Errorf("snug.policy_resolved is %v, want %v", meta.PolicyResolved, tc.resolved)
			}
			// ABSENT, not empty and not null: `"mounts": []` would be a
			// statement about a sandbox by a document that never got one.
			if _, present := raw["mounts"]; present != tc.resolved {
				t.Errorf("`mounts` present=%v, want %v", present, tc.resolved)
			}

			// The positive control on WHICH refusal this is.
			var ref struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(raw["refusal"], &ref); err != nil {
				t.Fatalf("no refusal block: %v\n%s", err, b)
			}
			if !strings.Contains(ref.Message, tc.says) {
				t.Errorf("this case is meant to hit the %q refusal and the document says %q",
					tc.says, ref.Message)
			}
			// The prose is still on stderr and NOT in the file.
			if !strings.Contains(errb.String(), "snug:") {
				t.Errorf("the refusal did not reach stderr:\n%s", errb.String())
			}
			for _, prose := range []string{"snug — dry run", "FILESYSTEM", "NOT GRANTED"} {
				if strings.Contains(string(b), prose) {
					t.Errorf("the redirected file carries the human screen's %q", prose)
				}
			}
		})
	}
}
