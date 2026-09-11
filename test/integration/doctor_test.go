//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDoctorRunsCleanOnAHostThatCanRunSnug is the regression for a gap CI found
// and the committed suite did not: `snug doctor` had no test at all.
//
// CI runs `./bin/snug doctor` as its own step, and its comment says why —
// "doctor is the first thing a human runs". But that made CI the ONLY thing
// exercising it, so a change to a constructor doctor calls could pass `make
// gate` and `make integration` locally and fail after the push. That is exactly
// what happened when issue #125's C2-gate made stage.Config.BwrapInfo required:
// doctor's stage probe is the one caller that starts a stage and deliberately
// never starts a sandbox, so it was the one caller nobody updated, and it went
// from a green tick to `🚫 snug cannot run on this host as configured` with
// exit 69.
//
// The probe it guards is not incidental. doctor's own comment argues that a
// probe which APPROXIMATES the code path can pass while the code path fails,
// which is why it calls the real stage.Start rather than re-typing the clone
// flags. This test is the same argument one level up: a `make gate` that never
// runs the binary can pass while the binary is broken.
//
// It asserts a clean exit rather than parsing the whole report, because the
// report legitimately differs by host — pasta may be absent, podman may be a
// shim, TIOCSTI may be enabled. What must not differ is that a host which CAN
// run snug is told so.
//
// XDG_CONFIG_HOME IS AN EMPTY DIRECTORY, AND WITHOUT THAT THIS TEST GRADES THE
// DEVELOPER'S DOTFILES. doctor reads the real profile store and reports `❌ 1
// profile file(s) did not load` for anything in it that does not parse — which is
// doctor working, and is the right thing for a human to be told. But it made the
// verdict of a repository test depend on state no reader of the repository can
// see: anyone whose ~/.config/snug/profiles.d predates a schema change fails here,
// with nothing in the tree to fix. Measured during #454's rename: a personal
// accounts.toml still carrying the flat identity keys turned this green tick into
// a FAIL on the maintainer's machine while `make gate` stayed clean.
//
// Nothing is lost by isolating it. This test exists for the stage probe and for
// host capability; whether a profile file parses is covered by every test that
// WRITES one, and there are dozens.
func TestDoctorRunsCleanOnAHostThatCanRunSnug(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	cmd := exec.Command(snugBin, "doctor")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	report := string(out)
	if err != nil {
		t.Fatalf("snug doctor failed on a host the rest of this suite runs on: %v\n%s", err, report)
	}

	// The stage line specifically, because it is the one this test was written
	// for and the one whose caller is unique. A clean exit alone would also pass
	// on a doctor that stopped probing the stage altogether.
	if !strings.Contains(report, "stage starts") {
		t.Errorf("doctor's report does not mention the stage probe at all, so a clean exit "+
			"here proves nothing about it:\n%s", report)
	}
	if strings.Contains(report, "❌") {
		t.Errorf("doctor reported a hard failure on a host that can run snug:\n%s", report)
	}

	// The inherited-hardening block (issue #526), by the one phrase all three
	// of its arms share — all five set, some weak, or some absent — because
	// which arm fires depends on the host and this test runs on several.
	// Without this, doctor could stop reading those five knobs entirely and
	// every assertion above would still pass: the block is WARN-only by
	// design, so its disappearance costs no ❌ and no exit code.
	if !strings.Contains(report, "threat model inherits") {
		t.Errorf("doctor's report says nothing about the kernel knobs snug's threat model "+
			"inherits from the host (issue #526):\n%s", report)
	}

	// The three sections, in order, and one row placed INSIDE the right one.
	// Asserting the headers alone would pass on a doctor that printed all
	// three and then every row under the last of them — which is what a
	// careless reorder produces, and it reads as fine until someone is
	// looking for what to install.
	programs := strings.Index(report, "🧰 programs")
	kernel := strings.Index(report, "🐧 kernel")
	host := strings.Index(report, "🏠 host configuration")
	if programs < 0 || kernel < 0 || host < 0 {
		t.Fatalf("doctor's report is missing a section header (programs=%d kernel=%d host=%d):\n%s",
			programs, kernel, host, report)
	}
	if !(programs < kernel && kernel < host) {
		t.Errorf("doctor's sections are out of order (programs=%d kernel=%d host=%d):\n%s",
			programs, kernel, host, report)
	}
	// bubblewrap is a binary a package manager installs; the userns probe is
	// what the kernel does or does not allow. They were adjacent before the
	// grouping and belong in different sections now.
	if bwrap := strings.Index(report, "bubblewrap"); bwrap < programs || bwrap > kernel {
		t.Errorf("the bubblewrap row is not in the programs section (at %d, section %d..%d):\n%s",
			bwrap, programs, kernel, report)
	}
	if knobs := strings.Index(report, "threat model inherits"); knobs < kernel || knobs > host {
		t.Errorf("the inherited-sysctl row is not in the kernel section (at %d, section %d..%d):\n%s",
			knobs, kernel, host, report)
	}
	if prof := strings.Index(report, "profiles load"); prof < host {
		t.Errorf("the profile-set row is not in the host-configuration section (at %d, section "+
			"starts %d):\n%s", prof, host, report)
	}
}

// TestDoctorReportsAProfileFileThatDidNotLoad is the counterpart to the empty
// XDG_CONFIG_HOME above, and it exists because that isolation removed the only
// thing in the suite that exercised this row.
//
// Before the isolation, doctor's profile-set check was graded by accident: it
// passed on a developer whose store was clean and failed on one whose store was
// stale, and in neither case was the row ASSERTED. So the check could have been
// deleted outright and the suite would have gone greener rather than red. This is
// the same shape as a sweep that skips every field and passes — the thing that
// makes a guard worth having is a test that fails when it stops guarding.
//
// The fixture is a profile that parses as TOML and is refused by snug, rather than
// malformed TOML: a broken parse would also fire this row, but it would not tell
// us the row survives a refusal that comes from snug's own rules.
func TestDoctorReportsAProfileFileThatDidNotLoad(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	cfg := t.TempDir()
	if err := os.MkdirAll(cfg+"/snug/profiles.d", 0o700); err != nil {
		t.Fatal(err)
	}
	// An [identity] block that sets nothing: legal TOML, refused by toIdentity.
	if err := os.WriteFile(cfg+"/snug/profiles.d/stale.toml",
		[]byte("[profile.stale]\n[profile.stale.identity]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(snugBin, "doctor")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+cfg)
	out, err := cmd.CombinedOutput()
	report := string(out)

	// The EXIT CODE, because that is what CI keys on and what the row above this
	// one in the suite (the clean-host test) asserts the absence of. A doctor that
	// printed the ❌ and exited 0 would pass every string check below.
	if err == nil {
		t.Errorf("snug doctor exited 0 on a profile store it refuses:\n%s", report)
	}
	if !strings.Contains(report, "did not load") {
		t.Errorf("doctor says nothing about a profile file it could not load, so the "+
			"profile-set row is not reporting refusals:\n%s", report)
	}
	if !strings.Contains(report, "stale.toml") {
		t.Errorf("doctor's report does not NAME the file that did not load, which is the "+
			"only part a human can act on:\n%s", report)
	}
	if !strings.Contains(report, "❌") {
		t.Errorf("a profile store snug refuses is a hard failure, not a warning, because "+
			"snug will not start a sandbox: no ❌ in:\n%s", report)
	}
}
