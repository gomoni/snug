package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/test/modroot"
)

// ── every network step in the engine container classifies its own failure ────
//
// test/engine-container.sh reaches the network three times before a single
// test runs — the image pull, the zypper refresh, the zypper install — and
// each of those is a MEASURED way this job dies printing no test name, no
// `--- FAIL` and no `engine tests: N ran` line (issue #478). Left unclassified
// they surface as the exit code of whichever tool gave up:
//
//	make: *** [Makefile:394: integration-engine] Error 4
//
// which is zypper's 4 and reads like a count of failed tests. Reruns became
// the reflex, and the reflex is how a real failure eventually gets waved
// through.
//
// This sweep is text over the script rather than a run of it, deliberately.
// The functional path needs kernel.apparmor_restrict_unprivileged_userns=0,
// which only the engine job's own runner sets — a test that skipped everywhere
// else would be a test that never runs in the gate. What CAN be checked
// anywhere is the property that actually decays: somebody adds a FOURTH
// network step and does not classify it.
func TestEveryNetworkStepInTheEngineContainerNamesItselfOnFailure(t *testing.T) {
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "test", "engine-container.sh")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")

	// The three tools that touch the network, matched where they are CALLED —
	// at the start of a command, not inside a comment or a string. `curl` and
	// `wget` are not in the script today; they are here so that adding one is
	// caught rather than so that something is currently matched.
	call := regexp.MustCompile(`^\s*(zypper|curl|wget)\s|^\s*"\$RUNTIME"\s+(pull|run)\b`)

	// A call is classified when infra_fail appears in the same command or in
	// the few lines that follow it. "The same command" is not one line: the
	// install lists twenty-five packages over seven continuation lines, so the
	// search runs to the END of the command — through every trailing `\` — and
	// only then allows a short window for the `[ "$rc" -eq 0 ] || infra_fail`
	// guard, which itself wraps.
	const window = 3

	found := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !call.MatchString(line) {
			continue
		}
		// The one call that must NOT be classified: `"$RUNTIME" run`, which is
		// the suite itself. A test failure inside it is exactly what this job
		// exists to report, and calling it infrastructure would be the bug
		// this whole change is against, facing the other way.
		if strings.Contains(line, `"$RUNTIME" run`) {
			continue
		}
		found++
		end := i
		for end+1 < len(lines) && strings.HasSuffix(strings.TrimRight(lines[end], " \t"), "\\") {
			end++
		}
		classified := false
		for j := i; j < len(lines) && j <= end+window; j++ {
			if strings.Contains(lines[j], "infra_fail") {
				classified = true
				break
			}
		}
		if !classified {
			t.Errorf("%s:%d reaches the network and does not classify its own failure:\n\t%s\n"+
				"Add `|| rc=$?` and a `[ \"$rc\" -eq 0 ] || infra_fail ...` guard, so a red run "+
				"says whether a test failed or an openSUSE mirror did (issue #478).",
				filepath.Join("test", "engine-container.sh"), i+1, strings.TrimSpace(line))
		}
	}

	// The positive control the sweeps here all carry: a matcher that matches
	// nothing passes vacuously, and this one is one refactor away from that —
	// the script could rename $RUNTIME or move the zypper calls into a
	// function and the loop above would report a clean bill of health over
	// zero call sites.
	if found < 3 {
		t.Fatalf("matched %d network call sites in %s, want at least 3 (the image pull, "+
			"the zypper refresh, the zypper install). The matcher has stopped seeing the "+
			"script, not the script stopped reaching the network.", found, path)
	}

	// infra_fail's contract, asserted where it is written rather than trusted:
	// the job still FAILS (invariant 5 — a refresh that leaves the container
	// unusable must not read as green), and it fails with a code that carries
	// the classification.
	src := string(b)
	for _, want := range []string{
		"readonly EX_TEMPFAIL=75",
		`exit "$EX_TEMPFAIL"`,
		"NO TEST RAN",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("%s no longer contains %q — infra_fail's whole contract is that the job "+
				"stays red AND says which kind of red it is", path, want)
		}
	}
}
