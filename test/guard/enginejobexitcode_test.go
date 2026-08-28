package guard

import (
	"regexp"
	"strings"
	"testing"
)

// THE ENGINE JOB'S EXIT CODE IS THE SCRIPT'S, NOT MAKE'S (issue #505).
//
// test/engine-container.sh classifies its own network failures and exits 75,
// EX_TEMPFAIL, with a message that says so:
//
//	engine-container: zypper refresh exited 4.
//	                  NO TEST RAN. This is openSUSE repository metadata — mirror
//	                  lag, a dead mirror or a CDN timeout, not a snug regression.
//	                  Exiting 75 (EX_TEMPFAIL) so the code says so too.
//
// Invoked through `make`, that last sentence is FALSE, and CI said so two lines
// later in run 33165401841:
//
//	make: *** [Makefile:395: integration-engine] Error 75
//	##[error]Process completed with exit code 2
//
// GNU make exits 2 on any recipe failure whatever the recipe exited. MEASURED
// on its own, so the claim does not rest on reading GitHub's rendering:
//
//	$ printf 't:\n\t@exit 75\n' > Makefile.probe
//	$ make -f Makefile.probe t; echo "make exit=$?"
//	make: *** [Makefile.probe:2: t] Error 75
//	make exit=2
//
// WHY THIS IS A TEST AND NOT A COMMENT. The classification's whole purpose is
// to be machine-readable — a retry step someone adds later, a human scripting
// the difference between an infra incident and a failing test. Restoring
// `run: make integration-engine` would be a one-word edit that reads as
// harmless, changes no behaviour a human notices (the job goes red either way,
// which #486 chose deliberately), and silently deletes the only thing that
// distinguishes the two. That is precisely the class a comment does not catch.
//
// It cannot be fixed in the Makefile and this test must not be "fixed" that
// way: catching 75 in the recipe to re-raise it still exits 2, because make's
// exit status is make's, and swallowing it would exit 0 and turn an infra
// incident green.
//
// What is NOT asserted: that the local recipe changes. A developer reading
// `Error 75` in their own terminal is being told the truth by make's own
// message, so `make integration-engine` keeps working exactly as it did.
const engineScriptRel = "test/engine-container.sh"

var engineStepRunRe = regexp.MustCompile(`(?m)^\s+- name: The engine suite, in a Tumbleweed container\n\s+run: (.+)$`)

func TestTheEngineJobRunsTheScriptNotMake(t *testing.T) {
	ci := repoFile(t, ciPath)

	m := engineStepRunRe.FindStringSubmatch(ci)
	if m == nil {
		t.Fatalf("no %q step with a `run:` line found in %s — if the step was renamed, "+
			"this test's regexp is what must be updated, and the thing it is guarding "+
			"(issue #505: the step must invoke %s directly so its exit 75 survives) "+
			"still holds", "The engine suite, in a Tumbleweed container", ciPath, engineScriptRel)
	}
	run := strings.TrimSpace(m[1])

	if strings.Contains(run, "make") {
		t.Errorf("the engine job's step runs %q, which goes through make.\n"+
			"GNU make exits 2 on any recipe failure whatever the recipe exited, so "+
			"%s's exit 75 (EX_TEMPFAIL, its own classification of an openSUSE infra "+
			"failure) is consumed and CI reports 2. Nothing downstream can then tell "+
			"an infra incident from a failing test, and the script's own message "+
			"(\"Exiting 75 (EX_TEMPFAIL) so the code says so too\") becomes false.\n"+
			"Run the script directly — `run: ./%s` — which is the SAME single command "+
			"the recipe runs, so no instruction moves into the yaml. Issue #505.",
			run, engineScriptRel, engineScriptRel)
	}

	if !strings.Contains(run, engineScriptRel) {
		t.Errorf("the engine job's step runs %q, which does not name %s.\n"+
			"The container's every detail — flags, packages, non-root user, subuid "+
			"range — must stay in that script, because nobody can run a yaml step "+
			"locally: a failure in an inlined step only ever reproduces by pushing "+
			"again. The step names the script; it never describes it.", run, engineScriptRel)
	}
}
