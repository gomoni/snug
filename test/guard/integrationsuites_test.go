package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE COMMITTED INTEGRATION SUITE IS ONE SET, RUN TWO WAYS (issue #379).
//
// CI has run the integration tests as two parallel jobs since 2026-08-21 —
// `integration-sandbox` and `integration-signals`, ~70s each — while local
// `make integration` ran everything in ONE `go test` process against ONE 4m
// budget. That budget then fired on every full local run: MEASURED 239.64s of
// test time, nothing hung, the panic landing on whatever test the alarm caught.
// Green in CI, panicking locally, same suite in both places, and the divergence
// itself was the defect.
//
// The fix makes local run CI's two suites sequentially. That leaves the suite
// LIST named in two files — the Makefile, which owns everything about how a
// suite runs, and ci.yml's matrix, which holds the two names and calls `make
// <suite>`. Two places saying the same thing is this project's recurring
// defect, and #379 is itself a stale-comment ticket, so shipping a fresh copy
// inside it would be poor. A `# keep in sync with ci.yml` comment is not an
// answer; it is the mechanism that failed everywhere else. This test is.
//
// Which of the three possible arrangements this turned out to be: the Makefile
// ALREADY owned the definitions, so nothing had to move. Only the names are
// duplicated, and only the names are asserted here.
const makefilePath = "Makefile"

var ciPath = filepath.Join(".github", "workflows", "ci.yml")

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

var (
	suiteListRe  = regexp.MustCompile(`(?m)^SNUG_INTEGRATION_SUITES\s*=\s*(.+)$`)
	matrixJobRe  = regexp.MustCompile(`(?m)^  integration:$`)
	matrixItemRe = regexp.MustCompile(`(?m)^\s+- suite:\s*(\S+)\s*$`)
	phonyRe      = regexp.MustCompile(`(?m)^\.PHONY:\s*(.+)$`)
)

// TestTheIntegrationSuitesAreTheSameLocallyAndInCI is the whole point: a suite
// added to one file and not the other means a set of tests that runs in one
// place and not the other, which is the shape #379 was filed for.
func TestTheIntegrationSuitesAreTheSameLocallyAndInCI(t *testing.T) {
	mk := repoFile(t, makefilePath)
	ci := repoFile(t, ciPath)

	m := suiteListRe.FindStringSubmatch(mk)
	if m == nil {
		t.Fatalf("%s has no SNUG_INTEGRATION_SUITES assignment. `make integration` runs the "+
			"suites that variable names; without it this test grades nothing and the local "+
			"target and CI can diverge again.", makefilePath)
	}
	local := strings.Fields(m[1])

	// Only the `integration` job's matrix. `hostless` is a separate job that
	// must run with SNUG_REQUIRE_SANDBOX UNSET, so it is deliberately not one
	// of the suites a strict local run performs — see its comment in the
	// Makefile.
	loc := matrixJobRe.FindStringIndex(ci)
	if loc == nil {
		t.Fatalf("%s has no `integration:` job. Either the job was renamed — in which case "+
			"this test is reading the wrong block and every comparison below is against an "+
			"empty set — or the matrix is gone.", ciPath)
	}
	rest := ci[loc[1]:]
	if end := strings.Index(rest, "\n  forkstress:"); end >= 0 {
		rest = rest[:end]
	}
	var remote []string
	for _, item := range matrixItemRe.FindAllStringSubmatch(rest, -1) {
		remote = append(remote, item[1])
	}

	// POSITIVE CONTROL. Both lists are built by a regexp over a file whose
	// layout can change under it, and the comparison below is set equality —
	// which two empty sets satisfy. The floor is 2 because the split exists to
	// have more than one.
	if len(local) < 2 || len(remote) < 2 {
		t.Fatalf("parsed %d local suite(s) %v and %d CI suite(s) %v. Fewer than two means a "+
			"regexp stopped matching, not that the split shrank; check both files before "+
			"believing this failure.", len(local), local, len(remote), remote)
	}

	sort.Strings(local)
	sort.Strings(remote)
	if strings.Join(local, " ") != strings.Join(remote, " ") {
		t.Errorf("the integration suites disagree:\n  %s: %s\n  %s: %s\n"+
			"A suite in one file and not the other runs in one place and not the other. "+
			"That is issue #379 exactly: CI stayed green for a fortnight while the local "+
			"target panicked on its own timeout.",
			makefilePath, strings.Join(local, " "), ciPath, strings.Join(remote, " "))
	}

	// Every suite must be a real target, or `make integration` fails on the
	// second one having already run the first.
	phony := map[string]bool{}
	for _, p := range phonyRe.FindAllStringSubmatch(mk, -1) {
		for _, name := range strings.Fields(p[1]) {
			phony[name] = true
		}
	}
	for _, suite := range local {
		if !phony[suite] {
			t.Errorf("%s names the suite %q, which is not in .PHONY. A suite that is not a "+
				"target is a `make integration` that fails partway through.", makefilePath, suite)
		}
		if !strings.Contains(mk, "\n"+suite+":") {
			t.Errorf("%s has no `%s:` rule", makefilePath, suite)
		}
	}
}

// TestTheTwoIntegrationSuitesPartitionThePackage is the other half, and it is
// the one that decides where a NEW test lands. The two suites are selected from
// ONE variable — `-run` in one target and `-skip` in the other — so every test
// in the package is in exactly one of them, by construction rather than by
// somebody remembering to add it. A test matching neither would run NOWHERE and
// look green, which is the "test that cannot fail" shape this repository
// refuses everywhere.
//
// Written against the MECHANISM (one variable, both senses) and not against the
// current names: a test list here would go stale the day a fourth signal test
// is written, which is the catalogue shape.
func TestTheTwoIntegrationSuitesPartitionThePackage(t *testing.T) {
	mk := repoFile(t, makefilePath)

	const selector = "SNUG_SIGNAL_TESTS"
	if !regexp.MustCompile(`(?m)^` + selector + `\s*=\s*\S`).MatchString(mk) {
		t.Fatalf("%s has no %s assignment; the two suites are then selected by two "+
			"independent expressions and nothing stops a test falling between them",
			makefilePath, selector)
	}

	for _, want := range []struct {
		target, flag string
	}{
		{"integration-signals", "-run '$(" + selector + ")'"},
		{"integration-sandbox", "-skip '$(" + selector + ")'"},
	} {
		body := makeTargetBody(t, mk, want.target)
		if !strings.Contains(body, want.flag) {
			t.Errorf("%s does not select with %s. The two suites must be the two halves of "+
				"ONE expression: if one of them names its own list, a test matching neither "+
				"runs in no suite at all and the run goes green having never executed it.\n"+
				"target body:\n%s", want.target, want.flag, body)
		}
	}
}

// makeTargetBody returns the recipe lines of one target: everything from its
// rule line to the first line that is neither blank nor indented.
func makeTargetBody(t *testing.T, mk, target string) string {
	t.Helper()
	i := strings.Index(mk, "\n"+target+":")
	if i < 0 {
		t.Fatalf("%s has no `%s:` rule", makefilePath, target)
	}
	lines := strings.Split(mk[i+1:], "\n")
	var body []string
	for _, line := range lines[1:] {
		if line != "" && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			break
		}
		body = append(body, line)
	}
	if len(body) == 0 {
		t.Fatalf("`%s:` has an empty recipe", target)
	}
	return strings.Join(body, "\n")
}
