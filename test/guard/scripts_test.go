package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE SCRIPT DIRECTORY IS GRADED HERE BECAUSE NOTHING ELSE CAN GRADE IT.
//
// `make verify` runs the checks, so it catches a check that FAILS. It cannot
// catch the failures that are about the directory rather than about a check: a
// number used twice, a file that is not executable and so is never run, a check
// missing from the index a reader navigates by, or a script that spells SKIP as
// 77 — which is snug's own exitPolicy (internal/cli/main.go), so a script
// ending on an uncaptured refusal would report SKIP and the run would go green
// having measured nothing.
//
// Every one of those is invisible to a green `make verify` and visible to
// `make gate`, which is why they are here and not there.

var checkName = regexp.MustCompile(`^([0-9]{4})-[a-z0-9-]+\.(sh|py)$`)

// checkScripts returns the checks in scripts/, keyed by filename. It fails
// rather than returning an empty map: a test that grades an empty set passes
// forever, which is the shape every floor in this repository exists to refuse.
func checkScripts(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "scripts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !checkName.MatchString(e.Name()) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(body)
	}
	if len(out) == 0 {
		t.Fatal("no NNNN-slug checks found in scripts/, so this test grades an empty set and passes forever")
	}
	return out
}

func TestEveryCheckScriptHasItsOwnNumber(t *testing.T) {
	seen := map[string]string{}
	for name := range checkScripts(t) {
		n := checkName.FindStringSubmatch(name)[1]
		if first, dup := seen[n]; dup {
			t.Errorf("scripts/%s and scripts/%s both claim number %s.\n"+
				"A number is an allocation sequence and is never reused: a reference to %s\n"+
				"has to mean one thing forever. Allocate the next free number instead.",
				first, name, n, n)
			continue
		}
		seen[n] = name
	}
}

func TestEveryCheckScriptIsExecutable(t *testing.T) {
	for name := range checkScripts(t) {
		fi, err := os.Stat(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&0o111 == 0 {
			t.Errorf("scripts/%s is not executable, so `make verify` reports it as an ERROR\n"+
				"rather than running it. chmod +x it.", name)
		}
	}
}

// A check that is not in the index is a check nobody finds. scripts/README.md is
// what the migration rule points a reader at, so an unlisted script is the index
// going stale — the exact failure that made VERIFY.md worth converting.
func TestEveryCheckScriptIsInTheIndex(t *testing.T) {
	index, err := os.ReadFile(filepath.Join("..", "..", "scripts", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name := range checkScripts(t) {
		if !strings.Contains(string(index), name) {
			t.Errorf("scripts/%s is not named in scripts/README.md.\n"+
				"The index is how a reader finds a check; one that is not in it is one\n"+
				"nobody runs by hand. Add a row saying what it asserts.", name)
		}
	}
}

// 77 IS SNUG'S OWN exitPolicy, which is why this is a test and not a comment.
//
// The conventional SKIP code is 77 and the reflex is to reach for it. A check
// that did would be indistinguishable from one that ended on a `snug` refusal it
// forgot to capture: the runner would read a real policy refusal as "this host
// could not run the check" and the run would go green. 79 is outside sysexits'
// 64-78 range entirely, so it cannot be one of snug's codes.
func TestNoCheckScriptSpellsSkipAs77(t *testing.T) {
	for name, body := range checkScripts(t) {
		for _, bad := range []string{"exit 77", "skip=77", "exit $((77", "SKIP=77"} {
			if strings.Contains(body, bad) {
				t.Errorf("scripts/%s contains %q. SKIP is 79, not 77: 77 is snug's own\n"+
					"exitPolicy (internal/cli/main.go), so a script ending on an uncaptured\n"+
					"refusal would report SKIP and the run would go green having measured nothing.",
					name, bad)
			}
		}
	}
}

// A check that never says what it asserted leaves a human reading `make verify`
// output with nothing but an exit code — which is the readable half of what
// replaced VERIFY.md's transcripts.
func TestEveryCheckScriptSaysWhatItAsserted(t *testing.T) {
	for name, body := range checkScripts(t) {
		if !strings.Contains(body, "asserted:") {
			t.Errorf("scripts/%s never prints an `asserted:` line.\n"+
				"The expected output lives in the assertions, and the run has to say which\n"+
				"ones it made — otherwise `make verify` is an exit code and nothing else.", name)
		}
	}
}

// The floor is what stops `make verify` going green having skipped everything.
// It has to be at most the number of checks that exist, or it can never be met;
// and a floor of zero is no floor at all.
func TestTheVerifyFloorIsMeetable(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`SNUG_VERIFY_FLOOR \?= ([0-9]+)`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("SNUG_VERIFY_FLOOR is not set in the Makefile, so `make verify` has no floor and\n" +
			"a run in which every check SKIPped would be green")
	}
	floor := string(m[1])
	n := len(checkScripts(t))
	if floor == "0" {
		t.Fatal("SNUG_VERIFY_FLOOR is 0, which is no floor: a run that skipped every check passes")
	}
	if len(floor) > 4 || atoiOrFatal(t, floor) > n {
		t.Errorf("SNUG_VERIFY_FLOOR is %s but only %d check(s) exist, so the floor can never be met\n"+
			"and `make verify` fails on every host.", floor, n)
	}
}

func atoiOrFatal(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}
