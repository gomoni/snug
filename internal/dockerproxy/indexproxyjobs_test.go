package dockerproxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestINDEXProxyJobTableNamesLiveSymbols keeps §7.2's job table — what each of
// the proxy's seven jobs guards, and whether it is the sole guard or
// belt-and-braces after Tier C — pointed at code that exists.
//
// WHY THIS AND NOT MORE. Most of that table is judgement, and judgement is not
// machine-checkable: no test can decide whether refusing `Devices` is still
// defence-in-depth. What IS checkable is the half that rots silently — the
// symbol names the classifications hang off. A renamed `stampRunLabel` or a
// deleted `namespaceModeKeys` leaves a row that reads as authoritative and
// points at nothing, which is the failure mode that made #146's own rows
// unusable three architectures later: they named things that had moved, so the
// reader could not tell a stale row from a live one.
//
// BOTH DIRECTIONS, which is what makes it a sync test rather than a spell
// check: the symbol must appear in the table AND in the file the table says it
// lives in. Renaming the symbol fails here; moving it between files fails here;
// dropping the row for a job that still exists does not — that one needs a
// human, and the seven-row count below is the flag that asks for one.
func TestINDEXProxyJobTableNamesLiveSymbols(t *testing.T) {
	index := filepath.Join("..", "..", ".claude", "design", "INDEX.md")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("cannot read %s: %v", index, err)
	}

	table, rows := proxyJobTable(t, string(body))

	// One row per job #146 named. A row that disappears is a job whose
	// classification nobody is claiming any more, which is a decision, not a
	// tidy-up — so it fails here and asks for a human.
	const wantRows = 7
	if rows != wantRows {
		t.Errorf("§7.2's proxy-job table has %d body rows, want %d — one per job: bind filter, "+
			"namespace modes, HostConfig refusals, injected values, endpoint allowlist, run "+
			"label, audit", rows, wantRows)
	}

	// Each symbol the table's classifications rest on, with the file that must
	// still hold it. Read as source TEXT rather than imported, for the reason
	// TestIpcAndUtsReasonsMatchTheEnginesActualCloneflags states: three of these
	// live in packages that do not export them and should not have to just so a
	// doc-sync test elsewhere can see them.
	for _, c := range []struct{ symbol, file string }{
		{"checkedMounts", "create.go"},
		{"checkOne", "create.go"},
		{"hostPathVisible", "create.go"},
		{"namespaceModeKeys", "create.go"},
		{"namespaceModeReason", "create.go"},
		{"refusedHostConfig", "create.go"},
		{"refusalReason", "create.go"},
		{"stampRunLabel", "create.go"},
		{"checkBuildVolume", "build.go"},
		{"checkAdditionalContexts", "build.go"},
		{"checkNSOptions", "build.go"},
		{"isPrune", "proxy.go"},
		{"isArchive", "proxy.go"},
		{"isImageDelete", "proxy.go"},
		{"isVolumeDelete", "proxy.go"},
		{"HostPathVisible", filepath.Join("..", "policy", "graft.go")},
		{"EngineCapBounding", filepath.Join("..", "policy", "enginecaps.go")},
		{"VisibleText", filepath.Join("..", "policy", "forging.go")},
		{"containerAudit", filepath.Join("..", "cli", "container.go")},
		{"Cloneflags", filepath.Join("..", "stage", "enginefork.go")},
	} {
		if !namesSymbol(t, table, c.symbol) {
			t.Errorf("§7.2's proxy-job table does not name %s, which the classifications rest "+
				"on — either the row was rewritten without it or this list is out of date",
				c.symbol)
		}
		src, err := os.ReadFile(c.file)
		if err != nil {
			t.Errorf("§7.2's table names %s and %s cannot be read: %v", c.symbol, c.file, err)
			continue
		}
		if !namesSymbol(t, string(src), c.symbol) {
			t.Errorf("§7.2's proxy-job table names %s as living in %s and it is not there. "+
				"A classification pointing at a symbol that moved reads as authoritative and "+
				"grades nothing", c.symbol, c.file)
		}
	}

	// The standing gate the bind-filter row cites by name, checked in the
	// package that owns it: a row claiming a test guards the invariant is worth
	// only as much as the test's existence.
	const gate = "TestContainerBindFilterMatchesPolicyVisibility"
	if !namesSymbol(t, table, gate) {
		t.Errorf("the bind-filter row no longer cites %s", gate)
	}
	if _, err := os.Stat("bindfilter_test.go"); err != nil {
		t.Errorf("§7.2 cites %s and bindfilter_test.go is gone: %v", gate, err)
	}
}

// namesSymbol reports whether text names exactly this identifier.
//
// Word-bounded, and that is not fussiness: strings.Contains was the first
// version and it passed a mutation that renamed `containerAudit` to
// `containerAuditXX` in BOTH the table and the source, because each still
// contains the other's prefix. A sync test defeated by appending two letters
// to a name is a sync test that grades the shape of the name, not its identity.
func namesSymbol(t *testing.T, text, symbol string) bool {
	t.Helper()
	re, err := regexp.Compile(`\b` + regexp.QuoteMeta(symbol) + `\b`)
	if err != nil {
		t.Fatalf("compiling a word-bounded match for %q: %v", symbol, err)
	}
	return re.MatchString(text)
}

// proxyJobTable returns §7.2's job table and its body-row count.
//
// Located by its header row rather than by a section offset, so an edit
// anywhere else in INDEX.md cannot silently point this test at a different
// table. Fatal if it is not found: a sync test that grades an empty string
// passes, and that reads as "the table is fine".
func proxyJobTable(t *testing.T, body string) (string, int) {
	t.Helper()
	const header = "| proxy job | what it guards | sole guard, or belt-and-braces |"
	i := strings.Index(body, header)
	if i < 0 {
		t.Fatalf("no proxy-job table header in INDEX.md §7.2. If it was reworded, update this "+
			"test rather than deleting the check; the header it looks for is:\n%s", header)
	}
	// TrimLeft, not a plain slice: the header row ends in a newline, so the
	// first field of the split below would be the empty string and the loop
	// would stop before reading a single row — which reads as "no rows".
	rest := strings.TrimLeft(body[i+len(header):], "\n")
	var table strings.Builder
	rows := 0
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "|") {
			break
		}
		if strings.HasPrefix(line, "|---") {
			continue // the separator row
		}
		table.WriteString(line)
		table.WriteString("\n")
		rows++
	}
	if rows == 0 {
		t.Fatal("the proxy-job table header is followed by no rows at all")
	}
	return table.String(), rows
}
