package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenInitState is the review artifact for initState's wire shape
// (issue #236): six keys, asserted byte-for-byte, so a patch adding a seventh
// — a command, an argv, a seccomp digest, anything runstate.go's own
// abuse-sentence list forbids in this file — shows up as a diff here rather
// than arriving silently.
func TestGoldenInitState(t *testing.T) {
	st := initState{
		Schema:        initStateSchema,
		Target:        "/home/u/proj",
		InitPID:       4242,
		InitStarttime: 987654,
		Namespaces: map[string]uint64{
			"mnt": 111, "pid": 222, "net": 333, "ipc": 444, "uts": 555, "cgroup": 666,
		},
		Owner: stateOwner{PID: 4200, Starttime: 987000},
	}

	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	blob = append(blob, '\n')

	path := filepath.Join("testdata", "initstate.golden.json")
	if *update {
		if err := os.WriteFile(path, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if string(blob) != string(want) {
		t.Errorf("initState's JSON shape changed — every key here is read back by "+
			"decodeInitState and killOrphanInit\ngot:\n%s\nwant:\n%s", blob, want)
	}
}
