package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// INDEX.md §2.3's table is the design's list of how each profile key joins.
// It carried rows for `dev`, `env` and `path` after all three stopped being
// keys a profile file may contain — a profile author copying one gets a
// strict-decoding refusal. This fails when the table names a key rawProfile
// does not decode.
//
// It grades only the Key column of that one table; keys named elsewhere in
// INDEX.md are not checked.
func TestINDEXJoinTableNamesOnlyRealProfileKeys(t *testing.T) {
	keys := map[string]bool{}
	rt := reflect.TypeOf(rawProfile{})
	for i := 0; i < rt.NumField(); i++ {
		keys[strings.Split(rt.Field(i).Tag.Get("toml"), ",")[0]] = true
	}

	index := filepath.Join("..", "..", ".claude", "design", "INDEX.md")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("cannot read %s: %v", index, err)
	}
	const header = "| Key | Domain | Join | Permissive direction |"
	_, table, ok := strings.Cut(string(body), header)
	if !ok {
		t.Fatalf("no %q table in %s; if it was renamed, update the header here rather than deleting the check", header, index)
	}
	table, _, _ = strings.Cut(table, "\n\n")

	tick := regexp.MustCompile("`([^`]+)`")
	rows := 0
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 3 || strings.HasPrefix(strings.TrimSpace(cells[1]), "---") {
			continue
		}
		rows++
		for _, m := range tick.FindAllStringSubmatch(cells[1], -1) {
			if !keys[m[1]] {
				t.Errorf("INDEX.md §2.3 lists `%s` as a profile key; rawProfile does not decode it, "+
					"so a profile that copies it is refused at parse time", m[1])
			}
		}
	}
	if rows == 0 {
		t.Fatal("§2.3's join table has no rows; this test is grading nothing")
	}
}
