package profile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// builtinProfileHeader is a builtin's top-level table, `[profile.NAME]`, and not one
// of its sub-tables such as `[profile.claude.environ.inherit]`.
var builtinProfileHeader = regexp.MustCompile(`^\[profile\.([a-z0-9-]+)\]\s*$`)

// TestEveryBuiltinProfileStatesItsAbuseSentence holds CLAUDE.md's working
// agreement for the profiles snug ships: a grant is not ready until its author
// can write "a hostile process inside the sandbox can use this to ___", and
// the sentence goes in the profile TOML as a comment. base.toml's header says
// the same. Nothing else reads those comments, so without this a builtin can
// ship without one.
//
// The sentence must sit between the previous `[profile.NAME]` header and this
// one, which is where every builtin writes it today: the comment block that
// introduces a profile is the one a reader sees before the grant.
func TestEveryBuiltinProfileStatesItsAbuseSentence(t *testing.T) {
	files, err := filepath.Glob("profiles/*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no profiles/*.toml: this test reads the builtin profile sources")
	}
	seen := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		abuse := false
		for i, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "# ABUSE") {
				abuse = true
			}
			m := builtinProfileHeader.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			seen++
			if !abuse {
				t.Errorf("%s:%d: [profile.%s] has no `# ABUSE` comment above it, after the previous profile.\n"+
					"      Write what a hostile process inside the sandbox can do with this grant first.",
					f, i+1, m[1])
			}
			abuse = false
		}
	}
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if seen != len(reg) {
		t.Errorf("found %d [profile.NAME] headers in profiles/*.toml and Builtins() has %d profiles: "+
			"the header scan no longer sees every builtin", seen, len(reg))
	}
}
