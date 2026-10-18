package policy

import (
	"os"
	"regexp"
	"testing"
)

// TestBookProfileKeysListExactlyTheParsedModes checks the `values` column of
// docs/src/reference/profile-keys.md for every enumerated key against the
// parser that decides it, in both directions — the same sameSet the Profile
// comments and INDEX.md are held to.
func TestBookProfileKeysListExactlyTheParsedModes(t *testing.T) {
	const page = "../../docs/src/reference/profile-keys.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	documentedValues := func(key string) []string {
		row := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(key) + "` \\| [^|]+ \\| ([^|]+) \\|")
		got := row.FindStringSubmatch(string(data))
		if got == nil {
			t.Errorf("%s has no row for %s", page, key)
			return nil
		}
		var documented []string
		for _, q := range quoted.FindAllStringSubmatch(got[1], -1) {
			documented = append(documented, q[1])
		}
		if len(documented) == 0 {
			t.Errorf("%s's %s row lists no quoted values: %q", page, key, got[1])
		}
		return documented
	}

	for _, m := range modeParsers {
		if documented := documentedValues(m.key); len(documented) > 0 {
			sameSet(t, page, m.key, documented, m.values(), m.parse)
		}
	}

	// identity.ssh.agent is not joined by maximum, so it has no floor and
	// sameSet's "the floor is refused" does not apply: both values are
	// writable, and the row must list exactly them.
	const agent = "identity.ssh.agent"
	documented := documentedValues(agent)
	want := map[string]bool{string(SSHAgentProxy): true, "none": true}
	for _, v := range documented {
		if _, err := ParseSSHMode(v); err != nil {
			t.Errorf("%s documents %s = %q and the parser refuses it: %v", page, agent, v, err)
		}
		delete(want, v)
	}
	for v := range want {
		t.Errorf("%s does not list %s = %q, which the parser accepts", page, agent, v)
	}
}

// TestBookListsExactlyThePathVariablesResolveBuilds checks the variable table
// in docs/src/filesystem.md against Resolve's variable map, in both
// directions. The `~/` row is expandVars' prefix rule, not a map entry.
func TestBookListsExactlyThePathVariablesResolveBuilds(t *testing.T) {
	const page = "../../docs/src/filesystem.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `\\{([a-z_]+)\\}` \\|").FindAllStringSubmatch(string(data), -1) {
		documented[m[1]] = true
	}
	built := resolvePathVars(t)
	for _, b := range built {
		if !documented[b] {
			t.Errorf("Resolve builds {%s} and %s's variable table does not list it", b, page)
		}
		delete(documented, b)
	}
	for d := range documented {
		t.Errorf("%s lists {%s}, which Resolve does not build: a profile writing it is refused", page, d)
	}
}
