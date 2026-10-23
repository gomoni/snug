package policy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// bookClaudePath is the user guide's page for @claude.
const bookClaudePath = "../../docs/src/claude.md"

// TestBookClaudeSettingsListsTheAllowlist checks the key list in the
// `settings.json` section of docs/src/claude.md against ClaudeSettingAllowlist,
// in both directions. The list is the bullet list between "keys are passed"
// and "Additionally".
func TestBookClaudeSettingsListsTheAllowlist(t *testing.T) {
	data, err := os.ReadFile(bookClaudePath)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)keys are passed(.*?)Additionally`).FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s has no \"keys are passed … Additionally\" list", bookClaudePath)
	}
	documented := map[string]bool{}
	for _, q := range regexp.MustCompile("`([A-Za-z]+)`").FindAllSubmatch(m[1], -1) {
		documented[string(q[1])] = true
	}
	for _, k := range ClaudeSettingAllowlist {
		if !documented[k.Name] {
			t.Errorf("snug carries %s from the host's settings.json and %s does not list it", k.Name, bookClaudePath)
		}
		delete(documented, k.Name)
	}
	for d := range documented {
		t.Errorf("%s lists %s as carried, and ClaudeSettingAllowlist drops it", bookClaudePath, d)
	}
}

// TestBookNamesTheWrapperPaths checks the guest paths the book quotes against
// the constants Resolve stages.
func TestBookNamesTheWrapperPaths(t *testing.T) {
	for page, wants := range map[string][]string{
		bookClaudePath: {
			"`BROWSER` inside the sandbox points to `" + BrowserGuest + "`",
		},
		"../../docs/src/network.md": {
			"`" + WrapperGuest + "` is snug's own executable",
			"`bind " + SelfExeHost + "`",
		},
	} {
		data, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wants {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s does not say %s", page, w)
			}
		}
	}
}
