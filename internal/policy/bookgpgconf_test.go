package policy

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestBookListsExactlyTheCarriedGPGConfOptions checks the bulleted option list
// under "#### Your gpg.conf" in docs/src/identity.md against GPGConfOptions, in
// both directions, and that every meta command the page names is one snug
// carries.
func TestBookListsExactlyTheCarriedGPGConfOptions(t *testing.T) {
	const page = "../../docs/src/identity.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "#### Your gpg.conf\n")
	if !ok {
		t.Fatalf("%s has no \"#### Your gpg.conf\" section", page)
	}
	section, _, _ = strings.Cut(section, "\n#")
	// The list is the first run of "- " lines and their indented continuations.
	var bullets strings.Builder
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "- ") || (bullets.Len() > 0 && strings.HasPrefix(line, "  ")) {
			bullets.WriteString(line + "\n")
		} else if bullets.Len() > 0 {
			break
		}
	}
	var documented []string
	for _, m := range regexp.MustCompile("`([a-z0-9-]+)`").FindAllStringSubmatch(bullets.String(), -1) {
		documented = append(documented, m[1])
	}
	for _, name := range documented {
		if _, ok := GPGConfOptions[name]; !ok {
			t.Errorf("%s lists %q as carried, and GPGConfOptions does not carry it", page, name)
		}
	}
	for _, name := range SortedGPGConfOptions() {
		if !slices.Contains(documented, name) {
			t.Errorf("%s does not list %q, which GPGConfOptions carries", page, name)
		}
	}
	for _, m := range regexp.MustCompile("`\\[([a-z+-]+)\\]`").FindAllStringSubmatch(section, -1) {
		if !slices.Contains(gpgConfMeta, m[1]) {
			t.Errorf("%s names meta command [%s], which snug does not carry", page, m[1])
		}
	}
}
