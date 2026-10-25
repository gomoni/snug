package policy

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestBookListsExactlyTheCarriedSSHKeys checks the first bullet under "####
// Your ssh configuration" in docs/src/identity.md against SSHKeyWhitelist, in
// both directions, and the file the page names against RevokedHostKeysGuest.
func TestBookListsExactlyTheCarriedSSHKeys(t *testing.T) {
	const page = "../../docs/src/identity.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "#### Your ssh configuration\n")
	if !ok {
		t.Fatalf("%s has no \"#### Your ssh configuration\" section", page)
	}
	section, _, _ = strings.Cut(section, "\n#")
	// The key list is the first bullet and its indented continuations.
	var bullet strings.Builder
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "- ") && bullet.Len() > 0 {
			break
		}
		if strings.HasPrefix(line, "- ") || (bullet.Len() > 0 && strings.HasPrefix(line, "  ")) {
			bullet.WriteString(line + "\n")
		}
	}
	var documented []string
	for _, m := range regexp.MustCompile("`([A-Za-z0-9]+)`").FindAllStringSubmatch(bullet.String(), -1) {
		if m[1] != "Host" && m[1] != "Match" && m[1] != "host" {
			documented = append(documented, m[1])
		}
	}
	for _, name := range documented {
		if !slices.Contains(SSHKeyWhitelist, strings.ToLower(name)) || SSHKeySpelling(strings.ToLower(name)) != name {
			t.Errorf("%s lists %q as carried, and SSHKeyWhitelist does not carry it under that spelling", page, name)
		}
	}
	for _, k := range SSHKeyWhitelist {
		if !slices.Contains(documented, SSHKeySpelling(k)) {
			t.Errorf("%s does not list %q, which SSHKeyWhitelist carries", page, SSHKeySpelling(k))
		}
	}
	if !strings.Contains(section, "`~/"+RevokedHostKeysGuest+"`") {
		t.Errorf("%s does not name ~/%s as where RevokedHostKeys is copied", page, RevokedHostKeysGuest)
	}
}
