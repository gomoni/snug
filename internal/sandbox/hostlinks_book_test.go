package sandbox

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The kinds docs/src/identity.md names as refused and as allowed are the kinds
// the classifier names, in both directions for the refused set.
func TestBookKubeLinkKindsMatchTheClassifier(t *testing.T) {
	const page = "../../docs/src/identity.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	book := string(data)
	for k := range namedVirtualKinds {
		if !strings.Contains(book, "`"+k+"`") {
			t.Errorf("%s does not name the refused kind `%s`", page, k)
		}
	}
	for _, k := range []string{"wwan", "tun", "wireguard"} {
		if kind, ok := classifyLink(linkInfo{Kind: k, Flags: unix.IFF_POINTOPOINT}); !ok || kind != k {
			t.Errorf("classifier does not allow %s", k)
		}
		if !strings.Contains(book, "`"+k+"`") {
			t.Errorf("%s does not name the allowed kind `%s`", page, k)
		}
	}
}
