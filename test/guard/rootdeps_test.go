package guard

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rootRequires is the root module's whole supply chain. CLAUDE.md: "do not add
// a third dependency without the maintainer". A change here is that decision.
var rootRequires = []string{
	"github.com/pelletier/go-toml/v2",
	"golang.org/x/sys",
}

// TestRootModuleRequiresOnlyTheTwoDependencies holds the root go.mod to its
// two requires, indirect ones included: an indirect require is still code in
// the snug binary's build graph.
func TestRootModuleRequiresOnlyTheTwoDependencies(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inBlock:
			continue
		}
		if f := strings.Fields(line); len(f) > 0 && !strings.HasPrefix(f[0], "//") {
			got = append(got, f[0])
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, rootRequires) {
		t.Fatalf("root go.mod requires %q, want exactly %q.\n"+
			"snug's dependencies are its attack surface; a new one needs the maintainer. "+
			"Tooling with its own dependencies (snug-setup) lives in its own module under setup/.",
			got, rootRequires)
	}
}

// TestSetupIsItsOwnModule: setup/ carries the chat setup and its UI
// dependencies. Without its own go.mod its packages would join the root
// module and drag those dependencies into it.
func TestSetupIsItsOwnModule(t *testing.T) {
	p := filepath.Join("..", "..", "setup")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skip("no setup/ directory in this tree")
	}
	b, err := os.ReadFile(filepath.Join(p, "go.mod"))
	if err != nil {
		t.Fatalf("setup/ has no go.mod (%v): its packages would build as part of the root "+
			"module. Restore setup/go.mod (module github.com/gomoni/snug/setup).", err)
	}
	if !strings.Contains(string(b), "module github.com/gomoni/snug/setup\n") {
		t.Fatalf("setup/go.mod does not declare module github.com/gomoni/snug/setup")
	}
}
