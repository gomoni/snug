package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the review artifact for a pinned signing key (#453) ─────────────────────
//
// No committed golden anywhere renders an [identity] block at all before this
// file (`grep -rn "id_snug" internal/*/testdata` returns nothing) — showCapabilities'
// own doc comment says this is "the screen a human reads to decide WHETHER to
// select a profile", and until now nothing pinned what it prints for the one
// TOML block whose abuse sentence is "sign commits and tags as that identity".
//
// It calls showCapabilities directly (as TestProfileShowRendersEveryEnvironVerb
// does for showEnviron), reproducing `profile show`'s own render closure
// (config.go) exactly, rather than running the real command: no builtin ships
// an [identity] block, so there is no real profile file this could run
// against without inventing one on disk.
func TestGoldenShowIdentityCapabilities(t *testing.T) {
	p := &policy.Profile{
		Name: "signed",
		Identity: &policy.Identity{
			SSH: policy.IdentitySSH{Agent: policy.SSHAgentProxy, Key: "{home}/.ssh/id_ed25519.pub"},
			Git: policy.IdentityGit{
				SigningKey: "{home}/.ssh/id_ed25519_signing.pub",
				Name:       "Some One",
				Email:      "some.one@example.com",
			},
			Gh: policy.IdentityGh{User: "some-one", Host: "github.com"},
		},
	}

	var b strings.Builder
	// The exact rendering closure config.go's `profile show` builds, so a
	// diff here is a diff in what that command would actually print.
	show := func(label string, vals []string) {
		for i, v := range vals {
			head := ""
			if i == 0 {
				head = label
			}
			fmt.Fprintf(&b, "  %-16s %s\n", head, visibleValue(v))
		}
	}
	showCapabilities(p, show)
	got := b.String()
	if got == "" {
		t.Fatal("showCapabilities printed nothing for a profile carrying [identity]")
	}

	path := filepath.Join("testdata", "show-identity.capabilities.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v — run `go test ./internal/cli/ -run TestGoldenShowIdentityCapabilities "+
			"-update` to create it, then READ the diff before committing", err)
	}
	if string(want) != got {
		t.Errorf("the identity capabilities block changed — this is what a human reads to "+
			"decide whether a profile may sign commits and tags as them, and a diff here is a "+
			"diff in that grant.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
