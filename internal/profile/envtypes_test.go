package profile

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestBuiltinCarryingEnvironTypesIsRefused would catch a profile snug ships
// declaring a type. The redundant case is the one the roster gate beside it
// cannot see: XDG_CONFIG_HOME has a row, so IsUnknownEnv is false for it and
// checkBuiltinEnvRoster's own loop passes — only checkBuiltinEnvTypes stops it.
func TestBuiltinCarryingEnvironTypesIsRefused(t *testing.T) {
	for _, tc := range []struct {
		why  string
		g    policy.EnvGrants
		want string
	}{
		{"an unrostered list", policy.EnvGrants{
			Types: map[string]policy.EnvKind{"GEM_PATH": policy.EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems"}}}, "GEM_PATH"},
		{"a redundant path on a rostered name", policy.EnvGrants{
			Types: map[string]policy.EnvKind{"XDG_CONFIG_HOME": policy.EnvKindPath},
			Set:   map[string]string{"XDG_CONFIG_HOME": "{home}/.config"}}, "XDG_CONFIG_HOME"},
	} {
		// The same grants are legal in a HUMAN's profile, so the refusal below
		// is about who ships it and nothing else.
		if err := policy.ValidateEnvGrants(tc.g); err != nil {
			t.Fatalf("%s: fixture is refused at parse, so mark() is not what is measured: %v", tc.why, err)
		}
		_, err := mark(Registry{"shipped": &policy.Profile{Name: "shipped", Environ: tc.g}})
		if err == nil {
			t.Errorf("%s: mark() accepted a builtin declaring environ.types", tc.why)
			continue
		}
		for _, want := range []string{`profile "shipped"`, "declares environ.types for " + tc.want,
			"A profile snug SHIPS does not declare"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal does not say %q: %v", tc.why, want, err)
			}
		}
	}

	// CONTROL: the redundant case with the declaration removed marks cleanly.
	clean := Registry{"shipped": &policy.Profile{Name: "shipped", Environ: policy.EnvGrants{
		Set: map[string]string{"XDG_CONFIG_HOME": "{home}/.config"}}}}
	if _, err := mark(clean); err != nil {
		t.Fatalf("control: the same builtin without the declaration was refused: %v", err)
	}
}

// TestParseDecodesEnvironTypes would catch the TOML door reading a kind it
// does not know as one it does, or losing which file, profile and key an
// author has to edit.
func TestParseDecodesEnvironTypes(t *testing.T) {
	const source = "/home/u/.config/snug/profiles.d/mine.toml"
	reg, err := parse([]byte(`
[profile.ruby]
ro = ["/opt/gems"]
[profile.ruby.environ.types]
GEM_PATH = "path-list"
GEM_HOME = "path"
[profile.ruby.environ.merge]
GEM_PATH = ["/opt/gems"]
[profile.ruby.environ.set]
GEM_HOME = "/opt/gems"
`), source, true)
	if err != nil {
		t.Fatalf("a well-formed environ.types block was refused: %v", err)
	}
	got := reg["ruby"].Environ.Types
	if len(got) != 2 || got["GEM_PATH"] != policy.EnvKindPathList || got["GEM_HOME"] != policy.EnvKindPath {
		t.Errorf("Types = %v, want GEM_PATH path-list and GEM_HOME path", got)
	}

	for _, tc := range []struct {
		why   string
		src   string
		wants []string
	}{
		{"an unknown kind", "[profile.ruby.environ.types]\nGEM_PATH = \"paths\"\n" +
			"[profile.ruby.environ.merge]\nGEM_PATH = [\"/opt/gems\"]\n",
			[]string{"mine.toml", `profile "ruby"`, `environ.types "GEM_PATH"`, `unknown environ type "paths"`,
				"want path or path-list"}},
		// Quoted, because the key has not been through the name grammar yet.
		{"an unknown kind under a malformed key", "[profile.ruby.environ.types]\n\"MY-PATH\" = \"list\"\n",
			[]string{"mine.toml", `environ.types "MY-PATH"`, `unknown environ type "list"`}},
		{"a kind that is not a string", "[profile.ruby.environ.types]\nGEM_PATH = 1\n",
			[]string{"mine.toml"}},
		// The kind is valid; ValidateEnvGrants' verdict still carries the file.
		{"a declaration nothing uses", "[profile.ruby.environ.types]\nGEM_PATH = \"path-list\"\n",
			[]string{"mine.toml", `profile "ruby"`, "neither merges nor prepends"}},
	} {
		_, err := parse([]byte("[profile.ruby]\n"+tc.src), source, true)
		if err == nil {
			t.Errorf("%s: accepted", tc.why)
			continue
		}
		for _, want := range tc.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q does not contain %q", tc.why, err, want)
			}
		}
	}
}
