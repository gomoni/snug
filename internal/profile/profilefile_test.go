package profile

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

func parseOne(t *testing.T, src string) (Registry, error) {
	t.Helper()
	return parse([]byte(src), "test.toml", true)
}

func TestFileKeyParses(t *testing.T) {
	reg, err := parseOne(t, "[profile.w]\n[[profile.w.file]]\npath = \"/etc/gitconfig\"\ncontent = \"\"\"\n[init]\n\\tdefaultBranch = main\n\"\"\"\n[[profile.w.file]]\npath = \"/etc/empty\"\ncontent = \"\"\n")
	if err != nil {
		t.Fatal(err)
	}
	got := reg["w"].File
	if len(got) != 2 || got[0].Path != "/etc/gitconfig" || got[0].Content != "[init]\n\tdefaultBranch = main\n" ||
		got[1].Path != "/etc/empty" || got[1].Content != "" {
		t.Errorf("File = %#v", got)
	}
}

func TestFileRefusals(t *testing.T) {
	cases := map[string]struct{ src, want string }{
		"no content":          {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\n", "no `content`"},
		"no path":             {"[profile.w]\n[[profile.w.file]]\ncontent = \"x\"\n", "empty path"},
		"unknown subkey":      {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"x\"\nmode = \"0755\"\n", "unknown key"},
		"executable subkey":   {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"x\"\nexecutable = true\n", "unknown key"},
		"NUL":                 {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u0000b\"\n", "NUL"},
		"ESC":                 {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u001b[2Kb\"\n", "x1b"},
		"CR":                  {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\rb\"\n", `\r`},
		"DEL":                 {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u007fb\"\n", "x7f"},
		"NEL":                 {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u0085b\"\n", "u0085"},
		"RLO":                 {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u202eb\"\n", "u202e"},
		"LS":                  {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\u2028b\"\n", "u2028"},
		"duplicate path":      {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"x\"\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"y\"\n", "written twice"},
		"malformed":           {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"{profile.x}\"\n", "malformed"},
		"non-addressable":     {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"{profile.x.identity.git.signing_key}\"\n", "host path"},
		"unknown placeholder": {"[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"{nope}\"\n", "unknown placeholder"},
	}
	for name, c := range cases {
		_, err := parseOne(t, c.src)
		if err == nil {
			t.Errorf("%s: parsed", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q lacks %q", name, err, c.want)
		}
	}
}

func TestFileContentTabAndNewlineAreLegal(t *testing.T) {
	if _, err := parseOne(t, "[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"a\\tb\\nc\"\n"); err != nil {
		t.Fatal(err)
	}
}

func TestFileContentSizeLimit(t *testing.T) {
	src := func(n int) string {
		return "[profile.w]\n[[profile.w.file]]\npath = \"/a\"\ncontent = \"" + strings.Repeat("x", n) + "\"\n"
	}
	if _, err := parseOne(t, src(policy.MaxFileBytes)); err != nil {
		t.Errorf("64 KiB refused: %v", err)
	}
	if _, err := parseOne(t, src(policy.MaxFileBytes+1)); err == nil {
		t.Error("64 KiB + 1 accepted")
	}
}

func TestNoBuiltinCarriesAFile(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range reg {
		if len(p.File) != 0 {
			t.Errorf("builtin %s carries a `file`; a builtin's text is a decision snug makes for every user", name)
		}
	}
}
