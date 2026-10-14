package ingest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const accounts = `# comment [profile.fake]
[profile.vyskocilm]
description = "GitHub account A: its ssh key, # not a comment"
include = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@net", "gh-cli"]
  [profile.vyskocilm.identity.ssh]
  host  = "github.com"
  key   = "{home}/.ssh/github_auth_id_ed25519.pub"
  agent = "proxy"
  [profile.vyskocilm.identity.git]
  name        = "Michal Vyskocil"
  email       = "michal.vyskocil@gmail.com"
  signing_key = "{home}/.ssh/github_sign_id_ed25519.pub"
  [profile.vyskocilm.identity.gh]
  host = "github.com"
  user = "vyskocilm"

# [profile.cv]
# description = "commented out"

[profile.cv-dev]
description = "phase01 development."
include = [
  "@net", # internet
  "@claude",
]
listen_names = ["web"]

[profile."quoted-one"]
include = ["@sys"]
[profile.dotted]
identity.git.email = "d@example.org"
`

func TestParseProfiles(t *testing.T) {
	ps, err := ParseProfiles(accounts)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Profile{}
	var names []string
	for _, p := range ps {
		byName[p.Name] = p
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"cv-dev", "dotted", "quoted-one", "vyskocilm"}) {
		t.Fatalf("names %v", names)
	}
	v := byName["vyskocilm"]
	if v.Description != "GitHub account A: its ssh key, # not a comment" {
		t.Errorf("description %q", v.Description)
	}
	if !slices.Equal(v.Include, []string{"@sys", "@home", "@cwd-rw", "@parent-ro", "@net", "gh-cli"}) {
		t.Errorf("include %v", v.Include)
	}
	want := ProfileIdentity{SSHKey: "{home}/.ssh/github_auth_id_ed25519.pub", SSHHost: "github.com", SigningKey: "{home}/.ssh/github_sign_id_ed25519.pub",
		GitName: "Michal Vyskocil", Email: "michal.vyskocil@gmail.com", GHUser: "vyskocilm", GHHost: "github.com"}
	if v.Identity != want {
		t.Errorf("identity %+v", v.Identity)
	}
	if !slices.Equal(byName["cv-dev"].Include, []string{"@net", "@claude"}) {
		t.Errorf("multi-line include %v", byName["cv-dev"].Include)
	}
	if byName["cv-dev"].Identity.Pins() {
		t.Error("cv-dev pins nothing")
	}
	if byName["dotted"].Identity.Email != "d@example.org" {
		t.Errorf("dotted key: %+v", byName["dotted"].Identity)
	}
}

// TestParseProfilesIsTOML: shapes the old line reader misread. A header-looking
// line inside a multi-line string invented a profile; an inline-table identity
// was dropped; a unicode escape was copied literally.
func TestParseProfilesIsTOML(t *testing.T) {
	ps, err := ParseProfiles("[profile.real]\ndescription = \"\"\"\nfirst\n[profile.fake]\n\"\"\"\n" +
		"[profile.inline]\nidentity = { git = { email = \"i@example.org\" }, gh = { user = \"u\" } }\n" +
		"[profile.esc]\ndescription = \"caf\\u00e9\"\n")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Profile{}
	for _, p := range ps {
		by[p.Name] = p
	}
	if _, ok := by["fake"]; ok || len(ps) != 3 {
		t.Errorf("a header inside a string made a profile: %+v", ps)
	}
	if by["inline"].Identity.Email != "i@example.org" || by["inline"].Identity.GHUser != "u" {
		t.Errorf("inline table: %+v", by["inline"].Identity)
	}
	if by["esc"].Description != "caf\u00e9" {
		t.Errorf("escape: %q", by["esc"].Description)
	}
	if _, err := ParseProfiles("[profile.a\n"); err == nil {
		t.Error("invalid TOML accepted")
	}
}

func TestLoadProfilesReportsInvalidTOML(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "bad.toml"), []byte("[profile.a\n"), 0o644)
	ps, files, warns := LoadProfiles([]string{d})
	if len(ps) != 0 || len(files) != 1 || len(warns) != 1 || !strings.Contains(warns[0], "bad.toml") {
		t.Errorf("%v %v %v", ps, files, warns)
	}
}

func TestLoadProfilesReadsLikeSnug(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "b.toml"), []byte("[profile.b]\n"), 0o644)
	os.WriteFile(filepath.Join(d, "a.toml"), []byte("[profile.a]\ndescription = \"x\"\n"), 0o644)
	os.WriteFile(filepath.Join(d, "notes.txt"), []byte("[profile.c]\n"), 0o644)
	os.Mkdir(filepath.Join(d, "sub.toml"), 0o755)
	if err := syscall.Mkfifo(filepath.Join(d, "fifo.toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, files, warns := LoadProfiles([]string{filepath.Join(d, "missing"), d})
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"a", "b"}) {
		t.Errorf("names %v", names)
	}
	if len(files) != 2 || files[0].Name != "a.toml" || !slices.Equal(files[0].Defines, []string{"a"}) {
		t.Errorf("files %+v", files)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "fifo.toml") {
		t.Errorf("warnings %v", warns)
	}
}

// TestProfileDirsAreSnugs holds ProfileDirs to the directories snug's
// ConfigDirs lists: the same system root, the same $XDG_CONFIG_HOME/snug with
// its $HOME/.config fallback, the same profiles.d leaf, and nothing else. The
// setup module cannot import snug's internal/profile, so it reads the source.
func TestProfileDirsAreSnugs(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/file.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	fn := func(sig string) string {
		i := strings.Index(src, sig)
		if i < 0 {
			t.Fatalf("%s is gone from internal/profile/file.go", sig)
		}
		return src[i : i+strings.Index(src[i:], "\n}\n")]
	}
	if !strings.Contains(src, `const systemConfigRoot = "/etc/snug"`) {
		t.Error(`snug's systemConfigRoot is no longer "/etc/snug"; ProfileDirs must follow it`)
	}
	for sig, wants := range map[string][]string{
		"func ConfigDirs() []string {": {
			`filepath.Join(systemConfigRoot, "profiles.d")`,
			`filepath.Join(user, "profiles.d")`,
		},
		"func userConfigRoot() string {": {
			`os.Getenv("XDG_CONFIG_HOME")`,
			`filepath.Join(xdg, "snug")`,
			`homeConfigRoot()`,
		},
		"func homeConfigRoot() string {": {`filepath.Join(home, ".config", "snug")`},
	} {
		body := fn(sig)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("snug's %s no longer contains %s; ProfileDirs must follow it", sig, want)
			}
		}
	}
	if got := ProfileDirs("", "/home/u"); !slices.Equal(got, []string{"/etc/snug/profiles.d", "/home/u/.config/snug/profiles.d"}) {
		t.Errorf("default: %v", got)
	}
	if got := ProfileDirs("/x", "/home/u"); !slices.Equal(got, []string{"/etc/snug/profiles.d", "/x/snug/profiles.d"}) {
		t.Errorf("xdg: %v", got)
	}
}
