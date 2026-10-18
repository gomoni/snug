package ingest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeTargetReadsMarkers(t *testing.T) {
	d := t.TempDir()
	write(t, d, "go.mod", "// c\nmodule github.com/acme/app\n\ngo 1.22\n")
	write(t, d, "web/package.json", `{"name":"app-web","version":"1"}`)
	write(t, d, "pyproject.toml", "[build-system]\nname = \"no\"\n[project]\nname = \"pyapp\"\n")
	write(t, d, "Cargo.toml", "[package]\nname = 'crate'\n")
	write(t, d, "Dockerfile", "FROM scratch\n")
	write(t, d, "compose.yaml", "services: {}\n")
	write(t, d, ".env", "X=1\n")
	write(t, d, ".env.example", "X=\n")
	write(t, d, "id_rsa", "x")
	write(t, d, "id_rsa.pub", "x")
	os.Mkdir(filepath.Join(d, ".git"), 0o755)
	os.Mkdir(filepath.Join(d, ".snug"), 0o755)

	f := AnalyzeTarget(d)
	got := map[string]string{}
	for _, l := range f.Languages {
		got[l.Marker] = l.Name + ":" + l.Project
	}
	want := map[string]string{"go.mod": "go:github.com/acme/app", "web/package.json": "node:app-web", "pyproject.toml": "python:pyapp", "Cargo.toml": "rust:crate"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all: %v)", k, got[k], v, got)
		}
	}
	if !f.Git || !f.RepoProfile {
		t.Errorf("git=%v repoProfile=%v", f.Git, f.RepoProfile)
	}
	if !slices.Equal(f.Containers, []string{"Dockerfile", "compose.yaml"}) {
		t.Errorf("containers %v", f.Containers)
	}
	if !slices.Equal(f.Secrets, []string{".env", "id_rsa"}) {
		t.Errorf("secrets %v", f.Secrets)
	}
}

// TestAnalyzeTargetDoesNotFollowOrBlock: a go.mod that links to a file outside
// the target, a package.json that is a FIFO and a name carrying an escape
// sequence yield no read of the link, no hang, and no control character.
func TestAnalyzeTargetDoesNotFollowOrBlock(t *testing.T) {
	outside := t.TempDir()
	write(t, outside, "secret", "module PRIVATE-KEY-BYTES\n")
	d := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(d, "go.mod")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(d, "package.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(t, d, "Cargo.toml", "[package]\nname = \"a\\u001b]0;x\x1b[2Jevil\"\n")
	write(t, d, "pyproject.toml", "[project]\nname = \"p\x1b[2Jq\"\n")

	f := AnalyzeTarget(d)
	for _, l := range f.Languages {
		if strings.Contains(l.Project, "PRIVATE") {
			t.Errorf("read through a symlink: %+v", l)
		}
		if strings.ContainsAny(l.Project, "\x1b\x00") {
			t.Errorf("control character kept: %q", l.Project)
		}
	}
	var sawGo, sawNode bool
	for _, l := range f.Languages {
		sawGo = sawGo || l.Name == "go"
		sawNode = sawNode || l.Name == "node"
		if l.Name == "go" && l.Project != "" || l.Name == "node" && l.Project != "" {
			t.Errorf("a name was read from a link or a FIFO: %+v", l)
		}
	}
	if !sawGo || !sawNode {
		t.Errorf("markers by name should still show: %+v", f.Languages)
	}
}

func TestAnalyzeTargetBoundsADirectory(t *testing.T) {
	d := t.TempDir()
	for i := 0; i < maxEntries+50; i++ {
		write(t, d, "f"+strings.Repeat("x", 1)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676)), "")
	}
	f := AnalyzeTarget(d)
	if len(f.Warnings) == 0 {
		t.Errorf("no warning for a directory over the bound")
	}
}

func TestProposeFromFacts(t *testing.T) {
	p := Propose(TargetFacts{
		Git:       true,
		Languages: []Lang{{"go", "go.mod", ""}, {"node", "web/package.json", ""}},
	})
	var names []string
	for _, i := range p.Include {
		names = append(names, i.Name)
		if i.Name == "@net" && i.Sure {
			t.Errorf("@net must never be sure")
		}
	}
	if !slices.Equal(names, []string{"@net"}) {
		t.Errorf("includes %v", names)
	}
	var env []string
	for _, e := range p.Env {
		env = append(env, e.Name)
		if !strings.HasPrefix(e.Value, "{target}/") {
			t.Errorf("%s=%s is not under the target", e.Name, e.Value)
		}
	}
	if !slices.Equal(env, []string{"GOMODCACHE", "GOCACHE", "NPM_CONFIG_CACHE"}) {
		t.Errorf("env %v", env)
	}
	if p := Propose(TargetFacts{Containers: []string{"compose.yaml"}}); p.Include[0].Name != "@podman-socket" {
		t.Errorf("compose only: %+v", p.Include)
	}
	if p := Propose(TargetFacts{Containers: []string{"Dockerfile"}}); p.Include[0].Name != "@podman-build" {
		t.Errorf("Dockerfile: %+v", p.Include)
	}
}

func TestAnalyzeTargetClaude(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(d string)
		want  bool
	}{
		{"CLAUDE.md", func(d string) { write(t, d, "CLAUDE.md", "x") }, true},
		{".claude dir", func(d string) { os.Mkdir(filepath.Join(d, ".claude"), 0o755) }, true},
		{".claude file", func(d string) { write(t, d, ".claude", "x") }, false},
		{".claude symlink", func(d string) { os.Symlink(t.TempDir(), filepath.Join(d, ".claude")) }, false},
		{"nothing", func(string) {}, false},
		{"only in a subdirectory", func(d string) { write(t, d, "sub/CLAUDE.md", "x") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			tc.setup(d)
			if got := AnalyzeTarget(d).Claude; got != tc.want {
				t.Errorf("Claude = %v, want %v", got, tc.want)
			}
		})
	}
}
