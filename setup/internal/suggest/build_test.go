package suggest

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
)

var update = flag.Bool("update", false, "rewrite golden files")

func hostFor(target string) draft.Host { return draft.Host{Home: home, Target: target} }

func claudeGoFacts() ingest.Facts {
	t := goFacts()
	t.Claude = true
	return ingest.Facts{
		Target:   t,
		Profiles: []ingest.Profile{profile("vyskocilm", "github.com", "m@example.org", "gh-cli")},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
}

func TestBuildGolden(t *testing.T) {
	const target = "/home/alice/work/app"
	f := claudeGoFacts()
	f.Profiles[0].Description = "work account"
	d, refused := Build(Suggest(f, home, target), hostFor(target), f.Profiles)
	if len(refused) != 0 {
		t.Fatalf("refused: %v", refused)
	}
	got := d.Render()
	path := filepath.Join("testdata", "build-claude-go.toml")
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
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("differs from %s:\n%s", path, got)
	}
}

func TestBuildGitOnlyWithoutIdentity(t *testing.T) {
	const target = "/home/alice/work/app"
	f := claudeGoFacts()
	s := Suggest(f, home, target)
	d, _ := Build(s, hostFor(target), f.Profiles)
	if slices.Contains(d.Includes(), "@git") || !slices.Contains(d.Includes(), "vyskocilm") {
		t.Errorf("identity set: %v", d.Includes())
	}
	s.Pick[Identity] = 0
	d, _ = Build(s, hostFor(target), f.Profiles)
	if !slices.Contains(d.Includes(), "@git") || slices.Contains(d.Includes(), "vyskocilm") {
		t.Errorf("identity none: %v", d.Includes())
	}
}

func TestBuildChangedRowsOnly(t *testing.T) {
	const target = "/home/alice/work/app"
	s := Suggest(claudeGoFacts(), home, target)
	s.Pick[Network] = 1
	d, _ := Build(s, hostFor(target), nil)
	if slices.Contains(d.Includes(), "@net") || !slices.Contains(d.Includes(), "@claude") {
		t.Errorf("includes %v", d.Includes())
	}
}

func TestBuildUnsureStartsOffAndTurnsOn(t *testing.T) {
	const target = "/home/alice/work/app"
	f := ingest.Facts{Target: ingest.TargetFacts{Containers: []string{"Containerfile"}}}
	s := Suggest(f, home, target)
	d, _ := Build(s, hostFor(target), nil)
	if slices.Contains(d.Includes(), "@podman-build") {
		t.Errorf("unsure pick on by default: %v", d.Includes())
	}
	s.Pick[Containers] = 0
	d, _ = Build(s, hostFor(target), nil)
	if !slices.Contains(d.Includes(), "@podman-build") {
		t.Errorf("includes %v", d.Includes())
	}
}

func TestBuildParentROUnderHomeNotes(t *testing.T) {
	const target = "/home/alice/app"
	s := Suggest(ingest.Facts{}, home, target)
	s.Pick[Base] = 0
	d, refused := Build(s, hostFor(target), nil)
	if slices.Contains(d.Includes(), "@parent-ro") {
		t.Errorf("includes %v", d.Includes())
	}
	if !strings.Contains(refused[Base], "@parent-ro would be $HOME") {
		t.Errorf("refused %v", refused)
	}
}

func TestBuildEnvAndNameRefusal(t *testing.T) {
	const target = "/home/alice/work/app"
	s := Suggest(ingest.Facts{Target: goFacts()}, home, target)
	d, _ := Build(s, hostFor(target), nil)
	out := d.Render()
	if !strings.Contains(out, `GOMODCACHE = "{target}/.cache/go-mod"`) {
		t.Errorf("env missing:\n%s", out)
	}
	s.Text[Name] = "bad_name"
	_, refused := Build(s, hostFor(target), nil)
	if refused[Name] == "" {
		t.Errorf("an invalid name must be reported on its row: %v", refused)
	}
}
