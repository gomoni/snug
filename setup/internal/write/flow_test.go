package write

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/probe"
	"github.com/gomoni/snug/setup/internal/testworld"
)

func newDraft(w *testworld.World, name string) *draft.Draft {
	d := draft.New(w.Host())
	d.Name = name
	d.Propose(draft.Action{Op: draft.OpUseProfile, Name: "@net"}, "test")
	return d
}

func TestPrepareNoSnugNotes(t *testing.T) {
	w := testworld.New(t)
	p, err := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "", w.Run, nil, nil, nil)
	if err != nil || !strings.Contains(strings.Join(p.Notes, "\n"), "not verified by snug") || len(p.Blocked) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if p.Path != filepath.Join(w.ProfDir, "x.toml") || p.Overwrite {
		t.Errorf("%+v", p)
	}
	if len(w.Cmds) != 0 {
		t.Errorf("ran %v without snug", w.Cmds)
	}
}

func TestPrepareChecksWithSnug(t *testing.T) {
	w := testworld.New(t)
	p, err := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "/fake/snug", w.Run, nil, nil, nil)
	if err != nil || len(p.Blocked) != 0 || len(p.Notes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if !strings.HasPrefix(p.Title(), "writes ") || strings.Contains(p.Body(), "not written") {
		t.Errorf("%s\n%s", p.Title(), p.Body())
	}
}

func TestWriteOverwriteShowsDiff(t *testing.T) {
	w := testworld.New(t)
	w.Profile("x.toml", "[profile.x]\ninclude = [\"@git\"]\n")
	p, err := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "", w.Run,
		[]ingest.Profile{{Name: "x", File: "x.toml", Dir: w.ProfDir}}, nil, nil)
	if err != nil || !p.Overwrite || len(p.Blocked) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	s := p.Title() + "\n" + p.Body()
	for _, want := range []string{"overwrites", "\n- include = [\"@git\"]", "\n+ "} {
		if !strings.Contains(s, want) {
			t.Errorf("screen lacks %q:\n%s", want, s)
		}
	}
	if err := Apply(p); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := ReadProfile(p.Path); got != p.New {
		t.Errorf("not written")
	}
}

func TestApplyRefusesOverwriteOfChangedFile(t *testing.T) {
	w := testworld.New(t)
	w.Profile("x.toml", "a\n")
	p, _ := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "", w.Run, nil, nil, nil)
	w.Profile("x.toml", "b\n")
	if err := Apply(p); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Errorf("err %v", err)
	}
	if got, _, _ := ReadProfile(p.Path); got != "b\n" {
		t.Errorf("file touched: %q", got)
	}
}

func TestApplyNewFileDoesNotReplaceOneThatAppeared(t *testing.T) {
	w := testworld.New(t)
	p, _ := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "", w.Run, nil, nil, nil)
	w.Profile("x.toml", "theirs\n")
	if err := Apply(p); err == nil {
		t.Errorf("a file that appeared since the diff was replaced")
	}
	if got, _, _ := ReadProfile(p.Path); got != "theirs\n" {
		t.Errorf("file touched: %q", got)
	}
}

func TestRunLineDot(t *testing.T) {
	w := testworld.New(t)
	d := newDraft(w, "x")
	if got := RunLine(d, w.Target); got != "snug -p x ." {
		t.Errorf("%q", got)
	}
	if got := RunLine(d, "/elsewhere"); got != "snug -p x "+w.Target {
		t.Errorf("%q", got)
	}
}

func TestPrepareVerifyMismatchBlocks(t *testing.T) {
	w := testworld.New(t)
	d := newDraft(w, "x")
	data := t.TempDir()
	if o := d.Propose(draft.Action{Op: draft.OpGrantPath, Path: data, Access: "rw"}, "test"); o.Refused != "" {
		t.Fatal(o.Msg)
	}
	w.DryRunDoc = `{"snug":{"format":2,"outcome":"ok","policy_resolved":true},"profiles":{"selected":["@sys","@home","@target-rw","x","@net"],"implied":[]},"network":{"mode":"egress","egress":true}}`
	p, err := Prepare(context.Background(), d, w.ProfDir, "/fake/snug", w.Run, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], data) {
		t.Fatalf("blocked %v", p.Blocked)
	}
	if err := Apply(p); err == nil {
		t.Errorf("a blocked plan was applied")
	}
	if !strings.Contains(p.Body(), "not written") {
		t.Errorf("a blocked plan does not say so:\n%s", p.Body())
	}
}

func TestPrepareIdentityRefusalIsNote(t *testing.T) {
	w := testworld.New(t)
	d := newDraft(w, "x")
	d.Propose(draft.Action{Op: draft.OpIncludeProfile, Name: "vyskocilm"}, "test")
	w.DryRunDoc = `{"snug":{"format":2,"outcome":"refused","policy_resolved":false},"refusal":{"message":"profile \"vyskocilm\" includes \"@cwd-rw\", which is now \"@target-rw\""}}`
	warn := &probe.Warning{Profiles: []string{"vyskocilm"}}
	p, err := Prepare(context.Background(), d, w.ProfDir, "/fake/snug", w.Run, nil, nil, warn)
	if err != nil || len(p.Blocked) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "vyskocilm: refused by snug, profile will not run") {
		t.Errorf("notes %v", p.Notes)
	}
	// A refusal naming some other profile is not excused.
	w.DryRunDoc = strings.ReplaceAll(w.DryRunDoc, "vyskocilm", "someone-else")
	if p, _ := Prepare(context.Background(), d, w.ProfDir, "/fake/snug", w.Run, nil, nil, warn); len(p.Blocked) == 0 {
		t.Errorf("a refusal that does not name the identity profile was excused")
	}
	if namesProfile("network is down", "work") {
		t.Errorf("name matched inside a word")
	}
}

func TestPrepareNameDefinedElsewhereBlocks(t *testing.T) {
	w := testworld.New(t)
	other := ingest.Profile{Name: "foo", File: "accounts.toml", Dir: w.ProfDir}
	p, err := Prepare(context.Background(), newDraft(w, "foo"), w.ProfDir, "", w.Run, []ingest.Profile{other}, nil, nil)
	if err != nil || len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], "accounts.toml") || !strings.Contains(p.Blocked[0], "change NAME") {
		t.Fatalf("%+v %v", p, err)
	}
	same := ingest.Profile{Name: "foo", File: "foo.toml", Dir: w.ProfDir}
	if p, _ := Prepare(context.Background(), newDraft(w, "foo"), w.ProfDir, "", w.Run, []ingest.Profile{same}, nil, nil); len(p.Blocked) != 0 {
		t.Errorf("foo.toml may be overwritten: %v", p.Blocked)
	}
	if _, err := Prepare(context.Background(), newDraft(w, "bad_name"), w.ProfDir, "", w.Run, nil, nil, nil); err == nil {
		t.Errorf("invalid name accepted")
	}
}

const accounts = "# keep\n[profile.a]\ninclude = [\"@cwd-rw\"] # old\n"

func fixWarning(t *testing.T, body string) (probe.Warning, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "accounts.toml")
	if err := os.WriteFile(f, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return probe.Warning{File: f, Profiles: []string{"a"}, Old: "@cwd-rw", New: "@target-rw"}, f
}

func TestApplyFixBackupFirst(t *testing.T) {
	w, f := fixWarning(t, accounts)
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	path, backup, oldB, newB, err := PrepareFix(w, now)
	if err != nil || path != f || backup != f+".bak-20261017" {
		t.Fatalf("%q %q %v", path, backup, err)
	}
	if !strings.Contains(LineDiff(string(oldB), string(newB)), "+ include = [\"@target-rw\"] # old") {
		t.Errorf("diff %s", LineDiff(string(oldB), string(newB)))
	}
	if err := ApplyFix(path, backup, oldB, newB); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(backup); string(b) != accounts {
		t.Errorf("backup %q", b)
	}
	if b, _ := os.ReadFile(f); string(b) != "# keep\n[profile.a]\ninclude = [\"@target-rw\"] # old\n" {
		t.Errorf("file %q", b)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	if err := ApplyFix(path, backup, newB, newB); err == nil {
		t.Errorf("an existing backup was overwritten")
	}
}

func TestApplyFixRefusesChangedFile(t *testing.T) {
	w, f := fixWarning(t, accounts)
	path, backup, oldB, newB, err := PrepareFix(w, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, []byte("someone else\n"), 0o640)
	if err := ApplyFix(path, backup, oldB, newB); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Errorf("err %v", err)
	}
	if _, err := os.Stat(backup); err == nil {
		t.Errorf("backup written for a refused fix")
	}
	if b, _ := os.ReadFile(f); string(b) != "someone else\n" {
		t.Errorf("file touched")
	}
}

func TestPrepareFixRefusals(t *testing.T) {
	w, f := fixWarning(t, accounts)
	link := filepath.Join(t.TempDir(), "link.toml")
	os.Symlink(f, link)
	lw := w
	lw.File = link
	if _, _, _, _, err := PrepareFix(lw, time.Now()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink: %v", err)
	}
	if _, _, _, _, err := PrepareFix(probe.Warning{File: f}, time.Now()); err == nil {
		t.Errorf("no rename accepted")
	}
	w2, _ := fixWarning(t, "# @cwd-rw only in a comment\n")
	if _, _, _, _, err := PrepareFix(w2, time.Now()); err == nil || !strings.Contains(err.Error(), "nothing to rename") {
		t.Errorf("no token: %v", err)
	}
}

func TestIdentityFiles(t *testing.T) {
	files := []ingest.ProfileFile{
		{Name: "accounts.toml", Body: []byte("a"), Defines: []string{"vyskocilm", "plainsof"}},
		{Name: "tools.toml", Body: []byte("t"), Defines: []string{"gh-cli"}},
		{Name: "unrelated.toml", Body: []byte("u"), Defines: []string{"other"}},
		{Name: "old.toml", Body: []byte("o"), Defines: []string{"mine"}},
	}
	profiles := []ingest.Profile{
		{Name: "vyskocilm", Include: []string{"@net", "gh-cli"}},
		{Name: "gh-cli", Include: []string{"@net"}},
	}
	got := IdentityFiles(files, profiles, "vyskocilm", "mine")
	if len(got) != 2 || !strings.HasSuffix(got[0].Name, "accounts.toml") || !strings.HasSuffix(got[1].Name, "tools.toml") {
		t.Errorf("%+v", got)
	}
	if IdentityFiles(files, profiles, "", "mine") != nil {
		t.Errorf("no identity must need no files")
	}
	if got := IdentityFiles(files, profiles, "other", "other"); len(got) != 0 {
		t.Errorf("the file defining the profile being written must be left out: %+v", got)
	}
}

func TestLineOf(t *testing.T) {
	body := "a\n[profile.x]\ninclude = [\n  \"@net\",\n]\n"
	if LineOf(body, "[profile.") != 2 || LineOf(body, `"@net"`) != 4 || LineOf(body, "absent") != 0 || LineOf(body, "") != 0 {
		t.Errorf("lines %d %d", LineOf(body, "[profile."), LineOf(body, `"@net"`))
	}
}

func TestDryRunTextUsesScratchConfig(t *testing.T) {
	w := testworld.New(t)
	d := newDraft(w, "x")
	var env []string
	var seen string
	run := func(_ context.Context, e []string, name string, args ...string) (hostfacts.Result, error) {
		env = e
		x := strings.TrimPrefix(e[0], "XDG_CONFIG_HOME=")
		b, err := os.ReadFile(filepath.Join(x, "snug", "profiles.d", "x.toml"))
		seen = string(b)
		return hostfacts.Result{Stdout: []byte("out " + strings.Join(args, " "))}, err
	}
	out, err := DryRunText(context.Background(), run, "snug", d, nil)
	if err != nil || out != "out --dry-run -p x "+w.Target || len(env) != 1 || seen != d.Render() {
		t.Errorf("%q %v %v", out, err, env)
	}
	if _, err := os.Stat(strings.TrimPrefix(env[0], "XDG_CONFIG_HOME=")); err == nil {
		t.Errorf("scratch directory left behind")
	}
}

func TestAfterWrite(t *testing.T) {
	const run = "snug -p x ."
	for _, c := range []struct {
		name, dir string
		want      []string
	}{
		{"default", "/home/a/.config/snug/profiles.d/", []string{run}},
		{"xdg shaped", "/tmp/my cfg/snug/profiles.d", []string{
			"snug will not look in /tmp/my cfg/snug/profiles.d: it reads /home/a/.config/snug/profiles.d",
			"XDG_CONFIG_HOME='/tmp/my cfg' " + run}},
		{"other", "/tmp/profiles", []string{
			"snug will not look in /tmp/profiles: it reads /home/a/.config/snug/profiles.d; move the file there to use it"}},
	} {
		got := AfterWrite(run, c.dir, "/home/a/.config/snug/profiles.d")
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestPrepareSymlinkTargetBlocks(t *testing.T) {
	w := testworld.New(t)
	real := filepath.Join(t.TempDir(), "real.toml")
	if err := os.WriteFile(real, []byte("[profile.x]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(w.ProfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(w.ProfDir, "x.toml")); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(context.Background(), newDraft(w, "x"), w.ProfDir, "", w.Run, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], "is a symlink") {
		t.Fatalf("blocked %v", p.Blocked)
	}
	if err := Apply(p); err == nil {
		t.Errorf("a blocked plan applied")
	}
	if got, _, _ := ReadProfile(real); got != "[profile.x]\n" {
		t.Errorf("the link's target was touched: %q", got)
	}
}
