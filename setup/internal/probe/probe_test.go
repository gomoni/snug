package probe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
)

func refusal(msg string) []byte {
	b, _ := json.Marshal(map[string]any{
		"snug":    map[string]any{"format": 2, "outcome": "refused", "policy_resolved": false},
		"refusal": map[string]any{"message": msg},
	})
	return b
}

const okDoc = `{"snug":{"format":2,"outcome":"ok","policy_resolved":true}}`

// fake answers each profile named after -p from answers; a name with no entry resolves.
func fake(answers map[string][]byte, ran *[]string) hostfacts.Runner {
	return func(_ context.Context, _ []string, name string, args ...string) (hostfacts.Result, error) {
		*ran = append(*ran, name+" "+strings.Join(args, " "))
		for i, a := range args {
			if a == "-p" {
				if doc, ok := answers[args[i+1]]; ok {
					return hostfacts.Result{Stdout: doc}, nil
				}
			}
		}
		return hostfacts.Result{Stdout: []byte(okDoc)}, nil
	}
}

func prof(name, file string) ingest.Profile {
	return ingest.Profile{Name: name, File: file, Dir: "/home/alice/.config/snug/profiles.d"}
}

const rename = "@cwd-rw is now @target-rw: the grant was always {target}"

func TestCheckGroupsRename(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"vyskocilm": refusal(rename), "plainsof": refusal(rename)}, &ran)
	ps := []ingest.Profile{prof("vyskocilm", "accounts.toml"), prof("fine", "other.toml"), prof("plainsof", "accounts.toml")}
	got := Check(context.Background(), run, "/usr/bin/snug", "/work/app", ps)
	if len(got) != 1 {
		t.Fatalf("want one warning, got %+v", got)
	}
	w := got[0]
	if w.Line != "vyskocilm, plainsof use @cwd-rw, renamed @target-rw" || w.Old != "@cwd-rw" || w.New != "@target-rw" {
		t.Errorf("warning %+v", w)
	}
	if w.File != "/home/alice/.config/snug/profiles.d/accounts.toml" || strings.Join(w.Profiles, ",") != "vyskocilm,plainsof" {
		t.Errorf("warning %+v", w)
	}
	if !strings.Contains(w.Full, "the grant was always") {
		t.Errorf("full %q", w.Full)
	}
	if len(ran) != 3 || ran[0] != "/usr/bin/snug --dry-run --json -p vyskocilm /work/app" {
		t.Errorf("ran %v", ran)
	}
}

func TestCheckGitRoSameShape(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"a": refusal("@git-ro is now @git: git is read-only by default")}, &ran)
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("a", "a.toml")})
	if len(got) != 1 || got[0].Old != "@git-ro" || got[0].New != "@git" || got[0].Line != "a uses @git-ro, renamed @git" {
		t.Errorf("%+v", got)
	}
}

func TestCheckRenameInsideWrappedMessage(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"a": refusal(`profile "a": include "@cwd-rw": @cwd-rw is now @target-rw: why`)}, &ran)
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("a", "a.toml")})
	if len(got) != 1 || got[0].Old != "@cwd-rw" {
		t.Errorf("%+v", got)
	}
}

func TestCheckOtherRefusalNoFix(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"a": refusal("something is wrong with it. Second sentence."), "b": refusal(strings.Repeat("x", 200))}, &ran)
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("a", "a.toml"), prof("b", "b.toml")})
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Old != "" || got[0].New != "" || got[0].Line != "a: something is wrong with it." {
		t.Errorf("%+v", got[0])
	}
	if got[1].Line != "b: "+strings.Repeat("x", 200) {
		t.Errorf("the line was cut: %q", got[1].Line)
	}
}

func TestCheckDoesNotRepeatTheProfileName(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"marp": refusal(`profile "marp" grants "/work/d/x" which does not exist. More.`)}, &ran)
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("marp", "marp.toml")})
	if len(got) != 1 || got[0].Line != `marp grants "/work/d/x" which does not exist.` {
		t.Errorf("%+v", got)
	}
}

func TestScopeIsIdentityCandidatesAndWhatTheDraftIncludes(t *testing.T) {
	pins := prof("work", "accounts.toml")
	pins.Identity = ingest.ProfileIdentity{SSHHost: "github.com", Email: "m@example.org"}
	tool := prof("gh-cli", "tools.toml")
	other := prof("marp", "marp.toml")
	d := draft.New(draft.Host{})
	d.Include = []string{"@net", "gh-cli"}
	got := Scope([]ingest.Profile{pins, tool, other}, d)
	if len(got) != 2 || got[0].Name != "work" || got[1].Name != "gh-cli" {
		t.Errorf("scope %+v", got)
	}
}

func TestCheckNoSnug(t *testing.T) {
	var ran []string
	if got := Check(context.Background(), fake(nil, &ran), "", "/w", []ingest.Profile{prof("a", "a.toml")}); got != nil || len(ran) != 0 {
		t.Errorf("got %v, ran %v", got, ran)
	}
}

func TestCheckSnugSilentIsAWarning(t *testing.T) {
	run := func(context.Context, []string, string, ...string) (hostfacts.Result, error) {
		return hostfacts.Result{}, nil
	}
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("a", "a.toml")})
	if len(got) != 1 || !strings.Contains(got[0].Line, "not checked") || got[0].Old != "" {
		t.Errorf("%+v", got)
	}
}

func TestCheckCleansSnugsMessage(t *testing.T) {
	var ran []string
	run := fake(map[string][]byte{"a": refusal("bad\x1b[2J thing\nsecond line")}, &ran)
	got := Check(context.Background(), run, "snug", "/w", []ingest.Profile{prof("a", "a.toml")})
	if len(got) != 1 || strings.ContainsRune(got[0].Line+got[0].Full, 0x1b) {
		t.Errorf("%q", got)
	}
}

func TestFixRenameKeepsBytes(t *testing.T) {
	body := `# my accounts, @cwd-rw below is a comment
[profile.vyskocilm]
description = "uses @cwd-rw"   # and here
include = [ # list
  "@sys",
  "@cwd-rw" ,   # the one
  '@cwd-rw',
  "@cwd-rw-extra",
  "gh-cli",
]
[profile.other]
include=["@cwd-rw","@net"]
note = '''
include = ["@cwd-rw"]
'''
`
	want := strings.NewReplacer(
		`  "@cwd-rw" ,   # the one`, `  "@target-rw" ,   # the one`,
		`  '@cwd-rw',`, `  '@target-rw',`,
		`include=["@cwd-rw","@net"]`, `include=["@target-rw","@net"]`,
	).Replace(body)
	got := string(FixRename([]byte(body), "@cwd-rw", "@target-rw"))
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if string(FixRename([]byte(body), "@absent", "@x")) != body {
		t.Errorf("no match must return the same bytes")
	}
}

func TestBackupPath(t *testing.T) {
	got := BackupPath("/a/accounts.toml", time.Date(2026, 10, 7, 23, 59, 0, 0, time.UTC))
	if got != "/a/accounts.toml.bak-20261007" {
		t.Errorf("%s", got)
	}
}
