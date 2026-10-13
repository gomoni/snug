package verify

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/intent"
)

type info struct{ fs.FileInfo }

func (info) Mode() fs.FileMode { return 0o644 }

func host() draft.Host {
	return draft.Host{
		Home: "/home/alice", Target: "/home/alice/src/webapp",
		EvalSymlinks: func(p string) (string, error) { return p, nil },
		Stat:         func(string) (fs.FileInfo, error) { return info{}, nil },
	}
}

func fixture(t *testing.T, name string) Doc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func say(d *draft.Draft, text string, acts ...intent.Action) {
	for _, a := range acts {
		d.Propose(a, draft.SourceUser, text, 1)
	}
}

func use(n string) intent.Action  { return intent.Action{Op: intent.OpUseProfile, Name: n} }
func drop(n string) intent.Action { return intent.Action{Op: intent.OpDropProfile, Name: n} }
func grant(p, a string) intent.Action {
	return intent.Action{Op: intent.OpGrantPath, Path: p, Access: a}
}

func netRO() *draft.Draft {
	d := draft.New(host())
	d.Name = "work"
	say(d, "needs internet", use("@net"))
	say(d, "let it read /srv/data", grant("/srv/data", "ro"))
	return d
}

func wantDiffs(t *testing.T, got []Diff, wants ...string) {
	t.Helper()
	if len(got) != len(wants) {
		t.Errorf("%d diffs, want %d: %v", len(got), len(wants), got)
	}
	for i, w := range wants {
		if i < len(got) && !strings.Contains(got[i].String(), w) {
			t.Errorf("diff %d: %q lacks %q", i, got[i], w)
		}
	}
}

func TestCompareMatches(t *testing.T) {
	wantDiffs(t, Compare(netRO(), fixture(t, "net-ro.json")))

	d := draft.New(host())
	d.Name = "review"
	say(d, "read-only here", grant("{target}", "ro"))
	wantDiffs(t, Compare(d, fixture(t, "readonly.json")))
}

func TestCompareRefusal(t *testing.T) {
	wantDiffs(t, Compare(netRO(), fixture(t, "refused.json")), "snug refused the draft: fixture refusal naming /srv/missing")
}

func TestCompareFindsEachDifference(t *testing.T) {
	cases := []struct {
		name   string
		draft  func() *draft.Draft
		mutate func(*Doc)
		want   []string
	}{
		{"requested profile missing", netRO, func(doc *Doc) {
			doc.Profiles.Implied = nil
			doc.Network.Egress, doc.Network.Mode = false, "isolated"
		}, []string{`"needs internet" asked for @net; snug's resolved selection does not have it`}},
		{"profile nobody asked for", netRO, func(doc *Doc) { doc.Profiles.Implied = append(doc.Profiles.Implied, "@claude") },
			[]string{"snug selects @claude, which nothing in the intent ledger asked for\n    fix: say \"drop @claude\""}},
		{"egress without @net", netRO, func(doc *Doc) { doc.Profiles.Implied = nil }, []string{
			`asked for @net; snug's resolved selection does not have it`, "snug's network is egress (egress true) while @net is not selected"}},
		{"access widened", netRO, func(doc *Doc) { doc.Mounts[3].Access = "rw" },
			[]string{`"let it read /srv/data" asked for ro on /srv/data; snug mounts it rw`}},
		{"grant missing", netRO, func(doc *Doc) { doc.Mounts = doc.Mounts[:3] },
			[]string{"asked for ro on /srv/data; snug mounts nothing there from work"}},
		{"mount nobody asked for", netRO, func(doc *Doc) {
			doc.Mounts = append(doc.Mounts, doc.Mounts[3])
			doc.Mounts[len(doc.Mounts)-1].Guest = "/srv/other"
		}, []string{"snug mounts /srv/other (ro) from work, which nothing in the intent ledger asked for"}},
		{"profile not selected", netRO, func(doc *Doc) { doc.Profiles.Selected = doc.Profiles.Selected[:3] },
			[]string{"snug did not select the profile work"}},
		{"dropping a default", func() *draft.Draft {
			d := netRO()
			say(d, "no write access", drop("@target-rw"))
			return d
		}, func(*Doc) {}, []string{"\"no write access\" asked to drop @target-rw; snug still selects it\n    fix: @target-rw comes with a bare `snug DIR`, so dropping it from the profile removes nothing; say \"read-only here\""}},
		{"dropped @net still there", func() *draft.Draft {
			d := draft.New(host())
			d.Name = "work"
			say(d, "let it read /srv/data", grant("/srv/data", "ro"))
			say(d, "keep it offline", drop("@net"))
			return d
		}, func(*Doc) {}, []string{
			`"keep it offline" asked to drop @net; snug still selects it`,
			"snug selects @net, which nothing in the intent ledger asked for"}},
		{"read-only target resolved writable", func() *draft.Draft {
			d := draft.New(host())
			d.Name = "review"
			say(d, "read-only here", grant("{target}", "ro"))
			return d
		}, func(doc *Doc) {
			doc.Profiles.Implied = append(doc.Profiles.Implied, "@target-rw")
			doc.Mounts[1].Access = "rw"
		}, []string{
			"snug selects @target-rw, which nothing in the intent ledger asked for",
			`"read-only here" asked for ro on /home/alice/src/webapp; snug mounts it rw`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := c.draft()
			file := "net-ro.json"
			if d.Name == "review" {
				file = "readonly.json"
			}
			doc := fixture(t, file)
			c.mutate(&doc)
			wantDiffs(t, Compare(d, doc), c.want...)
		})
	}
}

func TestParseRefuses(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":   "snug: unknown flag --json",
		"format 1":   `{"snug":{"format":1,"outcome":"ok","policy_resolved":true}}`,
		"format 3":   `{"snug":{"format":3,"outcome":"ok","policy_resolved":true}}`,
		"lossy":      `{"snug":{"format":2,"outcome":"ok","lossy":true,"policy_resolved":true}}`,
		"no snug":    `{}`,
		"wrong type": `{"snug":{"format":"2"}}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestRunWithoutDocument(t *testing.T) {
	d := netRO()
	run := func(context.Context, []string, string, ...string) (hostfacts.Result, error) {
		return hostfacts.Result{Stderr: []byte("boom")}, exec.ErrNotFound
	}
	if _, err := Run(context.Background(), run, "/nowhere/snug", d); err == nil || !strings.Contains(err.Error(), "cannot be run") {
		t.Errorf("%v", err)
	}
}

// TestCheckAgainstRealSnug builds snug from the root module and runs the check
// the way /save does. It is skipped, loudly, when the build is impossible; the
// comparison is then held only by the fixtures above, which were written to
// snug's format by hand.
func TestCheckAgainstRealSnug(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "snug")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/snug")
	cmd.Dir = "../../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build snug from the root module: %v\n%s", err, out)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	target, data := t.TempDir(), t.TempDir()
	h := draft.Host{Home: home, Target: target}
	ctx := context.Background()

	ok := draft.New(h)
	ok.Name = "checked"
	say(ok, "needs internet and podman builds", use("@net"), use("@podman-build"))
	say(ok, "read the data", grant(data, "ro"))
	say(ok, "scratch at /work", grant("/work", "tmpfs"))

	ro := draft.New(h)
	ro.Name = "review"
	say(ro, "read-only here", grant("{target}", "ro"))

	// redteam setup r3 R3-3: a prepend under the target, with the grant
	// the draft now asks for first, is one snug accepts.
	os.MkdirAll(filepath.Join(target, "bin"), 0o755)
	pathed := draft.New(h)
	pathed.Name = "pathed"
	say(pathed, "put the project's bin on PATH", grant("{target}/bin", "ro"),
		intent.Action{Op: intent.OpSetEnv, Name: "PATH", Verb: "prepend", Value: "{target}/bin", HasValue: true})
	if !strings.Contains(pathed.Render(), `PATH = ["{target}/bin"]`) {
		t.Fatalf("the prepend did not land:\n%s", pathed.Render())
	}

	dropped := draft.New(h)
	dropped.Name = "nowrite"
	say(dropped, "no write access", drop("@target-rw"))

	for _, c := range []struct {
		d    *draft.Draft
		want []string
	}{
		{ok, nil},
		{ro, nil},
		{pathed, nil},
		{dropped, []string{"asked to drop @target-rw; snug still selects it"}},
	} {
		doc, err := Run(ctx, hostfacts.ExecRunner, bin, c.d)
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.d.Name, err, c.d.Render())
		}
		t.Run(c.d.Name, func(t *testing.T) { wantDiffs(t, Compare(c.d, doc), c.want...) })
	}

	missing := draft.New(h)
	missing.Name = "missing"
	say(missing, "read /nonexistent", grant(filepath.Join(data, "not-there"), "ro"))
	doc, err := Run(ctx, hostfacts.ExecRunner, bin, missing)
	if err != nil {
		t.Fatal(err)
	}
	wantDiffs(t, Compare(missing, doc), "snug refused the draft")
}

// TestDefaultsMatchSnug holds Defaults equal to profile.BuiltinDefaults in
// snug's source, the list it copies.
func TestDefaultsMatchSnug(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/defaults.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)func BuiltinDefaults\(\) \[\]policy\.ProfileName \{\s*return \[\]policy\.ProfileName\{([^}]*)\}`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("no BuiltinDefaults in internal/profile/defaults.go")
	}
	var want []string
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(m[1], -1) {
		want = append(want, string(q[1]))
	}
	if !slices.Equal(Defaults, want) {
		t.Errorf("Defaults = %v, snug's BuiltinDefaults = %v", Defaults, want)
	}
}
