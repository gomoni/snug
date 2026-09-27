package profile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// #624: a run refuses only when its selection reaches a profile a bad file
// defines, so the names a bad file defines are what that decision reads.
// Recovered whenever the file is TOML at all — an unknown key, a bad value and
// a refused name each leave them intact — and marked unknown when it is not.
func TestABadFileRecordsTheNamesItDefines(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		known bool
		want  []policy.ProfileName
	}{
		{"unknown key", "[profile.future]\nnet_hosts = [\"github.com\"]\n[profile.also]\nro = [\"/opt\"]\n",
			true, []policy.ProfileName{"also", "future"}},
		{"unknown value", "[profile.fut]\n[profile.fut.environ.types]\nMYDIR = \"file\"\n", true, []policy.ProfileName{"fut"}},
		{"wrong type", "[profile.typed]\nro = \"/opt\"\n", true, []policy.ProfileName{"typed"}},
		{"refused name", "[profile.\"@x\"]\nro = [\"/usr\"]\n", true, []policy.ProfileName{"@x"}},
		{"not toml", "[profile.half]\nro = [\"/opt\"]\n[profile.gone\n", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pd := filepath.Join(dir, "snug", "profiles.d")
			if err := os.MkdirAll(pd, 0o755); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(pd, "x.toml"), tc.body)
			t.Setenv("XDG_CONFIG_HOME", dir)

			_, bad, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(bad) != 1 {
				t.Fatalf("POSITIVE CONTROL: the fixture was meant not to load, bad = %+v", bad)
			}
			if bad[0].NamesKnown != tc.known {
				t.Errorf("NamesKnown = %v, want %v", bad[0].NamesKnown, tc.known)
			}
			// A syntax-broken file decodes partially; a partial list read as
			// the whole one would let a run past a name the file defines.
			if !slices.Equal(bad[0].Defines, tc.want) {
				t.Errorf("Defines = %v, want %v", bad[0].Defines, tc.want)
			}
		})
	}
}

// A redefinition stays a hard error when one side did not load. Without it the
// good file's profile would answer to the name while the bad file's claim on
// it went unread — the one question with no answer, answered by whichever file
// happened to parse.
func TestABadFileStillCannotRedefineALoadedName(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pd, "a-good.toml"), "[profile.work]\nro = [\"/opt\"]\n")
	write(t, filepath.Join(pd, "b-future.toml"), "[profile.work]\nnet_hosts = [\"github.com\"]\n")
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, _, err := Load()
	if err == nil {
		t.Fatal("a name defined in a loaded file and again in one that did not load was accepted")
	}
	for _, want := range []string{`"work"`, "a-good.toml", "b-future.toml", "redefines"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// CONTROL: the same bad file under a name nothing else holds loads the
	// rest and is reported, not fatal.
	write(t, filepath.Join(pd, "b-future.toml"), "[profile.other]\nnet_hosts = [\"github.com\"]\n")
	if _, bad, err := Load(); err != nil || len(bad) != 1 {
		t.Errorf("control: want 1 bad file and no hard error, got bad=%v err=%v", bad, err)
	}
}

// Red team F2 (#624): the redefinition refusals print file paths, which are
// directory entries snug did not choose. A path carrying ESC and a newline
// must reach the screen escaped, in both the good/good and good/bad message.
func TestRedefinitionEscapesTheFilePaths(t *testing.T) {
	for _, bodyB := range []string{
		"[profile.foo]\nro = [\"/opt\"]\n",
		"[profile.foo]\nbogus = 1\n",
	} {
		dir := t.TempDir()
		pd := filepath.Join(dir, "snug", "profiles.d")
		if err := os.MkdirAll(pd, 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(pd, "a.toml"), "[profile.foo]\nrw = [\"/opt\"]\n")
		write(t, filepath.Join(pd, "b\x1b[31mRED\nsnug: forged.toml"), bodyB)
		t.Setenv("XDG_CONFIG_HOME", dir)

		_, _, err := Load()
		if err == nil || !strings.Contains(err.Error(), "redefines") {
			t.Fatalf("POSITIVE CONTROL: want a redefinition refusal, got %v", err)
		}
		if strings.ContainsAny(err.Error(), "\x1b\n") {
			t.Errorf("a raw ESC or newline from a file name reached the refusal: %q", err)
		}
	}
}

// Red team (#624): a profiles.d that exists but cannot be listed holds
// profiles whose names snug cannot know. It is a BadFile with NamesKnown
// false, never an absent directory — which would let a same-named profile in
// the other layer answer for it unrefused.
func TestAnUnlistableProfilesDirIsABadFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists a mode-000 directory")
	}
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pd, "x.toml"), "[profile.x]\nro = [\"/opt\"]\n")
	if err := os.Chmod(pd, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pd, 0o755) })
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, bad, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bad) != 1 || bad[0].Path != pd || bad[0].NamesKnown {
		t.Errorf("bad = %+v, want the directory recorded with NamesKnown false", bad)
	}

	// CONTROL: an absent directory is still normal.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, bad, err := Load(); err != nil || len(bad) != 0 {
		t.Errorf("an absent profiles.d must not be a bad file: bad=%v err=%v", bad, err)
	}
}
