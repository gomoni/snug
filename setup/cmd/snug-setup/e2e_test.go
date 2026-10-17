package main

// End-to-end tests: the real snug-setup binary, driven through --plain by a
// piped script, saving into a scratch config directory, and the real snug
// binary reading the file back. No model, no llama-server, no network: the
// requests are read by the fixed rules and --offline stops the GitHub lookup.
//
// They run in `make gate` and in the setup.yml unit job, because they carry no
// build tag. Both binaries are built with `go build` at test time; when that
// is impossible the tests skip with the reason, and the same comparison is
// then held only by the in-process tests of internal/session.
//
// Not reached from here: HOME. snug takes the home from the account (getent),
// never from $HOME, and refuses a draft whose $HOME differs, so a scratch HOME
// makes /save fail at snug's check. The tests therefore pass the account's
// real home as HOME, and what is scratch is XDG_CONFIG_HOME, --profile-dir,
// the target and GIT_CONFIG_*. snug-setup may READ the real home (ssh public
// keys for its host facts); nothing here proves it writes nothing there.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  string
)

// builtBinaries builds snug (root module) and snug-setup (this module) once
// and returns the directory holding both.
func builtBinaries(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "snug-setup-e2e-bin-")
		if err != nil {
			buildErr = err.Error()
			return
		}
		for _, b := range []struct{ dir, pkg, out string }{
			{"../../..", "./cmd/snug", "snug"},
			{"../..", "./cmd/snug-setup", "snug-setup"},
		} {
			cmd := exec.Command("go", "build", "-o", filepath.Join(dir, b.out), b.pkg)
			cmd.Dir = b.dir
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = "cannot build " + b.out + ": " + err.Error() + "\n" + string(out)
				return
			}
		}
		binDir = dir
	})
	if buildErr != "" {
		t.Skip(buildErr)
	}
	return binDir
}

type world struct {
	t       *testing.T
	bin     string
	home    string
	root    string // scratch root: everything snug-setup may write is under it
	xdg     string
	target  string
	profile string // where a profile must land: snug's trusted profile directory
}

func newWorld(t *testing.T) *world {
	t.Helper()
	bin := builtBinaries(t)
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("no account home to hand snug (it takes the home from the account): %v", err)
	}
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	w := &world{t: t, bin: bin, home: u.HomeDir, root: root,
		xdg:    filepath.Join(root, "config"),
		target: filepath.Join(root, "proj")}
	w.profile = filepath.Join(w.xdg, "snug", "profiles.d")
	if err := os.MkdirAll(w.target, 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) env() []string {
	return []string{
		"PATH=" + w.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + w.home,
		"XDG_CONFIG_HOME=" + w.xdg,
		"XDG_DATA_HOME=" + filepath.Join(w.root, "data"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
	}
}

// setup pipes script to snug-setup --plain --offline on the target and returns
// the transcript and the exit status.
func (w *world) setup(script string) (string, int) {
	w.t.Helper()
	cmd := exec.Command(filepath.Join(w.bin, "snug-setup"), "--plain", "--offline", w.target)
	cmd.Env = w.env()
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatalf("snug-setup did not start: %v", err)
	}
	return out.String(), code
}

// dryRun runs the real snug on the target and decodes the fields the tests
// read. profileName "" is the default profile set.
type dry struct {
	Snug struct {
		ExitCode int `json:"exit_code"`
	} `json:"snug"`
	Profiles struct {
		Selected []string `json:"selected"`
		Implied  []string `json:"implied"`
	} `json:"profiles"`
	Mounts []struct {
		Guest  string `json:"guest"`
		Access string `json:"access"`
		Kind   string `json:"kind"`
	} `json:"mounts"`
	Network struct {
		Mode         string `json:"mode"`
		HostLoopback bool   `json:"host_loopback"`
	} `json:"network"`
}

func (w *world) dryRun(profileName string) dry {
	w.t.Helper()
	args := []string{"--dry-run", "--json"}
	if profileName != "" {
		args = append(args, "-p", profileName)
	}
	cmd := exec.Command(filepath.Join(w.bin, "snug"), append(args, w.target)...)
	cmd.Env = w.env()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		w.t.Fatalf("snug %v: %v\n%s%s", args, err, out, stderr.String())
	}
	var d dry
	if err := json.Unmarshal(out, &d); err != nil {
		w.t.Fatalf("snug %v printed no JSON document: %v\n%s", args, err, out)
	}
	return d
}

func mountSet(d dry) []string {
	var s []string
	for _, m := range d.Mounts {
		s = append(s, m.Kind+" "+m.Access+" "+m.Guest)
	}
	slices.Sort(s)
	return s
}

// scratchFiles lists every regular file under the scratch root, relative to
// it, apart from what the tests put there on purpose.
func (w *world) scratchFiles() []string {
	var files []string
	filepath.WalkDir(w.root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(w.root, p)
			files = append(files, rel)
		}
		return nil
	})
	slices.Sort(files)
	return files
}

func mustContain(t *testing.T, transcript string, wants ...string) {
	t.Helper()
	for _, s := range wants {
		if !strings.Contains(transcript, s) {
			t.Errorf("transcript lacks %q:\n%s", s, transcript)
		}
	}
}

// TestE2ESaveWritesWhatWasAskedAndSnugReadsItBack fails if the profile that
// /save writes is not found by snug in its trusted directory, is refused by
// snug, or grants anything beyond the @net that was asked for. The mount list
// is compared with the default profiles' own, so a grant /save added on top
// shows up as a difference. It does not cover what an identity or a path
// grant would add; those need a host with keys and are held in
// internal/session.
func TestE2ESaveWritesWhatWasAskedAndSnugReadsItBack(t *testing.T) {
	w := newWorld(t)
	base := w.dryRun("")
	if base.Network.Mode == "egress" {
		t.Fatalf("positive control broken: the default profile already has egress")
	}

	out, code := w.setup("needs internet\nyes\n/save work\n")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	want := filepath.Join(w.profile, "work.toml")
	mustContain(t, out, "added @net.", "wrote "+want, "snug accepts it")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("no profile where snug loads trusted ones: %v\n%s", err, out)
	}

	got := w.dryRun("work")
	if got.Snug.ExitCode != 0 {
		t.Fatalf("snug refused the saved profile: %+v", got.Snug)
	}
	if !slices.Contains(got.Profiles.Implied, "@net") && !slices.Contains(got.Profiles.Selected, "@net") {
		t.Errorf("the saved profile does not reach @net: %+v", got.Profiles)
	}
	if got.Network.Mode != "egress" || got.Network.HostLoopback {
		t.Errorf("network = %+v, want egress without host loopback", got.Network)
	}
	if !slices.Equal(got.Profiles.Selected, append(slices.Clone(base.Profiles.Selected), "work")) {
		t.Errorf("selected profiles = %v, want the defaults %v plus work", got.Profiles.Selected, base.Profiles.Selected)
	}
	if a, b := mountSet(got), mountSet(base); !slices.Equal(a, b) {
		t.Errorf("the saved profile changes the mounts the defaults give:\n got %v\nwant %v", a, b)
	}
	if files := w.scratchFiles(); !slices.Equal(files, []string{"config/snug/profiles.d/work.toml"}) {
		t.Errorf("files under the scratch root = %v, want only the profile", files)
	}
}

// TestE2ERefusedGrantsAreNeverSaved fails if a request for a path under
// ~/.ssh, or for write access to snug's own profile directory, reaches the
// written profile. The @net request beside them is the positive control: the
// session worked and saved, so the absence of the refused grants is a
// decision and not a session that never ran. It checks the file and the
// mounts snug resolves from it; it does not cover a differently worded
// request, which internal/rules holds.
func TestE2ERefusedGrantsAreNeverSaved(t *testing.T) {
	w := newWorld(t)
	script := "needs internet\nyes\n" +
		"let it write to ~/.ssh\n" +
		"let it write to ~/.config/snug\n" +
		"/save work\n"
	out, code := w.setup(script)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if n := strings.Count(out, "refused (sensitive_home)") + strings.Count(out, "request snug refuses (sensitive_home)"); n != 2 {
		t.Errorf("%d of the 2 requests were reported as refused:\n%s", n, out)
	}
	mustContain(t, out, "Refused:", "wrote "+filepath.Join(w.profile, "work.toml"))

	body, err := os.ReadFile(filepath.Join(w.profile, "work.toml"))
	if err != nil {
		t.Fatalf("positive control: nothing was saved: %v\n%s", err, out)
	}
	if !strings.Contains(string(body), "@net") {
		t.Fatalf("positive control: the saved profile lacks @net:\n%s", body)
	}
	for _, bad := range []string{".ssh", ".config/snug"} {
		if strings.Contains(string(body), bad) {
			t.Errorf("saved profile mentions %q:\n%s", bad, body)
		}
	}
	for _, m := range w.dryRun("work").Mounts {
		g := m.Guest
		if strings.HasPrefix(g, filepath.Join(w.home, ".ssh")) || strings.HasPrefix(g, filepath.Join(w.home, ".config", "snug")) {
			t.Errorf("snug resolves a mount for a refused grant: %+v", m)
		}
	}
}

// TestE2EGarbledLineChangesNothingAndSavesNothing fails if a line the rules
// cannot read is guessed into a grant, or if /save then writes a file for an
// empty draft. The "did not understand" question printing is the positive
// control that the line was read at all.
func TestE2EGarbledLineChangesNothingAndSavesNothing(t *testing.T) {
	w := newWorld(t)
	out, code := w.setup("asdf qwer zxcv\n/save work\n")
	if code != exitOpen {
		t.Fatalf("exit %d, want %d (the did-you-mean question is left open):\n%s", code, exitOpen, out)
	}
	mustContain(t, out, `I did not understand "asdf qwer zxcv"; nothing changed. Did you mean:`, "nothing to save yet.")
	if files := w.scratchFiles(); len(files) != 0 {
		t.Errorf("files written: %v", files)
	}
}

// TestE2ESaveWaitsForOpenQuestions fails if /save writes while a request's
// card is unanswered, which would save a profile the user has not agreed to.
// The question printing is the positive control; answering it afterwards and
// saving again writes the file, so the first refusal was about the question
// and not about the setup. Ledger drift (the draft resolving differently from
// what was asked) cannot be produced from the outside with the real snug and
// is held in internal/session.
func TestE2ESaveWaitsForOpenQuestions(t *testing.T) {
	w := newWorld(t)
	out, _ := w.setup("needs internet\n/save work\n")
	mustContain(t, out, "your request \"needs internet\" widens the sandbox", "not saved: 1 question(s) are open", "1 question(s) were still open.")
	if files := w.scratchFiles(); len(files) != 0 {
		t.Fatalf("files written with a question open: %v", files)
	}

	out, _ = w.setup("needs internet\nyes\n/save work\n")
	mustContain(t, out, "wrote "+filepath.Join(w.profile, "work.toml"))
}

// TestE2EExitStatus fails if the status stops telling a script what became of
// the session: 0 for a saved profile or for nothing to lose, 3 for a draft
// left unsaved (a refused /save included), 4 for questions left open with
// no draft. The file is checked beside the status so a code is never
// satisfied by a session that did nothing.
func TestE2EExitStatus(t *testing.T) {
	profile := func(w *world) string { return filepath.Join(w.profile, "work.toml") }
	tests := []struct {
		name, script string
		code         int
		saved        bool
	}{
		{"saved", "needs internet\nyes\n/save work\n", 0, true},
		{"nothing asked", "", 0, false},
		{"only refused requests", "let it write to ~/.ssh\n", 0, false},
		{"accepted draft never saved", "needs internet\nyes\n", exitUnsaved, false},
		{"save refused by an open question, then EOF", "needs internet\n/save work\n", exitOpen, false},
		{"unsaved draft and a question open", "needs internet\nyes\nlet it write to ~/.cache/x\n", exitUnsaved, false},
		{"saved, then a question opened", "needs internet\nyes\n/save work\nlet it write to ~/.cache/x\n", exitOpen, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			out, code := w.setup(tc.script)
			if code != tc.code {
				t.Errorf("exit status %d, want %d:\n%s", code, tc.code, out)
			}
			_, err := os.Stat(profile(w))
			if (err == nil) != tc.saved {
				t.Errorf("profile written = %v, want %v:\n%s", err == nil, tc.saved, out)
			}
		})
	}
}

func TestExitStatusPrecedence(t *testing.T) {
	for _, tc := range []struct {
		unsaved bool
		open    int
		want    int
	}{{false, 0, 0}, {true, 0, exitUnsaved}, {false, 2, exitOpen}, {true, 2, exitUnsaved}} {
		if got := exitStatus(tc.unsaved, tc.open); got != tc.want {
			t.Errorf("exitStatus(%v, %d) = %d, want %d", tc.unsaved, tc.open, got, tc.want)
		}
	}
}

// TestE2EHelpExitsZeroWithUsageOnly fails if --help is reported as an error:
// a nonzero status, or a line starting "snug-setup:" on either stream. The
// usage text is the positive control that the flag was read.
func TestE2EHelpExitsZeroWithUsageOnly(t *testing.T) {
	w := newWorld(t)
	cmd := exec.Command(filepath.Join(w.bin, "snug-setup"), "--help")
	cmd.Env = w.env()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("snug-setup --help: %v\n%s", err, out.String())
	}
	mustContain(t, out.String(), "usage: snug-setup", "exit status:")
	if strings.Contains(out.String(), "snug-setup: ") || strings.Contains(out.String(), "help requested") {
		t.Errorf("--help printed an error line:\n%s", out.String())
	}
	if strings.Contains(out.String(), "asks nothing") {
		t.Errorf("--plain is still described as asking nothing:\n%s", out.String())
	}
}
