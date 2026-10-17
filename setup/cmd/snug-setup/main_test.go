package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "snug-setup-test-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "snug-setup")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

// snugSetup runs the binary with a temporary HOME and a PATH holding no snug.
func snugSetup(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "PATH=" + t.TempDir()}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return r
}

func project(t *testing.T, name string, files ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPrintNoSnug(t *testing.T) {
	dir := project(t, "app", "CLAUDE.md")
	r := snugSetup(t, "", "--print", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{`"@claude"`, `"@net"`, "[profile.app]"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %s:\n%s", want, r.stdout)
		}
	}
	if !strings.Contains(r.stderr, "snug not on PATH") {
		t.Errorf("stderr %q", r.stderr)
	}
}

func TestPrintUnsureIsCommented(t *testing.T) {
	dir := project(t, "app", "Containerfile")
	r := snugSetup(t, "", "--print", dir)
	if r.code != 0 || strings.Contains(r.stdout, "\n  \"@podman-build\"") || !strings.Contains(r.stdout, `# include = ["@podman-build"]  # Containerfile`) {
		t.Errorf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
}

func TestNoTTYNeedsPrint(t *testing.T) {
	r := snugSetup(t, "", project(t, "app"))
	if r.code != 1 || !strings.Contains(r.stderr, "use --print") {
		t.Errorf("exit %d: %s", r.code, r.stderr)
	}
}

func TestPrintNameCollision(t *testing.T) {
	dir := project(t, "app")
	home := t.TempDir()
	prof := filepath.Join(home, ".config", "snug", "profiles.d")
	os.MkdirAll(prof, 0o755)
	os.WriteFile(filepath.Join(prof, "accounts.toml"), []byte("[profile.app]\ninclude = [\"@net\"]\n"), 0o644)
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(binary, append([]string{"--print"}, args...)...)
		cmd.Env = []string{"HOME=" + home, "PATH=" + t.TempDir()}
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		code := 0
		if err := cmd.Run(); err != nil {
			code = err.(*exec.ExitError).ExitCode()
		}
		return out.String(), errb.String(), code
	}
	if out, errs, code := run(dir); code != 1 || !strings.Contains(errs, "profile name app exists in") || !strings.Contains(errs, "accounts.toml") || !strings.Contains(errs, "--name") || out != "" {
		t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
	}
	if out, _, code := run("--name", "app2", dir); code != 0 || !strings.Contains(out, "[profile.app2]") {
		t.Errorf("exit %d stdout %q", code, out)
	}
}

func TestPrintAmbiguousIdentityExitsZero(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	dir := project(t, "app", "README.md")
	gitEnv := []string{"GIT_AUTHOR_NAME=A", "GIT_AUTHOR_EMAIL=m@example.org", "GIT_COMMITTER_NAME=A", "GIT_COMMITTER_EMAIL=m@example.org", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@github.com:acme/app.git"}, {"add", "."}, {"commit", "-q", "-m", "x"}} {
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), gitEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	home := t.TempDir()
	prof := filepath.Join(home, ".config", "snug", "profiles.d")
	os.MkdirAll(prof, 0o755)
	both := "[profile.one.identity.ssh]\nhost = \"github.com\"\nkey = \"{home}/.ssh/one.pub\"\n[profile.one.identity.git]\nname = \"A\"\nemail = \"m@example.org\"\n" +
		"[profile.two.identity.ssh]\nhost = \"github.com\"\nkey = \"{home}/.ssh/two.pub\"\n[profile.two.identity.git]\nname = \"A\"\nemail = \"m@example.org\"\n"
	os.WriteFile(filepath.Join(prof, "accounts.toml"), []byte(both), 0o644)
	cmd := exec.Command(binary, "--print", dir)
	cmd.Env = []string{"HOME=" + home, "PATH=" + t.TempDir()}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(errb.String(), "identity: one or two — pick one") {
		t.Errorf("stderr %q", errb.String())
	}
	if strings.Contains(out.String(), `"one"`) || strings.Contains(out.String(), `"two"`) || !strings.Contains(out.String(), `"@git"`) {
		t.Errorf("an ambiguous identity must be left out:\n%s", out.String())
	}
}

func TestUsageHasNoModelFlags(t *testing.T) {
	r := snugSetup(t, "", "--help")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	for _, bad := range []string{"openai", "model", "plain"} {
		if strings.Contains(strings.ToLower(r.stdout), bad) {
			t.Errorf("usage mentions %q:\n%s", bad, r.stdout)
		}
	}
	for _, want := range []string{"--print", "--profile-dir", "--name", "130", "ambiguous identity"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
	if strings.Contains(r.stdout, "--offline") {
		t.Errorf("usage names a flag that was removed")
	}
	for _, flag := range []string{"--model", "--offline"} {
		if r := snugSetup(t, "", flag, "x", "--print"); r.code != 1 {
			t.Errorf("a removed flag %s was accepted: exit %d", flag, r.code)
		}
	}
}

func TestBadNameFlag(t *testing.T) {
	r := snugSetup(t, "", "--print", "--name", "bad_name", project(t, "app"))
	if r.code != 1 || !strings.Contains(r.stderr, "--name") {
		t.Errorf("exit %d: %s", r.code, r.stderr)
	}
}

// TestPrintProbesOnlyIdentityCandidates: a profile of yours that pins no
// identity and that the draft does not include is not asked about, so a marp
// setup beside a Go project does not warn about a path missing from the
// project. A refused identity candidate warns, with its whole line.
func TestPrintProbesOnlyIdentityCandidates(t *testing.T) {
	bin := t.TempDir()
	long := strings.Repeat("far ", 40)
	script := "#!/bin/sh\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = -p ]; then p=$2; fi; shift; done\n" +
		"echo \"$p\" >> \"" + filepath.Join(bin, "asked") + "\"\n" +
		"printf '%s' '{\"snug\":{\"format\":2,\"outcome\":\"refused\",\"policy_resolved\":false},\"refusal\":{\"message\":\"profile \\\"'$p'\\\" grants a path which is " + long + "missing\"}}'\n"
	if err := os.WriteFile(filepath.Join(bin, "snug"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	prof := filepath.Join(home, ".config", "snug", "profiles.d")
	os.MkdirAll(prof, 0o755)
	body := "[profile.marp]\ninclude = [\"@net\"]\n" +
		"[profile.work.identity.ssh]\nhost = \"github.com\"\nkey = \"{home}/.ssh/w.pub\"\n[profile.work.identity.git]\nname = \"A\"\nemail = \"m@example.org\"\n"
	os.WriteFile(filepath.Join(prof, "accounts.toml"), []byte(body), 0o644)
	cmd := exec.Command(binary, "--print", project(t, "app"))
	cmd.Env = []string{"HOME=" + home, "PATH=" + bin}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	asked, _ := os.ReadFile(filepath.Join(bin, "asked"))
	if strings.TrimSpace(string(asked)) != "work" {
		t.Errorf("snug was asked about %q, want only work", asked)
	}
	want := "! accounts.toml: work grants a path which is " + long + "missing"
	if !strings.Contains(errb.String(), want) {
		t.Errorf("stderr lacks the whole line:\n%s", errb.String())
	}
}
