package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// THE ORACLE. snug evaluates `includeIf "gitdir:"` itself — it has to, because
// no git invocation both honours the condition and keeps the sandboxed material
// out of the decision (see GIT-CONFIG.md §3). The price of owning the matcher is
// that it can DIVERGE from git, silently, in either direction:
//
//   - snug fires where git does not: the sandbox commits under an identity the
//     host would never use.
//   - snug does not fire where git does: the sandbox silently falls back to the
//     global identity, and commits land under the wrong address.
//
// A hand-written table of cases only tests the cases someone thought of, and an
// independent review found seven divergences in the first version — including
// `gitdir:work/`, the plainest relative pattern there is. So this test asks real
// git for the answer and compares, case by case.
//
// It lives in cmd/ rather than internal/policy because it shells out; the pure
// unit tests over GitdirMatches stay where they are.
func TestGitdirMatcherAgreesWithRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")

	cases := []struct{ pattern, repo string }{
		// The ordinary forms.
		{"~/work/", "work/proj"},
		{"~/work/", "personal/proj"},
		{"~/work/", "workshop/proj"},
		{"/does/not/exist/", "work/proj"},
		// Relative patterns: any pattern not starting with ~/ ./ or / gets **/.
		{"work/", "work/proj"},
		{"work/proj/", "work/proj"},
		{"a/b/", "x/a/b/proj"},
		{"work", "work"},
		// `**` as a whole component crosses separators.
		{"~/**/vendor/", "a/b/vendor/proj"},
		{"~/x/**/y/", "x/a/b/y/proj"},
		// `**` that is NOT a whole component degrades to `*`.
		{"~/**work/", "a/xwork/proj"},
		{"~/**x/", "a/bx/proj"},
		{"~/x/**y/", "x/a/b/y/proj"},
		{"~/p**j/", "p/q/r/j/proj"},
		{"~/wo**rk/", "wo/x/rk/proj"},
		{"~/a**b/", "aQ/Zb/proj"},
		{"~/a**b/", "aQZb/proj"},
		// `*` never crosses a separator.
		{"~/*/proj/", "a/proj"},
		{"~/*/proj/", "a/b/proj"},
		// Character classes and escapes are wildmatch features, not extras.
		{"~/[wp]ork/", "work/proj"},
		{"~/[wp]ork/", "fork/proj"},
		{"~/w[!x]rk/", "work/proj"},
		{"~/?ork/", "work/proj"},
	}

	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.repo, func(t *testing.T) {
			repo := filepath.Join(home, tc.repo)
			if err := os.MkdirAll(repo, 0o755); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, out)
			}
			cfg := filepath.Join(root, "gitconfig")
			if err := os.WriteFile(cfg, []byte(
				"[user]\n\temail = global@example.invalid\n"+
					"[includeIf \""+"gitdir:"+tc.pattern+"\"]\n\tpath = "+
					filepath.Join(root, "inc")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "inc"),
				[]byte("[user]\n\temail = included@example.invalid\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			// git's answer, asked in the repository, with HOME pointed at the
			// fixture so `~/` means the fixture home for git too.
			cmd := exec.Command("git", "-C", repo, "config", "--get", "user.email")
			cmd.Env = append(os.Environ(),
				"HOME="+home, "GIT_CONFIG_GLOBAL="+cfg, "GIT_CONFIG_NOSYSTEM=1")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("git config: %v", err)
			}
			gitFired := strings.TrimSpace(string(out)) == "included@example.invalid"

			// snug's answer, over the same repository. git matches against the
			// REAL path of the gitdir, so the fixture uses no symlinks and the
			// two see the same string.
			snugFired := policy.GitdirMatches(tc.pattern, home, filepath.Join(repo, ".git"))

			if snugFired != gitFired {
				direction := "snug fires where git does not: the sandbox would commit " +
					"under an identity the host never uses"
				if gitFired {
					direction = "git fires where snug does not: the sandbox silently falls " +
						"back to the global identity"
				}
				t.Errorf("pattern %q, repo %q: snug=%v git=%v — %s",
					tc.pattern, tc.repo, snugFired, gitFired, direction)
			}
		})
	}
}

// A pattern from a host config must not be able to hang snug. The previous
// character-wise matcher retried every suffix per `**` group: measured at 3
// seconds for `/**a**a**a**b` against a 400-component path, and it did not finish
// at all with one more group. A --dry-run that hangs on someone's gitconfig is
// close to undiagnosable.
func TestGitdirMatchingDoesNotBlowUp(t *testing.T) {
	long := "/" + strings.Repeat("a/", 400) + "b"
	for _, pattern := range []string{
		"/**a**a**a**b",
		"/**a**a**a**a**b",
		"/**a**a**a**a**a**a**c",
	} {
		done := make(chan bool, 1)
		go func() { done <- policy.GitdirMatches(pattern, "/home/u", long) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("pattern %q did not finish in 5s against a 400-component path", pattern)
		}
	}
}
