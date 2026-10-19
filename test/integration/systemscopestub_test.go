//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSystemScopeStubReachesGitBesideAnIdentity holds GIT-CONFIG.md §5: with an
// identity selected, a human-written git stub works only at system scope
// (read-only AT /etc/gitconfig), and the pinned identity still outranks it.
//
// It would catch: snug starting to occupy /etc/gitconfig itself (the stub then
// never reaches git); a pinned value losing to the stub (system outranking
// global); and GIT_CONFIG_GLOBAL ceasing to be set beside an identity, which
// would make the XDG path start working and the negative arm fail.
//
// It does not cover the `{home}/.gitconfig` placement (the dry-run provenance
// `replaces:` is the evidence for that one), nor git versions other than the
// one on the host running the suite.
func TestSystemScopeStubReachesGitBesideAnIdentity(t *testing.T) {
	budget(t)
	requireSandbox(t)

	stub := filepath.Join(t.TempDir(), "stub.gitconfig")
	if err := os.WriteFile(stub, []byte("[init]\n\tdefaultBranch = trunk\n[user]\n\temail = stub@example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	const me = "[profile.me]\n" +
		"description = \"git identity pin, no ssh\"\n" +
		"[profile.me.identity.git]\n" +
		"name = \"T\"\n" +
		"email = \"t@example.com\"\n"

	t.Run("system_scope_stub_is_read_and_pin_outranks_it", func(t *testing.T) {
		proj, _ := target(t)
		env := writeProfiles(t, map[string]string{
			"gitprefs": "[profile.gitprefs]\n" +
				"description = \"git stub at system scope\"\n" +
				"ro = [\"" + stub + ":/etc/gitconfig\"]\n",
			"me": me,
		})
		r := runEnv(t, env, []string{"-p", "gitprefs", "-p", "me"}, proj,
			`echo "branch=[$(git config --show-scope --get init.defaultBranch)]"
echo "email=[$(git config --show-scope --get user.email)]"
`).mustRun(t)

		if !strings.Contains(r.out, "branch=[system\ttrunk]") {
			t.Errorf("the stub granted at /etc/gitconfig was not read at system scope "+
				"beside an identity:\n%s", r.out)
		}
		if !strings.Contains(r.out, "email=[global\tt@example.com]") {
			t.Errorf("user.email is not the pinned value at global scope; either the "+
				"pin is not generated or the stub's stub@example.com outranked it:\n%s", r.out)
		}
	})

	// The positive control for this arm is the first subtest: the same stub
	// contents ARE read when granted at system scope. Here we also assert the
	// payload saw the pin, so a run with no identity at all cannot pass.
	t.Run("stub_at_xdg_path_is_not_read_beside_an_identity", func(t *testing.T) {
		proj, _ := target(t)
		env := writeProfiles(t, map[string]string{
			"gitprefs": "[profile.gitprefs]\n" +
				"description = \"git stub at the XDG path\"\n" +
				"ro = [\"" + stub + ":{home}/.config/git/config\"]\n",
			"me": me,
		})
		r := runEnv(t, env, []string{"-p", "gitprefs", "-p", "me"}, proj,
			`echo "email=[$(git config --get user.email)]"
echo "branch=[$(git config --get init.defaultBranch)]"
`).mustRun(t)

		if !strings.Contains(r.out, "email=[t@example.com]") {
			t.Fatalf("the pinned identity is not in effect, so the absence of the stub "+
				"below proves nothing:\n%s", r.out)
		}
		if !strings.Contains(r.out, "branch=[]") {
			t.Errorf("a stub at {home}/.config/git/config was read beside an identity, "+
				"which GIT_CONFIG_GLOBAL is meant to prevent:\n%s", r.out)
		}
	})
}
