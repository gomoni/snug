//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const profileFileBody = "[init]\n\tdefaultBranch = main\n# marker-653\n"

func profileFileTOML(path string) string {
	return "[profile.wf]\n" +
		"description = \"one literal read-only file\"\n" +
		"[[profile.wf.file]]\n" +
		"path = \"" + path + "\"\n" +
		"content = '''" + profileFileBody + "'''\n"
}

// TestProfileFileIsReadOnlyInside would catch: bwrap's data file arriving
// writable (the --perms 0444 ordering the spec measured), or a profile file
// landing on a mount the payload can replace or unlink.
//
// Ownership is RECORDED, not asserted: the spec calls it unmeasured, so the
// uid/gid line is printed into the failure output and the test only checks
// that stat answered. It does not cover a file at a path whose parent is
// writable (that combination is refused by the resolver, see
// TestProfileFileUnderTargetCreatesNothingOnHost).
func TestProfileFileIsReadOnlyInside(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := writeProfiles(t, map[string]string{"wf": profileFileTOML("/etc/snug-653.conf")})

	r := runEnv(t, env, []string{"-p", "wf"}, proj, `
f=/etc/snug-653.conf
echo "content-begin"; cat "$f"; echo "content-end"
echo "stat=[$(stat -c '%a %u:%g' "$f")]"
echo "uid=[$(id -u):$(id -g)]"
( echo pwned >> "$f" ) 2>&1; echo "append-rc=$?"
( echo pwned > "$f" ) 2>&1; echo "truncate-rc=$?"
rm -f "$f" 2>&1; echo "rm-rc=$?"
chmod 600 "$f" 2>&1; echo "chmod-rc=$?"
mv "$f" /tmp/x 2>&1; echo "mv-rc=$?"
echo "after=[$(stat -c '%a' "$f")]"
echo "content-after-begin"; cat "$f"; echo "content-after-end"
`).mustRun(t)

	// Positive control: the file exists with the exact bytes before any attack.
	want := "content-begin\n" + profileFileBody + "content-end\n"
	if !strings.Contains(r.out, want) {
		t.Fatalf("the file is not inside with its exact bytes, so the refusals below prove nothing:\n%s", r.out)
	}
	if !strings.Contains(r.out, "stat=[444 ") {
		t.Errorf("mode is not 444:\n%s", r.out)
	}
	t.Logf("observed (ownership is unmeasured by the spec, recorded only): %s",
		grepLines(r.out, "stat=", "uid="))
	for _, rc := range []string{"append-rc=", "truncate-rc=", "rm-rc=", "chmod-rc=", "mv-rc="} {
		if strings.Contains(r.out, rc+"0\n") {
			t.Errorf("%s0: the operation SUCCEEDED on a read-only profile file:\n%s", rc, r.out)
		}
		if !strings.Contains(r.out, rc) {
			t.Errorf("no %s line, the probe did not run:\n%s", rc, r.out)
		}
	}
	if !strings.Contains(r.out, "Read-only file system") {
		t.Errorf("write did not fail with EROFS (Read-only file system):\n%s", r.out)
	}
	if !strings.Contains(r.out, "after=[444]") {
		t.Errorf("mode changed or file gone after the attacks:\n%s", r.out)
	}
	if !strings.Contains("\n"+r.out, "content-after-begin\n"+profileFileBody+"content-after-end") {
		t.Errorf("content changed after the attacks:\n%s", r.out)
	}
}

func grepLines(out string, prefixes ...string) string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				got = append(got, l)
			}
		}
	}
	return strings.Join(got, " ")
}

// TestProfileFileAtEtcGitconfigIsReadAtSystemScope would catch: a profile
// file at /etc/gitconfig not being what git reads (wrong path, wrong scope),
// or the generated global config losing to it. The pinned user.email must stay
// at global scope; the file's init.defaultBranch must arrive at system scope.
// It does not cover git versions other than the host's.
func TestProfileFileAtEtcGitconfigIsReadAtSystemScope(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := writeProfiles(t, map[string]string{
		"wf": profileFileTOML("/etc/gitconfig"),
		"me": "[profile.me]\n" +
			"description = \"git identity pin, no ssh\"\n" +
			"[profile.me.identity.git]\n" +
			"name = \"T\"\n" +
			"email = \"t@example.com\"\n",
	})
	r := runEnv(t, env, []string{"-p", "wf", "-p", "me"}, proj,
		`echo "branch=[$(git config --show-scope --get init.defaultBranch)]"
echo "email=[$(git config --show-scope --get user.email)]"
`).mustRun(t)
	if !strings.Contains(r.out, "branch=[system\tmain]") {
		t.Errorf("init.defaultBranch from the profile file was not read at system scope:\n%s", r.out)
	}
	if !strings.Contains(r.out, "email=[global\tt@example.com]") {
		t.Errorf("user.email is not the pinned value at global scope:\n%s", r.out)
	}
}

// TestProfileFileUnderTargetCreatesNothingOnHost would catch: a profile file
// whose guest path is inside the writable target being materialised by bwrap
// onto the host directory behind it (the #186 shape, with a profile as the
// author instead of snug). Positive control: the same profile at a path
// outside the target runs, so the refusal is about the path.
func TestProfileFileUnderTargetCreatesNothingOnHost(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	before, err := os.ReadDir(proj)
	if err != nil {
		t.Fatal(err)
	}
	env := writeProfiles(t, map[string]string{
		"under": strings.ReplaceAll(profileFileTOML("{target}/generated-653.conf"), "profile.wf", "profile.under"),
		"ok":    strings.ReplaceAll(profileFileTOML("/etc/snug-653.conf"), "profile.wf", "profile.ok"),
	})

	ctl := runEnv(t, env, []string{"-p", "ok"}, proj, `cat /etc/snug-653.conf`).mustRun(t)
	if !strings.Contains(ctl.out, "marker-653") {
		t.Fatalf("control: the same profile at /etc does not work:\n%s", ctl.out)
	}

	out, code := cli(t, env, "-p", "under", proj, "--", "true")
	if code == 0 {
		t.Errorf("snug ACCEPTED a profile file inside the writable target:\n%s", out)
	}
	if !strings.Contains(out, "generated-653.conf") || strings.Contains(out, "unknown profile") {
		t.Errorf("the refusal is not about the path (a wrong profile name would also exit non-zero):\n%s", out)
	}
	if _, err := os.Lstat(filepath.Join(proj, "generated-653.conf")); err == nil {
		t.Errorf("a file appeared on the HOST in the target directory")
	}
	after, _ := os.ReadDir(proj)
	if len(after) != len(before) {
		t.Errorf("target directory changed: %d -> %d entries", len(before), len(after))
	}
}
