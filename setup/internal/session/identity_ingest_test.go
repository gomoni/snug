package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/testworld"
)

func gitIn(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("git unavailable or failed (%v): %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// sshSig is an armoured SSHSIG whose public key is the testworld key of seed.
func sshSig(seed byte) string {
	raw, _ := base64.StdEncoding.DecodeString(testworld.BlobOf(seed))
	var b bytes.Buffer
	b.WriteString("SSHSIG")
	binary.Write(&b, binary.BigEndian, uint32(1))
	binary.Write(&b, binary.BigEndian, uint32(len(raw)))
	b.Write(raw)
	for _, s := range []string{"git", "", "sha512", "x"} {
		binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	return "-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(b.Bytes()) + "\n-----END SSH SIGNATURE-----"
}

// repoWithHistory makes a git work tree at the world's target whose commits are
// by Account Two, every other one signed with the testworld key of signSeed.
func repoWithHistory(t *testing.T, w *testworld.World, remote string, signSeed byte, n int) {
	t.Helper()
	d := w.Target
	gitIn(t, d, "", "init", "-q", "-b", "main")
	gitIn(t, d, "", "remote", "add", "origin", remote)
	parent := ""
	for i := 0; i < n; i++ {
		body := "tree " + gitIn(t, d, "", "write-tree") + "\n"
		if parent != "" {
			body += "parent " + parent + "\n"
		}
		body += "author Account Two <two@example.com> 1700000000 +0000\ncommitter Account Two <two@example.com> 1700000000 +0000\n"
		if i%2 == 0 {
			lines := strings.Split(sshSig(signSeed), "\n")
			body += "gpgsig " + lines[0] + "\n"
			for _, l := range lines[1:] {
				body += " " + l + "\n"
			}
		}
		parent = gitIn(t, d, body+"\nc\n", "hash-object", "-t", "commit", "-w", "--stdin")
		gitIn(t, d, "", "update-ref", "HEAD", parent)
	}
}

func TestOpeningSuggestsTheIdentityTheRepositoryAndHostPointAt(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	os.WriteFile(filepath.Join(w.Home, ".ssh", "config"), []byte("Host github.com\n  IdentityFile ~/.ssh/id_account2\n"), 0o600)
	_, out := start(w)
	contains(t, out, "Remote origin git@github.com:account2/project.git (ssh).", "nothing is pinned until you answer",
		"GitHub login account2; ssh key id_account2; signing key id_other; git author Account Two <two@example.com>")
	lacks(t, out, "Last 10 commits", "Found on this host", "Each request stands alone")
	s, _ := start(w)
	contains(t, text(s.Details(ctx)),
		"Last 10 commits: 10 by Account Two <two@example.com>.", "5 carry an ssh signature made with your key id_other (signatures are read, not verified)",
		"ssh key id_account2  (~/.ssh/config: Host github.com)", "signing key id_other  (5 of the last 10 commits carry an ssh signature made with it)",
		"git author Account Two <two@example.com>", "GitHub login account2  (the owner in the remote url)", "nothing is pinned until you answer")
}

func TestIdentityQuestionPutsTheSuggestionFirstAndSigningNeedsSSHAndGit(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	os.WriteFile(filepath.Join(w.Home, ".ssh", "config"), []byte("Host github.com\n  IdentityFile ~/.ssh/id_account2\n"), 0o600)
	w.Reply("sign my commits", `{"op":"select_identity","kind":"signing","account":""}`)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	w.Reply("use my git author", `{"op":"select_identity","kind":"git","account":""}`)
	s, _ := start(w)

	out := say(s, "sign my commits")
	contains(t, out, "which ssh key should sign commits inside the sandbox?", "<- suggested: 5 of the last 10 commits", "/pick signing id_other takes the suggestion")
	if i, j := strings.Index(out, "id_other"), strings.Index(out, "id_account1"); i < 0 || j < 0 || i > j {
		t.Errorf("the suggested key is not first:\n%s", out)
	}
}

func TestSigningKeyIsPinnedAfterSSHAndGit(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	os.WriteFile(filepath.Join(w.Home, ".ssh", "config"), []byte("Host github.com\n  IdentityFile ~/.ssh/id_account2\n"), 0o600)
	w.Reply("sign my commits", `{"op":"select_identity","kind":"signing","account":""}`)
	w.Reply("use my ssh key", `{"op":"select_identity","kind":"ssh","account":""}`)
	w.Reply("use my git author", `{"op":"select_identity","kind":"git","account":""}`)
	s, _ := start(w)

	say(s, "sign my commits")
	out := text(s.Pick(ctx, "signing", "id_other"))
	contains(t, out, "a signing key goes with an ssh key and a git author, and the draft pins neither", "stays open", "Nothing written", "which ssh key should the sandbox act as?", "which git author should the sandbox act as?")
	if s.Draft().Git != nil {
		t.Fatal("a refused signing pick wrote an identity")
	}

	var pend strings.Builder
	for _, q := range s.Pending() {
		pend.WriteString(q.Line().Text + "\n")
	}
	contains(t, pend.String(), "id_account2  account2@laptop", "<- suggested: ~/.ssh/config: Host github.com", "/pick ssh id_account2 takes the suggestion")
	contains(t, text(s.Pick(ctx, "ssh", "id_account2")), "pinned ssh key id_account2")
	contains(t, text(s.Pick(ctx, "git", "two@example.com")), "pinned git author")
	out = text(s.Pick(ctx, "signing", "id_other"))
	contains(t, out, "pinned signing key id_other")
	contains(t, s.Draft().Render(), `signing_key = "{home}/.ssh/id_other.pub"`, "# intent (you, confirmed)")
	if _, ok := s.slotFull("signing"); !ok {
		t.Error("signing slot not full")
	}
}

// TestHostileRepositoryConfigRunsNothing is the abuse case for reading a
// repository: .git/config names programs git would run for `git log` (a signing
// program, an fsmonitor, a pager, a diff driver, an include), HEAD and objects
// are in place. snug-setup reads the files as bytes; no marker file appears,
// and the only git command run is `git config --global`.
func TestHostileRepositoryConfigRunsNothing(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 4)
	marker := filepath.Join(t.TempDir(), "RAN")
	script := filepath.Join(t.TempDir(), "evil.sh")
	os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	cfg := filepath.Join(w.Target, ".git", "config")
	old, _ := os.ReadFile(cfg)
	hostile := string(old) + "[gpg]\n\tprogram = " + script + "\n[gpg \"ssh\"]\n\tprogram = " + script + "\n[core]\n\tfsmonitor = " + script +
		"\n\tpager = " + script + "\n\tsshCommand = " + script + "\n[diff]\n\texternal = " + script + "\n[include]\n\tpath = /etc/passwd\n" +
		"[user]\n\tsigningkey = " + script + "\n[commit]\n\tgpgsign = true\n"
	os.WriteFile(cfg, []byte(hostile), 0o644)
	os.MkdirAll(filepath.Join(w.Target, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(w.Target, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)

	s, _ := start(w)
	contains(t, text(s.Details(ctx)), "Last 4 commits")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a program named by the repository's config ran")
	}
	for _, c := range w.Cmds {
		if strings.HasPrefix(c, "git ") && !strings.HasPrefix(c, "git config --global") {
			t.Errorf("git was run beyond the host's global config: %s", c)
		}
		if strings.Contains(c, w.Target) {
			t.Errorf("a command was given the target: %s", c)
		}
	}
}

// TestRepositoryLinksDoNotLeadOut: .git/config linked to a file outside the
// target, HEAD linked there too, and objects/ a link to another repository
// yield nothing from outside.
func TestRepositoryLinksDoNotLeadOut(t *testing.T) {
	w := testworld.New(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "config"), []byte("[remote \"origin\"]\n\turl = git@evil.example:ceo/secret.git\n"), 0o600)
	os.WriteFile(filepath.Join(outside, "HEAD"), []byte("ref: refs/heads/x\n"), 0o600)
	gitDir := filepath.Join(w.Target, ".git")
	os.MkdirAll(filepath.Join(gitDir, "refs"), 0o755)
	os.Symlink(filepath.Join(outside, "config"), filepath.Join(gitDir, "config"))
	os.Symlink(filepath.Join(outside, "HEAD"), filepath.Join(gitDir, "HEAD"))
	os.Symlink(outside, filepath.Join(gitDir, "objects"))
	_, out := start(w)
	lacks(t, out, "evil.example", "ceo/secret", "Remote origin")
	contains(t, out, "HEAD could not be resolved")
}

// TestCommitMessagesAndAuthorsCannotForgeLines: an author name carrying a
// newline and an escape sequence is shown on one line, cleaned.
func TestCommitAuthorTextIsCleaned(t *testing.T) {
	w := testworld.New(t)
	d := w.Target
	gitIn(t, d, "", "init", "-q", "-b", "main")
	gitIn(t, d, "", "remote", "add", "origin", "git@github.com:o/r.git")
	body := "tree " + gitIn(t, d, "", "write-tree") + "\nauthor Evil\x1b]0;pwn\x07 <e@x.org> 1 +0000\ncommitter Evil <e@x.org> 1 +0000\n\nmsg\n"
	id := gitIn(t, d, body, "hash-object", "-t", "commit", "-w", "--stdin")
	gitIn(t, d, "", "update-ref", "HEAD", id)
	_, out := start(w)
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("control characters reached the output: %q", out)
	}
}

// TestAdviceRequestIsAnsweredFromTheFacts: "should not AI recommend
// identities?" once reached the model and came back as a seccomp refusal.
func TestAdviceRequestIsAnsweredFromTheFacts(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 6)
	s, _ := start(w)
	for _, q := range []string{"should not AI reccomend identities?", "what identities do you suggest for this repo?", "which ssh key do you recommend"} {
		out := say(s, q)
		contains(t, out, "Suggested identity for this project", "nothing is pinned until you answer")
	}
	if len(w.Model.Prompts) != 0 {
		t.Errorf("the model was asked: %v", w.Model.Prompts)
	}
}

func TestShowSaysWhatIsPendingWhenTheDraftIsEmpty(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 2)
	s, _ := start(w)
	contains(t, text(s.Show()), "[profile.NAME]", "Nothing is in the draft yet; 1 question(s) are open")
}

// TestIdentityOneNoteWithNothingPinnedAdvises: the model answers "an ssh key
// and a signing key too?" with the two-accounts note; with no identity pinned
// that note answers nothing, so the facts are shown instead.
func TestIdentityOneNoteWithNothingPinnedAdvises(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 4)
	w.Reply("can I have two accounts in here", `{"op":"note","topic":"identity_one"}`)
	s, _ := start(w)
	out := say(s, "can I have two accounts in here")
	contains(t, out, "Suggested identity for this project")
	lacks(t, out, "A profile pins one account")
}

// TestSigningRequestOpensTheQuestionWithoutTheModel: "a ssh access and a signig
// key" (sic) once came back as the two-accounts note.
func TestSigningRequestOpensTheQuestionWithoutTheModel(t *testing.T) {
	w := testworld.New(t)
	repoWithHistory(t, w, "git@github.com:account2/project.git", 3, 10)
	s, _ := start(w)
	out := say(s, "with @git add there's a need for a ssh access and a signig key, dont?")
	contains(t, out, "which ssh key should the sandbox act as?", "which ssh key should sign commits inside the sandbox?")
	if len(w.Model.Prompts) != 0 || !s.Draft().Empty() {
		t.Errorf("model asked or draft changed")
	}
	lacks(t, say(s, "design a key"), "should sign")
}
