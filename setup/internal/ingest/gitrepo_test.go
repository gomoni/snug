package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Ann Dev", "GIT_AUTHOR_EMAIL=ann@example.org", "GIT_COMMITTER_NAME=GitHub", "GIT_COMMITTER_EMAIL=noreply@github.com")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("git unavailable or failed (%v): %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// sshsig returns an armoured SSHSIG whose embedded public key is blob.
func sshsig(blob []byte) (armoured, fingerprint string) {
	var b bytes.Buffer
	b.WriteString("SSHSIG")
	binary.Write(&b, binary.BigEndian, uint32(1))
	binary.Write(&b, binary.BigEndian, uint32(len(blob)))
	b.Write(blob)
	for _, s := range []string{"git", "", "sha512", "sig"} {
		binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	enc := base64.StdEncoding.EncodeToString(b.Bytes())
	var lines []string
	for len(enc) > 70 {
		lines = append(lines, enc[:70])
		enc = enc[70:]
	}
	lines = append(lines, enc)
	sum := sha256.Sum256(blob)
	return "-----BEGIN SSH SIGNATURE-----\n" + strings.Join(lines, "\n") + "\n-----END SSH SIGNATURE-----", "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func keyBlob(seed byte) []byte {
	raw := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	for i := 0; i < 32; i++ {
		raw[len(raw)-1-i] = seed + byte(i)
	}
	return raw
}

// signedCommit writes a commit with a gpgsig header on top of parent, using
// git hash-object (a trusted temp repository), and moves HEAD to it.
func signedCommit(t *testing.T, dir, parent, sig, msg string) string {
	tree := git(t, dir, "", "write-tree")
	body := "tree " + tree + "\n"
	if parent != "" {
		body += "parent " + parent + "\n"
	}
	body += "author Ann Dev <ann@example.org> 1700000000 +0000\ncommitter GitHub <noreply@github.com> 1700000000 +0000\n"
	if sig != "" {
		lines := strings.Split(sig, "\n")
		body += "gpgsig " + lines[0] + "\n"
		for _, l := range lines[1:] {
			body += " " + l + "\n"
		}
	}
	body += "\n" + msg + "\n"
	id := git(t, dir, body, "hash-object", "-t", "commit", "-w", "--stdin")
	git(t, dir, "", "update-ref", "HEAD", id)
	return id
}

func TestAnalyzeRepoReadsLooseAndPackedHistoryWithoutGit(t *testing.T) {
	d := t.TempDir()
	git(t, d, "", "init", "-q", "-b", "main")
	git(t, d, "", "remote", "add", "origin", "git@github.com:acme/app.git")
	sig, fp := sshsig(keyBlob(7))
	id := ""
	for i := 0; i < 12; i++ {
		s := ""
		if i%3 == 0 {
			s = sig
		}
		if i == 5 {
			s = "-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----"
		}
		id = signedCommit(t, d, id, s, fmt.Sprintf("c%d", i))
	}
	check := func(label string) {
		f, warns := AnalyzeRepo(d)
		if f == nil || len(warns) != 0 {
			t.Fatalf("%s: %v %v", label, f, warns)
		}
		if f.Sampled != 12 || f.Head != id {
			t.Errorf("%s: sampled %d head %s", label, f.Sampled, f.Head)
		}
		if len(f.Authors) != 1 || f.Authors[0] != (Person{"Ann Dev", "ann@example.org", 12}) {
			t.Errorf("%s: authors %+v", label, f.Authors)
		}
		var ssh, gpg int
		for _, s := range f.Signers {
			if s.Format == "ssh" && s.Fingerprint == fp && s.Email == "ann@example.org" {
				ssh += s.Commits
			}
			if s.Format == "gpg" {
				gpg += s.Commits
			}
		}
		if ssh != 4 || gpg != 1 {
			t.Errorf("%s: ssh %d gpg %d: %+v", label, ssh, gpg, f.Signers)
		}
		if len(f.Remotes) != 1 || f.Remotes[0].Host != "github.com" || f.Remotes[0].Owner != "acme" || f.Remotes[0].Repo != "app" || f.Remotes[0].Scheme != "ssh" {
			t.Errorf("%s: remotes %+v", label, f.Remotes)
		}
	}
	check("loose")
	git(t, d, "", "repack", "-a", "-d", "-q")
	git(t, d, "", "prune-packed")
	if ents, _ := filepath.Glob(filepath.Join(d, ".git", "objects", "??", "*")); len(ents) != 0 {
		t.Fatalf("still loose: %v", ents)
	}
	check("packed")
	// packed-refs instead of a loose ref
	git(t, d, "", "pack-refs", "--all")
	check("packed-refs")
}

// TestObjectStoreAppliesDeltas: blobs that git stores as deltas read back as
// git cat-file prints them.
func TestObjectStoreAppliesDeltas(t *testing.T) {
	d := t.TempDir()
	git(t, d, "", "init", "-q")
	var ids []string
	text := strings.Repeat("line of text that repeats\n", 200)
	for i := 0; i < 30; i++ {
		text += fmt.Sprintf("added line %d\n", i)
		ids = append(ids, git(t, d, text, "hash-object", "-w", "--stdin"))
	}
	for _, id := range ids {
		git(t, d, "", "update-ref", "refs/keep/"+id, id)
	}
	git(t, d, "", "repack", "-a", "-d", "-f", "-q", "--depth=40", "--window=50")
	git(t, d, "", "prune-packed")
	root, err := os.OpenRoot(filepath.Join(d, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	st := openStore(root)
	defer st.close()
	deltas := 0
	for i, id := range ids {
		sha, _ := parseSHA(id)
		typ, b, err := st.read(sha)
		if err != nil || typ != objBlob {
			t.Fatalf("%s: %d %v", id, typ, err)
		}
		want := strings.Repeat("line of text that repeats\n", 200)
		for j := 0; j <= i; j++ {
			want += fmt.Sprintf("added line %d\n", j)
		}
		if string(b) != want {
			t.Errorf("blob %d differs from what was written", i)
		}
		if out := git(t, d, "", "verify-pack", "-v", filepath.Join(d, ".git", "objects", "pack", packName(t, d))); strings.Contains(out, id[:8]) && deltas == 0 {
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, id) && len(strings.Fields(l)) > 5 {
					deltas++
				}
			}
		}
	}
	if deltas == 0 {
		t.Log("git stored no delta; the delta path was not exercised")
	}
}

func packName(t *testing.T, d string) string {
	m, _ := filepath.Glob(filepath.Join(d, ".git", "objects", "pack", "*.idx"))
	if len(m) != 1 {
		t.Fatalf("packs %v", m)
	}
	return filepath.Base(m[0])
}

func TestParseRemoteURL(t *testing.T) {
	for in, want := range map[string]Remote{
		"git@github.com:gomoni/snug.git":       {Scheme: "ssh", Host: "github.com", Owner: "gomoni", Repo: "snug"},
		"ssh://git@Codeberg.org:2222/a/b":      {Scheme: "ssh", Host: "codeberg.org", Owner: "a", Repo: "b"},
		"https://user:pw@gitlab.com/g/p/q.git": {Scheme: "https", Host: "gitlab.com", Owner: "g", Repo: "p/q"},
		"/srv/git/local.git":                   {Scheme: "other"},
		"../sibling":                           {Scheme: "other"},
		"github.com:o/r":                       {Scheme: "ssh", Host: "github.com", Owner: "o", Repo: "r"},
		"ssh://[::1]:22/x/y":                   {Scheme: "ssh", Host: "::1", Owner: "x", Repo: "y"},
	} {
		got := ParseRemoteURL(in)
		got.URL = ""
		if got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
}

// TestAnalyzeRepoSurvivesCorruptStorage: a truncated pack index, a loose
// object that is not zlib and a ref that is garbage give warnings or nothing,
// never a panic or a hang.
func TestAnalyzeRepoSurvivesCorruptStorage(t *testing.T) {
	d := t.TempDir()
	git(t, d, "", "init", "-q", "-b", "main")
	id := ""
	for i := 0; i < 3; i++ {
		id = signedCommit(t, d, id, "", fmt.Sprintf("c%d", i))
	}
	git(t, d, "", "repack", "-a", "-d", "-q")
	idx, _ := filepath.Glob(filepath.Join(d, ".git", "objects", "pack", "*.idx"))
	if len(idx) != 1 {
		t.Fatalf("%v", idx)
	}
	os.Truncate(idx[0], 700)
	os.MkdirAll(filepath.Join(d, ".git", "objects", id[:2]), 0o755)
	os.WriteFile(filepath.Join(d, ".git", "objects", id[:2], id[2:]), []byte("not zlib"), 0o644)
	f, warns := AnalyzeRepo(d)
	if f == nil || f.Sampled != 0 || len(warns) == 0 {
		t.Errorf("sampled %v warns %v", f, warns)
	}
	os.WriteFile(filepath.Join(d, ".git", "HEAD"), []byte("ref: refs/heads/../../../etc/passwd\n"), 0o644)
	if f, warns := AnalyzeRepo(d); f == nil || len(warns) == 0 {
		t.Errorf("odd ref: %v %v", f, warns)
	}
}
