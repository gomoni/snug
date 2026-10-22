package ingest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/hostfacts"
)

// The fixtures under testdata/sshsig were made once with throwaway keys whose
// private halves were deleted:
//
//	ssh-keygen -q -t TYPE -N '' -C fixture-TYPE -f key_TYPE
//	git -c gpg.format=ssh -c user.signingkey=key_TYPE.pub commit -S -m ...
//	git cat-file commit HEAD > commit_TYPE.txt
//
// so the signatures are ssh-keygen's own, not this package's idea of one.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sshsig", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureKey is a .pub fixture as hostfacts lists a key.
func fixtureKey(t *testing.T, typ string) hostfacts.SSHKey {
	t.Helper()
	f := strings.Fields(string(fixture(t, typ+".pub")))
	fp, err := hostfacts.FingerprintOf(f[1])
	if err != nil {
		t.Fatal(err)
	}
	return hostfacts.SSHKey{Stem: "id_" + typ, Blob: f[1], Fingerprint: fp, Comment: f[2]}
}

// resign replaces the SSHSIG of a commit object with armoured.
func resign(obj []byte, armoured string) []byte {
	payload := signedPayload(obj)
	head, msg, _ := bytes.Cut(payload, []byte("\n\n"))
	lines := strings.Split(armoured, "\n")
	sig := "gpgsig " + strings.Join(lines, "\n ") + "\n"
	return append(append(append(head, '\n'), sig...), append([]byte("\n"), msg...)...)
}

func armour(blob []byte) string {
	return "-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(blob) + "\n-----END SSH SIGNATURE-----"
}

func TestCommitSignatureVerified(t *testing.T) {
	for _, typ := range []string{"ed25519", "rsa", "ecdsa"} {
		obj := fixture(t, "commit_"+typ+".txt")
		k := fixtureKey(t, typ)
		c := parseCommit(obj)
		if c.sig.Format != "ssh" || c.sig.Fingerprint != k.Fingerprint || !c.sig.Verified {
			t.Errorf("%s: %+v, want verified with %s", typ, c.sig, k.Fingerprint)
		}
		// The message is signed too: one byte of it changed fails.
		bad := bytes.Replace(obj, []byte("second line"), []byte("Second line"), 1)
		if c := parseCommit(bad); c.sig.Verified || c.sig.Fingerprint != k.Fingerprint {
			t.Errorf("%s: tampered message still verifies: %+v", typ, c.sig)
		}
		// So is every header but gpgsig.
		bad = bytes.Replace(obj, []byte("author Fix Ture"), []byte("author Fix Turf"), 1)
		if parseCommit(bad).sig.Verified {
			t.Errorf("%s: tampered author still verifies", typ)
		}
	}
}

// TestForgedSignatureNeverSelectsKey: a repository can write a gpgsig header
// that names the human's own public key; one that does not verify is
// reported and never makes that key the suggested signing key.
func TestForgedSignatureNeverSelectsKey(t *testing.T) {
	ed, rsaKey := fixtureKey(t, "ed25519"), fixtureKey(t, "rsa")
	obj := fixture(t, "commit_ed25519.txt")
	sig, err := decodeSSHSig(string(obj[bytes.Index(obj, []byte("-----BEGIN")) : bytes.Index(obj, []byte("-----END"))+len("-----END SSH SIGNATURE-----")]))
	if err != nil {
		t.Fatal(err)
	}
	rsaBlob, _ := base64.StdEncoding.DecodeString(rsaKey.Blob)
	rebuild := func(pub, ns []byte) []byte {
		var b bytes.Buffer
		b.WriteString("SSHSIG\x00\x00\x00\x01")
		for _, f := range [][]byte{pub, ns, sig.reserved, []byte(sig.hashAlg), sig.sig} {
			putString(&b, f)
		}
		return b.Bytes()
	}
	// A key made here, signing this commit's payload correctly but in the
	// "file" namespace: ssh-keygen -Y sign -n file pasted into a commit.
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	var pub bytes.Buffer
	putString(&pub, []byte("ssh-ed25519"))
	putString(&pub, priv.Public().(ed25519.PublicKey))
	h := sha512.Sum512(signedPayload(obj))
	var signed, sigEnc, other bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{[]byte("file"), nil, []byte("sha512"), h[:]} {
		putString(&signed, f)
	}
	putString(&sigEnc, []byte("ssh-ed25519"))
	putString(&sigEnc, ed25519.Sign(priv, signed.Bytes()))
	other.WriteString("SSHSIG\x00\x00\x00\x01")
	for _, f := range [][]byte{pub.Bytes(), []byte("file"), nil, []byte("sha512"), sigEnc.Bytes()} {
		putString(&other, f)
	}
	otherFP, _ := hostfacts.FingerprintOf(base64.StdEncoding.EncodeToString(pub.Bytes()))
	otherKey := hostfacts.SSHKey{Stem: "id_mine", Blob: base64.StdEncoding.EncodeToString(pub.Bytes()), Fingerprint: otherFP}

	for _, tc := range []struct {
		name string
		obj  []byte
		key  hostfacts.SSHKey
	}{
		{"wrong key: ed25519 signature claiming the rsa key", resign(obj, armour(rebuild(rsaBlob, []byte("git")))), rsaKey},
		{"tampered payload", bytes.Replace(obj, []byte("signed with"), []byte("signed by"), 1), ed},
		{"namespace file", resign(obj, armour(other.Bytes())), otherKey},
	} {
		c := parseCommit(tc.obj)
		if c.sig.Verified || c.sig.Fingerprint != tc.key.Fingerprint {
			t.Errorf("%s: %+v (want the claim of %s, unverified)", tc.name, c.sig, tc.key.Fingerprint)
		}
		c.sig.Email, c.sig.Commits = "fix@example.org", 200
		in := SuggestInput{
			Repo: &RepoFacts{Remotes: []Remote{ParseRemoteURL("git@github.com:fix/x.git")},
				Authors: []Person{{"Fix Ture", "fix@example.org", 200}}, Signers: []Signature{c.sig}, Sampled: 200},
			Keys:    []hostfacts.SSHKey{ed, rsaKey, otherKey},
			Authors: []hostfacts.GitAuthor{{Name: "Fix Ture", Email: "fix@example.org"}},
		}
		if p := Suggest(in); p.Signing.Value != "" {
			t.Errorf("%s: suggested signing key %+v", tc.name, p.Signing)
		}
	}

	// The genuine commit does select its key, so the cases above fail for
	// the reason they name.
	c := parseCommit(obj)
	c.sig.Email, c.sig.Commits = "fix@example.org", 1
	p := Suggest(SuggestInput{
		Repo: &RepoFacts{Remotes: []Remote{ParseRemoteURL("git@github.com:fix/x.git")},
			Authors: []Person{{"Fix Ture", "fix@example.org", 1}}, Signers: []Signature{c.sig}, Sampled: 1},
		Keys:    []hostfacts.SSHKey{rsaKey, ed},
		Authors: []hostfacts.GitAuthor{{Name: "Fix Ture", Email: "fix@example.org"}},
	})
	if p.Signing.Value != "id_ed25519" || !strings.Contains(p.Signing.Why, "verifies") {
		t.Errorf("genuine signature: %+v", p.Signing)
	}
}

// TestAnalyzeRepoVerifiesStoredCommits: the object store's bytes, not a
// re-serialised commit, are what is verified.
func TestAnalyzeRepoVerifiesStoredCommits(t *testing.T) {
	d := t.TempDir()
	git(t, d, "", "init", "-q", "-b", "main")
	id := git(t, d, string(fixture(t, "commit_ed25519.txt")), "hash-object", "-t", "commit", "-w", "--stdin", "--literally")
	git(t, d, "", "update-ref", "HEAD", id)
	f, _ := AnalyzeRepo(d)
	if f == nil || len(f.Signers) != 1 || !f.Signers[0].Verified || f.Signers[0].Fingerprint != fixtureKey(t, "ed25519").Fingerprint {
		t.Fatalf("%+v", f)
	}
}
