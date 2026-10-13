package ingest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/safe"
)

// Bounds on the repository read.
const (
	maxCommits  = 200
	maxRefFile  = 4 << 20
	maxConfig   = 256 << 10
	maxRemotes  = 16
	maxPersons  = 64
	maxSigners  = 64
	maxFieldLen = 120
)

// Remote is one [remote "NAME"] url of the repository's config, parsed.
type Remote struct {
	Name   string
	URL    string
	Scheme string // ssh, https, git, other
	Host   string
	Owner  string // first path element
	Repo   string
}

// Person is an author name and email as commits spell them, with how many of
// the sampled commits carry exactly that pair.
type Person struct {
	Name, Email string
	Commits     int
}

// Signature counts sampled commits whose gpgsig header is of a Format and, for
// an ssh signature, was made with the key whose SHA256 fingerprint is
// Fingerprint. It is a claim the commit makes: nothing here verifies it, so
// the only thing a fingerprint is ever used for is to point at one of the
// human's own public keys.
type Signature struct {
	Format      string // ssh, gpg
	Fingerprint string // SHA256:..., ssh only
	Email       string // the author email of the signed commits
	Commits     int
}

// RepoFacts is what a repository's own files say.
type RepoFacts struct {
	Remotes []Remote
	Authors []Person
	Signers []Signature
	Sampled int // commits looked at
	Head    string
}

// AnalyzeRepo reads the git repository at target/.git with no git program:
// HEAD, the ref it names, the first-parent chain of up to maxCommits commits
// (author, committer and gpgsig headers only; messages and trees are never
// looked at) and the remote urls in .git/config.
//
// Abuse: running `git log --format=%G?` in a hostile repository executes
// whatever its config names: gpg.ssh.program, gpg.program, core.fsmonitor,
// core.pager, an include.path pointing at a file the attacker also planted. Not
// running git is the defence. What remains is reading bytes the attacker wrote:
// the files are opened through an os.Root on the target so no link leaves it,
// regular files only and non-blocking, every size bounded (see gitobj.go), and
// every string is cleaned and cut before it is shown. The signature claims in
// commits can be forged to make the suggestion point at a different one of the
// human's OWN keys; the suggestion is only ever a default for a question the
// human answers.
func AnalyzeRepo(target string) (*RepoFacts, []string) {
	root, err := os.OpenRoot(target)
	if err != nil {
		return nil, nil
	}
	defer root.Close()
	li, err := root.Lstat(".git")
	if err != nil {
		return nil, nil
	}
	var git, headDir *os.Root
	switch {
	case li.IsDir():
		git, err = root.OpenRoot(".git")
		if err != nil {
			return nil, []string{"cannot open .git: " + safe.Inline(err.Error())}
		}
		headDir = git
	case li.Mode().IsRegular():
		var why string
		headDir, git, why = openLinkedWorktree(root, target)
		if headDir == nil {
			return nil, []string{why}
		}
		defer headDir.Close()
	default:
		return nil, []string{"the target's .git is neither a directory nor a worktree link; the repository was not read."}
	}
	defer git.Close()
	var warns []string
	f := &RepoFacts{}
	if cfg, err := readSmallIn(git, "config", maxConfig); err == nil {
		f.Remotes = parseRemotes(string(cfg))
	}
	headID, err := resolveHead(headDir, git)
	if err != nil {
		return f, append(warns, "HEAD could not be resolved ("+safe.Inline(err.Error())+"); no commits were read.")
	}
	f.Head = headID
	st := openStore(git)
	defer st.close()
	if _, err := git.Lstat("objects/info/alternates"); err == nil {
		warns = append(warns, "the repository borrows objects from another (objects/info/alternates), which is not followed.")
	}
	sha, _ := parseSHA(headID)
	authors := map[Person]int{}
	signers := map[Signature]int{}
	seen := map[[20]byte]bool{}
	for i := 0; i < maxCommits; i++ {
		if seen[sha] {
			break
		}
		seen[sha] = true
		typ, body, err := st.read(sha)
		if err != nil || typ != objCommit {
			if i == 0 {
				warns = append(warns, "the head commit could not be read ("+safe.Inline(errString(err))+").")
			}
			break
		}
		c := parseCommit(body)
		f.Sampled++
		if c.author.Email != "" {
			authors[c.author]++
		}
		if c.sig.Format != "" {
			s := c.sig
			s.Email = c.author.Email
			signers[s]++
		}
		parent, ok := parseSHA(c.parent)
		if !ok {
			break
		}
		sha = parent
	}
	for p, n := range authors {
		p.Commits = n
		f.Authors = append(f.Authors, p)
	}
	slices.SortFunc(f.Authors, func(a, b Person) int {
		if a.Commits != b.Commits {
			return b.Commits - a.Commits
		}
		return strings.Compare(a.Email+a.Name, b.Email+b.Name)
	})
	if len(f.Authors) > maxPersons {
		f.Authors = f.Authors[:maxPersons]
	}
	for s, n := range signers {
		s.Commits = n
		f.Signers = append(f.Signers, s)
	}
	slices.SortFunc(f.Signers, func(a, b Signature) int {
		if a.Commits != b.Commits {
			return b.Commits - a.Commits
		}
		return strings.Compare(a.Fingerprint+a.Email, b.Fingerprint+b.Email)
	})
	if len(f.Signers) > maxSigners {
		f.Signers = f.Signers[:maxSigners]
	}
	return f, warns
}

func errString(err error) string {
	if err == nil {
		return "not a commit"
	}
	return err.Error()
}

func readSmallIn(r *os.Root, name string, limit int64) ([]byte, error) {
	f, err := openRegular(r, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	return b, err
}

// resolveHead returns the commit id HEAD names, read from headDir: a detached
// id, or the id of the branch it points at, looked up as a loose ref and then
// in packed-refs of git, the repository proper (the same directory unless the
// target is a linked worktree).
func resolveHead(headDir, git *os.Root) (string, error) {
	b, err := readSmallIn(headDir, "HEAD", 4096)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(b))
	ref, ok := strings.CutPrefix(line, "ref: ")
	if !ok {
		if _, ok := parseSHA(line); ok {
			return line, nil
		}
		return "", errBadHead
	}
	if !safeRef(ref) {
		return "", errBadHead
	}
	if rb, err := readSmallIn(git, ref, 4096); err == nil {
		if id := strings.TrimSpace(string(rb)); len(id) == 40 {
			if _, ok := parseSHA(id); ok {
				return id, nil
			}
		}
	}
	pb, err := readSmallIn(git, "packed-refs", maxRefFile)
	if err != nil {
		return "", errBadHead
	}
	sc := bufio.NewScanner(bytes.NewReader(pb))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		id, name, ok := strings.Cut(sc.Text(), " ")
		if ok && name == ref {
			if _, ok := parseSHA(id); ok {
				return id, nil
			}
		}
	}
	return "", errBadHead
}

type headErr string

func (e headErr) Error() string { return string(e) }

const errBadHead = headErr("HEAD does not name a readable branch or commit")

// safeRef accepts the ref names git itself would, minus anything that could
// walk out of refs/ even before os.Root refuses it.
func safeRef(r string) bool {
	if !strings.HasPrefix(r, "refs/") || len(r) > 200 || strings.Contains(r, "..") || strings.ContainsAny(r, "\x00\\ \t\n") {
		return false
	}
	return !strings.HasSuffix(r, "/") && !strings.Contains(r, "//")
}

type commit struct {
	parent string
	author Person
	sig    Signature
}

// parseCommit reads the headers of a commit object: first parent, author and
// the kind of signature (and for ssh the fingerprint of the key that made it).
// The message after the blank line is not read.
func parseCommit(b []byte) commit {
	var c commit
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		b = b[:i]
	}
	var sigLines []string
	inSig := false
	for _, l := range strings.Split(string(b), "\n") {
		if inSig && strings.HasPrefix(l, " ") {
			sigLines = append(sigLines, l[1:])
			continue
		}
		inSig = false
		name, val, _ := strings.Cut(l, " ")
		switch name {
		case "parent":
			if c.parent == "" {
				c.parent = val
			}
		case "author":
			c.author = parsePerson(val)
		case "gpgsig":
			inSig = true
			sigLines = append(sigLines, val)
		}
	}
	c.sig = parseSignature(strings.Join(sigLines, "\n"))
	return c
}

func parsePerson(s string) Person {
	lt, gt := strings.IndexByte(s, '<'), strings.LastIndexByte(s, '>')
	if lt < 0 || gt < lt {
		return Person{}
	}
	return Person{Name: cut(strings.TrimSpace(s[:lt])), Email: cut(s[lt+1 : gt])}
}

func cut(s string) string {
	s = safe.Inline(s)
	if r := []rune(s); len(r) > maxFieldLen {
		return string(r[:maxFieldLen])
	}
	return s
}

// parseSignature classifies a gpgsig value. For an SSH signature it decodes the
// armoured SSHSIG blob and returns the SHA256 fingerprint of the public key
// inside it, spelled as ssh-keygen -l does. The signature itself is not
// verified.
func parseSignature(s string) Signature {
	switch {
	case strings.Contains(s, "BEGIN SSH SIGNATURE"):
		var body strings.Builder
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
				body.WriteString(l)
			}
		}
		raw, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil || len(raw) < 6+4+4 || string(raw[:6]) != "SSHSIG" {
			return Signature{Format: "ssh"}
		}
		raw = raw[6+4:] // magic, version
		n := binary.BigEndian.Uint32(raw)
		if n == 0 || int64(n) > int64(len(raw)-4) {
			return Signature{Format: "ssh"}
		}
		sum := sha256.Sum256(raw[4 : 4+n])
		return Signature{Format: "ssh", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
	case strings.Contains(s, "BEGIN PGP SIGNATURE"), strings.Contains(s, "BEGIN SIGNED MESSAGE"):
		return Signature{Format: "gpg"}
	}
	return Signature{}
}

// parseRemotes reads [remote "NAME"] url = ... from a git config. Includes and
// every other key are ignored; a url is only ever split into host and path and
// compared, never contacted.
func parseRemotes(cfg string) []Remote {
	var out []Remote
	cur := ""
	for _, l := range strings.Split(cfg, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			cur = ""
			if rest, ok := strings.CutPrefix(l, "[remote \""); ok {
				if name, _, ok := strings.Cut(rest, "\""); ok {
					cur = name
				}
			}
			continue
		}
		if cur == "" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.ToLower(strings.TrimSpace(k)) != "url" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "\"")
		if len(out) < maxRemotes && !slices.ContainsFunc(out, func(r Remote) bool { return r.Name == cur }) {
			r := ParseRemoteURL(v)
			r.Name = cut(cur)
			out = append(out, r)
		}
	}
	return out
}

// ParseRemoteURL splits a git remote url: scp-like (user@host:owner/repo),
// ssh://, https://, git://. Fields are cleaned and cut; a url it does not
// understand yields Scheme "other" and no host.
func ParseRemoteURL(u string) Remote {
	r := Remote{URL: cut(u), Scheme: "other"}
	var host, path string
	if i := strings.Index(u, "://"); i >= 0 {
		scheme := strings.ToLower(u[:i])
		rest := u[i+3:]
		hp, p, _ := strings.Cut(rest, "/")
		if at := strings.LastIndexByte(hp, '@'); at >= 0 {
			hp = hp[at+1:]
		}
		host, path = hp, p
		switch {
		case strings.HasSuffix(scheme, "ssh"):
			r.Scheme = "ssh"
		case scheme == "https" || scheme == "http":
			r.Scheme = "https"
		case scheme == "git":
			r.Scheme = "git"
		}
		if strings.HasPrefix(host, "[") {
			if e := strings.IndexByte(host, ']'); e > 0 {
				host = host[1:e]
			}
		} else if c := strings.LastIndexByte(host, ':'); c >= 0 {
			host = host[:c]
		}
	} else if c := strings.IndexByte(u, ':'); c > 0 && !strings.Contains(u[:c], "/") {
		h := u[:c]
		if at := strings.LastIndexByte(h, '@'); at >= 0 {
			h = h[at+1:]
		}
		host, path, r.Scheme = h, u[c+1:], "ssh"
	}
	r.Host = strings.ToLower(cut(host))
	path = strings.Trim(path, "/")
	owner, repo, _ := strings.Cut(path, "/")
	r.Owner = cut(owner)
	r.Repo = cut(strings.TrimSuffix(repo, ".git"))
	return r
}

// openLinkedWorktree follows the `gitdir: PATH` file a linked worktree has in
// place of a .git directory, and returns the worktree's own admin directory
// (HEAD) and the repository's (objects, refs, config).
//
// Abuse: that file is written by the project, so a hostile one names any
// directory on the host, and following it would show the human another
// repository's remotes, authors and key fingerprints as if they were this
// project's. The pointer is therefore followed only when the directory it
// names points back: `git worktree add` writes PATH/gitdir holding the
// worktree's .git path, and a project cannot write into a repository it does
// not own. A pointer without that back-link, a submodule's, one not under a
// "worktrees" directory, is reported and not read.
func openLinkedWorktree(root *os.Root, target string) (head, git *os.Root, why string) {
	refused := func(why string) (*os.Root, *os.Root, string) {
		return nil, nil, "the target's .git is a file that does not name one of its own worktrees (" + why + "); the repository was not read."
	}
	b, err := readSmallIn(root, ".git", 4096)
	if err != nil {
		return refused("unreadable")
	}
	p, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir: ")
	if !ok || p == "" {
		return refused("no gitdir line")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(target, p)
	}
	p = filepath.Clean(p)
	if filepath.Base(filepath.Dir(p)) != "worktrees" {
		return refused("not under a worktrees directory")
	}
	admin, err := os.OpenRoot(p)
	if err != nil {
		return refused("cannot open it")
	}
	back, err := readSmallIn(admin, "gitdir", 4096)
	if err != nil || !samePath(strings.TrimSpace(string(back)), filepath.Join(target, ".git")) {
		admin.Close()
		return refused("it does not point back at this directory")
	}
	rel, err := readSmallIn(admin, "commondir", 4096)
	if err != nil {
		admin.Close()
		return refused("no commondir")
	}
	common := strings.TrimSpace(string(rel))
	if !filepath.IsAbs(common) {
		common = filepath.Join(p, common)
	}
	// The back-link binds only the admin directory, and commondir sits beside
	// it, written by whoever wrote the admin directory. A hostile project
	// places that directory inside itself, writes a valid back-link, and aims
	// commondir at any repository on the host. Git keeps an admin directory at
	// COMMON/worktrees/NAME and writes commondir as "../..", so anything else
	// is not a worktree of the repository whose admin directory this is.
	if filepath.Clean(common) != filepath.Dir(filepath.Dir(p)) {
		admin.Close()
		return refused("its commondir does not name the repository that holds it")
	}
	git, err = os.OpenRoot(filepath.Clean(common))
	if err != nil {
		admin.Close()
		return refused("cannot open the repository it belongs to")
	}
	return admin, git, ""
}

func samePath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}
