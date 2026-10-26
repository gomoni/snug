package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/vdir"
)

// The host-file half of login.claude = "host": the pin in ~/.claude.json,
// the host's ~/.claude/.credentials.json, and the sandbox's own credential
// file in this run's directory. Host I/O lives here, as identity.go's does;
// internal/loginbridge decides what to ask, internal/policy what the bytes
// are.

const (
	// claudeRunDirName is this run's directory the sandbox's credential
	// lives in, bound read-only at policy.ClaudeCredentialDirGuest.
	claudeRunDirName = "claude"
	// claudeCredentialsName is the file Claude Code reads in its storage
	// directory.
	claudeCredentialsName = ".credentials.json"
	// maxClaudeStateBytes caps the read of ~/.claude.json, which snug reads
	// for oauthAccount alone.
	maxClaudeStateBytes = 8 << 20
	// storageLockName is the directory Claude Code's own writes lock on; a
	// lock older than storageLockStale is one its owner left behind.
	storageLockName  = ".storage-write.lock"
	storageLockStale = 15 * time.Second
	storageLockTries = 10
)

// claudeLoginReads is what the host-mode preflight reads off the host. It is
// an interface so the screens that report the preflight's verdict can be
// pinned against a fake host; claudeLoginReadsFor picks the real one.
type claudeLoginReads interface {
	// ReadClaudeState is hostread.Optional on path.
	ReadClaudeState(path string) (data []byte, note string)
	Lstat(path string) (fs.FileInfo, error)
	// Writable is nil when this process may create entries in dir.
	Writable(dir string) error
}

type osClaudeLoginReads struct{}

func (osClaudeLoginReads) ReadClaudeState(path string) ([]byte, string) {
	return hostread.Optional(path, maxClaudeStateBytes)
}
func (osClaudeLoginReads) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (osClaudeLoginReads) Writable(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return unix.Access(dir, unix.W_OK|unix.X_OK)
}

// claudeLoginReadsFor is env's own reads when it has them (a test's fake
// host), and the real host's otherwise.
func claudeLoginReadsFor(env policy.Environ) claudeLoginReads {
	if r, ok := env.(claudeLoginReads); ok {
		return r
	}
	return osClaudeLoginReads{}
}

// readClaudePin reads the account ~/.claude.json's oauthAccount names. note
// is why it could not be read; a file with no oauthAccount is a zero pin and
// no note.
func readClaudePin(r claudeLoginReads, home string) (loginbridge.AccountPin, string) {
	path := filepath.Join(home, ".claude.json")
	data, note := r.ReadClaudeState(path)
	if note != "" {
		return loginbridge.AccountPin{}, "~/.claude.json " + note
	}
	if data == nil {
		return loginbridge.AccountPin{}, ""
	}
	var state struct {
		OAuthAccount struct {
			AccountUUID      string `json:"accountUuid"`
			OrganizationUUID string `json:"organizationUuid"`
			EmailAddress     string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return loginbridge.AccountPin{}, "~/.claude.json is not JSON snug can read"
	}
	a := state.OAuthAccount
	return loginbridge.AccountPin{AccountUUID: a.AccountUUID, OrganizationUUID: a.OrganizationUUID, Email: a.EmailAddress}, ""
}

// claudeHostPreflight refuses a host-mode run that could never rewrite the
// host's login, before any browser opens: one that names no account (both
// of ~/.claude.json's oauthAccount uuids), one whose
// ~/.claude/.credentials.json is anything but a regular file or absent, and
// one whose ~/.claude this process cannot write. It returns the pin.
func claudeHostPreflight(r claudeLoginReads, home string) (loginbridge.AccountPin, error) {
	const alt = ` — or use login.claude = "sandbox", which leaves the host's login alone`
	pin, note := readClaudePin(r, home)
	if note != "" {
		return pin, fmt.Errorf("login.claude = \"host\" renews the Claude login this host is signed in to, "+
			"and %s%s", note, alt)
	}
	if !pin.Present() {
		return pin, fmt.Errorf("login.claude = \"host\" renews the Claude login this host is signed in to, "+
			"and ~/.claude.json names none (no oauthAccount with both an accountUuid and an "+
			"organizationUuid). Sign in once with `claude` on the host%s", alt)
	}
	creds := filepath.Join(home, ".claude", claudeCredentialsName)
	if fi, err := r.Lstat(creds); err == nil && !fi.Mode().IsRegular() {
		return pin, fmt.Errorf("login.claude = \"host\" rewrites ~/.claude/.credentials.json, and %q is a %s, "+
			"not a regular file; snug replaces only a regular file there. Make it one (run `claude` on the "+
			"host)%s", creds, fileShape(fi.Mode()), alt)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return pin, fmt.Errorf("login.claude = \"host\" rewrites ~/.claude/.credentials.json, and snug could "+
			"not inspect %q: %v%s", creds, err, alt)
	}
	dir := filepath.Join(home, ".claude")
	if err := r.Writable(dir); err != nil {
		return pin, fmt.Errorf("login.claude = \"host\" rewrites ~/.claude/.credentials.json, and %q is not "+
			"a directory snug can write in (%v). Fix its ownership or mode, or sign in once with `claude` "+
			"on the host%s", dir, err, alt)
	}
	return pin, nil
}

// runSubdir is a directory this run created inside its own runtime
// directory, held as the verified *os.Root it was created through.
type runSubdir struct {
	path string
	root *os.Root
}

// Dir creates this run's subdirectory name, mode 0700, through the run
// directory's verified parent, refusing one that already exists: the run
// directory is this process's alone, so anything at the name was planted.
func (d *runtimeDir) Dir(name string) (*runSubdir, error) {
	if err := checkSocketName(name); err != nil {
		return nil, err
	}
	snugPath := filepath.Dir(d.path)
	runRoot, err := vdir.OpenExistingSubdir(d.snugRoot, snugPath, d.runName)
	if err != nil {
		return nil, err
	}
	defer runRoot.Close()
	child, err := vdir.MustCreateSubdir(runRoot, d.path, name)
	if err != nil {
		return nil, err
	}
	return &runSubdir{path: filepath.Join(d.path, name), root: child}, nil
}

// Replace writes content as name in the directory by temp file and rename,
// so a reader sees the old file or the new one and never a torn one, and a
// bind of the DIRECTORY shows the new inode.
func (s *runSubdir) Replace(name string, content policy.Secret) error {
	if err := checkSocketName(name); err != nil {
		return err
	}
	return replaceIn(s.root, name, content)
}

func (s *runSubdir) close() { s.root.Close() }

// replaceIn writes name inside root as Claude Code writes its own
// credential file: a 0600 temp file beside it named name.tmp.<8 hex>,
// created exclusively and refusing a link, synced, renamed over name, and
// the directory synced. The temp file is removed on every error path.
func replaceIn(root *os.Root, name string, content policy.Secret) error {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := name + ".tmp." + hex.EncodeToString(suffix[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			root.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write([]byte(content)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	ok = true
	if d, err := root.Open("."); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// claudeHostFiles is loginbridge.HostFiles for a real run.
type claudeHostFiles struct {
	home    string
	reads   claudeLoginReads
	sandbox *runSubdir
	now     func() time.Time
}

// startClaudeHostLogin creates this run's credential directory, seeds it
// with the projection @claude staged (when it staged one), and binds it
// read-only at policy.ClaudeCredentialDirGuest.
func startClaudeHostLogin(pol *policy.Policy, runDir *runtimeDir) (*claudeHostFiles, error) {
	dir, err := runDir.Dir(claudeRunDirName)
	if err != nil {
		return nil, fmt.Errorf("login.claude = \"host\": creating the sandbox's credential directory: %w", err)
	}
	if m, ok := claudeCredentialsMount(pol); ok {
		if err := dir.Replace(claudeCredentialsName, m.Content); err != nil {
			dir.close()
			return nil, fmt.Errorf("login.claude = \"host\": writing the sandbox's credential in %s: %w",
				dir.path, err)
		}
	}
	pol.BindRunDir(dir.path, policy.ClaudeCredentialDirGuest, policy.LoginKey(policy.LoginClaude, policy.LoginHost))
	return &claudeHostFiles{home: pol.Home, reads: osClaudeLoginReads{}, sandbox: dir, now: time.Now}, nil
}

func (h *claudeHostFiles) close() { h.sandbox.close() }

// Snapshot is loginbridge.HostFiles'.
func (h *claudeHostFiles) Snapshot() loginbridge.HostSnapshot {
	pin, note := readClaudePin(h.reads, h.home)
	return loginbridge.HostSnapshot{Pin: pin, PinProblem: note, File: readHostCredential(h.home)}
}

// readHostCredential reads the host credential file's two tokens for the
// compare-and-swap. A file that is there and does not parse still Exists,
// with no tokens.
func readHostCredential(home string) loginbridge.CredentialFile {
	path := filepath.Join(home, ".claude", claudeCredentialsName)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return loginbridge.CredentialFile{Exists: err == nil}
	}
	data, _ := hostread.Optional(path, maxCredentialsBytes)
	return credentialTokens(data)
}

func credentialTokens(data []byte) loginbridge.CredentialFile {
	var f struct {
		OAuth struct {
			AccessToken  *string `json:"accessToken"`
			RefreshToken *string `json:"refreshToken"`
		} `json:"claudeAiOauth"`
	}
	out := loginbridge.CredentialFile{Exists: true}
	if json.Unmarshal(data, &f) == nil {
		if f.OAuth.AccessToken != nil {
			out.AccessToken = policy.Secret(*f.OAuth.AccessToken)
		}
		if f.OAuth.RefreshToken != nil {
			out.RefreshToken = policy.Secret(*f.OAuth.RefreshToken)
		}
	}
	return out
}

func sameCredential(a, b loginbridge.CredentialFile) bool {
	return a.Exists == b.Exists &&
		subtle.ConstantTimeCompare(a.AccessToken, b.AccessToken) == 1 &&
		subtle.ConstantTimeCompare(a.RefreshToken, b.RefreshToken) == 1
}

// RenewSandbox is loginbridge.HostFiles'.
func (h *claudeHostFiles) RenewSandbox(_ context.Context, r policy.ClaudeLoginResult, now time.Time, keepPlan bool) error {
	var existing []byte
	if keepPlan {
		if f, err := h.sandbox.root.Open(claudeCredentialsName); err == nil {
			existing, _ = io.ReadAll(io.LimitReader(f, maxCredentialsBytes))
			f.Close()
		}
	}
	content, err := policy.ProjectClaudeLogin(existing, r, now)
	if err != nil {
		return err
	}
	return h.sandbox.Replace(claudeCredentialsName, content)
}

// Errors WriteHost answers with, each worded to follow "the host's login
// was not rewritten: ".
var (
	errNoHostLogin = errors.New("this host has no Claude login to renew; sign in once with `claude` on the host")
	errNewerLogin  = errors.New("another program on the host wrote a newer login while this one ran; it keeps that one")
	errLockHeld    = errors.New("~/.claude/.storage-write.lock is held by another program saving a Claude " +
		"login (a running claude, or another snug); run /login again later")
)

// WriteHost is loginbridge.HostFiles': under Claude Code's own storage lock,
// it re-reads the host credential file and rewrites it only when it is still
// what snap recorded — never a file that is absent, a link or not regular.
func (h *claudeHostFiles) WriteHost(ctx context.Context, snap loginbridge.HostSnapshot, r policy.ClaudeLoginResult, now time.Time) error {
	if !snap.File.Exists {
		return errNoHostLogin
	}
	dir := filepath.Join(h.home, ".claude")
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errNoHostLogin
		}
		return fmt.Errorf("opening %q: %v", dir, err)
	}
	defer root.Close()

	unlock, err := takeStorageLock(ctx, root, h.now)
	if err != nil {
		return err
	}
	defer unlock()

	fi, err := root.Lstat(claudeCredentialsName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return errNoHostLogin
	case err != nil:
		return fmt.Errorf("inspecting ~/.claude/.credentials.json: %v", err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return errors.New("~/.claude/.credentials.json is a symlink; snug replaces only a regular file there")
	case !fi.Mode().IsRegular():
		return fmt.Errorf("~/.claude/.credentials.json is a %s, not a regular file", fileShape(fi.Mode()))
	}
	f, err := root.OpenFile(claudeCredentialsName, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("reading ~/.claude/.credentials.json: %v", err)
	}
	existing, err := io.ReadAll(io.LimitReader(f, maxCredentialsBytes+1))
	f.Close()
	if err != nil || len(existing) > maxCredentialsBytes {
		return fmt.Errorf("reading ~/.claude/.credentials.json: %v", errOr(err, "over the size cap"))
	}
	if !sameCredential(credentialTokens(existing), snap.File) {
		return errNewerLogin
	}
	if ctx.Err() != nil {
		return errors.New("snug is shutting down")
	}
	content, err := policy.RenewClaudeCredentials(existing, r, now)
	if err != nil {
		return err
	}
	if err := replaceIn(root, claudeCredentialsName, content); err != nil {
		return fmt.Errorf("writing ~/.claude/.credentials.json: %v", err)
	}
	return nil
}

func errOr(err error, s string) error {
	if err != nil {
		return err
	}
	return errors.New(s)
}

// takeStorageLock takes Claude Code's write lock on its storage directory:
// a directory created with mkdir, which is atomic, so two writers cannot
// both hold it. A lock whose mtime is older than storageLockStale is one its
// owner left behind and is removed; otherwise snug backs off from 100 ms to
// 1 s, storageLockTries times, as the client itself does.
func takeStorageLock(ctx context.Context, root *os.Root, now func() time.Time) (func(), error) {
	delay := 100 * time.Millisecond
	for try := 0; ; try++ {
		err := root.Mkdir(storageLockName, 0o700)
		if err == nil {
			return func() { root.Remove(storageLockName) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("taking ~/.claude/%s: %v", storageLockName, err)
		}
		if fi, serr := root.Lstat(storageLockName); serr == nil && fi.IsDir() &&
			fi.ModTime().Before(now().Add(-storageLockStale)) {
			root.Remove(storageLockName)
			continue
		}
		if try >= storageLockTries {
			return nil, errLockHeld
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("snug is shutting down")
		case <-time.After(delay):
		}
		delay = min(2*delay, time.Second)
	}
}

// hostLoginLines is the host-mode paragraph of --dry-run's CLAUDE block.
func hostLoginLines() []string {
	return []string{
		"login.claude = \"host\": a /login inside is completed on the HOST, which REWRITES",
		"~/.claude/.credentials.json there for the account ~/.claude.json names. Claude",
		"Code in here reads " + policy.ClaudeCredentialDirGuest + "/" + claudeCredentialsName + ", a read-only",
		"copy snug renews; ~/.claude/.credentials.json in here is the same projection,",
		"unused in this mode. After such a /login one request may fail once; retry it.",
	}
}

// plannedClaudeRunDir is the --dry-run counterpart of startClaudeHostLogin:
// it names the directory a real run would create, creating nothing.
func plannedClaudeRunDir() (string, error) { return plannedSocket(claudeRunDirName) }
