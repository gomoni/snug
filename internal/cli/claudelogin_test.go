package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/loginbridge"
	"github.com/gomoni/snug/internal/policy"
)

const hostCredFixture = `{"primaryApiKey":"sk-x","claudeAiOauth":{"accessToken":"OLD-AT","refreshToken":"OLD-RT",` +
	`"expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"t"}}`

func hostLoginResult() policy.ClaudeLoginResult {
	return policy.ClaudeLoginResult{
		AccessToken: policy.Secret("NEW-AT"), RefreshToken: policy.Secret("NEW-RT"),
		ExpiresIn: 8 * time.Hour, Scopes: []string{"user:inference"},
		OrganizationType: "claude_max", RateLimitTier: "default_claude_max_5x",
	}
}

// hostFilesFixture is a home with a host credential file, and a run's
// credential directory, both in temp directories.
func hostFilesFixture(t *testing.T, cred string) (*claudeHostFiles, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if cred != "" {
		if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(cred), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"),
		[]byte(`{"oauthAccount":{"accountUuid":"acc-1","organizationUuid":"org-1","emailAddress":"a@example.com"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	root, err := os.OpenRoot(runDir)
	if err != nil {
		t.Fatal(err)
	}
	h := &claudeHostFiles{home: home, reads: osClaudeLoginReads{}, sandbox: &runSubdir{path: runDir, root: root}, now: time.Now}
	t.Cleanup(h.close)
	return h, home
}

func hostCredPath(home string) string { return filepath.Join(home, ".claude", ".credentials.json") }

func fileHash(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// TestHostModeWritesTheHostFileUnderTheLockAtMode0600: a matching snapshot
// gets the file rewritten in place by rename, 0600, foreign keys kept, no
// temp file and no lock left behind.
func TestHostModeWritesTheHostFileUnderTheLockAtMode0600(t *testing.T) {
	h, home := hostFilesFixture(t, hostCredFixture)
	snap := h.Snapshot()
	if !snap.File.Exists || string(snap.File.RefreshToken) != "OLD-RT" || !snap.Pin.Present() {
		t.Fatalf("snapshot: %+v", snap)
	}
	before, _ := os.Stat(hostCredPath(home))
	if err := h.WriteHost(context.Background(), snap, hostLoginResult(), time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(hostCredPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", after.Mode().Perm())
	}
	if os.SameFile(before, after) {
		t.Error("the file was rewritten in place, not replaced by rename")
	}
	b, _ := os.ReadFile(hostCredPath(home))
	if !strings.HasPrefix(string(b), `{"primaryApiKey":"sk-x","claudeAiOauth":{"accessToken":"NEW-AT","refreshToken":"NEW-RT",`) ||
		strings.HasSuffix(string(b), "\n") {
		t.Errorf("host file: %s", b)
	}
	entries, _ := os.ReadDir(filepath.Join(home, ".claude"))
	for _, e := range entries {
		if e.Name() != ".credentials.json" {
			t.Errorf("left behind in ~/.claude: %s", e.Name())
		}
	}
}

// TestHostModeDoesNotCreateAMissingHostFile: a host with no credential file
// is never given one, whatever the pin says, and the reason is the one the
// human is told.
func TestHostModeDoesNotCreateAMissingHostFile(t *testing.T) {
	h, home := hostFilesFixture(t, "")
	err := h.WriteHost(context.Background(), h.Snapshot(), hostLoginResult(), time.Now())
	if !errors.Is(err, errNoHostLogin) || !strings.Contains(err.Error(), "this host has no Claude login to renew") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(hostCredPath(home)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing host file was created: %v", err)
	}
	// Present at the snapshot and gone by the write: still not created.
	h2, home2 := hostFilesFixture(t, hostCredFixture)
	snap := h2.Snapshot()
	os.Remove(hostCredPath(home2))
	if err := h2.WriteHost(context.Background(), snap, hostLoginResult(), time.Now()); !errors.Is(err, errNoHostLogin) {
		t.Fatalf("removed after the snapshot: %v", err)
	}
	if _, err := os.Lstat(hostCredPath(home2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a host file removed after the snapshot was recreated")
	}
}

// TestHostModeLeavesTheHostFileOnACASMismatch: a file whose tokens changed
// since the snapshot is left byte-identical, blaming no particular program.
func TestHostModeLeavesTheHostFileOnACASMismatch(t *testing.T) {
	h, home := hostFilesFixture(t, hostCredFixture)
	snap := h.Snapshot()
	newer := strings.Replace(hostCredFixture, "OLD-RT", "SIBLING-RT", 1)
	os.WriteFile(hostCredPath(home), []byte(newer), 0o600)
	sum := fileHash(t, hostCredPath(home))
	err := h.WriteHost(context.Background(), snap, hostLoginResult(), time.Now())
	if !errors.Is(err, errNewerLogin) || strings.Contains(err.Error(), "claude on the host") {
		t.Fatalf("err = %v", err)
	}
	if fileHash(t, hostCredPath(home)) != sum {
		t.Fatal("the newer host file was overwritten")
	}
}

// TestHostModeRefusesASymlinkedHostFile: a link at the host file's name is
// refused and left alone, as is its target.
func TestHostModeRefusesASymlinkedHostFile(t *testing.T) {
	h, home := hostFilesFixture(t, "")
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	os.WriteFile(target, []byte(hostCredFixture), 0o600)
	os.Symlink(target, hostCredPath(home))
	sum := fileHash(t, target)
	snap := h.Snapshot()
	err := h.WriteHost(context.Background(), snap, hostLoginResult(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "symlink") && !errors.Is(err, errNoHostLogin) {
		t.Fatalf("err = %v", err)
	}
	if fi, _ := os.Lstat(hostCredPath(home)); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced")
	}
	if fileHash(t, target) != sum {
		t.Error("the link's target was written")
	}
	// The preflight refuses it before any browser opens.
	if _, err := claudeHostPreflight(osClaudeLoginReads{}, home); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("preflight: %v", err)
	}
}

// TestHostModeTakesOverOnlyAStaleLock: a lock younger than 15 s is waited
// out and then refused, naming it without blaming claude alone; an older
// one is removed and the write goes through.
func TestHostModeTakesOverOnlyAStaleLock(t *testing.T) {
	h, home := hostFilesFixture(t, hostCredFixture)
	lock := filepath.Join(home, ".claude", ".storage-write.lock")
	os.Mkdir(lock, 0o700)
	sum := fileHash(t, hostCredPath(home))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := h.WriteHost(ctx, h.Snapshot(), hostLoginResult(), time.Now())
	if err == nil || fileHash(t, hostCredPath(home)) != sum {
		t.Fatalf("a fresh lock was not respected: %v", err)
	}
	if _, serr := os.Stat(lock); serr != nil {
		t.Fatal("snug removed a lock it did not take")
	}
	old := time.Now().Add(-16 * time.Second)
	os.Chtimes(lock, old, old)
	if err := h.WriteHost(context.Background(), h.Snapshot(), hostLoginResult(), time.Now()); err != nil {
		t.Fatalf("a stale lock was not taken over: %v", err)
	}
	if _, serr := os.Stat(lock); !errors.Is(serr, os.ErrNotExist) {
		t.Error("the lock was left behind after the write")
	}
	if !strings.Contains(errLockHeld.Error(), "another program") {
		t.Error("the held-lock reason blames claude alone")
	}
}

// TestHostModeRenewsTheRunDirFileByRename: the sandbox's file is replaced
// by a new inode, 0600, carrying the projection only.
func TestHostModeRenewsTheRunDirFileByRename(t *testing.T) {
	h, _ := hostFilesFixture(t, hostCredFixture)
	if err := h.sandbox.Replace(claudeCredentialsName, policy.Secret(`{"claudeAiOauth":{"accessToken":"OLD-AT"}}`)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.sandbox.path, claudeCredentialsName)
	before, _ := os.Stat(p)
	if err := h.RenewSandbox(context.Background(), hostLoginResult(), time.Now(), true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Errorf("not replaced by a new 0600 inode: same=%v mode=%v", os.SameFile(before, after), after.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	var f map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if string(f["claudeAiOauth"]["accessToken"]) != `"NEW-AT"` {
		t.Errorf("sandbox file: %s", b)
	}
	if strings.Contains(string(b), "NEW-RT") || strings.Contains(string(b), "OLD-AT") {
		t.Errorf("the sandbox file carries a refresh token or the old token: %s", b)
	}
	entries, _ := os.ReadDir(h.sandbox.path)
	if len(entries) != 1 {
		t.Errorf("run directory holds %d entries, want the one file", len(entries))
	}
}

// TestHostModePreflightRefusesWhatCouldNeverBeRenewed: no pin, half a pin,
// an unwritable ~/.claude, and a non-regular credential file each refuse
// before any browser opens; an absent credential file does not.
func TestHostModePreflightRefusesWhatCouldNeverBeRenewed(t *testing.T) {
	_, home := hostFilesFixture(t, hostCredFixture)
	if _, err := claudeHostPreflight(osClaudeLoginReads{}, home); err != nil {
		t.Fatalf("control: a signed-in host was refused: %v", err)
	}
	for name, mut := range map[string]func(string){
		"no pin": func(h string) { os.WriteFile(filepath.Join(h, ".claude.json"), []byte(`{}`), 0o600) },
		"half a pin": func(h string) {
			os.WriteFile(filepath.Join(h, ".claude.json"), []byte(`{"oauthAccount":{"accountUuid":"a"}}`), 0o600)
		},
		"no .claude.json": func(h string) { os.Remove(filepath.Join(h, ".claude.json")) },
		"credential is a directory": func(h string) {
			os.Remove(hostCredPath(h))
			os.Mkdir(hostCredPath(h), 0o700)
		},
		"no ~/.claude": func(h string) { os.RemoveAll(filepath.Join(h, ".claude")) },
	} {
		_, home := hostFilesFixture(t, hostCredFixture)
		mut(home)
		if _, err := claudeHostPreflight(osClaudeLoginReads{}, home); err == nil {
			t.Errorf("%s: preflight passed", name)
		} else if !strings.Contains(err.Error(), `login.claude = "sandbox"`) {
			t.Errorf("%s: the refusal does not name the alternative: %v", name, err)
		}
	}
	if os.Getuid() != 0 {
		_, home := hostFilesFixture(t, hostCredFixture)
		os.Chmod(filepath.Join(home, ".claude"), 0o500)
		defer os.Chmod(filepath.Join(home, ".claude"), 0o700)
		if _, err := claudeHostPreflight(osClaudeLoginReads{}, home); err == nil || !errors.Is(err, syscall.EACCES) &&
			!strings.Contains(err.Error(), "not a directory snug can write in") {
			t.Errorf("unwritable ~/.claude: %v", err)
		}
	}
	_, absent := hostFilesFixture(t, "")
	if _, err := claudeHostPreflight(osClaudeLoginReads{}, absent); err != nil {
		t.Errorf("an absent credential file was refused at preflight: %v", err)
	}
}

var _ loginbridge.HostFiles = (*claudeHostFiles)(nil)

// Red-team #662 round 2, N1: fileShape already carries its article, and the
// refusal read `is a a symlink`.
func TestHostModePreflightNamesTheFileShapeOnce(t *testing.T) {
	_, home := hostFilesFixture(t, hostCredFixture)
	os.Remove(hostCredPath(home))
	if err := os.Symlink("elsewhere.json", hostCredPath(home)); err != nil {
		t.Fatal(err)
	}
	_, err := claudeHostPreflight(osClaudeLoginReads{}, home)
	if err == nil {
		t.Fatal("a symlinked credential file passed preflight")
	}
	if strings.Contains(err.Error(), "a a ") || !strings.Contains(err.Error(), "is a symlink, not a regular file") {
		t.Errorf("refusal: %v", err)
	}
}

// Red-team #662 round 2, N2: the browser's page deadline counts on the host
// write giving up within loginbridge.HostWriteBudget, and the lock back-off
// is all of that wait.
func TestStorageLockBackoffFitsTheHostWriteBudget(t *testing.T) {
	var total time.Duration
	for try := range storageLockTries {
		total += storageLockDelay(try)
	}
	if total >= loginbridge.HostWriteBudget {
		t.Errorf("lock back-off %v, budget %v", total, loginbridge.HostWriteBudget)
	}
}
