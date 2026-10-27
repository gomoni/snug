package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// hostWriteChildEnv names the directory the helper child below works in; it
// is set only by TestHostWriteKilledAtAnyInstantNeverTearsTheFile.
const hostWriteChildEnv = "SNUG_TEST_HOSTWRITE_CHILD_DIR"

// TestHostWriteLoopChild is the child process of
// TestHostWriteKilledAtAnyInstantNeverTearsTheFile and does nothing in a
// normal run. It rewrites the host credential file and the run directory's
// file in a loop with the production code, printing a line per completed
// round, until it is killed.
func TestHostWriteLoopChild(t *testing.T) {
	dir := os.Getenv(hostWriteChildEnv)
	if dir == "" {
		t.Skip("helper process; run by TestHostWriteKilledAtAnyInstantNeverTearsTheFile")
	}
	h := hostFilesAt(t, filepath.Join(dir, "home"), filepath.Join(dir, "run"))
	for n := 1; ; n++ {
		r := hostLoginResult()
		r.AccessToken, r.RefreshToken = policy.Secret(fmt.Sprintf("AT-%d", n)), policy.Secret(fmt.Sprintf("RT-%d", n))
		snap := h.Snapshot()
		if err := h.RenewSandbox(context.Background(), r, time.Now(), true); err != nil {
			fmt.Printf("RENEW-ERR %v\n", err)
			os.Exit(3)
		}
		if err := h.WriteHost(context.Background(), snap, r, time.Now()); err != nil {
			fmt.Printf("WRITE-ERR %v\n", err)
			os.Exit(3)
		}
		fmt.Printf("ROUND %d\n", n)
	}
}

// hostFilesAt is hostFilesFixture over directories the caller made.
func hostFilesAt(t *testing.T, home, runDir string) *claudeHostFiles {
	t.Helper()
	root, err := os.OpenRoot(runDir)
	if err != nil {
		t.Fatal(err)
	}
	return &claudeHostFiles{home: home, reads: osClaudeLoginReads{}, sandbox: &runSubdir{path: runDir, root: root}, now: time.Now}
}

// pairOf returns the access and refresh token numbers a credential file
// holds ("0" for the fixture's OLD pair), failing the test if the file is not
// one whole JSON document or the two tokens are not from the same write.
func pairOf(t *testing.T, path string, wantForeign bool) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s unreadable after a kill: %v", path, err)
	}
	var f struct {
		Key   *string `json:"primaryApiKey"`
		OAuth struct {
			AT string `json:"accessToken"`
			RT string `json:"refreshToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s is torn after a kill (%v): %.200q", path, err, b)
	}
	if wantForeign && (f.Key == nil || *f.Key != "sk-x") {
		t.Errorf("%s lost the foreign key primaryApiKey", path)
	}
	at, rt := strings.TrimPrefix(f.OAuth.AT, "AT-"), strings.TrimPrefix(f.OAuth.RT, "RT-")
	if f.OAuth.AT == "OLD-AT" {
		at = "0"
	}
	if f.OAuth.RT == "OLD-RT" {
		rt = "0"
	}
	if f.OAuth.RT != "" && at != rt {
		t.Errorf("%s holds a mixed pair, access %q refresh %q", path, f.OAuth.AT, f.OAuth.RT)
	}
	return at
}

// TestHostWriteKilledAtAnyInstantNeverTearsTheFile fails if a SIGKILL of
// the process rewriting the host's credential file, delivered at a random
// instant of a loop of real WriteHost and RenewSandbox calls, ever leaves
// either file as anything but one whole JSON document of one write: the
// original or a complete new one, access and refresh token from the same
// round, the host file's foreign key kept. It also fails if the leaked
// storage lock a kill can leave wedges the next flow: the next WriteHost
// takes a lock older than the stale window over and succeeds.
//
// What SIGKILL does NOT guarantee, and this test only counts and logs: that
// no .storage-write.lock directory and no .credentials.json.tmp.* file is
// left behind. Nothing runs after a SIGKILL to remove them; the temp file
// holds the new pair at mode 0600. The positive control is that every child
// completed at least one round before the kill, so the kill landed in a
// loop that was working. It does not show a kill landed in every phase of a
// write, only that 120 random instants were all survived.
func TestHostWriteKilledAtAnyInstantNeverTearsTheFile(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns 120 processes")
	}
	rng := rand.New(rand.NewSource(1))
	leakedLocks, leakedTemps := 0, 0
	for i := 0; i < 120; i++ {
		dir := t.TempDir()
		home, runDir := filepath.Join(dir, "home"), filepath.Join(dir, "run")
		for _, d := range []string{filepath.Join(home, ".claude"), runDir} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		// Padding so each write takes real time to copy and sync.
		cred := strings.Replace(hostCredFixture, `"primaryApiKey":"sk-x"`,
			`"primaryApiKey":"sk-x","pad":"`+strings.Repeat("p", 40<<10)+`"`, 1)
		if err := os.WriteFile(hostCredPath(home), []byte(cred), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude.json"),
			[]byte(`{"oauthAccount":{"accountUuid":"acc-1","organizationUuid":"org-1","emailAddress":"a@example.com"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runDir, claudeCredentialsName),
			[]byte(`{"claudeAiOauth":{"accessToken":"OLD-AT"}}`), 0o600); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(os.Args[0], "-test.run=^TestHostWriteLoopChild$")
		cmd.Env = append(os.Environ(), hostWriteChildEnv+"="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		got := ""
		for !strings.Contains(got, "ROUND 1") {
			n, err := out.Read(buf)
			got += string(buf[:n])
			if err != nil {
				cmd.Wait()
				t.Fatalf("control: the child died before its first round (%v):\n%s", err, got)
			}
		}
		time.Sleep(time.Duration(rng.Intn(4000)) * time.Microsecond)
		cmd.Process.Signal(syscall.SIGKILL)
		cmd.Wait()

		if strings.Contains(got, "ERR") {
			t.Fatalf("the child's write failed on its own:\n%s", got)
		}
		pairOf(t, hostCredPath(home), true)
		pairOf(t, filepath.Join(runDir, claudeCredentialsName), false)
		entries, _ := os.ReadDir(filepath.Join(home, ".claude"))
		for _, e := range entries {
			switch {
			case e.Name() == ".storage-write.lock":
				leakedLocks++
			case strings.HasPrefix(e.Name(), ".credentials.json.tmp."):
				leakedTemps++
			case e.Name() != ".credentials.json":
				t.Errorf("unexpected entry in ~/.claude after a kill: %s", e.Name())
			}
		}

		// A leaked lock must not wedge the next flow.
		h := hostFilesAt(t, home, runDir)
		h.now = func() time.Time { return time.Now().Add(2 * storageLockStale) }
		if lock := filepath.Join(home, ".claude", ".storage-write.lock"); dirExists(lock) {
			old := time.Now().Add(-2 * storageLockStale)
			os.Chtimes(lock, old, old)
		}
		if err := h.WriteHost(context.Background(), h.Snapshot(), hostLoginResult(), time.Now()); err != nil {
			t.Fatalf("the next flow could not write after a kill left %v: %v", dirNamesOf(filepath.Join(home, ".claude")), err)
		}
		h.close()
	}
	t.Logf("120 SIGKILLs: ~/.claude/.storage-write.lock leaked in %d, a .tmp file leaked in %d",
		leakedLocks, leakedTemps)
	if leakedLocks+leakedTemps == 0 {
		t.Error("control: no kill left a lock or temp file, so no kill landed inside a write and the " +
			"survival above says nothing about writes")
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func dirNamesOf(p string) []string {
	var out []string
	es, _ := os.ReadDir(p)
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}
