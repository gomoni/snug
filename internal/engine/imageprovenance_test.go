package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// specEnv runs Spec against a throwaway Engine and returns the environment the
// engine will be started with. The sibling of engine_test.go's specConf, and
// deliberately the same shape: these assertions are about the ENVIRONMENT
// rather than about the generated containers.conf.
func specEnv(t *testing.T, baseEnv []string) []string {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec("/usr/bin/podman", baseEnv, false, policy.NetPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	return spec.Env
}

// envValue returns the value of name in a KEY=VALUE environment, and how many
// times it appears. The COUNT is the point: a duplicate is not a cosmetic
// problem, it is the variable silently not taking effect, because glibc's
// getenv returns the first match.
func envValue(env []string, name string) (string, int) {
	value, n := "", 0
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, name+"="); ok {
			if n == 0 {
				value = rest
			}
			n++
		}
	}
	return value, n
}

// TestSpecAuthorsEveryFileTheEngineReadsFromAHome is issue #137's and #142's
// regression, asserted as a SET rather than one variable at a time: every
// channel that reaches the engine through a home directory must be pointed at
// a file snug generated under this run's own directory.
//
// The set, not the site, because that is what the two issues have in common —
// #132 closed containers.conf and left registries.conf, policy.json and the
// registry credentials open, each of which had to be measured separately to
// be noticed at all. A new file podman starts reading from $HOME will not be
// caught by this test, but a REGRESSION of any of these will.
func TestSpecAuthorsEveryFileTheEngineReadsFromAHome(t *testing.T) {
	env := specEnv(t, []string{"PATH=/usr/bin"})

	home, n := envValue(env, "HOME")
	if n != 1 {
		t.Fatalf("HOME appears %d times in the engine's environment, want exactly 1", n)
	}
	if hostHome, err := os.UserHomeDir(); err == nil && home == hostHome {
		t.Fatalf("the engine's HOME is the host user's own (%s): every file podman reads out "+
			"of a home directory is then host-authored (issues #137, #142)", home)
	}

	policyPath := filepath.Join(home, ".config", "containers", "policy.json")
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("no generated policy.json at %s: podman refuses to pull without one, so the "+
			"answer would come from whatever the host has, or the pull would fail (issue #137): %v",
			policyPath, err)
	}

	for _, name := range []string{"CONTAINERS_REGISTRIES_CONF", "REGISTRY_AUTH_FILE", "CONTAINERS_CONF"} {
		path, n := envValue(env, name)
		if n != 1 {
			t.Errorf("%s appears %d times in the engine's environment, want exactly 1", name, n)
			continue
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s=%s does not exist: %v", name, path, err)
		}
	}
}

// TestSpecReplacesACallerSuppliedHome is setEnv's positive control, and it
// guards the failure mode CLAUDE.md names twice: the flag is present and the
// feature is not there.
//
// execve preserves duplicate entries in order and getenv returns the FIRST,
// so appending an override rather than replacing one leaves the caller's
// value live while the environment reads as though snug's had won. The caller
// (internal/cli's container.go) no longer passes HOME at all, which is why
// this test passes one deliberately: the guard has to survive a caller that
// starts doing it again.
func TestSpecReplacesACallerSuppliedHome(t *testing.T) {
	env := specEnv(t, []string{"PATH=/usr/bin", "HOME=/host/home", "REGISTRY_AUTH_FILE=/host/auth.json"})

	if home, n := envValue(env, "HOME"); n != 1 || home == "/host/home" {
		t.Errorf("HOME = %q (%d occurrences), want exactly one entry that is not the caller's", home, n)
	}
	if auth, n := envValue(env, "REGISTRY_AUTH_FILE"); n != 1 || auth == "/host/auth.json" {
		t.Errorf("REGISTRY_AUTH_FILE = %q (%d occurrences), want exactly one entry that is not "+
			"the caller's", auth, n)
	}
}

// TestTheGeneratedAuthFileCarriesNoCredential asserts the empty-by-design
// decision of issue #142 rather than the file's bytes: whatever snug writes
// there, it must name no registry, because the point is that the engine
// authenticates as nobody.
func TestTheGeneratedAuthFileCarriesNoCredential(t *testing.T) {
	env := specEnv(t, []string{"PATH=/usr/bin"})
	path, _ := envValue(env, "REGISTRY_AUTH_FILE")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Auths map[string]any `json:"auths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the generated auth file is not JSON (%v); containers/image would fail to read "+
			"it and fall back to the host's own: %s", err, raw)
	}
	if len(doc.Auths) != 0 {
		t.Errorf("the generated auth file names %d registry/registries, want none: %s",
			len(doc.Auths), raw)
	}
}

// TestTheGeneratedRegistriesConfRedirectsNothing is the other half of #137:
// snug taking over registries.conf is only worth anything if snug's own file
// does not do the thing the host's file was able to do.
//
// The keys named here are the ones that STEER a pull — a mirror, a location
// rewrite, an insecure (plaintext) registry, a prefix match — as opposed to
// the single search key snug does write. Asserted by name, so a future edit
// that adds one has to argue with a test rather than with a comment.
func TestTheGeneratedRegistriesConfRedirectsNothing(t *testing.T) {
	env := specEnv(t, []string{"PATH=/usr/bin"})
	path, _ := envValue(env, "CONTAINERS_REGISTRIES_CONF")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, key := range []string{"[[registry", "mirror", "insecure", "location", "prefix", "blocked"} {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // the comment explains the absence; it is not the config
			}
			if strings.Contains(line, key) {
				t.Errorf("the generated registries.conf names %q (%q): snug would then be "+
					"steering a pull, which is the thing issue #137 took away from the host's file",
					key, line)
			}
		}
	}
	if !strings.Contains(body, `unqualified-search-registries = ["docker.io"]`) {
		t.Errorf("the generated registries.conf does not name docker.io as the single search "+
			"registry, so a short image name resolves somewhere this test cannot predict:\n%s", body)
	}
}

// TestTheGeneratedSignaturePolicyIsPodmansOwnDefault pins what SignaturePolicyJSON
// MEANS, not how it is spelled.
//
// It is the file with no environment variable, so it is the one whose content
// is the whole mechanism, and its value is a deliberate NON-hardening choice
// (see its doc comment): accept anything, exactly as a stock podman does. A
// patch that quietly made it stricter would break every unsigned image at
// runtime, and one that made it emptier would make podman refuse to pull at
// all — neither shows up in a golden argv diff, so it is asserted here.
func TestTheGeneratedSignaturePolicyIsPodmansOwnDefault(t *testing.T) {
	var doc struct {
		Default []struct {
			Type string `json:"type"`
		} `json:"default"`
	}
	if err := json.Unmarshal([]byte(SignaturePolicyJSON), &doc); err != nil {
		t.Fatalf("SignaturePolicyJSON is not valid JSON (%v); podman would refuse every pull "+
			"with a parse error: %s", err, SignaturePolicyJSON)
	}
	if len(doc.Default) != 1 || doc.Default[0].Type != "insecureAcceptAnything" {
		t.Fatalf("SignaturePolicyJSON's default requirement is %+v, want exactly one "+
			"insecureAcceptAnything", doc.Default)
	}
}

// ── issue #125, Tier C piece C2-path ─────────────────────────────────────────

// TestSpecPinsTheEnginesPATH is the assertion that stops the pin being removed
// with the suite green.
//
// The engine used to be handed "PATH=" + os.Getenv("PATH") — the HOST's. On the
// development host that value leads with /home/<u>/bin and contains
// .local/bin, .cargo/bin, go/bin and an EMPTY element, which means the engine's
// cwd. Every /home/<u>/* element is inside {home}, which @home mounts as a
// WRITABLE TMPFS.
//
// Under Tier B those directories do not exist in the engine's private copy of
// the host tree in any payload-writable form, so the exposure is latent. Under
// Tier C's DERIVED view they become the payload's own tmpfs, at the head of the
// PATH of a process running as root-in-U with CAP_SYS_ADMIN and the full
// delegated subuid range — a shadow slot in front of crun. That is why this
// landed BEFORE the derived view rather than with it: Tier C creates the
// escape, it does not fix it.
//
// Every directory below is read-only in the sandbox's view under @sys's /usr
// bind (/bin and /sbin are @sys's own symlinks into /usr), which is what makes
// C2-view's sweep — for every element of the engine's PATH,
// EngineView().IsShadowSlot(elem) must be false — pass rather than be a comment.
func TestSpecPinsTheEnginesPATH(t *testing.T) {
	env := specEnv(t, nil)

	path, n := envValue(env, "PATH")
	if n != 1 {
		t.Fatalf("PATH appears %d times in the engine's environment, want exactly 1", n)
	}
	if want := "/usr/bin:/usr/sbin:/bin:/sbin"; path != want {
		t.Fatalf("the engine's PATH is %q, want %q — anything else is a directory snug did "+
			"not choose in front of the binaries podman executes", path, want)
	}
	// The empty element is called out separately because it is the one a reader
	// skims past: "" means the engine's cwd, which is not a fixed directory at
	// all, and it appeared in the host value this replaced.
	for _, elem := range strings.Split(path, ":") {
		if elem == "" {
			t.Error("the engine's PATH contains an EMPTY element, which means its cwd — not a " +
				"directory snug chose, and not one any sweep can check")
		}
		if !filepath.IsAbs(elem) {
			t.Errorf("the engine's PATH element %q is not absolute", elem)
		}
	}
}

// TestSpecReplacesACallerSuppliedPATH is setEnv's positive control for the pin,
// and it is the same shape as TestSpecReplacesACallerSuppliedHome: execve keeps
// duplicates in order and getenv returns the FIRST, so appending rather than
// replacing would leave the caller's PATH live while the environment read as
// though snug's had won — the flag is present and the feature is not there.
//
// internal/cli's container.go no longer passes a PATH at all. This test passes
// one deliberately, and passes the HOST's own, because the guard has to survive
// a caller that starts doing it again.
func TestSpecReplacesACallerSuppliedPATH(t *testing.T) {
	hostPATH := os.Getenv("PATH")
	if hostPATH == "" {
		t.Skip("no PATH in this test process's environment, so there is nothing to try to smuggle")
	}
	env := specEnv(t, []string{"PATH=" + hostPATH})

	path, n := envValue(env, "PATH")
	if n != 1 {
		t.Fatalf("PATH appears %d times in the engine's environment, want exactly 1: a duplicate "+
			"means getenv returns the caller's and snug's is decoration", n)
	}
	if path == hostPATH {
		t.Fatalf("a caller-supplied PATH won: the engine would resolve crun, conmon and "+
			"newuidmap through %q, which contains directories the payload can write", path)
	}
}
