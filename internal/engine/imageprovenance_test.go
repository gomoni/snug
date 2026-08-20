package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// TestTheGeneratedStorageConfIsSnugsOwn is issue #125's third instance of the
// argument #133 and #137 already made: a config file snug merely POINTS AT is
// someone else deciding on snug's behalf.
//
// CONTAINERS_STORAGE_CONF used to be caller-supplied, so on a host with a
// pinned engine bundle the storage configuration in play was the BUNDLE's,
// naming its own graphroot, runroot and mount_program. Under Tier C's derived
// mount view every path a config names has to still exist in that view, and
// snug cannot move a path it does not author.
func TestTheGeneratedStorageConfIsSnugsOwn(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec("/usr/bin/podman", []string{"PATH=/usr/bin"}, false, policy.NetPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	path, n := envValue(spec.Env, "CONTAINERS_STORAGE_CONF")
	if n != 1 {
		t.Fatalf("CONTAINERS_STORAGE_CONF appears %d times, want exactly 1: at zero the file the "+
			"engine reads is whatever the host or a pinned bundle ships, and at two getenv "+
			"returns the first, which is not necessarily snug's", n)
	}
	// It has to live in the half Tier C grafts READ-ONLY, like every other
	// file snug generates for the engine (issue #125, C2b).
	if got := filepath.Dir(path); got != e.confDir {
		t.Errorf("the generated storage.conf is in %s, want %s", got, e.confDir)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	// The two paths must be SNUG's, and must match what podman also gets on
	// its argv — libpod records the runroot in its database and refuses a
	// later run against the same store with a different one, so a disagreement
	// here is not cosmetic.
	for _, want := range []string{
		`graphroot = "` + e.store + `"`,
		`runroot = "` + e.runroot + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the generated storage.conf does not carry %s:\n%s", want, body)
		}
	}
}

// TestTheGeneratedStorageConfNamesAMountProgramOnlyWhenThereIsOne covers both
// arms of the one line in writeStorageConf that can be wrong in two
// directions: naming a path that does not exist breaks every run ("can't stat
// program"), and omitting it on a host that needs it breaks rootless overlay
// instead.
//
// The positive arm plants a file called fuse-overlayfs beside a stand-in
// engine binary; the negative arm uses a directory with no such file. Without
// the negative arm this passes on an implementation that hardcodes a path.
func TestTheGeneratedStorageConfNamesAMountProgramOnlyWhenThereIsOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		helper bool
	}{{"helper beside the engine", true}, {"no helper beside the engine", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			dir := t.TempDir()
			podman := filepath.Join(dir, "podman")
			if err := os.WriteFile(podman, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			helper := filepath.Join(dir, "fuse-overlayfs")
			if tc.helper {
				if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
			if err != nil {
				t.Fatal(err)
			}
			spec, err := e.Spec(podman, []string{"PATH=/usr/bin"}, false, policy.NetPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			path, _ := envValue(spec.Env, "CONTAINERS_STORAGE_CONF")
			_ = helper
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			named := strings.Contains(body, "mount_program = "+strconv.Quote(helper))
			switch {
			case tc.helper && !named:
				t.Errorf("a fuse-overlayfs sits beside the engine and the generated storage.conf "+
					"does not name it, so a host whose overlay needs it loses it:\n%s", body)
			case !tc.helper && strings.Contains(body, "mount_program"):
				t.Errorf("no fuse-overlayfs sits beside the engine and the generated storage.conf "+
					"names a mount_program anyway — podman refuses with \"can't stat program\" "+
					"before it does any work:\n%s", body)
			}
		})
	}
}

// TestEveryPathAGeneratedConfigNamesIsOneSnugOwns is the mechanical form of a
// finding that would otherwise be three names in someone's memory.
//
// Measured while probing Tier C's derived view: a config naming a writable path
// that ends up inside a READ-ONLY graft fails as `attempt to write a readonly
// database` — one message, naming none of the paths that caused it. Three of
// them (`static_dir`, `volume_path`, `tmp_dir`) were invisible until they broke.
// They came from a pinned bundle's containers.conf rather than from snug's own,
// and snug now authors every one of these files, so the current answer is that
// they are absent and podman derives them from graphroot. That is a fact about
// today's generated content, not a property of the format — which is exactly
// why it is checked rather than remembered.
//
// The check is DERIVED, not a list: it reads whatever the generators wrote and
// asks of every absolute path in it "is this somewhere snug owns?". A fourth
// path added later is caught the day it is added, without anyone remembering to
// extend a table — the same argument issue #206 made for /snug against
// snugsOwn's growing list.
func TestEveryPathAGeneratedConfigNamesIsOneSnugOwns(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec("/usr/bin/podman", []string{"PATH=/usr/bin"}, true,
		policy.NetPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	// Whatever snug pointed the engine at, read back from the environment
	// rather than rebuilt here: a generator that starts writing somewhere else
	// must be caught, not mirrored.
	var files []string
	for _, name := range []string{"CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF",
		"CONTAINERS_REGISTRIES_CONF", "REGISTRY_AUTH_FILE"} {
		if v, n := envValue(spec.Env, name); n == 1 && v != "" {
			files = append(files, v)
		}
	}
	if len(files) < 4 {
		t.Fatalf("only %d of the four generated files are named in the engine's environment; "+
			"this test would then be checking whichever ones happen to remain", len(files))
	}

	owned := func(p string) bool {
		for _, root := range []string{e.store, e.runroot, e.sockDir, e.confDir} {
			if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	// A quoted absolute path on a non-comment line. Deliberately crude: the
	// point is to notice a path, not to parse TOML, and a crude matcher that
	// over-reports is the safe direction for a check like this.
	quoted := regexp.MustCompile(`"(/[^"]*)"`)
	for _, f := range files {
		raw, readErr := os.ReadFile(f)
		if readErr != nil {
			t.Fatalf("%s: %v", f, readErr)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range quoted.FindAllStringSubmatch(line, -1) {
				p := m[1]
				// The engine binary's own directory is not snug's, and is the
				// subject of Tier C's open toolchain question rather than of
				// this test.
				if strings.Contains(line, "mount_program") || strings.Contains(line, "helper_binaries_dir") {
					continue
				}
				if !owned(p) {
					t.Errorf("%s names %q, which is not under the store, the runroot, sock/ or "+
						"conf/ — under Tier C's derived view a path snug does not own is a path "+
						"that may not exist there, and the failure names the database rather than "+
						"the path:\n  %s", filepath.Base(f), p, strings.TrimSpace(line))
				}
			}
		}
	}
}

// TestSpecReplacesACallerSuppliedStorageConf is setEnv's positive control for
// the variable this change took over.
//
// execve preserves duplicates in order and getenv returns the FIRST, so an
// APPENDED override is silently the loser: the caller's bundle storage.conf
// would still be the file in play while the environment read as though snug's
// had won. That is CLAUDE.md's "the flag is present and the feature is not".
func TestSpecReplacesACallerSuppliedStorageConf(t *testing.T) {
	env := specEnv(t, []string{"PATH=/usr/bin", "CONTAINERS_STORAGE_CONF=/host/bundle/storage.conf"})
	seen := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "CONTAINERS_STORAGE_CONF=") {
			seen++
			if strings.Contains(kv, "/host/bundle/storage.conf") {
				t.Errorf("the caller's storage.conf survived as %q", kv)
			}
		}
	}
	if seen != 1 {
		t.Errorf("CONTAINERS_STORAGE_CONF appears %d times; a duplicate means the caller's entry "+
			"is the one getenv returns", seen)
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
