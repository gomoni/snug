package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// specEnv runs Spec against a throwaway Engine and returns the environment the
// engine will be started with. The sibling of engine_test.go's specConf, and
// deliberately the same shape: these assertions are about the ENVIRONMENT
// rather than about the generated containers.conf.
// specEnv returns the engine's environment AND the engine, because since Tier C
// the two are needed together: every path in that environment is a GUEST path
// and hostSideOf needs the engine to say where snug actually wrote the file.
func specEnv(t *testing.T, baseEnv []string) ([]string, *Engine) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman", baseEnv, false, "", "", noSignaturePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	return spec.Env, e
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
	env, specEng := specEnv(t, []string{"PATH=/usr/bin"})

	home, n := envValue(env, "HOME")
	if n != 1 {
		t.Fatalf("HOME appears %d times in the engine's environment, want exactly 1", n)
	}
	if hostHome, err := os.UserHomeDir(); err == nil && home == hostHome {
		t.Fatalf("the engine's HOME is the host user's own (%s): every file podman reads out "+
			"of a home directory is then host-authored (issues #137, #142)", home)
	}

	policyPath := filepath.Join(hostSideOf(t, specEng, home), ".config", "containers", "policy.json")
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
		if _, err := os.Stat(hostSideOf(t, specEng, path)); err != nil {
			t.Errorf("%s=%s does not exist on the host side: %v", name, path, err)
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
	env, _ := specEnv(t, []string{"PATH=/usr/bin", "HOME=/host/home", "REGISTRY_AUTH_FILE=/host/auth.json"})

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
	env, specEng := specEnv(t, []string{"PATH=/usr/bin"})
	path, _ := envValue(env, "REGISTRY_AUTH_FILE")
	raw, err := os.ReadFile(hostSideOf(t, specEng, path))
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
	env, specEng := specEnv(t, []string{"PATH=/usr/bin"})
	path, _ := envValue(env, "CONTAINERS_REGISTRIES_CONF")
	raw, err := os.ReadFile(hostSideOf(t, specEng, path))
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
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman", []string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t))
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
	// file snug generates for the engine (issue #125, C2b) — and the engine is
	// told about it under the GUEST name that graft gives it, which is what
	// this now checks. hostSideOf asserts the first half and returns where the
	// file really is.
	if got := filepath.Dir(path); got != policy.EngineConfGuest {
		t.Errorf("the engine is told storage.conf is in %s, want %s", got, policy.EngineConfGuest)
	}
	raw, err := os.ReadFile(hostSideOf(t, e, path))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	// The two paths must be the ones the ENGINE can actually reach, and must
	// match what podman also gets on its argv — libpod records the runroot in
	// its database and refuses a later run against the same store with a
	// different one, so a disagreement here is not cosmetic.
	//
	// Since Tier C both are GUEST paths (issue #125): the engine's view is
	// derived from the sandbox's, so the host path this file used to carry
	// names nothing there. Note what that buys beyond correctness — the value
	// written here is now snug's own constant plus a fixed suffix, so no
	// property of the host's own directory layout reaches the config file at
	// all.
	for _, want := range []string{
		`graphroot = "` + policy.EngineStoreGuest + `"`,
		`runroot = "` + policy.EngineRunrootGuest + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the generated storage.conf does not carry %s:\n%s", want, body)
		}
	}
}

// TestTheGeneratedStorageConfNeverNamesAMountProgram is issue #390, and it
// replaces a test that asserted mount_program was written WHEN a helper sat
// beside the engine. That property is gone because the key is gone.
//
// Why the key went, and it is not "it was inert". Inertness was the old
// comment's argument — podman discards every [storage.options*] key when
// --root is on the argv, measured on 5.8.4 and 6.0.2, and Spec always passes
// --root. That answers whether podman HONOURS the key. It says nothing about
// whether snug WRITES it, and snug did: helperBesideEngine derives from
// filepath.Dir(podman) and e.guestPath maps that through EngineGuestPath's
// bind arm, which has no Access test. MEASURED with fuse-overlayfs beside an
// engine inside an @cwd-rw target: mount_program = "/proj/bin/fuse-overlayfs",
// a payload-writable path in the engine's storage configuration.
//
// So this asserts the SET rather than the site: no line of the generated
// storage.conf names a mount_program at all, whatever sits beside the engine.
// The three arms are the old test's three, kept because they are the inputs
// that used to PRODUCE the key — an executable helper, no helper, and a
// non-executable file of the right name. The first is the one that matters:
// the input that wrote a payload-writable path must now write nothing.
func TestTheGeneratedStorageConfNeverNamesAMountProgram(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode // 0 = do not create the file at all
	}{
		{"executable helper beside the engine", 0o755},
		{"no helper beside the engine", 0},
		{"non-executable file of the right name", 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			dir := t.TempDir()
			podman := filepath.Join(dir, "podman")
			if err := os.WriteFile(podman, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.mode != 0 {
				if err := os.WriteFile(filepath.Join(dir, "fuse-overlayfs"), []byte("#!/bin/sh\n"), tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
			if err != nil {
				t.Fatal(err)
			}
			spec, err := e.Spec(specPolicy(t, e, dir, policy.NetPolicy{}), podman, []string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t))
			if err != nil {
				t.Fatal(err)
			}
			conf, n := envValue(spec.Env, "CONTAINERS_STORAGE_CONF")
			if n != 1 || conf == "" {
				t.Fatalf("CONTAINERS_STORAGE_CONF appears %d times with value %q; this test would "+
					"then be reading a file nobody was pointed at", n, conf)
			}
			raw, err := os.ReadFile(hostSideOf(t, e, conf))
			if err != nil {
				t.Fatal(err)
			}
			// POSITIVE CONTROL: the file really is the generated storage.conf
			// and really has content. Without this, an empty or unwritten file
			// passes the assertion below for the wrong reason.
			if !strings.Contains(string(raw), "runroot") {
				t.Fatalf("the generated storage.conf does not mention runroot, so it is not the "+
					"file this test means to read:\n%s", raw)
			}
			if strings.Contains(string(raw), "mount_program") {
				t.Errorf("storage.conf names a mount_program (issue #390: it is derived from "+
					"filepath.Dir(podman) through an Access-blind mapping, so it can name a "+
					"payload-writable path):\n%s", raw)
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
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	const enginePath = "/usr/bin/podman"
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), enginePath, []string{"PATH=/usr/bin"}, true, "crun", "/usr/bin/crun", noSignaturePolicy(t))
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

	// The one path outside snug's own directories that a generated config may
	// name, derived the same way writeStorageConf derives it.
	// Stated here rather than obtained from helperBesideEngine, and the
	// difference is not style. Deriving the exemption from the function under
	// test moves BOTH when that function changes: a mutation pointing
	// mount_program at /usr/bin/env passed, because the test then exempted
	// /usr/bin/env too. An exemption has to be an independent restatement of
	// where the helper is allowed to be, or it exempts whatever the code did.
	// TWO exact values, because there are exactly two places a helper beside
	// the engine can END UP once the engine's view is derived: beside a
	// distribution engine under /usr (which @sys exposes, so it keeps its own
	// path), or beside a pinned bundle (which reaches the engine only through
	// the toolchain graft). Stated as exact strings rather than derived from
	// the code under test, for the reason the paragraph above gives.
	helperPaths := map[string]bool{
		"/usr/bin/fuse-overlayfs":                                    true,
		filepath.Join(policy.EngineToolchainGuest, "fuse-overlayfs"): true,
		// The OCI runtime [engine.runtimes] names (preflight P10), in the same
		// class and for the same reason as fuse-overlayfs above: it is an OS
		// program under /usr, which @sys exposes, so it keeps its own path
		// inside the engine's derived view. A container-capable run has to
		// grant /usr regardless — podman, conmon and netavark all live there —
		// so a run that could not see this path could not start an engine at
		// all.
		//
		// EXACT, and this test chose the value it passes to Spec above, so the
		// exemption is an independent restatement rather than a mirror of what
		// the code did. The residual it accepts, stated: a crun somewhere /usr
		// does not cover is pinned to a path the engine's view may not have,
		// and podman then says `requested OCI runtime crun is not available` —
		// which names the runtime, unlike the NoCgroups 500 that P10 exists to
		// prevent.
		"/usr/bin/crun": true,
	}
	// The directories containers.conf names for podman's own helper lookup.
	// Exempt as EXACT values, so a fourth entry — or any other path on such a
	// line — is caught rather than waved through by a prefix.
	helperDirs := map[string]bool{
		"/usr/libexec/podman": true,
		"/usr/lib/podman":     true,
		"/usr/bin":            true,
	}

	// The GUEST roots since Tier C, which is what turns this check from "a
	// path snug owns" into the stronger "a path the ENGINE can see" — a
	// generated config naming a host path now fails here rather than at the
	// moment podman opens it (issue #125).
	owned := func(p string) bool {
		for _, root := range []string{policy.EngineStoreGuest, policy.EngineRunrootGuest,
			policy.EngineSockGuest, policy.EngineConfGuest, policy.EngineToolchainGuest} {
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
		raw, readErr := os.ReadFile(hostSideOf(t, e, f))
		if readErr != nil {
			t.Fatalf("%s: %v", f, readErr)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range quoted.FindAllStringSubmatch(line, -1) {
				p := m[1]
				// ONE exemption, and it is a VALUE rather than a line match.
				//
				// It used to skip any line mentioning mount_program or
				// helper_binaries_dir, which meant a second path smuggled onto
				// such a line was skipped with it — and mount_program is the one
				// non-snug path this file introduces, so the exemption covered
				// exactly the thing most worth checking. Now the helper's own
				// derived path is allowed and nothing else is: a mount_program
				// pointing anywhere but beside the resolved engine fails here.
				//
				// helper_binaries_dir's three entries are exempt BY VALUE too,
				// not by a /usr/ prefix. A prefix would let a mount_program at
				// /usr/bin/anything through, and mount_program is precisely the
				// key this check exists for — measured: with the prefix form, a
				// mutation pointing mount_program at an existing /usr binary
				// passed.
				if helperPaths[p] || helperDirs[p] {
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

// TestARelativeEngineRefusesRatherThanWritingARelativeMountProgram is the other
// half of helperBesideEngine's absoluteness check.
//
// preflightPodmanBinary trusts $SNUG_PODMAN outright — os.Stat and !IsDir — so
// a relative value reaches Spec. filepath.Dir is then ".", the candidate is the
// bare name, it is stat'd against SNUG's working directory, and it would be
// written verbatim into storage.conf as a RELATIVE mount_program that the
// ENGINE resolves against its OWN. One string, two processes, two meanings.
func TestARelativeEngineRefusesRatherThanWritingARelativeMountProgram(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fuse-overlayfs"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "./podman", []string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t))
	if err == nil {
		t.Fatal("Spec accepted a relative engine path")
	}
	// THE REFUSAL MOVED, and the property did not — issue #390. It used to come
	// from helperBesideEngine's own absoluteness check, reached because
	// writeStorageConf derived mount_program from filepath.Dir(podman). That
	// derivation is gone, so the message no longer says "absolute"; the refusal
	// now comes from guestPath on the engine binary itself, which cannot place
	// a relative path in the engine's view either.
	//
	// Asserting the SURVIVING refusal rather than deleting the test, because
	// what mattered was never the wording: a relative $SNUG_PODMAN must not
	// reach a generated file, and preflightPodmanBinary trusts the variable
	// outright (os.Stat and a shim check, no absoluteness test), so Spec is
	// where it is caught. If a later change makes Spec accept one, this fails.
	if !strings.Contains(err.Error(), "engine binary") {
		t.Errorf("the refusal does not name the engine binary, so it may not be the check that "+
			"catches a relative path: %v", err)
	}
}

// TestAnUnquotablePathIsRefusedRatherThanSubstituted is invariant 5 applied to
// the one function that used to break it.
//
// tomlString's doc said it "REFUSES rather than escapes" while doing neither:
// it returned `"snug-refused-unquotable-value"` — a perfectly valid TOML
// string — and writeStorageConf ignored the error return it already had. The
// values are reachable: e.runroot comes from os.TempDir(), e.store from
// $XDG_DATA_HOME. Measured before the fix, with a quote in $TMPDIR: the argv
// carried the real runroot while storage.conf carried the placeholder, with no
// error anywhere.
func TestAnUnquotablePathIsRefusedRatherThanSubstituted(t *testing.T) {
	// A quote is the hazard that matters: it closes the string early and the
	// rest of the line is read as TOML.
	odd := filepath.Join(t.TempDir(), `a"b`)
	if err := os.MkdirAll(odd, 0o700); err != nil {
		t.Skipf("this filesystem will not hold a directory with a quote in its name: %v", err)
	}

	// HALF ONE, and it is the property Tier C ADDED rather than one it kept:
	// an unquotable HOST path can no longer reach storage.conf at all, because
	// the file names the GUEST path — snug's own constant — and the host's
	// directory layout stops being an input to the file's contents (issue
	// #125). The old refusal for this case is gone because the case is gone.
	t.Setenv("XDG_DATA_HOME", odd)
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
		[]string{"PATH=/usr/bin"}, false, "", "", noSignaturePolicy(t))
	if err != nil {
		t.Fatalf("Spec refused a store under a directory with a quote in its name, but the "+
			"quote can no longer reach the generated config — storage.conf names %s: %v",
			policy.EngineStoreGuest, err)
	}
	path, _ := envValue(spec.Env, "CONTAINERS_STORAGE_CONF")
	raw, err := os.ReadFile(hostSideOf(t, e, path))
	if err != nil {
		t.Fatal(err)
	}
	if body := string(raw); strings.Contains(body, `a"b`) {
		t.Errorf("the host store path's quote reached storage.conf:\n%s", body)
	}

	// HALF TWO. Its premise is now FALSE in the stronger direction, and that is
	// worth stating rather than quietly deleting the half.
	//
	// It used to read: "mount_program is the one value that CAN still carry a
	// host-chosen string, so a quote in the helper's own filename still reaches
	// tomlString and must be refused rather than substituted." Issue #390
	// deleted mount_program, and with it the last host-derived path in this
	// file. Every value writeStorageConf now renders is a GUEST CONSTANT —
	// policy.EngineStoreGuest and policy.EngineRunrootGuest, via guestPath — so
	// no host string reaches tomlString from here at all.
	//
	// Two assertions replace it, because "the hazard is unreachable" and "the
	// guard still works" are different claims and deleting the half would have
	// asserted neither.
	//
	// 2a: the hazard really is unreachable — a quote in the HELPER's own
	// directory name no longer reaches the generated file, where before it
	// produced a refusal naming mount_program.
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "podman"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oddHelperDir := filepath.Join(bundle, `q"d`)
	if err := os.MkdirAll(oddHelperDir, 0o755); err != nil {
		t.Skipf("this filesystem will not hold a directory with a quote in its name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oddHelperDir, "fuse-overlayfs"),
		[]byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oddHelperDir, "podman"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e2, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj2"))
	if err != nil {
		t.Fatal(err)
	}
	pol := specPolicy(t, e2, bundle, policy.NetPolicy{})
	confPath, err := e2.writeStorageConf(pol, filepath.Join(oddHelperDir, "podman"))
	if err != nil {
		t.Fatalf("writeStorageConf refused an engine whose own directory name holds a quote, but "+
			"no host path reaches this file any more: %v", err)
	}
	raw2, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), `q"d`) {
		t.Errorf("the engine directory's quote reached storage.conf:\n%s", raw2)
	}

	// 2b: the guard itself still refuses, tested directly. tomlString remains
	// reachable with host-chosen values elsewhere (writeContainersConf), so the
	// check must not be allowed to rot just because THIS file stopped feeding
	// it one. Without this, 2a alone would pass on a tomlString that silently
	// substituted.
	if _, err := tomlString(`a"b`); err == nil {
		t.Error("tomlString accepted a value containing a quote; a config line would carry a " +
			"placeholder, or close the string early and let the rest be read as TOML")
	}
	if _, err := tomlString("/plain/path"); err != nil {
		t.Errorf("tomlString refused an ordinary path, so the refusal above proves nothing: %v", err)
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
	env, _ := specEnv(t, []string{"PATH=/usr/bin", "CONTAINERS_STORAGE_CONF=/host/bundle/storage.conf"})
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

// TestTheGeneratedSignaturePolicyIsTheHostsOwn pins what Spec writes for the
// engine: not a value this package holds, but a projection of the host's own
// policy.json (signaturepolicy.go).
//
// It asserts through Spec rather than through the projection's own unit tests
// because the WIRING is the half those cannot see: a projection nothing calls
// leaves the engine reading whatever was written last.
func TestTheGeneratedSignaturePolicyIsTheHostsOwn(t *testing.T) {
	const hostPolicy = `{"default":[{"type":"reject"}],
	    "transports":{"docker":{"registry.example.internal":[{"type":"insecureAcceptAnything"}]}}}`

	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	pol := specPolicy(t, e, "", policy.NetPolicy{})
	sig, err := ProjectHostSignaturePolicy(hostWithPolicy(t, hostPolicy))
	if err != nil {
		t.Fatalf("a host policy snug should project was refused: %v", err)
	}

	spec, err := e.Spec(pol, "/usr/bin/podman", nil, false, "", "", sig)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := envValue(spec.Env, "HOME")
	body, err := os.ReadFile(filepath.Join(hostSideOf(t, e, home),
		".config", "containers", "policy.json"))
	if err != nil {
		t.Fatalf("no generated policy.json: podman refuses to pull without one (issue #137): %v",
			err)
	}

	want := []string{"default: reject", "docker/registry.example.internal: insecureAcceptAnything"}
	if got := requirementTypes(t, body); strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("the engine's policy.json requires\n  %v\nand this host's requires\n  %v\n"+
			"— the engine enforcing less than the host configured is the silent downgrade "+
			"invariant 5 forbids:\n%s", got, want, body)
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
	env, _ := specEnv(t, nil)

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
	env, _ := specEnv(t, []string{"PATH=" + hostPATH})

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
