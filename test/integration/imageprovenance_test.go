//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// This file is issues #137 and #142: who decides which bytes become the image
// a container runs, and as whom the engine authenticates while fetching them.
//
// Every test here drives the REAL environment engine.Spec builds — not a
// reconstruction of it — against the REAL pinned podman binary, and asserts an
// EFFECT (what podman does) rather than the content of a generated file. That
// is the shape issue #135 established for the containers.conf work and the
// reason it survived a podman that changed how it reads a key.
//
// Nothing here needs a network or an image: every assertion is decided before
// podman contacts a registry, which was measured rather than assumed —
// a missing policy.json and an unparsable registries.conf both surface before
// the first DNS lookup.

// engineSpecEnvWithSignaturePolicy returns the environment snug's engine is
// started with, built by calling engine.Spec itself, with the HOST's signature
// policy chosen by the caller. hostPolicy is planted under a temporary home and
// projected exactly as a run projects it, so what podman ends up reading came
// out of snug's real projection rather than out of a fixture.
//
// Calling the real thing matters more here than convenience: the whole subject
// of these tests is which variables that function sets, so a test that
// assembled its own environment would be grading a copy.
//
// THERE IS DELIBERATELY NO ENV-ONLY WRAPPER. One existed — it called this and
// threw the Engine away — and BOTH of its callers were silently broken by that:
// a probe that runs podman on the HOST has to pass --root and --runroot itself
// (storeArgs), because the generated storage.conf names the GUEST paths and a
// real run supplies the host ones on the argv. With no Engine there is nothing
// to build those from, so both died on
//
//	creating runtime static files directory "/snug/engine/store/libpod":
//	mkdir /snug: permission denied
//
// inside their own CONTROL, and skipped saying "there is nothing to regress" —
// issue #137's registries.conf regression and issue #142's host-credential
// regression, both inert behind a green line (issue #425). Returning the Engine
// unconditionally is what makes forgetting it impossible rather than merely
// discouraged.
func engineSpecEnvWithSignaturePolicy(t *testing.T, hostPolicy string) ([]string, *engine.Engine) {
	t.Helper()
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	// Registered AFTER the TempDir call, so it runs BEFORE that directory's own
	// RemoveAll (cleanups are LIFO) and leaves it nothing to trip over. See
	// removeContainerStore for why RemoveAll alone cannot do this.
	t.Cleanup(func() { removeContainerStore(t, data) })

	e, err := engine.New(&policy.Policy{Profiles: []policy.ProfileName{"@podman-socket"}, Target: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{
		Podman: policy.PodmanSocket,
		Mounts: map[string]policy.Mount{
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind,
				Access: policy.AccessRO, From: []string{"@sys"}},
		},
	}
	// NO pol.EngineToolchain call (issue #393 §6): with a system podman there
	// is no separate toolchain root to record — /usr/bin/podman passes G4's
	// first disjunct (@sys already binds /usr, right above), and
	// EngineToolchain("") errors by design rather than treating an empty root
	// as a clear. A harness that synthesised one would be grafting a tree
	// nobody named.
	if err := e.GraftInto(policy.OSEnviron{}, pol); err != nil {
		t.Fatal(err)
	}
	sig, err := engine.ProjectHostSignaturePolicy(plantHostSignaturePolicy(t, hostPolicy), "")
	if err != nil {
		t.Fatalf("projecting the planted host signature policy: %v", err)
	}
	// "crun" is the only value Spec is ever handed alongside cgroupsDisabled
	// = true: P10 (preflightOCIRuntime) returns exactly that pair, and where
	// crun is absent it REFUSES rather than reaching Spec at all. Passing a
	// resolved-from-PATH runtime here would let this fixture construct a
	// combination the production path cannot produce.
	spec, err := e.Spec(pol, hostEngine(t), []string{"PATH=/usr/bin:/bin"}, true, "crun", "/usr/bin/crun", sig)
	if err != nil {
		t.Fatal(err)
	}
	// Spec created this run's directory; nothing was started, so removing it
	// is the whole teardown.
	t.Cleanup(func() { _ = os.RemoveAll(e.ConfDir()) })

	// BACK TO HOST PATHS, and the translation is the point rather than a
	// workaround. Since Tier C every path Spec writes is a GUEST path — what
	// the engine sees inside its derived view — and these probes run podman
	// ON THE HOST, where /snug/engine/conf exists in no namespace at all. The
	// subject of these tests is which variables Spec sets and what the SYSTEM
	// podman does with them, so the variables are kept exactly as Spec wrote
	// them and only the four roots are mapped back. The toolchain root is not
	// among them any more (see above), so "" is passed and that substitution
	// is a no-op.
	// NO CONTAINERS_STORAGE_CONF is appended here. Spec has SET it since issue
	// #125 — at the storage.conf snug generated in this run's own config
	// directory — and a second entry appended after it named a file the
	// pinned bundle this suite used to run against did not ship, so every
	// probe in this file died with "Failed to obtain podman configuration"
	// before reaching what it was testing. MEASURED: removing it is what lets
	// the pull actually run.
	return hostSideEnv(t, e, "", spec.Env), e
}

// envLookup returns the value of name in a KEY=VALUE environment, failing the
// test when it is absent — an absent variable is the regression these tests
// exist for, so it must never read as an empty string.
func envLookup(t *testing.T, env []string, name string) string {
	t.Helper()
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, name+"="); ok {
			return rest
		}
	}
	t.Fatalf("the engine's environment carries no %s at all", name)
	return ""
}

// envWithout returns env with name removed. It builds the CONTROL for every
// test in this file: the same podman, the same planted host file, and snug's
// variable taken away. Without it "podman did not read the host's file" would
// pass on a plant podman never looks at.
func envWithout(env []string, name string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// envWith returns env with name set to value, replacing any existing entry —
// the same first-wins hazard engine.setEnv guards, applied to the probes.
func envWith(env []string, name, value string) []string {
	return append(envWithout(env, name), name+"="+value)
}

// runPodman runs the pinned bundle with exactly env (no host environment) and
// returns its combined output. A failure is expected in most of these probes —
// the interesting thing is always WHICH failure — so the error is folded into
// the output rather than reported.
func runPodman(t *testing.T, env []string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, hostEngine(t), args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\n" + err.Error()
	}
	return string(out)
}

// hostHomeWithDockerCredential plants a home directory holding the shape a
// developer machine really has: ~/.docker/config.json with a registry
// credential in it. Returns the home and the username that must not surface.
//
// It is the LAST entry in containers/image's search order, which is exactly
// why it was live: $XDG_RUNTIME_DIR/containers/auth.json is absent by
// construction on a snug run (snug points XDG_RUNTIME_DIR at this run's own
// runroot), so the fall-through reached the host user's docker config
// (issue #142).
func hostHomeWithDockerCredential(t *testing.T) (home, registry, user string) {
	t.Helper()
	home = t.TempDir()
	registry = "registry.snug-test.invalid"
	user = "snug-test-user"

	dockerDir := filepath.Join(home, ".docker")
	if err := os.MkdirAll(dockerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":snug-test-password"))
	body := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`+"\n", registry, auth)
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, registry, user
}

// TestTheEngineResolvesNoHostRegistryCredential is issue #142's regression.
//
// The engine used to be handed the host user's own HOME, so containers/image
// walked its ordinary search order and found the host's registry
// credentials. That is payload-reachable — the proxy allows the images tree,
// so a payload with @net can make the engine pull AND PUSH as the host user —
// and it is a credential rather than a configuration file.
//
// HOME is deliberately forced back to the planted host home here, which makes
// this the HARSHER assertion: it proves REGISTRY_AUTH_FILE alone closes the
// channel, on a podman that resolves a rootless home from the passwd entry
// rather than from $HOME. snug's own HOME override is a second line, measured
// only on podman 5.8.4 (engine.writeEngineHome says so plainly).
func TestTheEngineResolvesNoHostRegistryCredential(t *testing.T) {
	budget(t, 90*time.Second)

	home, registry, user := hostHomeWithDockerCredential(t)
	baseEnv, eng := engineSpecEnvWithSignaturePolicy(t, `{"default":[{"type":"insecureAcceptAnything"}]}`)
	env := envWith(baseEnv, "HOME", home)

	// storeArgs for the same reason TestAHostRegistriesConfDoesNotSteerTheEnginesPull
	// needs it (issue #425): this probe runs podman on the HOST, and the
	// generated storage.conf named by CONTAINERS_STORAGE_CONF carries the GUEST
	// paths. Without it `login` never reaches the credential lookup and dies on
	// the store instead —
	//
	//	creating runtime static files directory "/snug/engine/store/libpod":
	//	mkdir /snug: permission denied
	//
	// — which the control below then reported as "there is nothing to regress",
	// leaving issue #142's regression inert with a green line to show for it.
	// Found by reading the suite's own output after fixing the two tests #425
	// named; this is a third instance of the same defect.

	// CONTROL FIRST: without snug's variable the credential must be found, or
	// this test cannot fail and proves nothing.
	control := runPodman(t, envWithout(env, "REGISTRY_AUTH_FILE"),
		storeArgs(eng, "login", "--get-login", registry)...)
	if !strings.Contains(control, user) {
		t.Skipf("SKIP: the control did not resolve the planted credential, so this podman does "+
			"not read ~/.docker/config.json at all and there is nothing to regress: %s", control)
	}
	// COMMIT POINT for the run-count floor (issue #393 §4), same place and same
	// reason as TestTheEngineReadsItsOwnRegistriesConf's: past this Skipf the
	// control has proved this podman really resolves the planted credential, so
	// issue #142's regression is about to be exercised. Without this line the
	// floor cannot see this test go inert (issue #458).
	markEngineRan(t, hostEngine(t))

	got := runPodman(t, env, storeArgs(eng, "login", "--get-login", registry)...)
	if strings.Contains(got, user) {
		t.Fatalf("the engine resolved the HOST user's registry credential for %s: a payload "+
			"with @net can pull private images and push as %s (issue #142).\n%s",
			registry, user, got)
	}
	if !strings.Contains(got, "not logged into") {
		t.Errorf("expected a plain \"not logged into\" from an empty auth file, got:\n%s", got)
	}
}

// TestAHostRegistriesConfDoesNotSteerTheEnginesPull is issue #137's
// regression for the file that decides WHERE an image comes from.
//
// The plant is deliberately INVALID TOML rather than a working mirror: a
// parse error naming the planted path is unambiguous evidence the file was
// read, needs no registry, and cannot be confused with a network failure. A
// working mirror would need a second registry to exist.
//
// As in the credential test, HOME points at the planted home throughout, so
// what is under test is CONTAINERS_REGISTRIES_CONF and not snug's HOME.
func TestAHostRegistriesConfDoesNotSteerTheEnginesPull(t *testing.T) {
	budget(t, 90*time.Second)

	home := t.TempDir()
	conf := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	// The seeded policy.json, so that a MISSING signature policy cannot be
	// what stops the pull — this test is about registries.conf alone. See
	// seedEngineHome's own doc comment for why this is generated rather than
	// copied from a bundle: /etc/containers/policy.json is ABSENT on the
	// development host while /usr/share/containers/policy.json is present, so
	// generating the seed is what makes this test's result independent of
	// which of those a given host happens to carry.
	seedEngineHome(t, home)
	planted := filepath.Join(conf, "registries.conf")
	if err := os.WriteFile(planted, []byte("THIS IS NOT VALID TOML {{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env, eng := engineSpecEnvWithSignaturePolicy(t, `{"default":[{"type":"insecureAcceptAnything"}]}`)
	env = envWith(env, "HOME", home)
	const image = "registry.snug-test.invalid/snug/nothing:1"

	// storeArgs is required here: this probe runs podman on the HOST, and the
	// generated storage.conf (named by CONTAINERS_STORAGE_CONF) names the
	// GUEST paths — see engineSpecEnvWithSignaturePolicy's own doc comment.
	// Without it the pull never reaches registries.conf parsing at all and
	// instead fails on the store:
	//
	//	creating runtime static files directory "/snug/engine/store/libpod":
	//	mkdir /snug: permission denied
	control := runPodman(t, envWithout(env, "CONTAINERS_REGISTRIES_CONF"), storeArgs(eng, "pull", image)...)
	if !strings.Contains(control, planted) {
		t.Skipf("SKIP: the control did not read the planted registries.conf, so this podman "+
			"resolves it from somewhere else and there is nothing to regress: %s", control)
	}
	// COMMIT POINT for the run-count floor (issue #393 §4): the control above
	// just proved this podman really reads the planted file, in this env —
	// only past this Skipf is the test actually going to exercise the engine.
	markEngineRan(t, hostEngine(t))

	got := runPodman(t, env, storeArgs(eng, "pull", image)...)
	if strings.Contains(got, planted) {
		t.Fatalf("the engine read the HOST's registries.conf (%s), so a file snug does not "+
			"control decides which bytes become an image (issue #137):\n%s", planted, got)
	}
}

// TestTheEngineCarriesItsOwnSignaturePolicy is issue #137's other half, and
// the one file with no environment variable at all: podman looks for
// policy.json under $HOME/.config/containers and then /etc/containers, and
// REFUSES TO PULL without one. snug generates it into a home of its own.
//
// This is therefore the one assertion here that depends on the HOME override
// working, which is why it is stated separately rather than folded into the
// two above: on a podman that derives a rootless home from the passwd entry
// this would fail, and that failure is information rather than flake.
func TestTheEngineCarriesItsOwnSignaturePolicy(t *testing.T) {
	budget(t, 90*time.Second)

	// probeRuntime, for the same reason the enforcement test below needs it:
	// podman validates conmon and its network helper before it reaches the
	// signature policy, and on the host those live inside the pinned bundle
	// rather than at the absolute paths podman looks in. Without it the CONTROL
	// below never fires and this test skips on every run.
	baseEnv, eng := engineSpecEnvWithSignaturePolicy(t,
		`{"default":[{"type":"insecureAcceptAnything"}]}`)
	env := probeRuntime(t, baseEnv)
	const image = "registry.snug-test.invalid/snug/nothing:1"

	// CONTROL: a home with no policy.json, on a host that has no system one
	// either, must produce podman's refusal. Where /etc/containers/policy.json
	// exists the control cannot fire and the assertion below would pass for
	// the system file's reason rather than snug's.
	if _, err := os.Stat("/etc/containers/policy.json"); err == nil {
		t.Skip("SKIP: this host has /etc/containers/policy.json, so a missing per-home policy " +
			"is not observable and the control cannot fail")
	}
	control := runPodman(t, envWith(env, "HOME", t.TempDir()),
		storeArgs(eng, "pull", image)...)
	if !strings.Contains(control, "no policy.json file found") {
		t.Skipf("SKIP: the control did not produce podman's missing-policy refusal, so this "+
			"podman finds a signature policy some other way: %s", control)
	}

	got := runPodman(t, env, storeArgs(eng, "pull", image)...)
	if strings.Contains(got, "no policy.json file found") {
		t.Fatalf("the engine has no signature policy of its own, so whether an image may be "+
			"used at all is decided by the host, or not at all (issue #137):\n%s", got)
	}
}

// hostSideEnv maps the four guest roots in a spec's environment back to the
// host directories behind them, for a probe that runs the engine outside any
// sandbox. It is deliberately EXACT about which roots it knows: a guest path
// under a root not listed here is left alone and the probe will fail on it,
// which is the honest outcome — a new graft that these tests need to see must
// be added here consciously rather than mapped by a prefix rule that guesses.
func hostSideEnv(t *testing.T, e *engine.Engine, toolchainRoot string, env []string) []string {
	t.Helper()
	roots := [][2]string{
		{policy.EngineConfGuest, e.ConfDir()},
		{policy.EngineStoreGuest, e.Store()},
		{policy.EngineRunrootGuest, e.Runroot()},
		{policy.EngineSockGuest, e.SockDir()},
		{policy.EngineToolchainGuest, toolchainRoot},
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		for _, r := range roots {
			kv = strings.Replace(kv, r[0], r[1], 1)
		}
		out = append(out, kv)
	}
	return out
}

// plantHostSignaturePolicy writes body as the host's own policy.json under a
// throwaway home and returns that home.
//
// The HOME candidate is written rather than the system one, so
// /etc/containers/policy.json is never consulted and the probe means the same
// thing on a host that has one as on a host that does not.
func plantHostSignaturePolicy(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// removeContainerStore deletes a containers/storage store the way a store has
// to be deleted, and reports a failure rather than swallowing one.
//
// ISSUE #367. `t.TempDir`'s own cleanup is `os.RemoveAll`, and that CANNOT
// remove a store an image has been pulled into:
//
//	testing.go:1464: TempDir RemoveAll cleanup: unlinkat
//	  .../storage/overlay/<layer>/diff/var: permission denied
//
// Every assertion in the test passed; only the cleanup failed — so the single
// red line in an otherwise green suite said "the signature policy is not
// enforced" when what happened was "a directory could not be removed". A wrong
// sentence on the only integration test covering issue #307, and "that one is
// expected" is how a real regression gets waved through.
//
// THE CAUSE IS THE MODE, NOT THE OWNERSHIP, and the difference decides the fix.
// MEASURED on the leftover tree: every one of its paths is owned by uid 1000,
// the test's own uid — this is not the root-in-a-userns ownership a rootless
// engine's extracted layers were expected to carry. Exactly two directories
// lack the owner write bit, `diff` and `diff/proc`, both mode 0555, and both
// carry that mode because THE PULLED IMAGE'S OWN TAR says so. Unlinking an
// entry needs write on the directory holding it, and `os.RemoveAll` never
// chmods, so it stops at the first one.
//
// `rm -rf` is defeated identically — measured on a copy of the same tree:
//
//	rm: cannot remove '.../diff/var': Permission denied
//
// so this is not a Go-versus-coreutils detail. What removes it is restoring the
// owner's write bit on the directories first, which is what this does.
//
// It is NOT an unconditional ignore, and must not become one. Issue #308
// measured 4582 directories and 16 GB of store with no GC at all, and a
// cleanup that swallowed errors would hide exactly that. Every failure here is
// reported: a tree that cannot be walked, and a tree that will not remove after
// the modes are restored, are both a t.Errorf.
//
// Chmod is deliberately the minimum that makes a directory removable — u+wx,
// nothing else, and only on directories, and only on a tree that is being
// deleted in the next statement.
func removeContainerStore(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Chmod BEFORE the walk descends: a directory missing x cannot be
		// entered either, and WalkDir calls this for a directory before it
		// reads it.
		if perm := info.Mode().Perm(); perm&0o300 != 0o300 {
			return os.Chmod(p, perm|0o300)
		}
		return nil
	})
	if err != nil {
		t.Errorf("restoring write permission before removing the container store at %s: %v. "+
			"The store is not removable and the leak is real; do not silence this (issue "+
			"#308 measured 4582 directories and 16 GB with no GC).", root, err)
		return
	}
	if err := os.RemoveAll(root); err != nil {
		t.Errorf("removing the container store at %s after restoring write permission: %v. "+
			"Something other than a read-only directory is holding it; find out what "+
			"rather than ignoring it.", root, err)
	}
}

// TestRemoveContainerStoreRemovesWhatRemoveAllCannot is removeContainerStore's
// positive control, and it asserts the REPRODUCTION as well as the fix.
//
// Without the first half this would pass on a specimen that was never hostile,
// which is the shape CLAUDE.md calls a test that cannot fail. Without the
// second it would pass on a helper that removes nothing.
func TestRemoveContainerStoreRemovesWhatRemoveAllCannot(t *testing.T) {
	specimen := func() string {
		root := filepath.Join(t.TempDir(), "storage")
		// The exact shape the pull leaves: a layer root at 0555 with entries
		// under it. `diff/proc` is the second one alpine ships that way.
		diff := filepath.Join(root, "overlay", "deadbeef", "diff")
		for _, d := range []string{"var", "proc", "usr"} {
			if err := os.MkdirAll(filepath.Join(diff, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(diff, "var", "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(diff, "proc"), 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(diff, 0o555); err != nil {
			t.Fatal(err)
		}
		return root
	}

	// THE REPRODUCTION, and the control that the specimen really is hostile.
	hostile := specimen()
	if err := os.RemoveAll(hostile); err == nil {
		t.Fatal("os.RemoveAll removed the specimen, so it does not reproduce issue #367 and " +
			"the assertion below proves nothing. The layer root must be mode 0555 with " +
			"entries under it")
	}
	// Leave nothing behind: this tree is under t.TempDir, whose own RemoveAll
	// would fail on it for exactly the reason under test.
	removeContainerStore(t, hostile)

	// THE FIX.
	fixed := specimen()
	removeContainerStore(t, fixed)
	if _, err := os.Lstat(fixed); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("removeContainerStore left %s behind (lstat: %v)", fixed, err)
	}

	// Removing a path that is already gone is not an error: the cleanup runs
	// whether or not a pull ever happened.
	removeContainerStore(t, filepath.Join(t.TempDir(), "never-created"))
}

// TestTheEngineEnforcesTheProjectedSignaturePolicy is the test every other
// assertion about issue #307 is downstream of.
//
// The unit tests prove snug WROTE a file. Only this proves podman READS it, and
// that matters more than it sounds: writeEngineHome's own doc comment records
// that a rootless podman is free to derive "the user's home" from the passwd
// entry rather than from $HOME, in which case the generated file is one podman
// never opens. Under the old accept-anything policy that residual was harmless.
// Under a projection it would mean the enforcement snug believes it installed is
// not installed at all, with nothing on any screen saying so.
//
// So: plant a host policy that REJECTS everything, project it, and assert the
// pull is refused for a signature-policy reason. The CONTROL is the identical
// run with an accept-anything host policy, which must get past that check —
// without it, "the pull failed" would pass on a broken bundle, a missing
// network or a typo in the image name.
//
// THIS TEST NEEDS THE NETWORK, measured rather than assumed. The rest of this
// file does not, because a missing policy.json and an unparsable
// registries.conf both surface before the first DNS lookup — but a policy that
// REJECTS does not: podman 5.8.4 reaches `initializing source docker://…`
// first, so offline the failure is the DNS error and never `rejected by
// policy`. That case SKIPS by name rather than failing, because "no network" is
// not a verdict on the projection.
func TestTheEngineEnforcesTheProjectedSignaturePolicy(t *testing.T) {
	requireSandbox(t)
	// THE SUITE'S ONE REGISTRY DEPENDENCY, named through the constants that own
	// it rather than spelled out here — TestTheSuiteHasExactlyOneRegistryDependency
	// enforces that, and the gate it demands for a reference like this is
	// reachedNoRegistry below.
	image := dockerHubImage + ":" + dockerHubTag
	const rejected = "rejected by policy"

	rejectEnv, rejectEng := engineSpecEnvWithSignaturePolicy(t, `{"default":[{"type":"reject"}]}`)
	got := runPodman(t, probeRuntime(t, rejectEnv), storeArgs(rejectEng, "pull", image)...)
	if reachedNoRegistry(got) {
		t.Skipf("SKIP: this host cannot reach the registry, and podman evaluates the policy "+
			"only after initializing the source, so there is nothing to observe:\n%s", got)
	}
	// COMMIT POINT for the run-count floor (issue #393 §4). It is AFTER the
	// reachedNoRegistry skip and not at the top: the pull above may die on the
	// network, in which case nothing was graded and the floor must not count
	// this test. Past it, podman got as far as evaluating the policy, so issue
	// #307's assertion is live. Without this line the floor cannot see this
	// test go inert (issue #458).
	markEngineRan(t, hostEngine(t))
	if !strings.Contains(got, rejected) {
		t.Errorf("a host policy of {\"default\":[{\"type\":\"reject\"}]} was projected and the "+
			"pull was NOT refused for a signature-policy reason. The engine is enforcing "+
			"something other than what this host configured, so the projection is writing a "+
			"file podman does not read (issue #307):\n%s", got)
	}

	// CONTROL. Same bundle, same probe, a host policy that accepts anything:
	// the run must get PAST the signature check. It may still fail on the
	// network — this suite does not require one — so the assertion is on the
	// absence of the rejection, not on success.
	anyEnv, anyEng := engineSpecEnvWithSignaturePolicy(t,
		`{"default":[{"type":"insecureAcceptAnything"}]}`)
	control := runPodman(t, probeRuntime(t, anyEnv), storeArgs(anyEng, "pull", image)...)
	if strings.Contains(control, rejected) {
		t.Fatalf("control: an accept-anything host policy was ALSO refused, so the assertion "+
			"above proves nothing about the projection:\n%s", control)
	}
}

// probeRuntime overrides helper_binaries_dir through a
// CONTAINERS_CONF_OVERRIDE layered on top of the one Spec generated, undoing
// the GUEST path Spec wrote there.
//
// WHY A PROBE NEEDS THIS AND A RUN DOES NOT. podman validates its OCI runtime
// before doing anything else, and it looks for conmon at a fixed list of
// ABSOLUTE paths. Inside a real run the toolchain graft puts the engine's
// view where the generated helper_binaries_dir names it; here podman runs on
// the HOST, outside every namespace, where the GUEST path holds nothing.
//
// With a system podman the host's own defaults are the right ones (issue
// #393 §6): this overrides helper_binaries_dir with whichever of
// /usr/libexec/podman, /usr/lib/podman, /usr/bin actually exist on this
// host, and drops the conmon_path/runtime/runtimes pins entirely so podman
// resolves conmon and crun itself. What these tests grade is untouched — the
// signature policy reaches podman through HOME, and none of these keys is
// about images.
func probeRuntime(t *testing.T, env []string) []string {
	t.Helper()
	var dirs []string
	for _, d := range []string{"/usr/libexec/podman", "/usr/lib/podman", "/usr/bin"} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 {
		t.Skip("SKIP: none of /usr/libexec/podman, /usr/lib/podman, /usr/bin exist on this host")
	}
	if _, err := exec.LookPath("conmon"); err != nil {
		t.Skip("SKIP: conmon not found on PATH — cannot probe a runtime this host does not have")
	}
	if _, err := exec.LookPath("crun"); err != nil {
		t.Skip("SKIP: crun not found on PATH — cannot probe a runtime this host does not have")
	}
	quoted := make([]string, len(dirs))
	for i, d := range dirs {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	path := filepath.Join(t.TempDir(), "runtime.conf")
	body := fmt.Sprintf("[engine]\nhelper_binaries_dir = [%s]\n", strings.Join(quoted, ", "))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return envWith(env, "CONTAINERS_CONF_OVERRIDE", path)
}

// storeArgs prefixes --root and --runroot with this run's HOST directories.
//
// A real run passes them on the argv, which is why the generated storage.conf
// may name guest paths at all; a probe running podman outside every namespace
// has to do the same or podman tries to create /snug on the host.
func storeArgs(e *engine.Engine, args ...string) []string {
	return append([]string{"--root", e.Store(), "--runroot", e.Runroot()}, args...)
}

// reachedNoRegistry reports whether podman failed before it could evaluate the
// signature policy at all. Name-resolution and dial failures only: anything
// else must be judged, not skipped.
func reachedNoRegistry(out string) bool {
	for _, offline := range []string{
		"no such host", "server misbehaving", "Temporary failure in name resolution",
		"connection refused", "network is unreachable", "i/o timeout",
	} {
		if strings.Contains(out, offline) {
			return true
		}
	}
	return false
}
