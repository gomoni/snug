//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
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

// engineSpecEnv returns the environment snug's engine is started with, built
// by calling engine.Spec itself.
//
// Calling the real thing matters more here than convenience: the whole
// subject of these tests is which variables that function sets, so a test
// that assembled its own environment would be grading a copy. bundleStorage
// is added on top because the pinned bundle needs to be told where its store
// is (snug passes --root/--runroot on the ARGV, which these probes do not
// use) and because a test must never touch the developer's own store.
func engineSpecEnv(t *testing.T) []string {
	t.Helper()
	root := bundleRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := engine.New([]policy.ProfileName{"@podman-socket"}, t.TempDir())
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
	if err := pol.EngineToolchain(policy.OSEnviron{}, root); err != nil {
		t.Fatal(err)
	}
	if err := e.GraftInto(policy.OSEnviron{}, pol); err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec(pol, podmanBundleBinary(t), []string{"PATH=/usr/bin:/bin"}, true)
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
	// subject of these tests is which variables Spec sets and what the bundle
	// does with them, so the variables are kept exactly as Spec wrote them and
	// only the four roots are mapped back.
	return append(hostSideEnv(t, e, root, spec.Env),
		"CONTAINERS_STORAGE_CONF="+filepath.Join(root, "etc", "snug", "storage.conf"))
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
	cmd := exec.CommandContext(ctx, podmanBundleBinary(t), args...)
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
	env := envWith(engineSpecEnv(t), "HOME", home)

	// CONTROL FIRST: without snug's variable the credential must be found, or
	// this test cannot fail and proves nothing.
	control := runPodman(t, envWithout(env, "REGISTRY_AUTH_FILE"), "login", "--get-login", registry)
	if !strings.Contains(control, user) {
		t.Skipf("SKIP: the control did not resolve the planted credential, so this podman does "+
			"not read ~/.docker/config.json at all and there is nothing to regress: %s", control)
	}

	got := runPodman(t, env, "login", "--get-login", registry)
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
	// The bundle's own policy.json, so that a MISSING signature policy cannot
	// be what stops the pull — this test is about registries.conf alone.
	copyTree(t, filepath.Join(bundleRoot(t), "home"), home)
	planted := filepath.Join(conf, "registries.conf")
	if err := os.WriteFile(planted, []byte("THIS IS NOT VALID TOML {{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := envWith(engineSpecEnv(t), "HOME", home)
	const image = "registry.snug-test.invalid/snug/nothing:1"

	control := runPodman(t, envWithout(env, "CONTAINERS_REGISTRIES_CONF"), "pull", image)
	if !strings.Contains(control, planted) {
		t.Skipf("SKIP: the control did not read the planted registries.conf, so this podman "+
			"resolves it from somewhere else and there is nothing to regress: %s", control)
	}

	got := runPodman(t, env, "pull", image)
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

	env := engineSpecEnv(t)
	const image = "registry.snug-test.invalid/snug/nothing:1"

	// CONTROL: a home with no policy.json, on a host that has no system one
	// either, must produce podman's refusal. Where /etc/containers/policy.json
	// exists the control cannot fire and the assertion below would pass for
	// the system file's reason rather than snug's.
	if _, err := os.Stat("/etc/containers/policy.json"); err == nil {
		t.Skip("SKIP: this host has /etc/containers/policy.json, so a missing per-home policy " +
			"is not observable and the control cannot fail")
	}
	control := runPodman(t, envWith(env, "HOME", t.TempDir()), "pull", image)
	if !strings.Contains(control, "no policy.json file found") {
		t.Skipf("SKIP: the control did not produce podman's missing-policy refusal, so this "+
			"podman finds a signature policy some other way: %s", control)
	}

	got := runPodman(t, env, "pull", image)
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
