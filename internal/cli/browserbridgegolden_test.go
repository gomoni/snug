package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/stage"
)

// browserLoginProfile is the ordinary user profile that turns the login
// bridge on — `browser = "claude-login"` alone, since @claude and @net are
// selected directly beside it. There is no `@claude-login` builtin (issue
// #455, a maintainer decision).
var browserLoginProfile = &policy.Profile{Name: "login", Browser: "claude-login"}

// TestGoldenBwrapClaudeLogin pins the bwrap argv for `@claude @net login`
// against the real builtin profiles, the same shape TestGoldenClaudeArgv
// uses. The diff against @claude @net alone (asserted below) is the review
// artifact: it must be exactly the shim's data mount and the BROWSER setenv.
func TestGoldenBwrapClaudeLogin(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["login"] = browserLoginProfile
	ctx := envGoldenCtx()

	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude", "@net", "login")
	p, err := policy.Resolve(m, sel, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	if err := claudeFiles(p, ctx.Home, nil); err != nil {
		t.Fatalf("claudeFiles: %v", err)
	}
	if _, ok := p.Mounts[policy.BrowserShimGuest]; !ok {
		t.Fatal("control: the login-bridge shim is not staged — this golden would pin an argv " +
			"that never exercises browser = \"claude-login\"")
	}

	got := goldenFormat(p.BwrapArgs(1000, 1000))

	path := filepath.Join("testdata", "bwrap.claude-login.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the login bridge's bwrap argv changed — this is a change to the security "+
			"boundary and is read as such.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// TestBrowserBridgeGoldenDiffIsExactlyTheShimAndBROWSER is the review artifact
// §7 of the spec asks for: the ONLY difference between `@claude @net` and
// `@claude @net login` is the shim's data mount and the BROWSER setenv —
// nothing about @claude's or @net's own grants moves when the bridge turns on.
func TestBrowserBridgeGoldenDiffIsExactlyTheShimAndBROWSER(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["login"] = browserLoginProfile
	ctx := envGoldenCtx()
	base := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude", "@net")

	without, err := policy.Resolve(m, base, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", base, err)
	}
	if err := claudeFiles(without, ctx.Home, nil); err != nil {
		t.Fatal(err)
	}
	with, err := policy.Resolve(m, append(append([]policy.ProfileName{}, base...), "login"), ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if err := claudeFiles(with, ctx.Home, nil); err != nil {
		t.Fatal(err)
	}

	for guest, wm := range with.Mounts {
		if _, ok := without.Mounts[guest]; ok {
			continue
		}
		if guest != policy.BrowserShimGuest {
			t.Errorf("login adds an unexpected mount at %s (kind %s, host %q)", guest, wm.Kind, wm.Host)
		}
	}
	for guest := range without.Mounts {
		if _, ok := with.Mounts[guest]; !ok {
			t.Errorf("login DROPS the mount at %s that @claude @net alone grants", guest)
		}
	}

	wantArgs := strings.Join(with.BwrapArgs(1000, 1000), " ")
	baseArgs := strings.Join(without.BwrapArgs(1000, 1000), " ")
	if !strings.Contains(wantArgs, "--setenv BROWSER "+policy.BrowserShimGuest) {
		t.Errorf("the argv does not setenv BROWSER to the shim: %s", wantArgs)
	}
	if strings.Contains(baseArgs, "--setenv BROWSER") {
		t.Error("@claude @net alone already sets BROWSER — the fixture no longer isolates the change")
	}
}

// TestClaudeLoginPastaArgvEqualsClaudeNet: the login bridge relays into the
// sandbox's own netns over a socket the stage creates, never over pasta —
// pasta's argv must not move by one byte when browser = "claude-login" is
// added beside @claude @net.
func TestClaudeLoginPastaArgvEqualsClaudeNet(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["login"] = browserLoginProfile
	ctx := pastaGoldenCtx()
	base := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude", "@net")

	without, err := policy.Resolve(m, base, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	with, err := policy.Resolve(m, append(append([]policy.ProfileName{}, base...), "login"), ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	a := strings.Join(without.PastaArgs(policy.PastaTargetStage(0, stage.NetnsFD)), " ")
	b := strings.Join(with.PastaArgs(policy.PastaTargetStage(0, stage.NetnsFD)), " ")
	if a != b {
		t.Errorf("pasta argv changed when browser = \"claude-login\" was added:\n@claude @net:       %s\n@claude @net login: %s", a, b)
	}
}
