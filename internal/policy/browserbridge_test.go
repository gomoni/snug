package policy

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func loginOn(m LoginMode) map[LoginProvider]LoginMode {
	return map[LoginProvider]LoginMode{LoginClaude: m}
}

// TestBrowserBridgeNeedsEgress: both modes relay a callback into the
// sandbox's own network namespace, so a selection with no @net grant stages a
// BROWSER whose /login never ends — refused rather than granted-but-useless
// (issue #455), naming the profile and the key it wrote.
func TestBrowserBridgeNeedsEgress(t *testing.T) {
	for _, m := range []LoginMode{LoginSandbox, LoginHost} {
		reg := testRegistry()
		reg["bridge"] = &Profile{Name: "bridge", Login: loginOn(m)}
		_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
		if err == nil {
			t.Fatalf("login.claude = %q without egress resolved", m)
		}
		for _, want := range []string{`profile "bridge" turns the Claude login bridge on (mode "` + m.String() + `")`,
			"-p @net", "needs the stage @net starts"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal does not say %q: %v", m, want, err)
			}
		}
	}
}

// TestBrowserBridgeStagesTheWrapperAndBROWSER pins the positive case: with
// egress, Resolve points BROWSER at the symlink BrowserGuest, which leads to
// the one authored wrapper bind, and stages no data script.
func TestBrowserBridgeStagesTheWrapperAndBROWSER(t *testing.T) {
	for _, mode := range []LoginMode{LoginSandbox, LoginHost} {
		reg := testRegistry()
		reg["bridge"] = &Profile{Name: "bridge", Login: loginOn(mode), Network: "egress"}
		p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("%s: Resolve: %v", mode, err)
		}
		if want := (LoginModes{}).With(LoginClaude, mode); p.Login != want {
			t.Fatalf("p.Login = %v, want %v", p.Login, want)
		}
		m, ok := p.Mounts[BrowserGuest]
		if !ok || m.Kind != KindSymlink || m.Host != WrapperGuest || !m.Authored {
			t.Fatalf("%s: no authored symlink %s -> %s: %+v", mode, BrowserGuest, WrapperGuest, m)
		}
		w, ok := p.Mounts[WrapperGuest]
		if !ok || w.Kind != KindBind || w.Access != AccessRO || !w.Authored || w.Host != SelfExeHost {
			t.Fatalf("%s: no authored read-only bind of %s at %s: %+v", mode, SelfExeHost, WrapperGuest, w)
		}
		v, ok := p.Env["BROWSER"]
		if !ok || len(v.Entries) != 1 || v.Entries[0].Value != BrowserGuest || v.Entries[0].Verb != VerbSnug {
			t.Fatalf("%s: BROWSER not authored to %s: %+v", mode, BrowserGuest, v)
		}
	}
}

// TestWithoutLoginThereIsNoBridgeAndNoHostFlow pins the default: a selection
// with @net and @sys and no login key stages neither the browser link, nor
// the wrapper, nor BROWSER, nor CLAUDE_SECURESTORAGE_CONFIG_DIR, and maps
// nothing at the FIFO or the host-mode credential directory — the hole exists
// only where a profile spells the key itself.
func TestWithoutLoginThereIsNoBridgeAndNoHostFlow(t *testing.T) {
	p := mustResolve(t, "@sys", "@target-rw", "netty")
	if p.Login.Any() {
		t.Fatalf("login resolved on with no profile setting it: %v", p.Login)
	}
	for _, g := range []string{BrowserGuest, WrapperGuest, BrowserFIFOGuest, ClaudeCredentialDirGuest} {
		if _, ok := p.Mounts[g]; ok {
			t.Errorf("%s is mapped without login.claude anywhere in the selection", g)
		}
	}
	for _, n := range []string{"BROWSER", "CLAUDE_SECURESTORAGE_CONFIG_DIR"} {
		if _, ok := p.Env[n]; ok {
			t.Errorf("%s is authored without login.claude anywhere in the selection", n)
		}
	}
	// POSITIVE CONTROL: the selection has egress, so the absence above is the
	// key's and not the egress refusal's.
	if p.Net.Mode != NetEgress {
		t.Fatalf("control: netty resolved to %s, want egress", p.Net.Mode)
	}
}

// TestHostModeAuthorsExactlyOneMoreVariable: host mode adds
// CLAUDE_SECURESTORAGE_CONFIG_DIR, pointing at ClaudeCredentialDirGuest, and
// nothing else, on top of the bridge's BROWSER — and no mount at all, since
// the directory is bound after Resolve.
func TestHostModeAuthorsExactlyOneMoreVariable(t *testing.T) {
	resolve := func(m LoginMode) *Policy {
		t.Helper()
		reg := testRegistry()
		reg["bridge"] = &Profile{Name: "bridge", Login: loginOn(m), Network: "egress"}
		p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		return p
	}
	sandbox, host := resolve(LoginSandbox), resolve(LoginHost)
	var added []string
	for n := range host.Env {
		if _, ok := sandbox.Env[n]; !ok {
			added = append(added, n)
		}
	}
	for n := range sandbox.Env {
		if _, ok := host.Env[n]; !ok {
			t.Errorf("host mode DROPS %s, which sandbox mode authors", n)
		}
	}
	if !slices.Equal(added, []string{"CLAUDE_SECURESTORAGE_CONFIG_DIR"}) {
		t.Fatalf("host mode adds %v over sandbox mode, want exactly CLAUDE_SECURESTORAGE_CONFIG_DIR", added)
	}
	v := host.Env["CLAUDE_SECURESTORAGE_CONFIG_DIR"]
	if len(v.Entries) != 1 || v.Entries[0].Value != ClaudeCredentialDirGuest || v.Entries[0].Verb != VerbSnug {
		t.Errorf("CLAUDE_SECURESTORAGE_CONFIG_DIR = %+v, want snug's %s", v, ClaudeCredentialDirGuest)
	}
	for _, p := range []*Policy{sandbox, host} {
		if _, ok := p.Env["BROWSER"]; !ok {
			t.Errorf("%v: BROWSER is not authored", p.Login.Keys())
		}
	}
	if !reflect.DeepEqual(mountGuests(sandbox), mountGuests(host)) {
		t.Errorf("Resolve mounts differ between the modes:\nsandbox %v\nhost    %v",
			mountGuests(sandbox), mountGuests(host))
	}
}

// TestLoginModesJoinMustAgree: two profiles naming the same mode turn it on
// once and the result does not depend on fold order; two naming different
// modes are refused in both orders, naming both profiles and both keys; a
// profile that names no mode joins with either.
func TestLoginModesJoinMustAgree(t *testing.T) {
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Login: loginOn(LoginHost), Network: "egress"}
	reg["b"] = &Profile{Name: "b", Login: loginOn(LoginHost)}
	reg["c"] = &Profile{Name: "c", Login: map[LoginProvider]LoginMode{}}
	reg["s"] = &Profile{Name: "s", Login: loginOn(LoginSandbox)}
	ab, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "a", "b", "c"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve a b c: %v", err)
	}
	ba, err := Resolve(reg, []ProfileName{"c", "b", "a", "@target-rw", "@sys"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve c b a: %v", err)
	}
	want := LoginModes{}.With(LoginClaude, LoginHost)
	if ab.Login != want || ba.Login != want {
		t.Errorf("login = %v and %v, want %v in both orders", ab.Login, ba.Login, want)
	}
	if !reflect.DeepEqual(ab.Mounts[BrowserGuest], ba.Mounts[BrowserGuest]) ||
		!reflect.DeepEqual(ab.Env["BROWSER"], ba.Env["BROWSER"]) {
		t.Error("the shim or BROWSER depends on fold order")
	}

	for _, sel := range [][]ProfileName{{"@sys", "@target-rw", "a", "s"}, {"s", "a", "@target-rw", "@sys"}} {
		_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err == nil {
			t.Fatalf("%v: sandbox and host modes resolved together", sel)
		}
		for _, w := range []string{
			`profile "a" chooses "host" for the Claude login and profile "s" chooses "sandbox"`,
			"one /login cannot both stay in the sandbox and be completed on the host",
			"Make the two agree, or select one of them.",
		} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%v: refusal does not say %q:\n%v", sel, w, err)
			}
		}
		// Neither spelling of the key is quoted: "s" may have written either.
		if strings.Contains(err.Error(), "login.claude") || strings.Contains(err.Error(), "[") {
			t.Errorf("%v: the refusal quotes a spelling of the key:\n%v", sel, err)
		}
	}

	only := testRegistry()
	only["c"] = &Profile{Name: "c", Login: map[LoginProvider]LoginMode{LoginClaude: LoginOff}, Network: "egress"}
	p, err := Resolve(only, []ProfileName{"@sys", "@target-rw", "c"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve c: %v", err)
	}
	if p.Login.Any() {
		t.Errorf("a table naming nothing resolved to %v", p.Login.Keys())
	}
	if _, ok := p.Mounts[BrowserGuest]; ok {
		t.Error("a table naming nothing staged the shim")
	}
}

// TestLoginValuesSnugDoesNotKnowAreRefused: a Profile built in Go can hold a
// provider or a mode no parser produces; Resolve refuses both rather than
// skipping or clamping them.
func TestLoginValuesSnugDoesNotKnowAreRefused(t *testing.T) {
	for name, login := range map[string]map[LoginProvider]LoginMode{
		"provider": {LoginProvider(7): LoginSandbox},
		"mode":     {LoginClaude: LoginMode(9)},
	} {
		reg := testRegistry()
		reg["bridge"] = &Profile{Name: "bridge", Login: login, Network: "egress"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), `profile "bridge": login holds`) {
			t.Errorf("%s: want a refusal naming the profile, got %v", name, err)
		}
	}
}

// TestAnEmptyLoginModeIsRefused pins ParseLoginMode's refusal of "" and its
// wording: it names the key, quotes both modes and says to omit the key.
func TestAnEmptyLoginModeIsRefused(t *testing.T) {
	m, err := ParseLoginMode(LoginClaude, "")
	if err == nil {
		t.Fatalf(`ParseLoginMode("") = %v, nil; want a refusal`, m)
	}
	want := `login.claude = "" grants nothing: write "sandbox" or "host", or omit the key for no login.`
	if err.Error() != want {
		t.Errorf("ParseLoginMode(\"\") = %q, want %q", err, want)
	}
}

// TestAnUnknownLoginModeQuotesTheAcceptedSet: a value outside the accepted
// set is refused, quoting it and the set, never read as the mode it
// resembles; the two accepted values parse.
func TestAnUnknownLoginModeQuotesTheAcceptedSet(t *testing.T) {
	for _, s := range []string{"Host", "HOST", " host", "host ", "off", "browser", "claude-login", "sandboxed"} {
		_, err := ParseLoginMode(LoginClaude, s)
		if err == nil {
			t.Errorf("%q parsed", s)
			continue
		}
		want := `unknown login mode ` + strconv.Quote(s) + ` for claude (want "sandbox" or "host")`
		if err.Error() != want {
			t.Errorf("%q: %q, want %q", s, err, want)
		}
	}
	for s, want := range map[string]LoginMode{"sandbox": LoginSandbox, "host": LoginHost} {
		if got, err := ParseLoginMode(LoginClaude, s); err != nil || got != want {
			t.Errorf("control: %q = %v, %v", s, got, err)
		}
	}
}
