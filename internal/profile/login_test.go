package profile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

func parseLogin(t *testing.T, body string) (map[policy.LoginProvider]policy.LoginMode, error) {
	t.Helper()
	reg, err := parse([]byte("[profile.p]\n"+body+"\n"), "mine.toml", true)
	if err != nil {
		return nil, err
	}
	return reg["p"].Login, nil
}

// TestTheLoginTableParsesInEveryTOMLSpelling: a dotted key, an inline table
// and a subtable are one TOML table, and each reaches the profile as the same
// provider = mode map.
func TestTheLoginTableParsesInEveryTOMLSpelling(t *testing.T) {
	for _, mode := range []policy.LoginMode{policy.LoginSandbox, policy.LoginHost} {
		want := map[policy.LoginProvider]policy.LoginMode{policy.LoginClaude: mode}
		for _, body := range []string{
			`login.claude = "` + mode.String() + `"`,
			`login = { claude = "` + mode.String() + `" }`,
			"[profile.p.login]\nclaude = \"" + mode.String() + "\"",
		} {
			got, err := parseLogin(t, body)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%q: %v, %v; want %v", body, got, err, want)
			}
		}
	}
	// An absent key and an empty table both name nothing.
	for _, body := range []string{"", "login = {}"} {
		if got, err := parseLogin(t, body); err != nil || len(got) != 0 {
			t.Errorf("%q: %v, %v; want no login", body, got, err)
		}
	}
}

// TestTheListFormOfLoginMeansSandbox holds the one equivalence the list
// spelling keeps: `login = ["claude"]` is `login.claude = "sandbox"`, for a
// file written before the table existed. Duplicates are one, and an empty
// list names nothing.
func TestTheListFormOfLoginMeansSandbox(t *testing.T) {
	table, err := parseLogin(t, `login.claude = "sandbox"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`login = ["claude"]`, `login = ["claude", "claude"]`} {
		got, err := parseLogin(t, body)
		if err != nil || !reflect.DeepEqual(got, table) {
			t.Errorf("%q: %v, %v; want the table's %v", body, got, err, table)
		}
	}
	if got, err := parseLogin(t, `login = []`); err != nil || len(got) != 0 {
		t.Errorf("login = []: %v, %v; want no login", got, err)
	}
	// A list element is a provider, so an unknown one is refused by name, and
	// the refusal never shows the list spelling back.
	_, err = parseLogin(t, `login = ["claude", "x"]`)
	if err == nil || !strings.Contains(err.Error(), `unknown login provider "x" (want claude)`) {
		t.Errorf(`login = ["claude", "x"]: %v`, err)
	}
	if err != nil && strings.Contains(err.Error(), "[") {
		t.Errorf("the refusal shows the list spelling: %v", err)
	}
}

// TestAnEmptyLoginModeIsRefusedAtParseTime: `login.claude = ""` is refused
// with ParseLoginMode's wording behind the file and the profile, in every
// TOML spelling.
func TestAnEmptyLoginModeIsRefusedAtParseTime(t *testing.T) {
	for _, body := range []string{`login.claude = ""`, `login = { claude = "" }`, "[profile.p.login]\nclaude = \"\""} {
		_, err := parseLogin(t, body)
		want := `mine.toml: profile "p": login.claude = "" grants nothing: write "sandbox" or "host", ` +
			`or omit the key for no login.`
		if err == nil || err.Error() != want {
			t.Errorf("%q: %v\nwant %s", body, err, want)
		}
	}
}

// TestAnUnknownLoginProviderIsNamed: a provider key outside the accepted set
// is refused naming it and the set — strict decoding does not reach inside
// the table, so toLogin is what refuses it.
func TestAnUnknownLoginProviderIsNamed(t *testing.T) {
	for _, body := range []string{`login.claudee = "host"`, `login.Claude = "host"`, `login = { gh = "sandbox" }`} {
		_, err := parseLogin(t, body)
		if err == nil {
			t.Errorf("%q parsed", body)
			continue
		}
		for _, w := range []string{"mine.toml", `"p"`, "unknown login provider", "(want claude)"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%q: refusal does not say %s: %v", body, w, err)
			}
		}
	}
}

// TestAnUnknownLoginModeIsRefusedAtParseTime: a mode outside the accepted set
// is refused, quoting it and the set.
func TestAnUnknownLoginModeIsRefusedAtParseTime(t *testing.T) {
	for _, mode := range []string{"Host", "HOST", " host", "host ", "Sandbox", "off", "claude-login", "both"} {
		_, err := parseLogin(t, `login.claude = "`+mode+`"`)
		want := `unknown login mode "` + mode + `" for claude (want "sandbox" or "host")`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want it to contain %s", mode, err, want)
		}
	}
}

// TestLoginTableRefusesNonStringValues: a mode that is not a string is
// refused with the unknown-mode wording, its value made visible; a `login`
// that is neither a table nor a list says what to write.
func TestLoginTableRefusesNonStringValues(t *testing.T) {
	for body, says := range map[string]string{
		`login.claude = true`:                    `unknown login mode true for claude (want "sandbox" or "host")`,
		`login.claude = 3`:                       `unknown login mode 3 for claude (want "sandbox" or "host")`,
		`login.claude = ["host"]`:                `unknown login mode [host] for claude (want "sandbox" or "host")`,
		`login.claude.mode = "host"`:             `unknown login mode map[mode:host] for claude`,
		`login.claude.x = "\u001b[2J"`:           `\x1b[2J`,
		`login = "claude"`:                       `login is a table of provider = mode; write login.claude = "host" or login.claude = "sandbox"`,
		`login = true`:                           `login is a table of provider = mode`,
		`login = [true]`:                         `login is a table of provider = mode`,
		`login = [{ claude = "host" }]`:          `login is a table of provider = mode`,
		"[[profile.p.login]]\nclaude = \"host\"": `login is a table of provider = mode`,
	} {
		_, err := parseLogin(t, body)
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v, want it to contain %s", body, err, says)
		}
		if err != nil && strings.Contains(err.Error(), "\x1b") {
			t.Errorf("%s: a raw ESC reached the refusal: %q", body, err)
		}
	}
}
