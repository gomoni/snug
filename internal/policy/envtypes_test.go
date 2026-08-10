package policy

import (
	"strings"
	"testing"
)

// The refusals themselves are pinned, exactly, in testdata/refusals.txt (see
// TestGoldenRefusals). What lives here is the other half — the POSITIVE
// CONTROLS. A validator that refused everything would pass every negative test
// in this package and be indistinguishable from a correct one, so each rule
// below is paired with the spelling it is meant to leave alone.

func TestValidEnvGrantsAreAccepted(t *testing.T) {
	cases := []struct {
		name string
		g    EnvGrants
	}{
		// §1.2's worked @home: four scalar paths the same profile creates.
		{"xdg scalars via set", EnvGrants{Set: map[string]string{
			"XDG_CONFIG_HOME": "{home}/.config",
			"XDG_CACHE_HOME":  "{home}/.cache",
			"XDG_STATE_HOME":  "{home}/.local/state",
			"XDG_DATA_HOME":   "{home}/.local/share",
		}}},
		// §1.2's worked @rust, and the shape step 12 tells `path = [...]` users
		// to migrate to. If this ever starts failing, that migration has no
		// destination.
		{"merge on PATH", EnvGrants{Merge: map[string][]string{
			"PATH": {"{home}/.cargo/bin"},
		}}},
		{"prepend on PATH", EnvGrants{Prepend: map[string][]string{
			"PATH": {"/opt/bin"},
		}}},
		// A string is exactly one element, for merge as well as prepend
		// (CALL 1) — what is refused is the SEPARATOR, not the shape.
		{"single-element merge", EnvGrants{Merge: map[string][]string{
			"PKG_CONFIG_PATH": {"/opt/x/lib/pkgconfig"},
		}}},
		// §1.2's worked @claude.
		{"inherit scalars", EnvGrants{Inherit: []string{"ANTHROPIC_API_KEY", "EDITOR", "NO_COLOR"}}},
		// The list form of inherit, on a list whose empty element is ignored.
		{"sanitise a filterable list", EnvGrants{Sanitise: []string{"PKG_CONFIG_PATH"}}},
		// PATH's sanitise is "rebuild only" (§3.3) — allowed, because snug
		// rebuilds the value from elements it never split.
		{"sanitise PATH", EnvGrants{Sanitise: []string{"PATH"}}},
		// merge and sanitise on one name is legal and never an error: both are
		// unions (§2.6).
		{"merge and sanitise together", EnvGrants{
			Merge:    map[string][]string{"PKG_CONFIG_PATH": {"/opt/x/lib/pkgconfig"}},
			Sanitise: []string{"PKG_CONFIG_PATH"},
		}},
		// An unknown name is a scalar, and a scalar merges with nothing — so it
		// can only ever conflict, never silently combine (§2.1).
		{"unknown name as a scalar", EnvGrants{Set: map[string]string{"MY_TOOL_MODE": "fast"}}},
		{"leading underscore", EnvGrants{Set: map[string]string{"_PRIVATE": "x"}}},
		// The empty grant block: nothing to check, and no error.
		{"nothing at all", EnvGrants{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateEnvGrants(tc.g); err != nil {
				t.Errorf("refused a legal grant: %v", err)
			}
		})
	}
}

// PATH is the one name in SnugOwnedEnv that a profile may still contribute to,
// and the asymmetry is worth its own test rather than being left to be
// rediscovered.
//
// snug authors PATH's base band and the podman stub's band, and neither is
// something a profile may replace — but a merge or a prepend adds a band ahead
// of them and displaces nothing (§2.4). Refusing those would leave `path =
// [...]` with nowhere to migrate to (step 12's error message names
// environ.merge on PATH as the replacement) and would make §1.2's @rust profile
// unwritable.
//
// What must stay refused is every verb that would REPLACE the value, and the
// message must name the verb to use instead (§2.1).
func TestPATHIsSharedButNotReplaceable(t *testing.T) {
	for _, g := range []EnvGrants{
		{Merge: map[string][]string{"PATH": {"/opt/bin"}}},
		{Prepend: map[string][]string{"PATH": {"/opt/bin"}}},
	} {
		if err := ValidateEnvGrants(g); err != nil {
			t.Errorf("a profile must be able to contribute an entry to PATH: %v", err)
		}
	}

	err := ValidateEnvGrants(EnvGrants{Set: map[string]string{"PATH": "/opt/bin"}})
	if err == nil {
		t.Fatal("environ.set on PATH was accepted; it would replace every other profile's " +
			"entries and snug's own base")
	}
	if !strings.Contains(err.Error(), "environ.merge") {
		t.Errorf("the refusal must name the verb to use instead: %v", err)
	}

	err = ValidateEnvGrants(EnvGrants{Inherit: []string{"PATH"}})
	if err == nil {
		t.Fatal("environ.inherit on PATH was accepted; it imports the host's search path " +
			"wholesale, every entry of which names a directory the sandbox does not have")
	}
	if !strings.Contains(err.Error(), "environ.sanitise") {
		t.Errorf("the refusal must name the verb to use instead: %v", err)
	}

	// A scalar snug owns has no such shared band, so EVERY verb is refused for
	// it — this is the control that keeps the exemption above narrow.
	for _, g := range []EnvGrants{
		{Set: map[string]string{"HOME": "/tmp"}},
		{Inherit: []string{"HOME"}},
		{Merge: map[string][]string{"HOME": {"/tmp"}}},
	} {
		if err := ValidateEnvGrants(g); err == nil {
			t.Errorf("a profile wrote HOME (%+v); it is where the identity generator puts "+
				"~/.gitconfig and ~/.ssh/config, so moving it silently defeats identity "+
				"pinning", g)
		}
	}
}

// The forbid list splits by verb, and the split is the point: a `set` carries a
// value from a reviewed file in the trusted profile layer, an `inherit` carries
// whatever the process that launched snug happened to have. inherit is a hole
// punched in --clearenv; set is not (CALL 4, §2.1).
func TestForbidListSplitsBySetAndInherit(t *testing.T) {
	// The middle bucket: legal as set, refused as inherit.
	for _, name := range []string{"BASH_ENV", "ENV", "PERL5OPT", "NODE_OPTIONS",
		"PYTHONSTARTUP", "PYTHONBREAKPOINT", "LESSOPEN"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "{home}/x"}}); err != nil {
			t.Errorf("environ.set %s should be legal — a reviewed profile naming a path it "+
				"also grants is exactly what the format is for: %v", name, err)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err == nil {
			t.Errorf("environ.inherit %s was accepted; the host's value is code and this is "+
				"a hole punched straight through --clearenv", name)
		}
	}

	// And the names refused at BOTH verbs, because the value is code wherever
	// it came from.
	for _, name := range []string{"LD_PRELOAD", "LD_AUDIT", "GCONV_PATH", "TZDIR",
		"GIT_SSH_COMMAND", "GIT_EXEC_PATH", "PROMPT_COMMAND", "PS4",
		// Reached by a redteam run: GIT_SSH hijacked `git fetch` in a sandbox
		// whose ssh identity a different profile had pinned, while
		// GIT_SSH_COMMAND was refused. The rule is "the value is code", not
		// "the newest spelling" — see envtypes.go.
		"GIT_SSH", "GIT_PROXY_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS",
		"GIT_SEQUENCE_EDITOR", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
		"JDK_JAVA_OPTIONS", "RUBYOPT"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err == nil {
			t.Errorf("environ.set %s was accepted; the value is executed by every process "+
				"the sandbox launches", name)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err == nil {
			t.Errorf("environ.inherit %s was accepted", name)
		}
	}

	// PIP_* and npm_config_* are the prefix half of the same split: the host's
	// environment outranks the config FILE those tools read (§4.5), which is an
	// argument about inherit, not about set.
	if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{"PIP_CONFIG_FILE": "{home}/.config/pip.conf"}}); err != nil {
		t.Errorf("environ.set PIP_CONFIG_FILE is \"generate, don't bind\" written down: %v", err)
	}
	if err := ValidateEnvGrants(EnvGrants{Inherit: []string{"PIP_CONFIG_FILE"}}); err == nil {
		t.Error("environ.inherit PIP_CONFIG_FILE was accepted; the host's value would " +
			"outrank the file snug generates")
	}
}

// A prefix rule has to cover the prefix and NOT the near-miss, or it is either
// a hole or a nuisance. Both directions, because a rule that refused LD_ by
// refusing everything starting with L would pass every negative test here.
func TestForbiddenPrefixesCoverExactlyTheirPrefix(t *testing.T) {
	refused := []string{"LD_ANYTHING", "BASH_FUNC_x", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0"}
	for _, name := range refused {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err == nil {
			t.Errorf("environ.set %s was accepted", name)
		}
	}
	// Near misses: a name that merely starts with the same letters is a
	// different variable and must be left alone.
	for _, name := range []string{"LD", "LDFLAGS", "BASH_FUNCTION", "GIT_CONFIG", "GITCONFIG"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err != nil {
			t.Errorf("environ.set %s was refused; %q is not one of the forbidden prefixes "+
				"and a rule that catches it catches too much: %v", name, name, err)
		}
	}
}
