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
		"JDK_JAVA_OPTIONS", "RUBYOPT",
		// Found missing by an independent review, each measured on git 2.55
		// before being added. Three shapes, and the spread is why the list is
		// "the value is code" rather than "the value is a command":
		//   GIT_PAGER          — a command, exactly like GIT_EDITOR
		//   GIT_TEMPLATE_DIR   — a directory whose hooks are installed into
		//                        every repo `git clone`/`git init` creates
		//   GIT_DIR            — a repository whose hooks run on the next commit
		//   GIT_ALLOW_PROTOCOL — no code at all: it switches OFF git's refusal
		//   GIT_PROTOCOL_FROM_USER  of ext::, which runs an arbitrary command
		"GIT_PAGER", "GIT_TEMPLATE_DIR", "GIT_DIR",
		"GIT_ALLOW_PROTOCOL", "GIT_PROTOCOL_FROM_USER"} {
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

// A NUL in an environ VALUE authored a mount. This is the regression test.
//
// The mechanism, measured before the fix: `--setenv NAME VALUE` is three
// elements of the flag list, the list is NUL-joined into the args memfd, and
// bwrap's --args splits on NUL. VALUE is last in the triple, so the parser
// re-synced on the remainder and
//
//	EDITOR = "vim\\u0000--ro-bind\\u0000/home/u/.ssh\\u0000/home/u/.ssh"
//
// mounted ~/.ssh into a sandbox whose --dry-run listed ~/.ssh under NOT GRANTED
// and whose FILESYSTEM block had no such line — because there was no Mount, so
// Validate, rejectMasking and the provenance model never saw it. The same shape
// with --tmpfs masked @sys's `ro /usr`: a profile expressing subtraction.
//
// checkEnvName has refused NUL in a NAME since the beginning, with a comment
// whose reasoning applies word for word to the value. That is the shape of this
// defect: the rule was written, and applied to one of the two halves.
func TestEnvValueRefusesControlCharacters(t *testing.T) {
	// The spelling matters for anyone re-testing: a RAW NUL never gets this far,
	// because go-toml refuses control characters in a basic string. The \\u0000
	// ESCAPE is accepted by the parser and produces the same byte, which is why
	// the check lives here rather than being left to TOML.
	bad := map[string]string{
		"a NUL, which ends the flag and starts a new one": "vim\x00--ro-bind\x00/etc\x00/etc",
		"a newline, which forges a row in --dry-run":      "vim\n  ro     /etc/shadow",
		"an ESC, which rewrites the terminal":             "fast\x1b[1A\r  ro   /usr/share/doc",
		"a DEL":                                           "x\x7f",
	}
	for why, value := range bad {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{"EDITOR": value}}); err == nil {
			t.Errorf("environ.set accepted a value containing %s", why)
		}
		if err := ValidateEnvGrants(EnvGrants{Merge: map[string][]string{"XDG_DATA_DIRS": {value}}}); err == nil {
			t.Errorf("environ.merge accepted an element containing %s", why)
		}
		if err := ValidateEnvGrants(EnvGrants{Prepend: map[string][]string{"XDG_DATA_DIRS": {value}}}); err == nil {
			t.Errorf("environ.prepend accepted an element containing %s", why)
		}
	}

	// The positive control, and it is not decoration: a check that refused
	// everything would pass every assertion above while making the format
	// unusable. Ordinary values, including the ones the shipped profiles carry.
	for _, value := range []string{"vim", "/usr/share", "en_US.UTF-8", "1", ""} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{"EDITOR": value}}); err != nil {
			t.Errorf("environ.set EDITOR = %q was refused: %v", value, err)
		}
	}

	// inherit and sanitise are NOT covered and must not be: their values are the
	// HOST's, so a verdict on them would depend on the machine reading the
	// profile, and §2.3 puts every parse-time verdict on the profile TEXT. A NUL
	// cannot reach them anyway — the environment execve hands over is itself a
	// NUL-terminated list. Their rendering is visibleValue's job.
	if err := ValidateEnvGrants(EnvGrants{Inherit: []string{"EDITOR"}}); err != nil {
		t.Errorf("environ.inherit EDITOR was refused: %v", err)
	}
}

// The residual the list does NOT close, pinned as a test so it cannot become a
// belief that it does.
//
// git falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR, and GIT_PAGER ->
// core.pager -> PAGER. Both fallbacks measured; `PAGER="sh -c '…'" git log` runs
// the command. So a profile that wanted to hijack git would write the generic
// spelling, which §3.2 deliberately allows and @claude inherits.
//
// This test asserts the CURRENT DECISION, not a guarantee: the generic three are
// accepted, the GIT_* spellings are refused. If someone later decides the
// generic three must go, this test fails and points at §3.2 — which is right,
// because that is a grant being withdrawn from every profile that inherits them
// and belongs in the design document, not in a table edit.
func TestForbidListDoesNotCloseTheExecClassForGit(t *testing.T) {
	for _, name := range []string{"EDITOR", "VISUAL", "PAGER"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "sh -c x"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v.\nThat may well be the right call, but it "+
				"is a §3.2 decision — those three are inherited by @claude — so make it there "+
				"and update this test deliberately", name, err)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err != nil {
			t.Errorf("environ.inherit %s was refused: %v. @claude inherits all three", name, err)
		}
	}
	// …while the invisible half stays refused. Without this the test above would
	// pass on a table with no git entries at all.
	for _, name := range []string{"GIT_EDITOR", "GIT_PAGER"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "sh -c x"}}); err == nil {
			t.Errorf("environ.set %s was accepted", name)
		}
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
