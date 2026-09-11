package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/gomoni/snug/internal/policy"
)

// TestEmptyDefaultsMeansEmpty pins the fix for a bug found while retiring the
// @null profile: `defaults = []` used to silently fall back to the built-in four,
// because Defaults was a plain []string and could not distinguish an explicit
// empty list from an absent key — both decode to len 0. Defaults is now
// *[]string precisely so the written intent survives decoding, in both
// directions.
func TestEmptyDefaultsMeansEmpty(t *testing.T) {
	// An explicit empty list must mean empty.
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "snug")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("defaults = []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	names, source := defaultProfiles()
	if len(names) != 0 {
		t.Errorf("defaults = [] resolved to %v, want empty — the written intent was silently widened", names)
	}
	if source == "built-in" {
		t.Errorf("defaults = [] reported its source as built-in, contradicting the file that set it")
	}

	// CONTROL, the other direction: an ABSENT key must still fall back to the
	// built-in four. Without this, "defaultProfiles returns empty" above could
	// mean the *[]string distinction broke the other way — every config now
	// resolving to nothing, which would make a bare `snug <dir>` grant nothing
	// on every host with no config file at all.
	absentDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", absentDir)
	names, source = defaultProfiles()
	if len(names) == 0 {
		t.Error("an absent config.toml resolved to an empty default selection; " +
			"a bare `snug <dir>` would grant nothing")
	}
	if source != "built-in" {
		t.Errorf("an absent config.toml should report its source as built-in, got %q", source)
	}
}

// TestUnreadableConfigIsFatal — a red team finding from the same round, and the same class
// as TestEmptyDefaultsMeansEmpty above: a parse error was fatal, a READ error
// was not. `chmod 000` on a file saying `defaults = []` returned the zero config
// and so widened the sandbox back to the built-in four, while `snug config`
// reported the source as "built-in" with os.Stat proving the file was there.
// Invariant 5: no silent downgrade.
//
// loadUserConfig exits the process on this path, so the assertion is on the
// helper that decides — os.IsNotExist is the ONLY non-fatal read error. A test
// that re-implemented the condition would prove nothing, so this one asserts
// the two errors are distinguishable and leaves the exit to the integration
// tier, which runs the real binary.
func TestOnlyAMissingConfigIsANonEvent(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "snug")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfgDir, "config.toml")
	if err := os.WriteFile(path, []byte("defaults = []\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: mode 000 is still readable, so this cannot be tested here")
	}

	_, err := os.ReadFile(path)
	if err == nil {
		t.Fatal("control: a mode-000 file was readable; the rest of this test proves nothing")
	}
	if os.IsNotExist(err) {
		t.Fatalf("an unreadable file reported as not-existing (%v); loadUserConfig would "+
			"treat it as 'no config file' and silently widen the sandbox", err)
	}

	// CONTROL, the other direction: a genuinely absent file MUST classify as
	// not-exist, or the fix turns every host without a config.toml into a hard
	// failure.
	_, err = os.ReadFile(filepath.Join(t.TempDir(), "config.toml"))
	if !os.IsNotExist(err) {
		t.Errorf("control: an absent config.toml classified as %v, want not-exist — "+
			"snug would refuse to start on every host that has no config file", err)
	}
}

// `snug profile show` must render ALL FIVE verbs.
//
// The line this replaced was `show("env", p.Env)`, which rendered one of the two
// keys that existed and never rendered `path` at all — so a profile putting a
// directory on the sandbox's PATH looked, on this screen, like a profile that
// granted nothing to the environment. A display that omits a grant is worse than
// no display, because it is read as complete.
//
// It is also half of §2.3's argument: the environment rules are checked at parse
// time so `snug profile show` can report a verdict with no target, and showing
// what it checked is the other half.
func TestProfileShowRendersEveryEnvironVerb(t *testing.T) {
	g := policy.EnvGrants{
		Set:      map[string]string{"XDG_DATA_HOME": "{home}/.local/share"},
		Merge:    map[string][]string{"PATH": {"{home}/.local/bin", "/opt/tools/bin"}},
		Prepend:  map[string][]string{"PATH": {"/opt/first/bin"}},
		Inherit:  []string{"EDITOR"},
		Sanitise: []string{"PKG_CONFIG_PATH"},
	}
	got := map[string][]string{}
	showEnviron(g, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	want := map[string]string{
		// The prefix is the TOML's own spelling. Bare "set" and "merge" sit
		// directly under "ro" and "tmpfs" on this screen and read as two more
		// kinds of filesystem grant.
		"environ.set":      "XDG_DATA_HOME = {home}/.local/share",
		"environ.merge":    "PATH = {home}/.local/bin /opt/tools/bin",
		"environ.prepend":  "PATH = /opt/first/bin",
		"environ.inherit":  "EDITOR",
		"environ.sanitise": "PKG_CONFIG_PATH",
	}
	// PREFIX, not equality: a row may carry marks after the grant it renders —
	// `← unchecked` for a name with no roster row, and since the annotation flip
	// a sentence saying what the tool DOES with the value (EDITOR is inherited
	// here and git runs whatever it names). What this test is about is that every
	// verb renders its grant at all, so it asserts the grant is the START of the
	// line and leaves the marks to the tests that own them
	// (TestProfileShowMarksAnUnrosteredNameAsUnchecked,
	// TestProfileShowRendersTheAnnotation).
	for label, first := range want {
		vals, ok := got[label]
		if !ok {
			t.Errorf("%s was not rendered at all — a profile using it would look, on this "+
				"screen, like a profile that granted nothing to the environment", label)
			continue
		}
		if !strings.HasPrefix(vals[0], first) {
			t.Errorf("%s rendered %q, want it to start with %q", label, vals[0], first)
		}
	}

	// NEGATIVE CONTROL: a verb nobody used must not print an empty heading, or
	// the reader learns to skim the block.
	if len(got) != len(want) {
		t.Errorf("rendered %d verbs, want exactly %d: %v", len(got), len(want), got)
	}
}

// showIdentity renders TWO rows once signing_key is pinned — the ssh_key row
// this screen already had, and a new "signing key" row — because the two are
// separate grants (CLAUDE.md's abuse-sentence rule: signing does not imply
// push and push does not imply signing) and a screen that folded them into
// one row would read as one grant to the human deciding whether to select
// this profile.
func TestShowIdentityRendersTheSigningKey(t *testing.T) {
	id := &policy.Identity{
		SSHMode:    policy.SSHAgentProxy,
		SSHKey:     "{home}/.ssh/id_ed25519.pub",
		SigningKey: "{home}/.ssh/id_ed25519_signing.pub",
	}
	var rows []string
	showIdentity(id, func(label string, vals []string) {
		rows = append(rows, label+" "+strings.Join(vals, " "))
	})
	joined := strings.Join(rows, "\n")

	if !strings.Contains(joined, "{home}/.ssh/id_ed25519.pub") {
		t.Errorf("the ssh_key row is missing:\n%s", joined)
	}
	if !strings.Contains(joined, "{home}/.ssh/id_ed25519_signing.pub") {
		t.Errorf("the signing key row is missing:\n%s", joined)
	}
	// The consequence sentence, not a parenthetical. showIdentity was the only
	// member of showCapabilities that did not use capRows, so the grant whose
	// base.toml ABUSE line reads "SIGN COMMITS AND TAGS AS YOU" got four words
	// in brackets while `listen_names` got "THIS IS A SANDBOX ESCAPE" — a hole
	// that did not look like one. Found by the red team.
	if !strings.Contains(joined, "SIGN COMMITS AND TAGS AS YOU") {
		t.Errorf("the signing key row does not say what it is FOR, unlike every other "+
			"capability row on this screen:\n%s", joined)
	}
	if !strings.Contains(joined, "THE SANDBOX CAN ACT AS THIS ACCOUNT") {
		t.Errorf("the ssh_key row lost its consequence sentence:\n%s", joined)
	}
}

// A config.toml that will not decode used to print go-toml's bare
// *StrictMissingError.Error() — "strict mode: fields in the document are
// missing in the target struct" — and nothing else: no line, no key, no
// suggestion. Issue #558 reported it against a config.toml holding a
// [profile.npm] table, where the sentence names neither the mistake nor the
// file the table belongs in.
//
// The assertions are on configDecodeMessage rather than loadUserConfig because
// that function exits the process. The fixture is #558's config verbatim.
func TestConfigDecodeMessageNamesTheKeyAndTheFix(t *testing.T) {
	const reported = `defaults = ["@sys", "@home", "@net", "@cwd-rw", "@git-ro"]

[profile.npm]
description = "Share npm directory from home."
ro = ["{home}/.npm-packages:{home}/.npm-host"]

[profile.npm.environ.merge]
PATH = ["{home}/.npm-host/bin"]
`
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader(reported))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("control: the reported config decoded; the rest of this test proves nothing")
	}

	msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
	for _, want := range []string{
		// The path, so a reader with several config files knows which one.
		"/home/u/.config/snug/config.toml",
		// The position. This is the whole of what the old message lacked.
		"3| [profile.npm]",
		// Both accepted keys, because there are only two and listing them is
		// the cheapest possible "what did you mean".
		"defaults", "tmpfs_size",
		// The category error: the table is not misspelled, it is in the wrong
		// file, and no caret says that.
		"/home/u/.config/snug/profiles.d/*.toml",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not contain %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "strict mode: fields in the document") {
		t.Errorf("message still carries go-toml's positionless sentence:\n%s", msg)
	}
}

// The control, and it is the half that keeps the test above honest: an ordinary
// misspelled key gets the caret and the key list, and must NOT get the
// profiles.d line — that sentence is advice about a different mistake, and
// printing it for every typo would make it noise.
func TestConfigDecodeMessageDoesNotMentionProfilesDirForAPlainTypo(t *testing.T) {
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader("tmpfs_size_mb = 512\n"))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("control: tmpfs_size_mb decoded, so it is not an unknown key")
	}

	msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
	if !strings.Contains(msg, "1| tmpfs_size_mb = 512") {
		t.Errorf("message does not point at the misspelled key:\n%s", msg)
	}
	if !strings.Contains(msg, "tmpfs_size") {
		t.Errorf("message does not name the spelling that works:\n%s", msg)
	}
	if strings.Contains(msg, "profiles.d") {
		t.Errorf("a misspelled scalar was told to go and write a profile file:\n%s", msg)
	}
}

// Everything that is NOT a strict-mode error — a syntax error, an incomplete
// array — gets go-toml's numbered-source-and-caret rendering and nothing else.
// snug has no fix to name for a syntax error, and the caret is the position
// the bare Error() string does not carry.
func TestConfigDecodeMessagePassesThroughNonStrictErrors(t *testing.T) {
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader("defaults = [\n"))
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("control: an unterminated array decoded")
	}

	msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
	if !strings.Contains(msg, "1| defaults = [") {
		t.Errorf("message does not quote the offending line:\n%s", msg)
	}
	// go-toml's own sentence, minus the "toml: " prefix its Error() adds and
	// its String() does not.
	if !strings.Contains(msg, "array is incomplete") {
		t.Errorf("message dropped go-toml's own text %q:\n%s", err.Error(), msg)
	}
	if strings.Contains(msg, "accepts two keys") {
		t.Errorf("a syntax error was answered with the unknown-key advice:\n%s", msg)
	}
}

// A value the file DOES reach, refused by policy.ParseSize rather than by the
// decoder's own type check. go-toml hands the raw scalar text to
// tomlSize.UnmarshalText, so `tmpfs_size = 512` and `tmpfs_size = "512"` are
// the same refusal — but only the string form comes back wrapped in a
// *toml.DecodeError, so only that one can be quoted with a caret. The
// positionless forms still carry the advice, which is the half that names the
// fix.
func TestConfigDecodeMessageCarriesAParseSizeRefusal(t *testing.T) {
	cases := []struct {
		line  string
		quote bool
	}{
		{`tmpfs_size = "512"`, true},
		{`tmpfs_size = "4 GB!"`, true},
		{`tmpfs_size = 512`, false},
		{`tmpfs_size = true`, false},
	}
	for _, tc := range cases {
		var cfg userConfig
		dec := toml.NewDecoder(strings.NewReader(tc.line + "\n"))
		dec.DisallowUnknownFields()
		err := dec.Decode(&cfg)
		if err == nil {
			t.Fatalf("control: %s decoded", tc.line)
		}
		msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
		if tc.quote && !strings.Contains(msg, "1| "+tc.line) {
			t.Errorf("%s: message does not quote the offending line:\n%s", tc.line, msg)
		}
		if !strings.Contains(msg, `as in "512 MiB"`) {
			t.Errorf("%s: message does not name a value that works:\n%s", tc.line, msg)
		}
		if strings.Contains(msg, "accepts two keys") {
			t.Errorf("%s: a bad VALUE was answered with the unknown-KEY advice:\n%s", tc.line, msg)
		}
	}
}

// The trap that made tomlSize a struct, as a regression test. go-toml writes a
// TOML integer straight into a uint64-kinded field without calling its
// UnmarshalText: with the config field typed policy.Size directly,
// `tmpfs_size = 512` decoded to 512 BYTES and started a sandbox with a
// 512-byte tmpfs on every KindTmpfs mount. The reader who writes that line is
// the reader migrating from tmpfs_size_mib = 512, which is exactly who must
// not get it silently.
func TestABareIntegerTmpfsSizeIsRefusedRatherThanReadAsBytes(t *testing.T) {
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader("tmpfs_size = 512\n"))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatalf("tmpfs_size = 512 decoded to %d bytes; a bare integer has no unit",
			uint64(cfg.TmpfsSize.Size))
	}
	if !strings.Contains(err.Error(), "no unit") {
		t.Errorf("refusal does not say what is missing: %v", err)
	}
}

// tmpfs_size_mib is not a typo — it is the key snug used to have, and a file
// carrying it was correct until this change. The caret alone says "unknown
// key", which reads as "this setting is gone" when the setting is still here
// under a name that carries its own unit.
func TestConfigDecodeMessageNamesTheReplacementForTmpfsSizeMiB(t *testing.T) {
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader("tmpfs_size_mib = 512\n"))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("control: tmpfs_size_mib decoded, so it is still a key")
	}

	msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
	if !strings.Contains(msg, "tmpfs_size_mib is gone") {
		t.Errorf("message does not say the old key is gone:\n%s", msg)
	}
	if !strings.Contains(msg, `tmpfs_size = "512 MiB"`) {
		t.Errorf("message does not show what to write instead:\n%s", msg)
	}
	if strings.Contains(msg, "profiles.d") {
		t.Errorf("a retired scalar key was told to go and write a profile file:\n%s", msg)
	}
}

// A TOML TABLE at tmpfs_size decodes clean — go-toml allocates the struct and
// calls nothing — so the zero check downstream cannot tell it from a written
// zero, and used to quote `tmpfs_size = "0 B"` back at an author who wrote no
// such thing. tomlSize.text is what separates the two.
func TestATomlTableAtTmpfsSizeDecodesWithoutText(t *testing.T) {
	for _, src := range []string{"[tmpfs_size]\n", "tmpfs_size = {}\n"} {
		var cfg userConfig
		dec := toml.NewDecoder(strings.NewReader(src))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			t.Fatalf("%q: control: a table at tmpfs_size is expected to decode, got %v", src, err)
		}
		if cfg.TmpfsSize == nil {
			t.Fatalf("%q: control: a table at tmpfs_size left the field nil, so nothing "+
				"downstream would look at it", src)
		}
		if cfg.TmpfsSize.text {
			t.Errorf("%q: tmpfs_size reports that UnmarshalText ran; it did not", src)
		}
		if uint64(cfg.TmpfsSize.Size) != 0 {
			t.Errorf("%q: tmpfs_size decoded to %d", src, uint64(cfg.TmpfsSize.Size))
		}
	}
}

// The message carries config-file text, and $XDG_CONFIG_HOME can point into a
// hostile checkout (CLAUDE.md invariant 3) — so the file's author must not be
// able to move the cursor, erase a row or reverse the reading order of the
// screen that refuses their file (the issue #20 shape, one file over).
func TestConfigDecodeMessageEscapesControlCharactersFromTheFile(t *testing.T) {
	sources := []string{
		"tmpfs_size = \"512 \u001b[1AmiB\"\n",
		"\"k\u009b31m\" = 1\n",
		"\"k\u202eevil\" = 1\n",
		"defaults = [\"@sys\u001b[2K\"]\nbad = 1\n",
	}
	for _, src := range sources {
		var cfg userConfig
		dec := toml.NewDecoder(strings.NewReader(src))
		dec.DisallowUnknownFields()
		err := dec.Decode(&cfg)
		if err == nil {
			t.Fatalf("control: %q decoded", src)
		}
		msg := configDecodeMessage("/home/u/.config/snug/config.toml", err)
		for i, r := range msg {
			switch {
			case r == '\n' || r == '\t':
			case r < 0x20 || r == 0x7f:
				t.Errorf("%q: message carries raw control %U at byte %d:\n%q", src, r, i, msg)
			case r >= 0x80 && r <= 0x9f, r == '\u2028', r == '\u2029', r == '\u202e':
				t.Errorf("%q: message carries raw %U at byte %d:\n%q", src, r, i, msg)
			}
		}
	}
}

// go-toml renders a fresh numbered excerpt per unknown key, so the message
// grew with the number of bad keys in an attacker-influenced file: a 256001-
// byte config.toml of 29679 unknown keys rendered 5966021 bytes of stderr.
// The bound has to hold on the SHAPE, not on one measured file.
func TestConfigDecodeMessageIsBoundedForManyUnknownKeys(t *testing.T) {
	var few, many string
	for i := range 4000 {
		line := fmt.Sprintf("k%d = 1\n", i)
		if i < 3 {
			few += line
		}
		many += line
	}
	size := func(src string) int {
		var cfg userConfig
		dec := toml.NewDecoder(strings.NewReader(src))
		dec.DisallowUnknownFields()
		err := dec.Decode(&cfg)
		if err == nil {
			t.Fatal("control: a file of unknown keys decoded")
		}
		return len(configDecodeMessage("/home/u/.config/snug/config.toml", err))
	}
	// The excerpts are capped, but each one quotes the lines AROUND its key,
	// and those lines are longer in the bigger file (k3999 vs k2). So the
	// message may grow a little; what it must not do is grow with the KEY
	// COUNT. Twice the small message is far below the 1000x the key count
	// grew by.
	small, big := size(few), size(many)
	if big > 2*small {
		t.Errorf("4000 unknown keys rendered %d bytes against %d for 3; the message tracks "+
			"the key count", big, small)
	}
	if !strings.Contains(size2(t, many), "more unknown key(s) not shown") {
		t.Error("the message does not say how many keys it did not show")
	}
}

// size2 is TestConfigDecodeMessageIsBoundedForManyUnknownKeys' second look at
// the same message, kept separate so the length assertion above reads as one
// expression.
func size2(t *testing.T, src string) string {
	t.Helper()
	var cfg userConfig
	dec := toml.NewDecoder(strings.NewReader(src))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("control: a file of unknown keys decoded")
	}
	return configDecodeMessage("/home/u/.config/snug/config.toml", err)
}
