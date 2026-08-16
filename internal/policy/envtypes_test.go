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
		// §1.2's worked @claude. ANTHROPIC_API_KEY has no roster row and is
		// carried anyway — which is the case a user profile exists for: a
		// profile inheriting its own tool's SECRET must not have to write the
		// secret into the profile file, so `inherit` takes the name and the
		// value still comes from the host. Its row renders `← unchecked`.
		{"inherit scalars", EnvGrants{
			Inherit: []string{"ANTHROPIC_API_KEY", "EDITOR", "NO_COLOR"}}},
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
		// A name snug has no roster row for. It is a scalar, because `set`
		// writes the whole value and needs no fact about the name to do it —
		// what issue #44 changed is that the row now says so on every screen
		// (`← unchecked`) instead of the type table silently reporting a type
		// it does not have. The LIST verbs are the ones that need the fact, and
		// they refuse it: TestUnrosteredNameIsRefusedAtEveryListVerb.
		{"unrostered name as a scalar", EnvGrants{
			Set: map[string]string{"MY_TOOL_MODE": "fast"}}},
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

// THE INVERSION, and it is the whole of this change: every assertion in this
// section used to read "environ.<verb> NAME was accepted" as a FAILURE. snug has
// only allowlists, so those refusals are annotations now — the property being
// measured is no longer "a profile cannot do this" but "a profile can do this
// and the screen says what it does".
//
// The split by verb survived the inversion and is what this test still exists
// for. A `set` carries a value from a reviewed file in the trusted profile
// layer; an `inherit` carries whatever the process that launched snug happened
// to have. inherit is a hole punched in --clearenv; set is not (CALL 4, §2.1).
// While one of the two was refused, that difference was visible for free. Now
// that neither is, the difference IS the sentence — so a note table that
// flattened to one string per name would silently lose it, and the middle-bucket
// loop below is what notices.
func TestAnnotationSplitsBySetAndInherit(t *testing.T) {
	// The old middle bucket: legal at both verbs, annotated at both, and the two
	// sentences must DIFFER. `BASH_ENV = "{home}/init"` written in a profile that
	// also grants the path is a different proposition from taking whatever the
	// host had, and the reader is owed both halves.
	for _, name := range []string{"BASH_ENV", "ENV",
		"PYTHONSTARTUP", "PYTHONBREAKPOINT", "LESSOPEN"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "{home}/x"}}); err != nil {
			t.Errorf("environ.set %s should be legal — a reviewed profile naming a path it "+
				"also grants is exactly what the format is for: %v", name, err)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err != nil {
			t.Errorf("environ.inherit %s was refused: %v. It carries a hole punched straight "+
				"through --clearenv, and the answer to that is the sentence on the screen, not "+
				"a refusal of the human who wrote the profile", name, err)
		}
		set, inherit := EnvNote(name, VerbSet), EnvNote(name, VerbInherit)
		if set == "" || inherit == "" {
			t.Errorf("%s is annotated at neither or only one verb (set=%q inherit=%q); it names "+
				"a file a tool sources or executes and a human reading --dry-run has to be told",
				name, set, inherit)
		}
		if set == inherit {
			t.Errorf("%s renders the identical sentence at set and inherit (%q). That erases the "+
				"one thing forbidKind used to carry: WHERE THE VALUE CAME FROM. The inherit "+
				"sentence must say the file is chosen on the host, outside any profile", name, set)
		}
	}

	// And the names that used to be refused at BOTH verbs, because the value is
	// code wherever it came from. They are accepted at both now, and annotated at
	// both — one sentence, rendered twice, which is what `both()` is for.
	for _, name := range []string{"LD_AUDIT", "GCONV_PATH", "TZDIR",
		"GIT_SSH_COMMAND", "GIT_EXEC_PATH", "PROMPT_COMMAND", "PS4",
		// Reached by a redteam run: GIT_SSH hijacked `git fetch` in a sandbox
		// whose ssh identity a different profile had pinned, while
		// GIT_SSH_COMMAND was refused. The rule was "the value is code", not
		// "the newest spelling" — and now that neither is refused, the rule is
		// "the value is code, so SAY SO at every spelling". A missing sentence
		// is the modern shape of that same defect.
		"GIT_SSH", "GIT_PROXY_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS",
		"GIT_SEQUENCE_EDITOR", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
		"JDK_JAVA_OPTIONS", "RUBYOPT",
		// Found missing by an independent review, each measured on git 2.55
		// before being added. Three shapes, and the spread is why the class is
		// "the value is code" rather than "the value is a command":
		//   GIT_PAGER          — a command, exactly like GIT_EDITOR
		//   GIT_TEMPLATE_DIR   — a directory whose hooks are installed into
		//                        every repo `git clone`/`git init` creates
		//   GIT_DIR            — a repository whose hooks run on the next commit
		//   GIT_ALLOW_PROTOCOL — no code at all: it switches OFF git's refusal
		//   GIT_PROTOCOL_FROM_USER  of ext::, which runs an arbitrary command
		"GIT_PAGER", "GIT_TEMPLATE_DIR", "GIT_DIR",
		"GIT_ALLOW_PROTOCOL", "GIT_PROTOCOL_FROM_USER",
		// Confirmed end to end by redteam during the issue #26 follow-up:
		// `RUSTC_WRAPPER=./wrap.sh cargo build` ran wrap.sh in place of rustc, as
		// the sandbox's own uid. RUSTC and RUSTC_WORKSPACE_WRAPPER carry the
		// identical capability, and it is the same one CARGO_BUILD_RUSTC_WRAPPER
		// reaches through the CARGO_ prefix — which is why all three are named
		// here as well as covered there.
		"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC",
		// Second-pass red team review, not reasoning ahead of time — the space
		// of "an env var some tool turns into exec" is unbounded and each of
		// these was found only by trying it:
		//
		//   MAKEFLAGS="--eval=x:;$(shell ./evil.sh)"  make       -> evil.sh ran  (GNU make 4.x)
		//   GOFLAGS="-toolexec=/…/toolexec.sh"        go build   -> ran per compile (go 1.26)
		//   CC=./evil.sh                              make       -> ran as the compiler, via
		//                                                           make's implicit rules
		//   TAR_OPTIONS="--use-compress-program=/…/prog.sh" tar  -> prog.sh ran  (GNU tar 1.35)
		//   RSYNC_RSH=/…/prog.sh                      rsync      -> prog.sh ran  (rsync 3.4.3)
		//   GIT_COMMON_DIR=<attacker path>             git       -> hooks/pre-commit there ran
		//                                                           on the next commit (git 2.55)
		"MAKEFLAGS", "CC", "TAR_OPTIONS", "RSYNC_RSH", "GIT_COMMON_DIR",
		// The interpreter-hook class, one layer down:
		//
		//   PYTHONUSERBASE=…  python3 -c 'import site'
		//     -> …/site-packages/usercustomize.py ran on every python3  (CPython 3.13)
		//   NODE_OPTIONS="--require /…/pre.js"  node ...
		//     -> pre.js ran before the script, every invocation           (node 26)
		//   PERL5OPT="-I/… -Mevil"  perl ...
		//     -> evil.pm loaded on every perl invocation                  (perl 5)
		"PERL5OPT", "NODE_OPTIONS", "PYTHONUSERBASE"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v — a human's own profile may hand this to "+
				"the payload; what snug owes is the sentence, not a veto", name, err)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err != nil {
			t.Errorf("environ.inherit %s was refused: %v", name, err)
		}
		set, inherit := EnvNote(name, VerbSet), EnvNote(name, VerbInherit)
		if set == "" || inherit == "" {
			t.Errorf("%s carries no annotation at set=%q inherit=%q. This name's VALUE IS CODE, "+
				"measured — with no refusal left, an unannotated row is snug handing over an "+
				"exec vector and saying nothing at all", name, set, inherit)
		}
		if set != inherit {
			t.Errorf("%s says different things at set and inherit (%q vs %q). The value is code "+
				"wherever it came from, so this name should use both() — a per-verb split here "+
				"invites a reader to think one verb is the safe one", name, set, inherit)
		}
	}

	// LD_PRELOAD, LD_LIBRARY_PATH, CDPATH, GOFLAGS and PYTHONPATH are NOT in the
	// loop above, and the reason is the distinction this whole change rests on.
	// They are LISTS the roster marks neither mergeable nor sanitisable (except
	// PYTHONPATH, which is mergeable), so what refuses them is a TYPE verdict —
	// snug declining an operation it cannot perform correctly — and that survived
	// the flip untouched. Asserting it here is what keeps "nothing refuses a name
	// any more" from being read as "nothing refuses anything".
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "CDPATH", "GOFLAGS"} {
		for _, g := range []EnvGrants{
			{Set: map[string]string{name: "/x"}},
			{Inherit: []string{name}},
			{Merge: map[string][]string{name: {"/x"}}},
			{Sanitise: []string{name}},
		} {
			if err := ValidateEnvGrants(g); err == nil {
				t.Errorf("%s was accepted at %+v. It is a list whose elements do not compose, so "+
					"every verb is refused on TYPE grounds — that is snug saying it cannot carry "+
					"out the operation, which is not the same thing as a denylist and must not "+
					"have been removed with one", name, g)
			}
		}
	}
	// PYTHONPATH is the one name whose reach genuinely widened: it is mergeable,
	// and forbidBoth used to refuse merge/prepend on it as a side effect of
	// refusing the name. Stated as an assertion rather than left to be
	// discovered, because it is the only new LIST-verb capability in this change.
	if err := ValidateEnvGrants(EnvGrants{Merge: map[string][]string{"PYTHONPATH": {"/opt/py"}}}); err != nil {
		t.Errorf("environ.merge PYTHONPATH was refused: %v — it is a mergeable list, and what "+
			"used to refuse it was the forbidden-name table rather than its type", err)
	}
	if EnvNote("PYTHONPATH", VerbMerge) == "" {
		t.Error("environ.merge PYTHONPATH carries no annotation, and it is the one list verb this " +
			"change opened: python runs sitecustomize.py from ANY element at interpreter start")
	}

	// PIP_* and npm_config_* are the prefix half of the same split: the host's
	// environment outranks the config FILE those tools read (§4.5), which is an
	// argument about inherit, not about set. A POINTER is the opposite shape at
	// that verb — authoring it is the mechanism "generate, don't bind" asks for —
	// so it carries no FAMILY sentence at `set`.
	//
	// IT USED TO CARRY NOTHING AT ALL AT `set`, AND THIS LOOP ASSERTED THAT.
	// The argument was that a pointer "is the mechanism, not the hazard", which
	// is true of the mechanism and says nothing about where the pointer is
	// AIMED — and nothing enforces "at a file the profile authored": the coupling
	// rule asks only that the path be granted, and `rw = ["{target}"]` is a
	// grant. Measured, one profile, all five names inside the target:
	//
	//	CARGO_HOME/config.toml   build.rustc-wrapper    -> ran, cargo 1.97.1, uid 1000
	//	DOCKER_CONFIG/config.json {"credsStore":"evil"} -> helper ran on `docker pull`
	//	GIT_CONFIG_SYSTEM        alias/core.sshCommand  -> ran, git 2.55.0
	//
	// So the test changed with the model rather than the other way round: a
	// pointer must SAY WHAT ITS FILE IS at the authored verb, and must not say it
	// in the family's words.
	for _, name := range []string{"PIP_CONFIG_FILE", "CARGO_HOME", "NPM_CONFIG_USERCONFIG",
		"DOCKER_CONFIG", "GIT_CONFIG_SYSTEM"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "{home}/x"}}); err != nil {
			t.Errorf("environ.set %s is \"generate, don't bind\" written down: %v", name, err)
		}
		got := EnvNote(name, VerbSet)
		if got == "" {
			t.Errorf("environ.set %s carries no annotation. A pointer aimed at ground the payload "+
				"can write is one config file from exec as the sandbox's own uid, measured — and "+
				"the exemption it inherits from its prefix is an exemption from the FAMILY "+
				"sentence, not a licence to say nothing", name)
		}
		if strings.Contains(got, "*:") {
			t.Errorf("environ.set %s renders the FAMILY sentence %q. Authoring a pointer is the "+
				"RECOMMENDED mechanism; warning about it in the words written for its "+
				"setting-valued siblings is snug arguing with its own rule", name, got)
		}
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err != nil {
			t.Errorf("environ.inherit %s was refused: %v — this was `noInherit`, a permission bit "+
				"inside the roster, and it is an annotation now", name, err)
		}
		if EnvNote(name, VerbInherit) == "" {
			t.Errorf("environ.inherit %s carries no annotation. The host's value points the tool "+
				"back at the host's own config — the exact file \"generate, don't bind\" exists "+
				"to avoid — and the sentence saying so was the `noInherit` refusal's whole "+
				"content. It must not have evaporated with the bit", name)
		}
	}

	// THE XDG BASE DIRECTORIES ARE SILENT AT `set`, AND THAT IS A DECISION WITH A
	// MEASUREMENT BEHIND IT — issue #84, deferred deliberately rather than
	// forgotten. They are pointers in the same sense, and two of them are
	// measured exec surfaces: git reads a command table from
	// $XDG_CONFIG_HOME/git/config (alias `!cmd` ran as uid 1000, core.sshCommand
	// was EXECUTED as the transport — git 2.55.0, with ~/.gitconfig present, and
	// with GIT_CONFIG_GLOBAL unset, which suppresses it and produced a false
	// negative on the first attempt), and bash-completion SOURCES
	// $XDG_DATA_HOME/bash-completion/completions/<cmd> (bash-completion 2.12.0,
	// with the control).
	//
	// They are still silent because @home `set`s all four on every default run,
	// to its own writable tmpfs, and it has no alternative: an XDG base directory
	// must be writable, so the advice a pointer sentence carries — aim it where
	// the payload cannot write — is one @home structurally cannot take. The
	// hazard is the writable tmpfs, which the FILESYSTEM block already shows, so
	// the mark would attach to the wrong grant and fire on the most ordinary run
	// there is. Two of the four have no measured exec surface at all, so a
	// uniform XDG annotation would additionally be half unmeasured, in the table
	// F4 is about.
	//
	// cmd/snug/testdata/env.defaults.txt staying unchanged is the review artifact
	// for that decision. If it ever grows an XDG mark, this loop is the other
	// thing that has to change, and the argument above is what has to be answered.
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
		"XDG_DATA_HOME", "XDG_RUNTIME_DIR"} {
		if got := EnvNote(name, VerbSet); got != "" {
			t.Errorf("environ.set %s is annotated %q. That is issue #84 and it is deferred: "+
				"@home sets all four on every default run and cannot aim them anywhere "+
				"unwritable, so this fires on the most ordinary screen snug draws. If the "+
				"decision has been reversed, say so in #84 and in env.defaults.txt's comment "+
				"rather than here", name, got)
		}
		if EnvNote(name, VerbInherit) == "" {
			t.Errorf("environ.inherit %s carries no annotation; the host's value names a "+
				"directory this sandbox does not have", name)
		}
	}

	// NPM_CONFIG_SCRIPT_SHELL, in every case a human or npm's own env-loader
	// might spell it. The thing under test is that all three spellings agree,
	// which no other entry exercises — and it is now agreement about the
	// SENTENCE, which is the only thing left that can differ.
	for _, name := range []string{"npm_config_script_shell", "NPM_CONFIG_SCRIPT_SHELL", "Npm_Config_Script_Shell"} {
		for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
			if EnvNote(name, verb) == "" {
				t.Errorf("EnvNote(%s, %s) is empty; npm 10.9.8 honours this spelling exactly like "+
					"npm_config_script_shell, so the row hands over the shell npm runs lifecycle "+
					"scripts with and says nothing about it. This is the measured defect "+
					"prefixCaseFold exists to prevent, met one table further on", name, verb)
			}
		}
	}
	// NPM_CONFIG_USERCONFIG is npm_config_'s pointer, and EVERY SPELLING npm's own
	// case-insensitive rule reaches must say the same thing at every verb. At
	// `set` that is the exact `authored` sentence about the file it names, never
	// the FAMILY sentence — authoring a pointer is the point. At `inherit` the
	// exemption deliberately does not apply.
	//
	// THIS LOOP HAS NOW CAUGHT THE SAME DEFECT TWICE, in opposite directions.
	// First: a case-insensitive prefix's exemption applied to EVERY verb and fell
	// back to envTypes' noInherit flag (an exact-case lookup) to still catch
	// inherit, so `environ.inherit npm_config_userconfig` slipped through while
	// the canonical spelling did not. Then, in the commit that gave the pointers
	// their `authored` sentence: envNotes is an exact map, so the canonical
	// spelling said what the file was and the folded one — exempted from its
	// family, missing from the exact table — said nothing at all. noteExact is
	// the fix, and it is the roster's own fold rule applied one table over.
	want := map[EnvVerb]string{
		VerbSet:     EnvNote("NPM_CONFIG_USERCONFIG", VerbSet),
		VerbInherit: EnvNote("NPM_CONFIG_USERCONFIG", VerbInherit),
	}
	for verb, s := range want {
		if s == "" {
			t.Fatalf("fixture: NPM_CONFIG_USERCONFIG says nothing at %s, so the spellings below "+
				"would be compared against nothing", verb)
		}
	}
	for _, name := range []string{"NPM_CONFIG_USERCONFIG", "npm_config_userconfig", "Npm_Config_Userconfig"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "{home}/.npmrc"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v", name, err)
		}
		for verb, s := range want {
			if got := EnvNote(name, verb); got != s {
				t.Errorf("EnvNote(%s, %s) = %q, want the canonical spelling's %q. npm honours all "+
					"three spellings identically, so a reader who writes one of them and a "+
					"reader who writes another must be told the same thing", name, verb, got, s)
			}
		}
		if strings.Contains(EnvNote(name, VerbSet), "*:") {
			t.Errorf("environ.set %s renders the FAMILY sentence — the pointer exemption must "+
				"hold in every case spelling npm itself honours, or the fix for the false "+
				"negative becomes a warning against the one name snug needs to author", name)
		}
	}
}

// The property the whole class of defect in this test file collapses to:
// whether snug has something to SAY about environ.inherit of a name and whether
// IsInlineConfigEnv calls that name inline config must be the SAME QUESTION,
// because both exist for the same reason — the host's value for a
// config-surface variable outranks the file snug generates. Two tables each
// holding an independent copy of "does this tool's lookup fold case" is
// exactly how they drifted apart before this test existed: NPM_CONFIG_
// SCRIPT_SHELL was accepted by environ.inherit with nothing said about it while
// IsInlineConfigEnv already called it true. Since envNotePrefixes and
// inlineConfigPrefixes both now read the single prefixCaseFold table, the two
// answers should be identical BY CONSTRUCTION for every prefix and every case
// spelling — this test is what notices if a future edit gives either table its
// own copy of the case rule again, which is the only way they can disagree.
//
// It used to compare "does ValidateEnvGrants refuse it" against the predicate.
// That comparison is gone with the refusal, and the replacement is strictly
// stronger: it holds at EVERY verb, not only at inherit, because an annotation
// exists at every verb where a refusal only ever existed at one.
//
// It does not hard-code an expected true/false per spelling — that would pin
// TODAY's case rule, which the case-rule tests in cmd/snug already do per
// measurement. What this pins is AGREEMENT: whatever prefixCaseFold says for
// a prefix, both consumers must land on the same verdict for every case
// variant of a name under it.
func TestPrefixAnnotationsAndInlineConfigAgreeOnCase(t *testing.T) {
	annotated := make(map[string]bool, len(envNotePrefixes))
	for _, p := range envNotePrefixes {
		annotated[p.prefix] = true
	}

	for _, prefix := range inlineConfigPrefixes {
		if !annotated[prefix] {
			t.Fatalf("inlineConfigPrefixes names %q, which envNotePrefixes says nothing about — "+
				"IsInlineConfigEnv would call a name inline config while --dry-run hands it over "+
				"with no sentence at all", prefix)
		}

		// Four spellings of the same probe name: canonical (the prefix as
		// written in the table), all-lower, all-upper, and case-toggled. None
		// of these strings collides with any pointer exemption (GIT_CONFIG_
		// GLOBAL/SYSTEM, NPM_CONFIG_USERCONFIG, PIP_CONFIG_FILE, CARGO_HOME)
		// or the CARGO_ prefix's own exempt list, so a disagreement below can
		// only come from the two tables reading DIFFERENT case rules.
		suffix := "ZZPROBE"
		spellings := []string{
			prefix + suffix,
			strings.ToLower(prefix) + strings.ToLower(suffix),
			strings.ToUpper(prefix) + strings.ToUpper(suffix),
			toggleCase(prefix) + toggleCase(suffix),
		}
		for _, name := range spellings {
			inline := IsInlineConfigEnv(name)
			for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
				if got := EnvNote(name, verb) != ""; got != inline {
					t.Errorf("prefix %q, spelling %q, verb %s: annotated=%v, "+
						"IsInlineConfigEnv=%v — these must agree, or a profile hands over exactly "+
						"the class of variable the predicate exists to name as inline config and "+
						"the screen says nothing about it", prefix, name, verb, got, inline)
				}
			}
		}
	}
}

// The prefix must be NAMED in what the reader sees, and in its canonical
// spelling even where the match folded case.
//
// A row reading `← the dynamic loader reads this before main()` on LD_TRACE_X
// cannot be told apart from a sentence snug measured about LD_TRACE_X itself,
// and the difference matters: one is a fact about this variable, the other is a
// fact about a family this variable happens to be in. The canonical spelling is
// load-bearing for the case-folding families — a note reading `npm_config_*`
// when the profile wrote `NPM_CONFIG_FOO` is telling the reader which rule
// matched, and rendering the profile's own spelling instead would make the
// annotation text a third copy of a case fact this file has already watched
// drift twice.
func TestPrefixAnnotationNamesThePrefixCanonically(t *testing.T) {
	cases := []struct{ name, want string }{
		{"LD_TRACE_LOADED_OBJECTS", "LD_*:"},
		{"BASH_FUNC_build", "BASH_FUNC_*:"},
		{"GIT_CONFIG_KEY_0", "GIT_CONFIG_*:"},
		{"PIP_INDEX_URL", "PIP_*:"},
		{"CARGO_BUILD_RUSTC_WRAPPER", "CARGO_*:"},
		// The folded family: three spellings, one canonical label.
		{"npm_config_script_shell", "npm_config_*:"},
		{"NPM_CONFIG_SCRIPT_SHELL", "npm_config_*:"},
		{"Npm_Config_Script_Shell", "npm_config_*:"},
	}
	for _, tc := range cases {
		got := EnvNote(tc.name, VerbSet)
		if !strings.Contains(got, tc.want) {
			t.Errorf("EnvNote(%s, set) = %q, want it to name %s — a reader cannot otherwise tell "+
				"whether snug measured this name or its family", tc.name, got, tc.want)
		}
	}
	// The control: an EXACT entry must NOT wear a family label, or the
	// distinction the test above draws is decoration.
	if got := EnvNote("RUSTC_WRAPPER", VerbSet); strings.Contains(got, "*:") {
		t.Errorf("EnvNote(RUSTC_WRAPPER, set) = %q, which reads as a family note. RUSTC_WRAPPER "+
			"was measured by name — cargo runs it in place of rustc — and the sentence should "+
			"say so without a prefix label", got)
	}
}

// toggleCase flips the case of every ASCII letter, so "npm_config_" becomes
// "NPM_CONFIG_" and "GIT_CONFIG_" becomes "git_config_" — the two spellings
// most likely to be missed by a rule written against only one direction.
func toggleCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - ('a' - 'A')
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
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
		// C1, and PURE C1 on purpose (redteam host round 2, F6). This loop walked
		// BYTES against `c >= 0x20 && c != 0x7f`, so U+009B — CSI, the
		// single-character form of ESC-[ — and U+0085 (NEL) were accepted and
		// reached every screen raw. The asymmetry that hid it: mix one ASCII
		// control into the same value and %q escapes the C1 characters too, so a
		// mixed probe passes on a broken build. This one has no ASCII control in
		// it at all.
		"a C1 CSI, the 8-bit spelling of ESC-[": "fast\u009b1A\u009b1G",
		"a C1 NEL, which is a line break":       "fast\u0085  ro   /etc/shadow",
		// Zl/Zp rather than Cc, so unicode.IsControl does not cover them and they
		// are named in the predicate by hand — and this block is a table whose
		// rows are one line each.
		"a LINE SEPARATOR":      "fast\u2028  ro   /etc/shadow",
		"a PARAGRAPH SEPARATOR": "fast\u2029  ro   /etc/shadow",
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
	// The é and the arrow are the control that stops unicode.IsControl being read
	// as "anything non-ASCII": a value snug renders every day contains both.
	for _, value := range []string{"vim", "/usr/share", "en_US.UTF-8", "1", "", "café", "a → b"} {
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

// The residual the git entries do NOT close, pinned so it cannot become a belief
// that they do — and now pinned from the other side.
//
// git falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR, and GIT_PAGER ->
// core.pager -> PAGER. Both fallbacks measured; `PAGER="sh -c '…'" git log` runs
// the command. While the GIT_* spellings were refused and the generic three were
// not, that asymmetry was the finding: the table closed the invisible half of a
// class and not the class.
//
// Nothing is refused now, so the asymmetry is gone in the only direction that
// was ever available — the reader is told about all six. This test asserts
// exactly that, and it is the answer to both
// https://github.com/gomoni/snug/issues/35 and
// https://github.com/gomoni/snug/issues/45: neither was asking for a verb to be
// withdrawn from @claude (which inherits all three of the generic names), they
// were asking for the human to be told. A sentence that goes missing from either
// half puts the asymmetry back.
func TestBothSpellingsOfGitsExecClassAreAnnotated(t *testing.T) {
	for _, name := range []string{"EDITOR", "VISUAL", "PAGER", "GIT_EDITOR", "GIT_PAGER"} {
		for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
			var g EnvGrants
			if verb == VerbSet {
				g = EnvGrants{Set: map[string]string{name: "sh -c x"}}
			} else {
				g = EnvGrants{Inherit: []string{name}}
			}
			if err := ValidateEnvGrants(g); err != nil {
				t.Errorf("environ.%s %s was refused: %v.\nWithdrawing a verb from a human's own "+
					"profile is the denylist shape this model does not have — and @claude inherits "+
					"EDITOR, VISUAL and PAGER, so a refusal here breaks a shipped profile outright",
					verb, name, err)
			}
			if EnvNote(name, verb) == "" {
				t.Errorf("environ.%s %s carries no annotation. git runs whatever these name — "+
					"measured, via GIT_EDITOR -> core.editor -> VISUAL -> EDITOR and GIT_PAGER -> "+
					"core.pager -> PAGER — possibly in a sandbox where a DIFFERENT profile pinned "+
					"the ssh identity the next push uses. Being told is the whole of what snug "+
					"still owes here", verb, name)
			}
		}
	}
	// The control: a rostered scalar that names no program must NOT be
	// annotated, or "annotated" stops distinguishing anything. NO_COLOR changes
	// what tools PRINT; @claude inherits it too.
	for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
		if got := EnvNote("NO_COLOR", verb); got != "" {
			t.Errorf("EnvNote(NO_COLOR, %s) = %q. A flag that changes what a tool prints and names "+
				"no program should carry nothing; annotating every row is the same as annotating "+
				"none", verb, got)
		}
	}
}

// A prefix rule has to cover the prefix and NOT the near-miss, or it is either
// a silent hole or a nuisance. Both directions, because a rule that covered LD_
// by covering everything starting with L would pass every positive assertion
// here.
//
// It used to measure a refusal and now measures the annotation, which is the
// same rule at the same names — with one thing gained: the near-miss half is no
// longer "was it accepted" (everything is) but "did snug stay quiet about a name
// it knows nothing about", which is the failure mode an over-wide prefix
// actually has now.
func TestPrefixAnnotationsCoverExactlyTheirPrefix(t *testing.T) {
	for _, name := range []string{"LD_ANYTHING", "BASH_FUNC_x", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v", name, err)
		}
		if EnvNote(name, VerbSet) == "" {
			t.Errorf("environ.set %s carries no annotation; it matches a prefix whose family was "+
				"measured to name code or to outrank a config file", name)
		}
	}
	// Near misses: a name that merely starts with the same letters is a
	// different variable and snug has nothing to say about it. None of these
	// five is on the roster either, so a mark on one of these rows could only
	// come from the prefix rule reaching too far.
	for _, name := range []string{"LD", "LDFLAGS", "BASH_FUNCTION", "GIT_CONFIG", "GITCONFIG"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v", name, err)
		}
		if got := EnvNote(name, VerbSet); got != "" {
			t.Errorf("environ.set %s is annotated %q, but %q is not under any known prefix — a "+
				"rule that catches it catches too much, and a sentence about the wrong family is "+
				"worse than none because a reader will act on it", name, got, name)
		}
	}
}

// TestEveryMergeableListIsPathValued is the STRUCTURAL argument behind a
// property cmd/snug asserts empirically, and it belongs here because this table
// is where the property is actually decided.
//
// The rule on the screen (cmd/snug's TestNoEnvironmentLineCanBeMistakenForAMark)
// is: a line indented 20 or more is snug's own mark, and no data line can reach
// that column. A red team went looking for a way to forge one and found the mark
// column UNREACHABLE rather than merely unreached, by this chain (host round 2,
// §4.1):
//
//  1. a scalar always renders on the row that carries its NAME, at indent 2,
//     with the verb and provenance columns still to its right — so profile text
//     in a scalar cannot start a line at all;
//  2. the only profile text that reaches a line of its own is a continuation
//     BAND of a LIST, rendered at indent 19;
//  3. a list verb needs a roster row (checkUnrosteredName), and `merge`/
//     `prepend` additionally need `mergeable`;
//  4. every mergeable list is `path: true` — THIS TEST — so checkAbsoluteElement
//     refuses any element that does not begin with '/';
//  5. therefore a continuation line always begins with a slash at column 20, and
//     can never begin with whitespace or with '←'.
//
// A mechanical sweep of --dry-run with the arrow, U+2003, U+00A0 and U+009B
// planted in a value, a description, a guest path, a host path and a merge
// element found 12 lines at indent >= 20 and ZERO of them carrying any
// attacker-supplied token.
//
// Step 4 is the only step that is a fact about a table rather than about code,
// which makes it the one that can be broken by a one-line edit: adding a
// mergeable list that is not path-valued (a list of FLAGS, say — GOFLAGS is
// exactly that shape and is deliberately not mergeable) would put arbitrary
// profile text at the continuation column, and every step above it would still
// be true. So the screen's rule would fail in cmd/snug, far from the edit that
// caused it, with nothing pointing back here. This test is that pointer.
func TestEveryMergeableListIsPathValued(t *testing.T) {
	mergeable := 0
	for name, tp := range envTypes {
		if !tp.mergeable {
			continue
		}
		mergeable++
		if !tp.path {
			t.Errorf("%s is mergeable and NOT path-valued. A profile's `merge` elements are the "+
				"only text that reaches the continuation column of --dry-run's ENVIRONMENT "+
				"block, and what keeps them from starting a line that reads as snug's own mark "+
				"is checkAbsoluteElement forcing a leading '/'. That check is keyed on "+
				"valueIsAPath. Either this list carries paths and wants `path: true`, or it "+
				"carries something else and must not be mergeable — see "+
				"TestNoEnvironmentLineCanBeMistakenForAMark for what breaks", name)
		}
	}
	// POSITIVE CONTROL: the roster really does contain mergeable lists, so this
	// cannot pass over an empty loop.
	if mergeable < 5 {
		t.Fatalf("only %d mergeable lists in the roster; this test measured almost nothing", mergeable)
	}
	// THE BEHAVIOUR, not just the flag, because step 4 above is only worth
	// anything if the refusal actually fires. One relative element per mergeable
	// name, through the real resolver.
	for name, tp := range envTypes {
		if !tp.mergeable {
			continue
		}
		reg := testRegistry()
		reg["band"] = &Profile{Name: "band", Include: []ProfileName{"@cwd-rw"},
			Environ: EnvGrants{Merge: map[string][]string{name: {" ← not granted"}}}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "band"}, testCtx(), newFakeEnv())
		if err == nil {
			t.Errorf("environ.merge %s accepted an element beginning with an em space and an "+
				"arrow. Rendered, that is a continuation line whose visual indent reaches the "+
				"mark column while its ASCII indent does not — a profile's text wearing snug's "+
				"own verdict", name)
		}
	}
}
