package policy

import (
	"fmt"
	"sort"
	"strings"
)

// The variable types, and the two checks that run over a profile's `environ`
// block before anything resolves.
//
// Everything in the environment is a char*; that is all the variables share.
// snug owns the types because the ALTERNATIVE is inferring an operation from a
// value's shape, and the shape is the same for a search path, a URL, a template
// language bash performs command substitution on, and a set of delimiter
// characters. See .claude/design/ENVIRONMENT-VARIABLES.md §3.

// emptyKind is what an EMPTY ELEMENT means to the consumer of a list, and it is
// the discriminator that decides whether filtering that list is safe, hazardous
// or outright illegal. The type alone cannot say: a separator-carrying type that
// does not also carry this is a sanitiser written once and wrong for a third of
// its inputs (§3.3).
type emptyKind uint8

const (
	emptyNA emptyKind = iota

	// emptyIgnored — the consumer skips it. Filtering is safe.
	emptyIgnored

	// emptyCWD — an empty element resolves to the CURRENT DIRECTORY, which
	// inside snug is the target: the one writable thing a hostile payload
	// controls. Measured (§4.3): PATH="/usr/bin:" runs ./victim, through the
	// shell AND through execvp. This is why snug never splits a string on a
	// separator and never emits an element it did not receive whole.
	emptyCWD

	// emptyOperator — an empty element is an INSTRUCTION, not a gap. MANPATH is
	// the case: a leading empty prepends the system path, a trailing one appends
	// it, `::` inserts it in place. So REMOVING an element there can ADD
	// directories, which inverts what a filter is for.
	emptyOperator

	// emptySystem — an empty element names the system location.
	emptySystem
)

// envType is what snug knows about one variable name, and it holds TYPE FACTS
// ONLY — scalar or list, the separator, what an empty element means, whether the
// value is a path, whether the elements compose. There is no permission bit in
// this struct and there must never be one again.
//
// It carried one, `noInherit`, and the reason it is gone is the reason the whole
// table changed shape (issue #44). Its message read "snug refuses to take this
// from the host", which is a VERDICT about what a human's profile may do — and
// snug has only allowlists. A profile author is a human on the far side of the
// line the sandbox draws: snug constrains the payload, never the author. So
// every such verdict became an ANNOTATION (envNotes below, rendered by EnvNote),
// and the rule is now readable off the struct rather than off a doc comment: if
// a field you are about to add answers "may a profile do this", it belongs in
// envNotes; if it answers "what IS this variable", it belongs here.
//
// What a type fact still does is decline an OPERATION snug cannot carry out
// correctly — `merge` on a scalar, `sanitise` on MANPATH, where removing an
// element ADDS directories. That is snug saying "I cannot do this verb", not
// "you may not have this", and checkEnvVerbType is where the difference is
// spelled out.
//
// THE ZERO VALUE IS A REAL ROW, NOT A MISS, and that distinction is what the
// roster rests on. `envType{}` means "a scalar, both `set` and `inherit`" —
// EDITOR is one — while a name that is not in envTypes at all has no type at
// all, which is what the three LIST verbs need and what a builtin may not write.
// The two are told apart by the map lookup's second return and by nothing else,
// which is why typeOf returns it: a `known` FIELD could be forgotten on a new
// row, and a forgotten field would read as a row that grants nothing rather than
// as a row that grants a scalar. There is no spelling of "on the roster" that a
// new entry can omit.
type envType struct {
	list   bool
	sep    string
	altSep string // a second separator the CONSUMER also accepts, "" if none
	path   bool   // path-valued, so §2.5's grant-coupling rule applies
	empty  emptyKind

	// pathNoGrant marks a value that IS a filesystem path but which the
	// grant-coupling rule deliberately does not reach.
	//
	// It exists because `path` answered two questions at once and one of them was
	// answered wrongly by saying no to the other. Setting `path: true` on a name
	// turns on BOTH the coupling rule (the profile must grant what it names) and
	// the absolute-path rule (a relative value is refused); BASH_ENV, ENV and
	// PYTHONSTARTUP were given `path: false` so that the coupling clause stayed
	// unenforced — a deliberate, documented decision — and that silently took the
	// absolute rule with it. Measured: `set BASH_ENV = ".snug-init.sh"` resolved
	// clean, while `set CARGO_HOME = "cargo"` was refused with a message naming
	// exactly the hazard the first one has.
	//
	// Flipping one of these rows to `path: true` is the change that closes the
	// coupling half. It is one line and one golden row, and it is a NEW refusal
	// for user profiles, so it belongs in its own change rather than smuggled
	// into this one.
	//
	// It applies to THREE of the five startup-file names, not five, and the other
	// two are measured rather than assumed: PYTHONBREAKPOINT takes a
	// module:callable and python REFUSES a path there ("Ignoring unimportable
	// $PYTHONBREAKPOINT", CPython 3.13.14), and LESSOPEN's value is a command
	// line beginning with '|' (measured, less). A path rule for either would
	// refuse the only correct spelling.
	pathNoGrant bool

	// mergeable and sanitisable are §3.3's two columns of marks, kept as two
	// fields because they are two different questions and the table answers them
	// differently for the same name: PYTHONPATH may be merged by a profile that
	// grants the directory and may NOT be sanitised, because an empty element
	// there is the current directory. A ✗ in either column is "refused at load
	// time" (§3.1), not advice.
	//
	// They are consulted only for list variables.
	mergeable   bool
	sanitisable bool
}

// envTypes is snug's ROSTER: what snug has been TAUGHT about a variable, and
// NOTHING ABOUT WHAT ANYONE MAY DO WITH IT. It is §3.2, §3.3 and §3.4.
//
// THE ROSTER IS WHAT SNUG KNOWS, NOT WHAT SNUG PERMITS. Every verdict of the
// form "a profile may not do this with this name" was moved out of here and into
// envNotes, where it is rendered on --dry-run and on `snug profile show` instead
// of being refused. snug has only allowlists: the sandbox starts with an empty
// environment and a profile opens a named hole in it. The author of that profile
// is a human on the trusted side of the boundary — snug constrains the payload,
// not the person configuring it — so a table here saying "you may not have
// EDITOR" was snug refusing its own user, which is not a boundary at all
// (measured, one commit ago: 628 refused pairs, all 628 restored by four lines
// of TOML). You get what you configure, and the screen says what you got.
//
// What the roster still decides, and both are about snug's own competence rather
// than about anyone's permission:
//
//   - A profile snug SHIPS may write ONLY a name that has a row here. That is
//     enforced structurally in internal/profile's `mark` — the one door a
//     profile passes through to become snug's — expressed with the same
//     IsUncheckedEnv predicate the screen draws its mark from. So "a builtin may
//     not write a name snug has no row for" and "no builtin row renders as
//     unchecked" are one sentence, not two rules that can drift apart. This is a
//     REVIEW requirement, and a review requirement is something snug can impose
//     on its own material and cannot impose on a file someone else wrote: there
//     is no human standing behind a profile compiled into the binary.
//   - The three LIST verbs take no name that is not here, from anybody: a list
//     verb needs the separator and the empty-element kind, and neither is
//     something a profile can supply without snug sniffing the shape of a value.
//     That is snug declining an operation it cannot perform correctly.
//
// A profile a HUMAN wrote may write a name with no row here at `set` and
// `inherit`. It is carried, and every entry it produces is marked `← unchecked`
// on both screens (IsUncheckedEnv) — plus whatever envNotes has to say about it,
// which is a second and independent statement.
//
// IT USED TO SAY: "a name that is not here is a SCALAR". The table then reported
// a TYPE for a name it had never been taught, and three red-team rounds found
// three sets of names it had not been taught about, each round closing its own
// names and none of them closing the space, because the space is "every variable
// that some tool, in some version, turns into an exec" and it has no edge:
// RUSTC_WRAPPER/RUSTC_WORKSPACE_WRAPPER/RUSTC; then CARGO_BUILD_RUSTC_WRAPPER
// and NPM_CONFIG_SCRIPT_SHELL at a case the table did not fold; then MAKEFLAGS,
// GOFLAGS, CC, TAR_OPTIONS, RSYNC_RSH, GIT_COMMON_DIR, PYTHONUSERBASE,
// PYTHONPATH, NODE_OPTIONS and PERL5OPT. What that history bears on is what snug
// SHIPS, where the fix is the one @sys already uses when it lists fourteen /etc
// entries instead of binding all 109: name what you admit (issue #44).
//
// A ROW IS STILL A REVIEW, and now for one specific reason: a row is what makes
// a name writable by a profile snug SHIPS. Write the sentence saying what the
// verb lets the tool DO before adding one — the discipline GIT-CONFIG.md §5 asks
// of the config-key whitelist, for the same reason. Do not add a name to make a
// test pass, and READ envNotes before adding a row for a name that has an
// annotation: a row does not silence the annotation, but it does open the
// builtin gate for that name, which is the residual
// TestAnnotatedEnvPairsAShippedProfileWritesArePinned (internal/profile) exists
// to make visible.
//
// THERE IS NO ESCAPE HATCH AND THERE MUST NOT BE ONE. `environ.declare` existed
// for one milestone — a per-profile name set licensing `set` and `inherit` for a
// name with no row — and it was removed, deliberately, before it shipped. The
// argument that killed it: `environ.set MY_VAR = "x"` in a profile with a name,
// a file path and an author ALREADY is that author declaring the name and taking
// responsibility; EnvEntry.From records it and --dry-run renders it, so the
// hatch made them sign twice. The disclosure it was justified by never depended
// on it either — IsUncheckedEnv derives the mark from THIS TABLE, not from a
// Declare list, so deleting the hatch left the `← unchecked` row rendering
// unchanged on both sinks. It also bought nothing across profiles: it
// deliberately did not travel through `include`, and two profiles disagreeing
// about a scalar already fails on the conflict rule. And it added a failure mode
// of its own — snug adding a roster row later would break every profile that had
// declared that name.
//
// envNotes and envNotePrefixes below are a SEPARATE table and are read
// independently of this one: EnvNote reads those, checkEnvVerbType reads this.
// Neither is written in terms of the other, so a name may be rostered and
// annotated (BASH_ENV, EDITOR, CARGO_HOME all are), annotated and unrostered
// (GIT_SSH_COMMAND is), or rostered and silent (NO_COLOR is). The screen renders
// both statements when both apply; see EnvNote.
//
// Names snug owns are deliberately ABSENT even where §3.2 lists them: ownership
// refuses them for every verb, which is the stronger statement, and an entry
// here would invite someone to read the row as permission.
var envTypes = map[string]envType{
	// ── scalars a profile may both set and inherit ───────────────────────────
	//
	// An all-false row is not an empty row: it says SCALAR, both verbs. See
	// envType's doc comment for why that is expressed by the row EXISTING
	// rather than by a field inside it.
	//
	// EDITOR, VISUAL and PAGER: the value IS a command some tool will execute.
	// The sentence saying so lives in envNotes now, at both verbs, and it is on
	// the screen for every profile that writes one — including @claude, which
	// inherits all three.
	//
	// Issue #45 asked whether `set` should be withdrawn from these (the mirror of
	// the `noInherit` bit `inherit` used to carry). It is ANSWERED, not deferred,
	// and the answer is no: withdrawing a verb from a human's own profile is the
	// denylist shape this file stopped having. What #45 was really asking for was
	// that a human reading --dry-run be told what these three DO, and that is
	// what the annotation is. The rows stay type facts: three scalars.
	"EDITOR": {},
	"VISUAL": {},
	"PAGER":  {},
	// NO_COLOR is a FLAG, and for a flag EMPTY IS NOT UNSET — "set to any value,
	// including empty" is its specification, which is why nothing in the
	// resolver may collapse the two (§4.6a). At full abuse a profile that writes
	// it makes every tool inside emit plain text: it names no program, and
	// changes what a tool PRINTS rather than what it does. @claude inherits it
	// so that a human who turned colour off on the host keeps it off inside.
	"NO_COLOR": {},
	// ANTHROPIC_BASE_URL is the endpoint the Claude Code client talks to, and
	// @claude inherits it so a human behind a proxy or a gateway keeps working
	// inside the sandbox. At full abuse, a profile that writes it points every
	// request the agent makes — the conversation, and whatever file content the
	// agent decided to send with it — at a host of that profile author's
	// choosing. It names no program and nothing execs it; what it redirects is
	// where the sandbox's own traffic goes, which is a grant worth seeing on a
	// screen and is why it is a row rather than an assumption.
	"ANTHROPIC_BASE_URL": {},

	// ── the old middle bucket: startup files a tool reads (§2.1) ─────────────
	//
	// These five used to be "legal as `set`, refused as `inherit`". The refusal
	// is gone and the DISTINCTION is not: envNotes carries a different sentence
	// at each verb, because the two differ in where the value comes from — a
	// reviewable line in a profile file, or whatever the process that launched
	// snug happened to have. That is the same split forbidKind used to express by
	// refusing one half of it, said on the screen instead.
	//
	// What each lets a tool DO is in envNotes and is not restated here, so there
	// is one copy of it.
	//
	// `path` is false on all five and `pathNoGrant` is true on three, and the
	// split is the fix for a defect the previous version of this comment walked
	// straight past. It reasoned only about the COUPLING clause — correctly: a
	// grant requirement here would be a new refusal for user profiles, and it
	// still is, see pathNoGrant — and did not notice that the same flag also
	// switched off the ABSOLUTE-PATH rule, which is not a permission at all.
	//
	// BASH_ENV, ENV and PYTHONSTARTUP genuinely are paths, and a relative one is
	// resolved against the payload's cwd — which inside snug is `--chdir
	// <target>`, the one writable thing a hostile payload controls. Measured, all
	// three, with the cwd control:
	//
	//   cd cwd1; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> sourced from cwd1
	//   cd cwd2; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> nothing (control)
	//   cd cwd1; ENV=.shinit sh -i -c 'echo body'            -> sourced from cwd1
	//   cd cwd1; PYTHONSTARTUP=pystart.py python3 -i         -> ran (CPython 3.13.14)
	//
	// PYTHONBREAKPOINT is a module:callable and LESSOPEN is a command line
	// beginning with '|', both measured (see their envNotes entries), so neither
	// carries either flag: marking them path-valued would refuse a correct value.
	"BASH_ENV":         {pathNoGrant: true},
	"ENV":              {pathNoGrant: true},
	"PYTHONSTARTUP":    {pathNoGrant: true},
	"PYTHONBREAKPOINT": {},
	"LESSOPEN":         {},

	// ── path-valued scalars whose inherit carries an annotation (§3.2) ───────
	//
	// Every row here used to carry `noInherit: true`, a refusal INSIDE the
	// roster. The bit is gone; the sentence it stood for is in envNotes, at
	// `inherit` only, because that is the verb it was ever about. `path: true` is
	// a type fact and stays: it is what makes envcoupling.go's grant-coupling
	// sweep look at the value at all.
	//
	// The XDG four: snug's own @home creates these directories, so a profile
	// SETTING one to a path it grants is coherent. Inheriting the host's points
	// the sandbox at a directory it does not have — annotated, not refused.
	"XDG_CONFIG_HOME": {path: true},
	"XDG_CACHE_HOME":  {path: true},
	"XDG_STATE_HOME":  {path: true},
	"XDG_DATA_HOME":   {path: true},
	// XDG_RUNTIME_DIR carries obligations rather than just a value — mode 0700,
	// owned by the user, session lifetime — so authoring it IS a grant, and it
	// belongs to whichever profile creates a directory meeting them (§3.4).
	"XDG_RUNTIME_DIR": {path: true},
	// "generate, don't bind": the value is a path to a config snug or a profile
	// produced, never a credential.
	"CARGO_HOME":            {path: true},
	"DOCKER_CONFIG":         {path: true},
	"NPM_CONFIG_USERCONFIG": {path: true},
	"PIP_CONFIG_FILE":       {path: true},
	// PYTHONUSERBASE is PATH-VALUED and was absent from this table entirely for a
	// milestone — which meant writesAnyPath's grant-coupling sweep
	// (envcoupling.go) skipped it. The row is here for the coupling rule, and the
	// measurement that made it interesting (the value's directory is where
	// usercustomize.py runs from) is the annotation in envNotes.
	"PYTHONUSERBASE": {path: true},

	// ── the XDG lists (§3.4) ─────────────────────────────────────────────────
	//
	// The only two lists here that a naive filter is safe on BY SPECIFICATION:
	// empty is unset and relative paths must be ignored.
	"XDG_DATA_DIRS":   {list: true, sep: ":", path: true, empty: emptyIgnored, mergeable: true, sanitisable: true},
	"XDG_CONFIG_DIRS": {list: true, sep: ":", path: true, empty: emptyIgnored, mergeable: true, sanitisable: true},

	// ── lists (§3.3) ─────────────────────────────────────────────────────────
	"PATH": {list: true, sep: ":", path: true, empty: emptyCWD, mergeable: true, sanitisable: true},
	// ld.so(8) gives these two TWO separator sets each, neither escapable, which
	// is the reason a separator lives in the type at all rather than in the
	// parser. Both are annotated as well (see envNotes) — and note what refuses
	// them at every verb now that nothing denies a name: they are LISTS that are
	// neither mergeable nor sanitisable, so `set` and `inherit` are refused for
	// being list verbs on a list, and `merge`/`prepend`/`sanitise` are refused
	// because the elements do not compose. That is a type verdict end to end,
	// which is why it survived the flip untouched.
	"LD_LIBRARY_PATH": {list: true, sep: ":", altSep: ";", path: true, empty: emptyCWD},
	"LD_PRELOAD":      {list: true, sep: ":", altSep: " ", path: true, empty: emptyNA},
	// MANPATH: sanitise is ILLEGAL, not merely risky. Removing an element can
	// ADD directories — man-db announces the choice ("prepending
	// /etc/manpath.config"), measured in §3.3.
	"MANPATH": {list: true, sep: ":", path: true, empty: emptyOperator, mergeable: true},
	"CDPATH":  {list: true, sep: ":", path: true, empty: emptyCWD},
	"PKG_CONFIG_PATH": {list: true, sep: ":", path: true, empty: emptyIgnored,
		mergeable: true, sanitisable: true},
	"PYTHONPATH": {list: true, sep: ":", path: true, empty: emptyCWD, mergeable: true},
	"PERL5LIB": {list: true, sep: ":", path: true, empty: emptyIgnored,
		mergeable: true, sanitisable: true},
	"NODE_PATH": {list: true, sep: ":", path: true, empty: emptyIgnored,
		mergeable: true, sanitisable: true},
	"CLASSPATH": {list: true, sep: ":", altSep: ";", path: true, empty: emptyNA,
		mergeable: true, sanitisable: true},
	// GOPATH's element 0 is privileged (an empty first element yields an empty
	// GOMODCACHE), which is why sanitise keeps HOST ORDER rather than sorting.
	"GOPATH": {list: true, sep: ":", path: true, empty: emptyNA,
		mergeable: true, sanitisable: true},
	"INFOPATH": {list: true, sep: ":", path: true, empty: emptySystem,
		mergeable: true, sanitisable: true},
	"TERMINFO_DIRS": {list: true, sep: ":", path: true, empty: emptySystem,
		mergeable: true, sanitisable: true},
	// Space-separated FLAGS, not paths. Nothing here composes.
	"GOFLAGS": {list: true, sep: " ", empty: emptyNA},
}

// IsEnvList reports whether snug treats this name as a LIST — several elements
// joined by a separator — rather than as one scalar value.
//
// Exported for the renderer, which needs it to know whether the space in a value
// is part of the value or a gap between two of them. That is not a cosmetic
// question: a list element containing a space renders identically to two
// elements, and the same ambiguity in checkPrependAgreement's key silently
// deleted a profile's entry (seqKey). A scalar has no such reading — PS1 is
// mostly spaces — so the renderer must not quote one.
//
// It answers from the same table typeOf reads, because a second opinion about
// what a name IS is how the screen and the resolver come to disagree.
func IsEnvList(name string) bool {
	t, known := typeOf(name)
	return known && t.list
}

// typeOf returns what snug knows about a name, and WHETHER IT KNOWS IT. The
// second return is the roster membership test and there is deliberately no
// other one: a caller that ignores it is reading a zero envType as fact, which
// is what "unknown ⇒ scalar, allowed" was (issue #44).
func typeOf(name string) (envType, bool) {
	if t, ok := envTypes[name]; ok {
		return t, true
	}
	// A CONSUMER THAT FOLDS CASE MAKES TWO SPELLINGS ONE NAME, and the roster
	// has to answer the same for both or the flip becomes a refusal of a
	// spelling snug's own rules bless. npm's env loader lower-cases every name
	// before matching (measured — see prefixCaseFold), so
	// `npm_config_userconfig` IS `NPM_CONFIG_USERCONFIG`: the prefix table
	// already exempts it as a pointer in every spelling, and an exact-string
	// roster lookup would have exempted it from the forbidden prefix and then
	// refused it here for having no row. That is the same "one fact, two tables,
	// they drift" defect prefixCaseFold exists to prevent, met one table further
	// on, so the answer is to read that same table rather than to duplicate a
	// row per spelling.
	//
	// Scoped to prefixes that actually fold: nothing outside a folding family
	// gets a case-insensitive roster lookup, so PATH is still PATH and `path` is
	// still a name snug has never heard of.
	for prefix, fold := range prefixCaseFold {
		if !fold || !matchesPrefix(name, prefix) {
			continue
		}
		for k, t := range envTypes {
			if matchesPrefix(k, prefix) && sameName(name, k, prefix) {
				return t, true
			}
		}
	}
	return envType{}, false
}

// snugKnowsEnvName reports whether snug has a TYPE for a name — a roster row,
// and nothing else.
//
// IT READ THE ANNOTATION TABLE TOO, AND THAT HAD TO CHANGE WITH IT. While that
// table was `forbiddenEnv`, an entry in it was an opinion about the name
// ("refused at this verb") and folding it in here kept IsUncheckedEnv from
// reporting a REFUSED name as one snug knew nothing about — defensive only,
// since a refused pair never reached a screen. Once the same table stopped
// refusing, keeping it here would have quietly widened something else entirely:
// internal/profile's checkBuiltinEnvRoster is written on IsUncheckedEnv, so
// every annotated name — GIT_SSH_COMMAND, RUSTC_WRAPPER, PS4, sixty of them —
// would have become a name a profile snug SHIPS may write, in the same commit
// that stopped refusing them for everybody else. Annotation must not become
// grant. Measured: with the annotation table folded in, `mark` accepts a builtin
// carrying `environ.set GIT_SSH_COMMAND`; without it, it refuses.
//
// So the two tables answer two questions and this predicate asks only one. A
// name may be annotated and still unchecked, and a row that renders both marks
// is saying two true things: snug has no type for this name, and here is what
// the tool does with the value.
//
// The PREFIX table was never part of this and still is not. A prefix names an
// unbounded family (PIP_*), and a name matching one is not thereby a name snug
// has a TYPE for.
func snugKnowsEnvName(name string) bool {
	_, ok := typeOf(name)
	return ok
}

// IsUncheckedEnv reports whether one (name, verb) pair is one snug carried
// without knowing what the variable IS — no roster row, so no type.
//
// It is not "snug has nothing to say about this name": envNotes may still have a
// sentence for it, and the two marks are rendered together. See
// snugKnowsEnvName for why folding the annotation table into this predicate
// would have turned an annotation into a builtin's grant.
//
// IT HAS THREE CONSUMERS AND THAT IS THE DESIGN, not an accident of reuse:
//
//   - --dry-run's ENVIRONMENT block marks the row;
//   - `snug profile show` marks the name inside the verb's own block;
//   - internal/profile's `mark` REFUSES a builtin that produces a true here.
//
// So the rule a profile snug ships is held to is written as "may not hand over a
// name the screen would mark unchecked" rather than as a second roster-membership
// test beside this one. One predicate cannot disagree with itself; two would,
// eventually, and this file already records that failure twice over case-folded
// spellings (prefixCaseFold, noteFor).
//
// The argv block is the one sink with nothing to add — `--setenv NAME VALUE` has
// no provenance column at all, and the value got there through checkEnvValue
// like every other value a profile wrote.
//
// The verb is a parameter rather than a caller-side condition because snug's
// OWN names are mostly absent from the roster too — ownership refuses them for
// every verb, which is the stronger statement — so a name-only predicate would
// mark HOME, PATH and SNUG_PROFILES as unchecked on the screen a human reads to
// decide whether to trust the sandbox. VerbSnug is snug's authorship and is
// never unchecked.
func IsUncheckedEnv(name string, verb EnvVerb) bool {
	if verb == VerbSnug {
		return false
	}
	return !snugKnowsEnvName(name)
}

// UncheckedEnvNote renders IsUncheckedEnv for a screen, or "" when the pair is
// one snug has a type for. It is EnvNote's shape on purpose: both marks are
// prepended to a row by both screens, so both are one function returning either
// the rendered text or nothing.
//
// IT LIVES HERE RATHER THAN AT EITHER SINK BECAUSE THE WORDING DRIFTED THE
// MOMENT IT WAS WRITTEN TWICE. --dry-run and `snug profile show` each held their
// own copy of the string, with a comment at one of them claiming "both strings
// come from internal/policy, so `snug profile show` renders the identical text"
// — true of EnvNote, and false of this one, in the same commit. That is this
// project's most-repeated defect (one guard, N sinks; visibleValue; prefixCaseFold)
// and the fix is always the same: the property owns the wording, not the caller.
//
// The wording says TYPE, and the earlier "snug has no entry for this name" is
// what it replaced. Once the annotation table stopped refusing, the common case
// became a row carrying BOTH marks — sixty annotated names have no roster row —
// and "snug has no entry for this name" immediately followed by a detailed
// sentence about that very name reads to a human as snug contradicting itself
// within one line. Measured on `environ.set GIT_SSH`. The two marks answer two
// questions and the words now say which: this one is about the variable's TYPE
// (scalar or list, the separator, what an empty element means), which is what
// the type refusals in this file are already worded against, and EnvNote's is
// about what the tool DOES with the value.
func UncheckedEnvNote(name string, verb EnvVerb) string {
	if !IsUncheckedEnv(name, verb) {
		return ""
	}
	return "  ← unchecked: snug has no type for this name"
}

// envNote is snug's ANNOTATION for one variable name: what a tool DOES with the
// value, in one sentence, rendered on --dry-run and on `snug profile show`
// beside the row that hands it over.
//
// TWO SENTENCES, NOT ONE, and the split is the same one forbidKind used to make
// — it is just no longer a difference between "refused" and "allowed", which is
// why it now has to be SAID. `set`, `merge` and `prepend` carry a value from a
// reviewable file in the trusted profile layer, written by the person selecting
// the profile. `inherit` and `sanitise` carry whatever the process that launched
// snug happened to have, chosen on the host, outside any profile — a hole
// punched in --clearenv. For a name where that difference matters, the two
// fields differ; where it does not, both carry the same sentence (see `both`).
//
// Flattening this to one string per name would lose exactly what forbidKind
// carried, which was never a severity: it was a statement about WHICH VERB.
type envNote struct {
	// authored is the sentence for a value written in the profile file:
	// VerbSet, VerbMerge, VerbPrepend.
	authored string
	// host is the sentence for a value taken from the invoking host:
	// VerbInherit, VerbSanitise.
	host string
	// shape is the one MACHINE-READABLE fact this table carries, and it is here
	// rather than in a table of its own for a measured reason — see valueShape.
	//
	// THE ZERO VALUE IS INVALID AND IS SWEPT. A row that forgets it fails
	// TestEveryAnnotationSaysWhatItsValueIS, which is the whole mechanism: the
	// question "what does a RELATIVE value mean here" is then asked of every
	// annotation that is ever added, instead of being asked once about the names
	// somebody happened to think of.
	shape valueShape
}

// valueShape is what the VALUE of an annotated name IS, as opposed to what the
// tool DOES with it — and it exists because snug held the first fact in prose,
// stated it on --dry-run, and then decided the absolute-path refusal from two
// other tables that had never heard of the name.
//
// MEASURED, redteam host round 3, on this branch. `GIT_TEMPLATE_DIR = "tpl"` and
// `GIT_EXEC_PATH = "gx"` were both ACCEPTED and both ran attacker code out of
// `--chdir <target>` — a post-commit hook copied into every new repository, and
// a `git-probecmd` subcommand — while `GIT_CONFIG_SYSTEM = "sys.gitconfig"`, the
// same shape, was refused. The refusal keyed on the roster and the pointer set;
// these four names are in neither, and isPathValued's comment defended that with
// "for a name with no roster row snug holds no facts at all", which is FALSE for
// exactly these names: each carries an envNotes sentence saying what code the
// DIRECTORY runs.
//
// WHY A COLUMN HERE AND NOT A THIRD TABLE. A third table keyed by name is the
// failure this file has recorded three times over case rules and twice over
// exact-versus-family: one fact, two tables, they drift. The annotation table is
// already keyed by exactly the set of names snug holds a strong fact about, so
// the fact goes in a column of it and cannot be added without the sentence, or
// the sentence without the fact. The ROSTER would have been the natural home —
// this is a type fact — and it cannot be, because a roster row is what opens the
// builtin gate (IsUncheckedEnv -> checkBuiltinEnvRoster), and giving GIT_DIR a
// row would make it a name a profile snug SHIPS may write. That gate is
// deliberate and this fix must not touch it, which is the same reasoning
// valueIsAPath already applies to the pointer table.
//
// WHAT THE COLUMN DECIDES: shapePath, and only shapePath, makes valueIsAPath
// true, so a relative value is refused with the message the pointers get. It
// does NOT touch the grant-coupling rule, whose scope is still the roster alone
// (isPathValued) — a profile may still name an absolute path it does not grant,
// and the screen still marks that row `← not granted`.
//
// WHAT IT DOES NOT DECIDE, said plainly because the sweep must not be read as
// more than it is: nothing checks that a row's shape is TRUE of its name. A
// directory-valued name written down as shapeOpaque is accepted, exactly as a
// wrong sentence would be. What the sweep buys is that the question is ASKED at
// every row and that the answer is rendered, per name, in
// testdata/annotations.txt — so a mis-classification is a line in the review
// artifact rather than an absence nobody can see.
type valueShape uint8

const (
	// shapeUnset is the zero value and is not a classification. It exists only so
	// that forgetting the column is a test failure rather than a silent "not a
	// path".
	shapeUnset valueShape = iota

	// shapePath — the whole value is a filesystem path, so a RELATIVE one is
	// resolved against the payload's cwd. Inside snug that is `--chdir <target>`,
	// which the profile did not choose, cannot know, and which is the one
	// directory a hostile payload writes. There is no string snug can put in
	// --setenv that means what such an author meant, so it is refused.
	shapePath

	// shapeProgram — the value is a program name or a command LINE, which the
	// consumer looks up the way a shell does. A bare `vim`, `ssh -i k` or `gcc`
	// is a correct, host-independent thing to write: the lookup is on PATH, not
	// against the cwd, so the absolute rule would refuse the only spelling anyone
	// uses. That these are the names whose value is CODE is the annotation's
	// business, not this column's — the two questions are orthogonal and mixing
	// them is what made `path` answer two things at once (see envType.pathNoGrant).
	shapeProgram

	// shapeOpaque — not a filesystem path at all: flags a tool parses, a
	// module:callable, a URL, a prompt template, a protocol list, a setting. A
	// relative-looking value here means whatever the tool says it means and snug
	// has no business demanding a leading '/'.
	shapeOpaque

	// shapeFamily is for envNotePrefixes ONLY: a sentence about an unbounded
	// FAMILY of names (LD_*, GIT_CONFIG_*), where the shape differs name by name
	// — GIT_CONFIG_GLOBAL is a path and GIT_CONFIG_KEY_0 is a setting — so the
	// family cannot answer for them. valueIsAPath reads the EXACT table only
	// (noteExact), never a prefix, for this reason.
	shapeFamily
)

// String is what testdata/annotations.txt and the refusals print. It is one word
// per shape and it lives here rather than at the golden, for the reason
// UncheckedEnvNote gives at length: a second copy of the wording is how two
// sinks come to disagree about a fact neither of them owns.
func (s valueShape) String() string {
	switch s {
	case shapePath:
		return "path"
	case shapeProgram:
		return "program"
	case shapeOpaque:
		return "opaque"
	case shapeFamily:
		return "family"
	}
	return "UNSET"
}

// both is an annotation whose sentence does not depend on where the value came
// from — the value is code either way, so the reader needs the same fact at
// every verb. The shape is not a per-verb fact and is passed once.
func both(shape valueShape, s string) envNote {
	return envNote{authored: s, host: s, shape: shape}
}

func (n envNote) forVerb(verb EnvVerb) string {
	switch verb {
	case VerbSet, VerbMerge, VerbPrepend:
		return n.authored
	case VerbInherit, VerbSanitise:
		return n.host
	}
	return ""
}

// envNotes are names whose VALUE IS CODE, or whose value silently outranks a
// file snug generated. It is orthogonal to the roster: the roster says what a
// variable IS, this says what a tool DOES with it. §4.4 is a list to be
// EXTENDED, not retired.
//
// EVERY ENTRY CARRIES, IN THE COMMENT BESIDE IT, EITHER THE MEASUREMENT IT WAS
// WRITTEN FROM OR THE WORDS "DOCUMENTED, NOT MEASURED ON THIS HOST" AND WHAT WAS
// TRIED. A new row must carry one or the other, and that is the whole of the
// contract this header makes with its reader.
//
// IT IS SWEPT NOW, because for a milestone it was a promise and not a fact.
// Measured over the rendered catalogue by a red team: 76 of 167 (name, verb)
// pairs — 41 distinct names — carried neither "measured" nor "documented", and
// the shape of the gap is the one CLAUDE.md records twice. CLASSPATH said
// "(documented — no JVM on this host)" while JAVA_TOOL_OPTIONS, _JAVA_OPTIONS
// and JDK_JAVA_OPTIONS sat four lines above it saying nothing, on the same
// JVM-less host; RUBYOPT, NIS_PATH, RESOLV_HOST_CONF, RES_OPTIONS, LD_AUDIT,
// GCONV_PATH, LOCPATH, NLSPATH and PROMPT_COMMAND were the rest. A contract in a
// header comment that nothing checks is prose.
// TestEveryAnnotationCarriesItsMeasurementOrSaysItHasNone parses THIS FILE and
// fails a row that carries neither, and its own doc comment names the one thing
// it cannot catch: a block comment carrying a measurement for the rows beneath
// it that it does not actually cover, which is precisely how PROMPT_COMMAND came
// to sit under "measured, bash 5.3.15, all four in one run" while being none of
// the four. So a shared block still has to be READ, and a per-row line is worth
// more than a heading.
//
// It used to promise more than it could keep — "every entry below was measured,
// and the measurement is in the comment beside it" — while about forty rows
// carried no measurement at all, and three carried sentences that did not
// survive one:
//
//	PS3          claimed command substitution; bash 5.3.15 prints it VERBATIM
//	             (PS0 and PS2 substituted in the same run — the controls)
//	MALLOC_TRACE claimed "created by every process that runs"; on glibc 2.43 the
//	             implementation is not in libc.so.6 at all and the program must
//	             call mtrace()
//	HOSTALIASES  claimed "every hostname lookup"; DOT-FREE names only
//
// All three OVERSTATED, so nothing was reachable through them — and that is
// precisely why they mattered. A reader who checks one sentence in a table of
// 148 and finds it wrong has no way to tell which of the other 147 to trust,
// and this table's only job is to be trusted on a screen someone is using to
// decide whether to run a sandbox.
//
// THIS TABLE REFUSES NOTHING. It used to (as `forbiddenEnv`, with a `forbidKind`
// per entry), and the reason it stopped is the guiding principle read in the
// right direction: snug shares nothing and a profile opens a named hole, so
// there is no state a profile can be denied its way back to — the thing a
// denylist would deny was never there. The author of a profile is a human on the
// trusted side of the boundary; snug constrains the payload, not the person
// configuring it. So `set GIT_SSH_COMMAND` is legal now, and what a human gets
// for it is this sentence, on the screen they read to decide whether to trust
// the sandbox. You get what you configure.
//
// What that DOES leave standing, so this is not read as "anything goes":
//
//   - a profile snug SHIPS may still write only a rostered name
//     (internal/profile's checkBuiltinEnvRoster), and none of these names has a
//     roster row unless it is listed in envTypes above;
//   - checkEnvOwnership still refuses snug's own scalars to everybody;
//   - the type rules still refuse an operation snug cannot perform correctly.
//
// PS1 is deliberately absent, and so is SNUG*: they are snug's own (§1.1) and
// refused by ownership, which is the stronger statement and the only remaining
// refusal of a NAME. An annotation for either would invite someone to read the
// row as permission.
//
// WHAT THIS TABLE DOES NOT COVER, stated because reading it as a class closure
// is the mistake it invites. It never closed the exec class for git and it does
// not now: git falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR and
// GIT_PAGER -> core.pager -> PAGER, both measured, so the generic three reach
// the same programs the GIT_* names do. All six are annotated now, which is the
// only sense in which the class is "covered" — the reader is told, at both
// spellings. https://github.com/gomoni/snug/issues/35 and
// https://github.com/gomoni/snug/issues/45 were both asking for that and are
// answered by it.
var envNotes = map[string]envNote{
	// ── the loader and the C library ─────────────────────────────────────────
	//
	// §4.4 plus ld.so(8)'s own secure-execution list, which is the closest thing
	// to an authoritative denylist that exists — for glibc's own purposes, which
	// is why snug reads it as a source of SENTENCES rather than as a gate.
	// Measured, glibc 2.43, with the control — a shared object whose only content
	// is a constructor:
	//
	//	LD_PRELOAD=$W/libpre.so /bin/echo hi  -> LD-PRELOAD-RAN, then hi
	//	                        /bin/echo hi  -> hi              (control)
	"LD_PRELOAD": both(shapePath, "every process in the sandbox loads this library before its own code "+
		"(measured, glibc 2.43, with the control)"),
	// Measured, glibc 2.43, with the control. An audit library needs only
	// la_version(), and the loader calls it BEFORE the program's own constructors:
	//
	//	LD_AUDIT=$W/libaud.so /bin/echo hi  -> LD-AUDIT-RAN v=2, then hi
	//	                      /bin/echo hi  -> hi                (control)
	"LD_AUDIT": both(shapePath, "the loader runs this auditing library inside every process it starts "+
		"(measured, glibc 2.43, with the control)"),
	// Measured, glibc 2.43, with the control, against a binary that already names
	// its own library directory — so this is precedence, not merely a fallback:
	//
	//	./prog                     -> LIB-FROM-A  (its own RUNPATH; control)
	//	LD_LIBRARY_PATH=$W/b ./prog-> LIB-FROM-B
	"LD_LIBRARY_PATH": both(shapePath, "every process resolves its shared libraries from here first, "+
		"ahead of the binary's own RUNPATH and the system directories (measured, glibc 2.43)"),
	// Measured, glibc 2.43, with the control. A gconv module is dlopen'd, so a
	// constructor in one runs — the object planted here was not even a valid
	// converter and its code ran anyway, which is the point:
	//
	//	GCONV_PATH=$W/gc iconv -f FAKECHARSET -t UTF-8 in.txt
	//	  -> GCONV-MODULE-CODE-RAN, then a fatal glibc assertion
	//	                   iconv -f FAKECHARSET -t UTF-8 in.txt
	//	  -> conversion from `FAKECHARSET' is not supported   (control)
	"GCONV_PATH": both(shapePath, "iconv loads a character-set conversion MODULE from here and a module is "+
		"code — a constructor in one ran on the first conversion (measured, glibc 2.43)"),
	// Measured, glibc 2.43, with the control — AND THE PREVIOUS SENTENCE DID NOT
	// SURVIVE IT. It said "a locale object is code"; it is not. glibc mmaps
	// compiled locale DATA, and a shared object placed in the same directory is
	// never loaded (the LD_PRELOAD probe above, dropped into the locale directory,
	// printed nothing):
	//
	//	LOCPATH=$W/loc LC_ALL=probe.utf8 /usr/bin/printf '%.2f\n' 1.5  -> 1,50
	//	               LC_ALL=probe.utf8 /usr/bin/printf '%.2f\n' 1.5  -> 1.50  (control)
	//	               LC_ALL=C          /usr/bin/printf '%.2f\n' 1.5  -> 1.50  (control)
	//
	// That is the same overstatement class as PS3, MALLOC_TRACE and HOSTALIASES:
	// nothing was reachable through it, and a reader who checks one sentence and
	// finds it wrong cannot tell which of the others to trust. GCONV_PATH, two
	// rows up, IS the code one — keeping them apart is the whole value of both
	// rows. TestTheFalsifiedAnnotationsStayFalsified pins this one too.
	//
	// IT IS shapePath AND IT IS DATA, AND THOSE ARE TWO ANSWERS TO TWO QUESTIONS.
	// Round 3 listed LOCPATH's accepted relative value beside the four git ones
	// and asked, fairly, whether it belongs in the same refusal given that snug's
	// own corrected sentence calls it DATA and not code. It does, and the reason
	// is that the shape column is not a hazard column: the absolute rule refuses a
	// value snug CANNOT REPRESENT — a relative path means "wherever the payload
	// last was", which no profile can have meant — and that is as true of a
	// directory glibc reads collation tables out of as of one it runs hooks from.
	// Deciding it on "is it code" is precisely how `path` came to answer two
	// questions at once (envType.pathNoGrant). What DOES follow from data-not-code
	// is the sentence, which stays as measured.
	"LOCPATH": both(shapePath, "glibc reads compiled locale DATA from here — collation, case folding, the "+
		"decimal separator, the message translations — so a locale here changes what every "+
		"process computes and prints; it is data, and nothing in the directory is loaded as "+
		"code (measured, glibc 2.43, with the control)"),
	// Measured, glibc 2.43, with the control, through a C program calling
	// catopen()/catgets() — the template is expanded per process, %N and %L
	// included:
	//
	//	NLSPATH=$W/nls/%N.cat     ./catprog -> CATALOGUE-FROM-NLSPATH
	//	NLSPATH=$W/nls/%L/%N.cat  ./catprog -> CATALOGUE-FROM-NLSPATH (LC_MESSAGES=de_DE.UTF-8)
	//	                          ./catprog -> DEFAULT-BUILTIN-STRING (control)
	//
	// It is DATA, like LOCPATH and unlike GCONV_PATH: what it buys an attacker is
	// every message a program prints, which is a lie told to whoever reads the
	// output — not an exec.
	"NLSPATH": both(shapePath, "message catalogues come from here, on a template glibc expands per process, "+
		"so the messages a program prints are the catalogue author's (measured, glibc 2.43, "+
		"with the control)"),
	// Measured, glibc 2.43, with the control — and the sentence this replaced
	// ("every hostname lookup in the sandbox is rewritten through this file")
	// was wrong in two ways at once, which is why the corrected one names both:
	//
	//   $ cat aliases;  myhost localhost
	//   $ HOSTALIASES=aliases ./gethostbyname myhost           -> localhost -> 127.0.0.1
	//   $ HOSTALIASES=aliases ./gethostbyname example.invalid  -> NULL
	//   $ ./gethostbyname myhost                               -> NULL   (control)
	//
	// DOT-FREE names only, and the mapping is name -> NAME rather than name ->
	// address (a file written with an address in the second column does nothing
	// at all, which is how the limit was found).
	"HOSTALIASES": both(shapePath, "glibc rewrites a DOT-FREE hostname to another NAME through this file "+
		"before it is resolved; a name with a dot in it is untouched (measured, glibc 2.43)"),
	// Measured, glibc 2.43, with the control — the file is PARSED, and glibc names
	// it and the line when it dislikes something:
	//
	//	RESOLV_HOST_CONF=$W/hc.txt getent hosts localhost
	//	  -> …/hc.txt: line 1: bad command `bogus-keyword yes'   then ::1 localhost
	//	                           getent hosts localhost
	//	  -> ::1 localhost, no such message                       (control)
	//
	// The sentence is narrowed to what host.conf still DOES on modern glibc: the
	// keywords are `multi`, `reorder` and `trim`, and lookup ORDER moved to
	// nsswitch.conf years ago, so "steers name lookups" — what this row used to
	// say — claimed more than the file can deliver. Note also that the host's own
	// /etc/host.conf does not exist on this box, so the variable is the only way
	// any of it is read at all here.
	"RESOLV_HOST_CONF": both(shapePath, "glibc parses this file in place of /etc/host.conf, so its multi/"+
		"reorder/trim keywords decide what /etc/hosts lookups return (measured, glibc 2.43, "+
		"with the control)"),
	// DOCUMENTED, NOT MEASURED ON THIS HOST. Tried: `RES_OPTIONS=debug getent
	// hosts example.com` printed no debug output on glibc 2.43 (the resolver's
	// debug tracing is not compiled in), and the `ndots` behaviour that would
	// otherwise be observable needs a search domain — the sandbox's generated
	// /etc/resolv.conf carries `search .`, so no name is ever qualified and the
	// option cannot change an answer here. Re-measure on a host with a real search
	// list, or against a resolver built with DEBUG.
	"RES_OPTIONS": both(shapeOpaque, "resolver options for every lookup the sandbox makes — ndots, timeout, "+
		"attempts and the rest of resolv.conf's options line (documented, not measured on "+
		"this host)"),
	"TZDIR": both(shapePath, "every timestamp in the sandbox is read from this directory; a value glibc cannot "+
		"resolve is silently re-read as an inline rule instead of failing (measured, §3.2)"),
	// Measured, glibc 2.43. The sentence this replaced ("created by every process
	// that runs") was false twice over, and BOTH preconditions matter:
	//
	//   $ strings /lib64/libc.so.6              | grep -c MALLOC_TRACE   -> 0
	//   $ strings /lib64/libc_malloc_debug.so.0 | grep -c MALLOC_TRACE   -> 1
	//   $ MALLOC_TRACE=f /bin/echo hi                                    -> no file
	//   $ LD_PRELOAD=…/libc_malloc_debug.so.0 MALLOC_TRACE=f /bin/echo hi-> no file
	//   $ MALLOC_TRACE=f ./calls-mtrace                                  -> no file
	//   $ LD_PRELOAD=…/libc_malloc_debug.so.0 MALLOC_TRACE=f ./calls-mtrace
	//                                                                    -> 79-byte trace
	//
	// The implementation is not in libc.so.6 at all any more, and the program
	// must call mtrace() itself. What remains true, and is all the row now
	// claims, is that some processes CREATE and truncate the named file.
	"MALLOC_TRACE": both(shapePath, "glibc writes an allocation trace here, but only for a process that calls "+
		"mtrace() AND has libc_malloc_debug.so preloaded (measured, glibc 2.43)"),
	// DOCUMENTED, NOT MEASURED ON THIS HOST, and the previous sentence
	// ("getconf answers from this directory instead of the system's") asserted a
	// behaviour nothing here could produce. Tried: GETCONF_DIR appears in
	// libc.so.6 (1 hit) and NOT in /usr/bin/getconf; /usr/lib64/getconf and
	// /usr/libexec/getconf do not exist; `getconf -v SPEC PATH` with an
	// executable planted at $GETCONF_DIR/SPEC changed no answer and ran nothing,
	// for three different SPECs; there is no getconf(1) man page inside this
	// sandbox to cite either. Re-measure on a host that ships per-spec getconf
	// binaries.
	"GETCONF_DIR": both(shapePath, "getconf takes its specification directory from here, and for a spec it does "+
		"not implement natively it EXECUTES a program from it (documented, not measured)"),
	// DOCUMENTED, NOT MEASURED ON THIS HOST. Tried: there is no NIS here to
	// measure against — no `ypcat`, no `ypwhich`, no /var/yp, and nsswitch.conf
	// mentions `nis` only in its comment block, so no lookup ever reaches the NIS
	// backend. The row stays because the variable is read by glibc's NIS+ code
	// whenever that backend IS configured, and a reader deciding whether to
	// inherit it should be told what it steers rather than nothing.
	//
	// shapeOpaque DESPITE THE WORD "path" IN BOTH THE NAME AND THE SENTENCE, and
	// it is the one row where that word means something else: the elements are
	// NIS+ DIRECTORY NAMES in the NIS+ namespace (`org_dir.example.com.`), not
	// filesystem paths, so demanding a leading '/' would refuse every correct
	// value. Left unmeasured with the rest of the row — there is no NIS on this
	// host — and flagged here because a future reader sweeping for path-shaped
	// names will land on it.
	"NIS_PATH": both(shapeOpaque, "NIS+ lookups search this path, so it decides which server's tables the "+
		"sandbox believes (documented, not measured on this host)"),

	// ── git and ssh: the value is a program ──────────────────────────────────
	//
	// Each measured on git 2.55 rather than reasoned about. A redteam run reached
	// git's transport through GIT_SSH while GIT_SSH_COMMAND — its exact
	// equivalent — was refused two lines up, and hijacked a `git fetch` in a
	// sandbox that had been given a PINNED ssh identity by a DIFFERENT profile:
	//
	//   snug -p work -p helper <tgt> -- git fetch origin
	//     HIJACKED-GIT-TRANSPORT host=git@github.com … SSH_AUTH_SOCK=/snug/ssh-agent.sock
	//
	// `helper` granted no filesystem path at all. That finding is why the
	// sentences below say what the program is USED FOR: one profile can weaken
	// what another established, and the composition is only visible if the screen
	// says so at every spelling. The rule was never "the newest spelling"; it is
	// "the value is code", and forgetting one is indistinguishable from having
	// nothing to say about it.
	// Every row in this block now carries its own measurement, because the block
	// heading above carried one sentence ("each measured on git 2.55") for eight
	// rows and a reader cannot check a claim made on someone else's behalf. Run
	// today, git 2.55.0 / OpenSSH, each with the control that fails without the
	// variable:
	//
	//	GIT_SSH_COMMAND=/tmp/gs.sh git ls-remote git@example.com:x/y
	//	  -> GIT-SSH-COMMAND-RAN args=git@example.com git-upload-pack 'x/y'
	//	GIT_EXEC_PATH=/tmp/gx git probecmd
	//	  -> GIT-EXEC-PATH-SUBCOMMAND-RAN uid=1000
	//	                        git probecmd  -> 'probecmd' is not a git command (control)
	//	GIT_EXTERNAL_DIFF=/tmp/xd.sh git diff -> GIT-EXTERNAL-DIFF-RAN path=f
	//	                              git diff-> the real diff                    (control)
	//	GIT_EDITOR=/tmp/ed.sh git commit      -> GIT-EDITOR-RAN args=.git/COMMIT_EDITMSG,
	//	                                         and the commit message is the one the
	//	                                         script wrote
	//	GIT_SEQUENCE_EDITOR=/tmp/seq.sh git rebase -i --root
	//	  -> GIT-SEQUENCE-EDITOR-RAN todo=.git/rebase-merge/git-rebase-todo, before
	//	     any commit was replayed
	//	GIT_PROXY_COMMAND=/tmp/px.sh git ls-remote git://example.com/x
	//	  -> GIT-PROXY-COMMAND-RAN args=example.com 9418
	//	GIT_ASKPASS=/tmp/ask.sh git ls-remote http://127.0.0.1:8731/x   (a 401 server)
	//	  -> GIT-ASKPASS-RAN prompt=Username for 'http://127.0.0.1:8731'
	//	     GIT-ASKPASS-RAN prompt=Password for 'http://secret@127.0.0.1:8731'
	//	     — so it is handed the prompt AND its answer is used
	//	                            git ls-remote http://127.0.0.1:8731/x
	//	  -> could not read Username: terminal prompts disabled          (control)
	//	SSH_ASKPASS=/tmp/sa.sh SSH_ASKPASS_REQUIRE=force ssh-keygen -y -f k
	//	  -> SSH-ASKPASS-RAN prompt=Enter passphrase for "k", and the key DECRYPTED
	//	     with what the script printed
	//	                       SSH_ASKPASS_REQUIRE=force ssh-keygen -y -f k
	//	  -> the system askpass ran; incorrect passphrase                (control)
	"GIT_SSH_COMMAND": both(shapeProgram, "git runs this as the transport for every fetch and push, with whatever "+
		"ssh identity this sandbox was given (measured, git 2.55.0)"),
	"GIT_SSH": both(shapeProgram, "git runs this as the transport for every fetch and push — the older spelling of "+
		"GIT_SSH_COMMAND, measured to hijack a real `git fetch`"),
	"GIT_EXEC_PATH": both(shapePath, "git finds its own subcommands here, so `git anything` runs a program "+
		"from this directory (measured, git 2.55.0, with the control)"),
	"GIT_EXTERNAL_DIFF": both(shapeProgram, "git runs this program for every diff it produces (measured, "+
		"git 2.55.0, with the control)"),
	"GIT_EDITOR": both(shapeProgram, "git runs this whenever a commit, tag or rebase opens an editor, and what "+
		"it writes becomes the commit message (measured, git 2.55.0)"),
	"GIT_SEQUENCE_EDITOR": both(shapeProgram, "git runs this to edit the todo list of every interactive rebase, "+
		"before any commit is replayed (measured, git 2.55.0)"),
	"GIT_PROXY_COMMAND": both(shapeProgram, "git runs this as the transport proxy for git:// URLs (measured, "+
		"git 2.55.0)"),
	"GIT_ASKPASS": both(shapeProgram, "git runs this to ask for a credential, so it is handed whatever it asks "+
		"for and its answer is used (measured, git 2.55.0, with the control)"),
	"SSH_ASKPASS": both(shapeProgram, "ssh runs this to ask for a passphrase, so it is handed whatever it asks "+
		"for — measured decrypting a key with what the helper printed (with the control)"),
	// Measured on git 2.55, with the command that showed it:
	//   GIT_PAGER="sh -c 'echo HIJACK; cat >/dev/null'" git log   -> HIJACK
	//
	// Re-measuring this one needs a PTY: git only starts a pager when stdout is a
	// terminal, so the same command through a pipe runs nothing and reads as a
	// refutation of a true sentence (confirmed again in redteam host round 2).
	"GIT_PAGER": both(shapeProgram, "git runs this over the output of log, diff and show (measured, git 2.55)"),
	// GIT_TEMPLATE_DIR, GIT_DIR and GIT_COMMON_DIR are the same power one
	// indirection out: the value is a DIRECTORY, and the hooks in it are code.
	// Granting the path is not what makes them safe — nothing does, which is why
	// these are not path-coupling rows. GIT_COMMON_DIR was missed in the first
	// pass and found by an independent review's sweep, not by reasoning.
	//
	// THE SENTENCE "the value is a DIRECTORY" IS NOW A FIELD as well as prose,
	// and that is round 3's finding: these three and GIT_EXEC_PATH above said
	// exactly this on --dry-run while a relative value was accepted, because the
	// absolute-path rule read the roster and the pointer table and not the thing
	// snug was printing. `GIT_TEMPLATE_DIR = "tpl"` and `GIT_EXEC_PATH = "gx"`
	// were each measured executing attacker code out of `--chdir <target>`.
	// shapePath refuses the relative spelling; it does NOT make them coupling
	// rows, so the paragraph above stands unchanged.
	"GIT_TEMPLATE_DIR": both(shapePath, "the hooks in this directory are installed into every repository "+
		"`git clone` and `git init` create afterwards (measured: post-checkout fired on the clone)"),
	"GIT_DIR": both(shapePath, "git works in this repository, and the hooks in it run on the next commit (measured)"),
	"GIT_COMMON_DIR": both(shapePath, "git reads hooks/ from this directory, and a pre-commit there ran on the "+
		"next commit (measured, git 2.55)"),
	// A different shape again, and the reason the class is "the value is code"
	// rather than "the value is a command": these two carry no code at all. They
	// switch OFF git's own refusal to use the ext:: transport, which runs an
	// arbitrary command as the transport. Measured, with the control:
	//
	//   GIT_ALLOW_PROTOCOL=ext git ls-remote "ext::sh -c '…'"   -> ran
	//                           git ls-remote "ext::sh -c '…'"   -> refused
	//
	// A name that re-enables an exec path is the exec path.
	"GIT_ALLOW_PROTOCOL": both(shapeOpaque, "re-enables git's ext:: transport, which runs an arbitrary command "+
		"as the transport (measured, with the control)"),
	"GIT_PROTOCOL_FROM_USER": both(shapeOpaque, "re-enables the transports git refuses by default, ext:: among them "+
		"(measured, with the control)"),

	// ── a runtime's own flag channel, parsed before main() ───────────────────
	//
	// MEASURED IN A CONTAINER, NOT ON THIS HOST — temurin 21 JDK, pulled and
	// removed again (redteam host round 2). All three channels applied before
	// main(), announcing themselves, and the first one loaded an AGENT:
	//
	//	JAVA_TOOL_OPTIONS=…  -> "Picked up JAVA_TOOL_OPTIONS: …", flags applied
	//	_JAVA_OPTIONS=…      -> "Picked up _JAVA_OPTIONS: …"
	//	JDK_JAVA_OPTIONS=…   -> "NOTE: Picked up JDK_JAVA_OPTIONS: …"
	//	JAVA_TOOL_OPTIONS="-javaagent:/w/ag.jar" java Main
	//	  -> JAVA-AGENT-RAN-BEFORE-MAIN, then main
	//
	// These three carried NO marker at all for a milestone, four lines above a
	// CLASSPATH row that did — on a host whose very next comment says it has no
	// JVM. That asymmetry is what F4 of that round was about, and it is why the
	// contract is now swept mechanically
	// (TestEveryAnnotationSaysWhetherItWasMeasured).
	"JAVA_TOOL_OPTIONS": both(shapeOpaque, "every JVM in the sandbox parses these flags before main(), and they "+
		"can load an agent from a path — measured, temurin 21, in a container: the agent's "+
		"premain ran before main"),
	"_JAVA_OPTIONS": both(shapeOpaque, "every JVM parses these flags before main() — the second spelling of the "+
		"same channel (measured, temurin 21, in a container)"),
	"JDK_JAVA_OPTIONS": both(shapeOpaque, "the `java` launcher parses these flags before main(), agents included "+
		"(measured, temurin 21, in a container)"),
	// DOCUMENTED, NOT MEASURED ANYWHERE YET. Tried: there is no `ruby` and no
	// `irb` on this host, and unlike the JVM nobody has yet run it in a container
	// either — so this row is the last one in the table whose sentence rests on
	// documentation alone. ruby(1) documents RUBYOPT as accepting the same
	// -r/-I/-e-adjacent switches the command line takes, which is where "require a
	// file" comes from. Vendoring a ruby is the measurement; until someone does,
	// the row says so.
	"RUBYOPT": both(shapeOpaque, "every ruby parses these flags before the script and can require a file from "+
		"them (documented, not measured on this host — no ruby here)"),

	// cargo executes an arbitrary program as its own compiler driver — measured
	// (issue #26 red team): a profile with RUSTC_WRAPPER pointing at a script
	// made `cargo build` run that script in place of rustc, as the sandbox's own
	// uid, through both `environ.set` and `environ.inherit`. RUSTC_WORKSPACE_WRAPPER
	// and RUSTC carry the identical capability — the same one
	// CARGO_BUILD_RUSTC_WRAPPER carries under the CARGO_ prefix below — but none
	// of the three starts with a listed prefix, which is why they are named here
	// as well. That is the shape CLAUDE.md keeps recording: a rule applied to one
	// of its two spellings.
	"RUSTC_WRAPPER":           both(shapeProgram, "cargo runs this in place of rustc, as the sandbox's own uid (measured, issue #26)"),
	"RUSTC_WORKSPACE_WRAPPER": both(shapeProgram, "cargo runs this in place of rustc for workspace crates (measured, issue #26)"),
	"RUSTC":                   both(shapeProgram, "cargo runs this AS rustc (measured, issue #26)"),

	// The same class one indirection further out: a build tool's own "run this
	// program instead" or "pass these extra flags" variable, each measured to run
	// an attacker-chosen program as the sandbox's own uid — a second-pass review
	// sweep, not a spelling anyone reasoned about ahead of time. This is why the
	// table is enumerated rather than derived: the space of "an env var some tool
	// turns into exec" is unbounded, and each of these was found only by trying
	// it.
	//
	//   MAKEFLAGS="--eval=x:;$(shell ./evil.sh)"  make        -> evil.sh ran   (GNU make 4.x)
	//   GOFLAGS="-toolexec=/…/toolexec.sh"         go build    -> ran per compile (go 1.26)
	//   CC=./evil.sh                                make        -> ran as the compiler, via make's implicit rules
	//   TAR_OPTIONS="--use-compress-program=/…/prog.sh"  tar   -> prog.sh ran   (GNU tar 1.35)
	//   RSYNC_RSH=/…/prog.sh                        rsync       -> prog.sh ran   (rsync 3.4.3)
	"MAKEFLAGS": both(shapeOpaque, "make evaluates this before any rule, and `--eval=$(shell …)` runs a command "+
		"(measured, GNU make 4.x)"),
	"GOFLAGS": both(shapeOpaque, "go passes these to every compile, and -toolexec names a program it runs "+
		"(measured, go 1.26)"),
	"CC":          both(shapeProgram, "make's implicit rules run this as the compiler (measured)"),
	"TAR_OPTIONS": both(shapeOpaque, "tar reads these flags, and --use-compress-program names a program it runs (measured)"),
	"RSYNC_RSH":   both(shapeProgram, "rsync runs this as its remote shell (measured, rsync 3.4.3)"),

	// bash performs command substitution on the prompt templates, before the user
	// has typed anything (§3.5). PS1 is not here: it is snug's own.
	//
	// Measured, bash 5.3.15, all four in one run — and PS3 is the exception this
	// block used to state as the rule:
	//
	//   PS0='[$(echo PS0-SUBST-RAN >&2)]'  ...      -> PS0-SUBST-RAN   (substituted)
	//   PS2='[$(echo PS2-SUBST-RAN >&2)]'  ...      -> PS2-SUBST-RAN   (substituted)
	//   PS4='[$(echo PS4-SUBST-RAN >&2)]' set -x    -> PS4-SUBST-RAN   (substituted)
	//   PS3='[$(echo PS3-SUBST-RAN >&2)] pick: ' select …
	//        -> printed LITERALLY; the marker never ran
	//   PS3='[HOME=$HOME] `echo bt` ${PWD} pick: '  -> printed LITERALLY, all three
	// PS2 and PS4 were re-run today, bash 5.3.15, because the block heading's
	// "all four in one run" was doing the work for four rows and only two of them
	// said so on the screen:
	//
	//	printf 'echo "a\nb"\nexit\n' | PS2='[$(echo PS2-SUBST-RAN >&2)]> ' bash -i
	//	  -> PS2-SUBST-RAN, then the continuation prompt "[]> "
	//	PS4='[$(echo PS4-SUBST-RAN >&2)]' bash -c 'set -x; :'
	//	  -> PS4-SUBST-RAN, then the trace line "[]:"
	"PS0": both(shapeOpaque, "bash performs command substitution on this before every command it runs "+
		"(measured, bash 5.3.15)"),
	"PS2": both(shapeOpaque, "bash performs command substitution on this prompt template, which a human sees "+
		"the moment a command spans two lines (measured, bash 5.3.15)"),
	// PS3 is the one prompt bash does NOT run through decode_prompt_string, and
	// this row claimed the opposite for a milestone. The row stays rather than
	// being deleted: without it the next reader re-derives the false claim from
	// PS0/PS2/PS4 by analogy, which is exactly how it was written the first time.
	"PS3": both(shapeOpaque, "bash prints this VERBATIM as the `select` prompt — no command substitution and "+
		"no parameter expansion (measured, bash 5.3.15); what it buys is a prompt that lies "+
		"to whoever is at the shell"),
	"PS4": both(shapeOpaque, "bash performs command substitution on this trace prompt, before you type "+
		"anything (measured, bash 5.3.15)"),
	// Measured today, bash 5.3.15, with the control — and this row is the one that
	// showed how a shared comment block can rubber-stamp a row it never covered:
	// PROMPT_COMMAND sat under the PS block's "measured, all four in one run",
	// which was about PS0/PS2/PS3/PS4 and never about this name.
	//
	//	printf 'exit\n' | PROMPT_COMMAND='echo PROMPT-COMMAND-RAN >&2' bash -i
	//	  -> PROMPT-COMMAND-RAN, before the first prompt
	//	printf 'exit\n' | bash -i                              -> nothing (control)
	"PROMPT_COMMAND": both(shapeProgram, "bash runs this command before every prompt it draws, including the "+
		"first one (measured, bash 5.3.15, with the control)"),

	// An interpreter's own "run this file/module before anything else" variable.
	// These four sat in the middle bucket ("reviewable as set") until a
	// measurement moved them: that call is right for a variable carrying a path a
	// tool merely READS (BASH_ENV, ENV, LESSOPEN below) and wrong for one
	// carrying a path a tool EXECUTES unconditionally on every invocation, which
	// is what these turned out to be — indistinguishable in shape from
	// RUSTC_WRAPPER.
	//
	//   PYTHONUSERBASE=…  python3 -c 'import site'
	//     -> …/site-packages/usercustomize.py ran on every python3   (CPython 3.13)
	//   PYTHONPATH=…      python3 -c 'pass'
	//     -> sitecustomize.py on that path ran at interpreter start   (CPython)
	//   NODE_OPTIONS="--require /…/pre.js"  node ...
	//     -> pre.js ran before the script, every invocation             (node 26)
	//   PERL5OPT="-I/… -Mevil"  perl ...
	//     -> evil.pm loaded on every perl invocation                    (perl 5)
	"PYTHONUSERBASE": both(shapePath, "python runs usercustomize.py from under this path on every start "+
		"(measured, CPython 3.13)"),
	"PYTHONPATH": both(shapePath, "python runs sitecustomize.py from any element of this at interpreter start "+
		"(measured, CPython)"),
	"NODE_OPTIONS": both(shapeOpaque, "node runs whatever --require names here, before the script, on every "+
		"invocation (measured, node 26)"),
	"PERL5OPT": both(shapeOpaque, "perl loads whatever -M names here, on every invocation (measured, perl 5)"),

	// ── search paths a consumer SOURCES or LOADS from ────────────────────────
	//
	// The same class as PYTHONPATH above and found the same way — by trying it,
	// not by reasoning. Every one of these is a ROSTERED list, which means a
	// profile snug SHIPS may write it (checkBuiltinEnvRoster), and until this
	// pass all four handed over an exec surface with nothing said about it while
	// their measured sibling PYTHONPATH carried a sentence.
	//
	//   XDG_DATA_DIRS=$D bash -c 'source /usr/share/bash-completion/bash_completion
	//                             _comp_load frobnicate'
	//     -> $D/bash-completion/completions/frobnicate SOURCED, uid 1000
	//        (bash-completion 2.12.0). Control with the variable unset: nothing.
	//        /usr/share/bash-completion/bash_completion:3262 splits it; :3235 does
	//        the same for XDG_DATA_HOME, which is issue #84 and is discussed at
	//        @home rather than here.
	//   PERL5LIB=$D perl -MText::Abbrev -e 1
	//     -> $D/Text/Abbrev.pm loaded INSTEAD of the system module (perl 5.44.0).
	//        Control: the real one loads. The shadowing is the point — the element
	//        is searched ahead of the system directories.
	//   NODE_PATH=$D node -e 'require("evilmod")'
	//     -> $D/evilmod/index.js top-level code ran, uid 1000 (node 26.4.0).
	//        Control: MODULE_NOT_FOUND. Core modules ("util") are NOT shadowed,
	//        which is why the sentence says so rather than overstating.
	"XDG_DATA_DIRS": both(shapePath, "bash-completion SOURCES a file from <element>/bash-completion/completions "+
		"on the next completion (measured, bash-completion 2.12.0, with the control)"),
	"PERL5LIB": both(shapePath, "perl searches these BEFORE the system directories, so a module here replaces "+
		"the real one and its top-level code runs (measured, perl 5.44)"),
	"NODE_PATH": both(shapePath, "node resolves require() from here and runs the module's top-level code; "+
		"core modules are not shadowed (measured, node 26.4, with the control)"),
	// MEASURED IN A CONTAINER, NOT ON THIS HOST — temurin 21 JDK (alpine), pulled
	// and removed again; there is still no `java`, no `javac` and no /usr/lib*/jvm
	// here. Recorded that way on purpose: a measurement whose environment is not
	// this host is worth more than "documented" and less than a bare measurement,
	// and the sentence says which.
	//
	// The row it replaced said "a class on this path replaces the real one", which
	// OVERSTATES in exactly the way NODE_PATH's row is careful not to. With the
	// controls (redteam host round 2, F3):
	//
	//	CLASSPATH=capp:ca:cb java Main            -> LIB-FROM-A  (first entry wins)
	//	CLASSPATH=capp:cb:ca java Main            -> LIB-FROM-B  (order decides)
	//	CLASSPATH=capp:cb:ca java -cp capp:ca Main-> LIB-FROM-A  (-cp OVERRIDES it)
	//	CLASSPATH=/w/ca java -jar mainonly.jar    -> NoClassDefFoundError (-jar IGNORES it)
	//	control, same classpath without -jar      -> LIB-FROM-A
	//	javac -d cboot boot/java/util/Objects.java-> error: package exists in
	//	                                             another module: java.base
	//	CLASSPATH=/w/cboot java JdkProbe          -> loader of Objects=null
	//	                                             (a JDK class is NOT shadowed)
	//
	// So it holds for an APPLICATION class, only when the JVM is launched without
	// -cp and without -jar, and never for a platform class. No CI can run a JVM,
	// so testdata/annotations.txt IS the artifact for this wording.
	"CLASSPATH": both(shapePath, "the JVM's application class loader searches these in order, so an "+
		"application class here shadows one later on the path; platform/JDK classes are not "+
		"shadowed, and `java -cp` and `java -jar` ignore this variable outright (measured, "+
		"temurin 21, in a container — no JVM on this host)"),

	// ── the startup files a tool READS: two sentences, and the difference is
	// where the value came from ──────────────────────────────────────────────
	//
	// This is the old forbidInheritOnly bucket, and it is where the authored/host
	// split earns its keep: `BASH_ENV = "{home}/init"` in a profile that also
	// grants the path is a coherent, reviewable thing to write, while the same
	// name inherited names a file chosen on the host by whatever launched snug.
	// The refusal that used to express that difference is gone; the difference is
	// not, so it is said twice.
	// "grant the path in the same profile" USED TO STAND HERE and it was an
	// instruction snug did not carry out: these names are `path: false` for the
	// coupling rule, so nothing checked the grant, and a sentence that reads as a
	// rule while nothing enforces it is the "a gate that is documented but not
	// implemented is not a gate" shape. What IS enforced is the absolute-path
	// rule (pathNoGrant, envcoupling.go), so the sentences now state that and
	// describe the ungranted case as the consequence it is — the row still
	// renders `← not granted` for a path nothing covers.
	//
	// ALL THREE WERE MEASURED, with the cwd control, and the transcript is in
	// envTypes' comment on the same three names rather than copied here (one
	// measurement, one place):
	//
	//	cd cwd1; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> sourced from cwd1
	//	cd cwd2; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> nothing (control)
	//	cd cwd1; ENV=.shinit sh -i -c 'echo body'            -> sourced from cwd1
	//	cd cwd1; PYTHONSTARTUP=pystart.py python3 -i         -> ran (CPython 3.13.14)
	"BASH_ENV": {shape: shapePath,
		authored: "every non-interactive bash SOURCES this file at startup; the value must be an " +
			"absolute path, and one this profile does not grant names a file the sandbox will not have",
		host: "every non-interactive bash SOURCES this file at startup, and the file is chosen on the host, outside any profile",
	},
	// Measured with the cwd control, see the block comment above BASH_ENV.
	"ENV": {shape: shapePath,
		authored: "every non-interactive sh SOURCES this file at startup; the value must be an " +
			"absolute path, and one this profile does not grant names a file the sandbox will not have",
		host: "every non-interactive sh SOURCES this file at startup, and the file is chosen on the host, outside any profile",
	},
	// Measured, CPython 3.13.14, with the cwd control — see the block comment
	// above BASH_ENV.
	"PYTHONSTARTUP": {shape: shapePath,
		authored: "the interactive python interpreter EXECUTES this file on start; the value must be " +
			"an absolute path, and one this profile does not grant names a file the sandbox will not have",
		host: "the interactive python interpreter EXECUTES this file on start, and the file is chosen on the host",
	},
	// Measured, CPython 3.13.14, and this is why PYTHONBREAKPOINT is NOT
	// path-valued in any sense the coupling or absolute rules should touch:
	//
	//   PYTHONPATH=$D PYTHONBREAKPOINT=bpmod.hook python3 -c 'breakpoint()'
	//     -> the callable ran
	//   PYTHONBREAKPOINT=/tmp/nonexistent.py     python3 -c 'breakpoint()'
	//     -> RuntimeWarning: Ignoring unimportable $PYTHONBREAKPOINT
	//
	// A PATH is refused by python itself. Requiring one here would refuse the
	// only correct spelling.
	"PYTHONBREAKPOINT": {shape: shapeOpaque,
		authored: "this names the callable breakpoint() invokes, so it is imported and run",
		host:     "this names the callable breakpoint() invokes, chosen on the host, outside any profile",
	},
	// LESSOPEN carried "grant the path in the same profile" too, and there it was
	// wrong twice: unenforced, AND about the wrong kind of value. Measured:
	//
	//   LESSOPEN="|$D/lo.sh %s" less -F f.txt   -> lo.sh ran on the file
	//
	// The value is a command line whose leading '|' selects the pipe form, not a
	// path — the other half of why these five names are not path-valued.
	"LESSOPEN": {shape: shapeProgram,
		authored: "less runs this program over every file it opens; the value is a command line, " +
			"not a path — the '|' form pipes the file through it (measured)",
		host: "less runs this program over every file it opens, and it is chosen on the host",
	},

	// ── the generic three, which the git entries above do NOT close ──────────
	//
	// Measured: git falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR and
	// GIT_PAGER -> core.pager -> PAGER, and `PAGER="sh -c '…'" git log` runs the
	// command. So refusing the GIT_* spellings never closed the class — it closed
	// the invisible half of it, and the two halves differ in who they surprise: a
	// profile setting EDITOR is doing a legible thing to a variable a human
	// recognises, while the GIT_* names fire during operations nobody thinks of as
	// running a command.
	//
	// That asymmetry is exactly what an annotation fixes and a refusal could not.
	// @claude inherits all three, so this is the sentence a human sees on a
	// perfectly ordinary run — issues #35 and #45, both of which were asking for
	// the reader to be told rather than for the grant to be withdrawn.
	"EDITOR": both(shapeProgram, "the value is a command; git runs it for a commit message via "+
		"GIT_EDITOR -> core.editor -> VISUAL -> EDITOR (measured)"),
	"VISUAL": both(shapeProgram, "the value is a command; git runs it for a commit message when GIT_EDITOR and "+
		"core.editor are unset (measured)"),
	"PAGER": both(shapeProgram, "the value is a command; git runs it over log, diff and show via "+
		"GIT_PAGER -> core.pager -> PAGER (measured)"),

	// ── the endpoint @claude inherits ────────────────────────────────────────
	//
	// Not an exec vector at all, and it is here to show that the table is about
	// what a value DOES rather than about a single hazard: nothing runs this, and
	// a human still wants to know that a profile chose where the agent's traffic
	// goes.
	//
	// DOCUMENTED, NOT MEASURED ON THIS HOST. Tried: the only consumer here is the
	// Claude Code client, and the measurement — point a live agent session at a
	// local endpoint and watch a conversation arrive — is one nobody should take
	// from inside a live agent session, which is where every run of this suite
	// happens. The row rests on the client's documented behaviour, and @claude
	// inherits the name precisely so a human behind a gateway keeps working; if it
	// is ever measured, it wants a throwaway credential and a local listener.
	"ANTHROPIC_BASE_URL": both(shapeOpaque, "every request the agent makes, conversation included, goes to this "+
		"endpoint instead of Anthropic's (documented, not measured on this host)"),

	// ── the three other Claude Code surfaces, and they are three DIFFERENT
	//    hazards under one prefix ─────────────────────────────────────────────
	//
	// All four names here are in inlineConfigNames, which is a fact about the
	// SINK sweep over a resolved policy. These sentences are the other half: what
	// a human reads on the row when their own profile writes one.
	//
	// DOCUMENTED, NOT MEASURED ON THIS HOST, and the reason is the same one
	// ANTHROPIC_BASE_URL gives — the only consumer is the Claude Code client and
	// every run of this suite happens inside a live agent session. What IS
	// measured is the quotation: verbatim from the installed claude 2.1.232
	// binary's own settings-schema description of the `processWrapper` key,
	// "Equivalent to the CLAUDE_CODE_PROCESS_WRAPPER environment variable, which
	// takes precedence when set."
	//
	// The argv prefix is the sharpest spelling of "the value is code" in this
	// table: it does not name a program the tool MIGHT run, it names what runs
	// INSTEAD of every process the tool spawns. That is why it is not one
	// sentence shared with the three credentials below it — those leak, this one
	// executes, and a reader who is handed "this is sensitive" for both learns
	// nothing about either.
	"CLAUDE_CODE_PROCESS_WRAPPER": {shape: shapeProgram,
		authored: "this profile chooses an argv PREFIX for the agent's supervisor and every session " +
			"and worker it hosts, so the value runs in place of each process the agent spawns " +
			"(documented, not measured on this host)",
		host: "the agent's supervisor and every session and worker it hosts run behind this argv " +
			"prefix, chosen on the host, outside any profile",
	},
	// The credential three. The value IS the secret, so unlike every pointer in
	// this table there is no file for a human to read: /proc/self/environ is
	// readable by every process in the sandbox and inherited by every child, and
	// that is the sentence, not "this is secret".
	//
	// TWO CLAIMS, AND THEY HAVE DIFFERENT EVIDENCE, which is why this note is
	// here rather than folded into the block above. That the client ACCEPTS each
	// of these names as a credential is DOCUMENTED, NOT MEASURED ON THIS HOST,
	// for the reason ANTHROPIC_BASE_URL gives — the measurement wants a throwaway
	// credential and a live session, and every run of this suite happens inside
	// one. ANTHROPIC_AUTH_TOKEN is named beside apiKeyHelper in the installed
	// binary's own credential-selection strings, which is where the third name
	// came from rather than from a list someone remembered.
	//
	// That every process in the sandbox can READ them is not a fact about the
	// client at all — it is /proc, it is measured (VERIFY.md §6b reads
	// /proc/1/environ), and it holds whatever the consumer does with the value.
	// Keeping the two apart matters because the second is what makes the
	// sentence actionable: the remedy is a credentials FILE, which is what
	// @claude stages.
	"CLAUDE_CODE_OAUTH_TOKEN": both(shapeOpaque,
		"the value IS the agent's credential, and every process in the sandbox reads it out of "+
			"/proc/self/environ; @claude stages a credentials FILE instead, for that reason"),
	// The name came from the installed claude 2.1.232 binary's own
	// credential-selection strings, where it sits beside apiKeyHelper — that
	// much is measured, by reading the binary. What the client DOES with it is
	// DOCUMENTED, NOT MEASURED ON THIS HOST, for the reason two rows up.
	"ANTHROPIC_AUTH_TOKEN": both(shapeOpaque,
		"the value IS an API credential — named beside apiKeyHelper in the client's own "+
			"credential-selection strings — and every process in the sandbox reads it out of "+
			"/proc/self/environ"),
	// Already covered twice over — by the secrets sweep and by @claude's
	// environ.inherit refusing it by name — and here anyway, because a name
	// covered by one mechanism and not the other is how the two come to disagree
	// about it. DOCUMENTED, NOT MEASURED ON THIS HOST. Tried: the consumer is the
	// Claude Code client, and confirming which name it prefers means starting a
	// session with a throwaway credential in each variable and watching which one
	// authenticates — from inside a live agent session, which is where every run
	// of this suite happens. It wants a scratch account and a host-side run.
	"ANTHROPIC_API_KEY": both(shapeOpaque,
		"the value IS an API credential, and every process in the sandbox reads it out of "+
			"/proc/self/environ; @claude's environ.inherit refuses this name for the same reason"),

	// ── "generate, don't bind", the pointers ─────────────────────────────────
	//
	// These carried `noInherit: true` in the roster, whose message was "snug
	// refuses to take this from the host": a verdict about the author, inside a
	// table of type facts. The `host` sentence is what that became.
	//
	// THE `authored` SENTENCE SAYS WHAT THE FILE IS, and for a milestone there
	// was none — on the argument that a pointer "is the mechanism, not the
	// hazard", which is true of the MECHANISM and says nothing about where the
	// pointer is aimed. Nothing enforces "at a file the profile authored": the
	// coupling rule asks only that the path be GRANTED, and `rw = ["{target}"]`
	// is a grant. Measured (issue #44 redteam, reproduced here): one profile
	// aimed all five inside the target — the one directory a hostile payload
	// writes — and the screen said NOTHING on four of five rows. Each was one
	// config file from exec as the sandbox's own uid:
	//
	//	CARGO_HOME/config.toml   [build] rustc-wrapper  -> ran, cargo 1.97.1, uid 1000
	//	DOCKER_CONFIG/config.json {"credsStore":"evil"} -> docker-credential-evil ran
	//	                                                   on `docker pull`, before the
	//	                                                   daemon socket (docker 29.4)
	//	GIT_CONFIG_SYSTEM        [alias] st = "!echo"   -> ran, git 2.55.0
	//	                         core.sshCommand        -> EXECUTED as the transport
	//
	// So the exemption in envNotePrefixes means "no FAMILY sentence", not "no
	// sentence": warning about a pointer with its family's wording at the verb
	// that AUTHORS it would be snug arguing with its own "generate, don't bind"
	// rule (that was the PIP_ defect), while saying what the file IS is the
	// disclosure a reader needs in order to aim it somewhere the payload cannot
	// write. Aim it at a directory the profile authored.
	//
	// GIT_CONFIG_GLOBAL and GH_CONFIG_DIR are pointers too and are deliberately
	// ABSENT: they are in SnugOwnedEnv, so no profile reaches them at any verb,
	// and this table's rule is that snug's own names stay out of it — a row here
	// invites someone to read it as permission. testdata/annotations.txt renders
	// them as "(no profile may write this name)" so the artifact still accounts
	// for every pointer.
	//
	// The XDG four and XDG_RUNTIME_DIR carry NO `authored` sentence, and that is
	// a decision with a measurement behind it rather than an omission — issue
	// #84. They are the same shape one layer down: @home creates those
	// directories, so setting one to a path the same profile grants is the
	// intended use, and taking the host's names a directory the sandbox does not
	// have. XDG_RUNTIME_DIR additionally carries obligations a bare string cannot
	// satisfy — mode 0700, owned by the user, session lifetime.
	//
	// What #84 records, measured on this host: git reads a COMMAND TABLE from
	// $XDG_CONFIG_HOME/git/config (alias `!cmd` ran as uid 1000, core.sshCommand
	// was executed as the transport — git 2.55.0, with ~/.gitconfig present, and
	// note that GIT_CONFIG_GLOBAL being set suppresses it, which is how the first
	// attempt at this measurement produced a false negative), and bash-completion
	// SOURCES $XDG_DATA_HOME/bash-completion/completions/<cmd> (bash-completion
	// 2.12.0, with the control). Both directories are @home's writable tmpfs.
	// It is deferred for three reasons: two of the four names have no measured
	// exec surface at all, so a uniform XDG annotation would be half unmeasured;
	// the advice a pointer sentence carries — aim it where the payload cannot
	// write — is unfollowable by @home, because an XDG base directory must be
	// writable; and the hazard is the writable TMPFS, which the FILESYSTEM block
	// already shows, so the mark would attach to the wrong grant and fire on
	// every default run. internal/cli/testdata/env.defaults.txt staying unchanged is
	// the review artifact for that decision.
	"XDG_CONFIG_HOME": {shape: shapePath, host: "the host's value names a directory this sandbox does not have; " +
		"@home creates the one inside, so `set` it to a path the same profile grants"},
	// These five say something about SNUG rather than about a tool, so what backs
	// them is snug's own artifacts rather than a shell transcript — and that is
	// still a measurement, taken against files in this repository rather than
	// against this developer's memory of them: internal/profile/profiles/base.toml
	// ([profile.home]) is where the four directories are created, and
	// internal/cli/testdata/env.defaults.txt is the rendered proof that a default run
	// sets the four names to paths inside. If @home ever stops creating one, that
	// golden moves and these sentences are wrong in the same commit.
	// (measured against @home's grants and env.defaults.txt)
	"XDG_CACHE_HOME": {shape: shapePath, host: "the host's value names a directory this sandbox does not have; " +
		"@home creates the one inside, so `set` it to a path the same profile grants"},
	// (measured the same way: @home's tmpfs list and env.defaults.txt)
	"XDG_STATE_HOME": {shape: shapePath, host: "the host's value names a directory this sandbox does not have; " +
		"@home creates the one inside, so `set` it to a path the same profile grants"},
	// (measured the same way: @home's tmpfs list and env.defaults.txt — and
	// $XDG_DATA_HOME is the newest of the four, added so the name points at a
	// directory that exists; the "writable surface is eight paths" bullet in
	// CLAUDE.md is the count it moved)
	"XDG_DATA_HOME": {shape: shapePath, host: "the host's value names a directory this sandbox does not have; " +
		"@home creates the one inside, so `set` it to a path the same profile grants"},
	// XDG_RUNTIME_DIR is the one of the five @home does NOT create — measured, the
	// same way: no [profile.home] tmpfs names it and env.defaults.txt renders no
	// such row — which is why its sentence promises nothing about the inside and
	// names the obligations instead (mode 0700, owner, session lifetime).
	"XDG_RUNTIME_DIR": {shape: shapePath, host: "the host's value names a directory this sandbox does not have, and this " +
		"variable carries obligations a string cannot satisfy — mode 0700, owned by the user, session lifetime"},
	// Measured, cargo 1.97.1: $CARGO_HOME/config.toml carrying
	//   [build] rustc-wrapper = "…/wrap.sh"
	// ran wrap.sh in place of rustc on `cargo build --offline`, as uid 1000 —
	// the same exec CARGO_BUILD_RUSTC_WRAPPER reaches, one indirection out.
	"CARGO_HOME": {shape: shapePath,
		authored: "the config.toml under this path names a program cargo runs — build.rustc-wrapper " +
			"ran in place of rustc, as the sandbox's own uid (measured, cargo 1.97.1)",
		host: "taking the host's value points cargo back at the host's config, which is the " +
			"file \"generate, don't bind\" exists to avoid; `set` it to a path a profile authored",
	},
	// Measured, docker 29.4.0-ce: {"credsStore":"evil"} in this directory's
	// config.json ran docker-credential-evil with `get` on a plain `docker pull`
	// — BEFORE the daemon socket was contacted, and there is no daemon on this
	// host — and four times with `erase` on `docker logout`. The helper does not
	// need a working engine.
	"DOCKER_CONFIG": {shape: shapePath,
		authored: "credsStore in this directory's config.json is a program docker executes, and it " +
			"runs before docker reaches a daemon (measured, docker 29.4)",
		host: "taking the host's value points docker back at the host's config, credentials " +
			"included; `set` it to a path a profile authored",
	},
	// MEASURED INSIDE A RUNNING SANDBOX — redteam host round 2, which is also the
	// round that upgraded this row from "documented". /usr/bin/npm is still the
	// broken libalternatives shim on this host ("npm-default: No such file or
	// directory"), so the round vendored npm 12.0.2 from the registry tarball and
	// ran it under node 26.4.0:
	//
	//	NPM_CONFIG_USERCONFIG={target}/.npmrc  with  script-shell=/…/hijack.sh
	//	npm run probe
	//	  -> NPM_SCRIPT_SHELL_HIJACK-RAN uid=1000 args=[-c echo REAL-SHELL-RAN]
	//
	// Aimed inside `rw = ["{target}"]` — the one directory the payload writes —
	// which is the case the `authored` sentence exists for.
	"NPM_CONFIG_USERCONFIG": {shape: shapePath,
		authored: "the .npmrc this names carries script-shell, the shell npm runs every lifecycle " +
			"and `run` script with (measured inside a sandbox, npm 12.0.2)",
		host: "taking the host's value points npm back at the host's .npmrc, " +
			"auth tokens included; `set` it to a path a profile authored",
	},
	// MEASURED INSIDE A RUNNING SANDBOX for the first half — redteam host round 2,
	// pip 26.1.2 from `python3 -m venv`, since neither `pip` nor `python3 -m pip`
	// exists on this host:
	//
	//	PIP_CONFIG_FILE={target}/piprc  with  [global] index-url = http://127.0.0.1:9/from-file/simple
	//	pip install --dry-run …
	//	  -> Looking in indexes: http://127.0.0.1:9/from-file/simple
	//
	// The second half — that installing a package runs code out of it — is
	// DOCUMENTED and deliberately not measured: it is a build backend executing
	// setup.py, and running an attacker-chosen package to prove it is a
	// measurement with a blast radius. Nothing under PIP_ execs directly; what
	// this file decides is where packages come FROM.
	"PIP_CONFIG_FILE": {shape: shapePath,
		authored: "index-url in this file decides where every `pip install` fetches from " +
			"(measured inside a sandbox, pip 26.1.2), and installing a package runs code out " +
			"of it (documented)",
		host: "taking the host's value points pip back at the host's config, index " +
			"credentials included; `set` it to a path a profile authored",
	},
	// Measured, git 2.55.0, all three out of one file named by this variable:
	//   [alias] st = "!echo …"   -> ran, uid 1000
	//   core.sshCommand          -> `git config --show-origin` reported
	//                               file:…/sys.gitconfig, and `git ls-remote`
	//                               EXECUTED it as the transport
	//   credential.helper = "!…" -> the same shape
	// It has no roster row, so a row carrying this sentence also carries
	// `← unchecked`: two true statements answering two questions.
	//
	// THE `host` SENTENCE IS NOT DECORATION AND IT IS NOT THE FAMILY'S. For one
	// milestone this entry had `authored` only, and noteFor's fall-through then
	// rendered GIT_CONFIG_*'s family sentence at `inherit` — "git reads this at
	// the command-line scope, above the global file, above the repository's own
	// .git/config". True of GIT_CONFIG_COUNT/KEY_n/VALUE_n/PARAMETERS, and
	// MEASURABLY FALSE of this name, which renames git's SYSTEM file: the LOWEST
	// scope there is. Measured INSIDE a sandbox (redteam host round 2, F2), with
	// the control in the same session:
	//
	//	git config --show-origin --get-all user.email
	//	  file:…/sys.gitconfig  SYSTEM-SCOPE@example.com
	//	  file:.git/config      REPO-SCOPE@example.com     <- .git/config WINS
	//	git config --show-origin --get user.email
	//	  file:.git/config      REPO-SCOPE@example.com
	//	control, GIT_CONFIG_KEY_0 — the name the family sentence WAS measured on:
	//	  command line:         ENV-KEY-SCOPE@example.com
	//
	// The mechanism is the reusable half, and it is why every other pointer
	// carries a `host` string: noteFor falls through to the FAMILY table when the
	// exact entry says nothing at THIS verb, and the prefix exemption is
	// deliberately not applied at `inherit`/`sanitise`. So an exact entry with one
	// of its two fields empty does not render nothing — it renders its family's
	// sentence, which is a different claim about a different name. The defect was
	// never the fall-through; it was one missing string.
	// TestNoPointerEverRendersItsFamilysSentence is what keeps it filled in.
	"GIT_CONFIG_SYSTEM": {shape: shapePath,
		authored: "git reads a command table from this file: core.sshCommand, " +
			"credential.helper and alias.x = !cmd all name programs it runs (measured, git 2.55.0)",
		host: "taking the host's value points git's SYSTEM scope — the LOWEST, below the " +
			"global file and below the repository's own .git/config (measured) — at a command " +
			"table chosen on the host; `set` it to a path a profile authored",
	},
}

// prefixCaseFold is the ONE place "does this tool's env lookup fold case"
// lives. envNotePrefixes (what a profile is told about a family it writes) and
// inlineConfigPrefixes (what snug's sink sweep treats as inline config) both
// match against this same table instead of each carrying its own bool, so a
// re-measurement changes one line and both tables see it.
//
// That is not tidiness for its own sake: it is the fix for a defect measured
// in review. A previous round gave inlineConfigPrefixes a case-insensitive
// npm_config_ entry — correctly, npm 10.9.8 measured — but left
// the forbidden-prefix table's OWN npm_config_ entry case-sensitive, so
// `environ.inherit NPM_CONFIG_SCRIPT_SHELL` (the idiomatic, upper-case
// spelling a shell `export` produces) was ACCEPTED at parse time while the
// predicate that exists to name it as inline config said `true`. Two tables
// holding the same fact is how they end up disagreeing about it; one table
// cannot. The refusal is an annotation now, and the defect survives the change
// intact: the folded spelling would simply render no sentence.
var prefixCaseFold = map[string]bool{
	// Measured on this host, git 2.55.0: GIT_CONFIG_COUNT/KEY_0/VALUE_0 are
	// read; git_config_count and Git_Config_Count are not (both fall through
	// to the file value). getenv(3) is case-sensitive on Linux and git does
	// no folding of its own — consistent across every GIT_CONFIG_* name.
	"GIT_CONFIG_": false,
	// MEASURED, pip 26.1.2 — redteam host round 2, inside a sandbox, with pip
	// from `python3 -m venv` because neither `pip` nor `python3 -m pip` exists
	// on this host. Both directions, which is what makes it a case rule and
	// not a guess:
	//
	//	PIP_INDEX_URL=…/from-env/  + a config file naming …/from-file/
	//	  -> Looking in indexes: …/from-env/simple   (the variable beat the file)
	//	pip_index_url=…/from-env/  + the same file
	//	  -> Looking in indexes: …/from-file/simple  (the lower-case spelling
	//	                                              was NOT read)
	//
	// which is what pip's own source says it should do:
	// Configuration.get_environ_vars does `key.startswith("PIP_")` against
	// os.environ, a case-sensitive mapping on Linux.
	"PIP_": false,
	// Measured: node 22 + a vendored npm-cli.js (npm 10.9.8), since
	// /usr/bin/npm on this host is a broken libalternatives shim. All three
	// spellings won: npm_config_script_shell, NPM_CONFIG_SCRIPT_SHELL and
	// Npm_Config_Script_Shell all set `script-shell`. npm's own env-config
	// loader lower-cases every name before matching, so the prefix must be
	// matched case-insensitively or the idiomatic upper-case spelling — the
	// one a human or a shell `export` is most likely to produce — sails
	// past every check keyed on this table.
	"npm_config_": true,
	// Measured on this host, cargo 1.97.1: CARGO_BUILD_TARGET_DIR is read;
	// cargo_build_target_dir and Cargo_Build_Target_Dir are not (both fall
	// through to .cargo/config.toml). Same root cause as git: Rust's
	// std::env::var is a case-sensitive lookup on Linux and cargo does not
	// fold the name itself.
	"CARGO_": false,
}

// matchesPrefix reports whether name is matched by prefix, honouring
// prefixCaseFold for that prefix. Every prefix match in this file — the
// annotation table, the inline-config predicate, and any exemption from
// either — goes through this one function, so "how is a prefix matched" has
// one answer.
func matchesPrefix(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}
	if prefixCaseFold[prefix] {
		return strings.EqualFold(name[:len(prefix)], prefix)
	}
	return strings.HasPrefix(name, prefix)
}

// sameName reports whether name is the SAME NAME as other, honouring
// prefixCaseFold for the prefix that governs it — the exemption from a
// case-folding prefix must fold case too, or a case-insensitive prefix
// match turns the exemption into a false positive instead of fixing the
// false negative it exists to catch.
func sameName(name, other, prefix string) bool {
	if prefixCaseFold[prefix] {
		return strings.EqualFold(name, other)
	}
	return name == other
}

// envNotePrefixes is the half a map could never express, and four of §4.4's
// findings are exactly this shape: an unbounded FAMILY of names, where the fact
// worth telling a reader is about the family rather than about the spelling in
// front of them.
//
// The shape is kept from `forbiddenEnvPrefixes`, `kind` swapped for `note`, so
// that matchesPrefix, sameName and prefixCaseFold keep their single caller set.
// That is load-bearing rather than tidy: a second table holding the same case
// fact has drifted twice in this file's history, and a note table keyed its own
// way would be the third instance.
//
// The prefix is rendered INTO the sentence by noteFor, in the canonical spelling
// written here, so a reader can tell whether snug measured THIS name or its
// family — and so that the canonical spelling of a case-folding prefix
// (npm_config_) lives in exactly one place.
//
// BASH_FUNC_* is not a variable but a NAME PATTERN carrying exported shell
// functions — and function lookup precedes PATH entirely, so it defeats every
// ordering question in this file.
var envNotePrefixes = []struct {
	prefix string
	note   envNote
	// exempt names that match prefix but are POINTERS, not the capability the
	// prefix's sentence is about — matched with prefix's own case rule via
	// sameName, for the same reason inlineConfigPointers must be.
	//
	// AN EXEMPT NAME GETS NO *FAMILY* NOTE. It is not silent: every pointer a
	// profile can write carries an exact `authored` sentence of its own saying
	// what the file it names IS, which the exact table above answers first. The
	// distinction is the whole of the F1 fix — for a milestone "exempt" meant
	// "nothing at all", so a profile could aim a pointer inside the one directory
	// the payload writes and four of five rows said nothing (measured; see
	// envNotes' pointer block).
	exempt []string
}{
	// The FAMILY sentence rests on the three names in it that were measured on
	// this host, glibc 2.43, each with its control — LD_PRELOAD, LD_AUDIT and
	// LD_LIBRARY_PATH, transcripts in envNotes above. What the prefix adds is the
	// unbounded remainder (LD_BIND_NOW, LD_DEBUG, LD_PROFILE, …), which is not
	// measured name by name and does not need to be: the sentence claims only
	// "the loader reads this before main()", which is what makes it a family.
	{"LD_", both(shapeFamily, "the dynamic loader reads this before main() in every process (measured for "+
		"LD_PRELOAD, LD_AUDIT and LD_LIBRARY_PATH, glibc 2.43)"), nil},
	// Measured today, bash 5.3.15, with both controls — and the second probe is
	// the half worth keeping, because it is the sentence's real claim:
	//
	//	env 'BASH_FUNC_gitx%%=() { echo BASH-FUNC-HIJACK-RAN; }' bash -c 'gitx'
	//	  -> BASH-FUNC-HIJACK-RAN; `type gitx` says "gitx is a function"
	//	                                            bash -c 'gitx'
	//	  -> gitx: command not found                              (control)
	//	env 'BASH_FUNC_git%%=() { echo FUNCTION-BEAT-PATH; }' bash -c 'git --version'
	//	  -> FUNCTION-BEAT-PATH — the real /usr/bin/git never ran
	{"BASH_FUNC_", both(shapeFamily, "an exported shell FUNCTION, and function lookup precedes PATH entirely — "+
		"measured shadowing `git` itself, bash 5.3.15, with the control"), nil},
	{"GIT_CONFIG_", both(shapeFamily, "git reads this at the command-line scope, above the global file, above the "+
		"repository's own .git/config, and above any include (measured, issue #26)"),
		// GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM are POINTERS at a config FILE,
		// which is the mechanism, not the hazard — the same carve-out CARGO_HOME
		// and NPM_CONFIG_USERCONFIG have, and the same one inlineConfigPointers
		// makes for these two names. GIT_CONFIG_GLOBAL is also in SnugOwnedEnv, so
		// no profile reaches it at any verb; GIT_CONFIG_SYSTEM is not, and a
		// profile pointing git's system scope at a file it authored is doing the
		// thing "generate, don't bind" asks for.
		//
		// The two tables' exemption sets are now identical, and that is asserted
		// rather than asked for: TestPointerExemptionsAgreeBetweenTheTwoTables.
		[]string{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}},
	// PIP_* outranks the config FILE pip reads — MEASURED, pip 26.1.2, inside a
	// sandbox (redteam host round 2): PIP_INDEX_URL beat a PIP_CONFIG_FILE naming
	// a different index, and the file won again when only the lower-case
	// `pip_index_url` was set. Nothing under PIP_ was measured to exec a program
	// the way npm_config_ and CARGO_ below were — say so, and re-measure if that
	// changes.
	//
	// PIP_CONFIG_FILE is exempt, and it did NOT need to be while this was a
	// refusal: PIP_ was forbidInheritOnly, so `set PIP_CONFIG_FILE` was legal
	// through the KIND rather than through an exemption, and the pointer carve-out
	// was carried in inlineConfigPointers alone. As an annotation the kind no
	// longer helps — the family sentence renders at `set` — and a pointer warned
	// about at the verb that authors it is snug arguing with its own "generate,
	// don't bind" rule. So the exemption has to be written here too, and the
	// exempt lists of this table now name the same pointers inlineConfigPointers
	// does. If you add a pointer to one, add it to the other.
	{"PIP_", envNote{
		shape:    shapeFamily,
		authored: "outranks the config file pip reads, so it beats whatever a profile generated",
		host:     "outranks the config file pip reads, and the value is chosen on the host, outside any profile",
	}, []string{"PIP_CONFIG_FILE"}},
	// cargo executes an arbitrary program for CARGO_BUILD_RUSTC_WRAPPER,
	// CARGO_BUILD_RUSTC and CARGO_TARGET_<TRIPLE>_RUNNER/_LINKER — the SAME
	// capability as the un-prefixed RUSTC_WRAPPER/RUSTC/RUSTC_WORKSPACE_WRAPPER
	// in envNotes above, reached through a different spelling. Measured, issue
	// #26 review. CARGO_HOME is the one exemption: it is a POINTER (the mechanism
	// a future cargo adapter would use, same shape as GIT_CONFIG_GLOBAL), not a
	// code path, and it carries its own `inherit` sentence in the exact table.
	{"CARGO_", both(shapeFamily, "outranks .cargo/config.toml, and the BUILD_RUSTC_WRAPPER/BUILD_RUSTC/"+
		"TARGET_*_RUNNER keys name a program cargo RUNS (measured, issue #26)"),
		[]string{"CARGO_HOME"}},
	// npm_config_ is the same shape again: `npm_config_script_shell` names the
	// shell npm uses to run lifecycle and `run` scripts, and `npm_config_node_gyp`
	// names the program npm invokes for native builds — both ARE that code path,
	// not merely config that outranks a file. Measured, issue #26 review, in every
	// case spelling; see prefixCaseFold's npm_config_ entry for why case matters
	// here at all. NPM_CONFIG_USERCONFIG is the one exemption, for the same reason
	// CARGO_HOME is.
	{"npm_config_", both(shapeFamily, "outranks .npmrc, and the script_shell/node_gyp keys name a program npm "+
		"RUNS (measured, issue #26, in every case spelling)"),
		[]string{"NPM_CONFIG_USERCONFIG"}},
}

// inlineConfigPrefixes is the prefix half of IsInlineConfigEnv's table: every
// name matching one of these is a config-surface variable whose VALUE IS THE
// SETTING, unless it is named in inlineConfigPointers below. Case sensitivity
// for each prefix comes from prefixCaseFold, the same table
// envNotePrefixes reads — see that table's comment for why sharing it
// matters, not just naming the list here.
var inlineConfigPrefixes = []string{
	"GIT_CONFIG_",
	"PIP_",
	"npm_config_",
	"CARGO_",
}

// inlineConfigPointer is one entry of inlineConfigPointers: a name whose value
// is a PATH to a file snug or a profile generated, not the setting itself.
//
// prefix names which entry in prefixCaseFold governs the case rule for this
// name — NPM_CONFIG_USERCONFIG is a pointer in every spelling npm itself
// honours, or a case-insensitive prefix match would turn the exemption into a
// false positive instead of fixing the false negative it replaced. It is ""
// for a pointer that belongs to no annotated family, and sameName then falls
// through to an exact comparison (prefixCaseFold[""] is false).
type inlineConfigPointer struct {
	name   string
	prefix string
}

// inlineConfigPointers is EVERY NAME SNUG CALLS A POINTER, and it is one list
// rather than two because the two questions it answers are asked by different
// code and were already answered differently.
//
// The prefixed entries are also the exemption set for envNotePrefixes'
// family sentences (TestPointerExemptionsAgreeBetweenTheTwoTables). The
// prefix-less entries need no exemption — they match no prefix, so
// IsInlineConfigEnv answers false for them either way — and they are here
// because a sweep over "the pointers" that read only the prefixed ones would
// silently skip DOCKER_CONFIG, which is a pointer at a directory whose
// config.json names a program docker EXECUTES. That is the shape this file
// keeps recording: one fact, two tables, they drift.
//
// Naming one here is a policy change — ask what the name makes the tool DO,
// exactly as GIT-CONFIG.md §5 asks of the config-key whitelist — and a pointer
// a profile can write must carry an `authored` sentence in envNotes saying what
// the file it names IS (TestEveryPointerSaysWhatTheFileItNamesIs).
var inlineConfigPointers = []inlineConfigPointer{
	{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_"},
	{"GIT_CONFIG_SYSTEM", "GIT_CONFIG_"},
	{"NPM_CONFIG_USERCONFIG", "npm_config_"},
	{"PIP_CONFIG_FILE", "PIP_"},
	{"CARGO_HOME", "CARGO_"},
	// No family — and the two differ in a way worth reading, because assuming
	// they were the same is how DOCKER_CONFIG would have been skipped again.
	// GH_CONFIG_DIR is in SnugOwnedEnv, so no profile reaches it at any verb and
	// it carries no annotation (snug's own names stay out of that table).
	// DOCKER_CONFIG is NOT owned: it has a roster row, any profile may `set` it,
	// and it names a directory whose config.json `credsStore` is a program
	// docker executes — so it carries an `authored` sentence like every other
	// writable pointer.
	{"DOCKER_CONFIG", ""},
	{"GH_CONFIG_DIR", ""},
}

// namesAPointerFile reports whether name is one of the names snug's OWN tables
// call a POINTER: a value that is a PATH to a config file or directory, rather
// than the setting itself.
//
// It exists so that "this value is a filesystem path" has one answer for the
// pointers, read off the table that defines them, instead of depending on
// whether the name also happens to have a roster row. GIT_CONFIG_SYSTEM does
// not, which is how a relative `set` reached a running sandbox and executed out
// of the payload's own cwd — the reproduction is in valueIsAPath, which is this
// predicate's one production caller (envcoupling.go).
//
// Case is folded exactly as IsInlineConfigEnv folds it, through sameName and the
// pointer's own prefix, so `npm_config_userconfig` is the same name as
// NPM_CONFIG_USERCONFIG here too. A second case rule in this file is how this
// file has already drifted three times.
func namesAPointerFile(name string) bool {
	for _, p := range inlineConfigPointers {
		if sameName(name, p.name, p.prefix) {
			return true
		}
	}
	return false
}

// inlineConfigNames is the named half the prefix table structurally cannot
// express: a variable whose value is a setting (here, an arbitrary program
// cargo executes as its compiler driver) but whose NAME does not start with
// its tool's prefix. RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER and RUSTC carry
// the identical capability CARGO_BUILD_RUSTC_WRAPPER carries under the
// CARGO_ prefix in envNotePrefixes — measured, issue #26 red team: a
// profile setting RUSTC_WRAPPER to a script made `cargo build` run that
// script in place of rustc. All six names (these three, plus the three
// CARGO_BUILD_* / CARGO_TARGET_* spellings the prefix catches) are annotated
// there at every verb — and annotation is all they are, since the second pass
// over issue #44: a USER profile may now author any of them. This map is what
// keeps IsInlineConfigEnv's own promise true for the un-prefixed spelling, and
// what stops a BUILTIN shipping one is the sweep named in IsInlineConfigEnv's
// doc comment plus the roster rule; see there.
//
// THE CLAUDE_/ANTHROPIC_ ENTRIES BELOW ARE THE SAME SHAPE FOR A DIFFERENT TOOL,
// and `CLAUDE_` is not a prefix in inlineConfigPrefixes — nor should it become
// one, because most of that namespace is ordinary settings. Adding a name here
// is a policy change, and the question is what the name makes the tool DO:
//
//	CLAUDE_CODE_PROCESS_WRAPPER — an argv PREFIX applied to the background-agent
//	  supervisor, the sessions and workers it hosts, and the other covered
//	  background processes. Measured, verbatim from the installed claude 2.1.232
//	  binary's own settings-schema description of the `processWrapper` key:
//	  "Equivalent to the CLAUDE_CODE_PROCESS_WRAPPER environment variable, which
//	  takes precedence when set." Whoever sets it chooses what actually
//	  executes — LD_PRELOAD's shape for this tool. Issue #17 drops the settings
//	  KEY with an allowlist; the variable that outranks that key is this
//	  surface, and it was a separate one with no check.
//	CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY — the value
//	  IS the credential, reviewable nowhere. ANTHROPIC_AUTH_TOKEN is named
//	  beside apiKeyHelper in the binary's own credential-selection strings.
//	  ANTHROPIC_API_KEY was already covered by the secrets test and by
//	  @claude's environ.inherit refusing it by name, but it is an inline setting
//	  too and belongs in the same sweep rather than being covered only by a
//	  sibling mechanism — a name covered by one mechanism and not the other is
//	  how the two come to disagree about it.
//
// ALL FOUR ARE ANNOTATION ONLY, and the first of them is where this changed
// under review. It was written as a forbiddenEnv row, on the argument that an
// argv prefix is the sharpest spelling of "the value is code" there is and that
// no profile has a legitimate reason to choose the argv prefix for someone
// else's agent. Both halves are still true and neither is a reason to refuse: a
// refusal here binds the human writing the profile, while the agent the prefix
// applies to sets its own environment and always could. What the entry buys is
// that IsInlineConfigEnv names it, so the sink sweep over a resolved policy —
// TestNoBuiltinHandsOverAnInlineConfigVariable — fails if a SHIPPED profile ever
// carries one, and envNotes puts the sentence on the screen when a user's
// profile does.
var inlineConfigNames = map[string]bool{
	"RUSTC_WRAPPER":           true,
	"RUSTC_WORKSPACE_WRAPPER": true,
	"RUSTC":                   true,

	"CLAUDE_CODE_PROCESS_WRAPPER": true,
	"CLAUDE_CODE_OAUTH_TOKEN":     true,
	"ANTHROPIC_AUTH_TOKEN":        true,
	"ANTHROPIC_API_KEY":           true,
}

// IsInlineConfigEnv reports whether NAME is a config-surface variable whose
// VALUE IS THE SETTING, rather than a POINTER at a file snug generated.
//
// The distinction is the whole of "generate, don't bind" at the environment:
// GIT_CONFIG_GLOBAL carries a PATH to a file snug authored and a human can
// read; GIT_CONFIG_KEY_0 carries the setting itself, at a scope above every
// file (measured: git reports it as `command line:`, above global and above
// the repository's own .git/config — see .claude/design/GIT-CONFIG.md §9).
// snug may author the first and must never author the second.
//
// GH_CONFIG_DIR and DOCKER_CONFIG match no prefix here and need no exemption
// entry — they are listed in inlineConfigPointers's comment anyway, because
// the REASON they are safe is the same reason as the exemptions that are
// listed, and the next adapter should be written from that comment.
//
// What this predicate does NOT cover, stated because the name invites reading
// it as the whole of the sink sweep and it is not: the command-hook class —
// BASH_ENV, ENV, PERL5OPT, NODE_OPTIONS, PYTHONSTARTUP, LESSOPEN and the rest
// of envNotes — returns false here on purpose. Those are annotated, not
// classified as inline config, and TestNoBuiltinHandsOverAnInlineConfigVariable
// is not their guard; the roster rule (a builtin may write only a rostered
// name) is.
//
// WHAT THIS PREDICATE IS NOT, and the answer CHANGED with the second pass over
// issue #44, so read this rather than the version you remember. It still has no
// production caller. It used to be able to say that `forbiddenEnv` /
// `forbiddenEnvPrefixes` via `ValidateEnvGrants` stopped ANY profile — builtin
// or user — from authoring one of these names, and that this predicate was
// merely the second layer. That gate is GONE: those tables are annotations now
// (envNotes/envNotePrefixes), so a USER profile may author GIT_CONFIG_KEY_0,
// PIP_INDEX_URL or RUSTC_WRAPPER, and what it gets is a sentence on --dry-run.
// That is deliberate — a profile's author is a human on the trusted side of the
// boundary — and it makes the scope of this predicate exactly what CLAUDE.md
// says the rule is: THE ENVIRONMENT SNUG ITSELF HANDS OVER must not ship the
// override pre-installed. What holds that up is two things, both builtin-only:
// internal/profile's checkBuiltinEnvRoster (a shipped profile may write only a
// rostered name, and no inline-config name has a roster row) and internal/cli's
// TEST-TIME sweep TestNoBuiltinHandsOverAnInlineConfigVariable, which resolves
// `profile.Builtins()` and nothing a user's own `~/.config/snug/profiles.d`
// defines. Wiring this predicate into ValidateEnvGrants, so that it governs what
// ANY profile may author, would be re-introducing a denylist over a human's own
// file and is deliberately not done.
//
// The pointer set is a SECURITY BOUNDARY, not a convenience list. Adding a
// name to it says "snug hands this to the payload"; ask what the name makes
// the tool DO, exactly as GIT-CONFIG.md §5 asks of the config-key whitelist.
func IsInlineConfigEnv(name string) bool {
	if inlineConfigNames[name] {
		return true
	}
	if namesAPointerFile(name) {
		return false
	}
	for _, p := range inlineConfigPrefixes {
		if matchesPrefix(name, p) {
			return true
		}
	}
	return false
}

// noteExact is the EXACT-name lookup in envNotes, honouring the case rule of
// whichever prefix family governs the name — the same shape typeOf uses for the
// roster, and here for the same measured reason.
//
// A CONSUMER THAT FOLDS CASE MAKES TWO SPELLINGS ONE NAME. npm's env loader
// lower-cases every name before matching (prefixCaseFold), so
// `npm_config_userconfig` IS `NPM_CONFIG_USERCONFIG`. The prefix table's
// exemption already folds case; a plain map lookup here does not — so the moment
// the pointers gained an exact `authored` sentence, the canonical spelling said
// what the file was and the folded one said NOTHING, because it missed the exact
// row and was then exempted from its family's. Caught by the case-spelling loop
// in TestAnnotationSplitsBySetAndInherit, which existed because this table has
// now drifted over a case rule three times: once in the forbidden-prefix table,
// once in the roster, and once here.
//
// Scoped to prefixes that actually fold, exactly as typeOf is: PATH is still
// PATH, and `Editor` is still a name with no annotation.
func noteExact(name string) (envNote, bool) {
	if n, ok := envNotes[name]; ok {
		return n, true
	}
	for prefix, fold := range prefixCaseFold {
		if !fold || !matchesPrefix(name, prefix) {
			continue
		}
		for k, n := range envNotes {
			if matchesPrefix(k, prefix) && sameName(name, k, prefix) {
				return n, true
			}
		}
	}
	return envNote{}, false
}

// noteFor returns snug's annotation for one (name, verb) pair, already carrying
// the prefix label where the annotation is about a family.
//
// The exact table answers FIRST and, if it has a sentence for this verb, alone:
// one row on the screen carries one annotation, because a row carrying two would
// be read as one long one. A name with an exact entry that says nothing at THIS
// verb (CARGO_HOME at `set` — the pointers annotate `inherit` only) falls
// through to the prefix table, which is how the two tables composed when they
// were refusals and is what keeps CARGO_HOME's exemption meaningful.
//
// A prefix's exempt list applies to every verb EXCEPT VerbInherit and
// VerbSanitise, and that asymmetry is deliberate rather than an oversight: an
// exempt name is a POINTER (CARGO_HOME, NPM_CONFIG_USERCONFIG, …), and authoring
// one is the mechanism "generate, don't bind" asks for, while taking one from
// the HOST reintroduces exactly the file the rule exists to avoid — so at those
// two verbs the family's sentence is the right thing to say about it.
//
// The history is worth keeping, because it is why the exemption is matched with
// sameName rather than with `==`. That lookup used to be a case-SENSITIVE,
// exact-string one: exactly right for a case-sensitive prefix (CARGO_), exactly
// wrong for a case-INSENSITIVE one — npm_config_'s exemption matches every case
// spelling, while envTypes["npm_config_userconfig"] did not exist, so the type
// table's own refusal never fired for that spelling. Measured, before the rule
// existed: environ.inherit npm_config_userconfig was ACCEPTED while
// environ.inherit NPM_CONFIG_USERCONFIG was refused. Nothing is refused here any
// more, so the same defect would now show as a MISSING annotation on the folded
// spelling — the same drift wearing different clothes, which is why the rule is
// kept rather than simplified away.
func noteFor(name string, verb EnvVerb) string {
	if n, ok := noteExact(name); ok {
		if s := n.forVerb(verb); s != "" {
			return s
		}
	}
	for _, p := range envNotePrefixes {
		if !matchesPrefix(name, p.prefix) {
			continue
		}
		if verb != VerbInherit && verb != VerbSanitise {
			exempt := false
			for _, e := range p.exempt {
				if sameName(name, e, p.prefix) {
					exempt = true
					break
				}
			}
			if exempt {
				continue
			}
		}
		if s := p.note.forVerb(verb); s != "" {
			// The prefix is named in its CANONICAL spelling, from the table, even
			// where the match folded case: a reader has to be able to tell whether
			// snug measured THIS name or its family, and that answer must not
			// depend on how the profile happened to spell it. This is also the
			// only place the canonical spelling reaches a screen, so the
			// annotation text does not become a third copy of a case fact.
			return p.prefix + "*: " + s
		}
	}
	return ""
}

// EnvNote is snug's annotation for one (name, verb) pair, ready to append to a
// rendered row, or "" where snug has nothing to say about it.
//
// IT IS A STATEMENT, NOT A VERDICT. Nothing downstream of this function refuses
// anything; every caller is a screen. That is the whole of what the second pass
// over issue #44 changed — the tables behind it used to refuse, and refusing the
// author of a profile was snug denying its own user a hole in a sandbox that
// shares nothing to begin with. A human's profile may now `set EDITOR`, `inherit
// CARGO_HOME`, `set BASH_ENV` and `set RUSTC_WRAPPER`; what they get for it is
// this sentence, on --dry-run and on `snug profile show`. That is the point, not
// a regression.
//
// ONE FUNCTION, N CONSUMERS, for the same reason IsUncheckedEnv is one predicate
// with three: two screens deciding separately what snug has to say about a name
// is how one of them comes to say nothing. Today the consumers are --dry-run's
// ENVIRONMENT block (internal/cli/dryrun.go's envLines) and `snug profile show`
// (internal/cli/config.go's showEnviron). The argv block is again the sink with
// nothing to add: `--setenv NAME VALUE` has no provenance column at all.
//
// The mark JOINS the others rather than replacing them, and a row can carry
// three statements at once — envLines fixes the order:
//
//	unchecked   about the NAME:  snug has no roster row for it
//	this note   about what the tool DOES with the value
//	grantMark   about the VALUE as a path: nothing inside covers it
//
// VerbSnug returns "" because snug's own authorship is not something to warn a
// reader about — the same carve-out IsUncheckedEnv makes, for the same reason.
func EnvNote(name string, verb EnvVerb) string {
	if verb == VerbSnug {
		return ""
	}
	s := noteFor(name, verb)
	if s == "" {
		return ""
	}
	return "  ← " + s
}

// checkEnvName refuses a variable name that would break a mechanism, in the
// same spirit as checkName for profiles and for the same reason: TOML keys are
// arbitrary strings, so nothing in the SYNTAX stops [profile.x.environ.set]
// carrying "A=B", an empty key, or a name with a newline in it — and those go
// straight to --setenv NAME VALUE.
//
// The rule is what execve(2) and every shell already assume:
//
//	name ::= [A-Za-z_][A-Za-z0-9_]*
//
// Checked at PARSE time, so `snug profile show` reports it too and the verdict
// on a profile never depends on the host that happens to be reading it (§2.3).
func checkEnvName(name string, verb EnvVerb) error {
	v := verb.String()
	if name == "" {
		return fmt.Errorf("environ.%s has an entry with an empty name. A variable with no "+
			"name cannot be set; delete the line", v)
	}
	if strings.Contains(name, "=") {
		return fmt.Errorf("environ.%s names %q, which contains '='. NAME=VALUE is the wire "+
			"format of the environment itself, so a name with '=' in it is a second "+
			"assignment smuggled inside the first. Use one entry per variable", v, name)
	}
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("environ.%s names a variable containing a NUL byte. The environment "+
			"is a NUL-terminated list, so the name would be truncated at that byte and "+
			"the remainder read as something else entirely", v)
	}
	if strings.ContainsAny(name, "\n\r") {
		return fmt.Errorf("environ.%s names %q, which contains a newline. Every --dry-run line "+
			"and every refusal renders a variable name on one line; a name that spans two "+
			"makes those unreadable and unparseable", v, quoteVisible(name))
	}
	if name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("environ.%s names %q, which starts with a digit. A variable name is "+
			"[A-Za-z_][A-Za-z0-9_]*, and a shell cannot expand a name starting with a "+
			"digit — $%s is a positional parameter", v, name, name[:1])
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return fmt.Errorf("environ.%s names %q, which contains %q. A variable name is "+
				"[A-Za-z_][A-Za-z0-9_]* — the rule execve(2) and every shell already "+
				"assume. Rename it", v, quoteVisible(name), string(name[i]))
		}
	}
	// WHAT IS NOT HERE, because it was and its absence is the change: the
	// forbidden-name and forbidden-prefix tables used to be consulted at this
	// point and to refuse GIT_SSH_COMMAND, LD_*, RUSTC_WRAPPER and fifty others.
	// They are envNotes/envNotePrefixes now and they refuse nothing — a profile's
	// author is a human on the trusted side of the boundary, and every one of
	// those names is annotated on the two screens instead (EnvNote). Everything
	// left in this function is mechanism: a name that cannot be TRANSPORTED,
	// because the environment is a NUL-terminated list of NAME=VALUE and a screen
	// is one line per row.
	return nil
}

// checkEnvOwnership refuses a name snug writes itself (§1.1).
//
// SAY IT PRECISELY: this rule is "snug's SCALARS are untouchable", not "snug's
// NAMES are". It does NOT fire for a list snug owns, and PATH is the only one —
// read that carefully, because it is the one place ownership is narrower than
// "no profile may write a name snug writes", and because since the annotation
// change (ENVIRONMENT-VARIABLES.md §2.9) this is the ONLY refusal of a name left
// anywhere in the model. Everything else that refuses is refusing an OPERATION.
//
// A SCALAR has a single value, so any verb a profile could use on one REPLACES
// what snug wrote. HOME is where the identity generator puts ~/.gitconfig,
// ~/.ssh/config and known_hosts, so a profile able to move it silently defeats
// identity pinning; PS1 is executed by bash before the user types anything;
// SNUG* is what --dry-run and the injected ~/.claude/CLAUDE.md are read against,
// so a profile that could set one can lie to the artifacts a human reads to
// decide whether to trust the sandbox. There is no version of writing those
// that is additive.
//
// A LIST is shared by construction. snug authors the base band and the stub
// band; a profile's merge or prepend contributes its OWN band ahead of them and
// displaces nothing (§2.4). That is not a loophole — it is the documented way
// for a profile to put a tool on PATH, it is what today's `path = [...]` key
// already does, and §1.2 is precise about the scope: what stays unconditional
// is "the base PATH", not the variable.
//
// The two verbs that WOULD replace a list wholesale, set and inherit, are
// refused for it by the type rules instead, with a message naming the verb to
// use — which is the message §2.1 asks for, and better than this one.
func checkEnvOwnership(name string, verb EnvVerb) error {
	if t, known := typeOf(name); known && t.list {
		return nil
	}
	for _, owned := range SnugOwnedEnv {
		if name != owned {
			continue
		}
		return fmt.Errorf("environ.%s names %s, which snug writes itself. No profile may "+
			"write a name snug writes: HOME, PATH and SHELL have no safe absent state, "+
			"PS1 is executed by bash, and SNUG* is what --dry-run is read against — a "+
			"profile that could set one could lie to the artifact a human reads to decide "+
			"whether to trust the sandbox. Remove the line", verb, name)
	}
	return nil
}

// checkEnvVerbType refuses a verb the variable's TYPE does not accept, and a
// name the roster does not carry at all where that verb needs a type. The error
// names the right verb, because "wrong verb" without "use this one" leaves the
// author guessing (§2.1).
func checkEnvVerbType(name string, verb EnvVerb) error {
	t, known := typeOf(name)
	if !known {
		return checkUnrosteredName(name, verb)
	}
	switch verb {
	case VerbSet:
		if t.list {
			return fmt.Errorf("environ.set on %s, which is a list — use environ.merge, or "+
				"environ.prepend if the order matters. environ.set on a list would replace "+
				"every other profile's entries, which snug does not allow", name)
		}
	case VerbMerge, VerbPrepend:
		if !t.list {
			return fmt.Errorf("environ.%s on %s, which is a scalar, not a list — use "+
				"environ.set", verb, name)
		}
		if !t.mergeable {
			return fmt.Errorf("environ.%s on %s, which snug does not compose. Its elements "+
				"are not independent — see .claude/design/ENVIRONMENT-VARIABLES.md §3.3 — so "+
				"joining two profiles' entries would change what the value MEANS rather than "+
				"lengthen it", verb, name)
		}
	case VerbInherit:
		// The blanket rule, and it has no exceptions: copying a host search path
		// wholesale imports directories that do not exist inside, which is what
		// §2.7 case 4 refuses for `set` and what `sanitise` exists to do
		// properly. inherit is the scalar form; sanitise is the list form.
		if t.list {
			return fmt.Errorf("environ.inherit on %s, which is a list. Inheriting a host "+
				"search path wholesale imports directories the sandbox does not have — use "+
				"environ.sanitise, which copies the host value and keeps only the elements "+
				"policy grants", name)
		}
		// The `noInherit` arm that stood here is gone. It refused
		// XDG_CONFIG_HOME, CARGO_HOME and friends with "snug refuses to take this
		// from the host", which is a verdict on the profile's AUTHOR rather than a
		// statement about the type — the one permission bit the roster carried,
		// and it is an annotation now (envNotes, `host` sentence). The arm above
		// stays because it is the opposite kind of thing: `inherit` on a list is
		// an operation snug will not perform, and the message names the verb that
		// does perform it.
	case VerbSanitise:
		if !t.list {
			return fmt.Errorf("environ.sanitise on %s, which is a scalar. sanitise filters "+
				"the ELEMENTS of a host list; for a scalar there is nothing to filter — use "+
				"environ.inherit to take the host's value, or environ.set to write one", name)
		}
		if t.empty == emptyOperator {
			return fmt.Errorf("environ.sanitise on %s, where an empty element is an "+
				"INSTRUCTION rather than a gap: a leading one prepends the system path, a "+
				"trailing one appends it, and '::' inserts it in place. Removing an element "+
				"there can ADD directories, which is the opposite of what a filter is for. "+
				"Use environ.merge with the directories you mean", name)
		}
		if !t.sanitisable {
			return fmt.Errorf("environ.sanitise on %s, which snug refuses to filter: an "+
				"empty or dropped element changes the meaning of the value rather than "+
				"shortening it — see .claude/design/ENVIRONMENT-VARIABLES.md §3.3. Use "+
				"environ.merge with the directories you mean", name)
		}
	}
	return nil
}

// checkUnrosteredName is the verdict on a name snug has no row for, and it
// differs by VERB rather than by who wrote the profile.
//
// `set` and `inherit` need no fact about the name to be carried out: the whole
// value is written, or the host's whole value is copied. So they return nil
// here, and what the reader gets instead of a refusal is the `← unchecked` mark
// on every screen (IsUncheckedEnv). The one place this IS a refusal is a profile
// snug ships, and that is enforced one layer up, at internal/profile's `mark`,
// with this same predicate — see the roster's own comment for why the two halves
// differ.
//
// The three LIST verbs structurally cannot: a list verb needs the SEPARATOR and
// the meaning of an EMPTY ELEMENT, and neither is something a profile can hand
// over — inferring them from the shape of a value is exactly what this file
// exists not to do (see the header comment, and §3.3, where the same column
// decides that MANPATH may not be sanitised at all). That refusal is for
// everybody, builtin and user profile alike.
func checkUnrosteredName(name string, verb EnvVerb) error {
	if verb == VerbSet || verb == VerbInherit {
		return nil
	}
	return fmt.Errorf("environ.%s on %s, which snug has no entry for. A list verb needs the\n"+
		"       separator that variable is read with and what an EMPTY ELEMENT means to its\n"+
		"       consumer — ignored, the current directory, or an instruction that ADDS\n"+
		"       directories (§3.3) — and snug will not guess either from the shape of a value.\n"+
		"       Use environ.set with the whole value, or add a row to\n"+
		"       internal/policy/envtypes.go carrying the separator and the empty-element kind.",
		verb, name)
}

// checkEnvElement refuses a hand-written separator inside a value.
//
// CALL 1: both `merge` and `prepend` accept a string or an array, and a string
// is exactly ONE element — snug never splits a value on a separator. What is
// refused is any element, string or array member, containing that variable's
// separator. That is strictly stronger than refusing the bare-string SHAPE:
// PATH = ["/usr/bin:/usr/sbin"] is the identical smuggle, and a shape rule does
// not catch it.
//
// The reason is §4.3, measured: a hand-written separator can produce an EMPTY
// element, and an empty element in PATH is the current working directory, which
// inside snug is the target — the one writable thing a hostile payload controls.
func checkEnvElement(name string, verb EnvVerb, value string) error {
	// SCOPE, SAID OUT LOUD RATHER THAN LEFT TO BE DISCOVERED: this check protects
	// ROSTERED NAMES ONLY, and it must, because the separator it looks for is a
	// fact only a roster row carries. For a name snug has no row for there is no
	// separator to smuggle and no list verb to smuggle it into —
	// checkUnrosteredName refuses all three outright, which is the same fact
	// arriving from the other direction. If a list verb ever becomes reachable
	// for an unrostered name, this function goes blind in the same commit.
	t, known := typeOf(name)
	if !known || !t.list {
		return nil
	}
	for _, sep := range []string{t.sep, t.altSep} {
		if sep == "" || !strings.Contains(value, sep) {
			continue
		}
		return fmt.Errorf("environ.%s on %s has the element %q, which contains %q — a "+
			"separator %s is read with. Write the elements:\n"+
			"         %s = [%s]\n"+
			"       snug never splits a value on a separator, so a hand-written one can "+
			"smuggle in an empty element, which in a search path means the current "+
			"directory", verb, name, value, sep, name, name, splitHint(value, sep))
	}
	return nil
}

// checkEnvValue refuses a control character in a value a PROFILE wrote.
//
// checkEnvName has refused NUL in a name since the beginning, with a reason
// that applies verbatim to the value and was never applied there — and the gap
// was not cosmetic. `--setenv NAME VALUE` is three elements of the flag list,
// the whole list is NUL-joined into the args memfd, and bwrap's `--args` splits
// it on NUL. VALUE is the last element of the triple, so a NUL inside it
// re-syncs the parser cleanly on whatever follows:
//
//	EDITOR = "vim\\u0000--ro-bind\\u0000/home/u/.ssh\\u0000/home/u/.ssh"
//
// mounted ~/.ssh into the sandbox. Measured. `Validate`, `rejectMasking` and
// the whole provenance model never saw that mount, because it was never a
// Mount — and `--dry-run` printed one harmless `--setenv EDITOR vim` line while
// listing ~/.ssh under NOT GRANTED. The same shape with `--tmpfs` masked
// @sys's `ro /usr`: a PROFILE expressing subtraction, which invariant 1 calls
// structurally impossible.
//
// Note the spelling: a RAW NUL byte never got this far, because go-toml refuses
// control characters in a basic string. The `\\u0000` ESCAPE is accepted and
// produces the same byte. Anyone re-testing this needs the escape.
//
// Why every C0 control and DEL, not just NUL. NUL is the one that authors a
// mount, and on its own it would be enough to close the hole — but the other
// controls author a LIE, which this project treats as the same class of defect
// (§2.3, and the `--dry-run` block that `d2888b5` closed): a newline forges a
// grant row in the FILESYSTEM block, and ESC rewrites the terminal so a line
// vanishes from `snug profile show`. `visibleValue` escapes those where it is
// called; refusing them at parse time means the rendering guard is a second
// line of defence rather than the only one. No environment variable snug is in
// the business of setting needs a control character in its value.
//
// The verdict is a property of the profile TEXT, so it is the same on every
// host — which is why it belongs here and not in Resolve. It therefore does NOT
// and CANNOT cover `inherit`/`sanitise`, whose values are the host's: those are
// host-dependent, and by construction cannot contain a NUL (the environment
// execve hands over is a NUL-terminated list). Their rendering is the
// renderer's problem.
//
// THE SET IS NOT WRITTEN HERE ANY MORE, and that is the repair for the same
// defect arriving twice. C1 was added to this loop and to the renderer's copy in
// one commit (redteam host round 2, F6): `c >= 0x20 && c != 0x7f` walks BYTES,
// so it could never see U+0085 (NEL) or U+009B (CSI, the single-character form
// of ESC-[), and %q hid the gap in review because mixing in ONE ASCII control
// makes the escaper quote the C1 characters too. Then round 3 walked U+202E past
// BOTH widened copies, because the widening was to unicode.IsControl and a
// directional override is category Cf — while `Validate`'s guest-path check and
// `Identity.CheckText` had never been widened at all and were still ASCII-only.
// Two copies of one question AGREEING is not the same as one question, and four
// copies is how three of them stay behind.
//
// IsForgingRune (forging.go) owns the set now, every sink asks it, and the
// argument for where its edge is — the nine UAX #9 directional formatting
// characters IN, the invisible characters OUT — is written there, once.
//
// The NUL arm stays here and is unchanged: it is the one that authors a MOUNT
// rather than a lie, and it is a fact about the flag list rather than about a
// screen.
//
// The renderer (internal/cli/dryrun.go's visibleValue) asks the same predicate and
// carries one more case this function cannot: invalid UTF-8, which a TOML value
// cannot be and a HOST value can.
func checkEnvValue(name string, verb EnvVerb, value string) error {
	for _, r := range value {
		if !IsForgingRune(r) {
			continue
		}
		// %q of the RUNE, so a C1 character is NAMED in the message ("\u009b")
		// rather than printed into the very refusal that exists because printing
		// it is unsafe. A byte loop could not do this: it would quote each half
		// of the UTF-8 encoding separately, naming neither.
		what := fmt.Sprintf("%q", r)
		if r == 0 {
			return fmt.Errorf("environ.%s on %s has a value containing a NUL byte. The whole "+
				"bwrap flag list is NUL-separated, so a NUL inside a value ENDS the value "+
				"and everything after it is read as further flags — a mount snug's policy "+
				"model never sees and --dry-run never prints. Remove it", verb, name)
		}
		return fmt.Errorf("environ.%s on %s has a value containing %s. Every screen a human "+
			"reads to decide whether to trust a sandbox renders a value on one line; %s. "+
			"Remove it", verb, name, what, forgingRuneReason(r))
	}
	return nil
}

func splitHint(value, sep string) string {
	parts := strings.Split(value, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, fmt.Sprintf("%q", p))
	}
	return strings.Join(out, ", ")
}

// quoteVisible renders a name whose own characters would otherwise mangle the
// error message.
func quoteVisible(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%q", s), `"`), `"`)
}

// ValidateEnvGrants is the parse-time half of the environment rules: the name
// grammar, verb/type agreement, snug-owned and forbidden names, and
// hand-written separators. Everything here is a property of the profile TEXT,
// so the verdict is the same on every host — which is the whole reason it runs
// here and not in Resolve (§2.5, and §4.4's defect adopted as a design).
//
// The coupling rule — a profile must grant the paths it names — is the OTHER
// half and runs at resolve time, after {var} expansion.
//
// Exported so internal/profile can call it while the type table stays snug's.
func ValidateEnvGrants(g EnvGrants) error {
	for _, name := range sortedMapKeys(g.Set) {
		if err := checkEnvEntry(name, VerbSet); err != nil {
			return err
		}
		if err := checkEnvValue(name, VerbSet, g.Set[name]); err != nil {
			return err
		}
		if err := checkEnvElement(name, VerbSet, g.Set[name]); err != nil {
			return err
		}
	}
	for _, verb := range []EnvVerb{VerbMerge, VerbPrepend} {
		m := g.Merge
		if verb == VerbPrepend {
			m = g.Prepend
		}
		for _, name := range sortedListKeys(m) {
			if err := checkEnvEntry(name, verb); err != nil {
				return err
			}
			for _, v := range m[name] {
				if err := checkEnvValue(name, verb, v); err != nil {
					return err
				}
				if err := checkEnvElement(name, verb, v); err != nil {
					return err
				}
			}
		}
	}
	for _, name := range sortedCopy(g.Inherit) {
		if err := checkEnvEntry(name, VerbInherit); err != nil {
			return err
		}
	}
	for _, name := range sortedCopy(g.Sanitise) {
		if err := checkEnvEntry(name, VerbSanitise); err != nil {
			return err
		}
	}
	return nil
}

// checkEnvEntry is the whole parse-time verdict on one (name, verb) pair, in
// the order that produces the most useful message: what the name IS, then who
// owns it, then whether the verb fits its type — the last of which is also where
// a name with no roster row meets a LIST verb.
func checkEnvEntry(name string, verb EnvVerb) error {
	if err := checkEnvName(name, verb); err != nil {
		return err
	}
	if err := checkEnvOwnership(name, verb); err != nil {
		return err
	}
	return checkEnvVerbType(name, verb)
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedListKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
