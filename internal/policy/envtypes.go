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

// envType is what snug knows about one variable name.
//
// THE ZERO VALUE IS A REAL ROW, NOT A MISS, and that distinction is what the
// allowlist rests on (issue #44). `envType{}` means "a scalar both `set` and
// `inherit` accept" — EDITOR is one — while a name that is not in envTypes at
// all is refused for both verbs. The two are told apart by the map lookup's
// second return and by nothing else, which is why typeOf returns it: a `known`
// FIELD could be forgotten on a new row, and a forgotten field would read as a
// row that grants nothing rather than as a row that grants a scalar. There is
// no spelling of "on the roster" that a new entry can omit.
type envType struct {
	list   bool
	sep    string
	altSep string // a second separator the CONSUMER also accepts, "" if none
	path   bool   // path-valued, so §2.5's grant-coupling rule applies
	empty  emptyKind

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

	// noInherit is §3.2's `inherit ✗` column for SCALARS. It is a refusal flag
	// INSIDE the roster — the row grants `set`, and this withdraws `inherit`
	// from it. It used to be a refusal flag for a second reason as well, "so
	// that an unknown name defaults to inheritable", and that reason is gone:
	// an unknown name defaults to nothing now. Every name here is one where the
	// HOST's value outranks the
	// file snug generates — "generate, don't bind" is defeated by the
	// environment, not by the file (§4.5) — or one carrying obligations a bare
	// string cannot satisfy (XDG_RUNTIME_DIR: mode 0700, owned by the user).
	//
	// Lists need no flag: `inherit` is refused for EVERY list variable without
	// exception (§2.1), because copying a host search path wholesale imports
	// directories that do not exist inside. inherit is the scalar form;
	// sanitise is the list form.
	noInherit bool
}

// envTypes is snug's ROSTER, and it is §3.2, §3.3 and §3.4. A profile may `set`
// a name, or `inherit` it from the host, ONLY if that name has a row here and
// the row admits that verb. A name that is not here is REFUSED — for `set`, for
// `inherit`, and for the three list verbs, which never accepted an unknown name
// anyway because an unknown name is not a list.
//
// IT USED TO SAY THE OPPOSITE: "a name that is not here is a SCALAR". That
// reading made this the one place in snug built as a DENYLIST — every other
// grant names what it admits, while `set`/`inherit` admitted every name except
// the ones forbiddenEnv below had been taught about. Three red-team rounds
// found three sets of names it had not been taught about, each round closing
// its own names and none of them closing the space, because the space is "every
// variable that some tool, in some version, turns into an exec" and it has no
// edge: RUSTC_WRAPPER/RUSTC_WORKSPACE_WRAPPER/RUSTC; then
// CARGO_BUILD_RUSTC_WRAPPER and NPM_CONFIG_SCRIPT_SHELL at a case the table did
// not fold; then MAKEFLAGS, GOFLAGS, CC, TAR_OPTIONS, RSYNC_RSH,
// GIT_COMMON_DIR, PYTHONUSERBASE, PYTHONPATH, NODE_OPTIONS and PERL5OPT. That
// is CLAUDE.md invariant 2's corollary — wanting "everything except Y" means
// the grant above it was too coarse — applied to the one verb that was written
// the other way round, and the repair is the one @sys already uses when it
// lists fourteen /etc entries instead of binding all 109 (issue #44).
//
// EVERY ROW IS A GRANT. Adding a name says "a profile may hand this to the
// payload", so write the sentence saying what the verb lets the tool DO before
// adding one — the discipline GIT-CONFIG.md §5 asks of the config-key
// whitelist, for the same reason. Do not add a name to make a test pass.
//
// THE ESCAPE HATCH IS `environ.declare`, and it is not this table. A profile
// that legitimately writes a name snug has never heard of declares it in its
// own text; snug then carries the value while saying, on every screen, that it
// checked nothing about it. See checkDeclarations. A BUILTIN may not use it —
// enforced where the sigil is added (internal/profile's `mark`) — so every name
// a shipped profile writes is on this roster by construction.
//
// forbiddenEnv and forbiddenEnvPrefixes below are now REDUNDANT for every name
// that is not on this roster, and they stay. They are the backstop against a
// row added carelessly HERE, later, by someone who read this table as a
// catalogue of types rather than as a list of grants: the two rules are applied
// independently — checkEnvName runs the forbid tables, checkEnvVerbType runs
// this one — so a future roster row for a name the forbid list already covers
// is refused anyway instead of quietly granted. They are also what still
// governs the names `environ.declare` may reach, which are by definition the
// names this table says nothing about. A backstop that never fires is worth
// keeping precisely until the day it does.
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
	// git falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR, and
	// GIT_PAGER -> core.pager -> PAGER, both measured — so a profile that writes
	// one of these chooses the program that runs during an ordinary `git commit`
	// or `git log`, in a sandbox where a DIFFERENT profile may have pinned the
	// ssh identity that the next push will use. The GIT_* spellings are
	// forbidBoth below; these three are not, so the forbid list closes the
	// invisible half of that class and not the class.
	//
	// They are on the roster at both verbs because that is EXACTLY today's
	// behaviour, and this change is a flip of the default, not a withdrawal of a
	// grant: @claude inherits all three, so refusing them here would break a
	// shipped, tested profile outright. Withdrawing them is
	// https://github.com/gomoni/snug/issues/45 — a decision about what @claude
	// may inherit, argued in §3.2 — and these three rows are the seam it will
	// edit: delete them, or give envType a `noSet` flag beside noInherit if the
	// answer is "settable but not inheritable".
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

	// ── the middle bucket: legal as `set`, refused as `inherit` (§2.1) ───────
	//
	// forbiddenEnv marks all five forbidInheritOnly, so `inherit` is closed
	// there. The rows exist because after the flip a name with no row is refused
	// at BOTH verbs, and §2.1's decision — "BASH_ENV = {home}/init with the file
	// granted by the same profile is coherent and reviewable" — would otherwise
	// have been withdrawn by a change that never mentioned it.
	//
	// What each lets a tool DO, which is why these are grants and not
	// bookkeeping: BASH_ENV and ENV name a file every non-interactive bash and
	// sh SOURCES at startup; PYTHONSTARTUP names a file the interactive
	// interpreter executes; PYTHONBREAKPOINT names the callable breakpoint()
	// invokes; LESSOPEN names a program less runs over every file it opens. A
	// profile writing one is choosing code that runs inside — reviewable in the
	// file, which is the whole of why `set` is allowed and `inherit` is not.
	//
	// `path` is false on all five, and that is a decision rather than an
	// oversight. PYTHONBREAKPOINT is a module:callable and LESSOPEN is a command
	// line beginning with '|', so marking them path-valued would make the
	// coupling rule refuse a correct value. BASH_ENV and ENV genuinely are
	// paths, and path:true there would make §2.1's "granted by the same profile"
	// clause enforced rather than merely written down — a new refusal for user
	// profiles, so it belongs in its own change and not smuggled into this one.
	"BASH_ENV":         {},
	"ENV":              {},
	"PYTHONSTARTUP":    {},
	"PYTHONBREAKPOINT": {},
	"LESSOPEN":         {},

	// ── scalars whose inherit is refused (§3.2) ──────────────────────────────
	//
	// The XDG four: snug's own @home creates these directories, so a profile
	// SETTING one to a path it grants is coherent. Inheriting the host's points
	// the sandbox at a directory it does not have.
	"XDG_CONFIG_HOME": {path: true, noInherit: true},
	"XDG_CACHE_HOME":  {path: true, noInherit: true},
	"XDG_STATE_HOME":  {path: true, noInherit: true},
	"XDG_DATA_HOME":   {path: true, noInherit: true},
	// XDG_RUNTIME_DIR carries obligations rather than just a value — mode 0700,
	// owned by the user, session lifetime — so authoring it IS a grant, and it
	// belongs to whichever profile creates a directory meeting them (§3.4).
	"XDG_RUNTIME_DIR": {path: true, noInherit: true},
	// "generate, don't bind": the value is a path to a config snug or a profile
	// produced, never a credential. Inheriting the host's would reintroduce
	// exactly the file the rule exists to avoid.
	"CARGO_HOME":            {path: true, noInherit: true},
	"DOCKER_CONFIG":         {path: true, noInherit: true},
	"NPM_CONFIG_USERCONFIG": {path: true, noInherit: true},
	"PIP_CONFIG_FILE":       {path: true, noInherit: true},
	// PYTHONUSERBASE is refused outright now (forbiddenEnv, forbidBoth — the
	// value's directory is where usercustomize.py runs from, measured), but it
	// is still PATH-VALUED, and was absent from this table entirely — which
	// meant writesAnyPath's grant-coupling sweep (envcoupling.go) skipped it
	// even before the forbidBoth entry existed. noInherit is redundant with
	// forbidBoth here; it is set anyway so this row reads the same as its
	// siblings rather than as a special case someone has to explain.
	"PYTHONUSERBASE": {path: true, noInherit: true},

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
	// parser. Both are forbidden outright as well (see forbiddenEnv) — the
	// entries exist so the separator-in-a-value check can still see that ';' and
	// ' ' are separators for some consumer.
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

// snugKnowsEnvName reports whether snug has an OPINION about a name — a roster
// row, or an exact entry in the forbidden table.
//
// The second half is redundant today and is kept on purpose. Every
// forbidInheritOnly name now also has a roster row (the middle bucket), so
// nothing reaches this function that only forbiddenEnv covers — but the day
// someone adds a forbidInheritOnly entry without a roster row, this is what
// stops that name being `environ.declare`d as though snug had never heard of
// it. A declaration says "snug has no opinion about this name", and it must
// never be usable to say that about a name snug refuses at a verb.
//
// The PREFIX table is deliberately NOT part of this. A prefix names an
// unbounded family (PIP_*), and refusing to declare every name under one would
// leave `set PIP_INDEX_URL` — legal today, forbidInheritOnly by prefix — with
// nowhere to go. What governs a declared name under a prefix is the prefix rule
// itself, applied at the verb that uses it, exactly as before.
func snugKnowsEnvName(name string) bool {
	if _, ok := typeOf(name); ok {
		return true
	}
	_, ok := forbiddenEnv[name]
	return ok
}

// IsUncheckedEnv reports whether one entry of the resolved environment is one a
// PROFILE declared rather than one snug has a roster row for — the value snug
// carried without knowing anything about the name.
//
// Exported because being unchecked has to be VISIBLE, and at every sink rather
// than at the one somebody remembered: --dry-run's ENVIRONMENT block marks the
// row, `snug profile show` renders the `environ.declare` block as unchecked,
// and the refusal that sends an author to the hatch names it. The argv block is
// the one sink with nothing to add — `--setenv NAME VALUE` has no provenance
// column at all, and the value got there through checkEnvValue like every other
// value a profile wrote.
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

// forbidKind splits the forbidden list by VERB, because `set` and `inherit`
// carry values from two different places.
//
// A `set` carries a value from a reviewable file in the trusted profile layer.
// An `inherit` carries whatever the process that launched snug happened to have.
// So inherit is a hole punched in --clearenv and set is not, and one middle
// bucket is legal as `set` and refused as `inherit`: BASH_ENV = "{home}/init"
// with the file granted by the same profile is coherent and reviewable, while
// the same name inherited points at a host path (§2.1, CALL 4).
type forbidKind uint8

const (
	forbidBoth forbidKind = iota
	forbidInheritOnly
)

// forbiddenEnv are names whose VALUE IS CODE, orthogonal to the type table: the
// type table says what may be merged, this says what may never be inherited at
// all. Both are applied; neither replaces the other. §4.4 is a list to be
// EXTENDED, not retired.
//
// PS1 is deliberately absent, and so is SNUG*: they are snug's own (§1.1) and
// refused by ownership, which is the stronger statement. Adding a prefix rule
// for either would let a name pass the ownership check and be caught by a weaker
// mechanism instead.
//
// WHAT THIS LIST DOES NOT CLOSE, stated here because reading it as a class
// closure is the mistake it invites. EDITOR, VISUAL and PAGER are legal at
// `set` and at `inherit` by §3.2's decision, and @claude inherits all three. git
// falls back GIT_EDITOR -> core.editor -> VISUAL -> EDITOR, and GIT_PAGER ->
// core.pager -> PAGER, both measured. So the GIT_EDITOR and GIT_PAGER entries
// below do not make git unhijackable by a profile — a profile that wanted to
// would write the generic spelling.
//
// They are still worth having, and the reason is not defence in depth, it is
// that the two spellings differ in who they surprise. A profile setting EDITOR
// is doing a legible thing to a variable a human recognises; the GIT_* names are
// invisible in every screen a human reads and fire during operations nobody
// thinks of as running a command. Refusing the invisible half is not the same as
// closing the class, and the day someone decides the generic three must go too,
// it is a §3.2 decision — a grant being withdrawn from every profile that
// inherits them — not an addition to this table. Carried as
// https://github.com/gomoni/snug/issues/35.
var forbiddenEnv = map[string]forbidKind{
	// the value is code, at any verb — §4.4 plus ld.so(8)'s own secure-execution
	// list, which is the closest thing to an authoritative denylist that exists
	"LD_PRELOAD": forbidBoth, "LD_AUDIT": forbidBoth, "LD_LIBRARY_PATH": forbidBoth,
	"GCONV_PATH": forbidBoth, "LOCPATH": forbidBoth, "NLSPATH": forbidBoth,
	"HOSTALIASES": forbidBoth, "RESOLV_HOST_CONF": forbidBoth, "RES_OPTIONS": forbidBoth,
	"TZDIR": forbidBoth, "MALLOC_TRACE": forbidBoth, "GETCONF_DIR": forbidBoth,
	"NIS_PATH": forbidBoth,
	// git executes each of these, measured
	"GIT_SSH_COMMAND": forbidBoth, "GIT_EXEC_PATH": forbidBoth,
	"GIT_EXTERNAL_DIFF": forbidBoth, "GIT_EDITOR": forbidBoth,
	// The same power under older or adjacent spellings. A redteam run reached
	// git's transport through GIT_SSH while GIT_SSH_COMMAND — its exact
	// equivalent — was refused two lines up, and hijacked a `git fetch` in a
	// sandbox that had been given a PINNED ssh identity by a DIFFERENT profile:
	//
	//   snug -p work -p helper <tgt> -- git fetch origin
	//     HIJACKED-GIT-TRANSPORT host=git@github.com … SSH_AUTH_SOCK=/run/snug/ssh-agent.sock
	//
	// `helper` granted no filesystem path at all. That is one profile defeating
	// a guarantee another profile established, which is the composability case
	// this whole table exists to prevent — so the rule was never "the newest
	// spelling"; it is "the value is code". Anything git or ssh execs belongs
	// here, and forgetting one is indistinguishable from allowing it.
	"GIT_SSH": forbidBoth, "GIT_PROXY_COMMAND": forbidBoth,
	"GIT_ASKPASS": forbidBoth, "SSH_ASKPASS": forbidBoth,
	"GIT_SEQUENCE_EDITOR": forbidBoth,
	// Found missing by an independent review, and each measured on git 2.55
	// before being added here rather than reasoned about:
	//
	//   GIT_PAGER="sh -c 'echo HIJACK; cat >/dev/null'" git log   -> HIJACK
	//
	// GIT_TEMPLATE_DIR and GIT_DIR are the same power one indirection out: the
	// value is a DIRECTORY, and the hooks in it are code. A template dir installs
	// its hooks into every repository `git clone` and `git init` create
	// afterwards (measured: post-checkout fired on the clone), and GIT_DIR points
	// git at a repository whose hooks run on the next commit (measured). They
	// belong here rather than in the path-coupling rule, because granting the
	// path is not what makes them safe — nothing does. GIT_COMMON_DIR is the
	// identical shape, missed in the first pass and found by an independent
	// review's sweep, not by reasoning: it points git's SHARED directory
	// (where `hooks/` lives for a worktree) at an attacker-chosen path, and
	// `hooks/pre-commit` there ran on the next commit — measured, git 2.55.
	"GIT_PAGER": forbidBoth, "GIT_TEMPLATE_DIR": forbidBoth, "GIT_DIR": forbidBoth,
	"GIT_COMMON_DIR": forbidBoth,
	// A different shape again, and the reason the rule is "the value is code"
	// rather than "the value is a command": these two carry no code at all. They
	// switch OFF git's own refusal to use the ext:: transport, which runs an
	// arbitrary command as the transport. Measured, with the control:
	//
	//   GIT_ALLOW_PROTOCOL=ext git ls-remote "ext::sh -c '…'"   -> ran
	//                           git ls-remote "ext::sh -c '…'"   -> refused
	//
	// A name that re-enables an exec path is the exec path.
	"GIT_ALLOW_PROTOCOL": forbidBoth, "GIT_PROTOCOL_FROM_USER": forbidBoth,
	// Same class, different runtime: each is a flag string the runtime parses
	// before main(), and each can load code from a path.
	"JAVA_TOOL_OPTIONS": forbidBoth, "_JAVA_OPTIONS": forbidBoth,
	"JDK_JAVA_OPTIONS": forbidBoth, "RUBYOPT": forbidBoth,
	// cargo executes an arbitrary program as its own compiler driver — measured
	// (issue #26 red team): a profile with RUSTC_WRAPPER pointing at a script
	// made `cargo build` run that script in place of rustc, as the sandbox's
	// own uid, and this was reachable through both `environ.set` and
	// `environ.inherit` before this entry existed. RUSTC_WORKSPACE_WRAPPER and
	// RUSTC carry the identical capability — the same one CARGO_BUILD_RUSTC_WRAPPER
	// already forbids via the CARGO_ prefix below — but none of the three
	// starts with a listed prefix, so the prefix table alone missed them. This
	// is the shape CLAUDE.md keeps recording: a rule applied to one of its two
	// spellings.
	"RUSTC_WRAPPER": forbidBoth, "RUSTC_WORKSPACE_WRAPPER": forbidBoth, "RUSTC": forbidBoth,
	// The same class again, one indirection further out: a build tool's own
	// "run this program instead" or "pass these extra flags" variable, each
	// measured to run an attacker-chosen program as the sandbox's own uid —
	// a second-pass review sweep, not a spelling anyone reasoned about ahead
	// of time. This is why the table is enumerated rather than derived: the
	// space of "an env var some tool turns into exec" is unbounded, and each
	// of these was found only by trying it.
	//
	//   MAKEFLAGS="--eval=x:;$(shell ./evil.sh)"  make        -> evil.sh ran   (GNU make 4.x)
	//   GOFLAGS="-toolexec=/…/toolexec.sh"         go build    -> ran per compile (go 1.26)
	//   CC=./evil.sh                                make        -> ran as the compiler, via make's implicit rules
	//   TAR_OPTIONS="--use-compress-program=/…/prog.sh"  tar   -> prog.sh ran   (GNU tar 1.35)
	//   RSYNC_RSH=/…/prog.sh                        rsync       -> prog.sh ran   (rsync 3.4.3)
	"MAKEFLAGS": forbidBoth, "GOFLAGS": forbidBoth, "CC": forbidBoth,
	"TAR_OPTIONS": forbidBoth, "RSYNC_RSH": forbidBoth,
	// bash performs command substitution on the prompt templates, before the
	// user has typed anything (§3.5)
	"PS0": forbidBoth, "PS2": forbidBoth, "PS3": forbidBoth, "PS4": forbidBoth,
	"PROMPT_COMMAND": forbidBoth,

	// An interpreter's own "run this file/module before anything else"
	// variable — the same class as BASH_ENV/ENV below. PYTHONPATH,
	// NODE_OPTIONS and PERL5OPT were PROMOTED here from forbidInheritOnly:
	// "reviewable as set" was the call made for them, and it does not survive
	// a measurement of the value running code. PYTHONUSERBASE was simply
	// absent from this table until this measurement found it.
	//
	//   PYTHONUSERBASE=…  python3 -c 'import site'
	//     -> …/site-packages/usercustomize.py ran on every python3   (CPython 3.13)
	//   PYTHONPATH=…      python3 -c 'pass'
	//     -> sitecustomize.py on that path ran at interpreter start   (CPython)
	//   NODE_OPTIONS="--require /…/pre.js"  node ...
	//     -> pre.js ran before the script, every invocation             (node 26)
	//   PERL5OPT="-I/… -Mevil"  perl ...
	//     -> evil.pm loaded on every perl invocation                    (perl 5)
	//
	// "Reviewable as set, from a profile that also grants the path" was the
	// right call for a variable that carries a PATH a tool merely READS
	// (BASH_ENV, ENV, LESSOPEN). It was the wrong call here: these four
	// carry a path a tool EXECUTES, unconditionally, on every invocation —
	// indistinguishable in shape from RUSTC_WRAPPER above, which is
	// forbidBoth for the identical reason.
	"PYTHONUSERBASE": forbidBoth, "PYTHONPATH": forbidBoth,
	"NODE_OPTIONS": forbidBoth, "PERL5OPT": forbidBoth,

	// reviewable as `set`, a hole in --clearenv as `inherit` — each of these
	// carries a PATH the tool reads, not a path it unconditionally executes;
	// see the block above for the class this is NOT.
	"BASH_ENV": forbidInheritOnly, "ENV": forbidInheritOnly,
	"PYTHONSTARTUP": forbidInheritOnly, "PYTHONBREAKPOINT": forbidInheritOnly,
	"LESSOPEN": forbidInheritOnly,
}

// prefixCaseFold is the ONE place "does this tool's env lookup fold case"
// lives. forbiddenEnvPrefixes (what a profile may write) and
// inlineConfigPrefixes (what snug's sink sweep treats as inline config) both
// match against this same table instead of each carrying its own bool, so a
// re-measurement changes one line and both tables see it.
//
// That is not tidiness for its own sake: it is the fix for a defect measured
// in review. A previous round gave inlineConfigPrefixes a case-insensitive
// npm_config_ entry — correctly, npm 10.9.8 measured — but left
// forbiddenEnvPrefixes' OWN npm_config_ entry case-sensitive, so
// `environ.inherit NPM_CONFIG_SCRIPT_SHELL` (the idiomatic, upper-case
// spelling a shell `export` produces) was ACCEPTED at parse time while the
// predicate that exists to name it as inline config said `true`. Two tables
// holding the same fact is how they end up disagreeing about it; one table
// cannot.
var prefixCaseFold = map[string]bool{
	// Measured on this host, git 2.55.0: GIT_CONFIG_COUNT/KEY_0/VALUE_0 are
	// read; git_config_count and Git_Config_Count are not (both fall through
	// to the file value). getenv(3) is case-sensitive on Linux and git does
	// no folding of its own — consistent across every GIT_CONFIG_* name.
	"GIT_CONFIG_": false,
	// Documented, not measured: pip is not installed on this host (§1.2 of
	// the issue #26 design). pip's own source
	// (Configuration.get_environ_vars in pip/_internal/configuration.py)
	// does `key.startswith("PIP_")` against os.environ, which on Linux is a
	// case-sensitive mapping — so only the exact-case PIP_* spelling should
	// be recognised. Re-measure if pip becomes available here.
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
// forbidden table, the inline-config predicate, and any exemption from
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

// forbiddenEnvPrefixes is the half a map[string]bool could never express, and
// four of §4.4's findings are exactly this shape.
//
// BASH_FUNC_* is not a variable but a NAME PATTERN carrying exported shell
// functions — and function lookup precedes PATH entirely, so it defeats every
// ordering question in this file.
var forbiddenEnvPrefixes = []struct {
	prefix string
	kind   forbidKind
	// exempt names that match prefix but are POINTERS, not the capability the
	// prefix exists to block — matched with prefix's own case rule via
	// sameName, for the same reason inlineConfigPointers must be.
	exempt []string
}{
	{"LD_", forbidBoth, nil},
	{"BASH_FUNC_", forbidBoth, nil},
	{"GIT_CONFIG_", forbidBoth, nil},
	// PIP_* outranks the config FILE pip reads, so inheriting it defeats a
	// pinned config; setting one in a reviewed profile that also grants the
	// path is what "generate, don't bind" asks for. Nothing under PIP_ was
	// measured to exec a program the way npm_config_ and CARGO_ below were —
	// re-promote if that changes.
	{"PIP_", forbidInheritOnly, nil},
	// cargo executes an arbitrary program for CARGO_BUILD_RUSTC_WRAPPER,
	// CARGO_BUILD_RUSTC and CARGO_TARGET_<TRIPLE>_RUNNER/_LINKER — the SAME
	// capability as the un-prefixed RUSTC_WRAPPER/RUSTC/RUSTC_WORKSPACE_WRAPPER
	// in forbiddenEnv above, reached through a different spelling. forbidBoth,
	// not forbidInheritOnly: those three named entries are forbidBoth because
	// the value IS code, and CARGO_BUILD_RUSTC_WRAPPER is that same code path,
	// not merely config that outranks a file — treating the prefixed spelling
	// more leniently than the bare name it is a synonym for would just move
	// the hole rather than close it. Measured, issue #26 review: before this
	// entry existed, `environ.set CARGO_BUILD_RUSTC_WRAPPER = ...` and
	// `environ.inherit CARGO_BUILD_RUSTC_WRAPPER` were both accepted at parse
	// time. CARGO_HOME is the one exemption: it is a POINTER (the mechanism a
	// future cargo adapter would use, same shape as GIT_CONFIG_GLOBAL), not a
	// code path.
	{"CARGO_", forbidBoth, []string{"CARGO_HOME"}},
	// npm_config_ promoted from forbidInheritOnly for the identical reason
	// CARGO_ was above: `npm_config_script_shell` names the shell npm uses to
	// run lifecycle and `run` scripts, and `npm_config_node_gyp` names the
	// program npm invokes for native builds — both ARE that code path, not
	// merely config that outranks a file, and both are npm's exact analog of
	// CARGO_BUILD_RUSTC_WRAPPER. Measured, issue #26 review: before this
	// promotion, `environ.set NPM_CONFIG_SCRIPT_SHELL = ...` and
	// `environ.set NPM_CONFIG_NODE_GYP = ...` were both accepted, in every
	// case spelling — see prefixCaseFold's npm_config_ entry above for why
	// case matters here at all. NPM_CONFIG_USERCONFIG is the one exemption,
	// for the same reason CARGO_HOME is: it is a POINTER, not a code path.
	{"npm_config_", forbidBoth, []string{"NPM_CONFIG_USERCONFIG"}},
}

// inlineConfigPrefixes is the prefix half of IsInlineConfigEnv's table: every
// name matching one of these is a config-surface variable whose VALUE IS THE
// SETTING, unless it is named in inlineConfigPointers below. Case sensitivity
// for each prefix comes from prefixCaseFold, the same table
// forbiddenEnvPrefixes reads — see that table's comment for why sharing it
// matters, not just naming the list here.
var inlineConfigPrefixes = []string{
	"GIT_CONFIG_",
	"PIP_",
	"npm_config_",
	"CARGO_",
}

// inlineConfigPointer is one entry of inlineConfigPointers: a name that
// matches a prefix above but whose value is a PATH to a file snug generated,
// not the setting itself. prefix names which entry in prefixCaseFold governs
// the case rule for this exemption — NPM_CONFIG_USERCONFIG is exempt in
// every spelling npm itself honours, or a case-insensitive prefix match
// would turn the exemption into a false positive instead of fixing the false
// negative it replaced.
type inlineConfigPointer struct {
	name   string
	prefix string
}

// inlineConfigPointers is the exemption set. Naming one here is a policy
// change — ask what the name makes the tool DO, exactly as GIT-CONFIG.md §5
// asks of the config-key whitelist.
var inlineConfigPointers = []inlineConfigPointer{
	{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_"},
	{"GIT_CONFIG_SYSTEM", "GIT_CONFIG_"},
	{"NPM_CONFIG_USERCONFIG", "npm_config_"},
	{"PIP_CONFIG_FILE", "PIP_"},
	{"CARGO_HOME", "CARGO_"},
}

// inlineConfigNames is the named half the prefix table structurally cannot
// express: a variable whose value is a setting (here, an arbitrary program
// cargo executes as its compiler driver) but whose NAME does not start with
// its tool's prefix. RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER and RUSTC carry
// the identical capability CARGO_BUILD_RUSTC_WRAPPER carries under the
// CARGO_ prefix in forbiddenEnvPrefixes — measured, issue #26 red team: a
// profile setting RUSTC_WRAPPER to a script made `cargo build` run that
// script in place of rustc. All six names (these three, plus the three
// CARGO_BUILD_* / CARGO_TARGET_* spellings the prefix catches) are already
// refused outright in forbiddenEnv/forbiddenEnvPrefixes (forbidBoth, for
// every verb) — this map exists so IsInlineConfigEnv's own promise stays
// true for the un-prefixed spelling too, not because anything downstream of
// it is what stops a builtin from shipping one; see IsInlineConfigEnv's doc
// comment for what actually enforces that.
var inlineConfigNames = map[string]bool{
	"RUSTC_WRAPPER":           true,
	"RUSTC_WORKSPACE_WRAPPER": true,
	"RUSTC":                   true,
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
// it as the whole of the sink sweep and it is not: the command-hook-via-`set`
// class in forbiddenEnv — BASH_ENV, ENV, PERL5OPT, NODE_OPTIONS,
// PYTHONSTARTUP, LESSOPEN and the rest marked forbidInheritOnly — is
// deliberately reviewable AS `set`, from a reviewed profile that also grants
// the path (see forbidKind's doc comment). Those names return false here on
// purpose; TestNoBuiltinHandsOverAnInlineConfigVariable is not their guard.
//
// What this predicate is NOT, stated because a doc comment nearby overclaimed
// it once: it has no production caller. `forbiddenEnv`/`forbiddenEnvPrefixes`
// via `ValidateEnvGrants` is what stops a PROFILE — builtin or user — from
// ever authoring one of these names; that is the real, load-bearing gate.
// IsInlineConfigEnv is read only by cmd/snug's builtin-only, TEST-TIME sweep
// (TestNoBuiltinHandsOverAnInlineConfigVariable), which resolves
// `profile.Builtins()` and nothing a user's own `~/.config/snug/profiles.d`
// defines. If forbiddenEnv/forbiddenEnvPrefixes were ever narrowed, a USER
// profile writing one of these names would reach the payload with nothing in
// the way, and this sweep would stay green regardless — it never resolves a
// user profile. Wiring this predicate into ValidateEnvGrants itself, so it
// governs what ANY profile may author, is a policy decision and is
// deliberately not made here.
//
// The pointer set is a SECURITY BOUNDARY, not a convenience list. Adding a
// name to it says "snug hands this to the payload"; ask what the name makes
// the tool DO, exactly as GIT-CONFIG.md §5 asks of the config-key whitelist.
func IsInlineConfigEnv(name string) bool {
	if inlineConfigNames[name] {
		return true
	}
	for _, p := range inlineConfigPointers {
		if sameName(name, p.name, p.prefix) {
			return false
		}
	}
	for _, p := range inlineConfigPrefixes {
		if matchesPrefix(name, p) {
			return true
		}
	}
	return false
}

// forbiddenFor reports whether a name is refused for this verb, and why.
//
// A prefix's exempt list applies to every verb EXCEPT VerbInherit, and that
// asymmetry is deliberate rather than an oversight: an exempt name is a
// POINTER (CARGO_HOME, NPM_CONFIG_USERCONFIG, …), and "generate, don't bind"
// refuses to let a pointer be pulled from the HOST regardless — inheriting
// would reintroduce exactly the file the rule exists to avoid. Most of the
// time that refusal ALSO comes from the name's own noInherit row in envTypes,
// and the history is worth keeping because the fix is structural rather than
// belt-and-braces: that lookup used to be a case-SENSITIVE, exact-string one.
// Exactly right for a case-sensitive prefix (CARGO_), and exactly wrong for a
// case-INSENSITIVE one — npm_config_'s exemption (NPM_CONFIG_USERCONFIG)
// matches every case spelling via sameName/prefixCaseFold, while
// envTypes["npm_config_userconfig"] did not exist, so the type-table refusal
// never fired for that spelling. Measured, before this rule existed:
// environ.inherit npm_config_userconfig was ACCEPTED while environ.inherit
// NPM_CONFIG_USERCONFIG was refused, the same "one table disagrees with itself
// across two case spellings" defect this whole file exists to close, found one
// level deeper. Refusing to let exempt+Inherit combine at all closes it
// structurally, for every existing and future case-insensitive prefix.
//
// typeOf HAS since become case-fold aware (issue #44 had to make it: after the
// flip, an exact-string roster would have exempted npm_config_userconfig from
// the prefix and then refused it for having no row). So the two mechanisms now
// agree where they overlap. This rule is not thereby redundant, and must not be
// deleted as such: it holds for a name with NO roster row at all, which after
// the flip is every name a profile reached through environ.declare, and it does
// not depend on anyone remembering to add a row.
func forbiddenFor(name string, verb EnvVerb) (bool, string) {
	if k, ok := forbiddenEnv[name]; ok && appliesTo(k, verb) {
		return true, ""
	}
	for _, p := range forbiddenEnvPrefixes {
		if !matchesPrefix(name, p.prefix) {
			continue
		}
		if verb != VerbInherit {
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
		if appliesTo(p.kind, verb) {
			return true, p.prefix
		}
	}
	return false, ""
}

func appliesTo(k forbidKind, verb EnvVerb) bool {
	return k == forbidBoth || verb == VerbInherit
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
	if yes, prefix := forbiddenFor(name, verb); yes {
		if prefix != "" {
			return fmt.Errorf("environ.%s names %s, and snug refuses the whole %s* prefix "+
				"for this verb: the value is executed, or it outranks the config file "+
				"snug generates. Remove the line", v, name, prefix)
		}
		return fmt.Errorf("environ.%s names %s, which snug refuses for this verb: the value "+
			"is code, executed by every process the sandbox launches. Remove the line", v, name)
	}
	return nil
}

// checkEnvOwnership refuses a name snug writes itself (§1.1).
//
// It does NOT fire for a list snug owns, and PATH is the only one — read that
// carefully, because it is the one place ownership is narrower than "no profile
// may write a name snug writes".
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

// checkEnvVerbType refuses a verb the variable's TYPE does not accept, and — as
// of the flip — a name the roster does not carry at all. The error names the
// right verb, because "wrong verb" without "use this one" leaves the author
// guessing (§2.1).
//
// `declared` is whether the SAME PROFILE declared this name in its own
// `environ.declare` block. It licenses the two scalar verbs and nothing else;
// see checkDeclarations for what a declaration is and why it cannot come from
// another profile.
func checkEnvVerbType(name string, verb EnvVerb, declared bool) error {
	t, known := typeOf(name)
	if !known {
		return checkUnrosteredName(name, verb, declared)
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
		if t.noInherit {
			return fmt.Errorf("environ.inherit on %s, which snug refuses to take from the "+
				"host: the host's value names a path this sandbox does not have, and for a "+
				"config-file variable it would outrank the file snug generates. Use "+
				"environ.set with a path the same profile grants", name)
		}
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

// checkUnrosteredName is the flip itself: a name snug has no row for.
//
// Two different refusals, because there are two different fixes and they belong
// to two different people. The scalar verbs have an escape hatch and the list
// verbs structurally cannot: a list verb needs the SEPARATOR and the meaning of
// an EMPTY ELEMENT, and neither is something a profile can hand over — inferring
// them from the shape of a value is exactly what this file exists not to do
// (see the header comment, and §3.3, where the same column decides that
// MANPATH may not be sanitised at all).
func checkUnrosteredName(name string, verb EnvVerb, declared bool) error {
	if verb == VerbSet || verb == VerbInherit {
		if declared {
			return nil
		}
		return fmt.Errorf("environ.%s names %s, which snug has no entry for.\n"+
			"       `set` and `inherit` are an ALLOWLIST: snug refuses a name it has not been\n"+
			"       taught about rather than assuming it is an inert scalar. The space that\n"+
			"       assumption left open — every variable some tool, in some version, turns into\n"+
			"       an exec — has no edge, and three rounds of closing individual names never\n"+
			"       caught up with it. Two ways forward, for two different people:\n"+
			"         · a profile you own — declare the name in that same profile:\n"+
			"             [profile.NAME.environ.declare]\n"+
			"             %s = true\n"+
			"           which says snug has no opinion about it. It is carried, and it renders\n"+
			"           as unchecked in --dry-run and `snug profile show`. Every refusal snug\n"+
			"           already makes still applies to it.\n"+
			"         · a name snug should know — add a row to internal/policy/envtypes.go,\n"+
			"           with the sentence saying what the verb lets the tool DO. A row there is\n"+
			"           a grant, so that is a policy change and not a lookup-table edit.",
			verb, name, name)
	}
	hatch := ""
	if declared {
		hatch = "\n       This profile declares %s, and a declaration does not help here: it says\n" +
			"       snug has no opinion about the NAME, while environ.%s needs a fact about the\n" +
			"       VALUE that only a roster row carries."
		hatch = fmt.Sprintf(hatch, name, verb)
	}
	return fmt.Errorf("environ.%s on %s, which snug has no entry for. A list verb needs the\n"+
		"       separator that variable is read with and what an EMPTY ELEMENT means to its\n"+
		"       consumer — ignored, the current directory, or an instruction that ADDS\n"+
		"       directories (§3.3) — and snug will not guess either from the shape of a value.\n"+
		"       Use environ.set with the whole value, or add a row to\n"+
		"       internal/policy/envtypes.go carrying the separator and the empty-element kind.%s",
		verb, name, hatch)
}

// checkDeclarations is the escape hatch, and this comment is the argument for
// its shape.
//
// WHAT IT IS. `[profile.x.environ.declare]` is a set of NAMES — the same
// spelling as `inherit` and `sanitise`, `NAME = true` — and it carries no value
// and produces no entry. It is a LICENCE, not a verb: it says "snug has no row
// for this name, and I, the author of this profile, take that responsibility",
// and it makes `set` and `inherit` legal for that name IN THAT PROFILE. That is
// why it is not the denylist wearing a new name: a declaration and a roster row
// are mutually exclusive (rule 2 below), so the hatch is reachable ONLY where
// snug genuinely has nothing to say, and it can never become the ordinary
// spelling for PATH, EDITOR or XDG_CONFIG_HOME.
//
// WHAT THAT SENTENCE DOES NOT SAY, because the stronger reading is false and a
// red-team run measured it. A declaration cannot route around a decision snug
// made about a NAME. It CAN route around a decision snug made about a CLASS, by
// naming the sibling: `snugKnowsEnvName` is a per-name predicate, and every
// entry in forbiddenEnv is one spelling of a capability that has several.
// `declare ZDOTDIR` + `inherit ZDOTDIR` is legal while `inherit BASH_ENV` is
// refused, and zsh sources that directory's .zshrc exactly as bash sources
// BASH_ENV; LESSCLOSE is legal beside LESSOPEN, MAKESHELL beside CC, CVS_RSH
// beside GIT_SSH. About fifty such names were measured, and every one of them
// was equally reachable BEFORE this flip with no declaration at all — so the
// hatch bounds this rather than opening it, at the cost of four lines in the
// profile and an unchecked mark on the screen.
//
// State it plainly, because the direction matters: against a hostile profile
// author — and invariant 3 does not currently give us a trustworthy one, see
// issue #27 — the hatch is NOT a barrier. It is a DISCLOSURE mechanism, and a
// good one. Every property that earns it a place is a visibility property: the
// greppable per-profile block, the mark at both sinks, the unused-name refusal,
// builtins excluded. None of them is a refusal. Whether the forbid table should
// grow those fifty names, or stop pretending to be complete and say what it is
// FOR instead, is issue https://github.com/gomoni/snug/issues/77.
//
// WHY A LICENCE RATHER THAN A SIXTH VERB. A verb would have had to carry a
// value, and then `inherit` of an unknown name — a user profile taking their own
// tool's API token from the host — would have had no spelling at all except
// writing the secret into the profile file. Separating the licence from the use
// keeps all five verbs meaning exactly what they meant, keeps the unchecked set
// on one greppable line per profile, and makes the declaration itself grant
// nothing.
//
// WHY IT IS NOT INHERITED THROUGH `include`. ValidateEnvGrants sees one
// profile's own block, so a declaration cannot travel — and that is the point,
// not a limitation: the responsibility is the author's, and a profile that uses
// an unrostered name must say so in its own text where a reviewer reading that
// file sees it. It is also what keeps the verdict a property of the profile
// TEXT, decided at parse time, identical on every host.
//
// WHAT IT DOES NOT BUY. Every other refusal still applies, in the order
// checkEnvEntry already runs them: the name grammar, the names snug owns
// (checkEnvOwnership), forbiddenEnv and its prefixes, and the control-character
// rule on the value. The hatch buys "snug has no opinion about this name",
// never "snug's refusals do not apply".
//
// A BUILTIN MAY NOT USE IT, and that is structural rather than a convention
// here: internal/profile's `mark` — the one place a profile is published into
// the @-namespace — refuses to mark a profile that declares anything. So every
// name a shipped profile writes has a roster row, which is the property this
// whole change exists to establish.
func checkDeclarations(g EnvGrants, declared map[string]bool) error {
	used := func(name string) bool {
		if _, ok := g.Set[name]; ok {
			return true
		}
		for _, n := range g.Inherit {
			if n == name {
				return true
			}
		}
		return false
	}
	for _, name := range sortedCopy(g.Declare) {
		// The declaration is checked at `set` strength: the name grammar, and
		// the forbidden tables at the weakest verb a declaration licenses.
		// Inherit-strength is applied at the inherit USE, exactly as it is for a
		// rostered name — checking it here instead would refuse `declare
		// PIP_INDEX_URL` and leave `set PIP_INDEX_URL`, legal today, with
		// nowhere to go.
		if err := checkEnvName(name, VerbDeclare); err != nil {
			return err
		}
		if err := checkEnvOwnership(name, VerbDeclare); err != nil {
			return err
		}
		if snugKnowsEnvName(name) {
			return fmt.Errorf("environ.declare names %s, which snug already has an entry for.\n"+
				"       A declaration says snug knows nothing about a name; it is not a way to\n"+
				"       overrule what snug does know. Use the verb directly — and if that verb is\n"+
				"       refused for this name, the refusal IS the decision, argued in\n"+
				"       internal/policy/envtypes.go and .claude/design/ENVIRONMENT-VARIABLES.md,\n"+
				"       and changing it means changing that row rather than routing around it",
				name)
		}
		if !used(name) {
			return fmt.Errorf("environ.declare names %s, but no environ.set or environ.inherit "+
				"in this profile uses it.\n"+
				"       A declaration is a licence for this profile's own use of one name, and an\n"+
				"       unused one is a name on the unchecked list that nothing needs — which is\n"+
				"       how a hatch quietly turns back into a namespace. Delete the line, or add\n"+
				"       the verb that was meant to go with it.\n"+
				"       Note that a declaration does not travel through `include`: the profile\n"+
				"       that writes the name is the profile that must declare it", name)
		}
	}
	return nil
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
	// An unrostered name has no separator to smuggle, and it never reaches a
	// list verb anyway — checkUnrosteredName refuses those outright.
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
func checkEnvValue(name string, verb EnvVerb, value string) error {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x20 && c != 0x7f {
			continue
		}
		what := fmt.Sprintf("%q", string(c))
		if c == 0 {
			return fmt.Errorf("environ.%s on %s has a value containing a NUL byte. The whole "+
				"bwrap flag list is NUL-separated, so a NUL inside a value ENDS the value "+
				"and everything after it is read as further flags — a mount snug's policy "+
				"model never sees and --dry-run never prints. Remove it", verb, name)
		}
		return fmt.Errorf("environ.%s on %s has a value containing %s. Every screen a human "+
			"reads to decide whether to trust a sandbox renders a value on one line; a "+
			"control character forges rows in it or erases them from the terminal. "+
			"Remove it", verb, name, what)
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
	// The declarations are read FIRST and checked LAST. Read first because
	// every verb below needs to know whether this profile licensed the name;
	// checked last because a declaration's own faults (naming something snug
	// knows, naming something nothing uses) are less useful to report than the
	// verb that is actually wrong — a `merge` on a declared name should say why
	// a list verb cannot be declared, not that the declaration went unused.
	declared := make(map[string]bool, len(g.Declare))
	for _, name := range g.Declare {
		declared[name] = true
	}
	for _, name := range sortedMapKeys(g.Set) {
		if err := checkEnvEntry(name, VerbSet, declared[name]); err != nil {
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
			if err := checkEnvEntry(name, verb, declared[name]); err != nil {
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
		if err := checkEnvEntry(name, VerbInherit, declared[name]); err != nil {
			return err
		}
	}
	for _, name := range sortedCopy(g.Sanitise) {
		if err := checkEnvEntry(name, VerbSanitise, declared[name]); err != nil {
			return err
		}
	}
	return checkDeclarations(g, declared)
}

// checkEnvEntry is the whole parse-time verdict on one (name, verb) pair, in
// the order that produces the most useful message: what the name IS, then who
// owns it, then whether the verb fits its type — and, since the flip, whether
// snug has an entry for it at all, which is the last question because it is the
// one whose answer is "and here is the hatch".
func checkEnvEntry(name string, verb EnvVerb, declared bool) error {
	if err := checkEnvName(name, verb); err != nil {
		return err
	}
	if err := checkEnvOwnership(name, verb); err != nil {
		return err
	}
	return checkEnvVerbType(name, verb, declared)
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
