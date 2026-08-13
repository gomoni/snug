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
	// They are consulted only for list variables, so their zero value never
	// decides anything for an unknown name — an unknown name is a scalar (§2.1).
	mergeable   bool
	sanitisable bool

	// noInherit is §3.2's `inherit ✗` column for SCALARS, and it is a refusal
	// flag rather than an allow flag so that an unknown name defaults to
	// inheritable. Every name here is one where the HOST's value outranks the
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

// envTypes is §3.2, §3.3 and §3.4. A name that is not here is a SCALAR — the
// conservative reading, because a scalar merges with nothing, so it can only
// ever conflict and never silently combine (§2.1).
//
// Names snug owns are deliberately ABSENT even where §3.2 lists them: ownership
// refuses them for every verb, which is the stronger statement, and an entry
// here would invite someone to read the row as permission.
var envTypes = map[string]envType{
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

// typeOf returns what snug knows about a name. An unknown name is a scalar.
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
func IsEnvList(name string) bool { return typeOf(name).list }

func typeOf(name string) envType {
	if t, ok := envTypes[name]; ok {
		return t
	}
	return envType{}
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
	// path is not what makes them safe — nothing does.
	"GIT_PAGER": forbidBoth, "GIT_TEMPLATE_DIR": forbidBoth, "GIT_DIR": forbidBoth,
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
	// bash performs command substitution on the prompt templates, before the
	// user has typed anything (§3.5)
	"PS0": forbidBoth, "PS2": forbidBoth, "PS3": forbidBoth, "PS4": forbidBoth,
	"PROMPT_COMMAND": forbidBoth,

	// reviewable as `set`, a hole in --clearenv as `inherit`
	"BASH_ENV": forbidInheritOnly, "ENV": forbidInheritOnly,
	"PERL5OPT": forbidInheritOnly, "NODE_OPTIONS": forbidInheritOnly,
	"PYTHONSTARTUP": forbidInheritOnly, "PYTHONBREAKPOINT": forbidInheritOnly,
	"LESSOPEN": forbidInheritOnly, "PYTHONPATH": forbidInheritOnly,
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
}{
	{"LD_", forbidBoth},
	{"BASH_FUNC_", forbidBoth},
	{"GIT_CONFIG_", forbidBoth},
	// PIP_* and npm_config_* outrank the config FILE those tools read, so
	// inheriting one defeats a pinned config; setting one in a reviewed profile
	// that also grants the path is what "generate, don't bind" asks for.
	{"PIP_", forbidInheritOnly},
	{"npm_config_", forbidInheritOnly},
}

// forbiddenFor reports whether a name is refused for this verb, and why.
func forbiddenFor(name string, verb EnvVerb) (bool, string) {
	if k, ok := forbiddenEnv[name]; ok && appliesTo(k, verb) {
		return true, ""
	}
	for _, p := range forbiddenEnvPrefixes {
		if strings.HasPrefix(name, p.prefix) && appliesTo(p.kind, verb) {
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
	if typeOf(name).list {
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

// checkEnvVerbType refuses a verb the variable's TYPE does not accept. The
// error names the right verb, because "wrong verb" without "use this one"
// leaves the author guessing (§2.1).
func checkEnvVerbType(name string, verb EnvVerb) error {
	t := typeOf(name)
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
	t := typeOf(name)
	if !t.list {
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
// owns it, then whether the verb fits its type.
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
