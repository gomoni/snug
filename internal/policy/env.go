package policy

import (
	"sort"
	"strings"
)

// The environment is a grant like any other. `--clearenv` throws the host's
// away and every variable the sandbox has is put back by name, so this file is
// the whole of what a payload can read out of /proc/self/environ — its own and
// every child's.
//
// A flat map[string]string could carry the VALUES and nothing else. It could
// not say which verb produced one, which profile, where in a list's ordering an
// entry sits, or what a filter dropped on the way — and every one of those is
// something --dry-run has to show, because a human deciding whether to trust
// the sandbox reads that screen and nothing else.
// See .claude/design/ENVIRONMENT-VARIABLES.md §2.8.

// EnvVerb is who put an entry here and under what rule.
//
// VerbSnug is deliberately first and deliberately not a verb a profile can
// write: it is snug's OWN authorship, the environment's counterpart to
// Mount.Authored. The distinction is the same one the masking rule turns on — a
// profile writing over another profile's value would be subtraction wearing a
// hat, while snug authoring HOME and PATH is replacement, and there is no safe
// absent state for either (§4.2, §4.3).
type EnvVerb uint8

const (
	VerbSnug EnvVerb = iota
	VerbSet
	VerbMerge
	VerbPrepend
	VerbInherit
	VerbSanitise
)

func (v EnvVerb) String() string {
	switch v {
	case VerbSet:
		return "set"
	case VerbMerge:
		return "merge"
	case VerbPrepend:
		return "prepend"
	case VerbInherit:
		return "inherit"
	case VerbSanitise:
		return "sanitise"
	}
	return "(snug)"
}

// EnvEntry is one contribution to one variable: a scalar's whole value, or one
// element of a list.
type EnvEntry struct {
	Value string
	Verb  EnvVerb

	// From is the profiles that contributed this entry, UNIONED AND SORTED.
	//
	// Deliberately unlike Mount.From's treatment in the tests, which excludes
	// provenance from canon() because it is not part of the join. Here it must
	// be part of what the property tests compare: --dry-run prints per-entry
	// provenance as a trust artifact, so if which profile got the credit for an
	// entry depended on fold order, that screen would lie and no existing test
	// would see it. Union is idempotent, so rendering it cannot perturb the
	// fixpoint.
	//
	// Empty for a VerbSnug entry, which has Note instead.
	From []string

	// Note is why snug authored this entry — "base", "podman stub". VerbSnug
	// only; it is what the provenance column shows where a profile name would
	// otherwise go.
	Note string
}

// EnvDropReason is why sanitise dropped one host element, distinct from the
// fact that it did — "1 of 3 kept" was the failure §2.8 already guards
// against; this guards against the reason itself being wrong.
type EnvDropReason uint8

const (
	// The zero value is the pre-existing behaviour, deliberately: an EnvDrop
	// built without a reason reads as the conservative one.
	DropNoGrant EnvDropReason = iota
	DropTmpfsOnly
	// DropPseudoOnly is /proc and /dev. The directory really is populated, so
	// this is not the tmpfs reason wearing another name: what makes the element
	// untruthful is that /proc's magic symlinks resolve OUT of /proc, to
	// whatever the reading process has open — /proc/self/cwd is the target and
	// /proc/self/root/tmp is the writable tmpfs. The filter is lexical and does
	// not follow them.
	DropPseudoOnly
	// DropReplaceable is an element reaching real content through a SYMLINK that
	// stands on writable ground. It is a fourth reason rather than a spelling of
	// the other three because everything they say is false here: the path IS
	// granted, what it lands on IS populated, and it is NOT a tmpfs —
	// `symlink /data/bin -> /usr/bin` with /data a tmpfs resolves to the distro's
	// own bin directory, read-only and full of real commands.
	//
	// What makes it untruthful is the LINK, not the target. bwrap's --symlink
	// writes a link into whatever filesystem the parent is, so alone among the
	// nodes snug emits it is not a mountpoint and can simply be unlinked:
	// measured, the payload runs `rm /data/bin && mkdir /data/bin && echo … >
	// /data/bin/git` and owns the name whatever it used to point at. Keeping the
	// element is snug writing a shadow slot into the PATH it hands over, which is
	// the one thing the staging rule says it must never do.
	DropReplaceable
)

func (r EnvDropReason) String() string {
	switch r {
	case DropTmpfsOnly:
		return "only an empty writable tmpfs is mounted there"
	case DropPseudoOnly:
		return "only a kernel pseudo-filesystem is mounted there, and its magic symlinks leave it"
	case DropReplaceable:
		return "it reaches that content through a symlink the payload can delete and replace, " +
			"because the directory holding the link is writable from inside"
	default:
		return "nothing grants that path"
	}
}

// EnvDrop is a host element a filter removed. Named, not counted: a filter that
// silently removes two of three elements is the exact failure this whole model
// exists to avoid, and "1 of 3 kept" does not let anyone check it (§2.8).
type EnvDrop struct {
	Value  string
	Var    string
	From   []string
	Reason EnvDropReason
}

// EnvVar is one variable and everything that went into it.
type EnvVar struct {
	Name string

	// List reports whether the value is several entries joined by Sep. A scalar
	// has exactly one entry and an empty Sep.
	List bool
	Sep  string

	// Entries is in BAND order, which is structural — nothing a profile writes
	// chooses which band its entry lands in (§2.4).
	Entries []EnvEntry

	Dropped []EnvDrop
}

// Value renders what the sandbox will actually see.
func (v EnvVar) Value() string {
	if !v.List {
		if len(v.Entries) == 0 {
			return ""
		}
		return v.Entries[0].Value
	}
	parts := make([]string, 0, len(v.Entries))
	for _, e := range v.Entries {
		parts = append(parts, e.Value)
	}
	return strings.Join(parts, v.Sep)
}

// Present reports whether the variable reaches the sandbox at all.
//
// A variable with no entries is UNSET, not set-empty, and the difference is
// load-bearing rather than pedantic: an empty element in PATH is the current
// working directory, which inside snug is the target — the one writable thing a
// hostile payload controls (§4.3). So nothing must ever emit a name whose value
// collapsed to nothing.
func (v EnvVar) Present() bool { return len(v.Entries) > 0 }

// SnugOwnedEnv is every variable name snug writes itself. No profile may write
// one, and snug is not bound by the verbs' rules when writing them (§1.1).
//
// It exists as DATA, not as a derivation, because the check that uses it runs at
// parse time and parse time cannot run a resolve. What keeps it honest is
// cmd/snug/ownedenv_test.go: a static pass over every AuthorEnv/AuthorEnvList
// call in the tree, asserting that set equals this one exactly. Do not maintain
// this list by hand-counting the writers — an earlier draft of the design did,
// and missed the six that run AFTER Resolve, which are the dangerous half
// (environ.set DOCKER_HOST = "ssh://..." makes the client exec ssh).
var SnugOwnedEnv = []string{
	"CONTAINER_HOST",
	"DOCKER_BUILDKIT",
	"DOCKER_HOST",
	"GH_CONFIG_DIR",
	"GH_HOST",
	"GIT_CONFIG_GLOBAL",
	"HOME",
	"LANG",
	"LOGNAME",
	"PATH",
	"PS1",
	"SHELL",
	"SNUG",
	"SNUG_PROFILES",
	"SNUG_TARGET",
	"SSH_AUTH_SOCK",
	"TERM",
	"TMPDIR",
	"TZ",
	"USER",
}

// AuthorEnv writes one of snug's OWN scalars, modelled on Policy.Replace and
// for the same reason: it and AuthorEnvList are the only writers of a VerbSnug
// entry, which is what makes the ownership set above derivable from the code
// rather than retyped.
//
// It REPLACES rather than joins. That is not a carve-out sneaked in for
// convenience — snug is explicitly not bound by the verbs' rules for the names
// it owns (§1.1), and a profile cannot reach these names at all.
func (p *Policy) AuthorEnv(name, value string) {
	p.Env[name] = EnvVar{Name: name, Entries: []EnvEntry{{Value: value, Verb: VerbSnug}}}
}

// AuthorEnvList appends a band of entries to a list variable snug authors,
// recording why. Called once per band, in the order the bands appear in the
// rendered value, so PATH's stub directory and its base entries are two calls
// and read as two lines in --dry-run.
//
// The separator is ":" because PATH is the only list snug itself authors and
// that is PATH's separator (§3.3). Where a variable's separator has to be
// looked up rather than known, it comes from the type table, not from here.
func (p *Policy) AuthorEnvList(name string, values []string, note string) {
	v, ok := p.Env[name]
	if !ok {
		v = EnvVar{Name: name}
	}
	v.List, v.Sep = true, ":"
	for _, s := range values {
		v.Entries = append(v.Entries, EnvEntry{Value: s, Verb: VerbSnug, Note: note})
	}
	p.Env[name] = v
}

// addEnvEntry is the single writer behind every profile-authored entry, and it
// is deliberately the ONLY one: two one-line wrappers over it (inheritEnv,
// mergeEnvList) were orphaned when the resolver landed and are gone, because a
// spare writer of environment entries is a place a future caller can add one
// without passing the verb the resolver would have chosen.
//
// An entry that already exists with the same verb and value gains a contributor
// rather than being repeated: the value is the same either way, and a duplicate
// would make the rendered result depend on how many profiles happened to name
// it, which is a fold artifact and not a decision anybody made.
func (p *Policy) addEnvEntry(name string, list bool, sep string, e EnvEntry) {
	v, ok := p.Env[name]
	if !ok {
		v = EnvVar{Name: name, List: list, Sep: sep}
	}
	for i, existing := range v.Entries {
		if existing.Verb == e.Verb && existing.Value == e.Value {
			v.Entries[i].From = union(existing.From, e.From)
			p.Env[name] = v
			return
		}
	}
	v.Entries = append(v.Entries, e)
	p.Env[name] = v
}

// EnvValue returns what the sandbox will see for one name, and whether it is
// set at all. The second return is not decoration: unset and set-empty are
// different states and conflating them is how NO_COLOR= came to mean "colour
// on" (§4.6a).
func (p *Policy) EnvValue(name string) (string, bool) {
	v, ok := p.Env[name]
	if !ok || !v.Present() {
		return "", false
	}
	return v.Value(), true
}

// EnvNames is every name the policy knows about, sorted — including any that
// resolved to nothing. Use EnvPairs to emit.
func (p *Policy) EnvNames() []string {
	out := make([]string, 0, len(p.Env))
	for k := range p.Env {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EnvPairs is the sorted name/value list to hand to bwrap. It SKIPS a variable
// with no entries, because nothing surviving means UNSET (see EnvVar.Present),
// and because after --clearenv there is nothing to unset — snug never emits
// --unsetenv.
func (p *Policy) EnvPairs() [][2]string {
	out := make([][2]string, 0, len(p.Env))
	for _, k := range p.EnvNames() {
		v := p.Env[k]
		if !v.Present() {
			continue
		}
		out = append(out, [2]string{k, v.Value()})
	}
	return out
}

// AuthoredEnvNames is every name snug wrote itself, sorted. It is the runtime
// counterpart of SnugOwnedEnv — see cmd/snug/ownedenv_test.go for why both a
// static and an executed check exist, and why neither alone is enough.
func (p *Policy) AuthoredEnvNames() []string {
	var out []string
	for name, v := range p.Env {
		for _, e := range v.Entries {
			if e.Verb == VerbSnug {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
