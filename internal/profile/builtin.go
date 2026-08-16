package profile

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

//go:embed profiles/*.toml
var embedded embed.FS

// Builtins is the registry snug ships, with no host layers merged in: the
// embedded profiles/*.toml, marked into the @-namespace.
//
// Exported because it is the only registry that is a pure function of the
// binary — no $XDG_CONFIG_HOME, no /etc/snug — which makes it the one a golden
// test may resolve against. Load() reads host directories, so a golden built
// from it would describe a different sandbox on every developer's machine.
func Builtins() (Registry, error) {
	reg := Registry{}
	entries, err := embedded.ReadDir("profiles")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		path := "profiles/" + e.Name()
		data, err := embedded.ReadFile(path)
		if err != nil {
			return nil, err
		}
		layer, err := parse(data, "builtin:"+e.Name(), true)
		if err != nil {
			return nil, fmt.Errorf("builtin profile %s: %w", e.Name(), err)
		}
		marked, err := mark(layer)
		if err != nil {
			return nil, fmt.Errorf("builtin profile %s: %w", e.Name(), err)
		}
		if err := reg.merge(marked); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// mark moves a builtin layer into the @-namespace (see policy.Sigil).
//
// This is the ONLY place a sigil is ever added, which is what makes "@ means
// snug shipped it" true by construction: the TOML says [profile.sys], checkName
// refuses a leading @ in any file, and a builtin therefore cannot be published
// under a bare name or a user profile under a marked one.
//
// Includes are rewritten too, and unconditionally, because inside a builtin an
// include can only mean another builtin: base.toml is compiled in, so it cannot
// know a name from ~/.config, and the layers that could supply one are merged
// afterwards. A builtin reaching for a user profile is not a thing to preserve.
//
// IT IS ALSO WHERE THE ROSTER IS AN ALLOWLIST FOR A PROFILE SNUG SHIPS, and it
// is here rather than in a test for the reason the sigil rule itself is here:
// this function is the one door a profile passes through to become snug's, so
// "@ means snug ships it" and "a profile snug ships writes no name snug has no
// entry for" are established by the same construction. A builtin cannot acquire
// the exemption by an edit to base.toml, only by an edit to this function, and
// it fails at Builtins() — so every command and every test stops, rather than
// one sweep going red.
//
// THE RULE IS WRITTEN WITH THE PREDICATE THAT DRAWS THE SCREEN'S MARK,
// policy.IsUncheckedEnv, and that is the whole point of the shape. A profile a
// human wrote may write a name snug has no entry for; it is carried, and every
// row it produces renders `← unchecked` in --dry-run and in `snug profile show`.
// A profile snug SHIPS may not, and the sentence saying so is *a profile snug
// ships may not hand over a name the screen would mark unchecked* — one
// predicate with two consumers, rather than a roster-membership function beside
// the mark for the two to drift apart on. That drift is not hypothetical here:
// policy.typeOf folds case for names under a case-folding prefix, so an
// independent membership test written as an exact-string lookup would call
// `npm_config_userconfig` unrostered while the screen called it known.
func mark(layer Registry) (Registry, error) {
	out := make(Registry, len(layer))
	for name, p := range layer {
		if err := checkBuiltinEnvRoster(name, p.Environ); err != nil {
			return nil, err
		}
		q := *p
		q.Name = name.Marked()
		q.Include = nil
		for _, inc := range p.Include {
			q.Include = append(q.Include, inc.Marked())
		}
		out[q.Name] = &q
	}
	return out, nil
}

// checkBuiltinEnvRoster refuses a builtin that writes a name snug's roster has
// no entry for, at any verb.
//
// EVERY VERB IS ENUMERATED HERE, deliberately and by hand, because the thing
// that would defeat this rule is a sixth verb added to policy.EnvGrants and not
// added to this switch — the shape CLAUDE.md keeps recording as "a rule written
// once and applied to one of its two halves". The three list verbs are already
// refused for everybody at parse time (a list verb needs the separator and the
// empty-element kind, which only a roster row carries), so their arms here can
// never fire today; they are present so that this function's answer does not
// depend on that remaining true somewhere else.
//
// The message names the fix and names it as a POLICY change, not a lookup-table
// edit: a roster row is a grant, and it owes the sentence saying what the verb
// lets the tool DO.
func checkBuiltinEnvRoster(name policy.ProfileName, g policy.EnvGrants) error {
	var unchecked []string
	note := func(n string, verb policy.EnvVerb) {
		if policy.IsUncheckedEnv(n, verb) {
			unchecked = append(unchecked, fmt.Sprintf("%s (environ.%s)", n, verb))
		}
	}
	for n := range g.Set {
		note(n, policy.VerbSet)
	}
	for n := range g.Merge {
		note(n, policy.VerbMerge)
	}
	for n := range g.Prepend {
		note(n, policy.VerbPrepend)
	}
	for _, n := range g.Inherit {
		note(n, policy.VerbInherit)
	}
	for _, n := range g.Sanitise {
		note(n, policy.VerbSanitise)
	}
	if len(unchecked) == 0 {
		return nil
	}
	sort.Strings(unchecked)
	return fmt.Errorf("profile %q hands over %s, which snug's roster has no entry for.\n"+
		"       A profile snug SHIPS may not hand over a name the screen would mark\n"+
		"       `← unchecked`: that mark says a human took responsibility for a name snug\n"+
		"       knows nothing about, and there is no such human for a profile compiled into\n"+
		"       the binary. Add a row to internal/policy/envtypes.go, with the sentence\n"+
		"       saying what the verb lets the tool DO — a row there is a grant, and that is\n"+
		"       the review this profile owes",
		name, strings.Join(unchecked, ", "))
}
