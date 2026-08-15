package profile

import (
	"embed"
	"fmt"
	"strings"
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
// IT IS ALSO WHERE `environ.declare` IS REFUSED FOR A BUILTIN, and it is here
// rather than in a test for the reason the sigil rule itself is here: this
// function is the one door a profile passes through to become snug's, so
// "@ means snug ships it" and "a profile snug ships writes no unrostered name"
// are established by the same construction. A declaration says "snug's roster
// has nothing to say about this name, and the profile's author takes
// responsibility" — a sentence a human writes about their own file, and one
// nobody is left to say for a profile compiled into the binary. Refusing it
// here means a builtin cannot acquire the hatch by an edit to base.toml, only
// by an edit to this function, and it fails at Builtins() — so every command
// and every test stops, rather than one sweep going red.
func mark(layer Registry) (Registry, error) {
	out := make(Registry, len(layer))
	for name, p := range layer {
		if len(p.Environ.Declare) > 0 {
			return nil, fmt.Errorf("profile %q declares %s, and a profile snug SHIPS may not "+
				"declare anything: `environ.declare` is the escape hatch for a name snug's "+
				"roster has no entry for, and it works by naming a human who takes "+
				"responsibility for it. There is no such human here. Add the name to "+
				"internal/policy/envtypes.go with the sentence saying what the verb lets the "+
				"tool DO — a row there is a grant, and that is the review this profile owes",
				name, strings.Join(p.Environ.Declare, ", "))
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
