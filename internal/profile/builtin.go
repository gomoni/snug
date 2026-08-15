package profile

import (
	"embed"
	"fmt"
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
		if err := reg.merge(mark(layer)); err != nil {
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
func mark(layer Registry) Registry {
	out := make(Registry, len(layer))
	for name, p := range layer {
		q := *p
		q.Name = name.Marked()
		q.Include = nil
		for _, inc := range p.Include {
			q.Include = append(q.Include, inc.Marked())
		}
		out[q.Name] = &q
	}
	return out
}
