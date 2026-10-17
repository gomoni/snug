package draft

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Entry is one action the draft accepted, with what it was computed from.
type Entry struct {
	// Origin is what snug-setup computed the action from, as a row's reason
	// line words it.
	Origin string
	Action Action
}

// BuiltinIncludes is the include list of each built-in, with the @ every
// reference outside base.toml carries. TestBuiltinIncludesMatchBaseToml holds
// it equal to internal/profile/profiles/base.toml.
var BuiltinIncludes = map[string][]string{
	"@sys":           nil,
	"@home":          nil,
	"@target-rw":     {"@home"},
	"@parent-ro":     nil,
	"@git":           nil,
	"@net":           nil,
	"@claude":        {"@sys", "@home"},
	"@podman-socket": {"@sys", "@home"},
	"@podman-build":  {"@podman-socket"},
}

// Closure returns name and every built-in it includes, transitively. A user
// profile is opaque here: what it includes is in a file this package does not
// read, so Closure(name) is just name.
func Closure(name string) []string {
	out := []string{name}
	for i := 0; i < len(out); i++ {
		for _, n := range BuiltinIncludes[out[i]] {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// Ledger returns the actions the draft accepted, oldest first.
func (d *Draft) Ledger() []Entry { return slices.Clone(d.ledger) }

// HostPath is the absolute host path a spelling in the draft stands for.
func (d *Draft) HostPath(p string) string { return d.expand(p) }

// Propose applies a and, when the draft accepts it, records it with origin.
// A refused action, name_profile, and one that is not the draft's (NotMine)
// are applied or reported by Apply as usual and are not recorded.
func (d *Draft) Propose(a Action, origin string) Outcome {
	o := d.Apply(a)
	if o.Refused == "" && !o.NotMine && a.Op != OpNameProfile {
		d.ledger = append(d.ledger, Entry{Origin: origin, Action: a})
	}
	return o
}

// Effective returns the applied entries no later applied entry contradicts:
// what the draft should now be the sum of.
func (d *Draft) Effective() []Entry {
	var out []Entry
	for i, e := range d.ledger {
		superseded := false
		for _, later := range d.ledger[i+1:] {
			if d.Contradicts(e, later) {
				superseded = true
				break
			}
		}
		if !superseded {
			out = append(out, e)
		}
	}
	return out
}

// pathEffect is what an entry does to one host path: ro, rw, tmpfs, drop or
// stage. ok is false for entries that do not name a path.
func (d *Draft) pathEffect(a Action) (path, effect string, ok bool) {
	switch a.Op {
	case OpGrantPath:
		return d.expand(a.Path), a.Access, true
	case OpDropPath:
		return d.expand(a.Path), "drop", true
	case OpStageBinary:
		return d.expand(a.Host), "stage", true
	case OpUseProfile:
		if a.Name == "@target-rw" {
			return filepath.Clean(d.Host.Target), "rw", true
		}
	}
	return "", "", false
}

// Contradicts reports whether next has the opposite effect of prior on the
// same thing:
//
//   - use_profile X against drop_profile Y, in either order, when Y is X or a
//     built-in X includes;
//   - on the same host path, a grant or staged binary against drop_path;
//     an rw grant after a ro one (widening; narrowing is not a contradiction,
//     because a ro grant after an rw one changes nothing); a tmpfs against a
//     ro or rw grant, in either order. use_profile @target-rw is an rw grant
//     of the target here, so it contradicts a read-only target;
//   - set_env of the same name, set against inherit, or set to a different
//     value.
func (d *Draft) Contradicts(prior, next Entry) bool {
	ap, an := prior.Action, next.Action
	useDrop := func(use, drop Action) bool {
		return use.Op == OpUseProfile && drop.Op == OpDropProfile && slices.Contains(Closure(use.Name), drop.Name)
	}
	if useDrop(ap, an) || useDrop(an, ap) {
		return true
	}
	if pp, ep, ok := d.pathEffect(ap); ok {
		if pn, en, ok := d.pathEffect(an); ok && pp == pn {
			switch {
			case ep == "drop" || en == "drop":
				return ep != en
			case ep == "stage" || en == "stage":
				return false
			case ep == "ro" && en == "rw":
				return true
			case (ep == "tmpfs") != (en == "tmpfs"):
				return true
			}
			return false
		}
	}
	if ap.Op == OpSetEnv && an.Op == OpSetEnv && ap.Name == an.Name {
		if (ap.Verb == "set") != (an.Verb == "set") && (ap.Verb == "inherit" || an.Verb == "inherit") {
			return true
		}
		return ap.Verb == "set" && an.Verb == "set" && ap.Value != an.Value
	}
	return false
}

// commentMax is how many runes of a comment Comment keeps.
const commentMax = 60

// Comment is clean cut to commentMax runes, for descriptions and origins.
func Comment(s string) string {
	s = clean(s)
	if utf8.RuneCountInString(s) > commentMax {
		s = string([]rune(s)[:commentMax-3]) + "..."
	}
	return s
}

// clean makes s safe inside a TOML comment and on a terminal: invalid UTF-8,
// every control character (a newline would end the comment and start TOML),
// every Unicode format character (Cf: the bidi runes that render as text they
// do not contain, zero-width characters, U+FEFF, tag characters) and the line
// and paragraph separators become a space, runs of spaces collapse, and a
// double quote becomes a single one.
func clean(s string) string {
	s = strings.ToValidUTF8(s, " ")
	s = strings.Map(func(c rune) rune {
		switch {
		case c == '"':
			return '\''
		case unicode.IsControl(c), unicode.Is(unicode.Cf, c), c == 0x2028, c == 0x2029:
			return ' '
		}
		return c
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
