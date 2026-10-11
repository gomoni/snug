package draft

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gomoni/snug/setup/internal/intent"
)

// Source is where an action came from. Precedence is user > host facts > file
// > default: host facts are not a ledger source because they are enforced
// absolutely, by Apply's refusals and by identity candidates being only what
// the host has.
type Source int

const (
	SourceUser Source = iota
	SourceFile
	SourceDefault
)

// Entry is one action in the intent ledger.
type Entry struct {
	Turn   int
	Source Source
	// Origin is the human's request text for SourceUser, the file NAME for
	// SourceFile. File content never reaches the ledger.
	Origin string
	Action intent.Action
	// Names identify the identity a human picked, for select_identity entries
	// recorded by RecordIdentity: the first is what the ledger prints.
	Names []string
	// Confirmed is true when the human answered a question for this entry: an
	// identity pick, or a file action accepted over a conflicting request.
	Confirmed bool
	// Declined is true for a file or default action the human refused because
	// it contradicted Over. A declined entry was never applied.
	Declined bool
	// Over is the Origin of the user entry this one contradicted.
	Over string
}

// userRank reports whether the entry carries the human's authority.
func (e Entry) userRank() bool { return e.Source == SourceUser || e.Confirmed }

// Pending is a file or default action that contradicts what the human asked
// for. It has not been applied; Decide applies or declines it once the human
// has answered Question.
type Pending struct {
	Entry    Entry
	With     Entry
	Question string
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

// Closure returns name and every built-in it includes, transitively.
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

// Ledger returns the intent ledger, oldest first.
func (d *Draft) Ledger() []Entry { return slices.Clone(d.ledger) }

// HostPath is the absolute host path a spelling in the draft stands for.
func (d *Draft) HostPath(p string) string { return d.expand(p) }

// Propose applies a, unless it comes from a file or a default and contradicts
// what the human asked for: then nothing is applied and the returned Pending
// is the question to put to them. An accepted action is recorded in the
// ledger; a refused one, name_profile, or one that is not the draft's
// (NotMine) is not. select_identity is not applied either: Propose only
// checks it for a conflict, and the caller records the human's pick with
// RecordIdentity.
func (d *Draft) Propose(a intent.Action, src Source, origin string, turn int) (Outcome, *Pending) {
	e := Entry{Turn: turn, Source: src, Origin: origin, Action: a}
	if src != SourceUser {
		if with, ok := d.conflict(e); ok {
			return Outcome{}, &Pending{Entry: e, With: with, Question: d.question(e, with)}
		}
	}
	if a.Op == intent.OpSelectIdentity {
		return Outcome{NotMine: true}, nil
	}
	o := d.Apply(a)
	if o.Refused == "" && !o.NotMine && a.Op != intent.OpNameProfile {
		d.ledger = append(d.ledger, e)
	}
	return o, nil
}

// Decide applies p.Entry when accept is true and records it as confirmed;
// otherwise it records it as declined and changes nothing else. For a
// select_identity entry an accept returns NotMine and records nothing: the
// caller asks which identity, and RecordIdentity records the pick.
func (d *Draft) Decide(p Pending, accept bool) Outcome {
	e := p.Entry
	e.Over = p.With.Origin
	if !accept {
		e.Declined = true
		d.ledger = append(d.ledger, e)
		return Outcome{Msg: "not applied: " + phrase(d, e) + "."}
	}
	if e.Action.Op == intent.OpSelectIdentity {
		return Outcome{NotMine: true}
	}
	o := d.Apply(e.Action)
	if o.Refused == "" && !o.NotMine {
		e.Confirmed = true
		d.ledger = append(d.ledger, e)
	}
	return o
}

// RecordIdentity records an identity the human picked. names[0] is what the
// ledger prints; the rest are other spellings a later request may use for the
// same identity.
func (d *Draft) RecordIdentity(kind string, names []string, origin string, turn int) {
	d.ledger = append(d.ledger, Entry{
		Turn: turn, Source: SourceUser, Origin: origin, Confirmed: true, Names: slices.Clone(names),
		Action: intent.Action{Op: intent.OpSelectIdentity, Kind: kind, Account: names[0]},
	})
}

// Effective returns the applied entries no later applied entry contradicts:
// what the draft should now be the sum of. Declined entries are never in it.
func (d *Draft) Effective() []Entry {
	var out []Entry
	for i, e := range d.ledger {
		if e.Declined {
			continue
		}
		superseded := false
		for _, later := range d.ledger[i+1:] {
			if !later.Declined && d.Contradicts(e, later) {
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

func (d *Draft) conflict(next Entry) (Entry, bool) {
	eff := d.Effective()
	for i := len(eff) - 1; i >= 0; i-- {
		if eff[i].userRank() && d.Contradicts(eff[i], next) {
			return eff[i], true
		}
	}
	return Entry{}, false
}

// pathEffect is what an entry does to one host path: ro, rw, tmpfs, drop or
// stage. ok is false for entries that do not name a path.
func (d *Draft) pathEffect(a intent.Action) (path, effect string, ok bool) {
	switch a.Op {
	case intent.OpGrantPath:
		return d.expand(a.Path), a.Access, true
	case intent.OpDropPath:
		return d.expand(a.Path), "drop", true
	case intent.OpStageBinary:
		return d.expand(a.Host), "stage", true
	case intent.OpUseProfile:
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
//     value;
//   - select_identity of the same kind naming a different identity than a
//     picked one. An empty account names none and contradicts nothing.
func (d *Draft) Contradicts(prior, next Entry) bool {
	ap, an := prior.Action, next.Action
	useDrop := func(use, drop intent.Action) bool {
		return use.Op == intent.OpUseProfile && drop.Op == intent.OpDropProfile && slices.Contains(Closure(use.Name), drop.Name)
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
	if ap.Op == intent.OpSetEnv && an.Op == intent.OpSetEnv && ap.Name == an.Name {
		if (ap.Verb == "set") != (an.Verb == "set") && (ap.Verb == "inherit" || an.Verb == "inherit") {
			return true
		}
		return ap.Verb == "set" && an.Verb == "set" && ap.Value != an.Value
	}
	if ap.Op == intent.OpSelectIdentity && an.Op == intent.OpSelectIdentity && ap.Kind == an.Kind && len(prior.Names) > 0 {
		if len(next.Names) > 0 {
			return next.Names[0] != prior.Names[0]
		}
		return an.Account != "" && !slices.ContainsFunc(prior.Names, func(n string) bool { return strings.EqualFold(n, an.Account) })
	}
	return false
}

// phrase is an entry's action in a few words, for the ledger and questions,
// passed through clean: a declined entry was never checked by Apply, so its
// path or name is whatever the model wrote.
func phrase(d *Draft, e Entry) string { return clean(rawPhrase(d, e)) }

func rawPhrase(d *Draft, e Entry) string {
	a := e.Action
	switch a.Op {
	case intent.OpUseProfile:
		return a.Name
	case intent.OpDropProfile:
		return "drop " + a.Name
	case intent.OpGrantPath:
		return a.Access + " " + d.spell(a.Path)
	case intent.OpDropPath:
		return "drop path " + d.spell(a.Path)
	case intent.OpStageBinary:
		return "stage " + a.Host + " as " + a.Name
	case intent.OpSetEnv:
		return "env " + a.Name + " (" + a.Verb + ")"
	case intent.OpOpenDoor:
		return "door " + a.Name
	case intent.OpSelectIdentity:
		if a.Account == "" {
			return a.Kind + " identity"
		}
		return a.Kind + " identity " + a.Account
	}
	return a.Op
}

func (d *Draft) question(e, with Entry) string {
	verb := "apply it?"
	switch e.Action.Op {
	case intent.OpUseProfile:
		verb = "add it?"
	case intent.OpDropProfile, intent.OpDropPath:
		verb = "drop it?"
	case intent.OpGrantPath:
		verb = "grant it?"
	case intent.OpSelectIdentity:
		verb = "choose one?"
	}
	var what string
	if with.Source == SourceUser {
		what = "you said " + quote(with.Origin)
	} else {
		what = "you accepted " + phrase(d, with) + " from " + Comment(with.Origin)
	}
	return fmt.Sprintf("%s asks for %s, but %s (%s) — %s", sourceLabel(e), phrase(d, e), what, phrase(d, with), verb)
}

func sourceLabel(e Entry) string {
	switch e.Source {
	case SourceUser:
		return "you"
	case SourceDefault:
		return "default"
	}
	return Comment(e.Origin)
}

// commentMax is how many runes of a request the ledger keeps.
const commentMax = 60

// Comment is clean cut to commentMax runes, for request text and file names.
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
// double quote becomes a single one so the quoting in the ledger stays
// unambiguous.
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

func quote(s string) string { return `"` + Comment(s) + `"` }

// IntentLines renders the ledger as TOML comment lines, oldest first.
// Consecutive applied entries of one request share a line.
func (d *Draft) IntentLines() []string {
	var out []string
	for i := 0; i < len(d.ledger); {
		e := d.ledger[i]
		if e.Declined {
			out = append(out, fmt.Sprintf("# intent (%s, declined): %s — conflicts with %s", sourceLabel(e), phrase(d, e), quote(e.Over)))
			i++
			continue
		}
		j := i + 1
		for j < len(d.ledger) {
			n := d.ledger[j]
			if n.Declined || n.Turn != e.Turn || n.Source != e.Source || n.Origin != e.Origin || n.Confirmed != e.Confirmed || n.Over != e.Over {
				break
			}
			j++
		}
		var acts []string
		for _, x := range d.ledger[i:j] {
			acts = append(acts, phrase(d, x))
		}
		label := sourceLabel(e)
		switch {
		case e.Source == SourceUser && e.Confirmed:
			label += ", confirmed"
		case e.Source != SourceUser && e.Over != "":
			label += ", accepted over " + quote(e.Over)
		case e.Source != SourceUser:
			label += ", accepted"
		}
		text := ""
		if e.Source == SourceUser {
			text = quote(e.Origin) + " "
		}
		out = append(out, fmt.Sprintf("# intent (%s): %s-> %s", label, text, strings.Join(acts, ", ")))
		i = j
	}
	return out
}
