package session

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
)

// PendingKind is what a pending question decides.
type PendingKind int

const (
	// Card is a turn that widens the sandbox: accept applies every action
	// it lists, decline none.
	Card PendingKind = iota
	// Conflict is a file's action that contradicts what the human said
	// (draft.Pending): accept takes the file's, decline keeps the human's
	// and records the decline in the ledger.
	Conflict
	// Identity asks which identity of a kind to pin. It is answered by Pick,
	// never by Accept.
	Identity
	// SecondProfile asks whether to save this profile and start a second one
	// for another identity of a kind the draft already pins.
	SecondProfile
	// Overwrite asks whether the checked draft replaces a different file of
	// the same name.
	Overwrite
	// Choice offers the readings of a request that was not understood. A
	// number picks one and submits it as a request of its own; nothing is
	// applied until then.
	Choice
)

// Pending is an open question. N is its number for the session: numbers are
// never reused, so an answer typed for one question cannot land on another.
type Pending struct {
	N        int
	Kind     PendingKind
	Question string
	// Options are the card's actions, the candidates, or the diff lines.
	Options []string
	// Answer is the line that answers the question in --plain.
	Answer string

	turn *Turn
	held []int
	conf draft.Pending
	// kind and hint are an identity's kind and the model's account word.
	kind, hint string
	// said and at are the request and turn the question came from, for the
	// ledger entry an answer records.
	said string
	at   int
	// path and body are an overwrite's file and the checked draft.
	path, body string
	// unclear is what a Choice offers.
	unclear *intent.Unclear
	// shown are the keys of an identity question's numbered candidates.
	shown []string
}

// Line renders the question with its options and the line that answers it.
func (p Pending) Line() Line {
	var b strings.Builder
	fmt.Fprintf(&b, "? #%d %s", p.N, p.Question)
	for _, o := range p.Options {
		b.WriteString("\n    " + o)
	}
	b.WriteString("\n  answer: " + p.Answer)
	return Line{Question, b.String()}
}

// Pending returns the open questions, oldest first.
func (s *Session) Pending() []Pending { return slices.Clone(s.pending) }

// open numbers p, fills in its question and answer, and adds it.
func (s *Session) open(p Pending) Pending {
	s.lastN++
	p.N = s.lastN
	switch p.Kind {
	case Card:
		p.Question = "your request " + quote(p.turn.Said) + " widens the sandbox; nothing from it is applied yet:"
		if p.turn.Ingest {
			p.Question = "what I found in the project would widen the sandbox like this; nothing from it is applied yet:"
		}
		for j, i := range p.held {
			it := p.turn.Items[i]
			o := fmt.Sprintf("%d. %s", j+1, it.Sentence)
			if it.Why != "" {
				o += "  (from " + safe.Inline(it.Why) + ")"
			}
			if it.Abuse != "" {
				o += "\n      cost: " + it.Abuse
			}
			p.Options = append(p.Options, o)
		}
		p.Answer = fmt.Sprintf("/accept %d applies all of it, /decline %d none of it", p.N, p.N)
		if len(p.held) > 1 {
			p.Answer += "; or say which to keep (\"only 1 and 3\")"
		}
	case Conflict:
		p.Question = p.conf.Question
		p.Answer = fmt.Sprintf("/accept %d takes it, /decline %d keeps what you said", p.N, p.N)
	case Identity:
		p.Question = "which " + kindName(p.kind) + " should the sandbox act as?"
		if p.kind == "signing" {
			p.Question = "which ssh key should sign commits inside the sandbox?"
		}
		cands := s.Candidates(p.kind)
		if p.hint != "" {
			if bestMatch(p.hint, cands) < 0 {
				p.Question += " (nothing on this host matches \"" + safe.Inline(p.hint) + "\")"
			} else {
				p.Question += " (you said \"" + safe.Inline(p.hint) + "\")"
			}
		}
		shown, more := s.shortlist(p.kind, p.hint, cands)
		for j, c := range shown {
			p.Options = append(p.Options, fmt.Sprintf("%d. %s", j+1, c.Label))
			p.shown = append(p.shown, c.Key)
		}
		if more > 0 {
			p.Options = append(p.Options, fmt.Sprintf("... and %d more: /keys lists all %d", more, len(cands)))
		}
		p.Answer = fmt.Sprintf("/pick %s %s, or /pick %s none", p.kind, keyWord[p.kind], p.kind)
		if len(cands) > 0 && cands[0].Why != "" {
			p.Answer = fmt.Sprintf("/pick %s %s takes the suggestion, /pick %s %s another, /pick %s none", p.kind, safe.Inline(cands[0].Key), p.kind, keyWord[p.kind], p.kind)
		}
	case SecondProfile:
		cur, _ := s.slotFull(p.kind)
		p.Question = fmt.Sprintf("the draft already pins the %s %q, and a profile pins one: \"%s\" needs a second profile. Save this one and start a second?",
			kindName(p.kind), safe.Inline(cur), safe.Inline(p.hint))
		p.Answer = fmt.Sprintf("/accept %d saves this profile and starts an empty one, where the %s question opens; /decline %d keeps this one", p.N, p.kind, p.N)
	case Overwrite:
		p.Question = p.path + " exists and differs from the draft; overwrite it?"
		p.Answer = fmt.Sprintf("/accept %d writes it, /decline %d keeps the file", p.N, p.N)
	case Choice:
		u := p.unclear
		if len(u.Understood) > 0 {
			p.Question = "I understood " + s.sentences(u.Understood) + ", but not \"" + safe.Inline(u.Unknown) + "\". Nothing changed. Did you mean:"
		} else {
			p.Question = "I did not understand \"" + safe.Inline(u.Unknown) + "\"; nothing changed. Did you mean:"
		}
		for j, c := range u.Choices {
			o := s.sentences(c.Actions)
			if j == 0 && len(u.Understood) > 0 {
				o = "only " + o
			}
			p.Options = append(p.Options, fmt.Sprintf("%d. %s", j+1, o))
		}
		p.Answer = "the number of the reading you meant, or say it differently"
	}
	s.pending = append(s.pending, p)
	return p
}

var keyWord = map[string]string{"ssh": "STEM", "signing": "STEM", "github": "LOGIN", "git": "EMAIL"}

func kindName(kind string) string {
	switch kind {
	case "ssh":
		return "ssh key"
	case "github":
		return "GitHub login"
	case "signing":
		return "signing key"
	}
	return "git author"
}

func (s *Session) find(n int) (Pending, bool) {
	i := slices.IndexFunc(s.pending, func(p Pending) bool { return p.N == n })
	if i < 0 {
		return Pending{}, false
	}
	return s.pending[i], true
}

func (s *Session) close(n int) {
	s.pending = slices.DeleteFunc(s.pending, func(p Pending) bool { return p.N == n })
}

func notOpen(n int) []Line {
	return []Line{info("there is no open question #%d; /pending lists them.", n)}
}

// Accept answers question n with yes. An identity question is refused here:
// it is answered by Pick, which names the identity.
func (s *Session) Accept(ctx context.Context, n int) []Line {
	p, ok := s.find(n)
	if !ok {
		return notOpen(n)
	}
	before := s.snapshot()
	var out []Line
	switch p.Kind {
	case Identity:
		return []Line{info("#%d is answered by naming the identity: %s.", n, p.Answer)}
	case Choice:
		return []Line{info("#%d is answered with the number of a reading.", n)}
	case Overwrite:
		return s.acceptOverwrite(ctx, p)
	case SecondProfile:
		return s.acceptSecond(ctx, p)
	case Card:
		s.close(n)
		acts := p.turn.actions()
		pinned := false
		for _, i := range p.held {
			out = append(out, s.proposeUser(p.turn, acts, p.turn.Items[i])...)
			pinned = pinned || p.turn.Items[i].Pin
		}
		if pinned {
			out = append(out, s.checkIdentity(ctx)...)
		}
	case Conflict:
		s.close(n)
		o := s.d.Decide(p.conf, true)
		if o.NotMine {
			a := p.conf.Entry.Action
			out = append(out, s.askIdentity(a.Kind, a.Account, p.said, p.at)...)
		} else {
			out = append(out, outcome(o)...)
		}
	}
	s.commit(before, fmt.Sprintf("the answer to #%d", n))
	return out
}

// Decline answers question n with no: nothing from it is applied.
func (s *Session) Decline(n int) []Line {
	p, ok := s.find(n)
	if !ok {
		return notOpen(n)
	}
	before := s.snapshot()
	s.close(n)
	var out []Line
	switch p.Kind {
	case Card:
		if p.turn.Ingest {
			out = append(out, info("not applied: what I found in the project. Nothing from it is in the draft; /analyze offers it again."))
			break
		}
		out = append(out, info("not applied: your request %s. Nothing from it is in the draft.", quote(p.turn.Said)))
	case Conflict:
		out = append(out, outcome(s.d.Decide(p.conf, false))...)
	case Identity:
		out = append(out, info("no %s pinned.", kindName(p.kind)))
	case SecondProfile:
		out = append(out, info("nothing written; this profile keeps its %s.", kindName(p.kind)))
	case Overwrite:
		return []Line{info("not saved; %s is unchanged.", p.path)}
	case Choice:
		out = append(out, info("nothing changed."))
	}
	s.commit(before, fmt.Sprintf("the answer to #%d", n))
	return out
}

func outcome(o draft.Outcome) []Line {
	switch {
	case o.Refused != "":
		return refusal(o.Refused, o.Msg)
	case o.Msg != "":
		return []Line{info("%s", safe.Inline(o.Msg))}
	}
	return nil
}

// blocking are the questions a save waits for. A second-profile question does
// not block: it is about what happens after a save, not about the draft; nor
// does a choice, which is about a request that changed nothing.
func (s *Session) blocking() []Pending {
	return slices.DeleteFunc(slices.Clone(s.pending), func(p Pending) bool { return p.Kind == SecondProfile || p.Kind == Choice })
}

// AcceptSome answers card n with the items at the 1-based positions keep,
// as the card numbers them; the rest are not applied. It refuses a position
// the card does not have, changing nothing.
func (s *Session) AcceptSome(ctx context.Context, n int, keep []int) []Line {
	p, ok := s.find(n)
	if !ok {
		return notOpen(n)
	}
	if p.Kind != Card {
		return []Line{info("#%d is not a list to pick from: %s.", n, p.Answer)}
	}
	for _, k := range keep {
		if k < 1 || k > len(p.held) {
			return []Line{info("#%d has items 1 to %d; nothing changed.", n, len(p.held))}
		}
	}
	before := s.snapshot()
	s.close(n)
	acts := p.turn.actions()
	var out []Line
	pinned := false
	for j, i := range p.held {
		it := p.turn.Items[i]
		if slices.Contains(keep, j+1) {
			out = append(out, s.proposeUser(p.turn, acts, it)...)
			pinned = pinned || it.Pin
		} else {
			out = append(out, info("not applied: %s.", it.Sentence))
		}
	}
	if pinned {
		out = append(out, s.checkIdentity(ctx)...)
	}
	s.commit(before, fmt.Sprintf("the answer to #%d", n))
	return out
}

// sentences says what acts would do, notes left out.
func (s *Session) sentences(acts []intent.Action) string {
	var out []string
	for _, a := range acts {
		if a.Op != intent.OpNote {
			out = append(out, Sentence(s.d, a))
		}
	}
	return strings.Join(out, "; ")
}

// dropChoices closes the open choices: they were about the request before
// the one being read now.
func (s *Session) dropChoices() {
	s.pending = slices.DeleteFunc(s.pending, func(p Pending) bool { return p.Kind == Choice })
}
