package session

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/compose"
	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/texts"
)

// Class is what applying an action needs from the human.
type Class int

const (
	// ClassInfo changes nothing: note, ask, refuse, show, list_identities,
	// save. save runs after the rest of the turn.
	ClassInfo Class = iota
	// ClassEdit cannot widen the sandbox or add a value, so it applies without
	// a question.
	// It includes a widening op that would change nothing or that the draft
	// refuses.
	ClassEdit
	// ClassGrant widens the sandbox or adds a value the model chose. It goes on
	// the turn's card.
	ClassGrant
	// ClassIdentity is select_identity: an identity question, never a card.
	ClassIdentity
	// ClassFile is read_file.
	ClassFile
)

// Item is one action of a turn, with what it would do in Go's words.
type Item struct {
	Action   intent.Action
	Class    Class
	Sentence string
	// Abuse is the ABUSE sentence of what a ClassGrant adds, "" when there is
	// none to quote.
	Abuse string
	// Ticked is whether a card starts with the item ticked: true only for a
	// ClassGrant the human's own request produced.
	Ticked bool
	// Already is the number of the open card that holds this same action, 0
	// when none does. Such an item is ClassInfo: a second card for it would
	// leave Save two blockers for one decision.
	Already int
}

// Turn is one request the model understood, classified and not yet applied.
type Turn struct {
	N     int
	Said  string
	Items []Item
}

// HasCard reports whether the turn widens the sandbox and so needs a card.
func (t *Turn) HasCard() bool {
	return slices.ContainsFunc(t.Items, func(it Item) bool { return it.Class == ClassGrant })
}

func (t *Turn) actions() []intent.Action {
	out := make([]intent.Action, len(t.Items))
	for i, it := range t.Items {
		out[i] = it.Action
	}
	return out
}

// widening are the ops that go on a card when they change the draft: the ones
// that make the sandbox see or do more, and the ones that put a value the
// model chose into every later run (set_env of any verb, a tmpfs). A drop or
// a name narrows or labels, so it applies at once.
func widening(a intent.Action) bool {
	switch a.Op {
	case intent.OpUseProfile, intent.OpStageBinary, intent.OpOpenDoor, intent.OpSetEnv:
		return true
	case intent.OpGrantPath:
		return a.Access == "ro" || a.Access == "rw" || a.Access == "tmpfs"
	}
	return false
}

// Submit sends text to the model and returns the understood turn, applying
// nothing. It returns a nil Turn, with lines saying why, when the model could
// not be reached or its reply was not a valid action list twice.
func (s *Session) Submit(ctx context.Context, text string) (*Turn, []Line) {
	text = strings.TrimSpace(text)
	acts, lines := s.ask(ctx, text)
	if acts == nil {
		return nil, lines
	}
	s.turn++
	return s.classify(s.turn, text, acts), lines
}

// classify decides each action's class against a clone of the draft with the
// turn's earlier actions applied, so "already in the draft" is judged where
// the action would land.
func (s *Session) classify(n int, said string, acts []intent.Action) *Turn {
	t := &Turn{N: n, Said: said}
	trial := s.d.Clone()
	for _, a := range acts {
		it := Item{Action: a, Sentence: Sentence(trial, a)}
		switch a.Op {
		case intent.OpNote, intent.OpAsk, intent.OpRefuse, intent.OpShow, intent.OpSave, intent.OpListIdentities:
			it.Class = ClassInfo
		case intent.OpSelectIdentity:
			it.Class = ClassIdentity
		case intent.OpReadFile:
			it.Class = ClassFile
		default:
			o := trial.Apply(a)
			it.Class = ClassEdit
			if widening(a) && o.Changed {
				it.Class, it.Ticked, it.Abuse = ClassGrant, true, abuseOf(a)
				if n := s.heldBy(a); n > 0 {
					it.Class, it.Ticked, it.Abuse, it.Already = ClassInfo, false, "", n
				}
			}
		}
		t.Items = append(t.Items, it)
	}
	return t
}

// heldBy returns the number of the open card that lists a among the actions it
// will apply, 0 when no card does.
func (s *Session) heldBy(a intent.Action) int {
	for _, p := range s.pending {
		if p.Kind != Card {
			continue
		}
		for _, i := range p.held {
			if p.turn.Items[i].Action == a {
				return p.N
			}
		}
	}
	return 0
}

func abuseOf(a intent.Action) string {
	switch a.Op {
	case intent.OpUseProfile:
		return draft.Abuse[a.Name]
	case intent.OpOpenDoor:
		return draft.Abuse["listen_names"]
	}
	return ""
}

// Defer applies a turn the way --plain does: everything but its card at once,
// and the card, when there is one, as a pending question that /accept
// applies. Edits are held on the card with the grants, so the turn applies in
// the order it was said and stays one undo step.
func (s *Session) Defer(ctx context.Context, t *Turn) []Line {
	return s.applyTurn(ctx, t, nil, true)
}

// Apply applies a turn whose card the human has answered: the ClassGrant
// items at the indices in ticked, and every other item. An unticked grant
// leaves no trace in the draft or the ledger.
func (s *Session) Apply(ctx context.Context, t *Turn, ticked []int) []Line {
	return s.applyTurn(ctx, t, ticked, false)
}

func (s *Session) applyTurn(ctx context.Context, t *Turn, ticked []int, deferCard bool) []Line {
	before := s.snapshot()
	card := deferCard && t.HasCard()
	acts := t.actions()
	var out []Line
	var held []int
	save := false
	for i, it := range t.Items {
		a := it.Action
		switch it.Class {
		case ClassInfo:
			if it.Already > 0 {
				out = append(out, info("%s is already proposed as #%d: /accept %d applies it.", it.Sentence, it.Already, it.Already))
				continue
			}
			if a.Op == intent.OpSave {
				save = true
				continue
			}
			out = append(out, s.infoAction(t, acts, a)...)
		case ClassIdentity:
			out = append(out, s.askIdentity(a.Kind, a.Account, t.Said, t.N)...)
		case ClassFile:
			out = append(out, s.readFile(a.Path)...)
		case ClassGrant:
			if card {
				held = append(held, i)
			} else if slices.Contains(ticked, i) {
				out = append(out, s.proposeUser(t, acts, a)...)
			} else {
				out = append(out, info("not applied (unticked): %s.", it.Sentence))
			}
		case ClassEdit:
			if card {
				held = append(held, i)
			} else {
				out = append(out, s.proposeUser(t, acts, a)...)
			}
		}
	}
	if card {
		p := s.open(Pending{Kind: Card, turn: t, held: held, said: t.Said, at: t.N})
		out = append(out, p.Line())
	}
	s.commit(before, "your request "+quote(t.Said))
	if save {
		_, l := s.Save(ctx, "")
		out = append(out, l...)
	}
	return out
}

func (s *Session) infoAction(t *Turn, acts []intent.Action, a intent.Action) []Line {
	switch a.Op {
	case intent.OpRefuse:
		return modelRefusal(a.Code)
	case intent.OpNote:
		var out []Line
		if e, ok := texts.Note(a.Topic); ok {
			out = append(out, info("%s", e))
		}
		if a.Topic == "net" && offlineWish(t.Said, acts) && !slices.Contains(s.d.Include, "@net") {
			s.d.Propose(intent.Action{Op: intent.OpDropProfile, Name: "@net"}, draft.SourceUser, t.Said, t.N)
		}
		return out
	case intent.OpAsk:
		return []Line{{Question, "the model asks: \"" + safe.Inline(a.Question) + "\"\n  Nothing changed. Answer with a request of its own, for example \"I need internet\" or \"use my github\"; each request stands alone."}}
	case intent.OpShow:
		return s.Show()
	case intent.OpListIdentities:
		return s.ListIdentities(a.Kind)
	}
	return nil
}

// offlineWish reports whether the human asked for the sandbox to be offline,
// on a turn the model answered with `note net` and no profile action on @net.
// The model has no op for "keep it as it is", so without this the wish leaves
// no ledger entry for a file to contradict. The request has to say it:
// `note net` is also the model's answer to "with internet", and reading that
// as a wish to be offline records the opposite of what was asked.
func offlineWish(said string, acts []intent.Action) bool {
	if slices.ContainsFunc(acts, func(a intent.Action) bool {
		return (a.Op == intent.OpUseProfile || a.Op == intent.OpDropProfile) && a.Name == "@net"
	}) {
		return false
	}
	w := " " + strings.ToLower(said) + " "
	for _, no := range []string{" offline ", " off-line ", " no net ", " no network ", " no internet ", " without net ", " without network ", " without internet ", " without the internet ", " without the network ", " no outside access ", " air-gapped ", " airgapped ", " bez internetu ", " bez sítě ", " bez site "} {
		if strings.Contains(w, no) {
			return true
		}
	}
	return false
}

// proposeUser applies one of the human's own actions and says what happened.
// The defaults note is said once per turn: by the model's note when it gave
// one, otherwise here.
func (s *Session) proposeUser(t *Turn, acts []intent.Action, a intent.Action) []Line {
	o, _ := s.d.Propose(a, draft.SourceUser, t.Said, t.N)
	switch {
	case o.Refused != "":
		return refusal(o.Refused, o.Msg)
	case o.Msg != "":
		return []Line{info("%s", safe.Inline(o.Msg))}
	case o.Default && !slices.ContainsFunc(acts, func(x intent.Action) bool { return x.Op == intent.OpNote && x.Topic == "defaults" }):
		e, _ := texts.Note("defaults")
		return []Line{info("%s", e)}
	}
	return nil
}

// readFile answers read_file. Only a compose file is read: every other file in
// the project says what the project wants, and is not followed up.
func (s *Session) readFile(name string) []Line {
	shown := safe.Inline(name)
	if !compose.IsComposeName(path.Base(name)) {
		return []Line{info("snug-setup does not suggest grants from %s. A file in the project says what the project wants, not what you want, "+
			"and the model reads free text wrongly far more often than rightly. Read it yourself and say what you need, for example \"I need internet\".", shown)}
	}
	digest, err := compose.ReadTarget(s.cfg.Host.Target, name)
	if err != nil {
		return []Line{info("not read: %s", safe.Inline(err.Error()))}
	}
	n := 0
	for _, l := range strings.Split(digest, "\n") {
		if strings.HasPrefix(l, "service ") {
			n++
		}
	}
	return []Line{info("read %s: %d service(s). snug-setup does not derive grants from a compose file yet; "+
		"say what you need, for example \"I need podman and internet\".", shown, n)}
}

func quote(s string) string { return "\"" + draft.Comment(s) + "\"" }
