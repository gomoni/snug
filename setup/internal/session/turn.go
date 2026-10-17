package session

import (
	"context"
	"errors"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/compose"
	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
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
	// Msg is what an item that cannot be applied says instead of doing it.
	Msg string
	// Why is what an ingest proposal was computed from (".git", "go.mod"),
	// "" for an action the human asked for. A non-empty Why records the
	// action as SourceIngest.
	Why string
	// Pin is true for an identity the opening card names exactly: accepting
	// the card pins Action.Account, a candidate Key of Action.Kind, with no
	// further question.
	Pin bool
}

// Turn is one request the interpreter understood, classified and not yet
// applied.
type Turn struct {
	N     int
	Said  string
	Items []Item
	// Ingest is true for the proposal snug-setup computed itself: its card
	// speaks for the project, not for a request.
	Ingest bool
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
	case intent.OpUseProfile, intent.OpIncludeProfile, intent.OpStageBinary, intent.OpOpenDoor, intent.OpSetEnv:
		return true
	case intent.OpGrantPath:
		return a.Access == "ro" || a.Access == "rw" || a.Access == "tmpfs"
	}
	return false
}

// Submit reads text through the interpreter and returns the understood turn,
// applying nothing. It returns a nil Turn, with lines saying why, when the
// interpreter did not understand text or failed.
func (s *Session) Submit(ctx context.Context, text string) (*Turn, []Line) {
	text = strings.TrimSpace(text)
	if a, ok := parseAnswer(text); ok {
		return s.answer(ctx, a)
	}
	s.dropChoices()
	acts, err := s.cfg.Interpreter.Interpret(ctx, s.context(), text)
	if err != nil {
		var u *intent.Unclear
		if errors.As(err, &u) {
			if t, lines, ok := s.answerTypo(ctx, text); ok {
				return t, lines
			}
		}
		return nil, s.notUnderstood(text, err)
	}
	return s.understood(ctx, text, acts)
}

// understood runs the session's own ops among acts at once (analysis, advice,
// undo) and returns the rest as a turn, nil when nothing is left.
func (s *Session) understood(ctx context.Context, said string, acts []intent.Action) (*Turn, []Line) {
	var out []Line
	var rest []intent.Action
	if slices.ContainsFunc(acts, func(a intent.Action) bool { return a.Op == intent.OpUndo }) &&
		slices.ContainsFunc(acts, func(a intent.Action) bool { return a.Op != intent.OpUndo && a.Op != intent.OpNote }) {
		// "read ~/.ssh, no wait, never mind": the line takes itself back.
		// Undoing the step before it as well would reach a decision the human
		// made earlier, so neither half runs.
		return nil, []Line{info("that line both asks for something and takes something back (%s), so nothing from it is applied and nothing earlier was undone. Say each on a line of its own.", quote(said))}
	}
	for _, a := range acts {
		switch a.Op {
		case intent.OpAnalyze:
			out = append(out, s.Analyze(ctx)...)
		case intent.OpAdvise:
			out = append(out, s.Advice(ctx)...)
		case intent.OpUndo:
			out = append(out, s.undoRequest()...)
		case intent.OpToolchain:
			acts, lines := s.toolchain(a.Name)
			rest = append(rest, acts...)
			out = append(out, lines...)
		case intent.OpDropProfile:
			if n, j := s.proposedBy(a.Name); n > 0 {
				out = append(out, s.dropProposal(n, j, a.Name)...)
				continue
			}
			rest = append(rest, a)
		case intent.OpNote:
			if a.Topic == "net" && !slices.Contains(s.d.Include, "@net") && !slices.ContainsFunc(acts, func(x intent.Action) bool { return x.Op == intent.OpUseProfile && x.Name == "@net" }) {
				if n, _ := s.proposedBy("@net"); n == 0 {
					out = append(out, info("@net is not in the draft."))
				}
			}
			rest = append(rest, a)
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 {
		return nil, out
	}
	s.turn++
	return s.classify(ctx, s.turn, said, rest), out
}

// proposedBy returns the number of the open card that lists use_profile name,
// and the item's 1-based position on it; 0, 0 when no card does.
func (s *Session) proposedBy(name string) (int, int) {
	for _, p := range s.pending {
		if p.Kind != Card {
			continue
		}
		for j, i := range p.held {
			if a := p.turn.Items[i].Action; a.Op == intent.OpUseProfile && a.Name == name {
				return p.N, j + 1
			}
		}
	}
	return 0, 0
}

// dropProposal answers "no internet" while card n proposes @net as its item j.
// A card of that one item is declined; on a card of several, declining it all
// would also throw away what the human did not mention, and keeping the rest
// is an acceptance, so it says which answer does that and applies nothing.
func (s *Session) dropProposal(n, j int, name string) []Line {
	p, _ := s.find(n)
	if len(p.held) == 1 {
		return append([]Line{info("#%d proposed %s; you said no to it.", n, name)}, s.Decline(n)...)
	}
	var keep []string
	for k := range p.held {
		if k+1 != j {
			keep = append(keep, strconv.Itoa(k+1))
		}
	}
	l := info("#%d proposes %s as item %d, together with %d other item(s), so nothing was declined. "+
		"/decline %d drops all of it; \"only %s\" applies the others without %s.", n, name, j, len(p.held)-1, n, strings.Join(keep, " and "), name)
	l.Q = n
	return []Line{l}
}

// markers name the file that shows each toolchain, for the line that says the
// target has none.
var markers = map[string]string{"go": "go.mod", "node": "package.json", "python": "pyproject.toml, requirements.txt or uv.lock", "rust": "Cargo.toml"}

// toolchain answers a request that names a language: what the analysis
// proposes for it when the target shows that language (its cache variables,
// which then go on the turn's card), and otherwise a line saying there is
// nothing to propose. Downloads are @net's, asked for in words of their own.
func (s *Session) toolchain(lang string) ([]intent.Action, []Line) {
	var langs []ingest.Lang
	for _, l := range s.facts.Target.Languages {
		if l.Name == lang {
			langs = append(langs, l)
		}
	}
	if len(langs) == 0 {
		return nil, []Line{info("the target has no %s, so there is no %s cache to propose; downloading packages needs @net (say \"needs internet\").", markers[lang], lang)}
	}
	var acts []intent.Action
	for _, e := range ingest.Propose(ingest.TargetFacts{Languages: langs}).Env {
		acts = append(acts, intent.Action{Op: intent.OpSetEnv, Name: e.Name, Verb: "set", Value: e.Value, HasValue: true})
	}
	return acts, nil
}

// notUnderstood says why a request changed nothing. An interpreter's choices
// become a numbered question the next line can answer with a number.
func (s *Session) notUnderstood(said string, err error) []Line {
	var u *intent.Unclear
	if !errors.As(err, &u) {
		return []Line{warn("error: %s", safe.Inline(err.Error()))}
	}
	var open []Line
	if q, ok := s.find(s.before); ok {
		open = append(open, info("if you meant to answer #%d, which is still open, use its own commands: %s.", q.N, q.Answer))
	}
	if len(u.Choices) == 0 {
		why := ""
		if u.Why != "" {
			why = " (" + safe.Inline(u.Why) + ")"
		}
		return append([]Line{warn("I did not understand that, and nothing changed%s. Try saying it differently.", why)}, open...)
	}
	before := s.snapshot()
	p := s.open(Pending{Kind: Choice, said: said, at: s.turn, unclear: u})
	s.commit(before, "your request "+quote(said))
	return append(open, p.Line())
}

// classify decides each action's class against a clone of the draft with the
// turn's earlier actions applied, so "already in the draft" is judged where
// the action would land.
func (s *Session) classify(ctx context.Context, n int, said string, acts []intent.Action) *Turn {
	t := &Turn{N: n, Said: said}
	trial := s.d.Clone()
	for _, a := range acts {
		it := Item{Action: a, Sentence: Sentence(trial, a)}
		if a.Op == intent.OpIncludeProfile {
			if msg := s.includeRefusal(ctx, a.Name); msg != "" {
				it.Class, it.Msg = ClassInfo, msg
				t.Items = append(t.Items, it)
				continue
			}
			if p, ok := s.userProfile(a.Name); ok && p.Description != "" {
				it.Sentence += " (" + p.Description + ")"
			}
		}
		switch a.Op {
		case intent.OpNote, intent.OpAsk, intent.OpRefuse, intent.OpShow, intent.OpSave, intent.OpListIdentities:
			it.Class = ClassInfo
		case intent.OpSelectIdentity:
			it.Class = ClassIdentity
			s.typedAuthorItem(&it, said)
		case intent.OpReadFile:
			it.Class = ClassFile
		default:
			o := trial.Apply(a)
			it.Class = ClassEdit
			if widening(a) && !o.Changed && !o.Default && o.Refused == "" {
				// It changes nothing, so it is said, not put on a card.
				it.Class, it.Msg = ClassInfo, it.Sentence+"."
				if o.Msg != "" {
					it.Msg = o.Msg
				}
			}
			if widening(a) && o.Changed {
				it.Class, it.Ticked, it.Abuse = ClassGrant, true, s.abuseOf(a)
				if n := s.heldBy(a); n > 0 {
					it.Class, it.Ticked, it.Abuse, it.Already = ClassInfo, false, "", n
				}
			}
		}
		t.Items = append(t.Items, it)
	}
	return t
}

// typedAuthorItem makes a git author the request spells out ("commit as NAME
// <EMAIL>") a pin on the turn's card instead of a question: the human typed
// both values, so there is nothing to choose between. It applies only when
// both appear in the request as typed, so a model cannot invent them, and
// only while the draft pins no author; a value CheckAuthor refuses is said
// and not applied.
func (s *Session) typedAuthorItem(it *Item, said string) {
	a := it.Action
	name, email, ok := draft.ParseAuthor(a.Account)
	if a.Kind != "git" || !ok || !strings.Contains(said, name) || !strings.Contains(said, email) {
		return
	}
	if _, full := s.slotFull("git"); full {
		return
	}
	if err := draft.CheckAuthor(name, email); err != nil {
		it.Class, it.Msg = ClassInfo, "not pinned: "+safe.Inline(err.Error())+"."
		return
	}
	it.Class, it.Ticked, it.Pin = ClassGrant, true, true
	it.Sentence = "pin git author " + safe.Inline(name+" <"+email+">")
	it.Abuse = pinCost("git", "")
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

func (s *Session) abuseOf(a intent.Action) string {
	switch a.Op {
	case intent.OpIncludeProfile:
		if p, ok := s.userProfile(a.Name); ok {
			return profileCost(p)
		}
	case intent.OpUseProfile:
		return draft.Abuse[a.Name]
	case intent.OpOpenDoor:
		return draft.Abuse["listen_names"]
	case intent.OpGrantPath:
		return pathCost(a.Access)
	}
	return ""
}

// pathCost is the cost line of a read-only or writable path grant: what a
// hostile process in the sandbox can do with it. "" for any other access.
func pathCost(access string) string {
	switch access {
	case "ro":
		return "the sandbox can read everything under this path, and with @net send it anywhere."
	case "rw":
		return "the sandbox can read, change and delete everything under this path, and the change persists on the host after the sandbox exits."
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
			if it.Msg != "" {
				out = append(out, info("%s", it.Msg))
				continue
			}
			if it.Already > 0 {
				out = append(out, info("That is already on the open card #%d (%s): /accept %d applies it.", it.Already, it.Sentence, it.Already))
				continue
			}
			if a.Op == intent.OpSave {
				save = true
				continue
			}
			out = append(out, s.infoAction(ctx, t, acts, a)...)
		case ClassIdentity:
			out = append(out, s.askIdentity(a.Kind, a.Account, t.Said, t.N)...)
		case ClassFile:
			out = append(out, s.readFile(a.Path)...)
		case ClassGrant:
			if card {
				held = append(held, i)
			} else if slices.Contains(ticked, i) {
				out = append(out, s.proposeUser(t, acts, it)...)
			} else {
				out = append(out, info("not applied (unticked): %s.", it.Sentence))
			}
		case ClassEdit:
			if card {
				held = append(held, i)
			} else {
				out = append(out, s.proposeUser(t, acts, it)...)
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

func (s *Session) infoAction(ctx context.Context, t *Turn, acts []intent.Action, a intent.Action) []Line {
	switch a.Op {
	case intent.OpRefuse:
		return readRefusal(a.Code)
	case intent.OpNote:
		var out []Line
		if a.Topic == "identity_one" && s.d.SSH == nil && s.d.GH == nil && s.d.Git == nil && !s.includesPin() {
			// "two accounts are two profiles" answers a second pin; with nothing
			// pinned it answers a question nobody asked, and the human was
			// asking which identity to use.
			return s.Advice(ctx)
		}
		if e, ok := texts.Note(a.Topic); ok {
			out = append(out, info("%s", e))
		}
		if a.Topic == "net" && offlineWish(t.Said, acts) && !slices.Contains(s.d.Include, "@net") {
			s.d.Propose(intent.Action{Op: intent.OpDropProfile, Name: "@net"}, draft.SourceUser, t.Said, t.N)
		}
		return out
	case intent.OpAsk:
		return []Line{{Kind: Question, Text: "the model asks: \"" + safe.Inline(a.Question) + "\"\n  Nothing changed. Answer with a request of its own, for example \"I need internet\" or \"use my github\"; each request stands alone."}}
	case intent.OpShow:
		return s.Show()
	case intent.OpListIdentities:
		// Beside a refusal the list says what to use instead; the full
		// table is /keys.
		short := slices.ContainsFunc(acts, func(x intent.Action) bool { return x.Op == intent.OpRefuse })
		return s.listIdentities(a.Kind, short)
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
func (s *Session) proposeUser(t *Turn, acts []intent.Action, it Item) []Line {
	a := it.Action
	if it.Pin {
		return s.pinKey(a.Kind, a.Account, t.Said, t.N, it.Why != "")
	}
	src, origin := draft.SourceUser, t.Said
	if it.Why != "" {
		src, origin = draft.SourceIngest, it.Why
	}
	o, _ := s.d.Propose(a, src, origin, t.N)
	if a.Op == intent.OpIncludeProfile && o.Changed {
		if p, ok := s.userProfile(a.Name); ok {
			s.d.NoteProfile(a.Name, p.Description)
		}
	}
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
		return []Line{info("%s", describeTarget(s.cfg.Host.Target, s.facts.Target)),
			info("snug-setup does not read %s for grants: a file in the project says what the project wants, not what you want. "+
				"Say what you need, for example \"I need internet\".", shown)}
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
