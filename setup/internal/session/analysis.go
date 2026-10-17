package session

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
)

// langWords says how a language's project is named in the opening text, with
// the project's name after it; langUnnamed says it when the marker file gives
// no name.
var (
	langWords   = map[string]string{"go": "Go module", "node": "Node package", "python": "Python project", "rust": "Rust crate"}
	langUnnamed = map[string]string{"go": "Go project", "node": "Node project", "python": "Python project", "rust": "Rust project"}
)

// describeTarget is the first thing the human reads about the project, in
// Go's words. Names from the project pass through safe.Inline; ingest has
// already shortened them.
func describeTarget(target string, t ingest.TargetFacts) string {
	var parts []string
	for _, l := range t.Languages {
		w := langUnnamed[l.Name]
		if l.Project != "" {
			w = langWords[l.Name] + " " + safe.Inline(l.Project)
		}
		parts = append(parts, w+" ("+safe.Inline(l.Marker)+")")
	}
	if len(parts) == 0 {
		parts = append(parts, "no go.mod, package.json, pyproject.toml or Cargo.toml")
	}
	if t.Git {
		parts = append(parts, "a git work tree")
	}
	if len(t.Containers) == 0 {
		parts = append(parts, "no Dockerfile, Containerfile or compose file")
	} else {
		names := make([]string, len(t.Containers))
		for i, c := range t.Containers {
			names[i] = safe.Inline(c)
		}
		parts = append(parts, "container files: "+strings.Join(names, ", "))
	}
	return "Target " + safe.Inline(target) + ": " + strings.Join(parts, "; ") + "."
}

// proposalTurn turns the proposal into a Turn of the grants that would change
// the draft, each carrying what it was computed from. It returns nil when
// nothing would change. Only what the project's own files make plain goes on
// the card: a pick that is not Sure (the internet, a container engine) is the
// human's to ask for.
//
// Abuse: a hostile project chooses which markers exist, so it chooses which of
// these fixed proposals appear. None of them carries text or a path from the
// project, every one goes through the draft's own checks, and none applies
// before the human accepts the card.
func (s *Session) proposalTurn(ctx context.Context, p ingest.Proposal) *Turn {
	var acts []intent.Action
	var why []string
	for _, pk := range p.Include {
		if pk.Sure {
			acts = append(acts, intent.Action{Op: intent.OpUseProfile, Name: pk.Name})
			why = append(why, pk.Why)
		}
	}
	for _, e := range p.Env {
		acts = append(acts, intent.Action{Op: intent.OpSetEnv, Name: e.Name, Verb: "set", Value: e.Value, HasValue: true})
		why = append(why, e.Why)
	}
	s.turn++
	t := s.classify(ctx, s.turn, "the analysis of the project", acts)
	t.Ingest = true
	var items []Item
	for i, it := range t.Items {
		if it.Class == ClassGrant && s.heldBy(it.Action) == 0 {
			it.Why = why[i]
			items = append(items, it)
		}
	}
	ids := s.identityItems(ctx)
	// @git writes the host's author into the sandbox's git config; a pinned
	// author with a name and an email overrides both, so @git would add
	// next to nothing beside it. Accepting the two from separate cards is
	// still allowed.
	if slices.ContainsFunc(ids, func(it Item) bool { return it.Pin && it.Action.Kind == "git" && s.fullAuthor(it.Action.Account) }) {
		items = slices.DeleteFunc(items, func(it Item) bool { return it.Action == intent.Action{Op: intent.OpUseProfile, Name: "@git"} })
	}
	items = append(items, ids...)
	if len(items) == 0 {
		s.turn--
		return nil
	}
	t.Items = items
	return t
}

// remoteLine names the remote the identity was picked for. Its name and url
// are the project's text, so they are quoted as data: a url can be written to
// read like snug-setup's own words.
func remoteLine(r ingest.Remote) Line {
	return info("Remote %s %s (%s).", strconv.Quote(safe.Inline(r.Name)), strconv.Quote(safe.Inline(r.URL)), safe.Inline(r.Scheme))
}

// fullAuthor reports whether the host's git author with this email has a
// name too.
func (s *Session) fullAuthor(email string) bool {
	return slices.ContainsFunc(s.authors, func(a hostfacts.GitAuthor) bool { return a.Email == email && a.Name != "" })
}

// pinLabel names a candidate on a card line: the key and its comment, the
// login, or the author, without the fingerprint and the reason the line
// already carries.
func (s *Session) pinLabel(kind string, c Candidate) string {
	switch kind {
	case "ssh", "signing":
		k := s.keys[c.idx]
		l := safe.Inline(k.Stem)
		if k.Comment != "" {
			l += " (" + safe.Inline(k.Comment) + ")"
		}
		if !k.InAgent {
			l += " [not in the agent]"
		}
		return l
	case "github":
		return safe.Inline(s.gh[c.idx].Host + "/" + s.gh[c.idx].User)
	}
	return safe.Inline(s.authors[c.idx].String())
}

// identityItems are the opening card's identity: the profile of the human's
// that already pins the identity the facts point at, when snug accepts it, or
// else each suggested piece the draft does not pin yet, in the order a pin
// needs them (a signing key goes with an ssh key and an author). Every value
// is one of the host's own candidates, matched exactly; nothing comes from
// the repository.
//
// Abuse: a hostile repository steers which of the human's own keys, logins
// and profiles is suggested (ingest.Suggest says how far). The card names
// each one with its reason and pins nothing until the human answers it, and
// "only 1 and 3" leaves any of them out.
func (s *Session) identityItems(ctx context.Context) []Item {
	p := s.pick
	if p == nil {
		return nil
	}
	if p.Profile.Value != "" {
		if msg, checked := s.refusalOf(ctx, p.Profile.Value); !(checked && msg != "") {
			a := intent.Action{Op: intent.OpIncludeProfile, Name: p.Profile.Value}
			if _, ok := s.userProfile(a.Name); !ok || slices.Contains(s.d.Include, a.Name) || s.heldBy(a) > 0 {
				return nil
			}
			return []Item{{Action: a, Class: ClassGrant, Ticked: true, Sentence: Sentence(s.d, a), Abuse: s.abuseOf(a), Why: p.Profile.Why}}
		}
	}
	var out []Item
	for _, c := range []struct {
		kind string
		r    ingest.Reason
	}{{"ssh", p.SSH}, {"git", p.Author}, {"signing", p.Signing}, {"github", p.GH}} {
		if c.r.Value == "" {
			continue
		}
		if _, full := s.slotFull(c.kind); full {
			continue
		}
		if _, ok := s.includedPin(c.kind); ok {
			continue
		}
		cands := s.Candidates(c.kind)
		i := slices.IndexFunc(cands, func(k Candidate) bool { return k.Why != "" })
		if i < 0 {
			continue
		}
		if c.kind == "signing" && !(s.d.SSH != nil || slices.ContainsFunc(out, func(it Item) bool { return it.Action.Kind == "ssh" })) {
			continue
		}
		if c.kind == "signing" && !(s.d.Git != nil || slices.ContainsFunc(out, func(it Item) bool { return it.Action.Kind == "git" })) {
			continue
		}
		it := Item{Action: intent.Action{Op: intent.OpSelectIdentity, Kind: c.kind, Account: cands[i].Key}, Class: ClassGrant,
			Ticked: true, Pin: true, Sentence: "pin " + kindName(c.kind) + " " + s.pinLabel(c.kind, cands[i]), Why: c.r.Why}
		name := safe.Inline(cands[i].Key)
		if c.kind == "github" {
			name = s.pinLabel(c.kind, cands[i])
		}
		it.Abuse = pinCost(c.kind, name)
		out = append(out, it)
	}
	return out
}

// pinCost is the cost line of a pin on the opening card, so a "yes" to the card
// is a yes to each of them read. name is the key stem or the HOST/LOGIN.
func pinCost(kind, name string) string {
	switch kind {
	case "ssh":
		return draft.Abuse["identity"]
	case "signing":
		return "the sandbox gets a SIGNING ORACLE for " + name + ": anything signed with it, commits and tags in your name included, comes from inside; and the agent proxy also lets it authenticate with this key to any host that trusts it."
	case "github":
		return "the sandbox gets the GitHub token of " + name + " and can act as that account on GitHub with whatever the token allows."
	}
	return "commits made in the sandbox carry this name and email."
}

// notProposed lists what the analysis saw a use for and did not put on the
// card, with the words that add it. short leaves out what each was seen for.
func notProposed(p ingest.Proposal, d *draft.Draft, short bool) string {
	var out []string
	for _, pk := range p.Include {
		if pk.Sure || slices.Contains(d.Include, pk.Name) {
			continue
		}
		var say string
		switch pk.Name {
		case "@net":
			say = "I need internet"
		case "@podman-build":
			say = "I need to build images"
		case "@podman-socket":
			say = "I need podman"
		default:
			continue
		}
		if short {
			out = append(out, pk.Name+" (say \""+say+"\")")
		} else {
			out = append(out, pk.Name+" (for "+safe.Inline(pk.Why)+"; say \""+say+"\")")
		}
	}
	return strings.Join(out, "; ")
}

// projectWarnings are the things about the project itself that the human must
// not miss: a shipped profile that is not read, secrets the target holds, and
// what the analysis could not read.
func (s *Session) projectWarnings() []Line {
	t := s.facts.Target
	var out []Line
	if t.RepoProfile {
		out = append(out, warn("the project ships .snug or snug.toml. snug-setup does not read it: profiles come from your own config, never from the project."))
	}
	if len(t.Secrets) > 0 {
		names := make([]string, len(t.Secrets))
		for i, n := range t.Secrets {
			names[i] = safe.Inline(n)
		}
		out = append(out, warn("the project holds %s (names only; nothing was read). The sandbox can read them: the target is visible inside.", strings.Join(names, ", ")))
	}
	for _, w := range t.Warnings {
		out = append(out, warn("%s", w))
	}
	return out
}

// Analyze is the opening, and /analyze or a request to analyze afterwards: a
// few lines about the project, the identity it points at and the profiles snug
// refuses, then the card for what the project's files make plain. Asked again
// it says what is still open and what the draft pins instead of printing the
// opening a second time; Details prints everything.
func (s *Session) Analyze(ctx context.Context) []Line {
	prop := ingest.Propose(s.facts.Target)
	if s.analyzed {
		return s.analyzeAgain(ctx, prop)
	}
	s.analyzed = true
	out := s.profileWarnings()
	out = append(out, info("%s", describeTarget(s.cfg.Host.Target, s.facts.Target)))
	out = append(out, s.projectWarnings()...)
	if s.pick != nil {
		out = append(out, remoteLine(s.pick.Remote))
	}
	card := s.proposalLines(ctx, prop)
	if l := s.suggestionLine(ctx); l != "" {
		out = append(out, info("%s", l))
	}
	out = append(out, s.profileSummary(ctx)...)
	out = append(out, card...)
	if n := notProposed(prop, s.d, true); n != "" {
		out = append(out, info("Not proposed: %s.", n))
	}
	out = append(out, info("/why has the reasons, your profiles and the full text of the above."))
	return out
}

// proposalLines opens the card for the proposal unless one is already open or
// the draft has all of it.
func (s *Session) proposalLines(ctx context.Context, prop ingest.Proposal) []Line {
	for _, p := range s.pending {
		if p.Kind == Card && p.turn.Ingest {
			return []Line{info("The proposal is open as #%d: /accept %d applies it, /decline %d drops it.", p.N, p.N, p.N)}
		}
	}
	turn := s.proposalTurn(ctx, prop)
	if turn == nil {
		return []Line{info("Nothing to propose that the draft does not already have.")}
	}
	before := s.snapshot()
	card := s.open(Pending{Kind: Card, turn: turn, held: heldAll(turn), said: turn.Said, at: turn.N})
	s.commit(before, "the analysis")
	return []Line{card.Line()}
}

// analyzeAgain answers a repeated request to analyze: the project has not
// changed under the session, so what is new is the state of the proposal, the
// identity and the questions.
func (s *Session) analyzeAgain(ctx context.Context, prop ingest.Proposal) []Line {
	out := s.proposalLines(ctx, prop)
	if st := s.identityStatus(); st != "" {
		out = append(out, info("%s", st))
	}
	return append(out, info("The project is as at the start; /why prints the full analysis."))
}

// Details is /why: everything the opening leaves out. Nothing in it opens a
// question or changes the draft.
func (s *Session) Details(ctx context.Context) []Line {
	out := []Line{info("Found on this host: %d ssh public key(s), %d GitHub login(s), %d git author(s). Each request stands alone: nothing but the draft is remembered between them.", len(s.keys), len(s.gh), len(s.authors))}
	if s.cfg.Offline {
		out = append(out, info("Offline: GitHub is not asked whether a key belongs to an account."))
	}
	out = append(out, s.profileLines(ctx)...)
	out = append(out, info("%s", describeTarget(s.cfg.Host.Target, s.facts.Target)))
	out = append(out, s.projectWarnings()...)
	out = append(out, s.repoLines(ctx)...)
	prop := ingest.Propose(s.facts.Target)
	if len(prop.Env) > 0 {
		out = append(out, info("The caches go under %s/.cache: add .cache/ to the project's .gitignore.", safe.Inline(s.cfg.Host.Target)))
	}
	if n := notProposed(prop, s.d, false); n != "" {
		out = append(out, info("Not proposed: %s.", n))
	}
	for _, p := range s.pending {
		if p.Kind == Card && p.turn.Ingest {
			out = append(out, info("The proposal is open as #%d: /accept %d applies it.", p.N, p.N))
		}
	}
	return out
}

func heldAll(t *Turn) []int {
	out := make([]int, len(t.Items))
	for i := range out {
		out[i] = i
	}
	return out
}

// Advice answers a request for a recommendation about identities from the
// facts the session has. It is the same short answer every
// time it is asked, with what the draft pins by now; /why has the reasons.
func (s *Session) Advice(ctx context.Context) []Line {
	l := s.suggestionLine(ctx)
	if l == "" {
		out := s.repoLines(ctx)
		if len(out) == 0 {
			return []Line{info("I have nothing to base a suggestion on: the project has no git remote I could read, so I cannot tell which of your accounts or keys it belongs to. Say \"use my github account\" and I list what is on this host.")}
		}
		return out
	}
	out := []Line{info("%s", l)}
	if st := s.identityStatus(); st != "" {
		out = append(out, info("%s", st))
	}
	return append(out, info("/why has the reasons for each."))
}

// suggestionLine is the identity the host's facts point at for this project on
// one line, "" when they point at none. Nothing is pinned by it.
func (s *Session) suggestionLine(ctx context.Context) string {
	p := s.pick
	if p == nil {
		return ""
	}
	var parts []string
	for _, c := range []struct {
		what string
		r    ingest.Reason
	}{{"GitHub login", p.GH}, {"ssh key", p.SSH}, {"signing key", p.Signing}} {
		if c.r.Value != "" {
			parts = append(parts, c.what+" "+safe.Inline(c.r.Value))
		}
	}
	if p.Author.Value != "" {
		parts = append(parts, fmt.Sprintf("git author %s <%s>", safe.Inline(p.AuthorName), safe.Inline(p.Author.Value)))
	}
	if len(parts) == 0 {
		return ""
	}
	l := "Suggested identity for this project (nothing is pinned until you answer): " + strings.Join(parts, "; ") + "."
	if p.Profile.Value != "" {
		if msg, checked := s.refusalOf(ctx, p.Profile.Value); !(checked && msg != "") {
			l += fmt.Sprintf(" Your profile %q already pins it: \"use my %s profile\" or /include %s.", p.Profile.Value, p.Profile.Value, p.Profile.Value)
		}
	} else if len(p.Conflict) > 1 {
		l += fmt.Sprintf(" Several of your profiles pin %s with this author: %s. Name one.", safe.Inline(p.Remote.Host), strings.Join(p.Conflict, ", "))
	}
	for _, q := range s.pending {
		if q.Kind == Card && q.turn.Ingest && slices.ContainsFunc(q.turn.Items, func(it Item) bool { return it.Pin }) {
			return l + fmt.Sprintf(" It is on card #%d.", q.N)
		}
	}
	return l + " Say \"use my ssh key\", \"use my github account\", \"sign commits with my key\" or \"commit as NAME <EMAIL>\" to be asked."
}

// identityStatus says what the draft pins and which questions are open, ""
// when neither.
func (s *Session) identityStatus() string {
	var pinned []string
	if g := s.d.GH; g != nil {
		pinned = append(pinned, "GitHub login "+safe.Inline(g.User))
	}
	if k := s.d.SSH; k != nil {
		pinned = append(pinned, "ssh key "+safe.Inline(k.Stem))
	}
	if g := s.d.Git; g != nil {
		if g.SigningStem != "" {
			pinned = append(pinned, "signing key "+safe.Inline(g.SigningStem))
		}
		pinned = append(pinned, "git author "+safe.Inline(g.Email))
	}
	var open []string
	for _, p := range s.pending {
		open = append(open, fmt.Sprintf("#%d", p.N))
	}
	var out []string
	if len(pinned) > 0 {
		out = append(out, "The draft pins "+strings.Join(pinned, "; ")+".")
	}
	if len(open) > 0 {
		out = append(out, "Open: "+strings.Join(open, ", ")+" (/pending).")
	}
	return strings.Join(out, " ")
}

// repoLines say what the repository's own files show about who works on it and
// how, and the identity the host's facts point at for it. The suggestion is
// text and a default for the identity questions; nothing is pinned by it.
func (s *Session) repoLines(ctx context.Context) []Line {
	r := s.facts.Repo
	if r == nil || r.Sampled == 0 && len(r.Remotes) == 0 {
		return nil
	}
	var out []Line
	if p := s.pick; p != nil {
		out = append(out, remoteLine(p.Remote))
	}
	if r.Sampled > 0 {
		var who []string
		for i, a := range r.Authors {
			if i == 2 {
				break
			}
			who = append(who, fmt.Sprintf("%d by %s <%s>", a.Commits, safe.Inline(a.Name), safe.Inline(a.Email)))
		}
		line := fmt.Sprintf("Last %d commits: %s.", r.Sampled, strings.Join(who, ", "))
		type key struct {
			format, fp string
			ok         bool
		}
		var order []key
		count := map[key]int{}
		for _, sg := range r.Signers {
			k := key{sg.Format, sg.Fingerprint, sg.Verified}
			if _, ok := count[k]; !ok {
				order = append(order, k)
			}
			count[k] += sg.Commits
		}
		var sigs []string
		for _, k := range order {
			mine := s.stemByFingerprint(k.fp)
			switch {
			case k.format == "ssh" && k.ok && mine != "":
				sigs = append(sigs, fmt.Sprintf("%d carry an ssh signature that verifies with your key %s", count[k], safe.Inline(mine)))
			case k.format == "ssh" && mine != "":
				sigs = append(sigs, fmt.Sprintf("%d carry an ssh signature naming your key %s that does NOT verify, so it is not evidence of anything", count[k], safe.Inline(mine)))
			case k.format == "ssh" && k.ok:
				sigs = append(sigs, fmt.Sprintf("%d carry an ssh signature that verifies with a key you do not have", count[k]))
			case k.format == "ssh":
				sigs = append(sigs, fmt.Sprintf("%d carry an ssh signature that does not verify", count[k]))
			default:
				sigs = append(sigs, fmt.Sprintf("%d carry a gpg signature (not checked)", count[k]))
			}
		}
		if len(sigs) > 0 {
			line += " " + strings.Join(sigs, "; ") + "."
		}
		out = append(out, info("%s", line))
	}
	p := s.pick
	if p == nil {
		return out
	}
	if p.Profile.Value != "" {
		if msg, checked := s.refusalOf(ctx, p.Profile.Value); checked && msg != "" {
			out = append(out, info("Your profile %q already pins this identity (%s), but snug refuses it today: %s. Fix that file and /include %s, or pin the identity below one piece at a time.", p.Profile.Value, p.Profile.Why, firstClause(msg), p.Profile.Value))
		} else {
			out = append(out, info("Your profile %q already pins this identity (%s): \"use my %s profile\" or /include %s.", p.Profile.Value, p.Profile.Why, p.Profile.Value, p.Profile.Value))
		}
	} else if len(p.Conflict) > 1 {
		out = append(out, info("Several of your profiles pin %s with this author: %s. Name one.", safe.Inline(p.Remote.Host), strings.Join(p.Conflict, ", ")))
	}
	var sug []string
	add := func(what string, r ingest.Reason, extra string) {
		if r.Value != "" {
			sug = append(sug, fmt.Sprintf("  %s %s  (%s%s)", what, safe.Inline(r.Value), safe.Inline(r.Why), extra))
		}
	}
	known := ""
	if s.facts.SSH.Known[p.Remote.Host] {
		known = "; " + strconv.Quote(p.Remote.Host) + " is in your known_hosts"
	}
	add("GitHub login", p.GH, "")
	add("ssh key", p.SSH, known)
	add("signing key", p.Signing, "")
	if p.Author.Value != "" {
		sug = append(sug, fmt.Sprintf("  git author %s <%s>  (%s)", safe.Inline(p.AuthorName), safe.Inline(p.Author.Value), safe.Inline(p.Author.Why)))
	}
	if len(sug) > 0 {
		out = append(out, info("Suggested identity for this project (nothing is pinned until you answer):\n%s\nSay \"use my github account\", \"use my ssh key\", \"commit as NAME <EMAIL>\" or \"sign commits with my key\" and the question puts these first.", strings.Join(sug, "\n")))
	}
	return out
}

func (s *Session) stemByFingerprint(fp string) string {
	for _, k := range s.keys {
		if k.Fingerprint == fp {
			return k.Stem
		}
	}
	return ""
}
