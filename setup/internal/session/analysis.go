package session

import (
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
)

// langWords says how a language is named in the opening text.
var langWords = map[string]string{"go": "Go module", "node": "Node package", "python": "Python project", "rust": "Rust crate"}

// describeTarget is the first thing the human reads about the project, in
// Go's words. Names from the project pass through safe.Inline; ingest has
// already shortened them.
func describeTarget(target string, t ingest.TargetFacts) string {
	var parts []string
	for _, l := range t.Languages {
		w := langWords[l.Name]
		if l.Project != "" {
			w += " " + safe.Inline(l.Project)
		} else {
			w = strings.TrimSuffix(w, " module") + " project"
			if l.Name == "go" {
				w = "Go project"
			}
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
func (s *Session) proposalTurn(p ingest.Proposal) *Turn {
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
	t := s.classify(s.turn, "the analysis of the project", acts)
	t.Ingest = true
	var items []Item
	for i, it := range t.Items {
		if it.Class == ClassGrant && s.heldBy(it.Action) == 0 {
			it.Why = why[i]
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		s.turn--
		return nil
	}
	t.Items = items
	return t
}

// notProposed lists what the analysis saw a use for and did not put on the
// card, with the words that add it.
func notProposed(p ingest.Proposal, d *draft.Draft) string {
	var out []string
	for _, pk := range p.Include {
		if pk.Sure || slices.Contains(d.Include, pk.Name) {
			continue
		}
		switch pk.Name {
		case "@net":
			out = append(out, "@net ("+safe.Inline(pk.Why)+" needs the internet: say \"I need internet\")")
		case "@podman-build":
			out = append(out, "@podman-build ("+safe.Inline(pk.Why)+": say \"I need to build images\")")
		case "@podman-socket":
			out = append(out, "@podman-socket ("+safe.Inline(pk.Why)+": say \"I need podman\")")
		}
	}
	return strings.Join(out, "; ")
}

// Analyze describes the project and opens a card for what it makes plain, the
// same text and card the session starts with. It is /analyze.
func (s *Session) Analyze() []Line {
	t := s.facts.Target
	out := []Line{info("%s", describeTarget(s.cfg.Host.Target, t))}
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
	prop := ingest.Propose(t)
	for _, p := range s.pending {
		if p.Kind == Card && p.turn.Ingest {
			out = append(out, info("The proposal is already open as #%d: /accept %d applies it.", p.N, p.N))
			if n := notProposed(prop, s.d); n != "" {
				out = append(out, info("Not proposed: %s.", n))
			}
			return out
		}
	}
	turn := s.proposalTurn(prop)
	if turn == nil {
		out = append(out, info("Nothing to propose that the draft does not already have."))
	} else {
		before := s.snapshot()
		card := s.open(Pending{Kind: Card, turn: turn, held: heldAll(turn), said: turn.Said, at: turn.N})
		s.commit(before, "the analysis")
		out = append(out, card.Line())
		if len(prop.Env) > 0 {
			out = append(out, info("The caches go under %s/.cache: add .cache/ to the project's .gitignore.", safe.Inline(s.cfg.Host.Target)))
		}
	}
	if n := notProposed(prop, s.d); n != "" {
		out = append(out, info("Not proposed: %s.", n))
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
