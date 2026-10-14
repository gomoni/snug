// Package session is snug-setup's engine: a request goes to the interpreter
// with the host's facts, its actions are classified and applied to the draft,
// and every point where a human must decide becomes a numbered pending
// question instead of a prompt. It never reads a terminal and never prints;
// every call returns the lines a front end shows. --plain and the TUI are two
// renderings of the same session, so they cannot disagree about what a
// request means.
package session

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/texts"
)

// Interpreter reads one request into actions. c is what the session knows
// (the draft, the host's identities, the human's profile names); nothing is
// applied by interpreting. An *intent.Unclear error means the request was not
// understood and its Choices may be offered; any other error is the
// interpreter's own failure. Neither changes anything.
type Interpreter interface {
	Interpret(ctx context.Context, c intent.Context, request string) ([]intent.Action, error)
}

// Config is everything the session needs from outside.
type Config struct {
	Interpreter Interpreter
	Run         hostfacts.Runner
	Host        draft.Host
	Offline     bool
	LookPath    func(string) (string, error)

	// ProfileDir is where Save writes NAME.toml.
	ProfileDir string
	// ProfileDirs are the directories snug reads profiles from, which
	// snug-setup reads to offer the human's own profiles (ingest.ProfileDirs).
	ProfileDirs []string
}

// LineKind says what a line is, for a front end that styles them.
type LineKind int

const (
	Info LineKind = iota
	Warn
	Refused
	Question
	Shown // the rendered draft
)

// Line is one thing to show. Text is Go's words; host, file and model text in
// it has been through safe.Inline, and a front end still passes the whole of
// it through safe.Clean.
type Line struct {
	Kind LineKind
	Text string
	// Q is the number of the question the line prints, 0 for any other line.
	// Shown reads it.
	Q int
}

func info(format string, a ...any) Line { return Line{Kind: Info, Text: fmt.Sprintf(format, a...)} }
func warn(format string, a ...any) Line { return Line{Kind: Warn, Text: fmt.Sprintf(format, a...)} }

// Session is one conversation: the draft, the host's facts, the pending
// questions and the undo stack.
type Session struct {
	cfg Config
	d   *draft.Draft

	undo    []step
	pending []Pending
	lastN   int
	// shown is the question the front end printed last in answer to the
	// current line, and before that the one printed last in answer to the
	// line before it: the only question a bare yes, no or number may answer.
	shown, before int

	keys        []hostfacts.SSHKey
	gh          []hostfacts.GHAccount
	ghInstalled bool
	authors     []hostfacts.GitAuthor
	facts       ingest.Facts
	pick        *ingest.IdentityPick
	resolves    map[string]resolveResult

	turn      int
	analyzed  bool
	lastSaved string
}

// step is what Undo restores: the draft, its ledger with it, and the pending
// list, so undoing a turn also takes back the questions it opened.
type step struct {
	what    string
	d       *draft.Draft
	pending []Pending
	// declined is the card a decline closed, 0 for any other step: a
	// request to undo never reopens it, only /undo does.
	declined int
}

// New detects the host's facts and returns a session, with the lines that
// describe what was found.
func New(ctx context.Context, cfg Config) (*Session, []Line) {
	if cfg.LookPath == nil {
		cfg.LookPath = exec.LookPath
	}
	s := &Session{cfg: cfg, d: draft.New(cfg.Host)}
	var out []Line
	var warns []string
	s.keys, warns = hostfacts.SSHKeys(ctx, cfg.Host.Home, cfg.Run)
	for _, w := range warns {
		out = append(out, warn("warning: %s", w))
	}
	s.gh, s.ghInstalled = hostfacts.GitHubAccounts(ctx, cfg.Run)
	s.authors = hostfacts.GitAuthors(ctx, cfg.Run)
	s.facts = ingest.Gather(ctx, cfg.Host.Target, cfg.Host.Home, cfg.ProfileDirs, cfg.Run)
	s.pick = ingest.Suggest(ingest.SuggestInput{Repo: s.facts.Repo, SSH: s.facts.SSH, Keys: s.keys, Profiles: s.facts.Profiles,
		Authors: s.authors, GH: s.gh, GitSigningKey: s.facts.GitSigningKey})
	return s, append(out, s.Analyze(ctx)...)
}

// Draft returns the profile built so far. The caller must not change it.
func (s *Session) Draft() *draft.Draft { return s.d }

// Unsaved reports whether the draft holds something no save has written.
func (s *Session) Unsaved() bool { return !s.d.Empty() && s.d.Render() != s.lastSaved }

func (s *Session) snapshot() step {
	return step{d: s.d.Clone(), pending: slices.Clone(s.pending)}
}

// commit pushes before onto the undo stack when the draft or the pending list
// differs from it. Every human act is one commit.
func (s *Session) commit(before step, what string) {
	same := before.d.Render() == s.d.Render() && slices.EqualFunc(before.pending, s.pending, func(a, b Pending) bool { return a.N == b.N })
	if same {
		return
	}
	before.what = what
	s.undo = append(s.undo, before)
}

// Heard tells the session that the human typed a line: what the front end
// printed for the line before it is now what a bare answer refers to.
func (s *Session) Heard() { s.before, s.shown = s.shown, 0 }

// Shown tells the session that the front end printed lines. A front end
// that never calls Heard and Shown gets no bare answers: each one asks which
// question it is for.
func (s *Session) Shown(lines []Line) {
	for _, l := range lines {
		if l.Q > 0 {
			s.shown = l.Q
		}
	}
}

// Undo restores the state before the last commit. An overwrite question is
// never restored: it was asked about a body the draft no longer has.
func (s *Session) Undo() []Line {
	if len(s.undo) == 0 {
		return []Line{info("nothing to undo.")}
	}
	st := s.undo[len(s.undo)-1]
	s.undo = s.undo[:len(s.undo)-1]
	s.d = st.d
	s.pending = slices.DeleteFunc(st.pending, func(p Pending) bool { return p.Kind == Overwrite })
	if st.declined > 0 {
		return []Line{info("undone: %s; #%d is open again and nothing from it is applied.", st.what, st.declined)}
	}
	return []Line{info("undone: %s.", st.what)}
}

// undoRequest is an undo the interpreter read in a request ("never mind",
// "take that back"). It does not reopen a card the human declined: a "no" is
// already the narrow answer, and words that sound like retracting the line
// just typed must not resurrect a grant refused earlier. /undo still does.
func (s *Session) undoRequest() []Line {
	if n := len(s.undo); n > 0 && s.undo[n-1].declined > 0 {
		d := s.undo[n-1].declined
		return []Line{info("the last thing done was your no to #%d, and nothing from it is in the draft, so nothing was undone. /undo reopens #%d if that is what you meant.", d, d)}
	}
	return s.Undo()
}

// Show returns the draft as it would be saved.
func (s *Session) Show() []Line {
	out := []Line{{Kind: Shown, Text: strings.TrimRight(s.d.Render(), "\n")}}
	if s.d.Empty() && len(s.pending) > 0 {
		out = append(out, info("Nothing is in the draft yet; %d question(s) are open and nothing from them is applied until you answer (/pending lists them).", len(s.pending)))
	}
	if s.d.ReadOnlyTarget {
		out = append(out, info("# run with: %s", s.d.RunLine(s.cfg.Host.Target)))
	}
	return out
}

func (s *Session) context() intent.Context {
	c := intent.Context{Target: s.cfg.Host.Target, Draft: s.d.Summary()}
	for _, k := range s.keys {
		c.SSH = append(c.SSH, intent.SSHKey{Stem: k.Stem, Comment: k.Comment, Agent: k.InAgent})
	}
	for _, a := range s.gh {
		c.GitHub = append(c.GitHub, intent.GHAccount{Host: a.Host, User: a.User, Active: a.Active})
	}
	for _, a := range s.authors {
		c.Git = append(c.Git, a.String())
	}
	c.Profiles = s.profileNames()
	return c
}

// refusal is Go's verdict on an action the draft refused.
func refusal(code, detail string) []Line {
	text := "refused (" + code + ")"
	if detail != "" {
		text += ": " + safe.Inline(detail)
	}
	out := []Line{{Kind: Refused, Text: text}}
	if e, ok := texts.Refusal(code); ok {
		out = append(out, Line{Kind: Refused, Text: e.String()})
	}
	return out
}

// readRefusal is the interpreter's reading of a request as one snug refuses.
// The code is shown as a reading, not as snug's verdict: a reading can be
// wrong, and the human must be able to tell the two apart.
func readRefusal(code string) []Line {
	text := "I read that as a request snug refuses (" + code + ")."
	if e, ok := texts.Refusal(code); ok {
		text += "\n" + e.String()
	}
	text += "\nIf I misread you, say it differently — nothing changed."
	return []Line{{Kind: Refused, Text: text}}
}

// ListIdentities lists the host's identities of kind.
func (s *Session) ListIdentities(kind string) []Line { return s.listIdentities(kind, false) }

// listIdentities lists the host's identities of kind; short lists at most
// maxShown ssh keys, the suggested one first, and says how to see the rest.
func (s *Session) listIdentities(kind string, short bool) []Line {
	footer := ""
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	switch kind {
	case "ssh", "signing":
		if len(s.keys) == 0 {
			return []Line{info("no ssh public keys (~/.ssh/*.pub) on this host.")}
		}
		fmt.Fprintln(tw, "KEY\tCOMMENT\tAGENT\tFINGERPRINT")
		keys := s.keys
		if short {
			keys = nil
			shown, more := s.shortlist(kind, "", s.Candidates(kind))
			for _, c := range shown {
				keys = append(keys, s.keys[c.idx])
			}
			if more > 0 {
				footer = fmt.Sprintf("... and %d more: /keys lists all %d", more, len(s.keys))
			}
		}
		for _, k := range keys {
			held := "-"
			if k.InAgent {
				held = "held"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", safe.Inline(k.Stem), dash(safe.Inline(k.Comment)), held, k.Fingerprint)
		}
	case "github":
		if len(s.gh) == 0 {
			why := " (gh is not installed)"
			if s.ghInstalled {
				why = " (see `gh auth login`)"
			}
			return []Line{info("no GitHub logins known to gh%s.", why)}
		}
		fmt.Fprintln(tw, "HOST\tUSER\tACTIVE")
		for _, a := range s.gh {
			fmt.Fprintf(tw, "%s\t%s\t%v\n", safe.Inline(a.Host), safe.Inline(a.User), a.Active)
		}
	case "git":
		if len(s.authors) == 0 {
			return []Line{info("no global git author (git config --global user.name / user.email).")}
		}
		fmt.Fprintln(tw, "NAME\tEMAIL")
		for _, a := range s.authors {
			fmt.Fprintf(tw, "%s\t%s\n", safe.Inline(a.Name), safe.Inline(a.Email))
		}
	}
	tw.Flush()
	if footer != "" {
		b.WriteString(footer + "\n")
	}
	return []Line{{Kind: Shown, Text: strings.TrimRight(b.String(), "\n")}}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
