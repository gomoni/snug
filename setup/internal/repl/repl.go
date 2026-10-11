// Package repl is the chat loop: a line from the human goes to the model with
// the host's facts, the reply is validated and applied to the draft, and
// anything that must be exact or confirmed is Go's.
package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/gomoni/snug/setup/internal/compose"
	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/texts"
)

// Model answers one prompt. temperature is 0 for the first attempt and higher
// for the single retry, because the same prompt at temperature 0 would return
// the same bytes.
type Model interface {
	Complete(ctx context.Context, system, user string, temperature float64) (string, error)
}

// Config is everything the loop needs from outside.
type Config struct {
	Model    Model
	In       io.Reader
	Out      io.Writer
	Run      hostfacts.Runner
	Host     draft.Host
	Offline  bool
	LookPath func(string) (string, error)

	// ProfileDir is where `save` writes NAME.toml.
	ProfileDir string
}

// REPL holds the session: the draft, the host's facts and the undo stack.
type REPL struct {
	cfg Config
	in  *bufio.Reader
	out io.Writer

	draft *draft.Draft
	undo  []*draft.Draft

	keys        []hostfacts.SSHKey
	gh          []hostfacts.GHAccount
	ghInstalled bool
	authors     []hostfacts.GitAuthor

	eof       bool
	lastSaved string
	quit      bool

	// turn numbers requests; said is the current one's text. Both go into
	// the ledger with every action the request causes.
	turn int
	said string
}

// New detects the host's facts and returns a session. Detection warnings are
// printed to cfg.Out.
func New(ctx context.Context, cfg Config) *REPL {
	if cfg.LookPath == nil {
		cfg.LookPath = exec.LookPath
	}
	r := &REPL{cfg: cfg, in: bufio.NewReader(cfg.In), out: cfg.Out, draft: draft.New(cfg.Host)}
	var warns []string
	r.keys, warns = hostfacts.SSHKeys(ctx, cfg.Host.Home, cfg.Run)
	for _, w := range warns {
		r.say("warning: %s", w)
	}
	r.gh, r.ghInstalled = hostfacts.GitHubAccounts(ctx, cfg.Run)
	r.authors = hostfacts.GitAuthors(ctx, cfg.Run)
	return r
}

// Draft returns the profile built so far.
func (r *REPL) Draft() *draft.Draft { return r.draft }

// say prints a line. Text the model chose (a question, a path in a refusal)
// reaches the terminal only through here, with control characters removed: a
// reply may carry an ESC sequence that rewrites what the screen already shows.
func (r *REPL) say(format string, a ...any) {
	fmt.Fprintln(r.out, sanitize(fmt.Sprintf(format, a...)))
}

func sanitize(s string) string {
	return strings.Map(func(c rune) rune {
		switch {
		case c == '\n' || c == '\t':
			return c
		case c < 0x20, c >= 0x7f && c <= 0x9f, c >= 0x202a && c <= 0x202e, c >= 0x2066 && c <= 0x2069, c == 0x2028, c == 0x2029:
			return -1
		}
		return c
	}, s)
}

// readLine reads one line; ok is false at end of input.
func (r *REPL) readLine() (string, bool) {
	line, err := r.in.ReadString('\n')
	if err != nil && line == "" {
		r.eof = true
		return "", false
	}
	return strings.TrimRight(line, "\r\n"), true
}

func (r *REPL) prompt(msg string) (string, bool) {
	fmt.Fprint(r.out, msg)
	s, ok := r.readLine()
	return strings.TrimSpace(s), ok
}

// confirm asks a yes/no question. End of input and anything but yes/no's
// default is a no for def=false.
func (r *REPL) confirm(msg string, def bool) bool {
	hint := " [y/N] "
	if def {
		hint = " [Y/n] "
	}
	s, ok := r.prompt(msg + hint)
	if !ok {
		return false
	}
	switch strings.ToLower(s) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

// Run reads lines until /quit or end of input.
func (r *REPL) Run(ctx context.Context) {
	r.say("snug-setup: describe the sandbox you want; /help lists commands. Target: %s", r.cfg.Host.Target)
	r.hostSummary()
	for !r.quit {
		fmt.Fprint(r.out, "> ")
		line, ok := r.readLine()
		if !ok {
			r.say("")
			break
		}
		r.Handle(ctx, line)
	}
	if r.draft.Render() != r.lastSaved && !r.draft.Empty() {
		r.say("The draft was not saved.")
	}
}

func (r *REPL) hostSummary() {
	r.say("Found on this host: %d ssh public key(s), %d GitHub login(s), %d git author(s).", len(r.keys), len(r.gh), len(r.authors))
	if r.cfg.Offline {
		r.say("Offline: GitHub is not asked whether a key belongs to an account.")
	}
}

// Handle processes one input line.
func (r *REPL) Handle(ctx context.Context, line string) {
	line = strings.TrimSpace(line)
	switch {
	case line == "":
	case strings.HasPrefix(line, "/"):
		r.slash(ctx, line)
	default:
		r.request(ctx, line)
	}
}

func (r *REPL) slash(ctx context.Context, line string) {
	switch strings.Fields(line)[0] {
	case "/show":
		r.show()
	case "/save":
		r.save(ctx)
	case "/undo":
		r.doUndo()
	case "/help":
		e, _ := texts.Note("help")
		r.say("%s", e)
	case "/quit", "/exit":
		r.quit = true
	default:
		r.say("unknown command %q; /help lists them.", strings.Fields(line)[0])
	}
}

func (r *REPL) show() {
	fmt.Fprint(r.out, r.draft.Render())
	if r.draft.ReadOnlyTarget {
		r.say("# run with: %s", r.draft.RunLine(r.cfg.Host.Target))
	}
}

func (r *REPL) doUndo() {
	if len(r.undo) == 0 {
		r.say("nothing to undo.")
		return
	}
	r.draft = r.undo[len(r.undo)-1]
	r.undo = r.undo[:len(r.undo)-1]
	r.say("undone.")
}

func (r *REPL) context(file *intent.File) intent.Context {
	c := intent.Context{Target: r.cfg.Host.Target, Draft: r.draft.Summary(), File: file}
	for _, k := range r.keys {
		c.SSH = append(c.SSH, intent.SSHKey{Stem: k.Stem, Comment: k.Comment, Agent: k.InAgent})
	}
	for _, a := range r.gh {
		c.GitHub = append(c.GitHub, intent.GHAccount{Host: a.Host, User: a.User, Active: a.Active})
	}
	for _, a := range r.authors {
		c.Git = append(c.Git, a.String())
	}
	return c
}

// ask sends the prompt and returns validated actions. A reply that fails
// intent.Parse is retried once at a higher temperature; after that nothing is
// guessed.
func (r *REPL) ask(ctx context.Context, c intent.Context, request string) ([]intent.Action, bool) {
	system, user := intent.FormatPrompt(c, request)
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		temp := 0.0
		if attempt > 0 {
			temp = 0.3
		}
		reply, err := r.cfg.Model.Complete(ctx, system, user, temp)
		if err != nil {
			r.say("error: %v", err)
			return nil, false
		}
		acts, err := intent.Parse([]byte(strings.TrimSpace(reply)))
		if err == nil {
			return acts, true
		}
		last = err
	}
	r.say("I did not understand that, and nothing changed (the model's reply was not a valid action list: %v). Try saying it differently.", last)
	return nil, false
}

func (r *REPL) request(ctx context.Context, line string) {
	acts, ok := r.ask(ctx, r.context(nil), line)
	if !ok {
		return
	}
	r.turn++
	r.said = line
	before, snap := r.draft.Render(), r.draft.Clone()
	r.apply(ctx, acts, line, "")
	if r.draft.Render() != before {
		r.undo = append(r.undo, snap)
	}
}

func (r *REPL) refusal(code, detail string) {
	if detail != "" {
		r.say("refused (%s): %s", code, detail)
	} else {
		r.say("refused (%s)", code)
	}
	if e, ok := texts.Refusal(code); ok {
		r.say("%s", e)
	}
}

// apply runs the model's actions. file is the name of the file the actions
// were read from, "" when they came from the human's request: then they are
// the human's own, and otherwise any that contradicts the human is put to them
// as a question before it is applied.
func (r *REPL) apply(ctx context.Context, acts []intent.Action, request, file string) {
	src, origin := draft.SourceUser, request
	if file != "" {
		src, origin = draft.SourceFile, file
	}
	for _, a := range acts {
		switch a.Op {
		case intent.OpRefuse:
			r.refusal(a.Code, "")
		case intent.OpNote:
			if e, ok := texts.Note(a.Topic); ok {
				r.say("%s", e)
			}
			if a.Topic == "net" && file == "" && offlineWish(acts) && !slices.Contains(r.draft.Include, "@net") {
				r.draft.Propose(intent.Action{Op: intent.OpDropProfile, Name: "@net"}, draft.SourceUser, request, r.turn)
			}
		case intent.OpAsk:
			r.say("? %s", a.Question)
		case intent.OpShow:
			r.show()
		case intent.OpSave:
			r.save(ctx)
		case intent.OpListIdentities:
			r.listIdentities(a.Kind)
		case intent.OpSelectIdentity:
			if _, p := r.draft.Propose(a, src, origin, r.turn); p != nil {
				if o := r.decide(*p); !o.NotMine {
					r.say("%s", o.Msg)
					continue
				}
			}
			r.selectIdentity(ctx, a.Kind, a.Account)
		case intent.OpReadFile:
			r.readFile(ctx, a.Path, request, file != "")
		default:
			o, p := r.draft.Propose(a, src, origin, r.turn)
			if p != nil {
				o = r.decide(*p)
			}
			switch {
			case o.Refused != "":
				r.refusal(o.Refused, o.Msg)
			case o.Msg != "":
				r.say("%s", o.Msg)
			case o.Default && !slices.ContainsFunc(acts, func(x intent.Action) bool { return x.Op == intent.OpNote && x.Topic == "defaults" }):
				e, _ := texts.Note("defaults")
				r.say("%s", e)
			}
		}
	}
}

// offlineWish reports whether a reply to the human is the labeling guide's
// answer to "no network / offline" on a draft without @net: `note net` and no
// profile action on @net. The model has no op for "keep it as it is", so
// without this the wish leaves no ledger entry for a file to contradict.
func offlineWish(acts []intent.Action) bool {
	return !slices.ContainsFunc(acts, func(a intent.Action) bool {
		return (a.Op == intent.OpUseProfile || a.Op == intent.OpDropProfile) && a.Name == "@net"
	})
}

// decide puts a conflict to the human; anything but yes declines it.
func (r *REPL) decide(p draft.Pending) draft.Outcome {
	return r.draft.Decide(p, r.confirm(p.Question, false))
}

func (r *REPL) readFile(ctx context.Context, name, request string, followUp bool) {
	if followUp {
		r.say("refused: one file per request; ask again to read another.")
		return
	}
	digest, err := compose.ReadTarget(r.cfg.Host.Target, name)
	if err != nil {
		r.say("not read: %v", err)
		return
	}
	r.say("read %s (%d bytes of digest) and asked again.", name, len(digest))
	acts, ok := r.ask(ctx, r.context(&intent.File{Name: name, Body: digest}), request)
	if !ok {
		return
	}
	r.apply(ctx, acts, request, name)
}

func (r *REPL) listIdentities(kind string) {
	tw := tabwriter.NewWriter(r.out, 0, 4, 2, ' ', 0)
	switch kind {
	case "ssh":
		if len(r.keys) == 0 {
			r.say("no ssh public keys (~/.ssh/*.pub) on this host.")
			return
		}
		fmt.Fprintln(tw, "KEY\tCOMMENT\tAGENT\tFINGERPRINT")
		for _, k := range r.keys {
			held := "-"
			if k.InAgent {
				held = "held"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Stem, dash(k.Comment), held, k.Fingerprint)
		}
	case "github":
		if len(r.gh) == 0 {
			r.say("no GitHub logins known to gh%s.", map[bool]string{false: " (gh is not installed)", true: " (see `gh auth login`)"}[r.ghInstalled])
			return
		}
		fmt.Fprintln(tw, "HOST\tUSER\tACTIVE")
		for _, a := range r.gh {
			fmt.Fprintf(tw, "%s\t%s\t%v\n", a.Host, a.User, a.Active)
		}
	case "git":
		if len(r.authors) == 0 {
			r.say("no global git author (git config --global user.name / user.email).")
			return
		}
		fmt.Fprintln(tw, "NAME\tEMAIL")
		for _, a := range r.authors {
			fmt.Fprintf(tw, "%s\t%s\n", a.Name, a.Email)
		}
	}
	tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
