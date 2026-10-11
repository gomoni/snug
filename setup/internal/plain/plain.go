// Package plain is snug-setup without a screen: one reader, one line at a
// time, and a line is either a request for the model or a slash command.
// Nothing is ever asked. Where the TUI would ask, the session opens a
// numbered question and the human — or the script — answers it with a line
// of its own (/accept N, /decline N, /pick KIND VALUE), so no line meant as a
// request can be taken as an answer.
package plain

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/session"
	"github.com/gomoni/snug/setup/internal/texts"
)

// Config is the session's configuration and the two streams.
type Config struct {
	Session session.Config
	In      io.Reader
	Out     io.Writer
	// Echo prints each line read, prefixed with "> ", so a transcript of a
	// piped script shows what was asked.
	Echo bool
}

const answerHelp = `Answers to open questions (--plain asks nothing; it opens numbered questions):
  /pending                  list the open questions and the line that answers each
  /accept N                 yes to question N
  /decline N                no to question N
  /pick ssh STEM|none       answer the open ssh question
  /pick github LOGIN|none   answer the open GitHub question (HOST/LOGIN when two hosts share a login)
  /pick git EMAIL|none      answer the open git author question
  /save [NAME]              check with snug and write; NAME names an unnamed draft`

// Run reads lines from cfg.In until /quit or end of input and returns the
// session.
func Run(ctx context.Context, cfg Config) *session.Session {
	p := &printer{w: cfg.Out}
	s, lines := session.New(ctx, cfg.Session)
	p.say("snug-setup --plain: one request per line; questions are answered with /accept, /decline and /pick (see /help). Target: " + cfg.Session.Host.Target)
	p.print(lines)
	in := bufio.NewReader(cfg.In)
	for {
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			break
		}
		line = strings.TrimSpace(line)
		if cfg.Echo && line != "" {
			p.say("> " + line)
		}
		if quit := handle(ctx, s, p, line); quit {
			break
		}
	}
	if s.Unsaved() {
		p.say("The draft was not saved.")
	}
	if n := len(s.Pending()); n > 0 {
		p.say(fmt.Sprintf("%d question(s) were still open.", n))
	}
	return s
}

type printer struct{ w io.Writer }

func (p *printer) say(s string) { fmt.Fprintln(p.w, safe.Clean(s)) }

func (p *printer) print(lines []session.Line) {
	for _, l := range lines {
		p.say(l.Text)
	}
}

// handle runs one line and reports whether it was /quit.
func handle(ctx context.Context, s *session.Session, p *printer, line string) bool {
	if line == "" {
		return false
	}
	if !strings.HasPrefix(line, "/") {
		t, lines := s.Submit(ctx, line)
		p.print(lines)
		if t != nil {
			p.print(s.Defer(ctx, t))
		}
		return false
	}
	f := strings.Fields(line)
	switch f[0] {
	case "/pending":
		ps := s.Pending()
		if len(ps) == 0 {
			p.say("nothing is pending.")
		}
		for _, q := range ps {
			p.print([]session.Line{q.Line()})
		}
	case "/accept", "/decline":
		n, ok := number(f)
		if !ok {
			p.say("usage: " + f[0] + " N, with N the number /pending shows.")
			break
		}
		if f[0] == "/accept" {
			p.print(s.Accept(ctx, n))
		} else {
			p.print(s.Decline(n))
		}
	case "/pick":
		if len(f) != 3 || (f[1] != "ssh" && f[1] != "github" && f[1] != "git") {
			p.say("usage: /pick ssh STEM, /pick github LOGIN or /pick git EMAIL, or none in place of the value.")
			break
		}
		p.print(s.Pick(ctx, f[1], f[2]))
	case "/save":
		if len(f) > 2 {
			p.say("usage: /save [NAME]")
			break
		}
		name := ""
		if len(f) == 2 {
			name = f[1]
		}
		_, lines := s.Save(ctx, name)
		p.print(lines)
	case "/show":
		p.print(s.Show())
	case "/undo":
		p.print(s.Undo())
	case "/help":
		e, _ := texts.Note("help")
		p.say(e.String())
		p.say(answerHelp)
	case "/quit", "/exit":
		return true
	default:
		p.say(fmt.Sprintf("unknown command %q; /help lists them.", f[0]))
	}
	return false
}

func number(f []string) (int, bool) {
	if len(f) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(f[1])
	return n, err == nil && n > 0
}
