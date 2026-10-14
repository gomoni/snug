// Package plain is snug-setup without a screen: one reader, one line at a
// time, and a line is a request, an answer, or a slash command. Nothing is
// ever asked. Where the TUI would ask, the session opens a numbered question;
// a line that is only yes, no or numbers ("only 1 and 3") answers the newest
// one, and /accept N, /decline N and /pick KIND VALUE answer any. Every other
// line is a request, so a request is never taken for an answer.
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
  yes | no | 2 | only 1 and 3  answer the newest question: all, none, or the items to keep
  /pending                  list the open questions and the line that answers each
  /accept N                 yes to question N
  /decline N                no to question N
  /pick ssh STEM|none       answer the open ssh question
  /pick github LOGIN|none   answer the open GitHub question (HOST/LOGIN when two hosts share a login)
  /pick git EMAIL|none      answer the open git author question
  /pick signing STEM|none   answer the open signing key question
  /include NAME             include one of your own snug profiles (the same as "use my NAME profile")
  /analyze                  describe the project and propose what its files make plain
  /why                      the reasons behind the opening: profiles, commits, what was not proposed
  /keys                     list every ssh public key on this host
  /save [NAME]              check with snug and write; NAME names an unnamed draft`

// Run reads lines from cfg.In until /quit or end of input and returns the
// session.
func Run(ctx context.Context, cfg Config) *session.Session {
	p := &printer{w: cfg.Out}
	s, lines := session.New(ctx, cfg.Session)
	p.say("snug-setup: one request per line; answer the newest question with yes, no or its numbers, any question with /accept, /decline and /pick (see /help).")
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
		if len(f) != 3 || (f[1] != "ssh" && f[1] != "github" && f[1] != "git" && f[1] != "signing") {
			p.say("usage: /pick ssh STEM, /pick signing STEM, /pick github LOGIN or /pick git EMAIL, or none in place of the value.")
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
	case "/include":
		if len(f) != 2 {
			p.say("usage: /include NAME, with NAME one of your snug profiles.")
			break
		}
		p.print(s.IncludeProfile(ctx, f[1]))
	case "/why", "/details":
		p.print(s.Details(ctx))
	case "/keys":
		p.print(s.ListIdentities("ssh"))
	case "/analyze":
		p.print(s.Analyze(ctx))
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
