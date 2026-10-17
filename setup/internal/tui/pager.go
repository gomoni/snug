package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/viewport"

	"github.com/gomoni/snug/setup/internal/safe"
)

// pager is a title, a scrollable body and a hint line, filling the terminal.
// A pager is copied by value; scrolling works on the copy and the caller keeps
// it.
type pager struct {
	title string
	lines []string
	vp    viewport.Model
	w     int
}

// chrome is the lines a pager spends on its title, the gap and the hint.
const chrome = 3

func newPager(title, body string, w, h int) pager {
	p := pager{title: title, lines: strings.Split(string(safe.Clean(body)), "\n"), vp: viewport.New()}
	p.resize(w, h)
	return p
}

func (p *pager) resize(w, h int) {
	p.w = w
	p.vp.SetWidth(w)
	p.vp.SetHeight(max(h-chrome, 3))
	clipped := make([]string, len(p.lines))
	for i, l := range p.lines {
		clipped[i] = clip(l, w)
	}
	p.vp.SetContentLines(clipped)
}

// scroll applies a scrolling key and reports whether k was one.
func (p *pager) scroll(k string) bool {
	switch k {
	case "j", "down":
		p.vp.ScrollDown(1)
	case "k", "up":
		p.vp.ScrollUp(1)
	case "pgdown", "space":
		p.vp.PageDown()
	case "pgup":
		p.vp.PageUp()
	case "g", "home":
		p.vp.GotoTop()
	case "G", "end":
		p.vp.GotoBottom()
	default:
		return false
	}
	return true
}

func (m Model) viewPager(p pager, hint string) string {
	body := strings.Split(p.vp.View(), "\n")
	for i := range body {
		body[i] = strings.TrimRight(body[i], " ")
	}
	pos := fmt.Sprintf("  %3.0f%%", p.vp.ScrollPercent()*100)
	out := append([]string{m.st("head", clip(p.title, p.w)), ""}, body...)
	out = append(out, m.st("dim", clip(hint+pos, p.w)))
	return strings.Join(out, "\n")
}
