package tui

import (
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/suggest"
)

// whyLines is the `?` panel for the cursor: the facts behind the current
// choice, what each built-in it names costs, and the other values the row can
// take. Every line is wrapped to width.
func (m Model) whyLines(width int) []string {
	var out []string
	add := func(prefix, s string) { out = append(out, wrap(prefix+s, width)...) }
	if w, ok := m.warningAt(); ok {
		add("snug says: ", w.Full)
		add("file: ", safe.Inline(w.File))
		return out
	}
	id := suggest.RowID(m.cursor)
	c := m.choice(id)
	for _, f := range c.Facts {
		add("", f)
	}
	for _, tok := range strings.Fields(c.Label) {
		if a, ok := draft.Abuse[tok]; ok {
			add(tok+": ", a)
		}
	}
	if c.Label == suggest.NewFromHost {
		add("identity: ", draft.Abuse["identity"])
	}
	if c.Label == suggest.Off {
		for i, ch := range m.sel.Rows[id].Choices {
			if i == m.sel.Pick[id] {
				continue
			}
			for _, tok := range strings.Fields(ch.Label) {
				if a, ok := draft.Abuse[tok]; ok {
					add("turned on, "+tok+": ", a)
				}
			}
		}
	}
	switch id {
	case suggest.Name, suggest.Desc:
	default:
		var others []string
		for i, ch := range m.sel.Rows[id].Choices {
			if i != m.sel.Pick[id] {
				others = append(others, ch.Label)
			}
		}
		if len(others) > 0 {
			add("other values: ", strings.Join(others, ", "))
		}
	}
	if len(out) == 0 {
		out = append(out, "nothing more to say about this row")
	}
	return out
}

// choice is the Choice the row currently shows.
func (m Model) choice(id suggest.RowID) suggest.Choice { return m.sel.Current(id) }

// wrap breaks s at spaces into lines of at most width runes, indenting
// continuation lines by two. A word longer than a line is cut.
func wrap(s string, width int) []string {
	if width < 8 {
		width = 8
	}
	var lines []string
	cur := ""
	for _, w := range strings.Fields(s) {
		for len([]rune(w)) > width {
			r := []rune(w)
			if cur != "" {
				lines, cur = append(lines, cur), ""
			}
			lines = append(lines, string(r[:width]))
			w = string(r[width:])
		}
		switch {
		case cur == "":
			cur = w
		case len([]rune(cur))+1+len([]rune(w)) <= width:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = "  " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
