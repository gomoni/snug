package tui

import (
	"path/filepath"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/suggest"
)

const labelW = 11

var rowName = map[suggest.RowID]string{
	suggest.Name: "NAME", suggest.Desc: "DESC", suggest.Base: "BASE", suggest.Identity: "IDENTITY",
	suggest.Agent: "AGENT", suggest.Network: "NETWORK", suggest.Containers: "CONTAINERS",
	suggest.Tools: "TOOLS", suggest.Env: "ENV",
}

// View implements tea.Model.
func (m Model) View() tea.View {
	return tea.NewView(m.render())
}

func (m Model) render() string {
	w := m.width
	if w < 20 {
		w = 20
	}
	if m.showDry {
		var out []string
		for _, l := range strings.Split(string(safe.Clean(m.dry)), "\n") {
			out = append(out, clip(l, w))
		}
		return strings.Join(append(out, "", m.st("dim", clip(" any key returns", w))), "\n")
	}

	var refused map[suggest.RowID]string
	if m.cfg.Build != nil {
		_, refused = m.cfg.Build(m.sel)
	}
	notes := m.sel.Notes()

	var vals [9]string
	valW := 0
	for _, r := range m.sel.Rows {
		vals[r.ID] = m.value(r.ID)
		if n := lipgloss.Width(vals[r.ID]); n > valW {
			valW = n
		}
	}
	if cap := (w - 15) / 2; valW > cap {
		valW = max(cap, 8)
	}

	lines := []string{m.st("head", clip("snug-setup  "+safe.Inline(m.cfg.Target), w)), ""}
	for _, r := range m.sel.Rows {
		id := r.ID
		cur := "  "
		if m.cursor == int(id) {
			cur = "▸ "
		}
		val := vals[id]
		if m.edit != nil && m.cursor == int(id) {
			m.edit.SetWidth(valW)
			val = m.edit.View()
		} else {
			val = clip(val, valW)
		}
		head := cur + padTo(rowName[id], labelW) + padTo(val, valW) + " "
		room := w - lipgloss.Width(head)
		reason := ""
		if room > 0 {
			reason = m.reason(id, refused, notes, room)
		}
		line := m.st("cursor", cur) + padTo(rowName[id], labelW) + padTo(val, valW)
		if reason != "" {
			kind := "dim"
			if m.sel.Changed(id) || refused[id] != "" {
				kind = "changed"
			}
			line += " " + m.st(kind, reason)
		}
		lines = append(lines, strings.TrimRight(line, " "))
	}

	if m.why {
		lines = append(lines, "")
		for _, l := range m.whyLines(w - 4) {
			lines = append(lines, "    "+m.st("dim", l))
		}
	}

	var warns []string
	for i, wn := range m.cfg.Warnings {
		cur := "  "
		if m.cursor == len(m.sel.Rows)+i {
			cur = "▸ "
		}
		suffix := ""
		if wn.Old != "" {
			suffix = "   f fix"
		}
		text := safe.Inline(filepath.Base(wn.File)) + ": " + wn.Line
		warns = append(warns, m.st("cursor", cur)+m.st("warn", clip("! "+text, w-2-utf8.RuneCountInString(suffix))+suffix))
	}
	for _, n := range m.cfg.Notes {
		warns = append(warns, "  "+m.st("warn", clip("! "+safe.Inline(n), w-2)))
	}
	if m.cfg.SnugMissing {
		warns = append(warns, "  "+m.st("warn", "! snug not on PATH: profiles not checked"))
	}
	if len(warns) > 0 {
		lines = append(lines, "")
		lines = append(lines, warns...)
	}

	lines = append(lines, "")
	if m.status != "" {
		lines = append(lines, " "+m.st("warn", clip(safe.Inline(m.status), w-1)))
	}
	for _, l := range m.footer(w) {
		lines = append(lines, m.st("dim", l))
	}
	return strings.Join(lines, "\n")
}

// footer is the key line, wrapped between keys so no line passes width.
func (m Model) footer(w int) []string {
	switch {
	case m.askQuit:
		return []string{" quit without writing? y/n"}
	case m.edit != nil:
		return []string{" enter accept  esc cancel"}
	}
	keys := []string{"j/k move", "space cycle", "u revert", "? why", "e edit"}
	if m.cfg.DryRun != nil {
		keys = append(keys, "d dry-run")
	}
	keys = append(keys, "w write", "q quit")
	if wn, ok := m.warningAt(); ok && wn.Old != "" {
		keys = append([]string{"f fix"}, keys...)
	}
	var out []string
	cur := ""
	for _, k := range keys {
		switch {
		case cur == "":
			cur = " " + k
		case utf8.RuneCountInString(cur)+2+utf8.RuneCountInString(k) <= w:
			cur += "  " + k
		default:
			out = append(out, cur)
			cur = " " + k
		}
	}
	return append(out, cur)
}

// value is the text of the value column for a row.
func (m Model) value(id suggest.RowID) string {
	switch id {
	case suggest.Name, suggest.Desc:
		return safe.Inline(m.sel.Text[id])
	case suggest.Tools:
		return m.sel.Tools().Label
	}
	r := m.sel.Rows[id]
	if !r.Sure {
		mark := "○"
		if m.sel.Pick[id] == 0 {
			mark = "●"
		}
		return mark + " " + r.Choices[0].Label
	}
	return r.Choices[m.sel.Pick[id]].Label
}

// reason is the right column of a row, at most room runes, never wrapped. A
// changed row says so with `*` and keeps its `u revert` hint; only the detail
// before it is cut.
func (m Model) reason(id suggest.RowID, refused, notes map[suggest.RowID]string, room int) string {
	detail := notes[id]
	if msg := refused[id]; msg != "" {
		detail = "not in the profile: " + msg
	}
	if !m.sel.Changed(id) {
		why := m.choice(id).Why
		if id == suggest.Name || id == suggest.Desc {
			why = m.sel.Rows[id].Choices[0].Why
		}
		if detail != "" {
			why = detail
			if refused[id] != "" {
				why = "! " + detail
			}
		}
		return clip(safe.Inline(why), room)
	}
	const suffix = "   u revert"
	head := "* " + m.word(id)
	if detail != "" {
		head += " — " + safe.Inline(detail)
	}
	return clip(head, room-utf8.RuneCountInString(suffix)) + suffix
}

// word names what a changed row now says: on or off for a row with an off
// choice, "changed" otherwise.
func (m Model) word(id suggest.RowID) string {
	r := m.sel.Rows[id]
	hasOff := false
	for _, c := range r.Choices {
		hasOff = hasOff || c.Label == suggest.Off
	}
	if !hasOff {
		return "changed"
	}
	if r.Choices[m.sel.Pick[id]].Label == suggest.Off {
		return "off"
	}
	return "on"
}

// st styles s unless colour is off. The markers `▸ * ○ ● !` carry the meaning
// without it.
func (m Model) st(kind, s string) string {
	if m.cfg.NoColor || s == "" {
		return s
	}
	switch kind {
	case "head":
		return lipgloss.NewStyle().Bold(true).Render(s)
	case "cursor":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render(s)
	case "dim":
		return lipgloss.NewStyle().Faint(true).Render(s)
	case "changed":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(s)
	case "warn":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(s)
	}
	return s
}

// clip cuts s to n runes, ending in an ellipsis when it was cut.
func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string([]rune(s)[:n-1]) + "…"
}

func padTo(s string, n int) string {
	if d := n - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}
