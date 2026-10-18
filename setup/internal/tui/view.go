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
	suggest.Env: "ENV",
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
	if m.rev != nil {
		hint := " y " + map[Result]string{Write: "write", Edit: "write, then open $EDITOR", Fixed: "fix"}[m.rev.kind] + "   n back   j/k pgup/pgdn g/G scroll"
		if m.rev.r.Blocked {
			hint = " esc back   j/k pgup/pgdn g/G scroll"
		}
		return m.viewPager(*m.pg, hint)
	}
	if m.pg != nil {
		return m.viewPager(*m.pg, " q back   j/k pgup/pgdn g/G scroll")
	}

	if m.idm != nil {
		return m.renderIdentity(w)
	}

	var refused map[suggest.RowID]string
	if m.cfg.Build != nil {
		_, refused = m.cfg.Build(m.sel)
	}
	notes := m.sel.Notes()

	vals := make([]string, len(m.sel.Rows))
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
	if iw := m.sel.IdentityWarning(); iw != "" {
		warns = append(warns, "  "+m.st("warn", clip("! "+iw, w-2)))
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
		for _, l := range wrap(safe.Inline(m.status), w-2) {
			lines = append(lines, " "+m.st("warn", l))
		}
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
	keys := []string{"j/k move", "space cycle"}
	switch {
	case m.cursor == int(suggest.Name) || m.cursor == int(suggest.Desc):
		keys = append(keys, "enter edit text")
	case m.cursor == int(suggest.Identity):
		keys = append(keys, "enter open")
	}
	keys = append(keys, "u revert", "? why")
	if m.cfg.DryRun != nil {
		keys = append(keys, "d dry-run")
	}
	keys = append(keys, "w write", "q quit")
	if wn, ok := m.warningAt(); ok && wn.Old != "" {
		keys = append([]string{"f fix"}, keys...)
	}
	keys = append(keys, "e edit & exit")
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
	}
	if id == suggest.Identity {
		return m.sel.Current(id).Label
	}
	r := m.sel.Rows[id]
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
		if r := m.sel.Rows[id]; !r.Sure && m.sel.Pick[id] == r.Suggested {
			// An unsure row sits at off; the reason names what space turns on.
			why = "○ " + r.Choices[r.Cand].Label + "? " + why
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

// word names what a changed row now says: "off" when it sits at the off
// choice, "changed" otherwise; the value column already shows which choice.
func (m Model) word(id suggest.RowID) string {
	r := m.sel.Rows[id]
	if r.Choices[m.sel.Pick[id]].Label == suggest.Off && id != suggest.Name && id != suggest.Desc {
		return "off"
	}
	return "changed"
}

// renderIdentity is the IDENTITY submenu: a section per block with every
// source of the block, the pinned values of each profile under it, the
// switches the cursor can reach, and a window of those lines that keeps the
// cursor visible.
func (m Model) renderIdentity(w int) string {
	items := m.sel.IdentityItems()
	var body []string
	start := make([]int, len(items))
	section := suggest.Block(-1)
	for n, it := range items {
		if it.Block != section {
			section = it.Block
			if len(body) > 0 {
				body = append(body, "")
			}
			body = append(body, m.st("head", "  "+it.Block.String()))
		}
		start[n] = len(body)
		cur := "  "
		if m.idm.cursor == n {
			cur = "▸ "
		}
		if it.IsPart {
			box := "[ ]"
			if it.On {
				box = "[x]"
			}
			body = append(body, m.st("cursor", cur)+m.st("dim", clip("      "+box+" "+safe.Inline(it.Text), w-2)))
		} else {
			b, i := it.Block, it.Choice
			radio := "( )"
			if m.sel.Block[b] == i {
				radio = "(•)"
			}
			head := radio + " " + safe.Inline(m.sel.BlockChoices(b)[i].Label)
			if i == m.sel.BlockSuggested(b) {
				head += "   suggested"
			}
			body = append(body, m.st("cursor", cur)+clip(head, w-2))
			for _, l := range m.sel.IdentityDetail(b, i) {
				body = append(body, m.st("dim", clip("        "+safe.Inline(l), w)))
			}
			if name, val, ok := m.sel.Locked(b); ok && i == 0 {
				body = append(body, m.st("dim", clip("        "+safe.Inline(name)+" is included and pins this: "+val, w)))
			}
			if iw := m.sel.SourceWarning(b, i); iw != "" {
				body = append(body, "        "+m.st("warn", clip("! "+iw, w-8)))
			}
			if pr := m.sel.BlockProblem(b, i); pr != "" {
				body = append(body, "        "+m.st("warn", clip("! "+pr, w-8)))
			}
		}
		if m.idm.why && m.idm.cursor == n {
			for _, l := range m.identityWhy(it, w-8) {
				body = append(body, "      "+m.st("dim", l))
			}
		}
	}
	foot := []string{" j/k move  space pick or toggle  ? why  esc back"}
	room := m.height - 3 - len(foot)
	lo := 0
	if room > 0 && len(body) > room {
		lo = max(0, min(start[m.idm.cursor], len(body)-room))
		body = body[lo:min(lo+room, len(body))]
	}
	lines := []string{m.st("head", clip("snug-setup  "+safe.Inline(m.cfg.Target)+"  IDENTITY", w)), ""}
	lines = append(lines, body...)
	lines = append(lines, "")
	for _, l := range foot {
		lines = append(lines, m.st("dim", l))
	}
	return strings.Join(lines, "\n")
}

// identityWhy is the `?` text under a submenu line: the reasons it carries.
func (m Model) identityWhy(it suggest.IdentItem, width int) []string {
	var out []string
	for _, f := range it.Why {
		out = append(out, wrap(safe.Inline(f), width)...)
	}
	if len(out) == 0 {
		out = append(out, "nothing more to say about this one")
	}
	return out
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
