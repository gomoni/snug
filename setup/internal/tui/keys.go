package tui

import (
	"maps"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/suggest"
)

// maxText bounds what the inline editor accepts per row.
var maxText = map[suggest.RowID]int{suggest.Name: 64, suggest.Desc: 120}

func (m Model) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	switch {
	case m.showDry:
		m.showDry = false
		return m, nil
	case m.edit != nil:
		return m.editKey(msg, k)
	case m.askQuit:
		switch k {
		case "y":
			return m.finish(Quit)
		case "n", "esc", "q":
			m.askQuit = false
		}
		return m, nil
	}
	m.status = ""
	rows := len(m.sel.Rows)
	switch k {
	case "j", "down":
		if m.cursor < m.positions()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "space":
		m.cycle()
	case "enter":
		if m.cursor < rows && (m.cursor == int(suggest.Name) || m.cursor == int(suggest.Desc)) {
			return m.startEdit()
		}
		m.cycle()
	case "?":
		m.why = !m.why
	case "u":
		if m.cursor < rows {
			m.sel = m.sel.Revert(suggest.RowID(m.cursor))
		}
	case "U":
		m.sel = m.sel.RevertAll()
	case "d":
		return m.dryRun()
	case "f":
		w, ok := m.warningAt()
		switch {
		case !ok:
		case w.Old == "":
			m.status = "no mechanical fix for this one; ? shows snug's message"
		default:
			m.out.Fix = &w
			return m.finish(Fix)
		}
	case "w":
		return m.finish(Write)
	case "e":
		return m.finish(Edit)
	case "q", "ctrl+c":
		if m.anyChanged() {
			m.askQuit = true
			return m, nil
		}
		return m.finish(Quit)
	}
	return m, nil
}

func (m Model) finish(r Result) (tea.Model, tea.Cmd) {
	m.out.Result = r
	if r != Fix {
		m.out.Fix = nil
	}
	return m, tea.Quit
}

// cycle moves the current row to its next choice. Name, Desc and Tools have no
// alternatives to cycle through.
func (m *Model) cycle() {
	if m.cursor >= len(m.sel.Rows) {
		return
	}
	id := suggest.RowID(m.cursor)
	switch id {
	case suggest.Name, suggest.Desc, suggest.Tools:
		return
	}
	n := len(m.sel.Rows[id].Choices)
	pick := maps.Clone(m.sel.Pick)
	pick[id] = (pick[id] + 1) % n
	m.sel.Pick = pick
}

func (m Model) startEdit() (tea.Model, tea.Cmd) {
	id := suggest.RowID(m.cursor)
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = maxText[id]
	ti.SetValue(m.sel.Text[id])
	ti.CursorEnd()
	cmd := ti.Focus()
	m.edit = &ti
	return m, cmd
}

func (m Model) editKey(msg tea.KeyPressMsg, k string) (tea.Model, tea.Cmd) {
	id := suggest.RowID(m.cursor)
	switch k {
	case "enter":
		text := maps.Clone(m.sel.Text)
		text[id] = m.edit.Value()
		m.sel.Text = text
		m.edit = nil
		return m, nil
	case "esc", "ctrl+c":
		m.edit = nil
		return m, nil
	}
	ti, cmd := m.edit.Update(msg)
	m.edit = &ti
	return m, cmd
}

func (m Model) dryRun() (tea.Model, tea.Cmd) {
	if m.cfg.DryRun == nil || m.cfg.Build == nil {
		m.status = "snug not on PATH: nothing to dry-run"
		return m, nil
	}
	d, _ := m.cfg.Build(m.sel)
	out, err := m.cfg.DryRun(d)
	if err != nil {
		out = "snug --dry-run failed: " + err.Error() + "\n" + out
	}
	m.dry, m.showDry = out, true
	return m, nil
}
