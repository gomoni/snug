package tui

import (
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/suggest"
)

// maxText bounds what the inline editor accepts per row.
var maxText = map[suggest.RowID]int{suggest.Name: 64, suggest.Desc: 120}

func (m Model) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	switch {
	case m.rev != nil:
		return m.reviewKey(k)
	case m.pg != nil:
		return m.dryKey(k)
	case m.edit != nil:
		return m.editKey(msg, k)
	case m.idm != nil:
		return m.identityKey(k)
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
		switch {
		case m.cursor == int(suggest.Name) || m.cursor == int(suggest.Desc):
			return m.startEdit()
		case m.cursor == int(suggest.Identity):
			m.idm = &identityMenu{cursor: m.sel.Pick[suggest.Identity]}
		}
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
		case m.cfg.PlanFix == nil:
			m.status = "nothing to fix with"
		default:
			r, err := m.cfg.PlanFix(w)
			return m.openReview(Fixed, r, err)
		}
	case "w", "e":
		kind := Write
		if k == "e" {
			kind = Edit
		}
		if m.cfg.Plan == nil {
			m.status = "nothing to write with"
			return m, nil
		}
		r, err := m.cfg.Plan(m.sel)
		return m.openReview(kind, r, err)
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
	return m, tea.Quit
}

// openReview shows the confirmation screen for r, or, when preparing it
// failed, the reason on the main screen.
func (m Model) openReview(kind Result, r Review, err error) (tea.Model, tea.Cmd) {
	if err != nil {
		m.status = err.Error()
		return m, nil
	}
	p := newPager(r.Title, r.Body, m.width, m.height)
	m.pg, m.rev = &p, &reviewState{kind: kind, r: r}
	return m, nil
}

// reviewKey: y applies, n and esc go back with the selection as it was,
// ctrl-c ends the program with nothing applied, and the pager keys scroll.
func (m Model) reviewKey(k string) (tea.Model, tea.Cmd) {
	rev := *m.rev
	switch k {
	case "ctrl+c":
		return m.finish(Interrupted)
	case "n", "esc", "q":
		m.pg, m.rev = nil, nil
	case "y":
		if rev.r.Blocked {
			return m, nil
		}
		m.pg, m.rev = nil, nil
		if err := rev.r.Apply(); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.out.Done = rev.r.Done
		return m.finish(rev.kind)
	default:
		p := *m.pg
		if p.scroll(k) {
			m.pg = &p
		}
	}
	return m, nil
}

func (m Model) dryKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "ctrl+c":
		return m.finish(Interrupted)
	case "q", "esc":
		m.pg = nil
	default:
		p := *m.pg
		if p.scroll(k) {
			m.pg = &p
		}
	}
	return m, nil
}

// identityKey: j/k move, space picks, ? shows why, esc and q go back. Enter
// does nothing: the menu is read-only apart from the pick.
func (m Model) identityKey(k string) (tea.Model, tea.Cmd) {
	menu := *m.idm
	n := len(m.sel.Rows[suggest.Identity].Choices)
	switch k {
	case "j", "down":
		if menu.cursor < n-1 {
			menu.cursor++
		}
	case "k", "up":
		if menu.cursor > 0 {
			menu.cursor--
		}
	case "space":
		m.sel = m.sel.WithPick(suggest.Identity, menu.cursor)
	case "?":
		menu.why = !menu.why
	case "esc", "q", "ctrl+c":
		m.idm = nil
		return m, nil
	}
	m.idm = &menu
	return m, nil
}

// cycle moves the current row to its next choice. Name and Desc have no
// alternatives to cycle through.
func (m *Model) cycle() {
	if m.cursor >= len(m.sel.Rows) {
		return
	}
	id := suggest.RowID(m.cursor)
	switch id {
	case suggest.Name, suggest.Desc:
		return
	}
	m.sel = m.sel.WithPick(id, (m.sel.Pick[id]+1)%len(m.sel.Rows[id].Choices))
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
		m.sel = m.sel.WithText(id, m.edit.Value())
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
	p := newPager("snug --dry-run", out, m.width, m.height)
	m.pg = &p
	return m, nil
}
