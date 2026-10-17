// Package tui is the one screen of snug-setup: the suggested profile as rows,
// each of which can be inspected, changed and reverted. The model never writes
// a file and never runs a command of its own; it returns an Outcome and the
// caller acts, so everything here is exercised by feeding Update key presses
// and reading View.
package tui

import (
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/probe"
	"github.com/gomoni/snug/setup/internal/suggest"
)

// Config is everything the screen shows and calls.
type Config struct {
	Target      string // shown in the header, already ~-shortened
	Sel         suggest.Selection
	Warnings    []probe.Warning
	Notes       []string // ingest warnings, one `!` line each
	SnugMissing bool
	NoColor     bool
	// Build returns the draft for a selection and, per row, why the draft
	// lacks something the row shows.
	Build func(suggest.Selection) (*draft.Draft, map[suggest.RowID]string)
	// DryRun renders `snug --dry-run` for a draft; nil when snug is missing.
	DryRun func(*draft.Draft) (string, error)
}

// Result is what the caller does after Run returns.
type Result int

const (
	Quit Result = iota
	Write
	Edit
	Fix
)

// Outcome is how the screen ended.
type Outcome struct {
	Result Result
	Sel    suggest.Selection
	Fix    *probe.Warning // set for Fix
	// Row is the row the cursor was on, for Edit to open the file at.
	Row suggest.RowID
}

// Model is the bubbletea model of the screen.
type Model struct {
	cfg     Config
	sel     suggest.Selection
	cursor  int
	width   int
	why     bool
	askQuit bool
	status  string
	dry     string // full-screen `d` output; "" when not showing
	showDry bool
	edit    *textinput.Model
	out     Outcome
}

// New returns the screen for c.
func New(c Config) Model {
	return Model{cfg: c, sel: c.Sel, width: 80, out: Outcome{Result: Quit, Sel: c.Sel}}
}

// Outcome reports how the screen ended; before it has ended it is Quit with
// the current selection.
func (m Model) Outcome() Outcome {
	o := m.out
	o.Sel = m.sel
	if m.cursor < len(m.sel.Rows) {
		o.Row = suggest.RowID(m.cursor)
	}
	return o
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// positions is the number of selectable positions: the rows, then the warnings.
func (m Model) positions() int { return len(m.sel.Rows) + len(m.cfg.Warnings) }

func (m Model) warningAt() (probe.Warning, bool) {
	i := m.cursor - len(m.sel.Rows)
	if i < 0 || i >= len(m.cfg.Warnings) {
		return probe.Warning{}, false
	}
	return m.cfg.Warnings[i], true
}

func (m Model) anyChanged() bool {
	for _, r := range m.sel.Rows {
		if m.sel.Changed(r.ID) {
			return true
		}
	}
	return false
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}
