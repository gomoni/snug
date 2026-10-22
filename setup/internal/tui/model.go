// Package tui is the one screen of snug-setup: the suggested profile as rows,
// each of which can be inspected, changed and reverted, and the screens that
// confirm a write or a fix. The model never writes a file and never runs a
// command of its own: Config carries the functions that prepare and apply a
// write, and an Outcome tells the caller what to do once the program ends.
// Everything here is exercised by feeding Update key presses and reading View.
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
	// DryRun renders `snug --dry-run` for a selection; nil when snug is
	// missing.
	DryRun func(suggest.Selection) (string, error)
	// Plan prepares writing the selection. The error is shown on the main
	// screen: a Plan that fails never ends the program.
	Plan func(suggest.Selection) (Review, error)
	// PlanFix prepares fixing the file a warning is about.
	PlanFix func(probe.Warning) (Review, error)
	// Status is the line shown under the rows when the screen opens.
	Status string
}

// Review is a confirmation screen: a title, a body to scroll and what y does.
type Review struct {
	Title string
	Body  string
	// Blocked means the change would not do what the screen says; y does
	// nothing and the screen offers only a way back.
	Blocked bool
	// Apply makes the change. Its error is shown on the main screen.
	Apply func() error
	// Done is what the caller prints once Apply has succeeded and the program
	// has ended.
	Done string
}

// Result is what the caller does after Run returns.
type Result int

const (
	Quit Result = iota
	// Write: the profile was written. Edit: it was written and the caller
	// opens it in an editor. Fixed: a user file was fixed and the caller
	// checks the profiles again. Interrupted: ctrl-c on a confirmation
	// screen; nothing was written.
	Write
	Edit
	Fixed
	Interrupted
)

// Outcome is how the screen ended.
type Outcome struct {
	Result Result
	Sel    suggest.Selection
	// Row is the row the cursor was on, for Edit to open the file at.
	Row suggest.RowID
	// Done is the Review.Done of the change that was applied.
	Done string
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
	height  int
	pg      *pager // `d` output or a review; nil on the main screen
	rev     *reviewState
	edit    *textinput.Model
	idm     *identityMenu // the IDENTITY submenu; nil on the main screen
	out     Outcome
}

// identityMenu is the IDENTITY submenu: cursor is an index into
// Selection.IdentityItems, the choices and the switches under them.
type identityMenu struct {
	cursor int
	why    bool
}

type reviewState struct {
	kind Result
	r    Review
}

// New returns the screen for c.
func New(c Config) Model {
	return Model{cfg: c, sel: c.Sel, width: 80, height: 24, status: c.Status, out: Outcome{Result: Quit, Sel: c.Sel}}
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
		if msg.Height > 0 {
			m.height = msg.Height
		}
		if m.pg != nil {
			p := *m.pg
			p.resize(m.width, m.height)
			m.pg = &p
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}
