// Package suggest turns what snug-setup found on the host and in the target
// into a Selection: one row per part of a profile, each with a suggested value,
// a one-line reason and the alternatives a person may pick instead.
//
// Nothing here grants anything. A Selection is a set of choices; build.go turns
// it into a draft, and the draft's own rules still apply to every op.
package suggest

import (
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/safe"
)

// RowID names a row. The values are the rows' order on screen and their index
// in Selection.Rows.
type RowID int

const (
	Name RowID = iota
	Desc
	Base
	Identity
	Agent
	Network
	Containers
	Tools
	Env
)

// Labels of the choices other code compares against.
const (
	// Off is the label of the "not selected" choice of a toggle row.
	Off = "—"
	// NoIdentity is the label of Identity's "no identity profile" choice.
	NoIdentity = "none"

	baseWithParent = "@sys @home @target-rw @parent-ro"
	baseWithout    = "@sys @home @target-rw"
)

// Choice is one value a row can take.
type Choice struct {
	Label string   // shown in the value column
	Why   string   // one line, right column
	Facts []string // lines of the `?` panel
}

// Row is one part of the profile.
type Row struct {
	ID        RowID
	Suggested int      // index into Choices
	Choices   []Choice // Name and Desc: one Choice, whose value is edited as text
	// Sure is false for a pick that only the person can know the need for
	// (a toggle shown as an unfilled or filled circle); Suggested is then its
	// "off" choice.
	Sure bool
}

// Selection is the person's current state; Rows hold the suggestions it is
// measured against. Copy it with Revert or RevertAll, never by assignment: the
// maps are shared by a plain copy.
type Selection struct {
	Rows []Row
	Pick map[RowID]int    // current choice per row
	Text map[RowID]string // Name and Desc, current text

	profiles     []ingest.Profile
	env          []ingest.EnvHint
	parentIsHome bool
}

// Suggest computes the Selection for the facts. home and target are the
// absolute, symlink-resolved paths snug will see.
//
// Abuse: the target chooses its remote, authors, file names and project names,
// so it can steer a row toward any value that already exists on the host and
// nowhere else. Identity offers only the person's own profiles that pin an
// identity, and the other rows offer built-in names; a name taken from the
// target reaches the screen only as a reason, through safe.Inline. Nothing the
// target says turns an unsure pick on.
func Suggest(f ingest.Facts, home, target string) Selection {
	s := Selection{
		Pick:         map[RowID]int{},
		Text:         map[RowID]string{},
		profiles:     slices.Clone(f.Profiles),
		parentIsHome: filepath.Dir(target) == home,
	}
	prop := ingest.Propose(f.Target)
	s.env = prop.Env

	id := identityRow(f)
	agent := agentRow(f.Target)
	rows := []Row{
		nameRow(f.Profiles, target),
		{},
		baseRow(s.parentIsHome),
		id,
		agent,
		networkRow(prop, agent.Suggested == 0),
		containersRow(prop),
		{},
		envRow(prop),
	}
	rows[Desc] = descRow(f.Target, target, id)
	s.Rows = rows
	for i := range s.Rows {
		s.Rows[i].ID = RowID(i)
		s.Pick[RowID(i)] = s.Rows[i].Suggested
	}
	s.Text[Name] = rows[Name].Choices[0].Label
	s.Text[Desc] = rows[Desc].Choices[0].Label
	s.Rows[Tools] = Row{ID: Tools, Sure: true, Choices: []Choice{s.Tools()}}
	return s
}

func nameRow(profiles []ingest.Profile, target string) Row {
	n := profileName(filepath.Base(target))
	c := Choice{Label: n, Why: "from directory"}
	if i := slices.IndexFunc(profiles, func(p ingest.Profile) bool { return p.Name == n }); i >= 0 {
		c.Why = "exists: " + profiles[i].File
		c.Facts = []string{"a profile called " + n + " is defined in " + profiles[i].File + "; writing overwrites only a file of that name, and asks first"}
	}
	return Row{Choices: []Choice{c}, Sure: true}
}

// profileName makes a directory's base name a valid profile name: lower case,
// anything outside a-z, 0-9 and dash becomes a dash, no leading dash, at most
// 64 characters. "project" stands in when nothing is left.
func profileName(base string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	n := strings.TrimLeft(b.String(), "-")
	if len(n) > 64 {
		n = n[:64]
	}
	if n == "" {
		return "project"
	}
	return n
}

func descRow(t ingest.TargetFacts, target string, id Row) Row {
	name := filepath.Base(target)
	for _, l := range t.Languages {
		if l.Project != "" {
			name = path.Base(l.Project)
			break
		}
	}
	d := safe.Inline(name)
	if c := id.Choices[id.Suggested]; c.Label != NoIdentity {
		d += ", " + c.Label
	}
	return Row{Choices: []Choice{{Label: d, Why: "from project and identity"}}, Sure: true}
}

func baseRow(parentIsHome bool) Row {
	r := Row{Sure: true, Choices: []Choice{
		{Label: baseWithParent, Facts: []string{"@git is added when no identity profile is selected"}},
		{Label: baseWithout},
	}}
	if parentIsHome {
		r.Suggested = 1
		r.Choices[1].Why = "parent is your home"
		r.Choices[1].Facts = []string{"the target is directly under your home, so @parent-ro would make all of it readable"}
	}
	return r
}

func identityRow(f ingest.Facts) Row {
	r := Row{Sure: true, Choices: []Choice{{Label: NoIdentity}}}
	for _, p := range f.Profiles {
		if !p.Identity.Pins() || slices.ContainsFunc(r.Choices, func(c Choice) bool { return c.Label == p.Name }) {
			continue
		}
		r.Choices = append(r.Choices, Choice{Label: p.Name, Facts: []string{"defined in " + safe.Inline(p.File)}})
	}
	pick := ingest.Suggest(ingest.SuggestInput{Repo: f.Repo, SSH: f.SSH, Profiles: f.Profiles, GitSigningKey: f.GitSigningKey})
	switch {
	case pick == nil:
		r.Choices[0].Why = "no git remote"
	case len(pick.Conflict) >= 2:
		r.Choices[0].Why = strings.Join(pick.Conflict, " or ") + " — pick one"
	case pick.Profile.Value != "":
		i := slices.IndexFunc(r.Choices, func(c Choice) bool { return c.Label == pick.Profile.Value })
		if i < 0 {
			break
		}
		r.Suggested = i
		rm := pick.Remote
		r.Choices[i].Why = "remote " + safe.Inline(rm.Host+":"+rm.Owner+"/"+rm.Repo)
		r.Choices[i].Facts = append(r.Choices[i].Facts, safe.Inline(pick.Profile.Why))
	default:
		r.Choices[0].Why = "no profile of yours matches the remote"
	}
	return r
}

func agentRow(t ingest.TargetFacts) Row {
	r := Row{Sure: true, Choices: []Choice{{Label: "@claude"}, {Label: Off}}, Suggested: 1}
	if t.Claude {
		r.Suggested = 0
		r.Choices[0].Why = "CLAUDE.md found"
		r.Choices[0].Facts = []string{"the target has CLAUDE.md or a .claude directory"}
	}
	return r
}

func networkRow(p ingest.Proposal, agentOn bool) Row {
	r := Row{Sure: true, Choices: []Choice{{Label: "@net"}, {Label: Off}}, Suggested: 1}
	pickWhy := ""
	for _, pk := range p.Include {
		if pk.Name == "@net" {
			pickWhy = safe.Inline(pk.Why)
		}
	}
	switch {
	case agentOn:
		r.Suggested = 0
		r.Choices[0].Why = "@claude"
		r.Choices[0].Facts = []string{"@claude cannot work offline"}
		if pickWhy != "" {
			r.Choices[0].Why += ", " + pickWhy
			r.Choices[0].Facts = append(r.Choices[0].Facts, "also: "+pickWhy)
		}
	case pickWhy != "":
		r.Sure = false
		r.Choices[0].Why = pickWhy
		r.Choices[0].Facts = []string{"the target's files suggest fetching: " + pickWhy + "; only you know if the sandbox needs the internet"}
	}
	return r
}

func containersRow(p ingest.Proposal) Row {
	for _, pk := range p.Include {
		if pk.Name == "@podman-build" || pk.Name == "@podman-socket" {
			return Row{Sure: false, Suggested: 1, Choices: []Choice{
				{Label: pk.Name, Why: safe.Inline(pk.Why), Facts: []string{"found " + safe.Inline(pk.Why) + " in the target"}},
				{Label: Off},
			}}
		}
	}
	return Row{Sure: true, Choices: []Choice{{Label: Off}}}
}

func envRow(p ingest.Proposal) Row {
	if len(p.Env) == 0 {
		return Row{Sure: true, Choices: []Choice{{Label: Off}}}
	}
	var names, why []string
	var facts []string
	for _, h := range p.Env {
		names = append(names, h.Name)
		if !slices.Contains(why, h.Why) {
			why = append(why, h.Why)
		}
		facts = append(facts, h.Name+" -> "+h.Value+" ("+h.Why+")")
	}
	return Row{Sure: true, Choices: []Choice{
		{Label: strings.Join(names, " "), Why: safe.Inline(strings.Join(why, ", ")), Facts: facts},
		{Label: Off},
	}}
}

// Tools returns the TOOLS row's only choice for the current Identity pick: the
// profiles that identity profile already includes, other than built-ins. It is
// not a suggestion and is never stored in Pick; changing it means editing the
// identity profile's file, which the Facts name.
func (s Selection) Tools() Choice {
	id := s.Rows[Identity].Choices[s.Pick[Identity]]
	if id.Label == NoIdentity {
		return Choice{Label: Off}
	}
	for _, p := range s.profiles {
		if p.Name != id.Label {
			continue
		}
		var tools []string
		for _, inc := range p.Include {
			if !strings.HasPrefix(inc, "@") {
				tools = append(tools, inc)
			}
		}
		if len(tools) == 0 {
			return Choice{Label: Off, Facts: []string{"edit " + safe.Inline(filepath.Join(p.Dir, p.File)) + " to change what " + p.Name + " includes"}}
		}
		return Choice{
			Label: strings.Join(tools, " "),
			Why:   "from " + p.Name,
			Facts: []string{"included by " + p.Name + " in " + safe.Inline(filepath.Join(p.Dir, p.File)) + "; edit that file to change it"},
		}
	}
	return Choice{Label: Off}
}

// Changed reports whether row id differs from its suggestion. Tools never
// does: it follows Identity.
func (s Selection) Changed(id RowID) bool {
	switch id {
	case Name, Desc:
		return s.Text[id] != s.Rows[id].Choices[0].Label
	case Tools:
		return false
	}
	return s.Pick[id] != s.Rows[id].Suggested
}

// Revert returns a copy of s with row id back at its suggestion. s is not
// modified.
func (s Selection) Revert(id RowID) Selection {
	s.Pick, s.Text = maps.Clone(s.Pick), maps.Clone(s.Text)
	switch id {
	case Name, Desc:
		s.Text[id] = s.Rows[id].Choices[0].Label
	default:
		s.Pick[id] = s.Rows[id].Suggested
	}
	return s
}

// RevertAll returns a copy of s with every row back at its suggestion. s is
// not modified.
func (s Selection) RevertAll() Selection {
	for _, r := range s.Rows {
		s = s.Revert(r.ID)
	}
	return s
}

// Notes returns, per row, what the current choices conflict with. A note
// informs and refuses nothing: the choice stands.
func (s Selection) Notes() map[RowID]string {
	n := map[RowID]string{}
	if s.Pick[Agent] == 0 && s.Rows[Network].Choices[s.Pick[Network]].Label != "@net" {
		n[Network] = "@claude needs @net"
	}
	if s.parentIsHome && s.Rows[Base].Choices[s.Pick[Base]].Label == baseWithParent {
		n[Base] = "parent is your home"
	}
	return n
}
