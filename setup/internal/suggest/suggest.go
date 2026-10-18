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

	"github.com/gomoni/snug/setup/internal/hostfacts"
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
	Env
)

// Labels of the choices other code compares against.
const (
	// Off is the label of the "not selected" choice of a toggle row.
	Off = "—"
	// NoIdentity is the label of a block's "no source" choice, and the value
	// of the Identity row while no block has one.
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
	Suggested int // index into Choices
	// Name and Desc: one Choice, whose value is edited as text. Identity: one
	// Choice, whose label Current computes from Selection.Block.
	Choices []Choice
	// Sure is false for a pick that only the person can know the need for
	// (a toggle shown as an unfilled or filled circle); Suggested is then its
	// "off" choice.
	Sure bool
	// Cand is the choice an unsure row offers: shown as ○ while it is not
	// picked and ● when it is. Meaningful only when Sure is false.
	Cand int
}

// Selection is the person's current state; Rows hold the suggestions it is
// measured against. Copy it with Revert or RevertAll, never by assignment: the
// maps are shared by a plain copy.
type Selection struct {
	Rows []Row
	Pick map[RowID]int    // current choice per row
	Text map[RowID]string // Name and Desc, current text
	// Block is the picked source per identity block, an index into
	// BlockChoices; blockDefault and partsDefault are what Revert returns
	// Block and Parts to.
	Block map[Block]int
	// Parts are the switches of the IDENTITY submenu.
	Parts map[Part]bool

	profiles     []ingest.Profile
	env          []ingest.EnvHint
	parentIsHome bool
	netParts     []netPart
	sshHosts     []ingest.SSHHost
	gh           []hostfacts.GHAccount
	ghInstalled  bool
	descName     string
	home         string
	host         *hostIdentity
	sources      map[Block][]source
	blockDefault map[Block]int
	partsDefault map[Part]bool
	binaries     map[string]ingest.Binary
}

// netPart is one reason for @net and the row it depends on: it counts only
// while that row is on. hasVia is false for a reason the target's files give
// on their own.
type netPart struct {
	why    string
	via    RowID
	hasVia bool
}

// Suggest computes the Selection for the facts. home and target are the
// absolute, symlink-resolved paths snug will see.
//
// Abuse: the target chooses its remote, authors, file names and project names,
// so it can steer a row toward any value that already exists on the host and
// nowhere else. Each identity block offers the person's own profiles that pin
// it and FromHost, whose every value is one of the host's keys, gh
// logins or git author chosen by ingest.Suggest; the other rows offer built-in
// names. A name taken from the target reaches the screen only as a reason,
// through safe.Inline. Nothing the target says turns an unsure pick on.
func Suggest(f ingest.Facts, home, target string) Selection {
	s := Selection{
		Pick:         map[RowID]int{},
		Text:         map[RowID]string{},
		Parts:        map[Part]bool{},
		Block:        map[Block]int{},
		home:         home,
		binaries:     f.Binaries,
		profiles:     slices.Clone(f.Profiles),
		parentIsHome: filepath.Dir(target) == home,
		sshHosts:     f.SSH.Hosts,
		gh:           f.GH,
		ghInstalled:  f.GHInstalled,
	}
	prop := ingest.Propose(f.Target)
	s.env = prop.Env

	id := Row{Sure: true, Choices: []Choice{{Label: NoIdentity}}}
	s.sources, s.blockDefault, s.host = identitySources(f)
	s.Block = maps.Clone(s.blockDefault)
	if s.host != nil && s.host.sign != nil && s.srcAt(BlockSSH, s.Block).kind == srcHost && s.srcAt(BlockGit, s.Block).kind == srcHost {
		s.Parts[PartSigning] = true
	}
	for _, t := range identityTools {
		s.Parts[t.part] = true
	}
	s.partsDefault = maps.Clone(s.Parts)
	agent := agentRow(f.Target)
	s.netParts = []netPart{{why: "@claude", via: Agent, hasVia: true}}
	for _, r := range prop.NetReasons {
		s.netParts = append(s.netParts, netPart{why: safe.Inline(r.Why), via: Containers, hasVia: r.Via != ""})
	}
	rows := []Row{
		nameRow(f.Profiles, target),
		{},
		baseRow(s.parentIsHome),
		id,
		agent,
		networkRow(len(prop.NetReasons) > 0, agent.Suggested == 0),
		containersRow(prop),
		envRow(prop),
	}
	s.descName = descName(f.Target, target)
	rows[Desc] = Row{Choices: []Choice{{Label: s.derivedDesc(), Why: "from project and identity"}}, Sure: true}
	s.Rows = rows
	for i := range s.Rows {
		s.Rows[i].ID = RowID(i)
		s.Pick[RowID(i)] = s.Rows[i].Suggested
	}
	s.Text[Name] = rows[Name].Choices[0].Label
	s.Text[Desc] = rows[Desc].Choices[0].Label
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

func descName(t ingest.TargetFacts, target string) string {
	name := filepath.Base(target)
	for _, l := range t.Languages {
		if l.Project != "" {
			name = path.Base(l.Project)
			break
		}
	}
	return safe.Inline(name)
}

func (s Selection) descFor(identity string) string {
	if identity == "" {
		return s.descName
	}
	return s.descName + ", " + identity
}

// derivedDesc is the DESC text for the current identity: the name of the
// source of the first block that has one.
func (s Selection) derivedDesc() string {
	return s.descFor(s.resolve(s.Block).firstName())
}

func baseRow(parentIsHome bool) Row {
	r := Row{Sure: true, Choices: []Choice{
		{Label: baseWithParent},
		{Label: baseWithout},
	}}
	if parentIsHome {
		r.Suggested = 1
		r.Choices[1].Why = "parent is your home"
		r.Choices[1].Facts = []string{"the target is directly under your home, so @parent-ro would make all of it readable"}
	}
	return r
}

// identitySources returns, per block, the sources it can come from and the
// index suggested, and the identity FromHost writes. A block's sources are
// none, the profiles of yours that pin it, and FromHost when the host has the
// block. A profile that matches the remote is suggested for every block it
// pins and the other blocks get none. FromHost is suggested for every block
// the host has only when no profile of yours matches and the match is not a
// tie between two.
func identitySources(f ingest.Facts) (map[Block][]source, map[Block]int, *hostIdentity) {
	pick := ingest.Suggest(ingest.SuggestInput{Repo: f.Repo, SSH: f.SSH, Keys: f.Keys, Profiles: f.Profiles, Authors: f.Authors, GH: f.GH, GitSigningKey: f.GitSigningKey})
	taken := func(n string) bool {
		return slices.ContainsFunc(f.Profiles, func(p ingest.Profile) bool { return strings.EqualFold(p.Name, n) }) ||
			slices.ContainsFunc(f.Files, func(pf ingest.ProfileFile) bool { return strings.EqualFold(pf.Name, n+".toml") })
	}
	hi := newHostIdentity(f, pick, taken)
	noWhy := ""
	matched := ""
	noMatch := false
	switch {
	case pick == nil:
		noWhy = "no git remote"
	case len(pick.Conflict) >= 2:
		noWhy = strings.Join(pick.Conflict, " or ") + " — pick one"
	case pick.Profile.Value != "":
		matched = pick.Profile.Value
	default:
		noWhy = "no profile of yours matches the remote"
		noMatch = true
	}
	sources := map[Block][]source{}
	def := map[Block]int{}
	for _, b := range allBlocks {
		list := []source{{Choice: Choice{Label: NoIdentity, Why: noWhy}}}
		for _, p := range f.Profiles {
			if !pinned(p.Identity, b) || slices.ContainsFunc(list, func(c source) bool { return c.Label == p.Name }) {
				continue
			}
			c := source{Choice: Choice{Label: p.Name, Facts: []string{"defined in " + safe.Inline(p.File)}}, kind: srcProfile, name: p.Name}
			if p.Name == matched {
				rm := pick.Remote
				c.Why = "remote " + safe.Inline(rm.Host+":"+rm.Owner+"/"+rm.Repo)
				c.Facts = append(c.Facts, safe.Inline(pick.Profile.Why))
				def[b] = len(list)
			}
			list = append(list, c)
		}
		if hi != nil && hi.block(b) != nil {
			p := hi.block(b)
			c := source{Choice: Choice{Label: FromHost, Why: "from your host", Facts: []string{
				safe.Inline(strings.SplitN(p.text, " ", 2)[0] + ": " + p.why),
				"writes the profile " + safe.Inline(hi.name) + " beside the project's",
			}}, kind: srcHost, name: hi.name}
			if noMatch {
				def[b] = len(list)
			}
			list = append(list, c)
		}
		sources[b] = list
	}
	return sources, def, hi
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

func networkRow(fetches, agentOn bool) Row {
	r := Row{Sure: true, Choices: []Choice{{Label: "@net"}, {Label: Off}}, Suggested: 1}
	switch {
	case agentOn:
		r.Suggested = 0
	case fetches:
		r.Sure = false
	}
	return r
}

func containersRow(p ingest.Proposal) Row {
	r := Row{Sure: true, Suggested: 2, Choices: []Choice{{Label: "@podman-socket"}, {Label: "@podman-build"}, {Label: Off}}}
	for _, pk := range p.Include {
		i := slices.IndexFunc(r.Choices, func(c Choice) bool { return c.Label == pk.Name })
		if i < 0 || i == 2 {
			continue
		}
		r.Sure, r.Cand = false, i
		r.Choices[i].Why = safe.Inline(pk.Why)
		r.Choices[i].Facts = []string{"found " + safe.Inline(pk.Why) + " in the target"}
		break
	}
	return r
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

// Current returns the Choice row id shows now: its picked Choice, or, for an
// unsure row still at its suggestion, the candidate it offers, with the text
// of Name and Desc filled in. Identity's label is the summary of its blocks'
// effective sources. The Network choice names only the
// reasons whose source is on at the moment: no "container images" while
// Containers is off.
func (s Selection) Current(id RowID) Choice {
	switch id {
	case Name, Desc:
		c := s.Rows[id].Choices[0]
		c.Label = s.Text[id]
		return c
	}
	if id == Identity {
		return s.identityChoice()
	}
	r := s.Rows[id]
	c := r.Choices[s.Pick[id]]
	if !r.Sure && s.Pick[id] == r.Suggested {
		c = r.Choices[r.Cand]
	}
	if id == Network && c.Label == "@net" {
		c.Why, c.Facts = s.netReasons()
	}
	return c
}

func (s Selection) netReasons() (string, []string) {
	var whys, facts []string
	claude := false
	for _, p := range s.netParts {
		if p.hasVia && s.Rows[p.via].Choices[s.Pick[p.via]].Label == Off {
			continue
		}
		if !slices.Contains(whys, p.why) {
			whys = append(whys, p.why)
		}
		claude = claude || p.via == Agent && p.hasVia
	}
	for _, w := range whys {
		switch {
		case w == "@claude" && claude:
			facts = append(facts, "@claude cannot work offline")
		case claude:
			facts = append(facts, "also: "+w)
		default:
			facts = append(facts, "the target's files suggest fetching: "+w+"; only you know if the sandbox needs the internet")
		}
	}
	return strings.Join(whys, ", "), facts
}

// WithPick returns a copy of s with row id at choice i. Identity has no
// choices to pick; WithBlock picks its sources. s is not modified.
func (s Selection) WithPick(id RowID, i int) Selection {
	s.Pick = maps.Clone(s.Pick)
	s.Pick[id] = i
	return s
}

// WithText returns a copy of s with the text of row id (Name or Desc) set. s
// is not modified.
func (s Selection) WithText(id RowID, text string) Selection {
	s.Text = maps.Clone(s.Text)
	s.Text[id] = text
	return s
}

// Changed reports whether row id differs from its suggestion. Desc differs from the text derived from the
// current identity, not from the one at the start. Identity differs when a
// block's source or a switch is not what it was suggested.
func (s Selection) Changed(id RowID) bool {
	switch id {
	case Name:
		return s.Text[id] != s.Rows[id].Choices[0].Label
	case Desc:
		return s.Text[id] != s.derivedDesc()
	}
	if id == Identity {
		return !maps.Equal(s.Block, s.blockDefault) || !maps.Equal(s.Parts, s.partsDefault)
	}
	return s.Pick[id] != s.Rows[id].Suggested
}

// Revert returns a copy of s with row id back at its suggestion. s is not
// modified.
func (s Selection) Revert(id RowID) Selection {
	switch id {
	case Name:
		return s.WithText(id, s.Rows[id].Choices[0].Label)
	case Desc:
		return s.WithText(id, s.derivedDesc())
	}
	if id == Identity {
		follow := s.Text[Desc] == s.derivedDesc()
		s.Block, s.Parts, s.Text = maps.Clone(s.blockDefault), maps.Clone(s.partsDefault), maps.Clone(s.Text)
		if follow {
			s.Text[Desc] = s.derivedDesc()
		}
		return s
	}
	return s.WithPick(id, s.Rows[id].Suggested)
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

// IdentityDetail returns the read-only lines the IDENTITY submenu shows under
// source i of block b: what that profile pins in the block, as written in its
// file, for ssh the ~/.ssh/config Host block that gives the pinned host its
// key, for git the signing key, and for gh the profiles it includes other
// than built-ins. Nothing is opened; a hostile value cannot reach the screen
// except through safe.Inline.
func (s Selection) IdentityDetail(b Block, i int) []string {
	src := s.sources[b][i]
	switch src.kind {
	case srcNone:
		return []string{map[Block]string{
			BlockSSH: "no ssh key in the sandbox",
			BlockGit: "no git author in the sandbox",
			BlockGH:  "no gh login in the sandbox",
		}[b]}
	case srcHost:
		return []string{safe.Inline(identityLine(s.hostShown(map[Block]int{b: i}), b))}
	}
	pi := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == src.name })
	if pi < 0 {
		return nil
	}
	p := s.profiles[pi]
	id := p.Identity
	var out []string
	switch b {
	case BlockSSH:
		out = append(out, "ssh   "+safe.Inline(identityLine(id, b)))
		host := id.SSHHost
		if host == "" {
			host = "github.com"
		}
		if stem, pats := ingest.MatchHost(s.sshHosts, host); stem != "" {
			cfg := "      ~/.ssh/config  Host "
			if pats != "" {
				cfg += safe.Inline(pats) + "  "
			}
			out = append(out, cfg+"→ "+safe.Inline(stem))
		}
	case BlockGit:
		if id.GitName != "" || id.Email != "" {
			out = append(out, "git   "+safe.Inline(identityLine(id, b)))
		}
		if id.SigningKey != "" {
			out = append(out, "sign  "+safe.Inline(keyStem(id.SigningKey)))
		}
	case BlockGH:
		out = append(out, "gh    "+safe.Inline(identityLine(id, b)))
		var tools []string
		for _, inc := range p.Include {
			if !strings.HasPrefix(inc, "@") {
				tools = append(tools, inc)
			}
		}
		if len(tools) > 0 {
			out = append(out, "also includes: "+safe.Inline(strings.Join(tools, " ")))
		}
	}
	return out
}

func keyStem(p string) string {
	return strings.TrimSuffix(path.Base(p), ".pub")
}

// IdentityWarning returns what the host's own gh says against the effective
// gh source, "" when nothing: the profile pins a gh login that `gh auth
// status` does not list, or gh is not installed so the login was not checked.
// It is a fact about the host, found without snug, and refuses nothing.
func (s Selection) IdentityWarning() string {
	e, ok := s.resolve(s.Block).eff[BlockGH]
	if !ok || e.kind != srcProfile {
		return ""
	}
	return s.ghWarning(e.name)
}

// SourceWarning is IdentityWarning for source i of block b: only a profile in
// the gh section can have one.
func (s Selection) SourceWarning(b Block, i int) string {
	if b != BlockGH {
		return ""
	}
	if src := s.sources[b][i]; src.kind == srcProfile {
		return s.ghWarning(src.name)
	}
	return ""
}

func (s Selection) ghWarning(name string) string {
	pi := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == name })
	if pi < 0 || s.profiles[pi].Identity.GHUser == "" {
		return ""
	}
	id := s.profiles[pi].Identity
	if !s.ghInstalled {
		return safe.Inline("gh not on PATH: " + name + "'s gh login not checked")
	}
	host := id.GHHost
	if host == "" {
		host = "github.com"
	}
	if slices.ContainsFunc(s.gh, func(a hostfacts.GHAccount) bool {
		return strings.EqualFold(a.Host, host) && a.User == id.GHUser
	}) {
		return ""
	}
	return safe.Inline(name + ": gh not logged in as " + id.GHUser + " on " + host + " — gh auth login --hostname " + host)
}
