package suggest

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/safe"
)

// FromHost is the label of the source that writes a block into the one new
// identity profile made from what the host says.
const FromHost = "from host"

// Block is one identity block of a snug profile. Each is its own pin: snug
// refuses two selected profiles that set the same block differently, and lets
// different blocks come from different profiles. The values are the blocks'
// order on screen.
type Block int

const (
	BlockSSH Block = iota
	BlockGit
	BlockGH
)

var allBlocks = [...]Block{BlockSSH, BlockGit, BlockGH}

// String returns the block's key under identity in a profile.
func (b Block) String() string {
	if b < 0 || int(b) >= len(allBlocks) {
		return fmt.Sprintf("block(%d)", int(b))
	}
	return [...]string{"ssh", "git", "gh"}[b]
}

type sourceKind int

const (
	srcNone sourceKind = iota
	srcProfile
	srcHost
)

// source is one thing a block can come from: nothing, a profile of the
// person's, or the new profile made from the host.
type source struct {
	Choice
	kind sourceKind
	name string // the profile's name; the new profile's name for srcHost
}

// pinValue is what a block holds, comparable the way snug compares blocks.
type pinValue [3]string

// member is one profile in the included set: its name and what it pins.
type member struct {
	name string
	kind sourceKind
	id   ingest.ProfileIdentity
}

// effective is the source a block really comes from.
type effective struct {
	name   string
	kind   sourceKind
	locked bool // the pick is none, and this profile is included for another block
}

// idState is the result of folding the picks the way snug folds the selected
// profiles.
type idState struct {
	members  []member
	eff      map[Block]effective
	problems map[Block][]string
}

func (s Selection) srcAt(b Block, picks map[Block]int) source {
	list := s.sources[b]
	if i := picks[b]; i >= 0 && i < len(list) {
		return list[i]
	}
	return source{Choice: Choice{Label: NoIdentity}}
}

// normPath expands the {home} spelling so a profile's key path and the host's
// absolute path compare equal when they name the same file.
func (s Selection) normPath(p string) string {
	if p == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(p, "{home}"); ok && s.home != "" {
		p = s.home + rest
	}
	return filepath.Clean(p)
}

func normHost(h string) string {
	if h == "" {
		return draft.GitHubHost
	}
	return h
}

// pinned reports whether id sets block b.
func pinned(id ingest.ProfileIdentity, b Block) bool {
	switch b {
	case BlockSSH:
		return id.SSHKey != "" || id.SSHHost != ""
	case BlockGit:
		return id.GitName != "" || id.Email != "" || id.SigningKey != ""
	case BlockGH:
		return id.GHUser != "" || id.GHHost != ""
	}
	return false
}

func (s Selection) blockValue(id ingest.ProfileIdentity, b Block) pinValue {
	switch b {
	case BlockSSH:
		return pinValue{s.normPath(id.SSHKey), normHost(id.SSHHost)}
	case BlockGit:
		return pinValue{id.GitName, id.Email, s.normPath(id.SigningKey)}
	case BlockGH:
		return pinValue{id.GHUser, normHost(id.GHHost)}
	}
	return pinValue{}
}

// hostPins is what the new identity profile would set: only the blocks picked
// from the host.
func (s Selection) hostPins(picks map[Block]int) ingest.ProfileIdentity {
	var id ingest.ProfileIdentity
	h := s.host
	if h == nil {
		return id
	}
	if p := h.block(BlockSSH); p != nil && s.srcAt(BlockSSH, picks).kind == srcHost {
		id.SSHKey, id.SSHHost = p.pub, h.host
	}
	if p := h.block(BlockGit); p != nil && s.srcAt(BlockGit, picks).kind == srcHost {
		id.GitName, id.Email = p.a, p.b
		if h.sign != nil && s.Parts[PartSigning] {
			id.SigningKey = h.sign.pub
		}
	}
	if p := h.block(BlockGH); p != nil && s.srcAt(BlockGH, picks).kind == srcHost {
		id.GHUser, id.GHHost = p.a, h.host
	}
	return id
}

const signHostMsg = "sign needs the ssh and git parts on as well; switch them on, or sign off"

// resolve folds picks the way snug folds the selected profiles: the included
// set is every profile picked in any block, each block is compared across the
// members that set it, and a block picked none comes from the one profile that
// sets it, if there is one. Including a profile is never a subtraction, so a
// none pick does not remove another profile's pin.
func (s Selection) resolve(picks map[Block]int) idState {
	st := idState{eff: map[Block]effective{}, problems: map[Block][]string{}}
	for _, b := range allBlocks {
		src := s.srcAt(b, picks)
		if src.kind == srcNone || slices.ContainsFunc(st.members, func(m member) bool { return m.name == src.name }) {
			continue
		}
		m := member{name: src.name, kind: src.kind}
		if src.kind == srcHost {
			m.id = s.hostPins(picks)
		} else if i := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == src.name }); i >= 0 {
			m.id = s.profiles[i].Identity
		}
		st.members = append(st.members, m)
	}
	for _, b := range allBlocks {
		var owners []member
		for _, m := range st.members {
			if pinned(m.id, b) {
				owners = append(owners, m)
			}
		}
		conflict := false
		if len(owners) > 1 {
			sorted := slices.Clone(owners)
			slices.SortFunc(sorted, func(x, y member) int { return strings.Compare(x.name, y.name) })
			first := sorted[0]
			for _, o := range sorted[1:] {
				if s.blockValue(o.id, b) != s.blockValue(first.id, b) {
					st.problems[b] = append(st.problems[b], fmt.Sprintf("profiles %q and %q pin different identity.%s", first.name, o.name, b))
					conflict = true
					break
				}
			}
		}
		switch src := s.srcAt(b, picks); {
		case src.kind != srcNone:
			st.eff[b] = effective{name: src.name, kind: src.kind}
		case !conflict && len(owners) > 0:
			st.eff[b] = effective{name: owners[0].name, kind: owners[0].kind, locked: true}
		}
	}
	if g, ok := st.eff[BlockGit]; ok {
		m := st.member(g.name)
		if m.id.SigningKey != "" && !pinned(m.id, BlockSSH) {
			msg := fmt.Sprintf("profile %q: signing_key needs identity.ssh from the same profile", g.name)
			if g.kind == srcHost {
				msg = signHostMsg
			}
			st.problems[BlockGit] = append(st.problems[BlockGit], msg)
		}
	}
	return st
}

func (st idState) member(name string) member {
	for _, m := range st.members {
		if m.name == name {
			return m
		}
	}
	return member{}
}

// message returns every problem of the state, in block order.
func (st idState) message() string {
	var out []string
	for _, b := range allBlocks {
		out = append(out, st.problems[b]...)
	}
	return strings.Join(out, "; ")
}

func (st idState) usesHost() bool {
	return slices.ContainsFunc(st.members, func(m member) bool { return m.kind == srcHost })
}

// firstName is the name of the first block's effective source, "" for none.
func (st idState) firstName() string {
	for _, b := range allBlocks {
		if e, ok := st.eff[b]; ok {
			return e.name
		}
	}
	return ""
}

// summary is the IDENTITY row's value: none, the one profile every pinned
// block comes from, or the blocks with their sources.
func (st idState) summary() string {
	var parts []string
	same := true
	first := ""
	for _, b := range allBlocks {
		e, ok := st.eff[b]
		if !ok {
			continue
		}
		parts = append(parts, b.String()+" "+e.name)
		if first == "" {
			first = e.name
		} else if e.name != first {
			same = false
		}
	}
	switch {
	case len(parts) == 0:
		return NoIdentity
	case same:
		return first
	}
	return strings.Join(parts, ", ")
}

// Effective returns the name of the profile block b comes from and whether the
// pick is none, the profile being included for another block. The name is ""
// when nothing sets the block.
func (s Selection) Effective(b Block) (name string, locked bool) {
	e := s.resolve(s.Block).eff[b]
	return e.name, e.locked
}

// BlockChoices returns the sources block b can come from, in order: none, the
// profiles of yours that pin it, then FromHost when the host describes it.
func (s Selection) BlockChoices(b Block) []Choice {
	out := make([]Choice, len(s.sources[b]))
	for i, src := range s.sources[b] {
		out[i] = src.Choice
	}
	return out
}

// BlockSuggested is the index of the source suggested for block b.
func (s Selection) BlockSuggested(b Block) int { return s.blockDefault[b] }

// Locked returns, for a block picked none but set by an included profile, the
// profile and the value it pins; ok is false otherwise.
func (s Selection) Locked(b Block) (name, value string, ok bool) {
	e := s.resolve(s.Block).eff[b]
	if !e.locked {
		return "", "", false
	}
	return e.name, safe.Inline(s.pinText(e.name, e.kind, b)), true
}

// pinText is the one-line value profile name pins in block b.
func (s Selection) pinText(name string, kind sourceKind, b Block) string {
	var id ingest.ProfileIdentity
	if kind == srcHost {
		id = s.hostPins(s.Block)
	} else if i := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == name }); i >= 0 {
		id = s.profiles[i].Identity
	}
	return identityLine(id, b)
}

func identityLine(id ingest.ProfileIdentity, b Block) string {
	switch b {
	case BlockSSH:
		var parts []string
		if id.SSHHost != "" {
			parts = append(parts, id.SSHHost)
		}
		if id.SSHKey != "" {
			parts = append(parts, keyStem(id.SSHKey))
		}
		return strings.Join(parts, "  ")
	case BlockGit:
		who := id.GitName
		if id.Email != "" {
			who = strings.TrimSpace(who + " <" + id.Email + ">")
		}
		return who
	case BlockGH:
		if id.GHHost != "" {
			return id.GHHost + "/" + id.GHUser
		}
		return id.GHUser
	}
	return ""
}

// BlockProblem returns what snug would refuse if block b came from choice i,
// "" when nothing. Other blocks stay as picked.
func (s Selection) BlockProblem(b Block, i int) string {
	picks := maps.Clone(s.Block)
	picks[b] = i
	return strings.Join(s.resolve(picks).problems[b], "; ")
}

// WithBlock returns a copy of s with block b coming from choice i. DESC
// follows as long as its text is still the one derived from the identity. s is
// not modified.
func (s Selection) WithBlock(b Block, i int) Selection {
	follow := s.Text[Desc] == s.derivedDesc()
	s.Block, s.Text = maps.Clone(s.Block), maps.Clone(s.Text)
	s.Block[b] = i
	if follow {
		s.Text[Desc] = s.derivedDesc()
	}
	return s
}

// Included returns the names of the profiles the project profile would
// include for the identity: every profile picked in any block, the new one
// from the host last.
func (s Selection) Included() []string {
	var out []string
	st := s.resolve(s.Block)
	for _, m := range st.members {
		if m.kind == srcProfile {
			out = append(out, m.name)
		}
	}
	for _, m := range st.members {
		if m.kind == srcHost {
			out = append(out, m.name)
		}
	}
	return out
}

// IdentityProfile returns the first profile Included names, "" for none.
func (s Selection) IdentityProfile() string {
	if in := s.Included(); len(in) > 0 {
		return in[0]
	}
	return ""
}

// UsesHost reports whether any block is picked FromHost.
func (s Selection) UsesHost() bool { return s.resolve(s.Block).usesHost() }

// identityChoice is the Choice the Identity row shows: the summary, why the
// first block's source was picked, and one fact per block.
func (s Selection) identityChoice() Choice {
	st := s.resolve(s.Block)
	c := Choice{Label: st.summary()}
	var hostBlocks []string
	for _, b := range allBlocks {
		e, ok := st.eff[b]
		if !ok {
			continue
		}
		line := b.String() + ": " + e.name
		if e.locked {
			line += " (included for another block; none does not remove it)"
		}
		c.Facts = append(c.Facts, safe.Inline(line))
		if e.kind == srcHost {
			hostBlocks = append(hostBlocks, b.String())
		}
	}
	switch {
	case len(hostBlocks) > 0:
		c.Why = "from your host: " + strings.Join(hostBlocks, " ")
	case len(st.eff) > 0:
		c.Why = s.firstWhy(st)
	default:
		c.Why = s.sources[BlockSSH][0].Why
	}
	seen := map[string]bool{}
	for _, b := range allBlocks {
		e, ok := st.eff[b]
		if !ok || seen[e.name] {
			continue
		}
		seen[e.name] = true
		for _, src := range s.sources[b] {
			if src.name == e.name {
				c.Facts = append(c.Facts, src.Facts...)
				break
			}
		}
	}
	return c
}

// firstWhy is the reason of the first effective profile that carries one.
func (s Selection) firstWhy(st idState) string {
	for _, b := range allBlocks {
		e, ok := st.eff[b]
		if !ok {
			continue
		}
		for _, src := range s.sources[b] {
			if src.name == e.name && src.Why != "" {
				return src.Why
			}
		}
	}
	return ""
}
