package suggest

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

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

// member is one profile of the expanded set: a profile picked in some block,
// or one an included profile pulls in. snug expands includes transitively
// before the identity fold, so an inherited block joins it as if picked.
type member struct {
	name string
	kind sourceKind
	id   ingest.ProfileIdentity
	via  string // the picked profile that includes this one; "" for a picked one
}

// effective is the source a block really comes from.
type effective struct {
	name   string
	kind   sourceKind
	via    string // locked or inherited: the picked profile that includes name
	locked bool   // the pick is none, and this profile is in the expanded set for another block
}

type problem struct {
	block Block
	msg   string
}

// idState is the result of folding the picks the way snug folds the selected
// profiles.
type idState struct {
	members  []member
	eff      map[Block]effective
	problems []problem
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

// agentOf is identity.ssh.agent as snug normalises it: "proxy", or "" for
// none and for an absent key. ok is false for a value snug refuses.
func agentOf(raw string) (agent string, ok bool) {
	switch raw {
	case "proxy":
		return "proxy", true
	case "none", "":
		return "", true
	}
	return raw, false
}

// pinned reports whether id sets block b, the way snug reads a block: a block
// with any field set is pinned, and an ssh block holding only agent = "none"
// is not.
func pinned(id ingest.ProfileIdentity, b Block) bool {
	switch b {
	case BlockSSH:
		a, _ := agentOf(id.SSHAgent)
		return id.SSHKey != "" || id.SSHHost != "" || a != ""
	case BlockGit:
		return id.GitName != "" || id.Email != "" || id.SigningKey != ""
	case BlockGH:
		return id.GHUser != "" || id.GHHost != ""
	}
	return false
}

// blockValue is the whole normalised block, compared the way resolve.go
// compares: every field, hosts as written.
func (s Selection) blockValue(id ingest.ProfileIdentity, b Block) pinValue {
	switch b {
	case BlockSSH:
		a, _ := agentOf(id.SSHAgent)
		return pinValue{s.normPath(id.SSHKey), id.SSHHost, a}
	case BlockGit:
		return pinValue{id.GitName, id.Email, s.normPath(id.SigningKey)}
	case BlockGH:
		return pinValue{id.GHUser, id.GHHost}
	}
	return pinValue{}
}

// hostPins is what the new identity profile would set: only the blocks picked
// from the host. It names no host, because draft.Render writes none for
// github.com. The signing key is written only with ssh also from the host.
func (s Selection) hostPins(picks map[Block]int) ingest.ProfileIdentity {
	var id ingest.ProfileIdentity
	h := s.host
	if h == nil {
		return id
	}
	isHost := func(b Block) bool { return s.srcAt(b, picks).kind == srcHost }
	if p := h.block(BlockSSH); p != nil && isHost(BlockSSH) {
		id.SSHKey, id.SSHAgent = p.pub, "proxy"
	}
	if p := h.block(BlockGit); p != nil && isHost(BlockGit) {
		id.GitName, id.Email = p.a, p.b
		if h.sign != nil && s.Parts[PartSigning] && isHost(BlockSSH) {
			id.SigningKey = h.sign.pub
		}
	}
	if p := h.block(BlockGH); p != nil && isHost(BlockGH) {
		id.GHUser = p.a
	}
	return id
}

// resolve folds picks the way snug folds the selected profiles: the picked
// profiles and everything they include transitively are the set, each block is
// compared across the members that set it, and a block picked none comes from
// the one profile that sets it, if there is one. Including a profile is never
// a subtraction, so a none pick does not remove another profile's pin.
//
// Rules that read two blocks run on the merged identity, as resolve.go's
// refuseSigningWithoutAgent and refuseHalfNamedHost do. Not modelled:
// refuseUnprincipledSigningEmail, refuseUnhostlikeHost,
// refuseUnpinnedGhAccount, the text and key-path checks of Identity.CheckText,
// and an include of a profile that is not one of the person's own.
func (s Selection) resolve(picks map[Block]int) idState {
	st := idState{eff: map[Block]effective{}}
	add := func(name string, kind sourceKind, via string) {
		if slices.ContainsFunc(st.members, func(m member) bool { return m.name == name }) {
			return
		}
		m := member{name: name, kind: kind, via: via}
		if kind == srcHost {
			m.id = s.hostPins(picks)
		} else if i := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == name }); i >= 0 {
			m.id = s.profiles[i].Identity
		}
		st.members = append(st.members, m)
	}
	for _, b := range allBlocks {
		if src := s.srcAt(b, picks); src.kind != srcNone {
			add(src.name, src.kind, "")
		}
	}
	for n := 0; n < len(st.members); n++ {
		m := st.members[n]
		if m.kind != srcProfile {
			continue
		}
		root := m.via
		if root == "" {
			root = m.name
		}
		if i := slices.IndexFunc(s.profiles, func(p ingest.Profile) bool { return p.Name == m.name }); i >= 0 {
			for _, inc := range s.profiles[i].Include {
				if !strings.HasPrefix(inc, "@") {
					add(inc, srcProfile, root)
				}
			}
		}
	}
	owners := map[Block][]member{}
	for _, b := range allBlocks {
		for _, m := range st.members {
			if pinned(m.id, b) {
				owners[b] = append(owners[b], m)
			}
		}
		slices.SortStableFunc(owners[b], func(x, y member) int { return strings.Compare(x.name, y.name) })
	}
	conflict := map[Block]bool{}
	for _, b := range allBlocks {
		if o := owners[b]; len(o) > 1 {
			for _, other := range o[1:] {
				if s.blockValue(other.id, b) != s.blockValue(o[0].id, b) {
					st.problems = append(st.problems, problem{b, fmt.Sprintf("profiles %q and %q pin different identity.%s", o[0].name, other.name, b)})
					conflict[b] = true
					break
				}
			}
		}
		for _, m := range owners[b] {
			if _, ok := agentOf(m.id.SSHAgent); b == BlockSSH && !ok {
				st.problems = append(st.problems, problem{b, fmt.Sprintf("profile %q: unknown identity.ssh.agent %q (want proxy or none)", m.name, m.id.SSHAgent)})
			}
		}
		switch src := s.srcAt(b, picks); {
		case src.kind != srcNone:
			st.eff[b] = effective{name: src.name, kind: src.kind}
		case !conflict[b] && len(owners[b]) > 0:
			var first member
			for _, m := range st.members {
				if pinned(m.id, b) {
					first = m
					break
				}
			}
			st.eff[b] = effective{name: first.name, kind: first.kind, via: first.via, locked: true}
		}
	}
	st.crossBlock(owners)
	return st
}

// crossBlock applies the two rules that read more than one block.
func (st *idState) crossBlock(owners map[Block][]member) {
	git, ssh, gh := owners[BlockGit], owners[BlockSSH], owners[BlockGH]
	if len(git) > 0 && git[0].id.SigningKey != "" {
		agent, _ := agentOf("")
		if len(ssh) > 0 {
			agent, _ = agentOf(ssh[0].id.SSHAgent)
		}
		switch {
		case agent == "":
			who := "no selected profile sets identity.ssh"
			if len(ssh) > 0 {
				who = fmt.Sprintf("profile %q sets identity.ssh with no agent", ssh[0].name)
			}
			st.problems = append(st.problems, problem{BlockGit, fmt.Sprintf("profile %q: identity.git.signing_key needs identity.ssh.agent = \"proxy\", and %s", git[0].name, who)})
		case !slices.ContainsFunc(git, func(g member) bool {
			return slices.ContainsFunc(ssh, func(x member) bool { return x.name == g.name })
		}):
			st.problems = append(st.problems, problem{BlockGit, fmt.Sprintf("profiles %q and %q: identity.git.signing_key needs identity.ssh from the same profile", git[0].name, ssh[0].name)})
		}
	}
	if len(ssh) == 0 && len(gh) == 0 {
		return
	}
	var sshKey, sshHost, sshAgent, ghUser, ghHost string
	if len(ssh) > 0 {
		sshKey, sshHost = ssh[0].id.SSHKey, ssh[0].id.SSHHost
		sshAgent, _ = agentOf(ssh[0].id.SSHAgent)
	}
	if len(gh) > 0 {
		ghUser, ghHost = gh[0].id.GHUser, gh[0].id.GHHost
	}
	sshActive := sshKey != "" || sshAgent != ""
	ghActive := ghUser != "" || ghHost != ""
	switch {
	case ghHost != "" && sshHost == "" && sshActive:
		st.problems = append(st.problems, problem{BlockGH, halfNamed(gh[0].name, ssh[0].name, "gh", ghHost, "ssh")})
	case sshHost != "" && ghHost == "" && ghActive:
		other := ssh[0].name
		if len(gh) > 0 {
			other = gh[0].name
		}
		st.problems = append(st.problems, problem{BlockSSH, halfNamed(ssh[0].name, other, "ssh", sshHost, "gh")})
	}
}

// halfNamed is resolve.go's halfNamedHost, shortened: one block names a host
// and the other does not, and nothing is inherited between blocks.
func halfNamed(named, missingOwner, block, host, missing string) string {
	who := fmt.Sprintf("profile %q", named)
	if missingOwner != named {
		who = fmt.Sprintf("profiles %q and %q", named, missingOwner)
	}
	return fmt.Sprintf("%s: identity.%s.host = %q names a host and identity.%s.host does not; name it in both", who, block, host, missing)
}

func (st idState) member(name string) member {
	for _, m := range st.members {
		if m.name == name {
			return m
		}
	}
	return member{}
}

// message returns every problem of the state.
func (st idState) message() string {
	var out []string
	for _, p := range st.problems {
		out = append(out, p.msg)
	}
	return strings.Join(out, "; ")
}

// blockMessage returns the problems keyed to block b.
func (st idState) blockMessage(b Block) string {
	var out []string
	for _, p := range st.problems {
		if p.block == b {
			out = append(out, p.msg)
		}
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

// Locked returns, for a block picked none but set by a profile of the
// expanded set, that profile, the picked profile that includes it ("" when the
// profile was picked itself), and the value it pins; ok is false otherwise.
func (s Selection) Locked(b Block) (name, via, value string, ok bool) {
	e := s.resolve(s.Block).eff[b]
	if !e.locked {
		return "", "", "", false
	}
	return e.name, e.via, safe.Inline(s.pinText(e.name, e.kind, b)), true
}

// hostShown is hostPins with the host written out, for the screen.
func (s Selection) hostShown(picks map[Block]int) ingest.ProfileIdentity {
	id := s.hostPins(picks)
	if id.SSHKey != "" {
		id.SSHHost = s.host.host
	}
	if id.GHUser != "" {
		id.GHHost = s.host.host
	}
	return id
}

// pinText is the one-line value profile name pins in block b.
func (s Selection) pinText(name string, kind sourceKind, b Block) string {
	var id ingest.ProfileIdentity
	if kind == srcHost {
		id = s.hostShown(s.Block)
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
// "" when nothing. For the picked choice that is every problem keyed to the
// block now; for any other it is the problems the pick would add, in any
// block, so a line is marked for the conflict it would cause.
func (s Selection) BlockProblem(b Block, i int) string {
	cur := s.resolve(s.Block)
	if i == s.Block[b] {
		return cur.blockMessage(b)
	}
	picks := maps.Clone(s.Block)
	picks[b] = i
	var out []string
	for _, p := range s.resolve(picks).problems {
		if !slices.ContainsFunc(cur.problems, func(q problem) bool { return q.msg == p.msg }) {
			out = append(out, p.msg)
		}
	}
	return strings.Join(out, "; ")
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
// from the host last. A profile only an included one pulls in is not listed;
// snug expands it from the include.
func (s Selection) Included() []string {
	var out []string
	st := s.resolve(s.Block)
	for _, m := range st.members {
		if m.kind == srcProfile && m.via == "" {
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
			line += " (in the profile set for another block; none does not remove it)"
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
