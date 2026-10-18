package suggest

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
)

// Part is one switch of the IDENTITY submenu that is not a block pick: the
// signing key of the new identity profile, or the staging of the program a
// pinned block needs.
type Part int

const (
	PartSigning Part = iota
	PartGHBinary
)

// identityTool says that pinning block `block` needs the program `binary` in
// the sandbox, and which Part switches its staging.
type identityTool struct {
	block  Block
	binary string
	part   Part
}

// identityTools is the one table of programs an identity needs. @sys provides
// everything under /usr; a program anywhere else has to be staged, and this is
// what says which programs to look at.
//
// Abuse: a staged program is code the sandbox runs with the identity's
// credentials in reach. It is the host's own program found on the host's PATH,
// never a path the target names, and it is bound read-only at /snug/bin where
// the sandbox cannot replace it; it adds no authority beyond the credential
// already pinned.
var identityTools = []identityTool{{block: BlockGH, binary: "gh", part: PartGHBinary}}

// ToolBinaries returns the command names whose host location Suggest needs in
// Facts.Binaries.
func ToolBinaries() []string {
	var out []string
	for _, t := range identityTools {
		out = append(out, t.binary)
	}
	return out
}

const ghBinaryAbuse = "the sandbox can run every gh command the staged token authorises; the binary adds no authority of its own."

// hostIdentity is the new identity profile the host's facts describe: one
// part per block the host has, and the signing key beside them.
type hostIdentity struct {
	name string
	host string
	ssh  *hostPart
	git  *hostPart
	gh   *hostPart
	sign *hostPart
}

type hostPart struct {
	text string // the line without its reason
	why  string
	pub  string // ssh, signing: the .pub file
	a, b string // git: name, email; gh: user
}

func (h *hostIdentity) block(b Block) *hostPart {
	switch b {
	case BlockSSH:
		return h.ssh
	case BlockGit:
		return h.git
	case BlockGH:
		return h.gh
	}
	return nil
}

// newHostIdentity returns the identity pick describes, nil when it describes
// nothing worth a profile. Only a github.com remote is offered: identity.ssh
// and identity.gh default to github.com and the draft names another host in
// both blocks or neither, so a profile for any other host written from
// separately picked blocks could pin the key to the wrong host.
func newHostIdentity(f ingest.Facts, pick *ingest.IdentityPick, taken func(string) bool) *hostIdentity {
	if pick == nil || pick.Remote.Host != draft.GitHubHost {
		return nil
	}
	h := &hostIdentity{host: pick.Remote.Host}
	keyPath := func(stem string) string {
		for _, k := range f.Keys {
			if k.Stem == stem {
				return k.Path
			}
		}
		return ""
	}
	email, name := pick.Author.Value, pick.AuthorName
	sshPath, signPath := keyPath(pick.SSH.Value), keyPath(pick.Signing.Value)
	sshOK := pick.SSH.Value != "" && sshPath != ""
	gitOK := email != "" && draft.CheckAuthor(name, email) == nil
	if sshOK {
		h.ssh = &hostPart{text: "ssh " + h.host + " " + pick.SSH.Value, why: pick.SSH.Why, pub: sshPath}
	}
	if sshOK && gitOK && pick.Signing.Value != "" && signPath != "" {
		h.sign = &hostPart{text: "sign " + pick.Signing.Value, why: pick.Signing.Why, pub: signPath}
	}
	if gitOK {
		h.git = &hostPart{text: "git " + name + " <" + email + ">", why: pick.Author.Why, a: name, b: email}
	}
	if pick.GH.Value != "" {
		h.gh = &hostPart{text: "gh " + h.host + "/" + pick.GH.Value, why: pick.GH.Why, a: pick.GH.Value}
	}
	if h.ssh == nil && h.git == nil && h.gh == nil {
		return nil
	}
	h.name = uniqueName(identityBase(pick), taken)
	return h
}

// identityBase is the name the new profile would like: the gh login when it
// is a profile name, else the local part of the author's email, else the key.
func identityBase(pick *ingest.IdentityPick) string {
	if draft.ValidProfileName(pick.GH.Value) {
		return pick.GH.Value
	}
	local, _, _ := strings.Cut(pick.Author.Value, "@")
	for _, s := range []string{local, pick.SSH.Value} {
		if s != "" {
			return profileName(s)
		}
	}
	return "identity"
}

// uniqueName returns base, or base-2, base-3, ... for the first that is not
// taken. The result stays a valid profile name.
func uniqueName(base string, taken func(string) bool) string {
	n := base
	for i := 2; taken(n); i++ {
		suffix := "-" + strconv.Itoa(i)
		n = base
		if len(n)+len(suffix) > 64 {
			n = n[:64-len(suffix)]
		}
		n += suffix
	}
	return n
}

// PartOn reports whether part p is switched on.
func (s Selection) PartOn(p Part) bool { return s.Parts[p] }

// WithPart returns a copy of s with part p switched on or off. s is not
// modified.
func (s Selection) WithPart(p Part, on bool) Selection {
	s.Parts = maps.Clone(s.Parts)
	s.Parts[p] = on
	return s
}

type stagingKind int

const (
	stageNone stagingKind = iota
	// stageInclude: a profile of yours already stages the program; including
	// it is the suggestion.
	stageInclude
	// stageBinary: nothing does, and the draft stages the program itself.
	stageBinary
)

type staging struct {
	kind    stagingKind
	profile string // stageInclude
	spelled string // stageBinary: the host path as the profile spells it
	shown   string // stageBinary: the same, ~-shortened
}

// toolStaging says what tool t needs now. Nothing is needed when the block
// the tool serves has no effective source, the program is not on the host,
// resolves under /usr (which @sys binds), or is already staged by an included
// profile or one it includes.
func (s Selection) toolStaging(t identityTool) staging {
	b, ok := s.binaries[t.binary]
	if !ok || b.Resolved == "" || strings.HasPrefix(b.Resolved, "/usr/") {
		return staging{}
	}
	st := s.resolve(s.Block)
	if _, ok := st.eff[t.block]; !ok {
		return staging{}
	}
	var need []string
	for _, m := range st.members {
		if m.kind == srcProfile {
			need = append(need, m.name)
		}
	}
	for j := 0; j < len(need); j++ {
		for _, p := range s.profiles {
			if p.Name != need[j] {
				continue
			}
			if p.Stages(t.binary) {
				return staging{}
			}
			for _, inc := range p.Include {
				if !strings.HasPrefix(inc, "@") && !slices.Contains(need, inc) {
					need = append(need, inc)
				}
			}
		}
	}
	for _, p := range s.profiles {
		if p.Stages(t.binary) {
			return staging{kind: stageInclude, profile: p.Name}
		}
	}
	// The resolved path, not the one PATH names: snug refuses a grant that
	// resolves through a symlink the person owns, and its message says to grant
	// the destination instead.
	sg := staging{kind: stageBinary, spelled: b.Resolved, shown: b.Resolved}
	if s.home != "" && strings.HasPrefix(b.Resolved, s.home+"/") {
		sg.spelled = "{home}/" + strings.TrimPrefix(b.Resolved, s.home+"/")
		sg.shown = "~/" + strings.TrimPrefix(b.Resolved, s.home+"/")
	}
	return sg
}

func (t identityTool) line(st staging, shown string) string {
	switch st.kind {
	case stageInclude:
		return t.binary + " binary  include " + st.profile + ": it stages /snug/bin/" + t.binary + " (" + t.binary + " is not in /usr)"
	}
	return t.binary + " binary  " + shown + " → /snug/bin/" + t.binary + " (not in /usr)"
}

// IdentItem is one line of the IDENTITY submenu the cursor can reach: a
// source of a block, or a switch.
type IdentItem struct {
	Block Block
	// Choice is the index into BlockChoices(Block) of a source line; -1 on a
	// switch.
	Choice int
	// IsPart is false for a source line. Part, Text and On are meaningful only
	// when it is true.
	IsPart bool
	Part   Part
	Text   string
	On     bool
	// Why is the text `?` shows for this line.
	Why []string
}

// IdentityItems returns the submenu's reachable lines in order: per block,
// each source, the sign switch under git's FromHost source, and the staging
// switch of a tool whose block has an effective source. Every string is raw;
// the caller cleans it with safe.Inline before it reaches a screen.
func (s Selection) IdentityItems() []IdentItem {
	var out []IdentItem
	for _, b := range allBlocks {
		for i, src := range s.sources[b] {
			var why []string
			if src.Why != "" {
				why = append(why, src.Why)
			}
			why = append(why, src.Facts...)
			if src.kind == srcHost {
				why = append(why, "identity: "+draft.Abuse["identity"])
			}
			out = append(out, IdentItem{Block: b, Choice: i, Text: src.Label, Why: why})
			if b == BlockGit && src.kind == srcHost && s.host.sign != nil {
				p := s.host.sign
				out = append(out, IdentItem{Block: b, Choice: -1, IsPart: true, Part: PartSigning, Text: p.text + "  " + p.why, On: s.Parts[PartSigning], Why: []string{p.why, "identity: " + draft.Abuse["identity"]}})
			}
		}
		for _, t := range identityTools {
			st := s.toolStaging(t)
			if t.block != b || st.kind == stageNone {
				continue
			}
			w := []string{ghBinaryAbuse}
			if st.kind == stageInclude {
				w = append(w, "your profile "+st.profile+" stages it already; including it brings everything else that profile grants")
			}
			out = append(out, IdentItem{Block: b, Choice: -1, IsPart: true, Part: t.part, Text: t.line(st, st.shown), On: s.Parts[t.part], Why: w})
		}
	}
	return out
}

// newDescription is the description the new profile is written with.
func (s Selection) newDescription() string {
	var what []string
	pick := func(b Block) bool { return s.srcAt(b, s.Block).kind == srcHost }
	if pick(BlockSSH) {
		what = append(what, "its ssh key")
	}
	if pick(BlockGH) {
		what = append(what, "its gh token")
	}
	if pick(BlockGit) {
		what = append(what, "its git author")
		if s.host.sign != nil && s.Parts[PartSigning] {
			what = append(what, "its signing key")
		}
	}
	who := "GitHub identity " + s.host.name
	if pick(BlockGH) {
		who = "GitHub account " + s.host.gh.a
	}
	if len(what) == 0 {
		return who
	}
	return who + ": " + strings.Join(what, ", ") + "."
}

// BuildIdentity returns the draft of the identity profile the FromHost
// sources write, and nil when no block is picked from the host. It holds only
// the blocks picked from the host. The string is why the draft lacks the
// signing key the submenu shows switched on; "" when the draft is what the
// submenu says.
func BuildIdentity(s Selection, host draft.Host) (*draft.Draft, string) {
	if s.host == nil || !s.UsesHost() {
		return nil, ""
	}
	h := s.host
	d := draft.New(host)
	d.Name = h.name
	pick := func(b Block) bool { return s.srcAt(b, s.Block).kind == srcHost }
	if pick(BlockSSH) {
		d.SetSSH(h.ssh.pub)
	}
	if pick(BlockGit) {
		d.SetGit(h.git.a, h.git.b)
	}
	if pick(BlockGH) {
		d.SetGH(h.host, h.gh.a)
	}
	if pick(BlockGit) && h.sign != nil && s.Parts[PartSigning] && !d.SetSigningKey(h.sign.pub) {
		return d, signHostMsg
	}
	d.Description = s.newDescription()
	return d, ""
}
