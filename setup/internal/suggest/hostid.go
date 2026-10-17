package suggest

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
)

// NewFromHost is the label of the Identity choice that writes an identity
// profile of its own, made from what the host says, beside the project's.
const NewFromHost = "new from host"

// Part is one switch inside an Identity choice: a piece of the new identity
// profile, or the staging of the program a pinned part needs. The order of the
// identity parts is the order of their lines.
type Part int

const (
	PartSSH Part = iota
	PartSigning
	PartGit
	PartGH
	PartGHBinary
)

// identityTool says that pinning identity part `pinned` needs the program
// `binary` in the sandbox, and which Part switches its staging.
type identityTool struct {
	pinned Part
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
var identityTools = []identityTool{{pinned: PartGH, binary: "gh", part: PartGHBinary}}

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

// hostIdentity is the new identity profile the host's facts describe.
type hostIdentity struct {
	name  string
	host  string
	parts []hostPart
}

type hostPart struct {
	id   Part
	text string // the line without its reason
	why  string
	pub  string // ssh, signing: the .pub file
	a, b string // git: name, email; gh: user
}

// newHostIdentity returns the identity pick describes, nil when it describes
// nothing worth a profile. Only a github.com remote is offered: identity.ssh
// and identity.gh default to github.com and the draft names another host in
// both blocks or neither, so a profile for any other host written from
// separately toggled parts could pin the key to the wrong host.
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
		h.parts = append(h.parts, hostPart{id: PartSSH, text: "ssh " + h.host + " " + pick.SSH.Value, why: pick.SSH.Why, pub: sshPath})
	}
	if sshOK && gitOK && pick.Signing.Value != "" && signPath != "" {
		h.parts = append(h.parts, hostPart{id: PartSigning, text: "sign " + pick.Signing.Value, why: pick.Signing.Why, pub: signPath})
	}
	if gitOK {
		h.parts = append(h.parts, hostPart{id: PartGit, text: "git " + name + " <" + email + ">", why: pick.Author.Why, a: name, b: email})
	}
	if pick.GH.Value != "" {
		h.parts = append(h.parts, hostPart{id: PartGH, text: "gh " + h.host + "/" + pick.GH.Value, why: pick.GH.Why, a: pick.GH.Value})
	}
	if len(h.parts) == 0 {
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

func (h *hostIdentity) part(id Part) (hostPart, bool) {
	for _, p := range h.parts {
		if p.id == id {
			return p, true
		}
	}
	return hostPart{}, false
}

func (s Selection) picksNew() bool { return s.isNew(s.Pick[Identity]) }

func (s Selection) isNew(i int) bool {
	return s.host != nil && s.Rows[Identity].Choices[i].Label == NewFromHost
}

// IdentityProfile returns the name of the identity profile the project would
// include: the picked profile of yours, or the name of the one NewFromHost
// writes; "" for none.
func (s Selection) IdentityProfile() string {
	return s.profileOf(s.Pick[Identity])
}

func (s Selection) profileOf(i int) string {
	switch l := s.Rows[Identity].Choices[i].Label; {
	case l == NoIdentity:
		return ""
	case s.isNew(i):
		return s.host.name
	default:
		return l
	}
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

// partsChanged reports whether a part that matters for the current IDENTITY
// pick differs from its default.
func (s Selection) partsChanged() bool {
	for _, it := range s.IdentityItems() {
		if it.IsPart && it.Choice == s.Pick[Identity] && s.Parts[it.Part] != s.partsDefault[it.Part] {
			return true
		}
	}
	return false
}

// pins reports whether choice i writes or names a profile that pins part p.
func (s Selection) pins(i int, p Part) bool {
	if s.isNew(i) {
		_, ok := s.host.part(p)
		return ok && s.Parts[p]
	}
	pi := slices.IndexFunc(s.profiles, func(q ingest.Profile) bool { return q.Name == s.Rows[Identity].Choices[i].Label && q.Identity.Pins() })
	if pi < 0 {
		return false
	}
	id := s.profiles[pi].Identity
	switch p {
	case PartGH:
		return id.GHUser != ""
	case PartSSH:
		return id.SSHKey != "" || id.SSHHost != ""
	}
	return false
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

// toolStaging says what choice i needs for tool t. Nothing is needed when the
// program is not on the host, resolves under /usr (which @sys binds), or is
// already staged by the profile choice i names or one it includes.
func (s Selection) toolStaging(i int, t identityTool) staging {
	b, ok := s.binaries[t.binary]
	if !ok || b.Resolved == "" || strings.HasPrefix(b.Resolved, "/usr/") || !s.pins(i, t.pinned) {
		return staging{}
	}
	if own := s.profileOf(i); own != "" && !s.isNew(i) {
		need := []string{own}
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
	}
	for _, p := range s.profiles {
		if p.Stages(t.binary) {
			return staging{kind: stageInclude, profile: p.Name}
		}
	}
	// The resolved path, not the one PATH names: snug refuses a grant that
	// resolves through a symlink the person owns, and its message says to grant
	// the destination instead.
	st := staging{kind: stageBinary, spelled: b.Resolved, shown: b.Resolved}
	if s.home != "" && strings.HasPrefix(b.Resolved, s.home+"/") {
		st.spelled = "{home}/" + strings.TrimPrefix(b.Resolved, s.home+"/")
		st.shown = "~/" + strings.TrimPrefix(b.Resolved, s.home+"/")
	}
	return st
}

func (t identityTool) line(st staging, shown string) string {
	switch st.kind {
	case stageInclude:
		return t.binary + " binary  include " + st.profile + ": it stages /snug/bin/" + t.binary + " (" + t.binary + " is not in /usr)"
	}
	return t.binary + " binary  " + shown + " → /snug/bin/" + t.binary + " (not in /usr)"
}

// IdentItem is one line of the IDENTITY submenu the cursor can reach: a
// choice, or a switch inside one.
type IdentItem struct {
	// Choice is the index into the Identity row's Choices the line belongs to.
	Choice int
	// IsPart is false for the choice's own line. Part, Text and On are
	// meaningful only when it is true.
	IsPart bool
	Part   Part
	Text   string
	On     bool
	// Why is the text `?` shows for this line.
	Why []string
}

// IdentityItems returns the submenu's reachable lines in order: each choice,
// then the switches under it. Every string is raw; the caller cleans it with
// safe.Inline before it reaches a screen.
func (s Selection) IdentityItems() []IdentItem {
	var out []IdentItem
	for i, c := range s.Rows[Identity].Choices {
		var why []string
		if c.Why != "" {
			why = append(why, c.Why)
		}
		why = append(why, c.Facts...)
		if s.isNew(i) {
			why = append(why, "identity: "+draft.Abuse["identity"])
		}
		out = append(out, IdentItem{Choice: i, Text: c.Label, Why: why})
		if s.isNew(i) {
			for _, p := range s.host.parts {
				pw := []string{p.why, "identity: " + draft.Abuse["identity"]}
				out = append(out, IdentItem{Choice: i, IsPart: true, Part: p.id, Text: p.text + "  " + p.why, On: s.Parts[p.id], Why: pw})
			}
		}
		for _, t := range identityTools {
			st := s.toolStaging(i, t)
			if st.kind == stageNone {
				continue
			}
			w := []string{ghBinaryAbuse}
			if st.kind == stageInclude {
				w = append(w, "your profile "+st.profile+" stages it already; including it brings everything else that profile grants")
			}
			out = append(out, IdentItem{Choice: i, IsPart: true, Part: t.part, Text: t.line(st, st.shown), On: s.Parts[t.part], Why: w})
		}
	}
	return out
}

// newDescription is the description the new profile is written with.
func (s Selection) newDescription() string {
	var what []string
	for _, id := range []Part{PartSSH, PartGH, PartGit, PartSigning} {
		if _, ok := s.host.part(id); !ok || !s.Parts[id] {
			continue
		}
		what = append(what, map[Part]string{PartSSH: "its ssh key", PartGH: "its gh token", PartGit: "its git author", PartSigning: "its signing key"}[id])
	}
	who := "GitHub identity " + s.host.name
	if p, ok := s.host.part(PartGH); ok && s.Parts[PartGH] {
		who = "GitHub account " + p.a
	}
	if len(what) == 0 {
		return who
	}
	return who + ": " + strings.Join(what, ", ") + "."
}

// BuildIdentity returns the draft of the identity profile NewFromHost writes,
// and nil when another choice is picked. The string is why the draft lacks a
// part the submenu shows switched on, or that the profile would pin nothing; ""
// when the draft is what the submenu says.
func BuildIdentity(s Selection, host draft.Host) (*draft.Draft, string) {
	if !s.picksNew() {
		return nil, ""
	}
	d := draft.New(host)
	d.Name = s.host.name
	for _, p := range s.host.parts {
		if !s.Parts[p.id] {
			continue
		}
		switch p.id {
		case PartSSH:
			d.SetSSH(p.pub)
		case PartGit:
			d.SetGit(p.a, p.b)
		case PartGH:
			d.SetGH(s.host.host, p.a)
		}
	}
	if p, ok := s.host.part(PartSigning); ok && s.Parts[PartSigning] && !d.SetSigningKey(p.pub) {
		return d, "sign needs the ssh and git parts on as well; switch them on, or sign off"
	}
	if d.SSH == nil && d.GH == nil && d.Git == nil {
		return d, "every part is off, so the new profile would pin nothing"
	}
	d.Description = s.newDescription()
	return d, ""
}
