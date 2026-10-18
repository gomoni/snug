package suggest

import (
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
)

// Build returns a fresh draft for s, and, per row, the message of every op the
// draft refused. profiles are the person's own, read for the description
// rendered above an included one.
//
// The refusals matter: a row that shows "on" while the file lacks it would be
// a guarantee the file does not keep, so the caller puts the message on that
// row's reason line. Build never retries or substitutes a refused op.
//
// The project includes every profile picked in any block, and the new profile
// by name when a block is picked FromHost; BuildIdentity makes its draft. A
// refusal snug would give for the blocks together (two profiles setting one
// block differently, signing_key without ssh from the same profile) lands on
// the Identity row. A pinned gh that is not under /usr gets its binary
// staged, or the person's profile that stages it included. Both land in the
// project profile, never in the identity's.
//
// A hostile target cannot reach this: every value Build passes to the draft is
// a built-in name, a profile name taken from the person's own profiles or
// chosen from host facts, a program path found on the host's PATH, an
// environment hint ingest derives from marker file names, or text the person
// typed, and the draft applies its own rules to each.
func Build(s Selection, host draft.Host, profiles []ingest.Profile) (*draft.Draft, map[RowID]string) {
	d := draft.New(host)
	refused := map[RowID]string{}
	propose := func(row RowID, a draft.Action) {
		origin := s.Current(row).Why
		if origin == "" {
			origin = "snug-setup default"
		}
		if o := d.Propose(a, origin); o.Refused != "" {
			refused[row] = o.Msg
		}
	}
	use := func(row RowID, name string) {
		propose(row, draft.Action{Op: draft.OpUseProfile, Name: name})
	}

	propose(Name, draft.Action{Op: draft.OpNameProfile, Name: s.Text[Name]})
	d.Description = s.Text[Desc]

	choice := func(row RowID) string { return s.Rows[row].Choices[s.Pick[row]].Label }
	if strings.Contains(choice(Base), "@parent-ro") {
		use(Base, "@parent-ro")
	}
	for _, row := range []RowID{Agent, Network, Containers} {
		if l := choice(row); strings.HasPrefix(l, "@") {
			use(row, l)
		}
	}
	st := s.resolve(s.Block)
	for _, name := range s.Included() {
		propose(Identity, draft.Action{Op: draft.OpIncludeProfile, Name: name})
		if st.member(name).kind == srcHost {
			d.NoteProfile(name, s.newDescription())
			continue
		}
		for _, p := range profiles {
			if p.Name == name {
				d.NoteProfile(name, p.Description)
				break
			}
		}
	}
	if msg := st.message(); msg != "" {
		if prev := refused[Identity]; prev != "" {
			msg = prev + "; " + msg
		}
		refused[Identity] = msg
	}
	for _, t := range identityTools {
		if !s.Parts[t.part] {
			continue
		}
		switch sg := s.toolStaging(t); sg.kind {
		case stageInclude:
			propose(Identity, draft.Action{Op: draft.OpIncludeProfile, Name: sg.profile})
			for _, p := range profiles {
				if p.Name == sg.profile {
					d.NoteProfile(sg.profile, p.Description)
					break
				}
			}
		case stageBinary:
			propose(Identity, draft.Action{Op: draft.OpStageBinary, Host: sg.spelled, Name: t.binary})
		}
	}
	if choice(Env) != Off {
		for _, h := range s.env {
			propose(Env, draft.Action{Op: draft.OpSetEnv, Name: h.Name, Verb: "set", Value: h.Value, HasValue: true})
		}
	}
	return d, refused
}
