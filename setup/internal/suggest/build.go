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
// A hostile target cannot reach this: every value Build passes to the draft is
// a built-in name, a profile name taken from the person's own profiles, an
// environment hint ingest derives from marker file names, or text the person
// typed, and the draft applies its own rules to each.
func Build(s Selection, host draft.Host, profiles []ingest.Profile) (*draft.Draft, map[RowID]string) {
	d := draft.New(host)
	refused := map[RowID]string{}
	propose := func(row RowID, a draft.Action) {
		origin := s.Rows[row].Choices[s.Pick[row]].Why
		if origin == "" {
			origin = "snug-setup default"
		}
		if o, _ := d.Propose(a, draft.SourceIngest, origin, 0); o.Refused != "" {
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
	identity := choice(Identity)
	if identity == NoIdentity {
		use(Identity, "@git")
	}
	for _, row := range []RowID{Agent, Network, Containers} {
		if l := choice(row); strings.HasPrefix(l, "@") {
			use(row, l)
		}
	}
	if identity != NoIdentity {
		propose(Identity, draft.Action{Op: draft.OpIncludeProfile, Name: identity})
		for _, p := range profiles {
			if p.Name == identity {
				d.NoteProfile(identity, p.Description)
				break
			}
		}
	}
	if choice(Env) != Off {
		for _, h := range s.env {
			propose(Env, draft.Action{Op: draft.OpSetEnv, Name: h.Name, Verb: "set", Value: h.Value, HasValue: true})
		}
	}
	return d, refused
}
