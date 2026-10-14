package intent

import "strings"

// Ops that are not in schema.json. A model cannot emit them, because Parse
// refuses an op the schema does not list; only an interpreter written in Go
// returns them. Each changes nothing in the draft by itself.
const (
	// OpAnalyze asks for the analysis of the project: what its files make
	// plain, and the card for it.
	OpAnalyze = "analyze"
	// OpAdvise asks which identity the host's facts point at for this
	// project.
	OpAdvise = "advise"
	// OpUndo takes back the last thing the session did.
	OpUndo = "undo"
)

// Choice is one reading an interpreter offers when it did not understand a
// request. Label is Go's words for it; Actions are what picking it submits.
type Choice struct {
	Label   string
	Actions []Action
}

// Unclear is the error an interpreter returns for a request it did not
// understand well enough to act on. Nothing in it has been applied, and the
// caller must apply nothing on its account: Choices are offered to the human,
// never taken.
type Unclear struct {
	// Unknown is the part of the request that was not understood.
	Unknown string
	// Understood is what the rest of the request was read as.
	Understood []Action
	// Why is a short reason in Go's words, "" when there is nothing to add to
	// "not understood".
	Why string
	// Choices are the closest readings, best first, at most three.
	Choices []Choice
}

func (u *Unclear) Error() string {
	var b strings.Builder
	b.WriteString("did not understand")
	if u.Unknown != "" {
		b.WriteString(" \"" + u.Unknown + "\"")
	}
	if u.Why != "" {
		b.WriteString(": " + u.Why)
	}
	return b.String()
}
