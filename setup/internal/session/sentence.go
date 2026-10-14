package session

import (
	"slices"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
)

// Sentence says what a would do to d, in Go's words: the human decides on
// this, never on anything the model wrote. Paths, names and values the model
// chose are passed through safe.Inline.
func Sentence(d *draft.Draft, a intent.Action) string {
	path := func(p string) string { return safe.Inline(d.HostPath(p)) }
	switch a.Op {
	case intent.OpUseProfile:
		if a.Name == "@target-rw" && !d.ReadOnlyTarget {
			return "@target-rw is already the default; nothing to add"
		}
		if slices.ContainsFunc(d.Includes(), func(n string) bool { return slices.Contains(draft.Closure(n), a.Name) }) {
			return a.Name + " is already in the draft"
		}
		return "add " + a.Name
	case intent.OpDropProfile:
		return "drop " + a.Name
	case intent.OpIncludeProfile:
		if slices.Contains(d.Include, a.Name) {
			return "your profile " + safe.Inline(a.Name) + " is already in the draft"
		}
		return "include your profile " + safe.Inline(a.Name)
	case intent.OpGrantPath:
		switch {
		case a.Access == "ro" && d.HostPath(a.Path) == d.HostPath("{target}"):
			return "the project is read-only (run with --no-defaults)"
		case a.Access == "ro":
			return "read-only: " + path(a.Path)
		case a.Access == "rw":
			return "writable: " + path(a.Path) + " (persists)"
		}
		return "scratch tmpfs at " + path(a.Path) + " (empty, gone when the sandbox exits)"
	case intent.OpDropPath:
		return "remove " + path(a.Path) + " from the draft"
	case intent.OpStageBinary:
		return "stage " + path(a.Host) + " as /snug/bin/" + safe.Inline(a.Name)
	case intent.OpSetEnv:
		switch a.Verb {
		case "set":
			return "set " + a.Name + "=" + safe.Inline(a.Value)
		case "inherit":
			return "copy " + a.Name + " from your environment"
		}
		return "put " + safe.Inline(a.Value) + " in front of " + a.Name
	case intent.OpOpenDoor:
		return "open the door " + a.Name + " (listen_names)"
	case intent.OpNameProfile:
		return "call the profile " + a.Name
	case intent.OpSelectIdentity:
		s := "pick a " + kindName(a.Kind)
		if a.Account != "" {
			s += " (you said \"" + safe.Inline(a.Account) + "\")"
		}
		return s
	case intent.OpReadFile:
		return "read " + safe.Inline(a.Path) + " from the project"
	case intent.OpListIdentities:
		return "list the " + kindName(a.Kind) + "s on this host"
	case intent.OpShow:
		return "show the draft"
	case intent.OpSave:
		return "save the profile"
	case intent.OpRefuse:
		return "read as a request snug refuses (" + a.Code + ")"
	case intent.OpNote:
		return "note: " + a.Topic
	case intent.OpAsk:
		return "the model asks: \"" + safe.Inline(a.Question) + "\""
	case intent.OpAnalyze:
		return "analyze the project and propose what its files make plain"
	case intent.OpAdvise:
		return "suggest the identity this project points at"
	case intent.OpUndo:
		return "undo the last step"
	}
	return a.Op
}
