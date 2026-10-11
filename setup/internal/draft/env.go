package draft

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
)

var secretName = regexp.MustCompile(`(?i)TOKEN|SECRET|PASSWORD|API_?KEY|CREDENTIAL`)

// writtenBySnug are the names snug writes itself; set and inherit are refused.
// PATH still takes prepend.
var writtenBySnug = []string{"HOME", "PATH", "SHELL", "USER", "LOGNAME", "TMPDIR", "PS1"}

// noVerbs have no environ verb at all in snug's roster.
var noVerbs = []string{"CDPATH", "GOFLAGS", "LD_LIBRARY_PATH", "LD_PRELOAD"}

// listVars are the names snug knows as path lists, the only ones that take prepend.
var listVars = []string{
	"CLASSPATH", "GOPATH", "INFOPATH", "NODE_PATH", "PATH", "PERL5LIB", "PKG_CONFIG_PATH",
	"TERMINFO_DIRS", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS", "MANPATH", "PYTHONPATH",
}

var knownVar = regexp.MustCompile(`\{([^{}]*)\}`)

func (d *Draft) setEnv(a intent.Action) Outcome {
	name := a.Name
	if secretName.MatchString(name) {
		return refuse("secret_in_env", fmt.Sprintf("%s looks like a credential", name))
	}
	if strings.HasPrefix(name, "SNUG") {
		return refuse(CodeReservedEnv, name+" is a snug variable, written by snug")
	}
	if slices.Contains(noVerbs, name) {
		return refuse(CodeNoVerb, "snug accepts no profile setting for "+name)
	}
	switch a.Verb {
	case "set", "inherit":
		if slices.Contains(writtenBySnug, name) {
			return refuse(CodeReservedEnv, name+" is written by snug itself")
		}
		if slices.Contains(listVars, name) {
			return refuse(CodeUnknownList, name+" is a path list in snug: it takes prepend (and merge), not "+a.Verb)
		}
	case "prepend":
		if !slices.Contains(listVars, name) {
			return refuse(CodeUnknownList, name+" is not a path-list variable snug knows; prepend works for "+strings.Join(listVars, " "))
		}
	}
	if a.Verb != "inherit" {
		if hidden(a.Value) {
			return refuse(CodeBadValue, "an environment value cannot contain control or invisible formatting characters")
		}
		for _, m := range knownVar.FindAllStringSubmatch(a.Value, -1) {
			switch m[1] {
			case "home", "target", "target_parent":
			default:
				return refuse(CodeBadValue, "{"+m[1]+"} is not a variable snug expands (home, target, target_parent)")
			}
		}
	}
	switch a.Verb {
	case "inherit":
		if slices.Contains(d.EnvInherit, name) {
			return Outcome{Msg: name + " is already inherited."}
		}
		d.EnvInherit = append(d.EnvInherit, name)
		return changed("the sandbox gets your " + name + " (copied from the host when it is set). Everything in the sandbox can read it from /proc/self/environ.")
	case "set":
		for i, p := range d.EnvSet {
			if p.K == name {
				d.EnvSet[i].V = a.Value
				return changed(fmt.Sprintf("%s is now %q.", name, a.Value))
			}
		}
		d.EnvSet = append(d.EnvSet, pair{name, a.Value})
		return changed(fmt.Sprintf("%s=%q is set inside the sandbox.", name, a.Value))
	default:
		if a.Value == "" || !(filepath.IsAbs(a.Value) || strings.HasPrefix(a.Value, "~/") || strings.HasPrefix(a.Value, "{")) {
			return refuse(CodeBadValue, "prepend takes an absolute path (or ~/..., {home}/...)")
		}
		if !d.covered(a.Value) {
			return refuse(CodeNotGranted, a.Value+" is not inside anything the draft grants: grant the directory first (ro or rw), then prepend it")
		}
		for _, p := range d.EnvPrepend {
			if p.K == name && d.expand(p.V) == d.expand(a.Value) {
				return Outcome{Msg: a.Value + " is already prepended to " + name + "."}
			}
		}
		d.EnvPrepend = append(d.EnvPrepend, pair{name, a.Value})
		return changed(a.Value + " goes in front of " + name + " inside the sandbox.")
	}
}

// covered reports whether path lies inside a ro, rw or tmpfs grant of the draft.
func (d *Draft) covered(path string) bool {
	e := d.expand(path)
	for _, l := range [][]string{d.RO, d.RW, d.Tmpfs} {
		for _, g := range l {
			if under(e, d.expand(g)) {
				return true
			}
		}
	}
	// The target is always visible: read-only by the draft's own grant, or
	// writable by the @target-rw a bare `snug DIR` selects.
	return under(e, filepath.Clean(d.Host.Target))
}
