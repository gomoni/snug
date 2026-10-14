package draft

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
)

// secretName, secretWord, secretURL and secretProxy name the variables refused
// as credentials. The substrings match anywhere; the words match one
// _-separated segment, so PRIVATE_KEY, SSH_AUTH_SOCK and GITHUB_PAT (a
// personal access token) are refused while KEYBOARD_LAYOUT, AUTHOR_NAME and
// PATH are not, and TOKEN must end a segment, so
// GITHUB_TOKEN and APITOKEN_X are refused and TOKENIZERS_PARALLELISM is not. A
// glued ...KEY at the end (OPENAIKEY) is refused. A connection URL for a
// database, queue or index, and a proxy URL, routinely carry user:password, so
// they are refused by name. Some harmless names are refused too
// (PASSWORD_STORE_DIR, AUTH_TYPE); the human can set them by hand.
var (
	secretName  = regexp.MustCompile(`(?i)TOKEN(_|$)|SECRET|PASSWORD|PASSPHRASE|API_?KEY|CREDENTIAL|COOKIE|BEARER|JWT|WEBHOOK|CONNECTION_STRING|CONN_STR|KEY$`)
	secretWord  = regexp.MustCompile(`(?i)(^|_)(KEYS?|PASS|PASSWD|PWD|AUTH|DSN|PRIVATE|SESSION|SESSIONID|SK|HMAC|SALT|PAT)(_|$)`)
	secretURL   = regexp.MustCompile(`(?i)((^|_)(DATABASE|DB|REDIS|MONGO|MONGODB|POSTGRES|POSTGRESQL|PG|MYSQL|AMQP|RABBITMQ|BROKER|KAFKA|ELASTICSEARCH|CLICKHOUSE|SMTP|MAIL|NATS|CACHE)|INDEX)_UR[LI](_[A-Z0-9]+)?$`)
	secretProxy = regexp.MustCompile(`(?i)^(HTTPS?|ALL|FTP|SOCKS5?)_PROXY$`)
	// secretValue is a set value that carries a credential whatever the name:
	// URL userinfo, a known token prefix, an AWS access key id, a PEM block.
	secretValue = regexp.MustCompile(`://[^/@\s]+@|^(ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|xox[abprs]-|sk-)|\bAKIA[0-9A-Z]{16}\b|-----BEGIN `)
)

func secretEnv(name string) bool {
	return secretName.MatchString(name) || secretWord.MatchString(name) || secretURL.MatchString(name) || secretProxy.MatchString(name)
}

// writtenBySnug are the names snug (or bwrap, for PWD) writes itself: snug's
// SnugOwnedEnv and bwrapOwnedEnv without the SNUG prefix, which setEnv refuses
// on its own. set and inherit are refused; PATH still takes prepend.
var writtenBySnug = []string{"HOME", "LANG", "LOGNAME", "PATH", "PS1", "PWD", "SHELL", "TERM", "TMPDIR", "TZ", "USER"}

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
	if secretEnv(name) {
		return refuse("secret_in_env", fmt.Sprintf("%s looks like a credential", name))
	}
	if a.Verb != "inherit" && secretValue.MatchString(a.Value) {
		return refuse("secret_in_env", fmt.Sprintf("the value for %s looks like a credential", name))
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
				if p.V == a.Value {
					return Outcome{Msg: fmt.Sprintf("%s is already %q.", name, a.Value)}
				}
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
	// The target is visible through @target-rw, but snug wants the profile
	// that names a path to grant it, so the target is not counted here.
	return false
}
