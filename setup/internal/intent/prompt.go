package intent

import (
	"strings"
	"unicode"
)

// System is the fixed system message.
const System = "You are snug-setup. Turn the request into snug profile actions. Reply with JSON only."

// Context is everything the model is shown besides the request. Its JSON form
// is the shape of testdata/prompts.jsonl, shared with the Python training side.
type Context struct {
	Target string      `json:"target"`
	Draft  Draft       `json:"draft"`
	SSH    []SSHKey    `json:"ssh"`
	GitHub []GHAccount `json:"github"`
	Git    []string    `json:"git"`
	// Profiles are the names of the human's own snug profiles.
	Profiles []string `json:"profiles"`
	File     *File    `json:"file"`
	// Last is what the previous turn did, as LastItems renders it, so a
	// follow-up ("undo that", "actually remove it") can name its target.
	Last []string `json:"last"`
}

// Draft summarises the profile being built.
type Draft struct {
	Name     *string  `json:"name"`
	Include  []string `json:"include"`
	RW       []string `json:"rw"`
	RO       []string `json:"ro"`
	Tmpfs    []string `json:"tmpfs"`
	Env      []string `json:"env"`
	Identity []string `json:"identity"`
}

// SSHKey is one public key found on the host.
type SSHKey struct {
	Stem    string `json:"stem"`
	Comment string `json:"comment"`
	Agent   bool   `json:"agent"`
}

// GHAccount is one gh login.
type GHAccount struct {
	Host   string `json:"host"`
	User   string `json:"user"`
	Active bool   `json:"active"`
}

// File is the digest of a file the model asked to read.
type File struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// headers are the prefixes FormatPrompt starts its own lines with.
var headers = []string{"target:", "draft:", "host ", "file ", "last:", "request:"}

// fileBody returns a file's text for the prompt. The file comes from the
// target, the least trusted input there is, so it cannot add a line of the
// prompt's own: a control or formatting rune other than tab, and U+2028/2029,
// are dropped, and a line that starts like one of FormatPrompt's is indented
// by two spaces. An ordinary file is unchanged. prompt.py's _file_body is the
// same rule, and testdata/prompts.jsonl holds the two equal.
func fileBody(body string) string {
	body = strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029) {
			return -1
		}
		return r
	}, strings.TrimRight(body, "\n"))
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		for _, h := range headers {
			if strings.HasPrefix(l, h) {
				lines[i] = "  " + l
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func list(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}

// FormatPrompt returns the system and user messages for ctx and request. The
// user message is byte-exact with setup/model/prompt.py: lines in the order
// target, draft, host ssh, host github, host git, host profiles, file, last,
// request; the host, file and last lines are omitted when empty; lines are joined with "\n" and there is no
// trailing newline; a file body has its trailing newlines stripped and goes
// through fileBody.
func FormatPrompt(c Context, request string) (system, user string) {
	name := "-"
	if c.Draft.Name != nil && *c.Draft.Name != "" {
		name = *c.Draft.Name
	}
	lines := []string{
		"target: " + c.Target,
		"draft: name=" + name +
			" include=" + list(c.Draft.Include) +
			" rw=" + list(c.Draft.RW) +
			" ro=" + list(c.Draft.RO) +
			" tmpfs=" + list(c.Draft.Tmpfs) +
			" env=" + list(c.Draft.Env) +
			" identity=" + list(c.Draft.Identity),
	}
	if len(c.SSH) > 0 {
		parts := make([]string, 0, len(c.SSH))
		for _, k := range c.SSH {
			var attrs []string
			if k.Comment != "" {
				attrs = append(attrs, k.Comment)
			}
			if k.Agent {
				attrs = append(attrs, "agent")
			}
			if len(attrs) == 0 {
				parts = append(parts, k.Stem)
			} else {
				parts = append(parts, k.Stem+" ("+strings.Join(attrs, ", ")+")")
			}
		}
		lines = append(lines, "host ssh: "+strings.Join(parts, "; "))
	}
	if len(c.GitHub) > 0 {
		parts := make([]string, 0, len(c.GitHub))
		for _, a := range c.GitHub {
			s := a.Host + "/" + a.User
			if a.Active {
				s += " (active)"
			}
			parts = append(parts, s)
		}
		lines = append(lines, "host github: "+strings.Join(parts, "; "))
	}
	if len(c.Git) > 0 {
		lines = append(lines, "host git: "+strings.Join(c.Git, "; "))
	}
	if len(c.Profiles) > 0 {
		lines = append(lines, "host profiles: "+strings.Join(c.Profiles, "; "))
	}
	if c.File != nil {
		lines = append(lines, "file "+c.File.Name+":", fileBody(c.File.Body))
	}
	if len(c.Last) > 0 {
		lines = append(lines, "last: "+strings.Join(c.Last, "; "))
	}
	lines = append(lines, "request: "+request)
	return System, strings.Join(lines, "\n")
}

// oneLine drops every rune that could end or reformat a prompt line: a
// select_identity account or an ask question is model output of up to 128 or
// 200 runes of anything, and LastItems feeds it back into the next prompt.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}

// LastItems renders the actions of one turn for Context.Last: one item per
// action, notes left out (they change nothing), each "op" followed by the
// fields that say what it touched. prompt.py's last_items is the same rule,
// and testdata/last.jsonl holds the two equal.
func LastItems(acts []Action) []string {
	var out []string
	for _, a := range acts {
		var f []string
		switch a.Op {
		case OpNote:
			continue
		case OpUseProfile, OpDropProfile, OpIncludeProfile, OpOpenDoor, OpNameProfile:
			f = []string{a.Name}
		case OpGrantPath:
			f = []string{a.Path, a.Access}
		case OpDropPath, OpReadFile:
			f = []string{a.Path}
		case OpStageBinary:
			f = []string{a.Host}
		case OpSetEnv:
			f = []string{a.Name, a.Verb}
		case OpListIdentities:
			f = []string{a.Kind}
		case OpSelectIdentity:
			f = []string{a.Kind}
			if a.Account != "" {
				f = append(f, a.Account)
			}
		case OpRefuse:
			f = []string{a.Code}
		}
		item := a.Op
		for _, x := range f {
			item += " " + oneLine(x)
		}
		out = append(out, item)
	}
	return out
}
