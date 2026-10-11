package intent

import "strings"

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
	File   *File       `json:"file"`
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

func list(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}

// FormatPrompt returns the system and user messages for ctx and request. The
// user message is byte-exact with setup/model/prompt.py: lines in the order
// target, draft, host ssh, host github, host git, file, request; the host and
// file lines are omitted when empty; lines are joined with "\n" and there is no
// trailing newline; a file body has its trailing newlines stripped.
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
	if c.File != nil {
		lines = append(lines, "file "+c.File.Name+":", strings.TrimRight(c.File.Body, "\n"))
	}
	lines = append(lines, "request: "+request)
	return System, strings.Join(lines, "\n")
}
