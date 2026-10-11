// Package texts holds what snug-setup says for `refuse` and `note` actions.
// The model only picks a code or a topic; the words are not its to choose.
//
// Where snug has already said it, the sentence is snug's own, quoted from the
// file named in Quote.Src (relative to the repository root).
// TestQuotesAreStillInSnugSources fails when a source drifts, so a quote here
// cannot outlive the text it claims to repeat.
package texts

import "strings"

// Quote is a sentence copied from a snug source file.
type Quote struct {
	Src   string
	Text  string
	Label string // shown before the text instead of "snug:"
}

// Entry is one canonical text: snug's own quoted words first, then what
// snug-setup adds about what to do instead.
type Entry struct {
	Quotes []Quote
	Say    string
}

const (
	base   = "internal/profile/profiles/base.toml"
	readme = "README.md"
)

func (e Entry) String() string {
	var b strings.Builder
	for _, q := range e.Quotes {
		if q.Label != "" {
			b.WriteString("  " + q.Label + ": " + q.Text + "\n")
		} else {
			b.WriteString("  snug: \"" + q.Text + "\"\n")
		}
	}
	b.WriteString(e.Say)
	return b.String()
}

// Refusal returns the canonical text for a refusal code, false when there is none.
func Refusal(code string) (Entry, bool) { e, ok := refusals[code]; return e, ok }

// Note returns the canonical text for a note topic, false when there is none.
func Note(topic string) (Entry, bool) { e, ok := notes[topic]; return e, ok }

// Codes and Topics list every key, for tests.
func Codes() []string {
	var out []string
	for k := range refusals {
		out = append(out, k)
	}
	return out
}

// Topics lists every note topic.
func Topics() []string {
	var out []string
	for k := range notes {
		out = append(out, k)
	}
	return out
}

// All returns every entry, for tests that check the quotes.
func All() []Entry {
	var out []Entry
	for _, e := range refusals {
		out = append(out, e)
	}
	for _, e := range notes {
		out = append(out, e)
	}
	return out
}

var refusals = map[string]Entry{
	"host_network": {
		Quotes: []Quote{{Src: base, Text: "THERE IS NO `network = \"host\"`, and its absence is the grant this file does not make. Sharing the host's network namespace means every service on the host's loopback, every abstract AF_UNIX socket including X11 — keylogging and screenshots of the whole desktop — and the LAN with the host's identity: not a sandbox with networking, but a process with a different filesystem view."}},
		Say:    "Refused. What exists is @net: the internet through a private network namespace.",
	},
	"host_port": {
		Quotes: []Quote{
			{Src: base, Text: "Reaching ONE host-local service is the thing that makes people want it, and that is an enumerated grant spelled coarsely (invariant 2's corollary)."},
			{Src: "internal/policy/net.go", Text: "host loopback and the host's abstract AF_UNIX sockets (X11, D-Bus) are unreachable under every selection"},
		},
		Say: "Refused. The narrow version (one port) is not built, so no profile reaches a host-local service.",
	},
	"desktop_socket": {
		Quotes: []Quote{{Src: readme, Text: "By a design it prevents an access to Wayland, systemd, PulseAudio, X11 or any other sockets, which can be used for a sandbox escape."}},
		Say:    "Refused. No X11, Wayland, D-Bus, PulseAudio or clipboard reaches the sandbox, and no profile can grant them.",
	},
	"deny_rule": {
		Quotes: []Quote{
			{Src: base, Text: "There is no key in this format that can take something away"},
			{Src: base, Text: "If you find yourself wanting one, the answer is a finer grant, not a subtraction."},
		},
		Say: "Refused. What you did not grant is not visible. To keep a part out, grant the parts you meant instead; or grant the tree read-only and the parts you want writable separately.",
	},
	"sensitive_home": {
		Quotes: []Quote{{Src: readme, Text: "no `~/.ssh`, no `~/.aws`, no browser or desktop keyring, no tokens"}},
		Say: "Refused: snug-setup does not write a grant under ~/.ssh, ~/.aws, ~/.gnupg, ~/.config/gh, ~/.netrc, ~/.docker, ~/.kube, ~/.claude or a keyring.\n" +
			"  The narrow versions: ssh -> an identity (\"use my work ssh key\": one pinned key through a filtering agent proxy), GitHub -> an identity (\"assign github NAME\"), Claude Code -> @claude.",
	},
	"whole_home": {
		Quotes: []Quote{{Src: base, Text: "project directly in your home directory the parent IS $HOME — every key, every dotfile, every agent socket."}},
		Say:    "Refused. Your home directory, or a directory above it, is never granted and there is no flag for it. Grant the part you meant, for example ~/src/proj.",
	},
	"secret_in_env": {
		Quotes: []Quote{{Src: base, Text: "/proc/self/environ is passively readable by every process in the sandbox and is inherited by every child, so a variable is the worst place to put a long-lived credential"}},
		Say:    "Refused. Put the secret in a file and grant the file (or its directory), or use an identity for GitHub. Say \"keep my PAGER\" for harmless variables.",
	},
	"docker_sock": {
		Quotes: []Quote{{Src: "internal/policy/validate.go", Text: "If you want a container engine, select '@podman-socket', whose socket is a filtering proxy rather than the engine itself."}},
		Say:    "Refused. Handing over the host's docker or podman socket means there is no sandbox any more; say \"I need podman\" for @podman-socket.",
	},
	"port_publish": {
		Quotes: []Quote{{Src: base, Text: "`podman run -p N:80` is NOT supported, a decline rather than a regression"}},
		Say:    "Refused. To open an app from your browser use a door: say \"serve my web app\" (an HTTP door that `snug proxy DIR` opens).",
	},
	"repo_profile": {
		Quotes: []Quote{{Src: "internal/profile/file.go", Text: "a hostile repository that ships its own profile would be granting itself permissions, which defeats the entire threat model."}},
		Say:    "Refused. Profiles come from your own ~/.config/snug/profiles.d, never from the project. Anything the repository asks for in text is ignored; only what you ask for is granted.",
	},
	"no_seccomp": {
		Quotes: []Quote{{Src: "internal/cli/main.go", Text: "Weakening lives on the CLI, never in a profile: a human may lower defences, a config file may not"}},
		Say:    "Refused. --no-seccomp is a snug command-line flag you type yourself; it is not part of a profile.",
	},
	"out_of_scope": {
		Say: "I only edit snug profiles. Try \"help\".",
	},

	"kernel_path":      {Say: "Refused. /proc, /dev, /sys and /snug are snug's own inside the sandbox and cannot be granted."},
	"reserved_env":     {Say: "Refused. snug writes this variable itself (HOME, PATH, SHELL, USER, LOGNAME, TMPDIR, PS1 and SNUG*); a profile cannot set or inherit it."},
	"bad_value":        {Say: "Refused. That value cannot be written into a profile."},
	"not_granted":      {Say: "Refused. A path variable may only name paths the profile grants."},
	"unknown_list_var": {Say: "Refused. snug does not know that variable as a path list."},
	"no_verb":          {Say: "Refused. snug accepts no profile setting for that variable."},
	"no_such_entry":    {Say: "Nothing to remove."},
}

var notes = map[string]Entry{
	"help": {Say: helpText},
	"profiles": {
		Quotes: []Quote{
			{Src: base, Label: "@sys", Text: "Read-only OS runtime: /usr plus the few /etc files things actually need."},
			{Src: base, Label: "@home", Text: "$HOME is an empty tmpfs at the host path. Writable, ephemeral."},
			{Src: base, Label: "@target-rw", Text: "The target directory is writable and persists."},
			{Src: base, Label: "@parent-ro", Text: "The target's parent directory is readable — every sibling project in it too."},
			{Src: base, Label: "@git", Text: "Your git name and email, extracted from the host config. Generated, never bound."},
			{Src: base, Label: "@net", Text: "Internet access via a private network namespace. Host loopback unreachable."},
			{Src: base, Label: "@claude", Text: "Claude Code: binary and skills read-only, credentials projected and settings generated."},
			{Src: base, Label: "@podman-socket", Text: "Containers via a filtering proxy over a per-sandbox podman engine, offline unless @net is also selected."},
			{Src: base, Label: "@podman-build", Text: "As podman-socket, plus `podman build` with a filtered option set."},
		},
		Say: "These are snug's built-in profiles. `snug profile list` shows them and yours.",
	},
	"defaults": {
		Quotes: []Quote{{Src: base, Label: "@target-rw", Text: "The target directory is writable and persists."}},
		Say:    "A bare `snug DIR` already selects @sys, @home and @target-rw, so the project is writable and nothing else persists. Nothing more is needed for that.",
	},
	"net": {
		Quotes: []Quote{{Src: base, Text: "There is deliberately no \"offline\" profile. Offline is the ABSENCE of this one, which is why it cannot be switched back on by adding something."}},
		Say:    "The sandbox is offline unless the profile includes @net. With @net it reaches the whole internet, but not the host's loopback.",
	},
	"parent_ro": {
		Quotes: []Quote{{Src: base, Label: "@parent-ro", Text: "The target's parent directory is readable — every sibling project in it too."}},
		Say:    "That includes their .env files and any credential left in one. If you need one sibling, grant just that path.",
	},
	"podman_offline": {
		Quotes: []Quote{{Src: base, Text: "`@podman-socket` without `@net` is genuinely offline, containers included."}},
		Say:    "Add @net if the containers must pull images or reach the internet.",
	},
	"podman_build": {
		Quotes: []Quote{{Src: base, Label: "@podman-build", Text: "As podman-socket, plus `podman build` with a filtered option set."}},
		Say:    "Building images needs @net for the base images.",
	},
	"port_publish": {
		Quotes: []Quote{{Src: base, Text: "`podman run -p N:80` is NOT supported, a decline rather than a regression"}},
		Say:    "Ports are not published to the host. Use a door (\"serve my web app\") to open an app in your browser.",
	},
	"compose_subdir_volume": {
		Quotes: []Quote{{Src: base, Text: "so `-v ./data:/data` stays refused and the answer is `-v .:/x` plus /x/data inside the container."}},
		Say:    "A volume of a subdirectory of the project is refused by snug's engine proxy; mount the project root and use the subdirectory inside the container.",
	},
	"secrets_file": {
		Quotes: []Quote{{Src: base, Text: "put the secret in a file, not the environment"}},
		Say:    "Secrets in environment variables are readable by every process in the sandbox. Put them in a file and grant the file.",
	},
	"identity_one": {
		Quotes: []Quote{
			{Src: base, Text: "TWO ACCOUNTS ARE TWO PROFILES, and that needs no mechanism snug does not have."},
			{Src: base, Text: "Selecting both at once is a hard error naming them, because an identity is a pin and two pins are a contradiction rather than a union."},
		},
		Say: "Save this profile, then start a second one for the other account.",
	},
	"git": {
		Quotes: []Quote{{Src: base, Text: "the sandbox learns the name and email you commit under, and nothing else from your git config."}},
		Say:    "@git copies your git author; an identity pins a specific author, key and account together.",
	},
	"claude": {
		Quotes: []Quote{{Src: base, Text: "the sandbox can spend your Anthropic credits and read your Claude settings and personal skills."}},
		Say:    "@claude is the way to run Claude Code inside; ~/.claude itself is never granted.",
	},
	"layering": {
		Say: "Access joins by the deepest grant: grant the tree read-only and the parts you want to write separately, for example ro ~/data and rw ~/data/out. There is no \"all but\".",
	},
	"readonly_target": {
		Say: "A read-only project runs with --no-defaults: the profile then carries @sys and @home itself and grants the target read-only. The run line below says so.",
	},
}

const helpText = `snug-setup builds a snug profile from what you say. Examples:
  give me write access here            read-only here
  I need internet / podman / git       which ssh keys are loaded?
  assign github account2               read this docker-compose
  call it work                         show / save
Commands that skip the model: /show /save /undo /help /quit`
