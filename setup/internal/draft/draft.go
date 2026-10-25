// Package draft is the profile being built. Actions mutate it, Render writes it
// as a `[profile.NAME]` TOML table.
//
// The setup-side safety rules live here and are enforced whatever the model
// said: a model that was talked into emitting `grant_path ~/.ssh` gets a
// refusal from Apply, not a profile.
package draft

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Refusal codes Apply can return. They name rules that
// Go enforces.
const (
	CodeKernelPath  = "kernel_path"
	CodeReservedEnv = "reserved_env"
	CodeBadValue    = "bad_value"
	CodeNotGranted  = "not_granted"
	CodeUnknownList = "unknown_list_var"
	CodeNoVerb      = "no_verb"
	CodeNoSuchEntry = "no_such_entry"
	CodeHostPointer = "host_pointer"
	CodeHostSystem  = "host_system"
)

// Host is what path decisions need to know about the machine. FS functions
// default to the real filesystem; tests inject.
type Host struct {
	Home       string
	Target     string
	RuntimeDir string // $XDG_RUNTIME_DIR, "" when unset
	ConfigHome string // $XDG_CONFIG_HOME, "" when unset

	EvalSymlinks func(string) (string, error)
	Stat         func(string) (fs.FileInfo, error)
}

func (h Host) evalSymlinks(p string) (string, error) {
	if h.EvalSymlinks != nil {
		return h.EvalSymlinks(p)
	}
	return filepath.EvalSymlinks(p)
}

func (h Host) stat(p string) (fs.FileInfo, error) {
	if h.Stat != nil {
		return h.Stat(p)
	}
	return os.Stat(p)
}

// Outcome is the result of Apply.
type Outcome struct {
	// NotMine is true for ops the draft does not handle (identity, reads, session).
	NotMine bool
	// Refused is a refusal code, "" when the action was accepted.
	Refused string
	// Msg is for the human: the reason behind a refusal, or what changed.
	Msg string
	// Changed is true when the draft differs afterwards.
	Changed bool
	// Default is true when the request is already met by what a bare
	// `snug DIR` selects; Msg is then empty and the draft unchanged.
	Default bool
}

type pair struct{ K, V string }

// SSHIdentity pins one public key.
type SSHIdentity struct {
	Stem string
	Key  string // spelled for the profile, {home}/.ssh/NAME.pub
}

// GHIdentity pins one gh login.
type GHIdentity struct{ Host, User string }

// GitIdentity pins one git author, and optionally the key commits are signed
// with. SigningKey is spelled for the profile ({home}/.ssh/NAME.pub) and
// SigningStem is the file name without .pub.
type GitIdentity struct{ Name, Email, SigningKey, SigningStem string }

// Draft is the profile under construction. The zero value is not usable; call New.
type Draft struct {
	Name string
	// Description is rendered as the profile's `description` key, right
	// after the table header; "" renders nothing.
	Description string
	Host        Host
	Include     []string
	RO          []string
	RW          []string
	Tmpfs       []string
	// Staged are host:name pairs rendered as ro = ["HOST:/snug/bin/NAME"].
	Staged     []pair
	EnvSet     []pair
	EnvInherit []string
	EnvPrepend []pair // V is one path; several pairs may share a K
	Doors      []string
	// ReadOnlyTarget means the target is granted ro, so the profile must be run
	// with --no-defaults and carries @sys and @home itself.
	ReadOnlyTarget bool

	SSH *SSHIdentity
	GH  *GHIdentity
	Git *GitIdentity

	// Notes are the descriptions of the user profiles in Include, by name,
	// for the comment above each in the rendered file.
	Notes map[string]string

	ledger []Entry
}

// New returns an empty draft for host.
func New(host Host) *Draft { return &Draft{Host: host} }

// Clone returns a deep copy.
func (d *Draft) Clone() *Draft {
	c := *d
	c.Include = slices.Clone(d.Include)
	c.RO = slices.Clone(d.RO)
	c.RW = slices.Clone(d.RW)
	c.Tmpfs = slices.Clone(d.Tmpfs)
	c.Staged = slices.Clone(d.Staged)
	c.EnvSet = slices.Clone(d.EnvSet)
	c.EnvInherit = slices.Clone(d.EnvInherit)
	c.EnvPrepend = slices.Clone(d.EnvPrepend)
	c.Doors = slices.Clone(d.Doors)
	c.ledger = slices.Clone(d.ledger)
	c.Notes = maps.Clone(d.Notes)
	if d.SSH != nil {
		v := *d.SSH
		c.SSH = &v
	}
	if d.GH != nil {
		v := *d.GH
		c.GH = &v
	}
	if d.Git != nil {
		v := *d.Git
		c.Git = &v
	}
	return &c
}

// Empty reports whether nothing has been granted.
func (d *Draft) Empty() bool {
	return len(d.Include) == 0 && len(d.RO) == 0 && len(d.RW) == 0 && len(d.Tmpfs) == 0 &&
		len(d.Staged) == 0 && len(d.EnvSet) == 0 && len(d.EnvInherit) == 0 && len(d.EnvPrepend) == 0 &&
		len(d.Doors) == 0 && !d.ReadOnlyTarget && d.SSH == nil && d.GH == nil && d.Git == nil
}

func refuse(code, msg string) Outcome { return Outcome{Refused: code, Msg: msg} }

func changed(msg string) Outcome { return Outcome{Msg: msg, Changed: true} }

// Apply applies a model action to the draft. Accepted actions change it and say
// what happened in Msg; refused ones leave it untouched and carry a refusal
// code in Refused. Ops that are not the draft's business (identities, reading
// files, session control, refuse, note, ask) return NotMine.
func (d *Draft) Apply(a Action) Outcome {
	switch a.Op {
	case OpUseProfile:
		return d.use(a.Name)
	case OpDropProfile:
		return d.drop(a.Name)
	case OpIncludeProfile:
		return d.includeUser(a.Name)
	case OpGrantPath:
		return d.grant(a.Path, a.Access)
	case OpDropPath:
		return d.dropPath(a.Path)
	case OpStageBinary:
		return d.stage(a.Host, a.Name)
	case OpSetEnv:
		return d.setEnv(a)
	case OpOpenDoor:
		if slices.Contains(d.Doors, a.Name) {
			return Outcome{Msg: "door " + a.Name + " is already in the draft."}
		}
		d.Doors = append(d.Doors, a.Name)
		return changed("added the door " + a.Name + " (listen_names). Your server must accept on the descriptor snug hands it (LISTEN_FDS, fd 3); `snug proxy DIR` opens it. Add @net if your server needs the network.")
	case OpNameProfile:
		if !ValidProfileName(a.Name) {
			return refuse(CodeBadValue, "profile names are [a-zA-Z0-9][a-zA-Z0-9-]*: no underscore, no dot, no leading @")
		}
		d.Name = a.Name
		return changed("profile is called " + a.Name + ".")
	}
	return Outcome{NotMine: true}
}

func (d *Draft) use(name string) Outcome {
	if slices.Contains(d.Include, name) {
		return Outcome{Msg: name + " is already in the draft."}
	}
	switch name {
	case "@parent-ro":
		if filepath.Dir(d.Host.Target) == filepath.Clean(d.Host.Home) {
			return refuse("whole_home", "the target "+d.Host.Target+" sits directly in your home directory, so @parent-ro would be $HOME")
		}
	case "@podman-socket":
		if slices.Contains(d.Include, "@podman-build") {
			return Outcome{Msg: "@podman-build already includes @podman-socket."}
		}
	case "@podman-build":
		d.Include = slices.DeleteFunc(d.Include, func(s string) bool { return s == "@podman-socket" })
	case "@target-rw":
		// A bare `snug DIR` selects it, so the profile carries it only by
		// not being --no-defaults.
		if d.ReadOnlyTarget {
			d.ReadOnlyTarget = false
			d.RO = slices.DeleteFunc(d.RO, func(s string) bool { return d.expand(s) == d.Host.Target })
			return changed("the target is writable again: the read-only grant is gone, and a bare `snug DIR` selects @target-rw.")
		}
		return Outcome{Default: true}
	}
	d.Include = append(d.Include, name)
	return changed("added " + name + ".")
}

// includeUser adds one of the human's own profiles by name. Whether snug has a
// profile of that name, and whether it resolves, is the caller's check and
// snug's: the draft only refuses a name that cannot be a user profile.
func (d *Draft) includeUser(name string) Outcome {
	if !ValidProfileName(name) {
		return refuse(CodeBadValue, "profile names are [a-zA-Z0-9][a-zA-Z0-9-]*: no underscore, no dot, no leading @")
	}
	if slices.Contains(d.Include, name) {
		return Outcome{Msg: "your profile " + name + " is already in the draft."}
	}
	d.Include = append(d.Include, name)
	return changed("included your profile " + name + ".")
}

// NoteProfile records the description rendered above an included user profile.
func (d *Draft) NoteProfile(name, description string) {
	if d.Notes == nil {
		d.Notes = map[string]string{}
	}
	d.Notes[name] = description
}

func (d *Draft) drop(name string) Outcome {
	has := slices.Contains(d.Include, name)
	if name == "@podman-socket" && slices.Contains(d.Include, "@podman-build") {
		has = true
	}
	if !has {
		return Outcome{Msg: name + " is not in the draft."}
	}
	d.Include = slices.DeleteFunc(d.Include, func(s string) bool { return s == name })
	if name == "@podman-socket" {
		d.Include = slices.DeleteFunc(d.Include, func(s string) bool { return s == "@podman-build" })
	}
	return changed("dropped " + name + ".")
}

// expand turns the spelling of a path into an absolute clean path on the host.
// A relative path and the words `here` and `.` mean the target.
func (d *Draft) expand(p string) string {
	h := d.Host
	switch {
	case p == "" || p == "." || p == "here":
		return filepath.Clean(h.Target)
	case p == "~":
		return filepath.Clean(h.Home)
	case strings.HasPrefix(p, "~/"):
		p = h.Home + "/" + p[2:]
	}
	p = strings.NewReplacer(
		"{home}", h.Home,
		"{target_parent}", filepath.Dir(h.Target),
		"{target}", h.Target,
	).Replace(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(h.Target, p)
	}
	return filepath.Clean(p)
}

// spell normalises the one path that must stay portable across directories,
// the target itself, resolves relative spellings, and leaves every other
// spelling as the user wrote it.
func (d *Draft) spell(p string) string {
	if d.expand(p) == filepath.Clean(d.Host.Target) {
		return "{target}"
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "{") {
		return filepath.Clean(p)
	}
	return d.expand(p)
}

var badPathChars = regexp.MustCompile("[\\x00-\\x1f\\x7f\"\\\\:]")

// hidden reports whether s holds a character that renders as something other
// than what the profile file contains: any control character (C1 included),
// any Unicode format character (bidi overrides and isolates, zero-width
// characters, U+FEFF, tag characters), or a line or paragraph separator. A
// path or value the model chose is written into the file a human reads
// before selecting it.
func hidden(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
	}) >= 0
}

// CheckTarget refuses a target directory whose path carries a control or
// invisible formatting character. The path is shown on the screen and written
// into the model's prompt, where a newline would add a line of its own.
func CheckTarget(p string) error {
	if hidden(p) {
		return fmt.Errorf("the target path %q contains a control or invisible formatting character; rename the directory", p)
	}
	return nil
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// sensitiveHome lists paths, relative to $HOME, that hold credentials. Granting
// one, or a directory above it inside $HOME, is refused.
var sensitiveHome = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".docker", ".kube",
	".claude", ".claude.json",
	".local/share/keyrings", ".gnome2/keyrings", ".local/share/kwalletd",
	".git-credentials", ".npmrc", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
	".config/containers/auth.json", ".config/gcloud", ".password-store",
	// Browser profiles: saved passwords, session cookies, OAuth tokens.
	".mozilla", ".librewolf", ".config/google-chrome", ".config/chromium",
	".config/BraveSoftware", ".config/microsoft-edge",
}

// snugConfigDirs are the directories snug reads its trusted profile set from:
// ~/.config/snug, and $XDG_CONFIG_HOME/snug when that is set, each also as it
// resolves. A hostile process with rw on one, or on a directory above one,
// writes the profiles the next snug run trusts.
func (d *Draft) snugConfigDirs() []string {
	dirs := []string{filepath.Join(filepath.Clean(d.Host.Home), ".config", "snug")}
	if d.Host.ConfigHome != "" {
		dirs = append(dirs, filepath.Join(filepath.Clean(d.Host.ConfigHome), "snug"))
	}
	for _, c := range slices.Clone(dirs) {
		if r, err := d.Host.evalSymlinks(c); err == nil && r != c {
			dirs = append(dirs, r)
		}
	}
	return dirs
}

// hostRunHome lists paths, relative to $HOME, that the host executes or reads
// as configuration for programs it runs: shell startup files, user units,
// autostart entries, ~/.local/bin on PATH, and git config, whose core.hooksPath
// and core.fsmonitor name programs. A hostile process with rw on one plants a
// command the host runs outside the sandbox, so rw on one, or on a directory
// above it inside $HOME, is refused. ro and tmpfs write nothing to the host.
var hostRunHome = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
	".zshrc", ".zshenv", ".zprofile", ".zlogin", ".config/fish",
	".config/systemd/user", ".config/autostart", ".config/environment.d", ".local/share/applications",
	".local/bin", ".gitconfig", ".config/git",
}

// hostSystemTops are the first path components of the host's system
// directories, and "lib" stands for lib, lib32, lib64 and libexec. A rw grant
// on one, or on anything under it, is refused unless it is inside the
// target or $HOME: a change there outlives the sandbox as a change to the
// system itself. Read-only is a different question, answered by baseReadOnly.
var hostSystemTops = []string{"etc", "usr", "bin", "sbin", "opt", "var", "boot", "srv"}

func hostSystemPath(q string) bool {
	top, _, _ := strings.Cut(strings.TrimPrefix(q, "/"), "/")
	return slices.Contains(hostSystemTops, top) || strings.HasPrefix(top, "lib")
}

// baseReadOnly lists directories snug's @sys already binds read-only
// ([profile.sys] ro in base.toml; TestBaseReadOnlyIsStillInBaseToml holds it).
// Granting one again adds nothing. The /etc entries @sys lists are
// individual files and directories and are not repeated here.
var baseReadOnly = []string{"/usr", "/opt"}

var kernelPaths = []string{"/proc", "/dev", "/sys", "/snug"}

var socketTrees = []string{"/tmp/.X11-unix", "/tmp/.ICE-unix", "/run/user", "/var/run/user", "/run/dbus", "/var/run/dbus"}

var engineSocketTrees = []string{"/run/docker", "/var/run/docker", "/run/podman", "/var/run/podman", "/run/containerd", "/var/run/containerd"}

// checkHostPath returns a refusal for a host path that must never be granted at
// access, looking at both the spelling and where it resolves to.
func (d *Draft) checkHostPath(p, access string) *Outcome {
	if badPathChars.MatchString(p) || hidden(p) {
		o := refuse(CodeBadValue, fmt.Sprintf("%q contains a control or invisible formatting character, quote, backslash or colon, which a profile path cannot carry", p))
		return &o
	}
	exp := d.expand(p)
	cands := []string{exp}
	if r, err := d.Host.evalSymlinks(exp); err == nil && r != exp {
		cands = append(cands, r)
	}
	home := filepath.Clean(d.Host.Home)
	for _, q := range cands {
		via := ""
		if q != exp {
			via = " (" + exp + " is a symlink to it)"
		}
		if under(home, q) {
			o := refuse("whole_home", fmt.Sprintf("%s%s is your home directory or a directory above it", q, via))
			return &o
		}
		for _, s := range sensitiveHome {
			full := filepath.Join(home, s)
			if under(q, full) || (under(full, q) && under(q, home)) {
				o := refuse("sensitive_home", fmt.Sprintf("%s%s is, or contains, ~/%s", q, via, s))
				return &o
			}
		}
		if access == "rw" {
			for _, c := range d.snugConfigDirs() {
				if under(q, c) || under(c, q) {
					o := refuse("sensitive_home", fmt.Sprintf("%s%s is, or contains, %s, where snug reads the profiles it trusts; grant it ro", q, via, c))
					return &o
				}
			}
			for _, s := range hostRunHome {
				full := filepath.Join(home, s)
				if under(q, full) || (under(full, q) && under(q, home)) {
					o := refuse("sensitive_home", fmt.Sprintf("%s%s is, or contains, ~/%s, which your host runs outside the sandbox; grant it ro", q, via, s))
					return &o
				}
			}
		}
		for _, k := range kernelPaths {
			if under(q, k) {
				o := refuse(CodeKernelPath, fmt.Sprintf("%s%s is under %s, which snug owns inside the sandbox", q, via, k))
				return &o
			}
		}
		base := filepath.Base(q)
		if base == "docker.sock" || base == "podman.sock" || base == "containerd.sock" {
			o := refuse("docker_sock", fmt.Sprintf("%s%s is a container engine socket", q, via))
			return &o
		}
		for _, t := range engineSocketTrees {
			if under(q, t) {
				o := refuse("docker_sock", fmt.Sprintf("%s%s is under %s, where container engine sockets live", q, via, t))
				return &o
			}
		}
		if q == "/run" || q == "/var/run" || strings.HasSuffix(base, ".sock") || strings.HasPrefix(base, "wayland-") ||
			(d.Host.RuntimeDir != "" && under(q, filepath.Clean(d.Host.RuntimeDir))) {
			o := refuse("desktop_socket", fmt.Sprintf("%s%s is, or holds, a unix socket or the runtime directory", q, via))
			return &o
		}
		for _, t := range socketTrees {
			if under(q, t) {
				o := refuse("desktop_socket", fmt.Sprintf("%s%s is under %s", q, via, t))
				return &o
			}
		}
		if fi, err := d.Host.stat(q); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			o := refuse("desktop_socket", fmt.Sprintf("%s%s is a unix socket", q, via))
			return &o
		}
		if access == "rw" && hostSystemPath(q) && !under(q, filepath.Clean(d.Host.Target)) && !under(q, home) {
			o := refuse(CodeHostSystem, fmt.Sprintf("%s%s is a host system directory, and a change there persists on the host", q, via))
			return &o
		}
	}
	return nil
}

func (d *Draft) grant(path, access string) Outcome {
	if o := d.checkHostPath(path, access); o != nil {
		return *o
	}
	exp := d.expand(path)
	spelled := d.spell(path)
	note := ""
	if _, err := d.Host.stat(exp); err != nil && access != "tmpfs" {
		note = " Note: " + exp + " does not exist on this host; snug will not start until it does."
	}
	has := func(list []string) bool {
		return slices.ContainsFunc(list, func(s string) bool { return d.expand(s) == exp })
	}
	del := func(list *[]string) {
		*list = slices.DeleteFunc(*list, func(s string) bool { return d.expand(s) == exp })
	}
	isTarget := exp == filepath.Clean(d.Host.Target)
	switch access {
	case "ro":
		if has(d.RW) {
			return Outcome{Msg: exp + " is already writable; a path granted both ro and rw is rw (the deepest, widest grant wins)."}
		}
		if has(d.RO) || (isTarget && d.ReadOnlyTarget) {
			return Outcome{Msg: exp + " is already read-only in the draft."}
		}
		if dir := d.baseGranted(exp); dir != "" {
			return Outcome{Msg: exp + " is already read-only in every sandbox: snug's @sys binds " + dir + " read-only. Nothing to add."}
		}
		if isTarget {
			d.ReadOnlyTarget = true
			return changed("the target " + exp + " is read-only." + note)
		}
		d.RO = append(d.RO, spelled)
		return changed("read-only: " + exp + "." + note)
	case "rw":
		if has(d.RW) {
			return Outcome{Msg: exp + " is already writable in the draft."}
		}
		wasRO := has(d.RO) || (isTarget && d.ReadOnlyTarget)
		del(&d.RO)
		if isTarget {
			d.ReadOnlyTarget = false
		}
		d.RW = append(d.RW, spelled)
		if wasRO {
			return changed("writable: " + exp + " (it was read-only)." + note)
		}
		return changed("writable: " + exp + "." + note)
	default:
		if has(d.Tmpfs) {
			return Outcome{Msg: exp + " is already a scratch tmpfs in the draft."}
		}
		d.Tmpfs = append(d.Tmpfs, spelled)
		return changed("scratch tmpfs at " + exp + ": writable, empty, in memory, gone when the sandbox exits.")
	}
}

// baseGranted returns the directory of baseReadOnly that holds p, as spelled
// or as it resolves, "" when none does.
func (d *Draft) baseGranted(p string) string {
	cands := []string{p}
	if r, err := d.Host.evalSymlinks(p); err == nil && r != p {
		cands = append(cands, r)
	}
	for _, q := range cands {
		for _, b := range baseReadOnly {
			if under(q, b) {
				return b
			}
		}
	}
	return ""
}

func (d *Draft) dropPath(path string) Outcome {
	exp := d.expand(path)
	n := 0
	for _, l := range []*[]string{&d.RO, &d.RW, &d.Tmpfs} {
		before := len(*l)
		*l = slices.DeleteFunc(*l, func(s string) bool { return d.expand(s) == exp })
		n += before - len(*l)
	}
	if d.ReadOnlyTarget && exp == filepath.Clean(d.Host.Target) {
		d.ReadOnlyTarget = false
		n++
	}
	before := len(d.Staged)
	d.Staged = slices.DeleteFunc(d.Staged, func(p pair) bool { return d.expand(p.K) == exp })
	n += before - len(d.Staged)
	if n == 0 {
		return refuse(CodeNoSuchEntry, exp+" is not granted by the draft (grants from @-profiles are dropped with drop_profile, not by path)")
	}
	return changed("removed " + exp + " from the draft.")
}

var binNameBad = map[string]bool{".": true, "..": true}

func (d *Draft) stage(host, name string) Outcome {
	if binNameBad[name] {
		return refuse(CodeBadValue, fmt.Sprintf("%q is not a command name", name))
	}
	if o := d.checkHostPath(host, "ro"); o != nil {
		return *o
	}
	exp := d.expand(host)
	fi, err := d.Host.stat(exp)
	switch {
	case err != nil:
		return refuse(CodeBadValue, exp+" does not exist on this host")
	case !fi.Mode().IsRegular():
		return refuse(CodeBadValue, exp+" is not a regular file; stage_binary binds one program")
	}
	d.Staged = slices.DeleteFunc(d.Staged, func(p pair) bool { return p.V == name })
	d.Staged = append(d.Staged, pair{host, name})
	return changed("staged " + exp + " as /snug/bin/" + name + " (read-only; snug puts that directory first on PATH, and the sandbox cannot write to it).")
}
