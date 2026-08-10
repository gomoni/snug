// Package profile loads TOML profile files into policy.Profile values.
//
// Decoding is STRICT: an unknown key is a fatal error. That is not pedantry —
// it is what stops a future or foreign key (a `mask`, a `deny`, an `exclude`)
// from being silently ignored while the human who wrote it believes the sandbox
// is tighter than it is.
package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/gomoni/snug/internal/policy"
)

type file struct {
	Profile map[string]rawProfile `toml:"profile"`
}

type rawProfile struct {
	Description string           `toml:"description"`
	Include     []string         `toml:"include"`
	RO          []string         `toml:"ro"`
	RW          []string         `toml:"rw"`
	Tmpfs       []string         `toml:"tmpfs"`
	Symlink     []policy.Symlink `toml:"symlink"`
	Optional    []string         `toml:"optional"`

	// Environ is the five verbs, nested under one key. Nested rather than five
	// root keys for three reasons, the load-bearing one being that `environ` is
	// a struct with known fields, so DisallowUnknownFields catches
	// `environ.deny` exactly as it catches an unknown root key — "a negation key
	// cannot be smuggled in" applies one level down for free (§1.1b).
	//
	// A pointer so an absent block and an empty one are the same thing here and
	// neither needs a special case below.
	Environ *rawEnviron `toml:"environ"`

	// Env and Path are the retired spellings, kept as FIELDS rather than
	// deleted. Deleting them would let DisallowUnknownFields produce the generic
	// "unknown key" message, and a key whose meaning MOVED deserves a named
	// error pointing at the replacement (§6). Today they are rewritten into
	// Environ with a warning; the hard error comes later.
	Env  []string `toml:"env"`
	Path []string `toml:"path"`

	Network string `toml:"network"`
	DNS     bool   `toml:"dns"`
	Publish []int  `toml:"publish"`
	Address string `toml:"address"`
	Gateway string `toml:"gateway"`
	MTU     int    `toml:"mtu"`

	Podman   string       `toml:"podman"`
	Identity *rawIdentity `toml:"identity"`
}

// rawEnviron is the `[profile.NAME.environ.*]` block as TOML delivers it.
//
// Merge and Prepend are map[string]any rather than map[string][]string, and
// that is measured rather than defensive: go-toml v2.4.3 accepts BOTH
// `PATH = "/a"` and `PATH = ["/a","/b"]` into an `any`, and only into an `any`.
// Both spellings are legal — a string is exactly ONE element, because snug
// never splits a value on a separator (CALL 1, §2.2) — so the converter has to
// see either and say something useful about anything else. go-toml's own decode
// error names neither the profile nor the file.
//
// Inherit and Sanitise are map[string]bool because the TOML spelling is
// `NAME = true`: the profile supplies a name, never a value. `= false` is
// refused by name rather than stored, or it would be a negation key that parsed.
type rawEnviron struct {
	Set      map[string]string `toml:"set"`
	Merge    map[string]any    `toml:"merge"`
	Prepend  map[string]any    `toml:"prepend"`
	Inherit  map[string]bool   `toml:"inherit"`
	Sanitise map[string]bool   `toml:"sanitise"`
}

type rawIdentity struct {
	SSHKey   string `toml:"ssh_key"`
	SSHMode  string `toml:"ssh_mode"`
	GitName  string `toml:"git_name"`
	GitEmail string `toml:"git_email"`
	GhUser   string `toml:"gh_user"`
	GhHost   string `toml:"gh_host"`
}

// checkName rejects a profile name that would break a mechanism.
//
// These are not style rules and this is not namespace policing — a user may
// call a profile whatever they like, including uppercase or dotted. Each
// character below breaks something concrete, and every one of them parsed
// happily before this existed:
//
//	","  snug joins the resolved names with commas into SNUG_PROFILES, which is
//	     the sandbox's own account of what was selected. A profile named "a,b"
//	     corrupts it, and anything reading it back is silently misled.
//	":"  reserved for a parked design where a profile takes arguments
//	     (.claude/design/PARAMETERISED-PROFILES.md): "name:arg" must split unambiguously.
//	"-"  leading, because `snug -p -v` would otherwise name a profile "-v"
//	     rather than fail.
//	"@"  leading, because that mark means "snug ships this" and is added by
//	     Builtins() alone — see policy.Sigil. Note that this rule applies to
//	     EVERY file, base.toml included: the builtins are written here under
//	     bare names and marked on load, so no file anywhere may claim the mark
//	     for itself.
//	     whitespace/NUL, because every --dry-run line and every Validate error
//	     renders provenance as a space-free token; a name with a space in it
//	     turns those into nonsense.
//	""   the empty name, which TOML accepts as [profile.""].
//
// Checked in parse rather than merge: the FILE is what is wrong, and parse is
// where the source path and the offending name are both in hand.
func checkName(name, source string) error {
	if name == "" {
		return fmt.Errorf("%s: a profile with an empty name", source)
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%s: profile %q may not start with '-'; it would be "+
			"indistinguishable from a flag on the command line", source, name)
	}
	if strings.HasPrefix(name, policy.Sigil) {
		return fmt.Errorf("%s: profile %q may not start with '%s'; that mark means "+
			"\"snug ships this profile\" and snug adds it itself. Drop it and the "+
			"profile is yours: %q", source, name, policy.Sigil,
			strings.TrimPrefix(name, policy.Sigil))
	}
	for _, bad := range []struct {
		s    string
		what string
	}{
		{",", "a comma (snug joins profile names with commas into SNUG_PROFILES)"},
		{":", "a colon (reserved for profile arguments)"},
		{" ", "a space"},
		{"\t", "a tab"},
		{"\x00", "a NUL"},
	} {
		if strings.Contains(name, bad.s) {
			return fmt.Errorf("%s: profile %q contains %s", source, name, bad.what)
		}
	}
	return nil
}

// Registry is the merged set of known profiles.
type Registry map[string]*policy.Profile

// parse decodes one TOML document into profiles.
func parse(data []byte, source string, trusted bool) (Registry, error) {
	var f file
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		var se *toml.StrictMissingError
		if ok := asStrict(err, &se); ok {
			return nil, fmt.Errorf("%s: unknown key (snug decodes profiles strictly, so a key it does not "+
				"understand is an error rather than a silently ignored grant):\n%s", source, se.String())
		}
		return nil, fmt.Errorf("%s: %w", source, err)
	}

	reg := Registry{}
	for name, r := range f.Profile {
		if err := checkName(name, source); err != nil {
			return nil, err
		}
		environ, err := toEnvGrants(r, name, source)
		if err != nil {
			return nil, err
		}
		// Checked HERE, beside checkName and DisallowUnknownFields, and not in
		// Resolve: the name grammar, verb/type agreement and the forbidden names
		// are all properties of the profile TEXT, so `snug profile show` reports
		// them too and the verdict on a profile never depends on the host that
		// happens to be reading it (§2.3, §2.5).
		if err := policy.ValidateEnvGrants(environ); err != nil {
			return nil, fmt.Errorf("%s: profile %q: %w", source, name, err)
		}
		reg[name] = &policy.Profile{
			Name:        name,
			Description: r.Description,
			Include:     r.Include,
			RO:          r.RO,
			RW:          r.RW,
			Tmpfs:       r.Tmpfs,
			Symlink:     r.Symlink,
			Optional:    r.Optional,
			Environ:     environ,
			Network:     r.Network,
			DNS:         r.DNS,
			Publish:     r.Publish,
			Address:     r.Address,
			Gateway:     r.Gateway,
			MTU:         r.MTU,
			Podman:      r.Podman,
			Identity:    toIdentity(r.Identity),
			Source:      source,
			Trusted:     trusted,
		}
	}
	return reg, nil
}

// toEnvGrants turns one profile's raw `environ` block — plus the two retired
// keys it absorbs — into the value the resolver folds.
//
// The retired keys are REWRITTEN, not carried alongside: `env = [...]` is
// exactly `environ.inherit` and `path = [...]` is exactly `environ.merge` on
// PATH, and shipping both spellings would be two mechanisms for one idea, which
// is what the retired `default` profile exists to warn about.
func toEnvGrants(r rawProfile, name, source string) (policy.EnvGrants, error) {
	g := policy.EnvGrants{}
	if e := r.Environ; e != nil {
		g.Set = copyStringMap(e.Set)
		var err error
		if g.Merge, err = toElementLists(e.Merge, "merge", name, source); err != nil {
			return g, err
		}
		if g.Prepend, err = toElementLists(e.Prepend, "prepend", name, source); err != nil {
			return g, err
		}
		if g.Inherit, err = toNameSet(e.Inherit, "inherit", name, source); err != nil {
			return g, err
		}
		if g.Sanitise, err = toNameSet(e.Sanitise, "sanitise", name, source); err != nil {
			return g, err
		}
	}

	if len(r.Env) > 0 {
		warnRetiredKey(source, name, "env", "[profile."+name+".environ.inherit] with NAME = true per variable")
		g.Inherit = mergeNames(g.Inherit, r.Env)
	}
	if len(r.Path) > 0 {
		warnRetiredKey(source, name, "path", "[profile."+name+".environ.merge] on PATH")
		if g.Merge == nil {
			g.Merge = map[string][]string{}
		}
		g.Merge["PATH"] = append(append([]string(nil), g.Merge["PATH"]...), r.Path...)
	}
	return g, nil
}

// warnRetiredKey tells the human which file to edit and what to write instead.
// Non-fatal for now; the named hard error comes when the keys are retired.
//
// It is silent for a BUILTIN, and that is not snug covering for itself: the
// source of a builtin is a file compiled into the binary, so the message would
// name something the reader cannot edit — and a warning nobody can act on
// trains people to ignore warnings. snug's own use of the retired keys is
// caught by its own test suite the moment they become fatal, which is a harder
// gate than a line on stderr.
func warnRetiredKey(source, profile, key, replacement string) {
	if strings.HasPrefix(source, "builtin:") {
		return
	}
	fmt.Fprintf(os.Stderr, "snug: %s: profile %q uses `%s = [...]`, which is being retired. "+
		"Write it as %s.\n", source, profile, key, replacement)
}

// toElementLists accepts a bare string as ONE element and an array as its
// elements, per CALL 1. Anything else gets an error naming the profile, the
// file, the verb and the variable — go-toml's own would name none of them.
func toElementLists(in map[string]any, verb, profile, source string) (map[string][]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(in))
	for _, key := range sortedAnyKeys(in) {
		switch v := in[key].(type) {
		case string:
			// One element, NOT a value to be split. That is the whole of §2.2,
			// and the separator check in policy.ValidateEnvGrants is what makes
			// it safe: a hand-written separator can smuggle in an empty element,
			// and an empty element in a search path is the current directory.
			out[key] = []string{v}
		case []any:
			elems := make([]string, 0, len(v))
			for i, e := range v {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("%s: profile %q: environ.%s %s[%d] is %T, but an "+
						"environment value is a string — every element of a list variable is "+
						"one path or one word, written whole",
						source, profile, verb, key, i, e)
				}
				elems = append(elems, s)
			}
			out[key] = elems
		default:
			return nil, fmt.Errorf("%s: profile %q: environ.%s %s is %T, but it must be a "+
				"string or an array of strings — a string is exactly one element, because "+
				"snug never splits a value on a separator",
				source, profile, verb, key, in[key])
		}
	}
	return out, nil
}

// toNameSet turns `NAME = true` into a sorted list of names, and refuses
// `NAME = false` by name.
func toNameSet(in map[string]bool, verb, profile, source string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for _, name := range sortedBoolKeys(in) {
		if !in[name] {
			return nil, fmt.Errorf("%s: profile %q: environ.%s %s = false. `%s` takes `true`; "+
				"there is no way to un-%s, because nothing was %sed to begin with — the "+
				"environment starts empty and every variable in it was put there by name. "+
				"Remove the line",
				source, profile, verb, name, verb, verb, verb)
		}
		out = append(out, name)
	}
	return out, nil
}

func mergeNames(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toIdentity(r *rawIdentity) *policy.Identity {
	if r == nil {
		return nil
	}
	// ssh_mode is validated in policy.Resolve, not here: an unknown mode should
	// name the profile it came from, and only the resolver knows that.
	return &policy.Identity{
		SSHKey:   r.SSHKey,
		SSHMode:  policy.SSHMode(r.SSHMode),
		GitName:  r.GitName,
		GitEmail: r.GitEmail,
		GhUser:   r.GhUser,
		GhHost:   r.GhHost,
	}
}

func asStrict(err error, target **toml.StrictMissingError) bool {
	se, ok := err.(*toml.StrictMissingError)
	if ok {
		*target = se
	}
	return ok
}

// merge folds a layer into the registry. A later layer may ADD profile names but
// never redefine one: silently taking the last definition of a name would make
// what a profile grants depend on which file was read last, which is the same
// class of problem as a deny rule.
//
// Shadowing a BUILTIN no longer reaches this check at all, and that is the
// improvement the sigil bought. `@sys` is a name no file can write (checkName
// refuses a leading @, see policy.Sigil), so a user file saying [profile.sys]
// defines a profile of their own rather than half-redefining snug's. What
// remains here is collisions between the layers a human does control —
// /etc/snug/profiles.d against their own ~/.config — where a hard error naming
// both files is still the right answer.
func (r Registry) merge(other Registry) error {
	names := make([]string, 0, len(other))
	for n := range other {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if existing, ok := r[n]; ok {
			return fmt.Errorf("profile %q in %s redefines the one from %s; "+
				"pick a different name rather than shadowing it", n, other[n].Source, existing.Source)
		}
		r[n] = other[n]
	}
	return nil
}

// BadFile is a profile file that would not parse, kept rather than returned as
// the whole answer.
//
// Load used to stop at the first one, and the consequence was measured: a single
// stale file in profiles.d took down the ENTIRE registry, builtins included, so
// `snug --dry-run -p @sys .` reported that error and `snug profile list` — the
// one command that would tell the user what still works — was exactly what
// stopped working. A file the user may not have edited disabled @sys.
//
// The split is by consequence, not by severity. A command that RUNS A SANDBOX
// stays fatal on any bad file: the file that did not parse may be the one
// granting what was asked for, and a sandbox assembled from what happened to
// load is a silent downgrade (invariant 5). A DIAGNOSTIC command reports the
// file loudly and continues with what did load, because "what still works" is
// the question being asked.
type BadFile struct {
	Path string
	Err  error
}

// Load assembles the registry from the trusted layers, in precedence order:
//
//  1. embedded builtins   — compiled in, cannot be shadowed
//  2. /etc/snug/profiles.d/*.toml
//  3. $XDG_CONFIG_HOME/snug/profiles.d/*.toml   (the user's own)
//
// There is deliberately NO fourth layer. snug never auto-loads .snug/ or
// snug.toml from beside the target: a hostile repository that ships its own
// profile would be granting itself permissions, which defeats the entire threat
// model. See .claude/design/INDEX.md §2.7.
//
// The returned error is for failures that leave no usable registry at all: a
// builtin that will not parse (a bug in snug), an unreadable directory entry, or
// a REDEFINITION, which stays hard everywhere — two files claiming one name is a
// question with no answer, and continuing would mean picking one silently.
// Per-file parse failures come back as BadFiles instead; see there for why.
func Load() (Registry, []BadFile, error) {
	reg, err := Builtins()
	if err != nil {
		return nil, nil, err
	}
	var bad []BadFile
	for _, dir := range ConfigDirs() {
		layer, layerBad, err := loadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		bad = append(bad, layerBad...)
		if err := reg.merge(layer); err != nil {
			return nil, nil, err
		}
	}
	return reg, bad, nil
}

// ConfigDirs are the directories snug reads profiles from, in precedence order.
// Note what is not here: anything derived from the target directory.
func ConfigDirs() []string {
	dirs := []string{"/etc/snug/profiles.d"}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		if home, err := os.UserHomeDir(); err == nil {
			xdg = filepath.Join(home, ".config")
		}
	}
	if xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "snug", "profiles.d"))
	}
	return dirs
}

func loadDir(dir string) (Registry, []BadFile, error) {
	reg := Registry{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return reg, nil, nil // absent config dir is normal, not an error
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".toml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var bad []BadFile
	for _, n := range names {
		path := filepath.Join(dir, n)
		// A file that cannot be READ is recorded the same way as one that cannot
		// be parsed: it is one file's problem, and the rest of the layer is still
		// perfectly good.
		data, err := os.ReadFile(path)
		if err != nil {
			bad = append(bad, BadFile{Path: path, Err: err})
			continue
		}
		layer, err := parse(data, path, true)
		if err != nil {
			bad = append(bad, BadFile{Path: path, Err: err})
			continue
		}
		if err := reg.merge(layer); err != nil {
			return nil, nil, err
		}
	}
	return reg, bad, nil
}
