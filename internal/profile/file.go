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
	// error pointing at the replacement — see retiredEnvKey and retiredPathKey,
	// which is the whole reason these two lines are still here.
	Env  []string `toml:"env"`
	Path []string `toml:"path"`

	Network string `toml:"network"`
	DNS     bool   `toml:"dns"`
	Publish []int  `toml:"publish"`
	Address string `toml:"address"`
	Gateway string `toml:"gateway"`
	MTU     int    `toml:"mtu"`

	Podman   string       `toml:"podman"`
	Git      string       `toml:"git"`
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

// nameFault reports the byte offset of the first character the profile-name
// grammar refuses, or -1 when every character is legal.
//
//	first byte   [a-zA-Z0-9]
//	rest         [a-zA-Z0-9-]
//
// THIS IS THE ONLY PLACE THE GRAMMAR IS WRITTEN. checkName and checkRef both
// call it; neither re-implements it. A rule spelled out twice in this project
// has twice been fixed in one of its two halves (CLAUDE.md: checkEnvName vs
// checkEnvValue; visibleValue in one block and not the one four lines below).
//
// A BYTE loop, not `for _, r := range name`, and that is a decision rather than
// a habit: ranging over invalid UTF-8 yields U+FFFD and loses the byte that is
// actually in the file, so the error would describe a character nobody wrote.
// Every legal byte is ASCII, so a byte loop refuses multi-byte UTF-8 at its
// FIRST byte and can name that byte exactly.
//
// The EMPTY name faults at offset 0 — it is not legal, and a caller testing only
// the sign cannot mistake it for legal. Any caller that renders name[offset]
// must handle "" before calling.
func nameFault(name string) int {
	if name == "" {
		return 0
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		switch {
		case alnum:
		case c == '-' && i > 0:
		default:
			return i
		}
	}
	return -1
}

// nameByteDesc names one offending byte for an error message, and it must not
// lie about what is in the file.
//
// string(byte(0xc3)) is "Ã" — the byte-to-string conversion goes through a rune
// and MANGLES anything >= 0x80, so a UTF-8 name would be refused with a
// character the author never typed (internal/policy/envtypes.go:681 has this
// bug today; do not copy it). Printable ASCII is quoted, everything else is the
// hex byte, which is what a hex editor would show.
func nameByteDesc(c byte) string {
	if c >= 0x20 && c <= 0x7e {
		return fmt.Sprintf("%q", string(rune(c))) // exact: c < 0x80
	}
	return fmt.Sprintf(`the byte \x%02x`, c)
}

// checkName is an ALLOWLIST over a profile name, and the direction is the point.
//
//	first byte   [a-zA-Z0-9]
//	rest         [a-zA-Z0-9-]
//
// It was a DENYLIST of five individually-broken characters (comma, colon,
// space, tab, NUL) plus a leading '-' and a leading '@'. Every one of those was
// a real mechanism broken by a real character, and every one was found the hard
// way — but a denylist can only refuse what snug has already been taught about,
// and the sixth character was already reachable. Measured before this change:
// [profile."a\u001b[1A\rb"] parsed cleanly, and once selected the name reached
// the PROFILES line of --dry-run verbatim, where ESC[1A CR erases the row above
// it. What snug has not been taught about must fail closed.
//
// The reasons behind the old denylist all survive, and are now covered without
// naming a character:
//
//	","  snug joins the resolved names with commas into SNUG_PROFILES, and
//	     engine.New joins them with commas into the container store key — two
//	     consumers, and only one of them ever had a rule written for it.
//	":"  reserved for the parked design where a profile takes arguments
//	     (.claude/design/PARAMETERISED-PROFILES.md): "name:arg" must split
//	     unambiguously.
//	     whitespace and control characters, because every --dry-run line, every
//	     Validate error and every provenance string renders a name as a
//	     space-free token — a name with a space in it makes those nonsense, and
//	     a name with an ESC in it forges or erases rows in them.
//
// And it buys what a denylist could not: refusing punctuation in the FIRST
// position keeps every printable ASCII symbol free to become a sigil later
// without breaking a name somebody already chose. '@' is already one.
//
// The hyphen is IN — decided by the owner, and eight builtins depend on it
// (cwd-rw, parent-ro, tmp-shared, git-ro, net-anon, net-host, podman-socket,
// podman-build), so "alphanumerics only" would outlaw snug's own names.
// Underscore is OUT until someone asks: adding a character later is additive,
// removing one is a breaking change.
//
// THE GRAMMAR LIVES IN nameFault. The two branches before the loop below are
// message refinements, not rules — nameFault refuses a leading '-' and a
// leading '@' on its own — so deleting one costs a good error and cannot widen
// what parses.
//
// Checked in parse rather than merge: the FILE is what is wrong, and parse is
// where the source path and the offending name are both in hand.
func checkName(name, source string) error {
	if name == "" {
		return fmt.Errorf("%s: a profile with an empty name ([profile.\"\"]). Every place snug "+
			"renders a selection — $SNUG_PROFILES, --dry-run provenance, `snug profile list` "+
			"— would show a blank where a name belongs. A profile name is [a-zA-Z0-9] "+
			"followed by [a-zA-Z0-9-]", source)
	}
	if strings.HasPrefix(name, policy.Sigil) {
		suffix := "."
		if bare := strings.TrimPrefix(name, policy.Sigil); nameFault(bare) < 0 {
			suffix = fmt.Sprintf(": %q.", bare)
		}
		return fmt.Errorf("%s: profile %q may not start with '%s'; that mark means "+
			"\"snug ships this profile\" and snug adds it itself. Drop it and the "+
			"profile is yours%s A profile name is [a-zA-Z0-9] followed by [a-zA-Z0-9-]",
			source, name, policy.Sigil, suffix)
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%s: profile %q may not start with '-'; it would be "+
			"indistinguishable from a flag on the command line. A profile name is "+
			"[a-zA-Z0-9] followed by [a-zA-Z0-9-], so a hyphen is fine anywhere but "+
			"the front", source, name)
	}
	if i := nameFault(name); i >= 0 {
		c := name[i]
		hint := ""
		switch {
		case c == '_':
			if alt := strings.ReplaceAll(name, "_", "-"); nameFault(alt) < 0 {
				hint = fmt.Sprintf(" Underscore is not in the set and the hyphen is, which is "+
					"the spelling snug's own names use (@cwd-rw, @parent-ro): %q", alt)
			}
		case c >= 0x80:
			hint = " A profile name is ASCII; a non-ASCII character is several bytes in the " +
				"file and the byte above is the first of them."
		}
		return fmt.Errorf("%s: profile %q contains %s at byte offset %d. A profile name is "+
			"[a-zA-Z0-9] followed by [a-zA-Z0-9-] — an ALLOWLIST, so a character snug has "+
			"not been taught about is refused rather than carried into $SNUG_PROFILES, "+
			"--dry-run provenance and every message that renders a name. Rename the "+
			"profile.%s", source, name, nameByteDesc(c), i, hint)
	}
	return nil
}

// checkRef validates a name a profile REFERS to rather than defines: today the
// only one is an `include` target.
//
// The grammar is checkName's plus one character, and the difference is the
// whole reason this is a separate function instead of a bool argument. A user's
// profile including a builtin — include = ["@net"] — is a supported spelling,
// exercised by base.toml's own comments and by TestRetiredPublishAutoIsAHardError,
// so a reference may carry the leading mark that a DEFINITION may never carry.
// One mark, not two: "@@net" is not a name anything can define.
//
// Refused here rather than left to resolve time because the FILE is what is
// wrong. `unknown profile "x\x1b[1A\rb"` from some later command names neither
// the file nor the profile that wrote the include — and until this existed,
// `snug profile tree` rendered exactly that name RAW (printTree's unknown
// branch), which is a forged row on the one screen that says which profiles
// imply which.
func checkRef(ref, from, source string) error {
	if ref == "" {
		return fmt.Errorf("%s: profile %q has an empty entry in `include`. An include names "+
			"another profile; delete the entry", source, from)
	}
	bare := strings.TrimPrefix(ref, policy.Sigil)
	if i := nameFault(bare); i >= 0 {
		// bare[i] is only safe when bare is non-empty: nameFault("") returns 0,
		// which equals len(bare) for the empty string, so an include of the bare
		// sigil alone ("@") needs its own description rather than indexing past
		// the end of an empty slice.
		desc := "nothing after the sigil"
		if bare != "" {
			desc = nameByteDesc(bare[i])
		}
		return fmt.Errorf("%s: profile %q includes %q, which no profile file could define: a "+
			"profile name is [a-zA-Z0-9] followed by [a-zA-Z0-9-], optionally behind the "+
			"leading %s that marks one snug ships. %s is not in that set. An include that "+
			"cannot name anything is a typo, and snug says so here rather than as an "+
			"`unknown profile` from some later command that cannot name this file",
			source, from, ref, policy.Sigil, desc)
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
		// Every name a profile FILE contains obeys the grammar, references
		// included — see checkRef.
		for _, inc := range r.Include {
			if err := checkRef(inc, name, source); err != nil {
				return nil, err
			}
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
			Git:         r.Git,
			Identity:    toIdentity(r.Identity),
			Source:      source,
			Trusted:     trusted,
		}
	}
	return reg, nil
}

// toEnvGrants turns one profile's raw `environ` block into the value the
// resolver folds, and refuses the two keys it replaced.
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
		return g, retiredEnvKey(source, name, r.Env)
	}
	if len(r.Path) > 0 {
		return g, retiredPathKey(source, name, r.Path)
	}
	return g, nil
}

// The two retired keys, and why they are FIELDS on rawProfile rather than
// deletions.
//
// `publish_auto` was retired by deleting its struct field and letting
// DisallowUnknownFields fire, which yields the generic "unknown key" message.
// That is right for a key that never should have existed and wrong for a key
// whose MEANING MOVED: `env = [...]` is still a thing a profile wants to say,
// and the reader needs to be told the new spelling rather than told the key does
// not exist. So both fields stay, and both errors name the replacement — spelled
// out with this profile's own variables, so the fix can be pasted.
//
// The prefix changed deliberately. `env` became `environ.inherit` and not
// `environ.env`, because a silently CHANGED meaning is worse than a removed key:
// anyone whose muscle memory reaches for the old word gets an error naming the
// new one, rather than a subtly different grant that parses.

func retiredEnvKey(source, name string, names []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: profile %q uses `env = [...]`, which snug no longer accepts.\n", source, name)
	fmt.Fprintf(&b, "       It is now [profile.%s.environ.inherit], one NAME = true per variable:\n", name)
	fmt.Fprintf(&b, "         [profile.%s.environ.inherit]\n", name)
	for _, n := range sortedCopy(names) {
		fmt.Fprintf(&b, "         %s = true\n", n)
	}
	b.WriteString("       One name per line because `inherit` is a hole punched in --clearenv, and a\n")
	b.WriteString("       list is easy to extend without reading. Each name is now checked: snug\n")
	b.WriteString("       refuses the ones whose value is code, and refuses a list variable outright\n")
	b.WriteString("       (use environ.sanitise, which keeps only the elements policy grants).")
	return fmt.Errorf("%s", b.String())
}

func retiredPathKey(source, name string, dirs []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: profile %q uses `path = [...]`, which snug no longer accepts.\n", source, name)
	fmt.Fprintf(&b, "       It is now [profile.%s.environ.merge] on PATH:\n", name)
	fmt.Fprintf(&b, "         [profile.%s.environ.merge]\n", name)
	fmt.Fprintf(&b, "         PATH = [%s]\n", quotedList(dirs))
	b.WriteString("       Use environ.prepend instead if you need to be ahead of every other\n")
	b.WriteString("       profile's entry — at most one profile may hold the front of a variable, and\n")
	b.WriteString("       two claiming it is a refusal rather than whichever sorted first.\n")
	b.WriteString("       Note that the profile must now GRANT the directories it names: a variable\n")
	b.WriteString("       pointing at a path that is not inside the sandbox is worse than an absent one.")
	return fmt.Errorf("%s", b.String())
}

func quotedList(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return strings.Join(out, ", ")
}

// sortedCopy mirrors policy's, for a message that does not depend on map order.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
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
