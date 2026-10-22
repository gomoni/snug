package policy

import (
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxFileBytes bounds one `file` body, raw and after expansion. A file that
// does not fit is a file a human wrote somewhere else, and the refusal points
// there: ro = ["<file>:<path>"] is the same grant with the text on disk.
const MaxFileBytes = 64 << 10

// maxQuotedLine bounds how much of a line a refusal repeats. A refusal quotes
// the LINE that is wrong, never the whole body, so a 64 KiB file cannot turn
// one mistake into a screenful.
const maxQuotedLine = 120

func quoteLine(line string) string {
	if utf8.RuneCountInString(line) > maxQuotedLine {
		r := []rune(line)
		return VisibleText(string(r[:maxQuotedLine])) + "..."
	}
	return VisibleText(line)
}

// profilePlaceholderPrefix opens the one placeholder family that names another
// profile: {profile.NAME.identity.ssh.host}.
const profilePlaceholderPrefix = "profile."

// filePlaceholderKeys is the set of KEYs a {profile.NAME.KEY} may name:
// every identity leaf that is not a host path, derived from identityFields so
// a new leaf is addressable by declaring it.
func filePlaceholderKeys() map[string]identityField {
	out := map[string]identityField{}
	for _, f := range identityFields {
		if !f.Path {
			out["identity."+f.Key] = f
		}
	}
	return out
}

func filePlaceholderKeyList() string {
	keys := make([]string, 0)
	for k := range filePlaceholderKeys() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// profileRef is a parsed {profile.NAME.KEY}.
type profileRef struct {
	name  ProfileName
	key   string
	field identityField
}

// parseProfilePlaceholder judges the text between the braces of a
// {profile.NAME.KEY}. The verdict is a property of the text alone, so it is the
// same on every host and runs at parse time; whether NAME is reachable and
// whether KEY is set is the resolver's.
func parseProfilePlaceholder(inner string) (profileRef, error) {
	rest := strings.TrimPrefix(inner, profilePlaceholderPrefix)
	rawName, key, ok := strings.Cut(rest, ".")
	if !ok || key == "" {
		return profileRef{}, fmt.Errorf("{%s} is malformed: a placeholder is {profile.NAME.KEY}, "+
			"for example {profile.work.identity.ssh.host}", VisibleText(inner))
	}
	name, err := NewProfileName(rawName)
	if err != nil {
		return profileRef{}, fmt.Errorf("{%s}: %w", VisibleText(inner), err)
	}
	f, ok := filePlaceholderKeys()[key]
	if !ok {
		for _, g := range identityFields {
			if g.Path && "identity."+g.Key == key {
				return profileRef{}, fmt.Errorf("{%s}: %s is a host path snug reads, not a value a file "+
					"carries. The placeholders are: %s", VisibleText(inner), key, filePlaceholderKeyList())
			}
		}
		return profileRef{}, fmt.Errorf("{%s}: %s is not a key a placeholder can address. The "+
			"placeholders are: %s", VisibleText(inner), VisibleText(key), filePlaceholderKeyList())
	}
	return profileRef{name: name, key: key, field: f}, nil
}

// checkFileText refuses a body that is not text a human can read on one
// screen. Newline and tab are the only control characters a config file
// legitimately has; every other forging rune is refused for the reason every
// other sink gives (IsForgingRune), and a NUL gets its own sentence.
func checkFileText(path, body string) error {
	if !utf8.ValidString(body) {
		return fmt.Errorf("file %s: the content is not valid UTF-8. A file a profile carries is "+
			"text; to ship bytes, bind a file with ro = [\"<file>:<path>\"]", VisibleText(path))
	}
	for _, r := range body {
		if r == '\n' || r == '\t' || !IsForgingRune(r) {
			continue
		}
		if r == 0 {
			return fmt.Errorf("file %s: the content contains a NUL byte. Text ends there for most "+
				"programs that read it and for every screen that prints it, so what follows is "+
				"invisible to the human reviewing the profile. Remove it", VisibleText(path))
		}
		return fmt.Errorf("file %s: the content contains %q. Every screen a human reads to decide "+
			"whether to trust a profile prints this text, and %s. Remove it",
			VisibleText(path), r, forgingRuneReason(r))
	}
	return nil
}

func checkFileSize(path string, n int) error {
	if n > MaxFileBytes {
		return fmt.Errorf("file %s is %d bytes, over the %d-byte limit. Put the text in a file "+
			"of its own and bind it: ro = [\"<file>:%s\"]", VisibleText(path), n, MaxFileBytes, VisibleText(path))
	}
	return nil
}

// CheckFileGrants judges the text of a profile's `file` grants: the path is
// present and not repeated, the body is text of bounded size, and every
// {placeholder} in it is one this grammar knows and can address.
//
// It reads nothing but its argument, so internal/profile calls it at parse time
// and Resolve calls it again over a Profile built in code, which never went
// through a parser. It does NOT judge whether a {profile.NAME.KEY} names a
// profile the owner includes or whether the key is set: both depend on the
// registry, and CheckProfileFiles and Resolve answer them.
//
// The error is a bare sentence naming the file and line; the caller prefixes
// the profile.
func CheckFileGrants(fs []FileGrant) error {
	seen := map[string]bool{}
	names := pathVars("", "")
	for _, f := range fs {
		if f.Path == "" {
			return fmt.Errorf("a `file` has an empty path. Write where the file appears inside " +
				"the sandbox, for example path = \"/etc/gitconfig\"")
		}
		if seen[f.Path] {
			return fmt.Errorf("file %s is written twice by one profile. A profile writes a path "+
				"once; merge the two bodies", VisibleText(f.Path))
		}
		seen[f.Path] = true
		if err := checkFileSize(f.Path, len(f.Content)); err != nil {
			return err
		}
		if err := checkFileText(f.Path, f.Content); err != nil {
			return err
		}
		for n, line := range strings.Split(f.Content, "\n") {
			if _, err := scanBraces(line, func(key, _ string) (string, error) {
				if strings.HasPrefix(key, profilePlaceholderPrefix) {
					if _, err := parseProfilePlaceholder(key); err != nil {
						return "", fmt.Errorf("file %s, line %d: %w", VisibleText(f.Path), n+1, err)
					}
					return "", nil
				}
				if _, ok := names[key]; !ok {
					return "", fmt.Errorf("file %s, line %d: unknown placeholder {%s}: %s",
						VisibleText(f.Path), n+1, VisibleText(key), placeholderHelp())
				}
				return "", nil
			}, func(string) error {
				return fmt.Errorf("file %s, line %d: a `{` opens a placeholder and none closes it "+
					"on this line (%s). Write {lbrace} for a literal `{`",
					VisibleText(f.Path), n+1, quoteLine(line))
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func placeholderHelp() string {
	var names []string
	for k := range pathVars("", "") {
		names = append(names, "{"+k+"}")
	}
	slices.Sort(names)
	return "the placeholders are " + strings.Join(names, ", ") + " and {profile.NAME.KEY} with KEY one of " +
		filePlaceholderKeyList()
}

// expandFileContent expands one file body for the profile that wrote it.
//
// Expansion is one pass (scanBraces): a substituted value is never scanned for
// placeholders, so a target directory named `{home}` is data. `~/` is NOT
// expanded here, unlike in a path.
//
// A {profile.NAME.KEY} resolves only against owner's include closure, the same
// closure profileGuestGrants uses. A profile outside it is refused even when
// another selected profile includes it, so the text a profile carries never
// depends on what else the run selected. The value is the RAW value in the
// referenced profile, not the joined p.Identity. A key that is not set is
// refused: snug never expands a placeholder to nothing.
//
// Every substituted value must itself be a single line of text, so a target
// directory with a newline in its name cannot write a second line, and the
// whole body is judged again afterwards.
//
// The returned placeholders are sorted by Text and deduplicated. Errors are
// complete sentences carrying the profile; they quote the line, never the body.
func expandFileContent(reg map[ProfileName]*Profile, owner ProfileName, path, content string, vars map[string]string) (string, []Placeholder, error) {
	var closure map[ProfileName]*Profile
	var seen []Placeholder
	lines := strings.Split(content, "\n")
	for n, line := range lines {
		out, err := scanBraces(line, func(key, _ string) (string, error) {
			if !strings.HasPrefix(key, profilePlaceholderPrefix) {
				val, ok := vars[key]
				if !ok {
					return "", fmt.Errorf("profile %q: file %s, line %d: unknown placeholder {%s}: %s",
						owner, VisibleText(path), n+1, VisibleText(key), placeholderHelp())
				}
				return val, checkOneLineValue(owner, path, n+1, "{"+key+"}", val)
			}
			ref, err := parseProfilePlaceholder(key)
			if err != nil {
				return "", fmt.Errorf("profile %q: file %s, line %d: %w", owner, VisibleText(path), n+1, err)
			}
			if closure == nil {
				closure = map[ProfileName]*Profile{}
				if err := expand(reg, owner, closure); err != nil {
					return "", fmt.Errorf("profile %q: %w", owner, err)
				}
			}
			text := "{" + key + "}"
			target, ok := closure[ref.name]
			if !ok {
				return "", fmt.Errorf("profile %q: file %s, line %d: %s names %q, which is neither %q "+
					"nor a profile it includes, so the text would depend on what else the run "+
					"selects. Add include = [%q] to %q, or write the value.",
					owner, VisibleText(path), n+1, text, ref.name, owner, ref.name, owner)
			}
			if err := target.Identity.CheckText(ref.name); err != nil {
				return "", err
			}
			var val string
			if target.Identity != nil {
				val = reflect.ValueOf(*target.Identity).FieldByIndex(ref.field.Index).String()
			}
			if val == "" {
				return "", fmt.Errorf("profile %q: file %s, line %d: %s: %q does not set %s, and snug "+
					"never expands a placeholder to nothing. Set it in %q or remove the placeholder.",
					owner, VisibleText(path), n+1, text, ref.name, ref.key, ref.name)
			}
			if err := checkOneLineValue(owner, path, n+1, text, val); err != nil {
				return "", err
			}
			seen = append(seen, Placeholder{Text: text, Value: val})
			return val, nil
		}, func(string) error {
			return fmt.Errorf("profile %q: file %s, line %d: a `{` opens a placeholder and none "+
				"closes it on this line (%s). Write {lbrace} for a literal `{`",
				owner, VisibleText(path), n+1, quoteLine(line))
		})
		if err != nil {
			return "", nil, err
		}
		lines[n] = out
	}
	body := strings.Join(lines, "\n")
	if err := checkFileSize(path, len(body)); err != nil {
		return "", nil, fmt.Errorf("profile %q: after expansion, %w", owner, err)
	}
	if err := checkFileText(path, body); err != nil {
		return "", nil, fmt.Errorf("profile %q: after expansion, %w", owner, err)
	}
	slices.SortFunc(seen, func(a, b Placeholder) int { return strings.Compare(a.Text, b.Text) })
	seen = slices.CompactFunc(seen, func(a, b Placeholder) bool { return a.Text == b.Text })
	return body, seen, nil
}

func checkOneLineValue(owner ProfileName, path string, line int, text, val string) error {
	for _, r := range val {
		if IsForgingRune(r) {
			return fmt.Errorf("profile %q: file %s, line %d: %s expands to a value containing %q. A "+
				"placeholder is one piece of one line; a value carrying a control character would "+
				"write lines the profile does not show", owner, VisibleText(path), line, text, r)
		}
	}
	return nil
}

// CheckProfileFiles runs the registry-dependent half of CheckFileGrants for one
// profile: every {profile.NAME.KEY} in its `file` bodies must name a profile in
// its include closure and a key that profile sets. `snug profile show` calls it
// because it does not resolve; Resolve reaches the same answers through
// expandFileContent with the real variables.
//
// The path variables are stand-ins, since the verdict must not depend on the
// target or the home directory of whoever reads it.
func CheckProfileFiles(reg map[ProfileName]*Profile, name ProfileName) error {
	prof, ok := reg[name]
	if !ok {
		return UnknownProfile(reg, name)
	}
	if err := CheckFileGrants(prof.File); err != nil {
		return fmt.Errorf("profile %q: %w", name, err)
	}
	vars := pathVars("/target", "/home")
	for _, f := range prof.File {
		if _, _, err := expandFileContent(reg, name, f.Path, f.Content, vars); err != nil {
			return err
		}
	}
	return nil
}

// mergeProfileFile folds one profile's contribution into the ledger entry at
// guest, keeping From and Placeholders sorted and deduplicated so the entry
// does not depend on fold order.
func (p *Policy) mergeProfileFile(guest string, owner ProfileName, ph []Placeholder) {
	if p.Files == nil {
		p.Files = map[string]ProfileFile{}
	}
	e := p.Files[guest]
	if !slices.Contains(e.From, owner) {
		e.From = append(e.From, owner)
		slices.Sort(e.From)
	}
	e.Placeholders = append(e.Placeholders, ph...)
	slices.SortFunc(e.Placeholders, func(a, b Placeholder) int { return strings.Compare(a.Text, b.Text) })
	e.Placeholders = slices.CompactFunc(e.Placeholders, func(a, b Placeholder) bool { return a.Text == b.Text })
	p.Files[guest] = e
}

// rejectProfileFileDisplaced holds p.Files and the KindData mounts to each
// other, and refuses what that comparison finds.
//
// A profile's file is a grant like any other and has no authority over a path
// snug writes. Nothing here lets it win or lose quietly: if one of snug's own
// writers (Policy.Replace, which runs after Resolve too) lands on the same
// guest path, the run is refused, naming both. Validate runs after every such
// writer, so this holds for writers that do not exist yet.
//
// Three findings. A ledger entry whose mount is gone, or is no longer KindData,
// and a KindData mount no profile wrote that is not authored, are snug bugs
// (the ledger and the mounts disagree), reported as such rather than guessed
// around. A mount strictly beneath a profile file is refused because nothing
// can be mounted inside a regular file; rejectMasking cannot see it when the
// inner mount is Authored, since it exempts those.
func (p *Policy) rejectProfileFileDisplaced() error {
	guests := make([]string, 0, len(p.Files))
	for g := range p.Files {
		guests = append(guests, g)
	}
	slices.Sort(guests)
	for _, g := range guests {
		m, ok := p.Mounts[g]
		if !ok || m.Kind != KindData {
			return fmt.Errorf("snug bug: the profile-file ledger records %s but no file is mounted "+
				"there. This is a defect in snug, not in your profiles", VisibleText(g))
		}
		owners := profileFileOwners(p.Files[g])
		// /tmp yields to a profile's grant (yieldTo), so a file there comes out
		// unauthored and the arm below never sees snug's tmpfs. A grant at /tmp
		// is a real feature, a host directory bound there; a regular file in
		// its place is only snug's mount replaced, which decision 2 refuses.
		if g == "/tmp" {
			return fmt.Errorf("profile %s writes a file at /tmp, where snug mounts the sandbox's own "+
				"/tmp. A profile file never replaces a mount snug makes; write it under /tmp instead",
				owners)
		}
		if m.Authored {
			return fmt.Errorf("profile %s writes a file at %s, but snug generates that file for this "+
				"selection (from %s). A profile file never replaces a generated one. %s",
				owners, VisibleText(g), VisibleText(provenance(m)), generatedFileLayer(p, g))
		}
		for _, other := range p.SortedMounts() {
			if strings.HasPrefix(other.Guest, g+"/") {
				return fmt.Errorf("profile %s writes a FILE at %s and %s (from %s) is mounted beneath it. "+
					"Nothing can be mounted inside a regular file; write the file at another path",
					owners, VisibleText(g), VisibleText(other.Guest), VisibleText(provenance(other)))
			}
		}
	}
	for _, m := range p.SortedMounts() {
		if m.Kind != KindData || m.Authored {
			continue
		}
		if _, ok := p.Files[m.Guest]; !ok {
			return fmt.Errorf("snug bug: %s is a file no profile wrote and snug did not author. "+
				"This is a defect in snug, not in your profiles", VisibleText(m.Guest))
		}
	}
	return nil
}

func profileFileOwners(f ProfileFile) string {
	names := make([]string, len(f.From))
	for i, n := range f.From {
		names[i] = string(n)
	}
	return VisibleText(strings.Join(names, "+"))
}

// generatedFileLayer is the sentence that follows a displacement refusal: what
// a human can do instead. It is wording only. The refusal fires for every
// Authored mount at a profile file's path, current writer or future, and the
// default arm covers one this switch has not been taught.
func generatedFileLayer(p *Policy, g string) string {
	base := path.Base(g)
	switch {
	case g == p.Home+"/.gitconfig":
		return "write path = \"/etc/gitconfig\": git reads that system-scope file below the " +
			"generated global one, and snug's pins (user, signing, insteadOf, safe.directory) still win there."
	case g == p.Home+"/.ssh/config", g == p.Home+"/.ssh/known_hosts":
		return "snug has no layer for ssh configuration yet; the generated file is what ssh reads at user scope."
	case base == "hosts.yml", g == p.Home+"/.kube/config", base == "allowed_signers",
		strings.HasPrefix(base, "id_snug") && strings.HasSuffix(base, ".pub"):
		return "this is a credential or a pin snug derives; there is no layer to add to it."
	case g == "/etc/resolv.conf":
		return "generated in every sandbox from the network policy; there is no layer."
	case g == "/etc/passwd", g == "/etc/group", g == "/etc/nsswitch.conf":
		return "generated because a selected profile sets nss = true."
	}
	return "snug writes this path for this selection; choose another path."
}
