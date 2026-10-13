package ingest

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/gomoni/snug/setup/internal/safe"
)

// maxProfileFile is snug's own bound on one profile file
// (maxProfileFileBytes in internal/profile/file.go); a larger file is not
// read, and snug refuses it too.
const maxProfileFile = 4 << 20

// ProfileDirs are the directories snug reads user profiles from, in snug's
// order: /etc/snug/profiles.d, then $XDG_CONFIG_HOME/snug/profiles.d with
// $XDG_CONFIG_HOME defaulting to ~/.config. snug-setup is its own module and
// cannot call snug's profile.ConfigDirs, so TestProfileDirsAreSnugs holds the
// two spellings together. There is no directory derived from the target, and
// there must never be one: a project that chooses which profiles are read
// grants itself whatever it likes.
func ProfileDirs(xdgConfigHome, home string) []string {
	dirs := []string{"/etc/snug/profiles.d"}
	xdg := xdgConfigHome
	if xdg == "" && home != "" {
		xdg = filepath.Join(home, ".config")
	}
	if xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "snug", "profiles.d"))
	}
	return dirs
}

// ProfileIdentity is what a profile pins, as written in the file: key paths
// keep their {home} spelling and nothing is opened.
type ProfileIdentity struct {
	SSHKey, SSHHost string
	SigningKey      string
	GitName, Email  string
	GHUser, GHHost  string
}

// Pins reports whether the profile pins any identity.
func (i ProfileIdentity) Pins() bool { return i != ProfileIdentity{} }

// Profile is one user profile found in a profiles.d directory.
type Profile struct {
	Name        string
	Description string
	File        string // base name of the file that defines it
	Dir         string
	Include     []string
	Identity    ProfileIdentity
}

// ProfileFile is one profiles.d file as read, with the profiles it defines.
type ProfileFile struct {
	Dir, Name string
	Body      []byte
	Defines   []string
}

// LoadProfiles reads every NAME.toml in dirs the way snug's loadDir does: a
// missing directory is nothing, a subdirectory or a name not ending in .toml
// is skipped, files are taken in name order, and a file that is not a regular
// file or is over snug's size bound is reported and skipped. The text of a
// profile is the human's own configuration, read for display and for the names
// it includes; nothing in it is run, and snug (not this reader) decides what
// it means.
//
// Abuse: a profiles.d entry that is a FIFO would hang a plain os.ReadFile, and
// one that is a 4 GiB file would fill memory. The open is O_NONBLOCK with a
// regular-file check, and the read stops at snug's bound. Names, descriptions
// and values leave through safe.Inline.
func LoadProfiles(dirs []string) ([]Profile, []ProfileFile, []string) {
	var out []Profile
	var files []ProfileFile
	var warns []string
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				warns = append(warns, "cannot list "+safe.Inline(dir)+": "+safe.Inline(err.Error()))
			}
			continue
		}
		var names []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".toml") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			data, err := readSmall(filepath.Join(dir, n))
			if err != nil {
				warns = append(warns, "not read: "+safe.Inline(filepath.Join(dir, n))+": "+safe.Inline(err.Error()))
				continue
			}
			f := ProfileFile{Dir: dir, Name: n, Body: data}
			for _, p := range ParseProfiles(string(data)) {
				p.File, p.Dir = n, dir
				out = append(out, p)
				f.Defines = append(f.Defines, p.Name)
			}
			files = append(files, f)
		}
	}
	return out, files, warns
}

func readSmall(path string) ([]byte, error) {
	// HOSTREAD-EXEMPT: opened O_NONBLOCK and refused unless fstat says regular
	// file, so a FIFO at the name cannot block the open or the read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfileFile+1))
	if err == nil && len(b) > maxProfileFile {
		err = os.ErrInvalid
	}
	return b, err
}

// ParseProfiles extracts, from the text of one profiles.d file, each
// [profile.NAME] table's description, include list and [..identity.ssh|git|gh]
// keys. It is a line reader for the shapes snug-setup itself writes and the
// examples in the README, not a TOML parser: a value it cannot read is left
// empty, which shows less on the screen and never grants anything, because the
// only thing done with a profile is to have snug read the same file.
func ParseProfiles(text string) []Profile {
	var out []Profile
	var cur *Profile
	table := "" // "", "profile", "ssh", "git", "gh"
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(stripComment(lines[i]))
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") && !strings.HasPrefix(l, "[[") {
			name, kind := tableOf(strings.Trim(l, "[] \t"))
			table = ""
			cur = nil
			if name == "" {
				continue
			}
			idx := slices.IndexFunc(out, func(p Profile) bool { return p.Name == name })
			if idx < 0 {
				out = append(out, Profile{Name: name})
				idx = len(out) - 1
			}
			cur, table = &out[idx], kind
			continue
		}
		key, val, ok := strings.Cut(l, "=")
		if !ok || cur == nil {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		for strings.HasPrefix(val, "[") && !balanced(val) && i+1 < len(lines) {
			i++
			val += " " + strings.TrimSpace(stripComment(lines[i]))
		}
		tbl := table
		if parts := strings.SplitN(key, ".", 3); table == "profile" && len(parts) == 3 && parts[0] == "identity" {
			tbl, key = parts[1], parts[2]
		}
		switch tbl {
		case "profile":
			switch key {
			case "description":
				cur.Description = str(val)
			case "include":
				cur.Include = strs(val)
			}
		case "ssh":
			switch key {
			case "key":
				cur.Identity.SSHKey = str(val)
			case "host":
				cur.Identity.SSHHost = str(val)
			}
		case "git":
			switch key {
			case "name":
				cur.Identity.GitName = str(val)
			case "email":
				cur.Identity.Email = str(val)
			case "signing_key":
				cur.Identity.SigningKey = str(val)
			}
		case "gh":
			switch key {
			case "user":
				cur.Identity.GHUser = str(val)
			case "host":
				cur.Identity.GHHost = str(val)
			}
		}
	}
	for i := range out {
		out[i].Name = safe.Inline(out[i].Name)
		out[i].Description = safe.Inline(out[i].Description)
	}
	return out
}

// tableOf maps a table header (without brackets) to the profile it belongs to
// and which part: "profile.NAME" or "profile.NAME.identity.ssh|git|gh".
func tableOf(h string) (name, kind string) {
	rest, ok := strings.CutPrefix(h, "profile.")
	if !ok {
		return "", ""
	}
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return "", ""
		}
		name, rest = rest[1:1+end], rest[2+end:]
		rest = strings.TrimPrefix(rest, ".")
	} else {
		name, rest, _ = strings.Cut(rest, ".")
	}
	switch rest {
	case "":
		return name, "profile"
	case "identity.ssh":
		return name, "ssh"
	case "identity.git":
		return name, "git"
	case "identity.gh":
		return name, "gh"
	}
	return "", ""
}

// stripComment removes a trailing # comment that is not inside a string.
func stripComment(s string) string {
	q := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

// balanced reports whether every [ in v outside a string is closed.
func balanced(v string) bool {
	depth, q := 0, byte(0)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return depth <= 0
}

// str reads one TOML basic or literal string, "" for anything else.
func str(v string) string {
	if len(v) < 2 {
		return ""
	}
	q := v[0]
	if q != '"' && q != '\'' {
		return ""
	}
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		c := v[i]
		switch {
		case c == q:
			return b.String()
		case c == '\\' && q == '"' && i+1 < len(v):
			i++
			switch v[i] {
			case 'n':
				b.WriteByte(' ')
			case 't':
				b.WriteByte(' ')
			default:
				b.WriteByte(v[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return ""
}

// strs reads an array of strings, skipping what is not a string.
func strs(v string) []string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") {
		return nil
	}
	var out []string
	for i := 1; i < len(v); i++ {
		if v[i] == '"' || v[i] == '\'' {
			q := v[i]
			j := i + 1
			for j < len(v) && v[j] != q {
				if v[j] == '\\' && q == '"' {
					j++
				}
				j++
			}
			if j >= len(v) {
				break
			}
			if s := str(v[i : j+1]); s != "" {
				out = append(out, safe.Inline(s))
			}
			i = j
		}
	}
	return out
}
