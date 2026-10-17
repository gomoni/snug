package ingest

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/pelletier/go-toml/v2"

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
			ps, err := ParseProfiles(string(data))
			if err != nil {
				warns = append(warns, "not valid TOML, so no profile read from it: "+safe.Inline(filepath.Join(dir, n))+": "+safe.Inline(err.Error()))
			}
			for _, p := range ps {
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
// [profile.NAME] table's description, include list and identity.ssh|git|gh
// keys, in name order. The text is parsed as TOML, so quoting, multi-line
// arrays, dotted keys and inline tables mean what they mean to snug. A value
// of the wrong type is left empty, which shows less on the screen and never
// grants anything, because the only thing done with a profile is to have snug
// read the same file. An error is returned when text is not valid TOML; snug
// refuses such a file too, and nothing is guessed from a file that does not
// parse.
func ParseProfiles(text string) ([]Profile, error) {
	var doc struct {
		Profile map[string]map[string]any `toml:"profile"`
	}
	if err := toml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(doc.Profile))
	for n := range doc.Profile {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		t := doc.Profile[n]
		p := Profile{Name: safe.Inline(n), Description: safe.Inline(tomlStr(t["description"]))}
		if arr, ok := t["include"].([]any); ok {
			for _, v := range arr {
				if s := tomlStr(v); s != "" {
					p.Include = append(p.Include, safe.Inline(s))
				}
			}
		}
		id, _ := t["identity"].(map[string]any)
		ssh, _ := id["ssh"].(map[string]any)
		git, _ := id["git"].(map[string]any)
		gh, _ := id["gh"].(map[string]any)
		p.Identity = ProfileIdentity{
			SSHKey: tomlStr(ssh["key"]), SSHHost: tomlStr(ssh["host"]),
			SigningKey: tomlStr(git["signing_key"]), GitName: tomlStr(git["name"]), Email: tomlStr(git["email"]),
			GHUser: tomlStr(gh["user"]), GHHost: tomlStr(gh["host"]),
		}
		out = append(out, p)
	}
	return out, nil
}

func tomlStr(v any) string {
	s, _ := v.(string)
	return s
}
