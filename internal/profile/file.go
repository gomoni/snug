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

	"snug/internal/policy"
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
	Env         []string         `toml:"env"`

	Network     string `toml:"network"`
	DNS         bool   `toml:"dns"`
	Publish     []int  `toml:"publish"`
	PublishAuto bool   `toml:"publish_auto"`
	Address     string `toml:"address"`
	Gateway     string `toml:"gateway"`
	MTU         int    `toml:"mtu"`

	Identity *rawIdentity `toml:"identity"`
}

type rawIdentity struct {
	SSHKey   string `toml:"ssh_key"`
	SSHMode  string `toml:"ssh_mode"`
	GitName  string `toml:"git_name"`
	GitEmail string `toml:"git_email"`
	GhUser   string `toml:"gh_user"`
	GhHost   string `toml:"gh_host"`
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
		reg[name] = &policy.Profile{
			Name:        name,
			Description: r.Description,
			Include:     r.Include,
			RO:          r.RO,
			RW:          r.RW,
			Tmpfs:       r.Tmpfs,
			Symlink:     r.Symlink,
			Optional:    r.Optional,
			Env:         r.Env,
			Network:     r.Network,
			DNS:         r.DNS,
			Publish:     r.Publish,
			PublishAuto: r.PublishAuto,
			Address:     r.Address,
			Gateway:     r.Gateway,
			MTU:         r.MTU,
			Identity:    toIdentity(r.Identity),
			Source:      source,
			Trusted:     trusted,
		}
	}
	return reg, nil
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
// never redefine one: shadowing a builtin would let a config file quietly change
// what `sys` or `net` means, which is the same class of problem as a deny rule.
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

// Load assembles the registry from the trusted layers, in precedence order:
//
//  1. embedded builtins   — compiled in, cannot be shadowed
//  2. /etc/snug/profiles.d/*.toml
//  3. $XDG_CONFIG_HOME/snug/profiles.d/*.toml   (the user's own)
//
// There is deliberately NO fourth layer. snug never auto-loads .snug/ or
// snug.toml from beside the target: a hostile repository that ships its own
// profile would be granting itself permissions, which defeats the entire threat
// model. See docs/DESIGN.md §2.7.
func Load() (Registry, error) {
	reg, err := builtins()
	if err != nil {
		return nil, err
	}
	for _, dir := range ConfigDirs() {
		layer, err := loadDir(dir)
		if err != nil {
			return nil, err
		}
		if err := reg.merge(layer); err != nil {
			return nil, err
		}
	}
	return reg, nil
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

func loadDir(dir string) (Registry, error) {
	reg := Registry{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return reg, nil // absent config dir is normal, not an error
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".toml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		path := filepath.Join(dir, n)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		layer, err := parse(data, path, true)
		if err != nil {
			return nil, err
		}
		if err := reg.merge(layer); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
