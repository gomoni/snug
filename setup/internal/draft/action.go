package draft

import "regexp"

// Builtins are the snug built-in profiles an Action may name with
// OpUseProfile or OpDropProfile.
var Builtins = []string{"@target-rw", "@parent-ro", "@git", "@net", "@claude", "@podman-socket", "@podman-build"}

// Op names of the operations Apply understands.
const (
	OpUseProfile     = "use_profile"
	OpDropProfile    = "drop_profile"
	OpIncludeProfile = "include_profile"
	OpGrantPath      = "grant_path"
	OpDropPath       = "drop_path"
	OpStageBinary    = "stage_binary"
	OpSetEnv         = "set_env"
	OpOpenDoor       = "open_door"
	OpSelectIdentity = "select_identity"
	OpNameProfile    = "name_profile"
	OpShow           = "show"
)

// Action is one operation on the draft. Which fields are set depends on Op.
type Action struct {
	Op       string
	Name     string // use_profile, drop_profile, include_profile, stage_binary, set_env, open_door, name_profile
	Path     string // grant_path, drop_path
	Access   string // grant_path: ro, rw or tmpfs
	Host     string // stage_binary: host path
	Verb     string // set_env: set, inherit or prepend
	Value    string // set_env
	HasValue bool   // set_env: `value` was present
	Kind     string // select_identity
	Account  string // select_identity
}

var profRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)

// ValidProfileName reports whether s is a name snug accepts for a user
// profile (no leading @, no underscore).
func ValidProfileName(s string) bool { return profRE.MatchString(s) }
