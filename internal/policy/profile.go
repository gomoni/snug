package policy

// Profile is a named, composable generator of grants — the parsed form of one
// [profile.NAME] table.
//
// Note what is NOT here: there is no mask, hide, deny, remove, unset, or
// exclude. The grant language cannot express negation, which is one of the
// three legs monotonicity stands on. Adding such a field is not a feature, it
// is a change of model.
type Profile struct {
	Name        string
	Description string
	Include     []string

	RO      []string // paths, or "host:guest" pairs; may contain {variables}
	RW      []string
	Tmpfs   []string
	Symlink []Symlink

	// Optional lists paths that are silently skipped when absent on the host,
	// so one profile can cover several distro layouts.
	Optional []string

	// Network is "isolated" | "egress" | "host", joined by max. There is
	// deliberately no "offline": offline is the ABSENCE of a net profile, so it
	// cannot be re-enabled by adding one.
	Network string
	DNS     bool
	Publish []int
	// PublishAuto forwards every port the sandbox binds. Off by default because
	// it lets the SANDBOX choose what appears on the host's loopback.
	PublishAuto bool
	Address     string
	Gateway     string
	MTU         int

	// Identity pins one git/ssh/gh account. See identity.go.
	Identity *Identity

	// Env names host variables to re-admit past --clearenv. Values are read from
	// the host at launch; a profile never carries a value.
	Env []string

	// Source is the file this profile came from, and Trusted records whether
	// that file was a trusted layer. Profiles from an explicitly-named config
	// may not carry privileged grants — see docs/DESIGN.md §2.7.
	Source  string
	Trusted bool
}

// Symlink is a symlink snug creates inside the sandbox (usr-merge, mostly).
type Symlink struct {
	At     string `toml:"at"`
	Target string `toml:"target"`
}
