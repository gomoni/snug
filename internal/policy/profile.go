package policy

// Sigil marks a profile snug itself ships: `@sys`, `@net`, `@claude`. Nothing
// else may wear it, and every builtin does.
//
// It is not decoration. Provenance is the thing --dry-run exists to show, and a
// bare name cannot tell you whether a grant came from snug or from a file
// someone wrote on this host — you had to go and look. With the mark, `@sys` is
// snug's and `work` is yours, on the line you are already reading.
//
// The mark is DERIVED, not written: profile.builtins() adds it to the embedded
// layer and is the only code that does, while profile.checkName refuses a
// leading @ in every file it parses, base.toml included. "Starts with @" and "is
// compiled into snug" are therefore the same statement by construction rather
// than by a check someone has to remember. A user profile cannot borrow the
// mark, and a builtin cannot forget to wear it.
//
// The second thing it buys: the two namespaces cannot collide. A user file
// defining `sys` now defines a NEW profile rather than colliding with snug's,
// and `@sys` still means exactly what snug ships.
//
// It lives in this package, not in internal/profile, because internal/profile
// imports this one and the constant must have a single definition.
const Sigil = "@"

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

	// Publish names the ports the host's 127.0.0.1 forwards into the sandbox.
	// The human names them, one at a time. There is deliberately no "publish
	// everything the sandbox binds" — see NetPolicy.Publish.
	Publish []int

	Address string
	Gateway string
	MTU     int

	// Podman is "off" | "socket", joined by max like every other scalar.
	Podman string

	// Identity pins one git/ssh/gh account. See identity.go.
	Identity *Identity

	// Env names host variables to re-admit past --clearenv. Values are read from
	// the host at launch; a profile never carries a value.
	Env []string

	// Path names directories to put on the sandbox's PATH.
	//
	// This is the one key here that GRANTS NOTHING, and that is what makes it
	// safe rather than an exception. A directory on PATH that was never mounted
	// is inert, PATH is not an access control, and the payload can set its own
	// PATH or call anything by absolute path — so there is no abuse sentence to
	// write, which is the argument for allowing it at all.
	//
	// It exists because a profile that mounts an executable somewhere nothing
	// looks is broken on its own terms: `@claude` bound ~/.local/bin/claude and
	// `snug -p @claude . -- claude` answered "No such file or directory". The
	// alternative — a second profile the human has to remember — makes one
	// profile depend on another to do its job.
	//
	// Composes like everything else: the directories are collected into a SET
	// and sorted, so resolution stays commutative and idempotent, and adding a
	// profile can only ever ADD entries.
	Path []string

	// Source is the file this profile came from, and Trusted records whether
	// that file was a trusted layer. Profiles from an explicitly-named config
	// may not carry privileged grants — see .claude/design/INDEX.md §2.7.
	Source  string
	Trusted bool
}

// Symlink is a symlink snug creates inside the sandbox (usr-merge, mostly).
type Symlink struct {
	At     string `toml:"at"`
	Target string `toml:"target"`
}
