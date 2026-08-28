package policy

// Sigil marks a profile snug itself ships: `@sys`, `@net`, `@claude`. Nothing
// else may wear it, and every builtin does.
//
// It is not decoration. Provenance is the thing --dry-run exists to show, and a
// bare name cannot tell you whether a grant came from snug or from a file
// someone wrote on this host — you had to go and look. With the mark, `@sys` is
// snug's and `work` is yours, on the line you are already reading.
//
// The mark is DERIVED, not written: profile.Builtins() adds it to the embedded
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
	// Name and Include are ProfileName, not string: both are profile names, and
	// the type is what says they went through the grammar. Note the asymmetry
	// with Mount.From, which stays a plain []string — that field is PROVENANCE
	// and already carries non-profile values like "(snug)", "identity:<name>"
	// and "replaces:<...>", so typing it would be claiming something untrue of
	// most of what it holds.
	Name        ProfileName
	Description string
	Include     []ProfileName

	RO      []string // paths, or "host:guest" pairs; may contain {variables}
	RW      []string
	Tmpfs   []string
	Symlink []Symlink

	// Optional lists paths that are silently skipped when absent on the host,
	// so one profile can cover several distro layouts.
	Optional []string

	// Plugins is @claude's allowlist of Claude Code plugins whose
	// installed_plugins.json entry snug regenerates — an ALLOWLIST of names,
	// never a path: snug decides the guest path (issue #68). Empty or absent
	// names nothing, which is the strict default. Unioned across selected
	// profiles like Publish.
	Plugins []string

	// ListenNames names the doors a human may open into this sandbox with
	// `snug proxy` — one NAME per door, never a port. Unioned across selected
	// profiles like Plugins.
	//
	// A name and not a port because a port is a thing the payload could have
	// chosen: snug creates the listening socket itself and hands the sandbox a
	// descriptor, so nothing inside decides what is reachable. The name is what
	// the human types, what LISTEN_FDNAMES carries, and what --dry-run labels.
	//
	// Named for what the values BECOME: LISTEN_FDNAMES, the systemd
	// socket-activation variable the payload reads. The key was called
	// `http_proxy` first, which collided with the well-known environment variable
	// of that name — and that one means an OUTBOUND forward proxy, the opposite
	// direction. This is inbound, and it is the one grant in snug a human opens
	// after the sandbox is already running.
	ListenNames []string

	// EngineBinds names host paths the ENGINE may bind into a container, in
	// addition to whatever the anchored-source rule already accepts. Paths, one
	// per entry, `{variables}` expanded exactly as `ro`/`rw` are; unioned across
	// selected profiles like Plugins and ListenNames.
	//
	// ABUSE: a hostile process inside the sandbox can use one to bind the named
	// host tree into a container it starts itself — its own image, its own
	// command, running as root in this run's user namespace and in the ENGINE's
	// network namespace rather than the sandbox's — at the access the sandbox
	// already has at that path. Declaring a path the sandbox can write is
	// therefore a host-write channel out of a container, and declaring one it
	// can only read hands the bytes to arbitrary container code.
	//
	// Named for what the values BECOME: the set of host paths the engine may
	// bind into a container. Same convention as ListenNames, which is named for
	// LISTEN_FDNAMES rather than for the door a human opens.
	//
	// WHY THE GRANT EXISTS AT ALL, and why it is a declaration and not a flag
	// (issue #376). The anchored-source rule refuses any bind source with a
	// still-re-pointable component, which is every path strictly inside the
	// target: `podman run -v ./data:/data` is a 403 in every layout, and
	// correctly so, because the engine re-resolves the forwarded STRING at
	// container start and the payload can swap a name in the gap. A declared
	// entry stops being a string: snug open_tree(2)-clones the host path into
	// the engine's own view under EngineBindsDir and forwards THAT path, which
	// has no payload-writable component anywhere on it. The declaration has to
	// come from the trusted profile set rather than from the request, because a
	// path resolved at request time is a path resolved after the payload has
	// run — and it is resolved before the payload has EVER run only because the
	// payload is parked behind bwrap's --block-fd until the engine is up.
	//
	// There is deliberately no `host:guest` form: snug chooses the guest path
	// (EngineBindGuest), the same way it chooses where a staged binary lands.
	EngineBinds []string

	// Network is "isolated" | "egress" | "host", joined by max. There is
	// deliberately no "offline": offline is the ABSENCE of a net profile, so it
	// cannot be re-enabled by adding one.
	Network string
	DNS     bool

	// Address/Gateway and Address6/Gateway6 are raw profile TEXT, deliberately
	// NOT typed here: this struct must not depend on internal/policy's own
	// netip typing (it lives in the SAME package, but a *rawProfile in
	// internal/profile copies these fields verbatim without importing
	// net/netip), DisallowUnknownFields makes a typo in either key a fatal
	// parse error regardless, and dnsscreen_test.go's registry sweep keys on
	// `prof.Address != ""` and must keep working unmodified. Resolve is the
	// ONLY place that parses these into netip.Prefix/netip.Addr (net.go's
	// addrPairs). V6 requires all four or none — see net.go's
	// checkAddressPair — so a profile naming Address without Address6 is not
	// wrong to represent here; it is refused at Resolve time.
	Address  string
	Gateway  string
	Address6 string
	Gateway6 string
	MTU      int

	// Podman is "off" | "socket", joined by max like every other scalar.
	Podman string

	// Git is "off" | "extract", joined by max. "extract" reconstructs the
	// sandbox's git config from the host's — whitelisted keys only, never a
	// bind. See gitextract.go for why binding the file is the wrong shape.
	Git string

	// Identity pins one git/ssh/gh account. See identity.go.
	Identity *Identity

	// Environ is a profile's `environ` block: the five verbs, parsed.
	//
	// It replaces two earlier keys that said less. `env = [...]` named host
	// variables to re-admit past --clearenv, which is exactly `environ.inherit`;
	// `path = [...]` named directories for the sandbox's PATH, which is exactly
	// `environ.merge` on PATH. Both are rewritten into this at parse time.
	//
	// PATH deserves the note the old `path` key carried, because it is what
	// makes the whole key safe rather than an exception: a directory on PATH
	// that was never mounted GRANTS NOTHING. PATH is not an access control, and
	// the payload can set its own or call anything by absolute path. What the
	// key buys is that a profile mounting an executable somewhere nothing looks
	// is broken on its own terms — @claude bound ~/.local/bin/claude and
	// `snug -p @claude . -- claude` answered "No such file or directory".
	Environ EnvGrants

	// Source is the file this profile came from, and Trusted records whether
	// that file was a trusted layer. Profiles from an explicitly-named config
	// may not carry privileged grants — see .claude/design/INDEX.md §2.7.
	Source  string
	Trusted bool
}

// EnvGrants is a profile's `environ` block. Unordered, like every other grant:
// argv ordering is a COMPILER concern — which band an entry lands in is
// structural (§2.4) — and never something a profile writes.
//
// Inherit and Sanitise are []string of NAMES rather than map[string]bool on
// purpose. The TOML spelling is `NAME = true`, and a bool in the model would
// read like a switch that could be turned off, whereas `= false` has to be a
// refusal: there is no way to un-inherit, because nothing was inherited to
// begin with, and a stored false would be a negation key that parsed.
type EnvGrants struct {
	Set      map[string]string
	Merge    map[string][]string
	Prepend  map[string][]string
	Inherit  []string
	Sanitise []string
}

// Symlink is a symlink snug creates inside the sandbox (usr-merge, mostly).
type Symlink struct {
	At     string `toml:"at"`
	Target string `toml:"target"`
}
