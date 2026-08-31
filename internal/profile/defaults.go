package profile

import "github.com/gomoni/snug/internal/policy"

// BuiltinDefaults is the profile selection a bare `snug <dir>` starts from when
// the user's config.toml does not say otherwise. It is a PREFERENCE, not a
// policy object: it grants nothing itself, it names profiles that do. That is
// why it lives here as a list rather than as a `[profile.default]` in base.toml
// — a profile that grants nothing still appeared in SNUG_PROFILES, in
// `snug profile tree` and in every Mount's provenance as though it were a hole
// in the sandbox, and it duplicated an idea `config.toml` already expressed.
//
// The list is chosen so that snug is usable by just running it: a shell and the
// target writable, nothing else.
//
// `@parent-ro` IS NOT HERE, AND THAT IS THE POINT OF THE LIST. Every name in it
// has a blast radius fixed by the grant itself: `@sys` is a fixed enumeration,
// `@home` is an empty tmpfs, `@cwd-rw` is the directory the user named. The
// target's PARENT is a directory the user did NOT name, and what it holds is a
// property of their layout — every sibling project, their .git/config, their
// .env files, and any socket or FIFO sitting in the tree (issues #287 and #296
// are the escapes that shape found). A grant nobody asked for cannot be the one
// that is always on.
//
// What it costs, stated rather than papered over: a target one level below a
// repository root (`snug ~/src/proj/sub`) no longer sees the `.git` above it,
// and needs `snug -p @parent-ro ~/src/proj/sub`. The profile still ships and
// that one word is the whole fix. It is not made a default again on the git
// argument, because the grant answers that argument badly in both directions —
// a target two levels below the root still misses `.git`, and a target one
// level below is handed every sibling of the repository as well.
//
// It deliberately does NOT include `@net`. "Make it usable out of the box" is
// exactly the pressure that would push networking in here later, and it must be
// resisted: offline is the ABSENCE of the `@net` profile, so it cannot be
// switched back on by accident, and a default that opens a hole contradicts the
// guiding principle. `snug -p @net` is one word.
//
// There is deliberately no `@null` profile either, for the same reason
// there is no `[profile.default]`: a profile that grants nothing is a
// preference wearing a profile's clothes. The floor of the lattice is not
// something a file needs to name — it is what Resolve computes from an empty
// selection, reached directly with `--no-defaults`, which declines this list
// entirely rather than adding a no-op profile to work around it.
//
// The names carry the @ mark because these ARE the builtins (policy.Sigil). A
// user replacing this list in config.toml writes their own names without one.
//
// Precedence, implemented in internal/cli/config.go:
//
//  1. this list;
//  2. REPLACED wholesale by `defaults = [...]` in ~/.config/snug/config.toml —
//     replaced and not merged, because having fewer defaults than snug ships
//     with is a legitimate thing to want;
//  3. `-p NAME` ADDS to whatever (1) or (2) produced — naming a profile can
//     never take anything away;
//  4. `--no-defaults` declines the list entirely, and is the only way to get
//     less than it.
//
// Returned by value so no caller can mutate the shipped defaults.
//
// The elements are policy.ProfileName. Note that this needs no call to
// policy.NewProfileName and no conversion: they are untyped string CONSTANTS in
// a []policy.ProfileName literal, which Go converts at compile time. That is
// the safe case by construction — a constant cannot carry runtime data — and it
// is why the conversion sweep in internal/cli looks for ProfileName(x) rather than
// for every place a name is written down.
func BuiltinDefaults() []policy.ProfileName {
	return []policy.ProfileName{"@sys", "@home", "@cwd-rw"}
}
