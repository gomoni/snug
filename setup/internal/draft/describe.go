package draft

// Describe holds, per built-in, the one-line description snug ships for it in
// internal/profile/profiles/base.toml (`snug profile list` prints the same
// words). The rendered profile puts it above the include, so the file says what
// each name is without quoting the cost of it: the cost stays where snug shows
// it, in `snug profile show`. TestDescriptionsAreStillInBaseToml fails when
// base.toml changes a description.
var Describe = map[string]string{
	"@sys":           "Read-only OS runtime: /usr plus the few /etc files things actually need.",
	"@home":          "The home directory (from getent passwd) is an empty tmpfs at the host path. Writable, ephemeral.",
	"@target-rw":     "The target directory is writable and persists.",
	"@parent-ro":     "The target's parent directory is readable — every sibling project in it too.",
	"@net":           "Internet access via a private network namespace. Host loopback unreachable.",
	"@claude":        "Claude Code: binary and skills read-only, credentials projected and settings generated.",
	"@podman-socket": "Containers via a filtering proxy over a per-sandbox podman engine, offline unless @net is also selected.",
	"@podman-build":  "As podman-socket, plus `podman build` with a filtered option set.",
}
