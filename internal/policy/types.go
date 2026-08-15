// Package policy is the core of snug: it turns a set of profiles into a Policy,
// and a Policy into a bwrap argument vector.
//
// It is PURE. It starts no process, opens no socket, and reaches the host only
// through an injected Environ. That is what lets the security-critical tests run
// in CI with no privileges, and it is not a detail to trade away for convenience.
//
// The model has no subtraction. There is no mask, no deny, no un-grant. See
// .claude/design/INDEX.md §2.4 for why that makes monotonicity a structural fact rather
// than a review convention.
package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Access is a total order joined by max. More access always wins, which is what
// makes profile composition monotone.
type Access uint8

const (
	AccessNone Access = iota
	AccessRO
	AccessRW
)

// Join returns the more permissive of two accesses.
func (a Access) Join(b Access) Access {
	if b > a {
		return b
	}
	return a
}

func (a Access) String() string {
	switch a {
	case AccessRO:
		return "ro"
	case AccessRW:
		return "rw"
	default:
		return "none"
	}
}

// Kind is what sort of node exists at a Mount's Guest path.
type Kind uint8

const (
	KindBind    Kind = iota // Host -> Guest bind mount
	KindTmpfs               // fresh empty writable tmpfs
	KindSymlink             // Guest is a symlink; Host holds the link target
	KindProc                // procfs
	KindDev                 // bwrap's synthetic minimal /dev
	KindData                // generated file content, delivered via memfd
)

func (k Kind) String() string {
	switch k {
	case KindTmpfs:
		return "tmpfs"
	case KindSymlink:
		return "link"
	case KindProc:
		return "proc"
	case KindDev:
		return "dev"
	case KindData:
		return "data"
	default:
		return "bind"
	}
}

// Mount is one grant. Guest is the primary key: two grants at the same guest
// path are joined (or rejected), never both emitted.
type Mount struct {
	Guest    string
	Kind     Kind
	Host     string // KindBind: canonical host path. KindSymlink: the link target.
	Access   Access
	Optional bool // -try semantics: silently skip when Host is absent

	// Perms is the mode for a KindData file. nil means bwrap's default.
	Perms *uint32

	// Content is the file body for KindData. It is materialised into an
	// anonymous memfd at exec time, so nothing lands on disk and there is no
	// window for another process to read or swap it.
	//
	// Its type is Secret, not []byte, because these bytes are the host's Claude
	// credentials under a builtin profile and the gh token under an identity
	// one. Secret renders as "<redacted N bytes>" at every fmt, JSON and text
	// sink; see secret.go for why the guard is on the type rather than on
	// Mount, and why it redacts rather than erroring.
	Content Secret

	// From records which profiles contributed this grant. It is provenance for
	// `snug explain` only and is deliberately NOT part of equality — otherwise
	// accumulating it would perturb the fixpoint and break idempotence.
	From []string

	// Authored marks a mount snug wrote ITSELF rather than one a profile
	// granted, and it is the distinction the masking rule turns on: a profile
	// mounting over another profile's grant is MASKING and is refused, while
	// snug replacing a path with its own generated content is REPLACEMENT and is
	// allowed (the sandbox still sees a node there, just a truthful one).
	//
	// It is a FIELD rather than a convention because the previous spelling of
	// the same idea — "exempt Kind == KindData" — was a proxy that had already
	// drifted: /proc, /dev, /tmp and the ssh-agent socket are snug's too and are
	// not KindData, while a future TOML key producing KindData would have
	// inherited the exemption for free. Keying on provenance would be worse
	// still: the strings are "(snug)", "identity:<name>", "@claude" and
	// "(containers)", so no single match covers them.
	//
	// Set ONLY by Policy.Replace, which is the only permitted writer of p.Mounts
	// once Resolve has returned. Nothing a profile can write reaches it.
	Authored bool
}

// Mount deliberately has NO String or GoString method, and that is a decision
// rather than an omission — `%+v` on a Mount is already safe, because the one
// field that must not be printed carries its own guard (Content is a Secret).
//
// Writing one would make things worse in the direction this codebase keeps
// getting caught by: a hand-written String() is a second copy of the field
// list, and the next field added here would be silently missing from every
// diagnostic that prints a Mount — including resolve_test.go's failure message,
// which is read precisely when something unexpected is in a mount. The default
// struct rendering enumerates; a method asserts. Prefer the one that cannot
// drift.

// Policy is the single computed, immutable object. It is the sole author of the
// bwrap argv — and, once they exist, of the pasta argv and the container
// proxy's decisions too. One author means those cannot drift apart.
type Policy struct {
	Target   string // canonical host path of the writable project directory
	Home     string // $HOME inside == $HOME outside
	Hostname string
	Chdir    string
	Command  []string

	Mounts map[string]Mount

	// Env is keyed by EnvVar.Name. It carries structure rather than strings
	// because provenance per entry is a product requirement, not a debugging
	// aid — see env.go and ENVIRONMENT-VARIABLES.md §2.8.
	Env      map[string]EnvVar
	Net      NetPolicy
	Identity *Identity
	Podman   PodmanMode

	// Git says whether the sandbox's git config is reconstructed from the
	// host's. See gitextract.go — the host's file is read as data and never
	// mounted, because its keys name programs to run.
	Git GitMode

	// IdentityOwner names the profile that pinned Identity, so a mount staged
	// AFTER resolution can carry the same `identity:<profile>` provenance as the
	// ones Resolve stages itself. Without it the public key staged by
	// startIdentity read `(identity)` while its three siblings on the same
	// --dry-run screen read `identity:acct-a` — one file attributed to nobody,
	// in the block whose entire job is saying who asked for what.
	IdentityOwner ProfileName

	// Topology is the process shape this policy requires — DERIVED by
	// deriveTopology at the end of Resolve, never granted by a profile, a TOML
	// key or a CLI flag. See topology.go.
	Topology Topology

	// NewSession asks bwrap for a fresh TTY session, which blocks TIOCSTI input
	// injection into the parent terminal. It also breaks job control for an
	// interactive shell, so snug only asks for it on hosts where TIOCSTI is
	// actually available. See Context.LegacyTIOCSTI.
	NewSession bool

	// Profiles is the resolved, sorted profile set — everything that contributed
	// a grant, including whatever `include` pulled in. Sorted because resolution
	// is order-independent and the output should not imply an order that does
	// not exist.
	Profiles []ProfileName

	// Selected is what the human actually named. Kept only so output can
	// distinguish "you asked for this" from "this came along via an include";
	// it must never affect resolution, or order-independence is gone.
	Selected []ProfileName

	// ClaudeSettingsUnknown is every key stageClaudeSettings found in the
	// host's ~/.claude/settings.json that FilterClaudeSettings reported as
	// ClaudeSettingDrops.Unknown — on NEITHER catalogue, not
	// ClaudeSettingAllowlist and not ClaudeExecutingKeys. Sorted.
	//
	// It exists purely so --dry-run can render the fact truthfully. The
	// generated settings.json itself cannot carry it: that file IS the
	// allowlisted subset, so the names of what did not make it appear nowhere
	// inside it, and inventing a place for them there would mean writing a key
	// Claude Code was never asked to read. So this is set directly on the
	// Policy: a fact learned post-resolution that the dry-run screen still has
	// to be able to show.
	//
	// IdentityOwner is the nearest relative and the DIFFERENCE is the part to
	// keep in mind. That field also exists to serve a mount staged after
	// Resolve returns — but it is itself assigned INSIDE Resolve
	// (resolve.go, `p.IdentityOwner = name`), so it is resolver output like
	// every other field here. This one is not: cmd/snug writes it after
	// Resolve has returned, from host IO the resolver is forbidden to do.
	//
	// Two consequences follow, and neither is hypothetical. It is not covered
	// by Resolve's own determinism — commutativity and idempotence are
	// properties of what Resolve computes, and this is not that. And the
	// resolver's purity argument does not extend to it: the value comes from
	// reading a host file, which is exactly why the read lives in cmd/snug
	// and only the resulting names land here. Anything added alongside it
	// must be inert reporting data of the same kind. A field that CHANGED
	// what the sandbox can reach must never be set this way, because nothing
	// between here and bwrap re-derives it.
	//
	// nil when @claude was not selected, or when nothing on the host's file
	// fell into this class.
	ClaudeSettingsUnknown []string
}

// SortedMounts returns the mounts in bwrap emission order: ancestors strictly
// before descendants, lexicographic within a depth for determinism.
//
// Depth-ascending is both necessary and sufficient. Necessary: a read-only
// parent bind must precede a writable child bind or the child is shadowed.
// Sufficient: in a subtraction-free model the only ordering constraint is
// containment, and containment implies strictly greater depth.
func (p *Policy) SortedMounts() []Mount {
	out := make([]Mount, 0, len(p.Mounts))
	for _, m := range p.Mounts {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := depth(out[i].Guest), depth(out[j].Guest)
		if di != dj {
			return di < dj
		}
		return out[i].Guest < out[j].Guest
	})
	return out
}

func depth(p string) int {
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			n++
		}
	}
	return n
}

// Implied returns the profiles that were pulled in by include rather than named
// by the human — the answer to "why is this in my sandbox?".
func (p *Policy) Implied() []ProfileName {
	named := map[ProfileName]bool{}
	for _, s := range p.Selected {
		named[s] = true
	}
	var out []ProfileName
	for _, n := range p.Profiles {
		if !named[n] {
			out = append(out, n)
		}
	}
	return out
}

// Replace installs one of snug's OWN mounts, marking it Authored and recording
// what it displaced. It is the ONLY way to write p.Mounts once Resolve has
// assembled them — inside Resolve for the generated identity files and
// /etc/resolv.conf, and in cmd/snug for the things that must be created on the
// host before they can be granted (proxy sockets, staged credentials).
//
// These writes deliberately bypass `join`: a generated file must win over a
// profile's bind at the same path — a pinned git identity must not sit beside
// the host's credential helpers, which is the whole point of generating it. But
// the displacement must not be SILENT: selecting `@git-ro` alongside an identity
// profile used to make git-ro's bind of ~/.gitconfig vanish from the policy with
// no trace in --dry-run, so the provenance carries "replaces:<what it displaced>".
//
// The invariant is unharmed — "adding a profile can never make a path stop being
// visible" is a statement about PROFILES, and the path stays visible with
// different content — but a human reading --dry-run deserves to see that their
// grant was superseded rather than quietly ignored.
//
// Every caller that used to assign p.Mounts[g] directly (cmd/snug's claude and
// gh staging, BindSocket) now routes through here, which is what makes
// Mount.Authored true of exactly the things snug wrote.
func (p *Policy) Replace(m Mount) {
	m.Authored = true
	if old, ok := p.Mounts[m.Guest]; ok {
		m.From = append(append([]string{}, m.From...),
			"replaces:"+strings.Join(old.From, "+"))
	}
	p.Mounts[m.Guest] = m
}

// BindSocket grants a host socket at a fixed guest path, after the policy is
// resolved. It is how the CLI hands the sandbox something it had to create
// first — an ssh-agent proxy socket, say — and it is deliberately one of the
// two post-resolution writers (the other being Replace, which it uses), so the
// set of such things stays countable.
//
// `from` is the provenance the socket appears under in --dry-run. It is a
// parameter because it used to be hard-coded "(identity)", which made the
// CONTAINER socket — a completely different hole, granted by @podman-socket —
// read as though the identity machinery had opened it.
//
// It bypasses no check that matters: the path is snug's own choice under
// /run/snug, not a profile's, and the socket is one snug just created.
func (p *Policy) BindSocket(hostPath, guestPath, from string) {
	p.Replace(Mount{
		Guest: guestPath, Host: hostPath, Kind: KindBind,
		Access: AccessRW, From: []string{from},
	})
}

// PodmanMode is a total order joined by max: more engine surface wins.
type PodmanMode uint8

const (
	PodmanOff PodmanMode = iota
	PodmanSocket
	// PodmanBuild adds POST /build on top of PodmanSocket. Separate because a
	// build's options are a second, larger surface — a host bind is `-v` in a
	// query string rather than HostConfig.Binds, and every one of them has to
	// be judged again. Someone who only wants to RUN containers should not have
	// to carry that.
	PodmanBuild
)

func (m PodmanMode) Join(o PodmanMode) PodmanMode {
	if o > m {
		return o
	}
	return m
}

func (m PodmanMode) String() string {
	switch m {
	case PodmanSocket:
		return "socket"
	case PodmanBuild:
		return "build"
	}
	return "off"
}

func ParsePodmanMode(s string) (PodmanMode, error) {
	switch s {
	case "", "off":
		return PodmanOff, nil
	case "socket":
		return PodmanSocket, nil
	case "build":
		return PodmanBuild, nil
	default:
		return 0, fmt.Errorf("unknown podman mode %q (want off, socket or build)", s)
	}
}

// There is deliberately no restriction operation here — no Clamp, no Apply, no
// demote. An earlier version had one, serving a `--read-only` flag, and both are
// gone: snug stays minimal (bwrap is the swiss knife), and removing the flag
// removed the model's one exception. Profiles only ever GRANT, nothing anywhere
// un-grants, and an invariant with no carve-out is easier to trust and to test
// than one with. To grant less, select fewer profiles.
