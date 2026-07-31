// Package policy is the core of snug: it turns a set of profiles into a Policy,
// and a Policy into a bwrap argument vector.
//
// It is PURE. It starts no process, opens no socket, and reaches the host only
// through an injected Environ. That is what lets the security-critical tests run
// in CI with no privileges, and it is not a detail to trade away for convenience.
//
// The model has no subtraction. There is no mask, no deny, no un-grant. See
// docs/DESIGN.md §2.4 for why that makes monotonicity a structural fact rather
// than a review convention.
package policy

import "sort"

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

	// Content is the file body for KindData. It is materialised into an
	// anonymous memfd at exec time, so nothing lands on disk and there is no
	// window for another process to read or swap it.
	Content []byte

	// From records which profiles contributed this grant. It is provenance for
	// `snug explain` only and is deliberately NOT part of equality — otherwise
	// accumulating it would perturb the fixpoint and break idempotence.
	From []string
}

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
	Env    map[string]string
	Net    NetPolicy

	// NewSession asks bwrap for a fresh TTY session, which blocks TIOCSTI input
	// injection into the parent terminal. It also breaks job control for an
	// interactive shell, so snug only asks for it on hosts where TIOCSTI is
	// actually available. See Context.LegacyTIOCSTI.
	NewSession bool

	// Profiles is the resolved, sorted profile set — everything that contributed
	// a grant, including whatever `include` pulled in. Sorted because resolution
	// is order-independent and the output should not imply an order that does
	// not exist.
	Profiles []string

	// Selected is what the human actually named. Kept only so output can
	// distinguish "you asked for this" from "this came along via an include";
	// it must never affect resolution, or order-independence is gone.
	Selected []string
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
func (p *Policy) Implied() []string {
	named := map[string]bool{}
	for _, s := range p.Selected {
		named[s] = true
	}
	var out []string
	for _, n := range p.Profiles {
		if !named[n] {
			out = append(out, n)
		}
	}
	return out
}

// Clamp is restriction, and it is deliberately NOT part of the profile lattice.
// Profiles are data that may originate near untrusted material; the CLI is the
// human. Only the human may tighten, and tightening is always safe.
type Clamp struct {
	ReadOnly bool // demote every RW grant to RO
}

// Apply moves the policy DOWN the lattice. It can only ever remove capability.
func (p *Policy) Apply(c Clamp) {
	if !c.ReadOnly {
		return
	}
	for k, m := range p.Mounts {
		if m.Access == AccessRW && m.Kind == KindBind {
			m.Access = AccessRO
			p.Mounts[k] = m
		}
	}
}
