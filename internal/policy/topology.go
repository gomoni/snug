package policy

import "fmt"

// NetnsOwner says who created the network namespace the payload runs in. It is
// a total order joined by max: more reachability wins, exactly like NetMode.
type NetnsOwner uint8

const (
	NetnsSandbox NetnsOwner = iota // bwrap creates it. Today's shape, and the floor.
	NetnsStage                     // P1 creates it, pins it, LEAVES it, forks bwrap back in.
	NetnsHost                      // the host's own. --share-net, --i-know.
)

func (o NetnsOwner) Join(b NetnsOwner) NetnsOwner {
	if b > o {
		return b
	}
	return o
}

func (o NetnsOwner) String() string {
	switch o {
	case NetnsStage:
		return "stage"
	case NetnsHost:
		return "host"
	default:
		return "sandbox"
	}
}

// SubuidMode records WHETHER the host's subuid range is delegated to U. It
// never records how big it is: /etc/subuid on this host reads
// `michal:1001:64535`, so the conventional 65536-at-100000 layout is wrong here
// and a size in the model is a fact the next unusual host falsifies.
type SubuidMode uint8

const (
	SubuidNone SubuidMode = iota
	SubuidFull
)

func (m SubuidMode) Join(o SubuidMode) SubuidMode {
	if o > m {
		return o
	}
	return m
}

func (m SubuidMode) String() string {
	if m == SubuidFull {
		return "full"
	}
	return "none"
}

// AttachMode records whether a running sandbox can be joined from outside by a
// second client. Phase 1 never raises it — there is no listener to attach
// through (see SUPERVISOR-PHASE1-SPEC.md §3.3) — but the floor and the Join law
// land now so Phase 2 has to change a golden to raise it rather than invent the
// lattice at the same time it uses it.
type AttachMode uint8

const (
	AttachNone AttachMode = iota
	AttachPayloads
)

func (m AttachMode) Join(o AttachMode) AttachMode {
	if o > m {
		return o
	}
	return m
}

func (m AttachMode) String() string {
	if m == AttachPayloads {
		return "payloads"
	}
	return "none"
}

// Topology is the process shape a resolved Policy requires — how many
// long-lived processes snug runs, what namespaces it must build ahead of the
// sandbox, and what capability the host process tree carries as a result. It is
// DERIVED, never granted: see deriveTopology's doc comment for why no Profile
// field, TOML key or CLI flag may reach it.
type Topology struct {
	Netns  NetnsOwner
	Subuid SubuidMode
	Attach AttachMode
}

// Join is the lattice join of all three fields, field by field — the same
// pattern as Access.Join and NetMode.Join, so a Topology composes exactly the
// way every other resolved scalar in this package does.
func (t Topology) Join(o Topology) Topology {
	return Topology{
		Netns:  t.Netns.Join(o.Netns),
		Subuid: t.Subuid.Join(o.Subuid),
		Attach: t.Attach.Join(o.Attach),
	}
}

func (t Topology) String() string {
	return fmt.Sprintf("netns=%s subuid=%s attach=%s", t.Netns, t.Subuid, t.Attach)
}

// NeedsStage reports whether this policy requires a second long-lived process
// (P1, the namespace holder — see SUPERVISOR-PHASE1-SPEC.md §2) ahead of bwrap.
//
// It is deliberately NOT monotone over Netns: false at the floor (NetnsSandbox),
// true in the middle (NetnsStage), false at the top (NetnsHost). Raising
// NetnsStage -> NetnsHost REMOVES the stage while strictly WIDENING the grant —
// that looks alarming until you read it as: the lattice orders REACHABILITY,
// and the stage is a construction detail for one point on that lattice, not a
// grant in its own right. NetHost inherits the host's own netns directly; there
// is nothing for a stage to hold.
func (t Topology) NeedsStage() bool { return t.Netns == NetnsStage }

// deriveTopology is the ONLY producer of a Topology, called once at the end of
// Resolve. No Profile field, no TOML key, no CLI flag reaches it — a field set
// from the CLI instead of derived from the resolved profile set would
// re-create default_profile, which "Decisions made" in CLAUDE.md already
// reversed once. TestTopologyIsDerivedNotSettable checks this the same way
// TestPolicyHasNoRestrictionOperation checks invariant 1: by finding none.
//
// pm (PodmanMode) is taken and deliberately UNUSED here: Phase 1 delegates no
// subuids even for PodmanBuild, because the engine still runs on the host and a
// delegated range would be a capability with no consumer (SUPERVISOR-PHASE1-SPEC.md
// §3.6). TestPhase1DelegatesNoSubuids pins that down as a decision, not an
// oversight, so that Phase 3 raising Subuid for podman is a conscious edit
// rather than a silent side effect of adding a case here.
func deriveTopology(n NetMode, pm PodmanMode) Topology {
	_ = pm // Phase 3 raises Subuid for PodmanBuild; see TestPhase1DelegatesNoSubuids.
	t := Topology{Subuid: SubuidNone, Attach: AttachNone}
	switch n {
	case NetHost:
		t.Netns = NetnsHost
	case NetEgress:
		t.Netns = NetnsStage
	default:
		t.Netns = NetnsSandbox
	}
	return t
}
