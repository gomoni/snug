package policy

import "fmt"

// NetnsOwner says who created the network namespace the payload runs in. It is
// a total order joined by max: more reachability wins, exactly like NetMode.
type NetnsOwner uint8

const (
	NetnsSandbox NetnsOwner = iota // bwrap creates it. Today's shape, and the floor.
	NetnsStage                     // P1 creates it, pins it, LEAVES it, forks bwrap back in. THE TOP.
)

// Two points, and no third: every topology gets a network namespace of its own,
// created either by bwrap or by the stage. NeedsStage below is monotone over
// this order.

func (o NetnsOwner) String() string {
	switch o {
	case NetnsStage:
		return "stage"
	default:
		return "sandbox"
	}
}

// SubuidMode records WHETHER the host's subuid range is delegated to U. It
// never records how big it is: /etc/subuid on this host reads
// `u:1001:64535`, so the conventional 65536-at-100000 layout is wrong here
// and a size in the model is a fact the next unusual host falsifies.
type SubuidMode uint8

const (
	SubuidNone SubuidMode = iota
	SubuidFull
)

func (m SubuidMode) String() string {
	if m == SubuidFull {
		return "full"
	}
	return "none"
}

// There is deliberately no AttachMode here any more.
//
// One shipped, on the argument that landing the floor and the Join law early
// would force Phase 2 to change a golden rather than invent the lattice at the
// same time it used it. Phase 2's review reversed the premise: attach is not a
// topology. A topology is the process shape THIS run requires — what snug
// builds before the sandbox exists and what authority the host process tree
// carries as a result. A second client joining a namespace afterwards changes
// none of that; it is a property of the client, decided by the client, at a
// time when the shape is already fixed.
//
// The listener it was reserved for is cut with it (SUPERVISOR-DESIGN.md §3.3,
// and the settlement comment on #61). Measured: a same-uid host process joins
// a running sandbox's namespaces by descriptor, on both topologies, with no
// listener and nothing for snug to grant — so a mode recording "can this be
// attached to" would have been a field that never described anything snug
// controls.
//
// Nothing consumed it. Not resolution, not the stage, not --dry-run, which
// renders subuid and never rendered this. It was a lattice with no reader, and
// the cost of keeping it was that Topology.String() and every Join law test
// asserted a claim about the model that the model did not make.

// Topology is the process shape a resolved Policy requires — how many
// long-lived processes snug runs, what namespaces it must build ahead of the
// sandbox, and what capability the host process tree carries as a result. It is
// DERIVED, never granted: see deriveTopology's doc comment for why no Profile
// field, TOML key or CLI flag may reach it.
type Topology struct {
	Netns  NetnsOwner
	Subuid SubuidMode
}

// There is deliberately NO Topology.Join, and no Join on NetnsOwner or
// SubuidMode either.
//
// All three existed, mirroring Access.Join and NetMode.Join, and all three were
// dead: `Topology.Join` had no caller outside its own law test, and it was the
// only caller of the other two. Composition of what a topology is DERIVED from
// happens upstream and is very much alive — `resolve.go` folds `Net.Mode`,
// `Git` and `Podman` with their own Joins — and `deriveTopology` then runs once,
// at the end, over the already-joined result.
//
// Deleting them is not only YAGNI. A `Join` here is the one operation that
// would let something compose a Topology directly instead of deriving one, so
// its absence makes "derived, never granted" structural rather than
// conventional — the same device as TestPolicyHasNoRestrictionOperation, which
// checks an invariant by finding no code for the thing it forbids. The ORDER is
// untouched: the iota constants above still say which value is more, and
// TestAddingAProfileNeverLowersATopologyField compares them with `<`.
//
// That test is now the ONLY monotonicity check for Topology, which is why it
// grew a second base selection and a coverage assertion when these were
// removed. A lattice law about code nothing calls proves less than one walk of
// the real resolution path.

func (t Topology) String() string {
	return fmt.Sprintf("netns=%s subuid=%s", t.Netns, t.Subuid)
}

// NeedsStage reports whether this policy requires a second long-lived process
// (P1, the namespace holder — see SUPERVISOR-DESIGN.md §2) ahead of bwrap.
//
// Monotone over Netns: false at the floor (NetnsSandbox), true at the top
// (NetnsStage). That holds because the lattice orders REACHABILITY and the
// stage is what CONSTRUCTS the reachable point — a third owner above
// NetnsStage would break it, which is the thing to check before adding one.
//
// Subuid==SubuidFull is ALSO a trigger (issue #63): a container engine needs a
// stage to own its U — the full delegated subuid range and the private mount
// namespace the engine forks into — independently of which netns it joins.
// deriveTopology sets SubuidFull only from the podman branch below, and that
// branch raises Netns to at least NetnsStage in the same breath, so the
// disjunct never decides the answer for anything Resolve produces. It stays
// because the two facts are separately true and a future producer of
// SubuidFull must not silently lose its stage; TestPodmanSelectsAStage pins
// the podman half.
func (t Topology) NeedsStage() bool {
	// `>=`, not `==`, and the difference is the monotonicity above rather than
	// style. `==` is an upward-closed test only at the maximum, so on today's
	// two-point lattice both spellings have the same truth table — and a point
	// added above NetnsStage would silently make `==` NON-monotone in the
	// direction that hurts: the new top would lose its stage and nothing would
	// fail. `>=` makes a new top inherit "keeps a stage" and forces whoever
	// adds it to think.
	return t.Netns >= NetnsStage || t.Subuid >= SubuidFull
}

// deriveTopology is the ONLY producer of a Topology, called once at the end of
// Resolve. No Profile field, no TOML key, no CLI flag reaches it — a field set
// from the CLI instead of derived from the resolved profile set would
// re-create default_profile, which "Decisions made" in CLAUDE.md already
// reversed once. TestTopologyIsDerivedNotSettable checks this the same way
// TestPolicyHasNoRestrictionOperation checks invariant 1: by finding none.
func deriveTopology(n NetMode, pm PodmanMode) Topology {
	t := Topology{Subuid: SubuidNone}
	switch n {
	case NetEgress:
		t.Netns = NetnsStage
	default:
		t.Netns = NetnsSandbox
	}
	// A container engine (issue #63, Tier B) runs in the sandbox's OWN network
	// namespace, so it must be created and pinned by the stage exactly as @net's
	// is — even offline, where N holds only loopback. Its storage needs the full
	// delegated subuid range to chown across without ever touching a host uid it
	// was not given. Both are RAISED here, never granted: `pm` is the only input
	// this reads, it comes from the join-by-max of the resolved profile set, and
	// this is the single place it is consumed.
	//
	// THE `<` GUARD CANNOT FIRE FALSE TODAY and is kept anyway, which is a
	// choice and not an oversight: NetnsStage is the top of the order, so the
	// only value reaching here below it is NetnsSandbox and the guard is
	// equivalent to a plain assignment. It spells a monotone RAISE — a lattice
	// field only moves up — and a plain assignment would silently LOWER a
	// NetnsOwner added above NetnsStage later. The failure it prevents is one
	// no test can have yet, because the value it would protect does not
	// exist; that is exactly when the shape has to carry the intent.
	if pm != PodmanOff {
		if t.Netns < NetnsStage {
			t.Netns = NetnsStage
		}
		t.Subuid = SubuidFull
	}
	return t
}
