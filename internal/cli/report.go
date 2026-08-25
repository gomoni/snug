package cli

import (
	"runtime"
	"sort"
	"strings"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

// Report is the DATA layer under --dry-run: the facts about one resolved
// policy, with none of the English the human screen wraps around them. It
// exists because issue #52 adds a second renderer, and two renderers reading
// the policy independently is how the two drift.
//
// What it deliberately is NOT: a full model of the human screen. That screen is
// prose — wrapped explanation paragraphs, `←` marks, column alignment, and
// whole blocks (NOT GRANTED's preamble, the network guarantees, the seccomp
// residual) that exist to EXPLAIN rather than to state. Modelling those would
// mean putting English in the machine format, which is the weaker of the two
// choices systemd made: English cannot be asserted on. So the split is by
// substance, not by block —
//
//	shared here      every fact the JSON document carries
//	human only       the sentences ABOUT those facts
//
// The one place the sharing is STRUCTURAL rather than merely parallel is
// Mounts. Both renderers iterate this slice, so the FILESYSTEM block and the
// JSON `mounts` array cannot list different grants —
// TestHumanAndJSONFilesystemBlocksAgree drives both for real and compares the
// sets, which is what makes "cannot drift" a check rather than a claim.
//
// Issue #332 found this claim false for seven fact-producers that renderHuman
// called and this file did not: policy.EnvNote, grantMark/p.IsShadowSlot,
// policy.ProcfsClosuresSkipped, policy.ProcfsNote, p.PastaArgs,
// describeBwrapAuthoredEnv (the PWD row) and yieldedMark. All seven are
// fields here now (MountNotes, Topology.ProcfsClosures*, Pasta, the
// reportEnvEntry additions, and the synthetic PWD entry in buildReport).
// STILL NOT HERE, named rather than silently absent: the host-derived
// GIT/SSH/CLAUDE facts describeGit/describeSSH/describeClaude compute
// (#332 F1f) and graft provenance beyond EngineView's own fields — the
// "owned:" line and the engine-owned-host-paths list describeGrafts prints
// (#332 F1h). Both were judged materially larger than the seven above and
// were handed back rather than half-done.
type Report struct {
	// Outcome is "ok" or "refused", and is the discriminator every consumer
	// reads first. A refused policy is still fully described: --dry-run's
	// entire job is showing what snug decided, and "it was refused" without
	// the policy is the half a human cannot act on.
	Outcome string

	// Refusal is Validate's error text, empty when Outcome is "ok". A STRING
	// and nothing else in format 1, on purpose: Validate's errors are bare
	// fmt.Errorf values with no code, no type and no offending path as a
	// field, and restructuring all of them (plus the 50-case corpus in
	// internal/policy/testdata/refusals.txt) is not something the format
	// should wait for. refusal.code and refusal.path can be added later
	// without a version bump.
	Refusal string

	// ExitCode is the process status this report's document accompanies, so a
	// consumer holding only the redirected file still knows what the shell
	// saw. It is the mapping run() implements — 0 for a policy that can run,
	// exitPolicy for one Validate refused — and it is derived here rather
	// than threaded through dryRun because the two facts are the same
	// decision: refusedBy != nil IS why run() returns 77.
	//
	// The claim is not left as a comment: the refusal-class enumeration in
	// jsonrefusal_test.go drives the real refusals and compares this field
	// against the exit status run() actually returned, so a divergence is a
	// red test rather than a stale sentence.
	ExitCode int

	Target string
	Home   string
	Chdir  string

	Selected []policy.ProfileName
	Implied  []policy.ProfileName

	// Mounts is p.SortedMounts() — depth-then-lexicographic, an ARRAY and
	// never a map, because a map's iteration order would make the JSON
	// undiffable and the golden fixture worthless.
	Mounts []policy.Mount

	// TmpfsSizeBytes is Policy.TmpfsSizeBytes: the bound applied to every
	// mount in Mounts whose Kind is KindTmpfs (issue #281). It is
	// policy-level, not per-mount, so it lives here once rather than being
	// copied onto every policy.Mount.
	TmpfsSizeBytes uint64

	// MountNotes carries the two per-mount facts that are not properties of
	// policy.Mount itself, keyed by Mount.Guest (the same key Policy.Mounts
	// uses): whether a profile YIELDED one of the three paths snug would
	// otherwise author (yieldedMark, issue #223) and, for a snug-authored
	// /proc entry, why its content differs from the host's (policy.ProcfsNote,
	// issue #29). Present only where there is something to say — most mounts
	// have neither, so most Guests have no entry.
	MountNotes map[string]reportMountNote

	// Grafts is the ENGINE's derived-view mounts, sorted by Guest. The payload
	// cannot see any of them; they are a separate field for the same reason
	// p.Grafts is a separate map (issue #55).
	Grafts []policy.Graft

	NotGranted []string

	Network     reportNetwork
	Topology    reportTopology
	Containers  *reportContainers // nil when no engine runs
	Environment []reportEnvVar
	Seccomp     reportSeccomp
	NewSession  bool
	BwrapArgv   []string
	// BwrapIncomplete is true when BwrapArgv, run standalone, will NOT
	// reproduce this policy's actual network posture — see
	// BwrapIncompleteReason for why. Refs #332 F1d: making the argv look more
	// directly runnable without this caveat is worse than the omission it
	// replaces, because under a stage netns the argv carries no
	// --unshare-net and lands the caller in their OWN network namespace.
	BwrapIncomplete bool
	// BwrapIncompleteReason is "" when BwrapIncomplete is false, and otherwise
	// the same fact describeBwrap prints IN CAPITALS on the human screen: the
	// stage created and pinned the sandbox's netns and a setns shim placed
	// bwrap inside it before bwrap ran, so no --netns flag exists for bwrap to
	// carry, host loopback and the host's abstract sockets are reachable if
	// this argv is run standalone, and that contradicts network.host_loopback
	// and network.abstract_sockets elsewhere in this same document.
	BwrapIncompleteReason string
	// Pasta is the pasta invocation this run's egress actually uses, nil when
	// this policy starts no pasta (p.Net.Mode != NetEgress). Refs #332 F1e:
	// the rest of this document carries snug's CLAIM about the network
	// (Network.HostLoopback, Network.AbstractSockets) and not the closing
	// flag set that implements it — "never trust a helper's default, assert
	// the behaviour" applies to a consumer of this document exactly as it
	// does to an integration test.
	Pasta *reportPasta
	// BwrapExec is what snug will really exec for argv[0], which is NOT the
	// word BwrapArgv[0]'s renderers print. See reportExec.
	BwrapExec reportExec
}

// reportMountNote is MountNotes' value type.
type reportMountNote struct {
	// Yielded is true when a profile took over one of /tmp, /proc or /dev
	// instead of snug's own mount landing there — yieldedMark's predicate,
	// m.Authored == false at one of those three guests.
	Yielded bool
	// ProcfsReplacement is policy.ProcfsNote(m.Guest) for a snug-authored
	// mount: why this path's content differs from the host's ("replaced with
	// an EMPTY file — the host's copy is …", or /proc/sys's read-only note).
	// "" for every mount ProcfsNote has nothing to say about.
	ProcfsReplacement string
}

// reportPasta is the pasta invocation snug would run for this policy's
// egress, and the same placeholder every --dry-run screen already prints
// instead of a real pid: PastaTargetStage(0, 63) under the stage topology
// (dryrun.go's NetnsStage arm), PastaTargetChild(0) otherwise. See
// policy.PastaTarget's doc comment for why a single pid cannot always name
// both namespaces pasta needs.
type reportPasta struct {
	Argv []string
	// Exec is what snug will really exec for argv[0]. Same defect, same fix
	// and the same producer as BwrapExec — the pasta block carried the
	// literal word "pasta" for the same wrong reason.
	Exec reportExec
	// Placeholder names which part of Argv is a stand-in rather than the real
	// pid a live run would use, so a consumer does not mistake /proc/0/... for
	// a real path.
	Placeholder string
}

// reportNetwork is the NETWORK block's facts. Every field answers a question a
// CI gate might actually assert on — "does this policy reach the host's
// loopback", "does it name a LAN resolver inside" — rather than restating the
// paragraph the human screen prints about it.
type reportNetwork struct {
	Mode         string
	Egress       bool
	HostLoopback bool
	// AbstractSockets is netns-scoped reachability of the host's abstract
	// AF_UNIX namespace. It is FALSE for both private-netns modes and true
	// only under host networking. Pathname sockets are a mount question and
	// are deliberately absent here — they are in Mounts.
	AbstractSockets bool
	// DNS is the servers the sandbox will really read out of /etc/resolv.conf,
	// from the resolved policy rather than from a literal (issue #28).
	DNS []string
	// DNSForwarded says pasta answers those addresses from the host side, so
	// no host resolver address is named inside (NeedsDNSForward).
	DNSForwarded bool
	DNSHost      string
	Publish      []int
	Anonymised   bool
	Address      string
	Address6     string
}

type reportTopology struct {
	// Processes is every long-lived process this run starts, snug included,
	// by name — derived from longLivedProcesses, which reads the same
	// predicates runStaged branches on. Names only: each one's ROLE is a
	// sentence, and a sentence is not a fact a consumer can assert on.
	Processes  []string
	NeedsStage bool
	Netns      string
	Subuid     string
	// EngineCapBounding is the engine's capability bounding set, present only
	// when an engine runs. Widening it is a golden diff here as well as on the
	// human screen.
	EngineCapBounding []string
	// ProcfsClosuresSkipped is policy.ProcfsClosuresSkipped(p): true exactly
	// when this run starts a container engine, so NONE of snug's /proc
	// closures (config.gz, keys, key-users, /proc/sys) apply — CLAUDE.md
	// invariant 1's third named exception, and one of the two facts that
	// invariant says --dry-run must state. It reduces to the same test as
	// Containers != nil (both are p.Podman != PodmanOff), but nothing asserted
	// that equivalence before this field existed, and the exemption follows
	// PROFILE SELECTION transitively through include — so a consumer deriving
	// it from Containers rather than reading this field is reading a
	// coincidence, not a documented equivalence.
	ProcfsClosuresSkipped bool
	// ProcfsClosureNote is policy.ProcfsClosureExemptionNote, "" when
	// ProcfsClosuresSkipped is false: snug's own text for why, carried
	// verbatim because there is no further fact behind it to state instead —
	// the same convention policy.Graft.Why uses.
	ProcfsClosureNote string
}

// reportContainers is the CONTAINERS and IMAGES blocks' facts. The engine
// SOURCE is here rather than the engine binary: --dry-run runs no preflight
// and does not probe PATH (see describeEngineSource), so naming a binary it
// has not resolved would be a lie in the machine format as much as on screen.
type reportContainers struct {
	Socket string
	// EngineSource is "SNUG_PODMAN" or "PATH".
	EngineSource string
	// EngineBinary is $SNUG_PODMAN's value, empty when PATH answered.
	EngineBinary string
	// ToolchainRoot is $SNUG_PODMAN_ROOT's value, empty when unset. Named for
	// what it is — the directory the engine's own program files live under —
	// rather than for the retired static bundle that was its first consumer
	// (#384).
	ToolchainRoot      string
	RegistrySearch     []string
	SignaturesVerified bool
	// SignaturePolicySource is the host file the engine's signature policy is
	// PROJECTED from, empty when this host configured none. It is host text.
	SignaturePolicySource string
	// SignaturePolicyRefusal is why a real run will not start: a requirement in
	// that file snug cannot reproduce. Empty on every ordinary host.
	//
	// A dry run that omitted it would describe a run that cannot start, and
	// --dry-run is the mechanism by which a human trusts snug at all. It is
	// host text twice over — a path and a decoder's rendering of the file.
	SignaturePolicyRefusal string
	// EngineBinaryRefusal is why a real run will REFUSE this engine binary: a
	// grant of this sandbox makes it writable, so snug would be exec'ing a file
	// the PAYLOAD chooses, as uid 0 and pid 1 of the engine's pid namespace
	// (issue #405, first half). Empty when no grant covers it.
	//
	// Empty ALSO when $SNUG_PODMAN is unset, and that is the honest limit rather
	// than an omission: --dry-run runs no preflight, so it cannot resolve PATH,
	// and there is no path to judge. The screen says which of the two it is.
	//
	// It is the RUN's OWN refusal text, from the run's own entry point
	// (ResolveEngineBinary), not a paraphrase: since issue #422 this screen
	// judges by calling what the run calls over the same string, so the
	// refusal has four possible subjects — not absolute, a control character
	// in the value, writable bytes, a writable NAME on the resolution chain —
	// and a canned sentence asserting the third was the version that lied.
	EngineBinaryRefusal string
	// EngineBinaryResolved is what $SNUG_PODMAN resolves to on this host, "" on
	// a refusal (ResolveEngineBinary returns no path beside an error) and equal
	// to the spelling when nothing on the way to it is a symlink. Host text.
	EngineBinaryResolved string
	// EngineBinaryIsRegularFile discharges CheckEngineBinary's regular-FILE
	// precondition, which the run discharges with preflight's own stat. Without
	// it this screen would judge a DIRECTORY-valued $SNUG_PODMAN by an
	// ancestor-only arm that is blind to a writable grant strictly inside it —
	// issue #422 one field over. False renders NOT JUDGED, never a clearance.
	EngineBinaryIsRegularFile bool
	// ToolchainRootRefusal is the same for $SNUG_PODMAN_ROOT, and it covers the
	// arm G4b structurally could not see: a writable grant anywhere INSIDE the
	// tree, not only at or above the root (issue #405, second half). Also the
	// run's own text, from JudgeEngineToolchain.
	ToolchainRootRefusal string
	// ToolchainRootResolved and ToolchainRootIsDir are EngineBinaryResolved and
	// EngineBinaryIsRegularFile for the root; the kind asked about is IsDir
	// because a tree is what the two arms of CheckEngineToolchainTree walk.
	ToolchainRootResolved string
	ToolchainRootIsDir    bool
	Logins                bool
	PortMapping           bool
}

type reportEnvVar struct {
	Name    string
	Entries []reportEnvEntry
	Dropped []reportEnvDrop
}

type reportEnvEntry struct {
	Value string
	Verb  string
	From  []string
	// AuthoredBy is policy.EnvEntry.Note: why SNUG authored this entry
	// ("base", "podman stub", "--chdir" for the synthetic PWD row), set only
	// for a VerbSnug entry (or PWD's bwrap-authored row), which has no From.
	//
	// RENAMED from this field's original name "Note" (refs #332 F1a). The old
	// name collided with policy.EnvNote — a completely different fact, the
	// annotation that the VALUE is a command — so the JSON emitted `"note":
	// ""` for the one entry that HAD an annotation, with `unchecked:false`
	// beside it reading as approval. See ValueNote for the fact "note" used to
	// be mistaken for.
	AuthoredBy string
	// TypeUnknown is policy.IsUncheckedEnv(name, verb): snug has no TYPE for
	// this NAME — no roster row, so nothing is known about whether it is a
	// scalar or a list, its separator, or what an empty element means. It is
	// an ENVIRONMENT property and belongs on an entry — issue #52's brief
	// listed it under mounts, where there is no such mark and putting one
	// would be inventing a field.
	//
	// RENAMED from "Unchecked" for the same reason as AuthoredBy: the human
	// screen's `← unchecked` mark carries its own gloss on the same line, so
	// the label can stay short; a JSON key has no room for a gloss, so the
	// key has to BE the gloss instead. See policy.UncheckedEnvNote's doc
	// comment for the other half of this cross-reference.
	TypeUnknown bool
	// ValueNote is policy.EnvNote(name, verb)'s text, stripped of the
	// "  ← " prefix that is dryrun.go's rendering convention rather than part
	// of the fact: what the TOOL DOES with the value ("the value is a
	// command; git runs it…"), never a claim about the name's type — that is
	// TypeUnknown's question, and both can be true of the same entry without
	// contradiction. "" where snug has nothing to say.
	ValueNote string
	// Grant is envGrantVerdict's CODE for this entry's Value as a path:
	// grantOK ("") when Value is not shaped like an absolute path or is
	// covered by a grant, grantShadowSlot when Name is PATH and
	// p.IsShadowSlot(Value) (the payload can write a command at this entry —
	// @claude's {home}/.local/bin "survived a milestone on screen in front of
	// everybody" before this mark existed), grantNotGranted when nothing
	// inside covers it. grantMark's own comment forbids a consumer
	// reimplementing IsShadowSlot over mounts[]; this field is the fact that
	// check needs instead.
	Grant string
	// GrantsInside is meaningful only when Grant is grantNotGranted: the
	// count of mounts strictly beneath Value, the same count grantMark's
	// parenthetical reports ("not granted (2 grants inside)").
	GrantsInside int
}

type reportEnvDrop struct {
	Value  string
	Reason string
}

// reportSeccomp separates REQUESTED from INSTALLED, which is the distinction
// CLAUDE.md's "verify a security feature is active, not merely requested" is
// about: `--seccomp` was once passed, accepted and never installed, with a
// zero exit code. A consumer asserting `seccomp.installed` is asking the
// question that matters; one asserting `requested` is asking the one that
// looked the same and was not.
type reportSeccomp struct {
	Requested bool
	Installed bool
	// Reason is a CODE, not a sentence: "" when installed, else
	// "no-seccomp-flag", "assembly-error" or "unsupported-arch".
	Reason string
	// Error is the assembly failure's text, present only for
	// "assembly-error". It is snug's own message about snug's own filter
	// construction, so it is not host text.
	Error  string
	Arch   string
	Denied []string
	// CompatArchGap is BuildFilter's known gap: on x86_64 a 32-bit (i386
	// compat) payload runs under a different audit arch and this filter denies
	// it nothing. Saying "installed" without it would be the unqualified
	// guarantee the human block is careful not to make.
	CompatArchGap bool
}

// buildReport derives every fact both renderers need, once. It reads the same
// policy accessors the human blocks read — p.Net.Resolver(), NeedsDNSForward,
// longLivedProcesses, notGranted — rather than a second opinion computed
// beside them.
//
// It touches the host where --dry-run already did — notGranted stats candidate
// paths — plus, since issue #422, the resolution of $SNUG_PODMAN and
// $SNUG_PODMAN_ROOT when either is set: buildContainersReport judges them by
// calling what the run calls, which means following the symlinks the run
// follows.
// sig is a THUNK and a PARAMETER, for the reason buildContainersReport's own doc
// gives one line down: it is the only host read anywhere in this report, so a
// builder that fetched it itself would make every golden's verdict depend on
// whether the machine running it has an /etc/containers/policy.json. Measured:
// it does in CI and does not on the development host, so json.podman-socket.json
// passed locally and failed there with
// "signature_policy_source": "/etc/containers/policy.json".
func buildReport(env policy.Environ, p *policy.Policy, args []string, cfg config,
	refusedBy error, sig func() engine.SignaturePolicySummary) Report {
	rep := Report{
		Outcome:        "ok",
		Target:         p.Target,
		Home:           p.Home,
		Chdir:          p.Chdir,
		Selected:       p.Selected,
		Implied:        p.Implied(),
		Mounts:         p.SortedMounts(),
		TmpfsSizeBytes: p.TmpfsSizeBytes,
		Grafts:         sortedGrafts(p),
		NotGranted:     notGranted(p),
		Network:        buildNetworkReport(p),
		Topology:       buildTopologyReport(p),
		Containers:     buildContainersReport(env, p, sig),
		Seccomp:        buildSeccompReport(cfg),
		NewSession:     p.NewSession,
		BwrapArgv:      args,
	}
	if refusedBy != nil {
		rep.Outcome = "refused"
		rep.Refusal = refusedBy.Error()
		rep.ExitCode = exitPolicy
	}
	rep.MountNotes = buildMountNotes(p, rep.Mounts)
	// See BwrapIncomplete's own comment: this is the SAME condition
	// describeBwrap's NetnsStage arm branches on, read here rather than
	// recomputed independently so the two cannot disagree about which runs
	// get the caveat.
	if p.Topology.Netns == policy.NetnsStage {
		rep.BwrapIncomplete = true
		rep.BwrapIncompleteReason = "the network namespace is not in this argv: the stage " +
			"created it, pinned it, and a setns shim placed bwrap inside it before bwrap ran, " +
			"and bwrap has no --netns flag to carry that here. No pasta helper starts if this " +
			"argv is run standalone, either. Run as printed, this command lands in the CALLER's " +
			"own network namespace: host loopback and the host's abstract sockets are reachable, " +
			"contradicting network.host_loopback and network.abstract_sockets elsewhere in this " +
			"document."
	}
	rep.BwrapExec = execResolution("bwrap")
	rep.Pasta = buildPastaReport(p)
	for _, name := range p.EnvNames() {
		rep.Environment = append(rep.Environment, buildEnvReport(p, p.Env[name]))
	}
	// The one variable inside the sandbox snug does not write itself: PWD,
	// which bwrap sets from --chdir. Appended AFTER the sorted names for the
	// same reason describeBwrapAuthoredEnv renders it after the sorted rows —
	// it is not part of snug's own resolved environment, and its verb
	// ("(bwrap)") is a provenance no policy.EnvVerb value produces. Refs #332
	// F1g: 16 entries for a sandbox that has 17.
	if p.Chdir != "" {
		rep.Environment = append(rep.Environment, reportEnvVar{
			Name: "PWD",
			Entries: []reportEnvEntry{{
				Value:      p.Chdir,
				Verb:       "(bwrap)",
				AuthoredBy: "--chdir",
			}},
		})
	}
	return rep
}

// buildMountNotes computes Report.MountNotes. See its doc comment for what
// each note means; this only decides WHICH mounts get one.
func buildMountNotes(p *policy.Policy, mounts []policy.Mount) map[string]reportMountNote {
	notes := make(map[string]reportMountNote, len(mounts))
	for _, m := range mounts {
		var n reportMountNote
		// yieldedMark takes p for parity with every other describe* helper in
		// dryrun.go, but its answer depends only on m — see its own doc
		// comment.
		if yieldedMark(p, m) != "" {
			n.Yielded = true
		}
		if m.Authored {
			n.ProcfsReplacement = policy.ProcfsNote(m.Guest)
		}
		if n != (reportMountNote{}) {
			notes[m.Guest] = n
		}
	}
	return notes
}

// buildPastaReport mirrors dryrun.go's own NetnsStage/else branch for the
// pasta block, so the placeholder text and the target this renders agree with
// what a human --dry-run already prints. nil when this policy starts no
// pasta at all.
func buildPastaReport(p *policy.Policy) *reportPasta {
	if p.Net.Mode != policy.NetEgress {
		return nil
	}
	if p.Topology.Netns == policy.NetnsStage {
		return &reportPasta{
			Exec: execResolution("pasta"),
			Argv: p.PastaArgs(policy.PastaTargetStage(0, 63)),
			Placeholder: "/proc/0/fd/63 is a placeholder; the real pid is the stage's, " +
				"and 63 is fdNetnsN (internal/stage/fds.go)",
		}
	}
	return &reportPasta{
		Exec:        execResolution("pasta"),
		Argv:        p.PastaArgs(policy.PastaTargetChild(0)),
		Placeholder: "/proc/0/... is a placeholder; the real pid is bwrap's child",
	}
}

func sortedGrafts(p *policy.Policy) []policy.Graft {
	guests := make([]string, 0, len(p.Grafts))
	for g := range p.Grafts {
		guests = append(guests, g)
	}
	sort.Strings(guests)
	out := make([]policy.Graft, 0, len(guests))
	for _, g := range guests {
		out = append(out, p.Grafts[g])
	}
	return out
}

func buildNetworkReport(p *policy.Policy) reportNetwork {
	n := reportNetwork{
		Mode:            p.Net.Mode.String(),
		Egress:          p.Net.Mode != policy.NetIsolated,
		HostLoopback:    p.Net.Mode == policy.NetHost,
		AbstractSockets: p.Net.Mode == policy.NetHost,
		DNS:             p.Net.Resolver().Servers,
		Publish:         p.Net.Publish,
		Anonymised:      p.Net.Anonymised(),
	}
	// NeedsDNSForward and DNSHost only mean anything where a pasta actually
	// runs. Under host networking there is none, which is the defect issue
	// #164 was: the sandbox was handed pasta's interception address while
	// nothing was intercepting.
	if p.Net.Mode == policy.NetEgress && p.Net.NeedsDNSForward() {
		n.DNSForwarded = true
		n.DNSHost = p.Net.DNSHost()
	}
	// Anonymised(), not Address.IsValid(): a hand-built Policy can carry
	// Address6 without Address (net.go's checkAddressPair refuses it, but a
	// Policy that never went through Resolve did not meet that refusal), and
	// this must render what is there rather than what the ordinary case pairs.
	if p.Net.Address.IsValid() {
		n.Address = p.Net.Address.String()
	}
	if p.Net.Address6.IsValid() {
		n.Address6 = p.Net.Address6.String()
	}
	return n
}

func buildTopologyReport(p *policy.Policy) reportTopology {
	t := reportTopology{
		NeedsStage:            p.Topology.NeedsStage(),
		Netns:                 p.Topology.Netns.String(),
		Subuid:                p.Topology.Subuid.String(),
		ProcfsClosuresSkipped: policy.ProcfsClosuresSkipped(p),
	}
	for _, pr := range longLivedProcesses(p) {
		t.Processes = append(t.Processes, pr.name)
	}
	if p.Podman != policy.PodmanOff {
		t.EngineCapBounding = policy.EngineCapBounding
	}
	if t.ProcfsClosuresSkipped {
		t.ProcfsClosureNote = policy.ProcfsClosureExemptionNote
	}
	return t
}

// buildContainersReport takes the signature-policy summary as a PARAMETER
// rather than reading it here, and that is not a style choice. The summary is
// the one fact in this struct that comes off the host filesystem, so a builder
// that fetched it itself would make every golden test's verdict depend on
// whether the machine running it enforces image signatures — the same trap
// $SNUG_PODMAN is, and the reason the golden tests clear that too.
//
// A THUNK, not a value, because an argument is evaluated before the callee runs
// and this callee returns early for a run with no engine. Passed by value, a
// `snug --dry-run -p @sys -p @cwd-rw` read the host's policy.json and every key
// it names — measured by strace — and threw the answer away. --dry-run's whole
// pitch is that it touches as little as possible, and a host policy naming
// 24,000 key paths made an unrelated dry run do 24,000 host reads.
func buildContainersReport(env policy.Environ, p *policy.Policy,
	sig func() engine.SignaturePolicySummary) *reportContainers {
	if p.Podman == policy.PodmanOff {
		return nil
	}
	c := &reportContainers{
		Socket:       containerSocketGuest,
		EngineSource: "PATH",
		// docker.io and nothing else — a generated registries.conf, no mirror,
		// no rewrite, no insecure registry (issue #137).
		RegistrySearch: []string{"docker.io"},
		// Filled in below from the projection itself, not from a constant.
		// What the engine enforces is what the HOST configured (issue #307),
		// so it is host-dependent and --dry-run must read it rather than
		// assert it.
		SignaturesVerified: false,
		// REGISTRY_AUTH_FILE points at an empty file, so no private image can
		// be pulled from inside (issue #142).
		Logins: false,
		// The engine holds no CAP_NET_ADMIN, so it cannot reconfigure this
		// namespace to publish a port.
		PortMapping: false,
	}
	// AFTER the PodmanOff early return above: this is the one host read in this
	// function, and a run with no engine must not make it.
	summary := sig()
	c.SignaturesVerified = summary.Verified
	c.SignaturePolicySource = summary.Source
	if summary.Refusal != nil {
		c.SignaturePolicyRefusal = summary.Refusal.Error()
	}

	// THE RUN'S OWN ENTRY POINTS, not a subset of their checks re-composed here
	// (issue #422). This screen used to call CheckEngineBinary and
	// CheckEngineToolchainTree on the raw env value, so a $SNUG_PODMAN_ROOT
	// spelled outside every grant but resolving INTO the @cwd-rw target printed
	// "no grant makes the root ... writable" while the run refused it. Neither
	// ResolveEngineBinary nor JudgeEngineToolchain writes to p.
	//
	// This is host I/O the two lines it replaced did not do, and it is in
	// budget: bounded by the path's component count and spent only when the
	// variable is set, where the thunk above guards against a cost bounded by
	// HOST CONTENT (a policy.json naming 24,000 key paths).
	if custom := env.Getenv("SNUG_PODMAN"); custom != "" {
		c.EngineSource = "SNUG_PODMAN"
		c.EngineBinary = custom
		resolved, err := p.ResolveEngineBinary(env, custom)
		c.EngineBinaryResolved = resolved
		if err != nil {
			c.EngineBinaryRefusal = err.Error()
		}
		// EXISTENCE IS A RENDERING INPUT, NEVER A POLICY ONE, and it may only
		// move a verdict from cleared to NOT JUDGED — never create a refusal,
		// never soften one. That asymmetry is what stops it becoming a prettier
		// lie: a payload can turn NOT JUDGED into a clearance only by CREATING
		// the object, and only where a writable grant covers it, which is where
		// the refusal above has already fired.
		if fi, serr := env.Stat(custom); serr == nil && fi.Mode().IsRegular() {
			c.EngineBinaryIsRegularFile = true
		}
	}
	if root := env.Getenv("SNUG_PODMAN_ROOT"); root != "" {
		c.ToolchainRoot = root
		resolved, err := p.JudgeEngineToolchain(env, root)
		c.ToolchainRootResolved = resolved
		if err != nil {
			c.ToolchainRootRefusal = err.Error()
		}
		if fi, serr := env.Stat(root); serr == nil && fi.IsDir() {
			c.ToolchainRootIsDir = true
		}
	}
	return c
}

func buildEnvReport(p *policy.Policy, v policy.EnvVar) reportEnvVar {
	out := reportEnvVar{Name: v.Name}
	for _, e := range v.Entries {
		grant, inside := envGrantVerdict(p, v.Name, e.Value)
		out.Entries = append(out.Entries, reportEnvEntry{
			Value:      e.Value,
			Verb:       e.Verb.String(),
			From:       e.From,
			AuthoredBy: e.Note,
			// The same predicate the `← unchecked` mark uses, from
			// internal/policy so the two screens and this format cannot
			// disagree about what "no type for this name" means.
			TypeUnknown: policy.IsUncheckedEnv(v.Name, e.Verb),
			ValueNote:   envValueNoteText(v.Name, e.Verb),
			// envGrantVerdict returns insideCount == 0 for every grant other
			// than grantNotGranted, so this is never a stray count attached
			// to a "granted" or "not a path" verdict.
			Grant:        grant,
			GrantsInside: inside,
		})
	}
	for _, d := range v.Dropped {
		out.Dropped = append(out.Dropped, reportEnvDrop{Value: d.Value, Reason: d.Reason.String()})
	}
	return out
}

// envValueNoteText is policy.EnvNote's text with dryrun.go's own rendering
// prefix ("  ← ", wrapMark's convention for a line meant to be concatenated)
// removed. The fact is the sentence after the bullet; the bullet is
// presentation, and report.go carries facts.
func envValueNoteText(name string, verb policy.EnvVerb) string {
	return strings.TrimPrefix(policy.EnvNote(name, verb), "  ← ")
}

// buildSeccompReport is the one fact-gathering step both renderers MUST share
// rather than merely parallel, because it calls sandbox.BuildFilter — the same
// function sandbox.Run calls to build the real filter. Two callers would be two
// opinions about whether the filter assembles on this host.
func buildSeccompReport(cfg config) reportSeccomp {
	// DeniedSyscallNames panics if internal/sandbox's own name table has
	// fallen behind deniedSyscalls — see its doc comment. Failing this dry run
	// loudly beats rendering a screen, or a document, that no longer matches
	// the filter.
	s := reportSeccomp{
		Requested: !cfg.noSeccomp,
		Arch:      runtime.GOARCH,
		Denied:    sandbox.DeniedSyscallNames(),
	}
	if cfg.noSeccomp {
		s.Reason = "no-seccomp-flag"
		return s
	}
	prog, ok, err := sandbox.BuildFilter()
	_ = prog // only validity matters here; the argv carries the bytes
	switch {
	case err != nil:
		// An ASSEMBLY failure on an otherwise supported architecture — a bug
		// in snug's own filter construction, not a property of this host.
		// Collapsing it into "unsupported arch" would name the wrong fix.
		s.Reason = "assembly-error"
		s.Error = err.Error()
	case !ok:
		s.Reason = "unsupported-arch"
	default:
		s.Installed = true
		s.CompatArchGap = runtime.GOARCH == "amd64"
	}
	return s
}
