package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Resolving the environment: conflicts, bands, dedup, and the one filter.
//
// MONOTONICITY, stated precisely, because the loose version is false here in
// the same way it is false for mount depth.
//
// The ENTRY SET of a list variable is monotone. Adding a profile can only add
// entries: merge and prepend contribute, nothing subtracts, and `sanitise`'s
// predicate is "is this path granted", which only ever grows as profiles are
// added. So a profile can never remove a directory another profile put on PATH.
//
// The ORDER is not monotone. A `prepend` pushes another profile's merged entry
// one place later, and merge-versus-merge is decided by ASCII, so /opt/bin beats
// /usr/local/bin without anybody asking. That is the same effective-behaviour
// non-monotonicity CLAUDE.md already carves out for mount depth — lowering a
// thing's precedence is a tightening, not an escalation — and it belongs in the
// same paragraph rather than being left to be discovered.
// TestEnvIsMonotoneAsASet and TestPrependReordersWithoutRemoving pin both
// halves, the second existing so nobody reads the first as proving more than it
// does.
//
// Resolution stays commutative and idempotent: every conflict is a symmetric
// error naming every claimant, the merge band is sorted, and the only order
// that survives from outside is the host's own for `sanitise` — one external
// sequence, not a fold artifact.

// envClaim is one profile's claim on a single-valued slot.
type envClaim struct {
	profile string
	verb    EnvVerb
	value   string
}

// envSeq is one profile's ordered `prepend` sequence.
type envSeq struct {
	profile string
	values  []string
}

// envClaims accumulates what every profile asked for, WITHOUT deciding
// anything.
//
// Accumulate-then-check is the whole point, not a structural preference: §2.7
// requires a conflict to name EVERY claimant, and deciding during the fold can
// only ever name the two the fold happened to be holding. Today's scalar
// conflicts do exactly that — with three profiles where two agree, the message
// names the alphabetically-last agreeing profile and never mentions the first,
// which is a fold artifact with no meaning to the reader. Checking after the
// fold completes also means there is no fold order left to keep
// order-independent.
type envClaims struct {
	scalar   map[string][]envClaim          // set and inherit both land here
	prepend  map[string][]envSeq            // the front of a list
	merge    map[string]map[string][]string // name -> element -> profiles
	sanitise map[string][]string            // name -> profiles
}

func newEnvClaims() *envClaims {
	return &envClaims{
		scalar:   map[string][]envClaim{},
		prepend:  map[string][]envSeq{},
		merge:    map[string]map[string][]string{},
		sanitise: map[string][]string{},
	}
}

func (c *envClaims) addScalar(name string, cl envClaim) {
	c.scalar[name] = append(c.scalar[name], cl)
}

func (c *envClaims) addMerge(name, value, profile string) {
	if c.merge[name] == nil {
		c.merge[name] = map[string][]string{}
	}
	c.merge[name][value] = append(c.merge[name][value], profile)
}

func (c *envClaims) addPrepend(name string, values []string, profile string) {
	c.prepend[name] = append(c.prepend[name], envSeq{profile: profile, values: values})
}

func (c *envClaims) addSanitise(name, profile string) {
	c.sanitise[name] = append(c.sanitise[name], profile)
}

// names is every variable any profile mentioned, sorted.
func (c *envClaims) names() []string {
	seen := map[string]bool{}
	for _, m := range []map[string][]envClaim{c.scalar} {
		for k := range m {
			seen[k] = true
		}
	}
	for k := range c.prepend {
		seen[k] = true
	}
	for k := range c.merge {
		seen[k] = true
	}
	for k := range c.sanitise {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectEnv folds one profile's environ block into the claim set, expanding
// {variables} in everything a profile WROTE and nothing it merely named.
//
// inherit and sanitise carry the HOST's value, so there is nothing of the
// profile's to expand in them — and an inherit of a name the host does not have
// contributes nothing at all, which is why it can never take part in a conflict
// (CALL 2).
func collectEnv(c *envClaims, name ProfileName, g EnvGrants, vars map[string]string, env Environ) error {
	// The claim set records PROVENANCE, which is a plain string for the same
	// reason Mount.From is: the same field also carries "base" and "staged bin",
	// values no profile ever named. So the type stops here, deliberately, and
	// the conversion is written once instead of at every claim below.
	from := string(name)
	expand := func(s string) (string, error) {
		e, err := expandVars(s, vars)
		if err != nil {
			return "", fmt.Errorf("profile %q: %w", name, err)
		}
		return e, nil
	}

	for _, k := range sortedMapKeys(g.Set) {
		v, err := expand(g.Set[k])
		if err != nil {
			return err
		}
		c.addScalar(k, envClaim{profile: from, verb: VerbSet, value: v})
	}

	for _, k := range sortedListKeys(g.Merge) {
		for _, raw := range g.Merge[k] {
			v, err := expand(raw)
			if err != nil {
				return err
			}
			if err := checkAbsoluteElement(name, k, VerbMerge, raw, v); err != nil {
				return err
			}
			c.addMerge(k, v, from)
		}
	}

	for _, k := range sortedListKeys(g.Prepend) {
		seq := make([]string, 0, len(g.Prepend[k]))
		for _, raw := range g.Prepend[k] {
			v, err := expand(raw)
			if err != nil {
				return err
			}
			if err := checkAbsoluteElement(name, k, VerbPrepend, raw, v); err != nil {
				return err
			}
			seq = append(seq, v)
		}
		c.addPrepend(k, seq, from)
	}

	for _, k := range g.Inherit {
		// PRESENCE, not non-emptiness: a variable the host set to the empty
		// string is SET, and for a flag that is the whole meaning (§3.2).
		if v, ok := env.LookupEnv(k); ok {
			c.addScalar(k, envClaim{profile: from, verb: VerbInherit, value: v})
		}
	}

	for _, k := range g.Sanitise {
		c.addSanitise(k, from)
	}
	return nil
}

// checkAbsoluteElement refuses a relative element of a path-valued list. A
// relative entry is resolved against whatever the payload's cwd happens to be,
// which is a different directory per invocation — and in a search path an
// element resolved against cwd is the whole of §4.3's hazard.
//
// It guards on valueIsAPath rather than isPathValued, so it also covers the
// scalars whose value is a path but which the coupling rule exempts (BASH_ENV,
// ENV, PYTHONSTARTUP). The argument for that being a TYPE refusal rather than a
// permission is at valueIsAPath, in envcoupling.go. Widening it here is harmless
// for the list verbs this is also called from: all three of those names are
// scalars, so merge and prepend on them are refused on type grounds first.
func checkAbsoluteElement(profile ProfileName, name string, verb EnvVerb, raw, expanded string) error {
	if !valueIsAPath(name) || filepath.IsAbs(expanded) {
		return nil
	}
	return fmt.Errorf("profile %q: environ.%s %s entry %q must be an absolute path: a "+
		"relative one is resolved against whatever directory the payload happens to be "+
		"in, which is not something a profile can know", profile, verb, name, raw)
}

// applyEnvClaims turns the accumulated claims into entries, in BAND order.
//
// The bands are structural — nothing a profile writes chooses which one its
// entry lands in (§2.4):
//
//	prepend (one profile)  ->  merge (sorted)  ->  sanitise (host order)
//	                       ->  snug's generated  ->  base
//
// The last two are appended by the AuthorEnvList calls in Resolve, after this
// runs, which is what makes a profile's contribution beat the distro's.
//
// It runs AFTER the whole mount set exists — including snug's own authored
// mounts and every Replace — because `sanitise`'s predicate is "is this guest
// path granted" and a filter that ran earlier would answer it against half a
// policy.
func (p *Policy) applyEnvClaims(c *envClaims, env Environ) error {
	for _, name := range c.names() {
		// An unrostered name can only have reached here through `set` or
		// `inherit` — the list verbs refuse a name with no roster row, for
		// everybody — so `known` being false and `t.list` being false are the
		// same branch, not two.
		t, known := typeOf(name)

		if !known || !t.list {
			claims := c.scalar[name]
			if err := checkScalarAgreement(name, claims); err != nil {
				return err
			}
			// Sorted by verb then profile, so which claimant is credited first
			// does not depend on the fold. Every claim carries the same value
			// here — the check above is what guarantees it — so the rendered
			// result is the same either way and only the provenance ordering is
			// at stake.
			sort.Slice(claims, func(i, j int) bool {
				if claims[i].verb != claims[j].verb {
					return claims[i].verb < claims[j].verb
				}
				return claims[i].profile < claims[j].profile
			})
			for _, cl := range claims {
				p.addEnvEntry(name, false, "", EnvEntry{
					Value: cl.value, Verb: cl.verb, From: []string{cl.profile},
				})
			}
			continue
		}

		// BAND 1 — prepend. At most one VALUE across the selected set; several
		// profiles claiming the identical sequence agree and join.
		seqs := c.prepend[name]
		if err := checkPrependAgreement(name, seqs); err != nil {
			return err
		}
		if len(seqs) > 0 {
			from := make([]string, 0, len(seqs))
			for _, s := range seqs {
				from = append(from, s.profile)
			}
			sort.Strings(from)
			for _, v := range seqs[0].values {
				p.addEnvEntry(name, true, t.sep, EnvEntry{Value: v, Verb: VerbPrepend, From: from})
			}
		}

		// BAND 2 — merge, sorted. Sorting is not a tie-break dressed up as a
		// decision: `merge` is where an author declined to say who is first, so
		// ordering it by anything the fold saw would invent an answer nobody
		// gave. Whoever does care uses `prepend`, and only one of them gets it.
		for _, v := range sortedListKeys(c.merge[name]) {
			from := append([]string(nil), c.merge[name][v]...)
			sort.Strings(from)
			p.addEnvEntry(name, true, t.sep, EnvEntry{Value: v, Verb: VerbMerge, From: from})
		}

		// BAND 3 — sanitise: the host's value, filtered, in HOST ORDER.
		if profs := c.sanitise[name]; len(profs) > 0 {
			from := append([]string(nil), profs...)
			sort.Strings(from)
			p.sanitiseHostList(name, t, from, env)
		}
	}
	return nil
}

// sanitiseHostList copies the host's value for one list variable and keeps only
// the elements policy grants.
//
// Four decisions, each of which was argued and each of which is a separate
// assertion in the tests:
//
// DROP, NEVER REWRITE. An element survives iff, read verbatim as a GUEST path,
// some grant covers it. The host->guest map is not a function — KindData mounts
// have no host path at all — so translating would have to invent one.
//
// `ro` IS ENOUGH. No mode bits, no stat. This is a TRUTHFULNESS FILTER, NOT A
// CAPABILITY FILTER: a surviving element may name an empty bind, and sanitise
// cannot promise a surviving PATH element contains an executable. It removes
// elements naming paths the sandbox has no grant for, and that is all it claims.
//
// SURVIVORS KEEP HOST ORDER, not sorted. sanitise's contract is "copy the host
// value, keep only what policy grants", so sorting would be a second, silent
// transformation nobody asked for — and §3.3 documents a variable where position
// is semantic (GOPATH, element 0 privileged). There is no commutativity cost:
// the host's order is one external sequence, not a fold artifact.
//
// NOTHING SURVIVES MEANS UNSET, not set-empty. This is the one place in the
// whole feature where getting it wrong ADDS a hole rather than failing to close
// one: an empty PATH element is the current working directory, which inside snug
// is the target (§4.3). So no entry is added at all, and EnvPairs skips a
// variable with no entries.
func (p *Policy) sanitiseHostList(name string, t envType, from []string, env Environ) {
	// Unset and empty both mean absent — FOR LISTS. Written here rather than in
	// a shared helper on purpose: §3.2's flag scalars are "set to any value,
	// including empty", so the collapse is exactly inverted for them, and
	// "right for one type, wrong for the other" is how this class of bug ships.
	host, ok := env.LookupEnv(name)
	if !ok || host == "" {
		return
	}

	v := p.Env[name]
	for _, elem := range strings.Split(host, t.sep) {
		// An empty element from the host is dropped and never recorded as a
		// value snug carried: it is not a path that failed a check, it is the
		// current directory wearing a gap.
		if elem == "" {
			continue
		}
		keep, reason := p.keepHostElement(elem)
		if keep {
			p.addEnvEntry(name, true, t.sep, EnvEntry{Value: elem, Verb: VerbSanitise, From: from})
			continue
		}
		v = p.Env[name]
		v.Name, v.List, v.Sep = name, true, t.sep
		v.Dropped = append(v.Dropped, EnvDrop{Value: elem, Var: name, From: from, Reason: reason})
		p.Env[name] = v
	}
}

// View is a mount set in ONE mount namespace. There are exactly two, and
// naming them is the whole of issue #55: every predicate below silently meant
// "the sandbox's" while a graft lived in the other one. Before this type
// existed, a graft entered into p.Mounts directly would have made
// hostPathVisible, BwrapFlags, the FILESYSTEM block and Validate's hasRuntime
// all read it as something the PAYLOAD can see, which it is not — see issue
// #55's table of the four breakages. Lifting the walk onto a named view is
// what makes "which namespace is this a fact about" a type, not a convention a
// reader has to remember.
type View struct {
	// Mounts is EXPORTED, unlike the underlying field on a lesser type would
	// be, and that is a deliberate departure from "keep View's insides
	// private": policy.Mount can carry a Secret (staged credential content),
	// and fmt only calls Secret's own redacting Format method when the value
	// is reached through an EXPORTED field — reflect.Value.CanInterface() is
	// false the moment the walk crosses one unexported field, so an
	// unexported map here would print raw credential bytes on the first
	// %+v of a View instead of "<redacted N bytes>"
	// (TestNoUnexportedByValueFieldReachesASecret; measured at
	// internal/policy/secret_test.go's TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit).
	// It carries no new capability: a caller holding *Policy already has
	// p.Mounts exported and mutable, and SandboxView shares that very map
	// rather than copying it, so this is the same aliasing that already
	// existed, given a second name.
	Mounts map[string]Mount
	name   string // "sandbox" or "engine", used only in diagnostics
}

// SandboxView is the payload's own mount namespace — p.Mounts, unchanged. It
// is what IsShadowSlot and GrantsGuestPath answered before this type existed,
// and every existing caller of those two still gets exactly this view via the
// Policy-level wrappers.
func (p *Policy) SandboxView() View {
	return View{Mounts: p.Mounts, name: "sandbox"}
}

// EngineView returns the engine's derived view: the sandbox's mounts with
// every graft applied on top.
//
// The overlay is DEPTH-AWARE, not merely key-aware, because move_mount(2) is.
// G3's second disjunct explicitly accepts a graft whose Guest is a strict
// ANCESTOR of an existing sandbox mount (a directory bwrap auto-created via
// --dir), and move_mount onto a directory takes everything mounted beneath it
// with it — the kernel does not leave the deeper mounts poking through. So
// installing a graft at G must drop every v.Mounts[k] with covers(G, k) and
// k != G, not just overwrite the key at G itself.
//
// This replaces an earlier version of this comment that argued the opposite:
// "a graft's Guest can only ever coincide with an existing sandbox mount's
// Guest, never be its strict ancestor, so overlaying is a plain per-key
// replacement with no ordering to get wrong." That premise was false — G3's
// own second disjunct contradicts it in the very same file — and the
// per-key overlay it justified left every mount BENEATH a graft still
// visible in EngineView: a graft-rw at /etc left
// EngineView().IsShadowSlot("/etc/resolv.conf") false, and a graft-rw at /opt
// over a read-only /opt/tools/bin left IsShadowSlot("/opt/tools/bin") false —
// exactly the shape the #125 PATH sweep exists to catch (issue #55, finding
// F1). Do not restore the false premise; the loop below is the fix.
//
// ok is false when there are no grafts — which is every topology that ships
// today, where the engine's mount namespace is a private COPY of the host tree
// and this Policy does not model it at all (internal/stage/inengine.go's own
// doc comment). Deriving nothing and calling it a view would put a fiction on
// the --dry-run screen: len(p.Grafts) == 0 must render as "there is no engine
// view to show", not as "the engine view happens to equal the sandbox's".
func (p *Policy) EngineView() (View, bool) {
	if len(p.Grafts) == 0 {
		return View{}, false
	}
	mounts := make(map[string]Mount, len(p.Mounts)+len(p.Grafts))
	for k, m := range p.Mounts {
		mounts[k] = m
	}
	for guest, g := range p.Grafts {
		// move_mount(2) onto guest takes every mount beneath it with it, so
		// every key it covers other than itself is shadowed, not merely the
		// key at guest.
		for k := range mounts {
			if k != guest && covers(guest, k) {
				delete(mounts, k)
			}
		}
		mounts[guest] = g.Mount
	}
	return View{Mounts: mounts, name: "engine"}, true
}

// GrantsGuestPath reports whether some grant covers a path, read verbatim as a
// guest path. Coverage is downward with no depth limit, on `/` boundaries — the
// same lexical containment the mount rules use.
//
// Exported because --dry-run marks an authored value naming a path nothing
// grants (§4.2), and that mark MUST be computed by the same predicate the filter
// above uses. Two implementations of "is this granted" would eventually disagree,
// and the one on screen is the one a human trusts.
//
// IT FOLLOWS SYMLINKS, because the filter does. For one review round it did not,
// and the sentence above stopped being true the moment keepHostElement started
// resolving: with `symlink /other/l -> /nonexistent` this returned true (the
// lexical walk stops AT the symlink mount) while the filter returned
// (false, DropNoGrant) for the identical path, so the same spelling read as
// "granted" when a profile wrote it and "nothing grants that path" when the host
// did, four lines apart on one screen. Sharing resolveThroughLinks is what makes
// the doc paragraph above a fact rather than an intention.
//
// "Verbatim" still holds and is a different axis: the caller's string is not
// rewritten, and resolution decides only the verdict.
func (v View) GrantsGuestPath(guest string) bool {
	_, _, ok := v.resolveThroughLinks(guest)
	return ok
}

// (*Policy).GrantsGuestPath is a one-line wrapper over SandboxView so no
// existing caller or test moves (issue #55): dryrun.go, envresolve.go's own
// sanitiseHostList path and every TestIsShadowSlot* case in envresolve_test.go
// keep asking the Policy the question they always asked, and keep getting the
// sandbox's own answer.
func (p *Policy) GrantsGuestPath(guest string) bool {
	return p.SandboxView().GrantsGuestPath(guest)
}

// (*Policy).coveringMount and (*Policy).resolveThroughLinks are the same kind
// of one-line wrapper over SandboxView, kept for the package-internal callers
// that ask the walk directly rather than through IsShadowSlot/GrantsGuestPath
// — existsInSandbox (graft.go, G3) and the pre-issue-#55 test suite in
// envresolve_test.go, which built fixtures as bare *Policy values and calls
// these by name. Nothing here changes the walk; it is still SandboxView's.
func (p *Policy) coveringMount(guest string) (Mount, bool) {
	return p.SandboxView().coveringMount(guest)
}

func (p *Policy) resolveThroughLinks(guest string) (final Mount, replaceable, ok bool) {
	return p.SandboxView().resolveThroughLinks(guest)
}

// coveringMount finds the DEEPEST mount whose Guest path lexically contains
// guest: the walk starts at filepath.Clean(guest) and shortens one component
// per iteration, so the first v.Mounts[d] hit is the longest covering
// prefix, not merely some covering mount — the same "effective access is the
// deepest mount covering it" rule CLAUDE.md states for join. That stopped
// being incidental the moment keepHostElement started reading the mount's
// Kind: which mount answers now decides the verdict, not just whether one
// exists.
func (v View) coveringMount(guest string) (Mount, bool) {
	if !filepath.IsAbs(guest) {
		return Mount{}, false
	}
	for d := filepath.Clean(guest); ; d = filepath.Dir(d) {
		if m, ok := v.Mounts[d]; ok {
			return m, true
		}
		if d == "/" || d == "." {
			return Mount{}, false
		}
	}
}

// CoveringMount is the exported form of coveringMount, for a caller outside
// internal/policy that needs the same "what does this view already have at
// this path" walk without re-implementing it. --dry-run's ENGINE VIEW block
// (issue #55, finding F4) is the reason it exists: rendering an accurate note
// about a graft's destination means asking the SANDBOX's view what already
// covers that path — a bare root tmpfs (ok == false), a writable grant the
// payload can already write through, or a read-only one — rather than
// printing one fixed claim regardless of the answer.
func (v View) CoveringMount(guest string) (Mount, bool) {
	return v.coveringMount(guest)
}

// nearestCovering returns the deepest mount in this view that STRICTLY
// contains guest (guest itself excluded), for resolveThroughLinks's
// replaceability check: "is the ground under a symlink writable". It is the
// same lexical operation validate.go's Policy.nearestCovering performs for the
// masking rule, deliberately re-implemented here rather than shared, because
// the two ask different questions of different scopes. validate.go's version
// answers "does the SANDBOX's mount set have a masking problem" and is
// explicitly NOT extended to grafts (issue #55 §3) — reaching across
// namespaces to decide masking would assert a containment relation no kernel
// computes. This one never crosses a namespace either: it is handed a single,
// self-consistent View — the sandbox's own, or the engine's fully-derived one
// — and stays inside it for the whole walk.
func (v View) nearestCovering(guest string) (Mount, string, bool) {
	for d := filepath.Dir(guest); d != "/" && d != "."; d = filepath.Dir(d) {
		if m, ok := v.Mounts[d]; ok {
			return m, d, true
		}
	}
	return Mount{}, "", false
}

// maxGuestLinkHops bounds resolveThroughLinks. The only chain snug itself
// builds is ONE hop (usr-merge: /bin -> usr/bin), so eight leaves room for a
// hand-written profile that chains a few and is far below the kernel's
// SYMLOOP_MAX of 40 — any chain that exhausts this budget is a cycle or a
// construction nobody should be trusting a diagnostic about.
//
// A counter rather than a visited-set, deliberately: a visited-set terminates a
// CYCLE exactly but still admits an arbitrarily long acyclic chain, and both
// deserve the same answer ("I could not resolve this"). One bound covers both,
// and cannot itself loop — which is the property --dry-run needs, since it
// renders policies that Validate has already refused.
const maxGuestLinkHops = 8

// resolveThroughLinks walks a guest path through snug's OWN symlink grants and
// returns the first non-symlink mount it lands on. It never returns a
// KindSymlink: the walk is what removes that case from both callers' switches.
//
// It exists because the lexical walk in coveringMount stops AT a symlink while
// the kernel walks THROUGH it — the same class of bug that made keepHostElement
// keep /proc, restated one node kind over. Measured, before this: a profile with
// `tmpfs = ["/data/real"]`, `symlink /data/bin -> /data/real` and
// `merge = { PATH = ["/data/bin"] }` got NO writable-PATH mark on --dry-run,
// while the identical policy naming /data/real directly got one; in a live
// sandbox the payload wrote /data/bin/git and it ran.
//
// REPLACEABLE IS THE SECOND HALF, and it is not the same question as "where does
// this land". A symlink is the one node kind snug emits that is NOT a mountpoint
// — bwrap's --symlink writes a link into whatever filesystem the parent is — so
// if the ground under the link is writable the payload can `rm` the link and
// `mkdir` its own directory at that name, whatever the link used to point at.
// Measured: `tmpfs = ["/data"]` + `symlink /data/bin -> /usr/bin` refuses a write
// THROUGH the link with EROFS and then loses to `rm /data/bin && mkdir /data/bin`,
// with the shadowed git running. The control is the same link on the root tmpfs
// (`symlink /databin -> /usr/bin`), where `rm` fails EROFS and the real git runs
// — so the discriminator really is the ground, not the link.
//
// Ground is nearestCovering, whose "stops before / and never returns it" is
// exactly right here: no mount above means the link sits on the ROOT tmpfs,
// which --remount-ro / covers. KindData is not treated as replaceable even
// though it is also a non-mountpoint file, because a PATH element naming a
// generated FILE is not a directory search path at all; if a KindData grant ever
// becomes a directory, revisit this line rather than assuming it was considered.
//
// ok is false when the chain runs out (nothing granted at the end) or exhausts
// the hop budget. The two are NOT distinguished in the return, because both
// callers want the same thing from them and neither may pretend the walk
// resolved: keepHostElement drops the element, IsShadowSlot reports not-a-slot.
//
// Lifted onto View rather than Policy (issue #55) so the identical walk can be
// asked of the ENGINE's derived view, not only the sandbox's — a graft is a
// Mount like any other once it is sitting in v.Mounts, so nothing about the
// walk itself changes; only which map it reads does.
func (v View) resolveThroughLinks(guest string) (final Mount, replaceable, ok bool) {
	// CLEAN FIRST, EVERY HOP, and this line was missing for one review round.
	// coveringMount matches on filepath.Clean(cur) while the remainder below was
	// trimmed from the UNCLEANED cur, so the two disagreed for any non-canonical
	// spelling: `//data/bin` through `symlink /data/bin -> /t` computed
	// /t + "//data/bin" = /t/data/bin instead of /t. Measured as an outright
	// verdict flip in the FAIL-OPEN direction — with /t a tmpfs and /t/data/bin a
	// ro bind, `/data/bin` gave (drop, shadow) and `//data/bin` gave (keep, not a
	// shadow), same path, opposite answers, and the keep shipped `//data/bin`
	// into the --setenv PATH operand.
	//
	// This function's caller is contractually fed host PATH elements VERBATIM,
	// so unclean spellings are its INPUT DOMAIN, not an edge case. Cleaning here
	// decides the verdict only; what sanitiseHostList records is still the
	// element as the host spelled it (DROP-NEVER-REWRITE).
	cur := filepath.Clean(guest)
	for hop := 0; hop <= maxGuestLinkHops; hop++ {
		m, found := v.coveringMount(cur)
		if !found {
			return Mount{}, replaceable, false
		}
		if m.Kind != KindSymlink {
			return m, replaceable, true
		}
		if ground, _, has := v.nearestCovering(m.Guest); has && mountIsWritable(ground) {
			replaceable = true
		}
		target := m.Host
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(m.Guest), target)
		}
		// coveringMount matched on the cleaned cur and m.Guest is itself clean,
		// so the remainder is either empty or starts at a / boundary.
		cur = filepath.Join(target, strings.TrimPrefix(cur, m.Guest))
	}
	return Mount{}, replaceable, false
}

// mountIsWritable is the one place "can whoever holds this VIEW write here" is
// decided, so the walk above and IsShadowSlot below cannot drift apart.
// KindData is a generated file, KindProc and KindDev are the kernel's and
// bwrap's, and a future kind fails closed.
//
// KindGraft joins KindBind rather than getting its own branch, and that is the
// one place a graft is NOT treated identically to every other Mount by
// accident — it is the type's own contract (Graft's doc comment: "Access — a
// REQUIREMENT on the resulting tree, not a description of it"), so the rule is
// literally the same rule KindBind already has, asked of a different Kind
// value. This is also what makes the positive control in issue #55 §4 possible
// at all: without it, EngineView().IsShadowSlot at a graft's own Guest could
// never return true, and the lifted check would be unfalsifiable in the one
// direction that matters.
func mountIsWritable(m Mount) bool {
	switch m.Kind {
	case KindTmpfs:
		return true // an empty writable directory, by construction
	case KindBind, KindGraft:
		return m.Access == AccessRW
	default:
		return false
	}
}

// keepHostElement decides whether one element of a sanitised host list
// survives, and why not when it does not. It resolves the path through snug's
// own symlinks (resolveThroughLinks) and switches EXHAUSTIVELY on the Kind of
// the mount it lands on, fail-closed for any kind the switch does not name.
//
// The verdict at every kind, and at nesting — verbatim from the sanitise-C
// design, §2:
//
//	element                            deepest covering mount    verdict         why
//	/tmp/x/bin                         /tmp KindTmpfs             DROP (Tmpfs)    a tmpfs grants an EMPTY directory; the host's content is definitionally absent, so the element was never a truthful survivor
//	/tmp (the mountpoint itself)       /tmp KindTmpfs, exact      DROP (Tmpfs)    same rule, no exact-match special case — the purest shadow slot of all
//	/usr/bin                           /usr KindBind ro           KEEP            the host's directory really is there; `ro` IS ENOUGH is the standing contract
//	{target}/bin                       {target} KindBind rw       KEEP            the host's directory is there and the element is truthful; that it is also writable is a fact about the sandbox the human chose, not a lie in the value snug wrote
//	{home}/.local/bin (bind exists     {home} KindTmpfs           DROP (Tmpfs)    one bind INSIDE a directory does not make the host's directory content present — do NOT implement "keep if any mount exists at or below"
//	  below it)
//	{home}/.local/bin/claude (bind     that KindBind               KEEP            deepest wins; a bind under a tmpfs is still a bind
//	  nested inside the {home} tmpfs)
//	{home}/.gitconfig                  KindData                   KEEP            a real node with real content at exactly that path, put there deliberately
//	/bin (usr-merged host)             KindSymlink -> ro /usr      KEEP            RESOLVED, then judged: the walk lands on @sys's ro bind, so the row's verdict is unchanged and its reason is now the bind's
//	/data/bin -> tmpfs /data/real      KindSymlink -> KindTmpfs    DROP (Tmpfs)    CHANGED — see below; the tmpfs row's reason applies through a link
//	/data/bin -> nothing granted       KindSymlink -> —            DROP (NoGrant)  CHANGED — a dangling link resolves nowhere, so the host's content is absent
//	under /proc, /dev                  KindProc / KindDev         DROP (Pseudo)   see below — this arm was KEEP, and the red team walked through it
//	a future Kind                      —                          DROP (NoGrant)  trailing default: a new kind fails closed until someone decides
//	not absolute, e.g. "bin"           —                          DROP (NoGrant)  unchanged; coveringMount keeps the !filepath.IsAbs guard
//
// /proc AND /dev ARE DROPPED, and the reasoning that kept them was wrong in an
// instructive way. It read: "kernel- and bwrap-populated, not empty". That is
// true of the DIRECTORY and false of what /proc's magic symlinks RESOLVE TO.
// This function does not follow symlinks, so the walk stops at /proc (KindProc)
// while the kernel walks /proc/self/root/tmp/x/bin all the way to the writable
// tmpfs, and /proc/self/cwd to the target — where the shadow file also PERSISTS
// TO THE HOST. Reproduced end to end: markers SHADOWED-GIT-RAN-VIA-PROC-ROOT and
// SHADOWED-GIT-VIA-PROC-CWD. The mount the walk lands on was not the mount the
// kernel resolves, which is the whole class of bug a lexical predicate has.
//
// The argument for dropping is the one that had been written down as an argument
// for keeping. An earlier round declined to widen the rule to KindDev because "an element
// under /dev on a host PATH does not occur" — and if it never legitimately
// occurs, then keeping it costs nothing and serves only an attacker's spelling.
// The same holds for /proc. So both drop, and the cost is zero.
//
// KINDSYMLINK IS NOW RESOLVED, AND THIS COMMENT USED TO ARGUE THE OPPOSITE.
// The old text read: "a KindSymlink is a link some GRANT authored, pointing
// where that grant says, and following it here would be a second resolution rule
// with its own failure modes" — and it listed "NO SYMLINK RESOLUTION" as a
// deliberate non-change. That is word for word the argument this same comment
// records being reversed for /proc and /dev one paragraph up, and it fails the
// same way: the mount the LEXICAL walk lands on is not the mount the KERNEL
// resolves. A link to a tmpfs is an element whose host content is definitionally
// absent, which is the tmpfs row's own reason, reached one node later.
//
// What the reversal costs, checked rather than assumed: nothing on the row the
// old argument was written to protect. /bin on a usr-merged host resolves to
// @sys's `ro /usr` and still KEEPs, and every ENV golden is byte-identical.
// /proc's magic links remain a different thing entirely — authored by the
// KERNEL, pointing at whatever the reading process has open, not a grant — and
// are still refused at the KindProc arm rather than followed.
//
// Three deliberate non-changes, not to be "improved":
//
//   - VERBATIM, NEVER REWRITTEN. This decides only whether elem survives; the
//     value written to Entries is elem itself, never the cleaned path and never
//     the RESOLVED path — see sanitiseHostList's own DROP-NEVER-REWRITE
//     contract. Resolution decides the verdict; it must not touch the value.
//   - NO stat, no mode bits. internal/policy stays pure.
//
// REPLACEABILITY DROPS, and the first version of this function discarded it with
// a comment arguing that "can the payload OWN this path" was IsShadowSlot's
// question and not this one. That reasoning was wrong on the fixture it was
// written next to. With `tmpfs /data` + `symlink /data/bin -> /usr/bin` the two
// questions have the SAME answer, because the link is the only thing making the
// content reachable: measured, IsShadowSlot said true, this said keep, and
// /data/bin therefore reached the --setenv PATH operand bwrap receives, where
// `rm && mkdir && echo > .../git` gave the payload a command ahead of /usr/bin
// on a PATH SNUG HANDED OVER. Marking the danger on one screen while shipping it
// in the argv is the worse of the two failures, not a lesser one.
//
// It is checked BEFORE the Kind switch, because the switch judges the landing
// mount and the landing mount is exactly what is honest here — /usr/bin really
// is read-only and really is populated. The defect is one node earlier.
func (p *Policy) keepHostElement(guest string) (bool, EnvDropReason) {
	// Always the SANDBOX's own view: this filters what the PAYLOAD's PATH (and
	// every other sanitised host list) may keep, and a graft never reaches the
	// payload's namespace at all (issue #55).
	m, replaceable, ok := p.SandboxView().resolveThroughLinks(guest)
	if replaceable {
		return false, DropReplaceable
	}
	if !ok {
		// Nothing granted at the end of the chain, or the chain did not
		// terminate. Either way the element resolves to nothing inside the
		// sandbox, which is what DropNoGrant already means.
		return false, DropNoGrant
	}
	switch m.Kind {
	case KindBind, KindData:
		return true, DropNoGrant
	case KindTmpfs:
		return false, DropTmpfsOnly
	case KindProc, KindDev:
		return false, DropPseudoOnly
	default:
		// A future Kind fails closed until someone decides what it means here.
		// KindSymlink cannot arrive: resolveThroughLinks never returns one.
		return false, DropNoGrant
	}
}

// IsShadowSlot reports whether a directory named in the environment is
// writable from inside THIS VIEW — a PATH entry the payload (sandbox view) or
// the engine (engine view) can drop a file into and so choose what the next
// `git` or `sh` resolves to.
//
// It shares ONE walk with keepHostElement — resolveThroughLinks, and through it
// coveringMount and the deepest-mount rule — rather than asking the question a
// second way, because two implementations of "what is at this path" eventually
// disagree and the reader only ever checks one. They then apply DIFFERENT
// switches to the same landing mount, because they ask different things of it:
// keepHostElement asks whether the host's content is present, this asks whether
// the payload can write.
//
// It is NOT a refusal, and must not become one without a decision. A human's own
// profile merging a writable directory onto PATH is their declaration, recorded as
// an accepted residual; what snug must never do is ship that slot
// pre-installed. So the caller is a test over the BUILTINS (and the red team),
// not Validate.
//
// Writable rather than tmpfs: a `rw` bind of a host directory is a shadow slot
// too, and a worse one, because what the payload writes there PERSISTS TO THE
// HOST.
//
// TWO WAYS TO BE A SLOT, and only the first was checked until the red team found
// the second's cousin. The path may RESOLVE to something writable, or a symlink
// on the way may be REPLACEABLE — sitting on writable ground, so the payload
// unlinks it and puts its own directory at that name regardless of where it
// pointed. The second is checked FIRST because it wins outright: a link to a
// read-only /usr/bin, standing on a tmpfs, is a live shadow slot whose landing
// mount says read-only.
//
// UNRESOLVED IS false, AND THAT IS TRUTHFUL RATHER THAN OPTIMISTIC. A chain that
// cycles or overruns the hop budget resolves to nothing inside the sandbox
// (ELOOP, or ENOENT for a dangling link), so nothing can be written there and a
// mark would be a lie on the one screen CLAUDE.md says a human trusts. It is not
// a fail-open either, because the dangerous half of "unresolved" is already
// caught by replaceable: a cycle sitting in a writable tmpfs is marked at the
// first hop, before the budget ever runs out. Verified both ways.
func (v View) IsShadowSlot(guest string) bool {
	m, replaceable, ok := v.resolveThroughLinks(guest)
	if replaceable {
		return true
	}
	if !ok {
		// Nothing is there at all, or the chain never landed; either way a PATH
		// entry naming it is inert. Reached by its own branch rather than by
		// falling through the switch, so "we could not resolve it" is never
		// silently rendered as "we resolved it and it was fine".
		return false
	}
	return mountIsWritable(m)
}

// (*Policy).IsShadowSlot is a one-line wrapper over SandboxView so no existing
// caller or test moves (issue #55): internal/cli/shadowslot_test.go,
// dryrun_test.go and the eight TestIsShadowSlot* cases in
// envresolve_test.go all keep asking the Policy the question they always
// asked, and keep getting the sandbox's own answer.
//
// The control the issue demands is the OTHER half — EngineView().IsShadowSlot
// seeing a graft the sandbox's own view cannot — and that is asked directly
// against a View, never through a Policy-level wrapper, because there is no
// single Policy-level answer to give: which view is in question is exactly
// the fact issue #55 is about.
func (p *Policy) IsShadowSlot(guest string) bool {
	return p.SandboxView().IsShadowSlot(guest)
}

// dedupeEnvLists collapses a repeated element to its EARLIEST band.
//
// This is what makes `prepend`'s guarantee literally true, and it fixes a
// measured bug: `path = ["/nonexistent/bin", "/bin"]` used to resolve to
// /bin:/nonexistent/bin:/usr/bin:/bin:/usr/sbin:/sbin, with /bin twice. A
// duplicated entry means the rendered value depends on how many profiles
// happened to name a directory, which is a fold artifact and not a decision
// anybody made.
//
// It runs LAST, after snug's own bands are authored, because the duplicate that
// actually occurs is a profile's entry against the base — and the earliest band
// is the profile's, so the base copy is the one that goes.
func (p *Policy) dedupeEnvLists() {
	for name, v := range p.Env {
		if !v.List {
			continue
		}
		seen := map[string]bool{}
		kept := make([]EnvEntry, 0, len(v.Entries))
		for _, e := range v.Entries {
			if seen[e.Value] {
				continue
			}
			seen[e.Value] = true
			kept = append(kept, e)
		}
		v.Entries = kept
		p.Env[name] = v
	}
}

// checkScalarAgreement refuses a scalar two profiles disagree about.
//
// The SAME value from two profiles is fine, and the reason usually given for
// that is wrong: not "to keep include usable" — expand folds includes into a set
// keyed by profile name, so a diamond contributes its `set` exactly once and
// never reaches here twice. The real reason is independently-authored
// duplication: two profiles both writing XDG_CONFIG_HOME = "{home}/.config" is
// plausible and harmless.
//
// set and inherit land in one check together (CALL 2). "set beats inherit"
// would be a priority field wearing a verb's clothes, which the model does not
// have — so they join the one rule `set` already follows: equal claims agree,
// unequal claims are a symmetric error naming every claimant and both verbs.
func checkScalarAgreement(name string, claims []envClaim) error {
	byValue := map[string][]envClaim{}
	for _, c := range claims {
		byValue[c.value] = append(byValue[c.value], c)
	}
	if len(byValue) < 2 {
		return nil
	}
	values := make([]string, 0, len(byValue))
	for v := range byValue {
		values = append(values, v)
	}
	sort.Strings(values)

	var b strings.Builder
	fmt.Fprintf(&b, "profiles %s disagree about %s:\n", claimantList(claims), name)
	for _, v := range values {
		for _, c := range sortClaims(byValue[v]) {
			fmt.Fprintf(&b, "         %s (environ.%s) says %q\n", c.profile, c.verb, v)
		}
	}
	b.WriteString("       A scalar has one value and snug will not choose: picking one would make\n")
	b.WriteString("       the answer depend on the order profiles were folded, and the model has no\n")
	b.WriteString("       such order. Select one of them, or make them agree.")
	return fmt.Errorf("%s", b.String())
}

// checkPrependAgreement refuses two profiles wanting the front of one variable.
//
// The slot is A USER'S TO TAKE: snug's own contribution is authored, not a
// prepend, so the default profile selection never consumes it. Two profiles
// wanting to be first is a genuine disagreement and worth an error; snug quietly
// holding the slot forever would not have been.
//
// Identical claims AGREE. Two profiles naming the same directory do not disagree
// about who is first, and the resolved policy is byte-identical either way —
// refusing that would refuse a non-conflict. Equality is over the WHOLE ORDERED
// SEQUENCE after {var} expansion, so ["/a","/b"] against ["/b","/a"] is still a
// disagreement about order and still fails.
// seqKey renders an ordered sequence as a key that is injective — two different
// sequences never produce the same string.
//
// The doc comment above says equality is over the whole ordered sequence, and
// the code said `strings.Join(values, " ")`, which is only injective if no
// element contains a space. An absolute path may. Measured, before this:
//
//	-p ptools              PATH gets /srv/a  then  /srv/b     (two elements)
//	-p qtools              PATH gets "/srv/a /srv/b"          (ONE element, one space)
//	-p ptools -p qtools    the two "agree" — one entry silently deleted, exit 0
//
// So a profile removed a directory another profile put on PATH, which is the
// property stated at the top of this file as the reason merge and prepend are
// unions. The effect is a MISSING entry rather than an extra one — a tightening,
// and the two-profile arrangement needs a literal space inside an absolute path
// — but a silent deletion is not something to leave keyed on a coincidence.
//
// %q of the slice is injective because it quotes and escapes each element
// separately, and it reads well enough to put in the error message directly.
func seqKey(values []string) string { return fmt.Sprintf("%q", values) }

func checkPrependAgreement(name string, seqs []envSeq) error {
	if len(seqs) < 2 {
		return nil
	}
	distinct := map[string][]string{} // rendered sequence -> profiles
	for _, s := range seqs {
		distinct[seqKey(s.values)] = append(distinct[seqKey(s.values)], s.profile)
	}
	if len(distinct) < 2 {
		return nil
	}
	keys := make([]string, 0, len(distinct))
	for k := range distinct {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	names := make([]string, 0, len(seqs))
	for _, s := range seqs {
		names = append(names, s.profile)
	}
	sort.Strings(names)

	var b strings.Builder
	fmt.Fprintf(&b, "profiles %s prepend to %s, and they do not agree:\n",
		joinWithAnd(names), name)
	for _, k := range keys {
		profs := append([]string(nil), distinct[k]...)
		sort.Strings(profs)
		fmt.Fprintf(&b, "         %s wants %s\n", joinWithAnd(profs), k)
	}
	b.WriteString("       Only one profile may hold the front of a variable. Use environ.merge in\n")
	b.WriteString("       the ones that do not need to be first — a merged entry still beats every\n")
	b.WriteString("       entry snug adds, so nothing is lost but the guarantee of being first.")
	return fmt.Errorf("%s", b.String())
}

func sortClaims(in []envClaim) []envClaim {
	out := append([]envClaim(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].profile != out[j].profile {
			return out[i].profile < out[j].profile
		}
		return out[i].verb < out[j].verb
	})
	return out
}

func claimantList(claims []envClaim) string {
	seen := map[string]bool{}
	var names []string
	for _, c := range claims {
		if !seen[c.profile] {
			seen[c.profile] = true
			names = append(names, c.profile)
		}
	}
	sort.Strings(names)
	return joinWithAnd(names)
}

// joinWithAnd names EVERY claimant, never "two of them". A message that names
// the two the fold happened to be holding is a fold artifact with no meaning to
// the reader.
func joinWithAnd(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
