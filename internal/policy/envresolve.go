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
func collectEnv(c *envClaims, name string, g EnvGrants, vars map[string]string, env Environ) error {
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
		c.addScalar(k, envClaim{profile: name, verb: VerbSet, value: v})
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
			c.addMerge(k, v, name)
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
		c.addPrepend(k, seq, name)
	}

	for _, k := range g.Inherit {
		// PRESENCE, not non-emptiness: a variable the host set to the empty
		// string is SET, and for a flag that is the whole meaning (§3.2).
		if v, ok := env.LookupEnv(k); ok {
			c.addScalar(k, envClaim{profile: name, verb: VerbInherit, value: v})
		}
	}

	for _, k := range g.Sanitise {
		c.addSanitise(k, name)
	}
	return nil
}

// checkAbsoluteElement refuses a relative element of a path-valued list. A
// relative entry is resolved against whatever the payload's cwd happens to be,
// which is a different directory per invocation — and in a search path an
// element resolved against cwd is the whole of §4.3's hazard.
func checkAbsoluteElement(profile, name string, verb EnvVerb, raw, expanded string) error {
	if !typeOf(name).path || filepath.IsAbs(expanded) {
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
		t := typeOf(name)

		if !t.list {
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

// GrantsGuestPath reports whether some grant covers a path, read verbatim as a
// guest path. Coverage is downward with no depth limit, on `/` boundaries — the
// same lexical containment the mount rules use.
//
// Exported because --dry-run marks an authored value naming a path nothing
// grants (§4.2), and that mark MUST be computed by the same predicate the filter
// above uses. Two implementations of "is this granted" would eventually disagree,
// and the one on screen is the one a human trusts.
func (p *Policy) GrantsGuestPath(guest string) bool {
	_, ok := p.coveringMount(guest)
	return ok
}

// coveringMount finds the DEEPEST mount whose Guest path lexically contains
// guest: the walk starts at filepath.Clean(guest) and shortens one component
// per iteration, so the first p.Mounts[d] hit is the longest covering
// prefix, not merely some covering mount — the same "effective access is the
// deepest mount covering it" rule CLAUDE.md states for join. That stopped
// being incidental the moment keepHostElement started reading the mount's
// Kind: which mount answers now decides the verdict, not just whether one
// exists.
func (p *Policy) coveringMount(guest string) (Mount, bool) {
	if !filepath.IsAbs(guest) {
		return Mount{}, false
	}
	for d := filepath.Clean(guest); ; d = filepath.Dir(d) {
		if m, ok := p.Mounts[d]; ok {
			return m, true
		}
		if d == "/" || d == "." {
			return Mount{}, false
		}
	}
}

// keepHostElement decides whether one element of a sanitised host list
// survives, and why not when it does not. It finds the DEEPEST covering mount
// (coveringMount) and switches EXHAUSTIVELY on its Kind, fail-closed for any
// kind the switch does not name.
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
//	/bin (usr-merged host)             KindSymlink (@sys)         KEEP            a node exists; what it resolves to is decided by the OTHER grants — following it here would be a second resolution rule, and keeping it is exactly today's behaviour
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
// for keeping. TODO.md declined to widen the rule to KindDev because "an element
// under /dev on a host PATH does not occur" — and if it never legitimately
// occurs, then keeping it costs nothing and serves only an attacker's spelling.
// The same holds for /proc. So both drop, and the cost is zero.
//
// KindSymlink stays KEEP, and the distinction is not arbitrary: a KindSymlink is
// a link some GRANT authored, pointing where that grant says, and following it
// here would be a second resolution rule with its own failure modes. /proc's
// magic links are authored by the KERNEL, point at whatever the reading process
// happens to have open, and are not a grant at all.
//
// Three deliberate non-changes, not to be "improved":
//
//   - VERBATIM, NEVER REWRITTEN. This decides only whether elem survives; the
//     value written to Entries is elem itself, never the cleaned path — see
//     sanitiseHostList's own DROP-NEVER-REWRITE contract.
//   - NO SYMLINK RESOLUTION. What a KindSymlink resolves to is somebody else's
//     grant to make truthful, not this function's to chase.
//   - NO stat, no mode bits. internal/policy stays pure.
func (p *Policy) keepHostElement(guest string) (bool, EnvDropReason) {
	m, ok := p.coveringMount(guest)
	if !ok {
		return false, DropNoGrant
	}
	switch m.Kind {
	case KindBind, KindData, KindSymlink:
		return true, DropNoGrant
	case KindTmpfs:
		return false, DropTmpfsOnly
	case KindProc, KindDev:
		return false, DropPseudoOnly
	default:
		// A future Kind fails closed until someone decides what it means here.
		return false, DropNoGrant
	}
}

// IsShadowSlot reports whether a directory named in the environment is writable
// from inside the sandbox — a PATH entry the payload can drop a file into and so
// choose what the next `git` or `sh` resolves to.
//
// It is the SAME predicate keepHostElement uses for its Tmpfs verdict, deliberately
// sharing coveringMount and the deepest-mount rule rather than asking the question
// a second way, because two implementations of "what is at this path" eventually
// disagree and the reader only ever checks one.
//
// It is NOT a refusal, and must not become one without a decision. A human's own
// profile merging a writable directory onto PATH is their declaration, recorded as
// an accepted residual in TODO.md; what snug must never do is ship that slot
// pre-installed. So the caller is a test over the BUILTINS (and the red team),
// not Validate.
//
// Writable rather than tmpfs: a `rw` bind of a host directory is a shadow slot
// too, and a worse one, because what the payload writes there PERSISTS TO THE
// HOST.
func (p *Policy) IsShadowSlot(guest string) bool {
	m, ok := p.coveringMount(guest)
	if !ok {
		return false // nothing is there at all; a PATH entry naming it is inert
	}
	switch m.Kind {
	case KindTmpfs:
		return true // an empty writable directory, by construction
	case KindBind:
		return m.Access == AccessRW
	default:
		return false
	}
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
