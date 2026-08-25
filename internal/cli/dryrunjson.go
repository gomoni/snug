package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/policy"
)

// dryRunFormat is the machine format's version, and it is an INTEGER that
// starts at 1 rather than a semver string, because the only question a
// consumer asks it is "do I understand this document".
//
// What the number promises, and what it does not:
//
//	guaranteed        a field present in format 1 keeps its name, its type and
//	                  its meaning. outcome's two spellings, mounts[] and its
//	                  keys, the Kind and Access string sets.
//	additive, NO bump new fields, new members of mounts[], a whole new block.
//	                  Consumers MUST ignore fields they do not know.
//	needs a bump      removing or renaming a field, changing a type, changing
//	                  an enum spelling, changing mounts[] ordering.
//
// The version field is not what actually holds this: issue #52's survey found
// five projects that had drifted from their own documented format, terraform's
// docs disagreeing with its source and cargo breaking a consumer INSIDE
// --format-version=1. What held for git was v1 having its own renderer. snug
// gets the same guarantee more cheaply — the golden fixture
// (testdata/json.defaults.json) makes every format change a reviewable diff,
// which is the rule this repo already applies to the bwrap argv.
const dryRunFormat = 1

// renderJSON writes the WHOLE of stdout for a machine-readable dry run — one
// object, never NDJSON, and for every exit code `run` produces.
//
// That last part is the design decision most worth keeping. `snug --dry-run
// --json x > policy.json` must produce a parseable file even when the policy
// was refused; clang's SARIF does the opposite (0 bytes on redirect) and it is
// the failure mode this format is designed against. The human refusal text
// stays on stderr, where it already was.
//
// IT SAID "EVERY EXIT CODE" AND WAS FALSE FOR FIVE REFUSAL CLASSES (issue
// #334), which is worse than not claiming it: the strongest sentence in the
// feature's documentation was the one a user's redirect disproved. A refusal
// ahead of Validate has no policy, never reached this renderer, and wrote zero
// bytes. renderJSONRefusal below is the other half, and `run` now funnels
// every one of its refusals through refuse() so a new one cannot skip it
// silently.
//
// THE ONE EXIT THAT IS STILL NOT A DOCUMENT, named rather than left for a
// redirect to find: a flag that does not PARSE (exit 64) prints usage text and
// stops in Main, before `run`. The document's own flag is among the ones that
// failed to parse, so there is no request for a document to honour — and the
// answer to `--jsn` is the usage screen, not a JSON object saying the usage
// screen would have helped.
//
// The discriminator comes FIRST, which is why this builds an explicit struct
// tree rather than marshalling a map: encoding/json sorts map keys
// alphabetically, and "snug" is not alphabetically first. Every consumer
// surveyed reads its discriminator before anything else — cargo's `reason`,
// rustc's `$message_type`, terraform's `type` — and none of them makes you
// check whether a "refused" key is present to find out.
func renderJSON(out io.Writer, rep Report) error {
	var e lossyEncoder
	doc := e.document(rep)
	// Set LAST: lossy is true when ANY field in the document needed a bytes
	// sibling, so it cannot be known until every field has been through the
	// encoder. That is the whole point of it — a gate fails closed with ONE
	// assertion instead of auditing every field for a sibling it may not know
	// about yet.
	doc.Snug.Lossy = e.lossy
	return writeJSONDoc(out, doc)
}

// renderJSONRefusal is the document for a refusal that happened BEFORE a policy
// existed, and it is what makes renderJSON's doc comment above true rather than
// aspirational (issue #334).
//
// WHAT WAS MEASURED. `pol != nil` was the real boundary: policy.Resolve returns
// a policy only for a Validate failure, so every refusal ahead of Validate never
// entered the JSON path at all. All seven classes below exit 77; five of them
// wrote ZERO BYTES — unknown profile, target does not exist, @net-host without
// --i-know, a missing @tmp-shared grant, an unparseable profile file. So `snug
// --dry-run --json x > policy.json` produced exactly the empty file the format
// documents itself as designed against, for the most ordinary user errors, which
// are also the ones a CI gate hits most.
//
// WHY THE BLOCKS ARE ABSENT AND NOT EMPTY. There is no policy to describe, and
// "mounts": [] would say this sandbox mounts nothing — a statement about a
// sandbox, made by a document that never got far enough to have one. A consumer
// reading the empty array is worse off than one that finds no key and knows the
// question was never answered. snug.policy_resolved is the same fact as one
// boolean, for a gate that would rather not test for a missing key.
//
// WHAT IT DELIBERATELY DOES NOT CARRY. Not the selection, not the target: both
// are knowable at some of these call sites and not at others (profile.Load fails
// before the selection is assembled), and a key whose presence depends on which
// refusal fired is worse than one that is never there. Adding either later is
// additive and needs no format bump.
func renderJSONRefusal(out io.Writer, message string, code int) error {
	var e lossyEncoder
	// Through the SAME encoder as every other host-influenced value: these
	// messages quote host paths (an unreadable profile file names it, a
	// missing target names it), so they can carry bytes no Go string renders
	// and runes that forge a row.
	msg, _ := e.text(message)
	doc := jsonRefusalDoc{
		Snug: jsonMeta{
			Format:         dryRunFormat,
			Outcome:        "refused",
			ExitCode:       code,
			PolicyResolved: false,
		},
		Refusal: jsonRefusal{Message: msg},
	}
	doc.Snug.Lossy = e.lossy
	return writeJSONDoc(out, doc)
}

// jsonRefusalDoc is the policy-less document. It is a SEPARATE type rather than
// jsonDoc with everything omitempty, and that is the load-bearing choice: with
// omitempty, "absent" and "the zero value" become the same wire form, so a
// future field that is legitimately false or empty in a real document would
// silently vanish from it. Two types keep the two shapes honest, and the
// discriminator (snug.outcome, then snug.policy_resolved) is what a consumer
// reads to know which one it is holding — exactly the order renderJSON's doc
// comment argues for.
type jsonRefusalDoc struct {
	Snug    jsonMeta    `json:"snug"`
	Refusal jsonRefusal `json:"refusal"`
}

// writeJSONDoc marshals, escapes and writes — the tail both renderers share, so
// the forging-rune escape cannot be applied to one document shape and forgotten
// on the other. That is this repo's most-repeated defect (a rule written once
// and applied to one of its two halves), and here it is closed by there being
// one place to apply it.
func writeJSONDoc(out io.Writer, doc any) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err == nil {
		// After marshalling, ONCE, so it covers every string in the document
		// including the ones a later field adds. See its doc comment for why
		// this is fidelity-preserving and why it does not set lossy.
		b = escapeRawForgingRunes(b)
	}
	if err != nil {
		// Unreachable for either tree — both are strings, bools, ints and
		// slices of those — but reported rather than swallowed: a machine
		// format that half-wrote itself and said nothing is invariant 5's
		// shape.
		return fmt.Errorf("rendering the machine-readable dry run: %w", err)
	}
	if _, err := out.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("writing the machine-readable dry run: %w", err)
	}
	return nil
}

// lossyEncoder turns a Go string into the pair the format uses for a value it
// cannot carry at all, and remembers whether it ever had to.
//
// ONE TRIGGER, AND IT IS NOT "hard to display". A value gets a
// `<field>_bytes` sibling — and sets snug.lossy — exactly when the string field
// cannot BE the value: it is not valid UTF-8, so json.Marshal substitutes
// U+FFFD, returns NO error, and does not round-trip (measured). A CI gate
// saying "no mount grants anything under /etc" must not be bypassable by a path
// whose bytes are not UTF-8, and the sibling is what stops that.
//
// Everything else is the TRUE value, verbatim. That is the whole difference
// between this and a screen:
//
//   - NOT policy.VisibleText, which is what the human screen uses. It is a
//     TERMINAL-DISPLAY transform, and running a machine format through one
//     makes the string field not the actual value — `mount.host == "/etc/…"`
//     would then have to know about snug's escaping rules to compare. JSON's
//     job here is fidelity.
//   - VisibleText is also not injective (it returns a valid-UTF-8,
//     forging-rune-free string verbatim and %q-escapes everything else, so a
//     path containing the five literal ASCII characters \, x, f, f renders
//     identically to one containing byte 0xFF), which is a second reason not
//     to carry a screen's encoding into an interface people write gates
//     against.
//   - A polymorphic `string | number[]` — systemd's choice — would force Rego
//     rules, Go structs and serde to branch on the type of a field they mostly
//     want to compare as a string.
//
// The display hazard is real and is handled WITHOUT touching the value: see
// escapeRawForgingRunes, which spells those runes using JSON's own \uXXXX and
// therefore changes nothing a decoder gives back.
type lossyEncoder struct{ lossy bool }

// text returns the string field and, when the value is not valid UTF-8, the
// real bytes for its "<field>_bytes" sibling.
func (e *lossyEncoder) text(s string) (string, byteList) {
	if utf8.ValidString(s) {
		return s, nil
	}
	e.lossy = true
	return s, byteList(s)
}

// texts is text for a LIST of host-controlled strings. The sibling array is
// INDEX-ALIGNED with the string array and carries a null for every element
// that was fine, so a consumer reads element i's authoritative bytes at index
// i rather than having to re-derive which element the siblings belong to. It
// is absent entirely unless at least one element needed it.
func (e *lossyEncoder) texts(in []string) ([]string, []byteList) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, len(in))
	sib := make([]byteList, len(in))
	any := false
	for i, s := range in {
		v, b := e.text(s)
		out[i] = v
		if b != nil {
			sib[i] = b
			any = true
		}
	}
	if !any {
		return out, nil
	}
	return out, sib
}

// escapeRawForgingRunes rewrites every forging rune encoding/json left RAW in
// the finished document as JSON's own \uXXXX escape.
//
// WHY IT IS NEEDED. Measured on this host, encoding/json escapes C0 for free —
// ESC becomes , newline becomes \n — and leaves the rest raw:
//
//	ESC   U+001B  ->          escaped
//	CSI   U+009B  ->  raw bytes     NOT escaped
//	NEL   U+0085  ->  raw bytes     NOT escaped
//	RLO   U+202E  ->  raw bytes     NOT escaped
//
// A dry-run document is read by humans — in a golden diff, through jq, in a
// review UI — so a raw CSI or RLO in a host path is the same lie in a new
// artifact that visibleValue exists to stop on screen. C1 and the directional
// overrides are exactly the two classes CLAUDE.md records as having been missed
// once each already.
//
// WHY IT IS NOT VisibleText, AND NOT A SECOND VOCABULARY. This changes no
// value: `‮` IS U+202E to every JSON decoder, so the document round-trips
// byte for byte and a typed consumer never sees the escape at all. It is JSON's
// native spelling of a character, not snug's rendering of one — which is why it
// does NOT set snug.lossy: nothing was lost. The PREDICATE is shared with every
// screen (policy.IsForgingRune), so the two cannot disagree about which runes
// are hazards; only the spelling differs, because one output is a terminal and
// the other is a parser.
//
// Operating on the marshalled bytes is safe and is what makes this cover every
// field, present and future, rather than the ones someone remembered to wrap:
// JSON's own syntax is pure ASCII, so a byte sequence decoding to a C1 or Cf
// rune can only be inside a string literal.
// jsonRawForgingRune is escapeRawForgingRunes's predicate: a forging rune that
// encoding/json actually left RAW.
//
// C0 IS EXCLUDED, and getting that wrong destroys the document rather than
// hardening it. encoding/json escapes every rune below U+0020 inside a string,
// so a raw C0 byte in the marshalled output can only be MarshalIndent's own
// pretty-printing — the newlines between members and the indentation. The
// first draft of this used policy.IsForgingRune directly, rewrote every
// structural newline to \\u000a, and produced a document that no longer
// parsed. The predicate is deliberately expressed as "forging AND not
// something json already handled" rather than as a list of C1 and Cf ranges:
// a list beside policy.IsForgingRune is the second catalogue that drifts, and
// the hazard set stays the screen's.
//
// THE BOUND IS 0x20 BECAUSE THAT IS WHAT THE PARAGRAPH ABOVE ARGUES, and it
// shipped as 0x80 for a milestone (issue #333). encoding/json escapes runes
// BELOW U+0020, plus quote and backslash; it does not escape U+007F, and
// policy.IsForgingRune answers true for U+007F. So the two bounds differ by
// exactly one code point, DEL, and it reached the document raw — in an
// environment value, in mounts[].guest, in mounts[].host and in bwrap.argv —
// with `snug.lossy` false beside it asserting the document was clean. The
// justification and the constant now state the same boundary, which is the
// half that was missing: the comment was right and the code was not, and
// nothing made them answer to each other.
//
// The name is not `rawForgingRune`: screensinks_test.go already owns that one,
// for the sweep every SCREEN in this package shares. Two predicates, one
// vocabulary — that one asks "did a raw hazard reach a terminal", this one
// asks "did one survive encoding/json".
func jsonRawForgingRune(r rune) bool { return r >= 0x20 && policy.IsForgingRune(r) }

func escapeRawForgingRunes(b []byte) []byte {
	// The common document has none, and re-allocating every one of them to
	// discover that is waste on the path a human runs constantly.
	if !bytes.ContainsFunc(b, jsonRawForgingRune) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for _, r := range string(b) {
		if !jsonRawForgingRune(r) {
			out = utf8.AppendRune(out, r)
			continue
		}
		// Non-BMP runes need a surrogate pair; \uXXXX addresses 16 bits.
		// utf16.Encode handles both cases, so this does not have to decide
		// which one it is looking at.
		for _, u := range utf16.Encode([]rune{r}) {
			out = append(out, []byte(fmt.Sprintf(`\u%04x`, u))...)
		}
	}
	return out
}

// byteList is the authoritative form of a value the string field could only
// approximate: the real bytes, as JSON numbers.
//
// encoding/json renders a []byte as base64, which would be a second encoding
// to explain and would not read as bytes to anyone eyeballing the golden file.
// A nil byteList marshals to null so the index-aligned sibling arrays can say
// "this element was fine".
type byteList []byte

func (b byteList) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	out := make([]byte, 0, len(b)*4+2)
	out = append(out, '[')
	for i, c := range b {
		if i > 0 {
			out = append(out, ',')
		}
		out = strconv.AppendUint(out, uint64(c), 10)
	}
	return append(out, ']'), nil
}

type jsonDoc struct {
	Snug        jsonMeta     `json:"snug"`
	Refusal     *jsonRefusal `json:"refusal,omitempty"`
	Target      string       `json:"target"`
	TargetBytes byteList     `json:"target_bytes,omitempty"`
	Home        string       `json:"home"`
	HomeBytes   byteList     `json:"home_bytes,omitempty"`
	Chdir       string       `json:"chdir"`
	ChdirBytes  byteList     `json:"chdir_bytes,omitempty"`
	Profiles    jsonProfiles `json:"profiles"`
	Mounts      []jsonMount  `json:"mounts"`
	// EngineView is the grafts array. The Go field avoids the name `Grafts`
	// for the same reason jsonMount.SnugAuthored avoids `Authored`: policy's
	// TestOnlyGraftWritesGrafts greps the module for an assignment to a
	// selector of that name to prove Policy.Graft is the only writer of that
	// map (the regex is in graft_test.go, and yes, it matches a COMMENT
	// spelling it out too — which is why this one does not), and a textual sweep cannot
	// tell this output struct from a Policy. Keeping the sweep exception-free
	// is worth more than the tidier field name; the JSON key is unchanged.
	EngineView  []jsonGraft     `json:"grafts"`
	NotGranted  jsonNotGranted  `json:"not_granted"`
	Network     jsonNetwork     `json:"network"`
	Topology    jsonTopology    `json:"topology"`
	Containers  *jsonContainers `json:"containers"`
	Environment []jsonEnvVar    `json:"environment"`
	Seccomp     jsonSeccomp     `json:"seccomp"`
	TTY         jsonTTY         `json:"tty"`
	Bwrap       jsonBwrap       `json:"bwrap"`
	// Pasta is nil when this policy starts no pasta process
	// (network.mode != "egress"). Refs #332 F1e.
	Pasta *jsonPasta `json:"pasta"`
}

type jsonMeta struct {
	Format  int    `json:"format"`
	Outcome string `json:"outcome"`
	Lossy   bool   `json:"lossy"`
	// ExitCode is the process exit status this document accompanies, so a
	// consumer that only has the FILE still knows what the shell would have
	// seen. Both are stated because they are not the same fact: `outcome` is
	// snug's verdict on the policy and `exit_code` is sysexits-flavoured and
	// distinguishes a policy refusal (77) from an unavailable host (69) from
	// snug's own bug (70).
	ExitCode int `json:"exit_code"`
	// PolicyResolved says whether the policy-derived blocks are in this
	// document at all (issue #334).
	//
	// It exists because a refusal can happen on either side of
	// policy.Resolve, and the two produce documents of different SHAPE: a
	// profile file that does not parse, an unknown profile name or a target
	// that does not exist are refused before any policy exists, so there are
	// no mounts, no environment and no argv to describe. Those blocks are then
	// ABSENT rather than empty — a consumer reading `"mounts": []` as "this
	// sandbox mounts nothing" would be worse off than one that sees no
	// `mounts` key and knows not to ask.
	//
	// Absence alone is the mechanism; this boolean is the one-expression
	// spelling of it, so a gate does not have to test for a missing key to
	// learn which shape it is holding.
	PolicyResolved bool `json:"policy_resolved"`
}

// jsonRefusal carries the message and nothing else in format 1. See
// Report.Refusal for why, and for what can be added later without a bump.
type jsonRefusal struct {
	Message string `json:"message"`
}

type jsonProfiles struct {
	Selected []string `json:"selected"`
	Implied  []string `json:"implied"`
}

// jsonMount is one grant. The field set is the FILESYSTEM block's, with two
// deliberate differences:
//
//	kind + access are SEPARATE. The human column collapses them — it prints
//	the access word for a bind and "exec" for a KindData file with an
//	executable permission bit — because a human scanning that block wants one
//	column. A consumer wants two facts, and "exec" is not a Kind.
//
//	executable is the fact behind that "exec" rendering, stated as its own
//	boolean rather than smuggled into kind.
type jsonMount struct {
	Guest      string   `json:"guest"`
	GuestBytes byteList `json:"guest_bytes,omitempty"`
	// Host is EMPTY for a tmpfs, a procfs, a dev or generated content, and is
	// always present rather than omitted: a consumer should not have to branch
	// on whether the key exists to learn there is no host side.
	Host      string   `json:"host"`
	HostBytes byteList `json:"host_bytes,omitempty"`
	Kind      string   `json:"kind"`
	Access    string   `json:"access"`
	From      []string `json:"from"`
	Optional  bool     `json:"optional"`
	// SnugAuthored is Mount.Authored: snug wrote this mount itself rather than
	// a profile granting it.
	//
	// The Go field is NOT spelled `Authored`, and that is deliberate rather
	// than a style choice. internal/policy sweeps the whole module for writes
	// to a field of that name (TestAuthoredWritersAreTheThreeTheCommentsName),
	// because two security rules exempt an Authored mount and a fourth writer
	// would be a fourth way to earn the exemption. The sweep is TEXTUAL, so it
	// cannot tell this output-only struct from a policy.Mount — and the fix is
	// to keep the sweep maximally paranoid and give the DTO its own name,
	// never to teach the sweep an exception. The JSON key is still "authored";
	// only the Go spelling moves.
	SnugAuthored bool `json:"authored"`
	Executable   bool `json:"executable"`
	// Yielded is Report.MountNotes[guest].Yielded: a profile took over one of
	// /tmp, /proc or /dev instead of snug's own mount landing there
	// (yieldedMark, issue #223) — false for every mount that is not one of
	// those three guests, and false for snug's own mount AT one of them.
	Yielded bool `json:"yielded"`
	// ProcfsReplacement is Report.MountNotes[guest].ProcfsReplacement:
	// policy.ProcfsNote's text for a snug-authored mount, "" everywhere else.
	ProcfsReplacement string `json:"procfs_replacement,omitempty"`
	// SizeBytes is Policy.TmpfsSizeBytes, populated for KindTmpfs mounts only
	// (issue #281). omitempty is required here, not a style choice: a
	// non-tmpfs row carrying "size_bytes": 0 would read as "unbounded" to a
	// consumer, when it in fact means "not a tmpfs; this field does not
	// apply". Additive — see dryRunFormat's doc comment — so no format bump.
	SizeBytes uint64 `json:"size_bytes,omitempty"`
}

// jsonGraft is a mount in the ENGINE's derived namespace, never the payload's.
// It is a separate array rather than a flag on a mount for the same reason
// p.Grafts is a separate map: four callers read p.Mounts as "what the payload
// can see", which a graft is not (issue #55).
type jsonGraft struct {
	Guest      string   `json:"guest"`
	GuestBytes byteList `json:"guest_bytes,omitempty"`
	Host       string   `json:"host"`
	HostBytes  byteList `json:"host_bytes,omitempty"`
	// HostAsked is the path snug's own code named BEFORE symlink resolution,
	// and is empty unless resolution changed it. open_tree(2) follows a final
	// symlink, so the two can differ and a human is owed the difference.
	HostAsked      string   `json:"host_asked"`
	HostAskedBytes byteList `json:"host_asked_bytes,omitempty"`
	Kind           string   `json:"kind"`
	Access         string   `json:"access"`
	// Why is the abuse sentence. It is English, and it is here anyway: it is
	// snug's own text, Validate refuses an empty one, and there is no fact
	// behind it to carry instead.
	Why string `json:"why"`
}

type jsonNotGranted struct {
	Lines      []string   `json:"lines"`
	LinesBytes []byteList `json:"lines_bytes,omitempty"`
}

type jsonNetwork struct {
	Mode            string   `json:"mode"`
	Egress          bool     `json:"egress"`
	HostLoopback    bool     `json:"host_loopback"`
	AbstractSockets bool     `json:"abstract_sockets"`
	DNS             []string `json:"dns"`
	DNSForwarded    bool     `json:"dns_forwarded"`
	DNSHost         string   `json:"dns_host"`
	Publish         []int    `json:"publish"`
	Anonymised      bool     `json:"anonymised"`
	Address         string   `json:"address"`
	Address6        string   `json:"address6"`
}

type jsonTopology struct {
	Processes         []string `json:"processes"`
	NeedsStage        bool     `json:"needs_stage"`
	Netns             string   `json:"netns"`
	Subuid            string   `json:"subuid"`
	EngineCapBounding []string `json:"engine_cap_bounding,omitempty"`
	// ProcfsClosuresSkipped is Report.Topology.ProcfsClosuresSkipped —
	// CLAUDE.md invariant 1's third named exception, stated rather than left
	// derivable from Containers != nil. Refs #332 F1c.
	ProcfsClosuresSkipped bool `json:"procfs_closures_skipped"`
	// ProcfsClosureNote is policy.ProcfsClosureExemptionNote, omitted when
	// ProcfsClosuresSkipped is false.
	ProcfsClosureNote string `json:"procfs_closure_note,omitempty"`
}

type jsonContainers struct {
	Socket             string   `json:"socket"`
	EngineSource       string   `json:"engine_source"`
	EngineBinary       string   `json:"engine_binary"`
	EngineBinaryBytes  byteList `json:"engine_binary_bytes,omitempty"`
	ToolchainRoot      string   `json:"toolchain_root"`
	ToolchainRootBytes byteList `json:"toolchain_root_bytes,omitempty"`
	RegistrySearch     []string `json:"registry_search"`
	SignaturesVerified bool     `json:"signatures_verified"`
	// The host file the engine's signature policy is projected from, and the
	// reason a real run will refuse. Both are host text, so both carry a bytes
	// sibling (issue #307). Additive fields: format 1 does not bump for them.
	SignaturePolicySource       string   `json:"signature_policy_source"`
	SignaturePolicySourceBytes  byteList `json:"signature_policy_source_bytes,omitempty"`
	SignaturePolicyRefusal      string   `json:"signature_policy_refusal"`
	SignaturePolicyRefusalBytes byteList `json:"signature_policy_refusal_bytes,omitempty"`
	// Why a real run will refuse the engine binary or its toolchain root: a
	// grant of this sandbox makes it writable (issue #405). Additive and
	// omitempty — they are only computable when $SNUG_PODMAN/$SNUG_PODMAN_ROOT
	// name a path, since --dry-run runs no preflight and cannot resolve PATH.
	// Both are derived from env values, so both carry a bytes sibling.
	EngineBinaryRefusal       string   `json:"engine_binary_refusal,omitempty"`
	EngineBinaryRefusalBytes  byteList `json:"engine_binary_refusal_bytes,omitempty"`
	ToolchainRootRefusal      string   `json:"toolchain_root_refusal,omitempty"`
	ToolchainRootRefusalBytes byteList `json:"toolchain_root_refusal_bytes,omitempty"`
	// What each path RESOLVES to on this host, and whether an object of the
	// right kind is there (issue #422). A consumer needs all three states the
	// human block distinguishes: refused, cleared, and not judged — which is
	// `*_refusal` empty AND the `*_is_*` flag false, never a clearance. A
	// symlink target is host text, so both carry a bytes sibling.
	EngineBinaryResolved       string   `json:"engine_binary_resolved,omitempty"`
	EngineBinaryResolvedBytes  byteList `json:"engine_binary_resolved_bytes,omitempty"`
	EngineBinaryIsRegularFile  bool     `json:"engine_binary_is_regular_file"`
	ToolchainRootResolved      string   `json:"toolchain_root_resolved,omitempty"`
	ToolchainRootResolvedBytes byteList `json:"toolchain_root_resolved_bytes,omitempty"`
	ToolchainRootIsDir         bool     `json:"toolchain_root_is_dir"`
	Logins                     bool     `json:"logins"`
	PortMapping                bool     `json:"port_mapping"`
}

type jsonEnvVar struct {
	Name    string         `json:"name"`
	Entries []jsonEnvEntry `json:"entries"`
	// Dropped elements are NAMED, not counted, for the same reason the human
	// block names them: "1 of 3 kept" does not let anyone check a filter.
	Dropped []jsonEnvDrop `json:"dropped,omitempty"`
}

// jsonEnvEntry's field set was renamed one day after this format shipped
// (refs #332 F1a): the JSON key `note` used to carry policy.EnvEntry.Note
// (snug's own AUTHORSHIP reason, "base", "podman stub"), not
// policy.EnvNote's text (what the tool DOES with the value) — so a consumer
// reading `note` got "" for the one entry that had an annotation, with
// `unchecked:false` beside it reading as approval. `note` is retired rather
// than reused for the other meaning: a consumer pinned to the old format
// would silently misread the same key under a new meaning, which is worse
// than a rename it fails on.
type jsonEnvEntry struct {
	Value      string   `json:"value"`
	ValueBytes byteList `json:"value_bytes,omitempty"`
	Verb       string   `json:"verb"`
	From       []string `json:"from"`
	// AuthoredBy is policy.EnvEntry.Note — see reportEnvEntry.AuthoredBy.
	AuthoredBy string `json:"authored_by"`
	// TypeUnknown is policy.IsUncheckedEnv — see reportEnvEntry.TypeUnknown
	// and policy.UncheckedEnvNote's doc comment for why this key and the
	// screen's `← unchecked` mark are worded differently on purpose.
	TypeUnknown bool `json:"type_unknown"`
	// ValueNote is policy.EnvNote's text — see reportEnvEntry.ValueNote and
	// policy.EnvNote's doc comment.
	ValueNote string `json:"value_note,omitempty"`
	// Grant is envGrantVerdict's code ("", "shadow_slot", "not_granted") —
	// see reportEnvEntry.Grant. Always present, like Verb and From: "" is
	// itself the fact "nothing to say", not an absent key a consumer has to
	// branch on.
	Grant string `json:"grant"`
	// GrantsInside is meaningful only when Grant is "not_granted"; 0 (and
	// present) otherwise.
	GrantsInside int `json:"grants_inside"`
}

type jsonEnvDrop struct {
	Value      string   `json:"value"`
	ValueBytes byteList `json:"value_bytes,omitempty"`
	Reason     string   `json:"reason"`
}

type jsonSeccomp struct {
	Requested     bool     `json:"requested"`
	Installed     bool     `json:"installed"`
	Reason        string   `json:"reason"`
	Error         string   `json:"error"`
	Arch          string   `json:"arch"`
	Denied        []string `json:"denied"`
	CompatArchGap bool     `json:"compat_arch_gap"`
}

type jsonTTY struct {
	NewSession bool `json:"new_session"`
}

// jsonBwrap.Argv[0] is the bare name "bwrap", PREPENDED to Report.BwrapArgv
// (refs #332, the mechanical half). Before this the key named `argv` held only
// the ARGUMENTS — index 0 was "--unshare-user" — so
// `subprocess.run(doc.bwrap.argv)` executed a flag.
//
// It is the bare word and NOT exec.LookPath's resolved path, for the reasons
// reportExec's doc comment measures: snug resolves the name itself, from the
// host user's own $PATH, at the moment the run starts, so no value written
// here can be the binary that runs. `argv0_resolved` and `argv0_note` say that
// rather than leaving a consumer to read the bare word as an answer — a
// resolved path here would also make every golden host-dependent, the trap
// issues #301 and #320 both refused.
type jsonBwrap struct {
	Argv      []string   `json:"argv"`
	ArgvBytes []byteList `json:"argv_bytes,omitempty"`
	// Argv0Resolved is false: Argv[0] names a binary chosen at run time. A
	// field rather than an implied constant, so a consumer branches on the
	// fact and so the day it changes the document says it changed.
	Argv0Resolved bool `json:"argv0_resolved"`
	// Argv0Note is reportExec.Note, the same string the human screen wraps.
	Argv0Note string `json:"argv0_note"`
	// Incomplete is Report.BwrapIncomplete: true when running Argv standalone
	// will NOT reproduce this policy's actual network posture. See Reason,
	// and Report.BwrapIncompleteReason's doc comment for why this must not
	// ship unpaired with the caveat — making the argv look more directly
	// runnable without it is worse than the plain omission it replaces.
	Incomplete bool `json:"incomplete"`
	// Reason is "" when Incomplete is false, and otherwise the same fact
	// describeBwrap prints in capitals on the human screen.
	Reason string `json:"reason,omitempty"`
}

// jsonPasta is the pasta invocation this run's egress actually uses. See
// Report.Pasta's doc comment for the placeholder pid this carries instead of
// a real one, and CLAUDE.md's "never trust a helper's default" for why this
// exists at all: the rest of the document carries snug's CLAIM about the
// network (jsonNetwork.HostLoopback, .AbstractSockets) and this is the
// closing flag set that is supposed to implement it.
//
// Argv[0] is the bare name "pasta", prepended the same way and for the same
// reason as jsonBwrap.Argv[0]: Report.Pasta.Argv holds only the arguments
// (index 0 is "--config-net"), and a key named `argv` should not hold a value
// whose first element is a flag. It carries the same argv0_resolved /
// argv0_note pair, from the same producer, because snug starts pasta the same
// way it starts bwrap — exec.LookPath at run time (internal/sandbox/netns.go:93).
type jsonPasta struct {
	Argv          []string   `json:"argv"`
	ArgvBytes     []byteList `json:"argv_bytes,omitempty"`
	Argv0Resolved bool       `json:"argv0_resolved"`
	Argv0Note     string     `json:"argv0_note"`
	Placeholder   string     `json:"placeholder"`
}

func (e *lossyEncoder) document(rep Report) jsonDoc {
	doc := jsonDoc{
		Snug: jsonMeta{
			Format:   dryRunFormat,
			Outcome:  rep.Outcome,
			ExitCode: rep.ExitCode,
			// A Report only exists where a policy does: buildReport takes a
			// *policy.Policy and dereferences it on its first line. So this
			// renderer's answer is a constant, and the false case lives in
			// renderJSONRefusal, which has no Report at all.
			PolicyResolved: true,
		},
		Profiles: jsonProfiles{
			Selected: policy.NameStrings(rep.Selected),
			Implied:  policy.NameStrings(rep.Implied),
		},
		Network: jsonNetwork{
			Mode:            rep.Network.Mode,
			Egress:          rep.Network.Egress,
			HostLoopback:    rep.Network.HostLoopback,
			AbstractSockets: rep.Network.AbstractSockets,
			DNS:             rep.Network.DNS,
			DNSForwarded:    rep.Network.DNSForwarded,
			DNSHost:         rep.Network.DNSHost,
			Publish:         rep.Network.Publish,
			Anonymised:      rep.Network.Anonymised,
			Address:         rep.Network.Address,
			Address6:        rep.Network.Address6,
		},
		Topology: jsonTopology{
			Processes:             rep.Topology.Processes,
			NeedsStage:            rep.Topology.NeedsStage,
			Netns:                 rep.Topology.Netns,
			Subuid:                rep.Topology.Subuid,
			EngineCapBounding:     rep.Topology.EngineCapBounding,
			ProcfsClosuresSkipped: rep.Topology.ProcfsClosuresSkipped,
			ProcfsClosureNote:     rep.Topology.ProcfsClosureNote,
		},
		Seccomp: jsonSeccomp{
			Requested:     rep.Seccomp.Requested,
			Installed:     rep.Seccomp.Installed,
			Reason:        rep.Seccomp.Reason,
			Error:         rep.Seccomp.Error,
			Arch:          rep.Seccomp.Arch,
			Denied:        rep.Seccomp.Denied,
			CompatArchGap: rep.Seccomp.CompatArchGap,
		},
		TTY: jsonTTY{NewSession: rep.NewSession},
	}
	if rep.Refusal != "" {
		// The message is snug's own text about a policy, but it QUOTES host
		// paths (describeNode renders one in a masking refusal), so it goes
		// through the same encoder as every other host-influenced value.
		msg, _ := e.text(rep.Refusal)
		doc.Refusal = &jsonRefusal{Message: msg}
	}
	doc.Target, doc.TargetBytes = e.text(rep.Target)
	doc.Home, doc.HomeBytes = e.text(rep.Home)
	doc.Chdir, doc.ChdirBytes = e.text(rep.Chdir)

	doc.Mounts = make([]jsonMount, 0, len(rep.Mounts))
	for _, m := range rep.Mounts {
		jm := jsonMount{
			Kind:         m.Kind.String(),
			Access:       m.Access.String(),
			From:         m.From,
			Optional:     m.Optional,
			SnugAuthored: m.Authored,
			// The fact behind the human column's "exec" word: a KindData file
			// with an executable permission bit is CODE, not config (the
			// podman stub is the one case today).
			Executable: m.Perms != nil && *m.Perms&0o111 != 0,
		}
		if m.Kind == policy.KindTmpfs {
			jm.SizeBytes = rep.TmpfsSizeBytes
		}
		if n, ok := rep.MountNotes[m.Guest]; ok {
			jm.Yielded = n.Yielded
			jm.ProcfsReplacement = n.ProcfsReplacement
		}
		jm.Guest, jm.GuestBytes = e.text(m.Guest)
		jm.Host, jm.HostBytes = e.text(m.Host)
		doc.Mounts = append(doc.Mounts, jm)
	}

	doc.EngineView = make([]jsonGraft, 0, len(rep.Grafts))
	for _, g := range rep.Grafts {
		jg := jsonGraft{
			Kind:   g.Kind.String(),
			Access: g.Access.String(),
			Why:    g.Why,
		}
		jg.Guest, jg.GuestBytes = e.text(g.Guest)
		jg.Host, jg.HostBytes = e.text(g.Host)
		jg.HostAsked, jg.HostAskedBytes = e.text(g.HostAsked)
		doc.EngineView = append(doc.EngineView, jg)
	}

	doc.NotGranted.Lines, doc.NotGranted.LinesBytes = e.texts(rep.NotGranted)
	// The bare word, PREPENDED — never exec.LookPath's resolved path. The
	// word itself comes from the producer rather than from a literal here, so
	// the two renderers cannot print different names for the same binary.
	// See jsonBwrap's doc comment and reportExec's.
	bwrapArgv := make([]string, 0, len(rep.BwrapArgv)+1)
	bwrapArgv = append(bwrapArgv, rep.BwrapExec.Argv0)
	bwrapArgv = append(bwrapArgv, rep.BwrapArgv...)
	doc.Bwrap.Argv, doc.Bwrap.ArgvBytes = e.texts(bwrapArgv)
	doc.Bwrap.Argv0Resolved = rep.BwrapExec.Resolved
	doc.Bwrap.Argv0Note = rep.BwrapExec.Note
	doc.Bwrap.Incomplete = rep.BwrapIncomplete
	doc.Bwrap.Reason = rep.BwrapIncompleteReason

	if pa := rep.Pasta; pa != nil {
		pastaArgv := make([]string, 0, len(pa.Argv)+1)
		pastaArgv = append(pastaArgv, pa.Exec.Argv0)
		pastaArgv = append(pastaArgv, pa.Argv...)
		jp := jsonPasta{
			Placeholder:   pa.Placeholder,
			Argv0Resolved: pa.Exec.Resolved,
			Argv0Note:     pa.Exec.Note,
		}
		jp.Argv, jp.ArgvBytes = e.texts(pastaArgv)
		doc.Pasta = &jp
	}

	if c := rep.Containers; c != nil {
		jc := jsonContainers{
			Socket:                    c.Socket,
			EngineSource:              c.EngineSource,
			RegistrySearch:            c.RegistrySearch,
			SignaturesVerified:        c.SignaturesVerified,
			EngineBinaryIsRegularFile: c.EngineBinaryIsRegularFile,
			ToolchainRootIsDir:        c.ToolchainRootIsDir,
			Logins:                    c.Logins,
			PortMapping:               c.PortMapping,
		}
		// Both are environment variables' VALUES — host text, and the reason
		// the human block puts them through visibleValue.
		jc.EngineBinary, jc.EngineBinaryBytes = e.text(c.EngineBinary)
		jc.ToolchainRoot, jc.ToolchainRootBytes = e.text(c.ToolchainRoot)
		jc.SignaturePolicySource, jc.SignaturePolicySourceBytes = e.text(c.SignaturePolicySource)
		jc.SignaturePolicyRefusal, jc.SignaturePolicyRefusalBytes = e.text(c.SignaturePolicyRefusal)
		jc.EngineBinaryRefusal, jc.EngineBinaryRefusalBytes = e.text(c.EngineBinaryRefusal)
		jc.ToolchainRootRefusal, jc.ToolchainRootRefusalBytes = e.text(c.ToolchainRootRefusal)
		jc.EngineBinaryResolved, jc.EngineBinaryResolvedBytes = e.text(c.EngineBinaryResolved)
		jc.ToolchainRootResolved, jc.ToolchainRootResolvedBytes = e.text(c.ToolchainRootResolved)
		doc.Containers = &jc
	}

	for _, v := range rep.Environment {
		jv := jsonEnvVar{Name: v.Name}
		for _, en := range v.Entries {
			je := jsonEnvEntry{
				Verb:         en.Verb,
				From:         en.From,
				AuthoredBy:   en.AuthoredBy,
				TypeUnknown:  en.TypeUnknown,
				ValueNote:    en.ValueNote,
				Grant:        en.Grant,
				GrantsInside: en.GrantsInside,
			}
			je.Value, je.ValueBytes = e.text(en.Value)
			jv.Entries = append(jv.Entries, je)
		}
		for _, d := range v.Dropped {
			jd := jsonEnvDrop{Reason: d.Reason}
			jd.Value, jd.ValueBytes = e.text(d.Value)
			jv.Dropped = append(jv.Dropped, jd)
		}
		doc.Environment = append(doc.Environment, jv)
	}
	return doc
}
