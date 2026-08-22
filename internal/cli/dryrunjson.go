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
// object, never NDJSON, and for EVERY exit code including a refusal.
//
// That last part is the design decision most worth keeping. `snug --dry-run
// --json x > policy.json` must produce a parseable file even when the policy
// was refused; clang's SARIF does the opposite (0 bytes on redirect) and it is
// the failure mode this format is designed against. The human refusal text
// stays on stderr, where it already was.
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

	b, err := json.MarshalIndent(doc, "", "  ")
	if err == nil {
		// After marshalling, ONCE, so it covers every string in the document
		// including the ones a later field adds. See its doc comment for why
		// this is fidelity-preserving and why it does not set lossy.
		b = escapeRawForgingRunes(b)
	}
	if err != nil {
		// Unreachable for this tree — it is strings, bools, ints and slices of
		// those — but reported rather than swallowed: a machine format that
		// half-wrote itself and said nothing is invariant 5's shape.
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
// The name is not `rawForgingRune`: screensinks_test.go already owns that one,
// for the sweep every SCREEN in this package shares. Two predicates, one
// vocabulary — that one asks "did a raw hazard reach a terminal", this one
// asks "did one survive encoding/json".
func jsonRawForgingRune(r rune) bool { return r >= 0x80 && policy.IsForgingRune(r) }

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
}

type jsonMeta struct {
	Format  int    `json:"format"`
	Outcome string `json:"outcome"`
	Lossy   bool   `json:"lossy"`
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
}

type jsonContainers struct {
	Socket             string   `json:"socket"`
	EngineSource       string   `json:"engine_source"`
	EngineBinary       string   `json:"engine_binary"`
	EngineBinaryBytes  byteList `json:"engine_binary_bytes,omitempty"`
	BundleRoot         string   `json:"bundle_root"`
	BundleRootBytes    byteList `json:"bundle_root_bytes,omitempty"`
	RegistrySearch     []string `json:"registry_search"`
	SignaturesVerified bool     `json:"signatures_verified"`
	Logins             bool     `json:"logins"`
	PortMapping        bool     `json:"port_mapping"`
}

type jsonEnvVar struct {
	Name    string         `json:"name"`
	Entries []jsonEnvEntry `json:"entries"`
	// Dropped elements are NAMED, not counted, for the same reason the human
	// block names them: "1 of 3 kept" does not let anyone check a filter.
	Dropped []jsonEnvDrop `json:"dropped,omitempty"`
}

type jsonEnvEntry struct {
	Value      string   `json:"value"`
	ValueBytes byteList `json:"value_bytes,omitempty"`
	Verb       string   `json:"verb"`
	From       []string `json:"from"`
	Note       string   `json:"note"`
	Unchecked  bool     `json:"unchecked"`
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

type jsonBwrap struct {
	Argv      []string   `json:"argv"`
	ArgvBytes []byteList `json:"argv_bytes,omitempty"`
}

func (e *lossyEncoder) document(rep Report) jsonDoc {
	doc := jsonDoc{
		Snug: jsonMeta{Format: dryRunFormat, Outcome: rep.Outcome},
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
			Processes:         rep.Topology.Processes,
			NeedsStage:        rep.Topology.NeedsStage,
			Netns:             rep.Topology.Netns,
			Subuid:            rep.Topology.Subuid,
			EngineCapBounding: rep.Topology.EngineCapBounding,
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
	doc.Bwrap.Argv, doc.Bwrap.ArgvBytes = e.texts(rep.BwrapArgv)

	if c := rep.Containers; c != nil {
		jc := jsonContainers{
			Socket:             c.Socket,
			EngineSource:       c.EngineSource,
			RegistrySearch:     c.RegistrySearch,
			SignaturesVerified: c.SignaturesVerified,
			Logins:             c.Logins,
			PortMapping:        c.PortMapping,
		}
		// Both are environment variables' VALUES — host text, and the reason
		// the human block puts them through visibleValue.
		jc.EngineBinary, jc.EngineBinaryBytes = e.text(c.EngineBinary)
		jc.BundleRoot, jc.BundleRootBytes = e.text(c.BundleRoot)
		doc.Containers = &jc
	}

	for _, v := range rep.Environment {
		jv := jsonEnvVar{Name: v.Name}
		for _, en := range v.Entries {
			je := jsonEnvEntry{Verb: en.Verb, From: en.From, Note: en.Note, Unchecked: en.Unchecked}
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
