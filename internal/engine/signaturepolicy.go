package engine

// signaturepolicy.go projects the HOST's container signature policy into the
// one this run's engine reads.
//
// podman resolves a signature policy from three paths in order —
// $XDG_CONFIG_HOME (or $HOME/.config) /containers/policy.json,
// /etc/containers/policy.json, /usr/share/containers/policy.json — measured on
// 6.0.2 and pinned by hostSignaturePolicyPaths, whose comment carries the
// measurement. It is the one file it REQUIRES — no
// policy, no pull — and the one with no lever but the home directory: MEASURED
// on podman 5.8.4, `--signature-policy` exists as a HIDDEN flag on `pull` and
// `push` and on neither `system service` nor the global command, so it cannot
// reach the API-driven pull the container proxy makes. A home of snug's own is
// the whole mechanism.
//
// The generated file is a PROJECTION of the host's, not a replacement for it.
// A sandbox that accepts any image on a host configured to demand a signature
// is snug deciding, on the host user's behalf, that verification does not apply
// here — invariant 5, a guarantee dropped without saying so.
//
// THREE CLAUSES, and the third is the one to grep for:
//
//  1. A requirement snug can project faithfully is projected. Key material a
//     requirement names is copied into this run's config directory and the
//     emitted path is the copy's, because the engine resolves paths in its
//     DERIVED view and a host path resolves to nothing there.
//  2. A requirement snug cannot project REFUSES the run, naming the requirement
//     and the path. Not a warning, not a downgrade of that one requirement.
//  3. There is no fallback to insecureAcceptAnything. One function builds that
//     requirement out of nothing — hostConfiguredNoSignaturePolicy, for a host
//     that configured no policy at all — and the generated file says so, because
//     "your host has no policy.json" is a different sentence from "snug decided
//     not to verify".
//
// SNUG MODELS THIS SCHEMA BY HAND. go.mod has two dependencies and
// containers/image will never be one of them, so every spelling below is
// transcribed rather than compiled against. Strict decoding is what makes that
// safe in one direction: a field snug has not heard of REFUSES, so a schema
// that grows cannot be silently half-read. It buys nothing in the other — a
// field whose MEANING changed under a name snug already knows reads as before —
// which is the argument for keeping the projected set small and for refusing
// sigstoreSigned outright (see projectRequirement).
//
// THE EMITTER ADDS NO FIELD THE HOST DID NOT WRITE. containers/image defaults
// an absent signedIdentity to matchRepoDigestOrExact, so writing one in would
// be snug choosing a match rule; and a keyType snug synthesised would be snug
// choosing a trust root. Both are checkable, and
// TestTheEmitterAddsNoFieldTheHostDidNotWrite checks them.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// The five requirement types containers/image defines. All five are named, the
// three snug does not project included, so a refusal can say WHICH one rather
// than "a type snug does not know" — and so this list reads as the complete
// enumeration it is.
const (
	reqAcceptAnything  = "insecureAcceptAnything"
	reqReject          = "reject"
	reqSignedBy        = "signedBy"
	reqSignedBaseLayer = "signedBaseLayer"
	reqSigstoreSigned  = "sigstoreSigned"
)

// signedByKeyTypes are the four values containers/image accepts for signedBy's
// keyType. All four take the identical keyPath/keyPaths/keyData shape, so all
// four are equally projectable and the value is carried VERBATIM.
//
// The rule this comes from, because it is what keeps the allowlist small: snug's
// allowlist is about what SNUG must understand — is this field a host path,
// inline data, or an opaque string? — not about what containers/image will do
// with it. An opaque enum is carried and validated against a closed set. Only a
// PATH obliges snug to act. A fifth value added upstream refuses here, which is
// the fail-closed direction.
var signedByKeyTypes = map[string]bool{
	"GPGKeys":          true,
	"signedByGPGKeys":  true,
	"X509Certificates": true,
	"signedByX509CAs":  true,
}

// identityMatchFields is containers/image's policyReferenceMatch: which image a
// signature is accepted FOR. Keyed by type, valued by the EXACT field set that
// type admits, because upstream decodes each arm with exact fields — a
// dockerReference inside a matchExact is a file podman rejects, and snug must
// not be looser than the thing it projects for.
//
// None of these fields is a path.
var identityMatchFields = map[string][]string{
	"matchExact":             nil,
	"matchRepoDigestOrExact": nil,
	"matchRepository":        nil,
	"exactReference":         {"dockerReference"},
	"exactRepository":        {"dockerRepository"},
	"remapIdentity":          {"prefix", "signedPrefix"},
}

// scopedTransports are the transports whose non-empty policy scope is a
// REGISTRY-SHAPED string rather than a host path.
//
// This is the projection's own downgrade hazard, and it is not hypothetical.
// A scope for the `dir`, `oci`, `docker-archive` and `containers-storage`
// transports is a filesystem path — upstream validates it as one — and a host
// rule like `"dir": {"/mnt/untrusted": [{"type":"reject"}]}` carried verbatim
// into the engine's DERIVED view names a path that does not exist there. The
// scope never matches, the image falls through to `default`, and a rule
// stricter than the default has been dropped by the projection itself.
//
// So a non-empty scope is projected for these three and refused for everything
// else. The empty scope is projectable for ANY transport — it names nothing —
// which is what keeps the shape Fedora and RHEL actually ship
// (`"docker-daemon": {"": [...]}`) working.
var scopedTransports = map[string]bool{
	"docker":        true, // registry / namespace / repository / repository:tag
	"atomic":        true, // the same, for the atomic transport
	"docker-daemon": true, // algo:digest
}

// maxSignaturePolicyBytes bounds the host policy read. A signature policy is a
// small hand-written JSON document — podman's own shipped default is 256 bytes.
// The cap makes the read finite; over it the run refuses rather than treating
// the file as absent.
const maxSignaturePolicyBytes = 1 << 20

// maxSignatureKeyBytes bounds ONE projected key, and maxSignatureKeyTotalBytes
// the whole set. An ASCII-armoured public key is a few KiB and a small keyring a
// few tens; the per-file cap is headroom, and the total is what stops a host
// policy naming a hundred large keyrings from being an allocation primitive in
// snug's own process.
const (
	maxSignatureKeyBytes      = 8 << 20
	maxSignatureKeyTotalBytes = 32 << 20
)

// SignatureKeyDir is the subdirectory of this run's config directory that
// projected key material lands in. Named here because two places need it — the
// projection that writes into it and the test that reads it back — and a second
// literal would agree with the first until somebody changed one.
const SignatureKeyDir = "sigkeys"

// hostSignaturePolicyPaths are the THREE files containers/image reads a
// signature policy from, in order. MEASURED on podman 6.0.2 by hiding
// /usr/share/containers behind a bind mount inside `unshare -U -r -m` and
// letting podman print its own list:
//
//	Error: config file not found: no policy.json file found; searched paths:
//	  ["<config>/containers/policy.json" "/etc/containers/policy.json"
//	   "/usr/share/containers/policy.json"]
//
// THE THIRD PATH IS NOT OPTIONAL, and reading only the first two was a live
// defect on every distribution that ships a default there — openSUSE does, and
// so this machine did. snug read neither of its two, concluded "the host
// configured no policy", and generated an accept-anything one, while --dry-run
// told the human "this host has no policy.json where podman looks, so a podman
// here refuses every pull outright". Both halves false: podman looks at
// /usr/share, and a pull on that host SUCCEEDS (measured,
// `podman pull docker.io/library/alpine:3.20` with an empty home). Invariant 7
// is that snug interprets the host's configuration rather than substituting its
// own, and a search path snug does not know about is that invariant failing
// quietly.
//
// The comment this replaced said podman "does not look at it" and cited 5.8.4.
// That was true of 5.8.4 and is false of the 6.x snug supports — which is the
// whole hazard of a version-shaped fact: nothing turns red when the version
// moves. The list above is quoted from the binary rather than from memory for
// that reason, and re-measuring it is how it stays true.
//
// xdgConfigHome COMES FIRST WHERE IT IS SET, because containers/image resolves
// the per-user file under $XDG_CONFIG_HOME and only falls back to
// $HOME/.config. Measured on 6.0.2: with XDG_CONFIG_HOME=<dir>, podman's own
// list names <dir>/containers/policy.json; with it unset, $HOME/.config. Where
// the two diverge, reading HOME would project a file podman never loads and
// miss the one it does.
//
// home AND xdgConfigHome ARE PARAMETERS, and that is not a convenience.
// os.Getenv("HOME") with $HOME unset makes filepath.Join produce a RELATIVE
// path, resolved against snug's own working directory — so `snug` run inside a
// checked-out repo that ships .config/containers/policy.json would read that
// repo's file as the host's, which is invariant 3 with the repo choosing which
// host paths snug then copies. A signedBy requirement carries keyPaths, so the
// repo would also be choosing which host files snug reads key material out of.
//
// BE PRECISE ABOUT WHY policy.Policy.Home IS SAFE HERE, because the obvious
// reason is the wrong one: Resolve refuses an EMPTY home, not a relative one.
// What refuses a relative one is @home's own environ.set validation, and every
// path to a container profile includes @home — measured, `HOME=. snug --dry-run
// --no-defaults -p @sys …` refuses. The guarantee holds through a profile rather
// than through Resolve, so a future profile set reaching this code without
// @home would need its own check.
//
// A RELATIVE xdgConfigHome HAS NO SUCH GUARANTEE BEHIND IT and is refused here
// rather than ignored. Falling back to $HOME/.config would read a different
// file than podman, which is invariant 5: the sandbox would enforce a posture
// its own screen does not describe.
func hostSignaturePolicyPaths(home, xdgConfigHome string) ([]string, error) {
	perUser := filepath.Join(home, ".config", "containers", "policy.json")
	if xdgConfigHome != "" {
		if !filepath.IsAbs(xdgConfigHome) {
			return nil, fmt.Errorf("XDG_CONFIG_HOME is %s, which is not an absolute path.\n"+
				"       podman resolves the signature policy under it, and snug will not guess "+
				"what a relative one names from here — reading a different file than the engine "+
				"does would make the sandbox enforce a posture this run cannot describe.\n"+
				"       Fix: set XDG_CONFIG_HOME to an absolute path, or unset it so "+
				"$HOME/.config is used.", policy.VisibleText(xdgConfigHome))
		}
		perUser = filepath.Join(xdgConfigHome, "containers", "policy.json")
	}
	return []string{
		perUser,
		systemSignaturePolicyPath,
		usrShareSignaturePolicyPath,
	}, nil
}

// systemSignaturePolicyPath and usrShareSignaturePolicyPath are the second and
// third candidates, variables only so a test can point them somewhere that does
// not exist — otherwise this package's verdict would depend on whether the
// machine running it has one, and on this machine it does. There is no other
// writer.
var systemSignaturePolicyPath = "/etc/containers/policy.json"

var usrShareSignaturePolicyPath = "/usr/share/containers/policy.json"

// hostPolicyDoc is the decoded host file: the two top-level keys
// containers/image defines and nothing else.
//
// Requirements stay raw at this level because a requirement is a UNION — its
// keys depend on its `type` — and one struct covering every arm would make
// DisallowUnknownFields accept a sigstore key inside a signedBy. They are
// decoded a second time, strictly, per arm.
type hostPolicyDoc struct {
	Default    []json.RawMessage                       `json:"default"`
	Transports map[string]map[string][]json.RawMessage `json:"transports"`
}

// requirement is one PROJECTED requirement, held as understood fields rather
// than as the host's own bytes. Re-emitting the bytes would carry through
// whatever the decoder did not look at, which is the failure strict decoding
// exists to prevent.
//
// KeyPath and KeyPaths hold HOST paths here; render substitutes the guest path
// of the copy, the only form the engine can resolve. Exactly one of KeyPath,
// KeyPaths and KeyData is set, because upstream admits exactly one.
type requirement struct {
	Type string

	KeyType string
	// POINTERS, carrying PRESENCE rather than a value. Exactly one of the three
	// is non-nil for a signedBy, because upstream admits exactly one and keys
	// that rule off presence — `"keyData": ""` is present. render emits the same
	// way; see its own note for the file this distinction breaks when it is
	// collapsed to emptiness.
	KeyPath  *string
	KeyPaths *[]string
	KeyData  *string

	SignedIdentity *identityMatch
}

// identityMatch carries the union of every policyReferenceMatch field. Which
// ones may be present for a given Type is identityMatchFields' answer, checked
// at decode; the struct is a union only so one decoder can read them all.
type identityMatch struct {
	Type             string `json:"type"`
	DockerReference  string `json:"dockerReference,omitempty"`
	DockerRepository string `json:"dockerRepository,omitempty"`
	Prefix           string `json:"prefix,omitempty"`
	SignedPrefix     string `json:"signedPrefix,omitempty"`
}

// projectedKey is one key file the policy names, read at projection time.
//
// The BYTES are read here rather than at write time, so that --dry-run asks the
// same question a run asks and gets the same answer. A keyPath that is a FIFO
// must refuse on both paths or the two disagree about whether the run can
// start, which is the divergence --dry-run exists to not have.
type projectedKey struct {
	Host string
	Data []byte
}

// SignaturePolicy is one host policy.json, read and projected. Everything that
// can refuse has already refused by the time a value of this type exists.
//
// Source is the host file it came from, empty when this host configured none.
type SignaturePolicy struct {
	Source     string
	Default    []requirement
	Transports map[string]map[string][]requirement
	Keys       []projectedKey
}

// SignaturePolicySummary is what a screen needs from the projection: which host
// file authors the engine's signature policy, whether that policy demands
// anything of an image, and whether a real run will refuse.
//
// Refusal is CARRIED rather than returned so --dry-run can state it as a fact
// about this run beside the other image-provenance facts. A dry run that
// omitted it would describe a run that cannot start.
type SignaturePolicySummary struct {
	Source   string
	Verified bool
	Refusal  error
}

// SummariseSignaturePolicy answers the projection's questions for a screen. It
// reads the host's policy and every key it names, and writes nothing.
func SummariseSignaturePolicy(home, xdgConfigHome string) SignaturePolicySummary {
	sp, err := ProjectHostSignaturePolicy(home, xdgConfigHome)
	if err != nil {
		return SignaturePolicySummary{Refusal: err}
	}
	return SignaturePolicySummary{Source: sp.Source, Verified: sp.demandsSomething()}
}

// ProjectHostSignaturePolicy reads this host's signature policy and projects
// it, or refuses. It creates nothing: the caller runs it before engine.New, so
// that a refusal leaves no run directory behind.
//
// ABSENCE IS THE ONLY SILENT CASE, and it is not a downgrade: a host that
// configured no policy configured nothing to preserve. Every other failure to
// read — a FIFO, a directory, a file over the cap, a file that exists but this
// user may not read — REFUSES. hostread.Optional would fold that last one into
// absence, which is exactly the shape this ticket exists to remove: snug cannot
// say "your host configured nothing" about a file it was not allowed to open.
//
// A path that is a symlink to something absent gives ENOENT and falls through to
// the system file, which is what podman does too — the existence check upstream
// makes is on the resolved file. Deliberate; do not "fix" it into a refusal.
func ProjectHostSignaturePolicy(home, xdgConfigHome string) (*SignaturePolicy, error) {
	if home == "" {
		return nil, errors.New("the container signature policy cannot be projected: this " +
			"policy has no home directory, so snug does not know where to read the host's " +
			"policy.json from. This is a snug bug, not a host misconfiguration")
	}
	paths, err := hostSignaturePolicyPaths(home, xdgConfigHome)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		// hostread.Required rather than os.ReadFile: a FIFO at this path would
		// hang the run in open(2) with nothing on any screen, and a symlink to
		// /dev/zero would read until memory ran out (issue #337).
		raw, err := hostread.Required(path, maxSignaturePolicyBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("snug cannot read the container signature policy this host "+
				"configured (%s).\n"+
				"       The engine's policy.json is a PROJECTION of that file, so a policy snug "+
				"cannot read is a posture snug cannot reproduce — and generating a permissive "+
				"one instead would silently drop whatever it says (CLAUDE.md invariant 5).\n"+
				"       Fix: make %s readable, or remove it if it is not the policy you meant.",
				policy.VisibleText(err.Error()), policy.VisibleText(path))
		}
		sp, err := projectSignaturePolicy(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", policy.VisibleText(path), err)
		}
		sp.Source = path
		if err := sp.readKeys(); err != nil {
			return nil, err
		}
		return sp, nil
	}
	return hostConfiguredNoSignaturePolicy(), nil
}

// hostConfiguredNoSignaturePolicy is the ONE site in this package that builds an
// accept-anything requirement without a host requirement to carry, and it is a
// function taking no arguments so that clause 3 is checkable by name: a code
// path that HAD host bytes and gave up cannot reach it, and
// TestNothingFallsBackToAcceptAnything counts constructions.
//
// It is not a fallback in the sense clause 3 forbids: there is no host posture
// here to preserve, so nothing the host configured is being weakened.
//
// BUT IT IS A DECISION SNUG MADE, and saying otherwise would be the screen
// claiming a property nobody checked. MEASURED, pinned podman 5.8.4 with no
// policy.json in either place: `Error: no policy.json file found at any of the
// following: …`. A stock podman there pulls NOTHING. snug makes every pull
// succeed, so the sandbox is more permissive than the bare host — the trade
// being that a host-dependent total failure is not one a sandbox should
// inherit. The sidecar and --dry-run both say so in those words.
//
// An empty requirement list is not the alternative: containers/image refuses
// one outright ("List of verification policy requirements must not be empty").
func hostConfiguredNoSignaturePolicy() *SignaturePolicy {
	return &SignaturePolicy{Default: []requirement{{Type: reqAcceptAnything}}}
}

// projectSignaturePolicy is the projection proper, separated from the read so a
// test can feed it a document without a host.
func projectSignaturePolicy(raw []byte) (*SignaturePolicy, error) {
	// BEFORE anything is decoded: a duplicate key changes what the document
	// means to Go and makes it unloadable to podman, so neither half of the
	// projection can be trusted about a file that has one.
	if err := refuseDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("snug will not project it: %w", err)
	}
	var doc hostPolicyDoc
	if err := strictDecode(raw, &doc); err != nil {
		return nil, fmt.Errorf("snug cannot parse it (%s), so it cannot reproduce what it "+
			"requires.\n"+
			"       Fix: correct the file, or remove it if it is not the policy you meant",
			policy.VisibleText(err.Error()))
	}
	// Upstream: "Default policy is missing". A file podman refuses is not one
	// snug should project, and being looser than the thing being projected for
	// is how a projection stops being one.
	if doc.Default == nil {
		return nil, errors.New(`it has no "default" requirement list, which containers/image ` +
			`refuses outright ("Default policy is missing"). snug will not project a file podman ` +
			`itself would not load`)
	}

	out := &SignaturePolicy{}
	seen := map[string]bool{}
	var keyOrder []string
	addKey := func(host string) {
		if !seen[host] {
			seen[host] = true
			keyOrder = append(keyOrder, host)
		}
	}

	var err error
	out.Default, err = projectRequirements(doc.Default, "the default requirement", addKey)
	if err != nil {
		return nil, err
	}
	if len(doc.Transports) > 0 {
		out.Transports = map[string]map[string][]requirement{}
	}
	for _, transport := range sortedKeys(doc.Transports) {
		scopes := map[string][]requirement{}
		for _, scope := range sortedKeys(doc.Transports[transport]) {
			if err := checkScope(transport, scope); err != nil {
				return nil, err
			}
			where := fmt.Sprintf("transport %q, scope %q",
				policy.VisibleText(transport), policy.VisibleText(scope))
			reqs, err := projectRequirements(doc.Transports[transport][scope], where, addKey)
			if err != nil {
				return nil, err
			}
			scopes[scope] = reqs
		}
		out.Transports[transport] = scopes
	}
	for _, host := range keyOrder {
		out.Keys = append(out.Keys, projectedKey{Host: host})
	}
	return out, nil
}

// checkScope refuses a scope whose meaning inside the engine's derived mount
// view is not the meaning it has on the host. See scopedTransports.
func checkScope(transport, scope string) error {
	if scope == "" {
		return nil
	}
	if !scopedTransports[transport] {
		return fmt.Errorf("transport %q has the scope %q, which snug does not project.\n"+
			"       A scope for this transport is a HOST PATH, and the engine's mount view is "+
			"derived from the sandbox's — the same string names something else there, or "+
			"nothing, so the rule would never match and the image would fall through to the "+
			"default. Carrying it would be the projection itself dropping a rule stricter than "+
			"the default.\n"+
			"       Fix: express the rule against the docker transport, or select no container "+
			"profile.", policy.VisibleText(transport), policy.VisibleText(scope))
	}
	// docker and atomic scopes are registry-shaped; a leading slash means the
	// file means something this code does not.
	if transport != "docker-daemon" && strings.HasPrefix(scope, "/") {
		return fmt.Errorf("transport %q has the scope %q, which begins with '/'. A scope for "+
			"this transport is a registry, namespace or repository, never a path, so snug "+
			"cannot tell what this rule means and will not guess",
			policy.VisibleText(transport), policy.VisibleText(scope))
	}
	return nil
}

// projectRequirements walks one requirement list. where names the position in
// the file, because an error saying only "sigstoreSigned is not projected"
// leaves a human searching a policy.json for which of four it meant.
func projectRequirements(raws []json.RawMessage, where string, addKey func(string)) ([]requirement, error) {
	// Upstream: "List of verification policy requirements must not be empty".
	if len(raws) == 0 {
		return nil, fmt.Errorf("%s is an empty list, which containers/image refuses outright. "+
			"snug will not project a file podman itself would not load", where)
	}
	out := make([]requirement, 0, len(raws))
	for i, raw := range raws {
		at := where
		if len(raws) > 1 {
			at = where + " #" + strconv.Itoa(i+1)
		}
		req, err := projectRequirement(raw, at, addKey)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, nil
}

func projectRequirement(raw []byte, at string, addKey func(string)) (requirement, error) {
	var kind struct {
		Type string `json:"type"`
	}
	// Not strict: this pass only learns which arm to decode strictly below.
	if err := json.Unmarshal(raw, &kind); err != nil {
		return requirement{}, fmt.Errorf("%s is not a JSON object snug can read (%s)",
			at, policy.VisibleText(err.Error()))
	}

	switch kind.Type {
	case reqAcceptAnything, reqReject:
		// Names nothing outside the file. Decoded strictly anyway: a key beside
		// `type` in a requirement that admits none is a file this code does not
		// understand.
		var r struct {
			Type string `json:"type"`
		}
		if err := strictDecode(raw, &r); err != nil {
			return requirement{}, fmt.Errorf("%s (%s) carries something snug does not "+
				"understand (%s).\n"+
				"       snug reproduces this file rather than reading past it, so a key it "+
				"cannot account for is a refusal",
				at, kind.Type, policy.VisibleText(err.Error()))
		}
		return requirement{Type: kind.Type}, nil

	case reqSignedBy:
		return projectSignedBy(raw, at, addKey)

	case reqSigstoreSigned:
		// THE REASON MATTERS, because a comment carrying a false one is how the
		// wrong thing gets "fixed" later. sigstoreSigned reaches NO service:
		// Fulcio is caPath/caData plus an issuer and a subject, Rekor is a
		// public key, PKI is a CA roots file — every one an offline check
		// against a local file or inline base64. It is refused because snug
		// transcribes this schema by hand and this requirement is the one that
		// has grown: four independent trust-root families (key, Fulcio, Rekor,
		// PKI), each with Path/Paths/Data/Datas spellings, across podman 4, 5
		// and 6. A field snug has never heard of refuses, which is safe; a field
		// whose MEANING changed under a name snug already knows does not, and
		// that is the failure no strictness here can detect.
		return requirement{}, fmt.Errorf("%s is %q, which snug does not project.\n"+
			"       snug models the signature-policy schema by hand rather than linking "+
			"containers/image, and this requirement's trust roots (key, Fulcio, Rekor, PKI) "+
			"span four field families that have changed across podman releases. Reproducing it "+
			"from a transcription would be claiming a verification snug cannot check it "+
			"performs.\n"+
			"       Fix: express the scope with a signedBy requirement, or select no container "+
			"profile.", at, reqSigstoreSigned)

	case reqSignedBaseLayer:
		return requirement{}, fmt.Errorf("%s is %q, which snug does not project.\n"+
			"       containers/image accepts the requirement and enforces nothing for it "+
			"(base-layer verification is unimplemented upstream), so snug cannot tell what "+
			"reproducing it would mean.\n"+
			"       Fix: express the scope with insecureAcceptAnything, reject or signedBy.",
			at, reqSignedBaseLayer)

	case "":
		return requirement{}, fmt.Errorf("%s has no \"type\", so snug cannot tell what it "+
			"requires", at)

	default:
		return requirement{}, fmt.Errorf("%s is %q, a requirement type snug does not know.\n"+
			"       snug reproduces your host's signature policy rather than approximating it, "+
			"so a type it cannot reproduce is a refusal — accepting the image instead would "+
			"drop exactly the check you configured (CLAUDE.md invariant 5).\n"+
			"       Fix: express the scope with insecureAcceptAnything, reject or signedBy, or "+
			"select no container profile.", at, policy.VisibleText(kind.Type))
	}
}

// projectSignedBy is the one arm that names host artifacts.
//
// KEYS ARE DATA, NOT A COMMAND TABLE. A GPG public key or an X.509 CA root names
// no program and carries no credential — the care it needs is availability (the
// engine must be able to open it in its own view), not execution. That is why it
// is COPIED rather than refused, and why the copy is the whole of the
// projection.
func projectSignedBy(raw []byte, at string, addKey func(string)) (requirement, error) {
	// Pointers, so that "absent" and "present but empty" stay distinguishable:
	// upstream keys its exactly-one rule off PRESENCE, and `"keyData": ""` is
	// present. Collapsing the two here would accept a file podman refuses.
	var r struct {
		Type           string          `json:"type"`
		KeyType        *string         `json:"keyType"`
		KeyPath        *string         `json:"keyPath"`
		KeyPaths       *[]string       `json:"keyPaths"`
		KeyData        *string         `json:"keyData"`
		SignedIdentity json.RawMessage `json:"signedIdentity"`
	}
	if err := strictDecode(raw, &r); err != nil {
		return requirement{}, fmt.Errorf("%s (signedBy) carries something snug does not "+
			"understand (%s).\n"+
			"       snug reproduces this file rather than reading past it, so a key it cannot "+
			"account for is a refusal", at, policy.VisibleText(err.Error()))
	}

	// Upstream requires keyType and validates it; sbKeyType("").IsValid() is
	// false. snug neither accepts an absent one nor invents a value for it —
	// synthesising "GPGKeys" would be snug choosing a trust root.
	if r.KeyType == nil {
		return requirement{}, fmt.Errorf("%s (signedBy) has no keyType, which containers/image "+
			"requires. snug will not choose one for you: a keyType names the kind of trust root "+
			"the signature is checked against", at)
	}
	if !signedByKeyTypes[*r.KeyType] {
		return requirement{}, fmt.Errorf("%s has keyType %q, which is not one of the four "+
			"containers/image defines (GPGKeys, signedByGPGKeys, X509Certificates, "+
			"signedByX509CAs)", at, policy.VisibleText(*r.KeyType))
	}

	// Upstream: "Exactly one of keyPath, keyPaths and keyData must be
	// specified". Two of them is a file podman refuses, and snug re-emitting
	// both would produce a policy.json the engine then rejects at every pull.
	present := 0
	for _, ok := range []bool{r.KeyPath != nil, r.KeyPaths != nil, r.KeyData != nil} {
		if ok {
			present++
		}
	}
	if present != 1 {
		return requirement{}, fmt.Errorf("%s (signedBy) names %d of keyPath, keyPaths and "+
			"keyData; containers/image requires exactly one. %s", at, present,
			map[bool]string{true: "There is nothing for snug to project.",
				false: "snug will not choose between them."}[present == 0])
	}

	out := requirement{Type: reqSignedBy, KeyType: *r.KeyType}
	switch {
	case r.KeyPath != nil:
		out.KeyPath = r.KeyPath
		addKey(*r.KeyPath)
	case r.KeyPaths != nil:
		out.KeyPaths = r.KeyPaths
		for _, p := range *r.KeyPaths {
			addKey(p)
		}
	default:
		out.KeyData = r.KeyData
	}

	if r.SignedIdentity != nil {
		si, err := projectIdentityMatch(r.SignedIdentity, at)
		if err != nil {
			return requirement{}, err
		}
		out.SignedIdentity = si
	}
	return out, nil
}

// projectIdentityMatch decodes one signedIdentity against the EXACT field set
// its type admits.
//
// An identity match decides WHICH image a signature is accepted for, so a field
// snug dropped would widen the requirement rather than reproduce it, and a field
// snug carried that the type does not admit would produce a file the engine
// rejects. Both are refusals.
func projectIdentityMatch(raw json.RawMessage, at string) (*identityMatch, error) {
	var kind struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return nil, fmt.Errorf("%s has a signedIdentity snug cannot read (%s)",
			at, policy.VisibleText(err.Error()))
	}
	fields, known := identityMatchFields[kind.Type]
	if !known {
		return nil, fmt.Errorf("%s has a signedIdentity of type %q, which snug does not know.\n"+
			"       An identity match decides WHICH image a signature is accepted for, so "+
			"carrying one snug cannot read would widen the requirement rather than reproduce it.",
			at, policy.VisibleText(kind.Type))
	}

	// Decode loosely first, then assert the exact field set — the struct is a
	// union across all six types, so DisallowUnknownFields alone would let
	// exactReference's field through on a matchExact.
	var raw2 map[string]json.RawMessage
	if err := json.Unmarshal(raw, &raw2); err != nil {
		return nil, fmt.Errorf("%s has a signedIdentity snug cannot read (%s)",
			at, policy.VisibleText(err.Error()))
	}
	allowed := map[string]bool{"type": true}
	for _, f := range fields {
		allowed[f] = true
	}
	for _, k := range sortedKeys(raw2) {
		if !allowed[k] {
			return nil, fmt.Errorf("%s has a signedIdentity of type %q carrying the field %q, "+
				"which that type does not admit — containers/image decodes each match type with "+
				"an exact field set and refuses this", at, kind.Type, policy.VisibleText(k))
		}
	}
	for _, f := range fields {
		if _, ok := raw2[f]; !ok {
			return nil, fmt.Errorf("%s has a signedIdentity of type %q with no %q, which that "+
				"type requires", at, kind.Type, f)
		}
	}

	var m identityMatch
	if err := strictDecode(raw, &m); err != nil {
		return nil, fmt.Errorf("%s has a signedIdentity snug cannot read (%s)",
			at, policy.VisibleText(err.Error()))
	}
	return &m, nil
}

// refuseDuplicateKeys walks the whole raw document and refuses a repeated key at
// any object level.
//
// encoding/json takes the LAST duplicate silently; containers/image's
// ParanoidUnmarshalJSONObject treats one as fatal. Without this snug accepts,
// and re-authors, a file podman refuses to load — and picks the later value.
// MEASURED: a host file spelling `"default"` twice, first `reject` and then
// `insecureAcceptAnything`, made podman refuse every pull on the host while
// snug generated a policy that accepted every image. That is the only input
// found where the sandbox ends up materially MORE permissive than the posture
// the host configured, and it is the projection producing it.
//
// DisallowUnknownFields cannot see this: both keys are known. It has to be a
// token walk over the bytes.
// ONLY A DUPLICATE KEY is reported. A malformed document makes the token walk
// fail too, and reporting that here would replace strictDecode's "snug cannot
// parse it (…), so it cannot reproduce what it requires" — which names the fix —
// with a raw scanner error. Every other failure falls through to the decoder
// that has a message for it.
func refuseDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var dup *duplicateKeyError
	if err := walkDistinctKeys(dec, ""); errors.As(err, &dup) {
		return dup
	}
	return nil
}

// duplicateKeyError is the one failure the token walk owns.
type duplicateKeyError struct{ key, at string }

func (e *duplicateKeyError) Error() string {
	return fmt.Sprintf("the key %q appears twice in the same object (at %s).\n"+
		"       containers/image refuses a duplicate key outright, so this is a file podman "+
		"itself will not load — and snug will not reproduce it either, because Go's JSON "+
		"decoder would silently keep the LAST value and the file would then mean something "+
		"its author cannot see by reading it",
		policy.VisibleText(e.key), policy.VisibleText(e.at))
}

// walkDistinctKeys consumes exactly one JSON value from dec. where names the
// position for the error, because a policy.json with four transports repeats a
// key somewhere the reader has to be told about.
func walkDistinctKeys(dec *json.Decoder, where string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar: nothing below it
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("a JSON object key that is not a string")
			}
			at := key
			if where != "" {
				at = where + "." + key
			}
			if seen[key] {
				return &duplicateKeyError{key: key, at: at}
			}
			seen[key] = true
			if err := walkDistinctKeys(dec, at); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkDistinctKeys(dec, where+"[]"); err != nil {
				return err
			}
		}
	}
	// The closing delimiter.
	_, err = dec.Token()
	return err
}

// strictDecode decodes one JSON object into v, refusing an unknown key and a
// second value after the first.
func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing content after the JSON value")
	}
	return nil
}

// sortedKeys is what keeps the generated file byte-identical across runs. Go
// randomises map iteration, and a generated artifact that differs run to run is
// one no golden test and no human diff can hold.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keyFileName is the name a projected key gets inside SignatureKeyDir.
//
// Positional, not derived from the host path. A basename would collide the
// moment two requirements name key.gpg in different directories, and a hash
// would put a value snug did not choose into a path snug writes. The index is
// the position in SignaturePolicy.Keys, which is stable because that list is
// built in document order.
func keyFileName(i int) string { return strconv.Itoa(i) + ".key" }

// readKeys reads every key the policy names, in document order.
//
// Each is read with the same discipline as the policy itself: bounded,
// non-blocking, regular files only. hostread's open-then-fstat sequence is the
// whole check — it refuses a FIFO, a device and a directory by mode on the
// descriptor it actually opened. There is deliberately NO symlink rule: this is
// a copy, so the destination's bytes are already in snug's memory and cannot be
// re-pointed afterwards, and /etc/pki/rpm-gpg is a symlink farm on several
// distributions.
//
// A key that is absent, a FIFO, a directory or over the cap REFUSES — clause 2,
// and the error names the key and the fix. The key's CONTENT is never echoed.
func (sp *SignaturePolicy) readKeys() error {
	var total int64
	for i := range sp.Keys {
		host := sp.Keys[i].Host
		data, err := hostread.Required(host, maxSignatureKeyBytes)
		if err != nil {
			return fmt.Errorf("the signature policy at %s names the key %s, and snug cannot "+
				"project it (%s).\n"+
				"       The engine reads its keys from a copy snug makes, because its mount view "+
				"is derived from the sandbox's and a host path resolves to nothing there. A key "+
				"snug cannot copy is a requirement it cannot reproduce, and it will not accept "+
				"the image instead.\n"+
				"       Fix: make %s a readable regular file, or change the requirement in %s.",
				policy.VisibleText(sp.Source), policy.VisibleText(host),
				policy.VisibleText(err.Error()),
				policy.VisibleText(host), policy.VisibleText(sp.Source))
		}
		total += int64(len(data))
		if total > maxSignatureKeyTotalBytes {
			return fmt.Errorf("the signature policy at %s names key material totalling more "+
				"than the %d bytes snug will copy for one run",
				policy.VisibleText(sp.Source), maxSignatureKeyTotalBytes)
		}
		sp.Keys[i].Data = data
	}
	return nil
}

// demandsSomething reports whether this policy asks anything of an image at
// all — what --dry-run renders as "signatures verified".
//
// A comparison, not a construction: it reads the type a requirement already
// carries and builds none. TestNothingFallsBackToAcceptAnything counts
// constructions, which is why this site does not raise its number.
func (sp *SignaturePolicy) demandsSomething() bool {
	demanding := func(reqs []requirement) bool {
		for _, r := range reqs {
			if r.Type != reqAcceptAnything {
				return true
			}
		}
		return false
	}
	if demanding(sp.Default) {
		return true
	}
	for _, scopes := range sp.Transports {
		for _, reqs := range scopes {
			if demanding(reqs) {
				return true
			}
		}
	}
	return false
}

// write materialises the projection: the key copies, the policy.json the engine
// reads, and the sidecar a human reads.
//
// NOTHING HERE CAN REFUSE FOR A POLICY REASON. Everything that classifies has
// already run in ProjectHostSignaturePolicy, before engine.New created a
// directory — so a refusal leaves nothing behind, and the only errors left are
// a full disk and a guestPath that fails, which would be a snug bug.
//
// The key copies land in the run's config directory, which is grafted READ-ONLY
// into the engine's view: an engine talked into writing cannot rewrite the keys
// it verifies against.
func (sp *SignaturePolicy) write(confDir, containersDir string, guest func(what, host string) (string, error)) error {
	copies := map[string]string{}
	if len(sp.Keys) > 0 {
		keyDir := filepath.Join(confDir, SignatureKeyDir)
		if err := os.MkdirAll(keyDir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", keyDir, err)
		}
		for i, k := range sp.Keys {
			dst := filepath.Join(keyDir, keyFileName(i))
			if err := os.WriteFile(dst, k.Data, 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", dst, err)
			}
			copies[k.Host] = dst
		}
	}

	body, err := sp.render(copies, guest)
	if err != nil {
		return err
	}
	path := filepath.Join(containersDir, "policy.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	// The sidecar, beside the file it explains. It is NOT the policy: a `_snug`
	// key inside policy.json would be fatal, because containers/image resolves
	// unknown top-level keys to nil and reports `Unknown key`, so every pull in
	// every sandbox would fail. A file the schema has no room for goes beside
	// the schema.
	if err := os.WriteFile(path+".snug", sp.sidecar(copies), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path+".snug", err)
	}
	return nil
}

// render emits the generated policy.json.
//
// guest maps a host path snug wrote to the name the engine sees. Every key path
// in the output goes through it, so a copy that no graft exposes is a refusal
// here rather than a file the engine cannot open three layers down.
func (sp *SignaturePolicy) render(copies map[string]string, guest func(what, host string) (string, error)) ([]byte, error) {
	// POINTERS FOR THE THREE KEY SOURCES, and this is not a style choice.
	// containers/image keys its "exactly one of keyPath, keyPaths, keyData"
	// rule off PRESENCE, and projectSignedBy matches that. `omitempty` keys off
	// EMPTINESS, so a host `"keyPaths": []` or `"keyData": ""` — both present,
	// both loaded by podman — came out as a signedBy with NO key source, which
	// podman refuses outright: every image operation in every sandbox on that
	// host, dead, with the error naming a file inside /snug that the user
	// cannot open. Presence in, presence out.
	type jsonRequirement struct {
		Type           string         `json:"type"`
		KeyType        string         `json:"keyType,omitempty"`
		KeyPath        *string        `json:"keyPath,omitempty"`
		KeyPaths       *[]string      `json:"keyPaths,omitempty"`
		KeyData        *string        `json:"keyData,omitempty"`
		SignedIdentity *identityMatch `json:"signedIdentity,omitempty"`
	}
	// EXACTLY the two keys containers/image's resolver returns a destination
	// for. It reports `Unknown key %q` for anything else, so a third key here
	// is a file the engine refuses to load at all.
	type jsonPolicy struct {
		Default    []jsonRequirement                       `json:"default"`
		Transports map[string]map[string][]jsonRequirement `json:"transports,omitempty"`
	}

	keyGuest := func(hostPath string) (string, error) {
		dst, ok := copies[hostPath]
		if !ok {
			// Unreachable: every key path reached addKey during projection.
			return "", fmt.Errorf("internal: no projected copy of the signature key %s",
				policy.VisibleText(hostPath))
		}
		return guest("a signature policy key", dst)
	}

	convert := func(reqs []requirement) ([]jsonRequirement, error) {
		out := make([]jsonRequirement, 0, len(reqs))
		for _, r := range reqs {
			j := jsonRequirement{
				Type: r.Type, KeyType: r.KeyType, KeyData: r.KeyData,
				SignedIdentity: r.SignedIdentity,
			}
			switch {
			case r.KeyPath != nil:
				g, err := keyGuest(*r.KeyPath)
				if err != nil {
					return nil, err
				}
				j.KeyPath = &g
			case r.KeyPaths != nil:
				// A NON-NIL EMPTY SLICE stays a non-nil empty slice: the host
				// wrote `[]`, podman loads it, and dropping it would emit a
				// keyless signedBy podman refuses.
				guests := make([]string, 0, len(*r.KeyPaths))
				for _, p := range *r.KeyPaths {
					g, err := keyGuest(p)
					if err != nil {
						return nil, err
					}
					guests = append(guests, g)
				}
				j.KeyPaths = &guests
			}
			out = append(out, j)
		}
		return out, nil
	}

	var doc jsonPolicy
	var err error
	if doc.Default, err = convert(sp.Default); err != nil {
		return nil, err
	}
	if len(sp.Transports) > 0 {
		doc.Transports = map[string]map[string][]jsonRequirement{}
		for _, transport := range sortedKeys(sp.Transports) {
			scopes := map[string][]jsonRequirement{}
			for _, scope := range sortedKeys(sp.Transports[transport]) {
				if scopes[scope], err = convert(sp.Transports[transport][scope]); err != nil {
					return nil, err
				}
			}
			doc.Transports[transport] = scopes
		}
	}

	body, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// sidecar is the generated file's account of itself, written beside it because
// the schema has no room for a comment.
//
// THE TWO OPENING SENTENCES ARE DIFFERENT ON PURPOSE. "Your host configured no
// policy" and "snug decided not to verify" describe the same bytes and not the
// same decision, and the human reading this after a pull was refused — or after
// one was NOT refused — is entitled to know which happened.
func (sp *SignaturePolicy) sidecar(copies map[string]string) []byte {
	var b strings.Builder
	b.WriteString("snug generated the policy.json beside this file for one run.\n\n")
	if sp.Source == "" {
		b.WriteString("This host has no policy.json where podman looks " +
			"($XDG_CONFIG_HOME or ~/.config/containers, /etc/containers, " +
			"/usr/share/containers), so there was no posture to preserve and " +
			"the generated file accepts any image.\n\n" +
			"That IS a decision snug made, and it goes the permissive way. A podman on this " +
			"host with no policy.json refuses every pull outright (\"no policy.json file " +
			"found\"); snug generates one so the sandbox can pull at " +
			"all. Nothing your host configured has been weakened, because your host " +
			"configured nothing — but the sandbox verifies less than the bare host, not the " +
			"same.\n\n" +
			"To have the sandbox enforce something, write the policy.json you want at " +
			"~/.config/containers/policy.json; snug projects it.\n")
		return []byte(b.String())
	}
	fmt.Fprintf(&b, "It is a PROJECTION of %s. Every requirement there is reproduced; a "+
		"requirement snug cannot reproduce refuses the run rather than being dropped, so if "+
		"this file exists, what it says is what your host configured.\n", sp.Source)
	if len(sp.Keys) > 0 {
		b.WriteString("\nKey material is COPIED, because the engine's mount view is derived " +
			"from the sandbox's and a host path resolves to nothing in it:\n")
		for _, k := range sp.Keys {
			fmt.Fprintf(&b, "  %s\n    <- %s\n", copies[k.Host], k.Host)
		}
	}
	b.WriteString("\nSignature LOOKUP — where a signature is fetched from — is not projected. " +
		"That is registries.d, which the engine reads from /etc/containers/registries.d " +
		"through the sandbox's own read-only grant. A lookaside configured under " +
		"~/.config/containers/registries.d is not seen here, and a signedBy requirement that " +
		"then finds no signature REJECTS the image.\n")
	return []byte(b.String())
}
