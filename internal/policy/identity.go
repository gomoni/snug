package policy

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// SSHMode says how (and whether) the sandbox can use an ssh key.
type SSHMode string

const (
	// SSHAgentProxy is the recommendation for every real workflow: a filtering
	// proxy to the host's ALREADY-UNLOCKED agent, exposing exactly one key. No
	// key material inside, no passphrase prompt, other keys not enumerable.
	//
	// THE VALUE IS "proxy" AND THE IDENTIFIER IS STILL SSHAgentProxy. The key is
	// `identity.ssh.agent`, so the block already says ssh and the value no longer
	// repeats it; the Go name keeps saying both because it is read without the
	// block around it. The older spelling "agent-proxy" is not a synonym — it is
	// unknown, and ParseSSHMode says so.
	SSHAgentProxy SSHMode = "proxy"

	// SSHNone is the ZERO value, and that is load-bearing: every identity block
	// is its own pin, so a profile that sets no ssh block stores an empty
	// IdentitySSH, and every `Agent != SSHNone` reader must read that as "no
	// agent". Were it "none", an absent block would read as an active agent —
	// SSH_AUTH_SOCK set, an insteadOf rewrite and commit signing generated —
	// in a sandbox no profile asked to have one.
	SSHNone SSHMode = ""
)

// ParseSSHMode is one of the four doors into policy.SSHMode, and it accepts
// two values. Anything else is unknown — there is no catalogue of spellings it
// judges individually, which is what keeps the accepted set readable as the
// whole set.
//
// `none` and the empty string are both SSHNone, so a profile with an ssh block
// and no `agent` key gets no agent rather than a refusal, and an ssh block
// holding only `agent = "none"` normalises to the zero block — it grants
// nothing, so it pins nothing.
//
// IT GROWS NO ARM FOR THE OLDER "agent-proxy", deliberately, and that is the
// whole treatment a spelling snug has dropped gets: snug commits to no
// configuration compatibility, so there is no second refusal naming the
// replacement. A catalogue of spellings judged individually is exactly what the
// paragraph above says this function must not become, and an arm for a dropped
// value costs the same readability as an arm that accepted it. The message
// names the accepted set, which is the fix either way. One spelling, one fate.
func ParseSSHMode(s string) (SSHMode, error) {
	switch SSHMode(s) {
	case SSHAgentProxy:
		return SSHAgentProxy, nil
	case "none", "":
		return SSHNone, nil
	default:
		return "", fmt.Errorf("unknown identity.ssh.agent %q (want proxy or none)", s)
	}
}

// KubeTokenMode is how the host-side broker mints the token kubectl inside
// uses. T1 has one value; "" is UNSET, not a mode, and Resolve refuses a kube
// block without one, so absence never picks a minting route.
type KubeTokenMode string

// KubeTokenServiceAccount mints with the host's own kubectl, `kubectl create
// token`, for the one ServiceAccount identity.kube.service_account names.
const KubeTokenServiceAccount KubeTokenMode = "serviceaccount"

// ParseKubeTokenMode is the door into KubeTokenMode, with the same rule as
// ParseSSHMode: a named set, and anything else unknown, quoting the set.
func ParseKubeTokenMode(s string) (KubeTokenMode, error) {
	switch KubeTokenMode(s) {
	case KubeTokenServiceAccount, "":
		return KubeTokenMode(s), nil
	default:
		return "", fmt.Errorf("unknown identity.kube.token %q (want serviceaccount)", s)
	}
}

// Identity pins which account the sandbox acts as, ONE BLOCK AT A TIME. Each
// top-level field is its own pin: two profiles setting the same block
// differently are refused, naming both, and profiles setting different blocks
// compose. So ssh from one profile and gh from another make a sandbox that
// pushes as one account and calls the API as the other — the blocks are
// independent channels, and keeping them on one account is the profile
// author's choice, made by putting them in one profile. What no selection can
// do is hold two values of one block.
//
// The point is not secrecy — it is blast radius. An agent that can sign with
// one key can push as that account and no other, and `gh api user` answers with
// that account and no other. Without pinning, "the agent has ssh" means "the
// agent is you, everywhere".
type Identity struct {
	SSH  IdentitySSH  `snug:"ssh"`
	Git  IdentityGit  `snug:"git"`
	Gh   IdentityGh   `snug:"gh"`
	Kube IdentityKube `snug:"kube"`
}

// NESTED BY VALUE, AND A POINTER HERE WOULD BREAK THREE THINGS WHILE COMPILING,
// PASSING, AND SATISFYING THE == ASSERTION BELOW.
//
//  1. `*p.Identity != id` (resolve.go) would degrade to pointer identity, so two
//     profiles carrying byte-identical blocks would refuse each other.
//  2. `id := *prof.Identity` would share the inner struct with the LOADED
//     profile, and the normalisation loop writes the expanded path back through
//     it — mutating the registry for the rest of the process. Resolution becomes
//     order-dependent: resolve([a,b]) and resolve([b,a]) differ in what they
//     render. That is the decisive one, because it is the invariant rather than a
//     message.
//  3. FieldByIndex walks a multi-element index and panics on a nil pointer in the
//     path, which is what identityFields hands every caller.
//
// mustIdentityFields refuses any kind but Struct and String at package init, so
// this is enforced rather than documented.
type IdentitySSH struct {
	// Host is the host every ssh-shaped artifact names: the `Host` line of the
	// generated ~/.ssh/config, the known_hosts filter, and git's insteadOf
	// rewrite — which rewrites https://HOST/ to git@HOST:, so it is the host you
	// PUSH to rather than the host an API answers on. Separate from Gh.Host, and
	// nothing is inherited between them.
	Host string `snug:"host"`

	// Key is the PUBLIC key file that pins the identity. Only the public half is
	// read; the private key never leaves the host agent.
	Key string `snug:"key,path"`

	Agent SSHMode `snug:"agent"`
}

type IdentityGit struct {
	Name  string `snug:"name"`
	Email string `snug:"email"`

	// SigningKey is the PUBLIC key file for `gpg.format = ssh` commit and tag
	// signing. Only the public half is read; the private key never leaves the
	// host agent, which is why this field requires ssh.agent = "proxy".
	//
	// UNDER git AND NOT ssh, because git is what signs with it — the subject, not
	// the consumer that pins it. The ssh proxy is what holds the pin, and scoping
	// by consumer would put it beside Key where it reads as a second
	// authentication key, which is the one thing it is not.
	//
	// SEPARATE FROM SSH.Key ON PURPOSE, and the asymmetry is the reason there are
	// two fields rather than one wide one: a signing key is usually NOT an
	// authorized key, so granting signing does not grant push and granting push
	// does not grant signing. One field cannot say that.
	//
	// RESIDUAL, and it is not closable here: the ssh-agent protocol carries no
	// statement of PURPOSE, so once both keys are pinned, anything inside the
	// sandbox can ask the proxy to sign with either one for either use. The pin
	// bounds WHICH keys, never what they are used for.
	//
	// It is deliberately absent from SSHConfig: adding it as a second
	// IdentityFile would make ssh OFFER a key that is typically authorized
	// nowhere, spending an authentication attempt for nothing.
	SigningKey string `snug:"signing_key,path"`
}

// IdentityKube pins one cluster and one ServiceAccount on it. Context names a
// context in the host kubeconfig; snug reads that context's cluster as data
// and never carries its user entry inside. The namespace is the first half of
// ServiceAccount ("namespace/name") and is not a key of its own: it is where
// the account lives, and a default namespace for kubectl would be a setting
// for the program inside, which a profile does not carry.
type IdentityKube struct {
	Context        string        `snug:"context"`
	Token          KubeTokenMode `snug:"token"`
	ServiceAccount string        `snug:"service_account"`
	Kubeconfig     string        `snug:"kubeconfig,path"`
}

// DefaultKubeconfig is identity.kube.kubeconfig when a kube block omits it.
const DefaultKubeconfig = "{home}/.kube/config"

type IdentityGh struct {
	// Host is the host gh mints a token for, and the only thing it selects.
	// Separate from SSH.Host: the two MAY differ, and a profile naming one
	// without the other is refused rather than defaulted, because three of the
	// four consumers would otherwise name a host the profile never wrote.
	Host string `snug:"host"`
	User string `snug:"user"`
}

// A pointer, slice or map field would make this fail to compile — which is worth
// having, but it is NOT the guard for the three failures listed above
// IdentitySSH: a pointer is comparable, so this line passes while every one of
// them lands. mustIdentityFields and TestIdentityHasNoReferenceKindedField are
// the guards. This one catches the narrower case where == stops working at all.
var _ = Identity{} == Identity{}

// identityField is one string leaf of Identity: its dotted TOML key, the index
// path FieldByIndex needs, and whether the value is a host path.
type identityField struct {
	Key   string // dotted, with no "identity." prefix: "ssh.key", "git.signing_key"
	Index []int
	Path  bool
	Pin   string // the top-level block the leaf belongs to: "ssh", "git", "gh"
}

// identityPathRole is what an identity `path` leaf is FOR, in the words its
// refusals use. The loop that expands and link-checks every path leaf is
// shared, and its sentences were written for ssh keys; a kubeconfig is not a
// key, and a refusal telling the human to copy its PUBLIC half is a wrong
// instruction. mustIdentityFields panics on a path leaf with no role, so a new
// path leaf cannot reuse another leaf's sentences by omission.
type identityPathRole struct {
	chooses string // what a planted link at the path would choose
	reads   string // what snug does with the file
	example string // an absolute spelling for the "must be absolute" refusal
	fix     string // the instruction when the path sits in snug's own state
}

var identityPathRoles = map[string]identityPathRole{
	"ssh.key": {
		chooses: "which host key the sandbox can sign with",
		reads:   "snug would read the file and stage its contents into the sandbox's $HOME",
		example: "{home}/.ssh/id_ed25519.pub",
		fix:     "Copy the PUBLIC key to a directory snug does not manage (for example ~/.ssh) and name that path instead.",
	},
	"git.signing_key": {
		chooses: "which host key the sandbox can sign with",
		reads:   "snug would read the file and stage its contents into the sandbox's $HOME",
		example: "{home}/.ssh/id_ed25519.pub",
		fix:     "Copy the PUBLIC key to a directory snug does not manage (for example ~/.ssh) and name that path instead.",
	},
	"kube.kubeconfig": {
		chooses: "which cluster, and which of your host credentials, snug's host-side mint uses",
		reads:   "snug decodes it on the host and mints with the credential it names",
		example: "{home}/.kube/config",
		fix:     "Keep the kubeconfig in a directory snug does not manage (for example ~/.kube) and name that path instead.",
	},
}

// identityPin is one top-level block of Identity — one pin — and its field
// index, DERIVED from the type like identityFields, so a block added to
// Identity joins on its own without an edit to Resolve.
type identityPin struct {
	Key   string
	Index int
}

var identityPins = mustIdentityPins(reflect.TypeOf(Identity{}))

func mustIdentityPins(t reflect.Type) []identityPin {
	out := make([]identityPin, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Type.Kind() != reflect.Struct {
			panic(fmt.Sprintf("policy: Identity.%s is a %s. Every top-level identity field "+
				"is a BLOCK and joins as one pin; a bare leaf here would belong to no pin "+
				"and be compared by nobody", f.Name, f.Type.Kind()))
		}
		key, _, _ := strings.Cut(f.Tag.Get("snug"), ",")
		out = append(out, identityPin{Key: key, Index: i})
	}
	return out
}

// IdentityProvenance is the `identity:<profile>` provenance of a file generated
// from the given identity blocks: one profile, or several joined with `+`,
// sorted and without repeats, when the blocks came from different profiles. It
// is "(identity)" when none of the blocks is pinned.
func (p *Policy) IdentityProvenance(blocks ...string) string {
	var owners []string
	for _, b := range blocks {
		for _, o := range p.IdentityOwners[b] {
			if !slices.Contains(owners, string(o)) {
				owners = append(owners, string(o))
			}
		}
	}
	if len(owners) == 0 {
		return "(identity)"
	}
	slices.Sort(owners)
	return "identity:" + strings.Join(owners, "+")
}

// IdentityOwner is the first profile, in sorted order, that pinned block, for
// a refusal that names one; "" when no profile did.
func (p *Policy) IdentityOwner(block string) ProfileName {
	if o := p.IdentityOwners[block]; len(o) > 0 {
		return o[0]
	}
	return ""
}

// Pinned reports whether block key ("ssh", "git", "gh", "kube") is set. It is false
// for a nil Identity and for a key that names no block.
func (i *Identity) Pinned(key string) bool {
	if i == nil {
		return false
	}
	v := reflect.ValueOf(*i)
	for _, p := range identityPins {
		if p.Key == key {
			return !v.Field(p.Index).IsZero()
		}
	}
	return false
}

// identityFields is every string leaf of Identity, DERIVED FROM THE TYPE. That
// is the whole point and it is what issue #549 asks for in one sentence: a new
// identity field must not be expressible without passing through CheckText.
//
// It is the single list behind two sinks — CheckText's forging-rune refusal and
// Resolve's expand-and-symlink-check loop — and the reason it is derivation rather
// than a table per sink is that Go has no exhaustiveness check over
// struct fields: any table is guarded by a TEST, and a test that walks a nested
// struct for string-kinded fields silently covers nothing the moment the fields
// become structs. The type is the table, so there is nothing to forget.
var identityFields = mustIdentityFields(reflect.TypeOf(Identity{}), nil, "")

// IdentityFieldKeys is the dotted TOML key of every identity leaf, in declaration
// order. Exported for internal/profile, which is the only package that imports
// both this one and the TOML decode structs, and which asserts the two agree —
// a leaf with no matching `toml:` tag decodes nowhere and would be silently
// unsettable rather than loudly missing.
func IdentityFieldKeys() []string {
	out := make([]string, 0, len(identityFields))
	for _, f := range identityFields {
		out = append(out, f.Key)
	}
	return out
}

// mustIdentityFields walks Identity and PANICS rather than returning an error.
//
// A missing or malformed `snug:` tag is a programmer error in this package's own
// struct. Reported through CheckText it would render as `profile "x": ...`,
// blaming a human for our bug; panicking at package init means every test that
// imports internal/policy runs it, which is as close to compile time as Go gets.
func mustIdentityFields(t reflect.Type, index []int, prefix string) []identityField {
	var out []identityField
	for i := range t.NumField() {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("snug")
		if !ok || tag == "" {
			panic(fmt.Sprintf("policy: %s.%s has no snug tag. Every identity field must "+
				"declare its TOML key: CheckText renders it into the refusal a human reads, "+
				"and the expand loop uses it as the label on a symlink error", t.Name(), f.Name))
		}
		key, opts, _ := strings.Cut(tag, ",")
		path := false
		for opt := range strings.SplitSeq(opts, ",") {
			switch opt {
			case "":
			case "path":
				path = true
			default:
				panic(fmt.Sprintf("policy: unknown snug option %q on %s.%s (the only one is `path`)",
					opt, t.Name(), f.Name))
			}
		}
		idx := append(append([]int(nil), index...), i)
		switch f.Type.Kind() {
		case reflect.Struct:
			if path {
				panic(fmt.Sprintf("policy: %s.%s is a struct carrying `path`; only a string leaf "+
					"can be a host path", t.Name(), f.Name))
			}
			out = append(out, mustIdentityFields(f.Type, idx, prefix+key+".")...)
		case reflect.String:
			if _, ok := identityPathRoles[prefix+key]; path && !ok {
				panic(fmt.Sprintf("policy: identity.%s is a path leaf with no identityPathRoles "+
					"entry; its refusals would borrow another leaf's sentences", prefix+key))
			}
			pin, _, _ := strings.Cut(prefix+key, ".")
			out = append(out, identityField{Key: prefix + key, Index: idx, Path: path, Pin: pin})
		default:
			panic(fmt.Sprintf("policy: %s.%s is a %s. Only nested value structs and strings are "+
				"supported: a pointer, slice or map field would make `*p.Identity != id` stop "+
				"comparing it (a pointer is still comparable, so the == assertion beside the type "+
				"will not catch it), would make `id := *prof.Identity` share state with the loaded "+
				"profile, and would make FieldByIndex panic. Add a string leaf inside a block instead",
				t.Name(), f.Name, f.Type.Kind()))
		}
	}
	return out
}

// CheckText refuses a control character in any identity field.
//
// The same rule as checkEnvValue, at a sink that did not exist when it was
// written — and it is load-bearing rather than defensive, because every one of
// these fields is interpolated into a CONFIG FILE snug generates. With \u000A
// spelled as an escape, which is the only spelling go-toml accepts:
//
//	[profile.x.identity.git]
//	name = "x\u000A[core]\u000A\tsshCommand = curl ... | sh"
//	[profile.x.identity.gh]
//	host = "a\u000Ab: {oauth_token: ...}"
//
// The first writes a git directive into ~/.gitconfig; the second a second host
// entry into gh's hosts.yml. Neither is a Mount, so Validate, rejectMasking and
// the provenance model are all blind to it — the same shape as the NUL in
// environ.set, one layer over. gh.user and gh.host additionally reach a terminal
// through the no-token refusal, where ESC[1A CR forges a `snug:` line.
//
// A raw control character never survives go-toml in a basic string; the \u
// escape does, which is what anyone re-testing this needs.
//
// The verdict is a property of the profile text, so it is the same on every host
// and belongs beside resolution rather than in a renderer.
//
// IT WAS A BYTE LOOP OVER `c < 0x20 || c == 0x7f`, AND THAT IS TWO SINKS SHORT.
// The directive-authoring half above is genuinely ASCII — only a newline writes
// a second git or YAML line — but these fields reach two artifacts a human READS
// as well: the generated ~/.claude/CLAUDE.md interpolates gh.user into a
// sentence with %s (internal/cli/claude.go), and the no-token refusal renders
// gh.user and gh.host to a terminal (that one quotes, so it was already safe).
// A byte loop cannot see U+009B and no loop keyed on unicode.IsControl can see
// U+202E, so the field that names the account the sandbox pushes as could be
// spelled to render as a different account in the file the agent is handed. It
// asks the one predicate now (IsForgingRune, forging.go), so this sink is
// widened by whatever widens the others.
func (i *Identity) CheckText(profileName ProfileName) error {
	if i == nil {
		return nil
	}
	v := reflect.ValueOf(*i)
	for _, f := range identityFields {
		for _, r := range v.FieldByIndex(f.Index).String() {
			if !IsForgingRune(r) {
				continue
			}
			return fmt.Errorf("profile %q: identity.%s contains %q. Every identity field is "+
				"interpolated into a config file snug GENERATES — ~/.gitconfig, ~/.ssh/config, "+
				"gh's hosts.yml, the sandbox's ~/.kube/config — where a NEWLINE writes a directive snug did not author, "+
				"and none of it is a Mount that Validate could refuse. They are also "+
				"rendered into the ~/.claude/CLAUDE.md the agent reads, and there "+
				"%s. Remove it",
				profileName, f.Key, r, forgingRuneReason(r))
		}
	}
	return nil
}

// The generated ~/.gitconfig is rendered by GitConfigFrom in gitconfig.go, not
// here.
//
// One writer, one file. Two functions authoring the same path is how the last
// silent displacement happened. The insteadOf rule GitConfigFrom emits rewrites
// https://<host>/ to the ssh form so a push goes over the pinned key rather than
// hanging on a credential prompt no one can answer.

// PubKeyGuest is where the pinned PUBLIC key is staged inside the sandbox.
const PubKeyGuest = ".ssh/id_snug.pub"

// SigningKeyGuest is where the pinned SIGNING public key is staged. A SECOND
// path, not a reuse of PubKeyGuest: the two are usually different keys, and when
// a profile names the same file twice the two staged copies are identical and
// harmless — cheaper than a branch a reader has to simulate.
const SigningKeyGuest = ".ssh/id_snug_signing.pub"

// AllowedSignersGuest is the generated `gpg.ssh.allowedSignersFile`. It holds
// exactly ONE line — the pinned signing key, under the pinned git email — so a
// run can verify its OWN commits and nobody else's.
//
// UNDER .config/git AND NOT .ssh, because git is what reads it. The file is git
// configuration naming an ssh key, the same way user.signingkey is; .ssh holds
// what the ssh CLIENT reads (config, known_hosts, the staged .pub), and a
// verifier list there would be the first place a reader looks for keys ssh
// itself trusts, which this is not.
//
// The host's own ~/.config/git/allowed_signers is NEVER carried (#576): it is
// the list of people whose signatures you accept, so carrying it would hand the
// sandbox collaborators' emails and public keys plus a trust decision no grant
// named.
const AllowedSignersGuest = ".config/git/allowed_signers"

// SSHConfig is the generated ~/.ssh/config.
//
// IdentityFile pointing at a .pub is the standard way to make ssh select
// exactly one agent identity, and it is REQUIRED here rather than decorative:
// `IdentitiesOnly yes` with no IdentityFile tells ssh to use only the
// identities named in the config, and naming none can leave it declining to
// offer the agent's key at all. The previous generation of this project staged
// the .pub for exactly this reason; an earlier draft of snug set
// IdentitiesOnly without it and would have broken agent auth.
//
// Only the public half is ever staged. The private key stays in the host agent.
func (i *Identity) SSHConfig(home string) []byte {
	if i == nil || i.SSH.Agent == SSHNone {
		return nil
	}
	return fmt.Appendf(nil,
		"# Generated by snug. The host's ~/.ssh is not mounted.\n"+
			"Host %s\n"+
			"\tUser git\n"+
			"\tIdentitiesOnly yes\n"+
			"\tIdentityFile %s/%s\n"+
			"\tStrictHostKeyChecking accept-new\n"+
			"\tUserKnownHostsFile %s/.ssh/known_hosts\n",
		i.SSHHost(), home, PubKeyGuest, home)
}

// The system-wide ssh_config replacement is no longer part of identity: it is
// authored on every run whose deepest covering grant supplies the host's copy,
// identity pinned or not. See SystemSSHConfigPaths, SystemSSHConfig and
// replaceSystemSSHConfig in systemsshconfig.go — this is where
// (*Identity).SystemSSHConfig used to be.

// DefaultIdentityHost is what a generated artifact names when the block feeding
// it names no host.
//
// ONE CONSTANT because it was four separate literals — here, twice in
// internal/cli/identity.go, and once in internal/cli/config.go — plus two returns
// in identitySSHHost. A default that disagrees with itself across six sites is a
// default nobody can reason about, and the host split was the change that would
// have made them disagree.
const DefaultIdentityHost = "github.com"

// SSHHost is the host every ssh-shaped artifact names: the `Host` line of the
// generated ~/.ssh/config, the known_hosts filter, and git's insteadOf rewrite.
//
// It reads ssh.host and NOTHING ELSE. The host you push to over the pinned key and
// the host gh mints a token for are two questions with one answer each, and a
// profile naming only one of them is refused rather than having the other defaulted
// underneath it — see refuseHalfNamedHost.
func (i *Identity) SSHHost() string {
	if i == nil || i.SSH.Host == "" {
		return DefaultIdentityHost
	}
	return i.SSH.Host
}

// GhHost is the host gh mints a token for, and the only thing it selects.
//
// CALLERS THAT ARE DECIDING WHETHER TO ACT AT ALL MUST READ THE FIELD, not this:
// it is never empty, so `GhHost() == ""` is a gate that never closes. stageGhConfig
// had exactly that shape before the split.
func (i *Identity) GhHost() string {
	if i == nil || i.Gh.Host == "" {
		return DefaultIdentityHost
	}
	return i.Gh.Host
}
