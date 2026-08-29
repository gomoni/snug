package profile

import (
	"io/fs"
	"regexp"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #289's structural regression: a refusal must never name a profile
// snug does not ship ────────────────────────────────────────────────────────
//
// internal/policy's own regression test (endpointsource_test.go,
// TestEndpointRefusalNamesTheRealRemediation) pins the SPECIFIC string that
// was wrong. This test is the general form, and it belongs here rather than
// there because only this package can ask "is @X a profile snug ships" —
// internal/policy cannot import internal/profile (see resolve_test.go's own
// testRegistry comment for why), so it has no Builtins() to check against.

// refusalFakeEnv is the minimal policy.Environ this file needs: enough to
// drive rejectEndpointSource (Stat reporting a socket) and rejectHostHomeBind
// (which reads no filesystem at all). Deliberately not internal/policy's own
// fakeEnv, nor internal/cli's envFakeEnv — neither is reachable from this
// package, and a third small copy living in a _test.go file is the price
// CLAUDE.md already accepts for envFakeEnv's own existence ("a test fake that
// has to live in a non-test file is a fake that can be reached by something
// other than a test").
type refusalFakeEnv struct {
	sockets map[string]bool
}

func (e refusalFakeEnv) EvalSymlinks(p string) (string, error)   { return p, nil }
func (e refusalFakeEnv) HostMounts() ([]policy.HostMount, error) { return nil, nil }

func (e refusalFakeEnv) Stat(p string) (fs.FileInfo, error) {
	if e.sockets[p] {
		return refusalFakeInfo{mode: fs.ModeSocket}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

func (e refusalFakeEnv) Getenv(string) string            { return "" }
func (e refusalFakeEnv) LookupEnv(string) (string, bool) { return "", false }
func (e refusalFakeEnv) Uid() int                        { return 1000 }
func (e refusalFakeEnv) Gid() int                        { return 1000 }

// LookPath is never called by anything this file exercises. Not found,
// answered from the fixture's own (absent) data rather than the real host's.
func (e refusalFakeEnv) LookPath(name string) (string, error) {
	return "", &fs.PathError{Op: "lookpath", Path: name, Err: fs.ErrNotExist}
}

type refusalFakeInfo struct{ mode fs.FileMode }

func (i refusalFakeInfo) Name() string       { return "endpoint" }
func (i refusalFakeInfo) Size() int64        { return 0 }
func (i refusalFakeInfo) Mode() fs.FileMode  { return i.mode }
func (i refusalFakeInfo) ModTime() time.Time { return time.Time{} }
func (i refusalFakeInfo) IsDir() bool        { return false }
func (i refusalFakeInfo) Sys() any           { return nil }

// endpointSourceRefusal builds a minimal, hand-constructed Policy — not
// through Resolve, which this package's fake registries cannot mirror closely
// enough to matter here — that trips rejectEndpointSource (issues #219, #287)
// and returns the resulting message.
func endpointSourceRefusal(t *testing.T) string {
	t.Helper()
	env := refusalFakeEnv{sockets: map[string]bool{"/home/u/agent.sock": true}}
	p := &policy.Policy{
		Target: "/home/u/proj",
		Mounts: map[string]policy.Mount{
			"/usr": {Kind: policy.KindBind, Guest: "/usr", Host: "/usr",
				Access: policy.AccessRO, From: []string{"@sys"}},
			"/home/u/proj": {Kind: policy.KindBind, Guest: "/home/u/proj", Host: "/home/u/proj",
				Access: policy.AccessRW, From: []string{"@cwd-rw"}},
			"/home/u/mounted": {Kind: policy.KindBind, Guest: "/home/u/mounted", Host: "/home/u/agent.sock",
				Access: policy.AccessRO, From: []string{"binder"}},
		},
	}
	err := p.Validate(env)
	if err == nil {
		t.Fatal("fixture: a bind whose source is a unix socket was accepted — the endpoint-" +
			"source refusal did not fire, so this test is not exercising the message it claims to")
	}
	return err.Error()
}

// hostHomeBindRefusal builds a minimal Policy that trips rejectHostHomeBind
// (issue #220) — a KindBind mount whose Guest IS $HOME — and returns the
// resulting message.
func hostHomeBindRefusal(t *testing.T) string {
	t.Helper()
	env := refusalFakeEnv{}
	p := &policy.Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]policy.Mount{
			"/usr": {Kind: policy.KindBind, Guest: "/usr", Host: "/usr",
				Access: policy.AccessRO, From: []string{"@sys"}},
			"/home/u": {Kind: policy.KindBind, Guest: "/home/u", Host: "/home/u",
				Access: policy.AccessRO, From: []string{"@parent-ro"}},
		},
	}
	err := p.Validate(env)
	if err == nil {
		t.Fatal("fixture: a bind covering $HOME was accepted — the host-home-bind refusal did " +
			"not fire, so this test is not exercising the message it claims to")
	}
	return err.Error()
}

// atToken matches an '@' immediately followed by what a profile name always
// starts and continues with (policy.checkName's own grammar: lowercase,
// digits, hyphen). The boundary check below is what stops it matching an
// email address's local part.
var atToken = regexp.MustCompile(`@[a-z][a-z0-9-]*`)

// isIdentTailByte reports whether b could plausibly be the byte immediately
// BEFORE a genuine profile-name token in running prose — i.e. the set that
// would make the '@' the middle of some other token (an email address, a
// package spec, a doubled sigil) rather than its start.
func isIdentTailByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '.' || b == '_' || b == '@' || b == '-':
		return true
	}
	return false
}

// extractProfileTokens returns every substring of msg that reads as a
// profile-name reference: an '@' preceded by nothing, whitespace or
// punctuation (never by a letter, digit, dot, underscore, '@' or hyphen),
// followed by policy.checkName's grammar.
//
// The boundary rule is the whole point. `git@github.com` and
// `you@example.com` must NOT match — in both, the '@' is preceded by a
// lowercase letter, so plain `@[a-z][a-z0-9-]*` over the whole message would
// misread "github" and "example" as profile names and this test would fail on
// prose that names no profile at all.
func extractProfileTokens(msg string) []string {
	var out []string
	for _, loc := range atToken.FindAllStringIndex(msg, -1) {
		start := loc[0]
		if start > 0 && isIdentTailByte(msg[start-1]) {
			continue
		}
		out = append(out, msg[loc[0]:loc[1]])
	}
	return out
}

// TestRefusalMessagesNameOnlyProfilesSnugShips is issue #289's general form:
// whatever profile name a refusal message points a human at must actually
// resolve, or the message is sending someone to `snug: unknown profile "@X"`
// instead of a fix.
//
// BOUNDED TO EXACTLY THESE TWO MESSAGES, and deliberately NOT a sweep of
// every error string in internal/policy, with NO allowlist bolted on to make
// a wider sweep pass. A wider, unrestricted sweep is not viable, and that is
// worth recording rather than discovering by trial and error:
//
//   - internal/policy/resolve.go:876 deliberately writes '@null' to say it
//     does NOT exist — there is no @null builtin (CLAUDE.md, "the floor of the
//     lattice is what Resolve computes from an empty selection, not something
//     a file names") — and a membership check would flag the one place that
//     sentence is written down.
//   - This project's own prose carries adjectives shaped like profile names
//     that are not ones — '@claude-shaped', '@net-shaped' — which the token
//     grammar below cannot distinguish from a real reference without either a
//     second grammar just for adjectives or an allowlist, and an allowlist
//     here is the same subtractive shape invariant 2 calls a design smell:
//     it would need one entry per string someone happened to write, and
//     drifts the moment a new error message is added without updating it.
//
// So this checks the two messages this project has SPECIFICALLY gotten wrong
// (issue #289 measured '@ssh-agent' in the first; the second carries the same
// class of remediation text and is checked as the companion it is), rather
// than pretending to a general property this package cannot check soundly.
func TestRefusalMessagesNameOnlyProfilesSnugShips(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}

	for label, msg := range map[string]string{
		"the endpoint-source refusal (issues #219, #287)": endpointSourceRefusal(t),
		"the host-home-bind refusal (issue #220)":         hostHomeBindRefusal(t),
	} {
		tokens := extractProfileTokens(msg)
		if len(tokens) == 0 {
			t.Errorf("%s: found no @-token at all in the message — this refusal has, at least "+
				"once (issue #289), named a profile snug does not ship, and the point of this "+
				"sweep is to keep watching that message. If it no longer names ANY profile, that "+
				"is a real change worth a human's attention, not a silent pass:\n%s", label, msg)
			continue
		}
		for _, tok := range tokens {
			if _, ok := reg[policy.ProfileName(tok)]; !ok {
				t.Errorf("%s names %q, which is not a profile snug ships (see profile.Builtins()). "+
					"That is issue #289's exact defect: a human reading this follows it with "+
					"`snug -p %s` and gets `snug: unknown profile %q` instead of a fix.\n%s",
					label, tok, tok, tok, msg)
			}
		}
	}
}
