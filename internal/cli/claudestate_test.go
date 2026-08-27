package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #19: ~/.claude.json is GENERATED, and its key list is a gate ────────
//
// What shipped for a milestone: a verbatim 62 KB copy of the host's
// ~/.claude.json into the sandbox's writable tmpfs, justified in three places by
// a sentence that was measured false: it claimed Claude Code repeats its
// first-run flow and shows a LOGIN PROMPT without the file, and it does neither
// — only .credentials.json is load-bearing for login. The file is not a
// credential, and that is exactly why nothing caught it: it is a host-filesystem
// INVENTORY — every project path on the machine, org and account UUIDs, email,
// machine and user IDs, MCP server configuration, and the host's per-project
// tool approvals — handed to the payload in its own $HOME, while @parent-ro
// deliberately does not grant so much as a sibling directory.
//
// These tests are the ratchet on the replacement. The canary sweep is the
// "did any host byte get in" half; the key-set test is the "did the list grow
// back" half, and it is the one that will fire in a year.

// claudeCanaries is the host fixture, and every string in it is a real key of
// the host's file rather than an invented one — a canary that does not
// correspond to something the old code actually copied would make the sweep
// look stronger than it is.
var claudeCanaries = []string{
	"leak@example.com",       // oauthAccount.emailAddress
	"CANARY-MACHINE-ID",      // machineID
	"CANARY-ORG-UUID",        // oauthAccount.organizationUuid
	"CANARY-USER-ID",         // userID
	"/home/u/secret-project", // a projects[] key: the host inventory itself
	"CANARY-MCP-SERVER",      // mcpServers, the injection surface
	"CANARY-ALLOWED-TOOL",    // projects[*].allowedTools, a host-side approval
}

// hostTrustedOtherProject is the one directory the host fixture below has
// accepted the trust dialog for, and it is deliberately NOT the target. It is
// what makes "the target is not trusted" a statement about the PATH rather than
// about a reader that cannot see a trust entry at all.
const hostTrustedOtherProject = "/home/u/secret-project"

// hostClaudeJSON writes the host fixture with hostTrustedOtherProject trusted
// and the target NOT trusted — the state of any host meeting an unfamiliar
// repository for the first time.
func hostClaudeJSON(t *testing.T, home string) []byte {
	t.Helper()
	return writeHostClaudeJSON(t, home, "")
}

// hostClaudeJSONTrusting writes the same fixture with one extra projects entry:
// the target, accepted. This is the host state snug is allowed to carry across —
// the human answered "yes, I trust this folder" outside the sandbox already.
func hostClaudeJSONTrusting(t *testing.T, home, target string) []byte {
	t.Helper()
	return writeHostClaudeJSON(t, home, target)
}

func writeHostClaudeJSON(t *testing.T, home, alsoTrusted string) []byte {
	t.Helper()
	extra := ""
	if alsoTrusted != "" {
		// Marshalled, not concatenated: a t.TempDir() path is a host filename and
		// a quote or a backslash in it would otherwise author a different
		// document than the one this test believes it wrote.
		key, err := json.Marshal(alsoTrusted)
		if err != nil {
			t.Fatal(err)
		}
		extra = "    " + string(key) + `: {"hasTrustDialogAccepted": true},` + "\n"
	}
	body := []byte(`{
  "oauthAccount": {
    "emailAddress": "leak@example.com",
    "organizationUuid": "CANARY-ORG-UUID",
    "organizationName": "Acme"
  },
  "machineID": "CANARY-MACHINE-ID",
  "userID": "CANARY-USER-ID",
  "mcpServers": {"tmux": {"command": "CANARY-MCP-SERVER"}},
  "projects": {
` + extra + `    "` + hostTrustedOtherProject + `": {
      "hasTrustDialogAccepted": true,
      "allowedTools": ["CANARY-ALLOWED-TOOL"]
    }
  }
}
`)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return body
}

// canariesIn is the predicate both the sweep and its negative control use. One
// function, two call sites, on purpose: a sweep whose control re-implements the
// check is a sweep that can pass while the real one is broken.
func canariesIn(content []byte, canaries []string) []string {
	var hit []string
	for _, c := range canaries {
		if strings.Contains(string(content), c) {
			hit = append(hit, c)
		}
	}
	return hit
}

// hostClaude names the three host states that matter to the generated file, and
// they are three rather than two because "no host file" and "a host file that
// does not name this directory" are different hosts reaching the same answer.
type hostClaude int

const (
	noHostClaudeFile    hostClaude = iota // this host has never run Claude Code
	hostTrustsOther                       // has a file; trusts some other directory
	hostTrustsTheTarget                   // has a file; already trusts the target
)

// stageClaude resolves the real @claude profile against a throwaway home and
// runs the real staging code. It returns the generated mount.
func stageClaude(t *testing.T, host hostClaude) (policy.Mount, string, string) {
	t.Helper()
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	switch host {
	case hostTrustsOther:
		hostClaudeJSON(t, home)
	case hostTrustsTheTarget:
		// The target as Resolve will canonicalise it, which is what
		// claudeStateJSON looks up. testTree hands back a t.TempDir()-derived
		// path and /tmp is a symlink on some hosts, so writing the raw string
		// here would be testing a key snug never asks for.
		key, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatal(err)
		}
		hostClaudeJSONTrusting(t, home, key)
	}
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := claudeFiles(pol, home, false); err != nil {
		t.Fatalf("claudeFiles: %v", err)
	}
	m, ok := pol.Mounts[filepath.Join(home, ".claude.json")]
	if !ok {
		t.Fatalf("@claude staged NOTHING at ~/.claude.json. Without the mount every "+
			"assertion about its contents is vacuous — a sandbox with no file there shows "+
			"Claude Code's theme picker and its trust dialog on every run (mounts: %d)",
			len(pol.Mounts))
	}
	return m, home, target
}

// TestClaudeDotJSONIsGeneratedNotCopied is the canary sweep: not one byte of the
// host's ~/.claude.json may reach the sandbox.
func TestClaudeDotJSONIsGeneratedNotCopied(t *testing.T) {
	m, home, _ := stageClaude(t, hostTrustsOther)

	// POSITIVE CONTROLS, both required. The host file has to exist and be
	// non-empty (otherwise "no canaries" measures an empty host, not a generated
	// file), and the mount has to carry content (otherwise it measures nothing at
	// all).
	host, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil || len(host) == 0 {
		t.Fatalf("control: the host fixture is missing or empty (%v), so a clean sweep "+
			"below would prove nothing", err)
	}
	if len(m.Content) == 0 {
		t.Fatal("control: the staged mount is empty; the sweep would pass on a sandbox " +
			"with no Claude state at all")
	}
	if got := canariesIn(host, claudeCanaries); len(got) != len(claudeCanaries) {
		t.Fatalf("control: the host fixture does not carry every canary (found %v); the "+
			"sweep can only find what the fixture put there", got)
	}

	if hit := canariesIn([]byte(m.Content), claudeCanaries); len(hit) > 0 {
		t.Errorf("host bytes reached the sandbox's ~/.claude.json: %v\n"+
			"The file must be GENERATED from the resolved policy (claudeStateJSON), never "+
			"copied: the host's carries every project path on this machine, the account and "+
			"org UUIDs, the machine ID and the MCP server configuration — a host-filesystem "+
			"inventory @parent-ro deliberately does not grant. See issue #19.", hit)
	}
}

// TestCopyingTheHostFileWouldTripTheCanarySweep is the negative control for the
// test above, and it is not ceremony: CLAUDE.md records a leak check that
// matched a process name that could never appear, passed cleanly for as long as
// it existed, and measured nothing. This reconstructs the shape that shipped —
// Mount.Content set to the host's bytes verbatim — and asserts the predicate
// fires on it.
func TestCopyingTheHostFileWouldTripTheCanarySweep(t *testing.T) {
	home, _ := testTree(t)
	host := hostClaudeJSON(t, home)

	// The pre-#19 mount, rebuilt exactly: the host file's bytes, unmodified.
	old := policy.Mount{
		Guest: filepath.Join(home, ".claude.json"), Kind: policy.KindData,
		Access: policy.AccessRW, Content: policy.Secret(host),
	}
	hit := canariesIn([]byte(old.Content), claudeCanaries)
	if len(hit) != len(claudeCanaries) {
		t.Errorf("the pre-issue-19 arrangement — the host's ~/.claude.json copied verbatim — "+
			"tripped only %d of %d canaries (%v). The sweep in "+
			"TestClaudeDotJSONIsGeneratedNotCopied therefore cannot fail, which is worse "+
			"than having no sweep", len(hit), len(claudeCanaries), hit)
	}
}

// TestClaudeDotJSONKeySetIsExactlyTheDefensibleThree is the gate. Every key here
// was argued one line at a time in claudeStateJSON's doc comment; a fourth has
// not been.
//
// BOTH ARMS ARE REQUIRED, and the second is the security one. The first version
// of this test asserted `hasTrustDialogAccepted = true` unconditionally, which
// locked in a regression rather than guarding against one: writing that key for
// a directory the human has never trusted REMOVES Claude Code's trust dialog,
// and the dialog is what stops a repository's own .claude/settings.json hooks
// running at startup (A/B measured — see claudeStateJSON's doc comment). The key
// is legitimate only as a carry of the host's own answer.
func TestClaudeDotJSONKeySetIsExactlyTheDefensibleThree(t *testing.T) {
	const why = "\nAdding a key here is a policy change — argue why it is not disclosure, " +
		"see issue #19."

	// The two keys that are true of every snug run on every host. Asserted in
	// both arms, because a change that dropped one of them while getting the
	// trust arm right would otherwise pass.
	constantKeys := func(t *testing.T, top map[string]any) {
		t.Helper()
		if v, ok := top["hasCompletedOnboarding"].(bool); !ok || !v {
			t.Errorf("hasCompletedOnboarding = %v, want true — without it Claude Code blocks "+
				"on the theme picker on EVERY run ($HOME is a fresh tmpfs), and the picker's "+
				"answer is written to ~/.claude/settings.json, which cannot survive the run "+
				"either way", top["hasCompletedOnboarding"])
		}
		if v, ok := top["autoUpdates"].(bool); !ok || v {
			t.Errorf("autoUpdates = %v, want false — the binary is a read-only bind, so a "+
				"self-update inside can only fail", top["autoUpdates"])
		}
	}

	t.Run("host already trusts the target: the key is CARRIED", func(t *testing.T) {
		m, home, target := stageClaude(t, hostTrustsTheTarget)
		top := parseJSON(t, []byte(m.Content))

		// CONTROL: the fixture really does record this exact path, so a key found
		// below is a carry rather than an assertion snug invented.
		if !hostTrustsTarget(home, target) {
			t.Fatalf("control: the fixture host ~/.claude.json does not trust %q, so this "+
				"arm is not exercising the carry path", target)
		}

		if got, want := sortedKeys(top), []string{"autoUpdates", "hasCompletedOnboarding", "projects"}; !equalStrings(got, want) {
			t.Fatalf("top-level keys are %v, want exactly %v.%s", got, want, why)
		}
		constantKeys(t, top)

		projects, ok := top["projects"].(map[string]any)
		if !ok {
			t.Fatalf("projects is %T, want an object.%s", top["projects"], why)
		}
		if got, want := sortedKeys(projects), []string{target}; !equalStrings(got, want) {
			t.Fatalf("projects names %v, want exactly the ONE directory the human typed on "+
				"the command line, %v. The host's file pre-accepted trust for every project "+
				"path on the machine, including %q; snug's carries the answer for the target "+
				"and no other.%s", got, want, hostTrustedOtherProject, why)
		}
		entry, ok := projects[target].(map[string]any)
		if !ok {
			t.Fatalf("projects[%q] is %T, want an object.%s", target, projects[target], why)
		}
		if got, want := sortedKeys(entry), []string{"hasTrustDialogAccepted"}; !equalStrings(got, want) {
			t.Fatalf("projects[%q] carries %v, want exactly %v — allowedTools above all must "+
				"NOT be here: an approval given in a host session is not an approval given "+
				"inside the sandbox.%s", target, got, want, why)
		}
		if v, ok := entry["hasTrustDialogAccepted"].(bool); !ok || !v {
			t.Errorf("hasTrustDialogAccepted = %v, want true — the host records this exact "+
				"directory as trusted, so snug carries that answer and Claude Code does not "+
				"ask a question the human has already answered", entry["hasTrustDialogAccepted"])
		}
		if len(m.Content) > 1024 {
			t.Errorf("the generated file is %d bytes; three keys cannot need that. Something "+
				"host-derived has got in.%s", len(m.Content), why)
		}
	})

	// The regression arm. A host file exists and DOES record a trusted project —
	// just not this one.
	t.Run("host has not trusted the target: NO projects key at all", func(t *testing.T) {
		m, home, target := stageClaude(t, hostTrustsOther)
		top := parseJSON(t, []byte(m.Content))

		// POSITIVE CONTROL, and it is what makes the absence below mean anything:
		// the very same reader, over the very same file, DOES find the trust entry
		// for the other project. So "false for the target" is a fact about the
		// path, not a parser that cannot see a trust entry, a fixture that was
		// never written, or a home the lookup is not reading.
		if !hostTrustsTarget(home, hostTrustedOtherProject) {
			t.Fatalf("control: hostTrustsTarget cannot see the trust entry the fixture "+
				"records for %q, so its answer for the target measures the reader rather "+
				"than the host's decision", hostTrustedOtherProject)
		}
		if hostTrustsTarget(home, target) {
			t.Fatalf("control: the fixture host ~/.claude.json trusts the target %q; this "+
				"arm must exercise an UNTRUSTED directory", target)
		}

		if got, want := sortedKeys(top), []string{"autoUpdates", "hasCompletedOnboarding"}; !equalStrings(got, want) {
			t.Fatalf("top-level keys are %v, want exactly %v — with the host not trusting "+
				"this directory there must be NO projects key.\n"+
				"Writing projects.%q.hasTrustDialogAccepted here removes Claude Code's "+
				"trust dialog for a directory nobody has ever trusted. MEASURED A/B on a "+
				"target whose only content is .claude/settings.json with a SessionStart "+
				"hook: with the key, no dialog and the HOOK FIRES; without it, \"Quick "+
				"safety check\" blocks and the hook does not run. The sandbox holds the "+
				"staged Anthropic OAuth token and @claude is commonly combined with @net.%s",
				got, want, target, why)
		}
		constantKeys(t, top)
	})

	t.Run("host has never run Claude Code: NO projects key either", func(t *testing.T) {
		m, home, _ := stageClaude(t, noHostClaudeFile)
		top := parseJSON(t, []byte(m.Content))

		// CONTROL: there really is no host file, so this is the absent-file path
		// rather than a fixture that quietly wrote one.
		if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
			t.Fatal("control: the fixture home HAS a ~/.claude.json")
		}
		if got, want := sortedKeys(top), []string{"autoUpdates", "hasCompletedOnboarding"}; !equalStrings(got, want) {
			t.Fatalf("top-level keys are %v, want exactly %v. A host with no ~/.claude.json "+
				"has trusted nothing, and an unreadable or unparseable file is the same "+
				"answer: omit the key, never fail the run.%s", got, want, why)
		}
		constantKeys(t, top)
	})
}

// TestWritingTheTrustKeyUnconditionallyFailsTheUntrustedArm is that arm's
// positive control, and it is not ceremony: the shape it reconstructs SHIPPED,
// and the test that was supposed to catch it asserted the key must be present.
//
// It rebuilds the pre-fix generator — the trust entry written for pol.Target
// with no reference to the host at all — and asserts the untrusted arm's
// predicate (the top-level key set) fires on it.
func TestWritingTheTrustKeyUnconditionallyFailsTheUntrustedArm(t *testing.T) {
	_, _, target := stageClaude(t, hostTrustsOther)

	preFix, err := json.MarshalIndent(map[string]any{
		"autoUpdates":            false,
		"hasCompletedOnboarding": true,
		"projects": map[string]any{
			target: map[string]any{"hasTrustDialogAccepted": true},
		},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	got := sortedKeys(parseJSON(t, preFix))
	if equalStrings(got, []string{"autoUpdates", "hasCompletedOnboarding"}) {
		t.Fatalf("the pre-fix arrangement — projects.<target>.hasTrustDialogAccepted written "+
			"unconditionally — has the key set %v, which is the one the untrusted arm of "+
			"TestClaudeDotJSONKeySetIsExactlyTheDefensibleThree accepts. That assertion "+
			"therefore cannot fail on the shape it exists to forbid", got)
	}
}

// parseJSON is the one decoder both arms use, so a document that Claude Code
// could not parse fails as a parse error rather than as a missing key.
func parseJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("the generated ~/.claude.json is not valid JSON (%v); Claude Code parses "+
			"this file at startup:\n%s", err, body)
	}
	return top
}

// TestClaudeDotJSONIsGeneratedWithNoHostFile locks in the second half of the
// change: the mount no longer depends on the host having the file. Before this,
// stage() returned silently when os.ReadFile failed, so the sandbox's Claude
// state varied with the host's — a machine that had never run Claude Code got a
// sandbox with the theme picker in front of it.
func TestClaudeDotJSONIsGeneratedWithNoHostFile(t *testing.T) {
	m, home, _ := stageClaude(t, noHostClaudeFile)

	// CONTROL: there really is no host file, so this is measuring the absent
	// case rather than a fixture that quietly wrote one.
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		t.Fatal("control: the fixture home HAS a ~/.claude.json, so this test is not " +
			"exercising the host-absent path")
	}
	if len(m.Content) == 0 {
		t.Fatal("no content was generated on a host with no ~/.claude.json")
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(m.Content), &top); err != nil {
		t.Fatalf("the generated file is not valid JSON: %v", err)
	}
	if m.Access != policy.AccessRW {
		t.Errorf("the staged file is %v; Claude Code rewrites it at runtime, and the point "+
			"of a private tmpfs copy is that the rewrite goes nowhere", m.Access)
	}
	if m.Perms == nil || *m.Perms != 0o600 {
		t.Errorf("Perms = %v, want 0600", m.Perms)
	}
	if !m.Authored {
		t.Error("the mount is not Authored — Policy.Replace marks it, and --dry-run's " +
			"CLAUDE block and the NOT GRANTED block both key on it")
	}
}

// TestClaudeGuidanceDoesNotClaimTheHostJSONIsStaged covers the third site the
// false justification lived at: the ~/.claude/CLAUDE.md snug writes into the
// agent's own $HOME. It is the one a reader cannot check against the code, so a
// stale sentence there costs turns rather than review time.
func TestClaudeGuidanceDoesNotClaimTheHostJSONIsStaged(t *testing.T) {
	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"})
	got := string(claudeGuidance(p))

	for _, dead := range []string{"re-" + "onboard", "IS staged"} {
		if strings.Contains(got, dead) {
			t.Errorf("the injected guidance still contains %q:\n%s", dead, got)
		}
	}
	// The two behaviour changes an agent would otherwise diagnose as breakage.
	// Named rather than merely absent-checked: silence about them is what costs
	// the turns.
	for _, want := range []string{"no MCP servers configured", "approve a tool the human already"} {
		if !strings.Contains(got, want) {
			t.Errorf("the injected guidance does not say %q. /mcp being empty and a tool "+
				"prompt the human already answered on the host are both consequences of "+
				"generating this file, and an agent that has not been told will spend turns "+
				"treating them as misconfiguration:\n%s", want, got)
		}
	}
	// Both statements are SCOPED, and the scope is the correction. "No MCP
	// servers" is true of the host's user config and says nothing about a
	// .mcp.json committed in the target, which is in the project tree and is
	// still read; "settings do not persist" is true of $HOME and false of the
	// target, which is writable AND persistent and is where Claude Code puts a
	// project-scope permission grant. An unqualified sentence in a file an agent
	// treats as ground truth is a wrong answer it will act on.
	for _, want := range []string{".mcp.json", "persists"} {
		if !strings.Contains(got, want) {
			t.Errorf("the injected guidance never mentions %q, so one of its two absolute "+
				"claims is unscoped:\n%s", want, got)
		}
	}
}

// TestClaudeGuidanceDescribesTheGeneratedSettingsFile replaces the two-armed
// version of this test that existed while ~/.claude/settings.json was an
// OPTIONAL read-only bind of the host's file (removed by issue #17). There is
// no longer a bound/unbound arm to distinguish — claudeGuidance's paragraph
// about this path is now a single, unconditional sentence, true on every host,
// because stageClaudeSettings always generates the file and it is always
// writable (a private tmpfs copy, exactly like ~/.claude.json). What varies
// between hosts is the CONTENT (which allowlisted keys survived), never
// whether the file is bound or read-only — see
// TestClaudeSettingsFilterDropsEveryExecutingKey and its siblings in
// internal/policy for that half.
func TestClaudeGuidanceDescribesTheGeneratedSettingsFile(t *testing.T) {
	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}
	got := string(claudeGuidance(resolveFor(t, sel)))
	if strings.Contains(got, "read-only bind") {
		t.Errorf("the guidance still calls ~/.claude/settings.json a read-only bind of the "+
			"host's file. Issue #17 replaced that bind with a file snug GENERATES from an "+
			"allowlist, and it is WRITABLE — a private tmpfs copy, the same shape as "+
			"~/.claude.json — so no sentence here may say read-only:\n%s", got)
	}
	if !strings.Contains(got, "GENERATED by") {
		t.Errorf("the guidance does not say ~/.claude/settings.json is generated:\n%s", got)
	}
}

// TestNoShippedTextClaimsClaudeReonboardsWithoutTheJSON mechanises "the comment
// must die with the code".
//
// The justification for staging the host's file appeared in THREE places and was
// measured false in all three; it survived a milestone because a comment cannot
// fail. This sweep can. It covers _test.go files too — a false claim in a test's
// doc comment is read by exactly the person deciding whether the test still
// means anything — which is why the needles below are spelled in two pieces:
// otherwise this file would be its own first hit and the sweep could never pass.
//
// Fixed strings, never a regex alternation: CLAUDE.md records a sweep that could
// not fire because an unescaped pattern never matched what it was looking for.
func TestNoShippedTextClaimsClaudeReonboardsWithoutTheJSON(t *testing.T) {
	needles := []string{
		"re-" + "onboard",
		"re" + "onboard",
		"Both files " + "are needed",
		"needed as " + "well as",
	}

	var files []string
	for _, pat := range []string{"*.go", "../../internal/profile/profiles/*.toml"} {
		got, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, got...)
	}
	// CONTROL: the globs must actually resolve. A sweep over an empty file list
	// is the pasta.avx2 mistake in its purest form.
	if len(files) < 2 {
		t.Fatalf("the sweep found %d files (%v); it is measuring nothing", len(files), files)
	}
	sawClaudeGo, sawBaseTOML := false, false
	for _, f := range files {
		switch filepath.Base(f) {
		case "claude.go":
			sawClaudeGo = true
		case "base.toml":
			sawBaseTOML = true
		}
	}
	if !sawClaudeGo || !sawBaseTOML {
		t.Fatalf("the sweep did not reach internal/cli/claude.go (%v) and "+
			"internal/profile/profiles/base.toml (%v), which are two of the three sites the "+
			"false justification lived at", sawClaudeGo, sawBaseTOML)
	}

	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if strings.Contains(string(b), n) {
				t.Errorf("%s contains %q. MEASURED (claude 2.1.232): with ~/.claude.json "+
					"absent Claude Code connects and works; it is .credentials.json that is "+
					"load-bearing. What IS lost without the generated file is the theme "+
					"picker and the trust dialog, and both are stated in those terms. See "+
					"issue #19.", f, n)
			}
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestClaudeGuidanceDoesNotClaimSiblingProjectsAreAbsent.
//
// The sentence this pins was UNCONDITIONAL and false under the DEFAULT
// selection. It read "every other project on this machine [is] not hidden —
// [it was] never mounted, and read as **absent**", and the defaults are
// `@sys @home @cwd-rw @parent-ro`: @parent-ro binds the target's PARENT
// read-only, so every sibling of the target is readable. Reported from inside a
// real run (issue #461) — "Sibling project directories alongside the target ...
// are present and fully readable from inside the sandbox."
//
// Both arms are asserted, because only the pair distinguishes "derived" from
// "the sentence was deleted". The negative control is the second arm: with no
// read-only ancestor grant the absence claim is TRUE and must still be made,
// otherwise this test would pass on a guidance file that had simply stopped
// saying anything about other projects.
//
// Why a test and not just the fix: the shipped sentence had no test at all,
// which is how a false claim about the read boundary survived in the one file
// whose own header says it "describes what is actually true".
func TestClaudeGuidanceDoesNotClaimSiblingProjectsAreAbsent(t *testing.T) {
	t.Run("with @parent-ro the guidance says reads are NOT confined", func(t *testing.T) {
		sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro", "@claude"}
		pol := resolveFor(t, sel)
		got := string(claudeGuidance(pol))

		if strings.Contains(got, "every other project on this machine") {
			t.Errorf("@parent-ro grants the target's parent read-only, so sibling projects ARE "+
				"readable, and the guidance still makes the unconditional absence claim:\n%s", got)
		}
		if !strings.Contains(got, "Reads are NOT confined") {
			t.Errorf("the guidance does not tell the agent that reads reach outside the "+
				"project:\n%s", got)
		}
		// The grant must be NAMED. "reads are unconfined" without the path is a
		// warning an agent cannot act on.
		parent := filepath.Dir(pol.Target)
		if !strings.Contains(got, parent) {
			t.Errorf("the guidance warns that reads are unconfined but never names %q, the "+
				"grant that makes them so:\n%s", parent, got)
		}
	})

	t.Run("control: without it the absence claim is true and is still made", func(t *testing.T) {
		sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}
		got := string(claudeGuidance(resolveFor(t, sel)))

		if strings.Contains(got, "Reads are NOT confined") {
			t.Errorf("no read-only ancestor of the target is granted here, so nothing makes "+
				"a sibling readable, and the guidance warns about one anyway:\n%s", got)
		}
		if !strings.Contains(got, "reads as\n**absent**") {
			t.Errorf("the guidance no longer says other projects read as absent, which is "+
				"TRUE for this selection — the sentence was deleted rather than derived:\n%s", got)
		}
	})
}
