package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #19: the STAGED SET for @claude, not the absence of one filename ───
//
// The finding was that ~/.claude.json — 62 KB of the host's project inventory,
// account and org UUIDs, machine and user IDs, MCP server configuration and
// per-project tool approvals — was copied verbatim into the sandbox's writable
// $HOME on a justification measured false in three places.
//
// The obvious regression test is "assert ~/.claude.json is not a host copy".
// CLAUDE.md says not to write that one: assert the SET, not the site. The
// reason is specific rather than stylistic. The mechanism that produced the
// finding is a two-line closure, stage(rel, perm), which reads a host file and
// hands it to the payload; the bug was not that ~/.claude.json was the wrong
// ARGUMENT to it, it was that nobody had enumerated what the profile hands over
// in total. A per-filename assertion passes unchanged the day someone adds
// stage(".claude/history.jsonl", 0o600) — the same class of harm at a different
// path, and the CLAUDE.md sweep the red team runs is phrased for exactly this:
// working exactly as designed, WHAT DID WE HAND OVER?
//
// So these tests enumerate every mount @claude contributes, in both directions
// it can contribute one — a file snug STAGES (Authored, delivered by memfd) and
// a path the profile BINDS — and compare the whole table against a written-down
// expectation. Adding a path, changing an access, or turning a generated file
// back into a host copy each fail with the table diffed.
//
// The load-bearing column is ORIGIN, and it is measured rather than declared:
// every host file @claude reads or could plausibly reach is seeded with a
// distinct canary before the real staging code runs, and a staged mount whose
// content carries a canary is a host copy by observation. Declaring the origin
// from the call site would make the test a restatement of the code.

// claudeHostFixture is every host path under $HOME that @claude reads today,
// plus the neighbours a future stage() call would most plausibly reach for.
// Each maps to a canary that appears nowhere else.
//
// The neighbours are not padding. ~/.claude/history.jsonl and
// ~/.claude/projects/ are the host's session transcripts and project list, and
// base.toml's abuse block promises the sandbox CANNOT read them — a promise
// that was already false for ~/.claude.json's copy of the project list, which
// is how issue #19 happened. Seeding them means the promise is measured on
// every run of `make gate` instead of re-read by a human who trusts it.
var claudeHostFixture = map[string]string{
	// TWO canaries in this one file, and the pair is the measurement issue #58
	// added. The access token LEGITIMATELY crosses — that is the credential
	// Claude Code authenticates with — while the refresh token must not, so a
	// single canary could no longer tell "projected" from "copied". Which of
	// the two appears in the staged mount is exactly the difference.
	".claude/.credentials.json": `{"claudeAiOauth":{"accessToken":"CANARY-OAUTH-ACCESS",` +
		`"refreshToken":"CANARY-OAUTH-REFRESH"}}`,
	// The canary sits in a DROPPED key, deliberately, not in `model`. `model` is
	// on policy.ClaudeSettingAllowlist, so a canary placed there would make a
	// CORRECTLY carried value look like a copy — this fixture would then report
	// "COPIED FROM HOST" on the one row the fix's whole point is to turn
	// generated, and the table below would fail for the wrong reason. `model`
	// gets a plausible value instead (the real host shape this filter was
	// measured against, claude 2.1.232: `opus[1m]`), so it exercises
	// modelNamePattern's bracket allowance while the canary lives somewhere the
	// filter is required to drop.
	".claude/settings.json":       `{"model":"opus[1m]","apiKeyHelper":"CANARY-SETTINGS-HELPER"}`,
	".claude/CLAUDE.md":           "CANARY-HOST-GUIDANCE\n",
	".claude/history.jsonl":       `{"display":"CANARY-HOST-HISTORY"}`,
	".claude/projects/index.json": `{"cwd":"CANARY-HOST-TRANSCRIPT-PATH"}`,
	".claude/todos/list.json":     `[{"content":"CANARY-HOST-TODO"}]`,
	".claude/statsig/state":       "CANARY-HOST-STATSIG\n",
	".claude.json.backup":         `{"machineID":"CANARY-JSON-BACKUP"}`,
	".local/bin/claude":           "#!/bin/sh\n# CANARY-CLAUDE-BINARY\n",
	".local/share/claude/x":       "CANARY-CLAUDE-SHARE\n",
}

// stagedFact is one row of the table: what a mount IS, not which profile line
// happens to produce it.
type stagedFact struct {
	kind   string
	access string
	perms  string
	origin string
}

func (f stagedFact) String() string {
	return fmt.Sprintf("%-5s %-2s %-7s %s", f.kind, f.access, f.perms, f.origin)
}

// originOf is the measurement. A staged mount carrying a canary is a copy of
// that host file, whatever the code that produced it believed it was doing.
func originOf(m policy.Mount, home string) string {
	if m.Kind != policy.KindData {
		if rel, err := filepath.Rel(home, m.Host); err == nil && !strings.HasPrefix(rel, "..") {
			return "bound from host ~/" + rel
		}
		return "bound from host " + m.Host
	}
	// The credentials file first, because it is the one file whose staged form
	// is neither a copy nor free of host bytes (issue #58): it is a PROJECTION,
	// and the two canaries above are what distinguish the three outcomes.
	// Checked before the generic loop, whose whole-file match this file can no
	// longer produce — the projection re-encodes, so the host's byte sequence
	// is gone even though one of its VALUES legitimately crossed.
	if bytes.Contains([]byte(m.Content), []byte("CANARY-OAUTH-REFRESH")) {
		return "COPIED FROM HOST ~/.claude/.credentials.json"
	}
	if bytes.Contains([]byte(m.Content), []byte("CANARY-OAUTH-ACCESS")) {
		return "PROJECTED FROM HOST ~/.claude/.credentials.json"
	}

	rels := make([]string, 0, len(claudeHostFixture))
	for rel := range claudeHostFixture {
		rels = append(rels, rel)
	}
	sort.Strings(rels) // deterministic when a file somehow carries two canaries
	for _, rel := range rels {
		if bytes.Contains([]byte(m.Content), []byte(claudeHostFixture[rel])) {
			return "COPIED FROM HOST ~/" + rel
		}
	}
	if bytes.Contains([]byte(m.Content), []byte("CANARY")) {
		return "COPIED FROM HOST (unrecognised canary)"
	}
	return "generated"
}

// claudeMountSet is the predicate. Both the assertion and its controls call it,
// deliberately: a control that re-implements the check can pass while the real
// check is broken, which is the shape of the pasta.avx2 scar CLAUDE.md records.
func claudeMountSet(pol *policy.Policy, home string) map[string]stagedFact {
	set := make(map[string]stagedFact)
	for guest, m := range pol.Mounts {
		if !mountFrom(m, "@claude") {
			continue
		}
		name := guest
		if rel, err := filepath.Rel(home, guest); err == nil && !strings.HasPrefix(rel, "..") {
			name = "~/" + rel
		}
		perms := "-"
		if m.Perms != nil {
			perms = fmt.Sprintf("%04o", *m.Perms)
		}
		set[name] = stagedFact{
			kind: m.Kind.String(), access: m.Access.String(),
			perms: perms, origin: originOf(m, home),
		}
	}
	return set
}

func mountFrom(m policy.Mount, profile string) bool {
	for _, f := range m.From {
		if f == profile {
			return true
		}
	}
	return false
}

// diffMountSet reports every way got differs from want, as lines a human can
// read next to the table in the test source.
func diffMountSet(got, want map[string]stagedFact) []string {
	var out []string
	for _, name := range sortedFactKeys(want) {
		g, ok := got[name]
		if !ok {
			out = append(out, "MISSING  "+name+"  want: "+want[name].String())
			continue
		}
		if g != want[name] {
			out = append(out, "CHANGED  "+name+"\n           want: "+want[name].String()+
				"\n           got:  "+g.String())
		}
	}
	for _, name := range sortedFactKeys(got) {
		if _, ok := want[name]; !ok {
			out = append(out, "EXTRA    "+name+"  got:  "+got[name].String())
		}
	}
	return out
}

func sortedFactKeys(m map[string]stagedFact) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// claudeFixtureHome builds a home where every path in claudeHostFixture exists
// and carries its canary, then resolves @claude against it and runs the real
// staging code.
//
// trustTarget picks which host the fixture is: one that has already accepted
// Claude Code's trust dialog for this target, or one that has accepted it for
// some other directory and not this one. The staged mount SET is the same either
// way — that is the table below — but the generated file's contents are not, and
// both are asserted.
func claudeFixtureHome(t *testing.T, trustTarget bool) (*policy.Policy, string, string) {
	t.Helper()
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	for rel, body := range claudeHostFixture {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// @claude marks its binds `optional`, so a path that does not exist on the
	// host is silently dropped from the policy — and a dropped row would read as
	// "we do not hand this over" in the table below when in truth it is only
	// absent from this fixture. Both directory grants therefore have to exist.
	for _, dir := range []string{".claude/skills", ".claude/plugins"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The 62 KB file's shape, with issue #19's canaries.
	if trustTarget {
		key, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatal(err)
		}
		hostClaudeJSONTrusting(t, home, key)
	} else {
		hostClaudeJSON(t, home)
	}
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := claudeFiles(pol, home, nil); err != nil {
		t.Fatalf("claudeFiles: %v", err)
	}
	return pol, home, target
}

// TestClaudeStagedSetIsExactlyThisTable is the permanent regression test for
// issue #19.
//
// ORIGIN is the column the issue turns on, and since issue #58 **no row reads
// "COPIED FROM HOST" at all**. The last one that did was .credentials.json —
// MEASURED (claude 2.1.232), deleting it inside a sandbox gives "Not logged in
// · Please run /login" at once, while deleting ~/.claude.json costs the theme
// picker and the trust dialog and nothing else — and it is now a PROJECTION:
// the access token crosses, the refresh token does not.
//
// "PROJECTED FROM HOST" is a third origin, not a softer spelling of the second,
// and the fixture is built so the table cannot blur them: the credentials file
// carries two canaries, one in the field that legitimately crosses and one in
// the field that must never. A regression to a verbatim copy puts the refresh
// canary in the mount and this row reads "COPIED FROM HOST" again.
func TestClaudeStagedSetIsExactlyThisTable(t *testing.T) {
	pol, home, target := claudeFixtureHome(t, false)
	got := claudeMountSet(pol, home)

	want := map[string]stagedFact{
		// ── staged: snug's own content, delivered by memfd ───────────────────
		//
		// GENERATED, and that is the whole of issue #19. Three keys, no host
		// bytes; see claudeStateJSON. Writable because Claude Code rewrites it
		// at runtime and the point of a private tmpfs copy is that the rewrite
		// goes nowhere.
		"~/.claude.json": {"data", "rw", "0600", "generated"},
		// The only load-bearing file: MEASURED, without it Claude Code says
		// "Not logged in · Please run /login". It was the ONE row reading
		// "COPIED FROM HOST"; since issue #58 it is a PROJECTION — the access
		// token crosses, the refresh token does not, and NO row on this table
		// reads "COPIED FROM HOST" any more.
		"~/.claude/.credentials.json": {"data", "rw", "0600", "PROJECTED FROM HOST ~/.claude/.credentials.json"},
		// snug's guidance, generated per-run from the resolved policy. RO: the
		// payload must not be able to rewrite the description of its own
		// sandbox and then read it back as truth.
		"~/.claude/CLAUDE.md": {"data", "ro", "-", "generated"},
		// GENERATED, not bound, since issue #17: ~/.claude/settings.json is a
		// COMMAND TABLE (hooks, apiKeyHelper, env, mcpServers, enabledPlugins all
		// name a program or fetch code), so a read-only bind of the host's would
		// have SUPPLIED every one of them. This row is why the fixture's canary
		// lives in `apiKeyHelper` and not `model`: `model` is allowlisted and is
		// correctly carried, so it must never read as a host copy. Writable for
		// the same `gh` reason ~/.claude.json is: Claude Code rewrites settings
		// files at runtime and the rewrite must go nowhere the host can see.
		"~/.claude/settings.json": {"data", "rw", "0600", "generated"},
		// GENERATED from the profile's plugin allowlist since issue #68:
		// installed_plugins.json is what tells Claude Code which plugins to
		// auto-load, and the host's names every plugin ever installed. snug
		// regenerates it naming only the allowlisted set (empty here — no
		// `plugins` key on @claude by default — so an empty, valid manifest that
		// still REPLACES the host's, which is the point). RO: a writable copy
		// would let the sandbox re-add an excluded plugin by writing its name
		// back, handing the allowlist straight back.
		"~/.claude/plugins/installed_plugins.json": {"data", "ro", "0600", "generated"},

		// ── bound: read-only grants written in base.toml [profile.claude] ────
		//
		// Enumerated here for the same reason as the staged rows: a `ro` line
		// added to the profile hands the payload a host path just as a stage()
		// call does, and base.toml's abuse block makes promises about host
		// session history and MCP configuration that only an enumeration can
		// keep honest.
		"/snug/bin/claude":      {"bind", "ro", "-", "bound from host ~/.local/bin/claude"},
		"~/.claude/skills":      {"bind", "ro", "-", "bound from host ~/.claude/skills"},
		"~/.claude/plugins":     {"bind", "ro", "-", "bound from host ~/.claude/plugins"},
		"~/.local/share/claude": {"bind", "ro", "-", "bound from host ~/.local/share/claude"},
	}

	// CONTROLS, all three required before a clean diff below means anything.
	if len(got) == 0 {
		t.Fatal("control: @claude contributed no mounts at all, so an empty diff would " +
			"prove nothing")
	}
	for rel, canary := range claudeHostFixture {
		b, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil || !bytes.Contains(b, []byte(canary)) {
			t.Fatalf("control: the host fixture ~/%s is missing or does not carry its "+
				"canary (%v); originOf can only observe a copy of a file that exists", rel, err)
		}
	}
	if originOf(policy.Mount{Kind: policy.KindData,
		Content: policy.Secret(claudeHostFixture[".claude/history.jsonl"])}, home) == "generated" {
		t.Fatal("control: originOf reports a verbatim host file as \"generated\"; the " +
			"ORIGIN column is not measuring anything")
	}

	if d := diffMountSet(got, want); len(d) > 0 {
		t.Errorf("the set of mounts @claude contributes has changed:\n\n  %s\n\n"+
			"This is not a table to update — it is the answer to \"working exactly as "+
			"designed, what did we hand over?\", and each row was argued.\n"+
			"  EXTRA   — a new host path is reaching the payload. What does it disclose? "+
			"base.toml promises the sandbox cannot read host session history, the MCP "+
			"configuration, the project list or other projects' transcripts.\n"+
			"  CHANGED to \"COPIED FROM HOST\" — a generated file became a host copy. That "+
			"IS issue #19: ~/.claude.json was 62 KB of project paths, account and org "+
			"UUIDs, machine and user IDs and MCP servers, handed to the payload in its own "+
			"$HOME while @parent-ro refuses it a sibling directory.\n"+
			"  CHANGED to \"rw\" — a read-only bind became writable, which reaches the host.\n"+
			"  MISSING — @claude stopped staging something Claude Code needs; check it "+
			"still starts before deleting the row.",
			strings.Join(d, "\n  "))
	}

	// The target is not part of the table above but is part of the claim: the
	// generated file names the target and NO other path, on every host. Since
	// issue #460 the trust entry is snug's own answer for the directory the human
	// typed rather than the host's answer carried across, so this is one arm, not
	// two — what must never come back is a SECOND path, which is the host
	// inventory issue #19 removed.
	// pol.Target, not the raw fixture path: it is the canonicalised form, which
	// is the key the generator writes.
	body := string(pol.Mounts[filepath.Join(home, ".claude.json")].Content)
	if !strings.Contains(body, target) {
		t.Errorf("the generated ~/.claude.json does not name the target %q, so Claude Code "+
			"asks its trust question for the one directory the human typed (issue "+
			"#460):\n%s", target, body)
	}
	if strings.Contains(body, hostTrustedOtherProject) {
		t.Errorf("the generated ~/.claude.json names %q, a project from the HOST's own file. "+
			"snug answers for the directory on the command line and for no other:\n%s",
			hostTrustedOtherProject, body)
	}
}

// TestThePreIssue19StagedSetFailsTheTable is the positive control, and it is
// the reason the test above can be believed.
//
// It reconstructs what shipped for a milestone — stage(".claude.json", 0o600),
// i.e. Mount.Content set to the host file's bytes verbatim — on top of a real
// resolved policy, and asserts the check FIRES, naming the path and the origin.
// CLAUDE.md records a leak check that matched a process name which could never
// appear: it passed cleanly for as long as it existed and measured nothing.
//
// Two dimensions are controlled separately, because the table can fail two ways
// and a control for one is not a control for the other:
//
//   - ORIGIN — the pre-#19 shape at a path that is still in the table. The set
//     of PATHS is unchanged, so only the origin column can catch it.
//   - PATHS — a hypothetical stage(".claude/history.jsonl"), the same class of
//     harm at a filename no per-file assertion would be watching.
func TestThePreIssue19StagedSetFailsTheTable(t *testing.T) {
	t.Run("origin: the host file copied verbatim, as it shipped", func(t *testing.T) {
		pol, home, _ := claudeFixtureHome(t, false)
		host, err := os.ReadFile(filepath.Join(home, ".claude.json"))
		if err != nil {
			t.Fatal(err)
		}
		perm := uint32(0o600)
		pol.Replace(policy.Mount{
			Guest: filepath.Join(home, ".claude.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(host),
			Perms: &perm, From: []string{"@claude"},
		})

		got := claudeMountSet(pol, home)
		if f := got["~/.claude.json"]; !strings.HasPrefix(f.origin, "COPIED FROM HOST") {
			t.Fatalf("the pre-issue-19 arrangement — the host's ~/.claude.json copied "+
				"verbatim — is classified as %q. The ORIGIN column therefore cannot "+
				"distinguish a generated file from a host copy, and "+
				"TestClaudeStagedSetIsExactlyThisTable cannot fail on the very shape it "+
				"exists to forbid", f.origin)
		}
		if d := diffMountSet(got, map[string]stagedFact{
			"~/.claude.json": {"data", "rw", "0600", "generated"},
		}); len(d) == 0 {
			t.Fatal("diffMountSet reports no difference between a generated ~/.claude.json " +
				"and the host's copied verbatim")
		}
	})

	t.Run("paths: a new host file staged at a filename nothing watches", func(t *testing.T) {
		pol, home, _ := claudeFixtureHome(t, false)
		want := claudeMountSet(pol, home) // the table as it stands, whatever it is

		// The next stage() call somebody adds. ~/.claude/history.jsonl is the
		// host's session transcripts — the thing base.toml's abuse block says
		// the sandbox cannot read.
		body, err := os.ReadFile(filepath.Join(home, ".claude", "history.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		perm := uint32(0o600)
		pol.Replace(policy.Mount{
			Guest: filepath.Join(home, ".claude", "history.jsonl"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(body),
			Perms: &perm, From: []string{"@claude"},
		})

		d := diffMountSet(claudeMountSet(pol, home), want)
		if len(d) == 0 {
			t.Fatal("staging an EXTRA host file under @claude produced no diff. The table " +
				"is then a per-filename assertion wearing a set's clothes: it would pass " +
				"unchanged on the day someone adds stage(\".claude/history.jsonl\", 0o600), " +
				"which is issue #19's harm at a path nothing is watching")
		}
		if !strings.Contains(strings.Join(d, "\n"), "EXTRA") ||
			!strings.Contains(strings.Join(d, "\n"), "history.jsonl") {
			t.Fatalf("the diff does not name the extra path:\n%s", strings.Join(d, "\n"))
		}
	})
}

// ── the generated content: a key SET, not three string comparisons ───────────

// claudeDisclosureKeys is issue #19's list of what the host's file hands over,
// spelled as the JSON key each arrives under. Every one of these was measured
// present in the 62 274-byte host file on the machine the issue was filed from.
var claudeDisclosureKeys = []string{
	"accountUuid",      // oauthAccount: which Anthropic account
	"allowedTools",     // per project: approvals given in a HOST session
	"emailAddress",     // oauthAccount: the human's identity
	"history",          // per project: what was typed on the host
	"machineID",        // which machine this is
	"mcpServers",       // servers the payload could read, or point elsewhere
	"oauthAccount",     // the container of three of the above
	"organizationName", // which company
	"organizationUuid", // which company, canonically
	"projects",         // THE HOST FILESYSTEM INVENTORY
	"userID",           // which user
}

// claudeHostShapedJSON is the control's input: the host file's SHAPE, carrying
// every name in claudeDisclosureKeys, with the inventory keys where they really
// live — two levels down, under projects.<absolute path>.
//
// A second fixture beside hostClaudeJSON (claudestate_test.go) rather than a
// reuse of it, because the two measure different things and merging them would
// weaken both: that one carries canary VALUES and is the input to a byte sweep,
// this one carries every KEY NAME and is the input to a key walker. This one is
// never written to disk — no code under test reads it, and the control is
// "does the walker see these names", not "does the host have this file".
var claudeHostShapedJSON = []byte(`{
  "oauthAccount": {
    "emailAddress": "you@example.com",
    "accountUuid": "0000-account",
    "organizationUuid": "0000-org",
    "organizationName": "Acme"
  },
  "machineID": "0000-machine",
  "userID": "0000-user",
  "mcpServers": {"tmux": {"command": "tmux-mcp"}},
  "projects": {
    "/home/u/some-other-project": {
      "hasTrustDialogAccepted": true,
      "allowedTools": ["Bash(git push:*)"],
      "history": [{"display": "what was typed on the host"}]
    }
  }
}`)

// claudeAllowedKeys is every key the generated file may contain, at any depth.
// A SUBSET check against this catches a key nobody has thought of yet, which is
// the half a list of forbidden names cannot cover: Claude Code adds keys across
// releases, and the file that reintroduces the finding will be the one carrying
// a name that did not exist when this test was written.
var claudeAllowedKeys = []string{
	"autoUpdates", "hasCompletedOnboarding", "hasTrustDialogAccepted", "projects",
}

// jsonKeySet walks the whole document, not just the top level. The host's
// inventory lives two levels down (projects.<path>.allowedTools), so a
// top-level-only check would miss the exact shape that shipped.
func jsonKeySet(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("not valid JSON (%v); Claude Code parses this at startup", err)
	}
	keys := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, sub := range x {
				keys[k] = true
				walk(sub)
			}
		case []any:
			for _, sub := range x {
				walk(sub)
			}
		}
	}
	walk(v)
	return keys
}

// TestGeneratedClaudeJSONCarriesNoDisclosureKey checks the content half of the
// same claim as a set operation in both directions.
//
// Run against BOTH host states. Since issue #460 the two must produce the same
// answer — no host key, no host path other than the target, exactly one projects
// entry — and running only one arm would leave a reader that crept back in
// unmeasured. TestTheGeneratedClaudeJSONDoesNotVaryWITHTheHost states the
// equality directly; this states what each arm must independently contain.
func TestGeneratedClaudeJSONCarriesNoDisclosureKey(t *testing.T) {
	t.Run("host trusts the target", func(t *testing.T) {
		generatedClaudeJSONDisclosure(t, true)
	})
	t.Run("host does not trust the target", func(t *testing.T) {
		generatedClaudeJSONDisclosure(t, false)
	})
}

func generatedClaudeJSONDisclosure(t *testing.T, hostTrusts bool) {
	t.Helper()
	pol, home, _ := claudeFixtureHome(t, hostTrusts)
	target := pol.Target
	m, ok := pol.Mounts[filepath.Join(home, ".claude.json")]
	if !ok {
		t.Fatal("nothing is staged at ~/.claude.json, so there is no content to check; a " +
			"sandbox without it shows the theme picker on every run")
	}
	got := jsonKeySet(t, []byte(m.Content))

	// CONTROL: the same walker, over a document shaped like the host's, must
	// report every name in the list. Without this, "the generated file has none
	// of them" could be true because jsonKeySet finds nothing anywhere — and
	// note that the keys the check must catch are nested two levels down, which
	// is precisely what a top-level-only walker would miss.
	hostKeys := jsonKeySet(t, claudeHostShapedJSON)
	var missing []string
	for _, k := range claudeDisclosureKeys {
		if !hostKeys[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("control: the walker did not find %v in a document that contains them, so "+
			"finding none of them in the generated file measures the walker rather than "+
			"the generator", missing)
	}

	// Direction 1 — the SUBSET check, which catches a key that does not have a
	// name in the list below yet.
	allowed := map[string]bool{}
	for _, k := range claudeAllowedKeys {
		allowed[k] = true
	}
	// The one key in this document that is DATA rather than a schema name: the
	// single entry under projects. Allowing it here is not a hole — it is
	// allowed for this exact string only, so any other path-shaped key fails,
	// and the block at the end of this test says the same thing again in the
	// terms the issue is written in (a host-filesystem inventory). It is the
	// path the human typed on the command line, which the payload can read from
	// pwd; every OTHER path is a fact about the host.
	allowed[target] = true
	var unexpected []string
	for k := range got {
		if !allowed[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Errorf("the generated ~/.claude.json carries keys that were never argued: %v\n"+
			"Allowed, at any depth: %v.\nAdding one is a policy change, and the question is "+
			"not \"is it convenient\" but \"what does this disclose about the host, and what "+
			"does it pre-answer on the human's behalf\" — see issue #19 and "+
			"claudeStateJSON's doc comment.", unexpected, claudeAllowedKeys)
	}

	// Direction 2 — the NAMED disclosure keys, so a grep for any of them lands
	// on a test that says why it must not come back.
	for _, k := range claudeDisclosureKeys {
		if !got[k] {
			continue
		}
		// `projects` is the one key in both lists, and the exception is stated
		// rather than quietly allowed: the disclosure is the LIST OF PATHS, not
		// the key. The host's named all seven projects on the machine and
		// pre-accepted trust for each; snug's names at most the one directory the
		// human typed, which the payload can already learn from pwd.
		if k == "projects" {
			continue
		}
		t.Errorf("the generated ~/.claude.json carries %q. Not one byte of the host's file "+
			"may reach the sandbox: it is a host-filesystem inventory plus the account "+
			"identifiers, handed to the payload in its own $HOME while @parent-ro refuses "+
			"it a sibling directory. See issue #19.", k)
	}

	// The inventory itself: every path-shaped value in the file must be the
	// target. This is the harm stated directly, independent of key names.
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal([]byte(m.Content), &doc); err != nil {
		t.Fatal(err)
	}
	for p := range doc.Projects {
		if p != target {
			t.Errorf("the generated ~/.claude.json names the host path %q, which is not the "+
				"target %q. The file must name at most the ONE directory given on the command "+
				"line and no other — the host's pre-accepted trust for every project on the "+
				"machine, whichever of them the payload cd'd to.", p, target)
		}
	}
	// EXACTLY ONE entry, in both arms. The count is what the host used to decide
	// and no longer does (issue #460): snug answers for the directory on the
	// command line whatever the host's own file says, so a SECOND entry is the
	// host inventory coming back and ZERO is the trust dialog coming back — the
	// prompt issue #460 exists to remove, and one this test would otherwise let
	// return silently.
	if len(doc.Projects) != 1 {
		t.Errorf("projects has %d entries, want exactly 1 (hostTrusts=%v). Two is the "+
			"host's project list reaching the sandbox (issue #19); none is Claude Code "+
			"asking \"Quick safety check\" for the directory the human typed (issue "+
			"#460).", len(doc.Projects), hostTrusts)
	}
}
