package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/policy"
)

// claudeFiles stages Claude Code's writable state and injects the guidance file.
//
// Read-only paths come from the `claude` profile. This handles the three things
// a profile cannot express: files that must be WRITABLE COPIES, a file whose
// content depends on the resolved policy, and a file that must be RECONSTRUCTED
// from an allowlist of the host's rather than either bound or copied.
func claudeFiles(pol *policy.Policy, home string, verbose bool) {
	if !hasProfile(pol, "@claude") {
		return
	}

	// Staged as a copy, never bound. The sandbox writes to a private tmpfs, so a
	// token it refreshes does not reach the host and a compromised agent cannot
	// rewrite your host credentials.
	//
	// ONE file is copied, and it is the only one that is load-bearing. MEASURED
	// (claude 2.1.232): delete ~/.claude/.credentials.json inside a sandbox and
	// Claude Code says "Not logged in · Please run /login" at once; delete
	// ~/.claude.json and it connects and works. This comment used to read "both
	// files are needed" and carried that decision for a milestone (issue #19)
	// while 62 KB of the host's ~/.claude.json was copied in verbatim: every
	// project path on this machine, org, email, account and user UUIDs, machine
	// ID, MCP servers, and the host's per-project tool approvals — a
	// host-filesystem inventory @parent-ro deliberately does not grant. What
	// replaces it is claudeStateJSON below: generated, at most three keys, no
	// host bytes.
	//
	// Cost, stated plainly: a token refreshed inside the sandbox is lost when it
	// exits. Sync-back would mean writing a host file from sandbox-authored
	// bytes, which is a real channel out of the sandbox; it is deliberately not
	// implemented.
	stage := func(rel string, perm uint32) {
		data, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			return // absent on this host; nothing to stage
		}
		// Wrapped here rather than at the point it is stored into Mount: data is
		// 508 bytes of accessToken/refreshToken/sk-ant key the instant ReadFile
		// returns it, so the sooner it carries the guard the fewer lines can
		// render it by accident.
		//
		// Be honest about what this does NOT achieve, because the sibling case
		// does achieve it and the difference matters: ghToken's RETURN TYPE is
		// policy.Secret, so no plaintext name for the gh token exists at all.
		// Here os.ReadFile hands back a []byte and Go offers nowhere earlier to
		// intervene, so `data` stays in scope for the rest of this closure as an
		// unguarded alias. content is the second name, not the first. Anything
		// added below must use content; a fmt of `data` still leaks and no test
		// in the tree can see it.
		content := policy.Secret(data)
		guest := filepath.Join(home, rel)
		// Policy.Replace, never a raw pol.Mounts[...] = assignment: it marks the
		// mount Authored (which is what exempts it from the masking rule — it is
		// snug's own content, not a profile mounting over another profile's
		// grant) and records anything it displaced, so --dry-run still says so.
		pol.Replace(policy.Mount{
			Guest: guest, Kind: policy.KindData, Access: policy.AccessRW,
			Content: content, Perms: &perm, From: []string{"@claude"},
		})
	}
	stage(".claude/.credentials.json", 0o600)

	// The MOUNT is unconditional, unlike stage() above: a host that has never run
	// Claude Code still gets a file here, so the sandbox never opens on the theme
	// picker for a reason that is about the host rather than about this run.
	//
	// Its CONTENT is not unconditional, and the one variable part is deliberate:
	// claudeStateJSON reads the host's ~/.claude.json for a single boolean about a
	// single directory (see its doc comment). Nothing else about the host reaches
	// this file, and the read cannot fail the run.
	//
	// A nil body means json.Marshal failed, which is unreachable for a
	// map[string]any of bools and strings. It skips the mount rather than
	// substituting a literal: the degradation is then a visible prompt inside
	// the sandbox, which is the bound CLAUDE.md puts on every per-tool adapter —
	// an adapter that stops working must degrade to "that tool is unconfigured
	// in here", never to a leak or to a file snug did not author.
	if body := claudeStateJSON(pol, home); body != nil {
		perm := uint32(0o600)
		pol.Replace(policy.Mount{
			Guest: filepath.Join(home, ".claude.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(body),
			Perms: &perm, From: []string{"@claude"},
		})
	}

	stageClaudeSettings(pol, home, verbose)

	guest := filepath.Join(home, ".claude", "CLAUDE.md")
	pol.Replace(policy.Mount{
		Guest: guest, Kind: policy.KindData, Access: policy.AccessRO,
		Content: claudeGuidance(pol), From: []string{"@claude"},
	})
}

// stageClaudeSettings generates the sandbox's ~/.claude/settings.json from an
// ALLOWLIST of the host's, and is now the ONLY thing that ever writes a mount
// at this guest path — base.toml no longer grants one (issue #17; see
// .claude/design/CLAUDE-SETTINGS.md for the full argument this function is a
// straight transcription of).
//
// WHY GENERATE RATHER THAN BIND, restated here because this is where the
// decision becomes code. ~/.claude/settings.json is not a preferences file
// that sometimes runs a command — it is a COMMAND TABLE: `hooks` runs shell
// commands on ~34 tool/session lifecycle events, `apiKeyHelper` is a program
// whose stdout IS an API key, and `statusLine`, `env`, `mcpServers`,
// `enabledPlugins` and the marketplace keys each name a program to run, a
// variable to set, or code to fetch. A read-only bind of the host's file (what
// this profile did until now) stops the sandbox EDITING it and SUPPLIES every
// one of those — the ~/.gitconfig argument (gitextract.go's doc comment), one
// tool over. So this reads the host's file as DATA, keeps
// policy.ClaudeSettingAllowlist's ten scalar keys, and writes the file the
// sandbox actually sees. The filter itself lives in internal/policy, pure and
// privilege-free; this function does the one thing that package must not: read
// a host path.
//
// UNCONDITIONAL AND WRITABLE, unlike the read-only OPTIONAL bind it replaces,
// and both are deliberate:
//
//   - Unconditional, like claudeStateJSON's ~/.claude.json: the mount now
//     exists whether or not the host has ever run Claude Code, which is what
//     lets --dry-run's CLAUDE block make one true claim about this path
//     instead of branching on host state the way describeClaude used to.
//
//   - Writable, the `gh` precedent (identity.go: gh rewrites hosts.yml on
//     first use, and a read-only copy failed with "failed to write config
//     after migration"). Claude Code writes into settings files too — the
//     binary carries `Failed to set JSONC property` and `Failed to insert
//     item into user JSONC array` — for /theme, /config and user-scope
//     permission grants. It is a private tmpfs copy, so the write goes
//     nowhere the host can see and dies with the session.
//
//     THE COST OF `rw`, AS AN ACCEPTED RESIDUAL RATHER THAN A NON-EVENT. An
//     earlier draft of this comment said "the security delta over `ro` is
//     nil, because the payload already has arbitrary execution inside and
//     nothing at this path reaches the host either way". The red team
//     measured that false on the arm that matters. It is true only on a host
//     with NO settings file, where the path was already a writable tmpfs;
//     on a host that HAS one — the common case for a profile whose whole
//     purpose is running Claude Code — `main` refused the write with EROFS
//     and this build allows it. A barrier that existed is gone, measured both
//     ways.
//
//     What that buys an attacker is the in-sandbox analogue of the shadow
//     slot CLAUDE.md states about `PATH`: one compromised step now controls
//     every LATER `claude` in the same sandbox, including one a human starts
//     at the sandbox shell. It writes `hooks` (which fire with no tool gate),
//     `permissions.defaultMode = "bypassPermissions"` (which removes every
//     approval prompt) or `apiKeyHelper` (which substitutes the credential),
//     over snug's generated file, at the canonical path Claude Code reads on
//     every start. Confirmed not to reach the host: the host's file is
//     byte-identical afterwards.
//
//     It is accepted rather than fixed, because `ro` is not available — gh
//     and Claude Code both genuinely rewrite their config, and a read-only
//     copy breaks the tool (that is the `gh` measurement above, not a
//     guess). It is written down because CLAUDE.md's rule is that "the
//     payload can rewrite it anyway" is NOT the test; whether snug hands the
//     slot over pre-installed is. Here snug does, knowingly.
//
//     No test and no document may claim CONTAINMENT from anything written
//     into this file during the run — see policy.ClaudeSettingAllowlist's
//     refusal of `disableAllHooks` for the sharpest instance of that rule.
//
// EVERY FAILURE DEGRADES TO "carry nothing" and none of them fails the run:
// absent file, unreadable file, an oversized file, invalid or JSONC-flavoured
// JSON, a top-level value that is not an object. Each is named on stderr
// (invariant 5) except an absent file, which needs no line — a host that has
// never run Claude Code has nothing to say anything about, the same silence
// claudeFiles' stage() closure already keeps for every other optional host
// file.
//
// A HAND-EDITED JSONC FILE THEREFORE CARRIES NOTHING. encoding/json refuses
// comments and trailing commas that Claude Code itself accepts, and that is a
// deliberate, named divergence rather than an oversight: writing a JSONC
// parser to track Claude Code's own is out of scope for what this profile
// buys, and a human who hits it is told why on stderr instead of left to
// wonder why their theme did not carry over.
func stageClaudeSettings(pol *policy.Policy, home string, verbose bool) {
	const readCap = 1 << 20 // 1 MiB — §5.6's read cap
	path := filepath.Join(home, ".claude", "settings.json")

	raw, degraded := loadHostClaudeSettings(path, readCap)
	if degraded != "" {
		fmt.Fprintf(os.Stderr, "snug: %s\n", degraded)
	}

	carried, drops := policy.FilterClaudeSettings(raw)
	if len(drops.Executing) > 0 {
		fmt.Fprintf(os.Stderr, "snug: ~/.claude/settings.json: dropped %s — each names a "+
			"program, selects or fetches code, or sets a process environment variable; a "+
			"read-only bind would have supplied it, so snug does not carry it into the "+
			"generated file (see policy.ClaudeExecutingKeys)\n", strings.Join(drops.Executing, ", "))
	}
	// A refusal is a DIFFERENT kind of line from the one above, and the two must
	// not be merged: dropping an executing key is snug refusing on purpose, with
	// nothing for the human to act on; a refused VALUE is the human's OWN
	// setting failing to carry — a `model` with a ':' in it, a `theme` that is
	// not a string — and invariant 5 ("no silent downgrade, ever") means they
	// are entitled to be told which key and why, not left to notice their
	// preference silently did not survive. See policy.FilterClaudeSettings' doc
	// comment for the measurement that found this missing.
	for _, r := range drops.Refused {
		fmt.Fprintf(os.Stderr, "snug: ~/.claude/settings.json: dropping %q — %s\n", r.Name, r.Reason)
	}
	// drops.Unknown is a THIRD kind of line again: a key on neither catalogue,
	// which is dropped by the allowlist exactly like a named one but was
	// previously reported nowhere — see policy.ClaudeSettingDrops' doc comment
	// for the measurement that found it. It is gated on -v rather than
	// unconditional like the two lines above, because on a host with a rich
	// settings file most of these names are ordinary future preferences, not
	// something consequential — the executing-key line above stays
	// unconditional precisely because IT is consequential, and repeating that
	// weight here would train a human to stop reading stderr. --dry-run's
	// CLAUDE block carries the same names UNCONDITIONALLY (see describeClaude):
	// that screen is the trust artifact and has no volume problem a human can
	// choose to skip, so "what did snug not carry" belongs there regardless of
	// -v even though it is optional here.
	//
	// The names are HOST-CONTROLLED — unlike drops.Executing and drops.Refused,
	// which only ever contain snug's own constant key names — so each goes
	// through visibleValue before it reaches stderr: a newline or ESC inside a
	// key name in a crafted settings.json must not be able to forge a line on
	// this screen (see dryrun.go's visibleValue and
	// TestNoSnugScreenEmitsARawControlCharacter).
	if verbose && len(drops.Unknown) > 0 {
		escaped := make([]string, len(drops.Unknown))
		for i, name := range drops.Unknown {
			escaped[i] = visibleValue(name)
		}
		fmt.Fprintf(os.Stderr, "snug: ~/.claude/settings.json: %d key(s) on neither catalogue, not "+
			"carried and not individually classified — most likely ordinary preferences upstream "+
			"added since this list was written, but if one of these matters it is a snug change: "+
			"%s\n", len(drops.Unknown), strings.Join(escaped, ", "))
	}
	// Recorded on the policy REGARDLESS of -v, so --dry-run's CLAUDE block (the
	// trust artifact) can always say what snug did not carry — see the comment
	// above. policy.Policy.ClaudeSettingsUnknown's own doc comment explains why
	// this lives on the Policy rather than being re-derived from the generated
	// file's content: the generated file is the ALLOWLISTED subset, so the
	// names of what did NOT make it are not present anywhere inside it.
	pol.ClaudeSettingsUnknown = drops.Unknown
	if verbose {
		names := make([]string, 0, len(carried))
		for k := range carried {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "snug: ~/.claude/settings.json carried: %s\n", strings.Join(names, ", "))
	}

	body := policy.ClaudeSettingsJSON(carried)
	perm := uint32(0o600)
	pol.Replace(policy.Mount{
		Guest: path, Kind: policy.KindData, Access: policy.AccessRW,
		Content: policy.Secret(body), Perms: &perm, From: []string{"@claude"},
	})
}

// loadHostClaudeSettings reads and decodes the host's ~/.claude/settings.json,
// or reports why it could not — never both, and never an error the caller must
// treat as fatal (§5.6's degradation rules: every failure here is "carry
// nothing", none of them may fail the run).
//
// OPEN FIRST, THEN STAT THE DESCRIPTOR, THEN READ THROUGH A LIMIT. All three
// steps earned their place by a red-team finding against the first version,
// which did `os.Stat` on the PATH and then `os.ReadFile`:
//
//   - `O_NONBLOCK` is what stops a FIFO at this path hanging the run FOREVER.
//     Measured: `mkfifo ~/.claude/settings.json` made `os.ReadFile` block in
//     `open(2)` waiting for a writer that never came — no sandbox, no exit
//     code, no line on any screen. That is strictly worse than the fatal error
//     the degradation rule forbids, and the doc comment three paragraphs up
//     promised it could not happen.
//   - `IsRegular` refuses the FIFO, the device and the directory outright, so
//     the read below is only ever a read of a file.
//   - `io.LimitReader` is where the CAP actually lives. Statting the path
//     first only bounded what `st_size` CLAIMED. Measured: a symlink to
//     `/dev/zero` stats as zero bytes, sailed past the size branch and took
//     the process to 3.1 GB of resident memory in two seconds, still climbing;
//     a symlink to `/proc/self/environ` likewise stats as zero and had its
//     contents read in full (only the JSON decode stopped it). A regular file
//     that grows between the stat and the read is the same bug without the
//     symlink. The stat is now a cheap early exit for the honest case, never
//     the bound.
//
// It reads maxBytes+1 so that "exactly at the cap" and "over the cap" are
// distinguishable without a second syscall.
//
// The open FOLLOWS SYMLINKS, deliberately — a human may legitimately symlink
// their settings file — so a `~/.claude/settings.json` pointing at
// `~/.ssh/id_ed25519` is read here. It cannot leak: the content fails the JSON
// decode (an ssh key is not a JSON object), and even a file that somehow
// parsed could only contribute allowlisted, type-checked, charset-checked
// scalars through FilterClaudeSettings. Contrast the bind this replaces, which
// followed the identical symlink and mounted the target file WHOLE.
func loadHostClaudeSettings(path string, maxBytes int64) (map[string]any, string) {
	// O_NONBLOCK applies to the OPEN, and for a regular file it has no further
	// effect on the reads below — it exists solely so that opening a FIFO
	// returns instead of blocking.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		// Absent, or a permission error — either way there is nothing to carry
		// and no host file the human is entitled to be told snug ignored.
		// Matches claudeFiles' stage() closure for every other optional host
		// path.
		return nil, ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Sprintf("~/.claude/settings.json could not be inspected (%v); "+
			"carrying nothing", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Sprintf("~/.claude/settings.json is not a regular file (mode %s); "+
			"carrying nothing. snug reads that path as data and will not read a FIFO, a "+
			"device or a directory there", fi.Mode())
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Sprintf("~/.claude/settings.json is %d bytes, over the %d-byte cap "+
			"snug reads for it; carrying nothing rather than reading an arbitrarily large "+
			"file into memory on every run", fi.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Sprintf("~/.claude/settings.json exists but could not be read (%v); "+
			"carrying nothing", err)
	}
	// The real cap. A file whose st_size lied — /dev/zero through a symlink,
	// anything under /proc, a file that grew since the stat — lands here.
	if int64(len(data)) > maxBytes {
		return nil, fmt.Sprintf("~/.claude/settings.json produced more than the %d-byte cap "+
			"snug reads for it (its reported size was %d); carrying nothing", maxBytes, fi.Size())
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		// Also catches "the top-level value is not an object": json.Unmarshal
		// into map[string]any refuses an array or a bare scalar with the same
		// error shape, so there is one branch for both degradations rather than
		// two.
		return nil, fmt.Sprintf("~/.claude/settings.json did not parse as strict JSON (%v) — "+
			"Claude Code itself reads JSONC (comments, trailing commas) here and snug does "+
			"not, so a hand-edited file in that dialect carries nothing into the sandbox", err)
	}
	return raw, ""
}

func hasProfile(pol *policy.Policy, name policy.ProfileName) bool {
	for _, n := range pol.Profiles {
		if n == name {
			return true
		}
	}
	return false
}

// claudeStateJSON is the ~/.claude.json snug GENERATES, replacing the 62 KB
// verbatim copy of the host's that @claude staged until issue #19.
//
// "Generate, don't bind" (CLAUDE.md), applied here exactly as it is applied to
// ~/.gitconfig and gh's hosts.yml. The whole file is at most three keys and it
// copies ZERO bytes of the host: two are preferences true of every snug run on
// every host, and the third is one BOOLEAN extracted from the host's file about
// the one directory the human typed on the command line.
//
// PER KEY, and each measurement is claude 2.1.232 inside a real snug sandbox:
//
//   - hasCompletedOnboarding — MEASURED: with the file absent, or present and
//     without this key, Claude Code opens on "Let's get started. Choose the text
//     style that looks best with your terminal" and BLOCKS on a seven-option
//     picker. That is the half of issue #19's report that was wrong: there is no
//     login prompt without ~/.claude.json, but there is onboarding. It blocks on
//     EVERY run, not once ever, because $HOME is a fresh tmpfs each time, and the
//     picker's answer is written to ~/.claude/settings.json — which is itself
//     GENERATED and writable now (stageClaudeSettings, issue #17), so the
//     picker's answer cannot survive the run for the identical reason
//     ~/.claude.json's own answer cannot: both live on a tmpfs that dies with
//     the session, and neither is ever bound from the host any more. One
//     outcome, one reason, on every host — this used to be two reasons because
//     the settings.json bind was `optional`; it no longer is (see describeClaude,
//     which used to gate a sentence on that and no longer needs to).
//     A constant; it says nothing about this host.
//
//   - autoUpdates — the binary is a read-only bind at policy.StagedBinDir, so a
//     self-update inside can only fail. MEASURED: it prints "Auto-update failed
//     · Run claude doctor" over the prompt. A preference.
//
//   - projects.<target>.hasTrustDialogAccepted — CONDITIONAL, and the condition
//     IS the key: it is written if and only if the HOST's ~/.claude.json already
//     records hasTrustDialogAccepted = true for that exact path. snug CARRIES the
//     human's own decision about one directory across into the sandbox; it never
//     makes one on their behalf.
//
//     Written unconditionally, it removes Claude Code's trust dialog for a
//     directory nobody has ever trusted — and that dialog is not cosmetic. A/B
//     MEASURED on one hostile fixture, a target whose only content is
//     .claude/settings.json carrying a SessionStart hook:
//
//     host file copied (pre-#19)   "Quick safety check" blocks   hook NOT fired
//     key written unconditionally  no dialog, "Welcome back!"    hook FIRED
//     key omitted (this code)      "Quick safety check" blocks   hook NOT fired
//
//     Deleting the projects key inside a sandbox and relaunching restores the
//     dialog, so that key is precisely what enables repo-controlled config to
//     execute at startup. `snug -p @claude <unfamiliar-repo> -- claude` is the
//     review workflow this profile exists for, the sandbox holds the staged
//     Anthropic OAuth token, and @claude is commonly combined with @net — a
//     SessionStart hook is then one line from exfiltrating it. Omitting the key
//     makes the sandbox's trust behaviour identical to what the copied host file
//     produced (MEASURED pre-#19: an untrusted target was not in `projects`, so
//     the dialog appeared), which is what stops the disclosure fix from also
//     being a trust regression.
//
//     ABSENT OR UNPARSEABLE host file: omit the key, do not fail. A host that has
//     never run Claude Code has trusted nothing, and a run must not die on a file
//     snug only consults.
//
//     PATH MATCHING is exact, against pol.Target — the path Resolve has already
//     put through EvalSymlinks, which is the same shape Claude Code records
//     (node's cwd is resolved). Claude keys trust PER DIRECTORY, so a
//     subdirectory of a trusted target is NOT trusted (launching claude from
//     {target}/sub prompts once) and a trusted subdirectory does not trust its
//     parent. Both directions fail towards the prompt, which is the safe one; a
//     prefix match would be snug widening a decision the human did not make.
//
// WHAT THIS DISCLOSES, as the measurement rather than as a reassurance. It is NOT
// "strictly narrower than what shipped before", and saying so was this file's own
// version of the bug issue #19 fixed — a comment understating what is handed
// over. Measured: the old set was the host's SEVEN project paths, the new set is
// at most {target}, and neither contains the other. The old seven were also
// INERT — all seven are absent inside a @claude sandbox, so no entry could open
// anything — while {target} is the one directory that IS mounted, writable and
// persistent, i.e. the only live entry either version ever had. The bytes got
// smaller; the DECISION got bigger, and that is the half the old sentence hid.
// Carrying the host's answer rather than asserting one is what makes the entry
// a projection of the human's decision instead of snug's.
//
// DELIBERATELY NOT HERE, each one a stated behaviour change rather than an
// oversight: oauthAccount (email, organizationName/Uuid, accountUuid),
// machineID, userID, mcpServers, projects[*].allowedTools, and the project list
// itself. Two of those absences cost something real and both are the correct
// direction. MCP servers configured on the host are not configured in here, so
// /mcp is empty BY DESIGN. And tool approvals given in a host session no longer
// carry in, so an interactive session asks again — an approval given outside the
// sandbox is not an approval given inside it. Both are said in the injected
// guidance, in base.toml's abuse block and in --dry-run's CLAUDE block, so they
// are read rather than discovered.
//
// ADDING A KEY HERE IS A POLICY CHANGE. The question to answer first is not "is
// it convenient" but "what does this disclose about the host, and what does it
// pre-answer on the human's behalf".
//
// json.MarshalIndent plus a trailing newline, because a human who cats this file
// inside the sandbox is entitled to read it; a map[string]any marshals with
// sorted keys, so the bytes are deterministic and golden-diffable.
func claudeStateJSON(pol *policy.Policy, home string) []byte {
	state := map[string]any{
		"autoUpdates":            false,
		"hasCompletedOnboarding": true,
	}
	// No `projects` key at all when the host has not trusted this directory —
	// not an empty object and not `false`. Claude Code prompts on a missing
	// entry, which is the behaviour being restored; an explicit `false` is a
	// third state nothing has measured.
	if hostTrustsTarget(home, pol.Target) {
		state["projects"] = map[string]any{
			pol.Target: map[string]any{"hasTrustDialogAccepted": true},
		}
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

// hostTrustsTarget answers exactly one question about the host: had the human
// already accepted Claude Code's trust dialog for THIS directory?
//
// It is the only thing the generated ~/.claude.json reads from the host, and it
// reads it as DATA in the sense .claude/design/GIT-CONFIG.md uses the word — one
// boolean is extracted, nothing is bound, and no host string leaves this
// function. The host's file is a command table's neighbour (mcpServers names
// programs, projects[*].allowedTools names approvals) and none of that is
// touched: the decoder below names two fields and json.Unmarshal drops the rest,
// so a key added by a future Claude Code release cannot arrive by accident.
//
// Every failure is the same failure — "not trusted" — because the only cost of
// being wrong in that direction is one prompt the human answers once, while the
// cost in the other direction is a repo-controlled SessionStart hook running
// without anyone being asked. Absent file, unreadable file, invalid JSON, a
// `projects` value that is not an object: all false.
//
// home is main.go's raw os.UserHomeDir() (the same value stage() reads host
// files from), while target is the canonicalised pol.Target — see
// claudeStateJSON's doc comment on why the match is exact.
func hostTrustsTarget(home, target string) bool {
	b, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		return false
	}
	var doc struct {
		Projects map[string]struct {
			HasTrustDialogAccepted bool `json:"hasTrustDialogAccepted"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return false
	}
	return doc.Projects[target].HasTrustDialogAccepted
}

// claudeAllowlistNames renders policy.ClaudeSettingAllowlist as a prose list,
// so every sentence describing what the generated settings.json carries is
// derived from the allowlist rather than copied out of it by hand.
//
// The allowlist is already in a fixed, reviewed order (it is a slice, not a
// map, for exactly that reason), so this preserves it rather than sorting:
// `model` and `theme` lead because they are the two a human notices, and a
// reader comparing this line against claudesettings.go should see the same
// sequence in both places.
func claudeAllowlistNames() string {
	names := make([]string, 0, len(policy.ClaudeSettingAllowlist))
	for _, k := range policy.ClaudeSettingAllowlist {
		names = append(names, "`"+k.Name+"`")
	}
	return strings.Join(names, ", ")
}

// claudeGuidance is the ~/.claude/CLAUDE.md snug injects.
//
// It is generated from the ACTUAL resolved policy rather than written once, so a
// run whose network was refused truthfully says there is no network. The point
// is not politeness: every sentence here removes a class of wasted turns, and a
// class of confusing failure that an agent would otherwise try to "fix" by
// disabling something.
func claudeGuidance(pol *policy.Policy) []byte {
	var b strings.Builder
	b.WriteString("# You are running inside snug\n\n")
	b.WriteString("snug is an unprivileged sandbox. `$SNUG=1`, and the hostname is `snug`.\n")
	b.WriteString("This file was generated for THIS run and describes what is actually true.\n\n")

	b.WriteString("## Filesystem\n\n")
	fmt.Fprintf(&b, "Only `%s` is writable and persists. ", pol.Target)
	b.WriteString("`$HOME` (with its XDG directories), `/tmp`, `~/.claude` and `/dev` are writable\n")
	b.WriteString("but **ephemeral — they are gone when this session ends**. Put anything meant\n")
	b.WriteString("to survive in the project tree.\n\n")
	b.WriteString("Everything else is read-only or absent. Secrets (`~/.ssh`, `~/.gnupg`, cloud\n")
	b.WriteString("credentials), personal data, and every other project on this machine are not\n")
	b.WriteString("hidden — they were never mounted, and read as **absent**. Do not try to reach\n")
	b.WriteString("them; there is nothing there and it wastes your turns.\n\n")

	b.WriteString("## Network\n\n")
	switch pol.Net.Mode {
	case policy.NetIsolated:
		b.WriteString("**You have no network.** Not a misconfiguration — this sandbox was started\n")
		b.WriteString("offline. Do not attempt to fetch anything, install packages, or diagnose it.\n\n")
	case policy.NetEgress:
		b.WriteString("You have internet access. You **cannot** reach services on the host's\n")
		b.WriteString("`127.0.0.1`; this is intentional and is not a misconfiguration.\n")
		if len(pol.Net.Publish) > 0 {
			b.WriteString("Ports you bind ARE visible to the host on its 127.0.0.1.\n")
		} else {
			b.WriteString("Ports you bind are NOT visible to the host.\n")
		}
		b.WriteString("\n")
	case policy.NetHost:
		b.WriteString("You share the host's network namespace. Everything the host can reach, you\n")
		b.WriteString("can reach. Be correspondingly careful.\n\n")
	}

	b.WriteString("## Tooling\n\n")
	b.WriteString("Personal skills and plugins are re-exposed read-only — invoke them normally,\n")
	b.WriteString("do not try to edit them. Host `~/.claude` history and prior sessions are NOT\n")
	b.WriteString("carried in.\n\n")
	b.WriteString("`~/.claude.json` here is GENERATED by snug and holds at most three keys. The\n")
	b.WriteString("host's file was not copied in, so **there are no MCP servers configured** from\n")
	b.WriteString("the host's user config — `/mcp` shows nothing from there by design, not because\n")
	b.WriteString("it is broken. That statement is scoped to the HOST's configuration: a\n")
	b.WriteString("`.mcp.json` committed in this project lives in the target tree, snug does not\n")
	b.WriteString("remove it, and Claude Code still reads it.\n")
	b.WriteString("No host project list, session history or cost data is present. Tool permissions\n")
	b.WriteString("approved in a host session were not carried in either, so you may be asked to\n")
	b.WriteString("approve a tool the human already approved outside. None of this is a fault to\n")
	b.WriteString("diagnose.\n\n")
	// UNCONDITIONAL, unlike the two-arm text this replaces: ~/.claude/settings.json
	// is no longer ever a bind of the host's (issue #17 removed the last profile
	// grant at this path — base.toml's [profile.claude] `ro`/`optional` no longer
	// name it), so there is exactly one true sentence about it on every host,
	// not two gated on whether the host happened to have a file.
	// ENUMERATED FROM THE ALLOWLIST, never counted by hand. An earlier draft of
	// this paragraph said "ten scalar preferences (model, theme, editorMode and
	// seven booleans)", which is a copy of state held in
	// policy.ClaudeSettingAllowlist — and CLAUDE.md's "the writable surface is
	// eight paths" bullet is the record of what happens to such a copy: the list
	// grew, the prose did not, and no test could fail. This is the one copy that
	// mattered most, because it is text an AGENT reads inside the sandbox and
	// acts on. Now the sentence cannot drift: add a key to the allowlist and it
	// appears here on the next run.
	b.WriteString("`~/.claude/settings.json` is GENERATED by snug from an allowlist of your\n")
	fmt.Fprintf(&b, "host's. Carried: %s. NOT carried:\n", claudeAllowlistNames())
	b.WriteString("`hooks`, `apiKeyHelper`, `env`, `mcpServers`,\n")
	b.WriteString("`enabledPlugins` and the marketplace keys, because each names a\n")
	b.WriteString("program to run, a credential to print, or code to fetch. THIS DOES NOT CLOSE\n")
	b.WriteString("THE PLUGIN CHANNEL: `~/.claude/plugins` is still bound read-only, and a\n")
	b.WriteString("plugin's own manifest carries its own `hooks` block that Claude Code loads\n")
	b.WriteString("automatically, independently of this file. See\n")
	b.WriteString("https://github.com/gomoni/snug/issues/68 if that matters to what you are doing.\n")
	b.WriteString("Settings you change here do not persist: it is a writable file on the\n")
	b.WriteString("`~/.claude` tmpfs, and dies with this session along with the rest of that\n")
	b.WriteString("directory, so `/theme`, `/model` and friends will not stick.\n\n")
	// The exception, stated because "settings do not persist" is otherwise
	// absolute and the target is writable AND persistent — which is exactly where
	// Claude Code puts a project-scope permission grant.
	b.WriteString("One exception, and it is not a fault either. The PROJECT persists:\n")
	fmt.Fprintf(&b, "`%s`\n", pol.Target)
	b.WriteString("is on the host's disk, so anything Claude Code writes there — including\n")
	b.WriteString("`.claude/settings.local.json`, where a project-scope permission you accept in\n")
	b.WriteString("this session goes — is still there after the sandbox exits.\n\n")
	b.WriteString("A token you refresh here does not reach the host; it is lost when this session\n")
	b.WriteString("ends.\n\n")

	if id := pol.Identity; id != nil && id.SSHMode != policy.SSHNone {
		b.WriteString("## Identity\n\n")
		if id.GhUser != "" {
			fmt.Fprintf(&b, "git, ssh and gh are scoped to the account `%s`.\n", id.GhUser)
		}
		b.WriteString("Exactly one ssh key is available for signing. You cannot enumerate or use\n")
		b.WriteString("any other key, and no key material is present in this sandbox.\n\n")
	}

	b.WriteString("## If something is missing\n\n")
	b.WriteString("An absent path or a refused connection is almost always the sandbox doing its\n")
	b.WriteString("job, not a bug to work around. Say what you needed and why; do not try to\n")
	b.WriteString("disable, escape, or reconfigure the sandbox from inside.\n")
	return []byte(b.String())
}
