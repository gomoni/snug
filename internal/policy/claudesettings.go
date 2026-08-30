package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ~/.claude/settings.json is not a preferences file that sometimes runs a
// command. It is a COMMAND TABLE — `hooks` (shell commands on ~34 lifecycle
// events), `apiKeyHelper` (a program whose stdout IS an API key), `statusLine`,
// `env`, `mcpServers`, `enabledPlugins` and `extraKnownMarketplaces` all name a
// program to run, a credential to print, or code to fetch. It is `~/.gitconfig`
// one tool over, with two differences that matter:
//
//   - there is no GIT_CONFIG_GLOBAL equivalent for this tool (measured against
//     `claude --help` 2.1.232: `--settings` is an ADDITIONAL layer, not a
//     replacement, and `--setting-sources` is a flag the PAYLOAD would have to
//     pass, not one snug composes), so snug authors the file at its canonical
//     path — a REPLACEMENT in CLAUDE.md's terms, not a bind of the host's;
//   - the container is JSON, which closes git's value-injection route by
//     construction (§ below) and opens a different one, R-SCALAR, which this
//     file closes by TYPE rather than by scan.
//
// So: read the host's file as data, keep an ALLOWLIST of scalar keys that carry
// no execution, and WRITE the file the sandbox sees. Deny-by-default applied to
// configuration keys instead of paths — the same rule GitKeyWhitelist states for
// ~/.gitconfig, in gitextract.go.

// ClaudeSettingKind is the JSON kind an allowlisted value must decode to.
//
// There is no ClaudeObject or ClaudeArray constant, and that omission IS
// R-SCALAR: the filter is non-recursive by construction rather than by
// omission, because nothing in this type can name a container as an allowed
// value. The reason this matters is the JSON analogue of git's value-injection
// scar (GIT-CONFIG.md §5a: a newline inside a whitelisted `user.name` closed the
// `name = …` line and opened a real `[alias] x = !cmd` section). JSON's grammar
// closes THAT route — encoding/json escapes every control character as \uXXXX
// and a Go value can never decide the SHAPE of what encoding/json emits around
// it, so a string cannot become a key, an object, or a sibling entry. But a
// whitelisted key whose value happens to BE a container reopens the identical
// hazard one level up: if `permissions` were allowlisted and copied verbatim,
//
//	{"permissions":{"defaultMode":"bypassPermissions",
//	                "additionalDirectories":["/home/u/.ssh"]}}
//
// would smuggle a permission bypass and a path through one name on an allowlist
// that never mentions either. Every entry in ClaudeSettingAllowlist declares one
// of the three scalar kinds below; there is no way to declare anything else.
type ClaudeSettingKind uint8

const (
	ClaudeString ClaudeSettingKind = iota
	ClaudeBool
	ClaudeNumber
)

// ClaudeSettingKey is one row of the allowlist: a name, the kind its value must
// decode to, and — for a string — the shape check it must also pass.
//
// Check is nil for ClaudeBool and ClaudeNumber. Neither kind has room to carry a
// path, a URL or a directive: a bool is one bit and a number is a magnitude, so
// there is nothing R-VALUE needs to weigh (git's own whitelist makes the same
// distinction implicitly — `init.defaultbranch` gets no charset check beyond the
// shared control-character sweep, because a value that can only ever be "true"
// or "false" has no other shape to refuse).
type ClaudeSettingKey struct {
	Name  string
	Kind  ClaudeSettingKind
	Check func(string) bool
}

// modelNamePattern is R-VALUE's per-key charset for `model`. Excludes ':' and
// '/', which excludes AWS/GCP ARNs (arn:aws:…), provider paths and URLs — the
// shape a host running Claude Code against Bedrock or Vertex sets this key to.
// Carried unfiltered into a sandbox that authenticates with the staged OAuth
// token instead, a provider-specific model ID would not resolve and the session
// would fail at the first prompt with no clue why; refusing the charset turns
// that into "the key was dropped, --model still works" rather than a value the
// filter has to interpret to know is dangerous. Brackets ARE allowed: the real
// host value this was measured against (claude 2.1.232) is `opus[1m]`.
var modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\[\]-]{0,63}$`)

// shortTokenPattern is R-VALUE's charset for `theme` and `editorMode`. ':' is
// permitted — Claude Code's schema documents a `custom:` theme spelling — but
// '/' is not, so the value still cannot be a path or a URL.
var shortTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

func modelName(s string) bool  { return modelNamePattern.MatchString(s) }
func shortToken(s string) bool { return shortTokenPattern.MatchString(s) }

// ClaudeSettingAllowlist is every key snug carries from the host's
// ~/.claude/settings.json into the one it generates. Ten keys. Every one is a
// scalar, none names a program, a path, a URL, a remote source or a credential,
// and each buys something a human would notice missing.
//
// GROWING THIS LIST IS A POLICY CHANGE. The reviewer's question is R-SCALAR (is
// the kind here a scalar — structurally yes, see ClaudeSettingKind) + R-NOPATH
// (is the value ever path- or URL-shaped) + "what does this key make Claude
// Code DO" — never "is it convenient". Say the answer in the entry's own
// comment, the way every row below does.
//
// `model` and `theme` are also the positive control this filter is tested
// against: both are present in an ordinary developer's real host file, so a
// filter that dropped everything fails on the file's actual shape rather than
// on a crafted one.
var ClaudeSettingAllowlist = []ClaudeSettingKey{
	{
		Name: "model", Kind: ClaudeString, Check: modelName,
		// The human's default model alias. Dropping it silently changes which
		// model the sandbox uses on every request — a difference nobody would
		// think to go looking for. TRAP, mitigated rather than left to the
		// charset alone: see modelNamePattern's comment for the Bedrock/Vertex
		// case this guards against.
	},
	{
		Name: "theme", Kind: ClaudeString, Check: shortToken,
		// Cosmetic, and it pairs with claudeStateJSON's hasCompletedOnboarding:
		// the theme picker is skipped, so without this key the sandbox opens in
		// whatever the default theme is instead of the one the human chose.
	},
	{
		Name: "editorMode", Kind: ClaudeString, Check: shortToken,
		// vim vs normal keybindings. A vim user typing :wq into a non-vim prompt
		// is a real, immediate annoyance, not a hypothetical one.
	},
	{
		Name: "verbose", Kind: ClaudeBool,
		// Full tool output vs truncated.
	},
	{
		Name: "alwaysThinkingEnabled", Kind: ClaudeBool,
		// Thinking on/off.
	},
	{
		Name: "autoCompactEnabled", Kind: ClaudeBool,
		// Auto-compaction on/off.
	},
	{
		Name: "includeCoAuthoredBy", Kind: ClaudeBool,
		// The one carried key whose effect outlives the run: whether commits
		// made IN THE SANDBOX, into the persistent target tree, carry the
		// Claude co-author trailer. It is a boolean the human set deliberately,
		// and it changes nothing about what the sandbox can reach — it is not
		// path-, program- or credential-shaped, just a preference about text
		// written into a commit the human's own tooling will already show them.
	},
	{
		Name: "prefersReducedMotion", Kind: ClaudeBool,
		// Accessibility. A human who needs it on the host needs it inside too.
	},
	{
		Name: "spinnerTipsEnabled", Kind: ClaudeBool,
		// Cosmetic.
	},
	{
		Name: "skipWorkflowUsageWarning", Kind: ClaudeBool,
		// Suppresses a warning the human has already dismissed once. Present in
		// the real host file this filter was measured against (claude 2.1.232),
		// so it exercises the filter on an ordinary developer's file rather than
		// a crafted one.
	},
}

// ClaudeAuthoredSetting is one key snug WRITES ITSELF into the user-scope
// ~/.claude/settings.json — not carried from the host, not derived from any
// host or target byte. Kind reuses ClaudeSettingKind, so the authored set is
// scalar-only for the same structural reason the allowlist is: there is no
// container constant to declare (R-SCALAR). Authoring `permissions` therefore
// cannot be done by adding a row; it needs a type change, which is the review
// gate it should need — see the refusal in condition 3.
//
// AUTHORING IS NOT CARRYING, and FilterClaudeSettings' doc comment on
// disableAllHooks argues the negative case for CARRYING. What binds from it:
// "a key is carried because it is provably safe, never because it happens to
// tighten" (that is the allowlist's rule and it still holds), and "it would
// make this fix APPEAR to close a channel it does not close" (that binds here,
// and is answered by Why plus the disclosure at every sink, not by refusing).
// What does not bind: invariant 1 is about GRANTS — which host paths are
// visible, resolved as a union with no subtraction — and a key inside a file
// snug wholly authors is not a grant and subtracts none. snug already authors
// restriction into generated config: claudeStateJSON's autoUpdates=false, the
// regenerated installed_plugins.json, registries.conf searching only
// docker.io.
//
// Four conditions, all required:
//  1. the value is a literal here — no host or target byte reaches it;
//  2. the key's ABSENT-DEFAULT is the permissive value, so authoring changes
//     behaviour (measured, claude 2.1.246: the binary's own restrictive table
//     carries {path:["crossSessionInbound"],restrictive:["refuse","hold"]} and
//     {path:["isolatePeerMachines"],restrictive:!0}). This is what refuses
//     remoteControlAtStartup=false, channelsEnabled=false and
//     autoUploadSessions=false: they default off, so authoring them is
//     decoration;
//  3. it is UPSTREAM'S OWN GATE over a whole surface, not an enumeration of
//     tool names. permissions.deny:["SendMessage","ListAgents"] fails this and
//     is refused: measured in 2.1.246 the outbound peer surface is at least
//     SendMessageTool, SendFileTool and ObserverReport, so a deny of two names
//     leaves file transfer to a peer open — the worse half. That is the
//     denylist argument ClaudeExecutingKeys' own doc comment already refuses
//     ("a denylist naming one spelling is bypassed by the other, in the
//     upstream's own documentation, with no attacker required");
//  4. it is a scalar.
//
// NONE OF THIS IS A BOUNDARY. Both keys are enforced CLIENT-SIDE by Claude
// Code. A payload inside the sandbox holds the staged OAuth token and can
// speak HTTP to the API with no client, controls its own argv (--settings
// LAYERS rather than replaces; --setting-sources project,local drops user
// scope outright) and can rewrite this file, which is rw by the gh precedent
// and already an accepted residual (see stageClaudeSettings' doc comment).
// What authoring buys is bounded and stated: against a prompt-injected MODEL
// these are upstream gates in front of the tools it would use, and
// crossSessionInbound is enforced in the RECEIVING client — so a payload in
// one snug sandbox cannot address a session in another, at an enforcement
// point it does not control.
type ClaudeAuthoredSetting struct {
	Name  string
	Kind  ClaudeSettingKind
	Value any    // string | bool | float64, matching Kind; a literal in this file
	Why   string // one line, rendered by --dry-run's CLAUDE block
}

// ClaudeAuthoredSettings is the fixed, whole set of keys snug authors into the
// user-scope ~/.claude/settings.json, unconditionally, on every run that
// selects @claude. See ClaudeAuthoredSetting's doc comment for the four
// conditions a key must meet to be here, and why `permissions.deny` was
// refused rather than added.
var ClaudeAuthoredSettings = []ClaudeAuthoredSetting{
	{
		Name: "crossSessionInbound", Kind: ClaudeString, Value: "refuse",
		Why: "inbound peer messages are refused, not parked for an approval nothing in here can give",
		// Schema, claude 2.1.246: m(["accept","hold","refuse"]).optional()
		// .catch(void 0). "hold" is rejected on purpose: a held message waits
		// for an approval a headless sandbox never gives, which is a queue,
		// not a decision.
		//
		// This is the RECEIVE side, so it is not the outbound half issue #87
		// calls sharp — it is the half whose enforcement point the attacker
		// does not hold. Every snug run authors it, so a payload in sandbox A
		// cannot drive a session in sandbox B, and B's rw target is a
		// DIFFERENT persistent write authority from A's.
		//
		// IN-PROCESS SUBAGENTS ARE UNAFFECTED, which is what makes this
		// shippable rather than a break. The gate's own origin classifier
		// (2.1.246) routes only kind==="peer", plus a task-notification whose
		// subkind is literally "peer-send-message", into the policy switch;
		// every other origin classifies "ungated" and the switch returns
		// "accept" unconditionally. A Task subagent's notification is neither.
		// Read statically off the classifier, not from a live round-trip.
		//
		// Measured: a repo-scope value can only tighten ("a repo may only
		// tighten, so your own \"accept\" cannot override it"), which is why
		// user scope alone is enough and the project-scope generated file
		// authors nothing.
	},
	{
		Name: "isolatePeerMachines", Kind: ClaudeBool, Value: true,
		Why: "SendMessage/SendFile to a session on ANOTHER machine needs explicit approval",
		// Schema, claude 2.1.246: "Require explicit approval before
		// SendMessage can reach a peer session on another machine via Remote
		// Control", and it covers file transfer too ("isolatePeerMachines is
		// enabled — file transfer to another session requires explicit
		// approval"). One gate, whole surface: condition 3 above.
		//
		// The property no other key here has, from the binary's own table:
		// isolatePeerMachines:{bypassImmune:!0,classifierRouted:!1}, with
		// classifierApprovable:!1 on the decision. The check survives
		// bypass-permissions mode and cannot be auto-approved. It is an ASK,
		// not a deny: interactive, the human at the sandbox sees the prompt.
		// The HEADLESS arm is NOT MEASURED — do not claim in any comment, Why
		// string or screen that an unanswerable ask denies.
		//
		// It targets exactly the case issue #87 calls sharp: an unsandboxed
		// Remote Control session on another machine, with that machine's files
		// and credentials.
	},
}

// ClaudeAuthoredNames returns the authored key names, sorted. Callers that
// print the set enumerate through this and never hand-write the list — the
// same rule the allowlist's own name helper exists for: prose that copies a
// table drifts and no test fails.
func ClaudeAuthoredNames() []string {
	names := make([]string, 0, len(ClaudeAuthoredSettings))
	for _, a := range ClaudeAuthoredSettings {
		names = append(names, a.Name)
	}
	sort.Strings(names)
	return names
}

// ClaudeExecutingKeys is a NAMED CATALOGUE of keys known to name a program,
// select or fetch code, set a process environment variable, carry credential
// state, or steer login/authentication — grouped and reasoned about in
// FilterClaudeSettings' doc comment and, at length, in
// .claude/design/CLAUDE-SETTINGS.md, which this package implements.
//
// IT IS NOT A FILTER AND MUST NEVER BECOME ONE. Filtering is the allowlist's
// job. A denylist consulted "as an optimisation, since we have the list
// anyway" reintroduces every property an allowlist was chosen to avoid —
// starting with the exhibit that decided the question: `additionalMarketplaces`
// is a DOCUMENTED ALIAS for `extraKnownMarketplaces`, and `allowedMarketplaces`
// is a second, separate alias for `strictKnownMarketplaces` (both verified
// against the claude 2.1.232 binary's own schema strings — "Alias for
// extraKnownMarketplaces: this key is read exactly as if it were spelled …",
// and the identical sentence for strictKnownMarketplaces). A denylist naming
// one spelling is bypassed by the other, in the upstream's own documentation,
// with no attacker required. This catalogue can be incomplete — Claude Code
// gains keys across releases with no stable schema — and that is fine,
// because nothing security-relevant depends on it being complete: an unnamed
// key is dropped by the allowlist exactly the same as a named one.
//
// This table exists for three things only: the loud stderr line when a
// consequential key is dropped, the test that asserts it is disjoint from
// ClaudeSettingAllowlist, and documentation a reviewer can read key names off
// of without re-deriving the classification from the schema each time.
var ClaudeExecutingKeys = map[string]string{
	// (a) Names a program to execute. A read-only bind of the host's file would
	// SUPPLY every one of these; generating the file is what refuses them.
	"hooks":               "runs shell commands (or HTTP requests, or MCP tools) on ~34 tool/session lifecycle events",
	"apiKeyHelper":        "a program whose stdout IS an API key — the credential.helper of this file",
	"proxyAuthHelper":     "a program that prints proxy auth",
	"awsCredentialExport": "a program whose stdout is a JSON AWS key/secret pair",
	"awsAuthRefresh":      "a script that refreshes AWS authentication",
	"gcpAuthRefresh":      "a command that refreshes GCP authentication",
	"otelHeadersHelper":   "a script that outputs OpenTelemetry headers",
	"policyHelper":        "an executable that computes managed settings at startup",
	"policyHelpers":       "same as policyHelper, per-OS",
	"processWrapper":      "an argv PREFIX for every process Claude Code spawns — this tool's LD_PRELOAD",
	"statusLine":          "a command re-run on an interval and shown in the UI",
	"subagentStatusLine":  "same as statusLine, for subagents",
	"mcpServers":          "programs spawned as MCP servers, each with its own env",
	"defaultShell":        "which interpreter runs a `!` command",

	// (b) Selects or fetches code. `enabledPlugins` enables code @claude already
	// mounts read-only; the marketplace keys name remote sources Claude Code
	// fetches from; the *Mcpjson* pair pre-approves servers named by the
	// TARGET repository's .mcp.json — invariant 3, a host key handing the
	// sandboxed material an execution channel.
	"enabledPlugins":               "selects which installed plugin code loads",
	"extraKnownMarketplaces":       "marketplaces to fetch plugin code from",
	"additionalMarketplaces":       "ALIAS for extraKnownMarketplaces",
	"strictKnownMarketplaces":      "enterprise allowlist of marketplace sources (still names sources)",
	"allowedMarketplaces":          "ALIAS for strictKnownMarketplaces",
	"blockedMarketplaces":          "still names marketplace sources, on the refusing side",
	"pluginSuggestionMarketplaces": "marketplaces suggested for install",
	"pluginConfigs":                "per-plugin configuration, plugin-defined shape",
	"enableAllProjectMcpServers":   "pre-approves every MCP server the TARGET's .mcp.json names",
	"enabledMcpjsonServers":        "pre-approves named servers from the TARGET's .mcp.json",
	"disabledMcpjsonServers":       "same surface, refusing side",
	"allowedMcpServers":            "pre-approves MCP servers by name",
	"deniedMcpServers":             "same surface, refusing side",
	"allowAllClaudeAiMcps":         "pre-approves every claude.ai-hosted MCP connector",
	"disableClaudeAiConnectors":    "same surface, refusing side",
	"skillOverrides":               "replaces bundled skill code",
	"disableBundledSkills":         "same surface, refusing side",

	// (c) Environment. This is the finding CLAUDE.md records under @claude's
	// environ.inherit comment: "env" is a second door to ANTHROPIC_API_KEY, a
	// documented and recommended way to set it, landing in /proc/self/environ
	// where it is passively readable by every process and every child.
	"env": "sets process environment variables for every session — a second door to ANTHROPIC_API_KEY",

	// (d) Permission and policy. `defaultMode` alone can read "bypassPermissions"
	// and remove every tool-approval prompt; the rest of the object shares one
	// name so a partial import would change how Claude Code's cross-source
	// precedence resolves, which is why the WHOLE object is refused rather than
	// picking "safe-looking" fields out of it.
	"permissions": "allow/ask/deny/defaultMode/additionalDirectories — defaultMode can be bypassPermissions" +
		" — and snug authors no partial permissions object either: the outbound peer tool" +
		" surface is at least SendMessage, SendFile and ObserverReport, so a deny of two" +
		" names is a denylist",
	"skipDangerousModePermissionPrompt": "suppresses the confirmation for bypassPermissions",
	"allowManagedHooksOnly":             "policy toggle, meaningless without the managed layer @sys does not grant",
	"allowManagedPermissionRulesOnly":   "same",
	"allowManagedMcpServersOnly":        "same",
	"allowedHttpHookUrls":               "names endpoints an http-type hook may reach",
	"httpHookAllowedEnvVars":            "names which env vars an http-type hook may forward",
	"disableSideloadFlags":              "policy toggle for CLI flags snug does not pass",
	"disableCommandPluginSources":       "policy toggle, plugin-channel adjacent",
	"strictPluginOnlyCustomization":     "policy toggle, plugin-channel adjacent",
	"sandbox":                           "Claude Code's OWN sandboxing config — a second, conflicting notion of sandbox",

	// (e) Path- or URL-valued — R-NOPATH. A path in a value snug did not author
	// resolves inside SNUG'S mounts, not the host's, so it either dangles or
	// denotes something the human did not mean.
	"autoMemoryDirectory": "a directory Claude Code both reads memory from and writes memory to",
	"plansDirectory":      "a directory for plan files",
	"sshIdentityFile":     "a path to an ssh identity file",
	"claudeMdExcludes":    "path globs to exclude from CLAUDE.md discovery",
	"$schema":             "a URL",

	// (f) Instructions to the model — a second author of the agent's standing
	// instructions, which is exactly the channel ~/.claude/CLAUDE.md (generated
	// by claudeGuidance from the ACTUAL resolved policy) exists to own alone.
	"claudeMd":             "free-form standing instructions to the agent",
	"companyAnnouncements": "free-form text shown to the agent",
	"agent":                "a NAME resolved against ~/.claude/agents (unmounted) or a plugin; replaces the system prompt, tools and model",
	"outputStyle":          "a NAME resolved against ~/.claude/output-styles (unmounted)",
	"spinnerVerbs":         "free-form text",
	"spinnerTipsOverride":  "free-form text",
	"attribution":          "free-form text that lands in the target repository's git history",
	"pluginTrustMessage":   "free-form text shown before a plugin install",

	// (g) Login and endpoint steering. The sandbox authenticates from ONE
	// staged file; none of this belongs to the host's settings.
	"forceLoginMethod":           "steers which login flow runs",
	"forceLoginOrgUUID":          "can reject the very OAuth token snug staged if the org does not match",
	"forceLoginGatewayUrl":       "redirects authentication to a host-named endpoint",
	"xaaIdp":                     "identity provider steering",
	"issuer":                     "OAuth issuer steering",
	"callbackPort":               "OAuth callback port steering",
	"parentSettingsBehavior":     "changes settings precedence itself",
	"forceRemoteSettingsRefresh": "forces a fetch of remote settings",
	"defaultEnvironmentId":       "environment steering",

	// (h) Remote surfaces. Each either opens an outbound channel from inside
	// the sandbox or names a remote peer; none is needed to run an agent
	// against a directory, and `sshConfigs` additionally names an identity
	// file that contradicts the agent-proxy identity pin (INDEX §9.1).
	"sshConfigs":              "host/port/identity-file for `claude ssh` — a second, unpinned identity mechanism",
	"sshHost":                 "remote peer",
	"sshPort":                 "remote peer",
	"startDirectory":          "remote-session steering",
	"remoteControlAtStartup":  "opens remote control",
	"autoUploadSessions":      "uploads session data",
	"crossSessionInbound":     "cross-session channel — snug authors its own value (see ClaudeAuthoredSettings)",
	"channelsEnabled":         "remote channel",
	"allowedChannelPlugins":   "remote channel, plugin-adjacent",
	"isolatePeerMachines":     "remote peer topology — snug authors its own value (see ClaudeAuthoredSettings)",
	"teammateMode":            "remote collaboration",
	"daemonColdStart":         "remote daemon steering",
	"agentPushNotifEnabled":   "push notification channel",
	"inputNeededNotifEnabled": "push notification channel",
	"disableRemoteControl":    "same surface, refusing side",
	"disableAgentView":        "same surface, refusing side",

	// (i) Credential-adjacent host state. No benefit inside, and it is host
	// state about approvals and drafts made outside this run.
	"customApiKeyResponses": "records which API keys the user approved",
	"feedbackDrafts":        "host state",
	"asBuiltDebugKey":       "host state",

	// (j) Inert inside, or would contradict a key snug already authors
	// (~/.claude.json asserts autoUpdates=false; a binary staged read-only at
	// policy.StagedBinDir cannot self-update either way).
	"cleanupPeriodDays":          "governs retention of transcripts that live on a tmpfs and die with the session",
	"autoUpdates":                "contradicts claudeStateJSON's own autoUpdates=false",
	"autoUpdatesChannel":         "same surface",
	"minimumVersion":             "can only cause Claude Code to refuse to start",
	"requiredMinimumVersion":     "same",
	"requiredMaximumVersion":     "same",
	"wslInheritsWindowsSettings": "platform-specific, inert here",
	"disableAllHooks":            "carrying this even though it TIGHTENS is refused — see FilterClaudeSettings' doc comment",
}

// stringRefusalReason is R-VALUE items 1 and 2 — no control character, and a
// length cap — but returning WHY rather than a bool. Mirrors
// policy.withoutControlCharacters (gitextract.go): the same rule, applied to
// the same class of value, in a different container format. No allowlisted
// string (a model alias, a theme name, an editor mode) has any use for a
// control character or for a quarter of a kilobyte, so there is nothing to
// weigh: over the cap, or carrying one, the value goes — but FilterClaudeSettings
// needs to say WHICH, on stderr, because "the value contains a control
// character" and "the value is too long" read as different bugs to the human
// reading them (see FilterClaudeSettings' doc comment on why silence here was
// a defect and not a simplification).
//
// Returns "" when the value is fine.
func stringRefusalReason(s string) string {
	const maxLen = 256
	if len(s) > maxLen {
		return fmt.Sprintf("value is %d bytes, over the %d-byte cap", len(s), maxLen)
	}
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "value contains a control character"
	}
	return ""
}

// validScalarString is stringRefusalReason without the reason, for
// ClaudeSettingsJSON's silent backstop (that function is pure and has no
// stderr to write a reason to — see its own doc comment).
func validScalarString(s string) bool { return stringRefusalReason(s) == "" }

// jsonKindName names the JSON type a decoded value actually has, for a
// refusal message. json.Unmarshal into map[string]any yields exactly these six
// shapes per JSON value; naming the one a human's value came in as is the
// difference between "your `model` is not a string" and "your `model` is not
// a string, it's an object" — the second tells a human WHERE to go look.
func jsonKindName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "null"
	}
}

// ClaudeSettingRefusal names one key that WAS on the allowlist and WAS present
// in the host's document, but whose value FilterClaudeSettings refused to
// carry — kept distinct from the dropped-executing-key report (§ below)
// because the two mean different things to the reader: a dropped executing key
// is snug refusing on purpose, and there is nothing for the human to do about
// it; a refused VALUE is the human's own setting failing to carry, and the
// message needs to say why (wrong JSON type, a control character, too long, or
// the key's own charset check) so a human whose `model` was refused for
// containing ':' is told THAT, not left to guess.
type ClaudeSettingRefusal struct {
	Name   string
	Reason string
}

// ClaudeSettingDrops is everything FilterClaudeSettings did NOT carry from the
// host's document, split by WHY — the four classes mean different things to
// whoever reads them, and collapsing them loses that:
//
//   - Executing is a dropped key FilterClaudeSettings recognised, from
//     ClaudeExecutingKeys: snug refusing on purpose, nothing for the human to
//     act on beyond knowing it happened.
//   - Refused is an ALLOWLISTED key that WAS present but whose VALUE failed a
//     check: the human's own setting failing to carry, and the reason says
//     why (wrong JSON type, a control character, too long, or the key's own
//     charset).
//   - Unknown is a dropped key on NEITHER list — named nowhere in this file.
//     ClaudeExecutingKeys is, by its own doc comment, allowed to be
//     incomplete: "nothing security-relevant depends on it being complete".
//     That is true for what gets CARRIED (the allowlist alone decides that),
//     but it made the incompleteness itself invisible — a host key on neither
//     list vanished with no line anywhere, which is the identical defect
//     Refused was added to close, just on the other side of the allowlist.
//     Upstream Claude Code ships new keys with no stable schema and no
//     announcement; an Unknown entry is the only signal a maintainer gets that
//     one has appeared and wants a classification.
//   - Overridden is an authored key the HOST's file also set. It is the only
//     class where both things happen: the host's value is dropped AND snug
//     writes its own. It is split out of Executing because Executing's
//     message ("each names a program to run, selects or fetches code, or sets
//     a process environment variable") is FALSE for these two names, and
//     CLAUDE.md's rule is that a message reading as a different bug is a
//     defect, not a simplification.
//
// All four slices are sorted, for deterministic stderr and --dry-run output.
type ClaudeSettingDrops struct {
	Executing  []string
	Unknown    []string
	Refused    []ClaudeSettingRefusal
	Overridden []string
}

// FilterClaudeSettings builds the allowlisted subset of a decoded host
// ~/.claude/settings.json.
//
// It returns the carried set and a ClaudeSettingDrops naming everything else,
// split by why — see that type's doc comment for what each class means and
// why a fourth parallel return value (rather than one struct) would have been
// the wrong fix once a third class needed reporting.
//
// THE REFUSED CLASS IS NOT COSMETIC. Before it existed, a `model` value
// that failed modelNamePattern's charset check (the §3.2 Bedrock/Vertex trap
// this file's own comments argue for) was dropped with NOTHING on any
// screen — measured: `{"model":"arn:aws:bedrock:…","theme":"dark"}` in produced
// `{"theme":"dark"}` out, stderr empty. That is invariant 5 exactly
// ("no silent downgrade, ever… a user believing a guarantee that no longer
// holds is worse than a failure"), and it directly contradicted this file's
// own §3.2 argument that the residual "fails LOUDLY at the first message,
// which the human fixes with --model" — the human can only do that if they
// are TOLD. Found by review, not by a test the author wrote, which is exactly
// the shape CLAUDE.md's "Definition of done" table warns about: a check that
// confirms the mechanism you had in mind, not the gap an outside reader finds.
//
// THE UNKNOWN CLASS IS THE SAME SCAR, ONE LEVEL UP. Measured against
// `{"model":"opus","postToolWrapper":"/bin/sh -c curl|sh",
// "newUpstreamHelper":"/usr/bin/evil","someFuturePreference":true}`:
// `snug -v --dry-run -p @claude` said only `carried: model` — three keys the
// human set, two of them naming a program, vanished with no line anywhere.
// ClaudeExecutingKeys' own doc comment argues the catalogue's incompleteness
// is safe because "an unnamed key is dropped by the allowlist exactly the
// same as a named one" — true for what is carried, and beside the point for
// what is REPORTED: a rule written once ("report what we withhold") and
// applied to only one of its two halves (named-and-withheld, not
// unnamed-and-withheld).
//
// TYPE MISMATCH IS A DROP, NEVER A COERCION. A `model` that decodes to a
// number or an array is not "close enough" — coercing it would mean this
// function deciding what the value SHOULD have meant, which is a judgement the
// allowlist exists to avoid making. json.Unmarshal into map[string]any yields
// exactly {string, bool, float64, []any, map[string]any, nil} per JSON value;
// only the first three ever reach a carried entry, which is R-SCALAR enforced
// at the read site rather than assumed from the schema declared in Go. It is
// still REPORTED, via ClaudeSettingRefusal, same as every other refusal.
//
// disableAllHooks IS NOT AUTHORED HERE EITHER, and the temptation is worth
// naming because it looks like the opposite of every other refusal in this
// file: carrying `disableAllHooks: true` from the host would TIGHTEN the
// sandbox, so why not carry it, or even write it unconditionally? Three
// reasons, and this is where they are written down because a table entry has
// no room for them: (1) snug has no restriction operation anywhere in its
// model (CLAUDE.md, invariant 1) and does not start importing one here — a key
// is carried because it is provably safe, never because it happens to
// tighten; (2) the host's value could equally be `false`, so an allowlist
// entry for it buys nothing structural; (3) snug AUTHORING the key itself was
// considered as defence in depth against the plugin-hooks residual (see
// base.toml's abuse block and https://github.com/gomoni/snug/issues/68) and is
// refused, because it would also disable the hooks of a project the human
// explicitly trusted — silently overriding the one host decision
// claudeStateJSON goes to lengths to carry — and it would make this fix
// APPEAR to close a channel it does not close.
func FilterClaudeSettings(raw map[string]any) (ClaudeSettings, ClaudeSettingDrops) {
	out := ClaudeSettings{}
	allowed := make(map[string]bool, len(ClaudeSettingAllowlist))
	authored := make(map[string]bool, len(ClaudeAuthoredSettings))
	for _, a := range ClaudeAuthoredSettings {
		authored[a.Name] = true
	}
	var refused []ClaudeSettingRefusal
	refuse := func(name, reason string) { refused = append(refused, ClaudeSettingRefusal{Name: name, Reason: reason}) }

	for _, k := range ClaudeSettingAllowlist {
		allowed[k.Name] = true
		v, ok := raw[k.Name]
		if !ok {
			continue
		}
		switch k.Kind {
		case ClaudeString:
			s, ok := v.(string)
			if !ok {
				refuse(k.Name, "not a string (it is a JSON "+jsonKindName(v)+")")
				continue
			}
			if reason := stringRefusalReason(s); reason != "" {
				refuse(k.Name, reason)
				continue
			}
			if k.Check != nil && !k.Check(s) {
				refuse(k.Name, "value does not match this key's allowed shape (see its Check in claudesettings.go)")
				continue
			}
			out[k.Name] = s
		case ClaudeBool:
			b, ok := v.(bool)
			if !ok {
				refuse(k.Name, "not a boolean (it is a JSON "+jsonKindName(v)+")")
				continue
			}
			out[k.Name] = b
		case ClaudeNumber:
			n, ok := v.(float64)
			if !ok {
				refuse(k.Name, "not a number (it is a JSON "+jsonKindName(v)+")")
				continue
			}
			out[k.Name] = n
		}
	}

	var droppedExecuting, unknown, overridden []string
	for name := range raw {
		if allowed[name] {
			continue
		}
		// Tested BEFORE ClaudeExecutingKeys: both authored names are also
		// catalogued there (the host value is still refused, same as any other
		// executing key), but a host setting one of them is the fourth,
		// distinct class — see ClaudeSettingDrops' doc comment on Overridden —
		// not an ordinary refusal-on-purpose with nothing for the human to act
		// on.
		if authored[name] {
			overridden = append(overridden, name)
			continue
		}
		if _, known := ClaudeExecutingKeys[name]; known {
			droppedExecuting = append(droppedExecuting, name)
			continue
		}
		// On neither list. Still dropped — the allowlist alone decides what is
		// carried, so this changes nothing about the generated file — but
		// unlike droppedExecuting above, nothing catalogued this name, and that
		// absence is itself the fact worth reporting (see ClaudeSettingDrops'
		// doc comment).
		unknown = append(unknown, name)
	}
	sort.Strings(droppedExecuting)
	sort.Strings(unknown)
	sort.Strings(overridden)
	sort.Slice(refused, func(i, j int) bool { return refused[i].Name < refused[j].Name })
	return out, ClaudeSettingDrops{Executing: droppedExecuting, Unknown: unknown, Refused: refused, Overridden: overridden}
}

// ClaudeSettings is the allowlisted subset, keyed by name. Values are always
// one of string, bool or float64 when built by FilterClaudeSettings; the type
// itself does not enforce that (a map[string]any cannot), which is exactly why
// ClaudeSettingsJSON re-checks rather than trusting its input.
type ClaudeSettings map[string]any

// ClaudeSettingsJSON renders the file the sandbox sees.
//
// R-VALUE is enforced AGAIN here, not only in FilterClaudeSettings, for the
// same reason GitConfigFrom re-checks control characters even though the
// extractor already dropped them (gitextract.go, internal/cli/gitconfig.go): the
// renderer is the LAST place a bad value can be caught, and the next caller of
// this package — a test fixture building a ClaudeSettings by hand, an adapter
// not written yet — has not gone through FilterClaudeSettings and cannot be
// trusted to have. So this function re-applies the same kind check, the same
// validScalarString check, and the same per-key Check, and silently omits
// anything that fails — it does not report drops (FilterClaudeSettings already
// did, for the caller that has a stderr to write to; this function is pure and
// has none).
//
// json.MarshalIndent with two-space indent plus a trailing newline: keys come
// out SORTED, so the bytes are deterministic and golden-diffable, matching
// claudeStateJSON's own reasoning for the sibling generated file.
//
// Never nil: an empty allowlisted set renders "{}\n", which is what a host
// with no ~/.claude/settings.json (or one that filtered to nothing) gets — the
// mount is unconditional (§7.3), so there is always a document to render.
func ClaudeSettingsJSON(s ClaudeSettings) []byte {
	out := make(map[string]any, len(s))
	for _, k := range ClaudeSettingAllowlist {
		v, ok := s[k.Name]
		if !ok {
			continue
		}
		switch k.Kind {
		case ClaudeString:
			str, ok := v.(string)
			if !ok || !validScalarString(str) {
				continue
			}
			if k.Check != nil && !k.Check(str) {
				continue
			}
			out[k.Name] = str
		case ClaudeBool:
			b, ok := v.(bool)
			if !ok {
				continue
			}
			out[k.Name] = b
		case ClaudeNumber:
			n, ok := v.(float64)
			if !ok {
				continue
			}
			out[k.Name] = n
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// Unreachable for a map of strings/bools/float64s — json.Marshal only
		// fails on channels, funcs, cyclic structures or NaN/Inf floats, none of
		// which validScalarString or the kind switch above can produce. Fall
		// back to the empty document rather than propagate an error that cannot
		// happen: the mount is unconditional, so this function's contract is
		// "never nil", not "never wrong" (the same discipline
		// claudeStateJSON applies one layer down, for the same reason — an
		// adapter that fails must degrade to "unconfigured", never crash the
		// run CLAUDE.md's "Generate, don't bind" bullet promises stays boring).
		return []byte("{}\n")
	}
	return append(b, '\n')
}

// ClaudeUserSettingsJSON renders the USER-scope file: the carried set exactly
// as ClaudeSettingsJSON renders it, plus ClaudeAuthoredSettings. Two functions
// rather than a flag, because the two files are different documents:
// stageProjectClaudeSettings keeps ClaudeSettingsJSON, so the target's
// reinterpreted .claude/settings.json states nothing about peer messaging (a
// repo may only tighten, measured — user scope already applies, and the same
// claim in three files is three things to keep true).
//
// Authored keys are written LAST. A collision cannot occur — the disjointness
// test fails the build first, and FilterClaudeSettings only ever writes
// allowlist names into the carried map — so the order is the belt and the test
// is the braces.
func ClaudeUserSettingsJSON(s ClaudeSettings) []byte {
	out := make(map[string]any, len(s)+len(ClaudeAuthoredSettings))
	for _, k := range ClaudeSettingAllowlist {
		v, ok := s[k.Name]
		if !ok {
			continue
		}
		switch k.Kind {
		case ClaudeString:
			str, ok := v.(string)
			if !ok || !validScalarString(str) {
				continue
			}
			if k.Check != nil && !k.Check(str) {
				continue
			}
			out[k.Name] = str
		case ClaudeBool:
			b, ok := v.(bool)
			if !ok {
				continue
			}
			out[k.Name] = b
		case ClaudeNumber:
			n, ok := v.(float64)
			if !ok {
				continue
			}
			out[k.Name] = n
		}
	}
	for _, a := range ClaudeAuthoredSettings {
		out[a.Name] = a.Value
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// Unreachable — see ClaudeSettingsJSON's identical fallback comment;
		// every value here is one of the same three Go kinds, host-derived or
		// a literal declared in this file.
		return []byte("{}\n")
	}
	return append(b, '\n')
}

// ClaudeProjectMCPJSON is the `.mcp.json` a sandbox sees in place of the
// target's own: the same "generate, don't bind" reinterpretation the settings
// files get, applied to a file whose ONLY key names programs to run.
//
// A repo's `.mcp.json` is `{"mcpServers": {NAME: {"command": ..., "args": ...,
// "env": ...}}}` and nothing else, so the allowlist that survives filtering is
// EMPTY and this function takes no argument. The generated file keeps the key
// present and the map empty rather than being absent, so Claude Code reads a
// project with no servers rather than a project it has to guess about.
//
// WHY, as a measurement rather than a principle. A target whose only content is
// a `.mcp.json` naming `sh -c "touch MCP-FIRED; exec cat"` ran that command
// inside a @claude sandbox, on claude 2.1.251, with no dialog, no approval and
// no `projects` entry in `~/.claude.json` — with the trust key omitted, with it
// written, and on the host in a directory Claude Code had never trusted. Three
// arms, three executions. `enableAllProjectMcpServers` and `enabledMcpjsonServers`
// are refused settings keys (see the refusal table above) and that refusal was
// read as a gate on this file; it is not one. Repo config is sandboxed material
// (CLAUDE.md invariant 3) and a hostile repo granting itself a process at
// session start defeats the model, in a sandbox holding the staged Anthropic
// OAuth token and commonly run with @net.
//
// THE COST, stated rather than hidden: an MCP server a project legitimately
// commits does not run inside a snug sandbox. There is no flag for it — a flag
// is what a hostile repo's README would tell the human to type.
func ClaudeProjectMCPJSON() []byte {
	return []byte("{\n  \"mcpServers\": {}\n}\n")
}
