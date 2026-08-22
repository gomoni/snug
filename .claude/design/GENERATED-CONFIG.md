# Generating a tool's configuration inside the sandbox

**Status: the rule.** Several files are generated under it today, four with a
design document of their own — [`GIT-CONFIG.md`](GIT-CONFIG.md) (`@git-ro`,
`~/.gitconfig`), [`CLAUDE-SETTINGS.md`](CLAUDE-SETTINGS.md) (`@claude`,
`~/.claude/settings.json`), [`STORAGE-CONF.md`](STORAGE-CONF.md) and
[`SIGNATURE-POLICY.md`](SIGNATURE-POLICY.md) (the container engine's
`storage.conf` and `policy.json`) — and the rest are the container engine's,
authored in `internal/engine`: `containers.conf` (issue #133) and
`registries.conf` (#137). **Count them in the tree, not here.** The engine ones
arrived for a reason this document did not anticipate and which is worth
carrying: under a **derived** mount view, a config naming a path snug does not
own is a path snug cannot move, so authoring the file stopped being tidiness and
became load-bearing.

`policy.json` is the one that is a PROJECTION rather than an allowlisted
reconstruction, and the difference is the rule's sharpest edge. The others answer
"which keys carry no execution" and drop the rest; this one answers "can snug
reproduce this requirement faithfully", because the host configured an
enforcement posture and generating a permissive file over it would be snug
deciding that verification does not apply here. Where it cannot reproduce, it
refuses the run — a drop would be the silent downgrade.

`npm`, `cargo`, `docker` and `pip` are queued
behind them in CLAUDE.md's "Generate, don't bind" bullet. This document is what
the next adapter starts from, so it does not rediscover any of this. The
measurements stay in the instance documents and are cited here; what is here is
only what generalises.

---

## 0. The rule

> Where the sandbox needs a tool configured, snug reads the host's config file
> **as data**, keeps an **allowlist** of keys that carry no execution,
> **generates** the file the sandbox sees, and points the tool at it with that
> tool's own env var where the tool has one. It never binds the host's.

Stated as the property to defend: *the configuration a tool sees inside the
sandbox contains exactly the entries snug named, with values snug checked, and
nothing else, whatever the host's file contains.*

Two independent reasons, and both matter. A bind carries every unrelated thing
in that file — measured: while `@git-ro` still bound `~/.gitconfig`, selecting
it alongside a pinned `[identity]` put the host's credential helpers,
`insteadOf` rules and `user.email` back beside the pin. And the env var that
points at a generated file carries a **path, not a credential**:
`/proc/self/environ` is passively readable by every process in the sandbox and
inherited by every child, while a file has to be deliberately opened.

The rest of this document is the nine things that turned out to be needed to
make that one sentence hold.

---

## 1. Classify the file first: data, or command table

Before binding — or generating — any config file, answer one question and put
the answer in the profile's abuse sentence:

- **data** — the tool reads values out of it and does nothing else with them;
- **command table** — some key names a program the tool will execute.

**Read-only does not demote the second into the first.** It stops the sandbox
*editing* the file and it supplies every command in it. That is the whole
finding, and it has now been made twice:

| file | keys that name a program |
|---|---|
| `~/.gitconfig` | `credential.helper`, `alias.x = !cmd`, `core.pager`, `core.editor`, `core.sshCommand`, `core.fsmonitor`, `diff.*.textconv`, `filter.*.clean/smudge`, `uploadpack.packObjectsHook` |
| `~/.claude/settings.json` | `hooks`, `apiKeyHelper`, `statusLine`, `mcpServers`, `processWrapper`, `defaultShell`, the AWS/GCP/OTEL credential helpers, `policyHelper` |

The classification is a property of the **format**, not of this host's file. A
file with no `credential.helper` in it today is still a command table, because
the next `git config --global` writes one. So the question is never "does my
file contain something dangerous", it is "**what can a key in this format make
the tool DO**".

Both profiles got the abuse sentence wrong in the same direction before they got
it right. `@git-ro`'s said *"any secrets you unwisely put in `~/.gitconfig`"* —
the wrong noun (secrets, not commands) and the wrong owner (the user's
carelessness, not the file's purpose). It was written once, at authoring time,
was honest when written, and nothing re-read it as `GIT_CONFIG_GLOBAL`, identity
pinning and credential staging grew around it. **A comment cannot fail**, which
is why the check is now mechanical:
`TestNoBuiltinGrantsACredentialOrCommandTablePath` (`internal/profile`) refuses
this class of path in any BUILTIN, with no allowlist and no flag. When a grant
trips it the answer is a generator, never an exception. A human writing the same
grant in their own `profiles.d` is making a declaration about their own machine,
which invariant 3 puts outside the sandboxed material; what must never happen is
snug shipping that decision for everyone.

---

## 2. Allowlist, never denylist

> The generated file is BUILT by copying named keys out of the parsed host
> document into a fresh document. There is no code path that copies a key snug
> did not name. Adding a name is a policy change, and the question to answer
> first is not "is it convenient" but "what does this key make the tool DO".

### 2.1 The deciding property is what happens to a key nobody has heard of

- **Allowlist**: unknown key → **dropped**. The setting is unconfigured inside.
  Visible, annoying, harmless — which is exactly the degradation §9 names as the
  accepted bound for every per-tool adapter.
- **Denylist**: unknown key → **carried**. If it names a program, snug supplies
  it, and nothing on any screen says so.

An adapter is a thing nobody maintains between releases of the tool it adapts.
The shape whose *neglect* produces a leak is the wrong shape, whatever it costs
in churn.

### 2.2 The alias exhibit — a denylist is defeated by the upstream's own docs

Two instances, both verified verbatim against the claude 2.1.232 binary's own
schema strings (`CLAUDE-SETTINGS.md` §2.1):

- `additionalMarketplaces` is a documented **alias** for
  `extraKnownMarketplaces`;
- `allowedMarketplaces` is a second, separate alias for
  `strictKnownMarketplaces`.

Both are spelled out in the vendor's documentation as "read exactly as if it
were spelled …". A denylist naming one spelling is bypassed by the other, with
**no attacker involved** — a user who typed the other name gets the key carried.
An allowlist has no spelling problem: neither name is on it.

This is the strongest single argument in the section, and it is worth
generalising past aliases. Any mechanism by which two strings mean the same key
— aliases, case folding, dotted-vs-nested spellings, a deprecated name kept
working — is a denylist bypass and a no-op for an allowlist.

### 2.3 The arithmetic, once

`~/.claude/settings.json` carries roughly 150 keys with no stable
machine-readable schema. A denylist written from issue #17's own opening list
(`hooks`, `apiKeyHelper`, `env` "at minimum") would have carried **21** keys
that name a program, fetch code or steer authentication, on a schema that had
just been read once, carefully (`CLAUDE-SETTINGS.md` §2.2). The allowlist for
the same file is ten rows.

### 2.4 It is the same rule the rest of snug is built from

`policy.GitKeyWhitelist` is three keys. TOML parsing uses
`DisallowUnknownFields()`, so an unknown key is a fatal parse error rather than
a carried one. Invariant 2 is deny-by-default over **paths**; this is
deny-by-default over **configuration keys**. A denylist here would be the one
subtractive mechanism in a codebase whose central claim is that it has none.

### 2.5 A named catalogue of dangerous keys is allowed — as a REPORTER, never as a filter

`policy.ClaudeExecutingKeys` exists and is ~90 entries. It is not a filter and
must never become one; its doc comment says so at length, and
`TestClaudeSettingsAllowlistAndExecutingCatalogueAreDisjoint` asserts a name
cannot be on both lists (with a non-empty control, so disjointness cannot pass
trivially). It exists for exactly three things:

1. the stderr line that names a consequential key snug withheld (§6a);
2. the disjointness test;
3. documentation a reviewer can read key names off without re-deriving the
   classification from the vendor's schema each time.

The property that makes this safe is that **the catalogue may be incomplete and
nothing security-relevant changes**: an unnamed key is dropped by the allowlist
exactly like a named one. If you ever find yourself consulting such a catalogue
to decide whether to *carry* something, you have written a denylist and §2.1
applies again.

---

## 3. The value channel is per-container — and reconstruct, never edit

**A whitelist of KEYS is half a rule.** The red team defeated the first version
of `@git-ro` through values, not keys, and it defeated the whole design rather
than a corner of it.

### 3.1 INI: the grammar is the hazard

git config values may legally span lines. `git config --file … --list -z`
returns the embedded newline faithfully, and the renderer wrote it verbatim, so

```
[user]
	name = "evil\n[alias]\n\tanything = !touch /tmp/PWNED"
```

produced a generated `~/.gitconfig` containing a real `[alias]` section;
`git anything` inside the sandbox ran the command. All three whitelisted keys
worked as the carrier. The property that made it work is INI's: **the value's
terminator is a byte that can legally appear in a value, and section structure
is expressed by those same bytes.**

The guard there is a **scan**: extracted values that carry a control character
are dropped, named on stderr, and **not escaped** — escaping into git's
`"…\n…"` form is one more quoting rule to get subtly wrong, and no name, email
address or branch needs a control character (`GIT-CONFIG.md` §5a).

### 3.2 JSON: the encoder is the guard, and that is a different reason

`~/.claude/settings.json` is immune to §3.1 by construction, and it is important
to know *why*, because the next reader will reasonably assume the git scar
transfers:

- structure (`{`, `}`, `:`, `,`, nesting) is emitted by `encoding/json` **from
  Go values**. A string value cannot become a key, an object or a sibling entry,
  because nothing in the input decides the shape of the output;
- `encoding/json` escapes `"` and `\` and escapes every control character
  U+0000–U+001F as `\uXXXX`. A newline in a value produces `\n` *inside a JSON
  string*, which the tool's parser reads back as a newline in that value and
  nothing else.

So INI is made safe by snug's scan and JSON is made safe by the encoder. **Same
outcome, different load-bearing component.** snug still refuses control
characters in carried JSON strings (`CLAUDE-SETTINGS.md` §5.3) — not because the
container needs it, but because those values reach `--dry-run`'s screens, which
invariant 7 governs: a newline or an ESC there forges or erases a row in the
artifact a human reads to decide whether to trust the sandbox.

**When you add a container, say which half is doing the work before you claim
safety.** For a format nobody here has adapted yet, the questions are the same
two: can a value's bytes terminate the value and open a new directive (INI, and
anything line-oriented), and can a value carry a *directive of its own* that the
tool acts on (YAML anchors, aliases and tags are the obvious candidate, and no
measurement has been made here — make one before you generate YAML).

### 3.3 The general rule: reconstruct from parsed values, never edit host bytes

> The filter parses the host's document into a map and **builds a new
> document** from the allowlisted entries. It never edits, patches,
> deletes-from, or re-serialises the host's bytes.

Editing was considered for `settings.json` and refused. An editor must find
every occurrence of every bad key in bytes it did not write, in a dialect the
tool may read differently from snug — Claude Code reads **JSONC** (the binary
carries `Failed to set JSONC property` and jsonc array-insertion strings), so
comments, trailing commas, duplicate keys and unusual escapes all become places
where snug's view and the tool's view can differ, and **every such difference is
a key snug believes it removed and the tool still reads**. Reconstruction has no
such surface: the output contains exactly the entries snug put there.

Two consequences fall straight out.

- **Duplicate keys stop being a question.** JSON permits them; Go's decoder
  takes the last; the tool's parser may or may not agree. It does not matter,
  because the tool **never sees the host's bytes** — whatever snug's decoder
  resolved is rendered exactly once into a document with one entry per key.
  Reconstruction is what makes a parser-differential unexploitable rather than
  merely unlikely.
- **Symlinks stop being a leak.** `os.ReadFile` follows them, so a config path
  that symlinks to `~/.ssh/id_ed25519` *is read* — and cannot leak, because the
  content fails the decode and even a file that parsed could only contribute
  allowlisted, type-checked, charset-checked scalars. Contrast the bind: it
  follows the identical symlink and mounts the target file **whole**.

---

## 4. R-SCALAR — the filter is non-recursive by construction

> Every allowlisted value must be a scalar: a string, a boolean, or a number.
> No object, no array, ever.

The container-format analogue of "a value that authors a directive" is **a value
that is itself a container**. A non-recursive filter over a recursive container
is a key whitelist with a hole exactly the shape of the container:

```json
{ "permissions": { "defaultMode": "bypassPermissions",
                   "additionalDirectories": ["/home/u/.ssh"] } }
```

One name on the allowlist, and every key beneath it rides in unnamed — a
permission bypass and a path, neither of which any allowlist mentioned.

The implementation detail is the point: `policy.ClaudeSettingKind` has three
constants (`ClaudeString`, `ClaudeBool`, `ClaudeNumber`) **and no container
constant**, so an allowlist entry cannot declare a container as an allowed
value. That is a stronger statement than "the current allowlist happens to
contain no objects", and it is the form to copy. The type check is also applied
at the *read* site rather than trusted from the schema: a decoded value whose Go
type does not match the declared kind is dropped, never coerced — coercion would
mean the filter deciding what the value should have meant, which is the
judgement the allowlist exists to avoid making.

If a future key genuinely needs an object, it needs a **per-key recursive
sub-whitelist**, which is its own policy change with its own review — not a
relaxation of R-SCALAR at the top.

Note that `permissions` is thereby refused twice: once as policy (importing
another tool's permission model), once as structure. Belt and braces on the key
that can spell `bypassPermissions`.

---

## 5. R-NOPATH — no allowlisted key is path-valued or URL-valued

> A path or URL in a config value is a **reference resolved inside the
> sandbox**, so its meaning is decided by snug's mounts, not by the host's
> intent. Both outcomes are bad. If the path does not exist inside, the feature
> dangles and the failure mode is unmeasured. If it *does* exist inside, it
> denotes something different from what the human meant: `~/x` is a fresh tmpfs
> and `{target}` is the untrusted material. **A path in a file snug generates is
> authored by snug from the resolved policy, or it is not there.**

This rule is new with the Claude adapter and neither older document has it,
because git's three-key whitelist happens to carry no path — an accident of that
whitelist's size, not a property of git. The one path in a generated
`~/.gitconfig` is `safe.directory = *`, and snug writes it itself, from its own
knowledge that the bind's owner and the sandbox uid differ.

The sharp instance is `autoMemoryDirectory`: it names a directory Claude Code
both **reads memory from and writes memory to**. Pointed at anything inside the
target tree it makes the untrusted repository the source of the agent's
persistent memory — and the vendor's own schema note ("Ignored if set in
projectSettings … for security") shows upstream reached the same conclusion one
scope down.

**Make it mechanical, not editorial.** The way R-NOPATH is enforced is a per-key
charset that cannot spell a path: `model` matches
`^[A-Za-z0-9][A-Za-z0-9._\[\]-]{0,63}$`, which excludes `/` and `:` and
therefore excludes ARNs, provider paths and URLs; `theme`/`editorMode` allow `:`
(the vendor documents a `custom:` theme spelling) and still refuse `/`. A rule
that lives only in a reviewer's head is a rule that ships broken the first time
someone adds a key in a hurry.

---

## 6. Carrying can be worse than dropping

Ask of every candidate key: **if this key's referent is not inside the sandbox,
what happens?** Three answers, and only the first two can ever be carried:

- *inert* — nothing happens. Carrying buys nothing and costs a name a reviewer
  must audit forever. Drop it. (`cleanupPeriodDays` governs retention of
  transcripts that live on a tmpfs and die with the session.)
- *degraded* — a feature is missing and the human can see why. Carryable if it
  buys something.
- *hard failure* — the run dies, or dies worse than it would have without the
  key. **Never carry it.**

The worked instances, one per adapter:

- **`commit.gpgsign = true`** with a signing key that is not inside makes
  **every commit fail** — worse than an unsigned commit. The whitelist
  deliberately omits `user.signingkey`, `gpg.format`, `commit.gpgsign` and
  `tag.gpgsign` for that reason, and grows again only when signing has a design
  (issue #35).
- **`apiKeyHelper`** is `credential.helper` one tool over, and it fails in
  *both* directions. A helper that resolves inside substitutes a credential; one
  that does not resolve leaves the sandbox with "Your apiKeyHelper script is
  failing" **and a credential selector that still considers a non-OAuth
  credential configured** — while the OAuth token `@claude` staged sits unused
  two files away. Carrying the key can neutralise the one file the profile
  exists to provide.
- **`forceLoginOrgUUID`** can make the sandbox reject the very token snug
  staged. **`requiredMinimumVersion`** has no possible effect inside except a
  refusal to start.
- **`model` on a Bedrock/Vertex host** is the mitigated case: the host sets a
  provider-specific ID that will not resolve against an OAuth session, so the
  charset refuses it (§5) and the human is told (§6a) rather than the key being
  dropped from the allowlist for everyone.

### 6.1 The tightening trap

`disableAllHooks: true` is the key that looks like the opposite of every other
refusal here: carrying it would *tighten* the sandbox. It is refused, and so is
snug authoring it, for three reasons worth writing down so nobody re-invents
them:

1. **snug has no restriction operation anywhere in its model** (invariant 1) and
   does not start importing another tool's. A key is carried because it is
   provably safe, never because this host's value happens to be safe.
2. The host's value could equally be `false`, so an allowlist entry buys nothing
   structural.
3. snug authoring it unconditionally would also disable the hooks of a project
   the human **explicitly trusted** — silently overriding the one host decision
   the generated `~/.claude.json` goes to lengths to carry — and it would make
   the fix *appear* to close a channel it does not close (§8.2), on an upstream
   key snug does not control.

---

## 6a. Every drop is named — a refusal the human is not told about is a silent downgrade

Invariant 5 has no adapter-shaped exception. This project has now had to learn
it twice on the same kind of code, so it is a section rather than a sentence.

**First time, git.** A value carrying a control character is dropped, **named on
stderr**, not escaped; `includeIf "hasconfig:"` and `"onbranch:"` are ignored
and **named**, because silence would leave a human whose config uses them
wondering why the sandbox commits under a different identity from the host.

**Second time, Claude Code, in code that was written, tested and green.**
`FilterClaudeSettings` originally returned two values — the carried set, and the
dropped keys that were in the catalogue. An **allowlisted** key whose value
failed its charset or type check was dropped with **nothing on any screen**.
Measured:

```
in:      {"model":"arn:aws:bedrock:us-east-1::foundation-model/claude","theme":"dark"}
out:     {"theme":"dark"}
stderr:  (empty)
```

That is exactly the Bedrock/Vertex user the charset check was written to protect
(§6), and the adapter's own argument for mitigating rather than dropping that
key was *"the residual fails loudly at the first message, which the human fixes
with `--model`"* (`CLAUDE-SETTINGS.md` §3.2) — which a human can only do **if
they are told**. The function now returns a third value,
`[]ClaudeSettingRefusal`, and
`TestClaudeSettingsReportsWhyAnAllowlistedValueWasRefused` is the regression.
It was found by reading the code, not by any test the author wrote — the shape
CLAUDE.md's definition-of-done table warns about.

Three rules fall out, and they are the reusable part:

- **Keep the two kinds of line apart.** A dropped executing key is *snug
  refusing on purpose*, and there is nothing for the human to do about it. A
  refused **value** is *the human's own setting failing to carry*, and it is
  their mistake to fix. Merging the two into one "dropped:" line loses the
  distinction that decides whether the reader should act.
- **The reason must distinguish the failure modes from each other.** "Your
  `model` has the wrong shape" and "your `verbose` is not a boolean at all" are
  different mistakes; the test asserts the two reason strings differ, because a
  single generic reason is only marginally better than silence.
- **An absent host file needs no line.** A host that never ran the tool has
  nothing to be told snug ignored. Every *other* degradation — oversized file,
  unreadable file, a dialect snug does not parse, a top-level value that is not
  an object — gets one, and none of them fails the run.

---

## 7. Pointer, inline setting, or neither

Every tool that reads a config file also reads **variables**, and they come in
two kinds that must never be confused:

- a **pointer** — the value is a PATH to a file snug generated, and a human can
  read that file: `GIT_CONFIG_GLOBAL`, `GH_CONFIG_DIR`, `NPM_CONFIG_USERCONFIG`,
  `PIP_CONFIG_FILE`, `CARGO_HOME`, `DOCKER_CONFIG`. Authoring one is the
  mechanism.
- an **inline setting** — the value IS the setting, reviewable nowhere:
  `GIT_CONFIG_KEY_n`, `GIT_CONFIG_PARAMETERS`, `npm_config_*`, `PIP_*`,
  `CARGO_BUILD_*`, and `CLAUDE_CODE_PROCESS_WRAPPER` (an argv prefix for every
  process the tool spawns — this tool's `LD_PRELOAD`). **snug authors none, and
  no shipped profile carries one.** That is asserted at the **sink**, over the
  environment a resolved policy hands over
  (`TestNoBuiltinHandsOverAnInlineConfigVariable`), not only at the parse-time
  table — `PIP_*` and `npm_config_*` are refused for `inherit` only, so `set`
  reaches the resolved policy. Adding a name to the pointer set is a policy
  change: ask what the name makes the tool DO. (`policy.IsInlineConfigEnv` does
  not yet name `CLAUDE_CODE_PROCESS_WRAPPER`: issue #69, a gap in the mechanical
  check rather than a live leak, since nothing sets it.)

### 7.1 When the tool has a pointer: generate elsewhere and point

The best case, and it buys more than tidiness. `GIT_CONFIG_GLOBAL` replaces
**both** files git merges for global scope (`~/.gitconfig` *and*
`$XDG_CONFIG_HOME/git/config`, measured both directions) — generating one of the
two was not enough. It also stops a conditional include in the host's file from
firing *inside* the sandbox.

**Count the files the tool reads at that scope before you decide one generated
file is sufficient.** git: two. Claude Code: one user-scope file, and that was
measured from the binary's own settings-source enumeration rather than assumed.

### 7.2 When the tool has none: author at the canonical path

Claude Code has no `GIT_CONFIG_GLOBAL`. Measured against `claude --help`
(2.1.232): `--settings` loads *additional* settings — a merge layer above the
user file, so it cannot bound what the user file says — and `--setting-sources`
*could* exclude the user scope but is a **payload-side flag**, typed by whoever
runs `claude`, not composed by snug. Neither is a pointer.

So snug takes the first half of the rule alone and writes the file at its
canonical path. Under CLAUDE.md's replacement-vs-masking distinction that is
**replacement**, not masking: snug authoring its own content at a path via
`Policy.Replace`, which sets `Mount.Authored` and is what `rejectMasking`
exempts. Two conditions make it clean, and both must be checked when you do this
again:

- **No profile grant may exist at that path.** `@claude` names
  `~/.claude/settings.json` under neither `ro` nor `optional`, so nothing is
  displaced and `Replace` records no `replaces:` provenance. (`Replace` appends
  one when it *does* displace something — that is how the identity files'
  overwrite of a bind stays visible.)
- **Catalogue the path** so it can never be bound again:
  `TestNoBuiltinGrantsACredentialOrCommandTablePath`'s list now contains
  `{home}/.claude/settings.json`, which can only fire on a regression.

The cost of this branch, stated because it is real: **there is no escape
hatch.** A human who dislikes snug's generated gitconfig can unset
`GIT_CONFIG_GLOBAL` in their own profile; where the file *is* the path, there is
no such move. That puts more weight on §9's bound and is a reason to keep the
allowlist small enough that a stale adapter is boring rather than broken.

---

## 8. What a generated config does NOT do

Three limits. Each one has been mistaken for a guarantee at least once.

### 8.1 It bounds the HOST's configuration, never the sandbox's own processes

Every tool reads variables that outrank its config file, absolutely. Measured,
git 2.55.0:

```
$ git config --show-origin --show-scope --get-all user.name
global   file:/home/u/.gitconfig   Pinned
command  command line:             Injected
```

`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n` enter at the **command-line** scope —
above the global file, above the repository's own `.git/config`, above any
`include` the generated file could carry. `CARGO_BUILD_*` beats
`.cargo/config.toml` (measured); `npm_config_*` and `PIP_*` are the same shape
by documentation. There is no fix, and the reasons are in `GIT-CONFIG.md` §9
with the full probe set: the payload owns its own environment exactly as it owns
its own `PATH`, every candidate wrapper is itself selected by the environment,
and a writable `$HOME` reaches the same hijack through `~/.bashrc` regardless.

The bound on that residual is worth carrying here: a process cannot poison its
parent's or a sibling's environment, so a hostile injection only ever reaches a
process the attacker itself forked — and an attacker that forks the victim
already chooses its `argv`, its `PATH` and its binary. And it does not survive
into a later `snug` run, because `$HOME` is a fresh tmpfs every time.

### 8.2 It closes the door it is about, and no other door in the same profile

The worked example is the one that is still open. `@claude` generates
`settings.json` and therefore does not supply the host's `hooks` — and **the
hook channel is not closed**, because `@claude` also binds
`~/.claude/plugins` read-only, a plugin's own manifest carries its own `hooks`
block that Claude Code loads automatically, and `installed_plugins.json` records
the installed plugin set *and their install paths* independently of
`settings.json`, inside that same bind. Measured on the development host: the
`caveman@caveman` plugin's manifest (a `SessionStart` hook) and the official
`security-guidance` plugin's (`SessionStart`, `UserPromptSubmit`, `PostToolUse`,
`Stop`, each running a shell command). Dropping `enabledPlugins` is **not known
to disable any of it**. Issue #68.

That is the **third** time a rule in this project was defeated one indirection
below the layer it was written about — the `@claude` PATH shadow slot and the
`/snug/bin` overmount are the other two. So the rule for an adapter is:

> When you generate a file, write down what the adapter does **not** close, in
> the profile's abuse block, in the guidance the sandbox reads, and in the design
> document. A claim wider than its effect is how the last three findings
> happened.

### 8.3 It does not import the host's restrictions either

An organisation's managed settings (`/etc/claude-code/managed-settings.json`)
are not visible inside: `@sys` enumerates fourteen `/etc` entries and that is not
one of them. So `permissions.deny`, `allowManagedHooksOnly`, `availableModels`
and `forceLoginOrgUUID` do not apply inside a snug sandbox. This is the same
position `GIT-CONFIG.md` §7 takes on `/etc/gitconfig` — root-owned host policy;
the sandbox is not the host — and granting it would mean granting a file full of
`policyHelper` and `processWrapper` keys. Recorded rather than accidental: issue
#70.

---

## 9. The bound that keeps the cost finite

Each adapter must track its tool's config format, and formats change under us —
`gh` rewrites `hosts.yml` on first use; Claude Code gains keys across releases
with no stable machine-readable schema. There is no version of this that is
free. What keeps it affordable is a single structural rule:

> **One opt-in profile per tool, never in `defaults`.**

An adapter nobody maintains then degrades to "that tool has no config inside the
sandbox" — visible, annoying, harmless — rather than to a leak. If you find
yourself wanting the adapter on by default because it is convenient, you are
proposing to make the failure mode a leak.

Two more properties belong to the bound rather than to any one adapter:

- **Write generated files where they cannot become executables.** Mode `0600`,
  no execute bit, and never under `policy.StagedBinDir` — a generated config has
  no business interacting with `PATH`.
- **Writable is usually right for a staged or generated config.** `gh` migrates
  a file-stored token and writes the config back; a read-only `hosts.yml` failed
  with "failed to write config after migration" (gh 2.96). Claude Code writes
  into settings files for `/theme`, `/config` and user-scope permission grants.
  A private tmpfs copy absorbs those writes and they go nowhere. The security
  delta over `ro` is nil — the payload already has arbitrary execution inside and
  nothing at that path reaches the host — but the consequence must be said out
  loud: **no test and no document may claim containment from anything written
  into a writable generated file during the run.**

### 9.1 Checklist for the next adapter

1. Classify the file: data, or command table (§1). Write the abuse sentence
   naming the classification.
2. Enumerate the tool's config sources at the scope you are replacing, from the
   tool itself, and count them (§7.1).
3. Decide pointer or canonical path (§7). If canonical path, check no profile
   grants it and catalogue it (§7.2).
4. Write the allowlist as `(name, kind, value check)` rows, scalars only (§4),
   no paths or URLs (§5), each row carrying its own "what does this make the
   tool do" comment.
5. For each candidate, ask what happens when its referent is not inside (§6).
6. Reconstruct from parsed values; never edit host bytes (§3.3).
7. Report every drop and every refused value, in two distinguishable kinds of
   line, with distinguishable reasons (§6a).
8. Name what it does not close, in three places (§8.2).
9. Ship the golden diff. A security change that produces no golden diff is
   probably untested — and note that `@claude` still has no bwrap-argv golden at
   all (issue #71).
