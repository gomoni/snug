# Secrets

**Status: DRAFT. Nothing here is built.** The broker is blocked on one
unauthorised measurement (issue #18) and `gh`'s answer is a menu, not a pick
(D6). §5 records what is settled; everything else is analysis of a design space,
not a decision.

**Exempt from the prose-pruning pass**, deliberately: a shipped subject's design
doc may lose its option space to the code, because the code is the answer. This
one has no code, so the option space *is* the document. Do not compress §3
before the design lands — the exploration is the asset, and the thing to fix
after it lands is the same thing that was fixed in `CLAUDE.md`: a document
narrating its own drafting history (`Struck:`, "the earlier audit", "the first
draft said").

Builds on **the earlier secrets audit**, whose findings are now
[issue #18](https://github.com/gomoni/snug/issues/18). Where this contradicts
that audit it says so and gives the measurement.

**[M]** measured on this host this pass (method in the appendix) · **[R]**
reasoned from code or docs, not executed · **[M-prior]** measured by that audit, not
re-measured.

Versions at measurement: snug `d3e6430`, claude 2.1.226, gh 2.96.0, podman
5.8.3, bwrap 0.11.2, git 2.55.0, Go 1.26.5.

**Re-checked against `ae848de` (2026-08-09), and two findings had moved.** §1.2d
is **fixed** — the profile-model hardening reduced the post-resolution writers to one and made the
masking exemption a field rather than a kind heuristic. §1.3's measurement is
**no longer reproducible on this tree**: it was taken with `@podman-socket` and
no `@net`, and the profile now includes `net` unconditionally, so the "egress
without `@net`" framing no longer names a selectable configuration. The channel
it measured is still open; reproducing it needs a pre-`ae848de` tree. Everything
else was re-verified against the code and holds; several line numbers had
drifted and are corrected.

---

## 0. The principle

Stated here because it is the thing every section below is measuring against.
It is a goal, not a description of the code: today snug injects an Anthropic
OAuth token and a GitHub token (§1), and [#18](https://github.com/gomoni/snug/issues/18)
is the work that would make this true.

> ### Secrets are never injected
>
> No credential the host holds — token, key, cookie, password — is placed inside
> the sandbox: not in a file, not in the environment, not behind a mount. Where
> the sandbox needs to *act* with an identity, snug **brokers the act**: a
> host-side helper holds the secret, speaks the tool's own protocol over a socket
> or loopback address the sandbox can reach, and applies the credential on the
> host side of the fence. The sandbox receives **authority, bounded by what the
> broker will forward and by the lifetime of the sandbox** — never the credential.
>
> Three consequences, all of them the point:
>
> 1. Exfiltrating the sandbox buys nothing that outlives the run.
> 2. The blast radius is the broker's allowlist, not the credential's scope.
> 3. The security argument lives in the broker, so the broker is small, snug's
>    own, and reviewable — **never a user-supplied script, and never a host
>    command whose arguments the sandbox chose.** A wrapper that runs a CLI on the
>    host with sandbox-chosen argv is not a broker; it is remote code execution
>    with the credential attached, and it is strictly worse than injecting it.
>
> Two honest exceptions:
>
> - **Public material is not a secret.** A public key, a username, an email, a
>   host fingerprint: generated into the sandbox on purpose.
> - **A secret with no broker is refused, not injected — unless the human names
>   it.** Where no adapter exists the tool has no credentials inside, and that is
>   the correct degradation: visible, annoying, harmless. A profile may still
>   stage a real credential, but only under a name that says so
>   (`@<tool>-credentials`), never as a side effect of a profile named after a
>   tool, never in `defaults`, always with the abuse sentence in its TOML, and
>   `--dry-run` prints it as `SECRET`.
>
> What this does **not** claim: it does not bound what the sandbox *does* with the
> authority. A broker, exactly like the ssh-agent proxy, pins the identity and the
> operation set; it cannot pin intent.

The ssh-agent proxy (`internal/sshproxy`) is the one shipped instance: no key
material inside, one pinned key, other keys not enumerable, signing available
only while the sandbox lives.

**And read §3.3's warning in the same breath.** The target directory persists
and the sandbox writes to it. A `Makefile`, a git hook, an `.envrc`, a
`package.json` `postinstall`, a `.vscode/tasks.json` — every one runs **on the
host, as you, with all your credentials**, the next time you do the ordinary
thing in that directory. "Secrets are never injected" must never be read as "the
sandbox cannot get your secrets". It cannot get them *now*; it can arrange to be
handed them later.

---

## 0b. The three sentences this document is trying to make true

1. It should be possible to say, of any credential, *why* it is or is not
   allowed inside a snug sandbox, in one line, without appeal to taste.
2. A tool with no adapter should degrade to "that tool has no credentials
   inside" — visible, annoying, harmless — never to a leak, and never to a
   fallback.
3. When we do put authority inside, it should be authority we can end by ending
   the sandbox.

---

## 1. Ground truth

### 1.1 What snug touches today

The earlier audit's table is right in shape and wrong or incomplete in five places. The
column that matters most is the last, and the earlier audit did not have it.

| # | secret | where it lands | who can read it | authority | outlives sandbox? |
|---|---|---|---|---|---|
| 1a | Anthropic OAuth **access** token | `KindData` writable-tmpfs copy at `~/.claude/.credentials.json` (`internal/cli/claude.go:49`) | every process in the sandbox | `user:inference`, `user:profile`, `user:file_upload`, `user:mcp_servers`, `user:sessions:claude_code` **[M]** | **yes, ~8 h** **[M]** |
| 1b | Anthropic OAuth **refresh** token | *same file, same line* | same | mints new access tokens | **yes, ~20 days remaining of a rolling window** **[M]** |
| 2 | ~~`~/.claude.json`, 56 500 bytes verbatim~~ | **FIXED** (issue #19) — GENERATED, at most three keys, no host bytes (`claudeStateJSON`, `internal/cli/claude.go`); measured 284 bytes inside, against 62 274 on this host. The third key is snug's own trust answer for the target, in that sandbox only (§3.5, issue #460) | — | — | — |
| 3 | ~~`ANTHROPIC_API_KEY`~~ | **FIXED** — removed from `@claude`'s `env`; Claude now authenticates from the staged `.credentials.json` | — | — | — |
| 4 | GitHub token from `gh auth token` | `oauth_token:` in a generated `hosts.yml` (`identity.go:192`) | every process in the sandbox | on this host: `admin:public_key`, `gist`, `read:org`, `repo` **[M]** | **yes, indefinitely** |
| 5 | ssh private keys | **never** (`internal/sshproxy`) | nothing — no key material crosses | signing oracle, one pinned key | **no** — dies with the proxy |
| 6 | host container-registry auth | **never enters the sandbox**, but the engine may use it on the sandbox's behalf | — | pull/push as you | broker-shaped already, and undocumented **[R]** |

**Corrections to the earlier audit:**

- **The scope list was wrong.** The earlier audit wrote two scopes; measured, there are five,
  including `user:mcp_servers` and `user:sessions:claude_code`. If the last
  grants read access to Claude Code *sessions*, the blast radius is not "quota
  theft" but "read the transcripts of every other project on this account".
  Nobody has established what it does (Q3).
- **The earlier audit counted one Anthropic credential; there are two, unequally severe.**
  The access token expires in hours; the refresh token had ~20 days left and
  mints access tokens. "Until expiry" hides a factor of sixty. Splitting rows
  1a/1b is the whole of the severity argument, and it makes visible a cheap
  mitigation the earlier audit did not propose (§3.5).
- **`ANTHROPIC_API_KEY` is not merely leaky, it is authoritative.** Measured:
  with it set, Claude Code sends `x-api-key: <value>` and does **not** send the
  OAuth `Authorization: Bearer`. So `@claude` can put a long-lived org API key
  in `/proc/self/environ` and have it be the credential actually in use. The earlier audit
  called this a rule violation; it is also a severity upgrade, because an org
  key is typically not user-scoped and not auto-expiring.
- **Row 6 did not exist in the earlier audit.** `internal/engine` starts the podman service
  with `HOME` set to the host's home (`engine.go:189`), and podman resolves
  registry credentials from `$HOME/.config/containers/auth.json`. This host has
  none **[M]**, so nothing was observed; on a host that has one, a
  sandbox-issued `POST /images/create` or an image push would authenticate as
  the host user. `allowed()` permits everything under `images` except `load` and
  `import`, so `images/{name}/push` is reachable **[R, `proxy.go:270`]**. A
  credential broker that already exists, was never designed as one, and has no
  allowlist over *which registry*.
- **The earlier audit said `~/.claude.json` carries "no token".** True on this host **[M]**,
  but the file has two structural slots for one: `mcpServers[*].env` (a map
  injected into MCP server processes; empty here) and, in the sibling
  `settings.json` that `@claude` binds read-only, `env` and `apiKeyHelper`. "No
  token" is a property of *this host's data*, not of the format, so any
  statement about it must be conditional.

  **Fixed by issue #17, and worth saying why rather than just striking the
  row.** The conditional is what generation removes, on both files now: a
  generated `~/.claude.json` has no `mcpServers` key at all (issue #19), and
  the sibling `~/.claude/settings.json` — which used to be bound read-only,
  supplying `apiKeyHelper` and `env` as a COMMAND rather than stopping them,
  the `~/.gitconfig` shape — is now generated from a ten-key SCALAR allowlist
  that contains neither slot (issue #17, `.claude/design/CLAUDE-SETTINGS.md`).

  **What issue #17 does NOT close, and it is a separate, still-open finding.**
  `@claude` still binds `{home}/.claude/plugins` read-only, and a plugin's own
  manifest — plus `installed_plugins.json`, which records the installed
  plugin set independently of `settings.json` and sits inside that same
  bind — carries its own `hooks` block that Claude Code loads automatically.
  Measured on the development host: both the `caveman@caveman` plugin's
  manifest (a `SessionStart` hook) and the official `security-guidance`
  plugin's (`SessionStart`, `UserPromptSubmit`, `PostToolUse` and `Stop`
  hooks, each running a shell command). Dropping `enabledPlugins` from the
  generated `settings.json` is not known to disable any of that — the bound
  directory carries its own record of what is installed. See
  https://github.com/gomoni/snug/issues/68.

**Not present, confirmed:** `.netrc`, git credential helpers, any bind of the
host's `~/.config/gh`, any bind of `~/.ssh`. **[M, via `--dry-run` mount list]**

### 1.2 The places nobody had looked

Three of these are new defects.

**(a) `--dry-run` is not a dry run. [M]** `internal/cli/main.go:254-291` calls
`claudeFiles`, `startIdentity` and `startContainers` *before* the `cfg.dryRun`
branch. Measured with a `gh` shim first on `PATH`, which logged `auth token
--hostname github.com --user personal-account`. So `snug --dry-run` — whose first line
of output is *"nothing was started"* and whose doc comment says *"It starts no
process and creates no file"* — shells out to `gh auth token`,
**extracting a live credential from the host's gh store, including from the
system keyring** (one of this host's two accounts is keyring-backed **[M]**);
creates `$XDG_RUNTIME_DIR/snug/run-<pid>/` and **binds a live ssh-agent proxy
socket** onto the host's agent for the duration of the run; and, with
`@podman-socket`, binds the container proxy socket and starts its goroutine.

**And it creates a host directory that survives. [M]** `startContainers` →
`engine.New` (`internal/engine/engine.go:105-144`) `MkdirAll`s
`$XDG_DATA_HOME/snug/engines/<key>/storage` before anything starts — the same
persistent path §1.2f flags as a survivor. Measured: the engines directory count
went 44 → 45 on a single `--dry-run -p @podman-socket`. So the dry run does not
merely read a credential, it writes to the one host location that outlives the
sandbox. This strengthens Q9.

Severity: low on its own (host-side, mode 0700, torn down on exit), but it
falsifies the one artifact whose entire purpose is to be trustworthy, and it
makes "just dry-run it to see what it would do" advice that touches your
credential store. Q9 is the trade.

**(b) `--dry-run` denies, on screen, the credential it is staging. [M]** The
earlier audit found this for `~/.claude`; it is worse. With an identity profile, one screen
prints `data /home/u/.config/gh/hosts.yml (identity)` and, eleven lines
below, lists `~/.ssh ~/.gnupg ~/.aws ~/.config/gh ~/.kube …` under *"NOT GRANTED
(never mounted — these read as absent, they are not hidden)"* — reporting as
absent the very directory it has just staged an `admin:public_key` token into.
Cause is the earlier audit's: `covered()` (`internal/cli/dryrun.go:315`) only considers
`KindBind`.

**(c) `--dry-run` prints secret values in cleartext, twice. [M]** Once in
`ENVIRONMENT`, once as `--setenv ANTHROPIC_API_KEY <value>` in the bwrap argv.

**(d) Provenance was mislabelled for every socket snug binds — FIXED since this
was measured. [M at `d3e6430`; re-measured fixed at `ae848de`]** `BindSocket`
hard-coded `From: []string{"(identity)"}`, so `--dry-run -p @podman-socket`
attributed the container hole to identity. It read as cosmetic, and the deeper
finding was that `BindSocket` was a *third* path writing straight into
`p.Mounts`, bypassing `join` and `rejectMasking` alongside `replace` and
`claudeFiles` — so invariant 1 named one exception where there were three.

**Commit `af5f550` (the profile-model hardening) closed both halves, and the current shape is stronger
than the fix this document was going to ask for.** Provenance is now a parameter
(`internal/policy/types.go:243`), and `internal/cli/container.go:55` passes
`"(containers)"`; measured, `--dry-run -p @podman-socket` prints `rw
/snug/podman.sock (from …) (containers)`. More importantly there is now
**exactly one** post-resolution writer, `Policy.Replace` (`types.go:221`):
`claudeFiles`, `stageGhConfig`, `BindSocket` and `Resolve`'s identity/resolv.conf
block all route through it, it appends `"replaces:"+…` so displacement is no
longer silent, `rejectMasking` exempts on the `Authored` **field** rather than a
`Kind == KindData` heuristic (`internal/policy/validate.go:211`), and
`internal/cli/main.go:278` re-runs `Validate` after staging so the post-resolution
writes are checked rather than asserted.

Kept rather than deleted because the *lesson* outlives the defect: a carve-out
justified by "no TOML key produces this kind" was a proxy for the property that
actually mattered, which is who authored the mount. Anything this document later
proposes that writes into `p.Mounts` — a broker socket above all — must go
through `Replace` and inherit that check.

**(e) `-v/--verbose` audit output is clean. [M, by reading every call site]**
`internal/sshproxy` has eight `audit(...)` calls, none carrying key material or
a signature blob; `dockerproxy`'s `summarise()` (`build.go:404`) prints the
image tag and a *count* of host volumes, never `buildargs` values. Worth a
regression test precisely because it is currently true and one `%v` would end
it.

**(f) What snug writes to the host, and what survives.**

| path | written by | survives | why it matters here |
|---|---|---|---|
| `$XDG_RUNTIME_DIR/snug/run-<pid>/` | identity + container wiring | no | holds the sockets that *are* the holes |
| `$XDG_DATA_HOME/snug/engines/<key>/storage` | the per-sandbox podman engine | **yes**, keyed by `sha256(profile set + target)` | images the *sandbox* chose to pull sit on your disk, reused warm by the next run with the same key. An agent that pokes an image into that store has arranged for code to run in a later session |
| `/tmp/snug-<uid>-<hash>` (`@tmp-shared`) | `prepareHostTmpDir` | **yes** | same shape, smaller |
| the target directory | the payload | **yes, by design** | see below |
| host credential files | **nothing** | — | there is no sync-back |

**Documentation correction.** `CLAUDE.md` §Decisions made states *"Only the
credentials file syncs back to the host, and only after structural
validation"*. There is no sync-back code — `claude.go:31` says so explicitly
("deliberately not implemented yet") and a grep for a write to any host
credential path finds nothing **[M]**. The absence is the right call; the
sentence describing a validated write-back as a shipped decision is not. This is
exactly the "grep for X before you believe the comment" failure the project has
a rule about, and it is currently in the rule book itself.

**The target directory is the boundary this document does not move.** The
sandbox writes to it and it persists. A `Makefile`, a git hook, an `.envrc`, a
`package.json` `postinstall`, a `.vscode/tasks.json` — every one runs **on the
host, as you, with all your credentials**, the next time you do the ordinary
thing in that directory. A principle titled "secrets are never injected" must
not be read as "the sandbox cannot get your secrets". It cannot get them *now*;
it can arrange to be handed them later. Say this in the same breath, always.

**(g) Inside the sandbox, there are no process boundaries. [M]** Measured in a
default sandbox: a Python process spawned a child holding a sentinel string,
then read the child's `/proc/<pid>/mem` and found it — both `maps` and `mem`
readable. The seccomp filter denies `ptrace(2)`, but `/proc/<pid>/mem` does not
go through it: the kernel's check is `ptrace_may_access`, which same-uid
processes pass. Three consequences, all load-bearing for §3:

- "In the sandbox" means "readable by everything in the sandbox". File
  permissions, a private directory, a 0600 mode, a separate process — none of
  them separate anything.
- **An execute-only binary with an embedded secret does not work.** It is the
  first idea anyone has on hearing "stub" and it is dead on arrival: the payload
  runs it, then reads its memory. It does not even need that — it can `export
  LD_PRELOAD=...` for its own children, because everything snug has to say about
  that name (`policy.EnvNote`, `internal/policy/envtypes.go`) is about what a
  *profile* writes, not about what the payload may set. Since
  ENVIRONMENT-VARIABLES.md §2.9 it does not even constrain the profile: it
  annotates it. Neither version reaches the payload's own environment, which is
  the point being made here.
- Any design whose safety depends on a secret held by a *process inside the
  sandbox* is unsound, whatever the mechanism.

### 1.3 Exfiltration: the sandbox is not offline when you think it is

Severity depends on whether a leaked credential can leave. This channel bypasses
the `@net` decision entirely.

**Egress without `@net`, via the container engine. [M]** `snug -p
@podman-socket <dir>`, no `@net`, with a positive control:

```
DIRECT-EGRESS: refused (OSError)              # control: 1.1.1.1:443 unreachable
PULL-RESPONSE-HEAD: HTTP/1.1 200 OK ...       # docker.io/library/hello-world pulled
"status":"Download complete","id":"e2ac70e7319a"
```

The engine runs on the host, in the host's network namespace, and fetches on the
sandbox's behalf. The image *name* is fully sandbox-chosen — a DNS name plus a
path, i.e. a covert channel out — and the layers are bytes in.

**Host loopback, via the same channel. [M]** Pulling `127.0.0.1:<port>/x`
distinguishes open from closed ports on the *host's* loopback: 8731 (a
plain-HTTP recorder started for the test) returns `tls: first record does not
look like a TLS handshake`; 9 and 22 (closed here) return `connection refused`.
The 8731 error proves a TCP connection was established and bytes exchanged with
a host loopback service. Host-loopback unreachability is the property the private
netns exists for; `@podman-socket` re-opens it as an oracle, and would deliver a
payload to any host loopback service that speaks TLS or tolerates a ClientHello.
Note this half is unaffected by the `net` include — it is a channel `@net` never
grants, which makes it the sharper of the two findings.

**And it is not registry-shaped at all. [M]** Same configuration:

```
SANDBOX DIRECT: blocked - gaierror      # cannot resolve DNS. Correct.
pull: 200  create: 201  start: 204  logs: 200
CONTAINER REACHED THE INTERNET: True    # wget https://example.com, read back via logs
```

A container gets **arbitrary URLs, arbitrary payloads, and the response readable
back** through `containers/{id}/logs`.

**Abuse sentence as measured:** *a hostile process in a sandbox with
`@podman-socket` and no network profile can reach the internet, run arbitrary
code in a container with full egress, port-scan the host's loopback, and encode
data it wants to exfiltrate into an image name — all by asking the engine on its
behalf.*

**Status, 2026-08-09 — the false guarantee is closed; the channel is not.**
`@podman-socket` now carries `include = ["sys", "home", "net"]` (`ENGINE-NETNS.md` §5 step **M-a**,
commit `ae848de`), so `--dry-run` no longer prints "No egress" while
this is true, and a `CONTAINERS` block states that containers run in the
engine's netns. Selecting containers now selects egress *visibly*. Everything
measured above still happens; what changed is that snug stopped denying it. The
channel closes only when the engine moves into the sandbox's netns
(`ENGINE-NETNS.md` §5), at which point the `net` include is removed again.

**Status, 2026-08-18 — the `net` include is removed (issue #63, Tier B); the
channel is not YET measured closed, because the engine is not yet running at
all.** `@podman-socket` no longer includes `net`; `--dry-run` describes the
target state (a container confined to the sandbox's own netns, no
`CAP_NET_ADMIN`, no port publishing) and the stage layer beneath it is real
and tested (`internal/stage/subuid.go`, `capdrop.go`). But
`internal/engine.Engine.Start` still execs podman as a plain host process —
the same shape this section measured — and `internal/cli` currently REFUSES
to start a container engine on a real run rather than let that mismatch
reach a live sandbox (invariant 5; see `internal/cli/container.go`). So the
egress-without-`@net` channel this section measured cannot currently be
exercised at all, but for the wrong reason (nothing starts), not the right
one (netns confinement) — do not read this refusal as the channel being
closed by the fix this section calls for. Re-run this section's three `[M]`
measurements once the engine is actually forked through the stage into N,
and update this status to reflect the real result rather than the refusal.

**Status, 2026-08-21 — the engine is forked through the stage into N (issue #63
Tier B, #125 Tier C), and the finding is CLOSED.** `internal/engine` no longer
execs podman as a plain host process: the stage forks it into the sandbox's own
netns N by `setns`, drops it to `policy.EngineCapBounding`, and `internal/cli`
starts it on a real run. So the two premises the 08-18 entry hung its hedge on —
"the engine is not yet running at all" and "internal/cli REFUSES to start" — are
both superseded. The egress-without-`@net` CHANNEL this section measured is
closed structurally: a container runs in the sandbox's own netns, so with no
`@net` it has no egress and with `@net` exactly the sandbox's, measured both
directions by `TestContainerEgressFollowsNetProfile`, and it holds no
`CAP_NET_ADMIN` to publish a port. What §0 leaves LIVE is the *fact*, not the
channel: a container's network IS the sandbox's, exactly and no more (see
`ENGINE-NETNS.md` §0.1, finding-closed / fact-live). The three `[M]`
measurements the 08-18 entry asked to be re-run adversarially are the `redteam`
round still owed on #63 (its checklist's last open box); the structural closure
above is what the committed integration suite already asserts.

This remains a redteam finding rather than a secrets finding, and it is here
because it invalidates the broker plan's most attractive property — *"a brokered
Claude needs no `@net`, so exfiltration is closed by construction"* (that audit). That
holds only if no other profile opens a channel, and one does. The credential
half of the same hole is §3.8.

---

## 2. A severity model

The owner's steer: not all credentials are equal, and an Anthropic OAuth token
in a sandbox may be an acceptable risk where a GitHub token with
`admin:public_key` is not. This makes that judgement mechanical.

### 2.1 The axes, ordered by how much they should move the verdict

**A1. Does the authority outlive the sandbox?** The single most important
question, because it is the one the sandbox itself can answer: a credential that
dies with the run converts "the agent was compromised" into "…for twenty
minutes, and then it was over". *dies with the sandbox / hours / days /
indefinite.*

**A2. Can it extend its own life or scope?** The axis the earlier audit lacked, and the one
separating the two halves of the same file. A refresh token mints access tokens;
`admin:public_key` mints an SSH key — independent, non-expiring, and surviving
revocation of the token that created it. A token that can create tokens is not a
token, it is an account. *no / renews itself / mints an independent credential.*

**A3. Is the blast radius bounded by the issuer, cryptographically?** A
fine-grained PAT scoped to one repository is bounded by GitHub, not by us —
strictly better than any filter we write, because it holds even if every line of
snug is wrong. *server-enforced narrow / server-enforced broad / unscoped.*

**A4. What does the worst case cost?** *quota → disclosure → write to the
vendor's data → account takeover → code execution somewhere.* The discontinuity
is at code execution: `repo` scope means push, push means CI, CI means arbitrary
code running with *that repository's* secrets on a runner. A GitHub token with
`repo` is a code-execution primitive wearing a data label.

The last three break ties rather than deciding:

- **A5. Revocation — possible, fast, and free?** "You can revoke it" is weak if
  revoking logs you out of every machine you own, or if you would never notice
  you needed to.
- **A6. Is use detectable?** An audit log the human would plausibly read. Mostly
  no. A *yes* is a small mitigation, never a control.
- **A7. Shared or personal?** An org-wide key is a different object from a user
  token with the same scopes, because rotating it costs other people.

### 2.2 Today's secrets, placed

| | A1 outlives | A2 self-extending | A3 server scoping | A4 worst case | verdict |
|---|---|---|---|---|---|
| **ssh-agent proxy** (`@identity`) | **no** | no | n/a — one key, one lifetime | sign anything that key can sign, *while running* | **the model.** Injects nothing |
| **Anthropic access token** | hours | no | narrow-ish, 5 scopes | quota; `user:sessions:claude_code` unknown (Q3) | plausibly tolerable, *if* separated from 1b |
| **Anthropic refresh token** | ~20 days | **yes, renews** | same scopes | same, for weeks, and it rotates | **materially worse than 1a and currently indistinguishable from it** |
| **`ANTHROPIC_API_KEY`** | indefinite | no | often org-wide (A7) | quota, org-wide, rotating it is someone else's problem | never in the environment; §1.1 shows it also *wins* over the OAuth token |
| **GitHub token, `admin:public_key`+`repo`** | indefinite | **yes, mints an SSH key** | broad, user-wide | **account takeover + code execution via CI** | **never inject.** Fails A1, A2 and A4 simultaneously |
| **`~/.claude.json`** | ~~permanent (disclosure)~~ | n/a | n/a | ~~host inventory: 7 project paths, org, email, account UUIDs, machine ID~~ | **FIXED** (issue #19): generated, at most three keys, no host bytes — the third being snug's own trust answer for the target, scoped to the run (§3.5, issue #460). §3.5 predicted this fix; it landed |

### 2.3 What falls out

The discriminator is not "how sensitive does this feel" but **A1 ∧ A2** — *does
it outlive the sandbox, and can it extend itself*.

- **Both false** → a *capability*, not a secret. The ssh-agent proxy is the
  existence proof. Injecting a bounded-lifetime, non-renewing capability is
  defensible and needs only a named profile and an abuse sentence.
- **A1 true, A2 false** → a *time-boxed leak*. Arguable, needs a named profile,
  and the argument must be about the size of the box. The Anthropic access token
  sits here, *alone*.
- **A2 true** → **never inject, regardless of how narrow A3 looks.** A
  self-extending credential converts a sandbox breach into a permanent one, and
  no filter we write can undo an SSH key already added to an account.

That rule survives the owner's "not all credentials are equal" and lands exactly
where his instinct did — Anthropic maybe, GitHub `admin:public_key` no — without
appealing to instinct.

**Corollary, free:** the tolerable case (A1 hours, A2 no) is *precisely the case
where a broker is cheapest*, because a short-lived non-renewing credential is
also the one whose refresh you can keep on the host. The severity model and the
strategy space agree, which is weak evidence that both are drawn right.

---

## 3. The strategy space

### 3.0 No credential at all

No mechanism. **Abuse:** *nothing — it cannot authenticate.* Zero code. Does not
protect anything the tool could do unauthenticated, nor the target directory
(§1.2f). This is the floor and the default; the interesting question is never
"should this be the default" (yes) but "what is the smallest departure from it
that makes the tool work".

### 3.1 Vendor-side scoping

The human issues a narrow credential: a fine-grained PAT scoped to one
repository, a GitHub App installation token (1 h, repo-scoped), an Anthropic key
on a dedicated low-limit workspace. **Abuse:** *whatever the vendor's scope
permits, for the credential's lifetime, which outlives the sandbox.* Cost is
documentation; there is no code. It does not protect A1 — the earlier audit's objection, and
correct.

**It is nonetheless the strongest single lever available**, because it is the
only option here whose enforcement is **not ours**. Every other strategy converts
"a secret the agent can read" into "a secret behind a parser the agent can
attack", and `internal/dockerproxy` has a recorded history of four escapes in one
handler. A fine-grained PAT is enforced by GitHub whether or not our code is
right. A1 is a real weakness; "the filter has a bug" is a *certainty* over a long
enough horizon.

Suits GitHub above all — a fine-grained PAT removes `admin:public_key` and can
remove `workflow`, exactly the A2 and A4 failure — plus npm (granular tokens) and
AWS (an STS session with an inline policy, short-lived, so it improves A1 too).
**This is the cheapest large win in the document and it needs no milestone.**

### 3.2 Protocol broker (the `dockerproxy`/`sshproxy` pattern)

snug holds the credential on the host, runs a filtering proxy speaking the tool's
own protocol, and the sandbox points at it with the tool's own configuration
knob.

**Abuse:** *a hostile process can issue, with your full identity, any request the
allowlist permits, with content it chose, for the sandbox's lifetime only. It
cannot read the credential, cannot use the account afterwards, cannot reach an
endpoint outside the allowlist.*

**For Anthropic the cost is small and the shape is confirmed [M]**, measured this
pass independently of the earlier audit: Claude Code honours `ANTHROPIC_BASE_URL` over **plain
HTTP** to a loopback address (no CA, no TLS, no certificate wiring); across two
runs the *only* endpoint called was `POST /v1/messages?beta=true`, so the
allowlist is one rule, not three; auth is `Authorization: Bearer sk-ant-oat01-…`
from `.credentials.json`, or `x-api-key: …` when `ANTHROPIC_API_KEY` is set (the
latter wins); and it retries a 500 seven times in ~55 s, so the broker's *error*
behaviour is part of its interface — a refusal must be a 4xx the client will not
hammer. About as favourable as a broker ever gets.

**For `gh` the cost is large.** `gh` forces HTTPS **[M-prior]**, so a broker
needs a per-run CA, a leaf certificate and `SSL_CERT_FILE` wiring (Go's
`crypto/x509` honours it, so it is feasible **[R]**). Then the real problem:
`gh`'s high-level commands are `POST /api/graphql`, so the filter's choice is
*refuse GraphQL and break most of `gh`* or *forward it and be decorative*. A
GraphQL-aware filter is a query parser over a schema that changes without notice
— the D-Bus decision again, in a different hat.

**Does not protect** intent: the broker bounds the endpoint and the lifetime,
never what the agent asks for within them. Quota theft while running is
unaffected, and so is §1.2f.

Suits any tool with a base-URL knob and a small verb set — Anthropic
(excellent), OpenAI-shaped APIs, container registries (the auth belongs at the
*existing* proxy, host-side; §3.8), an S3 endpoint. It suits `gh` badly. **The
deciding rule:** *if the allowlist cannot be written in a handful of rules over
(method, path, host), the tool does not want a broker — it wants §3.1.*

### 3.3 The owner's policy-applying stub

The proposal: *mount a stub in place of the `gh` binary which (a) implements the
same sandbox policy for the command — e.g. refuses accessing paths outside the
grants — and (b) calls the real `gh` with the proper tokens.*

The earlier audit filed this under "user-scripted wrapper = arbitrary host code execution"
and dismissed it. **That dismissal does not apply as written.** The earlier audit objected to
a *user-supplied script* deciding on sandbox-controlled input; a snug-authored
stub with a snug-authored filter is the same authorship as `dockerproxy`, which
the project already accepts. And the staging mechanism already exists and was
chosen deliberately: `internal/cli/podmanshim.go` plus CLAUDE.md's *"PATH precedence,
not overmounting"* — stage the replacement in `policy.StagedBinDir`
(`/snug/bin`), the one directory snug owns, which snug puts on `PATH` in its
own band iff something is actually staged there (`policy.HasStagedBin`).
Additive, no mount, no masking-rule exemption, works where the target path is a
symlink; `@claude` uses it for this shape, binding one file read-only at
`{home}/.local/bin/claude:/snug/bin/claude`.

**Three corrections to what this paragraph said until 2026-08-13**, because each
is a shape someone will otherwise copy. *"Write the replacement into the writable
tmpfs `$HOME` and put that directory first on `PATH`"* is **the shadow-slot
defect the project already found and fixed** — a writable directory ahead of
`/usr/bin` means the payload writes a file called `git` into it. There is no
`policy.Profile.Path` field; `path` is a **retired TOML key** kept only to
produce a named error (`internal/profile/file.go`, `retiredPathKey`). And
`@claude` does not use it — it deliberately has no `PATH` merge, and says so at
length in `base.toml`.

So the question is not "is this allowed" but **where does the stub run, and what
crosses the boundary**.

#### 3.3.1 Placement A — stub inside the sandbox, holding the token

**Dead. [M]** By §1.2g, any secret held by a process inside the sandbox is
readable by every other process there via `/proc/<pid>/mem`, which the seccomp
ptrace denial does not cover. Execute-only modes do not help, and the payload
can `LD_PRELOAD` the stub's children. Even without that, the stub must *send*
the token somewhere and the payload controls its environment: `HTTPS_PROXY`,
`SSL_CERT_FILE`, `GH_HOST`. A leak with extra steps — named here so nobody
proposes it twice.

#### 3.3.2 Placement B — stub inside, host helper runs the real tool, **argv crosses**

The owner's proposal read literally: the sandbox runs `gh pr create --title X`,
the stub forwards `argv` over a unix socket, and a host-side helper judges it
and executes the real `gh` with the real token.

**What snug can judge well.** *Paths*, genuinely reusable, and the rule already
exists: `(*dockerproxy.Proxy).hostPathVisible`
(`internal/dockerproxy/create.go:611`) implements *a host path
is acceptable iff the sandbox itself can see it at the same or greater access*,
computed from the same `policy.Policy` that authored the bwrap argv — invariant 6
for free. Applied to `--body-file`, `--input`, `-F k=@file`, `gh release upload`
it is correct and cheap, and `resolveExisting` (`create.go:590`) already handles
the symlink-along-the-path problem. *A closed verb set*: `(command, subcommand)`
pairs are a finite allowlist with a default-deny, like `buildParams`.

**What snug cannot judge:**

- **`gh api`** — one subcommand re-exposing the entire GitHub REST and GraphQL
  API. Filtering it means reimplementing the HTTP broker on the *client's* side
  of the wire with none of its advantages.
- **`gh extension install <repo>`** — installs code that runs on the **host**, on
  every subsequent `gh` invocation. Persistent host code execution.
- **`gh alias set x '!sh -c ...'`** — persistent, and `!` is a shell escape by
  design.
- **`gh config set`** — `pager`, `editor`, `browser` are each "a command to run".
- **`gh gist create`** — an exfiltration primitive that looks like a verb.
- **`gh workflow run` / `gh secret set`** — code execution on runners; writes to
  the repository's secrets.
- **Anything shelling out to `git`.** `gh repo clone` passes trailing arguments
  to `git`, and `git -c core.pager=`, `-c core.fsmonitor=`, `-c
  filter.*.clean=`, `--upload-pack=`, `--exec=` are all command execution. `git`
  has a *config-injection flag*; that alone makes its argv unfilterable.

**And the part that dominates all of it:** even with a perfect argv filter, the
helper executes a real binary **on the host, outside every namespace**. It reads
the host's `~/.gitconfig` (credential helpers, `insteadOf`, `core.fsmonitor`),
the host's `~/.config/gh`, the host's `~/.netrc`; it writes to whatever cwd it is
given; it spawns `git`, which reads all of that again. The argv filter is
necessary and nowhere near sufficient.

**The synthesis the earlier audit missed:** *snug can sandbox its own helper.* Run the
host-side tool in a second, tighter snug sandbox — no `$HOME` but a generated
config directory, no `@net` beyond the vendor's host, no target bind, credential
staged in *that* sandbox where nothing the agent controls runs. The argv filter
then becomes defence in depth rather than the only line. It is the one shape in
which placement B is arguable, and it costs a `snug`-inside-`snug` story the
project does not have yet (Q6).

§3.3.6 takes that synthesis and drops the host half entirely: there is no
host-side execution left to be defence-in-depth *about*.

#### 3.3.3 Placement C — stub inside, **typed verbs cross**

The stub is `snug-gh`, not `gh`: a small snug-defined set of operations with
typed fields, sending a struct rather than argv, with the host helper
constructing the invocation — or calling the vendor's REST API directly.

**Abuse:** *a hostile process can perform any operation in snug's verb set, with
field values it chose, for the sandbox's lifetime.* Short, complete, reviewable.

This is the earlier audit's "shape 2" wearing the stub's clothes, and the clothes matter: it
dispreferred a verb broker because "the agent's real tools do not speak it", and
a stub on `PATH` fixes that — *provided it is not named after the real tool*.
Naming it `gh` would be a lie an agent acts on, assuming the full `gh` surface
and burning turns on flags that silently do not exist. `snug-gh` fails legibly. A
naming decision with a security consequence, and the same argument
`podmanshim.go` makes about not shipping a fake `podman` (Q5).

#### 3.3.4 Honest comparison: stub-B vs. HTTP broker

| | HTTP broker (§3.2) | argv stub, placement B (§3.3.2) |
|---|---|---|
| **what is judged** | `(method, path, host, header)` — a property of the wire | a CLI's argv grammar — a property of a vendor's UX |
| **blast radius if the filter is right** | the allowlist | the allowlist **plus** everything the host binary does on its own (host config, host cwd, spawned `git`) |
| **blast radius if the filter is wrong** | one extra API call | **arbitrary host code execution** (`gh extension install`) |
| **how it is reviewed** | read ~10 rules against an API reference | read N subcommand grammars against `--help` output that has no schema |
| **vendor ships a new flag** | invisible; the wire is unchanged | unknown flag → **default-deny → tool errors visibly**. *The earlier audit implied this was the discriminator. It is not — both fail closed and loudly* |
| **vendor changes a flag's meaning** | n/a | silent widening. **This is the real discriminator** |
| **adapter out of date** | endpoint moves → "Claude stops working" | verb refused → "that command stopped working" |
| **escape hatches in the surface** | none — an endpoint is an endpoint | `gh api`, `gh alias`, `gh config`, trailing `git` args. **Fatal** |

**The honest verdict.** The argv stub is *not* "not a security boundary"; the earlier audit
overstated. It is a boundary whose specification is a CLI's argv grammar instead
of a protocol, worse in two specific ways: a wrong decision costs host code
execution rather than one API call, and a flag's semantics can change without its
syntax changing. Whether that is acceptable turns on one property:

> **Does the tool have an escape hatch — a subcommand that performs an arbitrary
> protocol operation, or a flag that sets arbitrary configuration?**
>
> If yes, the argv surface is not enumerable, and the boundary must sit at the
> protocol. If no, and the verb set is small and closed, an argv filter is a
> legitimate boundary — and placement C is a better spelling of it than B.

**§3.3.6 deletes the row this verdict turns on.** *"Blast radius if the filter is
wrong = arbitrary host code execution"* is what makes an argv surface too
expensive to get wrong, and running the tool in a sibling sandbox does cost a
filter bug one capability instead of the host.

**But the row above it survives verbatim**, and it is the one that decides `gh`:
*"the allowlist **plus** everything the host binary does on its own (host config,
host cwd, spawned `git`)"*. In a sibling, "host cwd" becomes **the payload's
target directory** — and §3.3.6 (c) measures that a payload-authored
`.git/hooks/pre-push` and a repo-local `core.fsmonitor` both execute, with no
argv involved at all. Nor does confinement bound what the credential is *spent
on* at the vendor (§3.3.6 i). So this verdict holds for `gh` by a different route
than the one written here, and §3.10 is where the answer moved.

#### 3.3.5 Which side each tool falls on

| tool | escape hatch | verdict |
|---|---|---|
| `git` | `-c <anything>`, `--upload-pack`, `--exec` | **protocol.** And *already solved*: `git push`/`fetch` over ssh is brokered by `sshproxy` with `git_protocol: ssh`, no token anywhere. Do not build a git stub |
| `gh` | `api`, `extension`, `alias`, `config`, trailing git args | **protocol, or §3.1.** If a stub is built anyway it must be placement C with an explicit small verb list, named `snug-gh` |
| `aws`/`gcloud`/`az` | `--cli-input-json`, `--endpoint-url`, plugins | **protocol** — and the best case of all: sign on the host, so no bearer token exists to steal even in flight |
| `docker`/`podman` registry auth | n/a | **protocol, and the proxy already exists.** Put the credential at `dockerproxy`, host-side, with a registry allowlist. §3.8 |
| `npm`/`cargo`/`twine` **publish** | none in the publish path | **stub, placement C.** One write-only verb, one artefact path, judged by `hostPathVisible`. The best candidate in the list |
| Anthropic | n/a (no CLI) | **broker.** One endpoint, no TLS **[M]** |

#### 3.3.6 Placement D — stub inside, real tool in a **sibling sandbox**

The owner's correction to §3.3.2, 2026-08-13: the real tool never runs on the
host. It runs in a *second snug sandbox* — per-invocation, ephemeral, its own
policy — and the credential is placed there rather than in the payload's sandbox.
The stub in `policy.StagedBinDir` forwards, the sibling executes, stdout returns
down a pipe.

**Reviewed adversarially before anything was built** (four passes, 2026-08-13:
red team, policy model, host bridge, memory hygiene), and most of the first
draft did not survive. What follows is the corrected version; the sentences the
reviews killed are kept as struck claims rather than deleted, because each one is
a shape that will be proposed again.

**Verdict up front, so nobody reads the mechanism as a recommendation.** D is
**not** the answer for `gh`, and the reasons are measured below (§3.3.6 c, d).
It is the mechanism for a tool with a genuinely closed verb set and **no
repository as input** — §3.3.5 already named that candidate, `npm`/`cargo`
publish. For `gh`, §3.10 is the answer. D stays in this document because the
mechanism is sound for the case it fits, and because the reasons it does not fit
`gh` are the reusable part.

**D1's refusal reaches this more than the first draft admitted.** The clause is a
conjunction — *"A broker stays **small**, **snug's own**, and **reviewable** —
never a user-supplied script, and never a host command whose arguments the
sandbox chose"* — and the first draft read only the last conjunct, and only the
word `host` in it. D is not host; D satisfies **one of three**. A sibling running
whatever the payload's argv asks for is not small and not reviewable, wherever it
runs.

##### a. What it buys, and this part stands

Separate pid and mount namespaces mean the payload's `/proc` never contains the
tool's pid. §1.2g's `/proc/<pid>/mem` measurement — the finding that killed
placement A — stops applying, and not because the read is denied: there is no pid
to name. Same for `/proc/<pid>/environ`. **[M]** The red team looked for a route
and found none: the payload's `/proc` is its own pidns (pids `1 2 9 10 11`),
`/sys` is absent, `/proc/self/cgroup` is `0::/`, `PidMode: host` and
`container:`/`ns:` are refused by the container proxy, and the payload holds zero
capabilities.

Two residual observation channels, both minor and both worth recording:
`/proc/interrupts` and `/proc/softirqs` are readable inside and count host-wide
events **[M]**; and the time namespace is **not** unshared (`time:[4026531834]`
is the host's, `--unshare-all` does not cover it) **[M]**, so both sandboxes share
a `CLOCK_BOOTTIME` timebase, which is what makes the timing channel in (b) easy
to align.

##### b. The sinks, and the two the first draft got wrong

Stdout returns to the payload — that is the point of the stub. So `gh auth token`
prints the credential and the stub pipes it home; `gh alias set x '!sh -c …'`,
`gh api -F body=@<path>` and `gh gist create <file>` are the same move in
different clothes. **Confinement bounds where the credential may be used. It
bounds neither what gets printed nor what gets done.**

| sink | bounded by |
|---|---|
| stdout / stderr | a closed verb set. Redaction is accident hygiene, not a bound — see (e) |
| network egress from the sibling | a CONNECT proxy over `pasta --splice-only` (§3.3.6 f) — which bounds *third parties*, not the credential (§3.10) |
| files the sibling writes where the payload reads | policy: no writable path shared with the payload |
| **exit status** | **nothing, until it is clamped** |
| **timing** | nothing |
| the environment the payload sets on the stub | an explicit allowlist, or the sibling inherits `GH_HOST`, `SSL_CERT_FILE`, `GIT_SSH_COMMAND`, `http_proxy`, `LD_PRELOAD` |
| descriptors the payload hands the stub | P0 copying bytes, never forwarding the fd. A dirfd ignores the mount namespace entirely — `safeStdio`'s lesson, one layer out |
| cwd | same as a path field (d) |
| signals | a stub killed mid-call must not orphan a credential-holding sibling |
| filesystem metadata (mtime, size) on any shared path | — |
| **state left at the vendor** | **nothing. §3.10** |

**Exit status is a byte channel, and it is fast. [M]** `snug <dir> -- sh -c 'exit
137'` returns `137`; a stub that did not propagate status would be useless,
because `gh` callers branch on it. Arbitrary code in the sibling does
`exit(secret[i])`. At the measured 245 ms per `@net` sibling (§3.3.6 g), a 40-byte
token leaves in **≈10 seconds**. The first draft's table already carried the row
`exit status, timing | unbounded` and its conclusion three lines below ignored it.

*Required if D is built:* the stub returns a **clamped, snug-authored** status —
a small fixed enumeration (success / denied / tool-failed), with the real code
discarded and reported only to the human — and the number of invocations is
**budgeted per sandbox**. The clamp costs `gh api` callers the 4xx-vs-5xx
distinction, and that is the honest price. Timing is not closed by either; it is
raised in cost and must be said rather than implied.

##### c. `gh` fails D on its own, and the reason is not argv

**[M]** With `GIT_CONFIG_GLOBAL=/dev/null` and `HOME` unset — exactly how snug
neuters git — a payload-authored `.git/hooks/pre-push` and a repo-local
`core.fsmonitor` **both executed**. `.git/hooks/*`, `core.fsmonitor`, `core.pager`,
`diff.*.textconv`, `filter.*.clean/smudge`, `core.sshCommand`, `alias.*` and
`include.path` are all repo-local, all payload-writable, and all execute. `gh pr
create`, `gh repo sync` and `gh pr checkout` shell out to `git` in that repo.

So **D-verbs buys "no arbitrary code via a verb named install", not "no arbitrary
code beside the credential"**, and it buys it only for tools whose input is not a
repository. The first draft's discriminating case (`gh extension install`) was the
wrong example of the right problem: the repository is the argument, and git
treats repository data as code.

Either the sibling never sees a payload-controlled repository — which removes
most of `gh`'s point — or D-verbs is not a bound for `gh`. There is no third
option.

##### d. Typed fields are not safe when the type is a path

The first draft said snug "constructs the argv from typed fields", as though
typing the field made the value safe. It does not: a path **resolves in the
sibling's mount namespace**, where the credential is, not in the payload's, where
it is not. `gh gist create <path>`, `-F body=@<path>`, `--body-file`, `gh release
upload` are ordinary verbs with a path field. Aim it at the credential file, or at
`/proc/self/environ` inside the sibling. If P0 validates "must be under the
target", a **symlink planted in the shared target** wins: validation happens in
P0's namespace, `open` happens in the sibling's.

*Rule, if D is built:* **no path-typed field crosses the boundary.** File content
crosses the control channel, read on the payload's side, and snug materialises it
at a path only snug names.

##### e. Redaction is accident hygiene

Worth building, never a leg to count. The payload picks the argv, so it picks the
encoding: a literal match misses base64, hex, URL- and JSON-escaping, and case
changes, and any templating flag (`gh api --jq`, `--template`, `--format`) is an
arbitrary function over data the tool holds — `--jq '@base64'` is one flag. A
streaming matcher must keep an overlap buffer of `len(secret)-1` or a split across
two `read()`s passes through. And redaction fires visibly, so any verb that echoes
a caller-supplied value is a confirmation oracle — with an unbounded invocation
count (h), an oracle with unlimited free guesses.

Listing it as one of three legs overstated the composition by a third. See §3.9
for where the matcher may hold its window, which is not the Go heap.

##### f. Egress: buildable, measured, and it does not bound what it was meant to

**Struck:** *"pasta gives egress or none… 'the vendor and nothing else' needs an
HTTP CONNECT proxy **or a DNS-plus-IP pin**, and neither exists in the tree. This
decides whether D-sinks is buildable."*

**[M]** It is buildable in one flag and forty lines. `pasta --splice-only` removes
routed egress entirely and `-T <port>` splices exactly one loopback port to a
CONNECT proxy snug owns:

```
via proxy api.github.com   http=200  ssl_verify_result=0   TLS verified end to end
direct   api.github.com    exit=6                          no DNS in the netns
direct   140.82.121.6      exit=7                          no route, even by IP
host     127.0.0.1:18099   exit=7                          adjacent host port closed
raw.githubusercontent.com  403 from the proxy
```

**The D-Bus argument does not reach a CONNECT proxy.** It never terminates TLS,
never parses the tunnelled protocol, and makes one decision: is `host:port` on the
list. That is a string comparison, not the semantic filtering of a rich protocol
that "95% correct is 0% sound" is about. It also closes the arbitrary-code case
properly: code in the sibling can ignore `HTTPS_PROXY`, but under `--splice-only`
there is no other route.

Three costs, all mandatory:

- `-T <port>` is a host-loopback splice — **the exact hole `-T none` exists to
  close** (§4.2). One explicitly named port, never `auto`, never `all`, asserted
  by a behaviour test and not by a golden argv, because a golden argv would pass
  on the buggy configuration.
- The proxy binds `127.0.0.1` only.
- The sibling's netns has **no DNS at all**, which is the feature: the *proxy*
  resolves the allowlisted name on the host, so nothing inside ever resolves
  anything.

**And a DNS-plus-IP pin must be struck as an option, three ways, all measured.**
`api.github.com` has a **10 s TTL** and rotated address during a single session
(`140.82.121.6` → `140.82.121.5`), so a pin taken at sibling start is stale by the
next invocation, and refreshing it means trusting the DNS the pin was replacing.
GitHub's published ranges are `api` 10,260 addresses, `git` 10,280, `actions`
27,944,307 — effectively Azure. And `185.199.108.0/22` is **AS54113 (Fastly)**,
not GitHub's AS36459, serving `*.github.io` under a wildcard certificate:
`curl --resolve octocat.github.io:443:185.199.108.133` returns **200** with
`ssl_verify_result=0`. An IP pin authorises *tenants*, not a vendor. The CONNECT
construction is immune to all three because it pins a **name**, resolves it on the
host itself, and never hands an address to the sibling.

**What none of this buys.** Pinning egress to the vendor pins it to the one party
that can mint an independent, durable credential and that publishes
attacker-chosen bytes. See §3.10 and (i).

##### g. Do not share the payload's netns

**Struck:** *"Sharing N is one pasta instead of two and is the cheap option… TLS
covers that provided the sibling's trust store is snug-granted read-only and the
payload holds no `CAP_NET_RAW` in N."*

Wrong three ways.

- **It is the expensive option, not the cheap one.** bwrap 0.11.2 has **no
  `--netns` flag** — only `--unshare-net` and `--share-net`, and snug emits
  `--share-net` nowhere at all (`internal/policy/bwrap.go`).
  Putting a sibling in N requires `setns` with `CAP_SYS_ADMIN` in N's owning
  userns, i.e. new privileged code that does not exist. A sibling with its own
  netns is a normal `Resolve` plus a second pasta.
- **TLS does not cover the attack this section itself describes** two paragraphs
  earlier: the payload listens on `127.0.0.1` inside N and the argv names that
  endpoint. That is not interception; it is a payload-owned endpoint the caller
  chose.
- **[M]** A shared N hands the payload: a bindable loopback endpoint (`127.0.0.1:9999`
  OK, `0.0.0.0:443` EACCES), the sibling's five-tuples out of `/proc/net/tcp`, the
  neighbour table, and **abstract-socket squatting** — binding a helper's abstract
  name before the sibling can. That last one inverts one of the project's
  structural properties: "abstract sockets are netns-scoped, and that is why the
  sandbox cannot reach the host's" becomes "two sandboxes sharing a netns share
  their abstract namespace".

**Correction of fact, and the `[R]` is retired.** The first draft said *"there is
no `--cap-drop` anywhere in `internal/policy`"*. That was true of the tree it was
written against and is **no longer true of any tree**: the supervisor merge
brought `--cap-drop ALL`, passed unconditionally
(`internal/policy/bwrap.go:118`), after a red team found it missing. **[M]** on
both topologies the payload's `CapInh/CapPrm/CapEff/CapBnd/CapAmb` are all zero,
`NoNewPrivs: 1`, `Seccomp: 2`, and `AF_PACKET`/raw sockets fail `EPERM`. It also
survives a hypothetical seccomp bypass: **[M]** a nested userns with a full
effective set still cannot open a raw socket over a *foreign* netns, because
`CAP_NET_RAW` is evaluated against the userns that **owns** the netns.

The conclusion held and the stated reason did not, which is the part worth
keeping: for one milestone the guarantee rested on **bwrap's default** while the
document asserted it as a property. That is the shape "never trust a helper's
default" exists to catch, and it was caught by measuring rather than by reading.

*Related, and it is the engine phase that opens it:* **[M]** the only thing
between the payload and a DNS server on a shared resolver address is
`ip_unprivileged_port_start = 1024`, a **per-netns** sysctl writable by a
`CAP_NET_ADMIN` holder in the owning userns. `IP_FREEBIND` needs no capability at
all and succeeds above 1024. Rootless engines routinely want that floor at 0.
`ENGINE-NETNS.md` §5 puts an engine in N; if that phase lowers the floor, a
shared-N sibling's DNS becomes hijackable with no capability. That belongs in
ENGINE-NETNS §4 as a third guarantee that changes shape.

##### h. The control channel: accounting, not authentication

The stub is **not** a boundary and the first draft never said so. It sits in
`/snug/bin`, world-readable inside; the payload reads it, learns the protocol,
and speaks to P0 directly. Every check lives in P0. Authentication buys nothing —
the channel's holder is the whole sandbox by design.

What must be bounded is **rate, concurrency and total invocations per sandbox**:

- **Unbounded sibling creation.** The payload structurally cannot create a
  namespace — zero capabilities, `unshare(CLONE_NEWUSER)` denied, `clone3` denied
  with ENOSYS. D hands it namespace- and process-creation by proxy, unlimited,
  one line per request, and the damage lands on the host and on unrelated
  sandboxes rather than inside its own pidns.
- **Unbounded credential re-query.** §3.9's "never receive" shape re-runs the
  source per invocation; one account on this host is keyring-backed. N invocations
  is N keyring hits — a prompt storm, or an unlock the human grants once and the
  payload spends thousands of times — plus vendor rate-limit exhaustion, which is
  a denial of service on the human's own credential.
- **Unbounded oracle queries** (e) and **unbounded audit events**, which is a log
  flood that hides the one event that mattered.
- **Concurrency confusion** exists only because there is no accounting: two
  in-flight calls sharing one credential fetch, one sibling or one output pipe is
  where call A's argv reaches call B's sibling. `internal/stage/conn.go`'s
  `SOCK_SEQPACKET` one-message-one-datagram shape does not come for free to a
  pathname socket with concurrent clients.

A single-flight lock per credential, a hard cap on live siblings, and an
invocation budget — all surfaced in `--dry-run`.

##### i. Two legs, and they are not interchangeable

**Struck:** *"Composed, a miss in either is covered by the other, which is the
only reason paying for both is worth it."*

False in the direction that decides the verdict. **D-sinks bounds bytes leaving.
It bounds nothing about what the credential is spent on**, and §2.3's rule is
about exactly that: *"A2 true → never inject, regardless of how narrow A3 looks."*
Every leg is on the data path; authority extension is on the control path.

- **The capability leaves instead of the credential.** This host's `gh` token
  carries `admin:public_key`. Code in the sibling uploads an SSH public key the
  *payload* generated — the private half never moves — and the payload holds a
  durable, self-owned credential for the same account after the sibling is gone.
  Same shape: deploy keys, a repo webhook aimed at an attacker URL where the
  *vendor's* outbound delivers the data, adding a collaborator, authorising an
  OAuth app.
- **Store-and-forward through the vendor.** **[M]** `POST /gists` public, then an
  unauthenticated read returns 200. Issue bodies, commit messages, branch names,
  a private repo the payload reads back with an allowed read verb.
- **The vendor as an echo** even with no read verb: the created object's URL or
  id, or the rate-limit headers.

So: **D-verbs is load-bearing and D-sinks is exfiltration hygiene.** Pinning
egress to the vendor pins it to the attacker's target. The only thing that bounds
an A2-true credential is the *issuer* — §3.1, and §3.10's whole point.

**D is therefore inadmissible for any credential where A2 is true unless the verb
set is the boundary** — and (c) shows the verb set is not a boundary for any tool
that takes a repository.

##### j. The sibling's policy is not "derived"

**Struck:** *"the sibling's policy must be **derived** from the resolved parent
policy, or invariant 6 is gone."*

Derivation is not an operation this model has, and asking for it is asking for the
carve-out invariant 1 says exists nowhere.

- `Resolve` is one-way and has no inverse. The only per-grant record of origin is
  `Mount.From`, which `join` **unions** and which `internal/policy/types.go`
  explicitly disqualifies as semantic ("provenance for `snug --dry-run` only…
  deliberately NOT part of equality"). A mount granted by two profiles carries
  both names, so "keep the grants from X" is undefined for exactly the mounts that
  matter.
- The two post-resolution writers are `Policy.Replace` and `Policy.BindSocket`.
  `Replace` overwrites content at a path; **neither deletes a node**. So "no
  writable path shared with the payload" cannot be expressed as a transformation
  of the parent policy at all.
- Deriving it would inherit the parent's holes: `@tmp-shared` is a *persistent
  host* directory writable in both sandboxes, and `@podman-socket` gives the
  sibling the container hole, which §1.3 measured as arbitrary egress in the
  **engine's** netns on the host — the CONNECT proxy defeated in one hop from
  inside the credential sandbox.

*The model's own answer applies:* **to grant less, select fewer profiles.** The
sibling gets its **own named profile set, resolved independently**, with
`@tmp-shared`, `@podman-socket` and every socket bind structurally excluded. Invariant 6 is then restated **per sandbox** — "one `Policy` per
sandbox, one author" — plus an explicit, tested cross-policy rule for any decision
that mentions both, because `hostPathVisible` would have to answer "can the
payload see this" *and* "can the sibling read it" against two policies. That is a
real cost: a cross-policy obligation discharged by review is the thing invariant 6
exists to abolish, and D reintroduces it in a bounded, named place.

*Two facts that bound the sibling's floor:* `Resolve` fails closed with no target,
and `Validate` requires **both** an OS runtime (`/usr` or `/bin` in `p.Mounts`) and
a `KindBind` covering the target. §3.3.2's sketch of the sibling — "no `$HOME`, a
generated config directory, **no target bind**" — is refused as written. The
sibling's floor is a design input, not a free parameter.

*And a defect found while checking this, independent of D:*
`TestPolicyHasNoRestrictionOperation` does **not** sweep for a demote. It resolves
defaults, adds `cwd-ro`, and asserts the target is still `rw` — an assertion that
`Access.Join` takes the max. CLAUDE.md's claim that the invariant "can be checked
by grepping for a demote and finding none" is inaccurate: a `Policy.Derive`
returning a stripped copy would ship green.

##### k. Ephemerality, and what it does and does not buy

The sibling must be per-invocation and die with the call. A sibling that persists
its `~/.config/gh` turns `gh extension install` back into what made placement B
fatal — code that runs on every later invocation, next to the credential.

Ephemeral, that command is code execution the payload already commanded by
choosing the argv, for one call, with no persistence. **It is not harmless**, per
(i): one call is enough to spend the credential at the vendor.

##### l. Abuse sentence

*A hostile process inside the sandbox can invoke any operation in snug's verb set,
with field values it chose, for the sandbox's lifetime. It can cause arbitrary
code to run beside the credential in a sibling sandbox — certainly for any
git-touching verb, because the repository is an argument and git treats
repository data as code. That code can spend the credential at the vendor,
including on operations that create durable state the sandbox outlives. Bytes
leaving are bounded by a closed verb set, a CONNECT allowlist and a clamped exit
status; **authority is bounded only by what the issuer scoped the credential to**.*

The first draft's final clause — *"it cannot read the credential out of that
sandbox's memory, environment or filesystem"* — is struck. No test asserts it, and
(b) and (i) show it is not the property that matters.

##### m. Cost, and what it depends on

- **D requires a control channel the stage does not have, and snug decided not
  to build one**, which is the largest item and was omitted from the first draft
  entirely. `SUPERVISOR-DESIGN.md` §3.3 makes the stage channel's
  *unreachability* the load-bearing property, because one `start` request makes
  the stage `execve` an arbitrary path **as uid 0 with a full capability set in
  U**; §7 records that the protocol was kept a two-op state machine specifically
  so it would not become a server; and the listener that would have given it a
  second client was **cut on measurement** (issue #61). D makes **the untrusted
  payload the stage's second client**, so D does not inherit a mechanism — it
  has to propose one, against a decision that went the other way, and the
  `start` op must not live on any socket the payload can name. Until that is
  designed, D cannot be costed.
- **Q6 stops being optional.** D *is* snug-inside-snug.
- **Invariant 6 is restated per sandbox, with a cross-policy rule** (j).
- **Launch cost is measured, and it is not the problem. [M]** 245 ms and ≈53 MB
  per `@net` sibling (170 ms offline, 12 ms dry-run) against ≈215 ms of real `gh`
  work — a ≈2.2× latency tax. One stage serves exactly one sandbox
  (`internal/stage/serve.go` returns after a single `start`), so N invocations
  cost N namespaces and N pastas. Concurrent stages are possible — nothing holds
  package-level state — but nothing expresses it. *"Unmeasured and plausibly
  fatal" was wrong; the fatal problems are (c) and (i).*
- **`--dry-run` must name the credential, the sibling and the verb set**, and
  every payload-chosen string that reaches a screen — the redaction audit line,
  the "verb refused" error, the SECRETS block — must go through `visibleValue`.
  The standing rule is *assert the set, not the site*
  (`TestNoSnugScreenEmitsARawControlCharacter`), and the audit rule becomes "say
  that it happened, never what it matched, and never verbatim what the payload
  wrote".
- **Redaction is silent to its consumer**, which is invariant 5's shape: an agent
  believing `gh` output is faithful when snug altered it is "a user believing a
  guarantee that no longer holds". A fixed in-band marker, not a silent
  substitution — and note that the marker is also the oracle from (e). Name the
  trade rather than resolving it by omission.
- **A missing control must refuse, not degrade.** If the CONNECT proxy is
  unavailable, the sibling does not launch. Invariant 5 admits no quiet fallback,
  and `@podman-socket`'s interim `include = ["net"]` is the worked example of the
  alternative: widen the stated grant rather than narrow the printed guarantee.

### 3.4 Agent-proxy (the ssh model)

The credential stays in a host-side agent that already holds it; snug proxies the
agent's own wire protocol and filters at the message level, exposing exactly one
identity.

**Abuse:** *a hostile process gets a signing oracle for one pinned key, for the
sandbox's lifetime. It cannot enumerate other keys, cannot extract material, and
cannot sign after the sandbox exits.*

Cost already paid for ssh (292 lines). Does not protect *what* gets signed —
inherent to every agent forwarder. Suits anything with a real agent protocol: ssh
(done), `gpg-agent` (same shape; would cover commit signing and `pass`), in
principle a PKCS#11 token. **Nothing else has an agent**, which is why this does
not generalise — less a strategy than an existence proof that the shape is
achievable when the vendor gives you a socket. Its real role is as the
**calibration point**: A1 false, A2 false, filter reviewable in an afternoon.
Argue any new hole against it.

### 3.5 The measure-first mitigation for split credentials

Not a strategy; a cheap intervention the severity model makes visible and nobody
had proposed. Where a credential file carries *both* a short-lived token and a
self-extending one, stage a **rewritten** copy carrying only the short-lived half
— for `~/.claude/.credentials.json`, keep `accessToken` and drop
`refreshToken`/`refreshTokenExpiresAt`. Cheap because `claude.go` rewrites
nothing today, it copies bytes; parse-and-project is a few lines and the file is
508 bytes with a known shape. It moves the Anthropic row from *(A1 days, A2 yes)*
to *(A1 hours, A2 no)* — from "never inject" to "arguably tolerable". This is the
mechanism D2 adopts.

**Not measured.** Whether Claude Code works with the refresh token absent, and
what it does at the ~8 h boundary, was **not tested this pass** (the probe needed
a copy of the real credential file and was refused by tooling, correctly). **A
five-minute experiment; run it before believing this** (Q4).

Generalises to `~/.claude.json`: the earlier audit measured that it is not needed at all
**[M-prior]**; if that survives re-measurement, the 56 KB host inventory should
be *generated minimal*, not copied — the "generate, don't bind" rule the project
already applies to `.gitconfig` and `hosts.yml`.

**DONE, and the re-measurement corrected the premise on the way through** (issue
#19, claude 2.1.232). "Not needed at all" is half right: with the file absent
Claude Code connects and works — no login prompt, so nothing here was
load-bearing for AUTH — but it does block on the theme picker and then the trust
dialog, on every run, because `$HOME` is a fresh tmpfs. So stop-staging was the
wrong shape (two interactive prompts per run, and Claude Code then writes its own
35 KB file anyway), and *generated minimal* was the right one: three keys —
`hasCompletedOnboarding`, `autoUpdates=false` and
`projects.<target>.hasTrustDialogAccepted`, the last being snug's own answer for
the ONE directory named on the command line, in that sandbox only. Nothing here
is read from the host. 284 bytes measured inside against 62 274 on this host.

**The trust key removes Claude Code's dialog for the target, and what pays for
that is the projection rather than the dialog** (issue #460). Measured A/B,
claude 2.1.251, on one hostile fixture — a target containing only
`.claude/settings.json` with a `SessionStart` hook:

| build | trust dialog | repo hook |
|---|---|---|
| key omitted | "Quick safety check" blocks (interactive) | not fired |
| key written (now) | none, opens on the prompt | not fired |
| the same fixture, on the HOST | none | **fired** |

The hook fires in neither sandbox arm because `stageProjectClaudeSettings`
reinterprets the target's `settings.json` and drops its `hooks` block before
Claude Code reads it. `claude -p` shows no dialog in either arm — the headless
mode does not gate on trust at all — so the dialog was only ever an interactive
prompt, and it was gating a channel the projection had already closed.

`.mcp.json` is the same question with a sharper answer: a target whose only
content is a `.mcp.json` naming `sh -c "touch MCP-FIRED"` ran that command with
the key omitted, with it written, AND on the host in a never-trusted directory.
The trust key never gated that file, so `stageProjectMCPJSON` reinterprets it
into one naming no servers. The cost is stated rather than flagged around: an MCP
server a project legitimately commits does not run inside a snug sandbox.

**What the residual is, stated as the measurement.** It is NOT "strictly narrower
than the seven paths the copied file pre-accepted" — that sentence was written
here and in two places in the code, and it is false in both directions. Measured:
the old set was the host's SEVEN project paths, the new set is `{target}`, and
neither contains the other. The old seven were also **inert** — all seven are
absent inside a `@claude` sandbox, so no entry could open anything — while
`{target}` is the one directory that IS mounted, writable and persistent, i.e.
the only live entry either version ever had. The bytes got smaller and the one
live entry stayed one live entry; what changed is who decides it. snug decides it
now, which is why `--dry-run`'s `CLAUDE` block says PRE-ANSWERED BY SNUG in those
words (`internal/cli/testdata/claude-block.txt`) — a decision made on the human's
behalf has to be one they can read.

### 3.6 Staged injection under an explicitly-named profile

What happens today, but honest: the credential is staged only under a profile
whose *name says so* — never in `defaults`, with the abuse sentence in the TOML
and `--dry-run` printing the value as `SECRET`.

**Abuse:** *a hostile process reads the credential out of a file (or, worse, out
of `/proc/*/environ`), exfiltrates it, and uses your account for as long as the
credential lives.*

Cost is almost none — mostly naming plus §1.2b/c. It protects nothing once the
credential is inside; its entire value is that the human *chose* it, on a name
that could not be mistaken for a capability grant. Suits the escape hatch and
only that: its existence is what lets the default be §3.0 without making snug
unusable for someone with an unusual tool, and what stops "the adapter is late"
becoming "so we injected it quietly". (D1 settled the naming convention; D2
applies it as `@claude` / `@claude-refresh`.)

### 3.7 Two things already brokered that nobody had written down

- **`git push` needs no token.** With `git_protocol: ssh` in the generated
  `hosts.yml` and the ssh-agent proxy, clone/fetch/push already work with zero
  credential inside. The *only* residual need for a GitHub token is the API half
  (PRs, issues, releases). This substantially shrinks the `gh` problem and should
  be the recommended posture in the user docs.
- **Container registry auth is already a broker** — accidentally (§1.1 row 6).
  Right *shape* (credential on the host, sandbox speaks a protocol to a filtering
  proxy), none of the discipline: no registry allowlist, no abuse sentence,
  `images/*/push` reachable, undocumented. Making it deliberate is small,
  well-scoped work with a clear win.

### 3.8 Docker, registries and credentials — POSTPONED, and why it belongs here

**Decision (owner): the registry allowlist is postponed.** Not dropped — deferred
*into this document*, because it is a credential question wearing a network
question's clothes, and designing it under `@podman-socket`'s networking work
would get half of it. (The measurement that forced this is §1.3: the channel is
arbitrary-URL egress, not registry-shaped.)

**The two problems are ORTHOGONAL, and that is the whole point.**

|  | what it is | what fixes it |
|---|---|---|
| **Network** | a container reaches anything the ENGINE can reach | put the engine in the sandbox's netns (`ENGINE-NETNS.md` §5). *Declaring it — `include = ["net"]` — landed 2026-08-09 as step **M-a**: honest, not closed; §1.3* |
| **Credential** | the engine acts with the HOST's stored registry auth, inherited silently (§1.1 row 6) | point the engine's auth away from the host, or grant registries explicitly |

Neither fix addresses the other, and it is easy to believe otherwise: the netns
move leaves a sandbox with `@net` still pushing under *your* credentials (the
network became honest, the identity did not), and an allowlist alone leaves a
container `wget`ing anything (the identity became bounded, the network did not).

**What a design here has to answer:**

1. **Should the engine have ANY host registry credential by default?** The
   severity model says no: the authority outlives the sandbox — a pushed artifact
   persists in the registry after teardown — which is the axis separating
   tolerable from never. §3.0 is the honest default: a scratch auth file,
   anonymous pulls, which is what most builds need.
2. **If a run needs a private registry, how is it named?** The first credential
   grant that is neither a broker nor an injection: the credential never enters
   the sandbox (good) but the sandbox directs its use. Candidate shape: an
   explicit per-profile grant naming registry AND credential source, with
   `dockerproxy` refusing every other host. Note §4's warning that `allow` lists
   union across profiles, so a "read-only registry" profile cannot stop a second
   profile widening it.
3. **Is `push` separable from `pull`?** Pull is ingress of attacker-chosen
   content; push is egress of attacker-chosen content *under your identity*. Not
   the same risk; the allowlist should probably not treat them as one verb.
4. **What about the distrobox case**, where the engine is a shim forwarding to
   the host session and snug controls neither its environment nor its namespaces?
   Every fix above assumes snug can hand the engine an environment. Where it
   cannot, the honest answer may be that `@podman-socket` cannot be
   credential-isolated on such a host, and must say so rather than imply it.

**Cross-references:** `ENGINE-NETNS.md` §3 and §5, §1.1 row 6,
§1.3, §3.7, Q8.

---

### 3.9 Where the secret lives on snug's own side of the wire

Every strategy above moves the credential out of the payload's sandbox and into
snug's process. That is progress, and it relocates the question rather than
answering it: what can read snug's memory?

**Not the payload.** It sits outside the payload's pid namespace, so nothing
inside can `ptrace` it or read its memory. *Not* "nothing inside can name it" —
**[M]** `/proc/self/mountinfo` inside a sandbox prints the **host** source path of
every bind, including the run directory `run-<pid>`, which is named from snug's
own pid (`internal/cli/identity.go`); the same read leaked the container-storage
overlay chain and a btrfs subvolume path. Bind mounts publish host paths. Under D
that gets worse: a control socket bind-mounted at a pathname publishes it to every
process in the sandbox, forever. **Prefer an inherited descriptor over a pathname
socket** — `internal/stage/proto.go` already made exactly that choice, for exactly
this reason, and the first draft of D threw the property away without noticing.

The real threats are host-side and mundane: a core dump, swap, and another process
of the same user.

**Everything below was measured on this host** (2026-08-13), and the first draft's
ordering was backwards.

##### The strongest form: never receive it

Where the credential can be re-queried from its source, wire that source's stdout
straight into the sibling's input descriptor and never read a byte:

```go
cred := exec.Command("/usr/bin/gh", "auth", "token")
cred.Stdout = siblingInput   // MUST be an *os.File
```

**[M]** The mechanism is real and rests on a **runtime type assertion the first
draft did not state**. `os/exec` passes the descriptor straight through *iff* the
writer is an `*os.File`, and silently interposes `os.Pipe()` plus an `io.Copy`
goroutine inside snug for anything else. Scanning the process from outside:

```
Stdout = *os.File        one shared pipe, SECRET_FOUND=0
Stdout = bufio.Writer    two pipes, io.Copy in-process, SECRET_FOUND=1
```

So the `*os.File` constraint is **load-bearing and needs an assertion, not a
comment** — and adding any redactor, tee or `bufio` to that stream silently
reintroduces the heap copy. §3.9's own redactor proposal *is* the interposing
case.

Two more requirements the first draft missed:

- **Check the exit status and fail closed.** `gh auth token` prints nothing to
  stdout on failure; the sibling then runs unauthenticated and the failure
  surfaces as a vendor 401 attributed to the wrong cause. A silent downgrade in
  the credential path itself.
- **Resolve the source binary absolutely.** `exec.Command("gh", …)` resolves
  through the *host user's* `PATH`, and the appendix already records that a `gh`
  shim first on `PATH` was used as a measurement technique. A PATH-resolved
  per-invocation host exec is the most privileged position in the system.

`sshproxy` is the same idea one layer out — it holds no key material and asks the
host agent per operation — which is why this is a shape to reach for rather than
an invention. Cost: the source is re-queried per invocation, and a keyring-backed
account may prompt or be slow. Bound it with (h)'s invocation budget.

##### Why the Go caveat forces that shape

A credential read into a variable becomes a heap slice; the GC may move and copy
it; a `string` conversion is immutable and unfindable; zeroing what you still hold
does not reach the copies.

##### D5 amended: no cipher, but `memfd_secret` where a buffer must exist

**No in-memory cipher.** The key shares the address space with the ciphertext, so
whoever reads one reads the other; it narrows only a one-shot or post-mortem read;
and the Go caveat removes even that.

**But the first draft's "the three controls below are cheaper and strictly
stronger" is REFUTED. [M]** `memfd_secret(2)` is available on this host
(`CONFIG_SECRETMEM=y`), works unprivileged inside the distrobox, needs no boot
parameter, and beats every prctl:

```
[secretmem] VmFlags: … lo dd …    lo = VM_LOCKED, dd = VM_DONTDUMP
[anon     ] VmFlags: …            neither

with PR_SET_PTRACER_ANY, same uid, dumpable = 1:
  secretmem  pread = FAIL errno=5 (EIO)
  anon       pread = 32 bytes: "NORMALHEAP_TOKEN_ghp_BBBB"
```

One syscall, no prctl, no pasta collision: excluded from core dumps by
`VM_DONTDUMP` regardless of `RLIMIT_CORE` or of systemd's cooperation, never
swapped, unreadable through `/proc/<pid>/mem`, and off the kernel direct map. It
is the off-heap shape the first draft identified and then discarded, and it is
strictly better than `mmap(MAP_ANON)`+`mlock`, which is still `/proc/<pid>/mem`-
readable and still dumped.

**Where a buffer must exist — and the redactor's window is exactly such a case —
it belongs in a `memfd_secret` mapping, not the Go heap.** Keep "no cipher"; drop
the generalisation to all in-memory protection. `mlock` alone is retired: it is
strictly weaker than `memfd_secret` and needs a buffer that lives long enough to
matter.

##### The controls, reordered by what actually works

1. **`PR_SET_DUMPABLE = 0`.** The only one of the two prctls that stops the dump.
   **[M]** Mechanism corrected: `/proc/<pid>` itself is **not** reparented — the
   kernel keeps the mode-0555 directory owned by the user so `stat` still shows
   it — but its *entries* are, and a same-uid process then gets **EACCES** on
   `mem`, `environ`, `maps`, `fd`, `fd/0`, `ns`, `ns/user`, `ns/net`, `root`,
   `cwd`, `exe`, and **EPERM** on `PTRACE_ATTACH`. `cmdline` and `status` stay
   readable. Calibration: this host runs `yama/ptrace_scope=1`, which already
   blocks `mem` and attach from a non-ancestor; the prctl's marginal gain here is
   `environ`, `maps`, `fd`, `ns`, `exe`, `cwd`, `root`. It still earns its place,
   because `ptrace_scope=0` is common elsewhere.
2. **`RLIMIT_CORE = 0`, hard limit, second — and on this host it suppresses
   nothing by itself. [M]** `core_pattern` is
   `|/usr/lib/systemd/systemd-coredump`, and **the kernel ignores `RLIMIT_CORE`
   for piped dumps**:

   ```
   mode=none      WCOREDUMP=YES     kernel dumped -> pipe
   mode=rlimit    WCOREDUMP=YES     kernel dumped -> pipe   <-- RLIMIT_CORE = 0
   mode=dumpable  WCOREDUMP=no
   ```

   The full address space was written into a root-owned helper outside the
   container; `coredumpctl` then reported *"terminated abnormally without
   generating a coredump"*, which is **false** — the kernel generated it and
   systemd-coredump volunteered to discard it after reading the rlimit via `%c`.
   Suppression is a userspace helper's cooperation, not a kernel guarantee, and a
   host with a different `|helper` gets nothing. Set the **hard** limit: **[M]** a
   soft-only limit is restored by any descendant (`cur=0 max=-1` → `rc=0`).
3. **Re-apply `PR_SET_DUMPABLE = 0` in the credential child, after its `execve`.**
   **[M]** Dumpable resets on **every** `execve` — the one claim in the first
   draft nothing broke — and the kernel's special cases run the other way (1
   normally, `fs/suid_dumpable` = 2 for a privileged exec). So a process hardened
   before the exec is not hardened after it, and **the process holding the
   plaintext is not the one that was hardened**: end to end, with both controls
   applied in the parent, the credential source's post-`execve` crash still
   produced `WCOREDUMP = YES`. This needs a pre-exec hook (`SysProcAttr`), not a
   parent-side call. Same shape as `--seccomp`-after-`--`: a control set before a
   boundary and assumed after it.
4. **On the supervisor stage the prctl collides with the pasta attach, and this is
   now MEASURED, not `[R]`.** `/proc/<stage>/fd/<n>` and `/proc/<stage>/ns/user`
   both return **EACCES** to a same-uid process, and pasta drops privileges before
   opening a path — the same reason it already refuses `/proc/self/fd/<n>`
   (`SUPERVISOR-DESIGN.md` §1). Either set it after pasta has attached, or not at
   all. Independent of secrets, the stage is worth making non-dumpable: it holds
   `CAP_SYS_ADMIN` over its user and network namespaces for the whole run.
   *The stage is now in the tree* — it started as unmerged work this section was
   written against, and `SUPERVISOR-DESIGN.md` §9 already records the neighbouring
   finding from its own side: a same-uid ancestor can steal the supervisor's end
   of the socketpair in the `ready`→`start` window. Both point the same way, and
   §9 says it in one line — *"much cheaper to design before a pathname socket
   exists than after"*.

##### The tension has two resolutions, not three

*"snug never sees the credential"* and *"snug redacts the credential from the
sibling's output"* are mutually exclusive: a matcher must know the value.

**The rolling hash is struck as the way out. [M]** Implemented exactly as
recommended — the process holds only `H` and `len`, redaction works, the payload
sees `[REDACTED]` — and an external same-uid scan still found the plaintext in its
address space. It is unavoidable: **a sliding-window matcher must buffer `len`
bytes before it can decide whether to emit them, so when the window aligns, the
buffer *is* the secret.** Positive control confirmed the scanner (`SECRET_FOUND=2`
when the process deliberately held it).

Two further defects, recorded so the idea is not re-proposed:

- **A single-stage Rabin-Karp is forgeable**, varying four trailing bytes:
  collision at modulus 2¹⁶ in 41 k tries, 2²⁴ in 7.8 M, **2³¹ in ~2 minutes on one
  core**. An attacker who can force prefilter hits also forces the expensive
  confirm on every window — a denial of service.
- **`H(secret)` + `len` is not "nothing".** For GitHub tokens it is not a break
  (`ghp_` is 2¹⁷⁹, fine-grained 2⁴⁸⁸, against 2⁸¹ for a million GPUs for a
  decade), but the mechanism was scoped to no particular credential, and the same
  design over a passphrase (2⁵²), a 16-hex key (2⁶⁴) or a PIN (2²⁰) is an offline
  break. **Salting does not fix it** — the threat is a core dump, which contains
  the salt. And `len` alone fingerprints *which* credential type was held.

So the two real resolutions:

- **Matcher in snug**, which then sees the credential, with its window in a
  `memfd_secret` mapping and controls 1–3 applied. Redaction is described as
  accident hygiene, never a boundary.
- **Matcher in the sibling**, keeping snug clean — but arbitrary code in the
  sibling bypasses it (§3.3.6 c), leaving the structural legs alone.

If a hash is kept for other reasons, it must be **two-stage** (weak rolling
prefilter, cryptographic confirm), restricted to high-entropy credentials, and its
denial-of-service named.

---

### 3.10 The option space for keeping the credential outside — GitHub as the worked example

**Why this section exists.** §3.3.6 spent a full design pass trying to *bound* a
credential snug did not mint, and every leg failed on the same axis: A2. The
lesson generalises past `gh`.

> **If you cannot bound the authority, do not accept the credential — get a
> smaller one issued.** Every good answer below either needs no credential at
> all, or replaces the human's credential with one whose blast radius the
> *issuer* enforces. §2.1's A3 already said why that dominates: server-enforced
> scoping "holds even if every line of snug is wrong".

**No ranking, and no single pick — the owner's steer, 2026-08-13.** Anything that
keeps the credential out of the sandbox is admissible, they compose, and different
users have different setup budgets. What follows is the space, each option with
its A1/A2/A3 score and its abuse sentence, so a reader can choose rather than be
told.

**One correction against this document's own earlier verdict.** §3.2 rated a
broker "too hard", and §3.3.4 built its comparison on the assumption that a filter
*is* the boundary. That assumption is what changed. Behind a **fine-grained PAT
scoped to one repository**, a filter bug costs one repository rather than an
account, so the filter becomes defence in depth and stops needing to be perfect.
The reversal is in what the filter must be correct *about*, not in the difficulty
of writing one. Note also that §3.2's verdict was aimed at filtering `gh api`'s
argv and at a *general* API broker; three to five endpoints with `{owner}/{repo}`
pinned from the target's remote is a different object.

#### Class A — no credential exists

**A-1. The repository's own CI does the API half.** `git push` already needs no
credential (`git_protocol: ssh` plus the ssh-agent proxy, §3.7). So do not call
the API from the sandbox: push a branch and let a workflow open the PR, comment,
label, cut the release. The credential is then `GITHUB_TOKEN` **on the runner** —
repository-scoped, job-lifetime, non-renewing, minted by GitHub — and snug never
touches it.

*A1 n/a, A2 n/a, A3 server-enforced narrow.* Zero adapter to maintain, and the
"filter" is a workflow file reviewed where the human already reviews things.

*Abuse:* **a hostile process can push a branch, triggering whatever automation the
maintainers wrote** — which is the abuse the human accepted when they enabled CI.
It grants nothing over what the ssh-agent proxy already grants. Caveat to state
rather than discover: push plus a workflow-file edit is code execution on the
runner, and that is true of the ssh proxy today, so it is pre-existing rather than
introduced. Branch protection and `CODEOWNERS` on `.github/workflows` are the
mitigation, and they are the repository's to set.

*Costs:* latency (push → workflow → effect), and it only works where you control
the repository's automation.

**A-2. Unauthenticated reads.** The public REST API needs no credential, only IP
rate limits. The problem is **writes**, and **private repositories**. Say so
before designing anything: half the demand disappears.

**A-3. Intent as data, executed by the human.** The sandbox writes what it wants
done into the target; the human reads it and acts. §3.0 with no machinery. Slow,
and correct for anything high-stakes (a release, a permission change).

**A-4. Work on a mirror.** The agent's clone has no remote at all; snug pushes at
teardown after the human approves. Composes with A-3 and D-2.

#### Class B — a narrower credential, issued by the vendor

The family the lesson points at. Each of these is *still injection* — and each
produces an object that passes §2.3's A1 ∧ A2 test, so by D1's own definition it
is a **capability, not a credential**.

**B-1. A GitHub App installation token.** The App's private key stays on the host;
the host mints an installation access token per run. **One-hour expiry,
scoped to chosen repositories *and* chosen permissions, and unable to mint
another** — minting requires the App key, which never enters the sandbox. It
cannot add an SSH key to a user account, because App permissions do not reach
there.

*A1 one hour (see B-4), A2 **no**, A3 server-enforced narrow on two axes, A4 bounded
to the installation.* This is the closest thing GitHub has to the ssh-agent
proxy's calibration point.

Best property: **`gh` reads `GH_TOKEN` and simply works.** No verb set, no argv
filter, no sibling sandbox, no broker. snug's whole job is mint, stage, expire.

*Abuse:* *a hostile process can perform the permissions granted to this
installation, on the repositories granted to it, for one hour.* One sentence, and
the blast radius is a vendor-side fact rather than one of our claims.

*Cost, and it is the deciding one:* the human creates and installs a GitHub App
once. That ceremony is the reason this is not simply "the answer".

**B-2. A fine-grained PAT.** Same shape with less ceremony and a coarser floor:
per-repository, per-permission, with an expiry the human picks. Weaker than B-1
on A1 (days rather than an hour) and on rotation, stronger on setup cost. §3.1
already recommended this; what it lacked was B-4.

**B-3. A per-repository deploy key** in place of the user's key in the agent
proxy. Not the API half, but it narrows the half that already works: the ssh
proxy currently pins *one key*, and that key is usually the user's, with account
reach. A deploy key is server-scoped to one repository.

**B-4. Revoke at teardown — and this is the cheapest item in the whole
document.** If snug **minted** the token, snug can destroy it: `DELETE
/installation/token` for B-1, the PAT-deletion endpoint for B-2. That converts A1
from "one hour" or "thirty days" to **"dies with the sandbox"** — the exact
property that makes the ssh-agent proxy the calibration point, achieved for a
bearer token, in one HTTP call at exit.

With B-4, B-1 passes A1 ∧ A2 **by construction rather than by expiry**, which
removes the last reason to prefer a broker over injection for this case.

*Requirement:* teardown must be best-effort *and* the design must state what
happens when it fails (process killed, network down) — the honest answer is "the
token lives out its expiry", which is why a short expiry is still chosen and B-4
is a narrowing rather than a replacement.

**B-5. OIDC / workload identity — the general form.** The sandbox holds an
*assertion of identity*, not a credential, and a third party exchanges it for a
short-lived scoped token. For `aws`/`gcloud`/`az` this is the entire answer and it
is cleaner than anything GitHub offers: `AssumeRoleWithWebIdentity` and its
equivalents are designed for exactly this. §3.3.5 files those tools under
"protocol"; the more useful sentence is **"they already solved this — use their
mechanism instead of writing one"**.

**B-6. Ask the vendor first, always.** npm granular access tokens, GitLab
project access tokens, PyPI project-scoped API tokens, container registry robot
accounts. Before designing a broker for any tool, check whether the issuer will
mint something narrower. It is always cheaper than a filter and always stronger
(A3).

#### Class C — the credential stays outside and the sandbox drives

**C-1. An endpoint allowlist over a scoped PAT.** §3.2's broker, with the emphasis
inverted: the **PAT's scope is the boundary** and the allowlist is defence in
depth. The rules are endpoints, not a CLI grammar, and `{owner}/{repo}` is pinned
from the target's git remote, **never chosen by the sandbox**:

```
POST /repos/{pinned}/pulls
POST /repos/{pinned}/issues/{n}/comments
GET  /repos/{pinned}/pulls/{n}
```

Three to five rules, reviewable against an API reference in an afternoon, no
`gh api` escape hatch because a wire has none.

*Abuse:* *a hostile process can perform these N operations on this one repository
for the sandbox's lifetime.*

*Cost:* the agent's real tools do not speak it — which is what §3.3.3's stub on
`PATH` exists to fix, named `snug-gh` rather than `gh` so it fails legibly.

**C-2. A request signer, not a proxy.** The sandbox composes the request; the host
attaches the credential and forwards. §3.3.5 already calls this "the best case of
all" for AWS — with SigV4 **no bearer token exists even in flight** — and then
never generalises it. It is the ssh-agent shape for HTTP: an oracle that signs
what it is given, bounded by identity rather than by intent.

**C-3. Split the agent.** The privileged half runs outside the sandbox holding the
credential and exposing a handful of operations; the untrusted half runs inside.
Identical in mechanism to C-1, different in who defines the verbs: **the agent's
own operations**, snug-defined and small, instead of a vendor CLI's grammar. This
is the version where the verb set is genuinely closed, because we wrote it.

**C-4. mTLS with a host-held client certificate**, where the vendor supports it.
The sandbox's traffic passes through a host-side terminator presenting the
certificate; no key material inside. Rare outside enterprise APIs, listed for
completeness.

#### Class D — bound the run rather than the credential

**D-1. Time-boxed unlock.** The credential is reachable only during a window the
human opens out of band. Reduces A1 to minutes and composes with everything.

**D-2. A post-hoc effect gate.** The sandbox accumulates *intended* side effects;
at exit snug prints them and the human approves once; snug then executes them
outside. The human reviews a diff of **effects**, not of code — which is the
review they can actually perform. Composes with A-4.

**D-3. An invocation budget**, per §3.3.6 (h). Not a boundary; it converts an
unbounded oracle into a bounded one, which is the difference between a
byte-at-a-time extraction and a failed attempt.

#### Class E — detect and attribute, never protect

**E-1. Canary credentials.** Stage something that looks real; any use alerts.
Cheap, and honest about being detection.

**E-2. Per-run identity.** One installation token per run means a leaked token
names the run that leaked it. Free with B-1.

#### Dead ends, named so they are refused rather than rediscovered

- **A header-injecting proxy.** Injecting `Authorization` requires terminating
  TLS, which requires snug's CA in the sandbox's trust store. Honest note: doing
  that to set one header and check one path is *not* the semantic filtering of a
  rich protocol that "95% correct is 0% sound" was written about — so the argument
  against it is weaker than it first looks. It is still refused, on the record:
  a CA in the sandbox's trust store is an asset whose compromise is silent, and
  C-1 gets the same result without one. A **CONNECT** proxy needs none of this
  (§3.3.6 f).
- **Filtering `gh`'s argv** — §3.3.4, and §3.3.6 (c) adds the measurement that
  finishes it: the repository is an argument and git treats repository data as
  code.
- **A DNS-plus-IP pin** — §3.3.6 (f), refuted three ways.
- **Injecting the user's OAuth token or a classic PAT.** A2 true. §2.3.

#### What this answers

**Q7 is answerable now, and better than "a fine-grained PAT and stop".** For
`gh`: **A-1 where the repository's automation is yours, B-1 + B-4 where it is
not, C-1 where a GitHub App is more ceremony than the user will pay for** — with
A-2 and B-3 taken in every case because they are free. None of them puts a
credential snug did not mint inside the sandbox, and none of them is a
placeholder.

That leaves placement D for what it is actually good at: a tool with a closed verb
set and **no repository as input**. §3.3.5's own best candidate — `npm publish` /
`cargo publish`, one write-only verb, one artefact path — and even there, B-6
should be checked first.

---

## 4. Interactions with the profile model

- **A `broker` key needs sub-structure** (`host`, `listen`, `env`, a *secret
  reference*, an `allow` list) — the earlier audit covered this. Additions: it would be the
  first **declarative** profile key whose value *references a secret* — **not the
  first, as this bullet claimed until 2026-08-13**: `identity.gh_user`/`gh_host`
  already select which host account's OAuth token is minted and staged inside
  (`internal/cli/identity.go`), and `identity.ssh_key` already selects which of the
  host agent's keys becomes the sandbox's signing oracle. The mechanism has
  shipped for a milestone; only the declaration is new. That reference must
  resolve only on the host and never be expandable from `{…}` variables the
  sandbox can influence (the rule `PARAMETERISED-PROFILES.md` already applies to
  arguments) — **and that rule does not hold today**, see §4.1; `allow` lists
  **union** across profiles, which preserves
  monotonicity — adding a profile can only widen the broker, so a "read-only
  GitHub" profile cannot prevent a second profile widening it, and that must be
  said out loud; and two profiles declaring a broker on the same `listen` address
  is the same-path conflict of INDEX §3.4 and should be **fatal**, because silently picking
  one makes the effective credential boundary depend on profile order.
- **A `stub` key would be the first key that stages an executable.** Today a
  profile stages one by binding a file *inside* `policy.StagedBinDir`, and that is
  defensible because the directory is snug's — it is in `snugsOwn`, a profile
  cannot mount at it, and snug alone decides it goes on `PATH`. A key saying
  "stage this
  binary and put it first on `PATH`" does grant, and it grants the most powerful
  thing in the model — code that runs before the tool the human named. Its abuse
  sentence has to be written before its syntax.
- **`env` is the live leak and it is a profile key.** `@claude` names
  `ANTHROPIC_API_KEY` in `env` today, and §1.1 shows the value both leaks
  passively and *wins* over the OAuth token. Options, all with costs: refuse
  credential-shaped names (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`) at parse
  time, like `checkName` and `DisallowUnknownFields` — fails closed and loudly,
  but it is a name heuristic with false positives (`GPG_KEY_ID`, `SSH_KEY_PATH`);
  keep `env` permissive and **redact in `--dry-run`** — cheap, honest, does
  nothing about `/proc/*/environ`; or add an explicit `env_secret = [...]` so the
  human's intent is on the page. Note this is *not* a deny rule in the
  invariant-1 sense: refusing a profile at parse time makes the profile invalid,
  it does not narrow a grant.
- **`--dry-run`'s `covered()` must understand `KindData`** (§1.2b). A correctness
  fix to the trust artifact, not a feature.
- **A broker socket must be staged through `Policy.Replace`, not written into
  `p.Mounts` directly** (§1.2d). That hardening reduced the post-resolution writers to
  exactly one and made `rejectMasking` exempt on the `Authored` field; a broker
  that bypasses `Replace` re-opens the hole it closed, and would do it in the
  one place — a socket carrying a credential — where the provenance line matters
  most.
- **A broker socket is a new *kind* of hole in the `--dry-run` rendering.** Today
  the security-relevant surface is mounts, env, network. A broker's host, listen
  address and **full allowlist** are the boundary and must be printed as such — a
  mount line saying `rw /snug/anthropic.sock` tells a reader nothing.
- **`snug -p @claude` has no network today** (`include = ["sys","home"]`) **[M]**,
  so a brokered `@claude` changes the recommended invocation from `-p @claude -p
  @net` to `-p @claude` alone. A genuine usability win — *provided* §1.3's engine
  channel is closed, or the docs stop claiming that no `@net` means nothing
  leaves.

### 4.1 A secret reference and a profile parameter are one expander and two destinations

The owner's observation, 2026-08-13: this is converging on
`PARAMETERISED-PROFILES.md`. It is, and the convergence is one level down from
where the bullet above placed it.

> **A parameter's resolved value becomes part of the policy and is checked by
> every rule the policy has; a secret reference's resolved value must never
> become part of the policy at all — so the two share every rule about the
> *selector* and no rule about the *result*.**

A parameter is substituted into text that becomes a `Mount.Guest`, a `Mount.Host`,
a port or an env value, and is then seen by `splitSpec`, `underTargetIsLiteral`,
`join`, `rejectMasking`, `Validate` and `--dry-run`. **That visibility is the
security argument.** A secret's resolved value must be seen by none of them — not
in `p.Mounts`, not in argv, not on a screen, and per D5 not even in a Go
`string`, which is precisely what the expander produces.

**So a secret reference is a parameter in its selector and a resolver in its
result.** "Mint a GitHub App installation token for `{repo}`" decomposes cleanly
into the two layers rather than being circular, which is the test that the split
is real.

**Shared, and inherited wholesale from `PARAMETERISED-PROFILES.md` §origins:**
never from environment variables (direnv auto-loads `.envrc` from the repository
you are standing in — the sandboxed material would author its own boundary);
never from files read at resolve time; never from anything derived from the
target's *contents*; `Profile.Trusted` must actually be read, which makes
invariant 3's gate a prerequisite rather than a follow-up; and duplicate
declarations are fatal via `scalarConflict`, never last-writer-wins.

**Not shared:** the result. A selector is text; a resolver names an action, and
"a command to run" is host code execution chosen by a profile. The rule both
documents already imply and neither states in one place:

> **A profile may name *which* secret, from a closed set of snug-shipped
> resolvers. It may never name *how* to get one.**

That is the shape `identity.gh_user` already has — the account is data, the `gh
auth token` invocation is compiled in. A `secret_command = "…"` key inverts it and
is D3's executable plugins under a shorter name. It also resolves D3 against this
section: profiles *can* broker, because they select from a closed set rather than
supplying the mechanism.

**Parameterisation is parked, and composition by `include` is the better answer
for this case anyway** — the owner, 2026-08-13. `PARAMETERISED-PROFILES.md` is an
idea, not a plan — deliberately deferred, see that document's own status — and nothing below should be
read as scheduling it. The concrete question is how a user pins one of two
accounts, and there are two spellings:

```toml
# parameterised:  -p '@claude(personal)'
# include-based:  -p claude-personal
[profile.claude-personal]
include = ["claude"]
  [profile.claude-personal.identity]
  gh_user = "personal"
  ssh_key = "~/.ssh/personal.pub"
```

**The include-based spelling wins, and it wins by needing no new mechanism.** It
works today. The name is a *name*, so it renders as-is in `SNUG_PROFILES`, in
every `Mount.From` provenance and in `--dry-run`, where a parameterised instance
needs `canon` to render the argument — which is the entire complexity of the
parked design, along with its injectivity rule about `,`, `:` and NUL. Four lines
of file, not a duplicate of `@claude`, because `include` does the work.

Crucially it also makes **the whole shared-selector half of this section moot**.
A literal in a trusted-layer file has no argument-origin question: no
`-p name:arg` token to classify, no `--config` layer to demote, no `SNUG_PROFILE`
environment hazard, nothing for `Profile.Trusted` to gate. Those rules only
become load-bearing **if** parameterisation lands, and they are written here so
that whoever builds it inherits them rather than rediscovering them.

Two accounts at once is not a gap either way: **identity does not join.** Two
profiles pinning different identities is a hard conflict naming both
(`internal/policy/resolve.go`), which is the right answer and is what you want —
and a parameterised `@claude(personal) @claude(work)` produces two instances with
different canonical names, so the same conflict fires through more machinery.

**Sketch, if a declarative secret reference is ever built:** a typed sub-table
whose `from` is a closed enum
validated at parse time (so an unknown resolver is a fatal parse error, not a
silently ignored grant), every other field a selector going through the ordinary
expander. Selector expansion stays in `Resolve`, pure and host-side. The secret
resolves later, after `Validate`, in the `startIdentity` band, straight into the
consumer's descriptor. Stricter than the parameter rule in one place: **`{target}`,
`{target_parent}` and `{host_tmpdir}` are forbidden in a secret selector,
`{home}` only** — `{target}` is legitimate for a grant because the human chose the
directory, but which *credential* is used must not be steerable by the material
being sandboxed. And if parameterised profiles ever land, the join is one line:
a selector may be a template argument, and `canon` includes the expanded
selector, never the resolved secret.

**Three findings this comparison produced, all against shipped code:**

1. **`identity.ssh_key` broke the rule the bullet above asserts. FIXED
   2026-08-13.** It went through `expandVars` against the full `vars` map, which
   contains `{target}` — and unlike a `ro`/`rw` grant it did **not** pass through
   `underTargetIsLiteral` or `EvalSymlinks`. A profile writing `ssh_key =
   "{target}/deploy.pub"` followed a symlink a previous sandbox run planted, and
   since the path is *read* for the blob the proxy answers `REQUEST_IDENTITIES`
   with, redirecting it selects **which host key the sandbox may sign with**.
   Not reachable from any builtin, so the severity was low — but the rule §4
   stated as already holding did not hold, which is the part worth remembering:
   this section's whole argument is that the selector rules are shared, and the
   one place they were already needed was the one place they were missing.
   A key under the target now gets what a bind gets; outside it is deliberately
   not canonicalised (`internal/policy/identitykey_test.go`).
2. **The control-character rule is missing from both design documents, from
   opposite halves.** `PARAMETERISED-PROFILES.md` refuses `,`, `:` and NUL in an
   argument but justifies it *only* by canonical-name injectivity, never
   mentioning the argv-NUL hazard; this document never mentions control
   characters in a broker or secret value at all. The rule lives only in
   CLAUDE.md and in three code sites. Both new value classes are profile-authored
   text that reaches a rendered screen, and one of them reaches an argv. This is
   verbatim the "a rule written once and applied to one of its two halves" shape.
3. **`--dry-run` has an undisclosed host-side side effect.** `startIdentity` runs
   *before* the dry-run branch, so `snug --dry-run` really does shell `gh auth
   token` and stage a live token — and prints it as an unremarkable `data` mount
   row with nothing marking it as a credential. That is Q9 with a sharper edge
   than Q9 states: not only does the dry run start things, it resolves a secret
   and does not say so.

**One contradiction to resolve wherever the merged rule ends up living:**
`PARAMETERISED-PROFILES.md` forbids "files read at resolve time" as a value
source, and §3.9 *requires* exactly that — running the credential source and
piping it onward. Both are right under the selector/result split and neither
document states the split, so the next reader will cite one at the other.

---

## 5. Decisions — 2026-08-08

### D1 (was Q1) — the principle. SETTLED.

**The problem being fixed.** The earlier audit's principle text is good and mostly worth
keeping verbatim, but it is written as an absolute (*"No credential … is placed
inside the sandbox"*) and then carries an exception (*"a profile may still stage
a real credential"*) that swallows it. An invariant with an exception can only be
checked by understanding where the exception applies — precisely the argument
CLAUDE.md invariant 1 makes about `--read-only`.

**Two drafts.** **Draft A** kept the absolute and made the exception a different
noun: a profile whose name ends in `-credentials`, never in `defaults`, never
implied by `include`, and selected explicitly every time. Attractive because the invariant
stays checkable by grep — nothing outside `*-credentials` staging a credential —
rather than by judgement; it lost because the absolute is a dishonest sentence
for as long as `@claude` stages a credential, and the only fix is renaming
`@claude`. **Draft B** — *"a sandbox may hold capabilities, never durable
authority"* — states the rule the measurements support: a **capability** ends
with the sandbox and cannot extend itself (the ssh-agent proxy is canonical), a
**credential** outlives the run or can renew or widen itself, and the test is
§2.3's A1 ∧ A2 in that order.

**Draft B wins**, because it explains why ssh-agent is fine and
`admin:public_key` is not without special-casing either, and with no false
absolute. `@claude` therefore does **not** need renaming — that was Draft A's
entire cost. Cost accepted: "capability" is a second noun, against the project's
standing rule against second nouns for one concept — allowed because these are
genuinely two concepts. Neither draft bounds what the sandbox *does* with a
capability — a broker pins the identity and the operation set, never intent
(§3.2) — nor what the sandbox writes into the target directory (§1.2f).

**And the weasel word is struck.** The owner's first phrasing was *"credentials
SHALL NOT enter the sandbox **if possible**"*. `if possible` goes: it is the only
clause nobody can check,
and it hands every future adapter author the right to decide what "possible"
means for their own case — the same pressure that would put `@net` in
`defaults`. The test replaces it. Final text:

> **No credential enters the sandbox. A capability may — under a profile that
> names it.**
>
> A *credential* is a bearer secret that is broad, long-lived, or self-renewing:
> it can mint further access, and revoking it costs the human something. A
> *capability* is scoped, independently revocable, and its worst case fits in one
> sentence. **Which one a given secret is, is measured, not asserted — if you
> cannot write the blast radius in one sentence, it is a credential.**
>
> A capability enters only under an opt-in profile, never in `defaults`, and that
> profile's TOML carries its abuse sentence and its blast radius. `--dry-run`
> names every secret the run places inside, and where.
>
> **A broker answers from what the policy pinned, not by filtering what the host
> offers.** Where snug brokers access to a secret, the sandbox can neither
> enumerate what else exists nor request it: the ssh-agent proxy answers
> `REQUEST_IDENTITIES` with the pinned key alone and never forwards the question
> (`internal/sshproxy/proxy.go:139`); `gh`'s `hosts.yml` is generated with one
> account rather than bound (`internal/cli/identity.go:192`). Where snug cannot
> broker and must place a secret inside, it places the smallest form that works,
> and the profile states what that form still grants.

The last paragraph is a **requirement on brokers, not a description of snug
today**: `@claude` currently copies `.credentials.json` whole
(`internal/cli/claude.go:49`) and so fails its final clause until D2 lands. It earns
its place by being the sentence a future adapter fails — "forward the request and
filter the reply" is the design that always looks equivalent and never is; one
missed message type and the filter is a sieve.

**Two clauses survive from Draft A regardless of which draft won, because both
are definitional rather than structural:**

> *Public material is not a secret.* A public key, username, email or host
> fingerprint is generated into the sandbox on purpose. Without this said out
> loud, "no credential enters the sandbox" appears to forbid `known_hosts`, the
> pinned `.gitconfig`'s `user.email`, and `hosts.yml`'s account name — all of
> which snug generates deliberately and none of which is a credential.

> *A broker stays small, snug's own, and reviewable — **never a user-supplied
> script, and never a host command whose arguments the sandbox chose**.* The
> second half is the one-line verdict on §3.3.2: an argv filter in front of a
> real host binary is the shape this rule exists to refuse.

**And the closing rule, because it is the failure mode this whole area actually
has:**

> The failure mode of a missing or broken adapter is **"that tool has no
> credentials inside"** — a hard error, visible and annoying. It is **never** a
> fallback to injection. A fallback path is how deadline pressure reopens a hole
> that was already closed once.

Surfacing, per the owner: `--dry-run` gets a SECRETS section (per-run: what this
run places inside, and where — it is the only surface that knows the selection).
`doctor` gets the static inventory instead: *"profiles installed on this host
that place a secret inside: …"*, with each one's class and blast radius read from
its TOML. `doctor` runs before any profile selection exists, so it cannot answer
the per-run question and must not pretend to.

### D2 (was Q2) — two profiles, access token by default. SETTLED in shape; the size of the box still needs Q3/Q4.

Today `@claude` stages the credential file byte-for-byte, so the sandbox holds
the refresh token too: ~20 days, self-renewing. That is the row the severity
model marks **never inject**, so `@claude` as shipped violates D1. The split,
agreed with the owner:

- **`@claude`** — stages `accessToken` only (§3.5's parse-and-project). Hours,
  non-renewing. The common case, and the default.
- **`@claude-refresh`** — stages the pair. Abuse sentence: *"a hostile process
  inside can renew this token for ~20 days and rotate it."* For the overnight
  agent where re-login is not acceptable.

**Not a boolean in `config.toml`.** A switch that widens what enters the sandbox
*is* a grant, and config holds preferences and never grants — a boolean there
would be the first exception, invisible in `--dry-run` and `SNUG_PROFILES`, so
you would have to read a host file to know which of the two things your sandbox
is holding. Same shape as `@net`: the grant is the profile you named.

Bounding facts, verified while deciding this:

- **There is no sync-back** (`internal/cli/claude.go:31`) — the staged copies are
  tmpfs and die with the run, deliberately, because writing a host file from
  sandbox-authored bytes is a channel out. So a token refreshed or re-acquired
  inside never reaches the host. (The repo's own CLAUDE.md claims the opposite;
  that is on the truth-telling list — §1.2f.)
- **`/login` inside the sandbox mints a fresh pair, refresh token included**, so
  stripping is a speed bump rather than a boundary. Two things bound it: OAuth
  needs the human's browser session, so re-acquisition is not an autonomous
  escalation — only one the agent can *ask* for ("your session expired, please
  log in again"), a social-engineering class rather than a technical one; and
  with no sync-back the re-acquired token dies with the sandbox. Blast radius is
  that sandbox's lifetime, which is why it matters for a long-running agent and
  not for a 20-minute build.

Still open, and both measurements rather than decisions: **Q3** and **Q4**.

### D3 (was Q10) — no extensibility mechanism. YAGNI. SETTLED.

The owner's ruling: **ignore third parties and extensibility.** No plugin API, no
adapter registry, no generic description format — the shape will be clearer once
there is more than one real adapter to generalise from, and inventing it before
then is guessing. Both options on the table are dropped for now:

- **Executable plugins — dropped, and not only on YAGNI.** An adapter runs on the
  HOST, reads the host's secrets, and decides what enters the sandbox: the most
  privileged position in the system, strictly above a profile, which can only
  name paths. Plugins would load from `~/.config/snug/plugins.d` — the layer
  invariant 3 already admits is trusted unconditionally, so pointing
  `XDG_CONFIG_HOME` at a checked-out repo loads it. Today that hole yields
  profile grants; with plugins it would yield host code execution with the user's
  credentials. If ever revisited, invariant 3's designed gate (explicit
  `--config`, privileged grants refused from untrusted layers) is a
  PREREQUISITE, not a follow-up.
- **Declarative descriptions — deferred, not rejected.** A third party
  contributing *data* ("this tool reads config from $X, these fields, this env
  var repoints it") with snug's generator doing the work is the safe half of the
  idea: reviewable, diffable, cannot execute. It is what `.gitconfig` and
  `hosts.yml` already are, hard-coded. Revisit when there is a third adapter to
  generalise from.

**What this does NOT settle.** YAGNI stops snug building a *general mechanism*
speculatively; it does nothing to stop snug accreting *one-off adapters*, since
each is individually justified at the moment it is proposed ("we need gh today").
That is precisely how this becomes an integration project with a security story
attached. So there is **no numeric cap, but a bar every proposed adapter must
clear** — the D-Bus test the project already applies:

1. Can the tool's credential handling be expressed in a handful of rules a human
   can read and verify? If not, it gets §3.1 (a narrow token the user mints) and
   no code. A filtering proxy that is 95% correct is a sandbox that is 0% sound,
   and a vendor-API adapter is the same species.
2. Is the tool's config format one the vendor is likely to change under us? `gh`
   rewriting `hosts.yml` on first use cost real time. Cost is accepted only where
   the alternative is a leak.
3. The failure mode of a missing or broken adapter is D1's closing rule: a
   hard, visible error, **never** a fallback to injection.

Also unchanged by D3: **profiles are already the extension point.** Anyone can
write one in `profiles.d` today and stage their own credential with their own
abuse sentence, no snug code and no API. What they cannot do is *broker* — and
brokering is the part that needs snug to be involved at all.

### D4 (2026-08-13) — placement D, amended the same day by four reviews. Scope narrowed; NOT the answer for `gh`.

Where a real tool must run with a credential, it runs in a **sibling snug
sandbox**, never on the host. The owner's ruling was to build both bounds — a
closed verb set (D-verbs) and structurally bounded sinks (D-sinks) — and to
accept the code complexity as defence in depth.

**Four adversarial reviews (red team, policy model, host bridge, memory hygiene)
were run against the draft before any code was written, and they changed the
decision rather than confirming it.** The full corrected argument is §3.3.6; the
three changes that matter to a reader of §5:

1. **The two bounds are not interchangeable.** D-sinks bounds bytes leaving; it
   bounds nothing about what the credential is *spent on*, which is the axis §2.3
   decides on. Pinning egress to the vendor pins it to the one party that can mint
   a durable credential. **D-verbs is load-bearing; D-sinks is exfiltration
   hygiene.** D is inadmissible for an A2-true credential unless the verb set is
   the boundary.
2. **The verb set is not a boundary for any tool that takes a repository.**
   Measured: a payload-authored `.git/hooks/pre-push` and `core.fsmonitor` execute
   under snug's own git neutering, with no argv involved. So **`gh` is out of
   scope for D** — see D6 and §3.10.
3. **D's first step is a control listener snug decided not to build** (issue
   #61, cut on measurement), on a stage where one `start` request `execve`s an
   arbitrary path as uid 0 with a full capability set, and which
   `SUPERVISOR-DESIGN.md` §7 deliberately kept from becoming a server. D makes
   the untrusted payload its second client. Until that is designed, D cannot be
   costed.

**Settled scope:** D is the mechanism for a tool with a **closed verb set and no
repository as input** — §3.3.5's own best candidate, `npm`/`cargo` publish. If it
is built there, it carries the clamped exit status, the invocation budget, the
no-path-fields rule and the CONNECT egress of §3.3.6, and B-6 is checked first.

**Two corrections to what D4 assumed:** the egress pin *does* have an
implementation (`pasta --splice-only` plus a CONNECT allowlist, measured), and the
launch cost *is* measured — 245 ms and ≈53 MB, a ≈2.2× latency tax, not a fatal
one. "Derive the sibling's policy from the parent's" is struck: it is a
restriction operation the model does not have. The sibling gets its own named
profile set and invariant 6 is restated per sandbox.

### D5 (2026-08-13, amended) — no in-memory cipher; never receive the secret; `memfd_secret` where a buffer must exist.

snug does not encrypt credentials in its own memory: the key would share the
address space with the ciphertext, and Go's heap makes the plaintext window
uncontrollable regardless. That part stands.

**What the measurement pass changed:**

- **"The prctl controls are cheaper and strictly stronger" is wrong.**
  `memfd_secret(2)` is available on this host, unprivileged, and gives
  `VM_DONTDUMP` + `VM_LOCKED` and an `EIO` on `/proc/<pid>/mem` even with ptrace
  permitted. Where a buffer must exist — the redactor's window is exactly such a
  case — it belongs there, not on the Go heap. `mlock` is retired as strictly
  weaker.
- **The control ordering was backwards.** `PR_SET_DUMPABLE = 0` is what stops the
  dump. `RLIMIT_CORE = 0` suppresses nothing by itself on this host, because
  `core_pattern` is a pipe and the kernel ignores the rlimit for piped dumps —
  suppression came from `systemd-coredump` volunteering to discard it. Set the
  **hard** limit, second.
- **Harden the process that actually holds the plaintext.** Dumpable resets on
  every `execve`, so the credential child must re-apply it in a pre-exec hook;
  measured, a parent-side call leaves the child dumping.
- **"Never receive" requires an `*os.File`.** `os/exec` passes the descriptor
  through only for that type and silently interposes an in-process `io.Copy`
  otherwise. Load-bearing, and it needs an assertion.
- **The rolling hash is struck.** A sliding-window matcher must buffer `len`
  bytes, so the window *is* the secret when it aligns — measured by scanning the
  process from outside. The tension in §3.9 has two resolutions, not three.

### D6 (2026-08-13) — `gh` gets no credential snug did not mint. SETTLED in direction; the options are a menu, not a pick.

The owner's ruling: **anything that keeps the credential out of the sandbox is
admissible, they compose, and no single method is chosen.** §3.10 is the option
space, each entry scored on A1/A2/A3 with its abuse sentence.

The governing sentence, which generalises past `gh`:

> **If you cannot bound the authority, do not accept the credential — get a
> smaller one issued.** Server-enforced scoping holds even if every line of snug
> is wrong (A3); no filter we write does.

For `gh` in particular: the repository's own CI already holds a repo-scoped,
job-lifetime `GITHUB_TOKEN` (A-1); a GitHub App installation token is
repository- and permission-scoped, one hour, and cannot mint another (B-1); and
**snug can revoke a token it minted at teardown (B-4)**, which converts A1 to
"dies with the sandbox" — the ssh-agent proxy's property, achieved for a bearer
token, in one HTTP call. This answers **Q7**.

---

## 5a. Open questions — the owner's to decide

**Q3 — what does `user:sessions:claude_code` grant? [unmeasured]** If it reads
Claude Code sessions across the account, the access token's A4 is "read every
transcript on this account" rather than "quota theft", the remaining access token
is a credential rather than a capability, and D2's shape probably flips.
Establish this before fixing D2's box size.

**Q4 — does Claude Code work with `refreshToken` removed?** §3.5's mitigation —
and therefore D2 — rests entirely on this, and it was **not tested** this pass.
Five-minute experiment; run it first. Then: does `/login` complete headless, and
at the ~8 h boundary does it fail cleanly, or hang? If it hangs,
`@claude-refresh` is not a convenience but a requirement for anything
long-running.

**Q5 — if a stub is built, what is it called?** (§3.3.3.) `snug-gh`, which fails
legibly, or `gh` on `PATH`, which is ergonomic and a lie an agent will act on?

**Q6 — is "snug runs its own helper inside a snug sandbox" a direction?**
(§3.3.2.) **Answered yes, 2026-08-13, and it is now a prerequisite rather than a
direction:** §3.3.6's placement D *is* snug-inside-snug, and the owner has
decided to build it. What remains open is not whether but at what cost —

- The sibling's policy must be **derived** from the resolved parent policy, or
  invariant 6 ("one `Policy`, one author") is gone. Nobody has designed that
  derivation.
- A sandbox launch per tool invocation — **measured after this was written**: 245
  ms and ≈53 MB, a ≈2.2× latency tax, not the fatal problem. §3.3.6 (m).
- §3.3.6's D-sinks leg (1) — egress pinned to one host — **is buildable after
  all**, and was measured: `pasta --splice-only` plus a CONNECT allowlist. What it
  does *not* buy is the thing it was wanted for. §3.3.6 (f), §3.10.

The supervisor stage (`SUPERVISOR-DESIGN.md`, merged) is what makes the mechanism
affordable: the supervisor already builds a sandbox from a `Policy` and the stage
already holds the namespaces, so a sibling is a normal operation rather than a
fork of `main`. **And it is also where D's largest cost sits**: there is no
control listener and none is coming (issue #61, cut), and a same-uid ancestor
can already steal the supervisor's socketpair end in the `ready`→`start` window
— which is out of the threat model by the same rule as everything same-uid, and
is not out of it once the payload is a client. D would make the untrusted
payload a client of exactly that op. See §3.3.6 (m).

**Q7 — GitHub: build an adapter, or document §3.1 and stop? ANSWERED 2026-08-13,
and the answer is better than either option as posed.** §3.10 opens the space
that was missing: the credential the sandbox holds does not have to be one snug
did not mint. A-1 (the repository's CI holds a job-lifetime `GITHUB_TOKEN`), B-1
(a GitHub App installation token, repository- and permission-scoped, one hour,
cannot mint another) and B-4 (**snug revokes what snug minted, at teardown**) are
each stronger than a fine-grained PAT and none is a placeholder. C-1 — three to
five pinned endpoints over a repo-scoped PAT — is the fallback where an App is
more ceremony than the user will pay. D6.

What remains open is not the strategy but the **build order**: B-1+B-4 is the
smallest thing that makes `gh` work with no A2-true credential inside, and it is
mostly minting code with no filter at all. Is that the next milestone?

**Q8 — the engine egress channel (§1.3).** Partly addressed: step M-a landed
2026-08-09, so snug no longer *claims* offline while the channel is open. The
channel itself remains. Closed (the engine in the sandbox's netns per
`ENGINE-NETNS.md` §5, and/or a registry allowlist at `dockerproxy` refusing
non-allowlisted hosts and any literal IP), or carried as a known gap with
severity? Until it is closed, no broker milestone may claim exfiltration is
closed by construction.

**Q9 — should `--dry-run` stop starting things? ANSWERED, and neither option as
posed.** A third shape was built: the branch was not moved above
`startIdentity`/`startContainers`, and the fidelity was not traded. Both take a
plan-without-starting argument instead, so the socket paths and the staged
`hosts.yml` entry are still the real ones while nothing is started.

The promise is one predicate — `config.startsNothing()`,
`internal/cli/main.go:73`, `dryRun || explain` — and it is the ONE place that
decides it, which is what lets a second screen (`--explain`) inherit the claim
rather than re-derive it. Its own doc names the failure this replaced: eight
separate `!cfg.dryRun` guards, where one missed site is not a cosmetic bug but a
screen claiming it started nothing while holding a socket on the host.

The guards, all of them: the target lock and the orphan sweep
(`internal/cli/main.go:466`), the host tmp directory — NAMED, not created
(`:511`), the git probe (`:529`), the runtime directory (`:631`), the identity
proxy (`:660`), the container engine (`:666`), the http door sockets (`:699`),
and the resolver warning. A ninth guard added tomorrow gets that method by name
or it is wrong for `--explain`, and the compiler cannot say which.

**Q10 — the residual of D3: how many adapters, ever?** D3 settled on a *bar*
rather than a numeric cap, for the reasons in its closing paragraph. What it did
not settle: whether a cap stated *now* — "at most N brokers, and a tool that
cannot be expressed in a handful of rules gets §3.1 instead" — is the thing that
actually holds the line, or whether the bar is enough.

---

## Appendix — how each measurement was made

Scratch under `$CLAUDE_JOB_DIR/tmp/sec`; `snug` built from `d3e6430` at
`$CLAUDE_JOB_DIR/tmp/snug`. No repository file was modified.

| claim | method |
|---|---|
| token scopes, expiry windows | parsed `~/.claude/.credentials.json` in Python, printed field *names*, string *lengths* and decoded timestamps only |
| gh token scopes | `gh auth status` (redacted); two accounts, one keyring-backed |
| `~/.claude.json` contents | enumerated top-level keys and one `projects` entry's subkeys; regex-scanned the whole document for `sk-ant`, `ghp_`, `gho_`, `token`, `apiKey`, `secret`, `password`, `Bearer` |
| `ANTHROPIC_BASE_URL` over plain HTTP; endpoint set; auth header | a Python `BaseHTTPRequestHandler` on `127.0.0.1:8731` logging path + header prefixes and answering 500; `claude -p "say hi" --model sonnet` with `ANTHROPIC_BASE_URL` pointed at it, once with and once without `ANTHROPIC_API_KEY` |
| `--dry-run` prints the key twice | `grep -c` for a sentinel value in the dry-run output |
| `--dry-run` denies what it stages | dry run with a probe identity profile in a throwaway `XDG_CONFIG_HOME` |
| `--dry-run` invokes `gh auth token` | a `gh` shim first on `PATH`, appending its argv to a log |
| socket provenance says `(identity)` | `--dry-run -p @podman-socket`, read the mount line |
| `-v` output carries no secret | read all eight `audit(...)` call sites in `sshproxy` and `summarise()` in `dockerproxy/build.go` |
| no credential sync-back exists | grep for `WriteFile`/`sync` across `cmd/` and `internal/`, minus tests |
| egress without `@net` via the engine | `snug -p @podman-socket <dir>` (no `@net`), payload connects to `CONTAINER_HOST` and issues `POST /v1.41/images/create?fromImage=docker.io/library/hello-world`. Positive control in the same payload: `socket.create_connection(("1.1.1.1",443))` → `OSError` |
| host loopback reachable via the engine | same, with `fromImage=127.0.0.1:<port>/x` for ports 8731 (open), 9, 22 (closed); compared engine error strings |
| `/proc/<pid>/mem` readable inside the sandbox | default sandbox; a Python process spawns a child holding a sentinel string, reads `/proc/<child>/maps` then `/proc/<child>/mem`, searches for the sentinel → found |
| `@claude` implies no network | `--dry-run -p @claude` → `NETWORK isolated` |
| no `auth.json` on this host | `ls ~/.config/containers/` and `$XDG_RUNTIME_DIR/containers/` |

**Explicitly not measured this pass**, and each one is cheap: Q3
(`user:sessions:claude_code`), Q4 (Claude without `refreshToken`), the earlier audit's claim
that `~/.claude.json` is unnecessary, and whether `gh` can be MITM'd via
`GH_HOST` + `SSL_CERT_FILE`.
