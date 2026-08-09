# Secrets

**Status: living design document.** §5 records what is settled; everything else
is analysis, not a decision. It exists so each decision is made against measured
ground truth rather than against what the comments say.

Builds on `TODO.md` §MVY2 → *Findings*. Where this contradicts MVY2 it says so
and gives the measurement.

**[M]** measured on this host this pass (method in the appendix) · **[R]**
reasoned from code or docs, not executed · **[M-prior]** measured by MVY2, not
re-measured.

Versions at measurement: snug `d3e6430`, claude 2.1.226, gh 2.96.0, podman
5.8.3, bwrap 0.11.2, git 2.55.0, Go 1.26.5.

**Re-checked against `ae848de` (2026-08-09), and two findings had moved.** §1.2d
is **fixed** — MVY1 reduced the post-resolution writers to one and made the
masking exemption a field rather than a kind heuristic. §1.3's measurement is
**no longer reproducible on this tree**: it was taken with `@podman-socket` and
no `@net`, and the profile now includes `net` unconditionally, so the "egress
without `@net`" framing no longer names a selectable configuration. The channel
it measured is still open; reproducing it needs a pre-`ae848de` tree. Everything
else was re-verified against the code and holds; several line numbers had
drifted and are corrected.

---

## 0. The three sentences this document is trying to make true

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

MVY2's table is right in shape and wrong or incomplete in five places. The
column that matters most is the last, and MVY2 did not have it.

| # | secret | where it lands | who can read it | authority | outlives sandbox? |
|---|---|---|---|---|---|
| 1a | Anthropic OAuth **access** token | `KindData` writable-tmpfs copy at `~/.claude/.credentials.json` (`cmd/snug/claude.go:49`) | every process in the sandbox | `user:inference`, `user:profile`, `user:file_upload`, `user:mcp_servers`, `user:sessions:claude_code` **[M]** | **yes, ~8 h** **[M]** |
| 1b | Anthropic OAuth **refresh** token | *same file, same line* | same | mints new access tokens | **yes, ~20 days remaining of a rolling window** **[M]** |
| 2 | `~/.claude.json`, 56 500 bytes verbatim | writable tmpfs (`claude.go:50`) | every process in the sandbox | not a credential — a host inventory | disclosure is permanent |
| 3 | `ANTHROPIC_API_KEY` | **the environment** (`base.toml:269`) | every process, passively, via `/proc/*/environ` | **overrides the OAuth token entirely** **[M]** | as long as the key lives |
| 4 | GitHub token from `gh auth token` | `oauth_token:` in a generated `hosts.yml` (`identity.go:192`) | every process in the sandbox | on this host: `admin:public_key`, `gist`, `read:org`, `repo` **[M]** | **yes, indefinitely** |
| 5 | ssh private keys | **never** (`internal/sshproxy`) | nothing — no key material crosses | signing oracle, one pinned key | **no** — dies with the proxy |
| 6 | host container-registry auth | **never enters the sandbox**, but the engine may use it on the sandbox's behalf | — | pull/push as you | broker-shaped already, and undocumented **[R]** |

**Corrections to MVY2:**

- **The scope list was wrong.** MVY2 wrote two scopes; measured, there are five,
  including `user:mcp_servers` and `user:sessions:claude_code`. If the last
  grants read access to Claude Code *sessions*, the blast radius is not "quota
  theft" but "read the transcripts of every other project on this account".
  Nobody has established what it does (Q3).
- **MVY2 counted one Anthropic credential; there are two, unequally severe.**
  The access token expires in hours; the refresh token had ~20 days left and
  mints access tokens. "Until expiry" hides a factor of sixty. Splitting rows
  1a/1b is the whole of the severity argument, and it makes visible a cheap
  mitigation MVY2 did not propose (§3.5).
- **`ANTHROPIC_API_KEY` is not merely leaky, it is authoritative.** Measured:
  with it set, Claude Code sends `x-api-key: <value>` and does **not** send the
  OAuth `Authorization: Bearer`. So `@claude` can put a long-lived org API key
  in `/proc/self/environ` and have it be the credential actually in use. MVY2
  called this a rule violation; it is also a severity upgrade, because an org
  key is typically not user-scoped and not auto-expiring.
- **Row 6 did not exist in MVY2.** `internal/engine` starts the podman service
  with `HOME` set to the host's home (`engine.go:189`), and podman resolves
  registry credentials from `$HOME/.config/containers/auth.json`. This host has
  none **[M]**, so nothing was observed; on a host that has one, a
  sandbox-issued `POST /images/create` or an image push would authenticate as
  the host user. `allowed()` permits everything under `images` except `load` and
  `import`, so `images/{name}/push` is reachable **[R, `proxy.go:270`]**. A
  credential broker that already exists, was never designed as one, and has no
  allowlist over *which registry*.
- **MVY2 said `~/.claude.json` carries "no token".** True on this host **[M]**,
  but the file has two structural slots for one: `mcpServers[*].env` (a map
  injected into MCP server processes; empty here) and, in the sibling
  `settings.json` that `@claude` binds read-only, `env` and `apiKeyHelper`. "No
  token" is a property of *this host's data*, not of the format, so any
  statement about it must be conditional.

**Not present, confirmed:** `.netrc`, git credential helpers, any bind of the
host's `~/.config/gh`, any bind of `~/.ssh`. **[M, via `--dry-run` mount list]**

### 1.2 The places nobody had looked

Three of these are new defects.

**(a) `--dry-run` is not a dry run. [M]** `cmd/snug/main.go:254-291` calls
`claudeFiles`, `startIdentity` and `startContainers` *before* the `cfg.dryRun`
branch. Measured with a `gh` shim first on `PATH`, which logged `auth token
--hostname github.com --user vyskocilm`. So `snug --dry-run` — whose first line
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

**(b) `--dry-run` denies, on screen, the credential it is staging. [M]** MVY2
found this for `~/.claude`; it is worse. With an identity profile, one screen
prints `data /home/michal/.config/gh/hosts.yml (identity)` and, eleven lines
below, lists `~/.ssh ~/.gnupg ~/.aws ~/.config/gh ~/.kube …` under *"NOT GRANTED
(never mounted — these read as absent, they are not hidden)"* — reporting as
absent the very directory it has just staged an `admin:public_key` token into.
Cause is MVY2's: `covered()` (`cmd/snug/dryrun.go:315`) only considers
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

**Commit `af5f550` (MVY1) closed both halves, and the current shape is stronger
than the fix this document was going to ask for.** Provenance is now a parameter
(`internal/policy/types.go:243`), and `cmd/snug/container.go:55` passes
`"(containers)"`; measured, `--dry-run -p @podman-socket` prints `rw
/run/snug/podman.sock (from …) (containers)`. More importantly there is now
**exactly one** post-resolution writer, `Policy.Replace` (`types.go:221`):
`claudeFiles`, `stageGhConfig`, `BindSocket` and `Resolve`'s identity/resolv.conf
block all route through it, it appends `"replaces:"+…` so displacement is no
longer silent, `rejectMasking` exempts on the `Authored` **field** rather than a
`Kind == KindData` heuristic (`internal/policy/validate.go:211`), and
`cmd/snug/main.go:278` re-runs `Validate` after staging so the post-resolution
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
  LD_PRELOAD=...` for its own children, because `forbiddenEnv`
  (`resolve.go:457`) constrains what a *profile* may grant, not what the payload
  may set.
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

This remains a redteam finding rather than a secrets finding, and it is here
because it invalidates the broker plan's most attractive property — *"a brokered
Claude needs no `@net`, so exfiltration is closed by construction"* (MVY2). That
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

**A2. Can it extend its own life or scope?** The axis MVY2 lacked, and the one
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
| **`~/.claude.json`** | permanent (disclosure) | n/a | n/a | host inventory: 7 project paths, org, email, account UUIDs, machine ID | not a credential; still should not be there (§3.5) |

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
documentation; there is no code. It does not protect A1 — MVY2's objection, and
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
pass independently of MVY2: Claude Code honours `ANTHROPIC_BASE_URL` over **plain
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

MVY2 filed this under "user-scripted wrapper = arbitrary host code execution"
and dismissed it. **That dismissal does not apply as written.** MVY2 objected to
a *user-supplied script* deciding on sandbox-controlled input; a snug-authored
stub with a snug-authored filter is the same authorship as `dockerproxy`, which
the project already accepts. And the staging mechanism already exists and was
chosen deliberately: `cmd/snug/podmanshim.go` plus CLAUDE.md's *"PATH precedence,
not overmounting"* — write the replacement into the writable tmpfs `$HOME` and
put that directory first on `PATH` via the `path` profile key
(`policy.Profile.Path`). Additive, no
mount, no masking-rule exemption, works where the target path is a symlink;
`@claude` already uses `path` for this shape.

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

**The synthesis MVY2 missed:** *snug can sandbox its own helper.* Run the
host-side tool in a second, tighter snug sandbox — no `$HOME` but a generated
config directory, no `@net` beyond the vendor's host, no target bind, credential
staged in *that* sandbox where nothing the agent controls runs. The argv filter
then becomes defence in depth rather than the only line. It is the one shape in
which placement B is arguable, and it costs a `snug`-inside-`snug` story the
project does not have yet (Q6).

#### 3.3.3 Placement C — stub inside, **typed verbs cross**

The stub is `snug-gh`, not `gh`: a small snug-defined set of operations with
typed fields, sending a struct rather than argv, with the host helper
constructing the invocation — or calling the vendor's REST API directly.

**Abuse:** *a hostile process can perform any operation in snug's verb set, with
field values it chose, for the sandbox's lifetime.* Short, complete, reviewable.

This is MVY2's "shape 2" wearing the stub's clothes, and the clothes matter: MVY2
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
| **vendor ships a new flag** | invisible; the wire is unchanged | unknown flag → **default-deny → tool errors visibly**. *MVY2 implied this was the discriminator. It is not — both fail closed and loudly* |
| **vendor changes a flag's meaning** | n/a | silent widening. **This is the real discriminator** |
| **adapter out of date** | endpoint moves → "Claude stops working" | verb refused → "that command stopped working" |
| **escape hatches in the surface** | none — an endpoint is an endpoint | `gh api`, `gh alias`, `gh config`, trailing `git` args. **Fatal** |

**The honest verdict.** The argv stub is *not* "not a security boundary"; MVY2
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

#### 3.3.5 Which side each tool falls on

| tool | escape hatch | verdict |
|---|---|---|
| `git` | `-c <anything>`, `--upload-pack`, `--exec` | **protocol.** And *already solved*: `git push`/`fetch` over ssh is brokered by `sshproxy` with `git_protocol: ssh`, no token anywhere. Do not build a git stub |
| `gh` | `api`, `extension`, `alias`, `config`, trailing git args | **protocol, or §3.1.** If a stub is built anyway it must be placement C with an explicit small verb list, named `snug-gh` |
| `aws`/`gcloud`/`az` | `--cli-input-json`, `--endpoint-url`, plugins | **protocol** — and the best case of all: sign on the host, so no bearer token exists to steal even in flight |
| `docker`/`podman` registry auth | n/a | **protocol, and the proxy already exists.** Put the credential at `dockerproxy`, host-side, with a registry allowlist. §3.8 |
| `npm`/`cargo`/`twine` **publish** | none in the publish path | **stub, placement C.** One write-only verb, one artefact path, judged by `hostPathVisible`. The best candidate in the list |
| Anthropic | n/a (no CLI) | **broker.** One endpoint, no TLS **[M]** |

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

Generalises to `~/.claude.json`: MVY2 measured that it is not needed at all
**[M-prior]**; if that survives re-measurement, the 56 KB host inventory should
be *generated minimal*, not copied — the "generate, don't bind" rule the project
already applies to `.gitconfig` and `hosts.yml`.

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

## 4. Interactions with the profile model

- **A `broker` key needs sub-structure** (`host`, `listen`, `env`, a *secret
  reference*, an `allow` list) — MVY2 covered this. Additions: it would be the
  first profile key whose value *references a secret*, and that reference must
  resolve only on the host and never be expandable from `{…}` variables the
  sandbox can influence (the rule `PARAMETERISED-PROFILES.md` already applies to
  arguments); `allow` lists **union** across profiles, which preserves
  monotonicity — adding a profile can only widen the broker, so a "read-only
  GitHub" profile cannot prevent a second profile widening it, and that must be
  said out loud; and two profiles declaring a broker on the same `listen` address
  is MVY1's same-path conflict and should be **fatal**, because silently picking
  one makes the effective credential boundary depend on profile order.
- **A `stub` key would be the first key that stages an executable.** Today `path`
  is defensible precisely because it *grants nothing* (see the doc comment on
  `policy.Profile.Path`). A key saying "stage this
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
  `p.Mounts` directly** (§1.2d). MVY1 reduced the post-resolution writers to
  exactly one and made `rejectMasking` exempt on the `Authored` field; a broker
  that bypasses `Replace` re-opens the hole MVY1 closed, and would do it in the
  one place — a socket carrying a credential — where the provenance line matters
  most.
- **A broker socket is a new *kind* of hole in the `--dry-run` rendering.** Today
  the security-relevant surface is mounts, env, network. A broker's host, listen
  address and **full allowlist** are the boundary and must be printed as such — a
  mount line saying `rw /run/snug/anthropic.sock` tells a reader nothing.
- **`snug -p @claude` has no network today** (`include = ["sys","home"]`) **[M]**,
  so a brokered `@claude` changes the recommended invocation from `-p @claude -p
  @net` to `-p @claude` alone. A genuine usability win — *provided* §1.3's engine
  channel is closed, or the docs stop claiming that no `@net` means nothing
  leaves.

---

## 5. Decisions — 2026-08-08

### D1 (was Q1) — the principle. SETTLED.

**The problem being fixed.** MVY2's principle text is good and mostly worth
keeping verbatim, but it is written as an absolute (*"No credential … is placed
inside the sandbox"*) and then carries an exception (*"a profile may still stage
a real credential"*) that swallows it. An invariant with an exception can only be
checked by understanding where the exception applies — precisely the argument
CLAUDE.md invariant 1 makes about `--read-only`.

**Two drafts.** **Draft A** kept the absolute and made the exception a different
noun: a profile whose name ends in `-credentials`, never in `defaults`, never
implied by `include`, requiring `--i-know`. Attractive because the invariant
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
> account rather than bound (`cmd/snug/identity.go:192`). Where snug cannot
> broker and must place a secret inside, it places the smallest form that works,
> and the profile states what that form still grants.

The last paragraph is a **requirement on brokers, not a description of snug
today**: `@claude` currently copies `.credentials.json` whole
(`cmd/snug/claude.go:49`) and so fails its final clause until D2 lands. It earns
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
is holding. Same shape as `@net` / `@net-host`.

Bounding facts, verified while deciding this:

- **There is no sync-back** (`cmd/snug/claude.go:31`) — the staged copies are
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
(§3.3.2.) The only version of placement B with a defensible blast radius, **and
the strongest form of the owner's proposal**. It implies a `snug`-inside-`snug`
story that does not exist. Milestone, or out of scope?

**Q7 — GitHub: build an adapter, or document §3.1 and stop?** This document's
honest reading is that a fine-grained PAT plus the ssh-agent proxy covers most
real use with zero code (§3.1, §3.7), and any `gh` adapter is either decorative
(forwards GraphQL) or breaks most of `gh` (§3.2, §3.3.5). Is "ssh for git, a
fine-grained PAT if you must, no token by default" an acceptable *final* answer,
not a placeholder?

**Q8 — the engine egress channel (§1.3).** Partly addressed: step M-a landed
2026-08-09, so snug no longer *claims* offline while the channel is open. The
channel itself remains. Closed (the engine in the sandbox's netns per
`ENGINE-NETNS.md` §5, and/or a registry allowlist at `dockerproxy` refusing
non-allowlisted hosts and any literal IP), or carried as a known gap with
severity? Until it is closed, no broker milestone may claim exfiltration is
closed by construction.

**Q9 — should `--dry-run` stop starting things?** (§1.2a.) Moving the `cfg.dryRun`
branch above `startIdentity`/`startContainers` costs the dry run its ability to
show the *actual* socket paths and the staged `hosts.yml` entry. Trade the
fidelity for the claim, or keep the fidelity and change the claim?

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
(`user:sessions:claude_code`), Q4 (Claude without `refreshToken`), MVY2's claim
that `~/.claude.json` is unnecessary, and whether `gh` can be MITM'd via
`GH_HOST` + `SSL_CERT_FILE`.
