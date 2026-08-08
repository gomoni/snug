# Secrets

**Status: living design document. Nothing here is decided.** It exists so that
the decision, when it is made, is made against measured ground truth rather than
against what the comments say.

Builds on `TODO.md` §MVY2 → *Findings*. Where this document contradicts MVY2 it
says so explicitly and gives the measurement.

Everything marked **[M]** was measured on this host during this pass, and the
command is in the appendix. Everything marked **[R]** is reasoned from code or
docs and has not been executed. Everything marked **[M-prior]** was measured by
the MVY2 pass and not re-measured here.

Versions at the time of measurement: snug `d3e6430`, claude 2.1.226, gh 2.96.0,
podman 5.8.3, bwrap 0.11.2, git 2.55.0, Go 1.26.5.

---

## 0. The three sentences this document is trying to make true

1. It should be possible to say, of any credential, *why* it is or is not
   allowed inside a snug sandbox, in one line, without appeal to taste.
2. A tool with no adapter should degrade to "that tool has no credentials
   inside" — visible, annoying, harmless — never to a leak, and never to a
   fallback.
3. When we do put authority inside, it should be authority we can end by
   ending the sandbox.

---

## 1. Ground truth

### 1.1 What snug touches today

MVY2's table is correct in shape. It is wrong or incomplete in five places, all
marked. The column that matters most is the last one — *does it outlive the
sandbox* — and MVY2 did not have it.

| # | secret | where it lands | who can read it | authority | outlives sandbox? |
|---|---|---|---|---|---|
| 1a | Anthropic OAuth **access** token | `KindData` writable-tmpfs copy at `~/.claude/.credentials.json` (`cmd/snug/claude.go:46`) | every process in the sandbox | `user:inference`, `user:profile`, `user:file_upload`, `user:mcp_servers`, `user:sessions:claude_code` **[M]** | **yes, ~8 h** **[M]** |
| 1b | Anthropic OAuth **refresh** token | *same file, same line* | same | mints new access tokens | **yes, ~20 days remaining of a rolling window** **[M]** |
| 2 | `~/.claude.json`, 56 500 bytes verbatim | writable tmpfs (`claude.go:47`) | every process in the sandbox | not a credential — a host inventory | disclosure is permanent |
| 3 | `ANTHROPIC_API_KEY` | **the environment** (`base.toml:269`) | every process, passively, via `/proc/*/environ` | **overrides the OAuth token entirely** **[M]** | as long as the key lives |
| 4 | GitHub token from `gh auth token` | `oauth_token:` in a generated `hosts.yml` (`identity.go:192`) | every process in the sandbox | on this host: `admin:public_key`, `gist`, `read:org`, `repo` **[M]** | **yes, indefinitely** |
| 5 | ssh private keys | **never** (`internal/sshproxy`) | nothing — no key material crosses | signing oracle, one pinned key | **no** — dies with the proxy |
| 6 | host container-registry auth | **never enters the sandbox**, but the engine may use it on the sandbox's behalf | — | pull/push as you | broker-shaped already, and undocumented **[R]** |

**Corrections to MVY2:**

- **The scope list was wrong.** MVY2 wrote `user:inference`, `user:profile`.
  Measured: five scopes, including `user:mcp_servers` and
  `user:sessions:claude_code`. The last one is the interesting unknown — if it
  grants read access to Claude Code *sessions*, the blast radius is not "quota
  theft" but "read the transcripts of every other project on this account".
  Nobody has established what it does. This belongs in §6.
- **MVY2 counted one Anthropic credential. There are two, and they are not
  equally severe.** The access token expires in hours; the refresh token had
  ~20 days left and mints access tokens. "Until expiry" is doing a lot of work
  in MVY2's sentence and it hides a factor of sixty. Splitting rows 1a/1b is
  not pedantry — it is the whole of the severity argument, and it makes a cheap
  mitigation visible that MVY2 did not propose (§3.6).
- **`ANTHROPIC_API_KEY` is not merely leaky, it is authoritative.** Measured:
  with the variable set, Claude Code sends `x-api-key: <value>` and does **not**
  send the OAuth `Authorization: Bearer`. So `@claude` today can put a
  long-lived org API key in `/proc/self/environ` and have it be the credential
  actually in use. MVY2 called this a rule violation; it is also a severity
  upgrade, because an org API key is typically not user-scoped and not
  auto-expiring.
- **Row 6 did not exist in MVY2.** `internal/engine` starts the podman service
  with `HOME` set to the host's home (`engine.go:189`), and podman resolves
  registry credentials from `$HOME/.config/containers/auth.json`. This host has
  no `auth.json` **[M]**, so nothing was observed; on a host that does, a
  sandbox-issued `POST /images/create` or an image push would authenticate as
  the host user. `allowed()` permits everything under `images` except `load`
  and `import`, so `images/{name}/push` is reachable **[R, from
  `proxy.go:270`]**. This is a credential broker that already exists, was never
  designed as one, and has no allowlist over *which registry*.
- **MVY2 said `~/.claude.json` carries "no token".** True on this host **[M]** —
  but the file has two structural slots for one: `mcpServers[*].env` (a map
  injected into MCP server processes; empty here) and, in the sibling
  `settings.json` that `@claude` binds read-only, `env` and `apiKeyHelper`. So
  "no token" is a property of *this* host's data, not of the file format. Any
  statement about it has to be conditional.

**Not present, confirmed:** `.netrc`, git credential helpers, any bind of the
host's `~/.config/gh`, any bind of `~/.ssh`. **[M, via `--dry-run` mount list]**

### 1.2 The places nobody had looked

These are the additions the brief asked for. Three are new defects.

**(a) `--dry-run` is not a dry run. [M]**

`cmd/snug/main.go:246-267` calls `claudeFiles`, `startIdentity` and
`startContainers` *before* the `cfg.dryRun` branch. Measured, with a `gh` shim
first on `PATH`:

```
=== gh log:
GH-INVOKED: auth token --hostname github.com --user vyskocilm
```

So `snug --dry-run`, whose first line of output is *"nothing was started"* and
whose doc comment says *"It starts no process and creates no file"*:

- shells out to `gh auth token`, **extracting a live credential from the host's
  gh store — including from the system keyring**, since one of this host's two
  accounts is keyring-backed **[M, from `gh auth status`]**;
- creates `$XDG_RUNTIME_DIR/snug/run-<pid>/` and **binds a live ssh-agent proxy
  socket** onto the host's agent for the duration of the run;
- with `@podman-socket`, binds the container proxy socket and starts its
  goroutine.

Severity: low on its own (host-side, mode 0700, torn down on exit) but it is a
falsified claim on the one artifact whose entire purpose is to be trustworthy,
and it means "just dry-run it to see what it would do" is advice that touches
your credential store.

**(b) `--dry-run` denies, on screen, the credential it is staging. [M]**

MVY2 found this for `~/.claude`. It is worse than that. With an identity
profile, one screen prints:

```
  data   /home/michal/.config/gh/hosts.yml              (identity)
  ...
  NOT GRANTED (never mounted — these read as absent, they are not hidden):
    ~/.ssh  ~/.gnupg  ~/.aws  ~/.config/gh  ~/.kube  ...
```

`~/.config/gh` is listed as *absent* eleven lines below the line that stages an
`admin:public_key` token into it. Cause is MVY2's: `covered()`
(`cmd/snug/dryrun.go:242`) only considers `KindBind`.

**(c) `--dry-run` prints secret values in cleartext, twice. [M]**

Confirmed, 2 occurrences of the sentinel: once in `ENVIRONMENT`, once as
`--setenv ANTHROPIC_API_KEY <value>` in the bwrap argv.

**(d) Provenance is mislabelled for every socket snug binds. [M]**

`Policy.BindSocket` (`internal/policy/types.go:188`) hard-codes
`From: []string{"(identity)"}`. So `--dry-run -p @podman-socket` prints:

```
  rw     /run/snug/podman.sock (from /run/user/1000/snug/run-.../podman.sock) (identity)
```

The container hole is attributed to identity. Cosmetic, but provenance is the
product here.

Note also what `BindSocket` *is*: a third place that writes straight into
`p.Mounts`, bypassing `join` and `rejectMasking`, alongside `replace` (the
`KindData` carve-out invariant 1 already documents) and `claudeFiles`. Invariant
1 names one exception; there are three code paths.

**(e) `-v/--verbose` audit output is clean. [M, by reading every call site]**

`internal/sshproxy` has eight `audit(...)` calls; none carries key material or a
signature blob. `internal/dockerproxy`'s `summarise()` (`build.go:404`) prints
the image tag and a *count* of host volumes, never `buildargs` values. There is
no secret in `-v` output today. Worth a regression test precisely because it is
currently true and one `%v` would end it.

**(f) What snug writes to the host, and what survives.**

| path | written by | survives the sandbox | why it matters here |
|---|---|---|---|
| `$XDG_RUNTIME_DIR/snug/run-<pid>/` | identity + container wiring | no (removed on cleanup) | holds the sockets that *are* the holes |
| `$XDG_DATA_HOME/snug/engines/<key>/storage` | the per-sandbox podman engine | **yes**, keyed by `sha256(profile set + target)` | images the *sandbox* chose to pull sit on your disk and are reused warm by the next run with the same key. An agent that pokes an image into that store has arranged for code to run in a later session |
| `/tmp/snug-<uid>-<hash>` (`@tmp-shared`) | `prepareHostTmpDir` | **yes** | same shape, smaller |
| the target directory | the payload | **yes, by design** | see below |
| host credential files | **nothing** | — | there is no sync-back; see the correction below |

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
`package.json` `postinstall`, a `.vscode/tasks.json` — every one of these runs
**on the host, as you, with all your credentials**, the next time you do the
ordinary thing in that directory. A principle titled "secrets are never
injected" must not be read as "the sandbox cannot get your secrets". It cannot
get them *now*; it can arrange to be handed them later. Say this in the same
breath, always.

**(g) Inside the sandbox, there are no process boundaries. [M]**

Measured in a default sandbox: a Python process spawned a child holding a
sentinel string, then read the child's `/proc/<pid>/mem` and found it. Both
`/proc/<pid>/maps` and `/proc/<pid>/mem` were readable. The seccomp filter
denies `ptrace(2)`, but `/proc/<pid>/mem` does not go through `ptrace(2)` — the
kernel's check is `ptrace_may_access`, which same-uid processes pass.

Consequences, and they are load-bearing for §3:

- "In the sandbox" means "readable by everything in the sandbox". File
  permissions, a private directory, a 0600 mode, a different process — none of
  them separate anything.
- **An execute-only binary with an embedded secret does not work.** It is the
  first idea anyone has when they hear "stub", and it is dead on arrival: the
  payload runs it, then reads its memory. It does not even need that — it can
  `export LD_PRELOAD=...` for its own children, because `forbiddenEnv`
  (`resolve.go:426`) constrains what a *profile* may grant, not what the payload
  may set.
- Therefore: any design whose safety depends on a secret being held by a
  *process inside the sandbox* is unsound, whatever the mechanism.

### 1.3 Exfiltration: the sandbox is not offline when you think it is

Severity depends on whether a leaked credential can leave. Two measured
channels, both bypassing the `@net` decision.

**Egress without `@net`, via the container engine. [M]**

A sandbox started as `snug -p @podman-socket <dir>` — **no `@net`** — with a
positive control:

```
DIRECT-EGRESS: refused (OSError)              # control: 1.1.1.1:443 unreachable
PULL-RESPONSE-HEAD: HTTP/1.1 200 OK ...       # docker.io/library/hello-world pulled
"status":"Download complete","id":"e2ac70e7319a"
```

The engine runs on the host, in the host's network namespace, and fetches on the
sandbox's behalf. The image *name* is fully sandbox-chosen, so it is a DNS name
plus a path — a covert channel out — and the layers are bytes in.

**Host loopback, via the same channel. [M]**

Pulling from `127.0.0.1:<port>/x` distinguishes open from closed ports on the
*host's* loopback:

| port | engine's error |
|---|---|
| 8731 (a plain-HTTP recorder I started) | `tls: first record does not look like a TLS handshake` |
| 9 (closed) | `connection refused` |
| 22 (closed here) | `connection refused` |

The 8731 error proves a TCP connection was established and bytes were exchanged
with a host loopback service. Host-loopback unreachability is the property the
private netns exists for; `@podman-socket` re-opens it as an oracle, and would
deliver a payload to any host loopback service that speaks TLS or tolerates a
ClientHello.

**Abuse sentence for the channel as it stands today:** *a hostile process in a
sandbox with `@podman-socket` and no network profile can reach the internet and
port-scan the host's loopback by asking the engine to pull an image, and can
encode data it wants to exfiltrate into the image name.*

This is a redteam finding, not a secrets finding, and it should be filed and
tested as one. It is here because it invalidates the most attractive property of
the broker plan — *"a brokered Claude needs no `@net`, so exfiltration is closed
by construction"* (MVY2). That sentence is only true if no other profile opens a
channel, and one already does.

---

## 2. A severity model

The owner's steer: not all credentials are equal, and an Anthropic OAuth token
in a sandbox may be an acceptable risk where a GitHub token with
`admin:public_key` is not. This section tries to make that judgement
mechanical.

### 2.1 The axes

Ordered by how much they should move the verdict.

**A1. Does the authority outlive the sandbox?** The single most important
question, because it is the one the sandbox itself can answer. A credential that
dies with the run converts "the agent was compromised" into "the agent was
compromised for twenty minutes and then it was over". Values: *dies with the
sandbox* / *hours* / *days* / *indefinite*.

**A2. Can the credential extend its own life or scope?** This is the axis MVY2
did not have and it is the one that separates the two halves of the same file. A
refresh token mints access tokens. `admin:public_key` mints an SSH key — a new,
independent, non-expiring credential that survives revocation of the token that
created it. A token that can create tokens is not a token, it is an account.
Values: *no* / *renews itself* / *mints an independent credential*.

**A3. Is the blast radius bounded by the issuer, cryptographically?** A
fine-grained PAT scoped to one repository is bounded by GitHub, not by us. That
is strictly better than any filter we write, because it holds even if every line
of snug is wrong. Values: *server-enforced narrow* / *server-enforced broad* /
*unscoped*.

**A4. What does the worst case cost?** Escalating, and the boundaries matter
more than the labels: *quota* → *disclosure* → *write to the vendor's data* →
*account takeover* → *code execution somewhere*. Note that A4 has a discontinuity
at "code execution": `repo` scope means push, push means CI, CI means arbitrary
code running with *that repository's* secrets on a runner. A GitHub token with
`repo` is a code-execution primitive wearing a data label.

**A5. Revocation: possible, fast, and does it cost the human anything?** "You
can revoke it" is weaker than it sounds if revoking logs you out of every
machine you own, or if you would never notice you needed to.

**A6. Is use detectable?** Does the vendor give an audit log the human would
plausibly read? Mostly no. Treat a *yes* as a small mitigation, never as a
control.

**A7. Is it shared or personal?** An org-wide API key is a different object from
a user token with the same scopes, because the cost of rotating it falls on
other people.

### 2.2 Today's secrets, placed

| | A1 outlives | A2 self-extending | A3 server scoping | A4 worst case | verdict |
|---|---|---|---|---|---|
| **ssh-agent proxy** (`@identity`) | **no** | no | n/a — one key, one lifetime | sign anything that key can sign, *while running* | **the model.** Injects nothing |
| **Anthropic access token** | hours | no | narrow-ish, 5 scopes | quota; `user:sessions:claude_code` unknown (§6) | plausibly tolerable, *if* separated from 1b |
| **Anthropic refresh token** | ~20 days | **yes, renews** | same scopes | same, for weeks, and it rotates | **materially worse than 1a and currently indistinguishable from it** |
| **`ANTHROPIC_API_KEY`** | indefinite | no | often org-wide (A7) | quota, org-wide, rotating it is someone else's problem | never in the environment; §1.1 shows it also *wins* over the OAuth token |
| **GitHub token, `admin:public_key`+`repo`** | indefinite | **yes, mints an SSH key** | broad, user-wide | **account takeover + code execution via CI** | **never inject.** Fails A1, A2 and A4 simultaneously |
| **`~/.claude.json`** | permanent (disclosure) | n/a | n/a | host inventory: 7 project paths, org, email, account UUIDs, machine ID | not a credential; still should not be there (§3.6) |

### 2.3 What falls out

Reading down the table, the discriminator is not "how sensitive does this feel".
It is: **A1 ∧ A2** — *does it outlive the sandbox, and can it extend itself*.

- **Both false** → the credential is a *capability*, not a secret. The ssh-agent
  proxy is the existence proof. Injecting a bounded-lifetime, non-renewing
  capability is defensible and needs only a named profile and an abuse sentence.
- **A1 true, A2 false** → a *time-boxed leak*. Arguable, needs a named profile,
  and the argument must be about the size of the box. This is where the
  Anthropic access token sits, *alone*.
- **A2 true** → **never inject, regardless of how narrow A3 looks.** A
  self-extending credential converts a sandbox breach into a permanent one, and
  no filter we write can undo an SSH key that has already been added to an
  account.

That is a rule with a shape, it survives the owner's "not all credentials are
equal", and it lands exactly where his instinct did — Anthropic maybe, GitHub
`admin:public_key` no — without appealing to instinct.

**Corollary the model produces for free:** the tolerable case (A1 hours, A2 no)
is *precisely the case where a broker is cheapest*, because a short-lived,
non-renewing credential is also the one whose refresh you can keep on the host.
The severity model and the strategy space agree, which is weak evidence that
both are drawn right.

---

## 3. The strategy space

For each: what it is, the abuse sentence, cost, what it does **not** protect,
and which tools it suits.

### 3.0 No credential at all

**Mechanism:** none. The tool has no credentials inside the sandbox.

**Abuse:** *nothing — it cannot authenticate.*

**Cost:** zero code. **Does not protect:** anything the tool could do
unauthenticated; the target directory (§1.2f).

**Suits:** everything, by default. This is the floor and it is where every tool
starts. The interesting question is never "should this be the default" (yes) but
"what is the smallest departure from it that makes the tool work".

### 3.1 Vendor-side scoping

**Mechanism:** the human issues a narrow credential — a fine-grained PAT scoped
to one repository, a GitHub App installation token (1 h, repo-scoped), an
Anthropic key on a dedicated low-limit workspace.

**Abuse:** *whatever the vendor's scope permits, for the credential's lifetime,
which outlives the sandbox.*

**Cost:** documentation. No code at all.

**Does not protect:** A1 — the authority still outlives the sandbox. That is
MVY2's original objection and it is correct.

**Why it is nonetheless the strongest single lever available:** it is the only
option in this list whose enforcement is **not ours**. Every other strategy
converts "a secret the agent can read" into "a secret behind a parser the agent
can attack", and `internal/dockerproxy` has a recorded history of four escapes
in one handler. A fine-grained PAT is enforced by GitHub whether or not our code
is right. A1 is a real weakness; "the filter has a bug" is a *certainty* over a
long enough horizon.

**Suits:** GitHub above all, because a fine-grained PAT removes `admin:public_key`
and can remove `workflow`, which is exactly the A2 and A4 failure. Also npm
(granular tokens), AWS (STS session with an inline policy — and short-lived, so
it improves A1 too).

**This is the cheapest large win in the document and it needs no milestone.**

### 3.2 Protocol broker (the `dockerproxy`/`sshproxy` pattern)

**Mechanism:** snug holds the credential on the host, runs a filtering proxy
that speaks the tool's own protocol, and the sandbox points at it with the
tool's own configuration knob. The sandbox receives *authority bounded by the
allowlist and by the sandbox's lifetime*, never the credential.

**Abuse:** *a hostile process can issue, with your full identity, any request the
allowlist permits, with content it chose, for the sandbox's lifetime only. It
cannot read the credential, cannot use the account afterwards, cannot reach an
endpoint outside the allowlist.*

**For Anthropic the cost is small and the shape is confirmed. [M]** Measured
this pass, independently of MVY2:

- Claude Code honours `ANTHROPIC_BASE_URL` over **plain HTTP** to a loopback
  address. No CA, no TLS, no certificate wiring.
- Across two runs the *only* endpoint it called was
  `POST /v1/messages?beta=true`. The allowlist is one rule, not three.
- Auth is `Authorization: Bearer sk-ant-oat01-…` from `.credentials.json`, or
  `x-api-key: …` when `ANTHROPIC_API_KEY` is set (the latter wins).
- It retries a 500 seven times in ~55 s, so the broker's *error* behaviour is
  part of its interface — a refusal must be a 4xx the client will not hammer.

That is about as favourable as a broker ever gets: one method, one path, one
header to inject, no TLS.

**For `gh` the cost is large.** `gh` forces HTTPS **[M-prior]**, so a broker
needs a per-run CA, a leaf certificate and `SSL_CERT_FILE` wiring (Go's
`crypto/x509` honours it, so it is feasible **[R]**). Then the real problem: `gh`'s
high-level commands are `POST /api/graphql`, so the filter's choice is *refuse
GraphQL and break most of `gh`*, or *forward it and the filter is decorative*.
A GraphQL-aware filter is a query parser over a schema that changes without
notice — that is the D-Bus decision again, wearing a different hat.

**Does not protect:** intent. The broker bounds the endpoint and the lifetime,
never what the agent asks for within them. Quota theft while running is
unaffected. Nor does it protect §1.2f.

**Suits:** any tool with a base-URL knob and a small verb set — Anthropic
(excellent), OpenAI-shaped APIs, container registries (the auth belongs *at the
existing proxy*, host-side; see §3.7), an S3 endpoint. It suits `gh` badly.

**The rule that decides it:** *if the allowlist cannot be written in a handful of
rules over (method, path, host), the tool does not want a broker — it wants
§3.1.*

### 3.3 The owner's policy-applying stub

The proposal: *mount a stub in place of the `gh` binary which (a) implements the
same sandbox policy for the command — e.g. refuses accessing paths outside the
grants — and (b) calls the real `gh` with the proper tokens.*

MVY2 filed this under "user-scripted wrapper = arbitrary host code execution"
and dismissed it. **That dismissal does not apply as written**, for two reasons
it missed:

- **snug owns the stub.** MVY2's objection was to a *user-supplied script*
  making decisions on sandbox-controlled input. A snug-authored stub with a
  snug-authored filter is the same authorship as `dockerproxy`, which the
  project already accepts.
- **The staging mechanism already exists and was chosen deliberately.**
  `cmd/snug/podmanshim.go` and the CLAUDE.md section *"PATH precedence, not
  overmounting, is how snug substitutes a host binary"* say exactly how: write
  the replacement into the writable tmpfs `$HOME`, and put that directory first
  on `PATH` via the `path` profile key (`policy.Profile.Path`). Additive, no
  mount, no masking-rule exemption, works where the target path is a symlink.
  `@claude` already uses `path` for precisely this shape.

So the question is not "is this allowed". It is **where does the stub run, and
what crosses the boundary**.

#### 3.3.1 Placement A — stub runs inside the sandbox, holding the token

**Dead. [M]** §1.2g: any secret held by a process inside the sandbox is readable
by every other process inside it, via `/proc/<pid>/mem`, which the seccomp
ptrace denial does not cover. Execute-only file modes do not help; the payload
can also `LD_PRELOAD` the stub's children, since `forbiddenEnv` binds profiles,
not the payload.

Even without that, the stub must *send* the token somewhere, and the payload
controls the stub's environment: `HTTPS_PROXY`, `SSL_CERT_FILE`, `GH_HOST`. A
stub that holds a real credential inside the sandbox is a leak with extra steps,
and should be named as such so nobody proposes it twice.

#### 3.3.2 Placement B — stub inside, host helper runs the real tool, **argv crosses**

This is the owner's proposal read literally, and it is the one worth arguing
about. The sandbox runs `gh pr create --title X`; the stub forwards `argv` over
a unix socket; a host-side helper judges the argv and, if it passes, executes
the real `gh` with the real token.

**What snug can judge well:**

- **Paths.** Genuinely reusable, and the rule already exists:
  `(*dockerproxy.Proxy).hostPathVisible` (`internal/dockerproxy/create.go:611`,
  currently unused) implements *a host path is acceptable iff the sandbox itself
  can see it at the same or greater access*, computed from the same
  `policy.Policy` that authored the bwrap argv — invariant 6 for free. Applied
  to `--body-file`, `--input`, `-F k=@file`, `gh release upload`, this is
  correct and cheap. `resolveExisting` (`create.go:590`) already handles the
  symlink-along-the-path problem.
- **A closed verb set.** `(command, subcommand)` pairs are a finite allowlist
  with a default-deny, exactly like `buildParams`. This part is fine.

**What snug cannot judge:**

- **`gh api`.** One subcommand that re-exposes the entire GitHub REST and
  GraphQL API. To filter it you must filter method and path — at which point
  you have reimplemented the HTTP broker on the *client's* side of the wire,
  with none of its advantages.
- **`gh extension install <repo>`** — downloads and installs code that runs on
  the **host**, on every subsequent `gh` invocation. Persistent host code
  execution.
- **`gh alias set x '!sh -c ...'`** — persistent, and `!` is a shell escape by
  design.
- **`gh config set`** — `pager`, `editor`, `browser` are all "a command to run".
- **`gh gist create`** — an exfiltration primitive that looks like an ordinary
  verb.
- **`gh workflow run` / `gh secret set`** — code execution on runners; writes to
  the repository's secrets.
- **Anything that shells out to `git`.** `gh repo clone` passes trailing
  arguments to `git`, and `git -c core.pager=`, `-c core.fsmonitor=`,
  `-c filter.*.clean=`, `--upload-pack=`, `--exec=` are all command execution.
  `git` has a *config-injection flag*; that alone makes its argv unfilterable.

**And the part that dominates all of the above:** even with a perfect argv
filter, the helper executes a real binary **on the host, outside every
namespace**. It reads the host's `~/.gitconfig` (credential helpers,
`insteadOf`, `core.fsmonitor`), the host's `~/.config/gh`, the host's `~/.netrc`;
it writes to whatever cwd it is given; it spawns `git`, which reads all of that
again. The argv filter is necessary and nowhere near sufficient.

**The synthesis MVY2 missed, and it is the interesting one:** *snug can sandbox
its own helper.* Run the host-side tool in a second, tighter snug sandbox — no
`$HOME` but a generated config directory, no `@net` beyond the vendor's host,
no target bind, and the credential staged in *that* sandbox where nothing the
agent controls runs. Then the argv filter stops being the only line of defence
and becomes defence in depth, which is a completely different risk posture. This
is the one shape in which placement B becomes arguable, and it costs a
`snug`-inside-`snug` story the project does not have yet. **It is the strongest
version of the owner's idea and it deserves its own evaluation.**

#### 3.3.3 Placement C — stub inside, **typed verbs cross**, helper builds the invocation

The stub is `snug-gh`, not `gh`. It accepts a small, snug-defined set of
operations with typed fields, sends a struct (not argv), and the host helper
constructs the tool invocation — or calls the vendor's REST API directly and
skips the CLI entirely.

**Abuse:** *a hostile process can perform any operation in snug's verb set, with
field values it chose, for the sandbox's lifetime.* Short, complete, reviewable
— the property MVY2 rightly wanted.

**This is MVY2's "shape 2" wearing the stub's clothes, and the clothes matter:**
the reason MVY2 dispreferred a verb broker was that "the agent's real tools do
not speak it". A stub on `PATH` fixes that at the ergonomic level, *provided it
is not named after the real tool*. Naming it `gh` would be a lie that an agent
would act on — it would assume the full `gh` surface and burn turns on flags
that silently do not exist. `snug-gh` fails legibly. **This is a naming decision
with a security consequence, and it is the same argument `podmanshim.go` makes
in its point 1 about not shipping a fake `podman`.**

#### 3.3.4 Honest comparison: stub-B vs. HTTP broker

The prior pass's comparison was uncharitable in one place and right in another.
Correcting both:

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
of a protocol, which is worse in two specific ways — a wrong decision costs host
code execution rather than one API call, and the semantics of a flag can change
without the syntax changing.

Whether that is acceptable turns on one property, and it gives a clean test:

> **Does the tool have an escape hatch — a subcommand that performs an arbitrary
> protocol operation, or a flag that sets arbitrary configuration?**
>
> If yes, the argv surface is not enumerable, and the boundary must sit at the
> protocol.
> If no, and the verb set is small and closed, an argv filter is a legitimate
> boundary — and placement C is a better spelling of it than placement B.

#### 3.3.5 Which side each tool falls on

| tool | escape hatch | verdict |
|---|---|---|
| `git` | `-c <anything>`, `--upload-pack`, `--exec` | **protocol.** And it is *already solved*: `git push`/`fetch` over ssh is brokered by `sshproxy` with `git_protocol: ssh`, no token anywhere. Do not build a git stub |
| `gh` | `api`, `extension`, `alias`, `config`, trailing git args | **protocol, or §3.1.** If a stub is built anyway it must be placement C with an explicit small verb list, named `snug-gh` |
| `aws`/`gcloud`/`az` | `--cli-input-json`, `--endpoint-url`, plugins | **protocol** — and the best case of all: sign on the host, so no bearer token exists to steal even in flight |
| `docker`/`podman` registry auth | n/a | **protocol, and the proxy already exists.** Put the credential at `dockerproxy`, host-side, with a registry allowlist. §3.7 |
| `npm`/`cargo`/`twine` **publish** | none in the publish path | **stub, placement C.** One write-only verb, one artefact path, judged by `hostPathVisible`. The best candidate in the list |
| Anthropic | n/a (no CLI) | **broker.** One endpoint, no TLS **[M]** |

### 3.4 Agent-proxy (the ssh model)

**Mechanism:** the credential stays in a host-side agent that already holds it;
snug proxies the agent's own wire protocol and filters at the message level,
exposing exactly one identity.

**Abuse:** *a hostile process gets a signing oracle for one pinned key, for the
sandbox's lifetime. It cannot enumerate other keys, cannot extract material, and
cannot sign after the sandbox exits.*

**Cost:** already paid for ssh (292 lines). **Does not protect:** what gets
signed — inherent to every agent forwarder.

**Suits:** anything with a real agent protocol: ssh (done), `gpg-agent` (the
same shape; would cover commit signing and `pass`), and in principle a
PKCS#11 token. **Nothing else has an agent**, which is why this pattern does not
generalise — it is not a strategy so much as an existence proof that the shape
is achievable when the vendor gives you a socket.

Its real role in this document is as the **calibration point**: A1 false, A2
false, filter reviewable in an afternoon. Any new hole should be argued against
it.

### 3.5 The measure-first mitigation for split credentials

Not a strategy on its own; a cheap intervention the severity model makes visible
and that nobody has proposed.

**Mechanism:** where a credential file carries *both* a short-lived token and a
self-extending one, stage a **rewritten** copy carrying only the short-lived
half. For `~/.claude/.credentials.json` that means keeping `accessToken` and
dropping `refreshToken` / `refreshTokenExpiresAt`. Cheap, because `claude.go`
already rewrites nothing — it copies bytes; making it parse-and-project is a few
lines and the file is 508 bytes with a known shape.

Effect on the model: moves the Anthropic row from *(A1 days, A2 yes)* to
*(A1 hours, A2 no)* — from "never inject" to "arguably tolerable", which is
exactly the owner's intuition made mechanical.

**Not measured.** Whether Claude Code works with the refresh token absent — and
what it does at the ~8 h boundary — was **not tested this pass** (the probe
needed a copy of the real credential file and was refused by tooling, correctly).
**It is a five-minute experiment and it should be run before this idea is
believed.** §6 lists it.

Generalises to `~/.claude.json`: MVY2 measured that it is not needed at all
**[M-prior]**; if that survives re-measurement, the 56 KB host inventory should
be *generated minimal*, not copied — the same "generate, don't bind" rule the
project already applies to `.gitconfig` and `hosts.yml`.

### 3.6 Staged injection under an explicitly-named profile

**Mechanism:** what happens today, but honest: the credential is staged only
under a profile whose *name says so* — `@claude-credentials`, not `@claude` —
never in `defaults`, with the abuse sentence in the TOML, and `--dry-run`
printing the value as `SECRET`.

**Abuse:** *a hostile process reads the credential out of a file (or, worse,
out of `/proc/*/environ`), exfiltrates it, and uses your account for as long as
the credential lives.*

**Cost:** almost none — it is mostly a rename plus §1.2b/c.

**Does not protect:** anything, once the credential is inside. Its entire value
is that the human *chose* it, on a name that could not be mistaken for a
capability grant.

**Suits:** the escape hatch, and only that. Its existence is what lets the
default be §3.0 without making snug unusable for someone with an unusual tool —
and what stops "the adapter is late" from becoming "so we injected it quietly".

### 3.7 Two things already brokered that nobody has written down

- **`git push` needs no token.** With `git_protocol: ssh` in the generated
  `hosts.yml` and the ssh-agent proxy, clone/fetch/push already work with zero
  credential inside. The *only* residual need for a GitHub token is the API half
  (PRs, issues, releases). This substantially shrinks the `gh` problem and
  should be stated in the user docs as the recommended posture.
- **Container registry auth is already a broker** — accidentally (§1.1 row 6).
  It has the right *shape* (credential on the host, sandbox speaks a protocol to
  a filtering proxy) and none of the discipline: no registry allowlist, no abuse
  sentence, `images/*/push` reachable, and it is undocumented. Turning it into a
  deliberate one is a small, well-scoped piece of work with a clear win.

---

## 4. Principles — a draft that survives the severity model

MVY2's principle text is good and most of it should be kept verbatim. It has one
structural problem: it is written as an absolute (*"No credential … is placed
inside the sandbox"*) and then carries an exception (*"a profile may still stage
a real credential"*) that swallows it. An invariant with an exception can only be
checked by understanding where the exception applies — which is precisely the
argument CLAUDE.md invariant 1 makes about `--read-only`.

Two ways to fix it. **Which one is the owner's call** (§6).

### Draft A — keep the absolute, make the exception a different noun

> ### Secrets are never injected
>
> No credential the host holds — token, key, cookie, password — is placed inside
> a snug sandbox: not in a file, not in the environment, not behind a mount.
> Where the sandbox needs to *act* with an identity, snug **brokers the act**: a
> host-side helper holds the secret, speaks the tool's own protocol over a
> socket or loopback address the sandbox can reach, and applies the credential on
> the host side of the fence. The sandbox receives **authority, bounded by what
> the broker will forward and by the lifetime of the sandbox** — never the
> credential.
>
> Three consequences, all of them the point:
>
> 1. Exfiltrating the sandbox buys nothing that outlives the run.
> 2. The blast radius is the broker's allowlist, not the credential's scope.
> 3. The security argument lives in the broker, so the broker is small, snug's
>    own, and reviewable — **never a user-supplied script, and never a host
>    command whose arguments the sandbox chose.**
>
> **Public material is not a secret.** A public key, a username, an email, a host
> fingerprint: generated into the sandbox on purpose.
>
> **There is no exception to this rule. There is a different thing with a
> different name.** A profile whose name ends in `-credentials` does not broker;
> it *hands the sandbox a credential*, and it is not covered by the sentence
> above. Such a profile is never in `defaults`, never implied by `include` from a
> profile named after a tool, always carries its abuse sentence in the TOML,
> always renders as `SECRET` in `--dry-run`, and requires `--i-know`. Selecting
> one is the human saying "this run is not a no-secrets sandbox".

*Why this shape:* it keeps the invariant checkable by grep (nothing outside
`*-credentials` staging a credential) rather than by judgement, which is the
lesson invariant 1 already learned. Cost: it is a slightly dishonest sentence
until §6 Q1 is answered, because `@claude` stages a credential today.

### Draft B — state the rule the severity model actually supports

> ### A sandbox may hold capabilities, never durable authority
>
> snug distinguishes two things a host can lend a sandbox.
>
> A **capability** is authority that **ends when the sandbox ends** and **cannot
> extend itself**. The ssh-agent proxy is the canonical one: a signing oracle for
> one pinned key, no key material inside, gone when the run is over.
> Capabilities may be granted by a named profile with an abuse sentence.
>
> A **credential** is a secret that outlives the run, or that can renew or widen
> itself. A refresh token renews. A GitHub token with `admin:public_key` mints an
> SSH key that survives the token's own revocation. **snug does not put these
> inside a sandbox.** Where the sandbox needs to act with such an identity, snug
> brokers the act host-side and the sandbox receives a capability instead.
>
> The test, in order:
>
> 1. Does the authority outlive the sandbox? If no — capability. Grant it.
> 2. Can it renew or widen itself, or mint another credential? If yes — never
>    inject, whatever else is true.
> 3. Otherwise it is a time-boxed leak. It may be granted only by a profile whose
>    name says so, and the size of the box is the argument.
>
> What this does **not** claim, ever: it does not bound what the sandbox *does*
> with a capability — a broker pins the identity and the operation set, never
> intent — and it does not bound what the sandbox writes into the target
> directory, which runs on your host, as you, the next time you build it.

*Why this shape:* it is the rule that the measurements support, it explains
*why* ssh-agent is fine and `admin:public_key` is not without special-casing
either, and it does not require a false absolute. Cost: "capability" is a second
noun, and this project has a standing rule against second nouns for one concept
(*"One vocabulary: profile"*). These are genuinely two concepts, but that is a
judgement the owner should make, not me.

**A sentence that belongs in whichever draft wins**, because it is the failure
mode this whole area actually has:

> The failure mode of a missing or broken adapter is **"that tool has no
> credentials inside"** — a hard error, visible and annoying. It is **never** a
> fallback to injection. A fallback path is how deadline pressure reopens a hole
> that was already closed once.

---

## 5. Interactions with the profile model

Flagged, per the brief. Some extend MVY2's list; the last three are new.

- **A `broker` key needs sub-structure** (`host`, `listen`, `env`, a *secret
  reference*, an `allow` list) — MVY2 covered this. Additions:
  - it would be the first profile key whose value *references a secret*; the
    reference must resolve only on the host and must never be expandable from
    `{…}` variables the sandbox can influence (the rule
    `PARAMETERISED-PROFILES.md` already applies to arguments);
  - `allow` lists **union** across profiles, which preserves monotonicity —
    adding a profile can only widen the broker. A "read-only GitHub" profile
    therefore cannot prevent a second profile widening it. Say it out loud;
  - two profiles declaring a broker on the same `listen` address is MVY1's
    same-path conflict and should be **fatal**, because silently picking one
    makes the effective credential boundary depend on profile order.
- **A `stub` key would be the first key that stages an executable.** Today
  `path` is defensible precisely because it *grants nothing* (see the doc
  comment on `policy.Profile.Path`). A key that says "stage this binary and put
  it first on `PATH`" does grant, and it grants the most powerful thing in the
  model — code that runs before the tool the human named. Its abuse sentence has
  to be written before its syntax.
- **`env` is the live leak and it is a profile key.** `@claude` names
  `ANTHROPIC_API_KEY` in `env` today and §1.1 shows the value both leaks
  passively and *wins* over the OAuth token. Options, all with costs:
  - refuse credential-shaped names (`*_TOKEN`, `*_KEY`, `*_SECRET`,
    `*_PASSWORD`) at parse time, like `checkName` and `DisallowUnknownFields` —
    fails closed and loudly, but it is a name heuristic with false positives
    (`GPG_KEY_ID`, `SSH_KEY_PATH`);
  - keep `env` permissive and **redact in `--dry-run`** — cheap, honest, does
    nothing about `/proc/*/environ`;
  - add an explicit `env_secret = [...]` so the human's intent is on the page.
  Note this is *not* a deny rule in the invariant-1 sense: refusing a profile at
  parse time makes the profile invalid, it does not narrow a grant.
- **`--dry-run`'s `covered()` must understand `KindData`** (§1.2b). This is a
  correctness fix to the trust artifact, not a feature.
- **`BindSocket` hard-codes `(identity)` provenance** (§1.2d) and, like
  `replace` and `claudeFiles`, writes straight into `p.Mounts`. If a broker adds
  a fourth such path, invariant 1's "one exception" should be restated as a list.
- **A broker socket is a new *kind* of hole in the `--dry-run` rendering.** Today
  the security-relevant surface is mounts, env, network. A broker's host, listen
  address and **full allowlist** are the boundary and must be printed as such —
  a mount line saying `rw /run/snug/anthropic.sock` tells a reader nothing.
- **`snug -p @claude` has no network today** (`include = ["sys","home"]`) **[M]**,
  so a brokered `@claude` changes the recommended invocation from
  `-p @claude -p @net` to `-p @claude` alone. That is a genuine usability win —
  *provided* §1.3's engine channel is closed, or the docs stop claiming that no
  `@net` means nothing leaves.

---

## 6. Open questions — the owner's to decide

**Q1 — which principle text?** Draft A (absolute + a differently-named thing) or
Draft B (capability vs. credential)? A is cheaper to check by grep; B is what
the measurements support and does not need a false absolute. This choice
determines whether `@claude` has to be renamed before the principle can be
written down truthfully.

**Q2 — is the Anthropic access token, alone, acceptable inside?** The severity
model says *arguably yes* if and only if the refresh token is stripped and
`ANTHROPIC_API_KEY` is not passed. This is the owner's risk call, not a
technical one. It also depends on Q3.

**Q3 — what does `user:sessions:claude_code` grant? [unmeasured]** If it reads
Claude Code sessions across the account, the access token's A4 is "read every
transcript on this account", not "quota theft", and Q2's answer probably flips.
Nobody has established this. It should be established before Q2 is answered.

**Q4 — does Claude Code work with `refreshToken` removed?** §3.5's mitigation
rests entirely on this and it was **not tested** this pass. Five-minute
experiment; run it first. Second half: what does it do at the ~8 h boundary —
fail cleanly, or hang?

**Q5 — placement C, and what is it called?** If a stub is built, is it
`snug-gh` (legible failures, agent knows it is not `gh`) or `gh` on `PATH`
(ergonomic, and a lie an agent will act on)? `podmanshim.go` already argues the
first for `podman`; this is the same argument.

**Q6 — is "snug runs its own helper inside a snug sandbox" a direction?**
(§3.3.2.) It is the only version of placement B with a defensible blast radius
and it is the strongest form of the owner's proposal. It also implies a
`snug`-inside-`snug` story that does not exist. Worth a milestone, or out of
scope?

**Q7 — GitHub: build an adapter, or document §3.1 and stop?** The honest reading
of this document is that a fine-grained PAT plus the existing ssh-agent proxy
covers most real use with zero code, and that any `gh` adapter we write is
either decorative (forwards GraphQL) or breaks most of `gh`. Is "snug's answer
to GitHub is: ssh for git, a fine-grained PAT if you must, and no token by
default" an acceptable *final* answer rather than a placeholder?

**Q8 — the engine egress channel (§1.3).** It is a redteam finding, not a
secrets finding, but it invalidates "brokered ⇒ nothing leaves". Does it get
fixed (a registry allowlist at `dockerproxy`, refusing non-allowlisted hosts and
any literal IP), or documented as a known gap with severity? Until one of those
happens, no broker milestone should claim exfiltration is closed by
construction.

**Q9 — should `--dry-run` stop starting things?** (§1.2a.) Moving the
`cfg.dryRun` branch above `startIdentity`/`startContainers` costs the dry run
its ability to show the *actual* socket paths and the staged `hosts.yml` entry.
Trade the fidelity for the claim, or keep the fidelity and change the claim?

**Q10 — how many adapters is snug willing to own, ever?** The strongest argument
against all of §3.2/§3.3 is the D-Bus argument: a filtering proxy that is 95%
correct is a sandbox that is 0% sound, and a vendor-API adapter is the same
species. A cap stated *now* — "at most N brokers, and a tool that cannot be
expressed in a handful of rules gets §3.1 instead" — is what prevents this
becoming an integration project with a security story attached.

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
