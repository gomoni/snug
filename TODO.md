# TODO

Only things that are genuinely outstanding. Anything already true of the code
belongs in CLAUDE.md or the code itself, not here.

## MVY0: @null profile vs --no-default vs defaults

There seems to be a problem with an existence of a `@null` profile. So the goal is to give it the meaning or kick it?

Ideas are 

1. `@null` implies no defaults - so if the `@null` is in a chain, the `defaults` is not added - push back, seems to be confusing
2. kill the concept so `snug --no-defaults` will be an equivalent of `snug -p @null`

Think about it hard.

### Findings — recommendation is IDEA 2, with three things that must ship alongside

**Ground truth, verified by execution rather than read from the docs:**

| command | today |
|---|---|
| `snug --dry-run -p @null <dir>` | `PROFILES @sys @home @cwd-rw @parent-ro @null` — the full default sandbox plus a no-op |
| `snug --no-defaults <dir>` | exit 77 at `cmd/snug/main.go:160`, before any policy is computed |
| `snug --no-defaults -p @null <dir>` | exit 77 at `internal/policy/validate.go:41` |
| `defaults = []` in config.toml | **silently falls back to the built-in four**, and `snug config` reports the source as `built-in` while the file says otherwise |
| `defaults = ["@null"]` | works — this is `@null`'s one genuine job |

`base.toml:21` claims "`snug explain -p null <dir>` prints the true empty base".
**That is false twice over**: `-p` ADDS to `defaults` so `@null` cannot subtract
them, and `snug explain` is a command that no longer exists. snug ships a profile
whose documented purpose is unreachable by the documented command.

`@null`'s only operational effect today is to convert one error message into a
different error message: on `--no-defaults -p @null` it exists purely to make the
`len(selected) == 0` guard pass so a LATER guard can reject the same thing.

**What `@null` is for, and whether anything else covers it:**

| claimed job | covered? |
|---|---|
| pedagogy — `--dry-run` showing the true empty base | **No — and `--no-defaults` does not cover it either.** Both routes error. Unserved by everything. |
| a lattice floor the model needs | No. `@null` is the identity element of the grant union, which is why adding it changes nothing. The floor is `⋁∅` — what `Resolve` computes from an empty selection. It exists whether or not a profile names it. |
| a composition target (`include = ["@null"]`) | Vacuous — omit the key. |
| golden coverage (INDEX §12.1 lists `@null` first) | Not delivered. There is no `testdata/null.bwrap.txt`, because it cannot resolve. |
| `defaults = ["@null"]` meaning "empty" | **The one live job**, and only because `defaultProfiles()` tests `len(c.Defaults) > 0` and cannot tell absent from empty. |

#### Why idea 1 is wrong — and it is not "confusing", it is unsafe

*Commutativity SURVIVES idea 1* — `if @null ∈ closure(args)` is a set-membership
predicate, order-free and idempotent. That is not the objection, and saying so
makes the rest credible.

1. **It violates invariant 1 where a human observes it.** `snug -p @git-ro` gives
   `/usr`; `snug -p @git-ro -p @null` does not. Adding a profile made a path stop
   being visible. The defence — "`defaults` is a preference, so this is not the
   subtraction invariant 1 forbids" — relocates the invariant from the observable
   layer to an internal one. That is the exact shape CLAUDE.md rejected for
   `--read-only`/`Clamp`: an invariant with no exceptions can be checked by
   grepping; one with an exception can only be checked by understanding where the
   exception applies.
2. **It reverses a decision already made.** `[profile.default]` was deleted because
   a profile that grants nothing still appeared in `SNUG_PROFILES`, in
   `snug profile tree` and in every `Mount.From` provenance as though it were a
   hole — *one idea, one mechanism*. Idea 1 puts a preference VERB inside a grant
   object: the same thing pointing the other way. **MVY0 is the unfinished half of
   that decision, and idea 1 undoes it.**
3. **`include = ["@null"]` three levels deep has no good implementation.** Suppress
   only when named on the CLI → `include` stops being transparent, a bigger
   property broken than the one being fixed. Suppress anywhere in the closure → a
   profile in `~/.config/snug/profiles.d` silently changes the selection for a run
   the user thought they controlled, with no error to raise, and you must read
   every profile transitively to know what you selected.
4. **THE SECURITY ARGUMENT, which is what makes this more than taste.**
   "Suppression only narrows, so it fails closed" is true *today only because
   `defaults` happens to contain nothing protective*, and nobody promised to keep
   it that way. Two live cases: a user whose `defaults` omits `@cwd-rw` has made a
   security choice (read-only projects) that a profile three includes down would
   discard; and if the pseudo-fs hardening (R3/R4) ever lands in the `defaults`
   list rather than in `Resolve`'s unconditional path, a profile that suppresses
   `defaults` becomes **an escalation vector reachable from a profile file** — and
   invariant 3 already concedes `$XDG_CONFIG_HOME` is trusted unconditionally.

#### Idea 2 — what breaks, and what must ship with it

**In code: nothing.** `@null` is data. `mark()`, `expand`, `join`, `Resolve` and
the emitter have never heard of it. The grep is small: `base.toml:20-24`,
`README.md:110`, `docs/src/profiles.md:37`, `CLAUDE.md:27`, DESIGN
272/400/876/1411/1605, and three test sites.

**But idea 2 alone makes the pedagogy job WORSE** — the only remaining route,
`--no-defaults`, fails before a policy exists. So it must ship with:

**(a) Separate DESCRIBING a policy from ADMITTING it.** Today three places say
"this cannot run" in three wordings (`main.go:160`, `resolve.go:18`,
`validate.go:41`). Collapse them so **`Validate` is the only refuser**, and let
`--dry-run` print what was refused, then the error, then exit non-zero. ~15 lines;
prototyped, and the full suite showed exactly one failure — the intended one.
Exit non-zero because `snug --dry-run … && snug …` must not proceed.

**(b) `-p @null` becomes a named error** pointing at `--no-defaults`. Same shape
as `TestRetiredPublishAutoIsAHardError`. Implement in `policy.UnknownProfile`, so
`snug profile show @null` is covered by the same change.

**(c) `defaults = []` must mean empty.** `Defaults *[]string`, test `!= nil`.
Without it, deleting `@null` removes a capability. Note the current behaviour is a
**silent widening against written intent**.

*Risk introduced:* `Resolve` returns a non-nil policy alongside an error. Bounded
— one non-test caller, one `sandbox.Run` call site in the same function on the
`err == nil` path — but it must be pinned by a behavioural test, not a comment.

#### Files, tests, and the golden

Files: `base.toml` (delete 20-24, fold the rationale into the existing
"no `[profile.default]`" block); `resolve.go:18-20` (delete guard), `:343`
(`return p, err` + document the contract), `UnknownProfile` (retired-name table);
`validate.go:41-47` (reword to cover "nothing selected at all", name
`--no-defaults`); `main.go:160-165` (delete), `:219-223` (dry-run on error);
`dryrun.go:16-21` (take the error; derive annotations from `p.Mounts`);
`config.go:31,70` (`*[]string`), `:143` (list footer pointing at the empty base);
`defaults.go` doc comment; docs.

Tests: `TestNoNullProfileShips`; `TestRetiredNullProfileIsANamedError`;
`TestEmptySelectionResolvesToTheFloor` (non-nil policy AND an error; exactly
`{/proc,/dev,/tmp,/etc/resolv.conf}`, **zero** `KindBind` — this asserts
deny-by-default directly for the first time); `TestRefusedPolicyIsNeverExecuted`
(integration, the structural guard for the non-nil-policy-with-error contract);
`TestDryRunShowsARefusedPolicy`; `TestDryRunAnnotationsAreTruthful`;
`TestEmptyDefaultsMeansEmpty`; and a new golden
`internal/policy/testdata/floor.bwrap.txt` — **INDEX §12.1 has claimed `@null`
golden coverage since M0 and never delivered it**; this delivers it under an
honest name and pins what snug does when told to do nothing.

**No existing golden should change.** If one does, the change did more than
intended — that is the first check to run.

#### Strongest argument against (stated fairly)

Deleting `@null` removes the only *nameable* representation of the floor, and
names are how people learn a model. `@null` is discoverable from
`snug profile list`, which everyone runs; `--no-defaults` lives in `--help`, which
fewer read. `snug --dry-run -p @null <dir>` is a better teaching command than
`--dry-run --no-defaults <dir>`.

*Rebuttal:* the name is currently a lie, and the only way to make it true is idea
1, which costs the composability of the whole profile system. A name that requires
breaking the model to be honest is not worth keeping. Discoverability is
recoverable cheaply (list footer + retired-name error); model integrity is not.

#### Two INDEPENDENT bugs found on the way, both in `--dry-run`

Both verified, both unrelated to which way MVY0 goes, both in the artifact
CLAUDE.md calls *the* mechanism by which a human can trust snug:

- **[🟠] `--dry-run` hard-codes `(writable)` and `(tmpfs, ephemeral)`**
  (`dryrun.go:20-21`). `snug --dry-run --no-defaults -p @sys -p @parent-ro <dir>`
  prints `TARGET <dir>  (writable)` — it is not mounted at all — and
  `HOME <home>  (tmpfs, ephemeral)` with `@home` unselected. Two false guarantees
  in the first two lines of the trust artifact.
- **[🟡] `defaults = []` silently widens to the built-in four**, and `snug config`
  reports the source as `built-in` while the user's file says otherwise.

## MVY1: The profile model hardening

1. profiles must be order independent
2. that mean their order must not matter and the order they're evaluated must be explicitly random - like iterating through map in go
3. mentioning the same profile twice is not a problem - it'll works as a set
4. however there is an unresolved problem of a conflicts - the main design says that profile only enables, never disables. Let say there are three profiles
   * A: makes file /foo/bar read-only
   * B: makes file /foo/bar a wrapper from a host
   * C: makes file /foo/bar a read-write file
   * D: makes file /foo/bar a copy on write file (like claude token)
   The question is how to handle such case - however the best option seems to be a fatal error. Think about the same scenario and directories and subdirectories.

MUST update the relevant design document for profiles

### Findings — "fatal error" is right for ONE of the two relations

The report's most useful move is separating two questions the word "conflict"
conflates: **same path** and **nesting**. They have different answers.

#### Behaviour today, established by running every pair through `--dry-run`

Same guest path:

| pair | today | visible in `--dry-run`? |
|---|---|---|
| `ro` + `rw`, same host | **JOIN → rw**, `From = a+c` | yes |
| bind + tmpfs / bind + symlink / tmpfs + symlink | **FATAL**, names both | n/a |
| bind(H1) + bind(H2) | **FATAL**, names both hosts | n/a |
| **symlink + symlink, DIFFERENT target** | **SILENT — first-by-sorted-name wins** | **NO** |

Nested guest paths:

| outer | inner | today | verdict |
|---|---|---|---|
| bind `ro H` | bind `rw H/rel` | allowed, deepest wins → rw | **load-bearing** (`@cwd-rw` over `@parent-ro`) |
| bind `rw H` | bind `ro H/rel` | allowed, deepest wins → **ro** | **load-bearing AND a tightening** |
| bind `H` | unrelated bind / tmpfs / symlink | FATAL | correct (message says "an empty tmpfs" even for a symlink — bug) |
| **tmpfs** | anything | **allowed** | **load-bearing** — see the R2 correction |
| **proc** | bind | **allowed** — `ro = ["/proc/sys"]` accepted and emitted | 🔴 R2 |
| **dev** | bind | **allowed** — a bind replaced `/dev/null` with a regular file | 🔴 R2 |
| — | grant at exactly `/proc` | **allowed**, displaces snug's `--proc` | 🔴 R1 |

#### 🟠 THE BUG: `join` never compares a symlink's target

`resolve.go:439` guards the `Host` comparison with `old.Kind == KindBind`. For a
symlink, `Host` **is** the link target, so it is never checked. Verified:

    $ snug --dry-run -p 0shadow …
      link   /bin -> usr/sbin                    0shadow+@sys
      --symlink usr/sbin /bin

A user profile named `0shadow` (a digit sorts before `@`) **silently overrode
`@sys`'s `/bin -> usr/bin`**, and the provenance line claims BOTH profiles
authored it. This is a profile displacing another profile's grant — the thing
invariant 1 says is structurally impossible. It needs a file in
`~/.config/snug/profiles.d`, so it rides on the known invariant-3 gap rather than
being agent-reachable alone.

Fix: delete the guard. Applied in a throwaway copy — `go test ./...` green,
default-set `--dry-run` byte-identical, and all three symlink conflicts became
fatal with a symmetric message.

#### CORRECTION TO R2 (below): including `KindTmpfs` BREAKS THE PRODUCT

R2 as written says to treat mounts strictly beneath
`KindProc`/`KindDev`/`KindTmpfs` as masks. **`KindTmpfs` must come out.** Every
shipped profile that exposes a host file into the ephemeral `$HOME` is a bind
inside `@home`'s tmpfs: `@git-ro`'s `.gitconfig` and `.config/git`, `@claude`'s
`settings.json` and `CLAUDE.md`, and every generated identity file.

The principled reason: **a fresh tmpfs exposes nothing, so nothing can be hidden
by mounting inside it.** Masking requires the outer mount to have content at the
inner path. R2 narrows to `KindProc`/`KindDev`.

#### The rules recommended

**Rule 1 — same path: join iff identical node, else fatal.** Same `Kind`, `Host`,
`Perms`, `Content`; `Access` joins by max, `Optional` by AND, `From` unions.
This is the existing rule with the symlink hole closed.

*`ro` + `rw` must STAY a join, and the reason is structural.* INDEX §2.4's third
leg is `Resolve(A ∪ B) ⊒ Resolve(A)` — a statement about the access lattice.
`Access` is the only field whose value domain is a semilattice; everything else
names *what node exists here*, and two answers to that have no join, only an
error. Make differing access fatal and `Resolve` stops being a total join, at
which point monotonicity is no longer something the model IS, only something we
hope it does.

**Rule 2 — nesting: the OUTER mount's content decides.**

| outer | inner allowed? |
|---|---|
| `KindTmpfs` | **yes** — nothing to hide |
| `KindBind` of tree *H* | **yes** iff the inner is a bind of *H/rel*; else fatal |
| `KindProc`, `KindDev` | **fatal** — populated by the kernel and by bwrap |
| `KindData` | **fatal** — a grant beneath a file is meaningless |
| anything | **yes** if the inner is snug's own authored replacement |

Fatal-by-default here would destroy the product: three shipped combinations
depend on the permissive cases.

**Rule 3 — authorship as a FIELD, not a convention.** `Mount.Authored`, set only
by `Policy.Replace`, which becomes the single way to write `p.Mounts` after
`Resolve`. `rejectMasking` exempts on `Authored`, not on `Kind == KindData`.

Do **not** key the exemption on `provenance == "(snug)"` as R2 suggests — the
authored mounts carry four different provenance strings (`(snug)`,
`identity:<name>`, `@claude`, `(identity)`), so a string match would exempt none
of them and break `@claude`.

**Three `cmd/snug` sites write `pol.Mounts` raw** (`claude.go:44,50`,
`identity.go:196`) plus `BindSocket`. They bypass provenance recording AND
`Validate` entirely, because they run after `Resolve` returned. `Validate` must
be re-run after the staging layer.

*Note CLAUDE.md invariant 1 is now stale on one point*: it says the `KindData`
displacement happens "without saying so in `--dry-run`". `Resolve`'s `replace()`
DOES say so (`identity:ident+replaces:@git-ro`). It is the `cmd/snug` staging
layer that is silent.

**Rule 4 — R1 as policy, not as a `mustJoin` accident.** A grant at exactly
`/proc` or `/dev` is fatal; `/tmp` keeps the yield, because `@tmp-shared` is the
intended use of it. Split `mustJoin` into `yieldTo` (`/tmp`) and a `Validate`
refusal — one function serving two opposite intentions is the bug.

**Rule 5 — order is IRRELEVANT, not random.** Point 2 of the ask is rejected, and
for a reason that makes the requirement behind it stronger: randomising the fold
in production makes a resolver bug **intermittent**, and an intermittent security
tool is worse than a deterministic one that is wrong reproducibly. Randomness
belongs in the test suite, where a shuffle is a property test and a flake is a
finding.

Three orders the ask conflates: *selection* (already irrelevant, kept only for
display), *fold* (sorted by name; no resolved value may depend on it), *emission*
(depth-ascending — load-bearing, because bwrap applies mounts in argv order, and a
compiler concern that must never surface in the file format).

`resolve.go:77-79` still claims map iteration order is "a feature here"; the next
line sorts. Stale, fix it.

**Address/gateway/MTU are last-writer-wins today** and survive only because of
that sort. Make them a join or a symmetric error (as `identity` already is).
**No key in the model may be last-writer-wins.** `Publish` should union, not
append — §2.3 already claims union and the code produces `[3000 3000 4000]`.

**Test gap:** `TestResolveIsCommutative` compares `canon()`, which renders
`Mounts` and `Env` only — not `Net`, `Identity`, `Podman` or `Profiles`. A
commutativity break in `address` passes today.

Point 3 of the ask (mentioning a profile twice) is **already true** for
resolution. Only the cosmetic `PROFILES` line in `--dry-run` prints `p.Selected`,
implying a multiset and an order the model does not have.

#### THE DECISION FOR THE OWNER

Documenting "deepest mount wins, in both directions" converts an accident into a
**contract**, and that contract is a subtraction verb with a spelling:
`ro = ["{target}/.git"]` inside a writable target. §2.5 deleted `--read-only` and
`Clamp` precisely so no exception would exist — writing depth-demotion into the
design doc reintroduces the carve-out in the *model*, where nobody can grep for
it.

Against that: the behaviour exists whether or not it is written down (confirmed
against a live sandbox — `.git: READ-ONLY (demoted)`), and it is **not removable**
— `@git-ro`, `@claude` and every generated identity file are read-only binds
inside `@home`'s writable tmpfs, so forbidding a deeper grant from being less
permissive breaks all three on the first invocation.

The honest framing if it is documented: *"visibility is monotone; effective write
access at a strict subpath is not, and here is the sentence that says which mount
wins"* — rather than *"profiles only ever grant"*.

#### Review artifact

This change is almost entirely refusals, so it produces **no golden argv diff** —
and the working agreement says a security change with no golden diff is probably
untested. Right suspicion, wrong conclusion here. Add a second golden of the same
character: `internal/policy/testdata/refusals.txt`, a table of *(selection → exact
error text)*. For a change whose content is "these combinations now stop", the
refusal text IS the artifact a human reads to approve it.

Draft design-doc prose for §2.2, §2.3, §2.5, §3.2 and §3.4 is written and ready
to apply when this is decided.

## MVY2: The secrets (in)security

Atm the strategy is that secrets like github tokens are _injected_ into the
sandbox. This is wrong. It will cause the _untrusted_ code having an access to them, which kinda
defeats the purpose of the sandbox itself.

So there are things to do

1. secrets MUST never be injected into the snug's created sandbox - the
   ssh-agent proxy is the model case here - sandboxed ssh will never get an
   access to the ~/.ssh and its keys.
2. A good way of dealing with this is probably a wrapper for binaries like gh,
   which will execute it with the right secrets read from a "host".
3. As there are myriads of a CLI tools out there, it seems impractical for `snug` itself to
   hardcode such wrappers and there must be a way on how to make the wrappers being scripted by an end-user
   * the contenders are - known scripting language like golua, the scripted Go mvm.sh or mvdan.cc/sh/v3 for shell-like wrappers.

The principle that secrets are NEVER injected must be added to design notes.

### Findings — the trade-off you were bracing for DOES NOT EXIST for Claude

**The measurement that decides this:** Claude Code honours `ANTHROPIC_BASE_URL`
over plain HTTP to a loopback address **inside the sandbox's own netns**, and
runs happily with a `.credentials.json` containing a placeholder token. Both
verified on this host. So "claude runs without an immediate login" and "secrets
are never injected" are **not in conflict** — a broker delivers both. The
conflict is real only for tools with no base-URL knob, and `gh` is one (measured:
it forces TLS, and its high-level commands are all `POST /api/graphql`).

Bigger prize: **a brokered Claude needs no `@net` at all.** The sandbox then has
no route off the machine except the one API the broker forwards, so "prompt
injection posts your source to attacker.com" is closed by construction.

#### What is injected today — audited, not read off the docs

| # | secret | where | what an agent does with it |
|---|---|---|---|
| 1 | Anthropic OAuth access+refresh token | writable-tmpfs copy at `~/.claude/.credentials.json` (`claude.go:46`) | exfiltrate it; use your account **after the sandbox exits**, until expiry. Scopes `user:inference`,`user:profile` — quota theft + profile |
| 2 | `~/.claude.json`, 56 KB verbatim host copy | writable tmpfs (`claude.go:47`) | no token, but `emailAddress`, `organizationName/Uuid`, `accountUuid`, `machineID`, **the absolute paths of all 7 projects on this host**, per-project `allowedTools`, `mcpServers`. A host-filesystem inventory `@parent-ro` deliberately did not grant |
| 3 | ~~`ANTHROPIC_API_KEY`~~ | **nowhere — closed** | Was in the environment, readable from `/proc/self/environ` by every process and child, in violation of the project's own "put the secret in a file, not the environment" rule. `@claude` no longer names it, and `base.toml:313` says so in a comment that reads *"deliberately NOT here, and must not come back"*. `ANTHROPIC_BASE_URL` stays: it names an endpoint, not a credential |
| 4 | GitHub token from `gh auth token` | `oauth_token:` in generated `hosts.yml` (`identity.go:192`) | full user token — commonly `admin:public_key`, so **the agent can add an SSH key to your GitHub account, an effect that outlives the sandbox** |
| 5 | ssh private keys | **never** (`internal/sshproxy`) | signing oracle for one pinned key, sandbox lifetime only. **The model.** |

Confirmed absent: `.netrc`, git credential helpers, container registry auth, any
host `~/.config/gh` bind.

**Not all secrets are equal, and the docs treat them as if they were.** The
Anthropic token is quota theft + profile disclosure. The GitHub token is account
takeover persistence. Ranking them the same overstates one and understates the
other.

#### Three defects found while auditing — all cheap, all independent of the big decision

- **[🟠] `--dry-run` denies the credential it is staging.** With `-p @claude`, one
  screen prints `data …/.claude/.credentials.json @claude` under FILESYSTEM
  **and** `~/.claude` under `NOT GRANTED (never mounted — these read as absent)`.
  Cause: `covered()` (`dryrun.go:164`) only considers `KindBind`, so every staged
  `KindData` file is invisible to it. This is R7's shape on the one line where it
  matters most — the trust artifact is actively wrong about a token. **Verified.**
- **[🟠] `--dry-run` prints secrets in cleartext, twice** — in the ENVIRONMENT
  block and again in the bwrap argv (`--setenv ANTHROPIC_API_KEY …`). Anyone
  pasting a dry-run into an issue leaks their key. **Verified: 2 occurrences.**
- **[🟡] The justification for staging `~/.claude.json` is FALSE for claude
  2.1.226.** `claude.go:27` and `base.toml:257` both say "without it Claude
  re-onboards and shows a login prompt". Measured inside a sandbox with the file
  deleted: no login prompt, no onboarding — it connects. Deleting
  `.credentials.json` instead gives `Not logged in · Please run /login`
  immediately. **Only file (1) is load-bearing; file (2) is a 56 KB host-inventory
  leak buying nothing.** Exactly the "grep for X before you believe the comment"
  failure the project already has a rule about.

#### The four shapes, with their abuse sentences

**1. Filtering reverse proxy, snug holds the token** (the `dockerproxy` pattern).
*Abuse: a hostile process can issue, with your full identity, any request the
allowlist permits, with content it chose — **for the sandbox's lifetime only**. It
cannot read the credential, cannot use your account afterwards, cannot reach an
endpoint outside the allowlist.* Anthropic cost is small and closed: three rules,
no TLS, no CA. GitHub cost is large: per-run CA, leaf cert, `SSL_CERT_FILE`
wiring, and an answer to GraphQL that is either "refused, and most of `gh` stops
working" or "forwarded, and the filter is decorative".

**2. Per-operation verb broker.** Tightest blast radius, shortest abuse sentence,
but a bespoke API the agent's real tools do not speak. **Half of it already
exists** — `git push`/`fetch` over ssh is already brokered correctly by the
ssh-agent proxy with `git_protocol: ssh`, so the residual need is only the API
half (PRs, issues, releases).

**3. User-scripted wrapper running the CLI on the host — NOT A SECURITY BOUNDARY,
and cannot be made into one.** *Abuse: execute the brokered CLI on the host,
outside every namespace, with your real credentials and arguments it chose — for
`gh` that includes `gh api -X DELETE`, `gh extension install <attacker-repo>`
(arbitrary host code execution, persistent), `gh alias set` (persistent); for
`git`, `-c core.pager=<cmd>`.* Argument allowlisting does not save it: the
surface is one CLI's entire flag grammar plus config-injection flags plus
extensions plus env vars, growing on the vendor's release schedule.

  Three points on the scripting question:
  - **The boundary belongs at the protocol, not the CLI.** `sshproxy` filters
    agent wire messages, not `ssh` argv. `dockerproxy` filters HTTP, not `podman`
    argv. A credential broker filtering HTTPS is the third instance of one
    pattern; a wrapper filtering argv is the odd one out, and the only one whose
    filter the redteam cannot review because every user's is different.
  - **A user script is a fine place for a DECLARATION, a terrible place for a
    DECISION made on sandbox-controlled input.** "Which host, which paths, which
    header, which secret" is a declaration → TOML. "Given these bytes the sandbox
    sent, decide" is a decision → snug's Go.
  - **`mvdan.cc/sh/v3` is the wrong engine** — shell's entire bug history is
    quoting, and the input is attacker-chosen. `golua` is defensible; Go plugins
    are not (ABI-locked, in-process with the secret). **But do not choose an
    engine before one hand-written adapter exists.**

**4a. No token at all.** *Abuse: nothing — it cannot reach the API.* Zero code.
**This is the correct default** when no broker is configured.
**4b. Scope the credential at the vendor** (fine-grained PAT / App installation
token). Server-side, cryptographic enforcement — **strictly better than any filter
we would write**. Weakness is exactly MVY2's objection: the authority outlives the
sandbox. Cost: documentation, not code.

#### Recommendation

**Build shape 1, hand-written, for exactly ONE vendor; extract a TOML grammar
from it afterwards. Do not ship a scripting engine.**

*M6a — "no secret inside" for Claude:*
1. `internal/broker`: request-filtering, header-injecting HTTP reverse proxy.
   Binds inside the sandbox netns via locked-thread `setns` — **no child process,
   so nothing to orphan**; teardown is strictly better than pasta's. Slots into
   the existing `--block-fd`/`--json-status-fd` handshake (`sandbox/exec.go`) so
   the payload cannot race the bind.
2. `@claude`: synthetic `.credentials.json`; generated minimal `~/.claude.json`;
   `ANTHROPIC_BASE_URL` → the broker; **`ANTHROPIC_API_KEY` removed from `env`**;
   and `@claude` no longer needs `@net`.
3. Allowlist hardcoded in Go for this milestone. TOML comes after one adapter
   proves the shape.
4. `--dry-run`: route NOT-GRANTED through a `covered()` that understands
   `KindData`; render secret-bearing values as `SECRET`; print the broker's host,
   listen address and full allowlist — that IS the boundary now.
5. Legacy injection survives only as `@claude-credentials`: opt-in, never
   defaulted, abuse sentence in the TOML.

*Tests* (negative half is the point, each with a positive control): scan every
readable file **and every process's environ** for the host token → absent, with
the same scan under `@claude-credentials` **finding** it; upstream saw the real
credential while the sandbox never held it; adjacent-still-closed
(`POST /v1/organizations/…` refused, `Host: evil.example` refused, and with no
`@net` a plain `curl https://example.com` still fails while the broker works);
teardown on SIGKILL leaves no socket and no orphan.

*M6b — GitHub, only after M6a.* Start by **documenting 4b** as the supported
answer; it is available today at zero cost and beats any filter we would write.

#### What this does NOT solve — in the docs, not in a comment

**Intent.** A broker bounds the endpoint and the lifetime, never what the agent
does with the authority. Same limit as the ssh-agent proxy. Also: quota theft
while running, writes to the target, and tools with no base-URL knob (which need
a CA and MITM — often not worth paying, and "that tool has no credentials inside"
remains the correct answer).

#### THE PRINCIPLE, verbatim for the design notes

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

#### Strongest argument against (stated fairly)

**It makes snug the maintainer of per-vendor API adapters, and this project has
written down why that is dangerous.** The D-Bus decision says a filtering proxy
that is 95% correct is a sandbox that is 0% sound. A vendor-API broker is the same
species: Anthropic moves an endpoint and the adapter is wrong or broken. The `gh`
half is worse — the honest filter refuses GraphQL and breaks most of `gh`; the
useful one forwards it and the filter is decorative.

Sharper form: **we convert "a secret the agent can read" into "a secret behind a
parser the agent can attack"**, and `internal/dockerproxy`'s recorded history is
four escapes in one handler, three found after it shipped with passing tests. A
parsing bug in the broker leaks the same token, to an attacker who has already
demonstrated the ability to find such bugs here.

Three partial answers: `sshproxy` has exactly this property and is the model that
was chosen; the Anthropic allowlist is **three rules over method and path**, and
if a vendor's allowlist cannot be written in a handful of rules, that is the
signal to choose 4b instead of building an adapter; and the failure mode of a
broken adapter must be "Claude stops working", **never** "fall back to
injecting" — a hard error, or deadline pressure reintroduces the hole.

#### Interactions with MVY0/MVY1 — this is not free

If the broker's declaration moves into TOML it needs a new profile key with
sub-structure (`host`, `listen`, `env`, a **secret reference**, an `allow` list):

- It is the first key whose value **references a secret**. That reference must be
  resolvable only on the host and never expandable from `{…}` vars the sandbox can
  influence — the rule PARAMETERISED-PROFILES.md already applies to arguments.
- `allow` lists **union** across profiles, which keeps monotonicity: adding a
  profile can only widen the broker. Consistent — but a "read-only GitHub" profile
  cannot stop a second profile widening it. Say that out loud rather than
  discovering it.
- Two profiles declaring a broker on the same `listen` address is exactly MVY1's
  same-path conflict. **Fatal**, for MVY1's reason: silently picking one would make
  the effective credential boundary depend on profile order.

Also for whoever owns the profile model: `forbiddenEnv` (now
`internal/policy/envtypes.go`, split by verb) exists to stop code-injection
vectors. There is a case for a parallel refusal — or at minimum a `--dry-run`
redaction — for credential-shaped names (`*_TOKEN`, `*_KEY`, `*_SECRET`,
`*_PASSWORD`). **Still open**, and the counter-example that motivated it is gone:
`@claude` no longer names `ANTHROPIC_API_KEY`, and the `env` key it used is
retired in favour of `environ.inherit`. So the refusal would today cost nothing
that ships — which is an argument for writing it before something needs it, not
after.

## MVY3: Further profile model definitions

There should be a document describing the profiles, their verbs and keywords and a guide on how to make own one.

The interesting aspect is the naming - please limit the names to a safe subset
of ascii - 0-9|a-z|A-Z - @ is already reserved and it MAY happen that other
(ascii printable characters) willl be enabled in the future

**Taken literally that subset outlaws snug's own names.** Eight builtins contain
a hyphen: `cwd-rw`, `parent-ro`, `tmp-shared`, `git-ro`, `net-anon`, `net-host`,
`podman-socket`, `podman-build`. So the rule that carries the INTENT — a small
ASCII subset, with the punctuation space reserved for future sigils — is:

  first character   [a-zA-Z0-9]        never punctuation, so every printable
                                       ASCII symbol stays free to become a
                                       sigil later without breaking a name
                                       somebody already chose
  rest              [a-zA-Z0-9-]       alphanumerics and the hyphen

Everything else is refused by name, replacing the current denylist of five
individually-broken characters. Denylist -> allowlist is the same move the build
filter made: what snug has not been taught about must fail closed.

**DECIDED by the owner: the hyphen is in** — "harmless and enhances
readability". So the rule is settled:

    first character   [a-zA-Z0-9]
    rest              [a-zA-Z0-9-]

Underscore stays OUT unless asked for, on the grounds that adding a character
later is additive and removing one is a breaking change.

Note this is a TIGHTENING: an existing profile called `my_profile` or `my.tool`
stops loading. That is a loud fatal parse error naming the file and the
character, not a silent behaviour change, which is the right shape for a
pre-1.0 tool — but it is a real break and belongs in release notes.

## Nest fixes - M4 phase

 - ~~builtin profiles starts with sigil @~~ — done. The mark is DERIVED
   (`profile.mark`, the only code that adds one) and `checkName` refuses a
   leading `@` in every file it parses, base.toml included, so both halves are
   structural rather than checked: a builtin cannot miss the mark, a user
   profile cannot claim it. Side effects worth knowing: a user file defining
   `sys` is now a profile of their own rather than a rejected redefinition, so
   `merge`'s collision check is only about the /etc-vs-~/.config layers; and
   snug's own mounts (`/proc`, `/dev`, generated `/etc/resolv.conf`) now say
   `(snug)` instead of `(builtin)`, which had come to mean two things at once.
   **Note for R2 below: the string to key the `KindData` exemption on is now
   `"(snug)"`.** Warm engine stores keyed on the resolved profile list are
   orphaned by the rename — a re-pull, per the papercut already recorded below.
 - ~~user defined profiles can't start with @~~ — done, same change.
 - better examples in README
   * show a different gh account (or git user on ssh git@github.com) active per
     profile - note this may require user configuration somehow - so a longer
     example
   * show a running podman/docker ps, run images, whatever
   * show all ssh-keys available
   * claude credentials should be copied into a sandbox, so the claude can be executed without a need for immediate login
   * 

## M5 — `podman build` — known gaps

Shipped and redteamed. The redteam found two, both in the WAVED-THROUGH half of
the allowlist and both fixed before landing:

- **[🔴 host read, fixed] `secrets` src= climbed out of the build context.**
  buildah resolves it against the context dir without clamping `..`, so
  `secrets=["id=leak,src=../../../../home/u/.ssh/id_ed25519"]` plus
  `RUN --mount=type=secret` read a host file the sandbox is not granted and
  streamed it back. It was waved through because the podman CLI reads the file
  itself, client-side — true, and NOT a security argument: the threat model is an
  agent that POSTs to the socket directly. "The friendly client would never send
  that" is never a reason to skip a check, and this is the second time that shape
  has cost something (see the long-s note above).
- **[🟡 hardening, fixed] the seccomp check asked the wrong question.** It applied
  the mount rule — "a path the sandbox can see" — and the target is visible AND
  writable, so an allow-all profile written into the project passed the check
  meant to stop `unconfined`. Visibility is right for a MOUNT; for a file the
  engine applies AS THE SECURITY POLICY the question is who wrote it. Now
  readable-but-not-writable.

Both have named regression tests verified to fail against the code before them.

These are the things M5 does NOT do, recorded so they are not mistaken for
oversights.

- **[🟡 teardown] A build's working containers do not carry the run label.**
  buildah creates them inside the engine, server-side, not through the proxy — so
  `stop --all --filter label=snug.run=…` does not reach them. `rm=1` (the CLI's
  default) removes them when the build finishes, so this only bites an INTERRUPTED
  build, and only until the engine's idle timeout takes the whole engine down.
  Note it narrowed with the label fix: the previous store-wide `stop --all` would
  have caught them, at the cost of stopping a sibling's containers too. Closing it
  properly needs the label applied engine-side.
- **`cachefrom`/`cacheto` are refused.** A cache reference is resolved by the
  engine and can name a local path, so it needs the mount rule applying to it
  before it can be allowed. Nobody has asked for it yet.
- **The context tar is forwarded unread**, on the argument that the client
  assembled it inside the sandbox from files the sandbox can already read. The
  redteam tried `..`, absolute and symlink entries in the tar and could not get
  buildah 5.8.3 to write outside its builder directory — but that is the ENGINE's
  securejoin protecting us, not snug's, so it is a dependency to remember rather
  than a property snug holds.
- **`TestEveryBuildValidatorIsExercised` skips the waved-through parameters**,
  which is exactly why `secrets` had no coverage while it was `nil`. A test that
  a NEW nil entry must be justified would have caught it; nobody has written one.

## Postponed by decision

### Parameterised profiles

Deliberately deferred to a later stage — not rejected. It touches the identity
rule, which is where commutativity and idempotence live, so it is not something
to attach to the side of a milestone.

The shape, from the owner:

```
[[profile.-srv-rw]]
rw_dirs = /srv, /foo, /bar
```

Two things worth keeping from the discussion:

- **Why profiles and not CLI flags.** The obvious cheap alternative is
  `snug --ro /data --rw /build`, which needs no change to the model at all. It
  was rejected, correctly: *"bwrap itself is a powerful tool, yet humans can't be
  expected to write all the parameters by hand. The point of this tool is to
  enable a policy which can be specified by a mere human."* A flag you retype
  every invocation is bwrap with better spelling — ad-hoc, unreviewable,
  uncomposable, and gone when the shell history scrolls. The product is a named,
  reusable, reviewable policy. Do not solve this with flags.
- **The identity insight.** If a profile instance's canonical name ENCODES its
  arguments (`rw:/srv`, or `-srv-rw` in the sketch above), identity stays a
  single string. `expand`'s set-based dedup keeps working, so `rw:/srv` twice is
  one member and `rw:/srv` vs `rw:/data` are two — commutativity and idempotence
  survive untouched. That is far cheaper than making identity `(name, args)`,
  which would put a fingerprint on the core property tests.

**The design note is `.claude/design/PARAMETERISED-PROFILES.md`. Read it before starting.**
Headline: the sketched example is not actually parameterisation — a profile
granting /srv, /foo and /bar is an ad-hoc list of grants wanting a name, and
that already works today by writing `~/.config/snug/profiles.d/mine.toml`. The
identity insight holds, with three provisos. Arguments must never come from
environment variables (direnv would let a repo author its own boundary).

## Pending

### Prompt could show an unusually wide profile set

`PS1` is `🔒 snug:\w\$ `. A marker when something wide is active — `@net-host`,
or a user-written profile granting a large tree — would make a permissive
sandbox visible at a glance rather than only in `--dry-run`.

## Container proxy — found by mutation-testing (M4 review round)

**ALL FIXED**, plus a third the redteam found in the fix itself (long s, U+017F —
`strings.ToLower` is narrower than `encoding/json`'s fold, so `Bindſ` smuggled an
unchecked host-root bind past the mount rule). `decodeObject` now refuses
non-ASCII keys, which closes the class rather than the rune. Every one has a
named regression test verified to fail against the code before its fix. Kept here
as the record of what was wrong, because the next person to touch this handler
needs it.

- **[🔴 escape] Any create request with an `Upgrade:` header bypasses the whole
  proxy.** `isHijack` (`internal/dockerproxy/proxy.go:354`) returns true on
  `Upgrade`/`Connection: upgrade` for **any path**, before `handleCreate` runs, and
  `hijack` does `r.Write(up)` — the raw request goes to podman. Verified:
  `POST /v1.41/containers/create` + `Upgrade: tcp` with
  `{"Privileged":true,"Binds":["/:/host"]}` reached the engine byte-for-byte,
  200 OK. Fix: gate hijack on a known streaming PATH (containers attach; containers
  start *with* upgrade; exec start), never on the header alone.
- **[🔴 escape] Case-variant JSON keys bypass every denylist.** Lookups are
  exact-key on a `map[string]json.RawMessage` (`create.go:39,52`); podman decodes
  with `encoding/json`, which is **case-insensitive**, and `json.Marshal` sorts map
  keys so the attacker's lowercase variant always sorts last and wins.
  `{"hostconfig":{"privileged":true,"binds":["/:/host"]}}` reached the engine with
  snug's `"Privileged":false` sitting harmlessly beside it. Fix: reject any object
  with two keys equal under case-fold, fold `req`/`hc` keys to canonical case before
  filtering, and delete any case-variant of an injected key (`Privileged`,
  `SecurityOpt`) before re-inserting snug's own.

Both are `host-bridge`'s surface (the podman socket proxy). To fix in the same pass,
because they share the handler:

All five are FIXED. What the fixes were, since two of them changed the product:

- ~~`net-publish` auto does not work~~ — **the capability is removed, not
  repaired.** Re-measured before acting and it is worse than recorded: `-t
  127.0.0.1/auto` publishes nothing EVER, not merely late. pasta scans the
  namespace for bound ports once, at its own startup, which is before the payload
  exists — refused at 3, 10, 20 and 30 s after a listener came up inside. There is
  no pasta reconfigure API, so making it work would mean snug growing a
  port-forwarding daemon that watches the sandbox's /proc/net/tcp — i.e. handing
  the AGENT the choice of what appears on your loopback, which INDEX §4.6 argues
  against on its own merits. So `publish_auto`, and the `@net-publish` profile
  built on it, are gone; `publish = [3000]` stays and works. Strict decoding turns
  an existing `publish_auto` into a fatal parse error naming the key
  (`TestRetiredPublishAutoIsAHardError`) rather than a profile that quietly does
  nothing.
- ~~`docker run`/`create` refused by LogConfig~~ — `isDefaultLogConfig` lets
  `{"Type":"","Config":{}}` through (decoded, not pattern-matched, so key order and
  case reach the same verdict). A named `Type` or any `Config` option is still
  refused, which is where the host-file-write hazard lives.
- ~~`HostConfig.Tmpfs` silently deleted~~ — forwarded, with the abuse sentence in
  the code. A tmpfs has no source, so the mount rule has nothing to check; the RAM
  is the same RAM any process in the container could allocate, and that is R8's
  gap, not a new one.

## Engine — found by host-bridge (teardown work)

- ~~`stop --all` at teardown is store-wide~~ — fixed. The proxy stamps
  `snug.run=<pid>` (`engine.RunLabelKey`) on every container it creates, and both
  `Engine.stopLocked` and the reaper script stop with
  `--all --filter label=snug.run=…`. Verified against podman 5.8.3 that the filter
  scopes a stop to the matching container and leaves a sibling running. The
  client's own labels survive; a client VALUE for `snug.run` does not, because a
  container that could name its own owner would either survive its own teardown or
  be stopped by a sibling's.
- **[🟡 papercut] Warm stores are silently orphaned by profile renames.** The store
  key includes the resolved profile list, so a rename like `parent-ro`->`@parent-ro`
  changes it mid-session and a warm store with a pulled image becomes unreachable.
  Harmless (a re-pull), but worth a note.

## Independent bugs found while reviewing that idea

Neither is about parameterisation; both stand on their own.

### **[latent security]** A symlink in the target can divert a grant

`Resolve` canonicalises the host side of every bind, so a grant of
`{target}/build` — where a previous sandbox run left `build -> ~/.ssh` — would
bind `~/.ssh` into the sandbox. Not reachable today (no builtin uses a
`{target}`-relative subpath grant) but live the moment anyone writes one.

Fix sketched in `.claude/design/PARAMETERISED-PROFILES.md`: refuse a grant at or below the
target whose `EvalSymlinks` result differs from the lexical join under the
canonical target. Comparing against the lexical join rather than against the
path itself is what avoids false positives from `/home -> /var/home`. Apply the
same rule to `{host_tmpdir}`.

### `ctx.Home` is never canonicalised

The target is `EvalSymlinks`'d and fail-closed; `$HOME` is used verbatim. Host
sides of `{home}/...` grants get canonicalised by `add()`, the guest side does
not. Fix is one call in `Resolve`. Expect a golden argv diff on any host where
`$HOME` traverses a symlink — correct, and to be reviewed as a security change.

## Left open by the `environ` work

Two things the environment-variable change deliberately did not fix. Both were
found while implementing it; neither is a regression of it.

### **[portability]** The flat `environ = { set = { … } }` form parses here

TOML 1.0 does not allow a multi-line inline table, and go-toml v2.4.3 accepts one
anyway — measured. So a profile written

```toml
[profile.x]
environ = { set = {
  MY_VAR = "1",
} }
```

works on this host and fails on a stricter parser. **It is not implementable
post-decode:** the decoded value is byte-identical to the header form
(`[profile.x.environ.set]`), and go-toml hands us no syntax provenance, so
refusing it needs a second independent pass over the document text.

Recorded rather than fixed, and the important half is what must NOT happen: no
comment anywhere may claim snug refuses this form. A gate that is documented and
not implemented is not a gate. Write the header form.

### **[security, pre-existing]** The environment outranks the pinned config file

Untouched by the `environ` work, and a reader will assume `environ.set` made it
worse. It did not — a profile is reviewed text in a trusted layer — but the
underlying fact is live and measured:

```
env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=Injected \
       git config --get user.name          →  Injected
```

*A hostile process inside the sandbox can set `GIT_CONFIG_KEY_0=core.sshCommand`
and have the next `git fetch` — including one an unsuspecting user or agent runs
— execute its command, with `GIT_CONFIG_GLOBAL` pointing at a perfectly clean
generated file.* Not a break in the sandbox boundary (the payload already runs
code); a break in **identity pinning**, which is the guarantee `GIT_CONFIG_GLOBAL`
exists to make. The same shape is documented for npm (`npm_config_*` outrank
`.npmrc`) and pip (`PIP_*` outrank the file).

What the `environ` work did do is refuse those names in a profile:
`GIT_CONFIG_*` and `LD_*` are forbidden at every verb, `PIP_*` and `npm_config_*`
for `inherit`. That closes the profile-authored route and nothing else. The
payload-authored route wants its own investigation and its own fix —
"generate, don't bind" pins a tool's **file** and leaves its **environment**,
which is the higher-precedence source.

### **[fixed, with the reasoning that bounds it]** `sanitise` kept a host element a tmpfs covered

`GrantsGuestPath` returned true for any covering mount regardless of kind, so a
host `PATH` containing `/tmp/x/bin` survived the filter. `/tmp` is empty
inside, the payload can `mkdir -p /tmp/x/bin` and drop a binary named `git`,
and the sanitise band sits ahead of snug's base band — so that file wins
`PATH` resolution for any later `git` a human or another agent runs inside.
Reproduced end to end (marker `SHADOWED-GIT-RAN`). Reachable only via a
user-written `environ.sanitise = ["PATH"]`; no shipped profile sanitises
anything.

Two candidates. **A — drop an element whose covering mount is writable — was
rejected**, and the reason governs everything below it:

> the payload can rewrite `PATH` inside the sandbox at will, so no filter can
> close the shadowing attack. What the filter owes is that the environment
> SNUG ITSELF hands over does not ship the shadow slot pre-installed. A chases
> an invariant the sandbox cannot hold; C makes snug's own output truthful.

**C — drop an element whose coverage comes only from a `KindTmpfs` mount —
shipped.** It is the existing truthfulness contract (`envresolve.go:288`)
giving a correct answer to the question it already asks: a tmpfs grants an
EMPTY directory, not the host's content, so such an element was never a
truthful survivor. A writable *bind* still survives, target included.

Also rejected as part of this decision, and out of scope: refusing
`environ.merge PATH` entries naming a path granted `rw`.

### **[residual, accepted]** Shadow slots C does not remove, by construction

Each is a writable directory that can precede `/usr/bin` on the `PATH` snug
writes. None is closable by a filter — see the reasoning above — and each is a
grant the human selected:

- ~~`@claude` merges `{home}/.local/bin`, which is inside `@home`'s tmpfs. The
  merge band is a profile's own declaration and is unfiltered.~~ **Closed, and
  the bullet was wrong about whose declaration it was.** "A profile's own
  declaration" is the right defence for a profile a *human on this host* wrote;
  `@claude` is one snug ships, so this was snug installing the slot and then
  filing it as accepted. Everything about the filter reasoning stands — no
  filter can reach a `merge` entry — but the repair was never meant to be a
  filter: the binary is now bound at `/run/snug/bin/claude`, snug adds that
  directory to `PATH` itself, and `@claude` names no PATH directory at all. See
  `policy.StagedBinDir`, CLAUDE.md's staging rule, and
  `TestNoBuiltinPutsAWritableDirectoryOnPATH` with its positive control.

  The general rule this leaves: **the residuals below are ones a human selected;
  a shipped profile is never allowed to be one.**
- With `@tmp-shared`, `/tmp` is a `rw` bind of a host directory, so
  `/tmp/x/bin` survives sanitise — and that survivor **persists to the host**.
  The drop-never-rewrite half of this is already settled policy.
- A user profile creating a `KindSymlink` pointing into a tmpfs keeps its
  element (symlinks are not followed by the filter). This one stays: a
  `KindSymlink` is authored by a grant and points where that grant says, so
  following it here would be a second resolution rule with its own failure
  modes.
- ~~`/dev` is a writable synthetic tree and `KindDev` is a keep.~~ **Closed —
  and the bullet argued its own way out.** It said widening to `KindDev` was
  not worth it because "an element under `/dev` on a host `PATH` does not
  occur". If it never legitimately occurs, keeping it costs nothing to drop and
  serves only an attacker's spelling. `KindProc` and `KindDev` now both drop,
  with their own `DropPseudoOnly` reason. See the entry below for what forced
  it.

### **[fixed]** `/proc`'s magic symlinks were a fourth shadow slot, and the walk could not see them

Found by the red team against `a8652ba`, after the tmpfs fix had shipped.
`keepHostElement` kept `KindProc` and `KindDev` on the grounds that they are
"kernel- and bwrap-populated, not empty". That is true of the **directory** and
false of what `/proc`'s magic symlinks **resolve to**. The filter is lexical and
deliberately does not follow symlinks, so `coveringMount` stops at `/proc` while
the kernel walks:

```
/proc/self/root/tmp/x/bin   ->  the writable tmpfs        SHADOWED-GIT-RAN-VIA-PROC-ROOT
/proc/self/cwd              ->  the target, and the shadow file PERSISTS TO THE HOST
                                                          SHADOWED-GIT-VIA-PROC-CWD
/proc/1/root/tmp/x/bin      ->  the writable tmpfs
```

Same precondition as the finding it follows — a user-written `environ.sanitise
= ["PATH"]` plus a host `PATH` carrying the element — so the same bound, not a
weaker one. The general lesson is worth more than the fix: **a lexical
predicate answers about the path it was given, and the kernel answers about the
path it resolves. Wherever those two can differ, the difference is the
attack.** `..`, trailing slashes and repeated slashes were all probed and are
NOT exploitable, because `coveringMount` cleans before it walks.

Fixed by dropping both kinds. Asserted by
`TestSanitiseDropsProcAndDevMagicSymlinkElements`.

### **[fixed]** A newline in a host `PATH` element forged a `--dry-run` line

Also from the same run. The drop line rendered the host-supplied value verbatim,
so an element containing a newline split the line, and the injected second line
read as a legitimate ENVIRONMENT row complete with a fake provenance column.
Escapes nothing — but `--dry-run` is *the* mechanism by which a human can trust
snug, and a value that can author a row in it is a hole in the trust artifact.
`internal/policy` already applied this guard to variable NAMES in its error
messages (`quoteVisible`); the values had no equivalent.

Fixed by `visibleValue` in `cmd/snug/dryrun.go`, applied to kept entries as well
as dropped ones. A value with no control characters renders unchanged, so no
golden moved. Asserted by
`TestDryRunDropLineDoesNotRenderControlCharsVerbatim`.

### **[latent]** `sanitise`'s monotonicity now rests on `rejectMasking`

Adding a profile can only turn a drop into a keep *because* a `KindTmpfs`
cannot be installed beneath a `KindBind` (`validate.go:245-252`). Relax that
and the environment stops being monotone as a set. Asserted by
`TestSanitiseMonotonicityRestsOnRejectMasking`.

## Pseudo-filesystem exposure (`/proc`, `/sys`, `/dev`)

Full report: [`.claude/design/PSEUDOFS-AUDIT.md`](.claude/design/PSEUDOFS-AUDIT.md) — deep research +
live verification against HEAD. Headline: **no escape** (every `/proc` write
primitive is refused by kernel DAC + zero capabilities), but the **read side of
`/proc` leaks more than crun's default** and it is snug's to fix. `/sys` is absent
by construction and `/dev` is a 14-entry synthetic tree with the classic
device-escape surface missing — both verified, both stronger than the docs say.

Two of the findings are **structural defects that contradict invariant 1 as
written** and are the highest-value fixes (both are refusals-to-add, not
restrictions, so both are cheap and invariant-safe):

- **[🔴 structural] A profile can displace the `/proc` and `/dev` builtins.**
  `mustJoin` (`resolve.go:426`) installs a builtin only if the guest path is
  unclaimed, so `ro = ["/dev"]` yields `--ro-bind /dev /dev` (250+ host nodes, the
  host `/dev/shm` with readable contents) and `ro = ["/proc"]` yields the full
  outer process table. Gated today on the recorded invariant-3 XDG gap, but the
  payoff of that gap is far larger than its "low severity" note implies. **Fix R1:**
  a hard `Validate` error on a grant at exactly `/proc` or `/dev`.
- **[🔴 structural] `rejectMasking` skips non-`KindBind` ancestors**
  (`validate.go:143`), so a profile *can* mount host content on top of any path
  inside `/proc`, `/dev` or `/tmp` — `ro = ["/proc/config.gz"]` and
  `ro = ["/proc/sys"]` both accepted and live. This is the subtraction verb
  invariant 1 says the grant language cannot express. **Fix R2:** treat mounts
  strictly beneath a `KindProc`/`KindDev`/`KindTmpfs` mount as masks, and re-key
  the `KindData` exemption from kind to `provenance == "(snug)"` (must land with
  R2, or R3 below hands profiles the verb).

Leak closures snug *could* make (bwrap has no procfs masking options, so each is a
snug-authored **replacement**, which the author distinction licenses — verified
feasible with an empty regular file, NOT `/dev/null`, which yields EACCES not
empty content):

- **[🟠 leak] R3** — empty-file replacements at `/proc/config.gz`, `/proc/keys`,
  `/proc/key-users` (tier 1, no compat cost; `keys` is what crun/runc mask and snug
  already seccomp-denies the keyring syscalls); tier 2 is `kallsyms`, `modules`,
  `interrupts`, `sysrq-trigger`. Print every replacement in `--dry-run`.
- **[🟠 leak] R4** — `--ro-bind /proc/sys /proc/sys` makes the write side snug's
  (EROFS) instead of the kernel's; costs nothing, matches crun.
- **[🟡] R5** — `snug doctor` should read and report the host hardening it silently
  depends on (`kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid`,
  `ptrace_scope`, `unprivileged_bpf_disabled`). It checks none today.
- **[🟡] R6** — refuse a **rw** grant at/under `/sys` (cgroup delegation gives
  kill/freeze over out-of-sandbox processes); keep **ro** `/sys` expressible.
- **[🟡] R7** — route `dryrun.go:162`'s hard-coded NOT-GRANTED literal through
  `covered()`; today it can print `ro /sys` and "never mounted" on one screen, in
  the one artifact a human trusts. One line.
- **[🟢] R8** — bound the `/dev`, `/dev/shm`, `/tmp`, `$HOME` tmpfs with `size=`
  (host-RAM-exhaustion DoS; the engine's own containers already do this).
- **R9** — batched doc corrections (INDEX §5.2 `/dev` enumeration and §5.3
  fingerprint claim, the phantom `[profile.sysfs]`, N5's side-channel list,
  `podman-socket`'s host-resource claim, the time-namespace fact for CLAUDE.md).
- **R10** — opt-in `--new-session` for non-interactive payloads (closes the
  `/dev/tty` OSC-52 channel to the operator's terminal); do **not** filter escape
  sequences.
- **R11** — `SECCOMP_RET_ERRNO` on non-native arches instead of ALLOW (the i386
  path is the only remaining native route toward a writable remount).

Accepted gaps and the full test list (§Disposition) are in the report. **Every
confirmed finding becomes a named regression test with a positive control before
its fix lands** — several existing pseudo-fs tests fail the `pasta.avx2` "can this
test ever fail?" check and are named in the report.

Note: the workflow's `redteam`-typed phase did not spawn (that agent type is not
in the workflow runner's registry), so this rests on the research agents' own live
probing plus lead re-verification. A dedicated `redteam` pass over this surface is
still worth running before a fix lands.

## Known gaps in what the docs claim

All are documented where they bite; listed here so they are not forgotten.

- **`forbiddenEnv` does not close the exec class for git.** `EDITOR`, `VISUAL`
  and `PAGER` are legal at `set` and at `inherit` by ENVIRONMENT-VARIABLES.md
  §3.2's decision, and `@claude` inherits all three — while git falls back
  `GIT_EDITOR → core.editor → VISUAL → EDITOR` and `GIT_PAGER → core.pager →
  PAGER`. Measured: `PAGER="sh -c '…'" git log` runs the command. So the `GIT_*`
  spellings being refused closes the INVISIBLE half of the class, not the class.
  Profiles are the trusted layer, so this is a composability defect — one
  profile weakening what another established — rather than an escape. Closing it
  means withdrawing a grant from every profile that inherits those three, which
  is a §3.2 decision and not a table edit.
  `TestForbidListDoesNotCloseTheExecClassForGit` pins the current state so the
  change has to be deliberate.
  *(A separate clause claiming these were "refused inside `@git-ro`-style
  identity" was a phantom gate — nothing anywhere read `Policy.Identity` — and
  has been deleted from §3.2 rather than implemented.)*

- **`--config` and privileged-grant gating do not exist.** INDEX §2.7 describes
  them; `profile.Profile.Trusted` is set and never read. Consequence found by
  the redteam agent: `$XDG_CONFIG_HOME` is trusted unconditionally, so pointing
  it at a checked-out repository loads that repository's profiles. Low severity
  — it is the host user's own env var, not something the sandboxed agent
  controls. CLAUDE.md invariant 3 states the real behaviour.
- **Seccomp does not cover non-native architectures.** The x86_64 i386-compat
  path falls through to ALLOW, so a 32-bit binary bypasses the filter. Closing
  it means denying the compat arch outright, which breaks 32-bit binaries;
  the trade was taken deliberately and is documented in
  `internal/sandbox/seccomp.go`. (`clone3` and the x32 ABI WERE gaps and are now
  closed — clone3 is denied outright since classic BPF cannot read its flags,
  and x32 syscall numbers are rejected by their high bit.)

## Supervisor Phase 1 — found-and-not-fixed-here

Per `.claude/design/SUPERVISOR-DESIGN.md` §9; each is either a pre-existing
defect Phase 1 measured but had no mandate to fix (its contract is "adds and
removes nothing"), or a gap Phase 1 deliberately leaves for Phase 2/3.

- **`MS_REC|MS_PRIVATE` in P1 (`__stage-setup`) has no test of its own.** The
  obvious assertion cannot be one: a mount namespace created in the SAME clone
  as a user namespace already shows zero `shared:` peer groups on this kernel,
  so the check would pass with the call deleted. Its only real test arrives
  with a Phase 3 graft (the mechanism 0c measured RED, independent of this
  phase). Severity: low here, high the moment a graft exists.
- **`runtimeDir()` (`cmd/snug/identity.go:19`) has none of `prepareHostTmpDir`'s
  guards** and falls back to a predictable `/tmp/snug/run-<pid>` when
  `XDG_RUNTIME_DIR` is unset. MEASURED (pre-existing, not introduced by this
  phase): `os.MkdirAll` follows a pre-planted symlink-to-directory and does not
  chmod an existing one, so the ssh-agent proxy socket lands in the attacker's
  directory with the attacker's mode. Severity: low (same host, pid guess,
  sticky `/tmp`), but it is the directory Phase 2's control socket must **not**
  live in when it grows a pathname.
- **bwrap's `--unshare-all` uses the `-try` spellings for `user` and
  `cgroup`**, so on a host with unprivileged user namespaces disabled the
  sandbox silently gets none — on EITHER topology, since the stage's own
  enumerated `--unshare-*` set (§3.1) deliberately matches those same `-try`
  spellings rather than fix this inside a phase whose contract is "adds and
  removes nothing". INFERRED from bwrap's flag list; measure before acting.
  Severity: medium (invariant 5).
- **`pidfd_getfd(2)` is absent from `deniedSyscalls`** and was measured working
  inside a real sandbox (`.claude/design/NOCGO.md`). This is a hole in shipped
  snug, not in this phase, and it is worse than it first reads: two co-resident
  payloads are protected from each other's descriptors **only by the host's
  `kernel.yama.ptrace_scope = 1`**, a global non-namespaced sysctl that is
  commonly `0` inside containers — which is exactly where key feature 3 says
  snug must work. On such a host one payload reads another's descriptors with
  no error, no warning and no line in `--dry-run`: the invariant-5 shape. The
  fix is to deny `pidfd_getfd` only and leave `pidfd_open` allowed (it hands out
  a handle but no descriptors, and Phase 2's attach path wants it); verified not
  to repeat the `clone3`/ENOSYS trap. Severity: medium.
- **A user profile with `tmpfs = ["/run"]` plus `@podman-socket` is ACCEPTED
  by `Validate`** (found during Phase 0c, in shipped snug, not this branch):
  the sandbox starts and the payload writes `/run/snug/bin/git` and runs it.
  `snugsOwn` is keyed on the exact guest path, so a mount at an ANCESTOR of
  `StagedBinDir` is not refused. Detected loudly by `--dry-run` via
  `IsShadowSlot` ("IS WRITABLE from inside, which it must never be"), so it is
  detected-but-not-refused rather than silent. Severity: medium. The fix —
  extend the refusal from "a mount AT `StagedBinDir`" to "a mount covering
  `StagedBinDir`" — is the same fix the Phase 3 graft work needs anyway.
- **`P1` must stay dumpable** for pasta to open `/proc/<P1>/fd/<n>`, and
  `hidepid=2` (or an explicit `PR_SET_DUMPABLE=0`) breaks it. That this must
  land on the sandbox's own init in Phase 2 and **never** on P1 is a
  constraint that exists only in this file and in the design doc today, not
  enforced in code. The dependency is not new — today's `waitForNetDevice` and
  pasta's `--userns` already need P0 to read P1's `/proc`, same reason — but a
  future patch touching P1's own hardening must know about it.
- **Golden argv is necessary and not sufficient for the netns posture.** Stated
  narrowly, because the earlier wording ("byte-identical *except for* the
  enumerated `--unshare-*` set") refutes itself — the argv does distinguish all
  three topologies, by construction of `BwrapFlags`. What the argv cannot tell
  you is whether an ABSENT `--unshare-net` means "the stage put bwrap in N" or
  "nothing put bwrap in any network namespace at all". Which process called `fork` is
  what actually determines the topology, not anything a diff of the argv can
  show. `internal/policy/testdata/podman-socket.bwrap.txt` is the one golden
  that DOES show the difference (its first line), but nothing forces a reviewer
  to notice that a *different* golden case reading `NetEgress` unchanged is
  hiding an identical process-topology change. No test asserts this is a
  problem worth chasing further; recorded here as a reviewing hazard, not a
  code defect.
- **Deferred to Phase 2, not fixed here** (per SUPERVISOR-DESIGN.md §8,
  restated so it is findable from this file too): the control listener (a
  pathname socket, an accept loop, the 108-byte `sockaddr_un` budget check —
  Phase 1's protocol has no client but its own parent, so there is nothing to
  listen for yet); the subuid delegation and `newuidmap`/`newgidmap` (no
  consumer until an engine moves into the stage); `Topology.Attach` being
  raised by anything (the floor and the `Join` law exist now; nothing sets it
  above `AttachNone`); a pidfd table for more than the one bwrap fork Phase 1
  has; a `--dry-run` `attach` block; the injected `~/.claude/CLAUDE.md`
  mentioning the topology (the payload cannot observe the stage at all yet, so
  there is nothing true to say); starting pasta before bwrap (Phase 3 wants
  this for the engine; unmeasured whether a socket bound in N before P1 leaves
  it stays usable, per §8 — do not design around it before measuring it).

### The parked-payload window: the guard is armed after the thing it guards exists

Severity: **medium**. This entry replaces an earlier one that stated a mechanism
three independent measurements have since falsified. Reproduced by four separate
runs across three review rounds; the numbers below are the current ones.

bwrap releases a payload parked on `--block-fd` on **EOF just as readily as on a
byte**, and snug's own death closes the write end. So between bwrap forking the
payload and pasta being confirmed up, an exit of snug releases the payload.

**Measured directly, 2026-08-13, and the earlier numbers in this entry were
wrong in BOTH directions.** The window is ~12 ms, not ~90 ms, and it is
**SIGKILL-only** — the catchable signals really are closed.

*The timeline*, from an instrumented build of the stage arm, milliseconds from
process start:

```
13.0  bwrap forked          <- the payload exists and parks from here
19.5  readChildPID returns
19.6  park() armed          <- 6.6 ms after the fork, not 60 ms
30.1  pasta up
30.2  release               <- the payload legitimately runs from here
```

*The kills*, with the window widened to ~3 s by a deliberately slow pasta so
that a fixed offset lands unambiguously **inside** it, killing at 1.0 s:

| signal | payload ran | orphaned bwrap |
|---|---|---|
| SIGTERM | **0/5** | 0/5 |
| SIGINT | **0/5** | 0/5 |
| SIGKILL | **5/5** | 5/5 |

**Why three reviews said SIGTERM was open, and were wrong.** Each killed at a
fixed wall-clock offset — 60 ms, 100 ms — and observed the payload had run.
At those offsets the payload had *already been released*, at ~30 ms, on
purpose. Their positive control (an unkilled run writing the marker) cannot
tell "released early by the bug" from "released correctly, then killed", and
none of them established where release actually falls. Three independent agents
reached one wrong conclusion from one shared method error. **A fixed offset is
not a measurement of a window whose position you have not measured.**

**What is real, and it is real:** SIGKILL of snug between bwrap forking the
init and the release runs the payload, every time, and leaves an orphaned
sandbox. SIGKILL cannot be caught, so no guard inside snug can close it. The
chain: snug dies → `blockW` closes → the init's `--block-fd` read returns EOF →
bwrap releases on EOF exactly as readily as on a byte → the payload runs. The
stage's own teardown loses because bwrap does not arm the init's
`--die-with-parent` until that same read returns, so the init is unprotected for
the whole window rather than for an instant at the start of it (measured with a
matched pair, round 2).

What the orphan retains is narrower than it sounds: the stage, pasta and the
privileged ancestor user namespace are all gone by then, so what is left is the
bwrap tree, unbounded runtime, and persistent write access to the target — the
same shape an orphan on the pre-stage path leaves. **A lifetime defect, not a
confinement defect.**

**Arming the guard earlier does NOT fix it.** That was the agreed fix and it is
wrong: the guard exists to catch signals, and the only signal left cannot be
caught. Moving `park()` earlier narrows nothing that matters. (It is still worth
doing for tidiness, and costs a pid-less `park(0, …)` filled in later, but do not
record it as the fix.)

**The real fix is topological, and the blocker recorded against it is FALSE —
measured.** Under `NetnsStage` the namespace exists before bwrap does, so pasta
can be started *first* and bwrap forked with no `--block-fd` and no
`--json-status-fd` at all. Nothing is parked, so nothing can be released early,
and the `parked` type stops being needed on this path. The design deferred this
because "confirming the interface is up needs a process inside N to read
`/proc/<pid>/net/dev`, which is a control-protocol addition".

That premise does not hold. **A socket's network namespace is fixed when the
socket is created, and does not follow the process.** The stage already opens an
`AF_INET` datagram socket inside N to bring `lo` up; if it keeps that
descriptor, `SIOCGIFFLAGS` on `snug0` through it still queries N after the stage
has left. Measured, with both controls:

```
in N   : lo flags=0x0049 IFF_UP=true    <- positive control
in N2  : lo flags=0x0008 IFF_UP=false   <- fresh socket in the new namespace
in N2  : lo flags=0x0049 IFF_UP=true    <- the socket created in N, after the move
```

So the readiness check needs no extra process, no protocol message and no
`/proc` path — one descriptor the stage already has. That removes the stated
reason for deferring, and makes closing this a bounded piece of work rather than
a design question.

**One thing to know before touching it:** the parked machinery on the
NON-stage arm (`internal/sandbox/exec.go:165–197`) is **unreachable**.
`needsNet` is `Net.Mode == NetEgress`, and `deriveTopology` maps `NetEgress`
to `NetnsStage` and nothing else does, so `needsNet` ⟺ `NeedsStage()` and the
non-stage arm always returns at the `!needsNet` branch above it. There is one
site to fix, not two — and the second copy is dead code that reads like a
second implementation of the same discipline. (It becomes reachable only for a
`Policy` whose `Topology` disagrees with its `Net.Mode`, which `Validate`
refuses.)

### Supervisor review round 3 — confirmed, not fixed here

A full code review, an architecture/invariant review, a host-integration audit
and a red-team run. **No new escape was found**: capabilities empty on all three
topologies, host loopback closed by behaviour, abstract sockets private to N,
the payload holding exactly stdio, `/proc/1/environ` empty, and the stage
measured **not** to widen the host surface (a same-uid host process reaches
uid-0-with-full-caps over the sandbox's namespaces on the pre-stage path too,
via `NS_GET_USERNS` on the sandbox's own namespace descriptor). Fixed in this
branch: the `fdseal` silent no-op, `__innetns`'s inherited environment, the
`parked.release` fail-open ordering, the orphan pidfd, the two falsified
comments, and two tests that could not fail. Left open:

- **`Stage.Wait()` is an unbounded read** (`internal/stage/stage.go`). SIGSTOP
  the stage after the payload has finished and snug blocks forever — MEASURED.
  Host-side only: the payload is in another pid namespace and cannot signal the
  stage. It is the control-channel twin of the `netHelper.stop()` hang.
  `Start` already bounds its read with `recvEventTimeout`; `Wait` should too.
  Severity: low.
- **P1 keeps a full capability set, `NoNewPrivs 0`, no seccomp filter, and the
  launcher's IPC and UTS namespaces, for the whole run.** MEASURED. It needs
  capabilities exactly twice, both before it forks; afterwards it does `wait4`
  and a blocking read. Nothing today can reach it — but this is the process
  Phase 2 gives a pathname socket and an accept loop, at which point "parses
  input from a second client" and "holds `CAP_SYS_ADMIN` over the sandbox's
  mounts with no `no_new_privs` and no filter" become one sentence. Severity:
  low now, **medium as Phase 2's entry condition**. Note that dropping P1's own
  capabilities does not narrow U — a joiner still gets a full set in U — so this
  is defence in depth on P1, not a change to the topology's authority.
- **The pinned netns descriptor is held for the whole run**, not just until
  pasta has opened `/proc/<P1>/fd/<n>`. Narrowing it needs a `netns-attached`
  control event, which is a protocol addition. Recorded so the descriptor does
  not read as unconditionally necessary, which it is not. Severity: low.
- **`CLONE_NEWCGROUP` is taken unconditionally with no Phase 1 consumer.** The
  bwrap side deliberately uses `--unshare-cgroup-try` so the path adds no new
  failure mode; P1's own clone then takes the same namespace strictly, and
  nothing in `internal/stage` uses it. Kept because the engine needs it in
  Phase 3, so dropping and re-adding is churn — but `snug doctor` probes bwrap's
  namespaces and **not** the stage's clone, its uid-map write or `SIOCSIFFLAGS`
  on `lo`, so a host where `doctor` is green and every `@net` run fails is
  constructible. The error message now names all four causes; the `doctor` probe
  is still owed. Severity: medium (invariant 5).
- **`Topology.Subuid` and `Topology.Attach` have no consumer but `--dry-run`.**
  The stage hardcodes the single-uid map independently and `stage.Config`
  carries only `Netns`, so `subuid none` on screen is true by coincidence rather
  than by construction: change `deriveTopology` and the screen starts making a
  claim no code keeps. Fix is to pass the whole `Topology` into `stage.Config`
  and have `Start` refuse what it does not implement, exactly as it already
  refuses a wrong `Netns`. Severity: medium (invariant 6, in `--dry-run`).
- **`Topology.Join` and the three per-field `Join`s have no non-test callers.**
  Composition actually happens through `NetMode.Join` followed by
  `deriveTopology`, so the lattice-law test proves a law about dead code. The
  property that matters — `deriveTopology` is order-preserving in `NetMode` — is
  asserted only empirically, and the fake registry has no `network = "host"`
  fixture, so the `NetEgress → NetHost` edge is never exercised. Severity: low.
- **The `--unshare-*` exhaustiveness guard hardcodes its list.** The integration
  test compares a literal set against `bwrap --help`, so deleting
  `--unshare-pid` from `internal/policy/bwrap.go` leaves it green; the deletion
  is caught only indirectly, by two goldens. The test already drives the built
  binary, so parsing `snug --dry-run -p @net`'s argv would join both halves.
  Severity: low.
- **`checkFDBudget` proves the pass-through block avoids fd 63, not that fd 63
  is free.** `dup3` onto an occupied descriptor closes it silently, and the Go
  runtime allocates its own descriptors from 63 upwards once the block is large
  enough. Not reachable today (a real `@net` policy uses 6 descriptors, and no
  TOML key produces a `KindData` mount), but the check covers half of what its
  comment claims. Severity: low.
- **`strings.Builder` data race on the pasta deadline path**
  (`internal/sandbox/netns.go`). `os/exec`'s copier goroutine is still writing
  it when the deadline branch reads it. Pre-existing, but this branch makes a
  stalled pasta a first-class tested case. Severity: low.
- **Two tests assert less than their names say.** The fd-budget unit test never
  reaches `checkFDBudget` (the topology guard rejects the zero-value config
  first), and `TestTheStageHoldsFourDescriptorsAtTheFork` is named "four",
  asserts `n > 10`, and measures exactly 10 — correct today with zero margin in
  either direction. Assert the set of link targets rather than a count.
  Severity: low.
- ~~**`TestPodmanBuildIsFilteredEndToEnd` is red on this host** for an engine
  reason.~~ **Wrong, and the wrongness is the finding.** It passes. Three
  separate sessions recorded it as a known pre-existing failure and none
  checked. What actually happened: `SNUG_REQUIRE_SANDBOX=1 make integration`
  failed on *every* host, because `requireInternet` correctly treats "be strict
  about the sandbox but leave `SNUG_TEST_NET` unset" as a configuration error
  rather than a silent skip — there is no strict-but-offline mode. So the one
  command that means "run the whole committed suite" was guaranteed to fail
  unless the caller separately knew to export a second variable, and the two
  tests it named got blamed. Fixed in the Makefile: `SNUG_REQUIRE_SANDBOX`
  now implies `SNUG_TEST_NET` unless the caller set it, while a bare `go test`
  outside `make` still refuses to pretend. **The lesson is the durable part:
  three sessions carried "known failure" without running it once.** A test
  believed broken is a test whose output nobody reads, which is the same defect
  as a test that cannot fail, arriving from the other direction.
- **Same-uid descriptor theft in the `ready`→`start` window.** With
  `yama/ptrace_scope = 1` a same-uid *ancestor* — a launcher-side wrapper
  qualifies — can steal P0's end of the socketpair and send the one `start`
  request the stage will serve, making it `execve` an arbitrary path as uid 0
  in U. Out of the threat model by the same rule as everything same-uid, and
  bounded by the one-shot design. Recorded because it is the only thing in
  Phase 1 with escalation shape, and the mitigation Phase 2 needs (an
  authenticated request, or a nonce established at clone time) is much cheaper
  to design before a pathname socket exists than after. Severity: low.
