# snug

> fitting closely and comfortably
> marked by cordiality and secure privacy
> offering safe concealment
> a small private room or compartment in a pub (British)

Bubblewrap-based sandbox for running untrusted code: builds, dependency install
hooks, test suites, and AI agents among them. Nothing in the model is
agent-specific — an agent is just one more thing you would rather not hand your
`~/.ssh` to.

**The full design is [.claude/design/INDEX.md](.claude/design/INDEX.md).** Read it before implementing
anything. This file is the working agreement: the invariants that must not be
broken, who does what, and the facts about this environment that were expensive
to learn.

## The guiding principle

> **Share nothing. Then punch explicit, named, minimal holes until the sandbox
> is useful.**

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. A profile is a *named hole*.

There is no "deny rule" in snug, because there is nothing to deny — the thing you
would deny was never there. `@parent-ro` does not hide your other projects; it simply
never grants them. This is why a missing capability (no X11, no Wayland, no
D-Bus, no host loopback, no `~/.ssh`) is a **feature to state plainly**, not a
gap to apologise for.

## Invariants

Break any of these and the project has lost its point.

1. **Monotonicity — stated precisely, because the loose version is false.**

   *Visibility is monotone, and structurally so.* No deny rules, no `mask`, no
   negation, no priority/override fields. Adding a profile can never make a path
   stop being visible: `rejectMasking` refuses anything mounted on top of what
   another grant exposes, and the grant language cannot express subtraction.

   *One exception, and it is snug's own writing, not a profile's.* Generated
   `KindData` mounts (`/etc/resolv.conf`, the identity files `~/.gitconfig`,
   `~/.ssh/config`, `known_hosts`) are assigned **directly into `p.Mounts`** at
   the end of `Resolve` — they skip `join`, and `rejectMasking` exempts
   `KindData` by kind. At an identical path that is a silent overwrite: verified
   by execution, a profile's bind disappeared from the policy entirely and the
   provenance read `identity:<profile>` alone. Intended direction — the pinned
   identity must not sit alongside the host's credential helpers — but note what
   it is: **a profile cannot displace another profile's grant, while snug can,
   and does, without saying so in `--dry-run`.** `rejectMasking`'s comment
   justifies the exemption by "no TOML key produces a `KindData` grant", which
   guards a profile reaching this path but does not cover the displacement. If a
   TOML key ever does produce `KindData`, both holes open at once.

   *And the exception is about the KIND, not about who chose the PATH — measured,
   issue #42.* Discovery reads the system ssh_config's location out of `ssh -G
   -v`, which is host text; but a human's own `Include <some repo>/ssh_config`
   line puts a path from the **sandboxed tree** into that chain, and every
   candidate becomes a `KindData` mount. So snug would have written its own
   read-only file over the repository's own file, inside the one tree the run
   exists to let the payload write — no escalation, the content is snug's, but
   `rejectMasking` would not have stopped it and `--dry-run` would have shown a
   `data` row where a human expected their file. `systemSSHConfigCandidates`
   refuses a candidate under `{target}` (and under `{home}`) for that reason.
   **Whenever something outside snug influences the GUEST PATH of a generated
   mount, the exemption stops being about snug's own files and starts being a
   write primitive with someone else's aim.**

   *Effective write access at a strict subpath is NOT monotone, by design.*
   `join` is keyed by `Mount.Guest`, so it applies at identical paths only.
   Grants at different depths become two mounts, and effective access at a path
   is that of the **deepest mount covering it**. Invariant 2 depends on this
   (`ro /proj` + `rw /proj/src` protects `.git`); the inversion uses the same
   mechanism, so a profile adding `ro {target}/.git` demotes `.git` inside an
   otherwise writable target. Verified by execution, not inferred. Acceptable —
   only tightening — but say it out loud, and **do not read
   `TestResolveIsMonotone` as proving more than it does**: it compares `Access`
   per existing `Guest` key, and a deeper key did not exist in the base policy.

   Resolution remains commutative and idempotent: if `resolve([a,b]) !=
   resolve([b,a])`, the model is broken — fix the model, not the test.

   *There is no restriction operation anywhere*, in a profile or on the command
   line. `--read-only` and the `policy.Clamp`/`Policy.Apply` machinery behind it
   are **gone**; to grant less, select fewer profiles (`snug --no-defaults -p
   @sys -p @home -p @parent-ro <dir>`), verbose on purpose. The point is not the
   flag but the *carve-out*: an invariant with no exceptions is checked by
   grepping for a demote and finding none (`TestPolicyHasNoRestrictionOperation`),
   one with an exception only by understanding where the exception applies. A
   patch reintroducing a demote under any name is reintroducing the exception.
2. **Deny by default.** Every visible path traces to exactly one explicit grant.
   **Corollary — wanting "X but not Y" means X was too coarse a grant.** The
   urge to exclude is a design smell pointing at the grant above it, not a
   missing feature. Two ways out, both additive:
   - *Enumerate.* Grant the parts of X you meant. This is why `@sys` lists
     fourteen `/etc` entries instead of binding all 109.
   - *Layer by access.* Grant the tree read-only and the parts you want to
     write separately. Access joins by max, so `ro /proj` + `rw /proj/src`
     leaves `.git` read-only without any rule mentioning `.git`.

   Masking by overmount — an empty tmpfs on top of something a bind exposes —
   is subtraction wearing a hat, and `Validate` rejects it. Hiding *feels* like
   the safe direction, but it breaks the property that makes profiles
   composable (adding one never makes anything worse), and it is not reliably
   safe anyway: mask `/etc/ssl` and TLS clients lose their trust store.
3. **The trusted profile set comes from outside the sandboxed material.**
   Repo-local config is never auto-loaded. A hostile repo shipping `.snug/` is
   an attacker granting themselves permissions — a complete defeat of the threat
   model.

   *M0 reality, verified:* `.snug/`, `snug.toml` and `.config/snug/` inside a
   target are all ignored. **But the gate is weaker than INDEX §2.7 describes.**
   `$XDG_CONFIG_HOME/snug/profiles.d` is trusted unconditionally, so pointing
   `XDG_CONFIG_HOME` into a checked-out repo does load that repo's profiles,
   privileged grants included. The designed defences — an explicit `--config`
   flag and refusing privileged grants from untrusted layers — are **not
   implemented**; `Profile.Trusted` is set and never read. Low severity (it is
   the host user's own env var, not something the sandboxed agent controls), but
   do not claim the §2.7 gate exists until it does.
4. **No root, no setuid, no daemon.** Helpers are children that die with the
   sandbox and leave nothing behind. **"No daemon" means no process the user did
   not start and no state that survives them — not "exactly one process".**
   `@net` runs a second one, the stage; its cost is under "Decisions made →
   Networking".
5. **No silent downgrade, ever.** If a requested capability is unavailable, snug
   says so and exits. A user believing a guarantee that no longer holds is worse
   than a failure. (Seccomp is the single exception, and it still warns.)
6. **One `Policy`, one author.** The same resolved policy generates the bwrap
   argv, the pasta argv, *and* the container proxy's decisions. Divergence
   between what the sandbox can see and what a container may mount is then
   impossible by construction rather than by review.

## Facts about this environment

Verified by execution, not from memory. Re-verify with `--help` before relying
on any flag.

**This section is deliberately short. The facts only one agent needs live in that
agent's file** — `.claude/agents/host-bridge.md` (pasta's unsafe defaults and the
full closing flag set, `unshare`/`setns` thread semantics, `clone3`'s errno, fd
versus path for exec), `.claude/agents/sandbox-policy.md` (masking versus
replacement, generate-don't-bind and the pointer/inline distinction, the writable
surface, git's two config files, `gh`'s rewrite, root-owned files reading as
65534), `.claude/agents/sandbox-tester.md` (positive controls, verifying a
security feature is active, gates that are documented but not implemented), and
`.claude/agents/go-implementer.md` (the two rules an implementer can break by
hand: the staging directory, and inline config variables). What stays here is
what changes how you work regardless of which layer you are in.

**If you are the main thread editing policy code directly, you do not have those
facts loaded** — that is the trade this split makes. Read the relevant agent file
first, or delegate to the agent that owns it.

- **Development SHOULD happen inside a rootless-podman distrobox** — a
  requirement, not an observation of where it happens to run. Nested userns,
  netns creation, pasta attach, egress and DNS all work there, so nothing about
  snug needs the bare host; and the two host-damage incidents of 2026-08-19 both
  came from a shell that was on the host. Verified there: `bwrap` 0.11.2,
  `pasta` (passt) 20260612, Go 1.26.6, no `slirp4netns`. **The Go version is
  `go.mod`'s, and `go.mod` is the authority** — a version in prose is a copy of
  state held somewhere else.
- **Never trust a helper's default, in either direction.** Pass every
  security-relevant flag explicitly even when it matches the current default, and
  assert the *behaviour* in an integration test. The live case is pasta, where
  two independent defaults each re-open host loopback and a golden-argv test
  would have passed on the buggy configuration (INDEX §4.2, and host-bridge for
  the closing set).
- **`--clearenv` is not the last word on the environment.** `@sys` binds `/etc`,
  so `/etc/profile.d/*` runs inside the sandbox and can put variables back. On
  this box `distrobox_profile.sh` sees the empty environment, *re-derives*
  `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` from the uid, and calls
  `host-spawn`, which then fails to reach a bus the sandbox correctly cannot
  see. The noise is isolation working, but the point stands: the environment
  inside is what snug sets *plus whatever the bound `/etc` adds*. The designed
  fix is a `sys-min` profile (curated `/etc`), not a hack.
- **`--clearenv` does not cover bwrap's own process, and that leaked everything.**
  `exec.Cmd` with a nil `Env` passes `os.Environ()`. bwrap then becomes PID 1 of
  the sandbox's PID namespace, running as the same uid, so the payload could read
  the entire host environment — `SSH_AUTH_SOCK`, cloud credentials, tokens — out
  of `/proc/1/environ`, while its own `env` looked perfectly clean. The redteam
  agent pulled 106 host variables out of a default sandbox. Fixed by
  `cmd.Env = []string{}` in `internal/sandbox/exec.go` (and the same line in
  `netns.go` and `internal/stage/stage.go`). **A guarantee about the payload's
  environment is not a guarantee about the sandbox's PID 1.** Whenever a helper
  process joins the sandbox's namespaces, ask what its own `/proc/<pid>/`
  exposes.
- **Seccomp's residual is ONE object, not the four the syscall list suggests.**
  The filter denies ptrace, bpf, keyctl, perf_event_open, userfaultfd, TIOCSTI,
  nested user namespaces, and — ptrace's effect without calling ptrace —
  `pidfd_getfd`, `process_vm_readv`, `process_vm_writev`. That last group does
  **not** isolate co-resident payloads from each other: `/proc/<pid>/fd/N`
  reaches a sibling's files and `/proc/<pid>/mem` reaches its MEMORY, read and
  write, and neither is syscall-shaped, so **no filter can name them** (issue
  #47). And procfs already reopens a sibling's pipe, memfd, deleted and
  `O_TMPFILE` files through `/proc/<pid>/fd/N` **with contents intact**
  (measured, issue #115) — so what denying `pidfd_getfd` actually buys is the
  **socket**, which procfs cannot reopen (`ENXIO`: sockfs has no open method).
  One object. This line named four for a milestone before anyone measured it.
- **An open directory descriptor ignores the mount namespace entirely.**
  `openat(2)` walks from the descriptor's own vfsmount, so a dirfd handed into
  the sandbox is a complete bypass of every grant. `sealInheritedFDs` marks
  inherited fds >2 CLOEXEC for exactly this reason — but 0/1/2 must pass through
  for stdio, which left the same hole on three well-known numbers. The redteam
  agent read `~/.aws` and wrote into an ungranted directory through
  `/proc/self/fd/0`. `safeStdio` now substitutes /dev/null for a directory on
  stdio. **When you exempt something from a security sweep, ask what the
  exemption itself lets through.**
- **A config file a tool INTERPRETS is not data — ask whether it is a command
  table, because read-only does not demote one into the other.** `~/.gitconfig`
  names programs git will run (`credential.helper`, `alias.x = !cmd`,
  `core.pager`, `core.sshCommand`, `filter.*.clean/smudge`, …), so a read-only
  bind stops the sandbox *editing* the file and **supplies every command in it**.
  `@git-ro` shipped binding it for a milestone under an abuse comment about
  "secrets you unwisely put in `~/.gitconfig`" — the wrong noun and the wrong
  owner. It now extracts a whitelist and generates the file
  (`.claude/design/GIT-CONFIG.md`). The hazard is the same for a granted
  DIRECTORY, because that is a grant of every command table anyone writes into
  it later: `@claude` names `{home}/.claude/plugins`, `claude` then cloned
  marketplaces into it, and six `.git/config` and `.npmrc` files arrived inside
  a granted tree with nobody naming them (issue #140). The bar is the line
  worth carrying: a nested command table may **exist** — the plugin ecosystem
  legitimately produces them — and may not **name a program or carry a
  credential**.

  **Nothing checks any of this any more.** Two mechanical sweeps did —
  `TestNoBuiltinGrantsACredentialOrCommandTablePath` and
  `TestNoNestedCommandTableUnderAGrantNamesAProgram`, both built on a hardcoded
  catalogue of interpreted paths — and both were deleted with that catalogue,
  because a list of known-bad paths is the subtractive shape invariant 2 calls a
  design smell and `internal/policy` is where it least belongs. The trade is
  explicit, and "checked by review" would overstate it — no process has been
  committed to: **the rule above now depends on whoever reads a profile diff
  remembering it, and a builtin granting `~/.ssh` would ship.** `@git-ro` bound
  `~/.gitconfig` for an entire milestone before the mechanical sweep — not a
  `redteam` round — caught it, so treat that as the measured base rate for
  noticing this by eye. Read it as raising the bar, not as retiring the rule.
- **A SOCKET is the third noun, and `ro` restrains it least of all.** The rule
  above is about files a tool *interprets*. A socket is not interpreted, it is
  *spoken to*: read-only stops the sandbox replacing it and does nothing about
  using it, and the private netns does not help because a unix socket is
  filesystem, not network. Measured (issue #219): from inside a sandbox holding
  a read-only bind of a home directory, a payload **enumerated the host's
  ssh-agent and signed with it** — `--clearenv` had correctly stripped
  `SSH_AUTH_SOCK` and the payload simply re-derived the path. That is
  `@ssh-agent`'s filtering proxy — one pinned key, no enumeration, the whole
  reason that profile exists — defeated by a mount. The general form is #140's
  again with a different object: **a grant of a directory is a grant of every
  socket anyone puts in it later**, and `~/.ssh/agent`, `~/.docker/desktop`,
  podman's machine socket and gpg-agent's `S.gpg-agent` are all real spellings.
  **Nothing checks this**, the same way nothing checks the command-table rule
  since #207 — no builtin does it today, and the next `ro {home}`-shaped profile
  would not be noticed. The one structural defence that does exist is narrow and
  worth knowing: `Validate` refuses any bind covering `$HOME` (#220), so the
  measured route specifically is closed.
- **The abuse sentence is written once and nothing re-reads it as the code grows
  around it.** That is why `redteam` carries a standing inventory sweep —
  *working exactly as designed, what did we hand over?* — a question no
  escape-shaped check asks.
- **A rule written once and applied to one of its two halves is the shape to
  watch for.** `checkEnvName` refused a NUL in an environment NAME from the
  beginning, with reasoning that applied word for word to the VALUE — and a
  `\u0000` escape in a value re-synced bwrap's `--args` parser, authoring a mount
  no `Mount` existed for, invisible to `Validate`, `rejectMasking` and
  `--dry-run`. A raw NUL never got that far — go-toml refuses control characters
  in a basic string — so **the parser is not the defence**: `checkEnvValue` now
  refuses *every* control character in a profile-supplied value, `Validate`
  refuses one in a guest path, and `nulJoin` refuses an element containing the
  separator it owns, the last being the backstop for whatever writes a flag next.
  Keep the two hazards distinct: NUL authors a **mount**; newline and ESC author
  a **lie** in the artifact a human reads. **When you add a guard for a value,
  name every sink that value can reach and assert the set rather than the site**
  (`TestNoSnugScreenEmitsARawControlCharacter`).
- **Verify a security feature is active, not merely requested.** bwrap stops
  parsing flags at `--`, so `--seccomp` was once passed, accepted, and never
  installed, with a zero exit code and no warning; `BwrapFlags` and `BwrapArgs`
  are separate for this reason, **and a test asserts the first contains no `--`**
  (`internal/policy/bwrap_test.go`) — separation without that assertion is the
  "documented but not implemented" shape this list warns about elsewhere. The same shape bit the args memfd twice:
  **nothing may be appended to the flag slice after the `memfd("snug-args", …)`
  snapshot**, or bwrap never sees it and the only symptom is a missing feature.
  A comment marks the point.
- **A test that cannot fail is worse than no test.** Every negative test needs a
  positive control, and every payload needs a marker — otherwise "the sandbox did
  not reach X" passes on a sandbox that never started. Likewise, when a comment
  says "requires X", grep for X before believing it — and check the grep itself
  can fail: `grep -rn 'a|b'` **without `-E`** matches a literal pipe, so it finds
  nothing and looks like proof of absence. That is how one "verified by a
  fixed-string sweep" claim in this file was itself verified wrongly. Both worked
  examples are in `.claude/agents/sandbox-tester.md`.
- **The writable surface is eight paths, not one.** Say "the only writable thing
  that *persists*", never "the only writable thing". The target bind persists;
  `/tmp`, `$HOME`, `$HOME/.cache`, `$HOME/.config`, `$HOME/.local/state`,
  `$HOME/.local/share` and `/dev` are tmpfs that die with the sandbox. `/dev` is
  bwrap's own synthetic device tree and is the one people forget. The source is
  `internal/profile/profiles/base.toml`, `[profile.home]` — check there before
  quoting the count, because it has drifted once already: **a count in prose is a
  copy of state held somewhere else.**
- **The sandbox sets `PS1`, and an agent cannot read it.** snug does not grant
  `/etc/bash.bashrc`, so without it the shell shows bash's built-in `bash-5.3$`
  and nothing on screen says you are sandboxed. Keep it distinctive **for
  humans** — but bash unsets `PS1` when it is not interactive, so inside `sh -c`
  the payload's own `/proc/self/environ` has no `PS1`, and `/proc/1/environ`
  cannot supply it either because it is deliberately zero bytes. `SNUG`,
  `SNUG_PROFILES` and `SNUG_TARGET` do survive. Measured, issue #185.

  **And "am I inside?" is the wrong question anyway.** A guard answering it
  returned `exit=0` inside a real sandbox one command before the host's private
  key was destroyed **through that sandbox's own `rw` grant**. Inside is not the
  safety property; the mount policy is. `bin/blast-radius` asks what is
  *reachable from here* instead, and reads nothing snug produces — this being the
  repository where snug is built and attacked, a check trusting snug's own
  signals is only as truthful as the branch you are standing on.
- `/proc/sys/dev/tty/legacy_tiocsti` is `0` on this kernel, so `--new-session`
  is unnecessary here and snug omits it, which is why job control works inside
  an interactive sandbox shell. On a host where it is `1`, snug adds the flag
  and `--dry-run` says so. Never make this decision silently.

## Development agents

`.claude/agents/` — use them; they carry the context that keeps the invariants
intact. `.claude/design/` holds the design and research material they work from
(INDEX.md, the pseudo-filesystem audit, the secrets analysis, parked designs).
There is deliberately **no `docs/` tree**: a generated user guide was tried and
removed, because the prose churned faster than the code it described and nobody
was going to keep it honest. `VERIFY.md` at the root is the exception, and it
earns it by being executable — every line is a command with its expected output.

**Every new document starts in `.claude/scratchpad/`, which is in `.gitignore`**
— not "start it in design/ and remember not to commit it", but somewhere a
routine `git add -A` cannot reach, because that is exactly how an untracked plan
got committed twice in one session. **An instruction a routine command can
quietly undo is not a rule; the `.gitignore` entry is what makes it one.**

Plans, review write-ups, red-team round reports and working notes live there and
stay there. A document is *promoted* into `.claude/design/` by a deliberate `git
mv`, only once it is either **the** design for a subject (one per subject, no
`-PLAN` or `-REVIEW` twin beside it) or a research record whose measurements stay
useful after the work lands (`NOCGO.md`, `PODMAN-STATIC.md`, `ENGINE-NETNS.md`).
Findings never wait on promotion: a confirmed finding becomes a GitHub issue with
its severity label, which is the milestone rule anyway.

| agent | owns |
|---|---|
| `sandbox-policy` | The policy model and the bwrap argv. Invoke *before* writing policy code. Guards monotonicity. Advisory: like `redteam` it has **no edit tools**, so the decision is written down and reviewed before `go-implementer` turns it into code. **It defaults to opus and is the priciest agent here — pass `model: "sonnet"` for lookups** ("which mount covers this path", "what does this profile grant", "why is X visible"), and keep opus for judgement: changing a grant, changing how resolution works, deciding whether something breaks an invariant. |
| `host-bridge` | Every deliberate hole: netns/pasta, ssh-agent proxy, podman socket proxy, shared tmp. Decides the shape of a hole and says no when it is wider than the need. |
| `redteam` | Our own adversary: tries to escape the sandbox we build, with the maintainer's authority, so we find the holes first. Deliberately has no edit tools, so discovery stays separate from the code being graded. |
| `sandbox-tester` | The committed suite: resolver invariants, golden argv, integration tests that assert negatives. |
| `go-implementer` | Ordinary Go work. Explicitly forbidden from inventing policy — hands security decisions back. |

`redteam` and `sandbox-tester` are a pipeline, not two testers: **every escape
the red team confirms becomes a permanent named regression test.** A hole should
only ever be closable once.

## Definition of done for a milestone

All five, in order. A milestone is not finished until the last one is.

1. `make gate` green — gofmt, vet, and the full test suite.
2. `make integration` green (`SNUG_REQUIRE_SANDBOX=1`), with a new named test for
   whatever the milestone added. `VERIFY.md` gets the human-readable
   equivalent — it is the by-hand checklist and is not made redundant by the
   automated one.
3. **`redteam` has attacked it.** Not optional, not "if there's time". Every
   milestone that adds a hole gets a run before it lands, and so does any change
   to the policy model, mount generation, the seccomp filter, or a
   host-integration surface.
4. Every confirmed finding is either fixed, or **filed as a GitHub issue** with
   its severity label (`sev:high`/`sev:medium`/`sev:low`) and the measurement
   that confirmed it — never silently carried. The issue body carries the
   reproduction, because the reproduction is the valuable half. There is no
   `TODO.md`: it grew into 1800 lines mixing open work with shipped work written
   in the future tense, and the rule that grew it is this one.
5. Every confirmed finding becomes a permanent named regression test owned by
   `sandbox-tester`. A hole should only ever be closable once.

**Why this is a rule and not a suggestion.** Across two runs the red team found
five real issues, and *every one* was in code that had been written and tested,
with the tests passing:

| found | why the tests missed it |
|---|---|
| `/proc/1/environ` leaked 106 host variables | payload env was clean; nobody looked at PID 1 |
| nested *bind* masking | the rule and its test were written together, against one spelling |
| `--seccomp` after bwrap's `--` installed nothing | flag was present in the argv; exit code 0 |
| directory on stdio bypassed every mount grant | the fd sweep exempted 0/1/2 by design |
| `clone3` created a nested userns | classic BPF cannot read the flag it checks |

The pattern is consistent: **self-written tests confirm the mechanism you had in
mind, not the one an attacker uses.** `make gate` proves the code does what you
meant. It cannot prove the sandbox holds.

## Working agreement

- **Write the abuse sentence first.** Before implementing any grant: "a hostile
  process inside the sandbox can use this to ___". It goes in the profile TOML as
  a comment. If you cannot write it, the grant is not ready.
- **When you write down a limitation, ask what it GRANTS as well as what it
  costs.** A true ergonomics footnote sat in `base.toml` for a milestone —
  "containers run in the ENGINE's network namespace, not the sandbox's…
  `podman run -p 8080:80` will NOT work". From the user's side, an annoyance;
  from an attacker's, the same sentence says *a container has the engine's
  network, so a sandbox with no `@net` reaches the internet through one*
  (`.claude/design/ENGINE-NETNS.md` §0). **A limitation and a hole are frequently
  the same fact facing two directions.**

  **Tier B closed that particular hole** — a container now runs in the sandbox's
  own netns — and `-p` is still unsupported, for an unrelated reason: the engine
  holds no `CAP_NET_ADMIN`. Note what that means for the habit rather than for
  the fact: **the annoyance survived its own explanation.** When the hole closes,
  re-derive the limitation instead of assuming it went with it.
- **Golden argv diffs are the review artifact.** A change to a golden file is a
  change to the security boundary and is read as such. A security change that
  produces no golden diff is probably untested.
- **Test the negative.** A test proving the sandbox is *useful* proves nothing
  about whether it is *safe*. Sibling not visible; symlink does not resolve out;
  host loopback refused; abstract sockets unreachable; no orphans after SIGKILL.
- **Keep `internal/policy` pure.** No globals, no filesystem, no `exec` — host
  lookups go through an injected `Environ`. This is what lets the
  security-critical tests run in CI with no privileges.
- **Errors name the fix.** "failed to create user namespace (see
  /proc/sys/kernel/unprivileged_userns_clone)" beats "operation not permitted".
  snug runs in odd environments and a bad message there costs an hour.
- `snug --dry-run` is not a debugging convenience — it is *the* mechanism by
  which a human can trust snug at all. Keep it honest and keep it complete.
  (There is no `snug explain`; this line named it for several milestones after
  the rename. Prose quoting a command name is a copy of state held in `main.go`.)

## Decisions made

- **One vocabulary: `profile`.** Grants live in profiles and nowhere else. The
  CLI says the same word the config says: `-p/--profile`, `snug profile list`,
  `snug profile show NAME`. No second noun for the same concept.
- **`@` marks a profile snug ships, and the mark is derived, not written.**
  `@sys`, `@net`, `@claude`; a profile in `~/.config/snug/profiles.d` has no
  mark, and `checkName` refuses one. The point is provenance: `--dry-run`, a
  `Validate` error and `$SNUG_PROFILES` all render a profile name, and a bare
  name could not tell you whether the grant was snug's or something a file on
  this host defined — you had to go and look.

  Two properties, structural rather than checked. `profile.mark` (reached from
  `profile.Builtins()`) adds the sigil and is the ONLY code that does, while
  `checkName` refuses a leading `@` in
  **every** file it parses — `base.toml` included, which is why the builtins are
  written there under bare names. So a builtin cannot forget the mark and a user
  profile cannot borrow it. And the namespaces cannot collide: a user file
  defining `sys` defines their own profile, so "a config file could quietly
  change what `sys` means" **stops being a thing `merge` has to prevent** — do
  not remove `checkName`'s guard on the belief that `merge` covers it. That
  matters most where invariant 3 is weakest — `$XDG_CONFIG_HOME` is trusted unconditionally, and a profiles.d
  loaded from the wrong place still cannot impersonate `@sys`.

  Consequence: `include` inside a builtin is rewritten with the marks, so a
  builtin can only ever include another builtin — correct, but a rule rather than
  an accident (`profile.mark`). snug's own mounts (`/proc`, `/dev`, generated
  `/etc/resolv.conf`) carry `(snug)`, not `(builtin)`: with `@`-marked builtin
  profiles on screen, one word meant two things.
- **`--dry-run`, not `explain`.** It is the conventional name and the tool
  should not invent vocabulary. What it prints is unchanged: the resolved
  policy and the exact bwrap command, having started nothing.
- **`snug config` holds preferences, never grants.** Today that is `defaults` —
  which profiles a bare `snug <dir>` selects. It names profiles and cannot
  define one, because a config file able to redefine a builtin could quietly
  change what `@sys` means.
- **There is no `default` profile; there is a `defaults` setting.** A default
  selection is a *preference*, a profile is a *grant*; having both was two
  mechanisms for one idea, and the empty `[profile.default]` appeared in
  `SNUG_PROFILES` and in `Mount.From` provenance as though it were a hole. Now:
  built-in list in `internal/profile/defaults.go`; `defaults = [...]` in
  config.toml **replaces** it wholesale (merging would make "fewer defaults than
  snug ships" impossible); `-p` **adds** to what that resolved to;
  `--no-defaults` declines it. The list is `@sys @home @cwd-rw @parent-ro`, and
  **`@net` must never join it** — offline is the *absence* of a profile, which is
  what stops it being switched on by accident. Same reasoning kills `@null`: the
  floor of the lattice is what `Resolve` computes from an empty selection, not
  something a file names. `-p @null` errors and names `--no-defaults`.
- **The directory is positional, not `-C`.** `go -C` and `make -C` mean "go
  somewhere else, then do the usual thing"; for snug the directory *is* the
  thing being sandboxed, like `git clone <url>`. Defaults to `.`.
- **No cgo.** snug builds with `CGO_ENABLED=0` and nothing in it may change
  that. The full statement, with the measurements, is
  [`.claude/design/NOCGO.md`](.claude/design/NOCGO.md), and the temptation is
  concrete: a cgo `__attribute__((constructor))` runs before the Go runtime
  starts its threads, which is the one clean way to satisfy
  `setns(CLONE_NEWUSER)`'s single-threaded requirement, in less code. The price
  is paid elsewhere — a cgo binary is bound to the libc it linked against, so key
  feature 3 becomes a glibc build *and* a musl build, cross-compiling needs a
  toolchain per target, and snug re-execs itself through `/proc/self/exe` for the
  stage, so the binary is a runtime dependency of itself.

  Affordable because the requirement turned out avoidable: a raw `fork` from a
  multithreaded Go program yields a child that is single-threaded *and* owns its
  own `fs_struct` — exactly the two states the kernel checks.

  **What that child costs is not editorial care, it is `//go:nosplit`.** The fork
  child also carries the forking goroutine's `stackguard0`, which the runtime
  poisons whenever it wants that goroutine preempted, so an ordinary function's
  PROLOGUE calls `runtime.newstack` before its first statement and asks the
  scheduler for threads the fork did not copy. Measured: 17 of 40 forks wedged in
  `futex_do_wait` forever under stop-the-world pressure, 0 of 40 with a nosplit
  first call, and in the wild two `snug attach` bridges alive hours after their
  caller died (issue #221, NOCGO.md §3). "Nothing here may ask the Go runtime for
  anything" is therefore a property of the PRAGMAS, not of the body — the first
  ordinary call is already a runtime call whatever it says. `internal/attach` is
  the only raw-fork site; `internal/stage` re-execs and starts a fresh runtime.
- **Config format is TOML.** Strict decoding with `DisallowUnknownFields()` is
  load-bearing: an unknown key is a fatal parse error, so a negation key cannot
  be smuggled in.
- **ssh identities**: `ssh_mode = "agent-proxy"` — a filtering proxy to the
  already-unlocked host agent exposing exactly one pinned key. No key material
  inside, no passphrase prompt, other keys not enumerable. The `[identity]`
  vocabulary carries over from the previous generation unchanged. What it
  *cannot* do:
  restrict what gets signed. That is inherent to every agent forwarder.
- **`~/.config`**: no blanket bind — it is a credential dump and a persistence
  vector in one. Only `~/.config/git` by default; anything else is a line the
  human writes in their own profile.
- **Claude Code's files**: binary, `settings.json`, skills and plugins read-only;
  `.credentials.json` staged as a **projection** — `policy.ProjectClaudeCredentials`
  writes a five-key allowlist, not a copy of the host's file (issue #58). Say
  projection, not "writable copy": the difference is that a key the host adds
  later does not arrive inside by default. `~/.claude.json` is **generated,
  not copied** — three keys, zero host bytes (issue #19). The host's is 62 KB and
  carries every project path on the machine, org and account UUIDs, `machineID`,
  `mcpServers` and per-project tool approvals; copying it verbatim was justified
  as "both files are needed", measured false. Generation rather than removal —
  and **note that issue #19's own measurement is partly wrong**: without the file
  there is no login prompt, but there IS onboarding, and it blocks on every run
  since `$HOME` is a fresh tmpfs. Read that issue with this caveat.

  **No staged credential is written back to the host — that channel does not
  exist**, and the cost is that a token refreshed inside is lost when the sandbox
  exits. Keep that sentence credential-scoped: the sandbox writes to the host
  through the target bind by design, and through `@tmp-shared` when selected, so
  "nothing leaves the sandbox" is false. It previously read "only the credentials
  file syncs back, and only after structural validation" — describing a design
  never built, found by a red team sweeping what `@claude` hands over rather than
  by review. A doc that invents a host-write channel invites someone to reason
  about a boundary that does not exist. If sync-back is ever built, the
  structural validation is the load-bearing half: `~/.claude.json` carries MCP
  config, a natural target for injecting a tool that would run *outside* the
  sandbox on the next host-side session.
- **Injected `~/.claude/CLAUDE.md`**: generated per-run from the *actual*
  resolved policy, so a run whose engine failed to start truthfully reads "no
  engine". Every sentence in it removes a class of wasted agent turns.
- **Networking**: private netns per sandbox, egress via pasta, host loopback
  closed. Offline is the *absence* of the `@net` profile, not a setting — so it
  cannot be accidentally re-enabled.

  **`@net` runs a second long-lived process, the stage, and that is the cost.**
  It creates the netns, pins it, *leaves* it, and forks bwrap back in through a
  `setns` shim, which is what lets the container engine share that namespace.
  The price is on screen in `--dry-run`: the sandbox's user namespace has a
  **privileged ancestor for the whole run**, so a userns-escape bug is worth
  more than it was. Measured to give the payload no new reach and to widen no
  host surface — a same-uid host process already reaches that authority without
  a stage, via `NS_GET_USERNS` on the sandbox's own namespace descriptors.
  Offline and `@net-host` (the `--i-know` path) take the single-process path.

  *Containers included, now that Tier B has landed (issue #63).* A container
  runs in the sandbox's own network namespace, so `@podman-socket` without
  `@net` is genuinely offline and `--dry-run` says so truthfully. Selecting a
  container engine starts a stage and delegates the full subuid range even
  offline — a real cost the TOPOLOGY block states — and a container's egress
  follows the sandbox's exactly: with `@net` the whole internet, without it
  nothing; it publishes no port onto any loopback the sandbox does not already
  own, because the engine holds no `CAP_NET_ADMIN`. The engine is forked into
  that netns by the stage (`internal/stage`'s `start` request and `__inengine`),
  its own capabilities dropped to `policy.EngineCapBounding`. There is no
  `startengine` request: it was folded into `start` so that `start` stays
  terminal and the stage is never handed a pid it must trust (issue #125).
  `TestPodmanSocketDoesNotImplyEgress` and `TestPodmanSelectsAStage` are what
  keep this true; the mount view is still a private copy enforced by the proxy
  bind filter, which Tier C (#125) makes structural.

  **The pid row has moved and the sentence "pid is the host's" is now false
  wherever it appears**: Tier C's C0 piece gave the engine `CLONE_NEWPID` and a
  procfs bound to it (`internal/stage/enginefork.go`). Two consequences follow
  and both are tracked rather than folded in — the pids libpod records in the
  runroot are numbered in the **engine's** namespace, so no host-side caller may
  read them as host pids (issue #167, fixed by deleting the caller); and a
  container now gets the kernel's `SIGKILL` at pid-namespace collapse, **never a
  graceful `SIGTERM`** (issue #174, open). If graceful stop ever returns, it
  comes through the engine's **own socket**, where recorded pids are numbered in
  the namespace doing the killing — never a host-side CLI again. Host→sandbox port publishing is off by
  default and scoped to `127.0.0.1` when enabled: with `-t auto` the *agent*
  would choose which host loopback ports appear, which inverts the guiding
  principle. See INDEX §4.6 — this is the decision most likely to be revisited.
- **GUI, audio and D-Bus passthrough are out of scope deliberately** (Wayland,
  PulseAudio, X11, and the bus itself). No profile ships. A filtering proxy that
  is 95% correct is a sandbox that is 0% sound. The private netns excludes them
  by construction — **a property to keep, not a gap to close** — so do not add a
  profile for any of them without a decision to reopen this.

- **`/snug` is snug's own guest namespace, and it is a RULE rather than a list.**
  Everything snug needs a path for *inside* a sandbox lives there — `/snug/bin`
  (the staging directory), `/snug/podman.sock`, `/snug/ssh-agent.sock`, and
  `/snug/engine` when Tier C lands. A profile may do exactly one thing under it:
  stage a single executable read-only into `/snug/bin`. Anything else — a tmpfs,
  a writable bind, a mount at one of the directories snug creates — is refused.

  *Why a namespace and not more entries in `snugsOwn`.* That map held three
  paths, and the third was there for a reason the other two do not share:
  nothing is mounted at the staging directory, so a profile mounting **anything**
  there is a separate mount `--remount-ro /` does not reach inside, and the
  directory snug relied on being unwritable becomes writable — measured, issue
  #22: WROTE-OK, `command -v git` resolved to it, and the shadowed git RAN. That
  reason applies unchanged to every path snug will ever own, and Tier C alone
  would have added four. **A list that grows once per feature is a rule written
  somewhere it can be forgotten.** `snugsOwn` asks *does this grant swallow a
  node snug placed* (an ancestor test); the namespace rule asks *is this grant
  inside snug's namespace at all*, which is what catches a path snug has not
  placed anything at yet. They overlap at `/snug` and `/snug/bin`, where
  `snugsOwn` is checked first and wins.

  *The namespace rule has TWO halves and shipped with one.* `Validate`'s rule 4b
  covers the payload's mounts; **grafts** go through G1, which consults
  `snugsOwn` — the list — so the namespace was total on one side and partial on
  the other, in the change that quotes "a rule written once and applied to one of
  its two halves". Measured by an independent review: a writable graft at
  `/snug/podman.sock` was **accepted**, putting an arbitrary host tree where the
  engine expects the container proxy's socket. G1b now states the graft half as a
  rule too — a graft may land inside `/snug` **only** under `/snug/engine/`,
  which is the one subtree Tier C needs — so it does not grow either.

  *Why `/snug` and not `/opt/snug`.* `/opt` is a real FHS location a profile
  could legitimately want, and **reserving a subtree of a path other people have
  a claim to is a weaker reservation than reserving a name nobody claims**.
  `/snug` is not in the FHS, so the reservation is total and needs no exceptions.

  *Consequences to know.* A default sandbox no longer creates `/run` at all —
  it existed only because snug's paths lived under it. And the old location is
  kept **refused** rather than freed: a profile still naming it gets an error
  that names the replacement, because a rename whose old name merely stops
  working is a trap — the staging grant would keep validating and quietly stage
  into a directory that is no longer on PATH.
- **One live sandbox per target directory.** `snug <dir>` refuses to start a
  second sandbox while one is already live for the same target, and the refusal
  names the fix: `snug attach <dir>`. The guard is a per-target advisory `flock`
  named `target-<sha256(realpath)>.lock` in snug's per-uid runtime directory,
  resolved from the uid alone — canonical `/run/user/<uid>`, else
  `/tmp/snug-<uid>` — **never** from `$XDG_RUNTIME_DIR`/`$TMPDIR`, because two runs
  that disagreed on those env vars once flock'd two different inodes and both
  acquired, letting a second sandbox onto the target the lock exists to forbid
  (issue #122). It is taken in the run path before anything is created (no stage,
  no netns, no bwrap, no proxy), released by the kernel on exit — SIGKILL
  included, so a dead holder never wedges a directory — and deliberately never
  unlinked, which is what keeps the reclaim free of a sweep-vs-acquire race. It
  reuses `runtimeDir`'s `*os.Root`+`flock` machinery and fails **closed**: if the
  per-uid directory cannot be established the run refuses rather than falling back
  to a per-env path. "Same directory" is realpath, so a symlink to the target is
  the same target. The lock path is derived from the target the host user named,
  on a host path never bound into the sandbox: a hostile payload can neither reach
  the file nor steer its name, so it can neither release the lock to smuggle in a
  racing second sandbox nor point snug at the wrong path. This makes `snug
  attach`'s address-by-directory total — at most one live run per directory, so
  its multi-match branch is a defensive guard, not a user-facing dead end. A
  second sandbox on one directory is not a relaxation of this refusal but a
  different feature with a different name; it is a run-path guard, not a grant,
  and lives in `internal/cli`, never in the pure `internal/policy`.

