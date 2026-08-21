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

   *And one where visibility and PROTECTION point in opposite directions —
   measured, issue #29.* snug's procfs closures (`/proc/config.gz`, `/proc/keys`,
   `/proc/key-users` replaced with empty files, `/proc/sys` bound read-only) are
   **not applied on a run that starts a container engine**: the kernel refuses
   the engine a fresh procfs for its own pid namespace while any mount covers
   part of one it can see, and both ways of having both are closed (`MNT_LOCKED`;
   a mask the engine tolerates is one the payload never sees). So selecting a
   container profile makes that run **less protected while making those paths
   more visible** — invariant 1's letter holds and what a human means by "adding
   a profile never makes anything worse" does not. The exemption follows the
   SELECTION, not the host, and applies transitively through `include`;
   `--dry-run` states it on the `/proc` row for exactly the runs it applies to.
   `TestResolveIsMonotone` carries the exception explicitly — the removed mount
   must be one of the four closures **and** the added profile must be what turned
   the engine on.

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
   flag but the *carve-out*: an invariant with no exceptions could be checked by
   grepping for a demote and finding none, one with an exception only by
   understanding where the exception applies. A patch reintroducing a demote
   under any name is reintroducing the exception — **and no check catches one**
   (#271). `TestPolicyHasNoRestrictionOperation` only asserts that `Access.Join`
   takes the max; a `Derive()` returning a copy with every `AccessRW` rewritten
   to `AccessRO` ships green. This half of invariant 1 is enforced by review, and
   a list of demote spellings is not the fix — that is the catalogue shape
   invariant 2 rejects.
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
- **`--clearenv` is not the last word on the environment — a bound `/etc` can
  put variables back.** `/etc/profile.d/*` and `/etc/bash.bashrc` are EXECUTED by
  every shell, so a profile granting them hands the sandbox arbitrary startup
  code, not data. Observed before the fix: `distrobox_profile.sh` saw the empty
  environment, *re-derived* `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` from
  the uid, and called `host-spawn`.

  **`@sys` is already the curated answer** — it lists fourteen `/etc` entries
  (linker, TLS trust, `nsswitch`/`passwd`/`group`, locale, `os-release`) and
  grants **neither** `/etc/profile.d` nor `/etc/bash.bashrc`; nothing in
  `base.toml` binds `/etc` wholesale. There is no `sys-min` to build: this entry
  described a `sys-min` as the "designed fix" for a milestone after `@sys` became
  it. Check `internal/profile/profiles/base.toml` — **a profile's contents in
  prose is a copy of state held there**, and this line and invariant 2 disagreed
  about the same profile in the same file.

  The rule survives its own example, which is why the entry stays: **the
  environment inside is what snug sets plus whatever a bound `/etc` adds**, so a
  human profile granting `/etc` re-opens it in one line.
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
  socket — and every FIFO — anyone puts in it later**, and `~/.ssh/agent`,
  `~/.docker/desktop`, podman's machine socket and gpg-agent's `S.gpg-agent` are
  all real spellings. A FIFO is the same noun (measured, #287): it is *written
  through*, not interpreted, so `ro` restrains it no better, and under default
  `@parent-ro` a host-held pipe in a granted directory is a bidirectional
  channel.
- **Half of the socket rule is checked now**, and knowing WHICH half is the
  point. `Validate` refuses a bind whose SOURCE IS a socket **or a FIFO**
  (`rejectEndpointSource`, #219/#295), detected by `S_IFSOCK`/`S_IFIFO` through
  the injected `Environ` — not by a path list, which is why it
  is not the catalogue #207 deleted: a `stat` does not care how a path was
  spelled. snug's own proxy sockets are exempt by `Mount.Authored`, which is the
  distinction the rule turns on rather than a carve-out. What is NOT checked is
  the DIRECTORY case, which is the general form: a `stat` at resolve time sees
  only endpoints that exist then, so `ro {home}/.ssh` is accepted today and is a
  hole the moment an agent starts there. That half still depends on whoever reads
  a profile diff remembering it, and it is now tracked — the socket directory
  residual as #292, the FIFO directory residual as #296. **Two routes, one check each**: #220 refuses any
  bind covering `$HOME`, which is what closes the MEASURED route (a directory
  bind, so #219 never fires on it); #219 closes the direct spelling. Neither is
  redundant.
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
- **Pull requests: caveman prose, and never a session link.** A PR body is
  technical prose that prefers brevity and accuracy over narration — drop
  articles and filler, keep every measurement, path, flag and exact error
  string. **Never put a `claude.ai/code/session` URL in a PR body, a commit
  message, an issue or a comment.** It is a link nobody outside this machine can
  open, it dates the artifact, and it points at a transcript rather than at the
  code. Cite the issue, the file and the measurement instead.
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

Settled, with the reasoning in the document that owns each subject. **Re-opening
one of these is a maintainer decision, not a refactor** — that is the whole point
of the list. Where a line states a *rule* rather than a preference, breaking it
by hand is possible and the consequence is a security regression, so those are
stated in full.

**Vocabulary and CLI.** One noun: `profile`. Grants live in profiles and nowhere
else, and the CLI says the word the config says (`-p/--profile`, `snug profile
list|show|tree`). `--dry-run`, never `explain` — the tool does not invent
vocabulary. The directory is **positional**, not `-C`: it is the thing being
sandboxed, like `git clone <url>`. Config is TOML, and `DisallowUnknownFields()`
is **load-bearing** — an unknown key is a fatal parse error, so a negation key
cannot be smuggled in.

**`@` marks a profile snug ships, and the mark is derived, not written.**
`profile.mark` (via `profile.Builtins()`) is the ONLY code that adds the sigil,
and `checkName` refuses a leading `@` in **every** file it parses — `base.toml`
included, which is why builtins are written there under bare names. So a builtin
cannot forget the mark and a user profile cannot borrow it. **Do not remove
`checkName`'s guard on the belief that `merge` covers it:** the namespaces cannot
collide precisely because a user file defining `sys` defines *their own* profile,
which is what stops a `profiles.d` loaded from the wrong place impersonating
`@sys` — and invariant 3 is weakest exactly there. Consequence: `include` inside
a builtin is rewritten with the marks, so a builtin can only ever include another
builtin. snug's own mounts carry `(snug)`, not `(builtin)`.

**Reading and building a profile never needs network access.** Maintainer's
ruling, 2026-08-21. Parsing a profile, resolving a selection, validating it and
rendering `--dry-run` are offline, and no convenience may make them reach a
service — not to check that `identity.ssh_key` and `identity.gh_user` name the
same account, not to check a token's scopes. Egress is a profile the user
selects; a tool that phones a service while deciding what a sandbox may see has
inverted that, and it is what keeps `internal/policy` pure and testable in CI
with no privileges. Ergonomics that need the network go to a separate binary
with its own `go.mod` (issue #30, `snug setup`), whose output is a profile file
snug reads like any other. **snug's own `go.mod` stays minimal**: every
dependency there runs with the authority of the thing building the sandbox.

**`snug config` holds preferences, never grants**, and **there is no `default`
profile — there is a `defaults` setting.** The list is `@sys @home @cwd-rw
@parent-ro`; `defaults = [...]` **replaces** it wholesale (merging would make
"fewer defaults than snug ships" impossible), `-p` adds, `--no-defaults`
declines. **`@net` must never join it** — offline is the *absence* of a profile,
which is what stops it being switched on by accident. Same reasoning kills
`@null`: the floor of the lattice is what `Resolve` computes from an empty
selection, not something a file names.

**No cgo.** `CGO_ENABLED=0`, and nothing may change that —
[`NOCGO.md`](.claude/design/NOCGO.md) carries the measurements and why
`setns(CLONE_NEWUSER)`'s single-threaded requirement turned out avoidable. **The
rule an implementer can break by hand is `//go:nosplit`**, not editorial care: a
raw-fork child carries the forking goroutine's poisoned `stackguard0`, so an
ordinary function's *prologue* calls `runtime.newstack` and asks for threads the
fork did not copy — 17 of 40 forks wedged forever, 0 of 40 with a nosplit first
call (issue #221). "Nothing here may ask the runtime for anything" is a property
of the **pragmas**, not the body. `internal/attach` is the only raw-fork site;
`internal/stage` re-execs and starts a fresh runtime.

**`/snug` is snug's own guest namespace, and it is a RULE rather than a list.**
Everything snug needs a path for inside a sandbox lives there. A profile may do
exactly one thing under it: stage a single executable read-only into
`/snug/bin`. Anything else is refused. **The rule has two halves and shipped with
one** — `Validate`'s 4b covers the payload's mounts, while grafts go through G1;
a writable graft at `/snug/podman.sock` was accepted until G1b stated the graft
half too (a graft may land inside `/snug` only under `/snug/engine/`). A list
that grows once per feature is a rule written somewhere it can be forgotten, and
`/opt/snug` was rejected because **reserving a subtree of a path other people
have a claim to is a weaker reservation than reserving a name nobody claims.**
The old location stays **refused** rather than freed: a rename whose old name
merely stops working is a trap.

**A command table snug exposes is REINTERPRETED, not bound.** Maintainer's
ruling, 2026-08-21, generalising what `~/.gitconfig`, `~/.claude.json` and
`installed_plugins.json` already do: where a file the sandbox reads names
programs, snug generates its own version from an allowlist and mounts it
read-only, rather than binding the host's bytes or the target's. The answer to a
dangerous file is a refusal expressed as a projection — **never a warning**,
which reports a breach instead of preventing one, and never a bare read-only
bind, which stops the *editing* and supplies every command in it. The projection
closes both directions: what the file can run **inside** is only what the
allowlist kept, and what the payload writes **outward** hits EROFS. Its limit is
that it can only be mounted where the host file ALREADY EXISTS — over an absent
path bwrap creates the mountpoint on the host, which `rejectGeneratedOntoHost`
refuses (issue #73, `CLAUDE-SETTINGS.md` §4.5). The inbound half — a hostile repo
SHIPPING a command table — is closed either way.

**Identity and credentials** — [`SECRETS.md`](.claude/design/SECRETS.md),
[`GIT-CONFIG.md`](.claude/design/GIT-CONFIG.md),
[`CLAUDE-SETTINGS.md`](.claude/design/CLAUDE-SETTINGS.md),
[`GENERATED-CONFIG.md`](.claude/design/GENERATED-CONFIG.md) own the subjects.
`ssh_mode = "agent-proxy"`: a filtering proxy to the already-unlocked host agent
exposing one pinned key — no key material inside, other keys not enumerable, and
it **cannot restrict what gets signed**, which is inherent to every agent
forwarder. `~/.config` gets **no blanket bind** (a credential dump and a
persistence vector in one); only `~/.config/git`. Claude Code's files are
read-only, `.credentials.json` is a five-key **projection** and `~/.claude.json`
is **generated** — three keys, zero host bytes.

**No staged credential is written back to the host — that channel does not
exist.** Keep the sentence credential-scoped: the sandbox writes to the host
through the target bind by design and through `@tmp-shared` when selected, so
"nothing leaves the sandbox" is false. If sync-back is ever built, structural
validation is the load-bearing half — `~/.claude.json` carries MCP config, a
natural target for injecting a tool that runs *outside* the sandbox on the next
host-side session.

**Injected `~/.claude/CLAUDE.md`** is generated per-run from the *actual*
resolved policy, so a run whose engine failed to start truthfully reads "no
engine".

**Networking** — [`ENGINE-NETNS.md`](.claude/design/ENGINE-NETNS.md),
[`TIER-B.md`](.claude/design/TIER-B.md) and INDEX §4 own it. Private netns per
sandbox, egress via pasta, host loopback closed; **offline is the absence of
`@net`, not a setting**, so it cannot be accidentally re-enabled. Containers run
in the sandbox's own netns since Tier B, so `@podman-socket` without `@net` is
genuinely offline; a container's egress follows the sandbox's exactly, and it
publishes no port onto any loopback the sandbox does not already own, because
the engine holds no `CAP_NET_ADMIN`. Host→sandbox publishing is off by default
and scoped to `127.0.0.1` when enabled — with `-t auto` the *agent* would choose
which host ports appear, inverting the guiding principle (INDEX §4.6, the
decision most likely to be revisited).

**The cost `@net` carries is a second long-lived process**, the stage: the
sandbox's user namespace has a **privileged ancestor for the whole run**, so a
userns-escape bug is worth more than it was. Measured to give the payload no new
reach — a same-uid host process already reaches that authority via
`NS_GET_USERNS` without a stage. Offline and `@net-host` take the single-process
path.

**The engine's pid namespace is its own** since Tier C's C0, so *"pid is the
host's"* is false wherever it appears. Two consequences are tracked, not folded
in: libpod's recorded pids are numbered in the **engine's** namespace, so no
host-side caller may read them as host pids (#167, fixed by deleting the
caller); and a container gets the kernel's `SIGKILL` at namespace collapse,
**never a graceful `SIGTERM`** (#174, open). If graceful stop returns it comes
through the engine's **own socket**, never a host-side CLI again.

**GUI, audio and D-Bus passthrough are out of scope deliberately.** No profile
ships. A filtering proxy that is 95% correct is a sandbox that is 0% sound, and
both mechanisms exclude them by construction — the **abstract** desktop sockets
are netns-scoped, the **pathname** ones (`/tmp/.X11-unix/X0`,
`/run/user/<uid>/bus`) are simply never mounted, since `/tmp` is a fresh tmpfs
and the host's is never a source — **a property to keep, not a gap to close.**
Do not add a profile without a decision to reopen this.

**One live sandbox per target directory** —
[`ONE-SANDBOX-PER-DIR.md`](.claude/design/ONE-SANDBOX-PER-DIR.md) and INDEX §11.
`snug <dir>` refuses a second live run and names `snug attach <dir>` as the fix.
The guard is a per-target advisory `flock` on `sha256(realpath)`, resolved **from
the uid alone — never from `$XDG_RUNTIME_DIR`/`$TMPDIR`**, because two runs
disagreeing on those once locked two different inodes and both acquired (#122).
It fails **closed**, is never unlinked, and is a run-path guard in
`internal/cli` — never in the pure `internal/policy`.
