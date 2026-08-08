# snug

> fitting closely and comfortably
> marked by cordiality and secure privacy
> offering safe concealment
> a small private room or compartment in a pub (British)

Bubblewrap-based sandbox for running untrusted code: builds, dependency install
hooks, test suites, and AI agents among them. Nothing in the model is
agent-specific — an agent is just one more thing you would rather not hand your
`~/.ssh` to.

**The full design is [.claude/design/DESIGN.md](.claude/design/DESIGN.md).** Read it before implementing
anything. This file is the working agreement: the invariants that must not be
broken, who does what, and the facts about this environment that were expensive
to learn.

## Status

**M3 works: share nothing, hardened, networking, scoped identity.** `snug <dir>` runs a command in a
sandbox where the target is the only writable thing that *persists*, the parent
is readable, and nothing else exists. A seccomp filter denies ptrace, bpf,
keyctl, perf_event_open, userfaultfd, TIOCSTI and nested user namespaces. The
flag list travels through a memfd, and inherited descriptors are sealed CLOEXEC.
Networking is a private netns per sandbox with a pasta helper: full egress, host
loopback unreachable, abstract sockets (X11/D-Bus) unreachable. Offline is the
absence of the `@net` profile. Profiles: `@sys`, `@home`,
`@cwd-rw`, `@parent-ro`, `@tmp-shared`, `@git-ro`, `@net`, `@net-anon`,
`@net-host`, `@claude`, `@podman-socket`, `@podman-build` — the `@` marks a profile
snug ships, and nothing else may wear it. There is deliberately **no `@default`
profile**: what a bare `snug <dir>` selects is the `defaults` *setting*
(`internal/profile/defaults.go`, overridable by `defaults = [...]` in
`~/.config/snug/config.toml`), because a default selection is a preference and a
profile is a grant.

Identity pins one git/ssh/gh account: a filtering ssh-agent proxy exposes exactly
one key (no key material inside, other keys not enumerable), and `.gitconfig`,
`.ssh/config`, `known_hosts` and gh's `hosts.yml` are all generated rather than
bound. The `@claude` profile stages credentials as writable copies and injects a
`~/.claude/CLAUDE.md` generated from the ACTUAL resolved policy.

`snug --dry-run` shows exactly what will happen; `snug doctor` says whether a
host can run it. `make gate` is the pre-commit check, and `docs/src/verify.md` is the
by-hand checklist — run it rather than trusting this paragraph.

Containers and `podman build` both work, each behind its own profile and its own
filter. Add holes one at a time, and see "Definition of done for a milestone"
below — `redteam` runs on every one, without exception.

**Out of scope, deliberately:** GUI, audio and D-Bus passthrough (Wayland,
PulseAudio, X11). Proxying those protocols safely is a project in its own right,
and a filtering proxy that is 95% correct is a sandbox that is 0% sound. The
private netns already excludes them by construction — that is a property to
keep, not a gap to close. Do not add a profile for them without a decision to
reopen this.

## Key features

 1. No root, no setuid — it has always been questionable that restricting access
    and improving security should need elevated privileges.
 2. No daemon, no service files — just execute a binary.
 3. Works everywhere, including from containers like a `distrobox` environment.
 4. Host integration is possible, just tightly controlled.
 5. Written in Go around bubblewrap — it reads the configuration, creates a
    policy, and provides integration with a "host".

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

   *One exception, and it is snug's own writing, not a profile's.* The generated
   `KindData` mounts (`/etc/resolv.conf`, and the identity files
   `~/.gitconfig`, `~/.ssh/config`, `known_hosts`) are assigned **directly into
   `p.Mounts`** at the end of `Resolve` — they do not go through `join`, and
   `rejectMasking` exempts `KindData` by kind. At an identical path that is a
   silent overwrite: with `@git-ro` and an identity profile both selected, the
   `@git-ro` bind of `~/.gitconfig` disappears from the policy entirely and the
   provenance reads `identity:<profile>` alone. **Verified by execution.** That
   is the intended direction — the pinned identity must not sit alongside the
   host's credential helpers, and `GIT_CONFIG_GLOBAL` exists for the same reason
   — but note what it is: a *profile* cannot displace another profile's grant,
   while *snug* can, and does, without saying so in `--dry-run`. The
   `rejectMasking` comment justifies the exemption by "no TOML key produces a
   `KindData` grant", which is true and is the right guard against a profile
   reaching this path; it does not cover the displacement. If a TOML key ever
   does produce `KindData`, both holes open at once.

   *Effective write access at a strict subpath is NOT monotone, by design.*
   `join` is keyed by `Mount.Guest`, so it only applies at identical paths.
   Grants at different depths do not join — they become two mounts, and the
   effective access at a path is that of the **deepest mount covering it**.
   Invariant 2 depends on this working (`ro /proj` + `rw /proj/src` protects
   `.git`); the inversion uses the same mechanism, so a profile adding
   `ro {target}/.git` demotes `.git` inside an otherwise writable target.
   **Verified by execution, not inferred.**

   That is acceptable — lowering write access is a tightening, and a profile
   that only tightens is a nuisance rather than an escalation — but it must be
   said out loud. `TestResolveIsMonotone` does not catch it: it compares
   `Access` per existing `Guest` key, and a deeper key did not exist in the base
   policy. Do not read that test as proving more than it does.

   Resolution remains commutative and idempotent: if `resolve([a,b]) !=
   resolve([b,a])`, the model is broken — fix the model, not the test.

   *There is no restriction operation anywhere.* Not in a profile, not on the
   command line. `--read-only` and the `policy.Clamp`/`Policy.Apply` machinery
   behind it existed — restriction applied by the human after resolution, on the
   argument that a file may not tighten but a person may — and both are **gone**.
   snug stays minimal; bwrap is the swiss knife. To grant less, select fewer
   profiles: a read-only project is `snug --no-defaults -p @sys -p @home -p
   @parent-ro <dir>`, verbose on purpose. The point of removing it is not the
   flag, it is the *carve-out*: an invariant with no exceptions can be checked by
   grepping for a demote and finding none (`TestPolicyHasNoRestrictionOperation`);
   one with an exception can only be checked by understanding where the exception
   applies. If a patch reintroduces a demote — anywhere, under any name — it is
   reintroducing the exception, not just a convenience.
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
   target are all ignored. **But the gate is weaker than DESIGN §2.7 describes.**
   `$XDG_CONFIG_HOME/snug/profiles.d` is trusted unconditionally, so pointing
   `XDG_CONFIG_HOME` into a checked-out repo does load that repo's profiles,
   privileged grants included. The designed defences — an explicit `--config`
   flag and refusing privileged grants from untrusted layers — are **not
   implemented**; `Profile.Trusted` is set and never read. Low severity (it is
   the host user's own env var, not something the sandboxed agent controls), but
   do not claim the §2.7 gate exists until it does.
4. **No root, no setuid, no daemon.** Helpers are children that die with the
   sandbox and leave nothing behind.
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

- `bwrap` 0.11.2, `pasta` (passt) 20260612, Go 1.26. No `slirp4netns`.
- Development happens *inside* a rootless-podman distrobox. Nested userns, netns
  creation, pasta attach, egress and DNS all work there.
- **`pasta`'s defaults are unsafe for us, in two independent ways.**
  `--map-host-loopback` defaults to *the gateway address*, and `-T`/`-U`
  (`--tcp-ns`/`--udp-ns`, namespace→host forwarding) both default to **`auto`**.
  Either one alone re-opens host loopback. The full closing set is:

  ```
  --map-host-loopback none -t none -u none -T none -U none
  ```

  The previous generation of this project passed the first three and not
  `-T`/`-U`, so its "private" netns reaches every host loopback service. Its
  probe notes saw the symptom and dismissed it as an `ss`/procfs artifact. It
  was a live TCP forward. See DESIGN §4.2.
- The lesson generalises: **never trust a helper's default, in either
  direction.** Pass every security-relevant flag explicitly even when it matches
  the current default, and assert the *behaviour* in an integration test — a
  golden-argv test would have passed on the buggy configuration.
- **`--clearenv` is not the last word on the environment.** `@sys` binds `/etc`,
  so `/etc/profile.d/*` runs inside the sandbox and can put variables back. On
  this box `distrobox_profile.sh` sees the empty environment, *re-derives*
  `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` from the uid, and calls
  `host-spawn`, which then fails to reach a bus the sandbox correctly cannot
  see. The noise is isolation working. But the general point stands: the
  environment inside is what snug sets *plus whatever the bound `/etc` adds*.
  The designed fix is the `sys-min` profile (curated `/etc`), not a hack.
- **`--clearenv` does not cover bwrap's own process, and that leaked everything.**
  `exec.Cmd` with a nil `Env` passes `os.Environ()`. bwrap then becomes PID 1 of
  the sandbox's PID namespace, running as the same uid, so the payload could read
  the entire host environment — `SSH_AUTH_SOCK`, cloud credentials, tokens — out
  of `/proc/1/environ`, while its own `env` looked perfectly clean. The redteam
  agent pulled 106 host variables out of a default sandbox. Fixed by
  `cmd.Env = []string{}` in `cmd/snug/main.go`. The general lesson: **a guarantee
  about the payload's environment is not a guarantee about the sandbox's PID 1.**
  Whenever a helper process joins the sandbox's namespaces, ask what its own
  `/proc/<pid>/` exposes.
- **A denied syscall's ERRNO is part of the interface.** `clone3` is denied
  because classic BPF cannot read its flags — but denying it with **EPERM broke
  the world**, because glibc's `pthread_create` falls back to `clone()` only on
  **ENOSYS**. Symptom: `curl https://example.com` returned 000 inside the sandbox
  while `getent hosts example.com` resolved fine. curl uses a threaded resolver;
  the thread could not be created; the failure surfaced as a DNS timeout that
  looked exactly like a networking bug. About an hour went into pasta before the
  cause turned out to be seccomp. **When denying a syscall, return the errno
  callers already have a tested fallback for.**
- **`flags` is snapshotted into a memfd.** Anything appended to the slice after
  `memfd("snug-args", ...)` is silently dropped — same shape as the
  `--seccomp`-after-`--` bug, and it bit again during M2: the networking flags
  went in after the snapshot, so bwrap never saw them, the payload ran anyway,
  and the only symptom was "no network". There is now a comment marking the
  point past which nothing may be appended.
- **An open directory descriptor ignores the mount namespace entirely.**
  `openat(2)` walks from the descriptor's own vfsmount, so a dirfd handed into
  the sandbox is a complete bypass of every grant. `sealInheritedFDs` marks
  inherited fds >2 CLOEXEC for exactly this reason — but 0/1/2 must pass through
  for stdio, which left the same hole on three well-known numbers. The redteam
  agent read `~/.aws` and wrote into an ungranted directory through
  `/proc/self/fd/0`. `safeStdio` now substitutes /dev/null for a directory on
  stdio. **When you exempt something from a security sweep, ask what the
  exemption itself lets through.**
- **A test that cannot fail is worse than no test.** The leak check matched
  `/proc/<pid>/comm` against the literal `"pasta"`; passt ships CPU-dispatched
  binaries, so the real comm is `pasta.avx2` and the count was always zero —
  `after > before` could never be true. It passed cleanly for as long as it
  existed. Every negative test in the integration suite now has a positive
  control: assert the thing you are measuring is actually present before
  asserting it did not grow, and make every payload emit a marker so "the
  sandbox did not reach X" cannot pass on a sandbox that never started.
- **A gate that is documented but not implemented is not a gate.**
  `ssh_mode = "host-agent"` forwards the entire ssh-agent, and three separate
  places — the profile, the mode's doc comment, and the code comment at the call
  site — said it required `--i-know`. Nothing checked it. The redteam agent
  enumerated every key in the agent and signed with one the profile had not
  pinned. `cfg.iKnow` existed and was consulted only for `NetHost`.
  **When you write "requires X" in a comment, grep for X before you believe it.**
- **Generate, don't bind — and put the secret in a file, not the environment.**
  One rule, stated once, because it was previously spread over four bullets.

  *The rule.* Where the sandbox needs a tool configured, snug **generates** a
  private config file or DIRECTORY from the resolved policy and points the tool
  at it with that tool's own env var: `GH_CONFIG_DIR`, `GIT_CONFIG_GLOBAL`, and
  the same shape for `NPM_CONFIG_USERCONFIG`, `CARGO_HOME`, `DOCKER_CONFIG`,
  `PIP_CONFIG_FILE` when they arrive. It never binds the host's. Two reasons,
  and both matter: a bind carries every unrelated thing in that file (see the
  `git` two-file bullet below — `@git-ro` reintroduced the host's credential
  helpers alongside a pinned identity), and **the env var then carries a PATH,
  not a credential.** `/proc/self/environ` is passively readable by every
  process in the sandbox and inherited by every child; a file has to be
  deliberately opened. `/etc/resolv.conf` is the same rule one layer down.

  *The cost, accepted.* Each adapter must track that tool's config format, and
  formats change under us (`gh` rewrites `hosts.yml` on first use — see below).
  There is no version of this that is free.

  *The bound, which is what keeps the cost finite.* One **opt-in profile per
  tool**, never in `defaults`. An adapter nobody maintains then degrades to
  "that tool has no config inside the sandbox" — visible, annoying, harmless —
  rather than to a leak. If you find yourself wanting the adapter on by default
  because it is convenient, you are proposing to make the failure mode a leak.

- **PATH precedence, not overmounting, is how snug substitutes a host binary —
  and the reason is authorship, not capability.** Correcting the record: it was
  once claimed, confidently, that "snug structurally cannot overmount
  `/usr/bin/podman`". That was **WRONG**. snug overmounts generated files inside
  bound directories all the time — `/etc/resolv.conf` sits inside the `/etc`
  bind, and `rejectMasking` carries an explicit `KindData` exemption for exactly
  that case.

  The real distinction is **who authors the replacement**:

  - A *profile* mounting something over what *another profile's* grant exposes
    is **masking**. Refused, unconditionally, because it destroys the property
    that lets you compose profiles without reading every one of them.
  - *snug itself* replacing a specific path with its OWN generated content is
    **replacement**. Allowed: the sandbox still sees a file there, just a
    truthful one, and no profile's grant is silently subtracted.

  So the capability exists. It is simply not the right tool for a whole binary.
  Where a command needs substituting — the live case is `/usr/bin/podman` being
  a distrobox shim that cannot work from inside (`cmd/snug/podmanshim.go`) —
  **write the replacement into the writable tmpfs `$HOME` and put that directory
  first on `PATH`.** It is additive (nothing is hidden; the original is still
  there and still reachable by absolute path), it needs no mount at all, it
  cannot fail on a host where the target path is a symlink (bwrap cannot create
  a mountpoint at a symlink destination — DESIGN §3.3), and it is one line of
  policy instead of a new exemption in the masking rule. Reach for an overmount
  only when the consumer reads an absolute path it will not let you configure.
- **`git` merges its global config from TWO files.** `~/.gitconfig` AND
  `$XDG_CONFIG_HOME/git/config` are both read. So generating `~/.gitconfig` was
  not enough: with `@git-ro` also selected, the host's credential helpers,
  `insteadOf` rules and `user.email` sat alongside the pinned identity. Setting
  `GIT_CONFIG_GLOBAL` replaces both outright, which is why snug sets it whenever
  an identity is pinned. Verified by execution, both directions.
- **`gh` rewrites its token file on first use.** It migrates a file-stored token
  and writes the config back; a read-only `hosts.yml` fails with "failed to write
  config after migration" (gh 2.96). So the staged copy is deliberately WRITABLE
  — it is a private copy on tmpfs, so the rewrite goes nowhere and the host's gh
  config is never touched.
- **bwrap stops parsing flags at `--`.** A flag appended to the full argv lands
  after the separator and is handed to the payload instead — so `--seccomp` was
  once passed, accepted, and never installed, with a zero exit code and no
  warning. `Seccomp: 0` in `/proc/self/status` was the only evidence. Hence
  `BwrapFlags` (no separator) and `BwrapArgs` (with it) are separate, and a test
  asserts the first contains no `--`. **Verify a security feature is active, not
  merely requested.**
- **The writable surface is seven paths, not one.** The target bind is the only
  one that persists; `/tmp`, `$HOME`, `$HOME/.cache`, `$HOME/.config`,
  `$HOME/.local/state` and **`/dev`** are all writable tmpfs that die with the
  sandbox. `/dev` is bwrap's own synthetic device tree and is easy to forget —
  it was found by running `docs/src/verify.md`, not by review. Say "the only
  writable thing that persists", never "the only writable thing".
- **The sandbox sets `PS1`.** snug does not grant `/etc/bash.bashrc`, so without
  it the shell shows bash's built-in `bash-5.3$` and nothing on screen says you
  are sandboxed. Humans and agents both act on the prompt, and "am I inside?" is
  the question where guessing wrong is expensive. Keep it distinctive.
- `/proc/sys/dev/tty/legacy_tiocsti` is `0` on this kernel, so `--new-session`
  is unnecessary here and snug omits it, which is why job control works inside
  an interactive sandbox shell. On a host where it is `1`, snug adds the flag
  and `--dry-run` says so. Never make this decision silently.

## Development agents

`.claude/agents/` — use them; they carry the context that keeps the invariants
intact. `.claude/design/` holds the design and research material they work from
(DESIGN.md, the pseudo-filesystem audit, parked designs). **`docs/` is the USER
guide and nothing else** — an mdBook, built with `make docs`. Keep the two
apart: a reader looking for "how do I give this sandbox my work GitHub account"
must not land in a threat model.

| agent | owns |
|---|---|
| `sandbox-policy` | The policy model and the bwrap argv. Invoke *before* writing policy code. Guards monotonicity. |
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
   whatever the milestone added. `docs/src/verify.md` gets the human-readable
   equivalent — it is the by-hand checklist and is not made redundant by the
   automated one.
3. **`redteam` has attacked it.** Not optional, not "if there's time". Every
   milestone that adds a hole gets a run before it lands, and so does any change
   to the policy model, mount generation, the seccomp filter, or a
   host-integration surface.
4. Every confirmed finding is either fixed, or written into `TODO.md` as a known
   gap with its severity — never silently carried.
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
- `snug explain` is not a debugging convenience — it is *the* mechanism by which
  a human can trust snug at all. Keep it honest and keep it complete.

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

  Two properties fall out, and both are structural rather than checked.
  `profile.builtins()` adds the mark and is the ONLY code that does, while
  `checkName` refuses a leading `@` in **every** file it parses — `base.toml`
  included, which is why the builtins are written there under bare names. So a
  builtin cannot forget the mark and a user profile cannot borrow it. And the
  two namespaces can no longer collide: a user file defining `sys` defines a
  profile of their own, so "a config file could quietly change what `sys` means"
  stops being a thing `merge` has to prevent. That matters most where invariant 3
  is weakest — `$XDG_CONFIG_HOME` is still trusted unconditionally, and a
  profiles.d loaded from the wrong place still cannot impersonate `@sys`.

  Consequence to keep in mind: `include` inside a builtin is rewritten with the
  names, so a builtin can only ever include another builtin. That is correct (it
  is compiled in and cannot know a user's names) but it is a rule, not an
  accident — see `profile.mark`.

  The provenance snug writes for its OWN mounts (`/proc`, `/dev`, the generated
  `/etc/resolv.conf`) reads `(snug)`, renamed from `(builtin)` in the same pass:
  with `@`-marked builtin profiles on the screen, one word meant two things.
- **`--dry-run`, not `explain`.** It is the conventional name and the tool
  should not invent vocabulary. What it prints is unchanged: the resolved
  policy and the exact bwrap command, having started nothing.
- **`snug config` holds preferences, never grants.** Today that is `defaults` —
  which profiles a bare `snug <dir>` selects. It names profiles and cannot
  define one, because a config file able to redefine a builtin could quietly
  change what `@sys` means.
- **There is no `default` profile; there is a `defaults` setting.** A default
  selection is a *preference*, a profile is a *grant*, and having both was two
  mechanisms for one idea: the builtin `[profile.default]` granted nothing yet
  appeared in `SNUG_PROFILES`, in `snug profile tree`, and in every `Mount.From`
  provenance as though it were a hole in the sandbox — while `default_profile`
  in config.toml expressed the same idea with a level of indirection whose
  built-in value was, circularly, `["default"]`. Now: built-in list in
  `internal/profile/defaults.go`; `defaults = [...]` in config.toml **replaces**
  it wholesale (merging would make "fewer defaults than snug ships" impossible);
  `-p` **adds** to whatever that resolved to; `--no-defaults` declines it
  entirely. The list is `@sys @home @cwd-rw @parent-ro` — enough that snug is
  usable by just running it — and `@net` must never join it, because offline is the
  *absence* of a profile and that is what stops it being switched on by accident.
  For the same reason there is no `@null` profile either: a profile that grants
  nothing is a preference wearing a profile's clothes, and the floor of the
  lattice is not something a file needs to name — it is what `Resolve` computes
  from an empty selection, reachable directly with `snug --no-defaults`.
  `-p @null` is a retired name that errors, naming `--no-defaults` (MVY0).
- **The directory is positional, not `-C`.** `go -C` and `make -C` mean "go
  somewhere else, then do the usual thing"; for snug the directory *is* the
  thing being sandboxed, like `git clone <url>`. Defaults to `.`.
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
  `.credentials.json` and `~/.claude.json` staged as writable copies (Claude
  re-onboards without the latter). Only the credentials file syncs back to the
  host, and only after structural validation — `~/.claude.json` carries MCP
  config, which is a natural target for injecting a tool that would run *outside*
  the sandbox on the next host-side session.
- **Injected `~/.claude/CLAUDE.md`**: generated per-run from the *actual*
  resolved policy, so a run whose engine failed to start truthfully reads "no
  engine". Every sentence in it removes a class of wasted agent turns.
- **Networking**: private netns per sandbox, egress via pasta, host loopback
  closed. Offline is the *absence* of the `@net` profile, not a setting — so it
  cannot be accidentally re-enabled. Host→sandbox port publishing is off by
  default and scoped to `127.0.0.1` when enabled: with `-t auto` the *agent*
  would choose which host loopback ports appear, which inverts the guiding
  principle. See DESIGN §4.6 — this is the decision most likely to be revisited.
- **D-Bus**: no profile ships. A filtering bus proxy that is 95% correct is a
  sandbox that is 0% sound.

