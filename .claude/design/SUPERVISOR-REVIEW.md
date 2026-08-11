# Independent review of the supervisor topology

Four agents were asked to *disprove* [SUPERVISOR.md](SUPERVISOR.md), not to
approve it: `sandbox-policy` on the invariants, `redteam` on escape,
`host-bridge` on the holes, `sandbox-tester` on whether the 49 measurements can
fail. None of them could edit a file, so nothing here is a fix — it is a list of
what the design owes.

This document is the review's output. Anything it confirms belongs either in
SUPERVISOR.md as a decision or in `TODO.md` as a known gap with a severity;
nothing may be carried silently, and every confirmed hole becomes a named
regression test before the topology ships.

---

## 1. Invariants (`sandbox-policy`)

**Verdict: the topology breaks invariant 1 and invariant 6 in the same place,
for the same reason.** The graft is a second mount authority with its own path
namespace, no provenance, no masking rule and no `--dry-run` rendering.
Invariant 4 survives — but on the lifeline pipe, not on the reference count that
§9 credits. Invariant 3 is untouched. Invariant 5 has three live silent-downgrade
paths, one of them already measured.

### 1.1 The graft is not the `KindData` carve-out

The precedent invited by §6 does not cover it. `KindData` replacement
(`internal/policy/types.go:99`, `Policy.Replace` at `types.go:221`) is narrow in
four independent ways, and every one is load-bearing: the path is already a key
in `p.Mounts`; the content is *in* the policy; it is marked `Authored` by exactly
one writer; and `Replace` records `replaces:<what it displaced>` so `--dry-run`
says so.

`poc/nsd/join/nsdmount.c:59-101` has none of the four. The destination is not a
key in `p.Mounts`, the content is a host subtree reached through an `open_tree`
descriptor, nothing marks it, nothing records it. "Additive" is true of the
*mount operation* and false of the *policy operation*: `rejectMasking`
(`internal/policy/validate.go:197`) walks one guest-path→mount map. There are now
two mount views and the rule is written against one of them.

**And the graft can mask.** E10 grafted onto an empty `/storage`, so the
collision case is untested — but SUPERVISOR §8 already names `/etc/containers`,
`/run` and `/var/tmp` as "the same mechanism repeated", and ENGINE-NETNS §3 says
the engine *requires* a tmpfs on `/run`. `/run` is a path the policy grants
into: `/run/snug/ssh-agent.sock` (`cmd/snug/identity.go:128`) and the container
socket (`cmd/snug/container.go:55`). The second shipped graft is therefore a
tmpfs overmounting a path two grants live under, in a view no rule inspects.

The honest framing is not "profiles gained subtraction". It is **snug gained a
second mount authority, and that authority's operations are unconstrained by the
rules that constrain the first**. The two-year failure is a maintainer reading
"snug may author replacements, see KindData" and adding graft #4 with no policy
object behind it, because the first three shipped that way.

Commutativity is not yet threatened but is one field away: a `[]string` of host
paths on an engine config struct — the obvious first implementation — has no
access lattice, no provenance and no conflict rule, and `resolve([a,b]) !=
resolve([b,a])` becomes expressible again as soon as two profiles want a graft.

### 1.2 §6's "short list snug wrote itself" is a denylist

> *"The remaining job is to refuse snug's own grafts, which is a short list snug
> wrote itself"* — SUPERVISOR §6

That sentence is a denylist. It is small and it is snug's own, and it is still
the first denylist in the security path — required precisely because graft
destinations are not grants and so cannot be judged by the allowlist.

The sharper version: `Proxy.hostPathVisible` (`internal/dockerproxy/create.go:611`)
is keyed on `Mount.Host`. Under a derived view the string in a container's
`HostConfig.Binds` is resolved by podman in the sandbox's naming, i.e. against
`Mount.Guest`. The rule and the resolution end up in different vocabularies. It
looks fine only because every shipped grant except one has `Guest == Host` — the
exceptions are `@tmp-shared`'s `{host_tmpdir}:/tmp` and the two `/run/snug`
socket paths — so the suite cannot see the divergence and it fails closed *by
accident*. Concrete future collision: `@podman-socket` grants `ro =
["/etc/containers"]` while §8 wants `/etc/containers` grafted in; the proxy would
approve the string against the grant and the engine would act on the graft. Same
string, two objects, two authorities.

(`hostPathVisible` is currently unused — its own comment says the proxy uses a
replace-everything strategy — but it is documented as the rule *any future
opt-in submount mode must use and nothing else*, and the derived view is exactly
that mode arriving.)

Related: `checkOne` resolves symlinks with `resolveExisting` in the **host**
mount namespace (`internal/dockerproxy/create.go:295`). Under a derived view the
engine resolves in a different filesystem, so the residual TOCTOU becomes
namespace-of-check versus namespace-of-use — strictly harder, and the mitigation
that saved it (forward the resolved path) does not apply when the two namespaces
disagree about what that path denotes.

### 1.3 One grant with no profile at all

`writeFullMaps` (`poc/nsd/stage.go:109,173`) delegates the entire `/etc/subuid`
range unconditionally on every `up`. That is a capability — 65536 host uids owned
by the namespace holder — required only by the engine, granted even under
`--no-defaults`, invisible to `--dry-run`, traceable to no profile. It also makes
a bare `snug <dir>` fail on any host with no subuid entry. Making it conditional
on `Podman != PodmanOff` is the fix, and it is exactly what forces topology into
`Policy`.

### 1.4 Invariant 4 — argue both sides

*For.* The distinction §0 draws is right. Invariant 4 spells out what it defends
— "helpers are children that die with the sandbox and leave nothing behind" — and
P1 satisfies it. No unit file, no socket activation, nothing survives a reboot.
The uid 0 is uid 0 *in its own user namespace*, which is what every rootless
runtime does and what bwrap already does twice. No setuid binary appears:
`newuidmap` has file capabilities and podman already uses it. The socket is 0600
in a 0700 directory and is not in the sandbox's mount namespace (measured).

*Against.* Three things are true at once: it holds a listening socket on the host
filesystem; it accepts unauthenticated commands that execute arbitrary argv with
CAP_SYS_ADMIN over the sandbox; and **its lifetime rule has a hole in exactly the
failure case**. `everRan` is set only in `hold` and in `startSandbox` — and in
`startSandbox` it is set *after* `readChildPID` and `waitReady`. If bwrap is
missing, or `waitReady` times out, `everRan` stays false and the exit rule is
disabled: the stage serves forever with zero payloads. E11 measures only the
happy path. So "P1 is not a daemon" rests on the **lifeline pipe**, not on the
reference count, in precisely the case where something went wrong. That is
acceptable, but §9's prose attributes the guarantee to the count, and the failure
path has no test.

Second, and worse: `graft` and `runChild` deliberately do not `hold()`, justified
by "in the real thing those are not user-visible processes". **In the real thing
the engine is exactly a `runmnt`/`graft`-shaped child.** Under the shipped
topology the engine holds no reference, the stage exits when the sandbox's
payload exits, and the engine's `conmon` — which double-forks out of the tree —
stays in N. E11's teardown check counts processes under `/proc/*/ns/net`, which
is blind to a netns pinned by a bind mount with no process attached. That is the
exact failure `MS_REC|MS_PRIVATE` at `poc/nsd/stage.go:277` exists to prevent, so
**deleting that line leaves every test green on this host, forever**, because the
engine leg cannot run here.

What would have to be true for the answer to stay "no daemon": (a) the lifetime
rule fires on the startup-failure path too; (b) every member of N holds a
reference, or teardown asserts on the *namespace object* rather than a process
count; (c) the control protocol gets the `internal/dockerproxy` discipline —
`control.go:106` is a plain `json.Decoder.Decode`, no `DisallowUnknownFields`, no
trailing-data check, the opposite of what §7 argues for; (d) the ops are minimal,
because `runmnt` today means "give me a root-in-userns shell with the whole host
tree and the full subuid range".

### 1.5 Invariant 5 — three live silent-downgrade paths

- **Seccomp on an attached process.** Measured `Seccomp: 0`, already named in §4.
  Shipped as-is, `snug attach` puts an unfiltered process inside a sandbox
  advertised as seccomp-filtered, and `ps` inside shows it as an ordinary
  sibling. The joiner reproduces two of the six protections `internal/sandbox/exec.go`
  applies (caps, `no_new_privs`); it does not reproduce seccomp, the empty
  environment (the `/proc/1/environ` lesson, now applying to a process in the
  payload's own pid namespace and readable by it), `safeStdio`, or
  `sealInheritedFDs`. Two payloads in one sandbox with different confinement is
  invariant 6 violated in the most literal sense.
- **The abstract-socket rule.** §5's mitigation is "no process in N may bind an
  abstract socket" — a rule imposed on code snug does not control (podman,
  conmon, netavark, aardvark-dns, crun). It cannot be checked at build time, and
  the only check is an integration test with the engine running, which §8 says
  cannot run on this host. Meanwhile CLAUDE.md states "abstract sockets
  unreachable" as a property *by construction*, twice. If the topology lands and
  those sentences do not change in the same commit, snug asserts a guarantee it
  no longer delivers — the same shape as the `@podman-socket` finding this work
  exists to fix.
- **Fallback.** Both docs say the preflight must refuse, never fall back. There
  is no code yet, and the failure is invisible by construction. Note the
  asymmetry: today `@podman-socket` includes `net`, so a fallback is *honest*;
  after the include is removed a fallback means "the sandbox says offline and a
  container reaches the internet" — the original measured bug, restored, by a
  path whose only trigger is a host we cannot test on.

Minor, but new: `/proc/net/unix` is netns-scoped, so with the stage and engine in
N the sandbox's `ss -xl` lists the stage's control socket path, the engine's
socket path (which encodes snug's pid) and every container's. Measured. Not an
escalation; a host-layout disclosure, and it belongs in PSEUDOFS-AUDIT.md.

### 1.6 Invariant 3 holds, with two new runtime-resolved inputs

No new config file, no repo-local load path. But the process about to become
root-in-U resolves two paths from the filesystem at runtime:

- `poc/nsd/stage.go:261` re-execs `os.Getenv("NSD_SELF")` **after** the uid map is
  written. Between the first exec and the re-exec that path can be replaced by
  any process of the same uid; the replacement then runs with euid 0 in U, the
  full subuid map, and CAP_SYS_ADMIN over the sandbox's namespaces. Must be
  `/proc/self/exe` or `fexecve`.
- `control.go:333,373` locate `nsdjoin` and `nsdmount` as
  `dirname(NSD_SELF)/name` and execute them as root-in-U. §3.4 correctly flags
  "shipping a second binary is a change in kind"; locating it by `dirname(argv0)`
  is what turns a packaging decision into a security one.

### 1.7 Invariant 6 — the claim is backwards for mounts

§5 claims invariant 6 "extends to the engine by construction rather than by
review". It extends the *network* by construction, which is the real win. It does
the opposite for mounts. Authorities after this lands:

| authority | input | reviewed how |
|---|---|---|
| `Policy.BwrapFlags` | resolved policy | golden argv |
| `Policy.PastaArgs` | resolved policy | argv test + behaviour test |
| `Proxy.hostPathVisible` | `Mount.Host` | unit tests |
| stage: clone flags + uid_map | hardcoded | nothing |
| stage: graft set | request argv | nothing |
| joiner: attached-process confinement | request argv | nothing |

Three new authors, two of which decide *mount topology* — the thing `Policy`
exists to be the sole author of. `PastaArgs(childPID)` already shows the seam
moving: the netns belongs to P1 now, not to the bwrap child.

### 1.8 What the policy model has to grow

- **A `Topology` on `Policy`, derived and monotone.** Every field needs a `Join`
  and must be folded like `Access.Join`, `NetMode.Join`, `PodmanMode.Join`.
  Minimum: who owns the netns; whether the full subuid map is delegated (⇐
  `Podman != PodmanOff`, so a plain `snug` does not pay for it); whether attach
  is permitted. The moment any of these is set from a flag rather than derived
  from the resolved profile set, `default_profile` has been re-created — a
  preference and a grant expressing one idea through two mechanisms, which
  "Decisions made" already reversed once.
- **A second mount view, modelled — not a `[]string`.** `map[string]Mount` with
  `From`, `Access`, `Authored`; run the *same* `rejectMasking` over the derived
  view; a graft destination colliding with a grant is a hard error, not a silent
  overmount. `Validate` becomes view-parameterised and `nearestCovering` takes
  the view. `internal/policy` stays pure — a graft is still just paths.
- **Attach must be compiled, not hand-written.** A `Policy.AttachSpec()` beside
  `BwrapFlags`: seccomp fd, `--setenv` set, caps drop, stdio substitution, with
  the joiner as a dumb executor. Otherwise the joiner *is* the second author and
  every future hardening lands in one of two places.
- **`--dry-run` renders a topology, and the golden discipline follows.** Today it
  prints one argv, covering one of six authorities. After this the boundary is
  five argvs and a uid_map: either `TestGoldenStageArgs`,
  `TestGoldenEngineView`, `TestGoldenAttachSpec` exist next to
  `TestGoldenBwrapArgs`, or "a security change that produces no golden diff is
  probably untested" stops being enforceable.
- **The proxy shrinks less than §6 claims.** It changes vocabulary (Host→Guest),
  keeps `checkOne`'s symlink handling but now across a namespace boundary, and
  gains a graft denylist. Net code change is plausibly positive. Do not budget it
  as a deletion.

### 1.9 What this review says to keep unchanged

The sibling-not-parent placement of the engine; "no control socket inside the
sandbox" and its argument; the lifeline over `Pdeathsig`; the setns ordering;
`unshare` before `move_mount` with its negative test; and §9's lifetime decision.
Those are right for stated reasons rather than by luck.
