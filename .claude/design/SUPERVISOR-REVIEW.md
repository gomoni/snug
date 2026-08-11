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

---

## 2. The holes (`host-bridge`)

Reproduced the PoC (`pass=49 fail=0`) and then ran four probe suites of its own
against it. Everything marked MEASURED below was executed on this host.

**Verdict: the topology is sound and the paper is honest about its costs — but
its abuse sentence names the wrong socket, "attach adds no attack surface" is
false in the one dimension this project has been burned by twice (descriptors),
and §6's proxy simplification replaces an allowlist with a denylist.**

### 2.1 Hole-by-hole, before and after

| of today's four guarantees | after |
|---|---|
| host loopback unreachable | **survives verbatim.** MEASURED: 000 from N and from the sandbox against a live host listener answering 200. The closing set is unchanged and still aimed at a `/proc/<pid>/ns/net`. |
| no host filesystem beyond grants | **survives, with three qualifications** below. |
| abstract sockets unreachable | **dies as stated; survives only in its useful half.** The host's X11/D-Bus are still out — they live in the host netns. But N's abstract namespace is not empty and not one-way: E6 measures snug's helper leaking to the payload, and a new probe measures the payload *squatting* a name snug's helper then could not bind (`HELPER-REFUSED [Errno 98]`). |
| engine reached only through a filtering proxy | **survives as a fact, dies as an invariant.** Today the engine is in a different netns, so "the only way in is the socket snug bound" is kernel-enforced. After, the engine and every helper it spawns are network peers of the payload, and the property becomes a configuration promise — nobody listens on IP in N — rather than a namespace boundary. Nothing in the design says the engine's service must never be `tcp://`. |

The three qualifications:

- **The graft point.** A directory appears in the sandbox that no profile
  authored. In the PoC the `mkdir` succeeds because `startSandbox` never passes
  `--remount-ro /`; real snug does (`internal/policy/bwrap.go:120`), so snug must
  pre-create that mountpoint *before* the remount. Cheap — but it is a
  policy-authored path and it must appear in `--dry-run`.
- **Attached processes.** MEASURED `Seccomp: 0`. Silent downgrade of a live
  sandbox, and no mechanism is proposed to make it a refusal instead of a gap.
- **Descriptors. This is the finding.** MEASURED: every attached process holds
  `fd 5 -> pipe:[…]`, the stage's lifeline read end — `stage.go:256-260` clears
  CLOEXEC on fds 4 and 5 to survive the re-exec and never re-sets it, so it is
  inherited by every subsequent fork and is visible from inside the sandbox on a
  long-running attached process. MEASURED: the sandbox's own PID 1 holds
  `1 -> /tmp/nsd-probe2/sandbox.log` **`lrwx`** — a host file outside every
  grant, open read-write, reachable from inside as `/proc/1/fd/1`.

  The lifeline leak is benign (a duplicated *read* end cannot forge or prevent
  EOF) and the log fd is a PoC choice. **The class is not benign, and it is the
  exact class `sealInheritedFDs`/`safeStdio` exist for.** Under this topology the
  process that forks the sandbox is no longer P0 — a short-lived launcher whose
  fd table snug fully controls at `cmd.Start()` — but **P1, a long-lived server
  with an accept loop, per-connection sockets, pidfds, an eventpoll and an
  eventfd, whose fd table at fork time depends on which control connections
  happen to be open.** `sealInheritedFDs` must be re-run in P1 immediately before
  every fork, and `snug attach` — which by §7 passes a pty over `SCM_RIGHTS` — is
  a deliberate fd-into-the-sandbox channel. §4's "attach adds no attack surface
  inside the sandbox. No socket, no listener, no fd handed in" is true about
  listeners and false about fds, in the design and in the PoC.

**One structural change nobody wrote down.** Today bwrap's user namespace is a
child of the initial userns, where the host user has no capabilities: escaping it
lands you as uid 1000 with nothing. After, it is a child of U, which holds the
**full subuid range and CAP_SYS_ADMIN over N and over the sandbox's own mounts**,
and which lives for the whole run. The value of a userns-escape bug goes up a
lot, and the sandbox has a privileged ancestor for the first time. That belongs
next to the abuse sentence.

### 2.2 "No process in N may bind an abstract socket" is not sufficient

It is one of three rules, and it is aimed only at snug.

**(a) 127.0.0.1 in N is shared, and the abuse sentence omits it.** MEASURED: a
helper run as a child of P1 bound `127.0.0.1:19099`; the payload read
`SECRET-FROM-A-LOOPBACK-HELPER-IN-N` out of it while the host got `000`. §9 says
"any socket they bind on `0.0.0.0` or in the abstract namespace". Loopback is the
address a careful engineer picks *because it feels safe*, and it is exactly as
exposed. Rewrite that sentence before anything else here is implemented.

**(b) The rule constrains snug, not the attacker.** MEASURED: the payload bound
`0.0.0.0:19100` and abstract `\0snug-broker`; a later host-side helper in N got
`EADDRINUSE` on both. The payload can deny service to snug's helpers and to the
engine's (`aardvark-dns` on :53, `rootlessport`), and can pre-empt any well-known
name a future helper *connects* to. Whatever P1 starts must start before the
payload, and that ordering guarantee is currently nowhere.

**(c) The socket tables are the leak, not just the one path.** MEASURED: inside
the sandbox `/proc/net/unix` lists the control socket path and `/proc/net/tcp`
shows the helper's listener *and its established peer*, with `uid 0` rows. §5's
"put the run directory under a name that says nothing" understates it: this is a
standing enumeration channel that grows with every helper and every container, it
will carry the engine socket path (which embeds the store hash and snug's pid),
and it lets the payload watch which remote addresses snug's helpers and
containers talk to. Renaming obscures one entry; it does not close a channel.

**(d) The engine's helpers are in N by construction** — netavark's bridge,
aardvark-dns, rootlessport, conmon. ENGINE-NETNS §4 measured zero abstract
sockets with the engine running, which should stay a test, but it says nothing
about IP listeners.

So the rule is: **no snug-owned process may listen in N at all — not on an
abstract name, not on any IP address including 127.0.0.1.** Anything the sandbox
must reach stays a pathname AF_UNIX socket in a directory the sandbox does not
mount, exposed through exactly one `BindSocket` of exactly one file — the
mechanism snug already has.

Which condemns §5's worst sentence:

> **A natural home for the MVY2 secrets broker. P1 is outside the sandbox, holds
> host authority, and already has a control socket.**

P1 is the one process that now shares a network namespace with the untrusted
payload and with every container. Proposing it as the home for the
highest-value host authority in the project, three bullets after proving that
namespace is shared, is "a limitation and a hole are the same fact facing two
directions" happening *inside the document that quotes it*. If a broker lives in
P1 it must bind nothing in N, and that constraint goes where the suggestion is.

### 2.3 The control socket — argument holds, enforcement is thinner

§5's reasoning ("any socket a shim inside can reach, the payload can reach —
there is no *only my shim may use this* in a shared namespace") is correct and is
the right decision. Host-side only, one filtering proxy per hole. Keep it. The
mechanism is right too: `test -e $RUN/control.sock` fails inside because the path
is not in the sandbox's mount namespace — deny by default, not a permission
check. But:

- `listenControl` (`control.go:81-91`) does `net.Listen` then `os.Chmod(0600)` —
  a window where the socket carries the umask default. Bind in a 0700 directory,
  or `umask` around the listen.
- The measured configuration has the run dir at **0755**: `run.sh:32` does
  `mkdir -p "$RUN"` before `cmdUp`'s `MkdirAll(0700)`, and `MkdirAll` does not
  chmod an existing directory. Only the socket mode saves it.
- In real snug this lands in `runtimeDir()` (`cmd/snug/identity.go:19-29`), a bare
  `MkdirAll` with **none** of `prepareHostTmpDir`'s guards
  (`cmd/snug/tmpdir.go:58-92`: refuse symlink, refuse foreign owner, refuse
  group/other bits), falling back to `/tmp` with a predictable name when
  `XDG_RUNTIME_DIR` is unset. That directory already holds the ssh-agent proxy
  and podman proxy sockets; this would add **the socket that grants setns into a
  userns with the full subuid map**. Raise the guard to `tmpdir.go`'s standard,
  and put the control socket somewhere `BindSocket` never touches — snug binds
  two of that directory's *siblings* into the sandbox today, and the first person
  who "simplifies" that to a directory bind opens the hole with no visible policy
  change.
- The protocol as written is a general-purpose "setns into any pid and run
  anything" service: `Target` is a client-supplied pid and `DropCaps` a
  **client-supplied boolean** (`control.go:28,317-346`). Deliberate for
  measurement. In the real thing the drop is unconditional and server-side and
  `Target` is validated against sandboxes P1 itself started — otherwise "the
  authority stays in a process the payload cannot name" holds for the payload and
  for nothing else running as your uid.

### 2.4 Does the derived view delete most of `internal/dockerproxy`?

Partly, and in the wrong direction. Two measurements first, both in the
proposal's favour:

- MEASURED: a process in the derived view with CapEff `000001ffffffffff` still
  cannot upgrade a read-only sandbox bind — `mount -o remount,bind,rw /nsd` →
  `permission denied`, rc=32. The access dimension is kernel-enforced, better
  than §6 claims.
- MEASURED: it also cannot mount procfs — `mount -t proc` → `permission denied`,
  even with a full capability set, because mounting proc needs CAP_SYS_ADMIN in
  the userns owning the **pid** namespace, and P1 never creates one. §6 lists
  "the engine needs its own proc mount" as a cost; it is not a cost, it is **a
  blocker whose naive fix the kernel refuses.** The fix is another namespace (P1
  or an engine stage unsharing `CLONE_NEWPID`), which changes the topology,
  changes who reaps conmon, and is unmeasured. **The single most likely place §6
  fails to ship.**

Of `create.go`'s checks:

**Must stay unchanged:** all 28 `refusedHostConfig` keys — devices, cgroups,
sysctls, capabilities, runtime selection, `SecurityOpt` are not mount-namespaced.
`handleVolumeCreate` in full: `o=addr=` NFS/CIFS is a network mount and does not
care about anyone's mount view. `decodeObject`'s case-fold and non-ASCII
refusals, the libpod-schema refusal, `isHijack`-by-path, the endpoint allowlist.

**Two refusals get *more* load-bearing.** `NetworkMode: host` today means the
host's netns; after, it means N — nearly harmless, since the payload is already
there. That tempts a relaxation, and it must be refused anyway: its safety would
then depend on the engine really being in N, and on this host `/usr/bin/podman`
is a distrobox shim that puts the engine back on the host. `UsernsMode: host`
goes from "uid 1000, unprivileged" to "**root in U**, with CAP_SYS_ADMIN over the
sandbox's mounts and over N" — topology-defeating rather than medium. Both need
tests that say *why*, at the new severity.

**Genuinely retired:** the `archive`/`export` refusal becomes defensible to
relax — its stated reason is "serviced by the ENGINE, outside the sandbox, as the
HOST UID, not confined by the container's mount namespace", and under a derived
view it *is* confined. Keep it anyway; the point is that this is the one place
the argument dissolves.

**The mount rule: not a simplification, a substitution — and it inverts.**

- Today: *may bind iff the sandbox can see it*. An allowlist computed from the
  resolved policy, fail-closed against the whole filesystem, able to name the
  path in the refusal.
- Proposed: *may bind anything in the view, except our grafts*. A **denylist**
  over a set snug no longer enumerates. Unknown path → allowed. If the graft list
  is ever incomplete — and `/etc/containers`, `/run`, `/var/tmp` and "the rest of
  the engine's host shape" are §8's own list of unmeasured grafts — the failure
  is open, and it hands over the container store, which is shared across runs
  with the same key.

That inversion is what invariant 2 forbids, and it is why the check *looks*
smaller: the enumeration moved into the kernel, where snug can no longer print it
in `--dry-run`.

**And one check must move, not shrink.** `resolveExisting` (`create.go:590-605`)
resolves symlinks in *snug's own mount namespace*, correct today precisely
because the engine shares it. Under a derived view the engine resolves elsewhere,
so `filepath.EvalSymlinks` in P0 and podman's resolution answer different
questions: a symlink in the writable target pointing at the graft resolves to
nothing on the host and to real container storage in the engine's view. The
redteam finding that motivated that function (`ln -s ~/.ssh $TARGET/link`) does
not go away — it re-aims at snug's grafts, and the check has to run somewhere
snug currently cannot see. Deleting `checkOne` re-opens a closed hole in a new
namespace.

**Bonus finding in current code, independent of the proposal.**
`hostPathVisible` (`create.go:611-626`) returns on the *first* covering mount with
sufficient access, not the deepest — and `p.pol.Mounts` is a `map[string]Mount`,
so iteration order is random. With the demotion pattern invariant 1 documents
(`rw /proj` + `ro /proj/.git`), a writable container bind of `/proj/.git` is
approved non-deterministically, contradicting the "deepest mount covering it
wins" rule the policy layer depends on. No shipped profile creates that shape, so
severity is low — but it is a divergence between the proxy's model and the
policy's, which is what invariant 6 promises cannot happen. (Verified: `Mounts`
is a map; the loop returns on first match.)

### 2.5 Can the interim `include = ["net"]` be removed?

Yes in principle — this proposal is the right shape for it — and **no on this
host today**. Five things must be true first, and only the first is measured:

1. The engine really runs in N. Measured as a *shape* only (E7). §8 admits podman
   was never in it.
2. `podmanClientUsable()` becomes a **hard refusal**. Until then the shim puts the
   engine back on the host with the host's network, and the profile's new claim
   is false in exactly the way `ae848de` was written to stop. **The single most
   dangerous line in the transition: removing the include is safe only if the new
   topology cannot be silently skipped.**
3. Cgroup delegation — `podman info` fails on this box and nothing here improves
   it. Preflight, fatal, naming the fix.
4. The engine's `/proc` problem (§2.4) is solved, or podman does not start in the
   derived view at all.
5. The teardown leg is measured with a real engine. ENGINE-NETNS §4 measured
   conmon **surviving** a Pdeathsig teardown; N now holds the engine and the
   containers, so a surviving conmon keeps N alive. E8 proves the sandbox and
   attached-payload legs only. Until then "orphan netns impossible by
   construction" must be downgraded in prose and the gap written into `TODO.md`.

Then replace `TestPodmanSocketIncludesNetAsAnInterimHonestyFix` with a test that
asserts the *refusal* fires when the topology is unavailable. The include's
absence is not the property that matters; the impossibility of the old path is.

Two teardown remarks. The document proves `PR_SET_PDEATHSIG` is unreliable —
cleared by the privileged re-exec, fired by *thread* exit in Go — and then
depends on `Pdeathsig: SIGKILL` for bwrap, for pasta, for the joiner and for every
attached process. E8 passing is one sample of a race, not a proof. And `release()`
exits on `payloads <= 0 && everRan` while `attach` calls `hold()` unconditionally
— an attach that arrives and fails before any sandbox exists takes the stage down
with it. E11 does not cover that ordering.

### 2.6 What `--dry-run` must print, and what becomes a lie without it

Six lies, in severity order. Today's text is `cmd/snug/dryrun.go:223-300`.

1. **`abstract unix UNREACHABLE (netns-scoped: X11, D-Bus)`** — half-false, and
   dangerous because the reader generalises from it. It must say: the *host's*
   abstract sockets are unreachable; N has its own abstract namespace, shared
   with snug's stage and every container, and writable by the payload.
2. **`isolated — private netns, loopback only, no helper process.`** — "no helper
   process" is false; the stage lives there. And "loopback only" now means a
   *shared* loopback: anything in N bound on `127.0.0.1` is reachable by the
   payload (MEASURED). The sharing must be stated, not just the isolation.
3. **The topology itself.** A second long-lived process, a user namespace holding
   the full subuid range that is an ancestor of the sandbox's own, and a control
   socket at `<path>`, host-only. "No daemon, no service files" is a claim the
   human already believes from the README; a process that outlives the command
   belongs on screen with its lifetime rule.
4. **`snug attach` exists**, who can use it (anything reaching the socket as your
   uid), and — until §4's list is done — that an attached process runs **without
   the seccomp filter**. Printing it is the minimum; refusing to attach without
   the filter is better, because invariant 5 says a capability that silently is
   not there is worse than an error.
5. **The graft mountpoint** in the FILESYSTEM block, marked snug-authored, noting
   that the sandbox sees an empty directory there. A path inside the sandbox that
   no line of `--dry-run` explains is precisely what `--dry-run` exists to
   prevent.
6. **The CONTAINERS block inverts:** containers share *this* netns; a container
   reaches any port the sandbox binds on `0.0.0.0`; published ports land on the
   sandbox's loopback and are refused from the host. And the teardown sentence
   loses its "by construction".

One consequence that is not a print: **after this change the bwrap argv no longer
determines the network posture.** `--share-net` today means "the host's netns" and
requires `--i-know` (`internal/policy/bwrap.go:59-61`); under the supervisor it
means "N", and the two are byte-identical in the argv — the difference is which
process called `fork`. A bug that starts bwrap from P0 instead of P1 with
`--share-net` gives the payload the **host** network, with a green golden-argv
test. "Golden argv diffs are the review artifact" stops being sufficient here, by
construction. The parentage has to be printed *and* asserted behaviourally
(`readlink /proc/<bwrap child>/ns/net == readlink /proc/<stage>/ns/net`, plus the
host-loopback probe with its positive control).

Relatedly: `poc/nsd/stage.go:19-33` copies the pasta closing set verbatim out of
`internal/policy/net.go`. Correct for a PoC, and the comment says so — but if that
copy lands in the tree it is the drift path CLAUDE.md warns about. The real
implementation calls `p.PastaArgs(stagePID)` and changes nothing else.
