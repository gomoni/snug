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

---

## 3. The evidence (`sandbox-tester`)

Reproduced `pass=49 fail=0`, then attacked each check. **Four checks are
provably vacuous — they PASS on a sandbox and an attach that never happened.**
That is the `pasta.avx2` shape this project's own culture warns about, in the
run that was supposed to have learned the lesson.

### 3.1 The exit-code collapse — E3 and E6

`nsdjoin` forwards the exec'd command's exit code verbatim, but `main.go`
collapses **every** client-side failure — bad target pid, "no sandbox running",
refused setns, JOIN-FAIL, and a failure to dial at all — to `os.Exit(1)`. So
"the file does not exist" and "the attach never happened" are indistinguishable
at the shell, and both are what these two checks read as success:

```
run.sh:84   want "1" "$(inbox test -e "$HOME/.ssh"        >/dev/null 2>&1; echo $?)"
run.sh:166  want "1" "$(inbox test -e "$RUN/control.sock" >/dev/null 2>&1; echo $?)"
```

Reproduced with a stage up and **no sandbox ever started**:

```
$ nsd ctl "$R" attach 0 1 /usr/bin/test -e "$HOME/.ssh" >/dev/null 2>&1; echo $?
1                          # run.sh prints PASS "it does NOT see an ungranted host path"
$ nsd ctl "$R" attach 0 1 /usr/bin/test -e "$HOME/.ssh"
nsd: dial unix …/control.sock: connect: invalid argument
```

Note what the second line is: in that run the socket path was too long for
`sockaddr_un`, so the client never reached the stage at all. **Total
infrastructure failure scores as a security guarantee.** E3 also has no positive
control — a working attach querying `/this/path/is/nowhere/on/earth` produces the
identical exit 1.

### 3.2 The empty-readlink collapse — E1 and E2

`run.sh:53` and `:65` compare namespace ids with a hand-rolled `[ a != b ]` and
never check that either `readlink` succeeded. `readlink` on a nonexistent
`/proc/<pid>/ns/*` prints nothing and fails silently inside `$(...)`, and an
empty string is `!=` any real namespace id — so a stage or sandbox that never
started reads as "PASS, it has its own namespace."

Demonstrated through the unmodified check expressions, with only a mundane
failure (the bind directory does not exist — no PATH tampering, no binary
replacement). The two E2 assertions sit side by side, share the same broken
precondition, and disagree:

```
  FAIL  sandbox netns is the stage's netns (want 'net:[4026533003]', got '')
  PASS  sandbox has its own user namespace
```

The one that compares against a known value fails correctly; the one that only
asserts inequality lies. That is a check-construction bug, not a one-off.

### 3.3 The precondition nobody checks

`up()` calls `ctl sandbox >/dev/null` and never inspects `$?` — used by E2, E3,
E6, E9 and E10. A `startSandbox` failure (bad bind dir, bwrap missing, the 5s
`waitReady` timeout under load) degrades silently into "proceed with `$INIT`
empty" instead of aborting the section. This is the precondition that trips 3.2,
and it is also how a *timing flake* turns into a false PASS rather than a red.

**So `run.sh`'s own header boast — "Each check has a positive control: a negative
result on a sandbox that never started is not a result" — is false for at least
four checks.** The headline `pass=49 fail=0` is inflated by those four, and
possibly more under specific failure interleavings.

### 3.4 Portability of the "kernel facts"

Two of the seven are misfiled, and one piece of evidence is an accident of this
box:

| # | claim | classification |
|---|---|---|
| 1 | re-exec required after the uid map is written | **kernel** — `capabilities(7)` execve algorithm |
| 2 | re-exec clears `PR_SET_PDEATHSIG` | **kernel** — `secureexec` whenever new permitted ⊄ old permitted |
| 3 | bwrap creates TWO user namespaces; setns order is the trick | **bwrap implementation detail.** Reconfirmed present in 0.11.2 with *and* without `--uid`/`--gid`, so it is not conditioned on nsd's invocation — but it is bwrap-specific hardening, not a kernel guarantee, and it needs re-verification on every bwrap upgrade. To its credit it fails loudly (`JOIN-FAIL setns: Operation not permitted`), not silently. |
| 4 | the joiner needs C (single-threaded caller for `setns(CLONE_NEWUSER)`) | **kernel** — `setns(2)`; the Go-runtime framing is a correct corollary |
| 5 | joining a userns grants a full capability set | **kernel** (`user_namespaces(7)` ancestor rule) — but the hex literal `000001ffffffffff` is `cap_last_cap`-dependent (40 on this kernel), and "`/usr/bin/newuidmap` on this host has a file capability" is distro packaging; many ship it setuid-root instead. The underlying danger generalises; the artifacts cited do not. |
| 6 | `--json-status-fd` reports the pid before the mounts are ready | **bwrap implementation detail** — internal execution order, can change between releases |
| 7 | `/proc/<pid>/status` renders uids in the reader's userns | **kernel**, stable |

The hex-literal dependency fails *safe* (false red, not false green), but it
means "49 checks" is not a portable number as written.

### 3.5 Claims with no check behind them

- §3 fact 5's "the exec'd payload's effective set is empty" — E4 measures the
  **attach** path's capabilities and never the sandbox's own init or payload.
- §6's "podman will not start without one [a proc mount]" is stated as fact in
  the body; §8 self-corrects that no real podman was ever exercised, but that
  caveat does not travel with the §6 sentence.
- §9's "without `everRan` the stage exits during its own startup" — an asserted
  implementation necessity with no counterfactual test. There is no `_test.go` in
  `poc/nsd` at all.
- §5's "sandbox and containers become network peers" — inferred from E5/E7's
  egress results, never directly measured; no second instance was ever run to
  probe reachability between them.
- §4's entire "must still reproduce" list. The doc is honest that these are
  unimplemented, so this is unmeasured rather than false.

### 3.6 The pasta copy protects nothing

`poc/nsd/stage.go:19-33` is a hand-typed literal, separately maintained from
`internal/policy/net.go:184-239` (which computes `-t` via `publishSpec()`, has a
conditional `--dns-forward`, and optional `-a`/`-n`/`-g`/`--mtu`). The comment
says "copied verbatim", and E5 passing proves **the PoC's own copy** is safe. If
someone weakens `internal/policy/net.go` tomorrow, `run.sh` still reports
`pass=49`. Zero regression protection for the production code.

### 3.7 What survives

Genuinely sound — real positive controls, content-based comparisons, no
exit-code collapse: **E5** (egress works, host loopback refused, in both the
namespace and the sandbox, with a working positive control before the negative);
**E6's hole-confirmation half** (distinctive marker string, content-matched —
not the "cannot connect" half); **E8** (teardown on SIGKILL, with a positive
control, and the mechanism checks out on code reading); **E9** (shared
tmpfs/pidns, content-based); **E11** (not-a-daemon teardown, positive control
before the negative). And the core two-userns/setns-ordering finding is real and
was independently reconfirmed — only its filing is wrong.

---

## 4. The attack (`redteam`)

Ran the PoC green, then attacked it with live sandboxes. Three confirmed, ranked.

### F1 — P1's lifeline fd leaks into every payload, primary and attached

SUPERVISOR §4 says attach hands in "**No socket, no listener, no fd handed in.**"
False, and not only for attach. Exact inode match:

```
LIFELINE: P1 fd5 = pipe:[480455]
payload  fd5 = pipe:[480455]      # inside the sandbox, attached payload
PID2 (sandbox-init) /proc/2/fd/5 -> pipe:[475973]   # == P1 fd5, primary payload
```

`stage0()` clears CLOEXEC on fds 4 and 5 so they survive `syscall.Exec` into
`stage1` — needed exactly once. `stage1()` never restores it on fd 5, which stays
open for `watchLifeline`, so every subsequent child of P1 inherits it: `bwrap`
from `startSandbox`, `nsdjoin` from `attach`.

**Impact today: low.** fd 5 is the *read* end (`lr-x`); a payload cannot forge a
write end of an anonymous pipe, so it cannot spoof P0's death, and EOF teardown
still fires (verified). **The mechanism is the finding.** The moment P1 holds any
authority-bearing fd without CLOEXEC — a future secrets-broker socket, or a host
`open_tree`/dirfd for the graft — that fd lands in every sandbox by this same
path, with no new code and no visible change.

Narrowest fix: `fcntl(5, F_SETFD, FD_CLOEXEC)` in `stage1()` right after the
handshake. This is the same finding `host-bridge` reached from the other
direction (§2.1), and the two together say the real fix is `sealInheritedFDs`
running in P1 before every fork, not a one-line patch.

*Abuse sentence: a hostile process inside the sandbox holds an open host-side
pipe descriptor it was never meant to see, and any future P1 fd added without
CLOEXEC reaches it the same way.*

### F2 — the shared-netns exposure is bidirectional; the stated rule covers half

E6 tests the payload as a *client* reading a host-side helper's abstract socket.
The payload works as a *server* too: a host-authority P1 child that **connects**
to an abstract name or a loopback port gets the payload's impostor.

```
# payload binds \0snug-agent and 127.0.0.1:19099, serves "IMPOSTOR-PAYLOAD-SERVED-THIS"
ABSTRACT MITM: IMPOSTOR-PAYLOAD-SERVED-THIS
TCP MITM:      IMPOSTOR-PAYLOAD-SERVED-THIS
```

Plain loopback is reachable payload→helper in both protocols (`TCP REACHED:
SECRET-P1-TCP-LOOPBACK`, `UDP REACHED: SECRET-P1-UDP-LOOPBACK`), and the payload
can enumerate host-authority traffic metadata via sock_diag:

```
ss -tan (inside sandbox): CLOSE-WAIT 192.168.1.120:38948 172.66.147.243:80
                                            # P1 helper's outbound to example.com
```

SUPERVISOR's rule — "no process in N may bind an abstract socket" — does not
cover a snug process *connecting* to an abstract name or a loopback address,
where the payload is the binder and therefore the impersonator; nor the engine's
own netns helpers, which the engine will run in N. ENGINE-NETNS §4 frames
"sandbox and containers are network peers" as untrusted-equal and does not say
that a **host-authority** process talking loopback in N is impersonable.

Stronger rule, and it should be tested rather than written: *no snug or
host-authority process in N may bind **or connect to** a loopback address or an
abstract name; all snug IPC in N is a pathname AF_UNIX socket in a directory the
sandbox does not mount.* (`host-bridge` reached the same rule from the listening
side — §2.2. Together they are one rule with two halves, and the doc currently
has neither.)

*Abuse sentence: a hostile payload impersonates any snug or engine service that a
host-authority process reaches by loopback address or abstract name in the shared
netns.*

### F3 — co-resident payloads are one trust domain

The "several payloads in one sandbox" feature (§5) and a P1 secrets broker (§5)
are dangerous together. Same uid, shared pid and mount namespaces:

```
victim pid=8
read victim /proc/8/environ -> INJECTED_SECRET=host-token-xyz
```

By design — attach joins the sandbox's pidns and there is no per-payload
isolation. The doc notes a joiner must clear its environment and must not leak
P1's; it does not say that a *legitimately* per-payload injected secret, in the
environment or in any uid-readable file, is readable by every sibling.

The fix is a design constraint, not code: never deliver a secret to one payload
by environment or uid-readable file. A broker in P1 must mediate per request over
a channel a sibling cannot name — or the feature documents that all co-resident
payloads share every grant and every secret.

### Attacks that failed — defences that held

Worth pinning as positive regressions so they cannot silently regress:

- **Netns reconfiguration.** Payload has `CapEff=0`, `CapBnd=0`, `NoNewPrivs=1`;
  `ip link add` → EPERM; binding `127.0.0.1:53` and `0.0.0.0:80` → EACCES. The
  netns is owned by P1's userns and the payload sits in a grandchild with no
  authority over it.
- **Primary-payload escalation.** `/proc/1/status`: `NoNewPrivs=1`, `CapEff=0`,
  `CapBnd=000001ffffffffff`. The full bounding set is inert under nnp=1, and
  `getcap -r /usr/bin /usr/sbin` found no file-capability binary in the bound
  `/usr`. `mount` → "must be superuser."
- **Graft symlink/TOCTOU.** The payload pre-planted `/storage -> /work` on the
  shared tmpfs; the graft's `move_mount` onto the symlink returned **EINVAL** and
  leaked no host storage. The `unshare` + `MS_REC|MS_PRIVATE` before `move_mount`
  holds, and the graft does not propagate into the sandbox.
- **Undropped attach.** Reachable only through the control socket, which is not
  in the sandbox's mount namespace; the payload cannot request `DropCaps=0`.
- **SIGSTOP teardown pin.** A SIGSTOPped attached process does not keep the stage
  alive: the pidns collapse SIGKILLs stopped members, `nsdjoin`'s `waitpid`
  returns, the count releases. The lifeline overrides regardless.
- **Reaching P1.** Invisible to the payload — separate pidns; only `bwrap` (1)
  and `sandbox-init` (2) appear inside.

One asymmetry re-confirmed rather than counted as new: attached processes have
`Seccomp: 0`, so **until that is written, an attached payload is *less* confined
than the primary** — ptrace, nested userns and keyctl are available to it among
siblings at the same uid. That is the sharpest statement of the §1.5 downgrade.

---

## 5. Consolidated verdict

Four agents, four lenses, run independently. They converged on three things
without being able to see each other's work, which is the strongest signal in
this document:

- **The descriptor class.** `redteam` found it by inode from inside;
  `host-bridge` found it by reasoning about what P1 *is*. Same fd, same
  conclusion: `sealInheritedFDs` has to move into P1 and run before every fork.
- **The shared-netns rule is a third of a rule.** `host-bridge` found the
  listening half (loopback is as exposed as `0.0.0.0`; the payload can squat a
  name first); `redteam` found the connecting half (a host-authority process that
  dials an abstract name in N gets an impostor). Neither half is in the doc.
- **The engine leg is where this ships or does not.** `sandbox-policy` reached it
  from the reference count (the engine holds none, so the stage exits under it);
  `host-bridge` reached it from the kernel (`mount -t proc` is refused even with
  a full capability set, because P1 owns no pid namespace); `sandbox-tester`
  reached it from the evidence (§6's "podman will not start without one" is
  stated as fact, and §8 admits podman was never run). It is the same gap seen
  three ways.

### 5.1 What survives

The model works, and these parts are right for stated reasons rather than by
luck. Nothing below was successfully attacked:

- The topology itself: P1 holds N, the sandbox is its child, the engine is a
  **sibling** of the sandbox and not its parent.
- **No control socket inside the sandbox**, and its argument — any socket a shim
  inside can reach, the payload can reach. Enforced by absence from the mount
  namespace, not by a permission check.
- The lifeline pipe over `PR_SET_PDEATHSIG`, and the reason (`secureexec`).
- The `setns` ordering, and the two-user-namespace discovery behind it.
- `unshare` before `move_mount`, with its negative test — and the graft survived
  a symlink-planting TOCTOU attack (`move_mount` onto a payload-planted symlink
  returned EINVAL).
- §9's lifetime decision: P1 exits with its last payload, and does not become a
  daemon.
- The payload's own confinement: `CapEff=0`, `CapBnd=0`, `NoNewPrivs=1`, no
  file-capability binary in the bound `/usr`, no netns reconfiguration, and a
  SIGSTOPped attached process does not pin teardown.
- Host loopback stays closed, measured in both N and the sandbox, with a live
  positive control.

### 5.2 What must change before this ships, ranked

1. **`sealInheritedFDs` in P1, before every fork** — not the one-line CLOEXEC fix
   on fd 5. The fd 5 leak is harmless; the next one will not be. (§2.1, §4-F1)
2. **The netns rule, in its full form**, plus the ordering guarantee that snug's
   helpers bind before the payload exists. (§2.2, §4-F2)
3. **The engine's `/proc`.** Refused by the kernel in the derived view. The fix
   is another namespace, which changes who reaps conmon. Unmeasured. (§2.4)
4. **The graft becomes a policy object** with provenance, a masking check over
   the derived view, and a `--dry-run` rendering — or invariant 1 has an
   unbounded exception. (§1.1)
5. **Attach is compiled from the policy**, not hand-written: seccomp, the
   environment, `safeStdio`, the caps drop. Until then an attached payload is
   *less* confined than the primary. (§1.5, §1.8)
6. **The proxy keeps its allowlist.** The derived view changes its vocabulary
   from `Mount.Host` to `Mount.Guest`; it does not license replacing "may bind
   iff the sandbox can see it" with "anything in the view except our grafts".
   (§1.2, §2.4)
7. **The lifetime rule fires on the startup-failure path**, and teardown asserts
   on the namespace object rather than a process count. (§1.4)
8. **`--dry-run` grows a topology block**, and the golden discipline extends to
   the stage argv, the derived view and the attach spec — because after this
   change the bwrap argv **no longer determines the network posture**.
   `--share-net` is byte-identical whether it means N or the host's netns; the
   difference is which process called `fork`. (§1.8, §2.6)
9. **`/proc/self/exe` instead of `$NSD_SELF`**, and a shipped path for the
   joiner. (§1.6)
10. **The subuid delegation becomes conditional** on the engine being wanted.
    (§1.3)

### 5.3 What the transition owes `@podman-socket`

Removing the interim `include = ["net"]` is safe only if the old path cannot be
silently taken. Five preconditions (§2.5), of which the dangerous one is
`podmanClientUsable()` becoming a **hard refusal**: today a fallback is honest,
because the include says egress is there. After the include goes, a fallback
means the sandbox says offline while a container reaches the internet — the
original measured bug, restored, by a code path whose only trigger is a host we
cannot test on. And `TestPodmanSocketIncludesNetAsAnInterimHonestyFix` should be
replaced by a test of the *refusal*, not deleted: the include's absence is not
the property that matters, the impossibility of the old path is.

### 5.4 Regressions this owes `sandbox-tester`

Every confirmed finding, per the project rule — and the failed attacks too, so
the defences cannot silently regress:

1. No descriptor in the primary or an attached payload resolves to an inode also
   open in P1.
2. A host-side helper that connects to an abstract name or a loopback port in N
   reaches snug's service, not the payload's; and no snug helper listens on any
   IP port in N.
3. Two attached payloads: B can read A's environ today, so any per-payload-secret
   design must break this test.
4. `move_mount` onto a payload-planted symlink is refused.
5. The primary payload's `NoNewPrivs=1`/`CapEff=0`, and no file-capability binary
   in the bound `/usr`.
6. A SIGSTOPped attached process does not pin teardown.
7. The stage exits when `startSandbox` fails — the `everRan` path.

### 5.5 Acted on already

`run.sh`'s four vacuous checks are fixed (commit `4c1b94c`): negatives are
markers the payload emits, namespace comparisons refuse an empty side, and the
`ctl sandbox` exit code is checked. Verified in both directions — `pass=51
fail=0` with a working sandbox, and each repaired check fails against the
condition that used to pass it. The two rules are stated at the top of the file.

SUPERVISOR.md §4, §5 and §9 are corrected in the same pass: "no fd handed in" is
withdrawn and replaced with what was measured, the netns rule is restated in its
full form with its own weakness named, the secrets-broker bullet carries its
constraint, and the abuse sentence now says loopback, squatting, the socket
tables, the inherited descriptor and the privileged ancestor userns.

Everything else in §5.2 is a design debt, not a fix, and belongs in `TODO.md`
with a severity the moment this stops being a proof of concept.
