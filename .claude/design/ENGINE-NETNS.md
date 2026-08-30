# The container engine inside the sandbox's netns

Investigation, 2026-08-08, by `host-bridge`. Everything below marked with a
command was **executed**; everything else is marked as reasoning.

> **The finding in §0 is CLOSED and its FACT is LIVE — the distinction that
> matters.** The engine runs in the sandbox's own netns N: `internal/stage`'s
> `__inengine` (`EnterEngine`) `setns`es it there and drops it to
> `policy.EngineCapBounding`. So the finding — *a sandbox with no `@net`
> reaches the internet through a container* — is closed, and
> `@podman-socket` no longer includes `net`. The fact every citation relies on
> is permanent: **a container's network IS the sandbox's**, so
> `@podman-socket` hands a container exactly the network the sandbox has and
> nothing more. Measured against a real engine: `@podman-socket` alone, a pull
> fails "network is unreachable"; `@podman-socket -p @net`, the same pull
> succeeds and a container's `wget` reaches the internet; `version`/`info`
> succeeds in both — the engine answers either way, only egress differs.
>
> **§2's per-container-bridge / `podman run -p` measurement is a feasibility
> proof, not the shipped shape.** Containers share N host-mode: no
> per-container bridge, no port publishing, no `CAP_NET_ADMIN` in the engine.

## 0. Why this exists

> **§2 is a feasibility proof, not the shipped shape** — see the banner above.
> Containers share the sandbox's netns in host mode: no per-container bridge and
> no port publishing, because the engine holds no `CAP_NET_ADMIN`. Repeated here
> because a reader who jumps to §2 from a cross-reference never sees the banner.

**This section is the canonical write-up of the finding.** Code and prose across
the repo cite it — `CLAUDE.md`, `base.toml`, `internal/cli/dryrun.go`,
`internal/profile/file_test.go`, `VERIFY.md`, `.claude/design/SECRETS.md` §1.3.
If you arrived from one of those, this is the whole story; §5 is what is left to
do.

**The finding, as measured 2026-08-08.** `@podman-socket` granted **arbitrary
egress with no `@net`**, while `--dry-run` said "No egress. No host loopback."
A container started through the proxy runs on the *host's* engine, so it gets
the *host's* network; the payload reads the response back through
`containers/{id}/logs`. Measured with a positive control — the sandbox itself
could not resolve DNS, and a container reached `https://example.com` anyway.
That is a false guarantee, which is the one failure mode invariant 5 forbids
outright.

**Status, 2026-08-09 — step M-a landed (commit `ae848de`); the channel is still
open.** `@podman-socket` now carries `include = ["sys", "home", "net"]`, so
selecting containers selects egress *visibly*, `--dry-run` renders the egress
block, and a `CONTAINERS` block states that containers run in the engine's netns
and that the pasta guarantees do not cover them. **What changed is that snug
stopped denying it — not that a container can reach less.** Two consequences
worth stating plainly:

- The original measurement is **no longer reproducible on this tree**: there is
  no way to select `@podman-socket` without `@net`, so the "egress without
  `@net`" configuration no longer exists. Reproducing it needs a pre-`ae848de`
  checkout.
- The **host-loopback half is unaffected** and is now the sharper finding: a
  container can port-scan and reach the host's loopback, which is a channel
  `@net` never grants and `--dry-run` still does not describe.

The `net` include is interim and its removal is part of M-b;
`TestPodmanSocketIncludesNetAsAnInterimHonestyFix` makes that removal a
conscious act.

INDEX §4.4 described the fix ("topology A") in the present tense. It was never
implemented — see the banner now on that section.

## 0.1 What this document is for, and where each subject lives

Measurements. §1's kernel fact (you cannot join only the netns) and §3's host
requirements (subuid, cgroup and `$XDG_RUNTIME_DIR` delegation, the distrobox
shim) are preflight requirements today. §2's numbers were taken with plain
`unshare` and reproduced under the real stage topology. §4 is why teardown is
asserted rather than assumed. §5.1 measured the derived mount view.

The **shape** built on top of them is elsewhere: the supervisor topology in
[`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md), the engine's wiring in
[`ENGINE-WIRING.md`](ENGINE-WIRING.md). §5's proposed shape is superseded by
both; read it for its requirements list only.

## 1. The crux: you cannot join only the netns

The owner's steer was "start podman inside the sandbox's netns but outside its
mounts". That is **right about mounts and wrong about the userns**, and the
kernel decides, not podman.

An unprivileged process cannot create a bare netns (`CapEff: 0` here). It must
create one *together with* a userns U, and U then owns N. Joining N afterwards
needs `CAP_SYS_ADMIN` **in U**, which a process in U's parent does not have.
This is exactly why pasta is already passed `--userns` alongside `--netns`.

So the achievable shape is **join U + N, keep the host's uid, cgroup, and a
private copy of the host's mount tree**:

```
$ unshare --user --map-auto --map-root-user --cgroup --mount --propagation private -- podman info
rootless=false driver=overlay oci=runc net=netavark          # works

$ # identical, minus --mount:
Error: configure storage: overlay: failed to make mount private: … operation not permitted
```

The engine needs its **own** mount namespace — a private copy of the *host's*,
never bwrap's. Storage paths stay exactly where they are, which is the useful
half of the owner's idea and the reason no storage exception is needed.

`--propagation private` is load-bearing twice: for overlay, and to stop podman's
per-container nsfs binds (`/run/user/1000/netns/netns-<uuid>`) propagating to the
host, where they would pin netns objects with no process attached. Verified: the
bind exists in the engine's `mountinfo`, and the host's `/run/user/1000/netns/`
stayed empty.

## 2. The inversion works

snug creates U+N first; pasta, the engine and bwrap all join it.

**pasta attaches unchanged.** `--netns /proc/$PID/ns/net --userns /proc/$PID/ns/user`
plus the existing closing set. **No change to `PastaArgs` is needed.**

```
STAGE pid=1169846 netns=net:[4026532441] userns=user:[4026532418]
OUTSIDE: pasta pid=1169859 alive=yes
    2: snug0    inet 192.168.1.120/24
curl: 200
```

**Container network follows N, both directions** — this is the whole point:

```
N offline (no pasta):   CONTAINER-RAN  eth0 10.88.0.3/16  wget: bad address  NET-NO
N with pasta:           CONTAINER-RAN  <!doctype html>…                      NET-YES
```

**Host loopback stays closed from N and from inside a container**, with a
positive control on the host listener:

```
HOST control 127.0.0.1:18099            -> 200
IN-N  127.0.0.1 / gateway               -> REFUSED
CTR   127.0.0.1 / 10.88.0.1 / 192.168.1.120 -> REFUSED
CTR   internet control                  -> REACHED
```

**The bonus DESIGN promised is real** — published ports land on N's loopback:

```
IN-N curl 127.0.0.1:18080  -> HELLO-FROM-CONTAINER
HOST curl 127.0.0.1:18080  -> REFUSED
HOST curl 192.168.1.120:18080 -> REFUSED
```

**Nested pasta — the load-bearing unknown — does not break.** `pasta` inside
`pasta` works; `--network=none` works; offline N degrades gracefully in every
mode (containers run, they have no route). Throughput: host 41.3 MB/s, in-N
29–38 MB/s, container-in-N ≈37 MB/s.

**The proxy does not have to move.** The engine's socket is a *pathname*
AF_UNIX socket — only abstract sockets are netns-scoped — so snug on the host
talks to it directly across the namespace boundary. Verified with `_ping` and
`/version` over the socket from the host.

## 3. What it costs, and where it does not work

**Distrobox — the decisive negative, where `podman` has been replaced.** Not a
distrobox default; a configuration choice this host happens to carry. Where it
holds, `/usr/bin/podman` is
`distrobox-host-exec`, which forwards over a **filesystem** socket. A network
namespace does not touch that at all:

```
$ unshare --user --map-root-user --net -- sh -c 'ip -o link | wc -l; podman info'
ifaces: 1                       # lo only, no route out
engine-hostname=laptop store=/home/u/.local/share/containers/storage
```

From a netns with no route, the shim reached the **host's** engine. So on a
host so configured, topology A puts a *shim* in N, the engine stays on the host, and
the guarantee evaporates while everything looks like it worked. `podmanClientUsable()`
in `internal/cli/podmanshim.go` already performs exactly this detection and is
currently used only for a cosmetic warning. It must become a **hard refusal**,
with a test — per the standing rule that a documented-but-unchecked gate is not
a gate.

> **No longer decisive, 2026-08-13.** Calling this "the decisive negative" read
> the symptom as the cause. The engine is not broken on such a host; only the
> `/usr/bin/podman` *path* is, and `rpm -V podman` shows the package differing
> from its manifest in the symlink alone. A self-contained engine bundle sidesteps
> it entirely — the host's own podman is the engine, and the engine
> then runs rootless inside a netns on this very host, which is what unblocked
> the measurement this section said could not be taken here.
>
> The refusal above is still owed, and for an unchanged reason: where a shim
> *is* what gets invoked, the guarantee evaporates while everything looks like it
> worked. What changes is that the refusal now has an alternative to name — bring
> your own engine — rather than being a dead end.

**Full subuid delegation is structurally required.** A single-uid map fails:

```
… potentially insufficient UIDs or GIDs available in user namespace
  (requested 0:42 for /etc/shadow): Check /etc/subuid and /etc/subgid
```

`--storage-opt ignore_chown_errors=true` gets past storage and no further —
`devpts` then fails, because it needs gid 5 mapped. There is no rootless path
around it. Preflight: `unshare --user --map-auto --map-root-user -- true`, plus
`newuidmap`/`newgidmap` present **with file capabilities** (not setuid).

**Cgroup delegation is a second host-shaped failure.** On this box
`/proc/self/cgroup` reads `0::/../../app.slice/…` — outside the cgroup-ns root —
so `podman info` fails and an API-created container fails at start. Not caused
by N (the CLI works with `--cgroups=disabled --runtime crun`), but it means the
preflight must cover it and that the runtime/cgroup-manager choice can no longer
be "whatever `containers.conf` says".

**`$XDG_RUNTIME_DIR` gets masked.** Root-in-userns podman needs writable
`/run/lock` and `/var/cache`; `/run/lock` does not exist in this image, forcing
`mount -t tmpfs tmpfs /run`, which hides `$XDG_RUNTIME_DIR`. The engine socket
therefore **cannot** live under `/run/user/<uid>` as §8.1 specifies. Move it to
`/tmp/snug-<uid>-<runid>/`.

**The host uid must be carried explicitly.** `--uid 1000` still produces
host-uid-1000 files, but inside the stage `os.Getuid()` returns 0. If snug
re-execs itself, the host uid must be passed, or the sandbox becomes root-shaped.

## 4. Two guarantees change shape

**Teardown is no longer unconditional.** INDEX §4.3 says orphan netns leaks are
"impossible by construction" — true today, because N dies with bwrap. Under
topology A, N holds the engine and the containers, so N lives as long as the
engine does. Measured under `Pdeathsig: SIGKILL`:

```
stage, pasta   -> dead (Pdeathsig fired)
podman, conmon -> ALIVE, ppid=9242
```

conmon **double-forks by design** and reparents out of snug's tree. There is
still no persistent kernel reference (host `/run/user/1000/netns/` stayed
empty), so N is reaped when the last member exits — but the guarantee is now
*conditional on the engine being reaped*, which `lifeline.go`, `reaper.go` and
`reap.go` already do. `reap.go`'s sweep should additionally assert N is gone,
matching on the store path and **never on `comm`** (the `pasta.avx2` lesson).

**Sandbox and containers become network peers.** Not an escalation — both sides
are untrusted-equal and the host is still excluded — but it must be stated:

```
CONTAINER -> 10.88.0.1:9999 (sandbox service on 0.0.0.0) : REACHED
CONTAINER -> 127.0.0.1:9999                              : UNREACHABLE
```

Two things checked that do **not** open: `ss -xl` in N with the engine running
shows **zero** abstract sockets, and the sandbox's own pidns shows 5 processes —
the engine is invisible to it. Both belong in tests.

No capability change for the payload: bwrap already drops caps, so the sandbox
cannot `ip link add` today either. The marginal gain is that N is owned by an
*ancestor* userns, so even a hypothetical regained-caps path cannot reconfigure it.

## 5. The plan — M-a landed, M-b moved

**M-a, done.** `[profile.podman-socket] include = ["sys", "home", "net"]`,
commit `ae848de`. It stopped `--dry-run` lying, and it is interim by
construction: `TestPodmanSocketIncludesNetAsAnInterimHonestyFix` makes removing
it a conscious act rather than a tidy-up.

*The tension it settled, recorded because the trade is still the one being made:*
the include makes `@podman-socket` imply egress, which is honest about today's
behaviour but grants the sandbox itself network it did not ask for. The
alternative was to keep the profile as-is and fix only the `--dry-run` text —
that is, to keep the guarantee narrow on screen while the behaviour stayed wide.
Under M-b `include = ["net"]` becomes **wrong** and must be removed again,
because then `@net` genuinely implies nothing extra and offline goes back to
being the absence of a profile.

**M-b's topology has moved to [`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md).** The six steps
that stood here described a single one-shot `snug __netns-stage` re-exec, and
that shape came from an assumption — that snug must *become* the sandbox — which
`SUPERVISOR-DESIGN.md` §0 removed. Read that document for the topology; do not
reconstruct it from the list that used to be here. What it changes: the stage
holds the namespaces and the engine, the sandbox and later payloads are its
siblings rather than its successors, which is also what makes `snug attach`
possible.

**What carried over unchanged, and is still owed.** These are requirements, not
topology, so they survived the move intact:

1. **Preflight, all fatal, each naming its fix**, before anything starts: a real
   podman binary (`podmanClientUsable`, promoted from warning to refusal — see
   the §3 note on bringing your own engine); `unshare --user --map-auto
   --map-root-user -- true`; `newuidmap`/`newgidmap` with file capabilities; a
   cgroup write probe. **Refuse — never fall back to today's topology**, because
   the difference is invisible to the user. This is invariant 5 applied to a
   whole leg of the design.
2. The engine socket cannot live under `$XDG_RUNTIME_DIR`, which the engine's own
   `/run` tmpfs masks (§3). `/tmp/snug-<uid>-<runid>/` is the replacement.
3. The **host** uid must be carried explicitly across the re-exec, or the sandbox
   becomes root-shaped (§3).
4. `--dry-run` must render the topology: which process owns the netns, and that
   containers share it. Phase 1 has landed a first version of this
   (`internal/cli/testdata/topology.*.txt`).
5. Teardown must be *asserted* rather than assumed, because §4 measured that it
   stopped being unconditional the moment N held the engine.
6. **The engine's mount view must be DERIVED from the sandbox's, and the graft
   that puts host storage into it must not land in the sandbox's own namespace.**
   Measured, with the four-step sequence and the one ordering rule that makes it
   safe, in §5.1.
7. **A graft is not a `Mount`, so nothing that guards `Mount`s guards a graft.**
   `Validate` and `IsShadowSlot` each refuse the equivalent shape one layer up,
   and neither can see this one — measured against a real snug sandbox, §5.1.
   Whatever implements grafts must route them through those checks or reproduce
   them. It must not become a second, unguarded way to put a directory in front
   of the payload.

The current implementation status of all of the above lives in the GitHub
issues and in the supervisor phase documents, not here. This section states what must be true;
it deliberately no longer states when.

**The abuse sentence changes shape rather than shrinking:**

> a hostile process inside the sandbox can run arbitrary code in a container that
> shares the sandbox's network namespace — so it reaches exactly what the sandbox
> reaches, no more: with `@net`, the whole internet, as the sandbox already
> could; without `@net`, nothing. It can also publish a port onto the sandbox's
> loopback, and any container it starts can connect to services the sandbox binds
> on all interfaces. It cannot reach the host's loopback, the host's containers,
> or the host's images.

**Integration test — five assertions, each with a positive control:**
(a) `@podman-socket` without `@net` → container `wget` fails, **while** the same
container succeeds with `@net`; (b) a host listener answers on the host and is
refused from the sandbox **and** from a container; (c) `podman run -p N:80` is
reachable from the sandbox; (d) **adjacent, still closed** — the same published
port is refused *from the host*; (e) `ss -xl` in the sandbox reports zero
abstract sockets with the engine running. Plus a leak test that SIGKILLs snug
and asserts N is gone, matching on the store path.

## 5.1 The derived mount view, and what a graft costs

Everything in this section was **MEASURED on 2026-08-13** on the development host
(openSUSE Tumbleweed, `bwrap` 0.11.2, `pasta` 20260612, Go 1.26, inside a
rootless-podman distrobox), by the supervisor proof of concept — which has since
been deleted ([#49](https://github.com/gomoni/snug/issues/49)). The numbers are
here rather than in a script because a citation that points at a script is worth
nothing once the script is gone.

These measurements are now implemented: `policy.KindGraft` and `p.Grafts` carry
the grafts, `graftKindRules` judges them, `internal/cli/engineview.go` installs
the engine-view ones, and `__inengine` performs the `open_tree`/`move_mount`.
Read this section as the constraints that shape holds to.

### The view can be derived, and the order is the safety argument

§1 established that the engine needs its own mount namespace and §3 that it
cannot simply be the host's. It can be **derived from the sandbox's**, which is
the shape invariant 6 wants: if the engine's view is the sandbox's view, then a
container bind mount can only ever name a path the sandbox can already see, and
the proxy's bind-mount rules stop being a parallel implementation of the policy.

Four steps, and step 3 is load-bearing:

1. `open_tree(AT_FDCWD, src, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE)` on
   the host path, **while the host tree is still visible**. The result is a
   descriptor, and a descriptor does not care about mount namespaces — the same
   property that makes a stray dirfd a complete sandbox bypass (`CLAUDE.md`),
   used here deliberately, from outside, by the process that owns the policy.
2. `setns(CLONE_NEWNS)` into the sandbox's mount namespace. **The user namespace
   is deliberately NOT joined:** the capabilities that make steps 3 and 4 legal
   are the ones the stage already holds in its own user namespace, which is an
   ancestor of the one that owns those mounts.
3. `unshare(CLONE_NEWNS)`, then `mount("", "/", "", MS_REC|MS_PRIVATE, NULL)`.
   **Not optional.** Without it the graft in step 4 lands in the SANDBOX's own
   mount namespace and snug hands the payload the container storage. Everything
   after this point is invisible to the sandbox, and that is the entire safety
   argument.
4. `mkdir(dst)`, then
   `move_mount(tree, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH)`.

Measured by grafting the host's real container store
(`~/.local/share/containers/storage`) into a view derived from a live sandbox.
Six assertions, all green:

| assertion | result |
|---|---|
| the host path is grafted into the derived view | `GRAFT=yes` |
| the rest of the host tree is **not** there — this is the sandbox's view | `HOSTTREE=no` |
| the sandbox's own grants **are** there | the file written on the bind read back |
| `/proc` belongs to the sandbox's pid namespace, so the engine has none | `PROC=no` |
| the graft does **not** propagate into the sandbox | 0 entries under `/storage` inside |
| but the `mkdir` does | the mountpoint exists inside, empty |

The last row is the one to remember: the mount namespace is private, the **tmpfs
superblock is not**, so the destination directory appears inside the sandbox even
though the mount does not.

The negative control was measured in the same run: a child given the stage's own
private copy of the **host** tree stays in the sandbox's netns and *does* see
`~/.ssh` (`HOSTTREE=yes`). So "the engine cannot see the host tree" is a property
of deriving the view, not an artefact of the harness.

**It does not need to be C, and must not be.** The prototype was C only because
`setns(CLONE_NEWNS)` is closed to a multithreaded Go process;
[`NOCGO.md`](NOCGO.md) §3 then measured the way around that — a raw `fork` yields
a child that is single-threaded and owns its own `fs_struct`, the two states the
kernel checks. `internal/stage`'s `EnterEngine` (`inengine.go`) performs these
four steps in Go. `CGO_ENABLED=0` is not negotiable.

### Against a REAL snug sandbox, three of the four grafts collide

A second harness re-asked the same questions against `snug --profile @claude`
rather than against a bare bwrap, because the difference is the whole point: the
prototype's sandbox had a writable tmpfs root and nothing staged in it, while
snug's has a **read-only** root, `/snug/bin` first on `PATH`, and grants
under `/run`. Sixty checks. An earlier plan had called the grafts for
`/etc/containers`, `/run` and `/var/tmp` "the same mechanism repeated". They are
not.

| graft | what happens |
|---|---|
| `/etc/containers` | **cannot even be created** — `mkdir` fails `Read-only file system`, because the destination does not exist in the sandbox and the root is read-only |
| `/var/tmp` | identical, for the identical reason |
| `/run` | **lands** (`mkdir` is `EEXIST`, `move_mount` OK) — and takes `/snug/bin` with it |
| onto a writable grant | **lands**, and the `mkdir` persists **to the host**, because a writable grant is a bind of a host directory. The sandbox sees the empty directory but not the graft's contents |

**The read-only root cannot be forced open.** Remounting the derived root
writable is refused `Operation not permitted` — and that is not missing
privilege: in the *same* invocation a `move_mount` at `/run` succeeded, which
proves the process holds mount authority over that view. The root mount's
read-only flag is **locked**, and a locked flag cannot be cleared in a derived
namespace however much `CAP_SYS_ADMIN` the deriver holds.

**The `/run` graft is the expensive one, twice over.** It lands on top of three
grants, and:

- `PATH` still leads with `/snug/bin`, but **nothing is staged there any
  more** — the staged `claude` stops resolving, because the graft covered the
  very directory `PATH`'s head names. Grafting `/run` silently removes every
  command snug staged. *(Measured against the layout of the day, which put the
  staged directory under `/run`; snug stages at a top-level `/snug/bin` now, so
  the engine view's own `/run` tmpfs — `internal/cli/engineview.go` — does not
  reproduce this. The cost of a graft landing on a directory `PATH` names is
  what survives, and it is the reason the destination is chosen rather than
  inherited.)*
- It brings the host's `/run/user/<uid>` in with it. Measured present in the
  derived view, each against a host control: the **ssh-agent socket**
  (`$SSH_AUTH_SOCK`), the **session D-Bus socket**, the **Wayland socket** and
  the host's **rootless podman socket**. `CLAUDE.md` puts Wayland and D-Bus out
  of scope deliberately and notes the private netns excludes them by
  construction — a `/run` graft is a *filesystem* route that walks straight past
  that reasoning.

### The shadow slot, one layer below `Validate`

This finding is answered by requirement 7 above, and the answer is
`policy.View`: `IsShadowSlot` is a method on a *view* (`envresolve.go`), and
`EngineView()` is the view that includes `p.Grafts`. So the question "can the
payload own this path" is asked of the engine's derived view with the grafts
in it, by the same code that asks it of the sandbox's, rather than by a second
implementation that could drift. What follows is the measurement that made the
requirement.

A **writable** graft at `/run` — or a fresh tmpfs there, which is the wording an
earlier plan used — makes `PATH`'s head writable. Measured with capabilities
dropped, which is the authority a payload has: a process in the derived view
creates `/snug/bin`, writes a `claude` into it, and **that file is what
runs**. The planted file persists on the host side of the graft. The sandbox's
own `/snug/bin` is untouched, so this is the derived view only — and the
derived view is exactly where the engine lives.

`CLAUDE.md` states the rule this defeats: snug adds `/snug/bin` to `PATH`
only when something is staged there, and the directory is in `snugsOwn` so that a
profile cannot mount over it. Measured, that guard holds for a `Mount` and cannot
see a graft:

| shape | what snug does |
|---|---|
| a profile with `ro = ["/run"]` alongside `@claude` | **REFUSED** by `Validate`, naming the collision at `/snug/bin/claude` — a bind snug did not author |
| the same with `@podman-socket` instead | **accepted**: every grant under `/run` there is snug-authored, so nothing is masked |
| a profile with `tmpfs = ["/run"]` and `@podman-socket` | accepted by `Validate`, but `IsShadowSlot` catches it and `--dry-run` prints `/snug/bin IS WRITABLE from inside, which it must never be`. Measured exploitable: the payload wrote `/snug/bin/git` and shadowed the real one |
| the same directory arriving as a **graft**, when this was measured | nothing refused it, nothing warned, and `--dry-run` did not mention it |

The difference was one line: `IsShadowSlot` asked `coveringMount`, and a graft
is not in `p.Mounts`. `CLAUDE.md` already records that this rule was "defeated
by the layer beneath the one it was written about" twice. A graft would have
been the third, and it is the one case that was known in advance — which is
what requirement 7 is for, and why the predicate is a method on a **view** now
rather than a function over `p.Mounts`.
