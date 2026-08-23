# The supervisor stage — the design, as built

`@net` no longer runs one process. snug forks a second long-lived process, the
**stage**, whose job is to create the sandbox's network namespace, pin it,
*leave* it, and fork bwrap back into it. This document is what was implemented
and why. It is written in the past tense on purpose: earlier drafts of this
design described a system that was then built differently, and a design document
that describes the intention rather than the artifact is how a reader ends up
believing in a control socket that does not exist.

Everything marked **MEASURED** was executed on **2026-08-13**, on the development
host — openSUSE Tumbleweed, `bwrap` 0.11.2, `pasta` 20260612, Go 1.26, inside a
rootless-podman distrobox. Everything else is reasoning and is marked as such.

The original measurements were taken by a throwaway proof of concept, `poc/nsd`:
its own Go module plus four C helpers and three harnesses, imported by nothing
that shipped. **It has been deleted**
([#49](https://github.com/gomoni/snug/issues/49)), because what it prototyped
shipped as `internal/stage`, and a second unbuilt copy of the same `setns` logic
beside the real one is a divergence waiting to happen — one that `./...`,
`go vet` and `make gate` could not see, because it was a separate module.

Its results did not go with it. `run.sh` was 51 checks and last recorded
`pass=51 fail=0`; `run-netns.sh` was 42 checks, green in three identical
consecutive runs; both are distilled into §1 below. A third harness,
`run-graft.sh`, measured the derived mount view against a **real** snug sandbox,
and its sixty checks are carried in [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §5.1.

*Read the counts carefully, because one of them moved.* `run.sh` read `pass=49`
until a review found that four of those checks passed on a sandbox and an attach
that **never happened** — the `pasta.avx2` shape from `CLAUDE.md`, in the script
whose own header claimed the property. The count rose because nothing was
actually broken; the point is that it could not have told us if it had been. Two
rules came out of it and every measurement below obeys both: never assert an
exit code as a negative — assert a MARKER the payload emitted — and never
compare two namespace ids without refusing the empty case.

**Why this exists at all** is [`ENGINE-NETNS.md`](ENGINE-NETNS.md): a container
started through `@podman-socket` runs on the *engine's* network, not the
sandbox's, so the sandbox's network guarantees do not cover it. Moving the engine
into the sandbox's network namespace fixes that, and doing so requires something
other than bwrap to own the namespace. That engine move is a later phase; this
document covers the topology change that makes it possible, which shipped on its
own with the explicit contract that **it adds no user-visible capability**.

---

## 0. The correction that opened this up

ENGINE-NETNS §1 is right that you cannot join *only* a network namespace: an
unprivileged process must create the netns together with a user namespace, and
joining afterwards needs `CAP_SYS_ADMIN` in that user namespace. That fact is
unchanged and is why pasta is already passed `--userns` alongside `--netns`.

What was wrong was the shape it imposed on the answer. "No daemon, no service
files — just execute a binary" was being read as **one process**, so every design
had to end with snug *becoming* the sandbox. Nothing in the invariants says that.
Invariant 4 says *no root, no setuid, no daemon*, and spells out what it defends:
"helpers are children that die with the sandbox and leave nothing behind".

`tmux` is the model: no unit file, no socket activation, no root, nothing
surviving a reboot — and still a process that outlives the command you typed.
The distinction that matters is **who owns the process**, not how many there are.

---

## 1. What was measured before anything was written

| fact | status |
|---|---|
| A process can `setns` back into a netns it left; children forked through a setns shim land in it | **MEASURED** 2026-08-13, this host: 42 checks, `fail=0`, in three identical consecutive runs. Every section ran twice — once with the move off, which is the pre-stage topology and the positive control, and once with it on — so each payoff was shown absent before it was shown present |
| `unshare(CLONE_NEWNET)` is **per-task**, not per-process. One thread moves; the others stay; `/proc/self/ns/net` names the THREAD GROUP LEADER and so reports the OLD namespace | **MEASURED** — 1 of 11 threads moved. This is now a CLAUDE.md environment fact, because it is a scheduler-dependent false green waiting to happen |
| The only join point at which a multithreaded Go process moves as a WHOLE is `execve` immediately afterwards, on a `runtime.LockOSThread()` thread | **MEASURED** — after the `__stage-serve` re-exec, 0 of 6 threads remained |
| The pinned descriptor on N must **not** be CLOEXEC at the moment of that exec, and is marked CLOEXEC immediately after | **MEASURED** — doing it the obvious way destroys the only reference to N |
| pasta **refuses** `--netns /proc/self/fd/<n>`: it drops privileges before opening the path | **MEASURED** (`Permission denied`) |
| pasta aimed at `/proc/<stage>/fd/<n>` works: egress from N and from the sandbox, host loopback refused | **MEASURED** |
| Aiming pasta at `/proc/<stage>/ns/net` *after* the move succeeds **silently** and attaches to the wrong namespace | **MEASURED** — the failure mode that makes the descriptor form mandatory rather than stylistic |
| With the stage outside N, the only processes in N are bwrap, its child and the sandbox's init. No supervisor process, no listening socket | **MEASURED**, with positive controls |
| N dies with the stage when pinned only by a descriptor: after `kill -9`, stage, sandbox and both namespaces are gone | **MEASURED** (positive control: 3 processes in N before the kill) |
| A single-uid map in U (`0 <hostuid> 1`) is enough for `bwrap --uid 1000` to give the payload uid 1000 with host-uid-owned writes | **MEASURED against snug's real `BwrapFlags`**, not a hand-built invocation — see §4 Step 0 |
| pasta's forwarding side is outside N | **INFERRED** from egress working. pasta sets itself non-dumpable, so no test can sweep it. Any test claiming "only bwrap and the init are in N" must say this rather than imply coverage it does not have |
| `PR_SET_PDEATHSIG` **survives** the `__stage-setup → __stage-serve` re-exec | **MEASURED** (round 3). Capabilities do not widen at that exec — the stage already holds a full set in U from the moment it creates the userns — so there is no `secureexec` and the signal is preserved. An earlier draft asserted the opposite; see §3.5 |

---

## 2. The topology, as built

```
P0  snug                          host userns, host netns, host mount tree
 │   resolves the policy, builds every descriptor the sandbox needs, clones P1,
 │   writes its uid map, runs pasta at N, waits for the interface, THEN asks for
 │   the sandbox. Holds the lifeline and supervises.
 │
 ├── pasta --netns /proc/<P1>/fd/<n> --userns /proc/<P1>/ns/user
 │        started SECOND, while N still has no process in it at all
 │
 └── P1  snug __stage-setup → __stage-serve   THE NAMESPACE HOLDER
      │   U: user ns, ONE uid mapped (root inside)
      │   N: network ns, private — created by the clone, PINNED by a descriptor,
      │      and then LEFT: after __stage-serve, P1 is in a fresh empty netns
      │   + own mount ns (MS_REC|MS_PRIVATE)
      │   + an AF_INET socket CREATED IN N, kept: how it answers "is snug0 up?"
      │     after it has left N (§7)
      │   NO control socket on any filesystem. NO listener.
      │
      └── snug __innetns <fd> bwrap ...       a setns shim, one execve deep
           │                                  forked LAST, once the network is up
           └── bwrap (in N)                   THE SANDBOX, unchanged in every respect
                └── payload
```

**Read the two names as two axes.** `P0/P1` are distinct *processes*.
`__stage-setup`/`__stage-serve` are successive *exec images of P1* — same pid
throughout. `__innetns` is a third exec image but in a child. An earlier
spelling numbered the images `__stage1`/`__stage2`, which read as P1 and P2 and
meant neither.

**A bare `snug <dir>` starts no stage.** The stage exists only where something
other than bwrap must own the sandbox's namespaces. Ordinary offline runs and
`--i-know` host-network runs take the previous code path byte for byte. That is
deny-by-default applied to snug's own process tree.

*When this shipped that meant `NetEgress` alone.* **Tier B**
([#63](https://github.com/gomoni/snug/issues/63)) added the second trigger:
selecting a container engine also needs a stage — for the full delegated subuid
range and the private mount namespace the engine forks into — so an **offline**
`@podman-socket` run starts one too, with no pasta and an N holding only
loopback. `Topology.NeedsStage()` is the live answer; §3.2 and §3.6 below record
the phase-1 reasoning, not today's trigger set.

*The abuse sentence for the whole topology, and it is on screen in `--dry-run`:*

> a hostile process inside the sandbox gains no new reach — the stage is in
> neither its network namespace nor its pid namespace, binds nothing it can
> name, and holds no descriptor it can open — but its user namespace now has a
> **privileged ancestor** (U, root-in-userns with `CAP_SYS_ADMIN` over N and over
> the sandbox's own mounts) that lives for the whole run, so a userns-escape bug
> is worth more here than it was.

---

## 3. The decisions, and what each one overruled

### 3.1 The bwrap argv under the stage: enumerate, do not reuse `--share-net`

Under `Topology.Netns == NetnsStage`, `BwrapFlags` emits
`--unshare-user-try --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try`
and **omits `--unshare-net`**. Every other topology emits `--unshare-all` exactly
as before, and `--share-net` is still emitted **only** for `Net.Mode == NetHost`.

The rejected alternative was to reuse `--unshare-all --share-net` for the stage,
on the sound objection that an enumeration is a keep-list and a bwrap that grows
a namespace type would silently stop unsharing it. It lost for two reasons it
cannot answer: it puts **two meanings on one flag** — `--share-net` today means
"the host's network namespace, and the CLI demanded `--i-know`" — so no grep, no
golden and no future review could distinguish the most dangerous network posture
snug can produce from an ordinary one; and it would force the edit of a test
whose entire content is "host mode is the only mode that inherits a netns", when
nothing about host networking changed.

The keep-list objection is answered rather than dismissed, by a test that parses
`bwrap --help` for every `--unshare-<name>` and fails if the stage set does not
cover all of them except `net`. **Known weakness:** that test currently compares
against a hardcoded literal set, so deleting a flag from `bwrap.go` leaves it
green and is caught only indirectly by two goldens. It is
https://github.com/gomoni/snug/issues/31.

The spelling is deliberately `-try` for `user` and `cgroup`, matching what
`--unshare-all` expands to, so the stage path introduces no new failure mode. The
strict spellings would be better — a host with unprivileged user namespaces
disabled currently gets none, with no error — but that is a live defect on the
non-stage path too, and fixing it inside a phase whose contract is "adds and
removes nothing" is how a user-visible regression gets smuggled in. It is
https://github.com/gomoni/snug/issues/24.

### 3.2 The stage runs only when it is needed

`Topology.NeedsStage()` is derived. When this shipped it was true exactly when
`Topology.Netns == NetnsStage`; Tier B added `Subuid == SubuidFull` as a second
disjunct (§2's note). The rejected alternative started a stage for
every run — cloning without `CLONE_NEWNET` for host mode — so that there would be
one process shape to reason about. It loses because an unconditional stage hands
every default `snug <dir>` a privileged ancestor user namespace in exchange for
**no capability at all**.

Consequence, written down rather than discovered: `NeedsStage()` is **not**
monotone over the `NetnsOwner` lattice — false at the floor, true in the middle,
false at the top. Raising `NetnsStage → NetnsHost` removes the stage while
strictly *widening* the grant. That is correct. The lattice orders reachability;
the stage is a construction detail, not a grant.

### 3.3 No control listener at all

The channel between snug and the stage is an inherited
`socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC)`. No pathname, no listener, no
run directory, no `accept` loop — nothing for anything running as your uid to
connect to. It carries at most two requests — "is the network up?" and then
"start the sandbox" — and the stage exits after the second. The stage REFUSES a
"start" that was not preceded by a successful "netready", so the ordering that
keeps a payload from existing before its network is enforced by the stage
itself and not only by the order of calls in snug.

The **protocol** is written even so — strict decoder, typed request struct,
default-deny dispatch, and a descriptor-budget check on **both** sides because
the two ends are different trust positions — because that is the enforcement
point a later phase inherits, and bolting it on under schedule pressure is how
it ends up absent. Only the listener is deferred.

What the channel *would* grant a holder, which is why its unreachability is the
load-bearing property: one `start` request makes the stage `execve` an arbitrary
path as **uid 0 with a full capability set in U**, inside N. Verified unreachable
four ways — the payload's fd table is exactly `0,1,2`; a socket cannot be
reopened through `/proc/<pid>/fd` at all (`ENXIO` — and note that after issue
#115 this is the *only* surviving example of that: a memfd, a pipe, a deleted
file and an `O_TMPFILE` file all DO reopen through procfs, measured, so the
argument here works because the channel is a socket specifically, not because it
is "not a regular file"); the stage is not in the
payload's pid namespace so there is no pid to name for `pidfd_open`; and the
receive path uses `read`, never `recvmsg` with a control buffer, so the channel
cannot deliver a descriptor even to a peer that sends `SCM_RIGHTS`.

The third of those four — no pid to name — is a fact about pid-namespace
visibility and holds regardless of the seccomp filter. Issue #23's fix (denying
`pidfd_getfd`, `internal/sandbox/seccomp.go`) adds a second, independent lock on
the same door for when Phase 2 actually opens a listener: even a payload that
somehow *did* have a pid to name for `pidfd_open` (a same-pid-namespace
listener, which nothing here is yet) could not then steal the accepted
connection's descriptor out of another process's table. Two locks, two
different reasons they hold — namespace invisibility today, a denied syscall
whenever that stops being true — rather than one fact doing both jobs.

*`--dry-run` says all of this.* It used to print `control none (no socket, no
listener, nothing to connect to)`, which was true in its second half and false in
its first — and "no socket" is the half a reviewer would use to decide there was
nothing here to audit.

### 3.4 `PastaArgs` takes a target, not a pid

```go
type PastaTarget struct {
	NetnsPath  string // what pasta opens for --netns
	UsernsPath string // what pasta opens for --userns
}

func PastaTargetChild(childPID int) PastaTarget          // /proc/<pid>/ns/{net,user}
func PastaTargetStage(stagePID, netnsFD int) PastaTarget // /proc/<P1>/fd/<n> + /proc/<P1>/ns/user
```

An earlier plan said the signature could stay as it was and a caller would just
pass the stage's pid. Measured otherwise, three ways: after the move
`/proc/<P1>/ns/net` is the stage's own *empty* namespace and pasta attaches to it
silently; handing pasta the descriptor as `/proc/self/fd/<n>` is refused, because
pasta drops privileges before opening it; and **no single process is both in N
and in the user namespace that owns N** — bwrap's child is in N but its userns is
a descendant of U with no authority over it. One pid cannot produce both paths,
so it must not be asked to.

The closing set — `--map-host-loopback none -t none -u none -T none -U none` —
does not move and is not reformatted. `internal/policy` remains the sole author
of the pasta argv (invariant 6). The price of that is worth naming: `PastaTargetStage`
encodes a *stage implementation detail* inside the pure layer, so "policy knows
nothing about execution" is no longer quite true. It is the right trade, but it
is a trade.

### 3.5 Teardown has two mechanisms because they cover different failures

The **lifeline** is an anonymous pipe: snug holds the write end and never writes
to it, so the stage sees EOF the instant snug dies, however it dies — including
SIGKILL, which gives snug no chance to signal anyone. The stage then `os.Exit`s,
which makes bwrap's own `--die-with-parent` fire, because bwrap's real parent
across every exec in the chain is the stage.

**`PR_SET_PDEATHSIG` is the second mechanism and it is load-bearing, not
decorative.** The code used to carry a comment claiming it does not survive the
`setup → serve` re-exec, because that exec is a `secureexec` transition where
capabilities widen. **MEASURED FALSE.** Capabilities do not widen there, so
there is no `secureexec` and the signal is preserved.

The distinction matters because the lifeline requires the stage to *run a
goroutine* to notice EOF. A stopped process runs no user code at all. Measured
3/3: freeze the whole tree with SIGSTOP — stage, both bwraps, pasta — then
SIGKILL snug, and everything is gone with no leaked netns. Pdeathsig is the only
thing that can do that. The wrong comment was actively dangerous: it told a
future maintainer the line was dead weight.

### 3.6 One uid mapped in U, and no `newuidmap`/`newgidmap`

Phase 1 delegates no subuids. The engine still runs on the host, so a delegated
range would be a capability with no consumer, granted under `--no-defaults`,
traceable to no profile — and it would make `snug -p @podman-socket` fail on any
host with no `/etc/subuid` entry.

The map is a single uid written through Go's `SysProcAttr.UidMappings`, which
deletes `newuidmap`/`newgidmap` and the privileged re-exec that would have been
needed to use them. That keeps "no root, no setuid" literally true on this path,
and it removes the CLOEXEC-clearing dance that produced a confirmed descriptor
leak in review. It was adopted **gated on re-measuring it against snug's real
`BwrapFlags` and its two-user-namespace structure** rather than against a
hand-built bwrap invocation — see §4 Step 0. It held.

### 3.7 The stage brings `lo` up itself

An offline sandbox has `lo` UP with `127.0.0.1/8` because bwrap configures the
netns *it created*. Under the stage bwrap does not create the netns, so nothing
would configure loopback and every `NetEgress` sandbox would silently lose
working loopback — a thing a user finds, not a test. Except that a test does find
it, and the requirement was that it pass **unedited**.

Implementation is `SIOCGIFFLAGS`/`SIOCSIFFLAGS` with `IFF_UP` on `lo`, on a plain
`AF_INET` datagram socket, in the stage **while it is still in N**. Never by
executing `ip(8)`: that would add a host binary dependency snug does not have, on
a path that must not depend on what is installed.

---

## 4. The order the work happened in

The order is part of the design, because one step was a gate.

- **Step 0 — the measurement gate, no tree changes.** Re-measure the single-uid
  map against the real `BwrapFlags` argv. Everything downstream of §3.6 depended
  on it, and the rule was that nothing downstream would be built before it ran.
  It came back green; had it not, the phase would have fallen back to full maps
  plus `newuidmap`/`newgidmap` and recorded the cost as an issue rather than
  carrying it silently.
- **Step 1 — `internal/policy`: `Topology`.** A derived scalar on `Policy`,
  computed once from `Net.Mode` and `Podman`, pinned by `Validate`, rendered by
  the canonicaliser so the commutativity and idempotence tests cover it.
- **Step 2 — `--dry-run`: the topology block.** Printed always, including the
  one-process case, because "Phase 1 adds no user-visible capability" is a claim
  that has to stay checkable rather than merely asserted.
- **Step 3 — `internal/fdseal`.** Extracted from `internal/sandbox` because a
  long-lived forker is a different animal from a one-shot process: its descriptor
  table drifts. **The keep-list is empty by construction, and that is the fix** —
  the first cut derived one from `cmd.ExtraFiles`, which is precisely what let
  the args memfd through, read-write, to the payload. Go installs child
  descriptors with `dup3` and does **not** close the sources, so a source whose
  number is higher than its target survives into the child as a second, fully
  usable copy.
- **Step 4 — `internal/stage`.** The clone, the pin, the move, the re-exec, the
  protocol, the setns shim.
- **Step 5 — `internal/sandbox`: `Run` dispatches on the topology.** The stage
  arm takes a `*Stage`, a type only `stage.Start` can produce, so "bwrap forked
  into a topology that says `NetnsStage`" does not compile without going through
  it.
- **Step 6 — `internal/cli/main.go`: hidden verb dispatch.** Before flag parsing:
  `__stage-setup`, `__stage-serve`, `__innetns`. Each refuses immediately when
  invoked outside the fork chain.

---

## 5. What the reviews found

Three review rounds plus a red-team run per round, by agents with no edit tools.
**No round found an escape from the sandbox.** Independently re-confirmed on
fresh builds each time: capabilities empty on all three topologies, host loopback
closed *by behaviour* against a live listener, abstract sockets private to N, the
payload holding exactly stdio, `/proc/1/environ` empty.

Four confirmed defects were found and fixed in the code the reviews graded:

| found | why the tests missed it |
|---|---|
| the args memfd reached the payload read-write | the fd sweep exempted `ExtraFiles` — the careful-looking thing, and exactly the leak |
| `--cap-drop ALL` was absent | nobody asserted `CapBnd` on a topology where bwrap's parent is uid 0 in a userns |
| a three-reader deadlock in the pasta helper | the channel was written to once and read three times |
| `parked.release` declared the window over before it released | the failure path was unreachable in testing and fail-open in code |

And two tests were found that **could not fail**, by two different reviewers:

- The only test behind "the stage is one-shot" matched `/proc/<pid>/comm` against
  the literal `"snug"`. The kernel sets `comm` from the basename of the file
  exec'd — always `"exe"` here, because the stage is started as `/proc/self/exe`
  — and setting `cmd.Args[0]` moves `cmdline`, not `comm`. The same file's own
  helper documents this exactly, 700 lines above the loop that did not use it.
- The only structural guard keeping `Topology` out of profiles used a **keyed**
  composite literal, which compiles with fields missing. Proven fake by adding a
  `Topology` field to `Profile` and watching three packages stay green. It is
  unkeyed now, and the other half of the surface — the type TOML actually decodes
  into — is guarded in the package that can see it.

**Two claims the reviews falsified are worth carrying**, because both were stated
confidently and both were wrong in the direction that invites a bad edit:
`PR_SET_PDEATHSIG` does survive the re-exec (§3.5), and a same-uid host process
does **not** gain anything from the stage. On the second: the route by which a
same-uid process reaches the sandbox's namespaces is `NS_GET_USERNS` on the
sandbox's own namespace descriptor followed by `setns` into the owner — which
works on the pre-stage path too, and yields the sandbox's whole **mount**
namespace, not just its netns. Direct `setns` on `/proc/<child>/ns/net` is EPERM
on both. The parity conclusion holds; the reasoning that had been written down
for it did not, and a reader who tested the stated route would have concluded the
stage widened the host surface.

**One defect was open when this document was first written, and is now closed.**
The guard that stopped a dying snug from releasing a parked payload was armed
*after* the payload was already parked, and a SIGKILL inside the window ran the
payload and left an orphaned sandbox — measured 5/5. It was not fixable by
arming the guard earlier, because a guard catches signals and SIGKILL is the one
signal that cannot be caught.

It was closed by **deleting the thing that had a window** rather than by
defending it — see §7.

**Three review rounds agreed on a diagnosis that measurement contradicted, and
the agreed fix would not have worked.** The rounds reported SIGTERM as open too,
at 10/10, 6/6 and 3/3. All three killed at a fixed wall-clock offset — 60 ms,
100 ms — and the release happens at ~30 ms, so the payload had legitimately
started. **A positive control that only shows an unkilled run writing its marker
cannot tell "released early by the bug" from "released correctly, then killed".**
Measured properly, SIGTERM and SIGINT were **0/5**: the catchable signals had
been closed all along, and the defect was SIGKILL-only over ~17 ms. Both red
teams then converged on "arm the guard earlier, pid-less" — a guard catches
signals, and the only signal left cannot be caught, so it would have changed
nothing.

The shape to carry forward: **a positive control must distinguish the two
explanations, not merely prove the machinery runs.** The same mistake recurs in
[#13](https://github.com/gomoni/snug/issues/13), where two further plausible
mechanisms were agreed and refuted by measurement.

---

## 7. The ordering that removed the parked window

The startup sequence is now:

```
stage.Start   -> N exists, pinned by a descriptor, with nobody in it
startPasta    -> pasta attaches to that EMPTY N and configures snug0
WaitNetReady  -> the stage confirms snug0 is UP and RUNNING, from inside N
StartSandbox  -> only NOW does a payload exist
```

bwrap is forked with **no `--block-fd` and no `--json-status-fd`**. There is no
parked payload, so there is nothing for a dying snug to release, and
`internal/sandbox/parked.go` is gone along with `readChildPID` and
`waitForNetDevice`.

That is still true of every run this document describes, and **no longer true of
a run with a container engine** (issue #125): the engine's mount view is derived
from the sandbox's, so bwrap must exist first, and its payload parks on
`--block-fd` until the engine is confirmed. What makes that safe is a flag this
document never had — `--sync-fd` on the SAME pipe, held open by the sandbox's own
pid 1, so a dying snug still cannot release the payload (measured 5/5 → 0/5).
INDEX §4.3 carries the measurement; nothing about the network's own ordering
changes.

**What made it possible, having been recorded as a blocker.** Confirming the
interface needed a process inside N to read `/proc/<pid>/net/dev`, and before
bwrap there is none. But **a socket's network namespace is fixed when the socket
is created and does not follow the process** — measured, with both controls:

```
in N   : lo IFF_UP=true     positive control
in N2  : lo IFF_UP=false    a fresh socket in the stage's new namespace
in N2  : lo IFF_UP=true     the socket created in N, after the move
```

So the stage keeps the `AF_INET` socket it already opens in N to bring `lo` up,
parks it at `fdNetSock` across its own re-exec, and answers a `netready` control
request with `SIOCGIFFLAGS` on `snug0` — a name snug itself passes to pasta with
`--ns-ifname`, so the check is an exact lookup rather than an enumeration.

**Also measured before any of it was built:** pasta attaches to a network
namespace with no process in it at all, stays up, and its interface is waiting
when bwrap arrives.

Three consequences worth stating:

- **The regression test asserts SIGKILL now.** Its predecessor documented, in
  its own doc comment, that it could not. Same property, strictly stronger
  claim.
- **A dead pasta is still detected immediately.** Readiness is raced against the
  helper exiting, because otherwise a pasta that crashes at once would be
  reported only when the interface timeout expired — a 300ms error turned into a
  ten-second one that a human interrupts before reading.
- **The protocol grew a second op, and deliberately not a loop.** `netready` may
  be asked once, before `start`; `start` remains strictly one-shot. A loop would
  have been shorter and would have quietly turned a one-shot stage into a server
  — which matters when Phase 2 gives it a pathname socket and a second client.

---

## 8. Deferred, with reasons

- **The control listener** — a pathname socket, an accept loop, the 108-byte
  `sockaddr_un` budget. There is no client but the stage's own parent yet, and a
  socket with no operation is pure attack surface. When it arrives, the
  `--dry-run` `control` line changes from an anonymous pair to a path: a visible,
  reviewed security change rather than something that was already there.
- **Hardening the stage itself.** It keeps a full capability set, `NoNewPrivs 0`,
  no seccomp filter, and the launcher's IPC and UTS namespaces, for the whole
  run — needing capabilities only twice, both before it forks. Nothing can reach
  it today. It becomes the entry condition for the listener above, because at
  that moment "parses input from a second client" and "holds `CAP_SYS_ADMIN` over
  the sandbox's mounts with no `no_new_privs` and no filter" become one sentence.
- **Subuid delegation and `Topology.Attach`.** No consumer until an engine moves
  into the stage. The floor and the lattice law exist; nothing raises them.
- **The engine in the sandbox's netns** — the thing all of this is for.
  [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §2 measured that it works and §3 measured
  where it does not; the engine is the host's own podman
  that makes the measurement runnable on a host whose `podman` is a shim.
