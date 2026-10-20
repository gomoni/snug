# The supervisor stage

`@net` runs two processes. snug forks a second long-lived one, the **stage**, whose job is to create the sandbox's network namespace, pin it,
*leave* it, and fork bwrap back into it. This document is the stage and why it is shaped that way.

Everything marked **MEASURED** was executed on the development host (openSUSE Tumbleweed, `bwrap` 0.11.2, `pasta` 20260612,
Go 1.26, inside a rootless-podman distrobox). Everything else is reasoning and is marked as such. The numbers live here rather than
in a script because the measuring script is gone (its prototype shipped as `internal/stage`); the live checks are the tests named below.

Two rules every measurement here obeys: never assert an exit code as a negative — assert a MARKER the payload emitted — and never
compare two namespace ids without refusing the empty case.

**Why the stage exists** is [`ENGINE-NETNS.md`](ENGINE-NETNS.md): a container started through `@podman-socket` runs on the *engine's*
network, not the sandbox's. Moving the engine into the sandbox's network namespace fixes that, and doing so requires something other
than bwrap to own the namespace. The stage is that owner, and the engine is its second child (§2).

Invariant 4 (no daemon) is about who owns the process, not how many there are: the stage is a child that dies with snug, like `tmux`'s
server without the survival. You cannot join *only* a network namespace unprivileged: it must be created together with a user namespace,
and joining needs `CAP_SYS_ADMIN` in that user namespace, which is why pasta is passed `--userns` alongside `--netns`.

---

## 1. Measurements

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
| `PR_SET_PDEATHSIG` **survives** the `__stage-setup → __stage-serve` re-exec | **MEASURED**. Capabilities do not widen at that exec — the stage already holds a full set in U from the moment it creates the userns — so there is no `secureexec` and the signal is preserved (§3.5) |

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
      │   U: user ns — ONE uid mapped, or the delegated range (§3.6)
      │   N: network ns, private — created by the clone, PINNED by a descriptor,
      │      and then LEFT: after __stage-serve, P1 is in a fresh empty netns
      │   + own mount ns (MS_REC|MS_PRIVATE)
      │   + an AF_INET socket CREATED IN N, kept: how it answers "is snug0 up?"
      │     after it has left N (§7)
      │   NO control socket on any filesystem. NO listener, and none coming (§3.3).
      │
      ├── snug __innetns <fd> bwrap ...       a setns shim, one execve deep, forked
      │    │                                  FIRST once the network is up, and
      │    │                                  forked into a pid+mount namespace of
      │    │                                  P1's making — so after its execve
      │    │                                  BWRAP is pid 1 there
      │    └── bwrap (in N, pid 1 of NP)      THE SANDBOX
      │         └── bwrap (init, pid 1 of Q)
      │              └── payload              PARKED on --block-fd where an engine
      │                                       is selected, released by P0
      │
      └── snug __inengine <netnsfd> <mntfd>   forked SECOND, inside the same one
           │                                  "start" request, while the payload
           │                                  is still parked
           └── podman system service          THE ENGINE, in N by setns, in a
                                              DERIVED mount view, dropped to
                                              policy.EngineCapBounding
```

**Both legs are children of P1, and only where a container engine is selected
is there a second one.** They are siblings: the engine is not inside the
sandbox's mount or pid namespace, and the sandbox is not inside the engine's.
What they share is N and U. The engine is NOT in the sandbox leg's intermediate
pid namespace either — it is forked separately, from P1's own.

**Why the sandbox leg is nested at all**: pid 1 of a pid namespace ignores every signal it has no
handler for, and bwrap installs none. Unnested, bwrap is an ordinary member of
P0's process group — nothing in the chain calls `setpgid` — so a terminal's
anything. MEASURED: `SIGINT` to the outer bwrap alone ended the run; the same
signal to the offline arm's already-nested bwrap was ignored and the payload
kept running. Together with P1 catching and dropping `SIGINT/TERM/HUP/QUIT`
(`MainServe`), that leaves **snug as the only author of this run's death** — the
property the offline arm has had since the intermediate namespace landed there.
It costs no user-namespace nesting level, because P1 is already root in U and
holds the `CAP_SYS_ADMIN` that `unshare(CLONE_NEWPID)` needs.

The cost is one translation: bwrap reports its init as *it* sees it, which is
now pid 2 of NP, so `runOneSandbox` converts that to a host pid once
(`initwalk.ChildWithReportedPID`) before anything downstream — `parked.setInit`,
the mount settle, the engine, and the `forked` event P0 records the run by —
consumes it.

**Read the two names as two axes.** `P0/P1` are distinct *processes*.
`__stage-setup`/`__stage-serve` are successive *exec images of P1* — same pid
throughout. `__innetns` is a third exec image but in a child.

**A bare `snug <dir>` starts no stage.** The stage exists only where something
other than bwrap must own the sandbox's namespaces; an ordinary offline run has
no such thing and bwrap owns everything. That is deny-by-default applied to
snug's own process tree.

*Two things select a stage.* Egress is one; selecting a container engine is the
other ([#63](https://github.com/gomoni/snug/issues/63)) — for the full delegated subuid
range and the private mount namespace the engine forks into — so an **offline**
`@podman-socket` run starts one too, with no pasta and an N holding only
loopback. `Topology.NeedsStage()` is the live answer, and §3.2 is its argument.

*The abuse sentence for the whole topology, and it is on screen in `--dry-run`:*

> a hostile process inside the sandbox gains no new reach — the stage is in
> neither its network namespace nor its pid namespace, binds nothing it can
> name, and holds no descriptor it can open — but its user namespace now has a
> **privileged ancestor** (U, root-in-userns with `CAP_SYS_ADMIN` over N and over
> the sandbox's own mounts) that lives for the whole run, so a userns-escape bug
> is worth more here than it was.

---

## 3. The decisions, and the alternative each one rejected

### 3.1 The bwrap argv under the stage: enumerate, do not reuse `--share-net`

Under `Topology.Netns == NetnsStage`, `BwrapFlags` emits
`--unshare-user-try --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try`
and **omits `--unshare-net`**. Every other topology emits `--unshare-all`.
**`--share-net` is emitted nowhere at all**, which is what makes a grep for it a
complete answer.

The rejected alternative was `--unshare-all --share-net` for the stage, on the
sound objection that an enumeration is a keep-list and a bwrap that grows a
namespace type would silently stop unsharing it. It loses on a point it cannot
answer: `--share-net` relaxes a namespace snug created, and the stage's netns is
one snug created and pinned deliberately. Spelling "P1 already made N" with the
same flag that would spell "give the payload whatever netns bwrap was started
in" puts two meanings on one token, and no grep, golden or review could then
separate them.

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

`Topology.NeedsStage()` is derived, and true when either
`Topology.Netns == NetnsStage` or `Subuid == SubuidFull` (§2's note). The
rejected alternative started a stage for every run, so that there would be one
process shape to reason about. It loses because an unconditional stage hands
every default `snug <dir>` a privileged ancestor user namespace in exchange for
**no capability at all**.

Consequence, written down rather than discovered: `NeedsStage()` is monotone
over the `NetnsOwner` lattice only because `NetnsStage` is its top. The lattice
orders reachability and the stage is a construction detail rather than a grant,
so an owner ABOVE `NetnsStage` would take the stage away while strictly
*widening* the grant. Check that before adding one.

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
`pidfd_getfd`, `internal/sandbox/seccomp.go`) is a second, independent lock on
the same door: even a payload that somehow *did* have a pid to name for
`pidfd_open` could not then steal a descriptor out of another process's table.
Two locks, two different reasons they hold — namespace invisibility, and a
denied syscall for whatever makes that stop being true — rather than one fact
doing both jobs.

**There is no listener.** The namespaces this channel would let a
client reach are joinable by descriptor by any same-uid host process already,
confirmed five ways on both topologies, so a listener would be a second route to
authority the kernel already grants, behind a weaker gate than the kernel's.
There is no second client and no verb that would be one: snug places no
process into a running sandbox's namespaces, so the protocol's strictness
is the guard on the one client that exists — P0.

*`--dry-run` says all of this*, and says it precisely: a line reading "no
socket" is the half a reviewer would use to decide there is nothing here to
audit, so the socket is named whenever there is one.

### 3.4 `PastaArgs` takes a target, not a pid

```go
type PastaTarget struct {
	NetnsPath  string // what pasta opens for --netns
	UsernsPath string // what pasta opens for --userns
}

func PastaTargetChild(childPID int) PastaTarget          // /proc/<pid>/ns/{net,user}
func PastaTargetStage(stagePID, netnsFD int) PastaTarget // /proc/<P1>/fd/<n> + /proc/<P1>/ns/user
```

The signature cannot stay a pid. Measured, three ways: after the move
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
nothing about execution" is not quite true. It is the right trade, but it
is a trade.

### 3.5 Teardown has two mechanisms because they cover different failures

The **lifeline** is an anonymous pipe: snug holds the write end and never writes
to it, so the stage sees EOF the instant snug dies, however it dies — including
SIGKILL, which gives snug no chance to signal anyone. The stage then `os.Exit`s,
which makes bwrap's own `--die-with-parent` fire, because bwrap's real parent
across every exec in the chain is the stage.

**`PR_SET_PDEATHSIG` is the second mechanism and it is load-bearing, not
decorative.** It **survives** the `setup → serve` re-exec — **MEASURED**, and
worth measuring because the plausible reading is that it does not: a
`secureexec` transition would clear it, but capabilities do not widen at that
exec, so there is no `secureexec` and the signal is preserved.

The distinction matters because the lifeline requires the stage to *run a
goroutine* to notice EOF. A stopped process runs no user code at all. Measured
3/3: freeze the whole tree with SIGSTOP — stage, both bwraps, pasta — then
SIGKILL snug, and everything is gone with no leaked netns. Pdeathsig is the only
thing that can do that. The wrong comment was actively dangerous: it told a

### 3.6 Two uid maps, and the setuid helpers are on exactly one of them

`Topology.Subuid` picks the shape, and there are two:

- **`SubuidNone`** — one uid, namespace 0 to this process's own real id,
  written by Go's `SysProcAttr.UidMappings` in the child itself. This is the
  one self-map the kernel allows an unprivileged writer to make, so it needs
  no `newuidmap`/`newgidmap`, no `/etc/subuid` line, and no privileged
  re-exec. **"No root, no setuid" is literally true on this path.** MEASURED
  against snug's real `BwrapFlags` and its two-user-namespace structure, not a hand-built bwrap
  invocation. It is what every run without a container engine gets.

- **`SubuidFull`** — namespace 0 to the real id *plus* the delegated
  `/etc/subuid` range. A container engine needs it: an image whose content is
  owned by a non-root uid has nowhere to land in a single-uid map.
  `deriveTopology` raises it from the podman branch and from nowhere else, so
  the setuid dependency is **podman's rootless model adopted at its boundary**,
  not something the sandbox itself grew.

  A two-range map is not the self-map special case, so an unprivileged write of
  it is EPERM — which is what `newuidmap`/`newgidmap` exist for.
  `SysProcAttr.UidMappings` is left **nil**; `__stage-setup` notices its own uid
  is still the overflow id after the clone, asks P0 over the control socket
  ("needmap"), and blocks. P0 runs the two setuid helpers against P1's pid
  (`delegateSubuid`) and answers "mapped". **P0 runs them, not P1** — the
  privileged tools stay in the process that already had the host's authority,
  and P1 never execs one.

  A user namespace's map may be written **once, ever**. There is no "self-map
  now, widen later", which is why the whole range has to be asked for at clone
  time and why a failure here is fatal rather than a fallback to the map that
  was not asked for (invariant 5). `CheckSubuidDelegation` is the preflight that
  refuses early, naming the missing `/etc/subuid` line or the missing tool.

### 3.7 The stage brings `lo` up itself

An offline sandbox has `lo` UP with `127.0.0.1/8` because bwrap configures the
netns *it created*. Under the stage bwrap does not create the netns, so nothing
would configure loopback unless the stage does.

Implementation is `SIOCGIFFLAGS`/`SIOCSIFFLAGS` with `IFF_UP` on `lo`, on a plain
`AF_INET` datagram socket, in the stage **while it is still in N**. Never by
executing `ip(8)`: that would add a host binary dependency snug does not have, on
a path that must not depend on what is installed.

---

## 4. Where it lives

- `internal/policy`: `Topology`, a derived scalar on `Policy`, computed once from `Net.Mode` and `Podman`, pinned by `Validate`, rendered by the canonicaliser so the commutativity and idempotence tests cover it; `--dry-run` prints the topology block always, including the one-process case.
- `internal/fdseal`: the descriptor sweep of a long-lived forker, whose descriptor table drifts. **The keep-list is empty by construction.** Deriving one from `cmd.ExtraFiles` is what once let the args memfd through, read-write, to the payload: Go installs child descriptors with `dup3` and does **not** close the sources, so a source whose number is higher than its target survives into the child as a second, fully usable copy.
- `internal/stage`: the clone, the pin, the move, the re-exec, the protocol, the setns shim.
- `internal/sandbox`: `Run` dispatches on the topology. The stage arm takes a `*Stage`, a type only `stage.Start` can produce, so "bwrap forked into a topology that says `NetnsStage`" does not compile without going through it.
- `internal/cli/main.go`: hidden verb dispatch before flag parsing — `__stage-setup`, `__stage-serve`, `__innetns` — each refusing immediately when invoked outside the fork chain.

---

## 5. Claims to not re-derive

Two claims were stated confidently, were wrong, and were wrong in the direction that invites a bad edit:
`PR_SET_PDEATHSIG` does survive the re-exec (§3.5), and a same-uid host process
does **not** gain anything from the stage. On the second: the route by which a
same-uid process reaches the sandbox's namespaces is `NS_GET_USERNS` on the
sandbox's own namespace descriptor followed by `setns` into the owner — which
works with no stage too, and yields the sandbox's whole **mount**
namespace, not just its netns. Direct `setns` on `/proc/<child>/ns/net` is EPERM
on both topologies.

**A positive control must distinguish the two explanations, not merely prove the machinery runs.** A kill at a fixed
wall-clock offset (60 ms, 100 ms) after a release at ~30 ms cannot tell "released early by the bug" from "released correctly,
then killed"; a control that only shows an unkilled run writing its marker proves nothing about the window.

---

## 7. The ordering that removes the parked window

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

That holds for every run with no container engine. **With one** (issue #125) it
does not: the engine's mount view is derived from the sandbox's, so bwrap must
exist first, and its payload parks on `--block-fd` until the engine is
confirmed; nothing about the network's own ordering changes.

**`--block-fd` never travels alone.** `snug` passes `--block-fd R` and the
payload parks after the whole mount tree is built and before any payload is
forked; the engine starts behind it; `snug` writes one byte once the engine's
socket answers. A payload released early by a dying `snug` is
prevented by the **second** flag: the SAME pipe's write end is passed as
of the run, so the parked read never sees EOF however violently anything
outside dies. Measured on this host, 5 runs each: `--block-fd` alone, `SIGKILL`
of the holder while parked → `PAYLOAD_RAN` **5/5**; with `--sync-fd` on the
same pipe → **0/5**, release-by-byte still running the payload as the positive
control. Do not substitute any other inherited descriptor: an arbitrary extra
fd holds the pipe open just as well (0/5) and **leaks into the payload** —
measured fd tables `0,1,2,4,5` against exactly `0,1,2` with `--sync-fd`. Two
residuals follow and are written down rather than discovered: while parked,
`bwrap` has **not yet armed `--die-with-parent`** on that init (measured —
killing the outer `bwrap` leaves it alive and still releasable), so the stage
kills it explicitly on every abort path and on its own teardown; and a
`SIGKILL` of `snug` inside the parked window is **measured to leave nothing
behind, 20/20** — `do_exit` closes the lifeline (`exit_files`) before it
delivers the stage's `Pdeathsig` (`exit_notify`), the same ordering that makes
`--block-fd` alone unsafe, so the stage's watcher wins the race and kills the
parked init; with that one kill removed as the positive control, exactly one
process survives, 5/5. The residual is therefore narrower than it looks and
still real: a stage that cannot run code at all (a `SIGSTOP`ped tree) orphans
that init, holding N and the mount tree. `internal/sandbox/teardown.go`'s
residual paragraph states it in full.

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

- **The regression test asserts SIGKILL.**
  claim.
- **A dead pasta is still detected immediately.** Readiness is raced against the
  helper exiting, because otherwise a pasta that crashes at once would be
  reported only when the interface timeout expired — a 300ms error turned into a
  ten-second one that a human interrupts before reading.
- **The protocol grew a second op, and deliberately not a loop.** `netready` may
  be asked once, before `start`; `start` remains strictly one-shot. A loop would
  have been shorter and would have quietly turned a one-shot stage into a
  server, and the stage is not one: it answers a fixed number of requests from
  the single parent that forked it, and returns.
