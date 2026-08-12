# The supervisor topology — one namespace holder, several children

Investigation and proof of concept, 2026-08-11. Everything marked **MEASURED**
was executed on this host; the code that measures it is `poc/nsd/`, and
`poc/nsd/run.sh` re-runs all 49 checks (`pass=49 fail=0` at the time of writing).
Everything else is reasoning and is marked as such.

Read [ENGINE-NETNS.md](ENGINE-NETNS.md) first. This document does not replace it
— it removes the constraint that made its §5 read as a single awkward re-exec,
and it adds a capability (`snug attach`) that was not on the table.

## 0. The correction that opens this up

ENGINE-NETNS §1 is right that you cannot join *only* a network namespace: an
unprivileged process must create the netns together with a user namespace, and
joining afterwards needs `CAP_SYS_ADMIN` in that user namespace. That fact is
unchanged.

What was wrong was the shape imposed on the answer. "No daemon, no service files
— just execute a binary" (CLAUDE.md, key feature 2) was being read as **one
process**, so every design had to end with `snug` becoming the sandbox. Nothing
in the invariants says that. Invariant 4 says *no root, no setuid, no daemon*,
and spells out what it is defending: "helpers are children that die with the
sandbox and leave nothing behind".

`tmux` is the model. It has no unit file, no socket activation, no root, and
nothing survives a reboot — and it still has a server process that outlives the
command you typed. The distinction that matters is **who owns the process**, not
how many there are.

So: `snug` may fork a process whose entire job is to *hold namespaces*, and hang
everything else off it as children. That single change makes the engine, the
sandbox, and any number of later payloads siblings in one namespace set.

## 1. The topology

```
P0  snug                     host userns, host netns, host mount tree
 │                           creates P1, writes its uid maps, runs pasta at it,
 │                           holds the lifeline, then only supervises
 │
 ├── pasta --netns /proc/P1/ns/net --userns /proc/P1/ns/user
 │
 └── P1  snug __stage        THE NAMESPACE HOLDER
      │                      U: user ns, FULL subuid map (root inside)
      │                      N: network ns, private
      │                      + own mount ns (MS_REC|MS_PRIVATE) and cgroup ns
      │                      control socket on the HOST filesystem, host-only
      │
      ├── P2  bwrap ...      THE SANDBOX. Inherits U and N by descent; creates
      │    │                 its own mount/pid/ipc/uts namespaces and TWO more
      │    │                 user namespaces on top. --unshare-net is absent.
      │    └── P3  payload   uid 1000 again, writes land as the host user
      │
      ├── P2' engine stage   THE CONTAINER ENGINE. Same U and N, but its own
      │                      mount namespace holding a private copy of the HOST
      │                      tree — storage paths stay where podman expects them.
      │
      └── P3' attached payloads
                             injected by P1 into P2's namespaces with setns(2).
                             No socket inside the sandbox. See §4.
```

Two departures from the sketch this started from, both load-bearing:

**The engine is a sibling of the sandbox, not its parent.** `P1 → P2(engine) →
P3(sandbox)` would put the sandbox inside the engine's mount namespace — the
host tree — and every grant would then be a subtraction from it. Sibling
children of P1 share exactly what they must (U, N) and nothing else.

**The sandbox does not get a control socket.** The sketch has P2 exposing an
interface so more payloads can join it. It does not need one: P1 can inject a
process into P2's namespaces from outside (§4, MEASURED). A socket inside the
sandbox would be an accept()-able object owned by a process the payload can
`kill` — the payload cannot connect to P1's socket today precisely because there
is nothing to connect to.

## 2. What was measured

| # | claim | result |
|---|---|---|
| E1 | an unprivileged Go process creates U with the **full** subuid map, plus N, mount ns and cgroup ns, and serves a control socket the host can reach | PASS |
| E2 | bwrap as a child of P1 inherits N, and `--uid` carries the host uid through: the payload sees 1000 and its writes on the bind are owned by host uid 1000 | PASS |
| E3 | a process injected into a running sandbox lands in its mount and pid namespaces, sees its tmpfs, and does not see `~/.ssh` | PASS |
| E4 | joining a user namespace grants a **full capability set**; the joiner must drop it | PASS (and the undropped case measured) |
| E5 | egress works from N and from the sandbox; host loopback is refused from both, against a live host listener | PASS |
| E6 | **a new hole**: the stage shares N, so an abstract socket bound by a host-side helper IS reachable from the sandbox | PASS (hole confirmed) |
| E7 | an engine-shaped child keeps N and gets a private copy of the host mount tree | PASS |
| E8 | SIGKILL the launcher: stage, sandbox, attached payloads and the netns all go | PASS |
| E9 | two payloads share one sandbox's tmpfs and pid namespace; the host sees neither | PASS |
| E11 | the stage exits when its last payload does, taking the launcher and the netns with it, and does not stay up for the next client | PASS |
| E10 | the engine can run in a mount view **derived from the sandbox's**, with the container storage grafted in from outside, and the graft does not propagate back | PASS |

## 3. The kernel facts this rests on

Each of these cost a debugging cycle. They are the reason the code looks the way
it does.

**1. The stage must re-exec after its uid map is written, or it has no
capabilities at all.** Go cannot `unshare(CLONE_NEWUSER)` in-process (the
runtime is multithreaded), so the namespace is created by `clone` + `execve`.
`clone(CLONE_NEWUSER)` does hand the child a full capability set — and then
`execve` recalculates: euid is the overflow uid, the file has no file
capabilities, everything is dropped. Once `newuidmap` has run, euid reads as 0
and a second `execve` gets the capabilities back. `CapEff` in
`/proc/<stage>/status` is the check.

**2. The same re-exec silently clears `PR_SET_PDEATHSIG`.** `execve` sets
`secureexec` whenever the new permitted set is not a subset of the old one, and
`secureexec` zeroes `pdeath_signal` so a parent cannot signal a process that just
became more privileged. MEASURED: with `Pdeathsig: SIGKILL` set on the stage,
`kill -9` on the launcher left the **entire tree alive**, reparented to init.
Teardown must use a **lifeline pipe** — the launcher holds the write end, the
stage reads EOF — and the stage must then kill its own children. (Pdeathsig is
unreliable from Go for a second reason anyway: it fires when the parent *thread*
exits, and the runtime does not promise which thread forked.)

**3. `setns` order is the whole trick, and bwrap is why.** bwrap creates **two**
user namespaces: the mount, pid, ipc, uts and cgroup namespaces are owned by the
first, and the payload runs in the second, a child of it, so the sandbox cannot
reach the uid_map or the mounts of the namespace that built it. `nsowner`
(`poc/nsd/join/nsowner.c`, using `NS_GET_USERNS`) prints it:

```
user    ns=[4026533269]   owned-by-userns=[4026533151]
mnt     ns=[4026533152]   owned-by-userns=[4026533151]
net     ns=[4026532987]   owned-by-userns=[4026532983]     <- P1's own userns
```

`setns` into a non-user namespace needs `CAP_SYS_ADMIN` **in the user namespace
that owns it**. P1 holds that over both bwrap namespaces by the ancestor rule in
`user_namespaces(7)` — but only while it is still in U. Join the payload's user
namespace first and the next call fails:

```
JOIN-FAIL setns mnt: Operation not permitted
```

So: **every non-user namespace first, the user namespace last**. And open all
seven descriptors *before* the first `setns`, because after joining the mount
namespace `/proc` is the sandbox's own, where the target's pid number means
something else.

**4. The joiner needs C, or something equally single-threaded.** `setns` with
`CLONE_NEWUSER` requires a single-threaded caller, which the Go runtime is not.
The three real options are a cgo constructor (runc's `nsexec`), a tiny static
helper binary (what the PoC does), or `nsenter(1)`. snug shipping a second
binary is a change in kind — it is the first thing in the tree that is not
`snug` — and that deserves a decision, not a shrug. The cgo constructor keeps
one binary at the cost of enabling cgo.

**5. Joining a user namespace grants every capability in it.** MEASURED: an
attached process that does not drop them has `CapBnd: 000001ffffffffff` and
`NoNewPrivs: 0`. The exec'd payload's *effective* set is empty (euid is 1000 and
the file has no file capabilities) — but a full bounding set with no
`no_new_privs` is exactly the state in which a file-capability binary in the
bound `/usr` is a way back up, and `/usr/bin/newuidmap` on this host has one.
The joiner must set `PR_SET_NO_NEW_PRIVS`, empty the bounding set, and clear the
ambient set — and then it is **stricter than bwrap's own payload**, which runs
with a full bounding set and relies on `no_new_privs` alone.

**6. A pid from bwrap is not a sandbox.** `--json-status-fd` reports the child
pid as soon as the child *exists*, well before its mounts are in place.
Attaching on that pid lands a process in a half-built mount namespace, and the
symptom is `execve` returning **ENOENT for a binary that `stat()` can see a
moment later**. The sandbox's init must report readiness on its own pipe.

**7. `/proc/<pid>/status` renders uids in the READER's user namespace.** From
the host the stage's `Uid:` line reads 1000, not 0. Any test that checks "the
stage is root in its own namespace" from outside is checking nothing.

## 4. `snug attach` — the tmux operation, done from outside

P1 opens the seven namespace descriptors of the running sandbox, `setns`es in
the order above, drops capabilities, forks (because `CLONE_NEWPID` applies to
children), and execs. MEASURED: the new process is in the sandbox's mount and
pid namespaces, reads a file the first payload wrote to the sandbox's tmpfs, is
counted in `ps` alongside it, and cannot see `~/.ssh`; the host cannot see the
file either.

The half of this that survives review: **attach opens no listener inside the
sandbox.** No socket, no port, nothing to connect to; the authority stays where
it already was, in a process the payload cannot name (MEASURED: P1 is not in the
sandbox's pid namespace, and the control socket's path is not in its mount
namespace).

**"No fd handed in" was false, and it was false for the primary payload too.**
MEASURED, by inode: P1's lifeline read end (fd 5) is open in every attached
payload *and* in the sandbox's own init. `stage0()` clears CLOEXEC on fds 4 and 5
so they survive the privileged re-exec — needed exactly once — and `stage1()`
never restores it, so every later child of P1 inherits it: bwrap from
`startSandbox`, the joiner from `attach`.

Today that fd is harmless: it is the *read* end of an anonymous pipe, so the
payload can neither forge a write end nor suppress EOF, and teardown still fires.
The mechanism is the finding. **The process that forks the sandbox is no longer a
short-lived launcher whose fd table snug controls at `cmd.Start()`; it is a
long-lived server with an accept loop, per-connection sockets, pidfds, an
eventpoll and an eventfd, whose fd table at fork time depends on which control
connections happen to be open.** The first authority-bearing descriptor P1 holds
without CLOEXEC — a broker socket, a host `open_tree` for the graft — reaches
every sandbox by this same path, with no new code and no visible change. So
`sealInheritedFDs` must run **in P1, immediately before every fork**, not once in
the launcher; and a real `snug attach` passes a pty over `SCM_RIGHTS`, which is a
deliberate fd-into-the-sandbox channel and needs its own argument.

What the joiner must still reproduce before this is shippable — every one of
these is a restriction bwrap applies that `setns` does not inherit:

- the seccomp filter (`Seccomp: 0` on an attached process today — MEASURED);
- the capability drop and `no_new_privs` (done in the PoC);
- the environment — and note this got harder, not easier, since this section was
  written. `snug` no longer merely *clears* it: the `environ` verbs (`set`,
  `merge`, `prepend`, `inherit`, `sanitise`) make the environment part of the
  resolved policy, authored per variable by a named profile. So a joiner must
  reproduce **the environment that policy computed for this sandbox**, not an
  empty one, and must still not leak P1's. Clearing is now the wrong shape twice
  over: it drops what the policy granted, and "we cleared it" stops being a
  statement anyone can check against `--dry-run`, which prints one line per
  variable naming its verb and its profile. The joiner should read the same
  resolved policy, exactly as invariant 6 requires — one `Policy`, one author;
- the cgroup, and the `Pdeathsig`/lifeline story for the attached process;
- stdio: a real attach needs a pty, and §6 says where that lives.

## 5. What gets better, and what gets worse

**Better.**

- **The engine moves into the sandbox's netns**, which is the entire point of
  ENGINE-NETNS: `@podman-socket`'s interim `include = ["net"]` can go, and
  "offline is the absence of `@net`" becomes true again without a footnote.
- **One namespace set, one policy author** (invariant 6) extends to the engine
  by construction rather than by review.
- **Several payloads in one sandbox** — `claude` and a shell, sharing the
  policy, the tmpfs and the pid namespace. This is the feature; everything else
  above is what it costs.
- **A possible home for the MVY2 secrets broker — with one constraint that is
  not optional.** P1 is outside the sandbox, holds host authority, and already
  has a control socket. But it is also the one process that now shares a network
  namespace with the payload and with every container, so a broker living there
  **must bind nothing in N** — not an abstract name, not a loopback port — and
  must reach nothing in N by either. Its channel is a pathname AF_UNIX socket in
  a directory the sandbox does not mount, which is the mechanism snug already
  has. Note also what co-residency costs the broker: two payloads in one sandbox
  are one trust domain (same uid, shared pid and mount namespaces), and MEASURED,
  a sibling reads another payload's `/proc/<pid>/environ`. A per-payload secret
  delivered by environment or uid-readable file is a per-*sandbox* secret.

**Worse, and each one needs a rule.**

- **Abstract sockets in N are now reachable from the sandbox.** MEASURED: a
  helper running as a child of P1 bound `\0nsd-secret`, and the payload connected
  and read the bytes. Today's guarantee ("abstract sockets unreachable") holds
  only because nothing else lives in N.

  The first draft of this rule read "no process in N may bind an abstract
  socket". Review showed it covers about a third of the exposure, in three ways,
  all MEASURED. **Loopback is not safer than `0.0.0.0`**: a helper bound on
  `127.0.0.1:19099` in N was read by the payload while the host got `000`.
  **The rule binds snug and not the attacker**: the payload bound `0.0.0.0:19100`
  and `\0snug-broker` first, and a later host-side helper got `EADDRINUSE` on
  both — so the payload can deny service to snug's helpers and to the engine's
  (aardvark-dns on :53, rootlessport), and whatever P1 starts must start before
  the payload. **And it runs both directions**: a host-authority process that
  *connects* to an abstract name or a loopback port in N gets the payload's
  impostor, MEASURED on both (`ABSTRACT MITM`, `TCP MITM`).

  Rule, in the form that survives: **no snug-owned or host-authority process in N
  may bind or connect to an abstract name or any IP address, 127.0.0.1
  included.** Everything snug exposes in N is a pathname AF_UNIX socket in a
  directory the sandbox does not mount. The test is `ss -xl` reporting zero
  abstract sockets inside the sandbox *with the engine running* (ENGINE-NETNS §4
  proposed it for a different reason), plus an assertion that no snug helper
  listens on any TCP or UDP port in N.

  Note what makes this rule weaker than the ones it replaces: it constrains code
  snug does not own — podman, conmon, netavark, aardvark-dns, crun — so it cannot
  be checked at build time, and on this host it cannot be tested at all, because
  the engine leg does not run (§8). Until that test exists somewhere, CLAUDE.md's
  two "abstract sockets unreachable **by construction**" sentences must change in
  the same commit that lands this topology, or snug is asserting a guarantee it
  no longer delivers.
- **`ss -xl` inside the sandbox lists the stage's control socket path.** MEASURED.
  It cannot be connected to (the path is not in the sandbox's mount namespace,
  MEASURED) but the leak of a host path is real. Put the run directory under a
  name that says nothing, or accept it and write it down.
- **Sandbox and containers become network peers**, unchanged from
  ENGINE-NETNS §4.
- **Teardown is no longer unconditional.** It is now conditional on the lifeline
  and on P1 killing its children; and the engine's `conmon` double-forks out of
  the tree. MEASURED here for the sandbox and attached payloads (E8); the engine
  leg is unmeasured on this host (§7).
- **"Shims inside the sandbox will get P1's interface" cannot be true as
  stated.** Any socket a shim inside the sandbox can reach, the payload can
  reach — it can run the shim, `ptrace` it (if seccomp allowed it), read its
  descriptors, or simply connect itself. There is no "only my shim may use this"
  in a shared namespace. So P1's control socket stays **host-side only**, and
  anything the sandbox needs is exposed the way snug already does it: one
  purpose-built **filtering** proxy per hole (the podman socket proxy, the
  ssh-agent proxy), each of which assumes its client is hostile.

## 6. The engine's mount view, and how much proxy it deletes — MEASURED

The owner's guess was that running the engine in the same namespace set "may
reduce the amount of code inside a podman proxy". It does, and by more than the
netns alone would.

P1 holds `CAP_SYS_ADMIN` over the user namespace that owns the sandbox's mounts
(§3.3). So it can build the engine's mount namespace **out of the sandbox's own
view** instead of the host's:

1. `open_tree(AT_FDCWD, storage, OPEN_TREE_CLONE|AT_RECURSIVE)` — clone the host
   subtree while the host tree is still visible. A mount descriptor does not care
   about mount namespaces; this is the same property that makes a stray dirfd a
   complete sandbox bypass, used deliberately, from outside, by the process that
   owns the policy.
2. `setns(CLONE_NEWNS)` into the sandbox's mount namespace — **without** joining
   its user namespace, so the authority used is the one P1 already holds.
3. `unshare(CLONE_NEWNS)` + `MS_REC|MS_PRIVATE`. Everything after this point is
   invisible to the sandbox. Not optional: skip it and the graft lands in the
   sandbox's own mount namespace, which hands the payload the container storage.
4. `move_mount(fd, "", AT_FDCWD, dest, MOVE_MOUNT_F_EMPTY_PATH)`.

MEASURED (E10, `poc/nsd/join/nsdmount.c`): the grafted storage is readable in the
derived view; `~/.ssh` and the rest of the host tree are **not** there; the
sandbox's own grants (`/work`) **are**; and the sandbox sees an empty directory
at the graft point and nothing inside it.

Why this matters for `internal/dockerproxy`: today the bind-mount rule has to
*prove* that a requested source is one the sandbox may see, against the whole
host filesystem, with a daemon-namespace `realpath` and component-wise
containment checks to defeat symlinks the agent planted (DESIGN §7.2 step 4).
Under a derived view the engine **cannot resolve a path the sandbox cannot**,
because the paths are not in its namespace. The remaining job is to refuse
snug's own grafts, which is a short list snug wrote itself. Fail-closed still
applies; the surface it has to fail closed over shrinks from "the host" to
"three paths".

Two costs, both measured or obvious:

- **The graft leaves an empty directory** on the sandbox's writable tmpfs
  (`mkdir` acts on the shared superblock; only the *mount* is namespaced). Use a
  mountpoint snug creates deliberately, and say so in `--dry-run`.
- **The derived view has no usable `/proc`** — MEASURED, `/proc/self/mountinfo`
  is absent, because the procfs mounted there belongs to the sandbox's pid
  namespace and the engine is not a member. The engine needs its own `proc`
  mount, and podman will not start without one.

## 7. The control protocol: not varlink

Varlink is the natural first thought — simple, an IDL, JSON, systemd uses it.
Two reasons not to:

**It cannot carry a file descriptor.** Interactive attach needs a pty; the
choices are to pass fds over `SCM_RIGHTS` (varlink has no notion of them) or to
allocate the pty in P1 and relay bytes over the connection, which is what tmux
does. If the answer is "relay bytes", the IDL is buying nothing that a
newline-delimited JSON frame does not.

**The interface is a security boundary, and the house style for those is a
hand-written strict decoder.** `internal/dockerproxy` decodes with
`DisallowUnknownFields()` plus a trailing-data check so that an unmodelled field
is a 403 rather than an unmodelled capability. A generated dispatcher inherits
whatever the generator's defaults are. Same argument as TOML's strict decoding
(CLAUDE.md, "Decisions made").

Recommendation: newline-delimited JSON over `AF_UNIX`, strict decode, one
request per connection, and a byte relay for interactive sessions. If an IDL is
wanted later it can be written against a protocol that already works.

## 8. Not proven here, and honestly so

- **The container engine leg.** `/usr/bin/podman` on this host is
  `distrobox-host-exec`; the only real engine binary present is
  `podman-remote`. The PoC therefore proves the *shape* (E7: a child with the
  host mount tree and the sandbox's netns) and not podman itself. The container
  measurements in ENGINE-NETNS §2 stand and were taken with `unshare`. The
  preflight in ENGINE-NETNS §5 (real podman binary, `--map-auto` userns,
  `newuidmap` with file capabilities, a cgroup write probe) is unchanged and
  must be a **refusal**, not a warning.
- **Cgroup delegation** — ENGINE-NETNS §3's second host-shaped failure. Nothing
  here improves it.
- **Interactive attach**: pty allocation, resize, and what happens to a payload
  when the last client detaches.
- **Seccomp on an attached process.** The filter snug generates has to be
  installed by the joiner. Straightforward; unwritten.
- **`/etc/containers`, `/run`, `/var/tmp` and the rest of the engine's host
  shape** under §6's derived view. Storage was measured; the others are the same
  mechanism repeated, but each is a named hole and none is free.

## 9. P1 is not a daemon — DECIDED, and enforced

**Decision (owner, 2026-08-11): the stage exits as soon as its last payload
does. There is no detached mode, no `--keep`, and it is never converted into a
service.** MEASURED (E11): with a sandbox whose payload exits after two seconds,
the stage tears itself down, the launcher exits, the network namespace is
destroyed, and a subsequent `ping` on the control socket fails — it did not stay
up waiting for a client.

The mechanism is a reference count over payloads (a sandbox, and any process
attached to one), and the rule that ends the process is `count == 0` after the
count has been non-zero at least once. That last clause is the whole
implementation subtlety: without it the stage exits during its own startup.

This is deliberately *unlike* tmux, whose server survives the last client. tmux
was the model for the **shape** — a process that owns namespaces, several
children hanging off it, a control socket — and is not the model for the
**lifetime**. Invariant 4's promise is that helpers die with the sandbox and
leave nothing behind, and a stage that outlives its payloads to wait for the
next one has quietly become a service with a socket, which is exactly what
"no daemon, no service files" was written to prevent.

What this costs, stated plainly so nobody rediscovers it as a bug:

- **`snug attach` only works while a payload is running.** Attaching to an idle
  sandbox is not a thing, because an idle sandbox is not a thing. `snug <dir> --
  claude` in one terminal and `snug attach` in another is the supported shape;
  `snug attach` to nothing is an error naming the fix.
- **No reconnecting to a detached session.** If the payload's terminal goes
  away, the payload goes away. Running a multiplexer *inside* the sandbox is the
  answer, and it is the payload's choice rather than snug's.
- **Two independent teardown paths, both needed.** The reference count handles
  the ordinary exit; the lifeline pipe (§3.2) handles the launcher being
  SIGKILLed. Neither subsumes the other: the count never reaches zero if the
  payload is still alive, and the lifeline says nothing when the launcher is
  alive and healthy.

**The abuse sentence, for the topology as a whole:**

> a hostile process inside the sandbox can attach to nothing and open no listener
> the host can reach — but it now shares a network namespace with snug's own
> helpers and with every container the engine starts, so it reaches any socket
> they bind **on any address, `127.0.0.1` included, or in the abstract
> namespace**, and any port a container publishes; it can bind those names
> *first* and be connected to in their place; it can read the socket tables to
> enumerate what they talk to; and it holds any descriptor P1 forgot to mark
> CLOEXEC. It cannot reach the host's loopback, the host's containers, or the
> stage's control socket. Its ancestor user namespace is no longer the initial
> one — it is U, which holds the full subuid range and CAP_SYS_ADMIN over N and
> over the sandbox's own mounts, so a userns-escape bug is worth more here than
> it is today.
