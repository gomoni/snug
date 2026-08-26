# The container engine in the sandbox's netns — wiring as built

`host-bridge`, **2026-08-18**. Settles the one architecture question
`go-implementer` handed back: how the **long-lived** container engine composes
with the **one-shot** stage so it inherits the stage's user namespace **U**,
joins the sandbox's network namespace **N**, and serves proxied requests for
the whole run — with the engine confined to `policy.EngineCapBounding` and torn
down on every path.

> **Section numbers are load-bearing** — twenty-four Go comments across
> `internal/stage`, `internal/engine`, `internal/sandbox` and `internal/cli`
> cite them, and nothing checks a section number. Do not renumber; append.
>
> This is a record of a design pass, so the tense is as written. **Where it and
> the code disagree, the code is right and the disagreement is a bug here.**

Everything upstream of the runtime was already landed and is NOT reopened here:
`policy.EngineCapBounding` (12 caps, measured floor), `deriveTopology` raising
`Netns→NetnsStage`/`Subuid→SubuidFull` for podman, `stage.Start`'s
`SubuidFull` delegated-map handshake (`newuidmap`/`newgidmap`, done),
`internal/stage/capdrop.go`'s `dropCapsToExactly` (defined, **not yet called**),
the `--dry-run` engine block, and `TestContainerBindFilterMatchesPolicyVisibility`
(the invariant-6 gate, present). What is missing is the fork itself: today
`startContainers` (`internal/cli/container.go`) **refuses** a real run, and
`internal/engine.Engine.Start` execs podman on the **host** network.

---

## 0. The shape in one paragraph

The engine is forked **eagerly**, **by the stage**, as a **second long-lived
child of P1** alongside bwrap — never threaded through bwrap's lifecycle. The
engine start rides on the `start` request, which emits two events
(`enginestarted`, then `exited`): the engine has to come up while bwrap's
payload is parked, and a request answered without returning is a request after
which the stage reads another one. It happens strictly **after** `netready`. The engine child is cloned with
`CLONE_NEWNS|CLONE_NEWCGROUP` (fresh mount + cgroup ns, a private copy of P1's
host-tree view), then a new re-exec verb `__inengine` does, on a locked thread
and in this order: `setns(fd63, CLONE_NEWNET)` into the sandbox's pinned N →
`mount("", "/", MS_REC|MS_PRIVATE)` → `dropCapsToExactly(EngineCapBounding)` →
seal fds → `execve` podman `system service` on a `/tmp` socket. The engine dies
with the stage (`Pdeathsig` to P1, which is `Pdeathsig`+lifeline to P0);
containers are stopped explicitly before that on the clean path and by the
pipe-triggered reaper on SIGKILL. No `/run` graft; the socket lives on `/tmp`
because podman masks `/run`.

---

## 1. Eager vs lazy — EAGER, forked by the stage before the payload

**Decision: eager.** The engine is forked as a fixed step of the deterministic
stage startup sequence (after the network is confirmed, before bwrap), not on
the first proxied request.

Reasoning, in priority order:

1. **It preserves the stage's one-shot, no-server property** — the single
   biggest structural virtue the stage was built to keep (`serve.go`: "A loop
   would have been shorter and would have quietly turned a one-shot stage into a
   server"). Lazy launch means the stage must accept a "fork the engine now"
   request at an **arbitrary** later time, after it has already moved past its
   serve loop into `cmd.Wait()` on bwrap inside `runOneSandbox`. That is the
   concurrent-request redesign the handback explicitly did not want opened.
   Eager makes the engine fork message N of a fixed sequence, consumed once,
   before the loop exits — the same discipline `netready` and `start` already
   have.

2. **Invariant 5 lands the refusal before any payload exists.** The engine
   shares N; if it cannot be confined to N (preflight fails, `setns` fails, cap
   drop fails), snug must refuse and start **nothing** — never a payload that
   then discovers, mid-run, that its container engine is on the host network.
   Eager makes the engine's successful confinement a **precondition of the
   payload existing**, exactly the shape `WaitNetReady` already enforces ("a
   payload must not exist before its network is confirmed"). Lazy would let the
   payload run first and surface an unconfinable engine only when the payload
   calls `podman` — too late to "start nothing."

3. **`--dry-run` honesty is unconditional.** Eager lets the screen state "a
   per-sandbox engine runs in this sandbox's netns" as a fact of every real run.
   The engine's package doc comment (`internal/engine/engine.go`) currently says
   "starts LAZILY"; that sentence flips to eager, and `--dry-run` gains the
   explicit cost line (see §5).

4. **It removes the hold-the-request-while-it-boots latency plumbing** from the
   proxy entirely.

**The cost, stated plainly and put on screen:** every `@podman-socket` run —
including one that never runs a container, and including an **offline** one —
pays the engine boot (podman `system service` coming up, ~1–2s, plus overlay
store init). This is acceptable: selecting a container profile *is* the
declaration of intent to run containers, and offline-with-a-stage is already a
stated cost (the privileged-ancestor U line on the TOPOLOGY block). `--dry-run` states it (§5).

---

## 2. The fork + confine + join sequence — exact mechanics

### 2.1 Why a second stage child, and why a re-exec verb

The engine must (a) be a **member of U** — joining N needs `CAP_SYS_ADMIN` in
N's owning userns, which is P1's U, and `setns(CLONE_NEWUSER)` from
multithreaded Go is closed (EINVAL); the only route into U is **inheritance
through a fork by a member of U**, i.e. P1 ([`ENGINE-NETNS.md`](ENGINE-NETNS.md)
§1, "you cannot join only the netns"). It must (b)
have its **own** mount + cgroup namespaces — a private copy of the SANDBOX's
view, invisible to the payload — which P1 must **not** share (P1 forks bwrap
next and bwrap needs P1's mount view intact). And it must (c) reach `execve` podman with
`EngineCapBounding` in effect on the thread that execs.

`setns`, the private-copy `mount`, and the cap drop all have to run in the
child, between clone and exec-podman — so a re-exec verb is required, exactly as
`__innetns` is required for bwrap. Call it `__inengine`
(`stage.EnterEngine`), dispatched in `internal/cli/main.go` beside the existing
three verbs.

### 2.2 The clone flags — mount/cgroup ns at clone time, NOT via unshare

The engine child is forked with:

```
cmd := exec.Command("/proc/self/exe", "__inengine", <argv...>)
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP,
    Pdeathsig:  syscall.SIGKILL,
}
```

The mount and cgroup namespaces are created **at clone time**, not by an
`unshare(2)` inside `__inengine`, and that is load-bearing: `unshare(CLONE_NEWNS)`
from a multithreaded Go process returns **EINVAL** (`fs->users != 1`, because Go
threads share `CLONE_FS` — CLAUDE.md's own measured fact). Go's fork/exec does
the clone in the child *before* the runtime starts its threads, which is exactly
how `stageCloneflags` already gets `CLONE_NEWNS` for P1. `CLONE_NEWUSER` is
**deliberately absent** — the child must **inherit** U, not create a sibling.
`CLONE_NEWNET` is **deliberately absent** — N is joined by `setns` in
`__inengine`, per-task and multithread-safe, never at clone time.

`CLONE_NEWCGROUP` here re-adds what `stageCloneflags` deliberately dropped from
P1 (`fds.go`: "The phase that puts an engine in N adds it back, as a conscious
edit with a consumer to point at"). Its one hazard — a kernel without
`CONFIG_CGROUPS` fails the clone as a unit — only affects podman runs, which
need cgroups anyway; the failure is a clear stage-start error, not a silent
downgrade.

### 2.3 Passing N to the engine child

`MainServe` marks `fdNetnsN` (63) **CLOEXEC** at step 1, so it will not survive
the exec into `__inengine`. Use the identical trick `runOneSandbox` uses for
bwrap: wrap it with `os.NewFile(uintptr(fdNetnsN), "netns-N")` and pass it in
the engine child's `ExtraFiles` (Go `dup3`s it into the child **without**
CLOEXEC at a known number). `__inengine` receives that number as its first argv
element, `setns`es it, **closes it**, and never lets it reach podman. Both bwrap
and the engine get their own non-CLOEXEC dup of N; the original stays CLOEXEC in
P1, so P1 can hand it to bwrap afterwards unchanged.

### 2.4 `__inengine` — the order is the specification

On the child, after the clone gave it fresh mount+cgroup ns and U-membership:

1. `runtime.LockOSThread()`.
2. `setns(fdN, CLONE_NEWNET)` into the sandbox's N; re-read and **refuse if the
   thread did not move** (the `__innetns` check, verbatim). Use the
   **descriptor**, never a `/proc/<pid>/ns/net` path — the wrong-attach silent
   failure (`SUPERVISOR-DESIGN.md §3.4`).
3. `close(fdN)` — nothing downstream (podman, conmon, a container) ever holds a
   reference to N it could `setns` with.
4. `mount("", "/", "", MS_REC|MS_PRIVATE, "")` — load-bearing **twice**
   (`ENGINE-NETNS.md §1`): overlay refuses to make its own mount private without
   it, and it keeps podman's per-container nsfs binds out of the host mount tree
   (see teardown, §6). This is process-wide over the clone-created mount ns.
5. `dropCapsToExactly(policy.EngineCapBounding)` — `PR_CAPBSET_DROP` per cap then
   `capset`, on this locked thread. It **keeps** `CAP_SYS_ADMIN` (podman still
   needs it for per-container mounts/namespaces) and `CAP_SETPCAP` (required to
   perform the bounding-set drops), and **drops** `CAP_SYS_PTRACE` (the standing
   gate) and `CAP_NET_ADMIN` (so the engine cannot reconfigure the shared N —
   the reason `-p` publishing is declined rather than paid for). Runs here,
   **after** the mount that needs the full set and **immediately before** the
   exec — capdrop.go's documented contract.
6. `fdseal.SealExcept(...)` — this is the last exec before podman; whatever is
   not CLOEXEC here is what podman (and any container that inherits from it)
   holds. Keep only what podman needs (its stdio; the control channel is **not**
   passed to the engine — the engine talks to snug only through its `/tmp`
   socket, §3).
7. `syscall.Exec(podman, argv, env)` — with an **explicit, minimal env**
   (§3.3), never `os.Environ()` (the `/proc/1/environ` lesson; and P1's env is
   empty anyway).

### 2.5 No uid-map re-exec for the engine — keep the two cases apart

The foundation's `__stage-setup` re-execs itself once because **P1** starts life
as the overflow uid and capabilities compute empty until uid 0 is in effect at a
*second* execve (setup.go step 0, the uid_map-vs-execve recompute bug). **The
engine child has no such problem** and must not copy that dance: it forks from a
P1 that is **already uid 0 in U with a full effective set**, so it inherits full
caps immediately and `dropCapsToExactly` + the single `execve` podman is all
that is needed. The M-CAP measurement ran podman under exactly this shape
("drop bounding + capset, then exec") and it delivered the full M1 container set
— so the reduced set survives the exec for a uid-0-in-U process. State this
distinction in the `__inengine` comment so no one adds a spurious re-exec.

### 2.6 Protocol — one new single-use message

`internal/stage/proto.go`: add `startengine` to the `request` op set and
`enginestarted` to the `event` op set. `MainServe`'s state machine (serve.go)
gains a `case "startengine"` that:

- is refused if asked twice or before `netready` succeeded (same shape as
  `start`'s `!netReadyOK` refusal — the engine, like the payload, must not exist
  before N is confirmed);
- forks the engine child (§2.2–2.4), records its `*os.Process`;
- waits (bounded) for the engine's `/tmp` socket to appear, or reports the error
  in `enginestarted.Err`;
- does **not** return — unlike `start`, `startengine` leaves the loop running so
  `start` can still arrive. The state machine is now "at most one `netready`,
  at most one `startengine`, then exactly one `start`," still finite, still no
  loop-into-server.

`Stage.StartEngine(spec EngineSpec) error` (P0 side) sends the request and
blocks on `enginestarted`, mirroring `StartSandbox`. `EngineSpec` carries the
resolved podman path, the argv (`system service --time <idle> unix://<sock>`),
the store/runroot/socket paths, the `--cgroups=disabled` selection from
preflight P5, and the minimal env — all chosen by P0, none inherited.

---

## 3. The socket — dir, owner, mode, and the reach path

### 3.1 Why `/tmp`, decided (Q4)

Root-in-userns podman forces `mount -t tmpfs tmpfs /run` **inside the engine's
own mount ns** (MEASURED, `ENGINE-NETNS.md §3`), masking anything under
`/run/user/<uid>`. So neither the socket nor the runroot can live under `/run`:
in the engine's ns a pre-created path there is shadowed by the fresh tmpfs, and
a host-side transient podman aimed at the same path would see the **host** `/run`
— a different directory. The store stays under `XDG_DATA_HOME`
(`~/.local/share`, **not** masked, persistent for warm starts); the **socket and
runroot move to `/tmp`**.

### 3.2 Creation, owner, mode, reach

- **Directory:** `/tmp/snug-<uid>-<runid>/`, `<runid>` = snug's pid (unique per
  run, matching the socket's existing pid-keying). It holds `lock`, `sock/`
  (`podman-<pid>.sock`) and `conf/` (the generated containers.conf,
  registries.conf, storage.conf, auth.json and `home/`). The runroot is NOT in
  here: it is keyed by target, not by run — §13.
- **`lock`:** the first thing written into the directory, before `sock/` and
  `conf/` exist, held `LOCK_EX` for the life of the engine and never released
  explicitly. A held lock is what "this run is live" MEANS for this directory,
  and closing it is the only announcement that its owner is gone — which is
  what makes §6's sweep possible. Creation refuses if the lock cannot be taken
  or if the file has already lost its name to a concurrent sweep; it does not
  retry (invariant 5).
- **Who creates it:** **P0 (snug), on the host, before the stage forks the
  engine** — created in `engine.New`, hardened against a planted symlink exactly
  as commit `dfe6ac8` (#61/#85) hardened the live-sockets dir: `mkdir` that
  fails if it already exists (or `O_DIRECTORY|O_NOFOLLOW` + verify owner==uid and
  mode==0700), never a blind `MkdirAll` into world-writable `/tmp`. This is a
  real new exposure `/tmp` brings that `XDG_RUNTIME_DIR` (0700, single-owner)
  did not — call it out in the code.
- **Owner / mode:** host uid, `0700`. The engine runs as root-in-U = the host
  uid on the host filesystem, so the socket and everything under `rr/` are
  host-uid-owned, consistent with every other snug write; `0700` keeps other
  host users out.
- **Reach across the U/N boundary:** the engine's mount ns is a `CLONE_NEWNS`
  copy of P1's host tree, so its `/tmp` is the **same superblock** as the host's
  `/tmp`. podman binds the socket there in its ns; the file is visible on the
  host `/tmp` at the identical path (MEASURED reachable as a pathname socket,
  `ENGINE-NETNS.md §2`). **The host-side proxy dials it directly**, and so does
  the lifeline keepalive (§6). No proxy change, no socket move.

### 3.3 The payload cannot reach it — confirmed

bwrap gives the **sandbox** a fresh tmpfs `/tmp` in **its own** mount ns (the
writable-surface list). That is a different filesystem from the host `/tmp` the
engine's copy shares, so `/tmp/snug-<uid>-<runid>/podman.sock` **does not exist
in the payload's view**. The payload reaches the engine only through the
**proxy** socket bound at the fixed guest path `/snug/podman.sock`
(`containerSocketGuest`, via `pol.BindSocket`). The `/tmp` socket is the proxy's
private upstream endpoint, never the sandbox's — which is the whole point of
having a filtering proxy. redteam must confirm this negatively (§8).

### 3.4 Env for the exec'd podman

Explicit and minimal, chosen by P0 and passed in `EngineSpec` (P1's env is
empty, so nothing is inherited): `PATH` (to find crun/conmon from the static
bundle), `HOME`, `XDG_RUNTIME_DIR` pointing at `rr/`, and
`CONTAINERS_STORAGE_CONF` / `--root`/`--runroot` on argv as today. No host
secret can ride in because the set is enumerated.

---

## 4. Preflight — ordering, all fatal, no fallback

All probes run in **P0**, inside `startContainers`, **before** `sandbox.Run`
(hence before the stage exists), replacing today's blanket `!dryRun` refusal. A
failure prints one fix-naming message and starts **nothing** — and in
particular **never falls back to a host-netns engine** (invariant 5, the line
this whole tier is predicated on). `--dry-run` stays exempt from the *refusal*
(it starts nothing anyway) but should still *run and report* the probe results
so the screen tells the truth about whether this host can deliver the policy.

Order — cheapest and most decisive first, so the common misconfig fails
instantly:

| # | probe | fires | outcome |
|---|---|---|---|
| **P6** | `/proc/sys/kernel/yama/ptrace_scope` | first | **REFUSE iff == 0** (settled Q2). The M6 in-U cap-drop argument holds only on `ptrace_scope=1`; `2`/`3` are stricter and pass. No warn-and-continue. |
| **P1** | real podman, not a host-escape shim (`detectHostShim`/`podmanClientUsable`, promoted from warning to refusal) | 2nd | **FATAL.** A distrobox `distrobox-host-exec`/`host-spawn`/`flatpak-spawn`/`#!` wrapper forwards to the host engine over a *filesystem* socket netns does not touch — a container would land on the host and the whole tier evaporates while looking healthy. Error names the shim and the fix: install the distribution `podman` package. This also **eliminates the wrapper case** the old lifeline existed for (§6). |
| **P2** | `/etc/subuid` + `/etc/subgid` have a range for this user | 3rd | **FATAL.** Names the fix: `<user>:100000:65536`. |
| **P3** | `newuidmap`/`newgidmap` present with authority (file caps or setuid — accepted, Q3) to write a multi-range map | 4th | **FATAL.** Names shadow-utils. |
| **P4** | overlay + `MS_REC\|MS_PRIVATE` in a userns (a throwaway probe: unshare mount ns, make `/` private, confirm overlay usable) | 5th | **FATAL.** Names the storage-driver hint. |
| **P5** | cgroup write probe (attempt a write under `/sys/fs/cgroup/…`; ENOENT/EACCES ⇒ select `--cgroups=disabled`) | last | **SELECTS a flag**, not fatal — fatal only if even `--cgroups=disabled` cannot start a container. M-CGROUP: `--cgroups=disabled` is required on this host and forces a private pidns (the teardown lever, §6). `podman build`'s RUN step neither takes nor needs it — it is a `run`-path fact. |

P1–P4 and P6 gate the run; P5 sets an `EngineSpec` flag. Because the engine is
eager, all of this happens before the stage forks anything, so a failure costs
one message and no half-built namespace tree.

**The engine runs in a netns the stage made, always.** `deriveTopology`'s podman
branch raises `Netns` to at least `NetnsStage`, and `NetnsStage` is the top of
that order, so no selection can hand the engine a namespace `stage.Start`
refuses. `stage.Start`'s `Netns != NetnsStage` guard is therefore a statement
about hand-built topologies, not about anything `Resolve` produces.


---

## 4a. Which config key governs which binary

MEASURED against podman 5.8.4 and 6.0.2, driving real container starts. snug
writes `helper_binaries_dir` and does **not** write `conmon_path`,
`[engine.runtimes]` or `seccomp_profile`.

| key | governs | snug writes it | fallback if unset |
|---|---|---|---|
| `helper_binaries_dir` | netavark, aardvark-dns, catatonit, rootlessport, pasta | yes | **none** — no `$PATH`, no default merge |
| `conmon_path` | conmon | no | compiled default list, then **`$PATH`** |
| `[engine.runtimes]` | crun, runc | no | compiled default list |
| `seccomp_profile` | the seccomp profile | no | `/usr/share/containers/seccomp.json` |

Consequences, each measured:

- `helper_binaries_dir` does **not** govern conmon or the OCI runtime. Setting it
  and nothing else leaves both resolving from the compiled defaults.
- With `helper_binaries_dir` set to one empty directory:
  `Error: could not find "netavark" in one of [<that dir>]`. It is the whole
  authority for its five, so an entry snug omits is a helper the engine cannot
  find.
- `conmon_path` falls back to `$PATH`: with a nonexistent path,
  `Using conmon from $PATH: "/usr/bin/conmon"`. So `PinnedPATH` is a second door
  into conmon selection, and writing `conmon_path` alone would not pin it.
- `seccomp_profile` unset plus no `/usr/share/containers/seccomp.json` gives
  `building at STEP "RUN …": opening seccomp profile failed`, and the affected
  tests **skip** rather than fail — a green suite measuring nothing.

**Why this is here and not in prose elsewhere:** these are facts about podman,
not about any particular engine installation, and each one decides whether a
generated `containers.conf` actually pins what its author believed it pinned.

`--signature-policy` is per-subcommand, and the projection depends on it.
MEASURED on 5.8.4 and 6.0.2 alike, with a control
(`--snug-bogus-flag` -> `unknown flag`):

| command | verdict |
|---|---|
| global, `podman system service` | `Error: unknown flag: --signature-policy` |
| `pull`, `image pull`, `create`, `run`, `build` | accepted, hidden, absent from `--help` |

`system service` is the only command snug runs and the proxy's pull happens
inside that process over the API, so no per-command flag reaches it and the
engine's own `$HOME` is the whole mechanism. **The engine is not pinned, so this
is a claim about a moving target: it belongs in a test that goes red, not in this
table alone.**

---

## 5. `--dry-run` — the eager cost on screen

The policy pass already rewrote the engine and CONTAINERS blocks. Two additions
this wiring pass owns:

- The engine's package doc and any screen line implying **lazy** flips to
  **eager**: "a per-sandbox engine is started *with the sandbox* (before the
  payload), in this sandbox's netns" — with the cost stated: an offline
  `@podman-socket` run boots an engine it may never use.
- The preflight results (P5's `--cgroups=disabled` selection, P6's
  `ptrace_scope` value) appear on the screen, since `--dry-run` runs the probes.

Goldens: bwrap and pasta argv are **unchanged** (the engine attaches to the same
N; `PastaArgs` does not change). The `--dry-run` text goldens
(`topology.podman-*.txt`, `containers.podman-*.txt`) move — the review artifact.
A security change with no golden diff is untested.

---

## 6. Teardown — engine and containers die with the run

Layered, none assuming the engine is *directly* snug's child, matching on the
**store/socket path and the run label, never `comm`** (the `pasta.avx2` lesson).

**Engine process.** The engine is `Pdeathsig: SIGKILL` to **P1**; P1 is
`Pdeathsig`+lifeline to **P0**. So `engine ⊂ P1 ⊂ P0`: any death of snug —
exit, panic, SIGKILL, OOM — cascades SIGKILL down to the engine. `Pdeathsig`
survives the `execve` into podman because that exec **drops** caps (no widening
⇒ no secureexec ⇒ pdeath_signal preserved — the same measured fact that keeps
P1's own `Pdeathsig` alive across `setup→serve`). This **replaces** the engine's
old lifeline-as-teardown: the lifeline existed because a *wrapper* engine was not
snug's child, and **preflight P1 now refuses wrappers**, so the engine is always
a real stage child. No engine-orphan window, and because the engine's death
destroys its mount ns, its private-tree copy and any mount in it vanish with it.

**Keep the lifeline, repurposed.** podman `system service --time <idle>` is
finite (never `--time 0`, the daemon this project does not run). To keep the
engine alive during idle stretches of a live run, P0 still holds one keepalive
stream open to the `/tmp` socket (`internal/engine/lifeline.go`, dialing the new
path). Its role narrows from "tear down a wrapper engine" to "hold a finite-
timeout engine up while the sandbox lives"; the finite timeout is now only a
backstop for the should-never-happen case of an engine outliving P1.

**Containers.** With containers sharing N **host-mode** (settled: no per-container
netns, no bridge, no `-p`), podman creates **no** per-container netns nsfs bind —
so the host's `/run/user/<uid>/netns/` stays empty by construction, and
`MS_REC|MS_PRIVATE` on the engine's tree is the belt-and-suspenders that also
keeps any nsfs podman *does* make from propagating out. conmon still
double-forks, but the init that adopts the grandchild is **podman**, pid 1 of
the engine's own pid namespace (`CLONE_NEWPID` on the engine's clone in
`internal/stage/enginefork.go`, plus the fresh procfs `__inengine` mounts), so
**containers die with the engine**: killing it collapses the namespace and
everything in it. A SIGKILL of snug reaches a clean state in under 70 ms end to
end.

**Neither path runs a host-side `podman` teardown, and must not.** The pids
libpod records in the runroot are numbered in the ENGINE's pid namespace, so a
host-side invocation reads numbers meaningless in its own numbering — whether
the engine is still alive or already collapsed. Translating them through the
engine's namespace was rejected: it is new machinery to make a mechanism land
on namespace-local numbers, for an outcome the kernel already delivers faster.
The cost, stated: no best-effort graceful `SIGTERM` for a workload that handles
one. Restorable through the engine's OWN socket if wanted, never by reading
host-numbered pids. `internal/engine`'s package comment and `stopLocked` carry
the argument.

Two mechanisms:

- **Clean path:** `sandbox.Options.OnPayloadExit` (§12 item 1) fires after
  `st.Wait()` and before the deferred `st.Close()`, and calls `Engine.Stop`:
  drop the keepalive, verify by the socket-path sweep, tear down the reaper.
  Bookkeeping only — nothing in it depends on the engine still being
  reachable.
- **SIGKILL path:** the pipe-triggered reaper (`internal/engine/reaper.go`)
  stays: P0 holds a pipe; on EOF a detached `/bin/sh` removes the run
  directory (containers.conf, registries.conf, auth.json, resolv.conf, the
  generated home/, and the socket) — no `podman stop` any more, for the same
  reason as the clean path's. It carries its paths in the **environment**,
  not argv, so the by-path verification sweep does not mistake the reaper
  for a leak. `rm -rf` on the run directory rather than a per-file removal
  list: the directory is 0700, uid-checked, under an unpredictable pid-
  derived name — exclusively snug's own — so recursively removing it cannot
  reach anything this run did not itself create, and it needs no shell-side
  duplicate of what `Engine.Spec` writes there.

**The run DIRECTORY is part of this guarantee, and nothing above delivers it.**
`Pdeathsig` and the pid-namespace collapse delete processes; the run directory
and everything in it are files, and no signal removes a file. Two mechanisms,
and neither is the other's fallback:

- **`Engine.Stop`,** on every path snug controls — clean exit and every error
  path `container.go` arms a deferred `Stop` for. It removes the directory
  through the parent descriptor held since `New` rather than by re-walking the
  path — `os.RemoveAll` on a route that may not lead to this run's inode
  reports success having removed nothing — and names on stderr what it could
  not remove: a directory snug could not clean up is state that survives the
  user, invariant 4.
- **`sweepStaleEngineRunDirs`,** on the way IN of the next engine start, called
  by `New` before it claims its own name. This is the case `Stop` structurally
  cannot cover: a SIGKILLed run executes nothing on its way out, so the only
  code that can act there is the pre-armed shell above — and the sweep is what
  covers a run that never armed one, or whose shell did not get to it. The liveness
  test is §3.2's flock and nothing else — no `/proc`, no start-time compare, no
  parsing the pid back out of the name — because SIGKILL releases an flock
  along with everything else the dying process held. It also keeps a leftover
  from being a landmine for the very run doing the sweeping: the name carries
  this process's pid and creation refuses to reuse an existing entry, so a
  stale directory poisons that pid number until something removes it.

The sweep claims the prefix `snug-<uid>-`, and the **trailing dash is
load-bearing**: `snug-<uid>` (`internal/cli`'s runtime directory when
`$XDG_RUNTIME_DIR` is unset) and `snug-engines-<uid>-<key>` (the per-target
runroot, §13) are other mechanisms' state, and all three live in the same
`os.TempDir()`. What the sweep **deliberately leaves** is an entry with no
`lock` file at all: on shared, world-writable `/tmp` that shape is a
concurrent run mid-creation as much as it is litter, and it is left rather
than guessed at.

MEASURED (#425): one `go test ./internal/engine/` run took `/tmp/snug-1000-*`
from 855 to 896 directories, with 100 distinct pids represented across those
896, on a host whose `/proc/sys/kernel/pid_max` is 4194304.

**Verification.** `reap.go`'s `signalOwned`/`waitQuiet` still sweep `/proc/*/cmdline`
for the **socket path as the engine's own argv spells it** and for the label:
never `comm`, and never the shared **store** path (which would reach a
concurrent sibling). That spelling is the GUEST path inside the engine's derived
view, `/snug/engine/sock/podman-<pid>.sock`, pid-unique; the host spelling
`<run dir>/sock/podman-<pid>.sock` is deliberately not matched, because no
process on the machine carries it and sweeping for it is indistinguishable from
not sweeping. The engine's own cmdline names the socket; container/conmon
cmdlines carry the label. "The kill returned no error" is not evidence anything
died; the sweep is.

**Ugly paths redteam must exercise (§8):** engine segfault, snug SIGKILL, P1
killed directly, conmon's double-fork — after each, assert N is gone (no leaked
netns), no container survives, and host `/run/user/<uid>/netns/` is empty.

---

## 7. The `/run` graft — NOT needed

Decision: **no graft.** The engine's private mount-ns copy gets a working `/run`
from podman itself (the forced `tmpfs` on `/run`), and the socket + runroot live
on `/tmp` precisely to sit *outside* that masking. So there is nothing to graft.

A `/run` graft would put a piece of the **host's** `/run` in the engine's view,
which nothing needs: the engine's own `/run` is a fresh, empty tmpfs the stage
mounts (podman does not self-mount one for a root-in-U process holding the full
delegated subuid range), and `internal/cli/engineview.go` models that mount so
the model can see it. The distinction this rests on: a **graft** is an
`open_tree`/`move_mount` of a policy-named host subtree and is the only thing
that can carry host data into the view; `/proc`, `/sys/fs/cgroup`, `/run` and
`/var/tmp` are fresh mounts of empty or namespace-local filesystems and carry
none. State in the `__inengine` comment that a `/run` graft is deliberately
absent and why.

---

## 8. Invariant 6 — do not diverge the two authors

The engine's mount view is **derived from the sandbox's** (`policy.EngineView()`),
so a host path reaches the engine only through a `p.Grafts` entry the resolved
`Policy` authored. What stops a *container* binding an ungranted path is the
**proxy's bind filter**, which reads the **same resolved `Policy`**. Two
mechanisms over one model: no mount may be added to the engine's view that the
model does not name, and the engine spec must never become a second place that
decides what a container may see. `TestContainerBindFilterMatchesPolicyVisibility`
is the standing gate.

---

## 9, 10 — vacant

`§11` and `§12` keep their numbers: Go comments cite sections of this file by
number.

Where the answers live now: `internal/stage`'s `EnterEngine`
(`__inengine`), `Stage.StartEngine` and its `startengine` message;
`internal/engine`'s run directory and `EngineSpec`; `internal/sandbox`'s
`runStaged`; and `internal/cli/container.go`'s preflight. The integration
tests are in `test/integration/containerengine_test.go`.

---

## 11. Abuse sentence and threat notes for `redteam`

**Abuse sentence** (engine + wiring):

> A hostile process inside the sandbox can run arbitrary code in a container
> that shares the sandbox's own network namespace — reaching exactly what the
> sandbox reaches and no more (with `@net`, the internet; without it, nothing) —
> and can drive the per-sandbox podman engine, which runs in the sandbox's user
> namespace U as root-in-U bounded to 12 capabilities. It **cannot** reach the
> host loopback, the host's containers or images, the host `/run`, or reconfigure
> N (no `CAP_NET_ADMIN`); it **cannot** ptrace a peer in U (no `CAP_SYS_PTRACE`);
> and it can bind into a container only a path the sandbox can already see —
> structurally, because the engine's view is derived from the sandbox's
> (`policy.EngineView`), and by name, because the proxy's bind filter refuses
> one anyway. The engine's
> `/tmp` socket is the proxy's private upstream and is not in the payload's mount
> view.

**redteam should attack:**
- **A container escaping N** — confirm by *behaviour* (egress iff the sandbox has
  it), never by reading a namespace id (the empty-id/`pasta.avx2` trap).
- **The engine's authority in U** — `/proc/self/status` `CapEff/CapBnd` of the
  stage-forked engine is the 12-cap set with `PTRACE` and `NET_ADMIN` absent; a
  `process_vm_readv` of a peer in U **fails**; positive control: the same probe
  with the cap left in reads the peer (M6, re-run against the *integrated*
  topology, not a standalone `unshare`).
- **The wrong-attach silent failure** — the engine is in the *sandbox's* N, not
  P1's post-move empty netns or the host netns.
- **The `/tmp` socket** — the payload cannot reach `/tmp/snug-<uid>-<runid>/`
  (separate tmpfs), and the run dir is not a symlink-plant vector on shared
  `/tmp`.
- **Teardown on every ugly path** — engine segfault, snug SIGKILL, P1 killed,
  conmon double-fork: no orphaned netns, no surviving container, host
  `/run/user/<uid>/netns/` empty, matched on the socket path.
- **The offline claim under load** — `@podman-socket` no `@net`, a container
  trying DNS, raw IP, container-to-container: every path fails while the screen
  says "No egress."
- **The invariant-6 mount surface** — every `-v`/`--build-context`/`--mount`
  shape for a path the sandbox cannot see reaching a container. Both layers
  must refuse: the derived view has no such path to name, and the bind filter
  refuses it by name.

---

## 12. Two answers, and the one open question

1. **The `OnPayloadExit`/`EngineStop` seam (§6).** `sandbox` must not import
   `engine`, so the clean-path teardown call is a hook on `sandbox.Options` —
   `OnPayloadExit`, called after `st.Wait()` and before the deferred
   `st.Close()` collapses the stage. What it does there is verify-and-standdown
   bookkeeping, which also runs on the SIGKILL path, so its POSITION buys
   nothing observable; it is kept where it is because moving it is an
   independent decision with its own review.
2. **A container gets the sandbox's own netns and no other** (§4).
   `deriveTopology`'s podman branch raises `Netns` to `NetnsStage`, the top of
   that order, so it cannot produce a topology `stage.Start` rejects.
3. **OPEN — retiring the lifeline entirely.** With `Pdeathsig` cascading engine death
   and preflight refusing wrappers, the lifeline's *teardown* rationale is gone;
   it survives only to keep a finite-timeout engine alive during idle. An
   alternative is `--time 0` + `Pdeathsig` alone (simpler, but an immortal engine
   if `Pdeathsig` ever misses, and "the daemon this project does not run").
   Recommendation: keep the finite timeout + keepalive; the maintainer may prefer
   the simpler `--time 0`. Not blocking.

---

## 13. Reclamation — three directories, three lifetimes

| directory | keyed by | ends when |
|---|---|---|
| store, `$XDG_DATA_HOME/snug/engines/<key>/storage` | target | `snug engine gc` names it |
| runroot, `/tmp/snug-engines-<uid>-<key>/rr` | target | it goes with the store |
| run dir, `/tmp/snug-<uid>-<runid>/` | run | §6 |

`<key>` is `internal/targetkey.Hash` of the canonical target: `sha256_` + the
full hex digest, the same function the per-target lock's name goes through.
The store persists across runs ON PURPOSE — it is the image cache a warm start
reads — so nothing at teardown touches it, and `snug engine gc` with a selector
is the only thing that removes it. The runroot is per-target too, not per-run,
which is why it is not inside the run directory; both sit on `/tmp` rather than
under `$XDG_RUNTIME_DIR` for §3.1's masking reason.

### 13.1 What `gc` reclaims is what `gc` can SEE, and a payload shapes that

`gc`'s pre-flight walks the store read-only and refuses the WHOLE store on any
entry this uid does not own. It cannot look inside a directory it owns whose
mode denies traversal, so a foreign-uid subtree hidden under one is invisible
to that walk. This is payload-reachable rather than hypothetical: image content
owned by a non-root uid inside the image lands on disk owned by whatever host
uid the subuid map delegates that namespace uid to, which is commonly not
snug's own. **So a container payload can shape what a later `gc` is able to
reclaim.**

The gap is closed at phase 2 instead of papered over at phase 1. The recursive
delete reaches the same directory, gets the same denial, chmods open what it
has already confirmed it owns, meets the foreign-owned child and stops —
leaving a named `.gc-` directory that still carries its own `store.json`. The
next invocation describes that leftover by name and by target and retries it
whether or not a selector was given, because it needs no liveness question at
all. A store snug cannot finish removing is therefore visible, not silently
retried forever.

### 13.2 Three states, never two

- **attributed** — a breadcrumb whose `Target` checks out: `KeyForTarget(Target)`
  equals the directory's own name.
- **unattributed** — no breadcrumb at all. Ordinary rather than suspicious: a
  store whose breadcrumb was never written, or whose write failed.
- **untrustworthy** — a breadcrumb IS present and fails the check: unknown
  schema, a forging rune in `Target`, or a key mismatch. Reported as
  unattributed **and flagged**.

Three and not two: folding untrustworthy into either bucket would let a forged
or broken breadcrumb pick which liveness arm runs against a live store.

Attribution decides which liveness arm runs. **Arm A**, for an attributed
store, computes the EXACT per-target lock name from the breadcrumb's target —
the same function a live run calls — so there is no scan and nothing to drift,
and a published run-state whose full pid+starttime+namespace identity still
matches refuses on its own; that record's absence proves nothing and is never
read as safety. Arm A does not check liveness and then act: it HOLDS that lock
while it renames the store aside, and the slow recursive delete runs only after
the lock is released — the rename, not an assumption about how long deletion
takes, is what makes the rest safe to run unlocked. **Arm B** is §13.3, and it
holds no lock at all, because it cannot name one.

### 13.3 Arm B: any live snug run anywhere refuses an unattributable store

For a store with no trustworthy attribution — no breadcrumb, a breadcrumb that
fails the check, or a key a human named on the command line with nothing
attributing it — `gc` asks one question that needs no target string: **is any
snug run live on this host right now?** It probes every `target-*.lock` in the
shared runtime directory with a non-blocking shared flock; one `EWOULDBLOCK`
answers yes, and every unattributed removal is then refused. An absent lock
directory short-circuits the whole question: nothing has ever locked anything
on this host, so nothing can be live.

**Coarse by design.** A live run elsewhere may be the owner of the very store
that cannot be attributed, and arm B cannot tell that run from an unrelated
one, so it refuses on either. It also holds nothing while it works — it has no
name to lock — so its refusal is the only thing standing between an
unattributable store and a live user of it. That is the fail-closed direction,
and it is the direction that matters: removing a layer directory under a live
overlayfs corrupts it with no error on either side.

**Whether it is the right trade is UNRESOLVED.** The cost is real and falls on
a human: `--unattributed` does nothing until no sandbox is running anywhere on
the host, however unrelated. Stated as an open question because the alternative
has not been decided, not because the coarseness is a bug.

A narrower arm B needs one of two things it cannot have today:

- **Which store key each live run is using.** A run publishes its target
  (`state.json`), not its key, and that record's ABSENCE is never read as
  evidence a target is safe — so it cannot carry a fail-closed decision.
- **A guarantee that a store's key names its lock.** `engineKey` guarantees
  only the sound direction: the store's partition is at least as fine as the
  lock's, so a store has at most one live user. Today the two names are the
  same hash of the same canonical target string, but a probe built on that
  equality answers "no matching lock, not live" both when no run is live and
  when the equality has moved — deleting a live run's store on the second.
  Arm A refuses to lean on it even where it holds the target string, computing
  the exact lock name from that string instead.
