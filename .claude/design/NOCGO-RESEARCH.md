# Avoiding cgo for the attach path — research in progress

Constraint from the owner (2026-08-11): **avoid cgo at any cost.** The plan's
Phase 2 recommended a cgo constructor for the joiner; this document is the
attempt to disprove that recommendation. Written as it goes, because the laptop
suspends.

## The problem, stated exactly

`snug attach` in the PoC works by `setns(2)` into a running sandbox's seven
namespaces. Two kernel requirements make that hostile to Go:

1. `setns(CLONE_NEWUSER)` **requires a single-threaded caller** (EINVAL
   otherwise). The Go runtime starts sysmon and GC threads before `main`, so no
   Go program is ever single-threaded when its code runs.
2. `setns(CLONE_NEWNS)` requires the caller **not share filesystem context**
   (`CLONE_FS`) with another thread. Go creates its threads *with* `CLONE_FS`.

So the block is not one syscall in one place — pure Go cannot join either of the
two namespaces that matter. `runtime.LockOSThread` does not help: it pins the
goroutine to a thread, it does not remove the other threads.

## Why `/proc/self/exe` alone does not close it

The owner's suggestion — children reach the helper through `/proc/self/exe`
rather than a path on disk — is **right about the problem it solves**, and it
solves a real one the review found: the PoC locates its helper with
`dirname($NSD_SELF)` and executes the result as root-in-U, which is a same-uid
path-swap window. `/proc/self/exe` is a reference to the running inode, immune
to a replacement of the path it was loaded from, and `fexecve`/`execveat` on it
needs no name at all.

But it re-executes into *another Go program*, which is multithreaded again by the
time any of its code runs. `/proc/self/exe` fixes **locating**, not
**single-threadedness**. The two problems were conflated in the plan; they are
separate and only one of them is solved for free.

## Three candidate answers, being measured now

### A. Fork the new payload from the sandbox's own init — no setns at all

The strongest candidate, and it inverts the design rather than working around it.
snug already runs its own init inside the sandbox. That process is **already in
every namespace**. If P1 asks it to fork, nothing needs to be joined.

SUPERVISOR §5 rejected "a control socket inside the sandbox", and the argument
was correct: any socket a shim inside can reach, the payload can reach. But this
channel is **not a socket in the sandbox's filesystem** — it is an inherited
`socketpair` descriptor, bound to no path, present in no namespace's name space,
and marked CLOEXEC so the payload never inherits it. The payload's route to it
would be `/proc/<init>/fd/`, which is what must be closed and measured:

- `PR_SET_DUMPABLE, 0` makes `/proc/<pid>/{fd,environ,mem}` owned by the
  namespace's uid 0 rather than the process's uid, which is the same mechanism
  that protects a setuid binary. The payload is uid 1000 in the sandbox's
  innermost userns; init would be uid 0 there.
- snug's seccomp filter already denies `ptrace`, which is the other route.
- The payload cannot usefully kill it: if the forker dies, bwrap (pid 1 in the
  sandbox's pid namespace) exits and the sandbox goes with it. Self-defeating
  rather than an escape.

**And it is not merely a workaround — it is a better security property.** A
forked child inherits the seccomp filter, the capability sets, `no_new_privs` and
the cgroup **by construction**. The setns joiner has to *reproduce* all four, and
SUPERVISOR §4's own list of "what the joiner must still reproduce" is exactly the
set that fork gets for free. Phase 2's hardest exit criterion — an attached
process is confined identically to the primary — stops needing a test that
compares two code paths, because there is only one.

Open questions, all measurable:
- Does `PR_SET_DUMPABLE, 0` actually deny a same-uid sibling in a user namespace?
- Is the forker reachable at all — is it pid 1 or pid 2 inside, and does that
  change who can signal it?
- What does the *primary* payload's exit do to a forker that must outlive it?
- The pty still has to reach the new payload; with fork-from-init the fd travels
  P1 → init over the socketpair by `SCM_RIGHTS`, which is one hop more than the
  joiner needed.

### B. `nsenter(1)` from util-linux

Avoids cgo and ships no new binary. snug already depends on `bwrap`, `pasta`,
`newuidmap`/`newgidmap`, so one more external helper is consistent with existing
practice rather than a change in kind. The cost is that the confinement is then
applied by a program snug does not control, which is the same objection that
makes A better; and it must be located on disk, which is the problem
`/proc/self/exe` was meant to remove.

### C. A helper carried inside the snug binary and executed without a path

If a small static helper is unavoidable, it does not have to exist on disk:
embed it, `memfd_create` + seal + `fexecve`. No path to swap, nothing to
package, one binary on the filesystem. This keeps the setns design intact while
removing the review's `dirname(argv0)` finding. It is the fallback if A fails.

## Status

Being measured now, in `poc/nsd/`. Findings land here as they arrive.

## Measured while the research ran: how snug's own code gets INTO the sandbox

Option A needs snug's binary to run *as the sandbox's first process*, and today
it has no way in: `internal/sandbox/exec.go` builds `bwrap --args <memfd> --
<p.Command...>` and bwrap execs the user's command directly. **There is no snug
init inside the sandbox at all.** Adding one is the real cost of option A, and
the first question is how the binary crosses the boundary without a grant naming
a host path.

**MEASURED — an inherited descriptor is the way, and it works today:**

```
exec 9< /usr/bin/bash
bwrap … --ro-bind /proc/self/fd/9 /payload  /payload -c '…'
INSIDE-OK
```

bwrap resolves the bind source through its own `/proc/self/fd/9`, which is the
inode snug opened, not a path anything can replace. This is the owner's
`/proc/self/exe` intuition, and it is correct — with one correction on the
mechanism, also measured:

```
bwrap … --ro-bind /proc/<snug-pid>/exe /payload
bwrap: Can't find source path /proc/281110/exe: Permission denied
```

`/proc/<pid>/exe` is readable by an ordinary child of that pid (verified
separately), so the refusal is bwrap's own doing — it resolves bind sources
*after* unsharing its user namespace, where it no longer passes the
ptrace-access check against a process owned by the real uid. So the reference
must be **snug's own fd, inherited**, not a `/proc/<pid>/` path handed to a
helper that has already changed identity. Same idea; the fd survives the
identity change and the path does not.

Two properties fall out, and both are the ones the review asked for:

- **No path to swap.** The review found the PoC locating its helper by
  `dirname($NSD_SELF)` and executing the result as root-in-U. An inherited fd
  removes the lookup entirely; there is no name to win a race against.
- **No new grant.** The binary arrives as a descriptor snug already holds, so
  nothing in the policy has to name a host path for it, and `--dry-run` renders
  it as snug's own authored mount rather than as a hole.

Note the tension to resolve if option A is taken: the fd is inherited, and
CLAUDE.md's own lesson is that an inherited descriptor ignores the mount
namespace entirely. Here it points at snug's binary — not secret, read-only —
but `sealInheritedFDs` must still run, and the init must close it before forking
the payload, so the fd stops existing at the moment untrusted code starts.

## The other costs of option A, from reading the current code

Inserting an init changes four things that are working properties today, and
each needs an answer before the design is chosen:

1. **Exit codes.** `Run` returns "the payload's exit code verbatim, so
   `snug … -- make test` is usable in a pipeline" (`internal/sandbox/exec.go:24`).
   An init in between must wait and re-exit with the payload's status, including
   the signal-death cases.
2. **Signals.** Ctrl-C and SIGTERM currently reach the payload directly.
3. **Job control.** CLAUDE.md records that snug omits `--new-session` on this
   kernel, which is *why* job control works in an interactive sandbox shell. An
   init that does not get the foreground process group right breaks that, and
   the symptom will look like a terminal bug rather than a topology bug.
4. **`--die-with-parent` semantics** shift by one process.

None of these is hard. All four are the kind of thing that is discovered by a
user rather than by a test, so they belong in the plan as named work.

---

# ANSWER: cgo is avoidable, and so is the C helper

**The blocking claim was true and answered the wrong question.** `nsdjoin.c`'s
header says setns needs a single-threaded caller and the Go runtime never is.
Both halves are correct. What neither half says is that **the process calling
`setns` does not have to be the Go process.** A raw `fork` from a multithreaded
Go program produces a child that is single-threaded *and* owns its own
`fs_struct` — which are exactly the two states the kernel checks.

## What the kernel actually checks — MEASURED, both errnos

| namespace | pure Go, multithreaded |
|---|---|
| mnt | **EINVAL (22)** |
| user | **EINVAL (22)** |
| pid, ipc, uts, net, cgroup | OK |

Two independent checks with one root cause. `userns_install()` returns `-EINVAL`
on `!thread_group_empty(current)`; `mntns_install()` returns `-EINVAL` on
`fs->users != 1`, and Go creates every thread with `CLONE_FS`, so `fs->users` is
the thread count. **So mount-namespace setns is blocked in pure Go too** — that
was the question whose answer would have changed the conclusion, and it does not,
because the fix addresses both at once.

`runtime.LockOSThread` changes **no row**, and neither does `GOMAXPROCS=1`.
Neither reduces the thread count to one nor unshares `fs_struct`. LockOSThread is
a red herring here and would have been the obvious thing to try.

**Keep these two errnos apart, they are a diagnostic:** EPERM means the joiner
lacks `CAP_SYS_ADMIN` in its own user namespace — measured, every row fails that
way. **EINVAL means the wrong thread or fs state.** Confusing them costs an hour.
(It cost one here: the first verification run failed with the joiner invoked from
a host shell instead of as a child of P1.)

## The technique, and Go's own source is the model

`syscall/exec_linux.go` has **no** setns — `grep -c setns` is 0, and there is no
`SYS_SETNS` constant for amd64 in the stdlib. `Cloneflags`/`Unshareflags`
*create* namespaces and cannot join one; `CgroupFD` is a cgroup directory for
`CLONE_INTO_CGROUP`, not a namespace join. So `SysProcAttr` is not the answer.

But that same file is the proof the technique is sound, at `exec_linux.go:129`:

> *"In the child, this function must not acquire any locks, because they might
> have been locked at the time of the fork. This means no rescheduling, no malloc
> calls, and no new stack segments."*

Go's own exec child is single-threaded with its own `fs_struct` — `CLONE_FS` is
never set. **Go declines to expose setns there; it does not lack the
capability.**

The joiner therefore: opens all seven `/proc/PID/ns/*` descriptors *before* any
setns (after joining mnt, `/proc` is the sandbox's own); marshals argv and envp
before the fork, because the child cannot allocate; `LockOSThread`, `ForkLock`,
`runtime_BeforeFork`; `RawSyscall(SYS_CLONE, SIGCHLD, 0, 0)`; and in the child —
`//go:nosplit`, RawSyscall only, never returning to Go — the seven setns calls in
the order `mnt,pid,ipc,uts,net,cgroup,user`, the capability drop, a second raw
clone (because `setns(CLONE_NEWPID)` moves only *children*), and `execve`.

`//go:linkname beforeFork syscall.runtime_BeforeFork` **works in Go 1.26** —
`-checklinkname` does not block it. That is the same discipline
`syscall.forkExec` uses, and it closes the one real hazard: a signal landing in a
Go handler in a child whose runtime has no other threads.

## VERIFIED INDEPENDENTLY, against a real sandbox

Built `CGO_ENABLED=0`, static ("not a dynamic executable"), and run as a child of
P1 against a live PoC sandbox — the same target, the same run, both joiners:

```
                    pure Go                     C nsdjoin
  mnt      mnt:[4026533273]            mnt:[4026533273]
  pid      pid:[4026533279]            pid:[4026533279]
  net      net:[4026532452]            net:[4026532452]
  user    user:[4026533282]           user:[4026533282]
  CapEff       0000000000000000            0000000000000000
  CapBnd       0000000000000000            0000000000000000
  NoNewPrivs                  1                           1
```

Byte-identical. The joiner also reports `threads_at_main=5`, which is the direct
measurement of why the naive approach cannot work.

Stress, from the research run: 200 joins, then 100 under `GOMAXPROCS=16 GOGC=1`,
then 300 with the capability drop, then 500 with `BeforeFork` — zero failures,
including against a real `bwrap --unshare-all` sandbox rather than only
`unshare(1)`.

## What this kills

- **cgo.** Not needed.
- **The second binary.** `poc/nsd/join/nsdjoin.c` is deleted, and with it the
  review's `dirname($NSD_SELF)` finding — there is no helper to locate.
- **`/proc/self/exe` re-exec as a route to single-threadedness.** MEASURED: a Go
  process has **5 threads** at the first statement of `main`, and 3 under
  `GOMAXPROCS=1`. Never 1. There is no pre-runtime hook in pure Go — a cgo
  `__attribute__((constructor))` is precisely the hook cgo buys, and this removes
  the need for it rather than finding a substitute.
- **The memfd fallback (option C).** It works — `memfd_create` + full seals
  (verified: a later write returns EPERM) + `execveat(fd, "", AT_EMPTY_PATH)`
  executed a C helper that then joined the user namespace. But since a *Go*
  binary is never single-threaded at start, the memfd would have to carry a **C**
  helper, making it a C-helper design in disguise. It also inherits a real cost:
  there is no static glibc on this box, so the blob would be dynamically linked
  and would need the loader at exec time, or musl/`-nostdlib` becomes a build
  dependency. Strictly worse now.
- **`nsenter(1)` (option B).** Not a drop-in: **FAILED** in this topology with
  `nsenter: setgroups failed: Operation not permitted`.

## What survives from the `/proc/self/exe` idea — it is still right, for a
## different job

The owner's intuition was aimed at locating a helper. There is no helper now, but
the underlying property is still needed, still correct, and now MEASURED twice:

**An fd is a TOCTOU-free reference to an inode; a path is a lookup that can be
re-pointed between the check and the exec.** Replacing the binary on disk while
holding the fd, then `execveat` on it, ran the **old** inode
(`bin/prog (deleted)`), while exec by path ran the new one. And
`open("/proc/self/exe")` succeeds **inside a mount namespace that does not
contain the binary's path** — `stat` on that path returns ENOENT while the fd
works, because it is a magic link to the inode rather than a path resolution.
(Use the fd; `readlink` returns a stale path string.)

That is exactly what option A needs to get snug's own code into the sandbox,
and it is why the earlier bwrap measurement matters: bind through **snug's own
inherited fd**, never through a `/proc/<pid>/` path handed to a process that has
already changed identity.

## Consequences for the plan

Phase 2's "decide cgo or a second binary" **is answered: neither.** The decision
that replaces it is smaller and is about code, not packaging:

- `internal/nsjoin`, roughly 130 lines, with `Join(pid int, spec AttachSpec)`.
- The child function must obey `exec_linux.go:129`'s contract — **no allocation,
  no locks, no stack growth**. Annotate it as hard as bwrap's `--` separator is
  annotated. A future edit that adds an `fmt.Sprintf` to that function is a rare,
  latent, undebuggable hang, and it will look like a scheduler bug.
- The joiner needs `CAP_SYS_ADMIN` **in its own user namespace**, so it runs as a
  child of P1 and nowhere else. EPERM on every namespace is the symptom when that
  is wrong.
- The capability drop is not optional: the no-drop control shows
  `CapEff=000001ffffffffff` inside a sandbox whose payload has none.

This does **not** decide between the setns joiner and fork-from-init (option A).
It removes cgo as the reason to prefer one, so the choice returns to the security
argument alone: fork-from-init inherits seccomp, caps, `no_new_privs` and the
cgroup by construction, while the joiner must reproduce all four. That comparison
is being measured separately.

---

# Option A measured: fork-from-init works, and is safer than the joiner

Prototype: three payloads running concurrently in one sandbox, all children of an
init that holds one end of an inherited `socketpair`, attacked from one of them.

## The §5 objection does not apply to an inherited socketpair

SUPERVISOR §5 refused "a control socket inside the sandbox" with three
primitives: *connect to it, run the shim, read its descriptors or ptrace it*. The
argument was correct **about a pathname socket or an accept()able listener**. An
inherited, pathless, CLOEXEC socketpair is a different object, and each primitive
was tested against it:

- **"simply connect itself"** — there is no pathname and no listener. Nothing to
  `connect()` to.
- **"run the shim"** — running the init binary gives the payload no channel; the
  control fd is CLOEXEC and absent from its fd table. MEASURED: a forked
  payload's `/proc/self/fd` holds only stdio and Go's runtime eventpoll/eventfd.
- **"read its descriptors"** — blocked three ways, and one of them is a fact
  worth keeping on its own: **a socket cannot be reopened through procfs.**
  `open("/proc/<init>/fd/N")` on a socket returns **ENXIO** for `O_RDWR` and
  `O_RDONLY` alike; `O_PATH` yields a handle that cannot be read, written or
  `sendmsg`'d. That holds even with protection *off*.
- **"ptrace it"** — denied by snug's seccomp.

**`PR_SET_DUMPABLE=0` does deny a same-uid sibling inside a user namespace** —
MEASURED, with the unprotected positive control first: dumpable, `/proc/<init>/fd`
is readable and the socket is listed; non-dumpable, readdir and open are denied
and the directory is owned by **uid 65534** — the userns root translated to
overflow in the reader's namespace, *not* uid 0 as the theory in §A guessed. The
denial is what matters; the ownership detail is worth correcting because someone
will check for uid 0 and conclude the protection is absent.

## The win, measured: confinement is inherited, not reproduced

`/proc/<pid>/status` is byte-identical across a plain bwrap payload (today's
model), a fork-from-init primary, and a payload attached later:

```
Uid=1000  CapInh/Prm/Eff/Bnd/Amb = 0000000000000000
NoNewPrivs=1   Seccomp=2   Seccomp_filters=1   cgroup=0::/
```

Against the joiner's `Seccomp: 0`. **SUPERVISOR §4's entire "what the joiner must
still reproduce" list — the filter, the cap drop, `no_new_privs`, the environment,
the cgroup — is exactly the set `fork` inherits for free.** Phase 2's hardest exit
criterion stops being a comparison between two code paths, because there is only
one, and there is no full-capability window at any point.

## What it costs

1. **The init is killable, and that is a co-tenant availability problem.** At pid
   2 a payload's `SIGKILL` on init collapses the sandbox — self-defeating, not an
   escape. `bwrap --as-pid-1` gets the kernel's `SIGNAL_UNKILLABLE` protection…
   **but a Go init is not unkillable by default**: the Go runtime installs
   handlers for SIGTERM/SIGINT, which makes them *deliverable* to pid 1 (the pid-1
   rule only shields signals with default disposition), and Go's default action
   terminates. MEASURED: SIGKILL survived, SIGTERM and SIGINT killed it.
   `signal.Ignore` on the catchable set fixes it — and MEASURED, the enumeration
   must be exhaustive: `SIGABRT` was omitted and `kill(1, SIGABRT)` killed the
   sandbox. Ignore all catchable signals rather than a list; a denylist here is
   the same trap as everywhere else in this project.
2. **The hardening is load-bearing, not decorative.** `PR_SET_DUMPABLE=0`,
   `FD_CLOEXEC` on the control fd before any child exec, exhaustive signal
   ignore, and: **init must derive what it forks — path, argv, env, cwd — solely
   from the host request, never from sandbox-writable state.** No PATH lookup
   into a writable directory, no reading a tmpfs file to pick a binary. Hold that
   and there is no confused-deputy shape, because the payload has no channel.
3. **The fork must work under snug's own filter.** It does — Go and glibc fall
   back to `clone` on the `clone3 → ENOSYS` denial — but a future Go that hard-
   depends on `clone3` breaks the init's fork. Assert it in a test rather than
   discovering it on a toolchain upgrade.
4. `SCM_RIGHTS` carries a pty across the boundary — MEASURED, a master opened on
   the host was used by init. The payload cannot intercept it: it lands directly
   in init and is closed or duped before any exec.
5. The four integration costs above (exit codes, signals, job control,
   `--die-with-parent`) are unchanged and real.

## A live finding in SHIPPED snug, found on the way

**`pidfd_getfd(2)` is an fd-theft primitive equivalent to ptrace, and snug's
seccomp does not deny it.** `deniedSyscalls` in `internal/sandbox/seccomp.go`
lists ptrace, bpf, userfaultfd, perf_event_open, add_key, keyctl, request_key —
and neither `pidfd_open` nor `pidfd_getfd`.

MEASURED inside a real `snug` sandbox, today, with a positive control:

```
pidfd_open(child) -> 5
  pidfd_getfd SUCCEEDED -> pipe:[982192]     (seccomp does NOT deny it)
```

Against the sandbox's own pid 1 it currently fails:

```
pidfd_open(1) -> 3
  fd 0..11 denied errno 1 (EPERM)
  /proc/1/fd owned uid 1000 mode 0500       <- bwrap is DUMPABLE here
```

So the refusal is **not** snug's filter and **not** `dumpable` — it is one of two
things, and they have very different implications:

- **Yama**, `kernel.yama.ptrace_scope = 1` on this host, whose descendant rule
  refuses attaching to an ancestor. That is a **host sysctl snug neither sets nor
  checks**, so on a `ptrace_scope = 0` host the same call may succeed — and
  bwrap's pid 1 holds the args memfd and the seccomp filter fd.
- **The user-namespace boundary** between bwrap's two user namespaces, which
  would hold regardless of the sysctl.

**RESOLVED — it is Yama, and the case that settles it is the one that matters
most.** Two *sibling* processes inside a real snug sandbox, same uid, **same user
namespace**, neither a descendant of the other — which is precisely the shape of
the multi-payload attach feature this design exists for:

```
A: pidfd_open(B) -> 3
A: fd 0..7 denied errno 1 (Operation not permitted)
A: /proc/B/fd listing -> ['0','1','2','3']       <- enumeration still works
```

Both are in the same user namespace, so the userns-boundary explanation is
excluded here. The refusal is Yama's descendant rule: a sibling is not a
descendant. **So co-resident payloads are protected from each other's descriptors
by a host sysctl, not by anything snug does.** Note also that `/proc/B/fd` still
*lists* — the ptrace-mode check gates the theft, not the enumeration.

The owner's position (2026-08-12) is that `ptrace_scope = 1` is good enough for
bwrap, and that P1 orchestrating the process tree does not need a direct
parent-child relationship. Both halves are right, and the second is worth stating
because it removes the obvious objection: **snug's own machinery never needs
ptrace at all** — it uses `setns`, `fork` and descriptor passing — so a strict
Yama setting costs snug nothing operationally. `ptrace_scope=1` is the default on
Debian, Fedora, Ubuntu and this host.

What does not follow is *depending* on it silently. The sysctl is global (not
namespaced), so a sandbox inherits whatever the host has, and snug's third key
feature is that it works everywhere including inside containers — where
`ptrace_scope = 0` is common. On such a host the sibling measurement above
inverts and one payload reads another's descriptors, with no error, no warning
and no line in `--dry-run`. That is the invariant-5 shape exactly.

**The fix, and it is smaller than the earlier draft claimed.** Deny
**`pidfd_getfd` only**. It is the theft primitive; nothing a build, a test or an
agent legitimately does calls it, and denying it closes the hole regardless of
the sysctl. Leave `pidfd_open` allowed: it hands out a handle but no descriptors,
and it is on the ordinary path for well-behaved programs.

Verified that this is not a repeat of the `clone3`/ENOSYS trap: Go's own
`os.checkPidfd` probes `pidfd_open`, `waitid(P_PIDFD)`, `pidfd_send_signal` and
`CLONE_PIDFD`, and returns an error on **any** failure, which makes `pidfdWorks()`
false and falls the runtime back to pid-based handling. So even denying
`pidfd_open` would degrade rather than break — but it is unnecessary, and the
narrower denial perturbs nothing.

Then `doctor` reads `/proc/sys/kernel/yama/ptrace_scope` and reports it, because
it is genuine defence in depth worth knowing about — but after the filter change
no guarantee rests on it. This is independent of the supervisor work and applies
to snug as shipped.

## Recommendation

**Take option A: fork-from-init.** It is safer than the joiner on the merits, not
merely cgo-free — one code path, no full-capability window, confinement inherited
rather than reproduced.

Note what the pure-Go joiner result (above) changes about this recommendation: it
removes cgo as the *reason* to prefer A, which means A now has to win on the
security argument alone. It does. Keep `internal/nsjoin` as the measured
fallback — it is 130 lines and it works — for the case where something must be
injected into a sandbox that has no snug init, but do not build the attach path
on it.
