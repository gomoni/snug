# `snug attach` — the design, as built

`snug attach <dir>` runs a command inside a sandbox that is already running. It
is a **client**: it joins namespaces the kernel already lets any same-uid
process join, and everything it adds is confinement. This document is what it
does and why it is shaped that way; §2 holds the measurements the shape rests
on, taken on the development host on **2026-08-18** against real snug
sandboxes.

## 1. What this feature is not, and none of it is reopened here

Stated first, because each is a thing a reader arrives expecting:

- **There is no control listener, and none is coming.** Issue #61's parts (b)
  and (d) were cut on measurement: no pathname socket, no accept loop, no
  `start`-request authentication, no nonce, no pidfd table
  (`SUPERVISOR-DESIGN.md` §3.3). Attach joins **by descriptor**, from the host.
  A listener would have been a second route to authority the kernel already
  grants, behind a weaker gate.
- **Attach gates nothing.** Any same-uid process can already join these
  namespaces, confirmed five ways on both topologies. The help text says so.
- **Teardown is free**, because the pid namespace is the leash. Re-measured here
  (§11).
- **The content of the feature is confinement, not entry.** A naive `nsenter`
  attaches unconfined; §2 re-measures what that costs.
- **`Bwrap`/`Argv` never travels on a wire that snug then `syscall.Exec`s.** This
  design carries **no executable path and no argv** in any file it reads, with
  exactly one bounded exception that is named and justified in §8.3.
- **It cannot run a different policy in the same namespaces.** Attach resolves no
  profiles, reads no TOML, loads no config. If that is ever wanted it is a
  different feature with a different name.

---

## 2. What was measured for this document

Development host, 2026-08-18: openSUSE Tumbleweed, kernel `7.1.7-1-default`,
`bwrap` 0.11.2, Go 1.26.5, amd64, inside a rootless-podman distrobox,
`kernel.yama.ptrace_scope = 1`, `/proc/sys/kernel/cap_last_cap = 40`. The prober
is a throwaway (`attachprobe`) that does the exact sequence §4 specifies: raw
`clone(SIGCHLD)`, then raw syscalls only, then `execve`.

| # | measurement | result |
|---|---|---|
| M1 | Sandbox process shape, offline topology | `snug` → `bwrap`(outer) → `bwrap`(init, pid 1 inside) → payload. **The outer bwrap is in every one of the HOST's namespaces** (`user:[4026532913]`, `pid:[4026531836]`, …). It forks first and the child unshares. |
| M2 | Sandbox process shape, `@net` topology | `snug`(P0) → `snug __stage-serve`(P1) → `bwrap`(outer) → `bwrap`(init) → payload. P0 knows only P1's pid; the init is a **great-grandchild**. |
| M3 | Namespace ownership | bwrap makes **two** user namespaces. `userns2 = 4026533514` is the payload's; `userns1 = 4026533261` is its parent and **owns mnt, pid, net, ipc, uts and cgroup** (`NS_GET_USERNS` on each). `NS_GET_OWNER_UID` on userns1 = 1000. |
| M4 | **No process lives in userns1.** | The init (`bwrap`, pid 1 inside) is already in userns2. userns1 is kept alive only by the namespaces it owns and is reachable **only** via `NS_GET_USERNS`/`NS_GET_PARENT` on a descriptor. |
| M5 | One combined `setns(pidfd_open(payload), CLONE_NEWUSER\|NEWNS\|NEWPID\|NEWNET\|NEWIPC\|NEWUTS\|NEWCGROUP)` from a raw-fork child | **WORKS.** Lands in the payload's own userns2 (uid 1000 inside), the payload's mount view, `pid=3` in the sandbox's pid namespace. |
| M6 | Same call with `CLONE_NEWUSER` omitted (positive control) | **EPERM.** The userns join is what authorises the other six. |
| M7 | Joining userns1 first (`setns(NS_GET_PARENT(userns2), CLONE_NEWUSER)`) then the rest | Works, but lands the process as **uid 0 in the mount-owning namespace** — strictly more authority than the payload. Rejected; see §3. |
| M8 | Naming the wrong pid — the outer bwrap, or `snug` itself | **EINVAL**, from `userns_install`'s "don't allow re-entering the same user namespace". Fails closed, but EINVAL is *also* what a multithreaded caller gets: §4.1 pre-flights this in the parent so the message can tell them apart. |
| M9 | Naming host pid 1 | `open("/proc/1/ns/user")` → EACCES before any syscall of ours. |
| M10 | Naming the stage (P1) on the `@net` topology | **EPERM** at the combined `setns`. The stage is not the sandbox and cannot be mistaken for it. |
| M11 | Confinement applied in the child (NNP → seccomp → setns → capbset drop → capset) | Attached process reads, from the host and from inside: `NoNewPrivs: 1`, `Seccomp: 2`, `Seccomp_filters: 1`, `CapEff: 0`, `CapBnd: 0000000000000000` — **identical to the payload's own four lines** (M12). |
| M12 | The payload's own four lines | `NoNewPrivs: 1`, `Seccomp: 2`, `CapEff: 0`, `CapBnd: 0000000000000000`. |
| M13 | The naive attach (no NNP, no filter, no cap drop, host env) | `NoNewPrivs: 0`, `Seccomp: 0`, **`CapBnd: 000001ffffffffff`**, and host environment variables readable from inside the sandbox's own pid namespace. This is what the feature exists to prevent. |
| M14 | `setns(CLONE_NEWNS)` and the process's root/cwd | The kernel resets **both** `fs->root` and `fs->pwd` to the new mount namespace's root: `/proc/<attached>/cwd → /`, `/proc/<attached>/root → /`. **No host dirfd survives the join.** No `chroot` is needed and none should be added. |
| M15 | `CLONE_NEWPID` and the caller | The raw-fork child's `ns/pid` stays the **host's**; only `ns/pid_for_children` becomes the sandbox's. A second fork is mandatory (§4.3). |
| M16 | The host parent can read the joined child's `/proc/<pid>/status` | Yes — same uid, and it is our own child. This is what makes the verify-then-release gate in §4.2 possible. |
| M17 | `prctl(PR_SET_DUMPABLE, 0)` before `execve` | **Does not survive the exec.** `/proc/<attached>/environ` stays `michal`-owned and readable from inside. Hardening the attached process against the payload is not available to a process that execs an arbitrary program. |
| M18 | What the payload can do to the attached process | Reads `/proc/<attached>/environ`, lists `/proc/<attached>/fd`, and **reopened `/proc/<attached>/fd/1` and wrote through it into a host file outside every mount grant** (`WRITE-OK`, bytes verified present in the host file). `/proc/<attached>/mem` was refused **by Yama** (`ptrace_scope=1`), not by anything snug does. |
| M19 | Network, attached into a `@net` run | `lo snug0`; `https://example.com` → **200**; `http://127.0.0.1:18099` (live host listener, positive control returning **200** from the host) → **000**; `~/.ssh` absent; host `/home/michal` not visible. |
| M20 | Teardown, SIGKILL of snug | outer bwrap, init, payload, the attach client, its raw-fork child and the attached command: **all gone**, 1.5 s later. |
| M21 | Teardown, SIGKILL of the attach client | The raw-fork child and the attached command died (`PR_SET_PDEATHSIG`); the sandbox and payload were untouched. |
| M22 | `bwrap --info-fd N` | Emits one JSON object **before** exec'ing the payload (it appeared even on an `execvp` failure): `child-pid`, `mnt-namespace`, `pid-namespace`, `net-namespace`, `ipc-namespace`, `uts-namespace`, `cgroup-namespace` — pid plus six inode numbers. No userns inode. |
| M23 | Today's run directory | `runtimeDir()` is called **only** by `identity.go` and `container.go`. A plain `snug <dir>` creates **no** run directory. |
| M24 | **Which open file descriptions are reopenable through `/proc/<pid>/fd/N`**, cross-process, same uid, `ptrace_scope=1` | pipe: **OK, both ends** (wrote through another process's write end, read it back through its read end). memfd: **OK**, contents read back. Deleted file: **OK**, contents read back. Unix socket: refused, **ENXIO**. See §5.5 — this contradicts a comment in `internal/sandbox/seccomp.go` and a sentence in `CLAUDE.md`. |

Two of these deserve to be read twice: **M4** (the mount-owning user namespace has
no process in it, so it cannot be named by pid) and **M18** (the attached
process's stdio is a hole in the wall pointing outward, and the payload walked
through it in this measurement).

---

## 3. Which namespaces attach joins, in what order, and why

**Attach joins seven namespaces in ONE `setns(2)` call, by pidfd, naming the
sandbox's init:**

```
setns(pidfd, CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWCGROUP)
```

One call, not several, because the kernel validates and installs the set
atomically: either the attached process is in all seven or it is in none. A
sequence of six calls has six partial states, and a failure in the middle of one
leaves a process that is *half* inside — in the sandbox's mount namespace with
the host's network, say — which is a topology nothing in snug describes and no
test would cover.

The pidfd names **the sandbox's init** (bwrap's child, pid 1 inside), never the
payload and never the outer bwrap. The init exists for the whole run by
construction — if it dies the pid namespace dies and there is nothing to attach
to — whereas the payload may `exec`, fork, or be one of many. M1/M2 are why the
outer bwrap is useless: it is in the host's namespaces on both topologies.

What each flag buys, and what its absence would mean:

| flag | why | absent ⇒ |
|---|---|---|
| `CLONE_NEWUSER` | **Authorises the other six.** Measured: without it the same call is EPERM (M6). It also puts the process in the payload's *own* user namespace — the inner one, which owns nothing. | nothing works |
| `CLONE_NEWNS` | The sandbox's filesystem view. This is the feature. | you are not in the sandbox |
| `CLONE_NEWPID` | Two things: `/proc` inside is a procfs mounted **for that pid namespace**, so a process outside it has no `/proc/self`; and it is **the leash** — the kernel SIGKILLs every member of a pid namespace when its init dies (M20). | a broken `/proc`, and an attached process that outlives the sandbox |
| `CLONE_NEWNET` | The run's network guarantee applies to the attached process too: egress where the policy grants it, host loopback refused (M19). | an attached shell with the host's network *inside* the sandbox's filesystem — every host loopback service and every abstract AF_UNIX socket (X11, D-Bus), opened silently and reachable from no profile |
| `CLONE_NEWIPC` | SysV IPC and POSIX message queues are shared state; the payload's are the sandbox's. | a channel between the attached process and the host |
| `CLONE_NEWUTS` | The hostname. Cosmetic, but `--dry-run` claims the sandbox has its own and the claim should hold for every process in it. | a confusing hostname |
| `CLONE_NEWCGROUP` | `/proc/self/cgroup` reads as the sandbox does. Harmless to pass when the run has no private cgroup namespace (`--unshare-cgroup-try` may have declined): re-entering the namespace you are already in is not an error for anything except a user namespace. | a host cgroup path leaked into the sandbox's view |

`CLONE_NEWTIME` is **not** passed: bwrap creates no time namespace, so there is
nothing to join, and like `CLONE_NEWPID` it would apply to children only. Passing
it would be a flag with no consumer.

### 3.1 Why the payload's user namespace and not the mount-owning one

This is the sharpest decision in the design and it is not visible from the
settlement's one-line summary.

bwrap builds **two** user namespaces (M3). userns1 owns the mount, pid, net, ipc,
uts and cgroup namespaces; userns2 is its child and is where the payload runs.
A process in userns2 has a full capability set *in userns2*, which owns nothing —
that is precisely the confinement bwrap engineered, and it is why the payload
cannot remount its own read-only binds.

M7 measured that entering **userns1** works too, and that it lands the process as
**uid 0 in the namespace that owns the sandbox's mounts** — i.e. with
`CAP_SYS_ADMIN` over the mount namespace, able to bind-mount over grants and
remount read-only binds. Dropping capabilities afterwards leaves the *membership*
in place, which is a strictly worse starting position for no gain.

So: **the pidfd names a process inside the sandbox, and the `CLONE_NEWUSER` bit
resolves to that process's own user namespace.** Attach must never call
`NS_GET_PARENT` and must never join userns1. The reviewers reached userns1 via
`NS_GET_USERNS`/`NS_GET_PARENT` because they were proving reachability; this
feature is not a reachability proof and should not copy that step.

### 3.2 `CLONE_NEWPID` applies to children — what the user sees

M15: the process that calls `setns` keeps its own pid namespace; only its
*children* get the new one. So there are three processes, and the doc, the tests
and the error messages should use these names:

```
C   the attach client              host everything; the Go process the user typed
 └─ B  the bridge                  raw-fork child of C. Joins the seven namespaces.
    │                              IN the sandbox's mnt/user/net/ipc/uts/cgroup,
    │                              but still in the HOST's pid namespace.
    └─ A  the attached command     fork of B, and therefore pid N inside the
                                   sandbox's pid namespace. This is what the user
                                   thinks of as "the attached process".
```

Consequences to carry:

- **The payload cannot see B.** B has no entry in the sandbox's `/proc`, because
  it is not in that pid namespace. It is not a process the payload can address.
- **The pidns leash covers A, not B.** B is held instead by
  `PR_SET_PDEATHSIG(SIGKILL)` on C, and by having nothing to do but `wait4(A)`.
  Both were measured (M20, M21).
- B does exactly three things after the join — drop capabilities, fork, wait —
  and never execs. Its only job is to be the thing that is allowed to have
  children in the sandbox's pid namespace.

---

## 4. The sequence, step by step, with the failure mode of each step

Two sides. **Everything that can allocate, parse, or produce a good error message
happens in the parent (C) before the fork.** The child (B) is a raw-fork child of
a multithreaded Go program: it may make raw syscalls and nothing else — no
allocation, no channels, no `os/exec`, no `fmt`. That is not style, it is the
constraint that makes `setns(CLONE_NEWUSER)` and `setns(CLONE_NEWNS)` legal at
all (`NOCGO.md` §3: the fork child is single-threaded *and* owns its own
`fs_struct`, the two things `userns_install` and `mntns_install` check).

### 4.1 Parent (C), before the fork — every check that can produce a sentence

| # | step | failure mode |
|---|---|---|
| 1 | Resolve the run: find the run directory, verify owner+mode, confirm its lock is **held**, read and validate `state.json` (§6). | Refuse, naming what was wrong and, where relevant, `snug attach --list`. |
| 2 | `pidfd_open(state.sandbox.init_pid, 0)`. | ESRCH ⇒ "that sandbox is gone". |
| 3 | Read `/proc/<init>/stat` field 22 and compare with `state.sandbox.init_starttime`. | Mismatch ⇒ **refuse**: the pid was reused. |
| 4 | Read the six namespace inodes from `/proc/<init>/ns/{mnt,pid,net,ipc,uts,cgroup}` (`Fstat` the descriptors, not `readlink` the strings) and compare all six with `state.sandbox.namespaces`. | Any mismatch ⇒ **refuse**. This is the structural guard: even a reused pid whose start time collided cannot pass six inode comparisons. |
| 5 | Compare `/proc/<init>/ns/user` with our own `/proc/self/ns/user`. | Equal ⇒ refuse with "that process is not inside a sandbox — its user namespace is your own". **This exists to keep M8's EINVAL from reaching a user**, because EINVAL is also what a threaded caller gets and the two mean opposite things. |
| 6 | `sandbox.BuildFilter()`, hash it, compare with `state.seccomp` (§5.1). | Mismatch ⇒ refuse. Unavailable-but-required ⇒ refuse. Both `none` ⇒ one-line notice, continue. |
| 7 | Read `/proc/sys/kernel/cap_last_cap` (40 here; **never hardcode it** — a newer kernel with more capabilities would silently leave the new ones in the bounding set). | Unreadable ⇒ refuse rather than guess low. |
| 8 | Marshal `argv`, `envp`, the chdir path and the filter program into flat, already-allocated memory the child will pass to raw syscalls. | — |
| 9 | Prepare stdio (§5.4) and mark **every** descriptor except 0/1/2 close-on-exec, including the pidfd, the state-file and lock descriptors, and the report pipe. | The `execve` in step 4.3 installs nothing and clears no flags: what is not CLOEXEC here is what the payload ends up holding. This is `internal/fdseal`'s rule applied at the one exec in this feature. |
| 10 | `runtime.LockOSThread()`, then `clone(SIGCHLD)`. | The lock is **load-bearing**: `PR_SET_PDEATHSIG` fires on the death of the parent **thread**, so an unlocked forking goroutine whose thread the runtime later retires kills the attached session for no reason. C stays on that thread until `wait4` returns. |

### 4.2 Child (B) — raw syscalls only, in this order

```
 1  prctl(PR_SET_PDEATHSIG, SIGKILL)         C dies ⇒ B dies                (M21)
 2  prctl(PR_SET_NO_NEW_PRIVS, 1)            required before 3, inherited by A
 3  seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
 4  setns(pidfd, the seven flags)                                           (M5)
 5  for cap in 0..cap_last_cap: prctl(PR_CAPBSET_DROP, cap)
 6  capset(v3, {effective=0, permitted=0, inheritable=0})
 7  write(reportfd, "confined") ; read(gatefd, 1)   ← blocks; C verifies    (§4.2a)
 8  chdir(state.chdir)
 9  clone(SIGCHLD)  →  A                                                    (M15)
10  A: prctl(PR_SET_PDEATHSIG, SIGKILL); execve(argv[0], argv, envp)
11  B: wait4(A); _exit(status)
```

Ordering rules, each with its reason:

- **2 before 3.** `SECCOMP_SET_MODE_FILTER` needs `NO_NEW_PRIVS` or
  `CAP_SYS_ADMIN`; we deliberately have neither yet.
- **3 before 4.** A seccomp filter can never be removed, so installing it before
  the join means every subsequent step, and every failure of one, happens with
  the filter already on. Fail-closed. Measured to work (M5 installed the filter
  at step 3 and joined at step 4).
- **5 after 4, and it is not optional.** `setns(CLONE_NEWUSER)` **resets the
  bounding set to full** (`set_cred_user_ns` sets `cap_bset = CAP_FULL_SET`) — the
  same kernel behaviour `bwrap.go`'s `--cap-drop ALL` comment records for
  `--unshare-user`. A drop before the join would be theatre. M13 is what "we
  forgot" looks like: `CapBnd 000001ffffffffff` in the sandbox.
- **6 after 5**, so that nothing can be re-raised between the two.
- **8 after 4**, because the path is resolved in the sandbox's mount namespace.
- **9 after everything**, so A inherits a fully confined B by descent rather than
  reproducing anything.

#### 4.2a The gate at step 7 — verify it is active, not merely requested

Step 7 is a two-byte handshake and it exists because of `--seccomp` after bwrap's
`--`: a security feature that was passed, accepted, and never installed, with
exit code 0. B cannot check its own state without allocating; C can (M16: the
host parent reads `/proc/B/status` fine, and capability masks, `Seccomp` and
`NoNewPrivs` are absolute values, not rendered relative to the reader's user
namespace).

So C reads `/proc/<B>/status` and requires **all four**:

```
Seccomp:     2                     (or 0 iff state.seccomp.state == "none")
Seccomp_filters: 1
NoNewPrivs:  1
CapEff:      0000000000000000
CapBnd:      0000000000000000
```

and additionally that `/proc/<B>/ns/{mnt,net,ipc,uts,cgroup}` and
`ns/pid_for_children` equal the six recorded inodes — i.e. that B is where it
claims to be. Only then does C write the release byte. Any mismatch: C kills B
and exits non-zero, and **A never exists**. This is a gate, not an audit: the
program the user asked for has not been exec'd yet.

### 4.3 What the exec is, and what it is not

`execve` by path, of a path that came from the user's own command line (§8.3).
There is no fd-exec here and no `/proc/self/exe`: attach runs *the user's*
program inside the sandbox, not snug's own image. Nothing about the argv arrives
over a channel from another process.

---

## 5. Confinement

The rule, and it settles every case below: **attach reproduces the payload's
confinement — no more, no less.** More is as bad as less, because a difference in
either direction is a second author of the sandbox's confinement (invariant 6),
and the next person to change one will not know to change the other.

### 5.1 Seccomp — how the run's filter reaches a different process

**Attach rebuilds the filter from its own `sandbox.BuildFilter()` and refuses if
the digest recorded by the run does not match.** The state file carries
`{"state":"active","digest":"sha256:…"}`, the digest being over the assembled BPF
program bytes.

Why rebuild rather than carry the bytes:

- The bytes are authored by `deniedSyscalls` and `BuildFilter`, in code. Carrying
  them in a file makes the file a second author, and installing BPF read from a
  file is a "trust the wire" shape this project has already refused once for
  `Bwrap`/`Argv`.
- Rebuilding also cannot fail *open*: if `BuildFilter` is missing, broken, or on
  an architecture with no syscall table, there is no filter to install and attach
  says so.

The four cases, all closed:

| run recorded | attach's own `BuildFilter` | attach does |
|---|---|---|
| `active`, digest D | D | installs it, verifies at the gate (§4.2a) |
| `active`, digest D | D′ ≠ D | **refuses**: "this sandbox was started by a different build of snug; its seccomp filter is not the one this binary builds. Attach from the same binary." |
| `active`, digest D | unavailable or error | **refuses**, same message shape. Attaching *less* filtered than the payload is the "confinement not reproduced" hole. |
| `none` (`--no-seccomp`) | anything | installs nothing, prints one line: "this run was started with `--no-seccomp`; the attached process is unfiltered too." |

There is **no `snug attach --no-seccomp`.** Weakening is the human's prerogative
at the point the sandbox is created, and the run already made that choice; a
second knob would be a second author. The counter-argument is real and is paid
rather than answered: debugging an already-running sandbox with `ptrace` is not
possible without restarting it. The confinement guarantee stays
unconditional.

### 5.2 Capabilities and the bounding set

- **When:** after the last namespace-entering syscall (§4.2 step 5–6), before the
  exec. Both halves are forced by the kernel: nothing before the join survives it,
  and nothing after the exec can be applied by us.
- **Bounding set:** empty. Loop `PR_CAPBSET_DROP` over `0..cap_last_cap` read
  from `/proc/sys/kernel/cap_last_cap` at run time. This is the line that
  matters for issue #61's case G — *nothing snug puts in U may hold
  `CAP_SYS_PTRACE`* — and an empty bounding set is the strongest available
  spelling of it. Case F says hardening the *target* does not stop a
  full-capability peer; this drop is about not **being** such a peer.

  Attach is one of two enforcement points for that gate, and it is the stricter
  one. The other is `policy.StageCapDrop`: the stage drops `CAP_SYS_PTRACE`
  from its own bounding set before it forks, so P1, the outer bwrap and the
  container engine never hold it either. The two are independent — an attach
  from a build without the stage drop, or onto the offline arm where there is
  no stage, still confines itself — and neither may be relaxed on the argument
  that the other exists.
- **Effective / permitted / inheritable:** zeroed with one `capset(v3)`. Ambient
  is emptied by the kernel when permitted is.
- **`NoNewPrivs`: 1**, set before seccomp (which requires it) and inherited by A.
  With `CapBnd` 0, NNP 1, and every bwrap mount `MS_NOSUID`, there is no route
  back to a capability.
- **Securebits: not set.** bwrap does not set them for the payload, so setting
  them for the attached process would be attach inventing confinement of its own.
  If they are worth having, they are worth having for the payload first.
- **Supplementary groups: not touched.** The payload keeps the host's kgid list
  too (bwrap writes `setgroups deny` and cannot call `setgroups`), so leaving them
  is what "reproduce the payload" means here. Inside, they render as `nobody`.

The interval between step 4 and step 6 is the one moment B holds a full
capability set in the payload's user namespace. It is a handful of raw syscalls
long, it contains no exec and no fork, and it is the reason step 9 comes last.

### 5.3 The environment — who authors it

**The attached process's environment is the subset of the run's resolved policy
environment that snug itself authored** — `Policy.AuthoredEnvNames()` (verb
`VerbSnug`) intersected with `Policy.EnvPairs()` — recorded in `state.json` at
run start and set verbatim by attach.

Three properties follow, and each is the reason for a rejected alternative:

- **No host environment crosses.** Not the attach client's, not `snug`'s. M13
  measured that a naive attach carries host variables into
  `/proc/<pid>/environ` *inside the sandbox's pid namespace*, where a payload
  shell reads them back. `--clearenv` is a statement about the payload; it was
  never a statement about every process in the namespace, which is exactly the
  `/proc/1/environ` lesson one layer out.
- **A profile-passed host variable does not land on disk.** Restricting the
  record to snug-authored names is what keeps a token that some profile passes
  through out of a file in `$XDG_RUNTIME_DIR`. The run's own argv already lives in
  a memfd specifically so that nothing lands on disk; the state file must not
  quietly undo that.
- **The attached shell is not the agent's session.** It gets `HOME`, `PATH`,
  `SHELL`, `PS1`, `TERM`, `LANG`, `SNUG_PROFILES` and friends; it does not get
  whatever credentials the payload was given. An interactive debugging shell has
  no business holding the agent's tokens.

One deliberate exception, and it is snug authoring, not passing: **`PS1` is
replaced** with a variant that says the session is attached. The house rule is
that humans and agents both act on the prompt and "am I inside?" is the question
where guessing wrong is expensive; "am I the payload or a visitor?" is the same
question one turn later.

`TERM` comes from the **recorded** policy, not from the attach client, so that
the sentence "the environment is authored by the run's policy, full stop" has no
exception to remember. The cost: attaching from a terminal the run never saw
gets the run's `TERM`, not yours, and a mismatch shows up as wrong rendering in
a full-screen program. A low-stakes default taken in favour of the rule with no
exceptions.

### 5.4 stdio, cwd and inherited descriptors — the measured hole

**M18 is the finding of this design and it must not be softened.** The payload
listed `/proc/<attached>/fd`, reopened fd 1, and wrote through it into a host
file that no profile granted. The write landed. `/proc/<attached>/environ` was
readable in the same breath.

So the descriptors the attach client hands in are a hole in the sandbox wall
pointing outward, and its size is exactly the size of the user's own shell
redirection. Three rules:

1. **cwd and root need nothing.** M14: `setns(CLONE_NEWNS)` resets both to the new
   mount namespace's root. Do not add a `chroot`; do `chdir(state.chdir)` after
   the join so the session starts where the payload did.
2. **Everything above fd 2 is close-on-exec** (§4.1 step 9). A run-directory
   descriptor or a namespace descriptor reaching the sandbox would be far worse
   than stdio: an open directory descriptor ignores the mount namespace entirely.
3. **No host descriptor of the caller's stdio crosses into the sandbox, in
   either shape.** Non-tty stdio is relayed through pipes; a tty gets a FRESH
   pty pair, allocated by C, of which only the slave is handed to B. C copies
   bytes on the host side in both shapes. The relayed stream is what the payload
   holds, never the terminal or the file the caller redirected from.

   **C's drain of the far end is BOUNDED, and that is a correctness
   requirement, not a nicety.** A's fds 0/1/2 are `dup3`'d and `dup3` clears
   CLOEXEC by design, so a descendant A leaves behind inherits them and keeps
   the far end open after A is reaped. C therefore has the exit status and no
   EOF, and an unbounded drain never returns (issue #221). The bound lives on
   `stdioRelay.wait`'s `drainTimeout`; keeping the pty master in the runtime
   poller — no `os.File.Fd()` on it, ever — is what makes a deadline on it
   possible at all.

   **The bound is on SILENCE, not elapsed time, and it is announced.**
   `drainCopy` re-arms the deadline after every successful read, so a stream
   still delivering is never cut and only one that goes quiet with its far end
   held open ends the drain; an absolute bound truncated a benign payload's own
   output instead. A drain that ends on its deadline says so on the client's
   stderr — a sandbox that silently truncates its own transcript is the screen
   lying. A copy parked in `write(2)` is deliberately unbounded: that is the
   client's consumer applying back-pressure, which the sandbox cannot reach.

   **What the relay does and does not buy — measured, and less than it looks.**
   M24: a pipe *is* reopenable through
   `/proc/<pid>/fd/N`, both ends, cross-process, same uid. So the payload can
   still write into a relayed stream and read from it. What it can no longer do is
   reach the **host inode**: it cannot read what is already in the file, cannot
   seek or truncate it, and cannot reach anything else in the directory that
   dirfd sat on. The relay narrows "arbitrary read/write of an ungranted host
   inode" to "read/write of this attach session's live stream" — a real
   narrowing, and a smaller one than "the payload gets nothing".

This rule also subsumes `safeStdio`'s directory case: a directory is not a tty,
so it is relayed, and reads of a dirfd return EISDIR into a pipe nobody reads.
Keep the sentence "a directory descriptor would let the sandbox reach the host
filesystem through `/proc/self/fd/N`" in the code anyway — it is the reason.

### 5.5 A finding this design tripped over, which was not about attach

M24 was taken to justify the relay and contradicted shipped comments in two
places. Both said, in different words, that `pidfd_getfd` was the only route to
a non-file open file description — *"a socket cannot be reopened through
`/proc/<pid>/fd` at all (ENXIO), and pipes, memfds, deleted and O_TMPFILE files
have no path to reopen"*.

Measured cross-process, same uid, `ptrace_scope = 1`: **pipe reopenable (both
ends, verified by a write through one process's write end read back through its
read end), memfd reopenable (contents read back), deleted file reopenable
(contents read back), socket refused with ENXIO.** Three of the four examples
were wrong. Each of those objects has a backing inode, and `open(2)` on the
magic link re-derives a working descriptor once
`ptrace_may_access(PTRACE_MODE_READ_FSCREDS)` passes — which same-uid does, and
which Yama never gates.

**The socket survives for a structural reason rather than a permission one**:
sockfs installs `sock_no_open`, so the reopen is ENXIO for root as well. That is
what keeps `SUPERVISOR-DESIGN.md` §3.3's control-channel argument standing while
the other three examples fell.

It changed nothing about whether `pidfd_getfd` should be denied — it should, it
costs nothing — and nothing about attach beyond §5.4's wording. It was issue
#115, it is fixed, and `TestKnownOpenResidualSiblingReopensAnythingButASocket`
pins the corrected claim. Recorded here because the shape recurs: an abuse
sentence written once that nothing re-reads.

---

## 6. The state file

### 6.1 Where the state file lives, and why it is not where you would guess

`state.json` is **keyed by the TARGET DIRECTORY**, not by the run:
`<targetLockBase()>/snug/target-sha256_<hex>.json`, beside the per-target lock
that already enforces one live run per directory. `internal/cli/targetstate.go`
owns it.

**`targetLockBase()` is derived from the uid alone** — `/run/user/<uid>`, or
`/tmp/snug-<uid>` where that does not exist — and never from `$XDG_RUNTIME_DIR`
or `$TMPDIR`. That is the whole reason for the shape. Those two variables
differ between an interactive shell and cron, systemd or ssh, so a run started
under one environment published its state where an attach launched under
another would never look (issue #123). Repointing only the READER could not fix
it: the writer was env-derived too.

Three properties follow, and each removes code rather than adding it:

- **Discovery is a LOOKUP, not a scan.** The target's realpath hashes to
  exactly one filename. There is no directory listing, no per-entry
  parse-and-skip, and no "more than one live run matches" branch — issue #119
  made at most one run live per target, and a target-keyed name makes that
  structural, because two runs on one target cannot produce two names.
- **Liveness is the target lock**, the same fact `snug <dir>` consults when it
  refuses a second sandbox. It used to be a second, parallel `flock` on each
  run directory, so "is this run live" had two answers that could disagree.
- **A stale state file cannot be read as a live run.** The lock is the truth;
  the JSON beside it is only what the live holder published.

**The per-run directory still exists and is still env-derived.** It holds this
run's sockets — the ssh-agent proxy, the container proxy — and its own lock,
and none of that needs cross-run agreement, because a socket path is handed to
the sandbox by the same process that created it. It is simply not where attach
looks, and `--dry-run` names the target-keyed file rather than that directory
(§9).

**Publishing failure is not run failure, and the split is deliberate.** The
runtime directory failing to open is **fatal** — refusing beats falling back to
a per-environment path, which is issue #122's fail-open. `writeRunState`
failing inside the `OnInfo` callback is **warn-only**: by the time that
callback runs a payload already exists, or is about to on the staged topology,
and there is no way left to un-start one without reintroducing the
parked-payload window `runStaged` deliberately removed ([INDEX](INDEX.md)
§4.3). `internal/cli/main.go` carries the reasoning at the call site.

### 6.2 Contents

```json
{
  "schema": 1,
  "target": "/home/u/proj",
  "profiles": ["@sys", "@home", "@cwd-rw"],
  "chdir": "/home/u/proj",
  "sandbox": {
    "init_pid": 1323242,
    "init_starttime": 40042773,
    "namespaces": {
      "mnt": 4026533516, "pid": 4026533519, "net": 4026533521,
      "ipc": 4026533518, "uts": 4026533517, "cgroup": 4026533520
    }
  },
  "seccomp": { "state": "active", "digest": "sha256:…" },
  "env": [["HOME", "/home/u"], ["PATH", "…"], ["PS1", "…"], ["…", "…"]],
  "owner": { "…": "…" },
  "run_dir": "/run/user/1000/snug/run-1323240",
  "revision": "abc1234"
}
```

- `schema` — an int. Attach refuses anything it does not equal; there is no
  best-effort partial read. Every key is tagged explicitly in `runState`
  rather than left to reflection's default casing, so a struct-field rename
  cannot silently change the file.
- `init_pid`, `init_starttime`, `namespaces` — from `bwrap --info-fd` (§7) plus
  `/proc/<pid>/stat` field 22, read immediately after. Six inodes, not one: see
  §4.1 step 4. `runStateNamespaceKinds` is the one list both the writer and the
  reader range over, so a namespace cannot be added under two spellings.
- `seccomp` — §5.1. Digest only; never the program bytes. `state` is the word
  `"active"` or `"none"` rather than a bool, so a reader printing it never has
  to invent the wording.
- `env` — §5.3. Snug-authored names only.
- `owner` — the snug process holding this target's lock, and the sweep's
  **second** liveness signal: the one an `rm` or `mv` of the lock file cannot
  detach from the run (issue #489, `stateowner.go`).
- `run_dir` — this run's own env-derived runtime directory. One consumer:
  `snug proxy`, which has to find the http-doors file published beside the
  run's sockets. Optional, and **not** how attach finds anything — that stays
  on the target-keyed path (§6.1), because two processes need not agree on
  `$XDG_RUNTIME_DIR` and a path published by one of them is a fact rather than
  an agreement.
- `revision` — `debug.ReadBuildInfo()`'s `vcs.revision` if present, **used only
  to make the skew message concrete**. No decision reads it; the digest is the
  decision.
- **No command, no argv, no executable path**, other than what `env` already
  carries as `SHELL` (§8.3).

### 6.3 Mode, owner, writer, and what attach refuses

- Written by the run's own process (P0), through the target-state directory's
  `*os.Root`, mode **0600**, owner the running uid, into a directory
  `vdir.SecureSubdir` has already proven owned and 0700 — so the mode is belt
  and braces rather than the only guard.
- Written **once**, after bwrap answers on `--info-fd` (§7), never rewritten. A
  rewrite would need a rename dance for atomicity and there is nothing to
  update.
- A `SIGKILL`ed run leaves it behind, which is exactly why attach checks the
  **lock** rather than trusting a file's presence.

Attach refuses, loudly and by name:

| condition | why |
|---|---|
| directory owner ≠ us, or mode ≠ 0700, or a symlink at a name snug owns | `vdir`'s verification, unchanged |
| the target's lock is **not** held | the owning snug is gone; this is a corpse, not a run |
| `state.json` missing, unparsable, or `schema` ≠ 1 | no partial reads |
| `init_starttime` ≠ `/proc/<pid>/stat` field 22 | pid reuse |
| any of the six namespace inodes differs | wrong sandbox, or pid reuse whose start time collided |
| the target's `ns/user` == ours | not a sandbox; §4.1 step 5 |
| seccomp digest mismatch | §5.1 |

The liveness probe is `flock(LOCK_SH|LOCK_NB)` on the target lock, released
immediately: `EWOULDBLOCK` means a live owner, success means nobody holds it.
Attach **never** removes anything — sweeping belongs to the run that comes in
next, and a second remover would race it.

One convenience, bounded: if the lock is held but `state.json` is not there
yet, attach polls for up to **2 s** at 50 ms. That is the startup window
between the lock and bwrap's `--info-fd` answer, and a user who types `snug
attach` a beat too early should not have to think about it.

### 6.4 The stage-less/staged asymmetry, and why it does not appear here

The pid snug directly forks is useless on **both** topologies, in the same way,
which is a relief rather than a problem: §7 is one mechanism, not two, and
there is no per-topology branch anywhere in attach.

- **Offline**, P0 forks `__inpidns` (`internal/sandbox/inpidns.go`), which
  becomes pid 1 of an intermediate pid namespace and execs bwrap; the sandbox's
  init is bwrap's child below that.
- **Staged**, P0 forks P1 and the init is a great-grandchild it never learns
  of (M2).

Either way the obvious pid is the wrong one, and bwrap's own `--info-fd` answer
is what names the right one.

---

## 7. How snug learns the init pid: `bwrap --info-fd`

`bwrap --info-fd N` writes one JSON object to N **before** exec'ing the payload,
carrying `child-pid` and six namespace inodes (M22). That is precisely the state
file's `sandbox` block, from bwrap itself, with no procfs scanning, no `PPid`
walking and no race.

The pipe is created in `internal/sandbox.Run`; the write end joins `extra` and
gets a number from `nextFD()`, exactly as the `--seccomp` memfd does, and
`--info-fd <n>` is appended to `flags` **before the `snug-args` memfd snapshot**
— nothing may be appended after that — and therefore before bwrap's `--`.

**Who reads the answer depends on the topology, and the staged arm's answer is
not the one this design first assumed.**

- **Offline**, P0 forks bwrap directly, so P0 reads: `reportInfo` does it in a
  background goroutine, bounded by `infoFDTimeout`.
- **Staged**, the read end belongs to **P1**. It rides the control protocol as a
  fixed descriptor, `fdBwrapInfo`, marked CLOEXEC at `__stage-serve`'s first
  instant like every other descriptor P1 keeps, and P1 parses it with
  `bwrapinfo.Read` and reports the result to P0 in an **event**. So the stage's
  protocol did grow a member for this. It had to: issue #125's gate parks the
  payload and starts the engine inside the one `start` request, and the pid to
  release — or to kill on an abort — is the pid this answer carries. A pid P1
  reads itself, on a descriptor it owns, about a process it is the grandparent
  of, is not the hazard a pid arriving in a REQUEST would be (`proto.go`).

The read is one value, not a read to EOF, because the writing side's copy stays
open for the life of the run and an EOF would never come. If bwrap never answers
— an old bwrap, a failed start — snug **warns** that the run will not be
attachable and carries on.

`--info-fd`, not `--json-status-fd`: one document, not a stream.

## 8. The CLI surface

### 8.1 Shape

```
snug attach [dir] [-- command ...]
```

- `attach` joins `doctor`, `profile`, `config` and `help` as a reserved first
  word; the existing "to sandbox a directory that happens to be named one of
  these, write it as a path" sentence covers `./attach`.
- `dir` is positional and defaults to `.`, matching `snug <dir>` — the directory
  *is* the thing, as with `git clone <url>`.
- The run is selected by `filepath.Abs(dir)`, hashed to the one target-keyed
  state file (§6.1). One target, one live run (issue #119), one candidate.
- **There is no `--pid`.** Not because naming a pid would be unsafe — the kernel
  gates that, not snug — but because it is a second way to name the same thing
  with worse failure modes (M8's EINVAL), and a CLI surface is a thing to keep
  small.
- **There is no `--run` either.** It existed in this design to disambiguate one
  target with two live runs, and issue #119 removed the situation.
- **There is no `--list` yet.** `parseAttachArgs` refuses every flag and says so
  in the refusal, which is the honest shape for a convenience that is not built:
  the message names what a bare `snug attach [dir]` does instead of implying a
  flag that would work if spelled right.
- `-v/--verbose` is not added. There is nothing to audit here.

### 8.2 The help text

The honesty requirements are load-bearing, so `attachUsage` is written out
rather than described, and its three paragraphs each answer a question a user
would otherwise get wrong: attach **gates nothing** (any same-uid process can
join these namespaces; what attach adds is confinement); the attached process
**is inside and the payload can address it** (so whatever your stdio points at,
the payload reaches too); and it **cannot run a different policy** in the same
sandbox (attach resolves no profiles and reads no configuration).

`internal/cli/attach.go` is the text. It is static — nothing is interpolated
into it — and `TestAttachScreensAreCoveredByTheControlCharacterSweep` pins that,
so the moment it stops being static the control-character sweep has to be
re-argued.

### 8.3 The one path that comes from a file

With no `-- command`, attach runs the `SHELL` value recorded in the run's
environment. That is the single executable path this feature takes from a file
rather than from the user's own words, and it is bounded on purpose: the value
was authored by the run's policy, the file is 0600 inside a 0700 directory snug
verified, and a same-uid attacker able to rewrite it can simply run the program
directly. Attach still validates it — absolute path, no control characters — and
`execve` failure is reported as itself.

This is *not* the `Bwrap`/`Argv` shape issue #61's settlement kept off the wire:
nothing hands attach an argv over a channel from another process, and attach
never execs `/proc/self/exe`.

## 9. `--dry-run`

`snug --dry-run` starts nothing, so it may not create anything it names. It
carries one block after SECCOMP, in the existing style:

```
ATTACH   this run publishes /run/user/1000/snug/target-sha256_<hex>.json (0600,
         in a 0700 directory snug owns), so `snug attach <dir>` can join it.
         The file names the sandbox's init pid, its start time and its six
         namespace ids. It carries no command, no argv and no secret.
         Attach is NOT a permission: any process with your uid can join these
         namespaces without snug. What attach adds is the run's own seccomp
         filter, an empty capability set and this policy's environment — a
         plain nsenter has none of the three.
```

**It prints the EXACT path, and that is possible only because the file is
target-keyed** (§6.1): the name is `sha256(realpath)` under the uid-derived
`targetLockBase()`, so this run's own pid never enters it and there is nothing
to fabricate.

It used to print `run-<pid>/state.json` under the env-derived `runtimeBase()`,
deliberately as a *pattern*, on the sound argument that inventing a pid would
be the kind of small lie that makes the whole artifact untrustworthy. That
argument still holds and no longer applies here. What made the old rendering
wrong was not vagueness: after issue #123 it named a file that does not exist,
with the wrong basename, under a base the run need not even use — issue #123's
own failure mode, reappearing on the one screen whose job is to be trusted.
`TestDryRunAttachBlockNamesTheFileAttachActuallyReads` is the pin, and its
predecessor is the cautionary half: it kept passing while the screen was wrong,
because it asserted the pattern rather than the file.

`snug attach` itself gets **no** `--dry-run`. It starts a process; there is no
policy to print, because it resolves none.

---

## 10. The abuse sentences

For the profile TOML equivalent — there is no profile here, so these belong in
`attach.go`'s package comment, in the help text (§8.2) and in `VERIFY.md`:

> A hostile process inside the sandbox can use an attached session to reach
> whatever the attaching human's stdin, stdout and stderr point at — by listing
> `/proc/<attached>/fd` and reopening a descriptor there — and to read the
> attached process's environment. Measured: a payload reopened an attached
> process's stdout and wrote into a host file that no profile granted.

> A hostile process on the host with the same uid can use `snug attach` to enter
> the sandbox — and could equally have used twelve lines of C, because the kernel
> grants this on uid, not on anything snug controls. What it cannot do with snug
> attach is enter *unconfined*.

And the one this feature is explicitly **not** allowed to imply:

> Attach does not isolate the attached process from the payload. That needs
> #101's inner pid namespace, which does not exist. `/proc/<pid>/fd` and
> `/proc/<pid>/mem` reach it (issue #47), and `PR_SET_DUMPABLE 0` does not
> survive the `execve` (measured), so there is no cheap hardening available here.

---

## 11. Teardown analysis

| path | what happens | measured |
|---|---|---|
| A exits normally | B's `wait4` returns, B `_exit`s with A's status, C reports it. | M11/M5 |
| **snug is SIGKILLed** | The sandbox's init dies ⇒ the kernel SIGKILLs every task in that pid namespace ⇒ A dies ⇒ B's wait returns ⇒ C exits. Outer bwrap, init, payload, C, B and A all gone. | **M20** |
| **The attach client C is SIGKILLed** | B dies on `PR_SET_PDEATHSIG` (armed as the first thing B does), A dies on its own pdeathsig. The sandbox and payload are untouched. | **M21** |
| C segfaults / panics | Identical to SIGKILL: pdeathsig is a kernel property, not a handler. | follows from M21 |
| B is killed | A dies on pdeathsig; C sees `wait4` return and exits. | — |
| A is killed from inside the sandbox by the payload | Same-uid, same pid namespace: the payload **can** signal it. B reports the status, C exits. Not a defect — it is what "the payload can address it" means (§10). | — |
| C's forking thread is retired by the Go runtime | Would deliver a spurious SIGKILL to B. Prevented by `runtime.LockOSThread` (§4.1 step 10) — this is the one teardown path that is a *bug waiting* rather than a measured behaviour, so it needs the test in §13.6. |
| The run ends while an attach is live | Init exits ⇒ pid namespace collapses ⇒ A dies. The user sees their shell end, which is correct. | follows from M20 |
| Anything at all | **No state survives.** attach creates no files, binds no pathname, opens no listener, and leaves no process. The run directory and `state.json` belong to the run, not to attach. | — |

Leaked helpers and orphaned namespaces are policy-leak-severity bugs; §13.6 makes
each row above a test.

---

## 12. Where the code lives

- `internal/cli/attach.go` — the subcommand: argument parsing, run selection,
  every check in §4.1, the report/gate pipes, exit-code propagation.
- `internal/cli/attachstdio.go` — the stdio relay, both shapes (§5.4).
- `internal/cli/runstate.go` — `state.json`'s Go shape and its writer;
  `internal/cli/targetstate.go` — where the file lives and how it is found
  (§6.1). The split is the point: one file knows the CONTENT, the other knows
  the LOCATION, and issue #123 moved only the second.
- `internal/attach/` — the raw-fork child and its syscall sequence (§4.2), by
  analogy with `internal/stage`: namespace surgery lives in its own package,
  annotated as hard as `EnterNetns` is, and is testable on its own.
- `internal/sandbox/exec.go` — the `--info-fd` pipe (§7), beside the
  `--seccomp` descriptor and **above** the args-memfd snapshot comment.
- `internal/cli/dryrun.go` — `describeAttach` (§9).
- `internal/cli/main.go` — one line in `usage()`, one case in the subcommand
  switch, above the flag parsing and below the hidden-verb dispatch.

`cmd/snug` is `main.go` alone. Any brief quoting `cmd/snug/claude.go` or
`cmd/snug/dryrun.go` is quoting a tree that no longer exists.

Nothing is added to `internal/policy`: attach makes no policy decision, and the
package stays pure.

## 13. The tests

**All of them exist; the suite is the truth and this section is not.** They live
in `test/integration/attach_test.go`, `internal/attach/bridge_test.go` and
`internal/cli/attach_test.go`. Two names this section once required are folded
into larger tests as numbered sub-cases rather than standing alone — the pid
namespace membership (`test 14`) and adjacent-still-closed (`test 21`) — so
grepping for the name and finding nothing is not evidence of a gap here.

## 14. What this design deliberately does not do

- **No listener, no socket, no protocol.** (Settled.)
- **No `--pid`.** §8.1.
- **No hardening of the attached process against the payload.** M17 measured
  that the only cheap instrument, `PR_SET_DUMPABLE 0`, does not survive
  `execve`, and case F of issue #61's review matrix says it would not be
  sufficient anyway.

  The instrument that was proposed instead — an inner pid namespace making the
  attached process unaddressable (#101) — **now exists on the OFFLINE arm and
  not on the staged one**: `internal/sandbox/inpidns.go`'s `__inpidns` puts
  bwrap in an intermediate pid namespace, and #506 measured what that bought
  (issue #13's orphan window closed by construction, 0 leaks over 18 offsets;
  the staged arm already covered the same window with the parked gate, P1's
  `Pdeathsig` and the lifeline, so it deliberately did not follow).

  **It does not change this design**, and #101's own measurement is why: an
  intermediate level buys nothing for addressability on its own — two payloads
  bwrap starts are still co-resident and still read each other's
  `/proc/<pid>/fd/N`. Attach joins the namespaces of `state.json`'s
  `sandbox.init_pid`, which is bwrap's own `--info-fd` answer, so it lands
  where the payload is, on both arms. Do not write code that reads as though
  attach has a level to choose.
- **No sync-back of anything.** Attach writes nothing to the host except what the
  user's own redirection makes it write.
- **No policy resolution.** No profiles, no config, no TOML, no `Resolve`.
- **No second weakening knob.** §5.1.

---
