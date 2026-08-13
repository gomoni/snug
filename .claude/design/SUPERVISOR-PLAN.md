# Implementation plan — supervisor mode

Working document, uncommitted on purpose. Its inputs are
[SUPERVISOR.md](SUPERVISOR.md) (what was measured),
[SUPERVISOR-REVIEW.md](SUPERVISOR-REVIEW.md) (what four adversaries found wrong
with it) and [ENGINE-NETNS.md](ENGINE-NETNS.md) (why any of this exists). It adds
two things those do not have: a **phasing that separates the value from the
risk**, and one **topology change** that deletes most of the new attack surface
before it is written.

**Revised after the no-cgo research** ([NOCGO-RESEARCH.md](NOCGO-RESEARCH.md)).
Three things the first draft got wrong or did not know, all now measured:

- The cgo recommendation is **withdrawn**. A raw `fork` from multithreaded Go
  gives a child that is single-threaded *and* owns its own `fs_struct`, so
  `setns` works in pure Go. Neither cgo nor a second binary is needed.
- The setns joiner is **no longer the attach mechanism**. `fork` from snug's own
  init inside the sandbox inherits the seccomp filter, the capability sets,
  `no_new_privs` and the cgroup by construction — the joiner has to reproduce all
  four and starts at `Seccomp: 0`. One code path beats two kept in sync.
- **No raw pids** (§3a). `SysProcAttr.PidFD` gives a descriptor at the fork, and
  this kernel's `PIDFD_GET_*_NAMESPACE` ioctls give the joiner its seven
  namespace fds with no `/proc/PID` path anywhere.

One live finding in **shipped** snug fell out of the same work and does not
belong to this plan: `pidfd_getfd(2)` is an fd-theft primitive equivalent to
ptrace, it is absent from `deniedSyscalls`, and it was measured **working** inside
a real sandbox. See NOCGO-RESEARCH, last section — it needs a `TODO.md` entry and
a filter change independent of anything here.

## 0. Was this the right time to plan?

Yes, and the reason is narrow. The kernel facts are measured, the false claims
have been found and corrected, and both are still in reach. What is *not* known
is whether the expensive half can work at all: **podman has never run in N**, on
this host or any other. Three of the review's top five debts converge on that one
gap.

*An earlier draft of this paragraph said the reason was that `/usr/bin/podman`
here is `distrobox-host-exec`, and concluded 0a needed a VM. That was a wrong
diagnosis of a real symptom — see §2 0a, which now measures what is actually on
this host.*

So this is not a build plan. It is a plan with a kill gate in front of it, and
the first thing it buys is the right to stop cheaply.

## 1. The change that should come before any of it

**P1 should not stay in the network namespace it creates.**

Every "worse" bullet in SUPERVISOR §5 — the abstract socket hole, the loopback
hole, the bidirectional MITM, the socket-table enumeration, the constraint on a
future secrets broker — follows from one thing: the stage lives in N, so anything
it binds or dials is in the payload's reach. That was taken as a given because
the stage creates N by `clone` and therefore starts inside it.

It does not have to stay there. P1 holds `CAP_SYS_ADMIN` over U, and U owns N, so
by the `user_namespaces(7)` ancestor rule P1 can `setns` back into N at will. The
sequence:

1. `clone(CLONE_NEWUSER|CLONE_NEWNET|…)` as today — P1 starts in N.
2. Open a descriptor on `/proc/self/ns/net` and **mark it CLOEXEC**.
3. `unshare(CLONE_NEWNET)` — P1 moves to a fresh, empty netns of its own.
4. Every child that belongs in N (`bwrap`, the engine, a joiner) does
   `setns(nsfd, CLONE_NEWNET)` between `fork` and `exec`. No single-thread
   requirement: that applies to `CLONE_NEWUSER` only.

What it buys, if it holds: the control socket's accept loop, P1's own
descriptors, and anything a broker ever does are all in a namespace the payload
cannot reach or squat. The rule in SUPERVISOR §5 stops being "no snug process may
bind or connect in N" — a rule about code snug does not own and cannot test here
— and becomes **"the only snug process in N is the one that must be"**, which is
structural and checkable: `readlink /proc/<stage>/ns/net != readlink
/proc/<sandbox>/ns/net`.

Two things it does not fix, and they are the ones that matter for the engine:
the engine genuinely must be in N, so containers and their helpers
(netavark, aardvark-dns, rootlessport, conmon) stay peers of the payload; and
pasta must be aimed at N, so P1 must hand it a pinned reference — either the
descriptor from step 2 or the bwrap child's `/proc/<pid>/ns/net` — rather than
its own path, which after step 3 points at the wrong namespace. That is exactly
the shape of the memfd-snapshot bug in CLAUDE.md: a value captured before a step
that invalidates it.

**Status: unmeasured.** It is the second item in Phase 0 for that reason. If it
holds, Phases 1–3 are all cheaper and the review's F2 finding mostly evaporates.
If it does not, nothing else changes — the design proceeds as written, with the
full rule.

## 2. Phase 0 — the kill gate

Nothing lands in `internal/` or `cmd/`. All of it is `poc/nsd/`, and the output
is a decision.

**0a. The engine leg — and it runs on this host, contrary to the earlier draft.**
It was written down that 0a "cannot be done here" and "needs a VM or a host
outside the distrobox". Measured, that is wrong, and the way it is wrong is the
familiar one: a symptom was read as a cause. `/usr/bin/podman` being
`distrobox-host-exec` is true, and it says nothing about whether an engine is
available.

| measured | what it means for 0a |
|---|---|
| `rpm -q podman` → `podman-6.0.2-1.1.x86_64`, **installed**, and it *owns* `/usr/bin/podman`. `rpm -V podman` reports `....L....` — the only attribute that differs is `L`, the symlink. | distrobox replaced the engine binary with a shim. The engine is one `zypper install -f podman` away, not a VM away. Restore it to a path of our own rather than fighting distrobox for `/usr/bin/podman`. |
| `/usr/libexec/podman/` holds real `netavark`, `aardvark-dns`, `rootlessport`, `catatonit`, `quadlet`; `crun` and `runc` are both on `PATH`. | The whole network stack the engine needs *in N* is already present, which is precisely the part 0a's second question exercises. |
| `/usr/bin/dockerd` is a real 103 MB ELF; `containerd` is at `/usr/sbin/containerd` (off `PATH`, which is why a `command -v` sweep first reported it missing). | A second, independent engine is available locally. Genuinely useful as a fallback — but a fallback *engine*, not a fallback client. |
| `/usr/bin/docker` is a real client (29.4.0-ce), but `DOCKER_HOST=unix:///var/run/user/1000/podman/podman.sock` and `docker version` reports the server as **Podman Engine 6.0.2**. | It talks to the *host's* engine, outside the distrobox. All three questions below are about an engine **process running in N**, so a client answers none of them. Do not let "docker works here" be read as 0a being partly green. |

The distinction that table exists to hold: **0a needs an engine we can start, not
an engine we can talk to.** Every question below is about a process whose
namespaces we chose.

*Is `dockerd` a good enough substitute for podman here?* The question is worth
answering carefully rather than dismissing, because 0a does not need podman
specifically — it needs **an** engine, and `dockerd` is a real local one.

- **For questions 1 and 2, yes.** Whether an engine starts in a derived mount
  view, and whether a container gets N's network, are properties of the topology
  rather than of the engine. `dockerd --help` describes `--rootless` as
  "typically used with RootlessKit" rather than requiring it, and RootlessKit's
  job — make a user namespace, a network namespace and a uid map — is precisely
  what the stage already does. A green there is real evidence.
- **For question 3, no, and it will answer confidently and wrongly.** That
  question exists *because* ENGINE-NETNS §4 measured podman's `conmon`
  **surviving** a Pdeathsig teardown, which is a fact about podman's process
  model: fork-exec, one `conmon` per container, no daemon. dockerd's model is the
  opposite by construction — a long-lived daemon plus `containerd-shim`, which
  reparents and survives daemon restart as a designed feature. Measured against
  dockerd, question 3 reports on containerd's supervision tree, which snug does
  not ship against.

So use `dockerd` as a **cross-check, not a substitute**. It is most valuable
exactly where the two disagree: if an engine starts in N under dockerd and not
under podman, the problem is podman-specific and that is worth knowing before
Phase 3 budgets for it. Run question 3 against podman or not at all.

**The better answer to both problems is a static podman bundle, and it is also
how the engine leg reaches CI.** `mgoltzsche/podman-static` ships `podman`,
`crun`, `runc`, **`conmon`**, `netavark`, `aardvark-dns`, **`passt`/`pasta`**,
`fuse-overlayfs` and `catatonit` as static binaries, installable into `$HOME` with
no root at all.

Three reasons it beats both alternatives above:

- **It ships `conmon`**, so it preserves the process model question 3 exists to
  test. That is the precise thing `dockerd` cannot do — a bundle with conmon
  answers all three questions.
- **No root, and no fight with distrobox.** `zypper install -f podman` would
  restore the binary, but distrobox owns `/usr/bin/podman` and re-creates the
  symlink; an extracted bundle on `PATH` never enters that argument.
- **It is the same artifact in CI and on a laptop**, which is what makes an
  engine-leg result reproducible rather than a property of one developer's box.

Caveats, sorted by whether they actually bite:

- *Doesn't.* Built without systemd support — irrelevant here, arguably a feature.
- *Already handled.* The bundle warns about AppArmor on Ubuntu ≥23.10, which is
  exactly the `ubuntu-latest` runner, but `.github/workflows/ci.yml` already sets
  `kernel.apparmor_restrict_unprivileged_userns=0` for the integration job. That
  blocker is pre-cleared.
- **Does bite, and it is the interesting one.** The bundle still requires
  `uidmap` from the host, because `newuidmap`/`newgidmap` carry **file
  capabilities** — and a tarball a user extracts structurally cannot carry those;
  they are set by root at install time. So CI installs the distro's `uidmap`
  package regardless. Note the shape, because it recurs throughout this design:
  **the engine can be shipped statically, the privilege delegation cannot.**
  Anything that hands out uids is a thing root had to bless.
- *Pin the version.* A bundle tracking "latest" makes the engine leg
  irreproducible, and the engine leg is where the subtlest namespace behaviour in
  the project is being measured. Pin it in CI and record the version next to any
  0a result.

On *this* host the bundle is close to redundant and it is worth knowing why:
`conmon` 2.2.1, `crun`, `runc`, `netavark`, `aardvark-dns`, `rootlessport`,
`catatonit` and `pasta` 20260612 are all already present and correct. distrobox
replaced exactly one file. Taking the single `podman` binary out of the bundle is
still the cheapest correct route — `rpm2cpio` exists here but there is no `cpio`
or `bsdtar` to pipe it into.

**The engine is now provisioned, and the baseline is measured** —
[PODMAN-STATIC.md](PODMAN-STATIC.md) has the pinned version, the checksum, the
invocation, the helper-set decision and its reasoning, and a reproduction of
ENGINE-NETNS §2 with positive controls. Read it before running 0a; two of its
findings are prerequisites rather than notes, and both were measured:

- **`podman run` inside a userns+cgroupns stage needs `--cgroups=disabled`.**
  Otherwise `crun` fails with `write to /sys/fs/cgroup/libpod_parent/…/cgroup.procs:
  No such file or directory`. This is a property of this host, not a bug in the
  stage — do not spend an afternoon on the stage for it, which is the exact shape
  of the `clone3`/ENOSYS hour recorded in CLAUDE.md.
- **The stage must own its netns before the engine starts**, or `netavark` fails
  with `setns: IO error: Operation not permitted`. Note this interacts directly
  with 0b: if P1 moves out of N, the ordering of "P1 pins N" and "the engine
  enters N" becomes load-bearing rather than incidental.

That document is also honest about what does not work here (`podman info` under
the plain wrapper, `unshare --map-current-user --cgroup`, `podman system reset`),
which is the part that saves the time.

Three questions in order, each of which can stop the project:

| question | why it can stop everything |
|---|---|
| does podman start in a mount view derived from the sandbox's? | MEASURED-refused today: `mount -t proc` fails in the derived view even with `CapEff=000001ffffffffff`, because mounting procfs needs `CAP_SYS_ADMIN` in the userns owning the **pid** namespace and P1 creates none. The fix is an engine stage that unshares `CLONE_NEWPID` — which changes who reaps `conmon`. |
| does a container actually get N's network? | This is the entire payoff. ENGINE-NETNS §2 measured it with `unshare`, not with this topology. |
| does teardown hold with a real engine? | ENGINE-NETNS §4 measured `conmon` **surviving** a Pdeathsig teardown. N now holds the engine, so a surviving conmon keeps N alive, and E11's process count cannot see a netns pinned by a bind mount with no process attached. |

**0b. P1 outside N** (§1 above). One afternoon in the PoC. Cheap, and it changes
the shape of everything after it.

**0c. The graft repeated for `/etc/containers`, `/run`, `/var/tmp`.** SUPERVISOR
§8 calls these "the same mechanism repeated". `/run` is not: the policy already
grants into it (`/run/snug/ssh-agent.sock`, the container socket), so a tmpfs
graft there is a mount landing on top of two grants, in a view no rule inspects.
Measure the collision before designing around it.

*This got worse while the branch sat.* `/run/snug/bin` is now **the** staging
directory for executables snug substitutes, and it is first on the sandbox's
`PATH` — the `@claude` binary and the `podman` shim both moved there, precisely
so that snug never stages an executable into a directory the payload can write.
So `/run` now carries three grants, one of which the environment depends on: a
tmpfs grafted over `/run` in a joiner's view does not merely hide a socket, it
puts an empty (or payload-writable) directory at the head of `PATH` inside a
process the policy believes it configured. That is the exact defect the review
of `110a6be` caught in the main tree — "a profile mounting a tmpfs at
`/run/snug/bin` made snug put a writable directory first on PATH in its own
provenance" — reappearing one layer down, where `Validate` cannot see it because
the graft is built by `open_tree`/`move_mount` rather than by a grant. Measure
this case specifically, and treat the answer as a gate on the graft design, not
as a detail of it.

**Exit criteria.**

- All three of 0a green → the full plan, Phases 1→2→3.
- 0a red on the engine, 0b green → **Phases 1–2 only**, and they are worth doing
  on their own (see §3). `@podman-socket` keeps its `include = ["net"]`, and
  ENGINE-NETNS's §5 stays parked with a measurement attached to it.
- 0a red *and* 0b red → stop. Record why in ENGINE-NETNS §5 and delete nothing;
  the PoC is the record.

**"0a not run" is no longer one of the states.** While the first draft believed
0a needed hardware we did not have, deferring it was a defensible answer. The
measurements above removed that excuse: the engine is a package restore away and
its whole helper stack is already on disk. So an implementation that begins at
Phase 1 with 0a unmeasured is not being pragmatic, it is spending the stage's
entire attack surface against a payoff nobody has checked exists.

## 3. The phasing, and why it is this way

The review's findings are not evenly distributed. **Attach does not need the
engine, and the engine does not need attach.** They share only the stage. So:

```
Phase 1   the stage, with NO new user-visible capability
Phase 2   snug attach                        ← ships value without the engine
Phase 3   the engine in N                    ← needs Phase 0a green
```

Phase 1 is the dangerous refactor and it is deliberately invisible: the same
guarantees, the same `--dry-run` output plus one block, the same integration
suite passing unchanged. Every existing negative test becomes a regression test
for the new topology *for free*, and any divergence is a bug in the refactor
rather than an interaction with a new feature. This is the only phase where that
separation is available, and it is worth the extra step.

## 3a. No raw pids anywhere — pidfd, and it is viable in pure Go

Owner's instruction: do not track subprocesses by POSIX pid. Researched and
**MEASURED on this host — viable, in pure Go, with no cgo, and it closes more
than process tracking.**

A pid is a *number that can be reused*. Every use of one is a window: between
learning it and acting on it, the process can exit and the number can be handed
to something else. The topology makes that worse in two specific ways — P1 is
long-lived, so its windows are long, and the things it names by pid are
`bwrap`, the engine, and the namespaces the joiner is about to enter. A pid-reuse
race at the last one is not a crash, it is a process joining the wrong sandbox.

**1. Race-free from birth: `SysProcAttr.PidFD`.** Go 1.26 exposes it
(`syscall/exec_linux.go:112`), and it is filled in by `CLONE_PIDFD` *at the
fork*, so there is no lookup and therefore no window at all. MEASURED:

```
pid=348735 pidfd=10   (pidfd obtained AT FORK, no lookup)
```

Every process P1 owns — bwrap, pasta, the engine, a joiner — gets one this way,
and P1 stores the descriptor, never the integer.

**2. `os.Process` already does this internally**, and `WithHandle` exposes it.
`os/pidfd_linux.go` uses a pidfd whenever the kernel supports it, and its own
comment says why: *"When pidfd is used, there is no wait/kill race … because the
PID recycle issue doesn't exist."* `Process.Kill`, `Signal` and `Wait` are
therefore already race-free. `Process.WithHandle(func(h uintptr))` (Linux 5.4+)
hands out the handle under a guarantee it stays valid for the callback —
MEASURED working. So most of this is adopting what the stdlib does rather than
writing anything.

**3. The one that matters most: namespaces straight off a pidfd, no `/proc/PID`
path at all.** This kernel has the full `PIDFD_GET_*_NAMESPACE` ioctl set
(`/usr/include/linux/pidfd.h`), and MEASURED, all seven the joiner needs return
descriptors whose inodes match `/proc/<pid>/ns/*` exactly:

```
  mnt    ino=4026533608   /proc says mnt:[4026533608]
  pid    ino=4026533611   /proc says pid:[4026533611]
  ipc    ino=4026533610   /proc says ipc:[4026533610]
  uts    ino=4026533609   /proc says uts:[4026533609]
  net    ino=4026533612   /proc says net:[4026533612]
  cgroup ino=4026532982   /proc says cgroup:[4026532982]
  user   ino=4026533607   /proc says user:[4026533607]
```

This replaces the joiner's "open all seven `/proc/PID/ns/*` before the first
setns" with "ioctl all seven off a pidfd", and the reason to prefer it is not
tidiness: **the `/proc/PID` form re-resolves the pid seven times**, and the
`/proc` it resolves against changes identity the moment the mount namespace is
joined — which is exactly why SUPERVISOR §3.3 has to warn about opening them all
first. With a pidfd that warning stops being needed, because there is no path and
no pid.

MEASURED also for a process that is **not** the caller's child (`pidfd_open` then
the same ioctls), which is the joiner's real situation.

**Where a pid still enters, and what to do about it.** bwrap reports its inner
child through `--json-status-fd` as an integer, so that one crossing is a pid by
protocol and cannot be avoided. Narrow it: `pidfd_open` it **once**, immediately,
and use only the descriptor afterwards; `PIDFD_GET_INFO` can then confirm
identity. Note that under fork-from-init this need disappears entirely — the init
is already inside, so nothing is ever named by pid to attach to it. It survives
only for the `internal/nsjoin` fallback.

**Rule for the implementation, stated so it can be checked by grep:** an `int`
pid may appear only where a protocol forces it (bwrap's status fd, `newuidmap`'s
argv, pasta's `--netns /proc/<pid>/ns/net`). Everywhere else the type is a
descriptor. `PastaArgs(childPID int)` is the visible exception and stays one,
because pasta's CLI takes a path.

**Kernel floor this sets.** `CLONE_PIDFD` and `pidfd_send_signal` are 5.3/5.1;
`PIDFD_GET_*_NAMESPACE` is much newer. `snug doctor` must probe the ioctls rather
than assume them, and the fallback is the `/proc/PID/ns/*` path with its existing
ordering discipline — not a silent one, per invariant 5.

## 3b. The constraint `internal/nsjoin` carries

The pure-Go joiner works by raw `fork`, and its child function runs in the state
Go's own `syscall/exec_linux.go:129` describes: *"must not acquire any locks …
no rescheduling, no malloc calls, and no new stack segments."* Everything the
child touches — argv, envp, the seven descriptors — is marshalled **before** the
clone, and the child issues `RawSyscall` only and never returns to Go.

Annotate that as hard as bwrap's `--` separator is annotated. A future edit that
adds an `fmt.Sprintf` to that function is a rare, latent, undebuggable hang, and
it will present as a scheduler bug. Two more facts to keep next to it, both
measured: the joiner needs `CAP_SYS_ADMIN` **in its own user namespace** (EPERM
on every namespace otherwise, which is the diagnostic that distinguishes it from
EINVAL for the wrong thread state), and the capability drop is not optional — the
no-drop control shows `CapEff=000001ffffffffff` inside a sandbox whose payload
has none.

## 3c. What every phase owes the definition of done

This plan was written without a `redteam` step in it. That is a defect in the
plan, not an omission of detail, and it is worth stating why rather than quietly
inserting a line.

CLAUDE.md's definition of done mandates a `redteam` run for any change to the
policy model, mount generation, the seccomp filter, or a host-integration
surface. **Supervisor mode is all four at once.** It also requires `VERIFY.md` to
gain the by-hand equivalent of each new automated test, and this plan mentions
`VERIFY.md` nowhere.

The reason the gap is easy to miss is the reason it matters:
[SUPERVISOR-REVIEW.md](SUPERVISOR-REVIEW.md) exists, four adversaries wrote it,
and it is genuinely good — so adversarial coverage *feels* discharged. It is not.
That review attacked **the proof of concept**: a program with no seccomp on
attached processes, a control protocol that trusts its caller completely, and no
engine. None of those is what Phase 1 ships. Reusing it as the implementation's
red-team pass is the exact substitution CLAUDE.md warns about — "self-written
tests confirm the mechanism you had in mind, not the one an attacker uses" — with
one extra turn of the screw: the mechanism the review had in mind was a
*different program's*.

So each phase below carries these two, and they are numbered exit criteria rather
than a closing note, because a closing note is what the first draft would have
had:

- **`redteam` has attacked the phase as implemented**, against the merged tree,
  not the PoC. Each phase gets its own run because each opens a distinct surface:
  Phase 1 the stage's control socket and P1's descriptor table, Phase 2 the
  attach path and co-resident payloads, Phase 3 the engine's derived view and the
  grafts. Every confirmed finding is fixed or written into `TODO.md` with a
  severity, and every one becomes a named regression test — the `redteam` →
  `sandbox-tester` pipeline, unchanged.
- **`VERIFY.md` gains the by-hand equivalent** of what the phase added, every
  line a command with its expected output. For this work that is not
  box-ticking: the load-bearing Phase 1 assertion is a comparison of two
  `readlink /proc/<pid>/ns/net` values, which is a two-line manual check and a
  fiddly automated one, and it is the check that catches the failure the bwrap
  goldens structurally cannot.

### Phase 1 — the stage

**Entry:** Phase 0b answered.

**Work.**

- `internal/stage/` — new package. P0 side: clone with the four namespace flags,
  `newuidmap`/`newgidmap`, the lifeline pipe, the readiness handshake. P1 side:
  the re-exec (`/proc/self/exe`, **not** a path from the environment — the review
  found `$NSD_SELF` re-executed after the uid map is written is a same-uid
  replacement window), `MS_REC|MS_PRIVATE`, `lo` up, the netns move from §1, the
  control listener.
- **`sealInheritedFDs` moves into P1 and runs before every fork.** Not the
  one-line CLOEXEC fix on fd 5. `internal/sandbox/exec.go:299` already has the
  sweep; it needs a caller in the stage's fork path and a `keep` list that is
  computed per fork, because P1's fd table depends on which control connections
  are open at that moment.
- **Every child is tracked by pidfd, not by pid** (§3a). This is Phase 1 work,
  not a later cleanup: P1 is long-lived, so its pid windows are long, and
  retrofitting descriptors through a supervisor written around integers is a
  rewrite rather than a patch.
- `internal/policy`: a `Topology` field, **derived and folded**, never set from a
  flag. Minimum three: who owns the netns; whether the full subuid map is
  delegated (⇐ `Podman != PodmanOff`, so a plain `snug` does not delegate the
  range); whether attach is permitted. Each needs a `Join` alongside `Access.Join`,
  `NetMode.Join`, `PodmanMode.Join`. A field set from the CLI instead of derived
  from the resolved profile set re-creates `default_profile`.

  **Do not write the range size into the model.** An earlier draft of this bullet
  said "65536 uids", which is the conventional layout and is wrong here:
  `/etc/subuid` on this host reads `michal:1001:64535`, so the range is 64535 ids
  starting at 1001, not 65536 starting at 100000. The good news is that snug does
  not hardcode it today — a grep for `65536`, `subuid` and `newuidmap` across
  `internal/` and `cmd/` finds only a comment in `internal/sandbox/netns.go:27` —
  and the `Topology` field must not be where that changes. It records **whether**
  the range is delegated, never **how big** it is; the size is read from the host
  at run time, or it is a fact snug asserts and the next unusual host falsifies.

  Two related measurements from PODMAN-STATIC.md, worth keeping next to this
  because both contradict the obvious assumption. `newuidmap`/`newgidmap` carry
  **file capabilities, not setuid** — so "is it setuid" is the wrong probe. And
  on this host those capabilities are **v3, namespaced, `rootid=1000`**, because
  development happens in a rootless distrobox; a CI runner shows v2. Anything
  that inspects them has to handle both.
- `internal/policy/net.go`: `PastaArgs(childPID)` keeps its signature and gains a
  caller passing the stage's pid. Nothing else in it changes — that is the point
  of invariant 6, and the PoC's hand-typed copy of the closing set must not
  travel into the tree.
- `internal/sandbox`: `Run` becomes a stage child. `safeStdio` and the `--`
  discipline are unchanged.
- The control protocol: newline-delimited JSON, `DisallowUnknownFields()` plus
  the trailing-data check, one request per connection — the `internal/dockerproxy`
  house style, which the PoC deliberately does not have. `Target` is validated
  against sandboxes P1 itself started; the capability drop is unconditional and
  server-side, never a client-supplied boolean.
- The run directory gets `prepareHostTmpDir`'s guards (`cmd/snug/tmpdir.go:58`),
  which `runtimeDir()` (`cmd/snug/identity.go:19`) does not have today: refuse a
  symlink, a foreign owner, group or other bits. And the control socket goes in a
  directory `BindSocket` never touches — snug binds two of that directory's
  siblings into the sandbox today.

**Exit criteria — all of them, or Phase 1 is not done.**

1. **Behavioural tests green and unedited; golden files changed only where
   criterion 6 requires, and reviewed as boundary changes.** The earlier draft of
   this criterion said `make gate` and `make integration` green *unchanged*, "not
   adapted, not re-baselined" — and criterion 6 below requires `--dry-run` to
   print a new topology block. Since `110a6be` there are seven golden files under
   `cmd/snug/testdata/` plus the bwrap goldens under
   `internal/policy/testdata/`, and a new block edits some of them. So the two
   criteria as written could not both be met.

   That is worth more than a wording fix, because of *how* it fails. Whoever hits
   it re-baselines the goldens, the diff is expected, and the discipline that
   makes a golden diff mean something — "a change to a golden file is a change to
   the security boundary and is read as such" — gets spent on a diff nobody had
   to think about. The next golden diff in the same series then arrives
   pre-approved.

   Split it, and hold each half to a different standard:

   - *Behavioural* — every integration test asserting what the sandbox can and
     cannot reach passes **unedited**. This is the real content of the original
     criterion, and it is where "a test that had to be edited to pass is a
     guarantee that changed" applies without exception. Phase 1 adds no
     user-visible capability, so there is no legitimate reason for one of these
     to move.
   - *Golden* — the topology block lands in **one commit that changes nothing
     else**, so its diff is exactly the new block and can be read line by line. A
     golden file that moves in any other Phase 1 commit is a defect until
     explained, not a re-baseline. Every changed line gets the same question a
     new grant gets: which authority produced it, and does the policy already say
     so.

   The bwrap argv goldens are the sharper case: per criterion 2 the argv no
   longer determines the network posture, so an *unchanged* bwrap golden is now
   compatible with a completely different network topology. Do not read those two
   green as coverage.
2. `readlink /proc/<sandbox>/ns/net == readlink /proc/<stage's pinned N>` and
   `!= /proc/self/ns/net`, asserted behaviourally. **This is load-bearing in a
   new way:** after this change the bwrap argv no longer determines the network
   posture. `--share-net` is byte-identical whether it means N or the host's
   netns; the difference is which process called `fork`. Golden argv stops being
   sufficient here, by construction, and it is the first place in snug where that
   is true.
3. No descriptor in the payload resolves to an inode also open in P1 (review F1).
4. The stage exits when `startSandbox` *fails*, not only when it succeeds — the
   `everRan` path the PoC leaves disabled.
5. Teardown asserts on the **namespace object**, not a process count: a netns
   pinned by a bind mount with no process attached is invisible to
   `/proc/*/ns/net` counting.
6. `--dry-run` prints the topology block: a second long-lived process, a user
   namespace holding the subuid range that is an ancestor of the sandbox's own,
   the control socket path marked host-only, and the lifetime rule. "No daemon,
   no service files" is a claim the human already believes from the README.
7. **`redteam` has run against the merged stage** (§3c), aimed at the surfaces
   this phase actually creates: the control socket's permissions and its parent
   directory, whether a sandboxed payload can reach or name it, P1's descriptor
   table at the moment of each fork, and the re-exec path. Findings fixed or in
   `TODO.md` with a severity; each one a named regression test.
8. **`VERIFY.md` covers the phase by hand** (§3c) — at minimum the netns
   comparison from criterion 2 and the teardown check from criterion 5, each as a
   command with its expected output.

### Phase 2 — `snug attach`

**Entry:** Phase 1 green.

**Work.**

**This section was rewritten after the no-cgo research
([NOCGO-RESEARCH.md](NOCGO-RESEARCH.md)). The cgo recommendation is withdrawn,
and so is the setns joiner as the primary mechanism.**

- **Attach is `fork` from snug's own init inside the sandbox — not `setns` from
  outside.** MEASURED: a forked payload's `/proc/<pid>/status` is byte-identical
  to a plain bwrap payload's — `Seccomp=2`, `Seccomp_filters=1`, every capability
  set zero, `NoNewPrivs=1`. The setns joiner starts at `Seccomp: 0` with a **full
  capability set** and must correctly reproduce five things. SUPERVISOR §4's
  "what the joiner must still reproduce" list is exactly what `fork` inherits by
  construction. **`Policy.AttachSpec()` is therefore not needed for the primary
  path** — there is one code path, so there is nothing to keep in sync.
- **The channel is an inherited `socketpair`, and its properties are the design.**
  Pathless, so there is nothing to `connect()` to; `FD_CLOEXEC` before any child
  exec, so no payload inherits it; `PR_SET_DUMPABLE=0` on the init, so
  `/proc/<init>/fd` is denied to a same-uid sibling (MEASURED, with the
  unprotected positive control first). And a fact worth keeping on its own: **a
  socket cannot be reopened through procfs** — `open("/proc/<init>/fd/N")` on a
  socket returns ENXIO, even with protection off.
- **Init hardening is load-bearing, and one part of it is a trap.** `bwrap
  --as-pid-1` buys the kernel's `SIGNAL_UNKILLABLE` protection, but **a Go init is
  not unkillable**: the runtime installs SIGTERM/SIGINT handlers, which makes
  those signals *deliverable* to pid 1 (the pid-1 rule only shields signals with
  default disposition), and Go's default action terminates. MEASURED: SIGKILL
  survived, SIGTERM and SIGINT killed it. Ignore **all** catchable signals, not a
  list — MEASURED, omitting `SIGABRT` from the ignore list killed the sandbox.
- **Init must derive what it forks — path, argv, env, cwd — solely from the host
  request.** Never from sandbox-writable state: no PATH lookup into a writable
  directory, no reading a tmpfs file to choose a binary. Hold that and there is
  no confused-deputy shape, because the payload has no channel to the init.
- **Getting snug's binary into the sandbox: bind through snug's own inherited
  fd.** MEASURED both ways — `--ro-bind /proc/self/fd/9 /payload` works, while
  `--ro-bind /proc/<snug-pid>/exe` fails with `Permission denied` because bwrap
  resolves bind sources *after* unsharing its user namespace. An fd is a
  TOCTOU-free reference to an inode; a path is a lookup that can be re-pointed
  between the check and the exec (MEASURED: replacing the binary while holding
  the fd, then `execveat`, ran the **old** inode). No grant has to name a host
  path, and the review's `dirname(argv0)` finding disappears.
- **`internal/nsjoin` — the pure-Go setns joiner — is built anyway, as the
  fallback.** ~130 lines, no cgo, no second binary. It exists for injecting into
  a sandbox that has no snug init; the attach path is not built on it. See §3b for the
  constraint its child function carries.
- The pty travels host → init over `SCM_RIGHTS` on the same socketpair —
  MEASURED working across the sandbox boundary, and the payload cannot intercept
  it because the fd lands in init and is closed or duped before any exec.
- `snug attach` to nothing is an error naming the fix (§9's cost, stated).

**Exit criteria.**

1. An attached process has the **same** `Seccomp`, `CapBnd`, `NoNewPrivs` and
   environment as the primary. Until that test exists, an attached payload is
   *less* confined than the primary — ptrace, nested userns and keyctl available
   to it among siblings at the same uid — and invariant 5 says a capability that
   silently is not there is worse than an error. If it cannot be made equal,
   **refuse to attach**; do not print a warning.
2. Two attached payloads: B can read A's `/proc/<pid>/environ`. This test asserts
   the *current* behaviour on purpose, so that any future per-payload-secret
   design has to break it. Co-resident payloads are one trust domain.
3. `--dry-run` says attach exists, who can use it (anything reaching the socket
   as your uid), and what it grants.
4. **`redteam` has run against attach** (§3c), with the payload assumed hostile
   and a second payload assumed hostile *to the first*: can either reach the
   init's socketpair by any route, forge or replay a request, influence what the
   init forks, or recover the pty fd. This is the phase where the adversary is
   inside the sandbox rather than outside it, so it does not resemble any run
   done so far.
5. **`VERIFY.md` covers attach by hand** (§3c) — the `/proc/<pid>/status`
   comparison from criterion 1 above all, since that is the criterion whose
   failure mode is silent and whose fix is a refusal.

### Phase 3 — the engine in N

**Entry:** Phase 0a green in all three questions. Not otherwise.

**Work.**

- The engine stage: `setns` into N, its own pid namespace (0a's answer decides
  whether that is P1's job or the engine child's), the derived mount view, the
  grafts.
- **Grafts become policy objects.** `map[string]Mount` with `From`, `Access`,
  `Authored` — not a `[]string` of host paths on an engine config struct. Run the
  *same* `rejectMasking` over the derived view; a graft destination colliding with
  a grant is a hard error, not a silent overmount. `Validate` becomes
  view-parameterised and `nearestCovering` takes the view. `internal/policy` stays
  pure: a graft is still just paths, no `exec`, no filesystem.

  This is the invariant-1 crux. The `KindData` precedent does **not** cover it:
  that replaces *content* at a path `p.Mounts` already names, marked `Authored`,
  with `replaces:` rendered in `--dry-run`. A graft adds a *host subtree* at a
  path the policy does not name. Ship it without a policy object and graft #4
  arrives with none either, because the first three did.
- **The proxy keeps its allowlist.** The derived view changes its vocabulary —
  `hostPathVisible` is keyed on `Mount.Host`, and podman under a derived view
  resolves against `Mount.Guest` — and that is the whole change. It does not
  license replacing "may bind iff the sandbox can see it" with "anything in the
  view except our grafts", which is a denylist over a set snug no longer
  enumerates. Budget this as a **vocabulary change plus new tests**, not a
  deletion; net lines are plausibly positive.
- `resolveExisting` moves rather than shrinks: it resolves symlinks in snug's own
  mount namespace today, correct precisely because the engine shares it. Under a
  derived view the two answer different questions, and the redteam finding that
  motivated it (`ln -s ~/.ssh $TARGET/link`) re-aims at the grafts.
- Fix, independently and first, since it is a live divergence:
  `hostPathVisible` returns on the *first* covering mount, and `p.pol.Mounts` is a
  `map` with random iteration order. The policy layer's rule is "the deepest mount
  covering it wins". No shipped profile creates the shape today; it is still the
  proxy and the policy disagreeing, which is what invariant 6 promises cannot
  happen.

**Exit criteria.**

1. `podmanClientUsable()` is a **hard refusal**, not a warning. This is the most
   dangerous line in the transition: today a fallback to the old topology is
   *honest*, because `@podman-socket`'s `include = ["net"]` says egress is there.
   After the include goes, a fallback means the sandbox says offline while a
   container reaches the internet — the original measured bug, restored, by a
   code path whose only trigger is a host we cannot test on.
2. `TestPodmanSocketIncludesNetAsAnInterimHonestyFix` is **replaced** by a test
   of the refusal, not deleted. The include's absence is not the property that
   matters; the impossibility of the old path is.
3. `ss -xl` inside the sandbox reports zero abstract sockets **with the engine
   running**, and no snug-owned process listens on any IP port in N. Note what
   makes this weaker than snug's other rules: it constrains podman, conmon,
   netavark, aardvark-dns and crun — code snug does not own. §1's netns move is
   what turns most of it back into a structural property.
4. CLAUDE.md's two "abstract sockets unreachable **by construction**" sentences
   change in the **same commit**. Otherwise snug asserts a guarantee it no longer
   delivers, which is the failure invariant 5 exists to forbid and the same shape
   as the `@podman-socket` finding this work exists to fix.
5. The graft mountpoint appears in `--dry-run`'s filesystem block, marked
   snug-authored, noting the sandbox sees an empty directory there. A path inside
   the sandbox that no line of `--dry-run` explains is what `--dry-run` exists to
   prevent.
6. The containers block inverts: containers share *this* netns; a container
   reaches any port the sandbox binds; published ports land on the sandbox's
   loopback. And the teardown sentence loses its "by construction".
7. **`redteam` has run against the engine leg** (§3c), and this is the run that
   matters most, because criterion 3 above constrains code snug does not own —
   podman, conmon, netavark, aardvark-dns, crun. Aim it at the grafts (a
   container mounting through a graft destination the policy never named), at the
   proxy's vocabulary change (`Mount.Host` versus `Mount.Guest` under a derived
   view), and at whether a container can reach the sandbox's own services now
   that they share a netns.
8. **`VERIFY.md` covers the engine leg by hand** (§3c), including the `ss -xl`
   check from criterion 3 with the engine actually running — a positive control
   first, per the `pasta.avx2` lesson, since "zero abstract sockets" passes
   trivially on a sandbox whose engine never started.

## 4. The golden discipline has to grow with it

"Golden argv diffs are the review artifact" covers one of six authorities after
this lands. The others are the stage's clone flags and uid_map, the derived
view's graft set, and the attach spec. Either `TestGoldenStageArgs`,
`TestGoldenEngineView` and `TestGoldenAttachSpec` exist beside
`TestGoldenBwrapArgs`, or "a security change that produces no golden diff is
probably untested" stops being enforceable — most of the boundary simply would
not be in a golden file.

And per Phase 1's exit criterion 2: golden argv is now *necessary but not
sufficient*. The network posture lives in the process tree, not the argv. Every
phase needs at least one behavioural assertion with a positive control, which is
the lesson the PoC's own suite had to relearn — four of its checks passed on a
sandbox that never started.

## 5. Decisions a human owns

Three, and none should be made by whoever is implementing at the time:

1. ~~cgo, or a second binary.~~ **Answered by measurement: neither.** A raw
   `fork` from multithreaded Go gives a child that is single-threaded *and* owns
   its own `fs_struct` — the two states the kernel checks — so `setns` works in
   pure Go. And fork-from-init removes the need to `setns` at all. Nothing here
   is a judgement call any more.
2. **Whether Phase 2 ships alone** if Phase 0a comes back red. It is real value —
   `claude` and a shell in one sandbox — but it buys the stage's whole attack
   surface for a convenience feature. The answer depends on how much the
   multi-payload shape is actually wanted.
3. **Whether the MVY2 secrets broker goes in P1.** SUPERVISOR §5 suggests it.
   Today `sshproxy` and `dockerproxy` are deliberately separate processes;
   merging "holds host credentials" with "holds CAP_SYS_ADMIN over the sandbox"
   into one process is a real consolidation of blast radius, and §1's netns move
   makes it *safer* without making it *right*.

## 6. Not in this plan

Interactive reconnect and detached sessions (§9 decided against them —
a multiplexer inside the sandbox is the payload's choice). Cgroup delegation,
which nothing here improves. GUI, audio and D-Bus, which stay out of scope. And
`TODO.md` entries: every §5.2 debt in the review that this plan does not close in
its phase belongs there with a severity the moment the PoC stops being a PoC.
