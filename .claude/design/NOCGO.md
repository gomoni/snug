# No cgo

snug builds with `CGO_ENABLED=0` and nothing in it may change that. This
document is the whole statement: what the rule costs, what it nearly cost, and
the measurements that made it affordable. Everything marked **MEASURED** was
executed on this host.

The short version is in `CLAUDE.md` under "Decisions made". This is the long one,
and it exists because the rule was tested by a real case rather than asserted in
the abstract: a design was written that *needed* cgo, and the need turned out to
be a mistake about which process has to make a syscall.

## 1. The rule, and what it is defending

A cgo binary is linked against a specific libc, and that is the whole cost:

- **It breaks "works everywhere".** Key feature 3 says snug runs in odd
  environments, including from inside a distrobox or a CI container. A cgo build
  is a glibc build *and* a musl build, and the failure mode of getting it wrong
  is a sandbox that will not start on the host where you needed it.
- **It breaks cross-compilation.** `GOOS=… GOARCH=… go build` stops working and
  a toolchain per target starts being a prerequisite.
- **It is the wrong shape for this tool specifically.** snug re-execs itself
  through `/proc/self/exe` as part of how the stage works, so the binary is a
  runtime dependency of itself. A self-contained static binary is not a
  preference here; it is the thing being re-executed.

Against that, cgo buys real things. It is not superstition to want it — which is
why the rule needs the rest of this document rather than just the paragraph
above.

## 2. What the kernel actually checks — MEASURED, both errnos

`setns(2)` is where the rule was tested, because two of its namespaces are
hostile to a multithreaded runtime and one design concluded a cgo constructor
was the only way out. The constructor argument is sound as far as it goes: a
`__attribute__((constructor))` runs **before the Go runtime starts its threads**,
which is precisely the state `setns` demands, and there is no pure-Go equivalent
hook. That is the one thing cgo genuinely buys here.

| namespace | pure Go, multithreaded |
|---|---|
| mnt | **EINVAL (22)** |
| user | **EINVAL (22)** |
| pid, ipc, uts, net, cgroup | OK |

Two independent checks with one root cause. `userns_install()` returns `-EINVAL`
when `!thread_group_empty(current)`. `mntns_install()` returns `-EINVAL` when
`fs->users != 1` — and Go creates every thread with `CLONE_FS`, so `fs->users`
**is** the thread count.

**`runtime.LockOSThread` changes no row, and neither does `GOMAXPROCS=1`.**
MEASURED. LockOSThread pins a goroutine to a thread; it does not remove the
other threads, and both checks count threads rather than ask which one is
running.

**`/proc/self/exe` re-exec does not buy single-threadedness either.** A Go binary
is never single-threaded at its own first statement, so re-execing one changes
nothing about the two EINVAL rows. (The idea survives for a different job — §4.)

## 3. What snug does with that, which is not to work around it

**snug never joins a mount or user namespace.** The two EINVAL rows are a
constraint the architecture is shaped by rather than an obstacle any code here
steps over: `bwrap` creates those namespaces and the payload is `exec`'d into
them by a process that was already inside. Nothing in this tree calls `setns`
with `CLONE_NEWNS` or `CLONE_NEWUSER`.

The `__`-prefixed re-exec verbs exist for the OK rows, and their obstacle is a
different one — `setns(CLONE_NEWNET)` is **per-task**, exactly as `unshare` is,
so it moves the calling thread and not the process. A goroutine cannot be
relied on to stay on the thread it moved, and the Go runtime may run any other
goroutine there afterwards. So the move happens in a fresh process that does
nothing else: `__innetns` (`internal/stage/innetns.go`) locks the OS thread,
`setns`es into the sandbox's network namespace, re-reads its own
`/proc/self/ns/net` and refuses if it did not move, then `exec`s. `__inengine`
is the same shape with the engine's confinement attached, and `__inpidns` is
the pid-namespace equivalent. A verb is one syscall plus a proof it worked, and
that is the whole technique.

### The raw-fork route, retired with its measurements

There is a second answer to the EINVAL rows, it works, and nothing in this tree
uses it any more. It is recorded because it is the answer someone re-derives:
**a raw `fork` from a multithreaded Go program produces a child that is
single-threaded *and* owns its own `fs_struct`** — exactly the two states the
kernel checks. MEASURED, including against a real `bwrap --unshare-all` sandbox
rather than only against `unshare(1)`.

What it cost, and why "just be careful in the child" is not available: the child
carries the **forking goroutine's `stackguard0`**, and the Go runtime poisons
that value with `stackPreempt` whenever it wants the goroutine preempted — on
every stop-the-world and on any sysmon retake of a goroutine that has run for
10 ms. An ordinary Go function's prologue compares SP against it *before its
first statement*, loses, and calls `runtime.newstack`, which asks the scheduler
for threads the fork did not copy. MEASURED in isolation: a harness forking 40
children under `runtime.GC()` pressure wedged **17 of 40** when the child's
first call was an ordinary function, and **0 of 40** when it was
`//go:nosplit`. MEASURED in the wild as issue #221: two bridge processes alive
hours after their caller had died — `Threads: 1`, `wchan: futex_do_wait`,
`SigBlk: 0`, `NoNewPrivs: 0`, `Seccomp: 0` — having executed not one
instruction of their own first step, so they were also before their
`PR_SET_PDEATHSIG` and killing the client did not clean them up.

Making it safe was structural rather than editorial: `//go:nosplit` over the
child's entire call graph, `//go:norace` and `//go:nocheckptr` to keep a `-race`
or `-d=checkptr` build from injecting instrumentation into the same path, and
the parent blocking every signal on the forking thread across the clone. **If
anything in this tree ever raw-forks again it inherits all of that**, and the
linker checks only half of it — the nosplit budget for the chain, not whether a
function on the path was left unmarked.

Two routes measured and rejected alongside it, so they are not re-proposed:

- **A sealed memfd carrying a helper.** It works — `memfd_create` plus full
  seals, verified to refuse a later write with EPERM, plus
  `execveat(fd, "", AT_EMPTY_PATH)` — but since a *Go* binary is never
  single-threaded at start, the blob would have to be a **C** helper, making it
  a C-helper design in disguise. It also inherits a build dependency: there is
  no static glibc on this box, so the blob would need the loader at exec time,
  or musl/`-nostdlib` becomes a prerequisite.
- **`nsenter(1)` as a drop-in.** MEASURED **FAILED** in this topology:
  `nsenter: setgroups failed: Operation not permitted`.

## 4. What survived from the `/proc/self/exe` idea

The intuition was aimed at locating a helper. There is no helper, but the
property underneath it is what the re-exec verbs run on, and it is MEASURED
twice:

**An fd is a TOCTOU-free reference to an inode; a path is a lookup that can be
re-pointed between the check and the exec.** Replacing a binary on disk while
holding an fd, then `execveat`ing the fd, ran the **old** inode (`(deleted)` in
`/proc`), while exec by path ran the new one. And `open("/proc/self/exe")`
succeeds **inside a mount namespace that does not contain the binary's path** —
`stat` on that path returns ENOENT while the fd works, because it is a magic
link to the inode rather than a path resolution. Use the fd; `readlink` returns
a stale path string.

That is how snug's own code gets into a sandbox: through snug's own inherited
descriptor, never through a `/proc/<pid>/` path handed to a process that has
already changed identity.

## 5. A defect in shipped snug, found on the way

Recorded here because this is where it was measured; it is tracked as
https://github.com/gomoni/snug/issues/23, and it is independent of the
supervisor work.

**`pidfd_getfd(2)` is an fd-theft primitive and `deniedSyscalls` in
`internal/sandbox/seccomp.go` does not list it.** MEASURED succeeding inside a
real snug sandbox, with a positive control.

The sharp part is what currently prevents it. Two *sibling* processes inside one
sandbox — same uid, **same user namespace**, neither a descendant of the other —
are refused, and the refusal is **Yama's descendant rule**, not snug's filter and
not `dumpable`. The user-namespace explanation is excluded because both siblings
are in the same one. Note also that `/proc/<pid>/fd` still *lists*: the
ptrace-mode check gates the theft, not the enumeration.

So co-resident payloads are protected from each other's descriptors **by a host
sysctl snug neither sets nor checks**. `kernel.yama.ptrace_scope = 1` is the
default on Debian, Fedora, Ubuntu and this host, and it is not namespaced, so a
sandbox inherits whatever the host has — and `ptrace_scope = 0` is common inside
containers, which is exactly where key feature 3 says snug must work. On such a
host one payload reads another's descriptors with no error, no warning and no
line in `--dry-run`. That is the invariant-5 shape.

Two things are true at once and both matter: snug's own machinery never needs
ptrace — it uses `setns`, `exec` and descriptor passing — so a strict Yama
setting costs snug nothing operationally; and *depending* on it silently is
still wrong.

**The fix is narrower than it first looks: deny `pidfd_getfd` only.** It is the
theft primitive, and nothing a build, a test or an agent legitimately does calls
it. Leave `pidfd_open` allowed — it hands out a handle but no descriptors, and it
is on the ordinary path for well-behaved programs. Verified this is not a repeat
of the `clone3`/ENOSYS trap: Go's `os.checkPidfd` probes `pidfd_open`,
`waitid(P_PIDFD)`, `pidfd_send_signal` and `CLONE_PIDFD` and returns an error on
*any* failure, so the runtime falls back to pid-based handling rather than
breaking — but the narrow denial perturbs nothing at all.

`snug doctor` should then report `/proc/sys/kernel/yama/ptrace_scope`, because it
is genuine defence in depth worth knowing about — but after the filter change no
guarantee rests on it.

**Status: fixed.** `pidfd_getfd` is denied (EPERM) in `deniedSyscalls`
(`internal/sandbox/seccomp.go`) as of the commit closing issue #23, alongside
`process_vm_readv`/`process_vm_writev` — a follow-up audit measured the same
sibling-vs-sibling theft through that pair with Yama waived, `process_vm_writev`
being the worse half: a sibling did not just read another payload's memory, it
rewrote it. The same audit also found `/proc/<pid>/mem` delivers the identical
read+write effect with none of the three denied syscalls (open procfs, not
seccomp's to reach) — see issue #47.
`pidfd_open` stays allowed. The paragraphs above are left as measured — they are
the record of what was true before the fix and why EPERM was the right errno —
but **do not read "the fix is in" as "co-resident payloads are isolated from
each other."** They are not: the same audit measured that `/proc/<pid>/fd/N`
reopen (a `PTRACE_MODE_READ` operation, which Yama does not gate) still lets a
sibling read another payload's *regular files* today, with this filter active.
Seccomp cannot reach that path — it is not a syscall snug can name — so that
finding is tracked as https://github.com/gomoni/snug/issues/47.

**That residual is also why a session is a sandbox.** Everything above is one
sandbox's payloads reading each other, and no filter closes it. Two pieces of
work that are mutually distrusting therefore get two sandboxes, which is the
only boundary that holds: separate pid namespaces, separate `/proc`, separate
`$HOME`. `SECRETS.md` §8 costs what two sandboxes on one target still share.
