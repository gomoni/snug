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

## 2. The case that tested the rule

`snug attach` — injecting a second payload into a running sandbox — is
`setns(2)` into that sandbox's namespaces. Two kernel requirements make that
hostile to Go, and one design concluded a cgo constructor was the only way out.

The constructor argument is sound as far as it goes: a
`__attribute__((constructor))` runs **before the Go runtime starts its threads**,
which is precisely the state `setns` demands, and there is no pure-Go equivalent
hook. That is the one thing cgo genuinely buys here.

### What the kernel actually checks — MEASURED, both errnos

| namespace | pure Go, multithreaded |
|---|---|
| mnt | **EINVAL (22)** |
| user | **EINVAL (22)** |
| pid, ipc, uts, net, cgroup | OK |

Two independent checks with one root cause. `userns_install()` returns `-EINVAL`
when `!thread_group_empty(current)`. `mntns_install()` returns `-EINVAL` when
`fs->users != 1` — and Go creates every thread with `CLONE_FS`, so `fs->users`
**is** the thread count.

So it is not one syscall in one place: pure Go cannot join either of the two
namespaces that matter.

**`runtime.LockOSThread` changes no row, and neither does `GOMAXPROCS=1`.**
MEASURED. LockOSThread pins a goroutine to a thread; it does not remove the other
threads, and it does not unshare `fs_struct`. It is the first thing anyone tries
and it is a red herring. A Go process has **5 threads** at the first statement of
`main`, and **3** under `GOMAXPROCS=1`. Never 1.

**Keep the two errnos apart — they are a diagnostic.** EPERM means the joiner
lacks `CAP_SYS_ADMIN` in its *own* user namespace. EINVAL means the wrong thread
or fs state. Confusing them costs an hour.

## 3. The answer: the process calling `setns` does not have to be the Go process

The blocking claim was true and answered the wrong question. A raw `fork` from a
multithreaded Go program produces a child that is **single-threaded** *and* owns
its **own `fs_struct`** — which are exactly the two states the kernel checks.
MEASURED, including against a real `bwrap --unshare-all` sandbox rather than only
against `unshare(1)`.

What that killed:

- **cgo.** Not needed.
- **A second binary.** The C helper the proof of concept carried is gone, and
  with it a review finding about locating that helper by a path derived from an
  environment variable — there is no helper to locate.
- **`/proc/self/exe` re-exec as a route to single-threadedness.** It does not
  work: a Go binary is never single-threaded at its own first statement, so
  re-execing one changes nothing. (The idea survives for a different job — see §5.)
- **A sealed memfd carrying a helper.** It works — `memfd_create` plus full
  seals, verified to refuse a later write with EPERM, plus
  `execveat(fd, "", AT_EMPTY_PATH)` — but since a *Go* binary is never
  single-threaded at start, the blob would have to be a **C** helper, making it
  a C-helper design in disguise. It also inherits a build dependency: there is no
  static glibc on this box, so the blob would need the loader at exec time, or
  musl/`-nostdlib` becomes a prerequisite. Strictly worse.
- **`nsenter(1)` as a drop-in.** MEASURED **FAILED** in this topology:
  `nsenter: setgroups failed: Operation not permitted`.

## 4. The decision it changed, and the one it did not

Attach is **fork-from-init**: the new payload is forked by the sandbox's own
init rather than injected from outside by a joiner.

Note carefully what the measurement above did to the *argument* for that choice.
Fork-from-init was originally preferred because it avoided cgo. The pure-Go
joiner result removes that reason — a joiner is now buildable without cgo — so
the decision has to stand on its security merits alone. **It does**, on three
counts, all measured:

- one code path instead of two;
- no window in which a process holds a full capability set in the sandbox's user
  namespace (a joiner necessarily acquires one on entry and must remember to drop
  it — the undropped case was measured, and it is a full set);
- confinement is **inherited** rather than reproduced. A joiner has to re-apply
  every restriction the sandbox has, and every one it forgets is a hole. A child
  of init has them by descent.

Keep the measured joiner as a fallback for the case where something must be
injected into a sandbox that has no snug init. Do not build the attach path on it.

**Superseded, 2026-08-18: attach IS the joiner, and it shipped.** A later
settlement (issue #61 part (e)) measured that fork-off-the-stage produces a
*second* sandbox rather than entry into the first — the stage holds the
capability-carrying user and network namespaces, bwrap holds the mount and pid
namespaces the payload actually runs in, and there is no single process a
fork-from-init design could inject into that owns all seven. That also removed
the control listener this section's "fallback" reading assumed: attach joins
by descriptor, from the host, as a client, with no accept loop and no
`start`-request authentication to attach a listener onto in the first place.

`internal/attach` is the measured joiner from §3 above, unchanged in its
kernel-level shape (raw `clone(SIGCHLD)`, raw syscalls only, one combined
`setns` over all seven namespaces by pidfd, then a second raw fork before the
final `execve`) and carrying the cost this section named as the reason to
prefer fork-from-init: the interval between the `setns` and the capability
bounding-set drop is a real window in which the raw-fork child (B) holds a
full capability set in the *sandboxed* user namespace (never the mount-owning
one — see the attach design's own §3.1 for why that distinction is the whole
point). It is a handful of raw syscalls long, contains no exec and no
further fork, and reproduces (rather than inherits) the payload's seccomp
filter, capability bounding set, `NO_NEW_PRIVS` and environment — verified,
not merely asserted, by a release gate that reads the raw-fork child's own
`/proc/<pid>/status` before letting it proceed. Read together with §2's
review of the pure-Go joiner: cgo bought nothing here either way, and the
question this document settles is a threading one, not a capability-safety
one — that trade is the attach design's to make, and it did.

## 5. What survived from the `/proc/self/exe` idea

The intuition was aimed at locating a helper. There is no helper now, but the
property underneath it is still needed and is MEASURED twice:

**An fd is a TOCTOU-free reference to an inode; a path is a lookup that can be
re-pointed between the check and the exec.** Replacing a binary on disk while
holding an fd, then `execveat`ing the fd, ran the **old** inode (`(deleted)` in
`/proc`), while exec by path ran the new one. And `open("/proc/self/exe")`
succeeds **inside a mount namespace that does not contain the binary's path** —
`stat` on that path returns ENOENT while the fd works, because it is a magic link
to the inode rather than a path resolution. Use the fd; `readlink` returns a
stale path string.

That is how snug's own code gets into a sandbox: through snug's own inherited
descriptor, never through a `/proc/<pid>/` path handed to a process that has
already changed identity.

## 6. A defect in shipped snug, found on the way

Recorded here because this is where it was measured; it is tracked as
https://github.com/gomoni/snug/issues/23, and it is independent of the
supervisor work.

**`pidfd_getfd(2)` is an fd-theft primitive and `deniedSyscalls` in
`internal/sandbox/seccomp.go` does not list it.** MEASURED succeeding inside a
real snug sandbox, with a positive control.

The sharp part is what currently prevents it. Two *sibling* processes inside one
sandbox — same uid, **same user namespace**, neither a descendant of the other,
which is exactly the shape the multi-payload attach feature produces — are
refused, and the refusal is **Yama's descendant rule**, not snug's filter and not
`dumpable`. The user-namespace explanation is excluded because both siblings are
in the same one. Note also that `/proc/<pid>/fd` still *lists*: the ptrace-mode
check gates the theft, not the enumeration.

So co-resident payloads are protected from each other's descriptors **by a host
sysctl snug neither sets nor checks**. `kernel.yama.ptrace_scope = 1` is the
default on Debian, Fedora, Ubuntu and this host, and it is not namespaced, so a
sandbox inherits whatever the host has — and `ptrace_scope = 0` is common inside
containers, which is exactly where key feature 3 says snug must work. On such a
host one payload reads another's descriptors with no error, no warning and no
line in `--dry-run`. That is the invariant-5 shape.

Two things are true at once and both matter: snug's own machinery never needs
ptrace — it uses `setns`, `fork` and descriptor passing — so a strict Yama
setting costs snug nothing operationally; and *depending* on it silently is still
wrong.

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
finding is tracked as https://github.com/gomoni/snug/issues/47, and real
payload-vs-payload isolation remains a
pid-namespace/uid question for the supervisor work, not something this filter
closes. `snug doctor` reporting `ptrace_scope` is still open (not implemented by
the issue #23 fix); it would report information, not a warning — a `0` inside a
container is common and not itself a defect.
