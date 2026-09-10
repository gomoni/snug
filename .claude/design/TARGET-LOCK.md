# The per-target lock

A run takes a shared advisory `flock` naming its target directory. The lock
records that **a** sandbox is live on that target. It is bookkeeping for two
consumers — `snug proxy` and `snug engine gc` — and it is not an exclusion
rule: several sandboxes may be live on one target at once, and that is the
supported shape.

## 1. What it is for

Two things need to ask "is any run live on this target", and neither can ask by
walking `/proc`:

- **`snug proxy <dir>`.** A human names a directory and expects a door into a
  sandbox on it. With no live run there is nothing to open, and `liveRunsFor`
  reads no record at all beside an unheld lock: every one of them describes a
  corpse.
- **`snug engine gc`.** The engine store is keyed by the target hash alone
  (issue #276), so collecting it is safe only while no sandbox on that target
  can be writing it.

The orphan sweep is deliberately not one of them — §3.

Both take `LOCK_EX`. A run takes `LOCK_SH`. `LOCK_EX` fails while any shared
lock is held, so "no run is live here" is exactly "`LOCK_EX` succeeded", with
several concurrent runs and with none.

## 2. Mechanism

```
<per-uid runtime dir>/target-<sha256hex(realpath(target))>.lock
```

The directory is resolved from the **uid alone** — canonical `/run/user/<uid>`
when it exists (what `$XDG_RUNTIME_DIR` normally *is*), else the deterministic
`/tmp/snug-<uid>` — and **never** from `$XDG_RUNTIME_DIR`/`$TMPDIR`. That is the
whole point of `targetLockBase()` and the reason it does not reuse
`runtimeBase()` (which does read those env vars): a lock whose entire purpose is
cross-run agreement cannot let a mutable env var move it. Two runs on one target
that disagreed on `$XDG_RUNTIME_DIR` once flock'd two different inodes and both
believed they had answered the question (issue #122, found by red-team). The
per-run `run-<pid>/lock` stays env-derived: it never needs cross-run agreement,
so it does not share this hazard. If the per-uid directory cannot be established
the run **refuses** rather than falling back to a per-env path (invariant 5, fail
closed).

- **Key = realpath, hashed.** `sha256hex` is a fixed-length, separator-free path
  component: it cannot escape the directory and cannot collide with an unrelated
  target. The realpath — not the raw argument — is the key, so a symlink to the
  target, or any two paths resolving to the same inode, map to the same lock.
  This is the same canonicalisation `internal/policy/resolve.go` applies to the
  target, so lock and policy agree, and it is the same digest the engine store
  and the shared-tmp directory are keyed by, so all four agree on what "the same
  target" means.
- **Taken with `runtimeDir`'s machinery.** `vdir.SecureSubdir` opens (and, first
  time, creates) the shared snug root, verifying owner, mode 0700, and
  not-a-symlink; then `Root.OpenFile(name, O_CREATE|O_RDWR, 0600)` + `Flock`. A
  second lock file on the same primitives, not a second scheme.
- **Release is free.** A SIGKILLed holder's flock is released by the kernel, so
  neither consumer needs `/proc` parsing and there is no janitor.
- **It is swept, and that is why the acquire side checks `Nlink`.**
  `sweepOneStaleLock` takes `LOCK_EX` on unheld lock files and unlinks them.
  `flock` on an unlinked descriptor succeeds exactly as it does on a live one,
  so between the open and the flock a concurrent sweep can remove the inode this
  run is about to serialise on. `stillLinked` is what separates the two cases,
  and the retry loop above it is what stops a sweep in flight reading as a live
  run: a red-team round measured the false report at 401 lock files and 3413
  acquisitions producing one spurious "busy" in 20 ms.

## 3. What it deliberately does not do

**It does not refuse a second sandbox on one target.** A second session on a
directory *is* a second sandbox — snug has no other kind — and the surface the
two share is enumerated on `--dry-run` rather than forbidden here. The shared
surface is the host-backed writable one: the target directory itself, the engine
store and runroot when a `@podman*` profile is selected, and any host directory
a profile binds. `SECRETS.md` §8 carries what that costs, with
the measurement: a git hook one sandbox writes is a git hook the other's `git
commit` executes.

**It does not name a holder.** With several live runs there is no such thing as
the holder. Where a consumer needs to name one it names *a* live run.

**It does not gate the orphan sweep, and a shared lock could not.** The sweep
judges one record at a time, and this lock stays held until the LAST run on the
target exits, so consulting it would leave a run SIGKILLed beside a live peer
unswept — record and orphaned init both — for the whole of that peer's life,
which is invariant 4 failing on an ordinary sequence with no attacker. Per-run
liveness is the record's own owner (`stateowner.go`): the snug process that
took this lock, checked by pid plus `/proc/<pid>/stat` field 22, and the one
signal a `rm` or `mv` of the lock file cannot detach from the run it describes.
`orphansweep.go` carries the three conditions the sweep does apply.

## 4. Threat model

The lock file lives on a host path never bound into any sandbox, and its name is
the SHA-256 of the realpath the host user named, computed on the host before the
sandbox exists. A hostile payload can neither reach the file (not in its mount
namespace) nor influence its name (no input to snug's argv or to the host
realpath), so it can neither release the lock nor steer snug to lock an
unrelated path. Same-uid host tampering with the runtime directory is outside
the threat model, exactly as for `runtimeDir` (#61).

## 5. What this is not

Not a policy grant and not a deny rule — there is nothing to deny; it is a
run-path record, and it lives in `internal/cli`, never in the pure
`internal/policy`.
