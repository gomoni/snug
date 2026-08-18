# One sandbox per target directory

> Draft in scratchpad. Promote into `.claude/design/` with a deliberate
> `git mv` once it is the design for this subject (repo rule: new docs start in
> `.claude/scratchpad/`, are promoted only by `git mv`).

Issue #119. A `snug` run is tied to its target directory: `snug <dir>` refuses to
start a second sandbox while one is already live for that directory, and the
refusal names the fix, `snug attach <dir>`.

## 1. Why

- `snug attach` is the mechanism for a second shell in the same sandbox. Once it
  exists, a second `snug <dir>` buys only a *second, independent* sandbox writing
  the same target — and the target bind is the one writable thing that persists,
  so two sandboxes racing writes to the same files is a footgun, not a feature.
- It makes attach-by-directory total. attach addresses a run by its target; with
  at most one live run per directory, that address is unambiguous **by
  construction**. No run selector, no `--list`, no run-naming scheme — surface
  this decision removes before it is built. Less surface is less to get wrong,
  which is a security goal here, not only an ergonomic one.

## 2. Mechanism

A per-target advisory `flock`, in snug's per-uid runtime directory:

```
<per-uid runtime dir>/target-<sha256hex(realpath(target))>.lock
```

The directory is resolved from the **uid alone** — canonical `/run/user/<uid>`
when it exists (what `$XDG_RUNTIME_DIR` normally *is*), else the deterministic
`/tmp/snug-<uid>` — and **never** from `$XDG_RUNTIME_DIR`/`$TMPDIR`. That is the
whole point of `targetLockBase()` and the reason it does not reuse `runtimeBase()`
(which does read those env vars): a lock whose entire purpose is cross-run
agreement cannot let a mutable env var move it. Two runs on one target that
disagreed on `$XDG_RUNTIME_DIR` once flock'd two different inodes and both
acquired — a second sandbox onto the target the lock exists to forbid (issue
#122, found by red-team, fixed here). The per-run `run-<pid>/lock` stays
env-derived: it never needs cross-run agreement, so it does not share this
hazard. If the per-uid directory cannot be established the run **refuses** rather
than falling back to a per-env path (invariant 5, fail closed).

- **Key = realpath, hashed.** `sha256hex` is a fixed-length, separator-free path
  component: it cannot escape the directory and cannot collide with an unrelated
  target. The realpath — not the raw argument — is the key, so a symlink to the
  target, or any two paths resolving to the same inode, map to the same lock and
  the second run is refused. This is the same canonicalisation
  `internal/policy/resolve.go` applies to the target, so lock and policy agree.
- **Taken with `runtimeDir`'s machinery.** `secureSubroot` opens (and, first
  time, creates) the shared snug root, verifying owner, mode 0700, and
  not-a-symlink; then `Root.OpenFile(name, O_CREATE|O_RDWR, 0600)` +
  `Flock(LOCK_EX|LOCK_NB)`. A second lock file on the same primitives, not a
  second scheme.
- **Reclaim is free and race-free.** The kernel grants the exclusive lock to
  exactly one open file description, so two live runs can never both win; the
  loser gets `EWOULDBLOCK`. A SIGKILLed holder's flock is released by the kernel,
  so the next run's `LOCK_EX` reclaims it with no `/proc` parsing and no janitor.
- **Never unlinked, on purpose.** Because nothing unlinks the file, the inode the
  flock refers to is stable and there is no sweep-vs-acquire race — the
  `errLockFileSwept`/`stillLinked` dance `lockRunDir` needs does not apply here.
  A leftover file is a harmless small file reclaimed by the next flock. It is
  invisible to `sweepStaleRunDirs` (a flat file, not a `run-` dir) and to attach's
  `discoverLiveRuns` (not `run-` prefixed). *If anyone ever sweeps these files,
  they must add back the `stillLinked` acquire-side guard.*
- **Holder pid** is written into the file on acquire, read back by the loser to
  name the live run in the refusal. The flock is authoritative; the pid is a
  courtesy that degrades to "unknown" on a torn read.

## 3. The refusal

Invariant-5 shaped: fatal, non-zero (`exitUnavail`, 69), starts nothing. It fires
in `run()` right after the target's absolute path is known and **before**
anything is created — no host tmp dir, no staged Claude files, no ssh-agent or
container proxy, no stage, no netns, no bwrap. `--dry-run` takes no lock and is
never refused. The message names `snug attach <dir>` and identifies the live run
by target and pid. snug never falls back to a second run.

## 4. attach

attach keeps its multi-match branch as a defensive invariant guard: with one
live run per target it is unreachable in normal operation, but a lock bug or a
hand-edited `state.json` could still produce two matches, and refusing loudly
beats attaching to an arbitrary run. attach must canonicalise its target by
realpath the same way this guard does, so `snug attach <symlink>` resolves to the
run that `snug <symlink>` was refused for.

## 5. Threat model

The lock file lives on a host path never bound into the sandbox, and its name is
the SHA-256 of the realpath the host user named, computed on the host before the
sandbox exists. A hostile payload can neither reach the file (not in its mount
namespace) nor influence its name (no input to snug's argv or to the host
realpath), so it can neither release the lock to race a second sandbox onto the
target nor steer snug to lock an unrelated path. Same-uid host tampering with the
runtime directory is outside the threat model, exactly as for `runtimeDir` (#61).

## 6. What this is not

Not a policy grant and not a deny rule — there is nothing to deny; it is a
run-path guard, and it lives in `internal/cli`, never in the pure
`internal/policy`. A legitimately-wanted second sandbox on one directory (one
`@claude`, one plain shell) would be a different feature with a different name,
not a relaxation of this refusal.
