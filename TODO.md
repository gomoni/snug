# TODO

Only things that are genuinely outstanding. Anything already true of the code
belongs in CLAUDE.md or the code itself, not here.

## Postponed by decision

### Parameterised profiles

Deliberately deferred to a later stage — not rejected. It touches the identity
rule, which is where commutativity and idempotence live, so it is not something
to attach to the side of a milestone.

The shape, from the owner:

```
[[profile.-srv-rw]]
rw_dirs = /srv, /foo, /bar
```

Two things worth keeping from the discussion:

- **Why profiles and not CLI flags.** The obvious cheap alternative is
  `snug --ro /data --rw /build`, which needs no change to the model at all. It
  was rejected, correctly: *"bwrap itself is a powerful tool, yet humans can't be
  expected to write all the parameters by hand. The point of this tool is to
  enable a policy which can be specified by a mere human."* A flag you retype
  every invocation is bwrap with better spelling — ad-hoc, unreviewable,
  uncomposable, and gone when the shell history scrolls. The product is a named,
  reusable, reviewable policy. Do not solve this with flags.
- **The identity insight.** If a profile instance's canonical name ENCODES its
  arguments (`rw:/srv`, or `-srv-rw` in the sketch above), identity stays a
  single string. `expand`'s set-based dedup keeps working, so `rw:/srv` twice is
  one member and `rw:/srv` vs `rw:/data` are two — commutativity and idempotence
  survive untouched. That is far cheaper than making identity `(name, args)`,
  which would put a fingerprint on the core property tests.

**The design note is `docs/PARAMETERISED-PROFILES.md`. Read it before starting.**
Headline: the sketched example is not actually parameterisation — a profile
granting /srv, /foo and /bar is an ad-hoc list of grants wanting a name, and
that already works today by writing `~/.config/snug/profiles.d/mine.toml`. The
identity insight holds, with three provisos. Arguments must never come from
environment variables (direnv would let a repo author its own boundary).

## Pending

### Prompt could show an unusually wide profile set

`PS1` is `🔒 snug:\w\$ `. A marker when something wide is active — `net-host`,
or a user-written profile granting a large tree — would make a permissive
sandbox visible at a glance rather than only in `--dry-run`.

### `test/integration/sandbox_test.go` still uses the old vocabulary

Not done here because another agent owned the file. It references `dotdot`, the
`default` profile, `--no-default` and `--read-only`, all of which are gone. The
exact edits are listed in the report accompanying that change; until they land,
`make integration` fails while `make gate` stays green.

## Container proxy — found by mutation-testing (M4 review round)

The sandbox-tester ran 73 mutations against the committed suite; nine tests were
decorative or dead and are fixed. Two surviving mutations are **product bugs, not
test bugs** — both are full escapes through the docker/podman proxy, both verified
by forwarding real bytes to the engine. Regression tests are written and withheld
so `make gate` stays green until the fix lands; they arrive with it.

- **[🔴 escape] Any create request with an `Upgrade:` header bypasses the whole
  proxy.** `isHijack` (`internal/dockerproxy/proxy.go:354`) returns true on
  `Upgrade`/`Connection: upgrade` for **any path**, before `handleCreate` runs, and
  `hijack` does `r.Write(up)` — the raw request goes to podman. Verified:
  `POST /v1.41/containers/create` + `Upgrade: tcp` with
  `{"Privileged":true,"Binds":["/:/host"]}` reached the engine byte-for-byte,
  200 OK. Fix: gate hijack on a known streaming PATH (containers attach; containers
  start *with* upgrade; exec start), never on the header alone.
- **[🔴 escape] Case-variant JSON keys bypass every denylist.** Lookups are
  exact-key on a `map[string]json.RawMessage` (`create.go:39,52`); podman decodes
  with `encoding/json`, which is **case-insensitive**, and `json.Marshal` sorts map
  keys so the attacker's lowercase variant always sorts last and wins.
  `{"hostconfig":{"privileged":true,"binds":["/:/host"]}}` reached the engine with
  snug's `"Privileged":false` sitting harmlessly beside it. Fix: reject any object
  with two keys equal under case-fold, fold `req`/`hc` keys to canonical case before
  filtering, and delete any case-variant of an injected key (`Privileged`,
  `SecurityOpt`) before re-inserting snug's own.

Both are `host-bridge`'s surface (the podman socket proxy). To fix in the same pass,
because they share the handler:

- **[🟠 capability not delivered] `net-publish` auto does not work.** `-t 127.0.0.1/auto`
  only scans at pasta startup; a port bound afterwards is never published (measured
  to 10 s). `--dry-run` prints "host -> sandbox EVERY port the sandbox binds" — a
  claim not delivered, which is invariant 5's territory. Fails safe (nothing extra
  is exposed), but the `-t auto` mutation cannot be caught until this is fixed. A
  *named* port does work (`TestPublishedPortsAreReachable`).
- **[🟡 correctness] `docker run`/`create` is refused today.** The docker CLI always
  sends `HostConfig.LogConfig: {"Type":"","Config":{}}`; `isEmptyJSON` does not treat
  that as empty (`create.go:308`), so the `LogConfig` denylist entry refuses every
  create. The hazard is only a non-empty `Type` or a `Config` option (the `path`);
  refuse `LogConfig` only when one of those is set, so the empty default passes.
- **[🟡 silent drop] `HostConfig.Tmpfs` is silently deleted** (`create.go:100`),
  contradicting the "nothing is silently dropped" rule two comments above it. Either
  forward it (container-internal, harmless) or refuse it by name.

## Engine — found by host-bridge (teardown work)

- **[🟡 correctness] `stop --all` at teardown is store-wide.** A sandbox's teardown
  stops a *concurrent* sibling's containers when both resolve to the same store
  (warm-start sharing). The engine-level collateral is fixed (socket carries the
  run's pid; the store never does), but closing this needs a per-run label applied
  at container create, which lives in `internal/dockerproxy`.
- **[🟡 papercut] Warm stores are silently orphaned by profile renames.** The store
  key includes the resolved profile list, so a rename like `dotdot`->`parent-ro`
  changes it mid-session and a warm store with a pulled image becomes unreachable.
  Harmless (a re-pull), but worth a note.

## Independent bugs found while reviewing that idea

Neither is about parameterisation; both stand on their own.

### **[latent security]** A symlink in the target can divert a grant

`Resolve` canonicalises the host side of every bind, so a grant of
`{target}/build` — where a previous sandbox run left `build -> ~/.ssh` — would
bind `~/.ssh` into the sandbox. Not reachable today (no builtin uses a
`{target}`-relative subpath grant) but live the moment anyone writes one.

Fix sketched in `docs/PARAMETERISED-PROFILES.md`: refuse a grant at or below the
target whose `EvalSymlinks` result differs from the lexical join under the
canonical target. Comparing against the lexical join rather than against the
path itself is what avoids false positives from `/home -> /var/home`. Apply the
same rule to `{host_tmpdir}`.

### `ctx.Home` is never canonicalised

The target is `EvalSymlinks`'d and fail-closed; `$HOME` is used verbatim. Host
sides of `{home}/...` grants get canonicalised by `add()`, the guest side does
not. Fix is one call in `Resolve`. Expect a golden argv diff on any host where
`$HOME` traverses a symlink — correct, and to be reviewed as a security change.

## Pseudo-filesystem exposure (`/proc`, `/sys`, `/dev`)

Full report: [`docs/PSEUDOFS-AUDIT.md`](docs/PSEUDOFS-AUDIT.md) — deep research +
live verification against HEAD. Headline: **no escape** (every `/proc` write
primitive is refused by kernel DAC + zero capabilities), but the **read side of
`/proc` leaks more than crun's default** and it is snug's to fix. `/sys` is absent
by construction and `/dev` is a 14-entry synthetic tree with the classic
device-escape surface missing — both verified, both stronger than the docs say.

Two of the findings are **structural defects that contradict invariant 1 as
written** and are the highest-value fixes (both are refusals-to-add, not
restrictions, so both are cheap and invariant-safe):

- **[🔴 structural] A profile can displace the `/proc` and `/dev` builtins.**
  `mustJoin` (`resolve.go:426`) installs a builtin only if the guest path is
  unclaimed, so `ro = ["/dev"]` yields `--ro-bind /dev /dev` (250+ host nodes, the
  host `/dev/shm` with readable contents) and `ro = ["/proc"]` yields the full
  outer process table. Gated today on the recorded invariant-3 XDG gap, but the
  payoff of that gap is far larger than its "low severity" note implies. **Fix R1:**
  a hard `Validate` error on a grant at exactly `/proc` or `/dev`.
- **[🔴 structural] `rejectMasking` skips non-`KindBind` ancestors**
  (`validate.go:143`), so a profile *can* mount host content on top of any path
  inside `/proc`, `/dev` or `/tmp` — `ro = ["/proc/config.gz"]` and
  `ro = ["/proc/sys"]` both accepted and live. This is the subtraction verb
  invariant 1 says the grant language cannot express. **Fix R2:** treat mounts
  strictly beneath a `KindProc`/`KindDev`/`KindTmpfs` mount as masks, and re-key
  the `KindData` exemption from kind to `provenance == "(builtin)"` (must land with
  R2, or R3 below hands profiles the verb).

Leak closures snug *could* make (bwrap has no procfs masking options, so each is a
snug-authored **replacement**, which the author distinction licenses — verified
feasible with an empty regular file, NOT `/dev/null`, which yields EACCES not
empty content):

- **[🟠 leak] R3** — empty-file replacements at `/proc/config.gz`, `/proc/keys`,
  `/proc/key-users` (tier 1, no compat cost; `keys` is what crun/runc mask and snug
  already seccomp-denies the keyring syscalls); tier 2 is `kallsyms`, `modules`,
  `interrupts`, `sysrq-trigger`. Print every replacement in `--dry-run`.
- **[🟠 leak] R4** — `--ro-bind /proc/sys /proc/sys` makes the write side snug's
  (EROFS) instead of the kernel's; costs nothing, matches crun.
- **[🟡] R5** — `snug doctor` should read and report the host hardening it silently
  depends on (`kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid`,
  `ptrace_scope`, `unprivileged_bpf_disabled`). It checks none today.
- **[🟡] R6** — refuse a **rw** grant at/under `/sys` (cgroup delegation gives
  kill/freeze over out-of-sandbox processes); keep **ro** `/sys` expressible.
- **[🟡] R7** — route `dryrun.go:162`'s hard-coded NOT-GRANTED literal through
  `covered()`; today it can print `ro /sys` and "never mounted" on one screen, in
  the one artifact a human trusts. One line.
- **[🟢] R8** — bound the `/dev`, `/dev/shm`, `/tmp`, `$HOME` tmpfs with `size=`
  (host-RAM-exhaustion DoS; the engine's own containers already do this).
- **R9** — batched doc corrections (DESIGN §5.2 `/dev` enumeration and §5.3
  fingerprint claim, the phantom `[profile.sysfs]`, N5's side-channel list,
  `podman-socket`'s host-resource claim, the time-namespace fact for CLAUDE.md).
- **R10** — opt-in `--new-session` for non-interactive payloads (closes the
  `/dev/tty` OSC-52 channel to the operator's terminal); do **not** filter escape
  sequences.
- **R11** — `SECCOMP_RET_ERRNO` on non-native arches instead of ALLOW (the i386
  path is the only remaining native route toward a writable remount).

Accepted gaps and the full test list (§Disposition) are in the report. **Every
confirmed finding becomes a named regression test with a positive control before
its fix lands** — several existing pseudo-fs tests fail the `pasta.avx2` "can this
test ever fail?" check and are named in the report.

Note: the workflow's `redteam`-typed phase did not spawn (that agent type is not
in the workflow runner's registry), so this rests on the research agents' own live
probing plus lead re-verification. A dedicated `redteam` pass over this surface is
still worth running before a fix lands.

## Known gaps in what the docs claim

Both are documented where they bite; listed here so they are not forgotten.

- **`--config` and privileged-grant gating do not exist.** DESIGN §2.7 describes
  them; `profile.Profile.Trusted` is set and never read. Consequence found by
  the redteam agent: `$XDG_CONFIG_HOME` is trusted unconditionally, so pointing
  it at a checked-out repository loads that repository's profiles. Low severity
  — it is the host user's own env var, not something the sandboxed agent
  controls. CLAUDE.md invariant 3 states the real behaviour.
- **Seccomp does not cover non-native architectures.** The x86_64 i386-compat
  path falls through to ALLOW, so a 32-bit binary bypasses the filter. Closing
  it means denying the compat arch outright, which breaks 32-bit binaries;
  the trade was taken deliberately and is documented in
  `internal/sandbox/seccomp.go`. (`clone3` and the x32 ABI WERE gaps and are now
  closed — clone3 is denied outright since classic BPF cannot read its flags,
  and x32 syscall numbers are rejected by their high bit.)
