# snug pseudo-filesystem exposure — audit report

Deep research + live verification of `/proc`, `/sys` and `/dev` exposure, run as a
multi-agent workflow against HEAD `a082604`. The map and research phases verified
every load-bearing claim by execution on a real host (kernel 7.1.4-1-default,
`kptr_restrict=1`, `ptrace_scope=1`, cgroup v2, inside a rootless-podman
distrobox); the lead re-verified the claims the recommendations depend on. Where a
claim is marked **[lead-verified]** it was re-run during synthesis.

> Provenance note: the workflow's `redteam`-typed adversarial phase failed to
> spawn (that agent type is not in the workflow runner's registry), so the report
> below rests on the RESEARCH agents' own live probing plus the lead's
> re-verification, not on a separate red-team pass. A dedicated `redteam` run over
> this surface is still worth doing before any fix lands.

## The answer to the framing

> *"These are normally kernel-permission-protected and only exploitable via kernel
> bugs — but do they leak too much?"*

**Escape: no. Leak: yes — too much, and measurably more than any OCI runtime's
default.**

- **The write side is genuinely closed, and none of it is snug's doing.** Every
  classic escape primitive is present in snug's `/proc` and every one is refused:
  `core_pattern`, `modprobe`, `poweroff_cmd`, `usermodehelper/{bset,inheritable}`,
  `sysrq-trigger`, `vm/drop_caches`, `kcore`, `kmsg`, `binfmt_misc` registration,
  procfs re-mount. The refusals come from real-root inode ownership (rendered
  `nobody` in the sandbox's userns) plus `CapEff = CapBnd = 0`. `--remount-ro /` is
  non-recursive and does **not** cover procfs — the mount is `rw`. The only
  writable sysctls are IPC-ns/PID-ns scoped (`shm*`, `msg*`, `sem`, `mqueue/*`,
  `pid_max`) and die with the sandbox.
- **The read side is wide open and it is snug's to close.** bwrap's `--proc`
  mounts a plain, fully unmasked procfs with no `hidepid=` and no `subset=pid`.
  crun and runc mask `/proc/kcore`, `/proc/keys`, `/proc/timer_list`,
  `/proc/interrupts`, `/proc/acpi`, `/proc/asound`, `/proc/scsi` and mount
  `/proc/sys` read-only. snug masks nothing. Consequence, confirmed live: **a
  container the agent starts through `@podman-socket` has a better-masked `/proc`
  than the sandbox that spawned it.**

What a default `snug <dir>` leaks to a hostile payload, all [lead-verified] in one
run:

| leaked | measured |
|---|---|
| complete host kernel config | `/proc/config.gz`, 70 870 bytes / 12 450 lines |
| host boot cmdline | root device UUID, `rootflags=subvol=@/.snapshots/285/snapshot`, initrd hash, `security=selinux` |
| exact kernel + toolchain | `/proc/version` → `7.1.4-1-default … gcc (SUSE Linux) 16.1.1 …` |
| host user's kernel keyring | `/proc/keys`, 8 entries incl. `krb_ccache:primary`, `_krb`, `_persistent.1000` — the keyring is **not** userns-namespaced |
| kernel/module symbol names | `/proc/kallsyms` (addresses zeroed by the *host's* `kptr_restrict=1`, not by snug), `/proc/modules` 229 modules |
| host-operator input timing | `/proc/interrupts` i8042 IRQ1/IRQ12 counters, observed incrementing; `/proc/bus/input/devices` names the keyboard |
| stable host identity | `boot_id` (identical across runs), `btime`, `/proc/asound` → `LENOVO-…-ThinkPadT14Gen2a`, `/proc/bus/pci`, `/proc/partitions`, `/proc/cpuinfo` |
| real host paths | `/proc/self/mountinfo`, 18 lines containing the launcher's home, the podman overlay `lowerdir`/`upperdir`, the btrfs subvol |
| host audit + LSM identity | `/proc/self/loginuid` → 1000, `sessionid`, `attr/current` → `unconfined_u:unconfined_r:spc_t:s0` |
| hardening posture | `kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid`, `ptrace_scope`, `unprivileged_bpf_disabled`, `randomize_va_space`, `sysrq` — a recon oracle telling the attacker which finding is live on this host |

Two of these are load-bearing beyond recon:

- **`/proc/asound` + `boot_id` falsify DESIGN §5.3**, which says the generated
  per-sandbox `/etc/machine-id` means "the sandbox cannot fingerprint the host." It
  can, several ways, and `boot_id` lets two sandboxes prove they share a host.
- **`/proc/interrupts` is a live keystroke-timing oracle against the *operator*.**
  DESIGN N5 declares side channels out of scope, but its wording does not name a
  channel that reports when the human at the keyboard is typing.

## `/sys` and `/dev` — the good news

- **`/sys` is genuinely not there.** `stat /sys` → ENOENT; no `sysfs` line in
  `/proc/self/mountinfo`. Structurally inexpressible: `policy.Kind` has no sysfs
  member, `BwrapFlags` emits no sysfs flag, no TOML key produces one. It cannot be
  created from inside (`mount -t sysfs` → "must be superuser", `unshare -m` →
  EPERM). **Every classic sysfs vector — cgroup-v1 `release_agent`,
  `uevent_helper`, securityfs, efivarfs, module params, DMI/thermal — is closed at
  the root, not by permission.**
- **The device-node escape surface is absent.** `ls /dev` = exactly
  `core fd full null ptmx pts random shm stderr stdin stdout tty urandom zero`.
  `/dev/{mem,kmem,port,kmsg,kvm,fuse,net/tun,dri,snd,sd*,nvme*,loop*,mapper,input,…}`
  all ENOENT; `mknod` → EPERM; the `/dev` tmpfs is `nodev` anyway.
- **`/dev/shm` is per-sandbox and isolated** (empty inside, `shm_open()` works,
  host segments invisible) — *note this property is entirely lost under D2 below.*
- **PID/IPC/net/cgroup namespacing is clean.**
- **The container engine adds no device** (`Devices`/`Privileged`/etc. refused by
  name; `-v /dev:/hostdev` refused; volume `DriverOpts` refused at source).

## Finding inventory

Severity legend: **High / Medium / Low**, plus *kernel-protected* (escape needs a
kernel bug — correct today) vs *snug-level* (a leak snug could close).

### Reachable today, default profiles — snug-level, closable

| # | fs | finding | sev |
|---|---|---|---|
| P1 | /proc | `/proc/config.gz` — complete host kernel config, exploit-selection oracle | **High** |
| P2 | /proc | `/proc/cmdline` + `/proc/version` — root UUID, OS snapshot generation, initrd hash, kernel build | Medium |
| P3 | /proc | `/proc/keys` + `/proc/key-users` — host user's live keyring incl. Kerberos ccache. Key *use* is dead (seccomp), this is enumeration | Medium |
| P4 | /proc | `/proc/kallsyms` + `/proc/modules`. Addresses zeroed **only** by host `kptr_restrict=1`; on `=0` this is a full KASLR base leak snug neither checks nor reports | Medium (High on an unhardened host) |
| P5 | /proc | `/proc/interrupts` — operator keystroke/touchpad timing oracle; `/proc/bus/input/devices` names the hardware | Medium |
| P6 | /proc | Fingerprint set: `boot_id`, `btime`/`uptime`, `/proc/asound`, `/proc/bus/pci`, `/proc/partitions`, `loginuid`/`sessionid`/`attr/current`. `--unshare-all` does **not** unshare the time namespace, which is why `uptime`/`btime` leak. Contradicts DESIGN §5.3 | Medium |
| P7 | /proc | `/proc/self/mountinfo` — real host paths of every grant, launcher home, container storage layout. Inherent to guest==host path convention | Medium — **accept + document** |
| P8 | /proc | Hardening-posture sysctls readable | Low |
| P9 | /proc | Structural: procfs `rw`, no `hidepid=`, no `subset=pid`; `--remount-ro /` does not reach it. The cause behind every row above | Low as finding, High as cause |
| P12 | /proc | `/proc/1/environ` is 0 bytes (the 106-var fix holds). But PID 1 is bwrap at the same uid and `ptrace_scope=1` restricts ATTACH not READ, so `/proc/1/fd` is enumerable. Equals the known stdio hazard by a second route; `safeStdio` mitigates | Low |
| D1 | /dev | `/dev/console` is a bind of the operator's real host pty and `/dev/tty` is the inherited controlling terminal (`--new-session` deliberately omitted on this kernel). TIOCSTI is dead twice over, but **no rule inspects bytes written to a tty** — OSC 52 clipboard, title query, CSI reports all reach the emulator and the reply lands on a descriptor the sandbox can read | Medium |
| D5 | /dev | `/dev` and `/dev/shm` are unbounded tmpfs (= host RAM, no `size=`), and `/dev` is writable. Host RAM exhaustion. The engine's own containers get `size=64000k` | Low (DoS only) |
| Y5 | /sys | `cmd/snug/dryrun.go:162` appends the literal `/sys /tmp/.X11-unix …` to the NOT-GRANTED block **without consulting the policy** — so with `/sys` granted, `--dry-run` prints `ro /sys` *and* "never mounted" on one screen | Low sev, **high leverage** (the trust artifact) |

### Reachable today, but only with `@podman-socket` selected

| # | fs | finding | sev |
|---|---|---|---|
| Y4 | /sys,/proc | The engine runs **on the host**, so containers live in its namespaces and get a full read-only host sysfs (`product_name`, `sys_vendor`, host NIC names) and host-shaped procfs. `-v <target>:/out` is permitted, so the agent can `cp -a /sys/class/dmi/id /out` and land the host hardware inventory back inside the sandbox. `-v /sys:/sys` *is* refused | Medium — **accept + fix the claim** (`base.toml:255-267` is silent on host sysfs/procfs reaching the container) |

### Not payload-reachable — but reachable by a *trusted profile*, which composes with the recorded invariant-3 gap

CLAUDE.md already records that `$XDG_CONFIG_HOME/snug/profiles.d` is trusted
unconditionally and `Profile.Trusted` is set and never read. These are the payoff,
and they are worse than that gap's current "low severity" note implies.

| # | fs | finding | sev |
|---|---|---|---|
| **D2** | /dev | A profile with `ro = ["/dev"]` **displaces the builtin entirely** — `mustJoin` (`resolve.go:426`) installs the builtin only if the guest is unclaimed, so `--dev /dev` is never emitted and `--ro-bind /dev /dev` replaces it. 250+ host nodes appear (`/dev/mem`, `/dev/kvm`, `/dev/fuse`, `/dev/net/tun`, `/dev/nvme*`, `/dev/mapper`, `/dev/input`, …). The listing is a full hardware inventory, and the **host's `/dev/shm` comes along** with readable contents. Nodes are unopenable only because bwrap stamps `nodev` on ordinary binds — a default snug never states, asserts, or tests | **High** |
| **S1** | /proc | Same `mustJoin` displacement at `/proc`: `ro = ["/proc"]` → `--ro-bind /proc /proc`, 477 pids, the full outer process table with argv (incl. other sandboxes' bwrap command lines). `/proc/<pid>/{environ,root,fd}` stay EACCES, so it is process-table disclosure, not a filesystem bypass | **High** |
| **S2** | /proc,/dev,/tmp | `rejectMasking` skips any ancestor that is not `KindBind` (`validate.go:143`). The builtins are `KindProc`/`KindDev`/`KindTmpfs`, so **a profile may mount arbitrary host content on top of any path inside them, with no error.** Verified: `ro = ["/proc/config.gz"]` and `ro = ["/proc/sys"]` both accepted and live. A profile can make the sandbox lie about its own state or substitute content for `/dev/urandom`. **Directly contradicts invariant 1's "the grant language cannot express subtraction."** | **Medium-High (structural)** |
| Y2 | /sys | `rw = ["/sys"]` makes the recursively-dragged-in delegated cgroup2 subtree writable: `mkdir /sys/fs/cgroup/snugpwn` succeeded; `cgroup.kill`/`cgroup.freeze` writable on a cgroup whose `cgroup.procs` lists processes **outside** the sandbox. Not an escape (cgroup v2 has no `release_agent`), but kill/freeze/starve control over out-of-sandbox processes | Medium-High |
| Y3 | /sys | `ro = ["/sys"]` is **ten filesystems, not one** — bwrap binds recursively (securityfs, two cgroup2, pstore, efivarfs, bpf, configfs, selinuxfs, debugfs, tracefs, fusectl). `/sys/class/net` shows host NICs **and real MACs** despite the sandbox's empty netns, because sysfs net entries are netns-tagged at mount time. The opposite of the enumerate-don't-bind rule | Medium |
| D3 | /dev | A profile can bind individual host device nodes *into* the synthetic `/dev` (`rw = ["/dev/fuse"]` → `--bind-try`, no masking error — correctly, an addition at a deeper path). Inert **only** because of bwrap's `nodev` on ordinary binds; bwrap's own `--dev` nodes are mounted *without* `nodev`. One flag deep from an unprivileged mount primitive | Medium |

### Present but kernel-permission-protected — escape needs a kernel bug

Correct outcomes today; each depends on something snug does not own.

| # | fs | finding | dependency that must never change |
|---|---|---|---|
| P10a | /proc | `core_pattern`, `modprobe`, `poweroff_cmd`, `usermodehelper/*` — readable, none writable (`nobody:nobody`, `CapEff=0`) | uid mapping must never map the sandbox to 0 in a userns owning these inodes |
| P10b | /proc | `/proc/sysrq-trigger` — write → EPERM. OCI runtimes bind `/dev/null` over it; snug does not | same |
| P10c | /proc,/dev | `/proc/kcore` (EACCES), and **`/dev/core → /proc/kcore`** — the path exists twice. Same for `kmsg`, `slabinfo`, `vmallocinfo`, `timer_list` | same — if the uid mapping ever became 0, `/dev/core` is physical memory |
| P11 | /proc | `/proc/sys/net/*` is owned `<user>:<user>` mode 0644 — DAC alone would permit the write; what refuses it is `CAP_NET_ADMIN`. The one procfs region protected by a capability check rather than ownership | `CapBnd = 0` |
| P13 | /proc | procfs re-mount / namespace-regain: native paths closed (`unshare(CLONE_NEWUSER)` seccomp-denied, `clone3`→ENOSYS, `mount`→EPERM). **Residual:** the filter ALLOWs non-native arches, so a 32-bit `unshare` is unfiltered, and the remount target is real (`/` tmpfs and `/usr` overlay superblocks are both `rw`; the `ro` comes from the bind). DESIGN §5.4 calls the i386 path "a bypass" without saying what it buys | seccomp non-native ALLOW |
| D4 | /dev | devpts is a fresh `newinstance`; no host pty enumerable; TIOCSTI EPERM on both a fresh pty and `/dev/tty` | seccomp + host `legacy_tiocsti=0` — working |

## What bwrap can and cannot do (the honesty section — all run live)

**Cannot:**
- `--proc DEST` takes **no mount options** — no `hidepid=`, no `subset=pid`, no
  read-only procfs. A curated procfs (enumerate the entries you meant) is
  **impossible**; procfs is one mount, all or nothing.
- No subtraction primitive exists anywhere in bwrap. You cannot hide a path without
  mounting over it. **Therefore any closure of a `/proc` leak is necessarily a
  replacement** — exactly the case CLAUDE.md's author distinction licenses: *snug*
  replacing a path with its own truthful content is replacement; a *profile* doing
  it over another profile's grant is masking and stays refused.

**Can — verified:**
- **Overmount an individual procfs file with an empty regular file.**
  `--ro-bind /tmp/empty /proc/config.gz` (and `/proc/keys`, `/proc/kallsyms`,
  `/proc/sysrq-trigger`) → all read 0 bytes, control `/proc/cmdline` still present,
  exit 0. `KindData`/`--ro-bind-data` shaped; snug already has the machinery.
- **Make `/proc/sys` genuinely read-only via a self-bind.**
  `--ro-bind /proc/sys /proc/sys` → the write fails **EROFS instead of EPERM**,
  i.e. the refusal becomes snug's rather than the kernel's, and values still read
  correctly. Precisely what crun does.

**Can, but do not:**
- `--ro-bind /dev/null /proc/config.gz` — **does not** behave like crun's masking
  here. The bind inherits `nodev`, so `open()` returns **EACCES**, not empty
  content. Use an empty regular file, not `/dev/null`.
- Overmounting a procfs **directory**: an empty directory over `/proc/sys`
  succeeds but **annihilates the subtree** (`osrelease` → ENOENT), breaking every
  sysctl reader. Do not mask procfs directories.

**Invariant compatibility.** Emitting `ro` at `/proc/sys` under an `rw` `/proc` is
a *deeper mount with lower access* — the exact case invariant 1 already documents
as "effective write access at a strict subpath is NOT monotone, by design." It is
**not** a `Clamp`-style restriction: nothing is demoted in place, a second mount is
added at a deeper key, and it is snug-authored with `(snug)` provenance. Say so
in the commit, because "snug emits a read-only mount" reads like the thing
invariant 1 removed and is not.

## Ranked recommendations

Each is additive-or-refusing; none introduces a deny rule, a mask verb, or a
demote-in-place.

- **R1 — Make `/proc` and `/dev` non-displaceable. Closes S1 + D2 (both Highs).**
  `mustJoin` silently yields the builtin to any profile claiming the same guest.
  Change it to a hard `Validate` error on a grant at exactly `/proc` or `/dev`,
  naming the reason. This **refuses a grant** (same shape as the existing "refusing
  to bind /"), it does not demote one, so invariant 1 is untouched. Converts "you
  get a fresh pid-namespaced procfs" from a property of the default profile set
  into a structural guarantee.
- **R2 — Extend `rejectMasking` to `KindProc`/`KindDev`/`KindTmpfs` ancestors, and
  re-key the `KindData` exemption on provenance. Closes S2; restores invariant 1's
  literal truth.** Treat mounts strictly beneath a `KindProc`/`KindDev`/`KindTmpfs`
  mount as masks and refuse them. Simultaneously narrow the exemption from
  `m.Kind == KindData` to `provenance == "(snug)"` — the existing comment
  already warns the kind-keyed version reopens the moment a TOML key can produce
  `KindData`, and **R3 is exactly what makes snug produce more of them**. These two
  must land together or R3 hands profiles the subtraction verb. *(Distinct from the
  already-recorded identity-file `KindData` displacement on the same code path —
  don't make that worse.)*
- **R3 — Snug-authored empty-file replacements at a named procfs set. Closes P1,
  P3, most of P4/P5.** Provenance `(snug)`, `--ro-bind-data`/empty-file,
  **printed in `--dry-run`**.
  - *Tier 1, no compat cost:* `/proc/config.gz`, `/proc/keys`, `/proc/key-users`.
    `keys` is what crun/runc already mask, and snug half-made this decision already
    (`add_key`/`keyctl`/`request_key` are seccomp-denied).
  - *Tier 2, judgement:* `/proc/kallsyms`, `/proc/modules`, `/proc/interrupts`,
    `/proc/timer_list`, `/proc/sysrq-trigger`.
  - *Not:* `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat` — build/test runners
    parse them; N5 already accepts `cpuinfo`.
  - *Flag:* `/proc/config.gz` is read by out-of-tree module builds (DKMS). snug is
    a build sandbox too; if that matters, restoring it should be a named opt-in
    profile, not a default exposure.
- **R4 — Emit `--ro-bind /proc/sys /proc/sys`.** Makes the whole write side snug's
  instead of the kernel's; costs nothing (only IPC/PID-ns noise is writable today);
  matches crun; future-proofs P10a/P10b/P11 against any uid-mapping change.
- **R5 — Teach `snug doctor` to read and report the host hardening it silently
  depends on:** `kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid`,
  `yama/ptrace_scope`, `unprivileged_bpf_disabled`. "No silent downgrade" applied
  to an *inherited* guarantee. snug checks none today.
- **R6 — `Validate`-time refusal of a **rw** grant at or under `/sys`, naming
  cgroup delegation. Closes Y2.** Keep **ro** `/sys` expressible (DESIGN Q6's
  escape hatch; Y3 shows it mostly inert). Record the ro/rw asymmetry.
- **R7 — Route `dryrun.go:162`'s trailing literal through `covered()`. Closes
  Y5.** One line; the only screen a human has for trusting snug.
- **R8 — Bound the tmpfs (`--tmpfs /dev/shm` with `size=`). Closes D5.** A
  `KindTmpfs` mount at a deeper path — an addition, not a subtraction.
- **R9 — Documentation, batched:** correct DESIGN §5.2's `/dev` enumeration (name
  `console` as a bind of the host pty, `core` as a symlink to `/proc/kcore`);
  correct §5.3's fingerprint claim; rewrite the doc that says snug ships
  `[profile.sysfs]` (it does not — state the stronger truth, and that a `/sys`
  profile must enumerate leaves because **bwrap binds are recursive**); amend N5 to
  name `/proc/interrupts`; add one sentence to the `@podman-socket` ABUSE comment;
  add the time-namespace and `nodev`-on-ordinary-binds facts to CLAUDE.md.
- **R10 — Offer `--new-session` as an opt-in for non-interactive payloads (D1).**
  **Do not filter escape sequences** — a 95%-correct terminal filter is the
  D-Bus-proxy mistake in another costume. For CI/hooks/tests, losing job control
  costs nothing and closes the channel outright. Meanwhile state the channel in
  DESIGN §5.2, `docs/src/verify.md`, and the injected `~/.claude/CLAUDE.md`.
- **R11 — Consider `SECCOMP_RET_ERRNO` on non-native audit arches (i386/x32)
  rather than falling through to ALLOW (P13).** Nothing snug supports needs a
  32-bit payload; "no silent downgrade" argues for failing loudly.
- **R12 — Close the invariant-3 gap.** S1, S2, D2, D3, Y2, Y3 are all gated on it;
  the combined payoff is a full host device tree, the outer process table, and
  cgroup kill/freeze over out-of-sandbox processes. The current TODO framing ("low
  severity — the host user's own env var") should be re-read in that light.

## Disposition

### Becomes a permanent named regression test (`sandbox-tester`)

Each gets a **positive control** (the `pasta.avx2` lesson):

- `TestPseudoFSBuiltinsAreNotDisplaceable` — a grant at exactly `/proc` or `/dev`
  is a `Validate` error; golden argv still contains `--proc /proc` / `--dev /dev`.
  *(R1: S1 + D2)*
- `TestProfileCannotMaskInsidePseudoFS` — `ro=["/proc/config.gz"]`,
  `ro=["/proc/sys"]`, and grants under `/dev`/`/tmp` all refused; a snug-authored
  `(snug)` replacement at the same path still accepted. *(R2: S2, + the
  provenance-keyed exemption)*
- `TestUsermodeHelperFamilyIsDenied` — writes to `core_pattern`, `modprobe`,
  `poweroff_cmd`, `usermodehelper/{bset,inheritable}`, `sysrq-trigger`,
  `vm/drop_caches` refused **and** each file owned by an *unmapped* uid.
- `TestKcoreFamilyIsUnreadable` — EACCES on `kcore`, `kmsg`, `slabinfo`,
  `vmallocinfo`, `timer_list`, `pagetypeinfo` **and** `/dev/core`.
- `TestWritableSysctlSetIsExactlyTheNamespacedOnes` — enumerate every file under
  `/proc/sys` by **attempting the write**, assert the set equals the IPC/PID-ns
  set. Must attempt the write, not `test -w` (`cad_pid`/`ns_last_pid` pass
  `access(2)` then fail the write).
- `TestProcSysNetIsOwnedByUsButUnwritable` — `ip_forward` owned by the sandbox uid
  **and** the write refused (protection is `CAP_NET_ADMIN`).
- `TestSysfsIsAbsent` (strengthen) — `stat /sys` → ENOENT **and** no `sysfs` in
  mountinfo, with a positive control asserting `proc`/`devpts` **are** present.
  Today `sandbox_test.go:437` only checks the output *mentions* `/sys`.
- `TestDevContentsEqualSyntheticSet` (replace) — the `/dev` set **equals** the
  14-entry list (+`console` iff stdout is a tty), `mknod` → EPERM.
  `TestDevIsWritableButNeitherPersistsNorEscapes` checks only one runtime-discovered
  host entry, so an **added** device passes it today.
- `TestBoundDeviceNodeIsNodevAndUnopenable` — a profile-bound host device node is
  `nodev` and `open()` → EACCES, with a control that `/dev/null` **is** openable.
  This bwrap default carries the whole weight of D2/D3 and is stated nowhere.
- `TestShmIsPrivateAndEphemeral` — `shm_open()` **succeeds** (control), segment
  absent from host and from a second sandbox.
- `TestTIOCSTIDeniedWithControl` (strengthen) — TIOCSTI → EPERM **and** some other
  `ioctl` on the same fd succeeds.
- `TestPID1ExposesNothing` (extend) — `/proc/1/environ` empty **and** `/proc/1/fd`
  contains no descriptor naming a path outside the granted set.
- `TestDryRunNeverContradictsItself` — no path in both the FILESYSTEM and
  NOT-GRANTED blocks. *(R7)*
- *(with R3/R4)* `TestProcReplacementsAreEmptyAndDeclared` — replaced paths read 0
  bytes, `/proc/sys` write → **EROFS**, both appear in `--dry-run`.

### Accepted gaps (→ TODO.md, with severity)

- `/proc/self/mountinfo` discloses real host paths (P7) — Medium, inherent. Also
  state in the injected `~/.claude/CLAUDE.md`.
- `/proc/interrupts` operator keystroke-timing oracle (P5) — Medium; if R3 tier 2
  is declined this must be an explicit N5 decision, not an omission.
- Host fingerprinting defeats the generated machine-id (P6) — Medium; `boot_id` is
  a one-file replacement if host anonymity is wanted, else scope the §5.3 claim.
- `@podman-socket` transitively grants read-only host sysfs/procfs to containers,
  copyable back via `-v <target>:/out` (Y4) — Medium.
- `/dev/console` + `/dev/tty` OSC-52 / escape-sequence channel to the operator's
  terminal (D1) — Medium; R10's opt-in `--new-session` is the mitigation, not a
  filter.
- `ro=["/sys"]` is recursively ten filesystems and leaks host NIC names + real
  MACs despite the private netns (Y3) — Medium; record that sysfs net entries are
  netns-tagged at mount time (counterexample to "a private netns hides interfaces
  everywhere").
- Non-native seccomp arch ALLOW → nested userns → remount over an `rw` superblock
  (P13) — Low-Medium; write down what the bypass buys.
- Unbounded `/dev`, `/dev/shm`, `/tmp`, `$HOME` tmpfs → host RAM exhaustion (D5) —
  Low.
- Hardening-posture sysctls readable (P8) — Low; R5 is the real response.
- **Coupling to record:** the nested-userns seccomp denial is load-bearing for
  `/sys`, not just for escape. **Any future proposal to run the engine inside the
  sandbox is a `/sys` proposal** (an OCI runtime needs sysfs + a writable delegated
  cgroup subtree — Y2 measures what that reopens). Must go through `redteam`.

## Documentation defects found (not exploitable, but the shape that burned before)

- DESIGN §787: says snug "ships `[profile.sysfs] ro=["/sys"]`" and exports
  `NPROC`-shaped env hints — **neither exists**. Reality is *stronger*, but a
  reader will "wire up what's documented," i.e. `ro=["/sys"]`, which is exactly
  Y2/Y3.
- DESIGN §5.2 / VERIFY §77: synthetic `/dev` described as "null, zero, full,
  random, urandom, tty, plus a private devpts" — also contains `console` (host
  pty), `core → /proc/kcore`, `shm`, `ptmx`, `fd`, `std{in,out,err}`.
- DESIGN §5.3: generated machine-id ⇒ "cannot fingerprint the host" — false (P6).
- DESIGN §5.2: `--proc /proc` as "a fresh procfs bound to the sandbox's own PID
  namespace" — true and incomplete; the host-global files are all there.
- DESIGN N5: side channels list undersells `/proc/interrupts`.
- `base.toml:255-267`: `@podman-socket` host resources "untouched and unreachable" —
  silent on host sysfs/procfs reaching the container (Y4).
- CLAUDE.md facts: `--unshare-all` does **not** unshare the time namespace — a
  "never trust a helper's default" fact worth adding.

## One-paragraph summary

snug's `/sys` is absent by construction and its `/dev` is a 14-entry synthetic
tree with the entire classic device-escape surface missing — both hold up under
live attack and both are stronger than the docs claim. `/proc` is the outlier:
bwrap's `--proc` gives a plain, fully unmasked procfs with no options available,
and snug masks nothing, so a default sandbox hands a hostile payload the complete
host kernel config, the boot cmdline with the root UUID, the host user's kernel
keyring including a Kerberos ccache, all kernel symbol names, a live
keystroke-timing oracle against the operator, and a stable hardware fingerprint
that falsifies DESIGN §5.3. **No escape — every write primitive is refused by
kernel DAC and zero capabilities — but the read side leaks more than crun's
default, which is an awkward place for a sandbox to be, and it is snug's to fix.**
The two structural defects behind the worst cases are that a profile can displace
the `/proc` and `/dev` builtins outright (`mustJoin` yields silently) and that
`rejectMasking` skips non-`KindBind` ancestors, so a profile *can* express
subtraction inside `/proc`, `/dev` and `/tmp` — which contradicts invariant 1 as
written. Both are refusals to add, not restrictions, so both are cheap and
invariant-safe.
