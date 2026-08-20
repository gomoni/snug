# Tier B — the container engine in the sandbox's netns, as decided and measured

Issue [#63](https://github.com/gomoni/snug/issues/63). Decisions settled by the
maintainer on **2026-08-18**; measurements executed the same day on the
development host — openSUSE Tumbleweed, `bwrap` 0.11.2, `pasta` 20260612, Go
1.26, inside a rootless-podman distrobox, against the pinned static podman
bundle (5.8.4).

**Why this document exists.** Tier B's settled decisions were the only
justification for behaviour that reads as arbitrary from the code alone — why
the engine gets exactly twelve capabilities, why `NetworkMode="host"` is
*allowed*, why the `networks` endpoints carry no refusal list, why
`ptrace_scope=0` refuses the run outright. Six code comments cited them, and
for two milestones they cited a file that had never been committed: the
reasoning lived in `.claude/scratchpad/`, which is in `.gitignore`, and was
never promoted by the deliberate `git mv` `CLAUDE.md` describes. A reader
following the citation got nothing
([#154](https://github.com/gomoni/snug/issues/154) §C).

What is here is the *settled* material and the measurements that stay useful.
The planning around it — which goldens would move, what still needed measuring
before code, proposed `CLAUDE.md` wording — is deliberately not, because it
described work that has since landed and would drift the moment it did.
[`ENGINE-NETNS.md`](ENGINE-NETNS.md) remains the record of the original
finding; this is the record of what was decided about it.

---

## 1. Maintainer decisions, settled 2026-08-18

- **Q1 — the engine's capability bounding set.** Answered by measurement and
  by the NET_ADMIN decision below: **twelve capabilities**, a fixed constant
  rather than a profile field. §2 and §3.
- **Q2 — `ptrace_scope=0`: REFUSE.** The whole argument that dropping
  `CAP_SYS_PTRACE` from the engine's set closes the in-U peer-read (§3) holds
  only when `/proc/sys/kernel/yama/ptrace_scope` is `1`. At `0`, the kernel's
  own same-uid rule admits `ptrace` of a non-descendant peer with **no
  capability check involved at all**, and the confinement measurement under
  that setting was never re-run. If the host setting invalidates the
  measurement, do not run engine-in-N at all: **no warn-and-continue.** `2` and
  `3` are stricter than `1` — they narrow ptrace further — and pass.
  Implemented as `preflightPtraceScope` (P6, `internal/cli/containerpreflight.go`).
- **Q3 — `newuidmap`/`newgidmap` setuid: accept the host tool.** The common
  distro shape. The "no setuid" invariant is about snug's **own** staged
  binaries, not about host tools it invokes; the preflight message names it.
  May be tightened to file-caps-only later.
- **Q4 — the engine socket path: `/tmp/snug-<uid>-<runid>/`.** Root-in-userns
  podman masks `$XDG_RUNTIME_DIR` with a tmpfs `/run`, so the socket cannot
  live there. The proxy reaches it across the namespace boundary as a pathname
  socket (measured).
- **Q5 — the `networks` proxy gap: rely on N containment.** A container in N
  cannot escape N by creating a podman network, and the engine holds no
  `CAP_NET_ADMIN` to bring a bridge up in the first place. So the `networks`
  endpoints are **not** special-cased as a hole and carry no refusal list:
  containment answers it structurally. Do **not** also inject `NetworkMode`
  constraints. Implemented at `internal/dockerproxy/proxy.go`'s `case
  "networks"`.

---

## 2. The NET_ADMIN decision — twelve caps, share N, no port publishing

The measurement in §5 surfaced a real fork, and the maintainer took the
**tightest engine authority** of the two:

| | containers share N (host-mode) | containers get their own netns |
|---|---|---|
| engine caps | **12**, `CAP_NET_ADMIN` excluded | 13, `CAP_NET_ADMIN` granted |
| `podman run -p` | not supported | works, publishing onto the sandbox's loopback |
| per-container bridge | none | netavark, and its rootless-netns path still owed a re-measurement (it failed `netavark: setns: EPERM` under the bare topology even at 13 caps) |
| cost | — | more engine authority in U, for the whole run |

**Chosen: share N, twelve caps.** The consequences, stated so nobody carries
the port-publishing assumption forward:

- `CAP_NET_ADMIN` stays **excluded**, and its exclusion sentence in §3 —
  *"cannot reconfigure the shared netns N — pasta owns it"* — is load-bearing
  rather than incidental. A compromised engine must not be able to reconfigure
  N, and that is exactly why `-p` is dropped rather than `CAP_NET_ADMIN` added.
- **Containers share the sandbox's netns host-mode.** They reach exactly what
  the sandbox reaches: with `@net`, egress; without it, nothing. This is why
  `HostConfig.NetworkMode = "host"` is the one namespace mode the proxy
  **allows** — it means "join the engine's current netns", and that netns is
  now N, not the real host's. Every other `host`/`container:`/`ns:` mode stays
  refused, `PidMode` above all, because `__inengine` does not unshare pid and
  the engine's own pid namespace genuinely **is** the host's.

  > **Superseded by issue #125's C0, which is where this document stops being
  > current on this one point.** C0 put `CLONE_NEWPID` on the engine's own
  > clone and mounts a fresh procfs in `__inengine`, so the engine's pid
  > namespace is its own and `PidMode = "host"` would join *that*, not the
  > host's (measured A/B against C0's parent commit; the numbers are in
  > `internal/engine`'s package comment). **The refusal is unchanged** — it is
  > now conservative rather than the whole boundary, since the namespace it
  > declines still holds podman as pid 1 and every other container's conmon.
  > Whether to relax it is issue #145's. Tier B's own sentence above is left
  > as written because it was true of Tier B.
- **`podman run -p N:80` is not supported, and that is a decline, not a
  regression** — no in-sandbox-netns publishing shipped before Tier B either.
  The proxy refuses `PortBindings`/`PublishAllPorts` and says why: a container
  already shares the sandbox's namespace, so there is nothing to publish *to*,
  and the engine could not set a mapping up regardless.
- The `@podman-socket` footnote that once read "`podman run -p 8080:80` will
  NOT work" is **true again** under Tier B, and states the security reason
  rather than apologising for an ergonomic limit.
- [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §2's per-container-bridge and `-p`
  measurement is **superseded** by this decision. Read it as the feasibility
  proof it always was, not as the shipped shape.

---

## 3. The capability bounding set — twelve, and why each one

`policy.EngineCapBounding`, a fixed ordered constant in `internal/policy`,
rendered by `--dry-run`'s TOPOLOGY block and pinned by
`internal/cli/testdata/topology.podman-*.txt`. The abuse sentence per cap is
*"a compromised engine holding it in U can ___"*:

| cap | why podman needs it | a compromised engine holding it can |
|---|---|---|
| `CAP_SYS_ADMIN` | mount overlay/tmpfs/proc/bind, `unshare`/`setns`, `pivot_root` — the irreducible reason it cannot take the container set | mount/remount and enter namespaces within U; **cannot** ptrace, since `SYS_ADMIN` does not satisfy `PTRACE_MODE_ATTACH` |
| `CAP_SYS_CHROOT` | `pivot_root`/`chroot` into a container rootfs | chroot within U's mount tree |
| `CAP_CHOWN` | chown extracted image files across the delegated subuid range | change ownership only within the mapped range; a uid outside the map is unreachable |
| `CAP_DAC_OVERRIDE` | read/write/traverse extraction targets regardless of mode | read/write any file **in its private host-tree copy** — the honest gap the proxy filter guards, which Tier C makes structural (§4) |
| `CAP_FOWNER` | chmod/utime/setxattr on extracted files | bypass ownership checks on metadata ops within U |
| `CAP_FSETID` | preserve setuid/setgid bits on extracted files | keep suid bits on files it writes |
| `CAP_SETUID` / `CAP_SETGID` | run a container process as its configured id; `setgroups` | setuid/setgid within the mapped range only |
| `CAP_SETPCAP` | hand a container its capability set from the bounding/inheritable sets | raise/drop caps in its own sets within U; cannot exceed the bounding set it was given |
| `CAP_SETFCAP` | write file capabilities on extracted files (some images ship them) | set fcaps on files in its copy |
| `CAP_KILL` | signal container processes it owns | signal processes it owns |
| `CAP_NET_BIND_SERVICE` | passed down so a container may bind below 1024 | bind low ports in the **shared N** — the same reach the sandbox already has |

**Excluded, each a specific denial:** `CAP_SYS_PTRACE` (the gate — cannot
`process_vm_readv` or read `/proc/<pid>/mem` of a peer in U); `CAP_NET_ADMIN`
(§2); `CAP_MKNOD` (rootless crun bind-mounts devices rather than creating
them); `CAP_DAC_READ_SEARCH`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`,
`CAP_SYS_BOOT`, `CAP_SYS_TIME`, `CAP_BPF`, `CAP_PERFMON`, `CAP_AUDIT_*`,
`CAP_MAC_*`.

**Why the drop is effective even though the bounding set is not an escapee
ceiling.** A nested user namespace resets the bounding set to full — measured —
so dropping `CAP_SYS_PTRACE` does **not** cap an escapee, and reading it that
way is exactly the false comfort the measurement warned against. Its value is
that the engine's **own process, in U**, then lacks `CAP_SYS_PTRACE` *in U*. To
regain ptrace power a compromised engine must `unshare -U` into a descendant
U2, where full capabilities are namespace-relative and worthless against U's
members (`user_namespaces(7)`). So the drop closes the in-U peer-read the
standing gate forbids — and only on `ptrace_scope=1`, which is what makes Q2's
refusal load-bearing rather than cautious.

**One drop, and no uid-map re-exec — the distinction that stops a spurious
one being added.** `__inengine` forks from a P1 that is *already* uid 0 in U
with a **full** effective set, because it created no nested user namespace. So
it inherits full capabilities immediately, and a single
`dropCapsToExactly(policy.EngineCapBounding)` — after the mounts that need the
full set, immediately before the exec — is enough. This is unlike
`__stage-setup`, which does need a re-exec to pick up its map; do not copy that
shape here.

**A constant, not a `Profile` field.** It is a *mechanism*, like pasta's
closing flag set, and there is no per-profile reason to vary it. Making it a
profile field would let a profile **widen** the engine's authority — a
negative-grant hazard facing the other way. Keeping it off `Profile` makes "no
profile widens the engine" structural, the same device as `deriveTopology`
being derived rather than granted. Widening still lands in a review diff,
because `--dry-run` renders the named set and a golden pins it.

---

## 4. Invariant 6 — held at the authorship layer; structural mount enforcement deferred to Tier C

**Ruling: Tier B holds invariant 6 for both dimensions at the authorship layer,
and defers the *structural* enforcement of the mount dimension to Tier C
([#125](https://github.com/gomoni/snug/issues/125)). A named deferral, not a
silent violation — and only because it is gated by a test.**

- **Network dimension — structurally one author.** The engine `setns`es into
  the sandbox's *actual* N. There is one network namespace and no second
  author: the netns the pasta argv configures is the netns the container runs
  in. Invariant 6 is met the strongest way available.
- **Mount dimension — one author of the decision, two enforcement
  mechanisms.** Tier B gives the engine a private **copy of the whole host
  tree**, so structurally its view contains paths the sandbox cannot see. What
  stops a container mounting them is the proxy's bind filter — and that filter
  reads the **same resolved `Policy`**. So there is one *author* of the
  decision "may a container mount X", which is invariant 6's literal claim.
  Tier C adds a second, structural layer: a derived view that physically cannot
  name an ungranted path, removing the residual *"if the filter has a bug, the
  host tree is right there."*
**The boundary, drawn as a hard line so an implementer does not wander into
[#55](https://github.com/gomoni/snug/issues/55):**

| concern | Tier B | Tier C ([#125](https://github.com/gomoni/snug/issues/125)) |
|---|---|---|
| engine mount ns source | `unshare(CLONE_NEWNS)` + `MS_REC\|MS_PRIVATE` on a private copy of the **host** tree | `open_tree(…OPEN_TREE_CLONE\|AT_RECURSIVE)` of policy-named paths, grafted into a fresh tmpfs derived from the **sandbox's** view (`ENGINE-NETNS.md` §5.1) |
| what stops the engine seeing `~/.ssh` | **nothing structural** — the engine sees the whole host tree in its private copy; bind safety is enforced by the proxy's filter, which refuses a `-v` naming a path the sandbox cannot see. This is the honest gap. | the derived view — a `-v` can only ever name a path the sandbox already sees, so the filter stops being a parallel implementation of policy |
| grafts | **none.** No `/run`, `/etc/containers` or `/var/tmp` grafts; no fresh-tmpfs-mountpoint dance; no read-only-root fight; no `/snug/bin` PATH shadow. | the graft sequence, its ordering rule, and routing grafts through `Validate`/`IsShadowSlot` so they do not become a shadow slot one layer down |
| #55 | **not touched** — Tier B does not put the engine in bwrap's namespace, so the read-only-locked-root problem never arises | in scope |

> **The implementer's rule: if you find yourself writing `open_tree`,
> `move_mount`, a graft, or fighting a locked read-only root, you have crossed
> into Tier C — stop.** Tier B's engine mount namespace is a plain private copy
> of the host tree and nothing more.

- **Why deferral rather than violation.** Invariant 6's failure mode is
  *divergence* — the sandbox and the container disagreeing about what is
  visible. That is impossible only if the filter's predicate is provably the
  Policy's visibility predicate. The gate is a test proving that equality:
  `TestContainerBindFilterMatchesPolicyVisibility`
  (`internal/dockerproxy/bindfilter_test.go`), with the positive control that
  makes it mean something — a granted path accepted, and an adjacent **sibling**
  the policy does not grant refused. Asserting the sibling, not merely the
  grant, is what turns an honest gap into an asserted boundary.

---

## 5. Measurements that stay useful

**M-CAP — the twelve-cap set is the measured floor; none of the twelve is
droppable, and `CAP_SYS_PTRACE` was never required.**

**The trap in this measurement, and the reason it is recorded rather than
summarised: exit status is a FALSE floor.** A container's delivered capability
set is *its default set ∩ the engine's bounding set*, so `podman run alpine
true` exits 0 even when the container is cap-starved. A naive peel — drop a
cap, see whether the command still succeeds — reports a false **four**-cap
floor (`DAC_OVERRIDE`, `SETGID`, `SETPCAP`, `SYS_ADMIN`) that silently strips
every container's defaults. Measured: a 12-cap engine bounding set delivers
`0x800405fb` to the container (the full expected set); dropping
`CAP_NET_BIND_SERVICE` from the engine loses the container exactly bit 10.

**The constant's comment must state the intersection mechanism**, or a reviewer
tightens it to the false floor and nothing fails.

**M-CGROUP — `--cgroups=disabled` is required on the run path.** cgroupfs is
not delegated to the rootless user on this host. podman then **enforces** a
private pid namespace (`--cgroups=disabled --pid=host` is refused), and a
double-forked detached grandchild **was** reaped when the container's PID 1
exited — so teardown is sound by podman's own enforcement rather than by snug
trusting it. `podman build`'s `RUN` step neither takes nor needs the flag: it is
a `run`-path fact. The preflight probe attempts a cgroup write under
`/sys/fs/cgroup/libpod_parent/` and selects `--cgroups=disabled` on
`ENOENT`/`EACCES`.

**Two corrections the wiring pass found that the design's own reasoning did not
predict** — recorded here as well as in `internal/stage/inengine.go`, since a
comment is not a place a reader looks first:

1. *"No `/run` graft is needed — podman mounts its own tmpfs there"* holds for a
   rootless single-uid podman, **not** for this root-in-U, full-subuid shape.
   podman does not self-mount, so `__inengine` mounts a bare tmpfs on `/run`
   itself.
2. `CLONE_NEWCGROUP` at clone time changes what `/proc/self/cgroup` **reports**
   but not what the inherited `/sys/fs/cgroup` mount's content is rooted at.
   `__inengine` mounts a fresh `cgroup2` over it — with an unmount-then-retry
   fallback measured necessary on a triply-nested-container development host —
   to actually get the confinement the namespace was supposed to buy.
