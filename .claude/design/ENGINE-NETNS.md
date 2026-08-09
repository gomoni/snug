# The container engine inside the sandbox's netns

Investigation, 2026-08-08, by `host-bridge`. Everything below marked with a
command was **executed**; everything else is marked as reasoning.

## 0. Why this exists

**This section is the canonical write-up of the finding.** Code and prose across
the repo cite it — `CLAUDE.md`, `base.toml`, `cmd/snug/dryrun.go`,
`internal/profile/file_test.go`, `VERIFY.md`, `.claude/design/SECRETS.md` §1.3.
If you arrived from one of those, this is the whole story; §5 is what is left to
do.

**The finding, as measured 2026-08-08.** `@podman-socket` granted **arbitrary
egress with no `@net`**, while `--dry-run` said "No egress. No host loopback."
A container started through the proxy runs on the *host's* engine, so it gets
the *host's* network; the payload reads the response back through
`containers/{id}/logs`. Measured with a positive control — the sandbox itself
could not resolve DNS, and a container reached `https://example.com` anyway.
That is a false guarantee, which is the one failure mode invariant 5 forbids
outright.

**Status, 2026-08-09 — step M-a landed (commit `ae848de`); the channel is still
open.** `@podman-socket` now carries `include = ["sys", "home", "net"]`, so
selecting containers selects egress *visibly*, `--dry-run` renders the egress
block, and a `CONTAINERS` block states that containers run in the engine's netns
and that the pasta guarantees do not cover them. **What changed is that snug
stopped denying it — not that a container can reach less.** Two consequences
worth stating plainly:

- The original measurement is **no longer reproducible on this tree**: there is
  no way to select `@podman-socket` without `@net`, so the "egress without
  `@net`" configuration no longer exists. Reproducing it needs a pre-`ae848de`
  checkout.
- The **host-loopback half is unaffected** and is now the sharper finding: a
  container can port-scan and reach the host's loopback, which is a channel
  `@net` never grants and `--dry-run` still does not describe.

The `net` include is interim and its removal is part of M-b;
`TestPodmanSocketIncludesNetAsAnInterimHonestyFix` makes that removal a
conscious act.

DESIGN §4.4 described the fix ("topology A") in the present tense. It was never
implemented — see the banner now on that section.

## 1. The crux: you cannot join only the netns

The owner's steer was "start podman inside the sandbox's netns but outside its
mounts". That is **right about mounts and wrong about the userns**, and the
kernel decides, not podman.

An unprivileged process cannot create a bare netns (`CapEff: 0` here). It must
create one *together with* a userns U, and U then owns N. Joining N afterwards
needs `CAP_SYS_ADMIN` **in U**, which a process in U's parent does not have.
This is exactly why pasta is already passed `--userns` alongside `--netns`.

So the achievable shape is **join U + N, keep the host's uid, cgroup, and a
private copy of the host's mount tree**:

```
$ unshare --user --map-auto --map-root-user --cgroup --mount --propagation private -- podman info
rootless=false driver=overlay oci=runc net=netavark          # works

$ # identical, minus --mount:
Error: configure storage: overlay: failed to make mount private: … operation not permitted
```

The engine needs its **own** mount namespace — a private copy of the *host's*,
never bwrap's. Storage paths stay exactly where they are, which is the useful
half of the owner's idea and the reason no storage exception is needed.

`--propagation private` is load-bearing twice: for overlay, and to stop podman's
per-container nsfs binds (`/run/user/1000/netns/netns-<uuid>`) propagating to the
host, where they would pin netns objects with no process attached. Verified: the
bind exists in the engine's `mountinfo`, and the host's `/run/user/1000/netns/`
stayed empty.

## 2. The inversion works

snug creates U+N first; pasta, the engine and bwrap all join it.

**pasta attaches unchanged.** `--netns /proc/$PID/ns/net --userns /proc/$PID/ns/user`
plus the existing closing set. **No change to `PastaArgs` is needed.**

```
STAGE pid=1169846 netns=net:[4026532441] userns=user:[4026532418]
OUTSIDE: pasta pid=1169859 alive=yes
    2: snug0    inet 192.168.1.120/24
curl: 200
```

**Container network follows N, both directions** — this is the whole point:

```
N offline (no pasta):   CONTAINER-RAN  eth0 10.88.0.3/16  wget: bad address  NET-NO
N with pasta:           CONTAINER-RAN  <!doctype html>…                      NET-YES
```

**Host loopback stays closed from N and from inside a container**, with a
positive control on the host listener:

```
HOST control 127.0.0.1:18099            -> 200
IN-N  127.0.0.1 / gateway               -> REFUSED
CTR   127.0.0.1 / 10.88.0.1 / 192.168.1.120 -> REFUSED
CTR   internet control                  -> REACHED
```

**The bonus DESIGN promised is real** — published ports land on N's loopback:

```
IN-N curl 127.0.0.1:18080  -> HELLO-FROM-CONTAINER
HOST curl 127.0.0.1:18080  -> REFUSED
HOST curl 192.168.1.120:18080 -> REFUSED
```

**Nested pasta — the load-bearing unknown — does not break.** `pasta` inside
`pasta` works; `--network=none` works; offline N degrades gracefully in every
mode (containers run, they have no route). Throughput: host 41.3 MB/s, in-N
29–38 MB/s, container-in-N ≈37 MB/s.

**The proxy does not have to move.** The engine's socket is a *pathname*
AF_UNIX socket — only abstract sockets are netns-scoped — so snug on the host
talks to it directly across the namespace boundary. Verified with `_ping` and
`/version` over the socket from the host.

## 3. What it costs, and where it does not work

**Distrobox — the decisive negative.** `/usr/bin/podman` is
`distrobox-host-exec`, which forwards over a **filesystem** socket. A network
namespace does not touch that at all:

```
$ unshare --user --map-root-user --net -- sh -c 'ip -o link | wc -l; podman info'
ifaces: 1                       # lo only, no route out
engine-hostname=zelva store=/home/michal/.local/share/containers/storage
```

From a netns with no route, the shim reached the **host's** engine. So on a
distrobox host, topology A puts a *shim* in N, the engine stays on the host, and
the guarantee evaporates while everything looks like it worked. `podmanClientUsable()`
in `cmd/snug/podmanshim.go` already performs exactly this detection and is
currently used only for a cosmetic warning. It must become a **hard refusal**,
with a test — per the standing rule that a documented-but-unchecked gate is not
a gate.

**Full subuid delegation is structurally required.** A single-uid map fails:

```
… potentially insufficient UIDs or GIDs available in user namespace
  (requested 0:42 for /etc/shadow): Check /etc/subuid and /etc/subgid
```

`--storage-opt ignore_chown_errors=true` gets past storage and no further —
`devpts` then fails, because it needs gid 5 mapped. There is no rootless path
around it. Preflight: `unshare --user --map-auto --map-root-user -- true`, plus
`newuidmap`/`newgidmap` present **with file capabilities** (not setuid).

**Cgroup delegation is a second host-shaped failure.** On this box
`/proc/self/cgroup` reads `0::/../../app.slice/…` — outside the cgroup-ns root —
so `podman info` fails and an API-created container fails at start. Not caused
by N (the CLI works with `--cgroups=disabled --runtime crun`), but it means the
preflight must cover it and that the runtime/cgroup-manager choice can no longer
be "whatever `containers.conf` says".

**`$XDG_RUNTIME_DIR` gets masked.** Root-in-userns podman needs writable
`/run/lock` and `/var/cache`; `/run/lock` does not exist in this image, forcing
`mount -t tmpfs tmpfs /run`, which hides `$XDG_RUNTIME_DIR`. The engine socket
therefore **cannot** live under `/run/user/<uid>` as §8.1 specifies. Move it to
`/tmp/snug-<uid>-<runid>/`.

**The host uid must be carried explicitly.** `--uid 1000` still produces
host-uid-1000 files, but inside the stage `os.Getuid()` returns 0. If snug
re-execs itself, the host uid must be passed, or the sandbox becomes root-shaped.

## 4. Two guarantees change shape

**Teardown is no longer unconditional.** DESIGN §4.3 says orphan netns leaks are
"impossible by construction" — true today, because N dies with bwrap. Under
topology A, N holds the engine and the containers, so N lives as long as the
engine does. Measured under `Pdeathsig: SIGKILL`:

```
stage, pasta   -> dead (Pdeathsig fired)
podman, conmon -> ALIVE, ppid=9242
```

conmon **double-forks by design** and reparents out of snug's tree. There is
still no persistent kernel reference (host `/run/user/1000/netns/` stayed
empty), so N is reaped when the last member exits — but the guarantee is now
*conditional on the engine being reaped*, which `lifeline.go`, `reaper.go` and
`reap.go` already do. `reap.go`'s sweep should additionally assert N is gone,
matching on the store path and **never on `comm`** (the `pasta.avx2` lesson).

**Sandbox and containers become network peers.** Not an escalation — both sides
are untrusted-equal and the host is still excluded — but it must be stated:

```
CONTAINER -> 10.88.0.1:9999 (sandbox service on 0.0.0.0) : REACHED
CONTAINER -> 127.0.0.1:9999                              : UNREACHABLE
```

Two things checked that do **not** open: `ss -xl` in N with the engine running
shows **zero** abstract sockets, and the sandbox's own pidns shows 5 processes —
the engine is invisible to it. Both belong in tests.

No capability change for the payload: bwrap already drops caps, so the sandbox
cannot `ip link add` today either. The marginal gain is that N is owned by an
*ancestor* userns, so even a hypothetical regained-caps path cannot reconfigure it.

## 5. Proposed shape — two stages

**M-a, now, one line.** `[profile.podman-socket] include = [… , "net"]`. Stops
`--dry-run` lying today. Independent of everything below.

*Note the tension, which is the owner's call:* this makes `@podman-socket` imply
egress, which is honest about today's behaviour but grants the sandbox itself
network it did not ask for. The alternative is to keep the profile as-is and fix
only the `--dry-run` text. Under M-b, `include = ["net"]` becomes **wrong** and
must be removed again, because then `@net` genuinely implies nothing extra and
offline goes back to being the absence of a profile.

**M-b, the engine in the sandbox's netns.**

1. **Preflight, all fatal, each naming its fix**, before anything starts: real
   podman binary (`podmanClientUsable`, promoted from warning to refusal);
   `unshare --user --map-auto --map-root-user -- true`; `newuidmap`/`newgidmap`
   with caps; a cgroup write probe. **Refuse — never fall back to today's
   topology**, because the difference is invisible to the user.
2. `snug __netns-stage` re-exec: `CLONE_NEWUSER` (full map) + `CLONE_NEWNET` +
   `CLONE_NEWCGROUP` + `CLONE_NEWNS` with `MS_REC|MS_PRIVATE` on `/`; tmpfs on
   `/run` and `/var/cache`; `lo` up; assert
   `readlink /proc/self/ns/net != /proc/<parent>/ns/net` before proceeding.
3. Engine socket out of `$XDG_RUNTIME_DIR` (masked) into `/tmp/snug-<uid>-<runid>/`.
   Proxy stays on the host, unchanged.
4. pasta: unchanged argv, aimed at the stage's pid instead of bwrap's.
5. bwrap: `--unshare-all --share-net`, entered via the stage. Carry the **host**
   uid explicitly. The `--json-status-fd`/`--block-fd` handshake is unnecessary
   on this path (N exists before bwrap, so there is no race to lose); topology B
   keeps it.
6. `--dry-run` renders the topology: which process owns the netns, and that
   containers share it.

**The abuse sentence changes shape rather than shrinking:**

> a hostile process inside the sandbox can run arbitrary code in a container that
> shares the sandbox's network namespace — so it reaches exactly what the sandbox
> reaches, no more: with `@net`, the whole internet, as the sandbox already
> could; without `@net`, nothing. It can also publish a port onto the sandbox's
> loopback, and any container it starts can connect to services the sandbox binds
> on all interfaces. It cannot reach the host's loopback, the host's containers,
> or the host's images.

**Integration test — five assertions, each with a positive control:**
(a) `@podman-socket` without `@net` → container `wget` fails, **while** the same
container succeeds with `@net`; (b) a host listener answers on the host and is
refused from the sandbox **and** from a container; (c) `podman run -p N:80` is
reachable from the sandbox; (d) **adjacent, still closed** — the same published
port is refused *from the host*; (e) `ss -xl` in the sandbox reports zero
abstract sockets with the engine running. Plus a leak test that SIGKILLs snug
and asserts N is gone, matching on the store path.
