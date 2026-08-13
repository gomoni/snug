# A real container engine on this host

Provisioning, 2026-08-12, by `host-bridge`. Every claim below is tagged
**MEASURED** (a command was executed and its output is quoted) or **INFERRED**
(reasoning from a measurement, not itself run). Nothing is quoted from memory.

## 0. What this is and what it is not

The supervisor implementation plan — a working document held outside version
control, so do not go looking for it in a clone — makes Phase 0a the kill gate
on the engine leg, and 0a has
never been run because `/usr/bin/podman` on this host is a distrobox shim. This
document removes that excuse: **a real, local, rootless container engine now
runs here, and one command line invokes it.**

It deliberately stops there. The three Phase 0a questions — engine in a mount
view derived from the sandbox's, container gets N's network *under the stage's
topology*, teardown with a real engine — are **not answered here**. They need
`poc/nsd/stage.go`, which is being rewritten in parallel. What this document
provides is the *positive control* those questions need: a known-good reading
from before the stage is involved, so that a red result in 0a proper can be told
apart from "the engine never worked on this box".

Nothing under `poc/`, `internal/` or `cmd/` was touched.

## 1. The artifact, pinned

| | |
|---|---|
| project | `mgoltzsche/podman-static` |
| version | **`v5.8.4`**, published 2026-06-26 (this was also `latest` on the day; the tag is what is pinned, not the alias) |
| url | `https://github.com/mgoltzsche/podman-static/releases/download/v5.8.4/podman-linux-amd64.tar.gz` |
| size | 33 784 113 bytes |
| sha256 | `a58765fe8be6ab3fb79f892f1a027b4ce4a7e8eb589df1ef960c167cbde08d69` |

**Integrity: verified, with one honest caveat.** MEASURED — the release ships a
detached OpenPGP signature and it checks out:

```
$ gpg --recv-keys 0CCF102C4F95D89E583FF1D4F8B5AF50344BB503
gpg: key F8B5AF50344BB503: public key "Max Goltzsche" imported

$ gpg --batch --verify podman-linux-amd64.tar.gz.asc podman-linux-amd64.tar.gz
gpg: Signature made Sat 27 Jun 2026 01:16:34 AM CEST
gpg:                using RSA key 6E8EF2F5B1F26FF78431E3D1364FA5A62B410BA4
gpg: Good signature from "Max Goltzsche" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
```

The signing subkey `6E8E…0BA4` belongs to the primary key `0CCF…B503`, which is
the fingerprint the project's own `README.md` at tag `v5.8.4` tells you to
fetch. **That is circular and should be read as such**: the fingerprint and the
artifact come from the same GitHub account, so what the signature actually
proves is that the tarball was produced by whoever controlled that key — not
that the key is the right one. There is no third-party attestation and no
published checksums file. The sha256 above is ours, computed locally, and is
what makes the artifact identifiable later; it is the strongest claim available
and it is a reproducibility claim, not a trust one.

The `.asc` is kept next to the install at
`~/.local/opt/podman-static/podman-linux-amd64.tar.gz.asc`, alongside a
`PROVENANCE` file carrying the table above.

## 2. What the bundle contains

MEASURED — `tar -tzvf`, then `--version` on each binary after extraction. The
plan's claim holds in full, `conmon` included:

| binary | path inside the bundle | version |
|---|---|---|
| `podman` | `usr/local/bin/podman` | 5.8.4 |
| `crun` | `usr/local/bin/crun` | 1.28 |
| `runc` | `usr/local/bin/runc` | 1.4.3 |
| **`conmon`** | `usr/local/lib/podman/conmon` | **2.2.1** |
| `netavark` | `usr/local/lib/podman/netavark` | 1.17.2 |
| `aardvark-dns` | `usr/local/lib/podman/aardvark-dns` | 1.17.1 |
| `pasta` (+ `pasta.avx2`) | `usr/local/bin/pasta` | 2026_06_11.a9c61ff |
| `fuse-overlayfs` (+ `fusermount3`) | `usr/local/bin/fuse-overlayfs` | 1.16 |
| `catatonit` | `usr/local/lib/podman/catatonit` | (runs; reports as `podman-init`) |
| `rootlessport`, `quadlet` | `usr/local/lib/podman/`, `usr/local/libexec/podman/` | — |

Note the layout differs from the plan's prose: `conmon`, `netavark`,
`aardvark-dns`, `catatonit` and `rootlessport` are under `usr/local/lib/podman`,
**not** `libexec`. Anything that hard-codes `libexec` will find an empty
directory and a working `quadlet`.

MEASURED — everything is genuinely static:

```
$ file usr/local/bin/podman usr/local/lib/podman/conmon    # BuildID/SYSV trimmed
podman: ELF 64-bit LSB executable, x86-64, statically linked, stripped
conmon: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

`conmon` being present is the reason this bundle was chosen over `dockerd`:
Phase 0a's third question is a question about podman's fork-exec process model,
and ENGINE-NETNS §4 measured `conmon` *surviving* a Pdeathsig teardown. A bundle
without `conmon` cannot ask it.

## 3. Install layout

Plain extraction into `$HOME`. No root, no package manager, no `/usr`, no
argument with distrobox over `/usr/bin/podman`.

```
mkdir -p ~/.local/opt/podman-static
tar -xzf podman-linux-amd64.tar.gz -C ~/.local/opt/podman-static --strip-components=1
```

```
~/.local/opt/podman-static/
  PROVENANCE                     version, url, size, sha256, signature result
  podman-linux-amd64.tar.gz.asc  the detached signature, kept
  README.md  usr/  etc/containers/     THE BUNDLE, exactly as shipped
  bin/snug-podman                 snug's: the one command line (§5)
  bin/snug-podman-ns              snug's: the same, inside a userns+cgroupns
  bin/snug-podman-baseline        snug's: the §7 harness, `… {offline|pasta}`
  etc/snug/                       snug's: containers.conf, storage.conf,
                                  registries.conf, policy.json
  home/.config/containers/policy.json   snug's: see §5, the HOME trick
  var/lib/containers/storage      the private image store
  var/etc/{networks,hooks.d}      network config, empty hooks dir
```

**No existing host file was modified or overwritten.** MEASURED before writing:
`~/.local/opt` did not exist; `~/.config/containers/` exists and holds
`registries.conf`, `podman/` and `systemd/`, all left untouched;
`/etc/containers/` holds only empty drop-in directories and **no `policy.json`**;
`~/.config/containers/policy.json` does **not** exist and was **not** created.
Everything snug wrote lives under `~/.local/opt/podman-static`, plus a runtime
directory `/tmp/snug-podman-static/` (§5).

## 4. Which helper binaries, and why

The plan's observation that this host already has correct helpers is true, and
the interesting part is that the versions do **not** line up.

MEASURED:

| helper | host | bundle |
|---|---|---|
| `podman` | 6.0.2 (via the distrobox shim, i.e. the *host's* engine) | 5.8.4 |
| `conmon` | 2.2.1 (`/usr/bin/conmon`) | 2.2.1 |
| `crun` | version **UNKNOWN** (openSUSE build reports no version string) | 1.28 |
| `runc` | 1.4.3 | 1.4.3 |
| `netavark` | **2.0.0** | 1.17.2 |
| `aardvark-dns` | **2.0.0** | 1.17.1 |
| `pasta` | 20260612.a9c61ff-1.2 | 2026_06_11.a9c61ff |

**Both combinations run.** MEASURED — the ENGINE-NETNS §2 offline baseline (§7)
was executed twice, once with `helper_binaries_dir`/`conmon_path`/`runtimes`
pointing at the bundle and once pointing at `/usr/libexec/podman`, `/usr/bin/conmon`,
`/usr/bin/crun`. Both produced `CONTAINER-RAN` and `NET-NO`. So mixing is not
*broken* here today.

**The bundle set was chosen anyway, for three reasons, two of them measured.**

1. *Version skew is real and unbounded* (MEASURED). The host's `netavark` and
   `aardvark-dns` are **2.0.0**, a major version ahead of the 1.17.x that podman
   5.8.4 was built and tested against. It works for the one thing the baseline
   exercises — a bridge network with no DNS names — and that is a very small
   sample of the netavark surface. A helper one major version out is exactly the
   kind of thing that produces a *confusing* Phase 0a result rather than a clean
   red, which is the failure mode this whole exercise exists to avoid.
2. *`/usr/bin/crun` reports no version* (MEASURED: `crun version UNKNOWN`).
   Recording "which runtime produced this measurement" is not optional for the
   engine leg, and a runtime that cannot say what it is cannot be recorded.
3. *CI needs the same artifact* (INFERRED, and it is the plan's own argument).
   A result that depends on `/usr/libexec/podman` is a property of one
   developer's laptop.

MEASURED — the pinning is real, not aspirational. With a container running,
`ps` shows every helper resolved inside the bundle:

```
$ ps -eo pid,ppid,args | grep <container-id>
87244  8553 /home/michal/.local/opt/podman-static/usr/local/lib/podman/conmon
             --api-version 1 -c 0bc316b0… -r /home/michal/.local/opt/podman-static/usr/local/bin/crun …

$ pgrep -a -f podman-static/usr/local          # pids and argv only, no ppid
87229 /home/michal/.local/opt/podman-static/usr/local/bin/fuse-overlayfs -o lowerdir=…
87238 /home/michal/.local/opt/podman-static/usr/local/bin/pasta --config-net --dns-forward
      169.254.1.1 -t none -u none -T none -U none --no-map-gw --quiet --netns …
87244 /home/michal/.local/opt/podman-static/usr/local/lib/podman/conmon …
```

Two host paths leaked in at first and were closed, both found by reading
`podman info` rather than by anything failing:

- `seccompProfilePath: /usr/share/containers/seccomp.json` — the host's, present
  only because the distro `podman` package is installed. Now pinned to the
  bundle's own `etc/containers/seccomp.json`. MEASURED before and after.
- `hooks_dir` defaulted to `/usr/share/containers/oci/hooks.d` — arbitrary
  host-supplied code the bundle did not ship. Now an empty directory we own.

MEASURED after both fixes — `podman info` mentions no host path at all; every
`/usr/` in its output is `…/podman-static/usr/local/…`.

## 5. How to invoke it

**The single command line, for anything that runs a container:**

```
~/.local/opt/podman-static/bin/snug-podman run --rm docker.io/library/alpine:3.20 echo hi
```

The wrapper is nine lines and sets four variables:

```sh
CONTAINERS_CONF="$ROOT/etc/snug/containers.conf"
CONTAINERS_STORAGE_CONF="$ROOT/etc/snug/storage.conf"
CONTAINERS_REGISTRIES_CONF="$ROOT/etc/snug/registries.conf"
HOME="$ROOT/home"
exec "$ROOT/usr/local/bin/podman" "$@"
```

It puts **nothing on `PATH`** — helper lookup is pinned in `containers.conf`, so
the distrobox shim at `/usr/bin/podman` can never be picked up by accident. This
is the same reasoning as `policy.StagedBinDir`: the environment we hand over must
not ship the wrong binary pre-installed.

`HOME` deserves an explanation, because it looks like a hack and is one, with a
reason. MEASURED: podman 5.8.4 has **no `--signature-policy` flag** (`Error:
unknown flag`), and containers/image looks for a signature policy at exactly two
paths:

```
Error: no policy.json file found at any of the following:
  "/home/michal/.config/containers/policy.json", "/etc/containers/policy.json"
```

Neither exists on this host — openSUSE ships `/usr/share/containers/policy.json`,
which the upstream static build does not know about — and creating either would
be writing into host config that the user's own podman, skopeo and buildah read.
So the engine is given a `HOME` of its own containing precisely one file. There
is no `CONTAINERS_POLICY_JSON`; this is the only lever available.

**Storage and runtime paths.** MEASURED and load-bearing: this development
environment is a rootless distrobox whose `/run/.containerenv` says
`graphRootMounted=1`, i.e. `~/.local/share/containers/storage` **is the host
engine's store, bind-mounted in**. Two engines sharing one store is a locking and
layer-ownership hazard and would put the user's real images at risk, so:

- `graphroot = ~/.local/opt/podman-static/var/lib/containers/storage`
- `runroot   = /tmp/snug-podman-static/run`
- `tmp_dir   = /tmp/snug-podman-static/tmp`

`runroot` is under `/tmp` and not under `$XDG_RUNTIME_DIR` for the reason
ENGINE-NETNS §3 already recorded: an engine that believes it is root needs a
writable `/run/lock`, which forces a tmpfs over `/run`, which masks
`$XDG_RUNTIME_DIR`. MEASURED consequence of getting this wrong — libpod records
the runroot in its database and refuses to start against a different one:

```
Error: database run root "/run/user/1000/snug-podman-static" does not match
our run root "/tmp/snug-podman-static/run": database configuration mismatch
```

One runroot serving both invocation modes is what makes that error impossible.

### 5.1 The second wrapper, and why there has to be one

`bin/snug-podman-ns` runs the same engine inside a fresh
userns + cgroupns + mountns. It exists for one reason, and it is a host defect
rather than a bundle defect.

MEASURED — on this host `/proc/self/cgroup` reads

```
0::/../../app.slice/app-tmux.slice/tmux-spawn-36fb3bf1-….scope
```

The shell sits in a cgroup **above** the distrobox's cgroup-namespace root, so
podman resolves the controller file to a path that does not exist:

```
$ ~/.local/opt/podman-static/bin/snug-podman info
Error: getting host info: getting available cgroup controllers: failed while
reading controllers for cgroup v2: open /sys/app.slice/app-tmux.slice/
tmux-spawn-….scope/cgroup.controllers: no such file or directory
```

This is ENGINE-NETNS §3's "cgroup delegation is a second host-shaped failure",
reproduced exactly. It is **not** caused by the bundle: MEASURED, the distrobox
shim `/usr/bin/podman` — which reaches the host's podman 6.0.2 outside the
container — fails the same way on the same call, just with the host session's
cgroup path.

The fix is a cgroup namespace, which makes that path `/`. A cgroup namespace
needs `CAP_SYS_ADMIN`, which needs a user namespace, and here the chain forces
a choice that is worth writing down because the obvious option is the wrong one:

- `unshare --user --map-current-user --cgroup` keeps uid 1000 and gives a
  cgroupns — and **breaks podman**, MEASURED, because podman then cannot build
  its own userns: `running /usr/bin/newuidmap …: write to uid_map failed:
  Operation not permitted`. The subuids are not mapped in the intermediate
  namespace, so they cannot be delegated out of it.
- `unshare --user --map-auto --map-root-user --cgroup` maps the full subuid
  range, so podman needs no `newuidmap` of its own. It works — and it makes
  podman believe it is root (`rootless: false`), which needs `/run/lock`, hence
  `--mount --propagation private` plus a tmpfs on `/run`, hence a recreated
  empty `$XDG_RUNTIME_DIR` (MEASURED: without it, `creating network namespace
  …: lstat /run/user: no such file or directory`).

So `snug-podman-ns` is:

```
unshare --user --map-auto --map-root-user --cgroup --mount --propagation private
  -- sh -c 'mount -t tmpfs tmpfs /run
            mkdir -p /run/lock "$XDG_RUNTIME_DIR"
            exec .../bin/snug-podman "$@"'
```

which is ENGINE-NETNS §1's recipe with two additions that §1 did not need
because it never got as far as starting a container.

**Which wrapper to use.** MEASURED, both directions:

| | `snug-podman` (uid 1000) | `snug-podman-ns` |
|---|---|---|
| `podman version` | works | works |
| `podman info` | **fails** (cgroup path) | works |
| `podman run` | works, with and without `--cgroups=disabled` | needs `--cgroups=disabled` |
| `podman run` with bridge/netavark | n/a (uses pasta) | **fails** unless the unshare also has `--net` |
| reports | `rootless: true` | `rootless: false` |

Use `snug-podman` for running things; use `snug-podman-ns` when you need
`podman info`, or when you are building a stage that owns its own netns.

## 6. Proof that this is a real, local, rootless engine

**It is local, not a client talking to someone else's socket.** MEASURED:

```
$ ~/.local/opt/podman-static/bin/snug-podman-ns info | grep -E \
    'serviceIsRemote|rootless:|databaseBackend|cgroupManager|cgroupVersion|networkBackend:|graphDriverName|graphRoot:|configFile:|seccompProfilePath|Backing Filesystem'
  cgroupManager: cgroupfs
  cgroupVersion: v2
  databaseBackend: sqlite
  networkBackend: netavark
    rootless: false
    seccompProfilePath: /home/michal/.local/opt/podman-static/etc/containers/seccomp.json
  serviceIsRemote: false
  configFile: /home/michal/.local/opt/podman-static/etc/snug/storage.conf
  graphDriverName: overlay
  graphRoot: /home/michal/.local/opt/podman-static/var/lib/containers/storage
    Backing Filesystem: btrfs
```

and, from the same `podman info`, the helper block in full:

```
  conmon:
    path: /home/michal/.local/opt/podman-static/usr/local/lib/podman/conmon
    version: 'conmon version 2.2.1, commit: c8cc2c4db27531bd4e084ce7857f73cd21ee639d'
  ociRuntime:
    name: crun
    path: /home/michal/.local/opt/podman-static/usr/local/bin/crun
    version: crun version 1.28
  networkBackendInfo:
    backend: netavark
    path: /home/michal/.local/opt/podman-static/usr/local/lib/podman/netavark
    version: netavark 1.17.2
    dns:
      path: /home/michal/.local/opt/podman-static/usr/local/lib/podman/aardvark-dns
      version: aardvark-dns 1.17.1
  pasta:
    executable: /home/michal/.local/opt/podman-static/usr/local/bin/pasta
    version: pasta 2026_06_11.a9c61ff
```

**The contrast that makes "local" mean something** (MEASURED, the negative
control for this claim): the host's `/usr/bin/podman` is
`/usr/bin/distrobox-host-exec`, a shell script, and it answers as a *different*
engine with a *different* image store:

```
$ /usr/bin/podman version | head -3          $ snug-podman version | head -3
Client:       Podman Engine                  Client:       Podman Engine
Version:      6.0.2                          Version:      5.8.4
API Version:  6.0.2                          API Version:  5.8.4

$ /usr/bin/podman images | head -3           $ snug-podman images
localhost/sectest:1                          REPOSITORY                TAG
localhost/outtest:1                          docker.io/library/alpine  3.20
docker.io/minidocks/poppler:latest
```

Different version, different store, different image list. The bundle is not
talking to the host engine.

**A container starts and produces output.** MEASURED:

```
$ ~/.local/opt/podman-static/bin/snug-podman run --rm \
    docker.io/library/alpine:3.20 \
    sh -c 'echo CONTAINER-RAN-PLAIN; id -u; wget -q -O- -T 8 https://example.com | head -c 60'
Trying to pull docker.io/library/alpine:3.20...
Getting image source signatures
Copying blob sha256:25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471
Writing manifest to image destination
CONTAINER-RAN-PLAIN
0
<!doctype html><html lang="en"><head><title>Example Domain</
```

`--init` also resolves to the bundle's `catatonit` (MEASURED: `podman run --init
… cat /proc/1/comm` prints `podman-init`).

**It is rootless — no sudo, anywhere.** MEASURED: `id` reports
`uid=1000(michal)`; `/proc/self/status` reports `CapEff: 0000000000000000`; no
command in this document was run under `sudo` and no `sudo` is present in either
wrapper. The only privileged component is the uid delegation, which is §8.

## 7. The ENGINE-NETNS §2 baseline, reproduced

ENGINE-NETNS §2 measured, with plain `unshare`, that a container gets the network
namespace the engine was started in:

```
N offline (no pasta):   CONTAINER-RAN  eth0 10.88.0.3/16  wget: bad address  NET-NO
N with pasta:           CONTAINER-RAN  <!doctype html>…                      NET-YES
```

Reproduced with this engine, MEASURED. The harness is kept at
`~/.local/opt/podman-static/bin/snug-podman-baseline` and takes one argument,
`offline` or `pasta`; both rows below were re-run from that copy and reproduced.
It creates U+N with
`unshare --user --map-auto --map-root-user --cgroup --net --mount --propagation
private`, brings `lo` up, and — in the `pasta` case only — has the *parent*
attach pasta from outside the namespace with snug's closing set
(`--map-host-loopback none -t none -u none -T none -U none`) before the engine
starts.

**Row 1 — N offline** (verbatim, except that `valid_lft forever preferred_lft
forever` is trimmed from each address line):

```
STAGE pid=81765 netns=net:[4026532924] userns=user:[4026532919] uid=0
STAGE-LINKS: 1
OUTSIDE: stage job=81765 using pid=81765 netns=net:[4026532924]
OUTSIDE: my netns=net:[4026531833]
STAGE-ADDR: 1: lo    inet 127.0.0.1/8 scope host lo|
CONTAINER-RAN
CTR-ADDR: 1: lo inet 127.0.0.1/8|2: eth0 inet 10.88.0.4/16 brd 10.88.255.255|
NET-NO
STAGE EXIT=0
```

**Row 2 — pasta attached from outside:**

```
PASTA:     assign: 192.168.1.120   mask: 255.255.255.0   router: 192.168.1.1
OUTSIDE: pasta pid=83366 alive=yes
STAGE-ADDR: 1: lo inet 127.0.0.1/8|2: wlp3s0 inet 192.168.1.120/24|
CONTAINER-RAN
CTR-ADDR: 1: lo inet 127.0.0.1/8|2: eth0 inet 10.88.0.5/16 brd 10.88.255.255|
NET-YES
STAGE EXIT=0
```

Four things this establishes, and one it does not.

- **The engine is in a netns of its own.** `OUTSIDE: my netns=net:[4026531833]`
  against `STAGE …netns=net:[4026532924]` — different inodes, printed in the
  same run. Without that line "the container had no network" would be
  indistinguishable from a broken engine.
- **`CONTAINER-RAN` is the positive control for `NET-NO`.** The container
  demonstrably started and demonstrably had an address (`eth0 10.88.0.4/16`); it
  simply had nowhere to send packets.
- **The internet was up while `NET-NO` was measured.** Second positive control,
  MEASURED on the host at the same time: `curl -s -o /dev/null -w '%{http_code}'
  https://example.com` → `200`.
- **pasta attaches from outside the namespaces it configures**, using
  `--netns /proc/$PID/ns/net --userns /proc/$PID/ns/user` and unmodified snug
  flags — confirming ENGINE-NETNS §2's "no change to `PastaArgs` is needed", now
  against the bundle rather than the host engine.
- **It does not answer Phase 0a's second question.** This is `unshare`, not the
  supervisor's stage, and the mount view is a plain private copy of the host's,
  not one derived from the sandbox's. It is the *control*, not the experiment.

Incidental but relevant to Phase 0a's third question, and offered as an
observation rather than an answer (MEASURED): with a detached container running
under the plain wrapper, `conmon` had **ppid 8553** — the distrobox's own
`conmon`, not the shell that started it. The bundle's `conmon` 2.2.1 double-forks
and reparents out of the caller's process tree exactly as ENGINE-NETNS §4
described. Whether that survives a Pdeathsig teardown is question 3 and is not
measured here.

Cleanup after every run in this document (MEASURED): `podman ps -a` empty, no
`pasta`/`conmon`/`fuse-overlayfs` process with a `podman-static` path alive, and
the host's `/run/user/1000/netns/` empty — which also confirms §1's claim that
`--propagation private` keeps the per-container netns binds off the host.

## 8. The `uidmap` dependency, stated separately because it is the exception

The plan's sentence — *the engine can be shipped statically, the privilege
delegation cannot* — is exactly right, and MEASURED here.

```
$ env PATH=/nonexistent /usr/bin/unshare --user --map-auto --map-root-user -- /bin/true
unshare: failed to execute newuidmap: No such file or directory        (exit 127)

$ env PATH=/nonexistent /usr/bin/unshare --user --map-root-user -- /bin/true
                                                                       (exit 0)
```

A single-uid map needs nothing; the full subuid map needs `newuidmap`, and
`newuidmap` is a host binary the tarball cannot replace.

**Present and working for this user.** MEASURED:

```
$ ls -l /usr/bin/newuidmap /usr/bin/newgidmap
-rwxr-xr-x. 1 root root 41712 May  5 12:38 /usr/bin/newgidmap
-rwxr-xr-x. 1 root root 41712 May  5 12:38 /usr/bin/newuidmap        # NOT setuid

security.capability xattr, decoded:
  /usr/bin/newuidmap: rev=3 effective=True permitted=[CAP_SETUID] rootid=1000
  /usr/bin/newgidmap: rev=3 effective=True permitted=[CAP_SETGID] rootid=1000

$ grep ^michal: /etc/subuid /etc/subgid
/etc/subuid:michal:1001:64535
/etc/subgid:michal:1001:64535

$ unshare --user --map-auto --map-root-user -- cat /proc/self/uid_map
         0       1000          1
         1       1001      64534
```

File capabilities, not setuid — which is what the plan's preflight is supposed to
check for, and it holds here. Two details worth carrying forward:

- **`rootid=1000` means these are *namespaced* (v3) file capabilities.** They are
  effective only inside a user namespace owned by host uid 1000, which is this
  distrobox. On a plain host or a CI runner they would be v2 with no rootid. A
  preflight that merely asserts "has file caps" is right in both cases; one that
  asserts a specific encoding will be wrong on one of them.
- **The range is 64535 ids starting at 1001, not the conventional 65536 starting
  at 100000.** INFERRED, not measured: an image whose files are owned above
  uid 64534 will fail to `chown` in this store. Nothing in this document used
  such an image; if a future 0a measurement produces a `chown` error in the
  64534–65535 region, this is the first thing to look at, not a bug in the stage.

## 9. What did not work

Stated plainly, because a half-working engine described as working costs a day
when Phase 0a returns something confusing.

1. **`podman info` does not work under the plain wrapper.** MEASURED, §5.1. The
   host's cgroup layout, not the bundle. Use `snug-podman-ns` when you need
   `info`. **A script that shells out to `podman info` as a health check will
   report this engine as broken.**
2. **Inside a userns+cgroupns stage, `podman run` needs `--cgroups=disabled`.**
   MEASURED, reproducibly:
   ```
   Error: crun: write to `/sys/fs/cgroup/libpod_parent/libpod-<id>/cgroup.procs`:
   No such file or directory: OCI runtime attempted to invoke a command that was not found
   ```
   `/sys/fs/cgroup` in that mount namespace is still the distrobox's cgroup root
   from the *old* cgroup namespace, so the path podman computes and the path the
   mount exposes disagree. This matches ENGINE-NETNS §3's note that the
   runtime/cgroup-manager choice "can no longer be whatever `containers.conf`
   says". **Phase 0a will hit this**; it is a host property, not a stage bug.
3. **Bridge/netavark networking fails if the stage has no netns of its own.**
   MEASURED: `Error: netavark: setns: IO error: Operation not permitted (os error 1)`
   for `snug-podman-ns run` without `--net` in the unshare. Expected — netavark
   is being asked to reconfigure a namespace nobody in that chain owns — but it
   is an unhelpful error message and will cost time if not recognised.
4. **`unshare --user --map-current-user --cgroup` is a dead end.** MEASURED, §5.1.
   The tempting "keep uid 1000, just add a cgroupns" shape breaks podman's own
   `newuidmap`.
5. **`podman system reset` does not fully empty the store.** MEASURED:
   `rm: cannot remove '…/storage/overlay': Device or resource busy`. A
   `fuse-overlayfs` mount survives inside the rootless mount namespace. The
   images and containers *are* removed; the directory is not. Harmless here,
   but a CI job that asserts "store directory gone" will flake.
6. **podman 5.8.4 has no `--signature-policy`.** MEASURED. Worked around with a
   private `HOME` (§5). If a future bundle changes where it looks for
   `policy.json`, this breaks with a message about signatures rather than about
   `HOME`.
7. **A tmpfs on `/run` hides `$XDG_RUNTIME_DIR` and podman still reads it.**
   MEASURED: `creating network namespace for container …: lstat /run/user: no
   such file or directory`. ENGINE-NETNS §3 predicted the masking; the specific
   consequence for netns placement is new.
8. **The libpod database pins the runroot.** MEASURED, §5. Changing it between
   invocation modes is a hard error, so both wrappers must agree on it forever.
9. **Not attempted, deliberately:** anything under `poc/nsd/`, the derived mount
   view, `snug`'s own integration with this engine, and all three Phase 0a
   questions.

## 10. What this means for CI

INFERRED except where marked; nothing in this section was executed on a runner.

- **The artifact is the answer, and it is now pinned rather than floating.** URL,
  size and sha256 in §1 are enough for a CI step to fetch and verify without
  trusting `latest`. Verifying the signature in CI would need the maintainer's
  key pinned in the workflow — worth doing, and no worse than the sha256, which
  at least fails closed on a re-cut release.
- **The AppArmor blocker is already cleared** (MEASURED by reading the file):
  `.github/workflows/ci.yml` line 118 sets
  `kernel.apparmor_restrict_unprivileged_userns=0` in the integration job, which
  is precisely the `ubuntu-latest` restriction the bundle's README warns about.
- **CI must still `apt-get install uidmap`.** §8 is the reason and it is
  structural: `newuidmap`/`newgidmap` carry file capabilities that root sets at
  install time, and a tarball a user extracts cannot carry them. Every other
  piece of the engine ships in the bundle.
- **The `--cgroups=disabled` and `podman info` problems are probably local to
  this box.** They come from `/proc/self/cgroup` reading outside the cgroup-ns
  root, which is a distrobox-plus-tmux artifact. A GitHub runner is not in that
  shape. INFERRED — but it means a CI green does not prove the laptop path
  works, and a laptop red does not prove CI is broken. Any 0a result must record
  which of the two it came from.
- **Do not use `/tmp` for `runroot` in CI without checking the runner's `/tmp`.**
  Here it is a 15 GB tmpfs (MEASURED). Elsewhere it may be small or a real disk.
- **The bundle is 33.8 MB compressed and 85 MB extracted** (MEASURED, `du -sh`),
  so it should be cached by version, keyed on the sha256 rather than the tag.

## 11. Answers, short

- **Does a real engine run on this host?** Yes. podman 5.8.4, local
  (`serviceIsRemote: false`), rootless, its own store, its own helpers, no sudo.
- **The command line:**
  ```
  ~/.local/opt/podman-static/bin/snug-podman run --rm docker.io/library/alpine:3.20 echo hi
  ```
  and `~/.local/opt/podman-static/bin/snug-podman-ns` when a cgroup namespace is
  required (`podman info`, or a stage that owns its own netns).
- **What blocks Phase 0a from being measured next?** Nothing on the engine side.
  The remaining blocker is `poc/nsd/stage.go`, which is being rewritten in
  parallel. Two things Phase 0a should carry in from here: pass
  `--cgroups=disabled` to `podman run` inside the stage (§9.2), and give the
  stage its own netns before starting the engine (§9.3).
