# The engine's storage configuration

What pins each part of the container engine's store, and which keys snug's
generated `storage.conf` can and cannot deliver. Measured against podman 5.8.4 and 6.0.2; the two agree except on one row of
§3. 5.8.4 was a pinned static bundle, retired in #384 — the measurements stand,
but the engine is now host-provided and therefore **not pinned**, so any claim
here that depends on a version needs re-measuring rather than trusting.

## 1. The oracle

Questions of the form "did this podman read that configuration" are answered
with an image that exists in exactly one store. Store A holds
`localhost/onlyinstorea:1`, imported from a one-file tarball, so no registry, no
network and no name resolution take part. Store B is empty. The image appears in
`podman images` against store B only if something told podman to read store A.

The oracle produces both outcomes on both engines, in the shape the measurement
uses:

```
control: pinned config names NO extra store          NOT-READ
control: pinned config NAMES store A                 READ
```

Two sharper instruments are used where an effect is not enough.
`--log-level=debug` prints one line per graph-driver option actually handed to
the driver (`overlay: imagestore=…`, `overlay: mount_program=…`) and
`Using graph driver …` / `Using graph root …` for the store. `strace -f -e
trace=openat,newfstatat,statx` names the files a process looks at rather than
their effects.

`podman info` answers neither question. `additionalimagestores` never reaches
`.store.graphOptions` even when it is in force, and on this host `podman info`
fails outright (`getting available cgroup controllers: … cgroup.controllers: no
such file or directory`) where `podman images` succeeds.

Measuring podman on this host takes one precaution: `/usr/bin/podman` is a
symlink to `distrobox-host-exec`, which forwards through `host-spawn`, whose
`-env` flag defaults to `TERM` alone. A variable under test reaches the engine
only if it is named there explicitly, and a measurement taken through that
symlink observes a process with a different environment, a different filesystem
and a different `/tmp`. snug refuses that binary in preflight P1 for the same
reason.

## 2. Which configuration files the engine reads

**`CONTAINERS_STORAGE_CONF` replaces the file set.** With it set, podman reads
the file it names and no other storage configuration — no
`$HOME/.config/containers/storage.conf`, no `$XDG_CONFIG_HOME` one, no
`storage.conf.d` drop-in beside either. With it unset, the home file decides
both the driver and the store.

The discriminator is `driver`, the one key §3 shows surviving `--root`. A
host-side file says `driver = "vfs"` and points `graphroot` at a third store;
the pinned file says neither:

```
var UNSET,   no flags                    driver=[vfs] graphroot=storeC
var = pinned file, no flags              driver=[]    graphroot=storeB
var UNSET,   --root/--runroot            driver=[vfs] graphroot=storeB
var = pinned file, --root/--runroot      driver=[]    graphroot=storeB
```

Row 1 is the control: unset, the host file decides. Row 2 moves both facts to
the pinned file. Rows 3 and 4 add the flags — the store follows them either way,
and `driver`, which they do not carry, still follows the variable. `strace`
agrees by observation: with the variable set, no other `storage.conf` is opened
at all.

**No configuration is read from inside the store.** Eight candidate paths
planted in `graphroot`, each a complete valid config naming store A —

```
storage.conf   storage.conf.d/10.conf   containers/storage.conf   libpod/storage.conf
overlay/storage.conf   overlay-images/storage.conf   .storage.conf   conf/storage.conf
```

— are read by neither engine, both in the shape where config options are live
and in snug's `--root` shape. The same sweep against `runroot` gives the same
answer, and a full `podman run` references no planted path either.

`strace` makes that an enumeration rather than a spot check. The complete set of
paths under `graphroot` that podman opens or stats, with all eight planted:

```
GRAPHROOT                              GRAPHROOT/overlay-images
GRAPHROOT/defaultNetworkBackend        GRAPHROOT/overlay-images/images.json
GRAPHROOT/libpod                       GRAPHROOT/overlay-images/images.lock
GRAPHROOT/networks/netavark.lock       GRAPHROOT/overlay-layers
GRAPHROOT/overlay                      GRAPHROOT/overlay-layers/layers.json
GRAPHROOT/overlay/.has-mount-program   GRAPHROOT/overlay-layers/layers.lock
GRAPHROOT/overlay/l                    GRAPHROOT/overlay-layers/tmp
GRAPHROOT/overlay/staging              GRAPHROOT/overlay-layers/volatile-layers.json
GRAPHROOT/overlay/tempdirs             GRAPHROOT/storage.lock
GRAPHROOT/overlay-containers           GRAPHROOT/userns.lock
GRAPHROOT/overlay-containers/containers.json    GRAPHROOT/volumes
GRAPHROOT/overlay-containers/containers.lock
GRAPHROOT/overlay-containers/volatile-containers.json
```

No TOML, no `*.conf`, no drop-in directory.

Two of those files do steer the engine, and neither carries a pathname.
`overlay/.has-mount-program` holds the four bytes `true`: a path planted in it
appears nowhere in the debug log and is never executed — it is a boolean about
how the store was built, not a program name. `defaultNetworkBackend` holds
`netavark`; planting `cni` in a fresh store is ignored, and it names a backend
rather than a path in any case, since where a backend's binaries live is a
`containers.conf` question. **No file inside `graphroot` carries a host pathname
into the engine.**

## 3. `--root` discards every storage option

With `--root` on the argv, every key under `[storage.options]` and
`[storage.options.overlay]` in the storage configuration is discarded.
`graphroot`, `runroot` and `driver` survive; the options do not. `--runroot`
alone changes nothing; `--root` alone is the trigger.

podman 5.8.4:

```
driver=(absent) --root=no    mount_program=IGNORED  additionalimagestores=READ
driver=(absent) --root=yes   mount_program=IGNORED  additionalimagestores=NOT-READ
driver=overlay  --root=no    mount_program=HONORED  additionalimagestores=READ
driver=overlay  --root=yes   mount_program=IGNORED  additionalimagestores=NOT-READ
```

podman 6.0.2 is identical except that `mount_program` no longer needs a `driver`
key beside it, so row 1 reads `HONORED`.

`mount_program` is probed with a bogus path, `/nonexistent/fuse-overlayfs`:
containers/storage refuses at store initialisation with `configure storage:
overlay: can't stat program …` when the key reaches the driver and says nothing
when it does not, so HONORED and IGNORED are two observed behaviours rather than
the presence and absence of one.

The same holds for `podman system service`, not only the `images` client path:

```
--root=no   service: Error: configure storage: overlay: can't stat program "/none…
            client : Error: unable to connect to Podman socket: …
--root=yes  service: (starts)
            client : REPOSITORY  TAG  IMAGE ID  CREATED  SIZE
```

The `--root=yes` leg is not a silent failure read as success: the service bound
its socket and answered a real API request, its store initialised with the bogus
`mount_program` in the file it was told to read.

`--storage-opt overlay.mount_program=…` on the argv **is** honored alongside
`--root`, as is `--storage-opt overlay.imagestore=…`. Once `--root` is present,
the argv is where a graph-driver option has to go.

## 4. What this means for snug

`writeStorageConf` emits three keys: `graphroot`, `runroot`, and — when a
`fuse-overlayfs` sits beside the resolved engine —
`[storage.options.overlay] mount_program`. `Engine.Spec` builds the argv
`--root <store> --runroot <runroot> system service …`.

Both paths come from `planPaths`: the store is
`$XDG_DATA_HOME/snug/engines/<key>/storage`, the runroot
`$TMPDIR/snug-engines-<uid>-<key>/rr`, and `<key>` is a hash of the canonical
target alone, so every run on one target directory addresses one store. What
follows is about which configuration that engine then reads, which is
independent of how the two paths are named.

| fact about the engine's store | pinned by | without it |
|---|---|---|
| `graphroot`, `runroot` | `--root`/`--runroot` **and** the generated file | either alone suffices |
| `driver` and the rest of `[storage]` | `CONTAINERS_STORAGE_CONF` only | a host or bundle file chooses the driver |
| `[storage.options*]` — `additionalimagestores`, `imagestore`, `mount_program`, `mountopt`, `force_mask` | nothing: `--root` discards them and snug passes no `--storage-opt` | discarded |
| which config files exist at all | `CONTAINERS_STORAGE_CONF` | the `$HOME` file is read |

Two consequences.

**The generated `mount_program` never reaches the driver.** It is the one key in
the file with no argv duplicate, and `--root` discards it. On 5.8.4 it is inert
twice over, since the file also omits `driver`. The direction is toward less
driver configuration rather than more, so this is a portability defect and not a
hole: a host that needs `fuse-overlayfs` for rootless overlay gets whatever
containers/storage auto-selects.
`TestTheGeneratedStorageConfNamesAMountProgramOnlyWhenThereIsOne` asserts the
contents of the file, which is a real property, and not that the key reaches the
driver. The fix is one flag beside the existing `--root`,
`--storage-opt overlay.mount_program=<guest path>`, measured to work; it changes
the engine argv and its golden files.

**No `CONTAINERS_STORAGE_CONF_OVERRIDE` is needed, and none exists.** The
argument that makes `CONTAINERS_CONF_OVERRIDE` necessary — something between
snug and the engine can export `CONTAINERS_CONF` and win — does not carry here.
A re-export still loses the store location to `--root`/`--runroot`, and every
`[storage.options*]` key in the re-exported file to the same discard. What it
could still change is `driver` and the residual `[storage]` scalars: a
denial-of-service or a performance choice, not a path.

**`--root` is doing more than its name suggests.** Dropping it in favour of the
generated `graphroot` alone would re-open `additionalimagestores` as a live key.
Anything that changes the engine argv re-reads §3 first.

## 5. Reproducing it

```
$ podman --version
$ ./storage-conf-lab.sh /tmp/lab

$ cat hostpodman
#!/bin/sh
exec /usr/bin/host-spawn -no-pty \
  -env HOME,XDG_CONFIG_HOME,XDG_RUNTIME_DIR,TMPDIR,CONTAINERS_CONF,CONTAINERS_CONF_OVERRIDE,CONTAINERS_REGISTRIES_CONF,CONTAINERS_STORAGE_CONF \
  podman "$@"
$ ./storage-conf-lab.sh ~/.cache/lab-host ./hostpodman
```

### 5.1 `storage-conf-lab.sh`

```sh
#!/bin/bash
# storage-conf-lab.sh -- the oracle and the measurements behind STORAGE-CONF.md.
#
#   usage: storage-conf-lab.sh [LABDIR] [PODMAN]
#   default PODMAN: whatever `podman` resolves to on PATH
#
# The oracle is an image that exists ONLY in store A. If it appears in
# `podman images` against store B, something told podman to read store A.
# Every measurement is printed beside a control producing the OTHER outcome.
set -u
LAB="${1:-$(mktemp -d)}"
# A reused lab may hold a store A from an earlier run, and a plain rm cannot
# always remove one (an imported layer is owned by a uid inside the import
# userns). Refuse rather than measure on it.
[ -e "$LAB" ] && [ -n "$(ls -A "$LAB" 2>/dev/null)" ] && { echo "refusing to reuse a non-empty $LAB"; exit 1; }
PODMAN="${2:-$(command -v podman)}"
BUNDLE="$(cd "$(dirname "$PODMAN")/../../.." && pwd)"
mkdir -p "$LAB"/{home/.config/containers,xdgconf/containers,xdg,tmp,conf,pinned,storeA,runA,rootfs}
echo "lab:    $LAB"
echo "podman: $($PODMAN --version)"

echo '{"default":[{"type":"insecureAcceptAnything"}]}' > "$LAB"/home/.config/containers/policy.json
{ echo '[engine]'; echo 'cgroup_manager = "cgroupfs"'; echo 'events_logger = "file"'
  # Pin the helpers only when PODMAN sits in a tree that carries its own.
  # Pointed at anything else these keys name directories that do not exist, and
  # podman refuses before the question under test is asked.
  if [ -x "$BUNDLE/usr/local/lib/podman/conmon" ]; then
    echo "helper_binaries_dir = [\"$BUNDLE/usr/local/lib/podman\", \"$BUNDLE/usr/local/bin\"]"
    echo "conmon_path = [\"$BUNDLE/usr/local/lib/podman/conmon\"]"
  fi; } > "$LAB"/conf/containers.conf
echo 'unqualified-search-registries = ["docker.io"]' > "$LAB"/conf/registries.conf

# p: podman with a completely controlled environment. env -i so that nothing
# from the caller's shell can decide the answer. XDG_CONFIG_HOME as well as
# HOME, because the host leg reaches podman through host-spawn, which forwards
# HOME as the HOST user's own no matter what it is told, and containers/storage
# looks under XDG_CONFIG_HOME first.
p() { env -i PATH=/usr/bin:/bin HOME="$LAB/home" XDG_CONFIG_HOME="$LAB/xdgconf" \
        XDG_RUNTIME_DIR="$LAB/xdg" TMPDIR="$LAB/tmp" \
        CONTAINERS_CONF="$LAB/conf/containers.conf" \
        CONTAINERS_CONF_OVERRIDE="$LAB/conf/containers.conf" \
        CONTAINERS_REGISTRIES_CONF="$LAB/conf/registries.conf" \
        ${CSC:+CONTAINERS_STORAGE_CONF="$CSC"} "$PODMAN" "$@"; }
CSC=""

# --- the image that exists only in store A -------------------------------
echo "only in store A" > "$LAB"/rootfs/marker.txt
tar -C "$LAB"/rootfs --owner=0 --group=0 --numeric-owner -cf "$LAB"/rootfs.tar .
p --root "$LAB/storeA" --runroot "$LAB/runA" import "$LAB/rootfs.tar" onlyinstorea:1 >/dev/null 2>&1
p --root "$LAB/storeA" --runroot "$LAB/runA" images --format '{{.Repository}}' 2>/dev/null \
  | grep -q onlyinstorea || { echo "FATAL: could not populate store A"; exit 1; }

freshB() { rm -rf "$LAB/storeB" "$LAB/runB"; mkdir -p "$LAB/storeB" "$LAB/runB"; }
# pin CONF [DRIVER] [OPTIONS-LINES] -- writes the config the run is told to read
pin() { { echo '[storage]'; [ -n "${2:-}" ] && echo "driver = \"$2\""
          echo "graphroot = \"$LAB/storeB\""; echo "runroot = \"$LAB/runB\""
          [ -n "${3:-}" ] && { echo '[storage.options]'; echo "$3"; }; } > "$1"; }
ask() { # ask LABEL args...   -> READ / NOT-READ
  lbl="$1"; shift
  out=$(p "$@" images --format '{{.Repository}}' 2>/dev/null | tr '\n' ' ')
  echo "$out" | grep -q onlyinstorea && v=READ || v=NOT-READ
  printf '  %-52s %s\n' "$lbl" "$v"; }

echo; echo "== T1  the oracle, both outcomes (no --root, so config options are live)"
freshB; pin "$LAB/pinned/c.conf" overlay ""; CSC="$LAB/pinned/c.conf"
ask "control: pinned config names NO extra store"
freshB; pin "$LAB/pinned/c.conf" overlay "additionalimagestores = [\"$LAB/storeA\"]"
ask "control: pinned config NAMES store A"

echo; echo "== T2  is a storage.conf INSIDE graphroot read?"
freshB; pin "$LAB/pinned/c.conf" overlay ""
for f in storage.conf storage.conf.d/10.conf containers/storage.conf libpod/storage.conf \
         overlay/storage.conf overlay-images/storage.conf .storage.conf conf/storage.conf; do
  mkdir -p "$(dirname "$LAB/storeB/$f")"
  printf '[storage]\ndriver = "overlay"\ngraphroot = "%s"\nrunroot = "%s"\n[storage.options]\nadditionalimagestores = ["%s"]\n' \
    "$LAB/storeB" "$LAB/runB" "$LAB/storeA" > "$LAB/storeB/$f"
done
ask "8 configs planted in graphroot, oracle-live shape"
ask "8 configs planted in graphroot, snug's shape" --root "$LAB/storeB" --runroot "$LAB/runB"

echo; echo "== T3  every path under graphroot podman opens (snug's shape)"
if command -v strace >/dev/null && head -c4 "$PODMAN" 2>/dev/null | grep -q ELF; then
  CSC="$LAB/pinned/c.conf"
  env -i PATH=/usr/bin:/bin HOME="$LAB/home" XDG_CONFIG_HOME="$LAB/xdgconf" XDG_RUNTIME_DIR="$LAB/xdg" TMPDIR="$LAB/tmp" \
    CONTAINERS_CONF="$LAB/conf/containers.conf" CONTAINERS_CONF_OVERRIDE="$LAB/conf/containers.conf" \
    CONTAINERS_REGISTRIES_CONF="$LAB/conf/registries.conf" CONTAINERS_STORAGE_CONF="$CSC" \
    strace -f -qq -e trace=openat,newfstatat,statx -o "$LAB/trace.txt" \
    "$PODMAN" --root "$LAB/storeB" --runroot "$LAB/runB" images >/dev/null 2>&1
  echo "  syscalls traced: $(wc -l < "$LAB/trace.txt")"
  echo "  references to any *storage.conf* under graphroot: $(grep -cE "\"$LAB/storeB[^\"]*storage\\.conf" "$LAB/trace.txt")"
  echo "  the complete set of graphroot paths podman touched:"
  grep -oE '"[^"]*"' "$LAB/trace.txt" | sort -u | grep -E "$LAB/storeB" | sed "s|$LAB/storeB|    GRAPHROOT|;s|\"||g"
else echo "  (skipped: needs strace and a PODMAN that is the engine itself, not a wrapper)"; fi

echo; echo "== T4  does CONTAINERS_STORAGE_CONF beat a host storage.conf?"
# driver is the discriminator, because it is the one key that survives --root.
for d in "$LAB/home/.config/containers" "$LAB/xdgconf/containers"; do
  printf '[storage]\ndriver = "vfs"\ngraphroot = "%s"\nrunroot = "%s"\n' "$LAB/storeC" "$LAB/runC" > "$d/storage.conf"
done
pin "$LAB/pinned/snug.conf" "" ""     # snug's shape: no driver, no options
q2() { lbl="$1"; shift; freshB
  o=$(p "$@" --log-level=debug images 2>&1)
  printf '  %-40s driver=[%s] graphroot=%s\n' "$lbl" \
    "$(echo "$o" | grep -oE 'Using graph driver [a-z]*' | head -1 | cut -d' ' -f4-)" \
    "$(echo "$o" | grep -oE 'Using graph root [^"]*' | head -1 | sed "s|.*/||")"; }
CSC=""                       ; q2 "var UNSET,   no flags"
CSC="$LAB/pinned/snug.conf"  ; q2 "var = snug's file, no flags"
CSC=""                       ; q2 "var UNSET,   snug's shape" --root "$LAB/storeB" --runroot "$LAB/runB"
CSC="$LAB/pinned/snug.conf"  ; q2 "var = snug's file, snug's shape" --root "$LAB/storeB" --runroot "$LAB/runB"
rm -f "$LAB"/home/.config/containers/storage.conf "$LAB"/xdgconf/containers/storage.conf

echo; echo "== T5  which storage.conf keys survive --root?"
echo "     (two INDEPENDENT configs: one carrying only mount_program, one only"
echo "      additionalimagestores, so neither probe can mask the other)"
for drv in "" overlay; do for rt in no yes; do
  args=""; [ $rt = yes ] && args="--root $LAB/storeB --runroot $LAB/runB"
  hdr() { { echo '[storage]'; [ -n "$drv" ] && echo "driver = \"$drv\""
            echo "graphroot = \"$LAB/storeB\""; echo "runroot = \"$LAB/runB\""; }; }
  freshB; { hdr; echo '[storage.options.overlay]'
            echo 'mount_program = "/nonexistent/fuse-overlayfs"'; } > "$LAB/pinned/m.conf"
  CSC="$LAB/pinned/m.conf"
  p $args images >/dev/null 2>"$LAB/m.err"; grep -q "can't stat program" "$LAB/m.err" && mp=HONORED || mp=IGNORED
  freshB; { hdr; echo '[storage.options]'
            echo "additionalimagestores = [\"$LAB/storeA\"]"; } > "$LAB/pinned/a.conf"
  CSC="$LAB/pinned/a.conf"
  p $args images --format '{{.Repository}}' 2>/dev/null | grep -q onlyinstorea && ais=READ || ais=NOT-READ
  printf '  driver=%-8s --root=%-4s  mount_program=%-8s additionalimagestores=%s\n' \
    "${drv:-(absent)}" "$rt" "$mp" "$ais"
done; done

echo; echo "== T6  T5's --root row, on \`podman system service\` -- snug's ACTUAL invocation"
if head -c4 "$PODMAN" 2>/dev/null | grep -q ELF; then
SOCK="/tmp/svc-$$.sock"          # short: sun_path is 108 bytes
for rt in no yes; do
  freshB; rm -f "$SOCK"
  printf '[storage]\ndriver = "overlay"\ngraphroot = "%s"\nrunroot = "%s"\n\n[storage.options.overlay]\nmount_program = "/nonexistent/fuse-overlayfs"\n' \
    "$LAB/storeB" "$LAB/runB" > "$LAB/pinned/svc.conf"
  CSC="$LAB/pinned/svc.conf"; args=""; [ $rt = yes ] && args="--root $LAB/storeB --runroot $LAB/runB"
  p $args system service --time 8 "unix://$SOCK" >"$LAB/svc-$rt.log" 2>&1 &
  bg=$!
  for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
  cli=$(p --url "unix://$SOCK" images 2>&1 | tail -1)
  printf '  --root=%-4s service says: %-60s\n' "$rt" "$(tail -1 "$LAB/svc-$rt.log" | cut -c1-60)"
  printf '           client says : %s\n' "$(echo "$cli" | cut -c1-60)"
  kill $bg 2>/dev/null; wait $bg 2>/dev/null
done
else echo "  (skipped: needs a PODMAN that is the engine itself, not a wrapper)"; fi

echo; echo "lab left at $LAB"
```

## 6. Limits of these measurements

- **Only the `overlay` driver.** `vfs` appears above solely as a discriminator
  for which config won, never as a store that was read.
- **T3's `strace` leg is bundle-only.** Through the host wrapper it traces
  `host-spawn` rather than the engine, and the harness skips it.
- **The `/etc/containers` leg was never exercised**: this host has no
  `/etc/containers` directory. §2's control is the `$HOME`/`XDG_CONFIG_HOME`
  file; that `CONTAINERS_STORAGE_CONF` also displaces
  `/etc/containers/storage.conf` is inferred from no path under `/etc` other
  than `ld.so.cache` and `localtime` appearing anywhere in the trace.
- **Two podman versions**, 5.8.4 and 6.0.2. They already disagree on one row of
  §3, so treat the tables as version-dependent and re-run the harness rather
  than quoting them.
- **Whether an additional image store is itself read as a config is not asked.**
  snug emits none and `--root` discards the key that could name one, so the
  question has no reachable form until something puts `--storage-opt
  overlay.imagestore=` on the engine argv.
