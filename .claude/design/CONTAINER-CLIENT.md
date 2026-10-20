# The container client and the `podman` stub

Why the proxy serves the docker-compat schema and not podman's own, what the
staged `podman` stub may and may not do, and what the red team measured against
the proxy. How a user runs containers is in `docs/src/containers.md`.

Section numbers are cited from Go comments; they are not contiguous.

## 1. Engine, wire schema, client

Three nouns that get confused:

- the **engine** is always podman, rootless, per-sandbox, started by snug;
- the **wire schema** is docker-compat, which podman itself serves;
- the **client binary** is anything that speaks that schema.

`@podman-socket` is named correctly because the engine is podman. A profile
that talks to the host's `dockerd` cannot be written: docker's engine is a
rootful daemon, so a filter bug would be root rather than uid 1000, and the
engine's namespaces and storage would not be snug's to control. That is the
failure class of the distrobox shim.

## 3. Why `podman-remote` is not the client

**It speaks the libpod-native API, and snug refuses body-bearing libpod routes
by design.** `internal/dockerproxy/proxy.go` recognises both path shapes and
refuses libpod ones that carry a body it would have to inspect:

> the libpod-native API is not supported for POST /images/pull. snug filters the
> docker-compat schema, and the libpod body is a different shape that this filter
> cannot read — forwarding it unexamined would bypass every check.

That refusal is correct. The measurement that decides the design is narrower and
worse: **no flag keeps `podman-remote` on the docker-compat side of the wire.**

```
podman-remote create --pull=never docker.io/library/alpine
→ refused at POST /images/pull        # it pulls anyway, natively
```

So supporting `podman-remote` is not a matter of documenting an invocation. It
requires teaching the filter libpod's request schema — a **second** filter over a
different wire format, whose `SpecGenerator` for `containers/create` is
substantially larger than docker's `HostConfig` and moves with podman versions.
That is the D-Bus argument aimed at ourselves: *a filtering proxy that is 95%
correct is a sandbox that is 0% sound*, and doing it twice doubles the surface
invariant 6 has to keep consistent.

**`podman-remote` is supported for read-only inspection and nothing else**:
`version`, `info`, `ps` and `images` answer; `pull`, `create` and `run` are
refused at the libpod routes. `docker` is the client the proxy is written for.

## 4. `docker cp` is refused

`GET`/`PUT /containers/{id}/archive` is serviced by the engine, outside the
sandbox, as the host uid, and archive path resolution is the home of the
CVE-2018-15664 symlink-escape class. The argument that `exec tar` already does
the same is unsound: `exec tar` is confined by the container's mount
namespace. Allowing it would rest safety on podman's path resolution rather
than on snug's boundary. Refused in both schemas.

## 8. Specification (`host-bridge`)

**Abuse sentence.** *A hostile process inside the sandbox can use this to make a
human, or another agent, believe a command they typed as `podman` ran podman —
because snug has put a file named `podman` first on `PATH` that is not podman —
and, on any sandbox where a WRITABLE directory precedes snug's on `PATH`
(`@claude` puts `~/.local/bin` there), it can drop its own `podman` in front of
snug's and impersonate snug's own diagnostics.*

**Acceptable, because it grants no capability.** `PATH` is not an access control:
the sandbox already controls its own execution, `$HOME` and `PATH`, and can
ignore `PATH` entirely with an absolute path. Nothing crosses the boundary — the
stub is `/bin/sh` text delivered from a memfd with no host reference in it.

Two constraints follow and both are load-bearing:

1. **The staged file and its directory must be unwritable from inside.**
   Measured: under `--remount-ro /`, `/snug/bin` refuses both `touch
   .../evil` and `echo x > .../podman` (EROFS); `$HOME/.local/bin`, a writable
   tmpfs, refuses neither. A writable directory ahead of `/usr/bin` on `PATH` is
   a command-shadowing surface *snug would be creating*.
2. **Every message the stub emits begins `snug:` and says "stub".** The residual
   risk is belief, so identification is the mitigation — on the error paths only,
   never as a banner on the happy path.

> **No shipped profile puts a writable directory ahead of snug's on `PATH`.**
> `TestNoBuiltinPutsAWritableDirectoryOnPATH` and
> `TestSnugStagesNoCommandInAWritableDirectory` are what keep that true.
> `@claude` names no `PATH` directory at all — its binary is bound at
> `/snug/bin/claude` — and snug adds the staging directory itself whenever
> anything is staged there. Constraint 1 therefore covers every executable snug
> stages, not only the staged file and its own directory: see
> `policy.StagedBinDir`.

**Mechanism.** `/snug/bin/podman`, `KindData`, `AccessRO`, `Perms 0755`,
`From ["(snug)"]`, installed via `Policy.Replace` (sets `Authored`, so
`rejectMasking` skips it — no new exemption). Detection is impure and lives in
`internal/cli/podmanshim.go`, returning a value type carried into `policy.Context` as
`HostShims`, exactly as `LegacyTIOCSTI` is — so `Resolve` stays pure and the
goldens stay deterministic.

**Trigger:** resolves to a basename in `{distrobox-host-exec, host-spawn,
flatpak-spawn}`. NOT "is a symlink". The `#!` heuristic is fine for *warning* and
too broad to license *staging*.

**PATH order:** profile-contributed entries, then `/snug/bin`, then the base.
The stub must beat `/usr/bin/podman` — its whole job — and must LOSE to any
profile entry, because a profile entry is an explicit human grant.

**Stub behaviour:** a dispatcher, never a translator. Argv is forwarded
byte-for-byte; the stub only decides yes or no. Forward only a compiled-in
allowlist of *docker* subcommands; everything else exits **125** with a
snug-authored message. Allowlist not denylist, because a too-small allowlist
refuses in snug's voice while a too-small denylist lets docker answer `unknown
command` — `podmanshim.go` point 1.
snug allowlists the tool it *delegates to* (docker's command set is stable), not
the one it impersonates (podman's grows every release).

**Scope: `podman` only**, gated on `Podman != PodmanOff`. Not a scan of
`/usr/bin` — that is what turns "snug authored one replacement" into "snug
replaces host binaries it judges broken", the general mechanism SECRETS.md §4.3
says needs its abuse sentence first.

**`--dry-run`:** renders `KindData` with an executable bit as kind `exec`, and a
`COMMANDS` block names the stub, what it forwards, and that `/usr/bin/podman` is
untouched. Golden: `internal/policy/testdata/podman-socket.bwrap.txt`.

**Build selectors:** `DOCKER_BUILDKIT=0` is set for `Podman != Off` and is a
*tightening*, not a convenience: with BuildKit, `docker build` never POSTs
`/build` and the option surface bypasses the filter entirely. The `version`
build param is enumerated `{"", "1"}`, refusing `2` by name, because it is a
*selector* and `buildParams` already enumerates selectors.

## 9. Red team — no escape found

Attacked against the live proxy. **No working escape on any axis.** Clean
negatives worth pinning as regression tests:

- **Repointing `docker` off the proxy is impossible, and this is the property
  that makes the stub safe at all.** `/snug/podman.sock` is the only
  container socket in the namespace; the real engine socket lives under
  `/tmp/snug-<uid>-<runid>/` on the host, not in the sandbox's mount namespace
  (ENGINE-WIRING.md §3.3). The private netns kills any `tcp://` repoint.
  Structurally, `eng.Socket()` is only ever a dial target inside the proxy and is
  never handed to `BindSocket`/`Replace`.
- **Namespace-mode case-folding does not bypass the exact-match filter.** podman's
  *value* parser is case-sensitive even though its *key* parser is not:
  `NetworkMode:"Host"` → `network not found`; `PidMode:"Host"` → `unrecognized
  namespace mode`. Lowercase forms are `403`.
- **Path-normalisation evasion fails** at every spelling tried (`/v9.9/`,
  `//containers//create`, trailing slash, `/libpod/…`).
- `docker cp` refused in both schemas; `-v /etc`, `-v /:/host:ro`,
  `--privileged`, `--pid=host`, `--device /dev/fuse` all `403`.
- **The stub-replacement worry is a NON-finding.** The stub runs as a child of
  the payload, inheriting only the payload's own fds/env/cwd; snug never invokes
  it, so snug cannot leak an fd into it. It is content the payload could have
  written itself.

**The build context tar is forwarded unread, and what protects us is the ENGINE.**
The argument for waving it through is that the client assembled the tar inside
the sandbox out of files the sandbox can already read, so nothing new crosses.
The red team probed `..`, absolute and symlink entries in the tar and could not
get buildah 5.8.3 to write outside its builder directory — **but that is
buildah's securejoin protecting us, not snug's**. It is a property of a
dependency, and the version it was measured against is written here so a future
bump is read as a security change rather than a routine one.

The same distinction caught a real host read in the `secrets` parameter, which
had been waved through on the identical reasoning — *"the podman CLI reads the
file itself, client-side"* — which is true and is **not a security argument**,
because the threat model is an agent that POSTs to the socket directly.
`secrets=["id=leak,src=../../../../home/u/.ssh/id_ed25519"]` plus
`RUN --mount=type=secret` read a host file the sandbox was not granted and
streamed it back; buildah resolves `src=` against the context dir without
clamping `..`. **"The friendly client would never send that" is never a reason
to skip a check.**

**Concerns to carry into the implementation:**

- **`docker cp` — the equivalence argument in §4.2 is unsound**, independently of
  `host-bridge` reaching the same verdict. `exec tar` is confined by the
  container's mount namespace; `GET`/`PUT /archive` is serviced by the **engine,
  outside the sandbox, as the host uid**, and archive path resolution is the home
  of the CVE-2018-15664 symlink-escape class. Allowing it would rest safety on
  *podman's* path resolution rather than on snug's boundary.
- **The stub must never set `DOCKER_HOST` or `-H` to anything but the proxy.**
  This is the one way the first staged executable could carry authority the
  payload lacks. The property holds structurally; `TestContainerSocketNeverExposesEngineSocketDir` guards it.
- **`DOCKER_BUILDKIT=0` is a default the payload can override.** On a
  buildkit-capable host, `DOCKER_BUILDKIT=1 docker build` boots a builder
  container (filtered at create) and then negotiates `RUN --mount=type=bind,…`
  over the **buildkit session**, which the `/build` query-string filter never
  inspects. State that the `/build` filter is not the only backstop *because* the
  variable is attacker-overridable.

---
