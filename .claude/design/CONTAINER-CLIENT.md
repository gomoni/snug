# Which container CLI works inside the sandbox

Investigation, 2026-08-09. Everything in the matrix was **executed** in a real
sandbox against snug's proxy; reasoning is marked as such.

## 0. The goal, stated by the owner

> `docker foo ...` works flawlessly against a sandbox-provided podman daemon.
> The deciding criterion is end-user usability and the feeling that a dev or an
> LLM agent is working in a normal, non-sandboxed environment.

That criterion is what settles the argument below. It rules out anything whose
answer is "type a different command than you would outside", which is why
`podman-remote` loses despite matching the profile's name.

## 1. The problem this starts from

`/usr/bin/podman` **on this host** is a symlink to `distrobox-host-exec`, a
POSIX shell script that forwards to the engine outside the container. `rpm -V
podman` reports `....L....` — the packaged binary was replaced, for usability.

**This is a property of this machine, not of distrobox.** It is a configuration
someone chose, not a default, so nothing in the design may assume it: snug
DETECTS a host-escape shim and does nothing when it does not find one. Read
every "on a distrobox host" in this document as "where this has been done". So the CLI named after the profile cannot work inside the sandbox at
all: it tries to reach a host socket the sandbox correctly cannot see.

snug currently prints a 15-line warning about this and recommends "any
docker-compatible client, e.g. `docker`". That advice turns out to be right, and
one of the four arguments printed next to it is now false — see §5.

## 2. Measured: three clients, one sandbox

`snug -p @podman-build <dir>`, this host, engine started by snug.

| command | `podman` (shim) | `podman-remote` | `docker` |
|---|---|---|---|
| `version` | fail | **OK** | **OK** |
| `info` | fail | **OK** | **OK** |
| `ps` / `images` | fail | **OK** | **OK** |
| `pull` | fail | **refused** | **OK** |
| `run` | fail | **refused** | **OK** |
| `run -t` (tty) | fail | — | **OK** |
| `run -d` + `exec` + `logs` + `stop` + `rm` | fail | — | **OK** |
| `build` | fail | — | fail — §4.1 |
| `cp` | fail | — | fail — §4.2 |
| `run -p` | fail | — | refused **by design** — §4.3 |
| `run -v <target>` | fail | — | fail on this host — §4.4, **not snug's doing** |
| `run -v /etc` | fail | — | **refused, correctly** |
| `run --privileged` | fail | — | **refused, correctly** |

Negative controls held: `-v /etc` was refused with *"this sandbox cannot see
/etc as writable, so a container may not mount it either"*, and `--privileged`
with *"it disables essentially every container protection"*. So the proxy is
live in the same run that shows the successes — the OK column is not a proxy
that stopped filtering.

## 3. Why `podman-remote` cannot be the answer

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

**Decision: `podman-remote` is supported for read-only inspection and nothing
else.** It is strictly better than the shim — it connects, and `ps`/`images`/
`info` answer truthfully — so it is worth naming in `doctor`. It is not the
client the owner's criterion asks for.

## 4. The gaps in `docker`, and what each one is

### 4.1 `docker build` — two independent problems

Modern docker (29.4.0-ce here) defaults to **buildx/buildkit**, which tries to
boot a `moby/buildkit` builder *container* rather than POSTing `/build`. That
fails before snug sees anything meaningful.

Forcing the legacy path gets further and then hits snug:

```
DOCKER_BUILDKIT=0 docker build -t probe:1 .
→ snug refused this request: build parameter "version" is not permitted.
```

`version` is the docker CLI telling the engine which builder to use (`1` =
classic). It is a builder selector, not a capability. The refusal message itself
invites the fix: *"If this one is harmless, it belongs in buildParams with a note
saying why."*

**Both halves must be fixed for `docker build` to work at all**, and the first is
the one that makes it feel non-normal: a user who types `docker build` gets a
buildkit error about pulling an image, which names nothing about snug.

### 4.2 `docker cp` — a plainly missing endpoint

```
docker cp c2:/etc/hostname /tmp/hn
→ endpoint GET /containers/c2/archive is not permitted
```

`GET  /containers/{id}/archive` reads a tar out of a container.
`PUT  /containers/{id}/archive` writes one in. Neither is currently allowed.
This is a normal thing to do and its absence is felt immediately.

*Reasoned, not yet decided:* GET is a read of container-internal state the
sandbox could obtain anyway by `exec`ing `tar`, so it looks like an ergonomic
gap rather than a boundary. PUT writes attacker-chosen bytes into a container —
also already reachable via `exec`. Neither obviously widens the boundary, but
both are `host_path`-free and need the abuse sentence written before they land.
**This is the one item in this document that is a genuine security decision and
is deferred to `host-bridge`.**

### 4.3 `docker run -p` — refused by design, and M-b is the fix

> HostConfig.PortBindings is not permitted: published ports land on the engine's
> side of the boundary

Correct today and correctly explained. It is also exactly what
`ENGINE-NETNS.md` §5 M-b fixes: with the engine in the sandbox's netns,
published ports land on the sandbox's loopback and become reachable. Nothing to
do here except stop the message implying it is permanent.

### 4.4 `docker run -v <target>` — SELinux, and NOT snug's doing

Measured, and the diagnosis matters more than the symptom:

```
in-sandbox   docker run -v $PWD:/w alpine ls /w   → exit 1
snug -v says: container create: 1 mount(s) allowed   # the PROXY permitted it
host engine  podman run -v $PWD:/w alpine ls /w   → ls: can't open '/w': Permission denied
host engine  podman run -v $PWD:/w:z alpine cat /w/file.txt → hello from target
```

The proxy allowed the mount. The identical command fails **outside snug
entirely**, and `:z` fixes it. The host is openSUSE Aeon with SELinux, and
rootless podman needs a relabel to let a container read a host directory.

So this is not a snug defect and must not be "fixed" in snug. But it lands on
the owner's criterion anyway: on an SELinux host, `docker run -v` behaves
differently inside and outside, and the user is left with a bare
`Permission denied` and nothing pointing at `:z`. **The honest fix is
diagnosis, not behaviour** — see §6.

## 5. A stale comment to delete

`internal/cli/podmanshim.go` point 2 argues against staging a working client:

> It would not even fix `podman run` here … The docker CLI always sends
> HostConfig.LogConfig, and the proxy refuses that field.

The proxy stopped refusing it. `isDefaultLogConfig` (`create.go:75`) was added
precisely because the denylist *"refused every `docker run` there has ever been
through this proxy — the profile's whole purpose, failing with a message about
log drivers."* Measured this pass: `docker run --rm alpine echo` → OK.

The argument is dead and the comment must go. The other three points stand.

## 6. Owner's decision, 2026-08-09

> A host-escape shim should be replaced inside the sandbox by a tool that
> **reports an error**, rather than left as a binary that fails cryptically. For
> `podman` specifically, **re-execing `docker` is an acceptable fallback.**

This reverses `podmanshim.go`'s standing refusal to stage a `podman`, and the
reversal is justified by §5: one of that comment's four arguments (`docker run`
cannot work through the proxy) is now measurably false, and the owner's criterion
— the sandbox should feel like a normal environment — outranks the remaining
three, which are about misattributed error messages.

**Two constraints on how, both from existing doctrine:**

*It cannot be a mount, and not merely as a preference.* `/usr/bin/podman` **is a
symlink**, and bwrap cannot create a mountpoint at a symlink destination
(INDEX §3.3). CLAUDE.md's rule — *"PATH precedence, not overmounting, is how
snug substitutes a host binary"* — is therefore the only mechanism available
here, not the tidier of two. The replacement is written into the writable tmpfs
`$HOME` and that directory goes first on `PATH`, which is additive: nothing is
hidden, `/usr/bin/podman` still exists and is still reachable by absolute path,
and the masking rule is untouched.

*The trigger is "resolves to a host-escape shim", not "is a symlink".* Symlinks
are ordinary and mostly fine — `/bin -> usr/bin` is one snug creates itself, and
`vi -> vim` resolves perfectly well inside. The property that predicts breakage
is resolving to a **host-escape helper**: `distrobox-host-exec`, `host-spawn`,
`flatpak-spawn`. Detecting *that* is a grep-able rule with a short list;
detecting "symlink" would stage stubs over half of `/usr/bin`.

**This stages an executable, which the model has never done before.** SECRETS.md
§4 flags exactly this: *"a `stub` key would be the first key that stages an
executable … it grants the most powerful thing in the model — code that runs
before the tool the human named. Its abuse sentence has to be written before its
syntax."* It is snug-authored rather than profile-authored, which is the
distinction that makes it admissible at all — but the abuse sentence is still
owed, and `host-bridge` and `redteam` are the gate.

## 7. Decision detail

**`docker` is the supported client inside the sandbox.** It already works for
the whole core loop, it is what a dev or an agent types without thinking, and
supporting it costs no new filter — the docker-compat schema is the one snug
already reads.

Three things follow, in increasing order of how much judgement they need:

1. **Make `docker build` work.** Allow the `version` build parameter with a note
   saying it is a builder selector, and set `DOCKER_BUILDKIT=0` in the policy
   environment when a podman profile is selected, so the default `docker build`
   takes the path snug can filter. *(snug already sets `CONTAINER_HOST` and
   `DOCKER_HOST`; this is the same shape.)*
2. **`doctor` reports which client this host can use**, replacing a warning that
   only says what is broken with one that says what to type: `podman` shim
   detected → `docker` works, `podman-remote` inspects, and on an SELinux host
   `-v` needs `:z`.
3. **`docker cp`** — deferred to `host-bridge` with the abuse sentence written
   first (§4.2).

**A `@docker` profile is a different thing and probably cannot ever be written.**
*Reasoned, not measured.* Three nouns get confused here:

- the **engine** — always podman, rootless, per-sandbox, started by snug;
- the **wire schema** — docker-compat, which *podman itself serves*; an interop
  format, not an endorsement of docker;
- the **client binary** — anything that speaks that schema.

`@podman-socket` is therefore named correctly: the engine is podman. A profile
meaning "talk to the host's `dockerd`" is the thing that cannot be written —
docker's engine is a **rootful daemon**, so every container would run as root on
the host, one filter bug would be root rather than uid 1000, and the engine's
namespaces and storage would not be snug's to control. That is the same class of
failure as the distrobox shim, which is what this whole document exists to route
around. Rootless `dockerd` is podman's model with more moving parts and no
advantage.

Say this in the profile, because a reader currently infers the opposite from
`DOCKER_HOST` being set.

---

## 8. Specification (`host-bridge`, 2026-08-09)

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

> **CLAUDE.md amendment owed.** The rule says *"write the replacement into the
> writable tmpfs `$HOME`"*. The principle (PATH precedence, not overmounting) is
> right; the location is wrong. Replace with: *"…into a directory snug owns and
> the sandbox cannot write, and put that directory on `PATH` ahead of
> `/usr/bin`."* Pre-existing and separate: `@claude` already puts writable
> `~/.local/bin` first on `PATH`.
>
> **Both closed.** CLAUDE.md carries the amendment, and the `@claude` half — the
> one this note filed as "pre-existing and separate", which is how it survived a
> further milestone — is gone: its binary is bound at `/snug/bin/claude`,
> `@claude` names no `PATH` directory at all, and snug adds the staging directory
> itself whenever anything is staged there. So the abuse sentence above no longer
> has its second clause: **no shipped profile puts a writable directory ahead of
> snug's on `PATH`**, and `TestNoBuiltinPutsAWritableDirectoryOnPATH` plus
> `TestSnugStagesNoCommandInAWritableDirectory` are what keep that true. Constraint
> 1 generalised from "the staged file and its directory" to every executable snug
> stages — see `policy.StagedBinDir`.

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
command` — `podmanshim.go` point 1, which the owner's decision did not repeal.
snug allowlists the tool it *delegates to* (docker's command set is stable), not
the one it impersonates (podman's grows every release).

**Scope: `podman` only**, gated on `Podman != PodmanOff`. Not a scan of
`/usr/bin` — that is what turns "snug authored one replacement" into "snug
replaces host binaries it judges broken", the general mechanism SECRETS.md §4
says needs its abuse sentence first.

**`--dry-run`:** render `KindData` with an executable bit as kind `exec`, and add
a `COMMANDS` block naming the stub, why it exists, what it forwards, that it is
read-only, and that `/usr/bin/podman` is untouched. New golden
`internal/policy/testdata/podman-socket.bwrap.txt` — no existing golden selects a
podman profile, so without it this change has no review artifact.

**Follow-ups:** `DOCKER_BUILDKIT=0` for `Podman != Off` (a *tightening* — with
BuildKit, `docker build` never POSTs `/build` at all and the option surface
bypasses the filter entirely; say so or it gets deleted as a convenience).
`version` build param enumerated `{"", "1"}`, refusing `2` by name — it is a
*selector*, and `buildParams` already enumerates selectors. `docker cp` stays
**refused**; see §9.

## 9. Red team (2026-08-09) — no escape found

Attacked against the live proxy. **No working escape on any axis.** Clean
negatives worth pinning as regression tests:

- **Repointing `docker` off the proxy is impossible, and this is the property
  that makes the stub safe at all.** `/snug/podman.sock` is the only
  container socket in the namespace; the real engine socket lives under
  `$XDG_RUNTIME_DIR/snug/engines/…`, and `/run/user/1000` is **not in the
  sandbox's mount namespace**. The private netns kills any `tcp://` repoint.
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
  payload lacks. There is currently **no regression test** asserting the upstream
  engine socket is unreachable — the property holds structurally and nothing
  guards it.
- **`DOCKER_BUILDKIT=0` is a default the payload can override.** On a
  buildkit-capable host, `DOCKER_BUILDKIT=1 docker build` boots a builder
  container (filtered at create) and then negotiates `RUN --mount=type=bind,…`
  over the **buildkit session**, which the `/build` query-string filter never
  inspects. State that the `/build` filter is not the only backstop *because* the
  variable is attacker-overridable.

---

## 10. Open gap found while verifying the stub: `docker run` returns no stdout

**Measured, and PRE-EXISTING — not introduced by the stub.** In a sandbox with
`@podman-socket`:

```
podman run --rm alpine echo FORWARDED   exit=0  stdout=[]  stderr=[]
docker run --rm alpine echo DIRECT      exit=0  stdout=[]  stderr=[]
podman ps                               exit=0  CONTAINER ID  IMAGE  COMMAND ...
```

The stub is faithful — it produces exactly what `docker` produces, which is the
property it was built for. But **neither client gets the container's stdout
back**. The container runs (exit 0), `ps` and `logs` work, so output reaches the
engine and stops there: the attach stream is not being relayed to the client.

This matters more than its size suggests, because it is the owner's criterion
failing directly: `docker run alpine echo hi` printing nothing is not what a
normal environment does, and it is the first thing anyone tries. It also means
the §2 matrix's `run → OK` rows should be read as "exit status 0", not "behaves
normally" — the matrix measured success, not output, and that was too weak a
check.

Not fixed here, because it is a separate defect in the proxy's attach/upgrade
path rather than anything to do with the client. Next step is to establish
whether the docker-compat `POST /containers/{id}/attach` upgrade is being
forwarded at all, and whether `-a stdout`/`--attach` or a non-TTY stream frame
header is the missing piece.
