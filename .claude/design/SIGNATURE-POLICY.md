# Signature policy: the engine enforces what the host configured

## The lever

podman resolves a signature policy from `$HOME/.config/containers/policy.json`,
then `/etc/containers/policy.json`. It is the one file podman requires — no
policy, no pull — and the home directory snug gives the engine is the only way
to choose it.

MEASURED, podman 5.8.4: `--signature-policy` exists as a **hidden** flag on
`pull` and `push`. It is absent from the global command and from `system
service`, so it cannot reach the API-driven pull the container proxy makes.

```
$ podman --signature-policy=/x version
Error: unknown flag: --signature-policy
$ podman system service --signature-policy=/x --time 1 unix:///tmp/x.sock
Error: unknown flag: --signature-policy
See 'podman system service --help'
$ podman pull --signature-policy=/x alpine
Error: could not find a working conmon binary   # past flag parsing
```

`containers.conf` has no signature-policy key. The home is the whole mechanism.

## The rule

The generated file is a projection of the host's. Three clauses:

1. A requirement snug can project faithfully is projected.
2. A requirement snug cannot project refuses the run, naming the requirement
   and the path.
3. There is no fallback to `insecureAcceptAnything`.

A host with no `policy.json` configured nothing to preserve. The generated file
accepts any image and a sidecar says which of the two happened — "your host has
no policy.json" and "snug decided not to verify" describe the same bytes and
not the same decision.

## What projects

| requirement | answer |
|---|---|
| `insecureAcceptAnything`, `reject` | verbatim |
| `signedBy` with `keyData` | verbatim; inline base64 names no path |
| `signedBy` with `keyPath`/`keyPaths` | key bytes copied under `<confDir>/sigkeys/`, path rewritten to the engine's guest path |
| `sigstoreSigned` | refused |
| `signedBaseLayer` | refused |
| anything else | refused |

`signedIdentity` carries over for the six `policyReferenceMatch` types, each
decoded against the exact field set it admits.

## What containers/image demands, measured

From `signature/policy_config.go` and `signature/policy_types.go`. snug mirrors
every one of these as a refusal: being looser than the thing being projected for
is how a projection stops being one.

- **Unknown top-level keys are fatal.** `Policy.UnmarshalJSON` resolves
  `default` and `transports` and returns `nil` for everything else;
  `ParanoidUnmarshalJSONObject` turns a nil destination into `Unknown key %q`.
  A `_snug` comment key inside `policy.json` breaks every pull. The explanation
  goes in `policy.json.snug` beside it.
- **`default` is required**: `"Default policy is missing"`.
- **A requirement list may not be empty**: `"List of verification policy
  requirements must not be empty"`.
- **`signedBy` names exactly one of `keyPath`, `keyPaths`, `keyData`.** Two is
  an error upstream, so re-emitting two produces a file the engine rejects at
  every pull.
- **`keyType` is required** and is one of `GPGKeys`, `signedByGPGKeys`,
  `X509Certificates`, `signedByX509CAs`. All four take the identical key shape,
  so all four are equally projectable and the value carries verbatim.
- **Each `prm*` arm decodes with exact fields**, so `dockerReference` inside a
  `matchExact` is a file podman refuses.

## Transport scopes are the projection's own downgrade hazard

`policyTransportScopesWithTransport.UnmarshalJSON` validates a non-empty scope
with the transport's own `ValidatePolicyConfigurationScope`. For `dir`, `oci`,
`docker-archive` and `containers-storage` that scope is a filesystem path.

The engine's mount view is derived from the sandbox's, so
`"dir": {"/mnt/untrusted": [{"type":"reject"}]}` carried verbatim names a path
that does not exist there. The scope never matches, the image falls through to
`default`, and a rule stricter than the default is gone — dropped by the
projection itself.

So a non-empty scope projects for `docker`, `atomic` and `docker-daemon` only,
and a `docker` or `atomic` scope may not begin with `/`. The empty scope
projects for any transport: it names nothing, which keeps
`"docker-daemon": {"": [...]}` — the shape Fedora and RHEL ship — working.

## Why `sigstoreSigned` is refused

Not because it reaches a service. It does not: Fulcio is `caPath`/`caData` plus
an issuer and a subject, Rekor is a public key, PKI is a CA roots file. Every
check is offline against a local file or inline base64.

It is refused because snug transcribes this schema by hand — `go.mod` has two
dependencies and containers/image will never be one — and this requirement is
the one that has grown: four independent trust-root families, each with
`Path`/`Paths`/`Data`/`Datas` spellings, across podman 4, 5 and 6. Strict
decoding refuses a field snug has never heard of, which is safe. It cannot see a
field whose meaning changed under a name snug already knows.

## Keys

Keys are data, not a command table. A GPG public key or an X.509 CA root names
no program and carries no credential; the care it needs is availability, not
execution.

They are copied, not bound, because the engine resolves paths in its derived
view. The copies land in the run's config directory, which is grafted read-only
into that view — an engine talked into writing cannot rewrite the keys it
verifies against.

The read is `hostread.Required`: bounded, non-blocking, regular files only.
There is no symlink rule. This is a copy, so the bytes are in memory before
anything else runs and the destination cannot be re-pointed afterwards, and
`/etc/pki/rpm-gpg` is a symlink farm on several distributions.

`hostread.Optional` is wrong here and the distinction is load-bearing: it folds
EACCES into absence, so a policy snug was not allowed to open would read as "the
host configured nothing" and produce a permissive file. That is a fallback
wearing clause 3's clothes.

## Reach

The key copies live in the run's config directory. That directory reaches the
engine through a graft and the payload through nothing at all:
`policy.HostPathVisible` — the container proxy's bind filter — walks the
sandbox's own `KindBind` mounts and never `p.Grafts`, so no `-v` can name a copy
under either its host path or its guest path.

> A hostile process inside the sandbox can use the projected signature policy to
> — nothing it could not already do. It cannot read the key copies, and it
> cannot influence which host file is projected: `policy.json` is read from the
> host user's home and from `/etc`, neither writable from inside. Its only reach
> is the one it already had: poisoning the shared image store with an image the
> projected policy admitted, which is now the host user's decision rather than
> snug's.

Facing the other way:

> A host user who runs snug on a target containing their own
> `~/.config/containers/policy.json` gives the payload write access to the file
> that decides the next run's projection. It cannot weaken verification below
> what snug generates for a host with no policy at all, and it cannot reach the
> key copies. It can refuse every future container run on that target, and it
> can name an arbitrary host path as a `keyPath` and read the refusal as an
> existence-and-type oracle for it.

## Ordering

The projection runs in `startContainers`, before `engine.New` and before the
preflight. `engine.New` creates `/tmp/snug-<uid>-<pid>/` and only
`containerRun.cleanup` removes it, so a refusal after `New` leaks a run
directory that a later run with a recycled pid then refuses to reuse. Refusing
first creates nothing and copies no host key into `/tmp` on a run that will not
start.

`Spec` receives the projected value and only writes. Nothing there can refuse
for a policy reason.

## What is not projected

Signature **lookup** — where a signature is fetched from — is `registries.d`,
not `policy.json`. The engine's generated home has none, so containers/image
falls back to `/etc/containers/registries.d`, which `@podman-socket`'s
`ro = ["/etc/containers"]` puts in the engine's view. A lookaside configured
under `~/.config/containers/registries.d` is therefore not seen, and a projected
`signedBy` that finds no signature rejects the image. The sidecar says so.

## Registry TLS

Nothing in snug sets `tls-verify=false`, `InsecureSkipVerify` or an equivalent
skip. Swept over `*.go`, `*.toml` and `*.json`:

```
grep -rniE 'tls[_-]?verify|insecureskipverify|insecure[ _-]?=|"insecure"|skip[_-]?tls|tlsverify'
```

One hit: `internal/engine/imageprovenance_test.go`, the assertion that those
keys are absent from the generated `registries.conf`. The grep is proved able to
find something by adding one known-present alternative
(`unqualified-search-registries`), which matches `engine.go` and nothing else
new.

`internal/dockerproxy/proxy.go`'s `http.Transport` sets only `DialContext` (a
unix socket) and `DisableCompression`. No `TLSClientConfig`, no https, no
registry.

The CA store is in the engine's derived view: the grafts are
`/snug/engine/{store,runroot,sock,conf,toolchain}` plus `/proc`,
`/sys/fs/cgroup`, `/var/tmp` and `/run`, none of which covers `/etc/ssl`,
`/etc/pki` or `/etc/ca-certificates`, all bound read-only by `@sys`. A host that
relies on `SSL_CERT_FILE` for a corporate bundle loses it, and that fails
closed: the engine's environment is built from an empty base.
