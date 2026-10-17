# identity.kube — kubectl against one pinned cluster

`[identity.kube]` lets `kubectl` (and any client-go tool) inside a sandbox
reach ONE cluster as ONE ServiceAccount, with no credential file inside. The
abuse sentence is the `KUBERNETES` comment in
`internal/profile/profiles/base.toml`; it is the authority on what the hole
costs, and this document does not restate it.

| piece | where |
|---|---|
| block, token mode, path role | `internal/policy/identity.go` (`IdentityKube`, `ParseKubeTokenMode`, `identityPathRoles`) |
| host kubeconfig decoder | `internal/kubecfg` |
| Resolve: refusals, `KubeBinding`, generated files | `internal/policy/kube.go` (`resolveKube`) |
| host mint plan | `internal/policy/kube.go` (`MintKubeconfig`, `MintArgv`, `KubeMintEnv`, `ResolveKubeMintBinary`) |
| broker and shim | `internal/kubebroker` |
| run-time wiring | `internal/cli/kube.go` (`startKubeIdentity`), argv[0] dispatch in `main.go` |
| screens | `internal/cli/kubedryrun.go`, `dryrunjson.go`, `config.go` (`showIdentity`) |

## 1. Shape

```
inside                                   host (snug, P0)
kubectl ──exec──> /snug/bin/snug-kube-token ──unix──> broker ──> kubectl create token <sa>
   ^                (snug's own binary)   /snug/kube-token.sock      (own user+pid ns,
   └── ~/.kube/config (generated, RO)                                 per-run kubeconfig)
```

- **Inside.** `~/.kube/config` is generated JSON (JSON is YAML) from Go values:
  one cluster (`server`, `certificate-authority-data`, `tls-server-name`), one
  user whose only credential is `exec: /snug/bin/snug-kube-token`, one context
  named after the profile's `context`, namespace = the ServiceAccount's.
  `KUBECONFIG` points at it. The shim is a read-only bind of snug's own
  executable, dispatched on argv[0]: `sh` cannot speak to a unix socket, and a
  FIFO cannot answer concurrent `kubectl` runs.
- **The broker** is a goroutine in P0 on a `0600` run-scoped socket. It never
  reads a connection: the answer is the cached token while
  `now < expiry - 60s`, else one mint shared by every waiter. A failed mint is
  answered from cache for 10 s; at most 64 mints per run; 16 connections;
  35 s per connection.
- **The host mint** never reads the host kubeconfig. snug writes a per-run
  `kube-mint.json` (0600, through the verified run directory) holding the same
  cluster and the host user's credential re-encoded, all named `snug`, only
  while a mint is in flight. The argv is exact (`MintArgv`), the environment is
  exactly `PATH=/usr/bin:/bin HOME=<empty per-run dir> KUBERC=off`, cwd `/`.
  kubectl is pid 1 of its own user+pid namespace with `Pdeathsig: SIGKILL`
  from a locked OS thread, so a timeout, cancel or SIGKILL of snug takes its
  grandchildren with it (`TestKubeMintCancelLeavesNoGrandchild`,
  `TestKubeMintLeavesNoProcessAfterSIGKILL`). One preflight mint at start; a
  failure refuses the run. A cluster-issued lifetime over 1h10m is printed on
  stderr every run.

## 2. What is read, what is refused

The host kubeconfig is decoded by `internal/kubecfg`, a strict decoder for the
block-YAML subset kubectl and az write, and JSON. Anchors, aliases, tags, block
scalars, flow collections other than `{}`/`[]`, multi-line scalars, complex and
merge keys, a second document and duplicate keys refuse with the line. A
parser differential with client-go cannot widen anything: only allowlisted,
re-encoded values leave snug.

Refused at Resolve, each naming the fix:

- the kubeconfig under the target, or reachable by a writable grant (bytes,
  second mount, a name on its chain) — whoever writes it chooses where the
  host credential is sent. `@home`'s tmpfs does not count; it writes nothing
  through;
- a missing context, a duplicate context/cluster/user name;
- a cluster field outside the three above (`insecure-skip-tls-verify: true`,
  `proxy-url`, `certificate-authority` path, non-empty `extensions`, unknown);
- a non-https server, a loopback or host-owned server (a usability check; the
  bound is pasta's `--map-host-loopback none`/`-T none` and the stage's seal);
- no egress;
- a user entry that is an exec plugin (`token = "host-exec"` is #659), names
  files, or carries `auth-provider`, `as*`, `username`/`password`, `tokenFile`;
- a `service_account` that is not `namespace/name` of Kubernetes names;
- a host kubectl that is relative, in the target, writable through a grant, or
  not an ELF binary (distrobox-export, host-spawn, asdf shims).

When the host user has a client certificate AND a static token, only the
certificate goes into the mint file; the token is never sent.

## 3. Joins

`kube` is its own identity pin (identity joins one block at a time): a
kube-only profile composes with a forge profile; two kube blocks that differ
refuse naming both.

## 4. Not built

- **`az` inside.** Every buildable form hands over the tenant refresh token or
  an ARM token, and an ARM token mints durable keys. The narrow form is a
  dedicated identity the human creates, under their own profile. #660.
- **`token = "host-exec"`** (kubelogin, `aws eks get-token`): #659.
- **Bound-Secret revocation at teardown.** A Secret-bound token dies when snug
  deletes the Secret, but a SIGKILLed snug leaves the Secret on the cluster.
  The bound today is the token lifetime.
- **Host loopback clusters** (kind): the narrow grant is pasta `-T <port>`; not
  built.

## 5. Not measured

The AKS ServiceAccount token maximum lifetime, and whether `-o json` and
`KUBERC=off` behave as documented on every kubectl: `scripts/0050` measures
against a real cluster and prints the granted lifetime.
