# identity.kube — kubectl against one pinned cluster, no credential inside

`[identity.kube]` lets `kubectl` (and any client-go tool) inside a sandbox
reach ONE cluster as ONE ServiceAccount, and nothing inside ever holds a
credential for it — no file, no token, no exec plugin. The abuse sentence is
the `KUBERNETES` comment in `internal/profile/profiles/base.toml`; it is the
authority on what the hole costs, and this document does not restate it.

| piece | where |
|---|---|
| block, token mode, path role | `internal/policy/identity.go` (`IdentityKube`, `ParseKubeTokenMode`, `identityPathRoles`) |
| host kubeconfig decoder | `internal/kubecfg` |
| Resolve: refusals, `KubeBinding`, generated files | `internal/policy/kube.go` (`resolveKube`) |
| guest address | `internal/policy/snugns.go` (`KubeProxyGuest`, `KubeProxyGuestPort`) |
| topology | `internal/policy/topology.go` (`deriveTopology`'s `kube` input) |
| host mint plan | `internal/policy/kube.go` (`MintKubeconfig`, `MintArgv`, `KubeMintEnv`, `ResolveKubeMintBinary`) |
| token source | `internal/kubebroker` (`Source`) |
| proxy | `internal/kubeproxy` |
| run-time wiring | `internal/cli/kube.go` (`startKubeIdentity`, `kubeRun.listen`), `relays.go` |
| screens | `internal/cli/kubedryrun.go`, `dryrun.go` (`describeKubeReach`), `dryrunjson.go`, `config.go` (`showIdentity`) |

## 1. Shape

```
inside (sandbox netns N)                     host (snug, P0)
kubectl ──http──> 127.0.0.1:6443 ══ socket created in N by the stage,
   ^                                bound + listened by P0 ══> kubeproxy ──tls──> the ONE pinned server
   └── ~/.kube/config (generated, RO,                            │ adds Authorization: Bearer
       server http://127.0.0.1:6443, user {})                    └── kubebroker.Source ── host mint:
                                                                     kubectl create token <sa>
                                                                     (own user+pid ns, per-run kubeconfig)
```

- **Inside.** `~/.kube/config` is generated JSON (JSON is YAML) from Go values:
  one cluster whose server is `http://127.0.0.1:6443` with no CA, one user
  that is `{}`, one context named after the profile's `context`, namespace =
  the ServiceAccount's. `KUBECONFIG` points at it. Nothing of snug runs
  inside. Plain http: both ends of that loopback are the sandbox; the TLS hop
  is the proxy's, from the host.
- **The listener.** The stage creates an unconnected AF_INET socket in N
  (`stage.relaySocketsInN`, the login bridge's primitive; at most four per
  run, three of them the bridge's); P0 binds it to `127.0.0.1:6443` and
  listens in the relay callback, after the network is up and before bwrap is
  forked, so nothing inside exists to hold the port first. No `SO_REUSEADDR`
  or `SO_REUSEPORT`: a payload bind on `127.0.0.1:6443` or `0.0.0.0:6443`
  gets EADDRINUSE (`TestKubeProxyListenerIsInTheSandboxNetns`). A bind that
  fails refuses the run. A socket's netns is fixed at creation, so the host's
  own `127.0.0.1:6443` is a different address entirely.
- **No @net needed, and that is a hole.** The proxy dials from the host, so
  `deriveTopology` raises a kube run to a stage without granting egress. A
  kube profile is therefore not an offline profile: the sandbox reaches that
  API server, and through pods/exec, port-forward, services/proxy and
  workload creation whatever the cluster reaches. The NETWORK block says so
  on every kube run (`TestKubeOnlyProfileIsNotOffline`).
- **The proxy** (`internal/kubeproxy`) is goroutines in P0. It decides only WHERE
  a request goes and AS WHOM; every method, path and query is forwarded, and
  the cluster's RBAC decides the rest. It REFUSES, never strips:
  `Authorization`, `Proxy-Authorization`, `Impersonate-*`, `X-Remote-*`
  (lowercased, `_` read as `-`), a `base64url.bearer.authorization.k8s.io.`
  websocket subprotocol, request trailers, `CONNECT`, absolute-form targets,
  and paths with a dot segment, an empty segment, a backslash or an escaped
  `/` `.` `\` — a gateway in front of several clusters would resolve those
  outside the pinned prefix. `Host` is ignored. Upstream is HTTP/1.1 only
  (Go's h2 transport refuses `Upgrade`, and exec/attach/port-forward are
  upgrades), `Proxy: nil` (no `HTTPS_PROXY` from snug's environment), TLS
  against the re-encoded CA and `tls-server-name`. The dialer resolves the
  server's name, refuses loopback, unspecified, link-local, multicast,
  host-owned and cloud-metadata addresses (`fd00:ec2::254`,
  `100.100.100.200`, `168.63.129.16`), and dials the vetted IP. No read or
  write timeout (a watch would die); 64 connections; `Close` ends hijacked
  tunnels too.
- **The token source** (`kubebroker.Source`) takes no input but a context: the
  cached token while `now < expiry - 60s`, else one mint shared by every
  waiter — never because the cluster answered 401, which a pod the sandbox
  controls can make it do at will. A failed mint is answered from cache for
  10 s; at most 64 mints per run.
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

- a kube block without `server`, or a kubeconfig whose context names a
  different server. The profile — trusted, outside the sandboxed material —
  decides where the host credential goes; the kubeconfig only has to agree;
- the kubeconfig under the target, reachable by a writable grant (bytes,
  second mount, a name on its chain), or with a second hard link — whoever
  writes it chooses where the host credential is sent. `@home`'s tmpfs does
  not count; it writes nothing through;
- a missing context, a duplicate context/cluster/user name;
- a cluster field outside the three above (`insecure-skip-tls-verify: true`,
  `proxy-url`, `certificate-authority` path, non-empty `extensions`, unknown);
- a non-https server, a loopback or host-owned server literal. The proxy and
  the mint dial from the HOST, outside the seal that keeps the sandbox off
  host loopback, so this refusal (and the proxy dialer's repeat of it on
  resolved addresses) is what keeps identity.kube from being a grant to one
  host port;
- a user entry that is an exec plugin (`token = "host-exec"` is #659), names
  files, or carries `auth-provider`, `as*`, `username`/`password`, `tokenFile`;
- a `service_account` that is not `namespace/name` of Kubernetes names;
- a host kubectl that is relative, in the target, writable through a grant,
  hard-linked, or not an ELF binary (distrobox-export, host-spawn, asdf shims).

`certificate-authority-data` is parsed block by block as X.509 and re-encoded;
a non-certificate block or trailing bytes refuse.

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
- **Host loopback clusters** (kind): the proxy would be one dialer check away
  from reaching them, which is exactly base.toml's unbuilt one-port grant;
  refused until that is its own decision with its own abuse sentence.

## 4a. Residual, stated

The host kubectl is judged against THIS run's grants: a kubectl the sandbox
could write is refused. A kubectl replaced earlier — by a run whose target was
the directory it lives in, or by anything else running as you — is the host,
and snug does not defend against the host (`THREAT-MODEL.md`, user-provided
holes). The container engine binary has the same property. The same holds for
the certificate authority and `tls-server-name` in the kubeconfig: the server
is pinned by the profile, the CA is not.

## 5. Not measured

The AKS ServiceAccount token maximum lifetime; whether `-o json` and
`KUBERC=off` behave as documented on every kubectl; and that kube-apiserver
does not forward the client's Authorization to a workload behind
services/proxy or pods/proxy. `scripts/0050` measures all three against a real
cluster.
