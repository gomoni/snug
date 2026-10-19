# identity.kubectl — kubectl against one pinned cluster, no credential inside

`[identity.kubectl]` lets `kubectl` (and any client-go tool) inside a sandbox
reach ONE cluster as ONE identity — the host context's own, through ONE of its
credentials (`credential = "client-certificate"` or `"token"`) — and
nothing inside ever holds that credential: no file, no token, no key, no exec
plugin. Nothing is created on the cluster. The abuse sentence is the
`KUBERNETES` comment in `internal/profile/profiles/base.toml`; it is the
authority on what the hole costs, and this document does not restate it.

snug protects the HOST, not the cluster. The credential stays out of the
sandbox and goes to one server; what it may do there is the cluster's RBAC.
Every refusal below keeps the credential pinned to that server and the host's
own services and processes out of reach; none narrows what the identity does
on the cluster.

| piece | where |
|---|---|
| block, credential, path role | `internal/policy/identity.go` (`IdentityKube`, `ParseKubeCredential`, `identityPathRoles`) |
| host kubeconfig decoder | `internal/kubecfg` |
| Resolve: refusals, `KubeBinding`, generated file | `internal/policy/kube.go` (`resolveKube`, `kubeUser`) |
| guest address | `internal/policy/snugns.go` (`KubeProxyGuest`, `KubeProxyGuestPort`) |
| topology | `internal/policy/topology.go` (`deriveTopology`'s `kube` input) |
| proxy | `internal/kubeproxy` |
| run-time wiring | `internal/cli/kube.go` (`startKubeIdentity`, `kubeRun.listen`), `relays.go` |
| screens | `internal/cli/kubedryrun.go`, `dryrun.go` (`describeKubeReach`), `dryrunjson.go`, `config.go` (`showIdentity`) |

## 1. Shape

```
inside (sandbox netns N)                     host (snug, P0)
kubectl ──http──> 127.0.0.1:6443 ══ socket created in N by the stage,
   ^                                bound + listened by P0 ══> kubeproxy ──tls──> the ONE pinned server
   └── ~/.kube/config (generated, RO,                            │ presents ONE credential:
       server http://127.0.0.1:6443, user {})                    │  client certificate (TLS), or
                                                                 └─ static token (bearer)
```

- **Inside.** `~/.kube/config` is generated JSON (JSON is YAML) from Go values:
  one cluster whose server is `http://127.0.0.1:6443` with no CA, one user
  that is `{}`, one context named after the profile's `context`, no
  namespace (a default namespace is program configuration, not a grant).
  `KUBECONFIG` points at it. Nothing of snug runs inside. Plain http: both
  ends of that loopback are the sandbox; the TLS hop is the proxy's, from the
  host.
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
  kubectl profile is therefore not an offline profile: the sandbox reaches
  that API server, and through pods/exec, port-forward, services/proxy and
  workload creation whatever the cluster reaches. The NETWORK block says so
  on every kube run (`TestKubeOnlyProfileIsNotOffline`).
- **The proxy** (`internal/kubeproxy`) is goroutines in P0. It decides only
  WHERE a request goes and WITH WHICH credential; every Kubernetes API
  method (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS) and every path, query
  and header is forwarded, `Impersonate-*` and the client's own
  `Authorization` included, and the cluster decides the rest. Any other
  method refuses: TRACE would carry the credential to a front-end that may
  echo it back. Under a bearer
  shape it SETS `Authorization`, so the client's is replaced; under the
  certificate shape it presents the certificate in the handshake and adds no
  header. It refuses what would change WHERE: `CONNECT`, absolute-form
  targets, and paths with a dot segment, an empty segment, a backslash or an
  escaped `/` `.` `\` — the pinned server is the URL as written, path
  included, and a gateway in front of several clusters would resolve those
  outside its prefix. `Host` is ignored. Upstream is HTTP/1.1 only (Go's h2
  transport refuses `Upgrade`, and exec/attach/port-forward are upgrades),
  `Proxy: nil` (no `HTTPS_PROXY` from snug's environment), TLS against the
  re-encoded CA and `tls-server-name`. The dialer resolves the server's name,
  refuses the whole answer when any address in it is loopback, unspecified,
  `0.0.0.0/8`, link-local, multicast, host-owned, on a subnet attached to a
  host interface (a kind or minikube bridge, libvirt, podman, docker, and the
  LAN itself), cloud metadata (`fd00:ec2::254`, `100.100.100.200`,
  `168.63.129.16`), or an IPv6 spelling of any of them (NAT64 `64:ff9b::/96`
  and `64:ff9b:1::/48`, 6to4 `2002::/16`, IPv4-compatible `::/96`,
  IPv4-translated `::ffff:0:0:0/96`), and dials a vetted IP. The host's
  prefixes (`sandbox.HostPrefixes`) are read on every dial, so a bridge that
  appears mid-run is refused from its first new connection
  (`TestKubeProxyRereadsHostNetsOnEveryDial`); a pooled connection opened
  before it keeps the peer it was vetted against.
  `kubeproxy.Preflight` runs the same check once in `startKubeIdentity`,
  before the sandbox exists, so a server on this host refuses the run rather
  than answering 502 inside: a cluster on this host (kind, k3s, minikube,
  `kubernetes.docker.internal`) runs its nodes on this host, and acting as you
  there is acting on the host (`TestKubeRunRefusesAServerOnThisHost`,
  `TestKubeProxyPreflightRefusesAServerOnThisHost`,
  `TestKubeProxyRefusesASubnetAttachedToThisHost`,
  `TestKubeProxyRefusesIPv6SpellingsOfLocalAddresses`). No read or write timeout (a
  watch would die); 64 connections; `Close` ends hijacked tunnels too.
- **The credential** is read once, at start, from the decoded host file into
  snug's memory, and is never written: no run-directory file, no environment,
  no mount (`TestKubeCredentialNeverTouchesDiskOrStartsAChild`), and no
  process is started for it. `-v` prints which credential
  is presented — the certificate's subject and expiry, or the token's length —
  and, on the first handshake that asks for it, `server requested a client
  certificate; sent <subject>`; never a value.
## 2. Which credential

`credential` names ONE credential of the context's user entry:

| value | entry fields | presented as |
|---|---|---|
| `client-certificate` | `client-certificate-data` + `client-key-data` | the TLS client certificate |
| `token` | `token` | `Authorization: Bearer`, replacing the client's |

- Absent, on an entry holding exactly one: that one; the dry run says it is
  the entry's only credential.
- Absent, on an entry holding both: refused, naming the values to
  write. AKS local accounts hold a certificate (`CN=masterclient`,
  `system:masters`) AND a static token (`clusterUser`) — measured as two
  identities, each cluster-admin — and kubectl's own preference (the
  certificate) is not one the profile wrote.
- Naming a credential the entry lacks: refused, listing what it holds.
- The credentials not named are never decoded; the dry run lists them under
  `absent` as "not presented".
- A certificate and key that do not pair refuse at Resolve; a certificate
  past `notAfter` refuses the run (Resolve reads no clock). A token that is
  not bearer-shaped or over 16 KiB refuses.

## 2a. What is read, what is refused

The host kubeconfig is decoded by `internal/kubecfg`, a strict decoder for the
block-YAML subset kubectl and az write, and JSON. Anchors, aliases, tags, block
scalars, flow collections other than `{}`/`[]`, multi-line scalars, complex and
merge keys, a second document and duplicate keys refuse with the line. A
parser differential with client-go cannot widen anything: only allowlisted,
re-encoded values leave snug.

Refused at Resolve, each naming the fix:

- a kubectl block without `server`, or a kubeconfig whose context names a
  different server. The profile — trusted, outside the sandboxed material —
  decides where the host credential goes; the kubeconfig only has to agree;
- the kubeconfig under the target, reachable by a writable grant (bytes,
  second mount, a name on its chain), or with a second hard link — whoever
  writes it chooses where the host credential is sent;
- the kubeconfig READABLE inside through any grant (by path or a second
  mount): `@parent-ro` with it beside the target, an ro bind of `~/.kube`. It
  holds the credential the proxy keeps out, and every other context's.
  `@home`'s tmpfs at `{home}` is not a bind and counts for neither;
- a missing context, a duplicate context/cluster/user name;
- a cluster field outside the three above (`insecure-skip-tls-verify: true`,
  `proxy-url`, `certificate-authority` path, non-empty `extensions`, unknown);
- a non-https server, a loopback or host-owned server literal. The proxy
  dials from the HOST, outside the seal that keeps the sandbox
  off host loopback, so this refusal (and the proxy dialer's repeat of it on
  resolved addresses) is what keeps identity.kubectl from being a grant to one
  host port;
- a user entry that names files (`client-certificate`, `client-key`), or
  carries `exec`, `auth-provider`, `as*`, `username`/`password`, `tokenFile`
  or any unknown field.

`certificate-authority-data` is parsed block by block as X.509 and re-encoded;
a non-certificate block or trailing bytes refuse.

## 3. Joins

`kubectl` is its own identity pin (identity joins one block at a time): a
kubectl-only profile composes with a forge profile; two kubectl blocks that
differ in any key, `credential` included, refuse naming both.

## 4. Not built

- **A ServiceAccount identity snug mints.** It needs an object on the
  cluster, it was the one shape that wrote a credential to disk and ran a host
  kubectl, and its narrowing is the cluster's. A human who wants one mints the
  token themselves into a kubeconfig user and uses `credential = "token"`.
- **Narrowing requests in the proxy** (read-only verbs, namespace lists): a
  second RBAC written by snug, bounding the cluster, which is not snug's role.
- **Exec plugins** (kubelogin, `aws eks get-token`, `aws-iam-authenticator`,
  `gke-gcloud-auth-plugin`): an `exec` user entry refuses. Running one means
  running a host program the kubeconfig names, and the only measured cluster
  holds a certificate and a token, so no plugin could be tested against a
  real one. #674.
- **`az` inside.** Every buildable form hands over the tenant refresh token or
  an ARM token, and an ARM token mints durable keys. The narrow form is a
  dedicated identity the human creates, under their own profile. #660.
- **Clusters on this host or one hop from it** (kind, k3s, minikube, a VM on
  a host bridge, a cluster on the same LAN): their nodes run on this host or
  beside it, so the cluster's RBAC is the host's boundary, and reaching one is
  base.toml's unbuilt one-port grant. Refused at Resolve for a loopback or
  host-owned literal and at start, and on every dial, for any address on a
  subnet attached to a host interface. The cost: a cluster on the laptop's own
  LAN, or reached over a VPN whose interface carries the cluster's prefix, is
  refused too.

## 4a. Residual, stated

The kubeconfig is judged against THIS run's grants: one the sandbox could
read or write is refused. One rewritten earlier — by a run whose target was
the directory it lives in, or by anything else running as you — is the host,
and snug does not defend against the host (`THREAT-MODEL.md`, user-provided
holes). That covers the certificate authority and `tls-server-name` in it: the
server is pinned by the profile, the CA is not.

## 5. Not measured

Whether kube-apiserver forwards a client's Authorization to a workload behind
services/proxy or pods/proxy (on the measured AKS cluster, services/proxy on
`default/kubernetes` answers 503: no endpoints). `scripts/0050` measures it
when `SNUG_KUBE_ECHO_SERVICE` names a Service that echoes headers.
