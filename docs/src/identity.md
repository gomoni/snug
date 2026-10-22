# Identity

An identity pins the one account each tool acts as inside the sandbox. That
protects what is most worth protecting: no ssh key, git configuration, `gh`
login or token is mounted.

It is also simply convenient. Inside, each tool has exactly one account, and it
is the default: no `ssh -i`, no `gh auth switch` or `kubectl config
set-context`. A sandbox for your work account cannot push as your personal one,
so nothing can act as the wrong account. Two accounts are two profiles, one per
run, and so are two Kubernetes clusters:

```sh
# kubectl reaches the dev cluster only
snug -p kube-dev      ~/src/app
# kubectl reaches the test cluster only
snug -p kube-test     ~/src/app
```

`snug` pins each tool separately as it does not and cannot check that the ssh key
and the `gh` user are the same account. See [Rules](#rules).

snug **generates** every file involved from the `identity` key. It reads the
host's configuration as data and writes only keys that cannot run a program.

## `identity`

```toml
# first define work related identities
[profile.work]
include = ["@net"]

  [profile.work.identity.ssh]
  host  = "ghe.example.com"
  key   = "{home}/.ssh/work.pub"
  agent = "proxy"

  [profile.work.identity.git]
  name        = "Your Name"
  email       = "you@example.com"
  signing_key = "{home}/.ssh/work_sign.pub"

  [profile.work.identity.gh]
  host = "ghe.example.com"
  user = "you-at-work"

# make sure manually installed kubectl is available
[profile.kubectl-cli]
ro = ["{home}/bin/kubectl:/snug/bin/kubectl"]

[profile.kube-dev]
include = ["work", "kubectl-cli"]
  [profile.dev.identity.kubectl]
  context    = "aks-dev"
  server     = "https://aks-dev.example.azmk8s.io:443"
  credential = "client-certificate"

[profile.test]
include = ["work", "kubectl"]
  [profile.test.identity.kubectl]
  context    = "aks-test"
  server     = "https://aks-test.example.azmk8s.io:443"
  credential = "token"
```

`kube-dev` and `kubetest` push, commit and call `gh` as `work` does. Each adds
a different cluster definition. `kubectl` inside sees one context, and the
other cluster is not there at all.

`identity` itself holds up to five optional blocks: `ssh`, `git`, `gpg`, `gh`
and `kubectl`. Blocks from different profiles combine, but each block has one
value per run. A second, different value of the same block is refused, naming
both profiles:

```text
$ snug -p work -p other ~/src/app
snug: profiles "other" and "work" pin different identity.ssh; select only one of them, or make the two blocks identical
```

### `identity.ssh`

| key | value | default |
|---|---|---|
| `host` | the host you push to | `github.com` |
| `key` | path to the **public** key ssh logs in with | none |
| `agent` | `"proxy"` or `"none"` | `"none"` |

With `agent = "proxy"`, `SSH_AUTH_SOCK` inside points at a filtering proxy
to your host agent. It offers only the pinned keys and no key material enters
the sandbox, and your other keys can be neither used nor listed.

snug generates `~/.ssh/config` and a `known_hosts` holding only `host`.
With the proxy, the generated git config also rewrites `https://HOST/` to
`git@HOST:`, so clones over https push over ssh.

### `identity.git`

| key | value |
|---|---|
| `name` | commit author name |
| `email` | commit author email |
| `signing_key` | path to the **public** key used for `gpg.format = ssh` signing |

snug generates `~/.gitconfig` from this block and points `GIT_CONFIG_GLOBAL`
at it. It never reads the host git config. snug generates it when an `ssh`,
`git` or `gpg` block is set and without any of them there is no `~/.gitconfig`,
and `git commit` inside has no author.

With `signing_key`, snug generates the signing configuration and turns
commit signing on. The private key stays in your host agent, so it needs
`identity.ssh.agent = "proxy"`, and the profile that sets `signing_key` must
also set `identity.ssh`. The proxy then offers both keys, and it cannot tell
a commit signature from a login: the signing key also logs in wherever it is
trusted. snug checks before starting that the agent will actually sign with
it.

`email` must be a single address.

A `sign`-scoped [`identity.gpg`](#identitygpg) block also turns commit signing on,
in OpenPGP format. Because git signs in ONE format, a profile cannot pin both an
ssh `signing_key` and a sign-scoped gpg key: snug refuses that.

#### Other git settings

A profile is not a configuration surface for the programs inside, so
`identity.git` holds only the three keys above. Write any other setting
(`init.defaultBranch`, `pull.rebase`) in a file of your own and grant it
read-only at `/etc/gitconfig`:

```toml
[profile.git-prefs]
ro = ["{home}/.config/snug/sandbox.gitconfig:/etc/gitconfig"]
```

git reads it below the generated `~/.gitconfig`, so the pinned keys still win.
`~/.gitconfig` and `~/.config/git/config` do not work for this.

### `identity.gpg`

| key | value | default |
|---|---|---|
| `fingerprint` | the key's fingerprint, 40 or 64 hex characters | none |
| `scope` | array of `"sign"`, `"decrypt"` | none — required |

```toml
[profile.work]

  [profile.work.identity.gpg]
  fingerprint = "6732361300BBFDAE7F22972CD4381E1CE2880244"
  scope       = ["sign"]
```

`GNUPGHOME` inside points at a `~/.gnupg` snug generates, whose `S.gpg-agent`
socket is a filtering proxy to your host gpg-agent. Only the pinned key is
usable, and no key material enters the sandbox: your other keys can be neither
used nor listed, and `gpg --export-secret-keys` returns nothing.

The key is named by **fingerprint**, not by path — the private half lives in
your host agent and is matched there, so snug reads no key file for this block.
There is no `agent` knob: unlike ssh, where `"none"` is a real mode with keys of
its own on the sandbox disk, a pinned gpg key is useless without the agent, so a
block that names a fingerprint has already selected the proxy.

`scope` says what the sandbox may do with the key, and must be set:

| value | grants |
|---|---|
| `"sign"` | sign with the key (`gpg --detach-sign`, and `git commit -S` — snug turns OpenPGP commit signing on) |
| `"decrypt"` | decrypt a message addressed to the key |

`scope = ["sign", "decrypt"]` grants both. snug resolves the keygrips from the
fingerprint, and pins **subkeys only**:

- `"sign"` pins the key's signing subkeys. The primary key is never pinned,
  because it also certifies: through it the sandbox could add a user ID to your
  key, bind a subkey it holds, or revoke the key, and all of those outlive the
  run. A key without a signing subkey is refused. Add one on the host with
  `gpg --quick-add-key <fingerprint> ed25519 sign`.
- `"decrypt"` pins the encryption subkeys, expired ones included, so mail
  already addressed to them still decrypts. A key without one is refused.

There is no `"encrypt"` value, deliberately: encrypting **to** the key uses only
the public half, needs no agent, and so grants nothing a sandbox does not
already have. There is no `"auth"` value either: gpg-agent's ssh-emulation side
is a protocol snug has not measured, and a value whose verbs are unenforced
would be a scope in name only.

A `"decrypt"` grant cannot sign, and a `"sign"` grant cannot decrypt. The agent
keeps one selected key per connection whichever verb selected it, so the proxy
also checks that the signing or decrypting command follows a selection made
for that purpose.

A hostile process inside the sandbox can use this block to sign anything as you
with the pinned signing subkey, and to decrypt anything addressed to the pinned
encryption subkey that it can read, for as long as the run lasts. It cannot
certify, list or use your other keys, export key material, or decide where a
passphrase prompt appears or what it says. A prompt for a sandbox request names
snug and the keygrip, and appears wherever your agent shows prompts, never on
the terminal the sandbox shares with you.

### `identity.gh`

| key | value | default |
|---|---|---|
| `host` | the host `gh` gets a token for | `github.com` |
| `user` | the account whose token is staged | none |

snug stages that account's token in a private `hosts.yml` and sets
`GH_CONFIG_DIR` to its directory. `gh` itself must be inside; see
[Staging a single program](filesystem.md#staging-a-single-program-snugbin).

### `identity.kubectl`

| key | value | default |
|---|---|---|
| `context` | a context in the host kubeconfig | none |
| `server` | the API server **remote** URL that context must name | none |
| `credential` | `"client-certificate"` or `"token"` | the one the user entry holds |
| `kubeconfig` | path to the host kubeconfig | `{home}/.kube/config` |

```toml
[profile.aks-dev]
ro = ["{home}/bin/kubectl:/snug/bin/kubectl"]

  [profile.aks-dev.identity.kubectl]
  context    = "dev"
  server     = "https://dev.example.com:443"
  credential = "client-certificate"
```

`snug` reads the context's cluster and user entry from the host `kubeconfig`
and generates a `~/.kube/config` inside the sandbox. This config has a single
cluster, a single context and an empty user. No certificate, token or exec
plugin enters the sandbox. The server it names is `http://127.0.0.1:6443`,
which is snug's proxy. It presents the context's own credential and
forwards each request over TLS to `server`, and nowhere else.

The proxy runs on the host and uses the host network, so `@net` is not
required.

`credential` picks which one credential of the context's user entry the proxy
presents to the upstream `server`. It is required only when that entry in the
host kubeconfig holds more than a single credential.

- `client-certificate`: the `client-certificate-data` and
  `client-key-data`, as the proxy's TLS client certificate.
- `token`: the static token, as the bearer. It replaces any
  `Authorization` the sandboxed client may send.

snug protects the host, not the cluster.

Unlike the [container proxy](containers.md), this proxy does not filter the
Kubernetes API. The sandbox can do anything your RBAC allows on that server.

What snug does guarantee is that your Kubernetes credentials never enter the
sandbox, so nothing inside can leak them.

#### Refused before the run

snug does not start the sandbox for:

- a `server` on this host. Loopback, the host's own addresses, link-local and
  cloud-metadata addresses and their IPv6 spellings (NAT64, 6to4) are refused,
  and so is any address that lies on a subnet of a host interface snug does
  not trust as a remote network, or that a specific route of the host's
  routing table (not the default route) sends out through one, or whose route
  the kernel delivers to this host (local, broadcast, anycast, multipath). That would be an easy sandbox escape: a kind, minikube or
  libvirt cluster runs its nodes on this host. A cluster on a physical LAN,
  behind a layer-3 VPN or beyond the default gateway is allowed.
  The allowed interfaces are the whole list: a physical NIC (not enslaved to a
  bridge or bond), a `wwan` modem, a `tun` interface in layer-3 mode and a
  `wireguard` interface. Everything else is refused: `bridge`, `veth`, `tap`
  (a `tun` in layer-2 mode), `macvlan`, `macvtap`, `ipvlan`, `ipvtap`, `vxlan`,
  `geneve`, `dummy`, `vrf`, `bond`, `team`, `vlan`, `gre`, `gretap`, `ipip`,
  `sit`, `erspan`, and any kind not named here. A LAN uplink enslaved to a
  bridge, or a vlan or bond uplink, therefore refuses a LAN cluster; a cluster
  on the internet is still reached through the default route.
- `insecure-skip-tls-verify` or `proxy-url` in the cluster entry.
- a certificate, key or CA given by path.
- a kubeconfig the sandbox could read or write through any grant.
- a context whose user authenticates with an exec plugin (`kubelogin`,
  `aws`, `gke-gcloud-auth-plugin`): snug does not run exec plugins yet, see
  [#674](https://github.com/gomoni/snug/issues/674).

`snug --dry-run` shows the context, the credential presented, and what was
left out.

### Rules

- **`host` is written in both blocks.** `identity.ssh.host` and
  `identity.gh.host` are independent and nothing is inherited between them.
  Naming one while the other block is in use is an error. Just write the same
  value twice if it is the same host.
- **`gh.host` without `gh.user` is an error** as it would stage whichever
  account your host `gh` happens to be logged in to.
- snug does **not** checks that the ssh key and the `gh` user are the same
  account. Inside the sandbox, check with:

  ```sh
  ssh -T git@github.com
  gh api user --jq .login
  ```
