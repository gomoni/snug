# Profile keys

Every key a `[profile.NAME]` table accepts. Any other key is an error.

| key | type | values | combined by | page |
|---|---|---|---|---|
| `description` | string | one line | — | [Profiles](../profiles.md#description) |
| `include` | array of strings | profile names | union | [Profiles](../profiles.md#include) |
| `ro` | array of strings | path specs | union; `rw` wins at one path | [Filesystem](../filesystem.md) |
| `rw` | array of strings | path specs | union; `rw` wins at one path | [Filesystem](../filesystem.md) |
| `tmpfs` | array of strings | guest paths | union | [Filesystem](../filesystem.md#tmpfs) |
| `symlink` | array of tables | `{ at = "…", target = "…" }` | union; one target per `at` | [Filesystem](../filesystem.md#symlink) |
| `optional` | array of strings | paths | this profile only | [Filesystem](../filesystem.md#optional) |
| `nss` | boolean | `true`, `false` | any `true` | [Filesystem](../filesystem.md#generated-account-files-nss) |
| `environ.set` | table of strings | `NAME = "value"` | must agree | [Environment](../environment.md) |
| `environ.merge` | table of strings or arrays | `NAME = ["…"]` | union | [Environment](../environment.md) |
| `environ.prepend` | table of strings or arrays | `NAME = ["…"]` | one profile per name | [Environment](../environment.md) |
| `environ.inherit` | table of booleans | `NAME = true` | union | [Environment](../environment.md) |
| `environ.sanitise` | table of booleans | `NAME = true` | union | [Environment](../environment.md) |
| `environ.types` | table of strings | `NAME = "path"`, `NAME = "path-list"` | this profile only | [Environment](../environment.md#declaring-a-type) |
| `network` | string | `"egress"`; absent: `"isolated"` | maximum | [Network](../network.md) |
| `dns` | boolean | `true`, `false` | any `true` | [Network](../network.md#dns) |
| `mtu` | integer | bytes | must agree | [Network](../network.md#mtu) |
| `listen_names` | array of strings | door names | union | [Network](../network.md#http-doors-listen_names) |
| `identity.ssh.host` | string | host name | the block must match | [Identity](../identity.md#identityssh) |
| `identity.ssh.key` | string | path to a public key | the block must match | [Identity](../identity.md#identityssh) |
| `identity.ssh.agent` | string | `"proxy"`, `"none"` | the block must match | [Identity](../identity.md#identityssh) |
| `identity.git.name` | string | author name | the block must match | [Identity](../identity.md#identitygit) |
| `identity.git.email` | string | author email | the block must match | [Identity](../identity.md#identitygit) |
| `identity.git.signing_key` | string | path to a public key | the block must match | [Identity](../identity.md#identitygit) |
| `identity.gh.host` | string | host name | the block must match | [Identity](../identity.md#identitygh) |
| `identity.gh.user` | string | account name | the block must match | [Identity](../identity.md#identitygh) |
| `identity.kubectl.context` | string | context name in the kubeconfig | the block must match | [Identity](../identity.md#identitykubectl) |
| `identity.kubectl.server` | string | API server URL | the block must match | [Identity](../identity.md#identitykubectl) |
| `identity.kubectl.credential` | string | `"client-certificate"`, `"token"` | the block must match | [Identity](../identity.md#identitykubectl) |
| `identity.kubectl.kubeconfig` | string | path; absent: `{home}/.kube/config` | the block must match | [Identity](../identity.md#identitykubectl) |
| `podman` | string | `"socket"`, `"build"`; absent: `"off"` | maximum | [Containers](../containers.md) |
| `plugins` | array of strings | Claude Code plugin names | union | [Claude Code](../claude.md#plugins) |
| `login` | array of strings | `"claude"` | union | [Claude Code](../claude.md#login) |

`network` and `podman` combine by maximum, so the value a key has when
no profile sets it is the lowest one: `"isolated"`, `"off"`. A
profile cannot make a maximum lower, so writing that value would change
nothing, and the profile is refused:

```text
profile "p": podman = "off" changes nothing: "off" is the default and a profile can only add. Remove the line.
```

## `identity`

Each block (`ssh`, `git`, `gh`, `kubectl`) is its own pin. Two selected profiles
that set the same block differently are refused, naming both; different blocks
from different profiles combine. `identity.git.signing_key` must be in the
profile that sets `identity.ssh`.

It is recommended to create a profile with an identity only and include it.
