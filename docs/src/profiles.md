# Profiles

A profile is a basic configuration unit for `snug`. They can be `included` in
other profiles, but in a strictly order independent ways. The aim is that profiles
will be small independent reusable parts of a bigger configuration.

At the same time nothing prevents one to have a big monolithic profiles
including only a builtin ones. Configuration language is TOML and a profile
looks like this

```toml
# ~/.config/snug/profiles.d/build.toml
[profile.build]
description = "My build: network access and rw cache in /srv/cache/build"
include = ["@net"]
rw = ["/srv/cache/build"]
```

```sh
snug -p build ~/src/proj
```

## TOML style

Write a table that has more than one key, or does not fit on one line, as a
`[table]` header. Keep inline tables `{}` for short single-line values. This
is the same as `Cargo.toml` does.

```toml
[profile.tools]
symlink = [{ at = "/usr/local/bin/python", target = "/usr/bin/python3" }]

[profile.tools.environ.set]
EDITOR = "/usr/bin/vi"
PAGER  = "/usr/bin/less"
```

## Names

A profile name is one character from `[a-zA-Z0-9]` followed by any number
from `[a-zA-Z0-9-]`. No underscore, no dot and no leading hyphen.

Built-in profiles carry a leading `@` which is not allowed for user defined ones.
So user can define `sys`, but that is a different one from `@sys`.

## Keys

| key | page |
|---|---|
| `description`, `include` | this page |
| `ro`, `rw`, `tmpfs`, `symlink`, `optional`, `nss` | [Filesystem grants](filesystem.md) |
| `environ.set`, `.merge`, `.prepend`, `.inherit`, `.sanitise` | [Environment](environment.md) |
| `network`, `dns`, `mtu`, `listen_names` | [Network](network.md) |
| `identity.ssh.*`, `identity.git.*`, `identity.gh.*` | [Identity](identity.md) |
| `podman` | [Containers](containers.md) |
| `plugins` | [Profile keys: `plugins`](reference/profile-keys.md#plugins) |

The full list with types is [Profile keys](reference/profile-keys.md).

An unknown key anywhere in a profile is an error, and the file does not load.
A typo such as `netwrok = "egress"` is never silently ignored.

### Feature keys and built-ins

A feature key turns on a host integration that snug builds itself.

| key | snug makes |
|---|---|
| `network` | egress through the `pasta` helper (every sandbox has its own empty network namespace) |
| `dns` | `/etc/resolv.conf` |
| `nss` | `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf` |
| `podman` | a container engine and a proxy socket at `/snug/podman.sock` |

A built-in profile that sets a feature key is that key plus the grants and
includes the feature needs to be usable:

| built-in | is |
|---|---|
| `@net` | `network = "egress"` and `dns = true` |
| `@podman-socket` | `podman = "socket"`, `@sys`, `@home` and read-only `/etc/containers` (optional) |
| `@podman-build` | `@podman-socket` and `podman = "build"` |
| `@sys` | sets `nss = true` among its grants |

Prefer the built-in profiles: each enables a feature and grants the paths it
needs. [Built-in profiles](builtins.md) lists them all.

### `description`

One line, shown by `snug profile list`.

### `include`

Other profiles this one pulls in.

```toml
include = ["@sys", "@home", "work-identity"]
```

Profiles forms a set, so they're activated together, the order, duplicates or
even cycles does not matter.

## How profiles combine

Every key has one of four combination rules:

| rule | keys |
|---|---|
| **union** | `ro`, `rw`, `tmpfs`, `symlink`, `listen_names`, `plugins`, `environ.merge`, `environ.inherit`, `environ.sanitise` |
| **maximum** — the more permissive value wins | `network`, `podman`, `dns`, `nss`, and the access of two grants at one path (`rw` beats `ro`) |
| **must agree** — two different values are an error naming both profiles | `mtu`, `environ.set`, `identity` (as one whole block)|
| **at most once** | `environ.prepend` can be specified once per a variable |

When profiles define conflicting options, the run is rejected.
