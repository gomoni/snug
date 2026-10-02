# Filesystem grants

The sandbox root is an empty, read-only filesystem. Every path you can see
inside it is explicitly enabled (granted) by a profile. `snug` re-creates the
same filesystem structure as host to avoid confusion and make sandbox easier to
understand. The parent directories of a grant are created empty. Granting
`/opt/tools` creates `/opt` inside, and `ls /opt` shows `tools` and nothing
else from the host.

```toml
[profile.tools]
ro      = ["/opt/tools", "{home}/bin/rg:/snug/bin/rg"]
rw      = ["/srv/cache/tools"]
tmpfs   = ["{home}/.npm"]
symlink = [{ at = "/usr/local/bin/python", target = "/usr/bin/python3" }]
optional = ["/opt/tools"]
```

## Grant types

| key | value | creates |
|---|---|---|
| `ro` | list of path specs | a read-only bind of a host path |
| `rw` | list of path specs | a writable bind of a host path. Be aware writes reaches the host, there's no middle layer |
| `tmpfs` | list of guest paths | an empty writable directory in memory, at most [`tmpfs_size`](#tmpfs) (default 1 GiB) |
| `symlink` | list of `{ at, target }` | a symlink at guest path `at` pointing to `target` |
| `optional` | list of paths | nothing by itself; an `ro` or `rw` host path must exist, and listing it here skips it instead when it is absent |

