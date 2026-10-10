# Filesystem grants

The sandbox root is an empty, read-only filesystem. Every path you can see
inside it is explicitly enabled (granted) by a profile. `snug` re-creates the
same filesystem structure as host to avoid confusion and make sandbox easier to
understand. The parent directories of a grant are created empty. Granting
`/opt/tools` creates `/opt` inside, and `ls /opt` shows `tools` and nothing
else from the host.

```toml
[profile.example]
ro       = ["/opt", "/opt/app1:/app", "~/.cargo/bin", "{target_parent}"]
rw       = ["/run/foo/bar", "{target}:/work"]
optional = ["/opt/app1", "~/.cargo/bin", "/run/foo/bar"]
tmpfs    = ["{home}/.npm"]
symlink  = [{ at = "/usr/local/bin/python", target = "/usr/bin/python3" }]
```

## Grant types

| key | value | creates |
|---|---|---|
| `ro` | list of path specs | a read-only bind of a host path |
| `rw` | list of path specs | a writable bind of a host path. Be aware writes reaches the host, there's no middle layer |
| `tmpfs` | list of guest paths | an empty writable directory in memory, at most [`tmpfs_size`](#tmpfs) (default 1 GiB) |
| `symlink` | list of `{ at, target }` | a symlink at guest path `at` pointing to `target` |
| `optional` | list of paths | nothing by itself; an `ro` or `rw` host path must exist, and listing it here skips it instead when it is absent |

## Path specs

A path grant is read-only (`ro`) or read-write (`rw`). Host paths, which are
not granted remain not accessible inside the sandbox. The spec is split at the
first `:`. After variable expansion (for example `{target}`) both sides must be absolute.

- `PATH` — bind host `PATH` at the same path inside, or
- `HOST:GUEST` — bind host `HOST` at `GUEST` inside.

The host side is resolved through symlinks once, at start, and bwrap binds
the destination. Guest side is used as written.

A sandbox can create symlinks wherever it can write, and a later run would
follow them. So snug follows a symlink on the host side only when it is owned
by root:

- A link owned by root is followed, unless snug itself runs as root.
- A link owned by you (or a subuid) is refused, unless this run also grants
  its destination, or a directory above it, at the same or higher access.
- Inside `{target}` no link redirects a grant, whoever owns it.

If you made the link yourself, grant its destination instead. With
`~/projects -> /data/projects`, write `/data/projects`, or
`/data/projects:{home}/projects` to keep the path inside. The refusal names
the link and suggests both.

<!-- TODO(#636, #637): a link planted on the target path itself still
redirects the target, and a concurrent sandbox can swap a grant's path
between resolve and bind. Update this section when those land. -->

By default not existing host paths fail to start, unless `optional` is used.

### Examples

The examples below assume `{home}` (or `~`) is `/home/me` and the `{target}` is
`/home/me/src/app` and a `{target_parent}` is then `/home/me/src`.

| spec | host | guest | note |
|---|---|---|---|
| `/opt` | `/opt` | `/opt` | same path on both sides |
| `/run/foo/bar/` | `/run/foo/bar` | `/run/foo/bar` | a trailing `/` is dropped |
| `/opt/app1:/app` | `/opt/app1` | `/app` | bind at a different path |
| `~/.cargo/bin` | `/home/me/.cargo/bin` | `/home/me/.cargo/bin` | `~/` only at the start |
| `{home}/bin/rg:/snug/bin/rg` | `/home/me/bin/rg` | `/snug/bin/rg` | a single file |
| `{target}` | `/home/me/src/app` | `/home/me/src/app` | the project directory |
| `{target_parent}` | `/home/me/src` | `/home/me/src` | its siblings too |
| `{target}:/work` | `/home/me/src/app` | `/work` | project at a fixed path |
| `opt` | — | — | refused: not absolute |
| `/opt:ro` | — | — | refused: guest `ro` is not absolute |
| `/opt:` | — | — | refused: empty guest |
| `{user}/bin` | — | — | refused: unknown variable |
| `$HOME/bin` | — | — | refused: `$` is not expanded, so not absolute |
| `/opt/$HOME` | `/opt/$HOME` | `/opt/$HOME` | `$` is a literal character |

### Variables

Those are NOT environment variables. The home directory is spelled `{home}` or
`~`. `$HOME` has no meaning and is taken as it. `/opt/$HOME` is the literal
path `/opt/$HOME`, and `$HOME/bin` is refused because it is not absolute.

| variable | value |
|---|---|
| `{target}` | the directory given on the command line, symlinks resolved |
| `{target_parent}` | the parent of `{target}` |
| `{home}` | `$HOME`, symlinks resolved |
| `~/` | `{home}/`, only as the first two characters |

Variables expand in `ro`, `rw`, `tmpfs`, `symlink`, `optional`. A path
containing `:` or `{` cannot be written in a spec. A `:` or `{` that comes from
a variable's value is part of the path:

| path to grant | spec | result |
|---|---|---|
| `/mnt/a:b` | `/mnt/a:b` | refused: `both sides must be absolute paths`; split into host `/mnt/a`, guest `b` |
| `/tmp/{foo}` | `/tmp/{foo}` | refused: `unknown variable {foo}` |
| `/mnt/a:b` | `/mnt` | works; grants the whole parent |
| `/w/x:y`, snug run on it | `{target}` | works; `/w/x:y` on both sides |
| `/tmp/{foo}`, snug run on it | `{target}` | works; `/tmp/{foo}` on both sides |


## `tmpfs`

Each entry is a guest path, never a host path. Each tmpfs is limited to
`tmpfs_size` from [`config.toml`](configuration.md#configtoml) (default
1 GiB). The limit is per mount, not a total: snug also creates its own tmpfs
mounts, such as `/tmp` and `$HOME` with `@home`, each with the same limit, and
`--dry-run` lists them all. A write past the limit fails with "No space left on
device".

The content lives in memory (and swap), so a full tmpfs uses host RAM until
the run ends.

## `symlink`

```toml
symlink = [{ at = "/bin", target = "usr/bin" }]
```

`at` is an absolute guest path. `target` is stored as written, so a relative
target is resolved from the link's directory, as with `ln -s`. `target` must
be a clean path with no `..` component.

A symlink is not a mount. snug writes a link into the sandbox's own root, and
nothing from the host comes with it. It grants nothing either: if no grant
makes `target` visible, the link dangles. Like a mount, it cannot be placed
inside a path another grant exposes.

## `optional`

```toml
ro       = ["/etc/ssl", "/etc/pki"]
optional = ["/etc/ssl", "/etc/pki"]
```

Normally the host path of every `ro` and `rw` grant must exist, or snug
refuses to start:

```text
snug: profile "go" grants "/usr/local/go/bin" which does not exist
      create it, or mark it optional if that is expected
```

`optional` relaxes that for the grants it lists. 

## Staging a single program: `/snug/bin`

`/snug/bin` is on the sandbox's `PATH` ahead of `/usr/bin` whenever something
is staged there, and it is not writable from inside. To add one tool, bind
the file, not its directory:

```toml
[profile.gh-cli]
ro = ["{home}/bin/gh_2.60.0_linux_amd64/bin/gh:/snug/bin/gh"]
```

Binding a directory such as `~/.local/bin` hands over every program in it.
Nothing else may be mounted under `/snug`.

## Two grants at one path

Grants at the **same** guest path combine only when they describe the same
thing: the same kind, the same host source. Their access is the maximum, so
`ro` and `rw` of one path give `rw`. Anything else is an error naming both
profiles.

## Grants inside grants

The **deepest** grant covering a path decides what is true there. This is how
to express "X but not Y" without a deny rule:

```toml
[profile.git-ro]
ro = ["{target}/.git"]
```

With `@target-rw`, the project is writable and its `.git` is read-only.

A grant inside another grant must not hide what the outer one shows:

| outer grant | a grant inside it is |
|---|---|
| `tmpfs` | allowed: there is nothing to hide |
| `ro`/`rw` of host `H` | allowed only when it binds the same tree, `H/sub` at `…/sub`; anything else is refused |

## Paths snug owns

| path | rule |
|---|---|
| `/proc`, `/dev`, `/sys` | snug creates them; any grant at or below them is refused |
| `/snug` | only a single read-only file under `/snug/bin` |
| `/tmp` | a private tmpfs, unless a profile grants the path itself, e.g. `rw = ["/srv/share:/tmp"]` |

A grant is also refused if it would carry in a kernel tree mounted beneath
its host path — `/sys`, `/proc` or `/dev` — because a bind is recursive.

Both checks see through symlinks: the host side is checked after symlinks
are resolved, the guest side after snug's own `symlink` entries are followed.

## Generated account files: `nss`

`nss = true` makes snug generate `/etc/passwd`, `/etc/group` and
`/etc/nsswitch.conf`. The files hold one account, yours, with the sandbox's
`$HOME` as its home directory, and one group, your primary group. They replace
any profile's grant at those three paths. Any profile setting `true` wins;
`@sys` sets it (see [Feature keys and built-ins](profiles.md#feature-keys-and-built-ins)).

Without `nss`, none of the three is generated, and a profile may bind its own
copies instead.

## The target

The target is the directory you run snug on. It must be visible inside the
sandbox, so at least one selected profile has to grant it, directly or by
granting a directory above it. If none does, snug refuses to start:

```text
snug: target /home/me/src/app is not visible inside the sandbox: no profile grants it.
```

Two built-in profiles exist for this:

- `@target-rw` grants the target read-write. It is in the default list, so a
  plain `snug DIR` gets it. Changes the sandbox makes there land on the host.
- `@parent-ro` grants the target's parent directory read-only. The target is
  then readable but not writable, and so is every sibling directory next to
  it. A target directly in your home directory is refused, because its
  parent would be `$HOME` itself.

To run with a read-only target, drop the defaults:
`snug --no-defaults -p @sys -p @home -p @parent-ro DIR`.

`--dry-run` shows how the target is reached on its `TARGET` line, for example
`(read-only, via @parent-ro covering /home/me/src)`.
