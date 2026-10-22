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

- `HOST` — bind host `HOST` at the same path inside, or
- `HOST:GUEST` — bind host `HOST` at `GUEST` inside.

The host side is resolved through symlinks once, at start; see
[Host symlinks](#host-symlinks). Guest side is used as written.

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
| `{target}` | the directory given on the command line, symlinks resolved, see [Host symlinks](#host-symlinks) |
| `{target_parent}` | the parent of `{target}` |
| `{home}` | your account's home directory (`getent passwd`), symlinks resolved, see [Host symlinks](#host-symlinks) and [The home directory](#the-home-directory) |
| `{lbrace}` | a literal `{` |
| `{rbrace}` | a literal `}` |
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

## Host symlinks

Symlinks are a _disaster_ for a security sensitive software and traditional
path based tools. TOCTOU, sandbox escapes, privilege problems, you name it.

A sandbox can create symlinks wherever it can write. And a later run would
follow them. So `snug` follows a host symlink only when it is owned by root.
`snug` checks every symlink on the host side of a grant, on the target and
on `{home}`:

- A link owned by root is followed when the directory it sits in is also
  owned by root and not writable by group or others, and snug itself does not
  run as root. A link in a directory someone else can write could have been
  moved there, so it counts as yours.
- A link owned by you (or a subuid) is refused, unless another `ro` or `rw`
  grant of this run already exposes the path the link resolves to, at the
  same or higher access. That grant may name the path itself or any of its
  ancestors, not only its parent: `/data` covers a link that resolves to
  `/data/projects/app`. It must not go through such a link itself.
- Inside `{target}` no link redirects a grant.

Resolve your own symlinks: write the real path in the profile and on the
command line (or `cd -P` first). If `{home}` is such a link, make the real
directory the account's home (`usermod -d`).

When the target went through a root-owned symlink, the `TARGET` line of
`--dry-run` shows the real path and ends with the path you gave. With
`/usr/share/groff/current -> 1.23.0`, owned by root:

```text
TARGET   /usr/share/groff/1.23.0  (read-only, via @parent-ro covering /usr/share/groff)  (resolved from /usr/share/groff/current)
```

### A link swapped in during start

Another sandbox could swap a path for a link after snug resolved it. So snug
opens each host path without following symlinks and hands bwrap the file
descriptor, not the path. A link found at that point refuses the run; a swap
after it changes nothing. Grants under `/proc` are bound by path.

`--dry-run` lists these as `bind sources` below the bwrap command, one line
per grant:

```text
  fd 18  ro  /opt  (optional: omitted if absent at launch)
  fd 19  ro  /usr
```
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

A grant whose guest path leads through a `symlink` entry is checked where it
lands. Landing in one of the [paths snug owns](#paths-snug-owns) is refused
with a message naming the link:

```toml
[profile.p]
symlink = [{ at = "/opt/lnk", target = "/proc" }]
tmpfs   = ["/opt/lnk/x"]
```

```text
snug: grant /opt/lnk/x (from p) resolves through the symlink /opt/lnk -> /proc,
      landing at /proc/x, at or inside /proc, which is snug's own; no grant may
      be made there. Remove the grant, or point the symlink somewhere else
```

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

### No `$PATH` lookup

snug never searches `$PATH` to find what a grant names. A grant is an absolute host
path or starting with `{home}` or `{target}`. A bare `claude` is not a program to look up,
and `$PATH` is not expanded.

`@claude` stages Claude Code from `~/.local/bin/claude`, where its installer
puts it. If yours is elsewhere, find the real file and stage it yourself next
to `@claude`:

```sh
$ readlink -f "$(command -v claude)"
/opt/claude/bin/claude
```

```toml
[profile.my-claude]
include = ["@claude"]
ro = ["/opt/claude/bin/claude:/snug/bin/claude"]
```

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

Both checks see through symlinks: the host side after
[Host symlinks](#host-symlinks) are resolved, the guest side after
[`symlink`](#symlink) entries are followed.

## Generated account files: `nss`

`nss = true` makes snug generate `/etc/passwd`, `/etc/group` and
`/etc/nsswitch.conf`. The files hold one account, yours, with the sandbox's
`$HOME` as its home directory, and one group, your primary group. They replace
any profile's grant at those three paths. Any profile setting `true` wins;
`@sys` sets it (see [Feature keys and built-ins](profiles.md#feature-keys-and-built-ins)).

Without `nss`, none of the three is generated, and a profile may bind its own
copies instead.

Inside a sandbox, snug takes the account only from these generated files. With
any other `/etc/passwd`, `snug --dry-run` inside the sandbox refuses to run.

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
  parent would be `{home}` itself.

To run with a read-only target, drop the defaults:
`snug --no-defaults -p @sys -p @home -p @parent-ro DIR`.

`--dry-run` shows how the target is reached on its `TARGET` line, for example
`(read-only, via @parent-ro covering /home/me/src)`. A target reached
through a symlink follows [Host symlinks](#host-symlinks).

## The home directory

`snug` never reads the `$HOME` and rely on `usr/bin/getent` or `/bin/getent` as
an input for user related data. This makes `snug` compatible with Glibc NSS
plugins, while avoiding cgo. Use `{home}` in the configuration.

A home that is a system directory (`/`, `/etc`, `/usr`, `/var`) is refused,
because `@home` puts a writable tmpfs over it. A home can be `/var/lib/me`.

`--dry-run` prints where the account came from:

```text
snug: account: me, home /home/me (from /usr/bin/getent)
```
