# Configuration files

Profiles are in `profiles.d/*.toml` and preferences can be stated in `$XDG_CONFIG_HOME/snug/config.toml`.

## Profile configuration

There are three layers.

| layer | path | holds |
|---|---|---|
| built-in | compiled into snug itself | built-in profiles like `@sys`, `@net`, default limits |
| system | `/etc/snug/profiles.d/*.toml` | system-wide shared profiles |
| user | `$XDG_CONFIG_HOME/snug/profiles.d/*.toml` (default `~/.config/snug/profiles.d/*.toml`) | user-specific profiles |

- Only regular files ending in `.toml` are read, in sorted order.
- A profile name defined twice, in any two files or layers, is an error naming both
  files. A later layer adds names; it **never** redefines one.
- A built-in profile cannot be shadowed by system or user profiles.
- A file that is valid TOML but fails snug's checks, such as an unknown key,
  makes the profiles it defines unselectable. A run or `--dry-run` that
  selects or includes one refuses, naming the file. Other runs go ahead and
  print a note naming it.
- A file that is not valid TOML or cannot be read, or a `profiles.d` that
  cannot be listed, stops every run: snug cannot tell which profiles it
  defines.
- A file that fails snug's checks still claims the names it defines. A name
  that another file or a built-in also defines is an error, as above, for
  every command.
- Otherwise `snug profile list` and `snug config` report a failed file,
  continue with the rest, and exit with status 77.

### Profiles are never read from a target directory

TOML files anywhere else are never read. `snug` exists to protect the host,
so it never reads repository content.

## Selecting profiles

A `-p` selects a set of profiles, built like this:

1. Start from `defaults`: the built-in list `@sys @home @target-rw`, or the
   `defaults` key in `config.toml`, which **replaces** the built-in list.
2. `--no-defaults` drops that list.
3. Each `-p NAME` **adds** one profile. `-p PROF1 -p PROF2` **adds** two.
4. Every `include` is followed, and the resulting sandbox is the union of all grants.

So `snug -p @net DIR` runs `@sys @home @target-rw @net`. Naming a profile
twice, or reaching it through two includes, changes nothing.

### Default profiles

- `@sys`: brings read-only `/usr`, `/bin`, and a safe and minimal subset of `/etc` entries.
- `@home`: tmpfs `$HOME` plus `.cache`, `.config`, `.local/state`, `.local/share` and the `XDG_*` environment variables.
- `@target-rw`: the target directory is read-write.

### Do not run default profiles

`@target-rw` is in the default list, so start from `--no-defaults`. The target
must still be visible, and `@parent-ro` makes it readable:

```sh
snug --no-defaults -p @sys -p @home -p @parent-ro DIR
```

`@parent-ro` grants the target's parent, so every sibling of `DIR` is readable
too. Without it snug refuses to run: no profile grants the target.

## `config.toml`

Path: `$XDG_CONFIG_HOME/snug/config.toml`

The file is optional; if it exists, it must be valid.

```toml
defaults   = ["@sys", "@home", "@target-rw", "@git"]
tmpfs_size = "512 MiB"
```

| key | type | default | meaning |
|---|---|---|---|
| `defaults` | array of profile names | `["@sys", "@home", "@target-rw"]` | What a run selects before `-p`. Replaces the built-in list. `[]` is legal and selects nothing. |
| `tmpfs_size` | string with a unit | `"1 GiB"` | Size limit of **each** tmpfs mount snug creates. Not a total: `--dry-run` lists every tmpfs. |

- Names in `defaults` are written as on the command line: `@sys` for a
  built-in, `work` for yours.
- `tmpfs_size` needs a unit: `B`, `kB`, `MB`, `GB`, `TB` (1000-based) or
  `KiB`, `MiB`, `GiB`, `TiB` (1024-based). A bare number, a fraction, `"0 B"`
  and anything above `1 TiB` are refused.
- Any other key is an error. A `[profile.NAME]` table here is an error too:
  profiles live in `profiles.d`.

`snug config` prints the effective values and where each came from.
