# Environment

Nothing from the host environment passes into the sandbox by default. `snug`
sets essential variables such as `HOME` and `PATH`, copies the host's `LANG`,
`TERM` and `TZ`, and always sets `SNUG=1`, `SNUG_PROFILES` and `SNUG_TARGET`.

Some features add their own, such as `DOCKER_HOST` when `podman` is on. See
[Names snug writes](reference/environment-names.md#names-snug-writes) for the
full list.

A profile writes variables under `environ`, with one table per verb:

```toml
[profile.tools]
ro = ["/opt/tools/bin", "/opt/tools/override"]

[profile.tools.environ.set]
EDITOR = "/usr/bin/vi"

[profile.tools.environ.merge]
PATH = ["/opt/tools/bin"]

[profile.tools.environ.prepend]
PATH = ["/opt/tools/override"]

[profile.tools.environ.inherit]
COLORTERM = true

[profile.tools.environ.sanitise]
PKG_CONFIG_PATH = true
```

## Types

Environment variables are, by Unix tradition, only strings. So that a
_declarative_ configuration language can interpret and modify them, `snug`
recognizes many of them and assigns each a _type_. Every name it knows by
default is in [Environment names](reference/environment-names.md).

The recognized types are:

- **scalar**: one value, such as `EDITOR`.
- **path**: a scalar whose value is a filesystem path, such as
  `XDG_CONFIG_HOME`. It must be absolute and [granted](#rules).
- **path-list**: filesystem paths joined by a separator, such as `PATH` with
  `:`. Each element must be absolute and [granted](#rules). Empty elements are
  guarded; see [Empty list elements](#empty-list-elements).
- **unknown**: a name snug has no type for. A profile can
  [declare](#declaring-a-type) it `path` or `path-list`.

snug also knows a few lists no profile may write, such as `LD_PRELOAD`; they
take no verbs.

## Verbs

A variable's type decides which verbs (operations) it accepts. Unsupported verbs are refused.

| verb | value | effect | across profiles | known name | unknown name |
|---|---|---|---|---|---|
| `set` | string | sets a scalar | profiles must agree on the value | scalar | yes |
| `merge` | string or array of strings | adds elements to a list | union, sorted, duplicates removed | path-list, if its row allows it | only if the profile declares it `path-list` |
| `prepend` | string or array of strings | puts elements at the front of a list, in the order written | one profile per variable | path-list, if its row allows it | only if the profile declares it `path-list` |
| `inherit` | `true` | copies the host's value, if the host has one | union | scalar | yes |
| `sanitise` | `true` | copies the host's list, keeping only elements that are granted inside and hold the host's content | union | path-list, if its row allows it | no |

- snug cannot check the value of an unknown name, so `snug profile show`
  marks its row `← unknown: snug has no type for this name`. Built-in profiles may not use
  unknown names.
- Some rows carry a `←` note saying what a tool does with the value, such as
  python running `sitecustomize.py` from a `PYTHONPATH` directory. The note is
  information only; it changes nothing.
- `sanitise` works only on names snug types itself, and only on those whose
  row in [Environment names](reference/environment-names.md) lists it. snug
  allows it where it knows what an empty element means to the program reading
  the list, so a declared `path-list` never takes it.
- A string in `merge` or `prepend` is **one** element. `snug` never splits a
  value. So always write `["/a", "/b"]`, not `"/a:/b"`.
- `inherit` and `sanitise` take `true`. `false` is an error: nothing was
  inherited to begin with, so there is nothing to turn off.
- `set`, `merge` and `prepend` values expand `{target}`, `{home}` and the
  other [path variables](filesystem.md#variables).

## Declaring a type

A profile can give an unknown name a type under `environ.types`. A type declaration
applies only to that profile's own `environ` lines.

```toml
[profile.ruby]
ro = ["{home}/.gem"]

[profile.ruby.environ.types]
GEM_PATH = "path-list"

[profile.ruby.environ.merge]
GEM_PATH = ["{home}/.gem"]
```

| type | shape | verbs | what the profile writes |
|---|---|---|---|
| `path` | one value | `set`, `inherit` | an absolute, granted path |
| `path-list` | list separated by `:` | `merge`, `prepend` | absolute, granted paths |

- Only `path` and `path-list` are accepted, spelled exactly so.
- A declared `path-list` takes `merge` and `prepend`, never `sanitise`. See
  [Verbs](#verbs).
- Because a declaration covers only its own profile, a profile is valid or
  not on its own, whatever else is selected.
- A declaration must be used: `path-list` needs a `merge` or `prepend` of the
  name in the same profile, `path` needs a `set`. `inherit` does not count.
- Two profiles may both declare one name `path-list` and merge into it; the
  elements are joined as for any list. A name that is a list in one profile
  and one value in another (`set`, `inherit` or `path`) is refused, naming
  both.
- A declaration cannot change the type of a name snug already knows, such as
  `PYTHONPATH`. Declaring it `path-list`, which it already is, has no effect,
  and `snug profile show` marks the line `← redundant`. Declaring it `path` is
  refused.
- These names cannot be declared at all: [names snug
  writes](reference/environment-names.md#names-snug-writes), [names snug writes
  when a feature is on](reference/environment-names.md#names-snug-writes-when-a-feature-is-on),
  `PWD`, and any name a built-in profile writes.
- Built-in profiles never declare a type: every name they write is one snug
  types itself.

## Rules

**Paths must be granted.** A path-valued variable written by `set`, `merge`
or `prepend` must name paths the same profile, or one it includes, lists in
`ro`, `rw` or `tmpfs`. A search path naming a directory that is not inside
the sandbox is refused:

```text
snug: profile "e1" merges PATH=/opt/nothere, which it does not grant.
```

### Special variables that cannot be written

No profile can `set` or `inherit` a name that `snug` writes in every run — `HOME`,
`PATH`, `SNUG_PROFILES` and the rest of [Names snug
writes](reference/environment-names.md#names-snug-writes).

However, as `PATH` is a `path-list`, profiles may still `merge` and `prepend` into it.
Some names, like `DOCKER_HOST` for `podman`, are conditionally enabled. Those are rejected
only if the `podman` setting is on. See
[the table](reference/environment-names.md#names-snug-writes-when-a-feature-is-on).

### Sanitize a content

Verb `sanitise` keeps only what is inside sandbox. An element survives only if a
configuration grant covers it and there is a mount inside a sandbox. Elements under
a `tmpfs` (such as `$HOME` with `@home`) or under `/proc` are dropped, and
`--dry-run` names each one.

Nothing is sanitised by default. Without `sanitise`, the host's value is not
copied at all; `PATH`, for example, is then only snug's own directories and the base.

For example, with this profile:

```toml
[profile.tools]
include = ["@sys", "@home"]
ro = ["/opt"]

[profile.tools.environ.sanitise]
PKG_CONFIG_PATH = true
```

and this host `PKG_CONFIG_PATH`:

```text
/opt/lib/pkgconfig:/home/user/.local/lib/pkgconfig:/usr/local/lib/pkgconfig:/var/lib/pkgconfig
```

`snug --dry-run -p tools .` shows:

```text
  PKG_CONFIG_PATH  /opt/lib/pkgconfig /usr/local/lib/pkgconfig sanitise  tools
                   (1 host entry dropped — nothing grants that path: /var/lib/pkgconfig)
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /home/user/.local/lib/pkgconfig)
```

- `/opt/lib/pkgconfig` is kept: the profile grants `/opt` read-only.
- `/usr/local/lib/pkgconfig` is kept: `@sys` grants it.
- `/var/lib/pkgconfig` is dropped: no profile grants it, so it does not
  exist inside.
- `/home/user/.local/lib/pkgconfig` is dropped: `@home` mounts an empty
  `tmpfs` on `$HOME`, so the directory holds none of the host's files. To
  keep it, grant it, for example `ro = ["{home}/.local/lib/pkgconfig"]`.

## Order of list elements

In a list variable (like `PATH`), order decides which program wins
when two directories hold one of the same name. So `snug` needs a rule for the
order. Yet profiles are explicitly order independent and a `-p foo -p bar`
gives you the same sandbox as `-p bar -p foo`.

Instead, the **verb** decides where an element goes. Each verb has its own
place in the list, always in this order:

| position | from | order inside |
|---|---|---|
| 1 | `prepend` | only one profile may `prepend` a variable |
| 2 | `merge` | sorted alphabetically, whichever profile wrote it |
| 3 | `sanitise` | the host's order |
| 4 | snug itself | for `PATH` only: `/snug/bin`, only when snug placed a program there |
| 5 | snug itself | for `PATH` only: the base, `/usr/bin /bin /usr/sbin /sbin` |

What each position gives you:

- **`prepend`** This ensures the value will be first in the list. You can't
  `prepend` the same variable from multiple profiles.
- **`merge`** Profiles have no order, so merged elements are sorted
  alphabetically.
- **`sanitise`** A directory from the
  host never pushes a profile's directory down the list.
- **snug's own directories come last.** A tool a profile adds wins over the
  distribution's copy of the same name.

For example, with four profiles (`pin` prepends, `go` and `node` merge,
`host` sanitises the host's `PATH=/usr/local/bin:/usr/bin:/bin`),
`snug --dry-run` shows the same list whichever order they are selected in:

```text
  PATH             /opt/pin/bin prepend   pin
                   /opt/go/bin merge     go
                   /opt/node/bin merge     node
                   /usr/local/bin /usr/bin /bin    sanitise  host
                   /usr/sbin /sbin                 (snug)    base
```

The middle column names the verb or `(snug)`, the right one the profile.

## Empty list elements

An empty element is what you get from a leading, trailing or doubled
separator: `PATH=/usr/bin:` or `PATH=/usr/bin::/bin`. It looks like a typo, but
programs give it a meaning, and the meaning differs by variable:

| variable | an empty element means |
|---|---|
| `PATH`, `PYTHONPATH`, `LD_LIBRARY_PATH` | the current directory |
| `MANPATH` | "insert the system manual path here" |
| `INFOPATH`, `TERMINFO_DIRS` | the system location |
| `PKG_CONFIG_PATH`, `NODE_PATH`, `PERL5LIB` | nothing; it is skipped |

snug never writes an empty element, and a profile cannot write one either:
a `merge` or `prepend` string containing the separator is refused, and so is a
relative one such as `.`. Write the directory you mean instead, such as
`{target}/bin` for the project or `/usr/share/man` for the system manuals.

`sanitise` drops the host's empty elements. It is refused on `MANPATH`, where
dropping one would change which pages are found; merge the directories there.

The **empty element** column of [Environment
names](reference/environment-names.md) lists the meaning for every list snug
knows.

## Secrets

Do not put credentials in the environment. Every process in the sandbox can
read `/proc/self/environ`, and every child inherits it. Put a secret in a
file and grant the file.
