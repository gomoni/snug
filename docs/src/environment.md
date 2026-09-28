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

**snug's own names cannot be written.** No profile may `set` or `inherit` a
name snug writes in every run — `HOME`, `PATH`, `SNUG_PROFILES` and the rest of
[Names snug writes](reference/environment-names.md#names-snug-writes).

However, as `PATH` is a `path-list`, profiles may still `merge` and `prepend` into it.
Some names, like `DOCKER_HOST` for `podman`, are conditionally enabled. Those are rejected
only if the setting is on. See
[the table](reference/environment-names.md#names-snug-writes-when-a-feature-is-on).

**Some values are code.** For some variables, the value decides what a
program runs: `EDITOR` and `PAGER` name a program, `BASH_ENV` a script bash
runs at start, `PYTHONPATH` a directory python runs `sitecustomize.py` from.
A profile may still write them, but `snug profile show` and `--dry-run` add a
note to the row saying what runs:

```text
environ.merge    PYTHONPATH = /opt  ← python runs sitecustomize.py from any element of this at interpreter start (measured, CPython)
```
