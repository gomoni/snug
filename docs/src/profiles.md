# Profiles

A profile is a **named hole** in a sandbox that starts out sharing nothing. It is
the only vocabulary for grants: the CLI says the same word the config says.

```console
$ snug profile list          # what exists
$ snug profile show @net     # what one grants, and what it costs
$ snug profile tree          # which profiles imply which
$ snug profile dot | dot -Tpng -o profiles.png
```

## The `@` mark

A leading `@` means **snug ships this profile**. Yours, written in
`~/.config/snug/profiles.d`, carry no mark.

That is not decoration. Wherever a profile name appears — the command line,
`--dry-run` provenance, `$SNUG_PROFILES` inside the sandbox — you can see at a
glance whether a grant is snug's or something on this host defined. The two
namespaces cannot collide: **no file may define an `@` name, and every builtin
has one**, so a profile of your own called `sys` is simply yours and `@sys` still
means exactly what snug ships.

If you type the bare name, snug says so:

```console
$ snug -p sys ~/src/proj
snug: unknown profile "sys"; snug's own profiles carry a leading @, so you
      probably meant "@sys" (see: snug profile list)
```

## What snug ships

| profile | grants |
|---|---|
| `@sys` | `/usr` plus the dozen `/etc` entries things actually need. |
| `@home` | `$HOME` as an empty tmpfs at the host path. Ephemeral. |
| `@cwd-rw` | The target directory, writable and persistent. |
| `@parent-ro` | The target's parent, read-only. |
| `@git-ro` | `~/.config/git` and `~/.gitconfig`, read-only. |
| `@tmp-shared` | A per-project host directory as `/tmp`. Survives the sandbox. |
| `@net` | Internet access. Host loopback unreachable. |
| `@net-anon` | As `@net`, but the sandbox does not learn your LAN address. |
| `@net-host` | **Dangerous.** Shares the host network namespace. Needs `--i-know`. |
| `@claude` | Claude Code: binary and skills read-only, credentials staged writable. |
| `@podman-socket` | Run containers, via a filtering proxy over a per-sandbox engine. |
| `@podman-build` | As `@podman-socket`, plus `podman build`. |

## The `defaults` setting

There is deliberately **no `@default` profile, and no `@null` profile either**.
A default selection is a preference and a profile is a grant — one idea, one
mechanism — and the floor of the lattice (grant nothing) is not something a
profile needs to name: it is what resolving an empty selection already gives
you, reachable directly with `--no-defaults`. What a bare `snug <dir>` selects
is a *preference*, not a grant:

```toml
# ~/.config/snug/config.toml — preferences, never grants
defaults = ["@sys", "@home", "@cwd-rw", "@parent-ro"]
```

Setting it **replaces** the built-in list rather than merging, so you can have
fewer defaults than snug ships with. `-p` then adds to whatever that resolved to,
and `--no-defaults` declines it entirely.

`@net` is not in the list and should not be added: offline is the *absence* of
the `@net` profile, so it cannot be switched back on by accident.

`snug config` prints the effective list and where it came from.

## Writing your own

Drop a file in `~/.config/snug/profiles.d/`:

```toml
[profile.srv-rw]
description = "The directories my build reaches outside the project."
include = ["@net"]              # the `defaults` are selected too; -p adds to them
rw = ["/srv", "/opt/cache"]
```

Then `snug -p srv-rw ~/src/proj`. See the [profile format](profile-format.md)
for every key.

Decoding is **strict**: a key snug does not understand is a fatal error, not a
silently ignored line. That is what stops a `mask` or `deny` written for some
other tool from leaving you believing the sandbox is tighter than it is.

## Where profiles come from

In order, later layers may **add** names but never redefine one:

1. compiled-in builtins (`@name`)
2. `/etc/snug/profiles.d/*.toml`
3. `$XDG_CONFIG_HOME/snug/profiles.d/*.toml` — yours

**There is no fourth layer.** snug never auto-loads `.snug/`, `snug.toml`, or
anything else from inside or beside the target directory. A repository that could
ship its own profile would be an attacker granting themselves permissions on your
first run — a complete defeat of the point.
