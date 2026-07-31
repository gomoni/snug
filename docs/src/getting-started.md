# Getting started

## Requirements

Linux with unprivileged user namespaces, `bubblewrap`, and Go 1.26+ to build.
`pasta` (package `passt`) if you want networking. It works inside `distrobox`
and other containers — nested user namespaces are fine.

## Build and check

```bash
make build
./bin/snug doctor
```

`doctor` reports whether this host can run snug at all, and names the exact
package or sysctl when something is missing rather than failing later with
"operation not permitted".

## Look before you leap

```bash
snug --dry-run .
```

This starts nothing. Read the `FILESYSTEM` block: **every line is a grant, and
the sandbox is the sum of exactly those lines.** The `NOT GRANTED` block below it
lists things a reasonable person would expect to be there and confirms they are
absent.

## Run something

```bash
snug ~/src/proj                        # an interactive shell
snug ~/src/proj -- make test           # one command; its exit code propagates
```

Inside, the prompt is `🔒 snug:~/src/proj$` and the hostname is `snug`, so
neither you nor an agent has to guess whether a shell is sandboxed.

## What you get by default

A bare `snug <dir>` selects `@sys @home @cwd-rw @parent-ro`:

- the target directory is **writable and persists** — that is the point
- its parent is readable, so `../other-package` works in a monorepo
- `$HOME` is an empty tmpfs at the same path as on the host
- `/usr` plus a dozen `/etc` entries, read-only
- **no network**

The complete writable surface is seven paths, and **only the target survives the
sandbox**: `/tmp`, `$HOME`, `$HOME/.cache`, `$HOME/.config`,
`$HOME/.local/state` and `/dev` are all ephemeral tmpfs.

## Adding capabilities

```bash
snug -p @net ~/src/proj                     # internet access
snug -p @git-ro -p @net ~/src/proj          # ...and your git config, read-only
snug -p @tmp-shared ~/src/proj              # a /tmp that survives, shared with future runs
```

`-p` **adds** to the defaults. There is no flag that grants *less* — to grant
less, select fewer profiles:

```bash
snug --no-defaults -p @sys -p @home -p @parent-ro ~/src/proj   # a read-only project
```

Verbose on purpose: a read-only working directory is possible but highly
unusual, and the verbosity is proportionate to how rarely it is wanted.
