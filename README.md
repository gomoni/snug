# snug

> *fitting closely and comfortably* · *marked by cordiality and secure privacy* ·
> *offering safe concealment* · *a small private room in a pub*

[Merriam-Webster on snug](https://www.merriam-webster.com/dictionary/snug)

## What is it

A sandbox for running an **untrusted code** on modern Linux machines. As
seamless experience as possible. It works without `root`, without any daemon,
without an installation. Static linked binary written in Go, which

1. reads the policy - aka _profiles_
2. builds a cli arguments for `bwrap`, which confines the access to the
    filesystem
3. provides a proxy or wrappers for well known services including `ssh-agent`
    or `podman` socket, ensuring `ssh` or `podman`/`docker` CLI can be
    safely used from the sandbox.
4. can use a private network namespace via `pasta`
5. supports running Claude Code via `@claude` profile

```bash
echo "hello" > hello
snug ~/src/myproject

# sandbox hides and protects the filesystem
🔒 snug:~/src/myproject> ls ~/.ssh
ls: cannot access '/home/you/.ssh': No such file or directory
🔒 snug:~/src/myproject$ echo "hello" > ../hello
bash: ../hello: Read-only file system
🔒 snug:~/projects/plainsof/cv/snug$

# yet allow a write access to cwd by default
🔒 snug:~/src/myproject$ cat hello
hello
🔒 snug:~/src/myproject$ echo "hello from snug" > hello
hello from snug
```

### What is untrusted code

In 2026? Every code

* LLM agents - the worst kind of such code. It runs autonomously,
  having a complete access to the system and the safeguards are just
  _a prompt_. They're ever changing blackox prone to prompt injections,
  manipulations and hallucinations.
* Supply chain dependencies - everything allowing post-install scripts
  (node, python, Ruby, ...) can get rogue and has been used to exfiltrate
  the production secrets in the past.
* A homework assigments, LLM code snippet, random post on web, curl | bash
  installing instructions and so

## Why

There is no tool I was aware about, which would match all points

1. Easy to use - `bwrap` is an excellent sandboxing tool on its own. Yet
   building the proper CLI invocation is anything than easy.
2. Sharing as much as environment with a regular system as possible.
3. Easy to poke holes into the sandbox, so developer flow feels like being
   on unrestricted host system, rather than inside sealed sandbox.
4. Must be compatible with `distrobox`.
5. It should enable users to inspect what command is supposed to do.

## Quick start

Needs `bubblewrap`, and `pasta` (package `passt`) if you want networking.

```bash
make build
./bin/snug doctor          # can this host run it?
./bin/snug --dry-run .     # what will happen, before it happens
./bin/snug .               # a shell in the sandbox
```

Useful shapes:

```bash
snug ~/src/proj -- make test           # run one command; its exit code propagates
snug -p @net ~/src/proj                # ...with internet access
snug -p @git-ro -p @net ~/src/proj     # ...and your git identity, read-only
snug -p @claude -p @net ~/src/proj     # Claude Code, its credentials staged (not your host's)
snug -p @podman-socket -p @net ~/src/proj  # run containers, via a filtering proxy
snug -p @podman-build -p @net ~/src/proj   # ...and build images too
snug -p @tmp-shared ~/src/proj         # a /tmp that survives, shared with future runs
snug --dry-run -p @net ~/src/proj      # print the policy and the exact bwrap line; start nothing
```

## The model

The default is **share nothing** and then define a named minimal holes aka
***profiles** which make the sandbox less contained and more useful.

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. A profile is a *named hole*.

![TODO] the `./bin/snug --no-defaults . -- ./bin/snug doctor` MAY work.

The profiles themselves are supposed to be easy

1. They're declarative - no fancy programming language, no conditionals
2. Order does not matter
3. Profile can include others, but this is to enable a reusability
4. Profile can never exclude or disable access
5. Profile conflicts are hard fails. Some conflicts like the same path requested
   as `ro` and `rw` are _coerced_ to `rw`.
6. They're restricted to ascii alphanumeric characters, hyphen (-) and those starting
   with `@` are `snug`'s own builtin.

## Profiles

```console
$ snug profile list          # what exists
$ snug profile show @net     # what one grants, and what it costs
$ snug profile tree          # which profiles imply which
$ snug profile dot | dot -Tpng -o profiles.png
```

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
| `@claude` | Claude Code: binary and skills read-only, credentials staged as writable copies. |
| `@podman-socket` | Run containers, via a filtering proxy over a per-sandbox engine. |
| `@podman-build` | As `@podman-socket`, plus `podman build` with a filtered option set. |

### Default profiles

Those are implicitly used unless `--no-defaults` are specified and makes
the CLI a bit shorter to type. This REPLACES the builtin defaults.

```toml
# ~/.config/snug/config.toml — preferences, never grants
defaults = ["@sys", "@home", "@cwd-rw", "@parent-ro"]
```

### Own profile

Write your own in `~/.config/snug/profiles.d/srv-rw.toml`:

```toml
[profile.srv-rw]
description = "The directories my build reaches outside the project."
include = ["@net"]    # enable networking
rw = ["/srv/project", "/opt/cache/project"]
```

Then `snug -p srv-rw ~/src/proj` will mount `/srv/project` and
`/opt/cache/project` as read-write and enable the networking.

## Networking

Each sandbox gets its own network namespace with a `pasta` helper. Egress is
unrestricted; the host's `127.0.0.1` is not merely blocked but *not
expressible* — the sandbox's loopback is a different loopback.

That namespace also isolates **abstract AF_UNIX sockets**, which is what keeps
X11 and D-Bus out for free. Filesystem sandboxing does nothing about those;
there is no path to not-mount.

Offline is the **absence** of the `@net` profile, not a setting — so it cannot be
switched back on by adding something.

Host→sandbox publishing is off, and opening it means naming the ports yourself:

```toml
[profile.myports]
include = ["@net"]
publish = [3000, 8080]     # bound to the host's 127.0.0.1 only, never the LAN
```

There is deliberately no "publish whatever the sandbox binds": that would let the
*sandbox* choose what appears on your loopback, and a prompt-injected agent could
squat `127.0.0.1:8080` ahead of your own dev server. A `@net-publish` profile
that did exactly that used to ship, and it never forwarded a single port — see
`internal/profile/profiles/base.toml` for why.

## Containers, and the `podman` shim

> **Provisional.** This section documents behaviour that landed ahead of its
> documentation. The measured version is
> [`.claude/design/CONTAINER-CLIENT.md`](.claude/design/CONTAINER-CLIENT.md).

The engine behind `@podman-socket` is podman, rootless, one per sandbox. What
snug *filters* is the **docker-compatible** schema — which podman itself serves —
so the client you run inside can be anything that speaks it. `CONTAINER_HOST` and
`DOCKER_HOST` both point at snug's proxy.

In practice that means **`docker` is the client to use inside a sandbox**:

```bash
docker pull alpine && docker run --rm alpine echo hi   # works
podman-remote ps                                       # works, read-only only
```

`podman-remote` speaks podman's *native* libpod API, which snug refuses for any
request carrying a body it would have to inspect — so it inspects fine and
cannot `run` or `pull`. There is no flag that changes this.

**The shim.** On a distrobox host `/usr/bin/podman` is a symlink to
`distrobox-host-exec`, which forwards to an engine *outside* the container. From
inside a sandbox that cannot work, and podman's own error for it names neither
the cause nor a fix. So snug stages its own `podman` at `/run/snug/bin/podman`
and puts that directory on `PATH` ahead of `/usr/bin`. It forwards the
subcommands `docker` can serve, byte-for-byte, and refuses the rest in its own
voice:

```
$ podman pod ps
snug: stub refuses 'podman pod' -- pods are a podman-only grouping; docker has
      no equivalent command.
```

Nothing is hidden: `/usr/bin/podman` is untouched and still runs by absolute
path, `/run/snug/bin` is read-only from inside, and a `podman` provided by a
profile's `path` still wins over snug's. It appears only when a podman profile
is selected — a default `snug <dir>` has no stub and an unchanged `PATH`.

**Known rough edges**, measured and not yet fixed:

- `docker run` exits 0 but prints nothing — the container's stdout is not
  relayed back. Plain `docker` behaves the same, so this is the proxy, not the
  stub.
- `docker build` needs the classic builder; snug sets `DOCKER_BUILDKIT=0` for
  you, because BuildKit bypasses the filter entirely rather than being filtered.
- `docker run -p` is refused: published ports land on the engine's side of the
  boundary today. [ENGINE-NETNS.md](.claude/design/ENGINE-NETNS.md) is the fix.
- `docker cp` is refused, deliberately — the engine resolves that path outside
  the sandbox as your user. Use `docker exec C tar -cf - …` instead.
- On an SELinux host, `-v` needs `:z` (`docker run -v "$PWD:/w:z" …`). That is
  rootless podman, not snug.

## What snug defends against

The first and most important aspect is that it prevents a filesystem access. So
no `~/.ssh`, no `~/.aws`, no browser or desktop keyring, no tokens, no
`~/Documents` or `~/.bashrc` access. By a design it prevents an access to Wayland,
systemd, PulseAudio, X11 or any other sockets, which can be used for a sandbox escape.

| defended | how |
|---|---|
| `~/.ssh`, `~/.aws`, `~/.gnupg`, keyrings, browser profiles | never mounted |
| your other projects | never mounted |
| host services on `127.0.0.1` | private netns |
| X11 keylogging, D-Bus, the desktop session | not mounted; netns-scoped |
| host persistence (`.bashrc`, autostart, cron) | `$HOME` is an ephemeral tmpfs |

## What snug does not defends against

Kernel zero days - the security perimeter is a Linux itself, so escape by
exploit is possible. Run the VM if expects more strict isolation though.

## Verifying the sandbox

[`VERIFY.md`](VERIFY.md) constains a set of instructions for humans to test the
sandbox.

The project also keeps an in-house red team (`.claude/agents/redteam.md`) whose
job is to escape. It runs before every milestone lands, and it keeps earning its
keep. 

 * a host-environment leak readable at `/proc/1/environ`
 * a masking rule that covered one of two spellings
 * a seccomp filter that was requested but never installed
 * a directory on stdin that bypassed every mount grant
 * a `clone3` call that created a nested user namespace
 * a `--secret` source that climbed out of the build context with `..` and
   read an arbitrary host file.
 * and so on

## Status

This is alpha status - while the basic concept feels solid, more real world usage are needed.

The builtin profiles, their dependencies, CLI or an ability to attach to an existing sandbox - all of this
may be refined in the near future.

## TODO

 * how to properly deal with [secrets](.claude/design/SECRETS.md)
 * [podman network](.claude/design/ENGINE-NETNS.md)
 * environment variable handling
 * tighten the podman build
 * better defined identities - requires secrets to be final

## Documentation

[`VERIFY.md`](VERIFY.md) is the hands-on checklist: run it rather than trusting
this file.

Design and research material is **not** user documentation and lives apart, under
[`.claude/design/`](.claude/design/), beside the agents that work from it:

| | |
|---|---|
| [`DESIGN.md`](.claude/design/DESIGN.md) | Architecture, threat model, the policy model, roadmap |
| [`PSEUDOFS-AUDIT.md`](.claude/design/PSEUDOFS-AUDIT.md) | What `/proc`, `/sys` and `/dev` expose, measured |
| [`PARAMETERISED-PROFILES.md`](.claude/design/PARAMETERISED-PROFILES.md) | A deferred design, and why |
| [`SECRETS.md`](.claude/design/SECRETS.md) | What snug does with credentials, and what it should |
| [`CLAUDE.md`](CLAUDE.md) | Working agreement: invariants, and hard-won facts about this environment |
| [`TODO.md`](TODO.md) | What is deferred, and known gaps between docs and code |

## Requirements

MIT licensed. Linux with unprivileged user namespaces, `bubblewrap`, Go 1.26+ to build,
`pasta` for networking. Works inside `distrobox` and other containers — nested
user namespaces are fine. `snug doctor` tells you where you stand, and names the
exact sysctl when something is missing.
