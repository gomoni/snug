# snug

> *fitting closely and comfortably* · *marked by cordiality and secure privacy* ·
> *offering safe concealment* · *a small private room in a pub*

An unprivileged sandbox for running coding agents. One Go binary, no root, no
daemon, no setuid. It reads a policy, builds a `bubblewrap` command line, and
runs your agent in a world that contains your project and almost nothing else.

```console
$ snug ~/src/myproject
🔒 snug:~/src/myproject$ ls ~/.ssh
ls: cannot access '/home/you/.ssh': No such file or directory
```

Not permission denied. **Absent.** It was never mounted.

## Why

`bubblewrap` can already build that sandbox. It just takes forty arguments in the
right order, and getting one wrong fails open rather than closed. snug's job is
to let a human write a *policy* once — a named, reusable, reviewable thing — and
stop thinking about mount mechanics.

The other half of the job is that you should not have to take snug's word for
any of it. `snug --dry-run` prints the resolved policy and the exact command
line, having started nothing.

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
snug ~/src/proj -- make test     # run one command, exit code propagates
snug -p net ~/src/proj           # ...with internet access
snug -p git-ro -p net ~/src/proj # ...and your git identity, read-only
snug --read-only ~/src/proj      # nothing writable at all
```

`-p` **adds** to the default profile. `--no-default` starts from nothing.

## The model

**Share nothing. Then punch explicit, named, minimal holes until it is useful.**

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. A profile is a *named hole*.

There is no deny rule, no `mask`, no negation — because there is nothing to
deny. `dotdot` does not hide your other projects; it never grants them. Which
means:

- **Adding a profile can never make a path stop being visible.** You can compose
  profiles without reading every one of them.
- **Order never matters.** `snug -p a -p b` and `snug -p b -p a` produce a
  byte-identical sandbox.
- **A missing capability is a feature.** No X11, no Wayland, no D-Bus, no host
  loopback, no `~/.ssh` — stated plainly, not apologised for.

When you want *"X but not Y"*, that means X was too coarse a grant. Grant the
parts of X you meant, or grant X read-only and the parts you want to write
separately.

## Profiles

```console
$ snug profile list          # what exists
$ snug profile show net      # what one grants, and what it costs
$ snug profile tree          # which profiles imply which
$ snug profile dot | dot -Tpng -o profiles.png
```

| profile | grants |
|---|---|
| `null` | Nothing. The floor — useful for understanding the base. |
| `sys` | `/usr` plus the dozen `/etc` entries things actually need. |
| `home` | `$HOME` as an empty tmpfs at the host path. Ephemeral. |
| `cwd-rw` | The target directory, writable and persistent. |
| `dotdot` | The target's parent, read-only. |
| `default` | `sys` + `home` + `cwd-rw` + `dotdot`. Offline. |
| `git-ro` | `~/.config/git` and `~/.gitconfig`, read-only. |
| `tmp-shared` | A per-project host directory as `/tmp`. Survives the sandbox. |
| `net` | Internet access. Host loopback unreachable. |
| `net-publish` | As `net`, plus sandbox ports on the host's `127.0.0.1`. |
| `net-anon` | As `net`, but the sandbox does not learn your LAN address. |
| `net-host` | **Dangerous.** Shares the host network namespace. Needs `--i-know`. |
| `etc-full` | All of `/etc`, including the distro's shell startup scripts. |

Write your own in `~/.config/snug/profiles.d/*.toml`:

```toml
[profile.srv-rw]
description = "The directories my build reaches outside the project."
include = ["default", "net"]
rw = ["/srv", "/opt/cache"]
```

Then `snug -p srv-rw ~/src/proj`. Profiles compose with `include`, and a config
file may add names but never redefine a builtin.

Repo-local config is **never** auto-loaded. A repository that could ship its own
profile would be granting itself permissions.

## Networking

Each sandbox gets its own network namespace with a `pasta` helper. Egress is
unrestricted; the host's `127.0.0.1` is not merely blocked but *not
expressible* — the sandbox's loopback is a different loopback.

That namespace also isolates **abstract AF_UNIX sockets**, which is what keeps
X11 and D-Bus out for free. Filesystem sandboxing does nothing about those;
there is no path to not-mount.

Offline is the **absence** of the `net` profile, not a setting — so it cannot be
switched back on by adding something.

## What it defends, and what it does not

Designed against a **prompt-injected or misbehaving agent**: one that reads a
hostile README, runs a malicious `npm install`, or simply does the wrong thing
with confidence. It contains what that process can read, write and reach.

| defended | how |
|---|---|
| `~/.ssh`, `~/.aws`, `~/.gnupg`, keyrings, browser profiles | never mounted |
| your other projects | never mounted |
| host services on `127.0.0.1` | private netns |
| X11 keylogging, D-Bus, the desktop session | not mounted; netns-scoped |
| host persistence (`.bashrc`, autostart, cron) | `$HOME` is an ephemeral tmpfs |

**Not** a defence against kernel 0-days, and **not** a boundary against a
determined human attacker — everything runs as your uid, so anything that
escapes has your authority. Use a VM if you need a real boundary.

And the project directory is writable by definition: an agent can always poison
the code it is working on. Review your diffs.

## Verifying it yourself

A sandbox you have not personally tried to break is one you are trusting on
someone's word. [`docs/VERIFY.md`](docs/VERIFY.md) is a hands-on checklist —
every command was run on a real host, with the output it should produce.

The project also keeps an in-house red team (`.claude/agents/redteam.md`) whose
job is to escape. It runs before every milestone lands, and it has earned its
keep: across two runs it found five real issues — a host-environment leak
readable at `/proc/1/environ`, a masking rule that only covered one of two
spellings, a seccomp filter that was requested but never installed, a directory
on stdin that bypassed every mount grant, and a `clone3` call that created a
nested user namespace. **Every one was in code that had been written and tested,
with the tests passing.** Each is now a permanent regression test.

## Status

**M2.** Filesystem isolation, seccomp hardening, and networking all work.
Not built yet: the ssh-agent proxy and git identity scoping, a `claude` profile,
container support, and GUI socket profiles.

## Documentation

| | |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, threat model, the policy model, roadmap |
| [`docs/VERIFY.md`](docs/VERIFY.md) | Check the sandbox holds, by hand |
| [`CLAUDE.md`](CLAUDE.md) | Working agreement: invariants, and hard-won facts about this environment |
| [`TODO.md`](TODO.md) | What is deferred, and known gaps between docs and code |

## Requirements

MIT licensed. Linux with unprivileged user namespaces, `bubblewrap`, Go 1.26+ to build,
`pasta` for networking. Works inside `distrobox` and other containers — nested
user namespaces are fine. `snug doctor` tells you where you stand, and names the
exact sysctl when something is missing.
