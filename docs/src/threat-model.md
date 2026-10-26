# Threat model

## What snug defends against

`snug` has two goals:

1. prevent sandboxed programs from accessing or even modifying the host filesystem, unless granted
2. integrate with the host as seamlessly as possible

Not surprisingly, the two goals contradict each other. However, all access to
the host itself must be explicitly enabled, controlled or filtered.

## What snug does not defend against

Kernel zero days. The security perimeter is the Linux kernel itself, so an
escape by exploit is possible.

A compromised or malfunctioning host, which actively or accidentally tries to
undermine `snug` state, like podman engine images. Or a misconfiguration, like
a wrong `XDG_RUNTIME_DIR` or `TMPDIR`, an evil version of `/usr/bin` mounted,
or your own profile granting `rw = ["{home}"]`. There is nothing `snug` can or
should do about it.

Networked escapes. Once `snug` allows network, programs can exchange
information between different sandboxes over the network. Claude and its
session offloading are the _perfect_ escape, which `snug` itself does not
prevent. See [Claude Code](claude.md#other-claude-code-sessions) for the
controls snug sets.

Several sandboxes on one directory. What one sandbox writes into a shared
writable directory, the other runs. With a `@podman*` profile they share the
image store too. You get what you write, and `snug --dry-run` lists it in the
`SHARED` block. The same goes for `/proc/<pid>/environ` and similar files,
which are readable from the host.

The complete document is at
[`.claude/design/THREAT-MODEL.md`](https://github.com/gomoni/snug/blob/main/.claude/design/THREAT-MODEL.md).

The sandbox is tested by Go tests and by the scripts in
[`scripts/`](https://github.com/gomoni/snug/blob/main/scripts/README.md). An
in-house [red team](https://github.com/gomoni/snug/blob/main/.claude/agents/redteam.md)
tries to escape it before each milestone.
