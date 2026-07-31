# Troubleshooting

## `unknown profile "sys"`

snug's own profiles carry a leading `@`. You want `@sys`. The error says so and
suggests the name; `snug profile list` shows them all.

## `execvp <tool>: No such file or directory`

The binary is not on the sandbox's `PATH`, which is
`/usr/bin:/bin:/usr/sbin:/sbin` plus whatever profiles added. Check `--dry-run`:
if the mount is there but the tool is not found, the profile needs a `path` entry
for the directory it lives in.

## `profiles "a" and "b" pin different identities`

By design — one sandbox gets one git/ssh/gh account. See
[identities](identity.md).

## `ssh_mode = "agent-proxy" needs ssh_key`

Point it at the **public** half of the key you want pinned:
`ssh_key = "{home}/.ssh/id_ed25519.pub"`.

## `You must run podman inside a container!`

Your `/usr/bin/podman` is a distrobox shim that forwards to the host, and that
forwarding cannot work from inside a sandbox. snug prints a longer explanation
naming the cause. The engine and proxy are fine — install a real podman binary,
or drive `$CONTAINER_HOST` directly.

## A container cannot mount a path

```text
this sandbox cannot see /etc as writable, so a container may not mount it either
```

Working as intended: a container may only bind what the sandbox itself can see,
at the same or greater access. Grant it to the sandbox first, or mount something
inside the target.

## `refusing to share the host network namespace without --i-know`

`@net-host` is an enormous hole and needs a deliberate act. Read the five-line
warning; if you only meant "the sandbox needs internet", use `@net`.

## The sandbox cannot reach my dev server on the host

Correct. The host's `127.0.0.1` is a different loopback from the sandbox's, and
that is the single most load-bearing property of the network design. Run the
service inside, or publish a port the other way (see [Networking](networking.md)).

## `unknown key` when loading a profile

Decoding is strict on purpose: a key snug does not understand is fatal rather
than silently ignored, so a `mask` or `deny` written for another tool cannot
leave you believing the sandbox is tighter than it is. `publish_auto` in
particular was removed — name the ports with `publish = [...]`.

## Shell startup noise about D-Bus or `host-spawn`

`@sys` binds parts of `/etc`, so `/etc/profile.d/*` runs inside the sandbox and
may try to reach a bus the sandbox correctly cannot see. The noise is isolation
working.

## Nothing works and I do not know why

```bash
snug doctor          # can this host run snug at all
snug config          # which defaults are in effect, and from where
snug --dry-run <dir> # the exact policy and bwrap command line
```
