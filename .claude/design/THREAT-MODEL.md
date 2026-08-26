# snug — threat model: goals and non-goals

**Status: authoritative.** This is the document that says what snug is *for*.
Part 1 sketched goals and part 2 non-goals. When a claim elsewhere in the tree
disagrees with this file about what snug protects, this file is right and the
other claim is stale — fix it.

## 0 What this document is

snug began as `agent-sandbox.sh`: a way to run `claude` without handing it
`~/.ssh` and access to other files. The asset it protects has not changed
since.

> It protects access to the user's filesystem unless an explicit named hole is
> dug in.

[xkcd 1200](https://www.xkcd.com/1200/) is the whole argument. The valuable
things on a personal machine are not `/` and not the root password; they are
`~/.ssh`, `~/.aws`, the browser profile, the keyring, the other projects, the
documents — the files that are *yours*. Neither classical unix permissions nor
advanced Linux systems like SELinux protect the user's data.

At the same time — for programs running inside the sandbox — it should look
like there is NO sandbox at all, and that it runs inside a stripped-down Linux
system.

## 1 The protected asset

"Host state" is everything the user has on the machine that a sandboxed program
should not be able to read, alter, or act through:

- **Files** — the home directory and everything under it that a profile did not
  name: credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`), other
  projects, documents, shell history.
- **Identity** — the ability to sign, push, or authenticate *as the user*: ssh
  keys, git/GitHub credentials, cloud tokens, the ssh-agent, API keys in the
  environment.
- **Loopback and desktop surface** — host services on `127.0.0.1`, the Wayland/
  X11 socket, the session D-Bus, PulseAudio: each a route to keylog, read the
  keyring, or drive host processes.
- **Persistence** — anywhere a program could write something the *host* will
  later execute: `~/.bashrc`, autostart, cron, `~/.local/bin` on `PATH`.

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. Every one of the goals below is a mechanism
that keeps some slice of host state out of the sandbox unless a profile — a
*named hole* — explicitly grants it.

## 2 Threats

### 2.1 Access to $HOME is not granted by default

`snug` never grants access to most of `$HOME` via a bubblewrap-based sandbox.
That means `~/.ssh`, `~/.aws` and similar are never available. The same
principle covers `~/Documents` or `~/Downloads`.

Access is supposed to be minimal (`rw` only to the target dir) and explicit
(`@parent-ro` grants read access to the parent of the target directory).

### 2.2 Access to secrets is proxied

A Linux development system without `ssh` is not very useful. The case of `ssh`
is solved by a builtin `ssh-agent` which exposes a subset of ssh keys to the
containment.

The same happens to `claude` tokens and settings: snug reinterprets most
well-known files — settings, hooks and so on.

### 2.3 Exposing secrets

`snug` NEVER exposes secrets via environment variables.

It SHALL avoid storing them as files where there is a way around it.

### 2.4 Hiding /proc and /dev

As an extra, access to the Linux filesystem is filtered and controlled.

### 2.5 Disallowing container escape

Normal `docker` or `podman` cannot work inside the sandbox and would be the
easiest escape vector.

`snug` solves this by providing a private `podman` engine, which uses the same
network namespace as the main sandbox.

## 3 Non-goals

`snug` is and will never be an all-in-one security tool. There are simply
threats this does not solve. Some may get implemented and move up in the
future, some won't.

### 3.1 Network security

There is no proxy deployed, and code inside the sandbox can have unrestricted
network access.

So code can download bad podman images, mine bitcoin, try to hack HuggingFace
(DO NOT DO IT), or try to escape the containment using claude's remote
abilities. And `snug` itself is not going to prevent this.

**The remote abilities deserve naming, because they are the one non-goal on this
page that reaches beyond this machine.** With `@claude`, the sandbox holds a
working credential and egress — both deliberate; they are what the profile is
for — and Claude Code's session mesh reaches other sessions of the same ACCOUNT
over the network. Measured from inside a live sandbox: `curl` to
`https://api.anthropic.com/v1/messages` returns **405**, the wrong verb on a
POST endpoint, i.e. the request arrived.

It is not a sandbox escape — no filesystem, no kernel, no host process, no
namespace. It is an authority escape **iff the peer is less confined than the
sender**. Another snug session gains nothing; a cloud session runs in
Anthropic's own sandbox; a **Remote Control session on another machine** is the
sharp case, being unsandboxed with that machine's files and credentials.

**snug's boundary is the MACHINE. The session mesh is the ACCOUNT.** That is
why this is a non-goal and not a bug: closing it needs a filtering proxy over
TLS to Anthropic, distinguishing "the agent doing its job" from "the agent
messaging a peer" on the same host, same credential, same protocol — the shape
[INDEX.md](INDEX.md) §7.4 already refuses for D-Bus, in these words: *a
filtering proxy that is 95% correct is a sandbox that is 0% sound*. The
alternatives are removing the credential or the egress, which is removing the
feature.

**The LOCAL half is closed, structurally.** Cross-session messaging on one
machine is unix sockets, not the API — the opposite of the obvious hypothesis,
which is why it was measured rather than reasoned about. `/tmp` inside is snug's
private tmpfs, so `/tmp/cc-socks/` holds only this session's own socket, and
`@tmp-shared` does not open it either: `prepareHostTmpDir` ALLOCATES a
per-sandbox directory rather than binding the host's `/tmp`. It holds because
the guiding principle paid out on a surface nobody had looked at.

**Claude Code's own controls exist and are worth setting, but they are not a
boundary.** `crossSessionInbound: "refuse"` and `permissions.deny` naming
`SendMessage`/`ListAgents` (a bare deny removes the tool from the session's
context) are enforced CLIENT-side by Claude Code; only organisation *managed
settings* cannot be overridden by a session. A payload holding the credential
can reach the API without the client, and it controls its own command line
inside the sandbox — `--settings` layers rather than replaces. So: a default,
not a guarantee. Invariant 5 is about not letting a user believe otherwise.

### 3.2 Resource management

`snug` itself does not control filesystem quotas, rlimits, or cgroups.

### 3.3 Mutable state

`snug` is not a hermetic tool. By default it gives you write access to the
target directory, and the embedded podman engine persists its storage per
target directory too.

The scenario in which a first run leaves an _evil_ payload (like a CLAUDE.md or
a bad OCI image) that a subsequent run then uses is not considered a breach.
Unless such payloads allow a containment escape, they are fine from the tool's
point of view.

A run that pulls or builds a bad image leaves it in the store, and a later run
on the same target may use it. That gains no host reach the later run's own
policy did not already grant, which is why it is a non-goal rather than a
threat. The store is keyed on the target alone, so selecting fewer profiles
does not give you a clean one — deleting the store directory does.

### 3.4 User-provided holes

Passing in a socket that snug does not control is outside the tool's scope. In
general `snug` very rarely refuses a configuration because it is insecure — the
only exception is `@parent-ro` refusing to run if the parent happens to be
`$HOME`.

In other words, feel free to grant access to the D-Bus socket — just do not be
surprised when this leads to a containment escape.

### 3.5 Sibling access

Two same-uid siblings inside one sandbox reach each other's fds and memory
through `/proc/<pid>/fd/N` and `/proc/<pid>/mem` — neither is syscall-shaped, so
no seccomp filter can name them. A file another payload holds open can be
re-opened with its contents intact, including a pipe, a memfd, a deleted file
and an unnamed temporary one; its memory can be read *and written*.

This follows from two payloads sharing one pid namespace under one uid, and it
holds for as long as that is what a sandbox is. It is not waiting on a fix, and
the seccomp filter is not a partial answer to it: what the filter's refusal of
`pidfd_getfd` keeps out of a sibling's reach is an open *socket*, which procfs
cannot re-open, and nothing else.

There is a structural answer — snug's own init inside a nested pid namespace, so
that co-resident payloads cannot see each other's processes at all. That is an
idea and not a plan: it is not scheduled and it is not promised here. Until it
exists, everything running inside one sandbox is one trust domain. Two payloads
that must not reach each other need two sandboxes.

### 3.6 Linux

Kernel bugs are out of scope.

### 3.7 Knowledge about the sandbox

`snug` pretends it's a stripped-down Linux system, but never tries to hide that
it is one. The `~/.claude/CLAUDE.md` provided when the `@claude` profile is
enabled says so, snug's own files sit under the read-only `/snug` mount, and
some environment variables reveal it too.
