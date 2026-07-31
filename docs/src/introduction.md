# snug

> *fitting closely and comfortably* · *marked by cordiality and secure privacy* ·
> *offering safe concealment* · *a small private room in a pub*

An unprivileged sandbox for running **untrusted code**: a build you did not
write, a dependency's install hook, a test suite from a repository you just
cloned, a `Makefile` off the internet — or an AI agent. One Go binary, no root,
no daemon, no setuid.

```console
$ snug ~/src/myproject
🔒 snug:~/src/myproject$ ls ~/.ssh
ls: cannot access '/home/you/.ssh': No such file or directory
```

Not permission denied. **Absent.** It was never mounted.

## The model, in one line

**Share nothing. Then punch explicit, named, minimal holes until it is useful.**

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. A profile is a *named hole*.

There is no deny rule, no `mask`, no negation — because there is nothing to
deny. `@parent-ro` does not hide your other projects; it never grants them.
Three things follow, and they are what make profiles usable:

- **Adding a profile can never make a path stop being visible.** You can compose
  profiles without reading every one of them.
- **Order never matters.** `snug -p a -p b` and `snug -p b -p a` produce a
  byte-identical sandbox.
- **A missing capability is a feature.** No X11, no Wayland, no D-Bus, no host
  loopback, no `~/.ssh` — stated plainly, not apologised for.

When you find yourself wanting *"X but not Y"*, that means X was too coarse a
grant. Grant the parts of X you meant, or grant X read-only and the parts you
want to write separately.

## You should not have to take snug's word for it

`snug --dry-run` prints the resolved policy and the exact `bubblewrap` command
line, having started nothing. If it and reality ever disagree, that is the most
serious class of bug in this project, because every other guarantee is read off
that output.

[Verify it yourself](verify.md) is a hands-on checklist for exactly that.

## Where to go next

- [Getting started](getting-started.md) — install it and run something
- [Profiles](profiles.md) — the vocabulary for everything else
- [Git, ssh and GitHub identities](identity.md) — one account per sandbox
- [What it defends, and what it does not](threat-model.md) — read before trusting it
