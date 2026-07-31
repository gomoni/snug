# What it defends, and what it does not

Designed against **code you are running but do not fully trust**: a build script
from a repository you just cloned, a dependency's install hook, a test suite, or
an AI agent that read a hostile README and did what it was told.

An AI agent is the sharpest version of the problem, because it is *supposed* to
run arbitrary commands — "just don't run untrusted code" is not advice you can
follow. But a postinstall script is untrusted in exactly the same way, and gets
exactly the same boundary.

## Defended

| | how |
|---|---|
| `~/.ssh`, `~/.aws`, `~/.gnupg`, keyrings, browser profiles | never mounted |
| your other projects | never mounted |
| host services on `127.0.0.1` | private network namespace |
| X11 keylogging, D-Bus, the desktop session | not mounted; namespace-scoped |
| host persistence (`.bashrc`, autostart, cron) | `$HOME` is an ephemeral tmpfs |
| your host container images and volumes | a per-sandbox engine behind a filtering proxy |
| your other GitHub accounts | one identity per sandbox, key material never enters |

## Not defended

**Kernel 0-days.** Everything runs as your uid in a user namespace. A kernel bug
that escapes a namespace escapes snug.

**A determined human attacker.** Everything runs as your uid, so anything that
escapes has your authority. Use a virtual machine if you need a real boundary.

**The project directory.** It is writable by definition — that is the point. An
agent can always poison the code it is working on. Review your diffs.

**What gets signed.** An identity profile bounds *which* ssh key is available,
not what is done with it. That is inherent to every agent forwarder.

## Known-open, and written down

The read side of `/proc` leaks more than a container runtime's default, and a
profile can currently displace snug's own `/proc` and `/dev` mounts. Both are
recorded with severities in [`TODO.md`](https://github.com/gomoni/snug/blob/main/TODO.md);
the measurements are in the pseudo-filesystem audit under `.claude/design/`.

`/sys` is absent by construction and `/dev` is a 14-entry synthetic tree — both
verified, and both stronger than the documentation used to claim.

## How this is checked

snug keeps an in-house red team whose job is to escape, and it runs before every
milestone lands. It has found, among others: a host-environment leak readable at
`/proc/1/environ`; a seccomp filter that was requested but never installed; a
directory on stdin that bypassed every mount grant; a `--secret` source that
climbed out of a build context with `..` and read an arbitrary host file.

**Every one was in code that had been written and tested, with the tests
passing.** Twice it has broken a fix within the hour of that fix landing. Each
finding is now a permanent regression test, verified to fail against the code
that preceded it.

That is the honest reason to run [Verify it yourself](verify.md) rather than
trusting this page.
