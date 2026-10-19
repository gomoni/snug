# Git configuration in the sandbox

**This is an instance of [GENERATED-CONFIG.md](GENERATED-CONFIG.md), which owns
the rule; this document holds the git-specific measurements.**

User-facing behaviour (the pin, the stub at `/etc/gitconfig`, the system scope)
is in `docs/src/identity.md`. This file holds the measurements and the reasoning
behind it, made on git 2.55 and to be re-run before changing any of it.

---

## 0. The one-sentence version

`~/.gitconfig` is not a data file that sometimes contains secrets. It is a
**command table**, and a read-only bind of a command table does not restrain it
— it supplies it. So snug authors the file the sandbox sees from the three
values a human pinned in `[identity.git]` — `name`, `email`, `signing_key` — and
every other git setting is a file the human wrote for the sandbox and granted
read-only at `/etc/gitconfig` (the book's "Other git settings").

## 1. What the file actually is

Keys in a global git config that name a program for git to run:

| key | when it runs |
|---|---|
| `credential.helper` | every authenticated fetch/push |
| `alias.X = !cmd` | `git X` |
| `core.pager` | every command that pages |
| `core.editor` | commit, rebase, tag |
| `core.sshCommand` | every ssh transport operation |
| `core.fsmonitor` | every status/diff |
| `diff.<driver>.textconv` | diff, log -p, show |
| `filter.<driver>.clean` / `.smudge` | checkout, add |
| `uploadpack.packObjectsHook` | serving a fetch |

Plus keys that are credentials outright (`sendemail.smtpPass`) or point at them
(`credential.helper = store --file …`).

None of that is exotic; it is what the file is *for*. Binding it read-only stops
the sandbox editing it and stops nothing else.

## 2. No builtin may grant a command table

`TestNoBuiltinGrantsACredentialOrCommandTablePath` (internal/profile) refuses,
with no allowlist and no flag, any builtin grant whose host side is in a
catalogue of credential paths and command tables. A human writing the same grant
in their own `profiles.d` is making a declaration about their own machine, which
invariant 3 puts outside the sandboxed material — what must never happen is snug
shipping that decision for everyone.

**An abuse sentence is not what stops this.** A sentence like *"the sandbox
learns your git name, email, aliases, and any secrets you unwisely put in
`~/.gitconfig`"* is honest at authoring time and still wrong: it classifies the
file as data with secrets in it rather than as the command table §1 shows it is,
and *"unwisely put in"* reads as a user error when the executable keys are the
file's purpose. **A comment cannot fail.** The test can.

## 5. What snug authors, and from what

From the pin, and nothing else. Adding a row is a policy change, and the
question to answer first is not "is it convenient" but "what does this key make
git DO":

| written | from |
|---|---|
| `user.name`, `user.email` | `identity.git.name`, `identity.git.email` |
| `user.signingkey`, `gpg.format = ssh`, `gpg.ssh.allowedSignersFile`, `commit.gpgsign = true` | `identity.git.signing_key`, only then |
| `url."git@<host>:".insteadOf = https://<host>/` | `identity.ssh`, when the agent is proxied |
| `safe.directory = *` | snug, unconditionally |

There is no `init.defaultBranch` and there will be no
`identity.git.default_branch`. An identity is a PIN — who the sandbox acts as —
and a key per program setting that someone finds convenient turns it into a
configuration file for every tool in the sandbox, written in snug's grammar and
validated by snug's code.

`GIT_CONFIG_GLOBAL` is owned by snug in any selection with an identity
(`conditionalEnvs`), and a stub at the system scope works precisely because
global outranks system. `TestSystemScopeStubReachesGitBesideAnIdentity`
(test/integration) holds it; a stub at `~/.gitconfig` is displaced
(`replaces:` in the provenance) and one at `~/.config/git/config` is never read.
git merges two global files, which is why the variable, not one generated file,
is the mechanism.

**The signing keys are authored, never carried.** `commit.gpgsign = true` from
a host config, with a signing key that is not inside the sandbox, makes **every
commit fail** — worse than an unsigned commit. snug writes all four only when
`identity.git.signing_key` is pinned: `user.signingkey` names snug's own staged
copy of the public half, and `commit.gpgsign = true` is written because snug
asked the host agent for one signature with that key at startup and GOT one — a
key the agent merely lists can still refuse every signature.

**`allowed_signers` is one line and it is a trust decision, so it is the narrow
version of the grant.** `<identity.git.email> namespaces="git" <keytype>
<base64>` — the pinned address as the principal, the staged signing key, and a
namespace pin so a signature the same key made for anything else does not read
as a good commit signature. A run verifies its OWN commits and nobody else's.
The host's `~/.config/git/allowed_signers` is never carried: it is the list of
people whose signatures you accept, so carrying it would hand the sandbox
collaborators' addresses and public keys *and* a trust decision no grant named.

**The principal is unquoted, and that is the whole reason for a refusal.**
`allowed_signers` has no quoting and space is its field separator, so an
`identity.git.email` that is not exactly one address stops being a value and
becomes syntax: an address of `u@example.com,evil@example.com ssh-ed25519
AAAA…` authors a six-field line whose key is the attacker's, with the pinned
key swallowed as a trailing comment, and `git verify-commit` then accepts
commits signed by a key no grant pinned. `CheckText` does not reach it — it
refuses forging runes and a space is not one. `refuseUnprincipledSigningEmail`
is scoped to `signing_key` for exactly that reason: everywhere else the email
is a value in a file `gitQuote` quotes, where a space is harmless.

## 5a. The value channel

A whitelist of KEYS is half a rule. git config values may legally span lines,
and a renderer that writes a value verbatim turns

```
[user]
	name = "evil\n[alias]\n\tanything = !touch /tmp/PWNED"
```

into a generated `~/.gitconfig` with a real `[alias]` section. The red team
measured exactly that against an earlier generator, with `git anything` running
the command inside the sandbox. Any written value is a carrier, so
`credential.helper`, `core.pager`, `core.sshCommand` and `filter.*.clean` come
back through the VALUE channel — exactly the class the key list exists to keep
out.

Two guards, deliberately both: `Identity.CheckText` refuses a control
character in any identity field at load, naming the field, and `GitConfigFrom`
drops control characters again as the backstop for whatever calls the renderer
next.

One value is not a value: `identity.ssh.host` lands unquoted inside the
`[url "git@<host>:"]` section HEADER, where `gitQuote` does not reach. Measured,
a host of `a"] [core] sshCommand = id ["x` closed the header and git inside
reported `global core.sshcommand=id [x:]`. `refuseUnhostlikeHost` holds both
host fields to letters, digits, `.` and `-`, because the same value is also
unquoted syntax in ssh's `Host` line and gh's `hosts.yml`
(`TestRefuseUnhostlikeHostCatchesSyntax`).

## 9. What a generated config does not bound

The generated file bounds what snug says to git inside the sandbox. It does not
bound what the *sandbox's own processes* say to git, because git reads
variables that outrank every config file, including the one snug just wrote.
Measured, git 2.55.0:

```
$ git config --show-origin --show-scope --get-all user.name
global   file:/home/u/.gitconfig   Pinned
command  command line:             Injected
```

`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n` (and the single-variable spelling
`GIT_CONFIG_PARAMETERS`) enter git at the **command-line** scope — above
`global`, above the repository's own `.git/config`, above any `include` the
generated file could carry. Tried and lost: an `[include] path = …` appended at
the end of the generated file (the env still wins, because the env is not a
file scope at all — probe F); a repository-local `.git/config` setting the same
key (the env still wins even against the *highest* file scope — probe G);
`GIT_CONFIG_NOSYSTEM=1` (it suppresses `/etc/gitconfig` only, one scope below
`global`, and is irrelevant here — probe P). There is no git switch that makes a
config file outrank the command line, because nothing outranks the command
line.

The same holds for the repository: a `.git/config` inside the target is read at
local scope, above the generated file, so a repository that asks for
`commit.gpgsign = true` with a key snug did not stage fails its commits with the
agent proxy's `agent refused operation`.

**Threat model, stated plainly.** A process cannot poison its parent's or a
sibling's environment — `/proc/<pid>/environ` is readable same-uid and not
writable, so a hostile injection only ever reaches a process the attacker
itself forked. And an attacker that forks the victim also chooses the victim's
`argv`, its `PATH`, and its binary — there is no configuration in which the
victim's environment is attacker-controlled while its `PATH` and binary are
not. So the intuitive case people reach for — a hostile `npm install`
postinstall runs, then the human types `git push` in the same shell — does
**not** work through the environment at all: the postinstall is a child and
cannot write its parent's environ. (It *can* work through a writable `$HOME`
and `~/.bashrc` — and closing the environment does not close that one either. This is an
**accepted residual**, not a tracked issue, and it is bounded: measured, the
poisoned `~/.bashrc` does not survive into a later `snug` run, because `$HOME`
is a fresh tmpfs every time and nothing writes it back to the host.)

Every candidate mitigation was tested and lives in the attacker's own channel:
a `git` wrapper on `PATH` that scrubs `GIT_CONFIG_*` is defeated by `PATH=` in
front of it and, more completely, by an exported `BASH_FUNC_git%%` shell
function, which precedes `PATH` lookup entirely; a classic-BPF seccomp filter
cannot dereference `envp` to see the variable at all (the same wall `clone3`
hit); `LD_PRELOAD` needs cgo, which `.claude/design/NOCGO.md` rules out, and is
itself one of the names snug annotates and never authors: snug writes only
`SnugOwnedEnv` and the feature-conditional names beside it. See issue #26 for
the full measurement set.

**What snug does own, and asserts mechanically:** the environment snug itself
hands the payload never ships an inline-config override pre-installed —
`policy.IsInlineConfigEnv` and `TestNoBuiltinHandsOverAnInlineConfigVariable`.
That is not a fix for the payload route above and must never be read as one;
see `GENERATED-CONFIG.md` §7 for the pointer-vs-inline-setting distinction it
enforces.
