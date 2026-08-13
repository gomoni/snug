# Git configuration in the sandbox

**Status: built.** `@git-ro` extracts and generates; it binds nothing. The
measurements below were made on git 2.55 on the development host and are what
the design rests on — re-run them before changing any of it.

---

## 0. The one-sentence version

`~/.gitconfig` is not a data file that sometimes contains secrets. It is a
**command table**, and a read-only bind of a command table does not restrain it
— it supplies it. So snug reads the host's config as data, keeps a whitelist of
keys that carry no execution, and generates the file the sandbox sees.

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

## 2. What `@git-ro` used to be, and why nobody caught it

```toml
[profile.git-ro]
ro = ["{home}/.config/git", "{home}/.gitconfig"]
```

The profile carried an abuse sentence, as the working agreement requires: *"the
sandbox learns your git name, email, aliases, and any secrets you unwisely put in
`~/.gitconfig`"*. It was written at authoring time and it was honest. It was also
wrong in two ways that matter:

- it classified the file as **data with secrets in it**, not as a command table;
- *"unwisely put in"* reads as a user error, when the executable keys are the
  file's purpose.

Nothing re-read that sentence as `GIT_CONFIG_GLOBAL`, identity pinning and
credential staging grew around it. **A comment cannot fail.** That is the
process finding, and the answer to it is mechanical:
`TestNoBuiltinGrantsACredentialOrCommandTablePath` (internal/profile) refuses,
with no allowlist and no flag, any builtin grant whose host side is in a
catalogue of credential paths and command tables. A human writing the same grant
in their own `profiles.d` is making a declaration about their own machine, which
invariant 3 puts outside the sandboxed material — what must never happen is snug
shipping that decision for everyone.

## 3. Why snug evaluates `includeIf` itself

The obvious implementation is to ask git — it owns the semantics, and
reimplementing a matcher invites divergence. It does not work, and both halves
were measured.

**Asking git in the target lets the repository vote.** Fixture: a global config
whose `includeIf "gitdir:<root>/work/"` supplies `work@example.com`, and a repo
inside that directory whose own `.git/config` sets `user.email`:

```
$ git -C <root>/work/repo config --get user.email
repo-said-so@example.com          # the repository won
```

The repository is the material being sandboxed. Letting it choose the identity
the sandbox commits under is the same class of defect as letting it choose the
credential — see `SECRETS.md` §4.1, which states the rule that a secret selector
must not be steerable by the target.

**Asking git outside a repository never fires the condition.** Same fixture,
same directory:

```
$ git -C <root>/work/repo config --global --get user.email
global@example.com                # the include never fired
```

`--global` restricts the *files*, and a `gitdir:` condition has no repository to
match against, so it is false by construction.

There is no invocation that both honours the condition and keeps the target out
of the decision. So snug reads the file (git still does the tokenising, via
`git config --file … --list -z`, so snug never writes an INI parser) and decides
the condition itself: `policy.GitdirMatches`, with git's `wildmatch` semantics
reduced to what a `gitdir:` pattern can contain.

## 4. `hasconfig:` is refused, and this is the sharpest measurement

`includeIf "hasconfig:remote.*.url:<glob>"` matches against **the repository's
own remotes**. Fixture: a repo outside every `gitdir:` pattern, whose only
property is a crafted remote URL:

```
$ git -C <root>/hostile config --get user.email
internal@example.com
$ git -C <root>/hostile config --get credential.helper
!echo internal-helper-ran
```

A repository selected which of the host's files was included, and that file
carried a `credential.helper` naming a command. If snug honoured `hasconfig:`,
cloning a hostile repository would choose which of your configs snug reads —
invariant 3 verbatim.

snug therefore ignores the condition **and says so on stderr**. Silence would
leave a human whose config uses it wondering why the sandbox commits under a
different identity from the host.

## 5. The whitelist, and what is deliberately not on it

```
user.name
user.email
init.defaultBranch
```

Not on it, and the reasoning is not "we ran out of time":

- **`credential.helper`, `alias.*`, `core.*`, `diff.*`, `filter.*`** — §1.
- **`user.signingkey`, `gpg.format`, `commit.gpgsign`, `tag.gpgsign`.** These
  look harmless and are the trap. `commit.gpgsign = true` with a signing key that
  is not inside the sandbox makes **every commit fail**, which is worse than an
  unsigned commit. Signing needs the public key staged *and* an agent willing to
  sign with it, and the ssh-agent proxy pins exactly one key today. That is a
  feature with a design of its own; it is in `TODO.md`, and the whitelist grows
  when it is built.
- **`url.*.insteadOf`** — rewrites where a fetch goes. An identity pin already
  generates the one rewrite it needs.
- **`safe.directory`** — snug writes `*` itself, because the sandbox uid and the
  bind's owner differ often enough that anything else is a support burden.

## 6. What a human sees

```
$ snug -p @git-ro <dir> --dry-run
  data   /home/u/.gitconfig                             git:@git-ro
  GIT_CONFIG_GLOBAL /home/u/.gitconfig                  (snug)
```

`GIT_CONFIG_GLOBAL` is not decoration. git merges **two** global files
(`~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`), so generating one of them is
not enough; setting the variable replaces both. It is also what stops a
conditional include in the host's file from firing *inside* the sandbox, which
matters on a host whose include files live inside the project trees — where
`@parent-ro` would otherwise make them reachable.

With an `[identity]` block as well, the block wins per key and the provenance
reads `identity:<profile>`. A pin that a host value could override would not be
a pin.

## 7. Known deviations from git

Stated because a divergence nobody wrote down is a bug report waiting to happen:

- **Ordering.** git applies an include at the point the `includeIf` line appears,
  so a key *after* the include wins over the included file. snug folds the global
  file first and overlays matched includes, so an included value wins regardless
  of line order. Only observable when the same whitelisted key appears both
  after an include and inside it.
- **Nesting.** Includes nest to depth 8 and then stop. A deeper chain is a
  configuration nobody has, and an unbounded one is a hang.
- **`hasconfig:`** — §4, deliberate.
- **System config** (`/etc/gitconfig`) is not read. It is root-owned host policy;
  the sandbox is not the host.

## 8. What this does NOT do

It does not verify that the identity it extracted matches the account an
`[identity]` block pins, or that either matches the ssh key. Nothing does — see
`TODO.md`. The three commands that answer the question are in the README, next
to the profile that needs them.
