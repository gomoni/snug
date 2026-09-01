# Git configuration in the sandbox

**This is an instance of [GENERATED-CONFIG.md](GENERATED-CONFIG.md), which owns
the rule; this document holds the git-specific measurements.**

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
credential — see `SECRETS.md` §4.2, which states the rule that a secret selector
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
  feature with a design of its own; it is
  https://github.com/gomoni/snug/issues/35, and the whitelist grows when it is
  built.
- **`url.*.insteadOf`** — rewrites where a fetch goes. An identity pin already
  generates the one rewrite it needs.
- **`safe.directory`** — snug writes `*` itself, because the sandbox uid and the
  bind's owner differ often enough that anything else is a support burden.

## 5a. A whitelist of KEYS is half a rule — the value channel

Found by the red team against the first version of this code, and it defeated
the whole design rather than a corner of it.

git config values may legally span lines. `git config --file … --list -z`
returns the embedded newline faithfully, and the renderer wrote it verbatim:

```
[user]
	name = "evil\n[alias]\n\tanything = !touch /tmp/PWNED"
```

produced a generated `~/.gitconfig` containing a real `[alias]` section. Inside
the sandbox, `git config --get alias.anything` returned the command and
`git anything` ran it. All three whitelisted keys worked as the carrier — so
`credential.helper`, `core.pager`, `core.sshCommand` and `filter.*.clean` came
back through the VALUE channel, which is exactly the class the key whitelist
exists to strip.

The fix is the rule that already existed one layer over: `checkEnvValue` has
refused control characters in a profile-supplied environment value since the NUL
finding. Extracted git values now get the same treatment — **dropped, named on
stderr, not escaped.** Escaping into git's `"…\n…"` form is one more quoting
rule to get subtly wrong, and no name, email address or branch needs a control
character. `GitConfigFrom` repeats the check as a backstop for whatever calls
the renderer next.

**The general shape, for the third time in this project: a rule written once and
applied to one of its two halves.** Keys were bounded; values were not.

## 5b. Owning the matcher means owning its divergences

An independent review found **seven** cases where snug's `gitdir:` matcher
disagreed with git, in both directions. Both directions are silent, and both are
wrong in the same way — the sandbox commits under an identity the human did not
choose:

| what | direction |
|---|---|
| `gitdir:work/` and every other relative pattern | git fires, snug did not — the `**/` prefix rule is *any* pattern not starting with `~/`, `./` or `/`, not "a pattern with no `/`" |
| `./rel/` | git fires, snug did not — the form was unimplemented |
| `[wp]ork`, `w[!x]rk`, `wo\rk` | git fires, snug did not — classes and escapes are wildmatch features, not extras |
| `~/**work/` against `~/a/xwork/proj` | snug fired, git does not — `**` crosses `/` **only as a whole component**; elsewhere it degrades to `*` |
| a target reached through a symlink | snug fired, git does not — git matches the **real** path (`strbuf_realpath`) |
| `gitdir/i:` on a host whose home has a capital | git fires, snug did not — the pattern and the gitdir were lowercased and `home` was not |

The matcher is now component-wise: split both sides on `/`, `**` as a whole
component consumes zero or more components, everything else goes to
`path.Match`, which implements what wildmatch does *within* a component. That
also removed an exponential case — the old character-wise version took 3 seconds
on `/**a**a**a**b` against a 400-component path and did not finish with one more
group.

**The durable answer is the oracle**, not the fix:
`TestGitdirMatcherAgreesWithRealGit` (internal/cli) builds a real repository and a
real config per case, asks *git* whether the include fired, and compares. A
hand-written table only tests the cases someone thought of, and the seven above
are the proof of it.

Unconditional `[include] path = …` is followed too — the commonest way people
split a gitconfig, and it was not read at all. `includeIf "onbranch:"` joins
`hasconfig:` in being ignored-and-named: both are decided by the sandboxed
material.

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

- **Ordering matches git**, which is not obvious and is easy to assume
  otherwise. `git config --list` emits entries in file order and the recursion happens
  at the include's position inside the same loop, so a whitelisted key written
  after an include still overrides it, exactly as git does.
- **Values are re-quoted.** snug writes `key = "value"` with `\` and `"`
  escaped, because writing them raw made `#`, `;`, a leading space and `\` change
  meaning, and a `"` in the host's `user.name` made `git version` itself fail
  inside the sandbox. The value the sandbox sees is the value git reported, not
  the bytes the host file used to spell it.
- **Nesting.** Includes nest to depth 8 and then stop. A deeper chain is a
  configuration nobody has, and an unbounded one is a hang.
- **`hasconfig:`** — §4, deliberate.
- **System config** (`/etc/gitconfig`) is not read. It is root-owned host policy;
  the sandbox is not the host.

## 8. What this does NOT do

It does not verify that the identity it extracted matches the account an
`[identity]` block pins, or that either matches the ssh key. Nothing does — see
https://github.com/gomoni/snug/issues/30. The three commands that answer the
question are in the README, next to the profile that needs them.

## 9. What a generated config does not do

The generated file bounds what the *host's* config says inside the sandbox. It
does not bound what the *sandbox's own processes* say to git, because git reads
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
and `~/.bashrc` — see CLAUDE.md's "writable surface is eight paths" bullet —
and closing the environment does not close that one either. This is an
**accepted residual**, not a tracked issue, and it is bounded: measured, the
poisoned `~/.bashrc` does not survive into a later `snug` run, because `$HOME`
is a fresh tmpfs every time and nothing writes it back to the host.)

Every candidate mitigation was tested and lives in the attacker's own channel:
a `git` wrapper on `PATH` that scrubs `GIT_CONFIG_*` is defeated by `PATH=` in
front of it and, more completely, by an exported `BASH_FUNC_git%%` shell
function, which precedes `PATH` lookup entirely; a classic-BPF seccomp filter
cannot dereference `envp` to see the variable at all (the same wall `clone3`
hit); `LD_PRELOAD` needs cgo, which `.claude/design/NOCGO.md` rules out, and is
itself one of the names snug annotates and never authors — that table refuses
nothing since ENVIRONMENT-VARIABLES.md §2.9, but it was never what stopped snug
writing `LD_PRELOAD` either: snug writes only `SnugOwnedEnv`. See issue #26 for
the full measurement set.

**What snug does own, and asserts mechanically:** the environment snug itself
hands the payload never ships an inline-config override pre-installed —
`policy.IsInlineConfigEnv` and `TestNoBuiltinHandsOverAnInlineConfigVariable`.
That is not a fix for the payload route above and must never be read as one;
see CLAUDE.md's "Generate, don't bind" bullet for the pointer-vs-inline-setting
distinction it enforces.
