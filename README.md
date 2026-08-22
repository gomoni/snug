# snug

> *fitting closely and comfortably* · *marked by cordiality and secure privacy* ·
> *offering safe concealment* · *a small private room in a pub*

[Merriam-Webster on snug](https://www.merriam-webster.com/dictionary/snug)

## What is it

A sandbox for running an **untrusted code** on modern Linux machines. Provides as
seamless experience as possible. It works without `root`, without any daemon,
without an installation. Assumes that processes inside sandbox are hostile and disallow
even a read access to the most of the system. Static linked binary written in Go, which

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

# nothing is hidden — what no profile grants is simply never there
🔒 snug:~/src/myproject> ls ~/.ssh
ls: cannot access '/home/you/.ssh': No such file or directory
🔒 snug:~/src/myproject$ echo "hello" > ../hello
bash: ../hello: Read-only file system
🔒 snug:~/src/myproject$

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
snug -p @git-ro -p @net ~/src/proj     # ...and your git config, read-only
snug -p work ~/src/proj                # pinned to one git/ssh/GitHub account — see Identity
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

**One live sandbox per directory.** A `snug <dir>` run is tied to its target.
While one is live, a second `snug <dir>` on the same directory is refused — two
independent sandboxes racing writes to the one writable thing that persists is a
footgun, not a feature. To open another shell in the sandbox that is already
running, use `snug attach <dir>`. "Same directory" is resolved by realpath, so a
symlink to the target counts as the same target.

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
| `@git-ro` | Your git name and email, extracted from the host config and regenerated. Never bound. |
| `@tmp-shared` | A per-project host directory as `/tmp`. Survives the sandbox. |
| `@net` | Internet access. Host loopback unreachable. |
| `@net-anon` | As `@net`, but the sandbox gets a synthetic address in both families instead of your host's. |
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

## Identity — one account per sandbox

An `[identity]` block pins the sandbox to one git/ssh/GitHub account. Bounds
blast radius, not secrecy: an agent that can sign with one key pushes as that
account and no other, and `gh` answers as that account and no other. Without
pinning, "the agent has ssh" means "the agent is you, everywhere".

```toml
# ~/.config/snug/profiles.d/accounts.toml
[profile.work]
include = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@net"]
  [profile.work.identity]
  ssh_mode  = "agent-proxy"
  ssh_key   = "{home}/.ssh/work.pub"     # the PUBLIC half
  gh_user   = "work-account"
  gh_host   = "github.com"               # optional, this is the default
  git_name  = "Your Name"
  git_email = "you@work.example"
```

`snug -p work ~/src/proj`. What that gets you:

- **ssh** — a filtering proxy to your already-unlocked host agent, exposing
  exactly the one key. No key material inside, no passphrase prompt, your other
  keys neither usable nor enumerable. What no agent forwarder can do is restrict
  *what* gets signed.
- **git** — `~/.gitconfig` is generated, not bound, and `GIT_CONFIG_GLOBAL`
  points at it. The host's credential helpers and `insteadOf` rules do not come
  along — what the sandbox's own processes set for themselves is another
  matter; see [GIT-CONFIG.md](.claude/design/GIT-CONFIG.md) §9.
- **gh** — a private `hosts.yml` holding that account's token, with
  `GH_CONFIG_DIR` pointing at it. The env var carries a path, not a credential.
- `~/.ssh/config` and a `known_hosts` filtered to that one host, both generated.
  Your real `~/.ssh` is never mounted.

### Your git identity without pinning an account

`-p @git-ro` gives the sandbox the name and email you commit under, so
`git commit` works, without pinning anything else. It does **not** bind
`~/.gitconfig`:

```console
$ snug -p @git-ro ~/src/proj -- cat '~/.gitconfig'
# Generated by snug from the host's git config. The host's file is not
# mounted: it names programs to run (credential.helper, alias = !cmd,
# core.pager, textconv), and a read-only bind supplies those rather than
# stopping them. Only keys that carry no execution are carried over.
[user]
	name = Your Name
	email = you@example.com
[init]
	defaultBranch = main
[safe]
	directory = *
```

Three keys cross: `user.name`, `user.email`, `init.defaultBranch`. Your aliases,
credential helpers, pagers and diff drivers do not — a read-only bind would not
have restrained them, it would have supplied them.

`includeIf "gitdir:…"` is honoured, so a per-directory identity keeps working:
snug evaluates the condition itself against the target. `includeIf "hasconfig:…"`
is ignored and says so on stderr, because that condition is decided by the
repository's own config — a repo whose only property is a crafted remote URL can
otherwise choose which of your files gets read.

Signing keys are deliberately not carried: `commit.gpgsign = true` with a key the
sandbox does not have turns every commit into a failure. Commits inside are
unsigned for now.

### Two accounts, two profiles

Write the block twice. Each sandbox then acts as one account through **both**
channels, and cannot act as the other.

```console
$ snug -p personal ~/src/proj    # one account
$ snug -p work     ~/src/proj    # the other
$ snug -p personal -p work ~/src/proj
snug: profiles "personal" and "work" pin different identities; select only one
```

Selecting both is an error rather than a merge: an identity is a pin, and two
pins are a contradiction.

### Checking which account you are

```console
$ gh auth status              # the account snug staged
$ gh api user --jq .login     # the account GitHub answers with
$ ssh -T git@github.com       # Hi <account>! You've successfully authenticated...
```

The middle one is the check that counts — it asks GitHub rather than reading
what snug wrote. **snug does not verify that `ssh_key` and `gh_user` name the
same account**; pin one account's key and another's token and both halves work,
so run all three the first time you write a profile.

### Two things that will bite

`gh` must be *inside* for the staged token to be usable. If your `gh` is not
under `/usr` — a tarball in `~/bin` is common — `@sys` does not carry it:

```toml
[profile.gh-cli]
ro = ["{home}/bin/gh_X.Y.Z_linux_amd64/bin/gh:/snug/bin/gh"]
```

And a normal `gh auth login` token carries `repo`, `gist`, `read:org` and
`admin:public_key`. With `admin:public_key` a sandbox that reads the staged file
can add an SSH key to the account — an effect that **outlives the sandbox**. Use
a fine-grained token if that matters.

### Why ssh works at all

The sandbox maps one uid, so every root-owned file reads as `65534` inside it,
and OpenSSH refuses a configuration file owned by neither root nor the caller.
On a host whose system-wide `ssh_config` lives under `/usr` (openSUSE), every
`ssh` inside the sandbox died with `Bad owner or permissions on
/usr/etc/ssh/ssh_config.d/50-suse.conf` — `git clone git@github.com:…` included.
So when an identity is pinned, snug replaces the system-wide `ssh_config` with
one it generates. The cost, stated plainly: your host's system-wide ssh defaults
do not apply inside. ssh's compiled-in defaults do.

## Environment variables

Empty environment is base state, same as filesystem. `bwrap --clearenv` drops
every host variable. Sandbox gets what snug writes plus what a profile asked for.
`snug --dry-run` prints all of it:

```console
$ snug --dry-run .
ENVIRONMENT  (--clearenv, then:)
  HOME             /home/u                         (snug)
  PATH             /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PS1              🔒 snug:\w\$                     (snug)
  SNUG_PROFILES    @cwd-rw,@home,@parent-ro,@sys   (snug)
  XDG_CONFIG_HOME  /home/u/.config                 set       @home
```

Every line names its verb and the profile that wrote it. `(snug)` is snug's own.

Profiles use five verbs under one `environ` section. Verb says how value merges.

```toml
[profile.mytools]
ro = ["/opt/tools/bin", "/opt/tools/override"]   # a profile grants what it names

[profile.mytools.environ.set]
EDITOR = "/usr/bin/vim"            # scalar. Two profiles disagreeing = error

[profile.mytools.environ.merge]
PATH = ["/opt/tools/bin"]          # list. Union, sorted, deduplicated

[profile.mytools.environ.prepend]
PATH = ["/opt/tools/override"]     # list, front. At most ONE profile per variable

[profile.mytools.environ.inherit]
COLORTERM = true                   # copy the host's value, if set

[profile.mytools.environ.sanitise]
PKG_CONFIG_PATH = true             # copy the host's list, drop what is not granted
```

Names snug knows carry a type (`internal/policy/envtypes.go`). List verbs need
one — merging needs the separator, and what an empty element means to whoever
reads the variable. `set` and `inherit` take any name: your profile has an author
and a file path, and that is who takes it on.

Whatever snug does know, it says on the row that grants it:

```console
$ snug profile show mytools
  environ.set      GIT_SSH = /opt/tools/bin/ssh  ← unchecked: snug has no type for this name  ← git runs this as the transport for every fetch and push
  environ.inherit  COLORTERM  ← unchecked: snug has no type for this name
```

Two separate statements, neither a refusal. `unchecked` means no type, so snug
checked nothing about the value. The sentence after it means snug measured what
some tool does with that value — `internal/policy/testdata/annotations.txt` is
the whole table, `GIT_SSH`, `RUSTC_WRAPPER`, `BASH_ENV`, `LD_*` and `GIT_CONFIG_*`
among them. A profile snug **ships** is held tighter: it may not write an
untyped name at all.

Profile order never matters. Two profiles setting the same scalar to different
values = **fatal error naming both**, never a silent winner — same rule as two
profiles fighting over a mount. Lists join, so cannot conflict. `prepend` is the
one slot only one profile may hold: "first" is not a thing two profiles share.

Resolution by band. Nothing a profile writes chooses its band:

```
prepend  ->  merge  ->  sanitise  ->  snug's own  ->  base
```

So a profile's contribution always beats the distro's, and `PATH` reads top to
bottom in the order the sandbox searches it.

Four rules to know before writing a profile:

- **Profile must grant what it names.** `merge PATH = ["/opt/tools/bin"]` without
  a grant for that path is refused at parse time. A search path pointing at
  nothing inside the sandbox is a lie the tool acts on.
- **Some names are annotated, not refused.** `LD_PRELOAD`, `GIT_SSH`,
  `GIT_CONFIG_*`, `BASH_FUNC_*`, `JAVA_TOOL_OPTIONS` and relatives: the value is
  code, so a profile granting no path at all still hijacks the next `git fetch`
  a human runs inside. Your profile, your call — the row just says so. snug has
  no deny rules anywhere.
- **Names snug writes itself cannot be replaced.** `HOME`, `SHELL`, `PS1`,
  `TERM`, `SNUG*` — a profile able to set `SNUG_PROFILES` could lie to the
  artifact you read to decide whether to trust the sandbox. `PATH` is owned the
  same way, but it is a list, so a profile may still `merge` or `prepend` into
  it: contributing is not replacing.
- **`sanitise` copies the host, so it filters hard.** Element survives only if a
  grant covers it *and* the mount there really holds the host's content. An empty
  tmpfs (`/tmp`, `$HOME`) and `/proc` do not; elements under them are dropped and
  named on screen. Otherwise the payload creates the directory, drops a file
  called `git` in it, shadows the real one.

Secrets go in files, not here. `/proc/self/environ` is readable by every process
in the sandbox and inherited by every child, so `@claude` passes an endpoint,
never a key.

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

> Issue #63 (Tier B) moved the container engine into the sandbox's own
> network namespace, so `@podman-socket` is offline unless `@net` is also
> selected, exactly like every other profile: a container reaches exactly
> what the sandbox reaches, no more, no less, in both directions — measured
> against a real engine. See `.claude/design/ENGINE-NETNS.md` §0 for the
> finding this closes.

The engine behind `@podman-socket` is podman, rootless, one per sandbox. What
snug *filters* is the **docker-compatible** schema — which podman itself serves —
so the client you run inside can be anything that speaks it. `CONTAINER_HOST` and
`DOCKER_HOST` both point at snug's proxy.

**A container profile creates persistent mutable state on your disk.**
`@podman-socket` and `@podman-build` give the sandbox its own image store at
`~/.local/share/snug/engines/<key>/`, keyed by the profile selection and the
target directory. It persists across runs and is reused, so images are not
re-downloaded every time — a deliberate convenience. Two consequences worth
stating plainly: the store is writable state a container leaves behind, and a
later run with the **same profiles on the same directory** reuses whatever images
and layers an earlier run pulled or built there; and it is never
garbage-collected today, so it grows (issue #308). What it does **not** touch is
your host's own podman/docker store — that is separate and never mounted. Why
this cross-run reuse is an accepted non-goal (it never reaches host state beyond
snug's own store) is spelled out in
[`.claude/design/THREAT-MODEL.md`](.claude/design/THREAT-MODEL.md).

In practice that means **`docker` is the client to use inside a sandbox**:

```bash
docker pull alpine && docker run --rm alpine echo hi   # works
podman-remote ps                                       # works, read-only only
```

`podman-remote` speaks podman's *native* libpod API, which snug refuses for any
request carrying a body it would have to inspect — so it inspects fine and
cannot `run` or `pull`. There is no flag that changes this.

**The shim.** `/usr/bin/podman` **may** be a symlink to `distrobox-host-exec`,
which forwards to an engine *outside* the container. That is not distrobox's
default — it is a choice someone made on that machine, for usability — so snug
detects it rather than assuming it. From inside a sandbox the forwarding cannot
work, and podman's own error for it names neither the cause nor a fix. Where snug
finds such a shim it stages its own `podman` at `/snug/bin/podman`
and puts that directory on `PATH` ahead of `/usr/bin`. It forwards the
subcommands `docker` can serve, byte-for-byte, and refuses the rest in its own
voice:

```
$ podman pod ps
snug: stub refuses 'podman pod' -- pods are a podman-only grouping; docker has
      no equivalent command.
```

Nothing is hidden: `/usr/bin/podman` is untouched and still runs by absolute
path, `/snug/bin` is read-only from inside, and a `podman` provided by a
profile's `path` still wins over snug's. It appears only when a podman profile
is selected — a default `snug <dir>` has no stub and an unchanged `PATH`.

**Known rough edges**, measured and not yet fixed:

- `docker run` exits 0 but prints nothing — the container's stdout is not
  relayed back. Plain `docker` behaves the same, so this is the proxy, not the
  stub.
- `docker build` needs the classic builder; snug sets `DOCKER_BUILDKIT=0` for
  you, because BuildKit bypasses the filter entirely rather than being filtered.
- `docker run -p` is refused, permanently, not a temporary limitation (issue
  #63, Tier B): the engine runs inside the sandbox's own network namespace and
  holds no `CAP_NET_ADMIN`, so it cannot reconfigure it to publish a port.
  Containers share the sandbox's own network instead — with `@net`, full
  egress; without it, none, measured both directions — which is the security
  property [ENGINE-NETNS.md](.claude/design/ENGINE-NETNS.md) exists to close.
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

Your own profiles. snug's line runs between the sandbox and the host: inside is
hostile by assumption, outside stands you, picking profiles. It does not
second-guess you.

`rw = ["{home}"]` really does hand over your real `$HOME`. `@net-host` really
does put the sandbox on the host's network. `environ.set EDITOR =
"/tmp/upload-everything"` really does give the next `git commit` a program you
chose. All holes, all on screen in `--dry-run`, all yours. Unix tool, enough
rope.

What snug owes you is that the screen does not lie. Every grant traces to one
profile that named it, nothing is visible that no profile granted, and a row
says what snug knows about the value — including when it knows nothing
(`← unchecked`). So read `--dry-run`, not the profile's name.

snug refuses three things, and none of them is "too dangerous for you":

- **mechanism** — a NUL in a value writes a bwrap flag of its own, a newline
  forges a row on that very screen;
- **names snug owns** — `HOME`, `PATH`, `SNUG*`. A profile that could set
  `SNUG_PROFILES` could lie to the artifact you check;
- **wrong operation for the type** — `sanitise MANPATH` would ADD directories,
  because an empty element there is an instruction, not a gap.

`snug doctor` may get louder about profiles that are dangerous but correct
(issue #80). It will not refuse to run one.

The complete goals and non-goals — what host state snug protects, what it
deliberately does not, and worked prevented/not-prevented examples — live in
[`.claude/design/THREAT-MODEL.md`](.claude/design/THREAT-MODEL.md).

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

## Drafts — designed, not built

Two designs are written down and deliberately unimplemented. They are kept
because the reasoning is expensive to re-derive, not because the work is
scheduled:

 * [`SECRETS.md`](.claude/design/SECRETS.md) — which credentials reach a
   sandbox, the severity model, and brokering versus injection. What ships
   today is narrower than what it proposes: one pinned ssh key through a
   filtering agent proxy, a five-key projection of Claude Code's credentials,
   and a generated `~/.gitconfig`. The broker itself is not built.
 * [`PARAMETERISED-PROFILES.md`](.claude/design/PARAMETERISED-PROFILES.md) —
   profiles that take arguments, postponed by decision.

Everything else that was once on this list has landed: the container engine
runs in the sandbox's own network namespace, environment handling has its five
`environ` verbs, and an identity is one `[identity]` block per profile.

**Known gaps live in the [issue tracker](https://github.com/gomoni/snug/issues),
never here** — each one carries a severity label and the measurement that
confirmed it. A list in prose goes stale; a list with issue numbers does not.

## Documentation

[`VERIFY.md`](VERIFY.md) is the hands-on checklist: every line is a command with
its expected output, so run it rather than trusting this file.

Design and research material is **not** user documentation — it is the best
record that exists, written for the people building snug and measured against
real hosts. It lives under [`.claude/design/`](.claude/design/), and
[`INDEX.md`](.claude/design/INDEX.md) is the way in: architecture, threat model,
the policy model, and a table of every topic document with what it settles.

## Requirements

MIT licensed. Linux with unprivileged user namespaces, `bubblewrap`, Go 1.26+ to build,
`pasta` for networking. Works inside `distrobox` and other containers — nested
user namespaces are fine. `snug doctor` tells you where you stand, and names the
exact sysctl when something is missing.
