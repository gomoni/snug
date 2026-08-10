# The environment configuration format

**Status: proposed, shape decided.** §1–§3 = format. §4 = measured evidence forcing each rule. §5 = sidenote on considered-and-rejected — read only to reopen something.

Decided: five verbs nested under one `environ` section, all of them profile
keys; `prepend` usable **once per variable** across the selected set, a second is
a failure; snug authors its own variables and is not bound by the verbs; snug
owns the variable types; snug never splits a string on a separator.

---

## 1. The format

### 1.1 Five verbs

| verb | where | operates on | two profiles both use it |
|---|---|---|---|
| `environ.set` | profile | **scalars** | same value fine; **different values are an error** |
| `environ.merge` | profile | **lists** | **union**, then sorted |
| `environ.prepend` | profile | **lists** | **error** — at most one per variable across the selected set |
| `environ.inherit` | profile | any | copy host value verbatim |
| `environ.sanitise` | profile | **lists** | copy host value, keep only elements policy grants |

**And a sixth thing that is not a verb: snug's own authorship.** snug sets
`HOME`, `SHELL`, `USER`, `LOGNAME`, `TMPDIR`, `PS1`, `SNUG*`, the base `PATH`,
and — when a podman profile is selected on a host where podman is a shim —
`/run/snug/bin` on `PATH`. **No profile may write any of those, and snug is not
bound by the verbs' rules when writing them.**

This is not an exemption invented for convenience; it is the distinction the
codebase already draws for mounts and CLAUDE.md already states: *a profile
mounting over another profile's grant is masking and is refused; snug replacing a
path with its own generated content is replacement and is allowed.* `Mount` has
an `Authored` field and `Policy.Replace` is its single writer. The environment
needs the same, and an earlier draft of this document did not have it — which
made the format contradict itself in three places (§1.2 note, §2.5, §4.2).

Nested, not five root keys. Written as table headers, not inline tables. Four reasons, heaviest first:

**(a) Multi-line inline tables are invalid TOML 1.0** — flat spelling not parse for case needing it most. Measured in reference parser and in snug's own:

```
environ-set = {                 python3 tomllib: Invalid initial character for a key part
  XDG_CONFIG_HOME = "...",      go-toml/v2:      toml: invalid character at start of key
  XDG_CACHE_HOME  = "...",
}
```

`@home` set four XDG variables. Flat force one long line, or invalid TOML.

**(b) Keep root namespace nouns.** `environ` sit beside `ro`, `rw`, `tmpfs`, `symlink`. Verbs one level down describe operations *within* a thing, not compete with grants for root.

**(c) Unknown verb refused for free.** `environ` = struct with known fields, so `DisallowUnknownFields` catch `environ.deny` exactly as it catch unknown root key. "A negation key cannot be smuggled in" apply one level down, no new code.

**(d) `append` later cost a nested field, not a sixth root key.**

Greppability survive — why verbs beat inferring operation from value type: `grep -rn 'environ.prepend' ~/.config/snug/profiles.d/` find every ordered claim on host, because header spell whole path. That would **not** hold for nested inline form.

### 1.2 Worked profiles

```toml
[profile.sys]
description = "The system's binaries, libraries and a curated /etc."
ro = ["/usr", "/etc/ssl", "/etc/pki", "/etc/passwd"]

[profile.sys.environ.set]
SHELL = "/usr/bin/bash"

[profile.sys.environ.merge]
PATH = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]


[profile.home]
description = "$HOME is an empty tmpfs at the host path. Writable, ephemeral."
tmpfs = ["{home}", "{home}/.config", "{home}/.cache",
         "{home}/.local/state", "{home}/.local/share"]

[profile.home.environ.set]
XDG_CONFIG_HOME = "{home}/.config"
XDG_CACHE_HOME  = "{home}/.cache"
XDG_STATE_HOME  = "{home}/.local/state"
XDG_DATA_HOME   = "{home}/.local/share"


[profile.stubs-in-path]
description = "permit snug's own stubs on PATH, ahead of /usr/bin"
# No environ key at all. This profile is a SWITCH, not a value — it decides
# whether snug may author /run/snug/bin onto PATH. The directory is a Go
# constant that only snug can create (KindData, via Policy.Replace), so no
# profile could legally name it under the rule below.


[profile.claude]
description = "Claude Code's configuration and credentials"

[profile.claude.environ.inherit]
ANTHROPIC_API_KEY = true
EDITOR            = true
```

```toml
# ~/.config/snug/config.toml — preferences, no grants
defaults = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@stubs-in-path"]
prompt   = "{lock} snug[{profiles}]:{cwd}$ "
```

Three things the layout does:

**`@home` binds authorship to the grant.** Variables sit next to the `tmpfs` that
creates the directories. Rule: every path a *profile* writes must be granted by
that same profile. This is a rule about profiles only — snug's own variables
(§1.1) are not subject to it, which is what makes `HOME` and the base `PATH`
still unconditional. See §4.2.

**`@stubs-in-path` grants nothing and writes nothing.** An earlier draft had it
`prepend` `/run/snug/bin`, and that was wrong twice over: the directory is
snug-authored so no profile can legally name it, and making it a profile's
prepend **inverted a documented decision** — `resolve.go:395-409` deliberately
places the stub *after* every profile `path` entry, because "a profile entry is
an explicit human grant and the stub is snug's own generated fallback".

**`@claude` keeps `inherit`, and that is deliberate.** An earlier draft moved
`inherit`/`sanitise` to `config.toml`. That is a regression: `ANTHROPIC_API_KEY`
enters only when `@claude` is selected today, whereas a host-wide config line
would put it in **every** sandbox on the machine — inverting CLAUDE.md's bound on
adapters ("one opt-in profile per tool, never in `defaults`"). The trust argument
for moving it does not survive either: `profiles.d` and `config.toml` sit in the
same `$XDG_CONFIG_HOME/snug/` tree at the same trust level, so moving it changes
only how narrowly it can be *scoped*, and that gets strictly worse.

---

## 2. How it behaves

### 2.1 The verb and the variable must agree

snug ship type table (§3). Mismatch = load error naming right verb:

```
environ.merge on SHELL   →  SHELL is a scalar, not a list — use environ.set.
environ.set   on PATH    →  PATH is a list — use environ.merge, or environ.prepend
                            if the order matters. environ.set on a list would
                            replace every other profile's entries, which snug
                            does not allow.
```

Unknown name default to **scalar** — conservative reading: scalar merge with nothing, so can only conflict, never silently combine.

### 2.2 snug never splits a string on a separator

String = exactly one element. Profile cannot write `"/usr/bin:"`, cannot produce `"/usr/bin::/bin"` by dropping element, cannot smuggle `;` into `LD_LIBRARY_PATH`. snug join with right separator for variable and refuse empty element.

Close §4.3 hazards by construction, not by implementer remembering. `environ.prepend` with `PATH = "/opt/bin"` = one-element prepend, not string to parse; several at once = array, and order within one profile unambiguous because one profile wrote it.

### 2.3 What `prepend` actually guarantees, and what it does not

A list variable is rendered in **bands**, and the band is structural — nothing a
profile writes can change which band its entry lands in:

```
prepend (at most one profile)  →  merge (sorted)  →  snug's generated  →  base
```

This is what `resolve.go` does today, with `prepend` added in front.

**Be precise about the guarantee, because an earlier draft overclaimed it.**
`prepend` guarantees *the front* — ahead of every merged entry. It does **not**
make merge order-free: merged entries are sorted, so between two profiles ASCII
decides, and `/opt/bin` beats `/usr/bin` without anyone using `prepend` or
consuming the slot. Two profiles merging directories that both contain `git` will
resolve to one of them silently.

So the honest statement is narrower than "two claims cannot both hold":

- **The front is exclusive**, and that is checkable from declarations alone.
- **Base entries are structurally last**, so a merged entry always beats the
  distro's — deliberately, because that is the point of a profile providing a
  tool.
- **Merge-vs-merge is sorted, and sorting is not a decision.** If you care which
  of two *profiles* wins, `prepend` is the only way to say so, and only one of
  you gets it.

That last point is an effective-behaviour non-monotonicity of the same shape
CLAUDE.md already carves out for mount depth, and it should be stated in the same
place rather than left to be discovered.

### 2.4 The errors

Errors = specification. Each name both profiles and fix.

```toml
# 1. Two prepends of one variable.
[profile.mytools.environ.prepend]
PATH = "/opt/bin"

[profile.othertools.environ.prepend]
PATH = "/srv/bin"
```
```
snug: mytools and othertools both prepend to PATH (/opt/bin and /srv/bin).
       Only one profile may hold the front of a variable. Use
       [profile.othertools.environ.merge] if you do not need to be first.
```

**The slot is a user's to take.** snug's own contribution (§1.1) is authored, not
a prepend, so `defaults` does not consume the slot — which an earlier draft got
wrong, leaving no way to prepend on an ordinary run short of `--no-defaults`.
Two profiles wanting the front is a genuine disagreement and is worth an error;
snug quietly holding it forever would not have been.

```toml
# 2. Two scalars disagree.
[profile.a.environ.set]
SHELL = "/usr/bin/bash"

[profile.b.environ.set]
SHELL = "/usr/bin/zsh"
```
```
snug: profiles a and b both set SHELL, to /usr/bin/bash and /usr/bin/zsh.
       A scalar has one value. Select one profile, or make them agree.
```
*Same* value in both fine — that what keep `include` usable.

```toml
# 3. A separator written by hand.
[profile.x.environ.merge]
PATH = "/usr/bin:/usr/sbin"
```
```
snug: PATH is a list, so environ.merge needs an array —
       PATH = ["/usr/bin", "/usr/sbin"]. snug joins with the right separator; a
       hand-written one can smuggle in an empty element, which in PATH means the
       current directory.
```

```toml
# 4. A value naming something the profile does not grant.
[profile.broken]
tmpfs = ["{home}/.config"]

[profile.broken.environ.set]
XDG_DATA_HOME = "{home}/.local/share"
```
```
snug: profile broken sets XDG_DATA_HOME=/home/u/.local/share, which it does not
       grant. Add it to tmpfs/ro/rw, or drop the variable — a variable naming a
       path that does not exist inside is worse than an absent one.
```

```toml
# 5. A name snug owns.
[profile.evil.environ.set]
SNUG_PROFILES = "@sys"
PS1 = "$(id)"
```
Refused. `SNUG_*` = what `--dry-run` and injected `~/.claude/CLAUDE.md` read against, so profile that can set it can lie to artifacts a human read to decide whether to trust sandbox. `PS1` executed by bash (§3.3). Refusal must cover **prefixes** — `BASH_FUNC_*`, `GIT_CONFIG_*`, `LD_*`, `npm_config_*`, `PIP_*` — which today's `map[string]bool` cannot express.

```toml
# 6. A verb that does not exist.
[profile.evil.environ.deny]
PATH = "/usr/bin"
```
Refused by `DisallowUnknownFields`, same as any unknown key.

### 2.5 What `--dry-run` shows

Provenance per entry = product. Mounts already render this way; environment should match, with verb and profile that supplied it:

```
ENVIRONMENT  (--clearenv, then:)
  HOME             /home/michal                    set       @home
  LANG             en_US.UTF-8                     inherit   (config)
  PATH             /run/snug/bin                   prepend   @stubs-in-path
                   /usr/bin /bin /usr/sbin /sbin   merge     @sys
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  (config)  1 of 3 kept
  SHELL            /usr/bin/bash                   set       @sys
  XDG_CONFIG_HOME  /home/michal/.config            set       @home
```

Two things flat list cannot say: **which verb** produced value, and for `sanitise`, **what dropped**. Filter that silently remove two of three elements = exact shape of failure this document try to avoid.

---

## 3. The variable types that drive the verbs

Everything `char*`; that all they share. Three types, and type decide which verbs apply.

### 3.1 Lists, and the empty-element column that decides `sanitise`

"→ CWD" mean empty element resolve to current directory, which inside snug = target: writable thing hostile payload control.

| variable | sep | empty element | merge | sanitise |
|---|---|---|---|---|
| `PATH` | `:` | **→ CWD** | ✓ | ⚠ rebuild only |
| `LD_LIBRARY_PATH` | **`:` or `;`** | **→ CWD** | ✗ | ✗ |
| `LD_PRELOAD` | **`:` or space** | n/a | ✗ | ✗ |
| `MANPATH` | `:` | **an OPERATOR** — leading = prepend system path, trailing = append, `::` = insert here | ⚠ | **✗** |
| `CDPATH` | `:` | **→ CWD, positionally** | ✗ | ✗ |
| `PKG_CONFIG_PATH` | `:` | **ignored** | ✓ | ✓ |
| `PYTHONPATH` | `:` | **→ CWD** | ⚠ | ✗ |
| `PERL5LIB` | `:` | **ignored** | ✓ | ✓ |
| `NODE_PATH` | `:` | **ignored** | ✓ | ✓ |
| `CLASSPATH` | `:` / `;` | unverified | ⚠ | ⚠ |
| `GOPATH` | `:` | element 0 privileged; empty first ⇒ empty `GOMODCACHE` | ⚠ | ⚠ |
| `INFOPATH` | `:` | trailing only = system default | ⚠ | ⚠ |
| `TERMINFO_DIRS` | `:` | = the system location | ✓ | ⚠ |
| `GOFLAGS` | **space** | n/a | ✗ | ✗ |

**Discriminator for `sanitise` not the type — this column.** Safe where empty element *ignored*; hazardous where it mean *CWD*; illegal where it *operator*. Type carrying separator must also carry empty-element kind, or sanitiser written once and wrong for third of its inputs.

`MANPATH` sharpest: empty element = instruction, so *removing* element can *add* directories. Measured — man-db announce the choice:

```
env -i MANPATH=/a     manpath  →  ignoring /etc/manpath.config    → /a
env -i MANPATH=:/a    manpath  →  prepending /etc/manpath.config  → /usr/share/man:/a
env -i MANPATH=/a::/b manpath  →  inserting /etc/manpath.config   → /a:/usr/share/man:/b
```

`LD_LIBRARY_PATH` and `LD_PRELOAD` = why separator live in type, not parser: `ld.so(8)` give them two different separator sets, neither escapable.

### 3.2 XDG — five scalars and two lists

| variable | type | default when not set **or empty** |
|---|---|---|
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` | scalar path | `$HOME/.config`, `.cache`, `.local/state`, `.local/share` |
| `XDG_RUNTIME_DIR` | scalar path | **no default value** |
| `XDG_DATA_DIRS` | **list**, `:` | `/usr/local/share/:/usr/share/` |
| `XDG_CONFIG_DIRS` | **list**, `:` | `/etc/xdg` |

Three things spec settle. **Empty is unset** — unlike `PATH`, XDG variables have genuine no-op value. **Relative paths must be ignored** — make these only two lists here where naive sanitiser safe *by specification*. And **`XDG_RUNTIME_DIR` carry obligations** — owned by user, mode 0700, session lifetime — so authoring it *is* a grant, and it belong to whichever profile create a directory meeting them.

Note `XDG_CONFIG_HOME` (scalar, `environ.set`) against `XDG_CONFIG_DIRS` (list, `environ.merge`). One character apart, different verbs — exactly what type table exist to catch.

### 3.3 Semi-structured: no verb — except `PS1`

`LS_COLORS`, `TERMCAP`, `DBUS_SESSION_BUS_ADDRESS`, `GIT_CONFIG_PARAMETERS`, `IFS`: **snug ignore them — position, not gap.** No verb accept semi-structured name, so nothing to refuse — operation not exist, same shape as "no X11 profile ships". Tool inside wanting colourful `ls` can set `LS_COLORS` itself.

Why they cannot be merged, one line each: `PS0`–`PS4` = template language on which bash perform **command substitution** (`promptvars`, on by default — measured). `PROMPT_COMMAND` = command bash run before every prompt. `LS_COLORS` = `key=value` pairs whose values contain `;` — the character that is a *separator* in `LD_LIBRARY_PATH`. `DBUS_SESSION_BUS_ADDRESS` = `;`-separated addresses, each `transport:` plus `,`-separated percent-encoded pairs. `IFS` = *set* of delimiter characters with first privileged. `BASH_FUNC_*` not a variable but name pattern carrying exported shell functions — and **function lookup precedes `PATH` entirely**, so it defeat every ordering question here.

**`PS1` is the exception, for a reason easy to get backwards.**

**Not a security control.** Anything inside can set it — payload first line can be `PS1='$ '` and marker gone. Refusing to let *user* configure it buy nothing against hostile payload; only hurt honest case, the one that matter: human at interactive shell asking *"am I inside?"*, where guessing wrong expensive.

But `environ.inherit = ["PS1"]` must still be refused — command substitution fire before user type anything. Same for `PS0`–`PS4` and `PROMPT_COMMAND`.

So neither verb nor flat no — **preference with constrained template**, "generate, don't bind" applied to display string:

```toml
prompt = "{lock} snug[{profiles}]:{cwd}$ "
```

snug render from fixed placeholder set — `{lock}`, `{profiles}`, `{target}`, `{cwd}` — emitting bash's own escapes. No command substitution, no host string. One caveat worth writing now: template still a display string, so `\r` or cursor-movement escape erase whatever precede it. Place marker last, or reject control characters.

*Machine-readable = separate channel, already solved:* `SNUG=1` and `SNUG_PROFILES` what agent or script should test. Prompt for humans; do not make it carry both jobs.

---

## 4. Why — the measured evidence

Every measurement executed against `main` (`408e8e4`).

### 4.1 What `main` does today

Thirteen variables, no XDG among them, and `PATH` only one any profile can influence:

```
snug <dir> -- env
HOME LANG LOGNAME PATH PS1 PWD SHELL SNUG SNUG_PROFILES SNUG_TARGET TERM TMPDIR USER

snug <dir> -- sh -c 'env | grep -c XDG'   →  0
```

`path` already work for user profiles and prepends — but entries come out **alphabetically**, from `sortedKeys` over a map, so author who care which of two directories win cannot say so:

```
snug -p zzz -p aaa . -- sh -c 'echo $PATH'   →  /aaa/bin:/zzz/bin:/usr/bin:…
snug -p aaa -p zzz . -- sh -c 'echo $PATH'   →  /aaa/bin:/zzz/bin:/usr/bin:…
```

Format fix this by *naming the regions*: `merge` = explicitly where you declined to care, so sorting it correct not arbitrary; `prepend` = where you said you do.

**`snug . -- podman` resolve against sandbox `PATH`, not host** — precondition for everything here, and nothing test it. bwrap `--clearenv`s, `--setenv`s `PATH`, then `execvp`s *inside* namespaces:

```
PATH=/…/hostonly:$PATH snug . -- hostmarker
  bwrap: execvp hostmarker: No such file or directory     ← host PATH contributes nothing
snug -p tbin . -- ls
  SANDBOX-LS-RAN                                          ← a fake ls beat /usr/bin/ls
```

Second case = `prepend` already working, unnamed and undeclared. Two gaps follow: **no test cover it** — refactor to host-side `exec.LookPath` would leave every test green and make negative case *succeed*, which read like a feature — and **error is bwrap's**, naming neither sandbox own `PATH` nor profile that would grant binary, for most ordinary mistake in tool.

### 4.2 Authoring and granting are two acts, and `main` already gets this wrong

`HOME` assigned unconditionally in `Resolve` while directory it name created by `@home`; `SHELL` and `PATH` name things `@sys` grant:

```
snug --dry-run --no-defaults -p @parent-ro . -- true

  HOME=/home/michal                     ← no @home: does not exist
  SHELL=/usr/bin/bash                   ← no @sys:  does not exist
  PATH=/usr/bin:/bin:/usr/sbin:/sbin    ← no @sys:  none of the four exist
```

Not a hole — twenty-minutes-of-confusion class. But **three existing
violations**, not hypothetical.

**The repair is to MARK them, not to stop authoring them.** An earlier draft
concluded the opposite — author only what the profile grants — and that converts
a confusion bug into a reachable hole, because §4.3 shows `PATH` has no safe
absent state: leave it unset and bash substitutes a compiled-in default ending in
`.`, which is the target. Same for `HOME`, which is where the identity generator
writes `~/.gitconfig`, `~/.ssh/config` and `known_hosts` — a profile able to move
it would silently defeat identity pinning.

So snug keeps authoring `HOME`, `PATH` and `SHELL` unconditionally (§1.1), and
`--dry-run` flags any authored value whose path nothing grants. That is
invariant 5's shape — say it rather than degrade silently — and it leaves the
"every path must be granted" rule where it belongs: on *profiles*, which have no
such floor to protect.

### 4.3 An empty element is not nothing

```
env -i PATH="/usr/bin:"      sh -c 'victim'  →  PWD-BINARY-RAN
env -i PATH="/usr/bin::/bin" sh -c 'victim'  →  PWD-BINARY-RAN
env -i PATH="/usr/bin:/bin"  sh -c 'victim'  →  command not found
env -i PATH="/usr/bin:" /usr/bin/env victim  →  PWD-BINARY-RAN   ← execvp(3), not the shell
```

Empty element in `PATH` = current directory — in snug, target. Naive sanitiser = string replace: `/usr/bin:/hostonly/bin` → `/usr/bin:`. *A feature sold as tightening the environment would let a hostile process drop a file named `git` in the project root and have it run.* Hence §2.2.

No safe *absent* state either. For `execvp` unset = floor, empty = CWD; for **bash** unset worse — substitute compiled-in default:

```
env -i bash --noprofile --norc -c 'echo "${PATH-UNSET}"'
  /usr/local/bin:/usr/bin:/bin:.        ← DEFAULT_PATH_VALUE, and it ends in "."
```

So `PATH` must always be authored, never merely omitted.

### 4.4 `forbiddenEnv` fires conditionally, and is both too wide and too narrow

Refusal sit *inside* "is it set on the host" guard, so profile carrying `env = ["LD_PRELOAD"]` **accepted** where host has it unset, refused where set. Not a leak — value never reach sandbox — but same profile pass review on one machine, fail on another.

Measured against type table, list wrong in both directions. `PYTHONSTARTUP` in it and does **not** fire for non-interactive interpreter; `PYTHONPATH` **not** in it and fire on every `python3` via `sitecustomize.py`. Missing, each measured to execute: `GIT_EXEC_PATH`, `GIT_CONFIG_PARAMETERS`, the `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` family, `GIT_EXTERNAL_DIFF`, `GIT_EDITOR`/`EDITOR`/`VISUAL`, `LESSOPEN`, `PYTHONBREAKPOINT`, `BASH_FUNC_*`. Missing on glibc's own authority — `ld.so(8)` strip exactly these under secure execution, closest thing to authoritative denylist: `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `RESOLV_HOST_CONF`, `RES_OPTIONS`, `TZDIR`, `MALLOC_TRACE`, `GETCONF_DIR`, `NIS_PATH`.

Four of these = name **prefixes**, which `map[string]bool` cannot express.

### 4.5 Out of scope but found here: the environment outranks the file

CLAUDE.md's "generate, don't bind" rule pin a tool's config **file** and leave its **environment** — higher-precedence source:

```
env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_PARAMETERS="'user.name'='StillInjected'" git config --get user.name
  StillInjected

env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=AlsoInjected \
       git config --get user.name
  AlsoInjected
```

*A hostile process inside the sandbox can set `GIT_CONFIG_KEY_0=core.sshCommand` and have the next `git fetch` — including one an unsuspecting user or agent runs — execute its command, with `GIT_CONFIG_GLOBAL` pointing at a perfectly clean generated file.* Not a break in sandbox boundary; payload already run code. Break in **identity pinning** — the guarantee `GIT_CONFIG_GLOBAL` exist to make. Same shape by documentation for npm (`npm_config_*` outrank `.npmrc`) and pip (`PIP_*` outrank the file).

**Want own investigation and own fix.** Recorded here because found here.

---

## 5. Sidenote — what was considered and rejected

Short on purpose. Reopen one only with a reason.

**Prior art.** makeWrapper (`--set` / `--prefix ENV SEP VAL` / `--unset`, argv order, imperative). systemd (`Environment=` / `PassEnvironment=` / `UnsetEnvironment=`, later wins). flatpak (`[Environment]`, empty value means unset). Environment Modules and Lmod (`prepend-path` with optional **priority** plus reference counting for unload). NixOS modules (`mkDefault`/`mkForce` = override priority 1000/50, `mkBefore`/`mkAfter` = order rank 500/1500). Nickel (symmetric merge, numeric priorities). CUE (unification = greatest lower bound; commutative, associative, idempotent; **conflict is an error, no override**). Kubernetes (`env`/`envFrom`, last wins).

Two conclusions shaped format. **Every system offering `prepend` give up commutativity and buy it back with a number** — Lmod need both priority argument and reference counting, own docs admit it "does not remember which module inserted which directory where". And **everyone except CUE and Kubernetes ship subtraction** — `--unset`, `UnsetEnvironment=`, `--unset-env`, `remove-path`, `mkForce` — so borrowing a vocabulary by analogy import the thing invariant 1 exist to prevent. Read any proposal asking "what is the `unset` here?"; answer must be *there isn't one*.

makeWrapper also only one putting separator in the signature (`--prefix ENV SEP VAL`) — §3.1's requirement already paid for by someone else.

**Rejected approaches.**

- *Sort and hope* — today's behaviour. Commutative and meaningless (§4.1).
- *A priority number* (`rank = 100`) — honest, familiar, and it is the priority
  field invariant 1 was written against. Ties put you back where you started.
- *Declared shadowing* (`shadows = ["podman"]`) — conflict detected by comparing
  directory **contents**. Need filesystem read, so `internal/policy` stop being
  pure, and stay *partial* because `/run/snug/bin/podman` not exist at resolve
  time. "One prepend across the set" get same guarantee from declarations alone.
- *Order from structure* — mounts need no priority because depth decide; nothing
  in a search path play that role. Provenance class give a *band* — the
  `prepend` / `merge` / base ordering — but not a total order.
- *Parameterised profiles as the ordering mechanism* —
  `PARAMETERISED-PROFILES.md` make each contribution a distinct set member so
  "the union falls out of set membership". Solve membership, not order.
- *An expression language* (Dhall, CUE, Nickel, Starlark, KCL, Pkl) — **the one
  worth understanding.** TOML with `DisallowUnknownFields` load-bearing because
  unknown key = fatal parse error, so negation key cannot be smuggled in. That
  guarantee **syntactic** — checked by listing keys. Expression language move it
  to **semantics**: nothing need a `deny` key when a profile can write
  `filter (λd → d != "/usr/bin") host.PATH`. Subtraction stop being a key you
  forgot to forbid and become a function composed from safe primitives, and
  invariant 1 would have to be re-proved against a language on every release of
  a dependency. CUE closest fit and still fail: its unification *is* the lattice
  this format want, but it is a full language with imports, and invariant 3 say
  trusted profile set come from outside the sandboxed material. **Borrow CUE's
  semantics; do not take the dependency.**

---

## 6. Open

- **The `env` key has to go.** `environ.inherit` take its meaning, so existing
  profiles with `env = [...]` break. Make it a named error pointing at the
  replacement, in shape of the retired `@null`. Keeping prefix `environ` rather
  than reusing `env` deliberate: a silently *changed* meaning worse than a
  removed key.
- **Is `environ.append` needed?** Nothing has asked. Leaving it out keep exactly
  one ordered operation — what make "at most one across the set" easy to state
  and check. Adding it mean answering whether prepend and append coexist (they
  do — different ends) and whether two appends conflict (yes, same argument).
- ~~Is `environ.inherit` a preference or a grant?~~ **Settled: a grant, so it
  stays in a profile.** An earlier draft moved it to `config.toml` and argued
  CLAUDE.md's "config holds preferences, never grants" should be amended. Wrong
  direction — see §1.2. Config keeps `defaults` and `prompt`, which really are
  preferences.
- **`path` must be retired alongside `env`.** `path = [...]` does exactly what
  `environ.merge` on `PATH` would, and `@claude` uses it today. Shipping both is
  two mechanisms for one idea — what the `default`-profile decision exists to
  prevent. Same named-error treatment.
- **`XDG_RUNTIME_DIR`** need an owner — whichever profile create a directory
  meeting the spec's obligations.
- §4.5 untouched by any of this.

## Tests this needs

- `resolve([a,b]) == resolve([b,a])` for the environment.
  `TestResolveIsCommutative` already cover `Env` via `canon()`; extend to new
  verbs.
- Second `prepend` refused, **with a positive control** — one that resolves — so
  refusal cannot pass on a resolver that refuse everything.
- **§4.3 as named regression test**: sanitise a `PATH` to one surviving element
  and assert no empty element, with positive control that a planted binary in
  the target *is* found when an empty element present. This the one place where
  getting it wrong add a hole rather than fail to close one.
- **§4.1's payload-name resolution**: binary only on host `PATH` must not run;
  one in a profile's directory must; name in both resolve to the profile's.
- `--dry-run` render §2.4, and golden file changes.
- `redteam` on `environ.set`, only genuinely new power here.

## Sources

- [makeWrapper](https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/setup-hooks/make-wrapper.sh) ·
  [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) ·
  [flatpak-run(1)](https://www.man7.org/linux/man-pages/man1/flatpak-run.1.html) ·
  [Lmod ref counting](https://lmod.readthedocs.io/en/latest/077_ref_counting.html) ·
  [NixOS properties](https://nixos.wiki/wiki/NixOS:Properties) ·
  [Nickel merging](https://nickel-lang.org/user-manual/merging/) ·
  [CUE spec](https://cuelang.org/docs/reference/spec/)
- [POSIX ch. 8, environment variables](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap08.html) ·
  [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html) ·
  [XDG Base Directory Specification](http://specifications.freedesktop.org/basedir/latest/) ·
  [Bash variables](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)