# BRAINSTORM — what a profile may say about the environment

**Status: exploration, with the syntax decided in shape — see §11.** Filed so the
reasoning is not re-derived later, in the shape of `PARAMETERISED-PROFILES.md`,
which this document leans on in §4.

**§11 is the part to read if you are implementing.** §1–§10 are the argument and
the measurements that constrain it; §11 is the proposed syntax, its errors, and
what it costs.

Everything measured is marked, and every measurement was executed **against
`main`** (`408e8e4`), not against a branch. That matters here more than usual: an
earlier draft measured an unmerged branch and reported a defect that does not
exist on `main`. §2 is what survived checking it, and it is more useful than the
bug report was.

This exists because a reviewer asked a question with no good answer:

> Do I understand that `[profile.stubs]` will be hardcoded, so a similar
> capability (insert new value to some variable) won't be available for
> user-defined profiles at all? … I need a brainstorming what kind(s) of
> operations snug can support.

The literal answer is "mostly, and inconsistently". The interesting part is
*why*, which is not syntax — snug has already committed to an algebra, and the
operation everyone reaches for does not fit in it.

---

## 1. What is true on `main`, measured

**(a) `path` already works for user-written profiles.** Not a builtin privilege,
and it prepends. Two profiles in `$XDG_CONFIG_HOME/snug/profiles.d`, selected in
both orders:

```
snug -p zzz -p aaa . -- sh -c 'echo $PATH'
  /aaa/bin:/zzz/bin:/usr/bin:/bin:/usr/sbin:/sbin
snug -p aaa -p zzz . -- sh -c 'echo $PATH'
  /aaa/bin:/zzz/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

Selection order does not change the result — resolution is commutative, as
invariant 1 requires. **But look at what bought that: the entries came out
alphabetically.** `aaa` before `zzz` is `sortedKeys` over a `map[string]bool`,
not a decision anyone made about search precedence. A profile author who cares
which of their two directories wins has no way to say so, and no way to find out
they have no way.

**(b) `/run/snug/bin` is a Go constant, gated in Go.** `Resolve` appends
`PodmanStubDir` after the sorted set when **both** `p.Podman != PodmanOff` **and**
`ctx.HostShims` contains a detected `podman` shim (`resolve.go:305-322`; the
second half has its own test). On a host where podman is a real binary rather
than a distrobox shim, `/run/snug/bin` never appears at all. So the *mechanism*
generalises — any profile may
prepend a directory — while the one instance snug ships does not use it. The
reason is not that builtins are special: the required order is *profile entries,
then snug's, then base*, and `path` cannot express it, because `path` entries are
sorted among themselves and snug's directory would land alphabetically among a
user's.

**(c) No variable other than `PATH` can be modified by anything.** `env` is
passthrough *by name only* — `env = ["FOO"]` copies the host's `FOO`. There is no
`set`, no `prepend`, no `append`, for `PATH` or anything else. A profile wanting
`PYTHONPATH`, `MANPATH`, `PKG_CONFIG_PATH`, `XDG_DATA_DIRS`, `GOFLAGS` or
`CARGO_HOME` has no key to write.

**(d) Thirteen variables, no XDG variable among them.**

```
snug <dir> -- env
HOME LANG LOGNAME PATH PS1 PWD SHELL SNUG SNUG_PROFILES SNUG_TARGET TERM TMPDIR USER

snug <dir> -- sh -c 'env | grep -c XDG'   →  0
```

Not authoring a variable is not neutral — it is inheriting a default. A tool
following the XDG spec computes `$HOME/.config` when `XDG_CONFIG_HOME` is unset,
which lands inside the sandbox only because `$HOME` happens to be a tmpfs at the
host path. `XDG_RUNTIME_DIR` is the sharp one: the spec gives it **no** fallback,
and podman, gnupg, systemd and pipewire all misbehave without it.

**(e) `forbiddenEnv` is a gate that fires conditionally on host state.** Live on
`main`, and it belongs here because it is the same family of problem:

```go
for _, e := range prof.Env {
    if v := env.Getenv(e); v != "" {
        if forbiddenEnv[e] { return nil, fmt.Errorf(...) }
        p.Env[e] = v
    }
}
```

The refusal sits *inside* the "is it set on the host" guard, so a profile
carrying `env = ["LD_PRELOAD"]` is **accepted** on a host where the variable
happens to be unset and refused on one where it is set. The value never reaches
the sandbox either way, so this is not a leak; what it breaks is determinism of
validation — the same profile passes review on one machine and fails on another.
CLAUDE.md already has the rule this violates (*a gate that is documented but not
implemented is not a gate*) in a third spelling: a gate that is implemented and
fires on state it does not control.

**(f) `snug . -- podman` resolves `podman` against the SANDBOX's `PATH`, not the
host's — and nothing tests it.** This is a precondition for everything below: if
the payload's own name were resolved on the host side, every ordering question in
this document would be moot, `shadows` could not work, and the podman stub would
be decoration. It holds. bwrap `--clearenv`s, sets `PATH` with `--setenv`, and
then `execvp`s *inside* the namespaces with its own modified environ, so the
lookup happens inside. Measured four ways:

```
# 1. a binary on the HOST's PATH, in a directory no profile grants
PATH=/…/hostonly:$PATH  snug . -- hostmarker
  bwrap: execvp hostmarker: No such file or directory        ← host PATH contributes nothing

# 2. the same binary by absolute path, under a directory @parent-ro DOES grant
PATH=/…/hostonly:$PATH  snug . -- /…/hostonly/hostmarker
  HOSTONLY-RAN                                                ← the grant, working as documented

# 2b. an absolute path outside every grant
snug . -- /…/outside/outmarker
  bwrap: execvp /…/outside/outmarker: No such file or directory

# 3. SHADOWING: a fake `ls` in a profile's `path` directory, against /usr/bin/ls
snug -p tbin . -- ls
  SANDBOX-LS-RAN                                              ← sandbox PATH ORDER governs
```

Case 3 is the decisive one — it is `shadows` (§7C) already working, unnamed and
undeclared. Case 2 is worth keeping in the record because it looks like a leak
and is not: `@parent-ro` grants the target's parent read-only, the binary lived
under it, and `touch` in the same directory returns `Read-only file system`.

Two gaps follow.

*No test covers any of it.* There is no assertion anywhere that the payload name
is resolved inside, and it is exactly the kind of property that would survive a
refactor to `exec.LookPath` on the host side with every existing test still
green — a host-side lookup would make case 1 *succeed*, which reads like a
feature. This is the "test the negative" rule with nothing behind it.

*The error is bwrap's, and it does not name the fix.* `bwrap: execvp podman: No
such file or directory` is what a user gets for the most ordinary mistake there
is — asking for a command no profile granted. It says nothing about the sandbox
having its own `PATH`, nothing about which profile would grant the binary, and it
carries bwrap's name rather than snug's. "Errors name the fix" is a working
agreement rule, and this is the highest-traffic error in the tool.

---

## 2. The trap: authoring a variable and granting the directory are two acts

*Measured on an unmerged branch, recorded here because the lesson outlives the
branch.*

A branch that authored the five XDG variables from `{home}` did so
unconditionally in `Resolve`, while the directories they name are created by the
`@home` profile's `tmpfs` list. Select a set without `@home` and the variables
survive, naming nothing:

```
snug --no-defaults -p @sys -p @parent-ro . -- ...

SNUG_PROFILES=@parent-ro,@sys
HOME=/home/michal                        ls: No such file or directory
XDG_CONFIG_HOME=/home/michal/.config     ls: No such file or directory
XDG_DATA_HOME=/home/michal/.local/share  ls: No such file or directory
```

**An earlier draft said "this is not a defect on `main`", and that was wrong.**
`main` authors no XDG variable, which is true and is not the point: the *pattern*
is already instantiated three times on `main`, and it already dangles. `HOME` is
assigned unconditionally at `resolve.go:396` while the directory it names is
created by `@home`'s `tmpfs`; `SHELL` and `PATH` name things `@sys` grants.
Measured on `main`:

```
snug --dry-run --no-defaults -p @parent-ro . -- true

ENVIRONMENT  (--clearenv, then:)
  HOME=/home/michal                     ← no @home: does not exist
  SHELL=/usr/bin/bash                   ← no @sys: does not exist
  PATH=/usr/bin:/bin:/usr/sbin:/sbin    ← no @sys: none of the four exist
  TMPDIR=/tmp                           ← fine; snug's own tmpfs
```

So this is not a forward-looking warning, it is **an existing violation with
three instances**, and the XDG work would be the fourth. That also upgrades §9's
checklist item — "select a set without `@home` and assert the variables are
absent, not dangling" is a test that **fails on `main` today**, which makes it a
repair rather than a nicety.

The reviewer's own framing is the fix:

> the variable is implicit for a profile — e.g. `@home` means `XDG_…` are
> authored

Not a stylistic preference. Binding the authorship to the grant that creates the
directory makes the broken selection above **impossible to express** rather than
merely detectable. A validation pass checking authored paths against the resolved
mounts would *catch* it; putting `authors` next to `tmpfs` in `@home` means there
is nothing to catch.

It generalises past XDG. `SSH_AUTH_SOCK` is authored by the identity machinery
that creates the proxy socket; `CONTAINER_HOST` by the container machinery that
creates the socket; `GIT_CONFIG_GLOBAL` by the generator that writes the file.
**Every authored variable is downstream of a grant, and today none of them says
so.** Any candidate in §7 that does not make that link is solving the smaller
half.

---

## 3. Variables have types, and the type decides which algebra applies

*The reviewer's second note, and it reorganises the whole problem:*

> some env variables are scalars and some are lists — while technically strings.
> And some (like PS1) are semi-structured.

Everything in the environment is a `char*`. That is the only thing they have in
common, and treating `map[string]string` as one concept is what makes this area
confusing. There are three types, and **each one has a different join**:

| type | examples | join | ordered? |
|---|---|---|---|
| **scalar** | `HOME`, `LANG`, `TERM`, `USER`, `SHELL`, `TMPDIR`, `GIT_CONFIG_GLOBAL`, `SSH_AUTH_SOCK` | equal, or it is a **conflict** | no |
| **list** | `PATH`, `MANPATH`, `PYTHONPATH`, `PKG_CONFIG_PATH`, `XDG_DATA_DIRS`, `XDG_CONFIG_DIRS`, `LD_LIBRARY_PATH`, `CLASSPATH`, `INFOPATH` | concatenate, with an order problem | **yes** |
| **semi-structured** | `PS1`–`PS4`, `PROMPT_COMMAND`, `LS_COLORS`, `TERMCAP`, `DBUS_SESSION_BUS_ADDRESS`, `GIT_CONFIG_PARAMETERS` | **none — it does not have one** | n/a |

Five consequences, and together they are worth more than any single candidate
below.

**(a) The ordering problem is confined to exactly one type.** Scalars have no
order to get wrong: two profiles setting `LANG` either agree or conflict, and
CUE-style "conflict is an error" resolves it with no priority field and no
sorting. So §4's entire discussion — ranks, bands, shadowing — applies to the
list type and nothing else. That directly answers what was previously an open
question: *is there any variable other than `PATH`-likes that needs ordering?*
No, **by type**.

**(b) Semi-structured variables cannot be merged at all, and that is why the
forbidden list looks the way it does.** `PS1` is a template language with
escapes; bash performs command substitution on prompt strings (`promptvars`, on
by default), so `PS4='$(cmd)+ '` *executes* `cmd`. `PROMPT_COMMAND` is a command
bash runs before every prompt. `LS_COLORS` is `key=value` pairs that happen to be
`:`-separated — which means **naive list handling would "merge" it and produce
garbage**, or worse, silently split a value containing a colon.

**A tempting overstatement, and it is wrong: `forbiddenEnv` is not this rule.**
An earlier draft claimed the list was "a type judgement in disguise". Checked
against `main` (`resolve.go:492`) it is `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`LD_AUDIT`, `BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND`,
`NODE_OPTIONS` — **not one** semi-structured name among them, while
`LD_LIBRARY_PATH` is in it and is a *list*. Measured with a profile carrying
`env = ["PROMPT_COMMAND","LS_COLORS","GIT_CONFIG_PARAMETERS"]`:

```
GIT_CONFIG_PARAMETERS='core.pager=id'
LS_COLORS=di=01;34
PROMPT_COMMAND=echo PWNED-PROMPT
exit=0                                  ← all three pass through, unrefused
```

The two rules are **orthogonal, and both are needed**:

- *`forbiddenEnv` is about what the value DOES.* Code injection, at any type.
  That is what its doc comment says and what §7F says later; it is why
  `LD_LIBRARY_PATH` belongs there and why merging the rules would argue for
  removing it.
- *Semi-structured values have no join.* A type fact, and a **separate, currently
  unenforced** one. Nothing on `main` stops `PROMPT_COMMAND` passing through, and
  the type argument is what says it should be stopped.

Merging them would have produced two wrong recommendations at once: add `PS1`
(which snug authors and must keep authoring) and drop `LD_LIBRARY_PATH` (which is
genuinely dangerous). Keep them apart.

**(c) The separator is per-variable and must be declared, not assumed.** `:` is
the Unix norm, `CLASSPATH` uses `;` on Windows, and some tools take
space-separated lists. `makeWrapper` gets this right and it is the reason its
signature is `--prefix ENV SEP VAL` rather than `--prefix ENV VAL`. Any list key
snug adds needs the separator in the type, not in the parser.

**(d) An empty element is not nothing, and in `PATH` it is the current
directory.** Measured:

```
env -i PATH="/usr/bin:"      sh -c 'victim'   →  PWD-BINARY-RAN
env -i PATH="/usr/bin::/bin" sh -c 'victim'   →  PWD-BINARY-RAN
env -i PATH="/usr/bin:/bin"  sh -c 'victim'   →  sh: victim: command not found
```

**This is a live hazard for the `sanitise` capability, and it must be in its
abuse sentence.** The naive implementation of "drop the elements the policy does
not grant" is a string replace, and `PATH=/usr/bin:/hostonly/bin` becomes
`/usr/bin:` — at which point the shell searches the **current working
directory**, which in snug is the target: the one place a hostile payload has
full write access. A feature sold as *tightening* the environment would create a
code-execution vector that did not previously exist. *A hostile process inside
the sandbox can drop a file named `git` in the project root and have it run.*

The rule that follows: **sanitising rebuilds the list from surviving elements; it
never edits the string.** And if nothing survives, **unset** rather than empty —
an empty `LD_LIBRARY_PATH` is not the same thing as an absent one to a dynamic
loader, and an empty `PATH` is not the same thing as an absent one to `execvp`.
Empty elements also carry *different* meanings per variable — in `MANPATH` an
empty element means "splice in the system default" — which is another argument
for (c): the type must carry the semantics, not the code that happens to touch it.

**(e) The type is orthogonal to the class.** The three classes — authored,
passthrough, sanitised — cross the three types, and **not all nine cells are
legal**:

| | scalar | list | semi-structured |
|---|---|---|---|
| **authored** | yes | yes | yes — the only legal cell for this type (`PS1`) |
| **passthrough** | yes | risky: inherits host paths wholesale | **never** — grammar the host controls, executed inside |
| **sanitised** | **yes — the degenerate case, and the most useful one** | **the capability being asked for** | **never** |

A table with holes in it is a better specification than prose, because the holes
are the design. Note that the illegal cells are **not** the ones `forbiddenEnv`
refuses — see §3(b); this table and that list are two different rules, and a
value needs to clear both.

**The scalar/sanitised cell deserves its own sentence, because calling it
"meaningless — nothing to filter" was a mistake an earlier draft made and §8
inherited.** A scalar is the one-element list, and filtering it is exactly the
*points-inside* check: inherit the host's `SSH_AUTH_SOCK`, `CARGO_HOME`,
`DOCKER_HOST` or `GIT_CONFIG_GLOBAL`, keep it iff it names something the policy
grants, otherwise **unset**. That is the same criterion §7F uses to scope
`sanitise` — danger is *pointing outside*, not *what it does* — and it is the
operation that repairs §2's three live instances. Excluding it would have put the
one class of variable with a measured dangling-path problem outside the scope of
the one new capability being proposed.

---

## 3a. Reference taxonomy — the variables that matter, by type

*Companion to §3. §3 argues the type decides the algebra; this is the type table.
Measured on this host (bash 5.3.15, glibc 2.43, Python 3.13.14, perl 5.44.0, node
26.4.0, go 1.26.5, git 2.55.0, man-db 2.13.1) unless marked **unverified**.*

Operations: **author** (snug writes it from policy), **pass** (copy the host's),
**sanitise** (inherit, rebuild from granted elements), **±** (prepend/append).

### 3a.1 There are three states, not two — and for `PATH` none of them is safe

*unset*, *set to empty*, *set with an empty element*, *set*. Not interchangeable,
and the mapping differs per variable. §3(d) ended "unset rather than empty". That
is **half right**, and the other half inverts:

```
env -i PATH="" ./execvp_probe   →  PWD-BINARY-RAN        # empty = the CWD
env -i         ./execvp_probe   →  rc=7                  # unset = confstr(_CS_PATH)

env -i /bin/bash --noprofile --norc -c 'echo "${PATH-UNSET}"'
  /usr/local/bin:/usr/bin:/bin:.                          # ← bash's compiled-in default
env -i /bin/bash --noprofile --norc -c 'command -v victim'
  ./victim
```

For `execvp` unset is the safe floor and empty is the CWD. For **bash** unset is
*worse*, because it substitutes `DEFAULT_PATH_VALUE`, which on this distro build
ends in `.`. So **`PATH` has no safe absent state at all** — it must always be
authored, and `sanitise` must be unable to produce either degenerate value.

### 3a.2 Lists — search paths

"→ CWD" means the empty element resolves to the current directory, which inside
snug is the target: the writable thing a hostile payload controls.

| variable | sep | empty element | author | pass | sanitise | note |
|---|---|---|---|---|---|---|
| `PATH` | `:` | **→ CWD** (POSIX: a zero-length prefix indicates the cwd) | ✓ | ✗ | ⚠ rebuild only | no safe absent state |
| `LD_LIBRARY_PATH` | **`:` or `;`** | **→ CWD** | ⚠ | ✗ | ✗ | `ld.so(8)`: two separators, **no escaping** |
| `LD_PRELOAD` | **`:` or space** | n/a | ✗ | ✗ | ✗ | a path with a space is inexpressible |
| `MANPATH` | `:` | **an OPERATOR** — leading = prepend system path, trailing = append, `::` = insert here | ✓ | ✗ | **✗** | see below |
| `INFOPATH` | `:` | trailing only = system default | ✓ | ✗ | ⚠ | **unverified** |
| `CDPATH` | `:` | **→ CWD, positionally** | ⚠ | ✗ | ✗ | affects every `cd sub` |
| `PKG_CONFIG_PATH` | `:` | **ignored** | ✓ | ✗ | ✓ | cleanest in the set |
| `PYTHONPATH` | `:` | **→ CWD** | ⚠ | **✗** | ✗ | **also an exec vector — §3a.4** |
| `PERL5LIB` | `:` | **ignored** | ✓ | ✗ | ✓ | shadowing only |
| `NODE_PATH` | `:` | **ignored** | ✓ | ✗ | ✓ | shadowing only |
| `CLASSPATH` | `:` / `;` | **unverified** | ✓ | ✗ | ⚠ | unset = CWD; the platform separator §3(c) names |
| `GOPATH` | `:` | element 0 is privileged; empty first ⇒ empty `GOMODCACHE` | ✓ | ✗ | ⚠ | relative entry is a hard error |
| `TERMINFO_DIRS` | `:` | = the system location | ✓ | ✗ | ⚠ | partially verified |
| `GOFLAGS` | **space** | n/a | ✓ | ✗ | ✗ | a flag list, not a path list |

**`MANPATH` cannot be sanitised at all, and it is the sharpest case.** An empty
element is not a path, it is an instruction — so *removing* an element can *add*
directories. man-db announces the choice:

```
env -i MANPATH=/a    manpath  →  ignoring /etc/manpath.config      → /a
env -i MANPATH=:/a   manpath  →  prepending /etc/manpath.config    → /usr/share/man:/a
env -i MANPATH=/a::/b manpath →  inserting /etc/manpath.config     → /a:/usr/share/man:/b
```

§3(d)'s rule ("rebuild, never edit the string") is necessary but **not
sufficient** here: a rebuild that emits an empty element for a dropped entry has
the identical effect.

### 3a.3 XDG — five scalars and two lists, and the spec is unusually specific

| variable | type | default when not set **or empty** |
|---|---|---|
| `XDG_DATA_HOME` / `XDG_CONFIG_HOME` / `XDG_STATE_HOME` / `XDG_CACHE_HOME` | scalar path | `$HOME/.local/share`, `.config`, `.local/state`, `.cache` |
| `XDG_RUNTIME_DIR` | scalar path | **no default value** |
| `XDG_DATA_DIRS` | **list**, `:` | `/usr/local/share/:/usr/share/` |
| `XDG_CONFIG_DIRS` | **list**, `:` | `/etc/xdg` |

Three things the spec settles that code would otherwise guess. **Empty is unset**
— so unlike `PATH`, XDG variables have a genuine no-op value. **Relative paths
must be ignored**, which makes these the only two lists here where the naive
sanitiser is safe *by specification*. And **`XDG_RUNTIME_DIR` carries obligations**
— owned by the user, mode 0700, lifetime bound to the session — so authoring it
*is* a grant, which is exactly §2's point. One correction to §1(d): the spec does
give a fallback ("a replacement directory with similar capabilities and print a
warning"); what it lacks is a *default value*.

### 3a.4 Semi-structured, and the naive classification that would bite

| variable | looks like | actually is |
|---|---|---|
| `PS0`–`PS4` | a string | a template language; `promptvars` is on by default, so it performs **command substitution** |
| `PROMPT_COMMAND` | a command | may be an **array** in bash ≥5.1; only the scalar form crosses the environment |
| `LS_COLORS` | a `:`-list | `key=value` pairs whose **values contain `;`** — the character that is a *separator* in `LD_LIBRARY_PATH` |
| `DBUS_SESSION_BUS_ADDRESS` | a `:`-list | **`;`**-separated addresses, each `transport:` + **`,`**-separated `key=value`, percent-encoded |
| `GIT_CONFIG_PARAMETERS` | a string | space-separated sq-quoted `'key'='value'` pairs |
| `BASH_FUNC_*` | nothing — a **name pattern** | exported shell functions. **Function lookup precedes `PATH` entirely**, so this defeats every ordering question in §4 |
| `IFS` | a list | a *set* of delimiter characters. bash and `sh` discard an inherited one — but `system(3)` does not |

### 3a.5 Two structural findings, and they outrank every row above

**(a) The environment outranks the file, so "generate, don't bind" does not close
the channel it claims to.** CLAUDE.md's rule points a tool at a generated config
with that tool's own variable. Measured — that pins the **file** and leaves the
**environment**, which is a higher-precedence config source:

```
env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_PARAMETERS="'user.name'='StillInjected'" git config --get user.name
  StillInjected

env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=AlsoInjected \
       git config --get user.name
  AlsoInjected
```

*A hostile process inside the sandbox can set `GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0=core.sshCommand` and have the next `git fetch` — including one an
unsuspecting user or agent runs — execute its command, while `GIT_CONFIG_GLOBAL`
points at a perfectly clean generated file.* This is not a break in the sandbox
boundary; the payload already runs code. It is a break in **identity pinning**,
which is the guarantee `GIT_CONFIG_GLOBAL` was introduced to make. The same shape
holds by documentation for npm (`npm_config_*` outranks `.npmrc`) and pip
(`PIP_*` outranks the file — though `PIP_CONFIG_FILE=/dev/null` is a documented
off switch). **This deserves its own investigation and probably its own fix; it is
outside the scope of the environment language and is recorded here because this is
where it was found.**

**(b) Four vectors are name PREFIXES, not names.** `BASH_FUNC_*`,
`GIT_CONFIG_KEY_n`/`VALUE_n`, `npm_config_*` (case-insensitive), `PIP_*`.
`forbiddenEnv` is a `map[string]bool` and cannot express any of them.

### 3a.6 What this says about `forbiddenEnv`

Measured against the table, today's list is **both too wide and too narrow**, in
an instructive way: `PYTHONSTARTUP` is in it and does **not** fire for a
non-interactive interpreter, while `PYTHONPATH` is **not** in it and fires on
every `python3` via `sitecustomize.py` (measured: `SITECUSTOMIZE-INJECTED`). The
list was assembled from names that sound dangerous rather than from measurements.

Missing, each measured to execute: `GIT_EXEC_PATH`, `GIT_CONFIG_PARAMETERS`, the
`GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` family, `GIT_EXTERNAL_DIFF`,
`GIT_EDITOR`/`EDITOR`/`VISUAL`, `LESSOPEN`, `PYTHONPATH`, `PYTHONBREAKPOINT`,
`BASH_FUNC_*`. Missing on glibc's own authority — `ld.so(8)` strips exactly these
under secure execution, which is the closest thing to an authoritative denylist
and should seed ours: `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`,
`RESOLV_HOST_CONF`, `RES_OPTIONS`, `TZDIR`, `MALLOC_TRACE`, `GETCONF_DIR`,
`NIS_PATH`.

**And the discriminator for `sanitise` is not the type — it is the empty-element
column.** Sanitise is safe where an empty element is *ignored*
(`PKG_CONFIG_PATH`, `PERL5LIB`, `NODE_PATH`, and by specification the two XDG
lists), hazardous where it means the *CWD* (`PATH`, `LD_LIBRARY_PATH`,
`PYTHONPATH`, `CDPATH`), and **illegal where it is an operator** (`MANPATH`,
`INFOPATH` trailing). A type that carries a `separator` must also carry an
`emptyElement` of that three-way kind, or the sanitiser will be written once and
be wrong for a third of its inputs.

*One more, and it is `TZ`:* it is a grammar with two branches, and when the file
is unreachable glibc silently re-reads the value as an inline rule string.
`TZDIR=/nonexistent TZ=Asia/Tokyo date` gives `+0000 Asia` — every timestamp
wrong, no error on any channel. Authoring `TZ` without granting
`/usr/share/zoneinfo` is a guarantee snug does not keep, which invariant 5 says is
worse than refusing.

---

## 4. The obstacle is an algebra, not a syntax

CLAUDE.md invariant 1: resolution is **commutative, associative and idempotent**.
That is a join-semilattice, and it is what lets a reader select two profiles
without reading either.

**`prepend` is not commutative.** The whole problem, in one line:

```
prepend(a) ∘ prepend(b)  =  [a, b, …]
prepend(b) ∘ prepend(a)  =  [b, a, …]
```

Every ordered list operation has this shape; `append` too. Per §3(a) this applies
to the **list** type only. A language offering `prepend` has left the lattice and
must buy order-independence back. There are five known ways, and snug has already
used the fifth for something else:

1. **Discard the order** — treat the list as a set, impose a canonical order at
   render. §1(a). Commutative and meaningless.
2. **Add a priority number** — order by `(rank, name)`. NixOS `mkOrder`, Lmod's
   optional priority argument. Commutative given a total order on ranks, and it
   re-introduces the priority field invariant 1 was written against.
3. **Make conflict an error** — keep the set, refuse when order would be
   observable. CUE's answer, generalised. §7C.
4. **Derive the order from structure** — as mounts already do. Mount overlap
   needs no priority because *depth* decides: the deepest mount covering a path
   wins. Nothing in `PATH` plays the role depth plays there.
5. **Make each contribution a distinct set member.**
   `PARAMETERISED-PROFILES.md` reaches this for ports: with
   `-p net-publish:3000 -p net-publish:8080`, identity is the canonical name, the
   two are separate members, and *"the union falls out of set membership"*.
   **It solves membership, not order** — a union of ports has no order to get
   wrong, and a search path does. Worth knowing precisely because it is the
   closest precedent and it does not reach.

---

## 5. Prior art

*Researched, not remembered; sources at the end.*

| system | vocabulary | order model | order-independent? | can subtract? |
|---|---|---|---|---|
| **makeWrapper** (Nix) | `--set`, `--set-default`, `--unset`, `--prefix ENV SEP VAL`, `--suffix`, `--prefix-each`, `--prefix-contents`, `--run` | argv order, imperative | no | yes (`--unset`) |
| **systemd.exec** | `Environment=`, `EnvironmentFile=`, `PassEnvironment=`, `UnsetEnvironment=` | later wins; `Environment=` beats `PassEnvironment=` | no | yes |
| **flatpak** | `[Environment] NAME=VALUE`, `--env`, `--unset-env`; empty value means unset | metadata, then CLI | no | yes |
| **Environment Modules / Lmod** | `prepend-path`, `append-path`, `remove-path`, optional **priority** arg, **reference counting** for unload | explicit priority, remembered across modulefiles | with priorities | yes |
| **NixOS modules** | `mkDefault`(1000)/`mkForce`(50); `mkOrder`(1000)/`mkBefore`(500)/`mkAfter`(1500) | two numeric axes: value priority and rank | with numbers | yes (`mkForce`) |
| **Nickel** | symmetric merge `&`; `default` / `force` / numeric priority | priority, else recursive merge | yes | via `force` |
| **CUE** | unification `&` = greatest lower bound on a lattice | none needed | **yes, structurally** | **no** |
| **Kubernetes** | `env`, `envFrom`, `valueFrom` | last wins | no | no |

Five observations worth more than the table.

**Every system that offers `prepend` gives up commutativity and buys it back with
a number.** Lmod is the most sophisticated PATH algebra in production and needed
*two* mechanisms: an optional priority argument, and reference counting so unload
is well-defined. Its own documentation names the limit — with duplicates allowed,
"Lmod does not remember which module inserted which directory where, it just
removes the first or last entry". A system tracking provenance per entry would
not have that problem. **snug already tracks provenance per mount.**

**CUE is the only one that keeps commutativity, and the price is that conflict is
an error rather than a winner.** There is no override in CUE at all. That is
strikingly close to snug's existing posture: no deny rules, no priority fields,
`rejectMasking` refuses rather than resolves. §7C is what happens if you take
that seriously.

**makeWrapper's `--prefix` already dedups** — it removes the first instance of the
value before prepending, and `--suffix` appends only if absent. Even the
imperative systems reach for idempotence once real configurations compose.

**makeWrapper is also the only one that puts the separator in the signature.**
`--prefix ENV SEP VAL`. §3(c) is not a subtlety this document invented; it is a
lesson someone already paid for.

**Everyone except CUE and Kubernetes ships subtraction.** `--unset`,
`UnsetEnvironment=`, `--unset-env`, `remove-path`, `mkForce`. Adopt a vocabulary
by analogy and subtraction arrives with it, and invariant 1 dies quietly in a
footnote. Read every candidate below asking "what is the `unset` here?" — the
answer must be *there isn't one*.

---

## 6. The composite case is the real one

The reviewer's sharpest note:

> the most complex case is a passthrough, yet later modified variables like PATH

`PATH` on `main` already has three contributors, and the one asked for would be a
fourth:

| segment | class | who decides | on `main` |
|---|---|---|---|
| `/aaa/bin` | profile-granted | a profile's `path` key | sorted among itself |
| `/run/snug/bin` | snug-generated | `Resolve`, when `p.Podman != PodmanOff` | appended after the sorted set |
| *(host `PATH`, filtered)* | sanitised | — | **does not exist** |
| `/usr/bin:/bin:/usr/sbin:/sbin` | authored base | `basePATH` | always last |

A three-class model assumes a variable belongs to one class. `PATH` belongs to
three at once, and the missing one is the capability that was asked for. **Any
design modelling a variable as a `string` has already lost** — the classes are
only distinguishable while the value is still a list of segments with provenance,
and §3(d) shows the string representation is where the security bug lives too.

**That is the same shape as `Mounts`, and it is not a coincidence.** A mount
carries `Guest`, `Access`, `From []string`. A path entry wants `Value`, `Class`,
`From`. The renderer joins with the type's separator exactly as `BwrapFlags`
renders mounts into argv, and `--dry-run` shows per-entry provenance the way it
already does for mounts — which is the actual product here.

---

## 7. Candidates

Each shown against the same three cases: `@stubs-in-path` (snug's directory
first), `@home` (authoring the XDG family), and a passthrough list.

### A. Typed slots, no operations — status quo, generalised

One key per known list variable. snug owns the order; the profile owns
membership.

```toml
[profile.stubs-in-path]
description = "snug's wrappers ahead of /usr/bin"
path = ["/run/snug/bin"]

[profile.home]
description = "$HOME is an empty tmpfs at the host path"
tmpfs = ["{home}", "{home}/.config", "{home}/.local/share", …]
xdg   = true                    # author the five XDG names from the tmpfs above
```

Passthrough unchanged: `env = ["ANTHROPIC_API_KEY"]`.

**For:** no new algebra; `path` already works and has a golden test. Ordering
stays a Go decision, where it is reviewable. `xdg = true` sits next to the `tmpfs`
that makes it true, which answers §2 for the one case that matters now.
**Against:** does not scale. `MANPATH`, `PKG_CONFIG_PATH`, `XDG_DATA_DIRS` each
need a new key and a new line in `Resolve`. Answers §1(c) not at all, and §1(b)
only by making the hardcoding official.

### B. Named operations with an explicit rank — the Lmod/NixOS shape

```toml
[profile.stubs-in-path.env.PATH]
prepend = ["/run/snug/bin"]
rank = 100                      # lower is earlier; snug's generated entries sit at 500

[profile.home.env]
XDG_CONFIG_HOME = "{home}/.config"
XDG_DATA_HOME   = "{home}/.local/share"

[profile.claude]
passthrough = ["ANTHROPIC_API_KEY"]
```

**For:** honest, familiar, two production systems use it, and it expresses the one
constraint snug actually needs.
**Against:** `rank` is a priority field. Invariant 1's value is that it has *no*
carve-out — `TestPolicyHasNoRestrictionOperation` works by grepping for a demote
and finding none. A rank is not a demote, but it is the first number in the
language whose only purpose is making one profile beat another, and the distance
to `rank = 0, force = true` is short. And ties: two profiles at rank 100 are back
where we started.

### C. Conflict-as-error, with declared shadowing — the CUE answer

Keep `PATH` a set. Sort it. Then observe that **the order of a search list is only
observable when two entries provide the same name.** If no two directories in
`PATH` contain an executable called `podman`, every ordering is behaviourally
identical, and sorting is not a compromise — it is correct.

So detect collisions, and require any intended shadowing to be *declared*.

```toml
[profile.stubs-in-path]
description = "snug's wrappers ahead of /usr/bin"
path    = ["/run/snug/bin"]
shadows = ["podman"]            # names what it intends to take over

[profile.home]
tmpfs   = ["{home}", "{home}/.config", …]
authors = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", …]

[profile.claude]
passthrough = ["ANTHROPIC_API_KEY"]
```

An undeclared collision is a resolve-time error naming both profiles and the
binary. A declared one sorts to the front deterministically, because `shadows` is
what establishes the order — not a number, but a *statement about the world*,
checkable against it.

**For:** the most snug-shaped idea here. It converts an ordering problem into a
conflict-detection problem, which is what a lattice does. No priority field.
`shadows` doubles as the abuse sentence in machine-checkable form — "this profile
takes over the name `podman`" is exactly what a reader needs and what `--dry-run`
should print. Additive: declaring more never subtracts.
**Against, seriously:** the check must *read directories*, and `internal/policy`
is pure by working agreement — no filesystem, no `exec`. It would go through the
injected `Environ`, widening that interface from "look up a variable" to "list a
directory". Worse, the directories are the ones that will exist *inside* the
sandbox, some of which snug has not created yet at resolve time —
`/run/snug/bin/podman` is `KindData` content. So the check is **partial**. A
partial check stated as partial is still worth having; one believed to be total
is not.

### D. Order from structure, not from number

Mounts need no priority because depth decides. Ask what plays that role for a
search list. Path length is arbitrary. **Provenance class gives a *band*** —
profile-granted, snug-generated, sanitised-host, authored base — and that band is
exactly the order `Resolve` hardcodes today. Real, but four buckets rather than a
total order; within a band you are back to sorting, or to C.

**Not a candidate alone, but the band is the right skeleton.** Combine with C:
bands give the coarse order structurally, `shadows` resolves the only case where
intra-band order is observable.

### E. A full expression language in the profile

Dhall, CUE, Nickel, Starlark, KCL, Pkl. Explicitly allowed by the reviewer —
*"some kinds of a pure functionalish language may be an acceptable price"*.

```dhall
{ name = "stubs-in-path"
, env = λ(host : Env) → host ⫽ { PATH = "/run/snug/bin:${host.PATH}" }
}
```

**Against, and close to disqualifying.** CLAUDE.md records that TOML with
`DisallowUnknownFields()` is *load-bearing*: an unknown key is a fatal parse
error, "so a negation key cannot be smuggled in". That guarantee is **syntactic**
— you check it by listing the keys. **An expression language moves it to
semantics.** Nothing needs a `deny` key when a profile can write
`filter (λ(d : Text) → d != "/usr/bin") host.PATH`. Subtraction stops being a key
you forgot to forbid and becomes a function composed from safe primitives.
Invariant 1 would have to be re-proved against a language rather than a key list,
on every release of a dependency.

Note also that §3 argues the value is *typed*, and the snippet above is exactly
what a language lets you write: string concatenation on `PATH`, which is the
representation §3(d) shows is unsafe to edit. A typed key list makes that
unspellable; an expression language makes it the obvious idiom.

**Where it is defensible:** the config file holding *preferences* — the `defaults`
list — contains no grants, so a language there cannot express a hole. A small
prize for a large dependency.

CUE deserves one more sentence, because it is the closest fit and still fails:
CUE's unification *is* snug's lattice, and if profiles were CUE the commutativity
property would come for free and be **proved** rather than tested. But CUE is a
full language with imports, and invariant 3 says the trusted profile set comes
from outside the sandboxed material — an import graph is a new way for that
boundary to move. Borrowing CUE's *semantics* (C) is cheap; adopting CUE the
*implementation* is not.

### F. Keys by class, values by type

```toml
[profile.home]
tmpfs   = ["{home}", "{home}/.config", …]
authors = { XDG_CONFIG_HOME = "{home}/.config", XDG_DATA_HOME = "{home}/.local/share" }

[profile.claude]
passthrough = ["ANTHROPIC_API_KEY"]

[profile.toolchain]
sanitise = ["MANPATH"]          # inherit host value, keep only granted elements
```

`authors` is a map; `passthrough` and `sanitise` are sets. **Nothing here is
ordered, so the lattice survives untouched** — and `PATH` stays the one ordered
key, governed by C. The §3(e) table is the validation rule: `sanitise` accepts
only list-typed names, `passthrough` refuses semi-structured ones, and snug owns
the type of every name it knows.

The sanitise rule, stated once and following §3(d): split on the **type's**
separator; keep an element iff the resolved policy grants it at any access;
**rebuild** the list from survivors rather than editing the string; report in
`--dry-run` how many were dropped and why; if nothing survives, **unset** rather
than set empty.

**For:** each key does one thing. `authors` next to `tmpfs` is the §2 fix,
structural rather than checked. `sanitise` is the asked-for capability.

**Against, and these are the two that would break an invariant if missed.**

*`passthrough` and `sanitise` over the same name is subtraction between
profiles.* Profile A says `passthrough = ["MANPATH"]`; profile B says
`sanitise = ["MANPATH"]`. Selecting B **removes elements A's grant put in the
sandbox** — invariant 1, structurally, with no `deny` key anywhere. This is not
the ergonomics question §10 once framed it as. Three ways out, and only the first
two are acceptable: make the pair a **resolve-time conflict**, CUE-style and
consistent with §7C; or make them one key. (The third — `sanitise` loses to
`passthrough` by join — is monotone but leaves `sanitise` unable to do its job
whenever anyone else asks for the name.)

*`authors` needs a reserved namespace, and it is the FIRST guard, not the third.*
The obvious guards — the `forbiddenEnv` name refusal and a points-inside check —
miss the sharp case: `authors = { PATH = "/evil" }` subtracts `basePATH` and every
other profile's `path` entries in one line, and carries §3(d)'s empty-element
hazard with it. Worse in kind, `authors = { SNUG_PROFILES = "@sys" }` or
`{ SNUG_TARGET = "/lies" }` lets a profile lie to the artifacts a human reads to
decide whether to trust the sandbox — `--dry-run` and the injected
`~/.claude/CLAUDE.md`. Today this is closed **by accident of ordering**: the
`prof.Env` loop runs at `resolve.go:282`, before snug's own assignments at
396–436, so snug always wins. Measured — a profile with `env = ["PATH"]` and a
hostile host `PATH` changes nothing inside. An `authors` key would have to make
that accident deliberate: **the names snug authors are not writable by a profile,
refused loudly.**

Related, and fixable today: `env = ["PATH"]` is currently **accepted and silently
discarded** — no error, no warning, nothing in `--dry-run`. Under "no silent
downgrade, ever" that should be a named refusal.

A real widening either way; wants a `redteam` run.

**Sanitising does not make a dangerous variable safe.** `LD_PRELOAD` names a file
loaded into every process; that it lives inside the sandbox does not make loading
it a good idea. The forbidden list stays, and `sanitise` is offered only for
variables whose danger is *pointing outside*, not *what they do*.

---

## 8. Where this seems to land

*Opinion, not a decision.* **F for the vocabulary, C for `PATH`, D's bands as the
skeleton, §3's types as the validation rule, and an explicit no to E in the grant
language.**

1. **Give every known variable a type**, and model list variables as
   `[]Entry{Value, Class, From}` with the separator in the type — never a string
   until render. Everything else needs this, it mirrors `Mounts`, it is what lets
   `--dry-run` show per-entry provenance, and it is what makes §3(d)'s empty-element
   bug unspellable. Worth doing first even if nothing else lands.
2. **Bands give the coarse order** — profile-granted, snug-generated,
   sanitised-host, authored base — as a fixed Go enum, not a number a profile can
   write. `Resolve` does this today; making it a named type rather than three
   appends is most of the value.
3. **Within a band, sort, and make an undeclared shadow an error.** `shadows` is
   the only new ordering vocabulary; it is additive, and it says something true
   about the world instead of asserting a rank.
4. **`authors` binds a variable to the grant that makes it true** — §2, and the
   reviewer's intuition.
5. **`sanitise` is the new capability**, smallest of the four, and it carries
   §3(d) in its abuse sentence.
6. **No `unset`, no `rank`, no `force`, no expression language.** If a candidate
   needs one it is the wrong candidate — and §5's most useful sentence may be that
   every neighbour except CUE ships subtraction, so borrowing their vocabulary
   means borrowing that too.

Independent of all of it, and fixable now, in rising order of how much they
matter:

- **§1(e)**, the conditional `forbiddenEnv` guard. Move the refusal out of the
  `v != ""` guard, or better, check it at parse time next to `checkName` and
  `DisallowUnknownFields`, so the verdict never depends on the invoking shell.
- **§1(f)'s error message.** Catch the "no such file" case and say what is
  actually true: the sandbox has its own `PATH`, the command was looked up in it,
  and here is what it contains. `snug` should own this message, not bwrap.
- **§1(f)'s missing test.** The property that the payload name resolves inside is
  load-bearing for every candidate here, and nothing asserts it.

## 9. What would have to be true before any of it ships

- ~~A commutativity test for the environment~~ — **this already exists**, and an
  earlier draft of this document wrongly reported it missing.
  `TestResolveIsCommutative` (`resolve_test.go:200`) shuffles seven profiles 200
  times and compares `canon()`, which renders `p.Env`; the fixture registry
  carries a `path` entry deliberately so that PATH assembly is covered. What
  `TestResolveIsMonotone` does not cover is mounts-at-different-depths, which is
  a separate and correctly-described gap. The correction matters in the other
  direction too: it means §1(a)'s alphabetical sort is an **enforced** property,
  not an accident nobody noticed.
- A test that an undeclared shadow is refused, **with a positive control** — a
  declared one that resolves — so the refusal cannot pass on a resolver that
  refuses everything.
- **A named regression test for §1(f)**, and it is a prerequisite rather than a
  nicety: a binary present only on the host's `PATH` must NOT run, a binary in a
  profile's `path` directory must, and a name present in both must resolve to the
  profile's. The first is the negative, the second is its positive control, and
  the third is what makes `shadows` meaningful. Without it, a refactor to
  host-side `exec.LookPath` passes every test in the suite while silently
  resolving the payload's name in the wrong namespace.
- **A named regression test for §3(d)**: sanitise a `PATH` down to one surviving
  element and assert the result has no empty element, with a positive control
  that a planted binary in the target *is* found when an empty element is present.
  This is the one place in the document where getting it wrong adds a hole rather
  than failing to close one.
- `--dry-run` renders `PATH` per entry with provenance and class, and the golden
  file changes. A security change with no golden diff is probably untested.
- `redteam` on F's `authors`, the only genuinely new power in the recommendation.
- §1(e) fixed and regression-tested in both directions — variable set and unset.
- Whatever implements XDG authoring is checked against §2 by selecting a set
  without `@home` and asserting the variables are absent, not dangling.

## 10. Open questions

- Does `shadows` name the *binary* (`podman`) or the *shadowed directory*
  (`/usr/bin`)? Naming the binary is more precise and more useful in `--dry-run`;
  naming the directory is checkable without reading any filesystem.
- Should `sanitise` and `passthrough` be one key with two strictnesses? The
  argument for keeping them visibly separate is that `passthrough` should *shrink*
  over time as adapters move to generated config files (the "generate, don't bind"
  rule), while `sanitise` should not.
- Where does the type table live — a Go map of known names, or a `type` key a
  profile may write? A profile declaring `PYTHONPATH` is a list is convenient and
  is also a profile declaring what snug is allowed to do to it. Leaning: snug owns
  the types, and an unknown name is scalar-by-default, which is the conservative
  reading.
- Does this interact with `PARAMETERISED-PROFILES.md`? A parameterised
  `stubs-in-path:/some/dir` would make the directory a value rather than a
  constant — §4's fifth route — attractive right up to the point where two
  instances need an order between them.

---

## 11. The proposed syntax — **decided in shape**

*Owner's sketch, 2026-08-10, with one rule settled:* **`prepend` may be used once
across the whole selected set of profiles. A second one is a failure, not a
merge.** The examples below are that sketch, filled in where it was rough.

### 11.1 Three keys, and one of them moves out of profiles

```toml
[profile.stubs-in-path]
description = "snug's wrappers ahead of /usr/bin"
environ-prepend = { PATH = "/run/snug/bin" }      # once per selected set

[profile.sys]
environ = { PATH = ["/usr/bin", "/usr/sbin"], SHELL = "/usr/bin/bash" }

[profile.home]
environ = { XDG_CONFIG_HOME = "{home}/.config", XDG_CACHE_HOME = "{home}/.cache" }
```

```toml
# ~/.config/snug/config.toml — preferences, not grants
defaults    = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@stubs-in-path"]
inherit-env = ["USER", "TERM", "LANG"]
```

### 11.2 The rule that was hard to express: **the TOML type IS the variable type**

The sketch says *"lists like PATH can be merged, while scalars like SHELL do not
— this is not very well expressed here."* It does not need expressing. TOML
already has both types, so let the value's own type carry it:

| written as | means | two profiles both set it |
|---|---|---|
| `PATH = ["/usr/bin", "/usr/sbin"]` | **array → list variable** | **merge** (union, then sorted) |
| `SHELL = "/usr/bin/bash"` | **string → scalar** | identical values fine; **different values are an error** |

No lookup table, no `type =` key, nothing to keep in sync. You already say which
one you mean by how you write it.

**And it closes the empty-element hazard by construction.** A profile never
writes a separator, so it cannot write `"/usr/bin:"` and it cannot produce
`"/usr/bin::/bin"` by dropping an element from a string. snug joins the array
with the right separator for that variable — `:` for `PATH`, and `;` where
`ld.so` wants one — and refuses an empty array element. §3(d)'s hazard, and the
`MANPATH`-operator problem in §3a.2, both stop being things an implementation has
to remember.

One consequence worth stating: `environ = { PATH = "/usr/bin:/usr/sbin" }` — a
string where the variable is a list — is a **load error**, not a helpful
coercion. Otherwise the separator comes back in through the front door.

### 11.3 The three worked profiles

```toml
[profile.sys]
description = "The system's binaries, libraries and a curated /etc."
ro = ["/usr", "/etc/ssl", "/etc/pki", "/etc/passwd", "…"]
symlink = [{ at = "/bin", target = "usr/bin" }, "…"]
environ = {
  PATH  = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
  SHELL = "/usr/bin/bash",
}

[profile.home]
description = "$HOME is an empty tmpfs at the host path. Writable, ephemeral."
tmpfs = ["{home}", "{home}/.config", "{home}/.cache",
         "{home}/.local/state", "{home}/.local/share"]
environ = {
  XDG_CONFIG_HOME = "{home}/.config",
  XDG_CACHE_HOME  = "{home}/.cache",
  XDG_STATE_HOME  = "{home}/.local/state",
  XDG_DATA_HOME   = "{home}/.local/share",
}

[profile.stubs-in-path]
description = "snug's wrappers ahead of /usr/bin, so a host tool that cannot work inside says so"
environ-prepend = { PATH = "/run/snug/bin" }
```

Three notes, all of which are the design doing work:

**`@home` is §2 fixed.** The variables sit next to the `tmpfs` that creates the
directories. A rule that every path in `environ` must be granted by the same
profile makes "select without `@home` and `XDG_CONFIG_HOME` names nothing"
**unspellable**, not merely detectable — and the same rule catches the three
instances §2 measured live on `main` today (`HOME`, `SHELL`, `PATH`).

**The sketch wrote `XDG_CONFIG_DIR`; the real name is `XDG_CONFIG_HOME`.**
`XDG_CONFIG_DIRS` is a different variable — plural, a *list*, defaulting to
`/etc/xdg` (§3a.3). Worth pointing out because it is exactly the confusion the
type table exists to catch: one is a scalar you author, the other is a list that
merges, and they are one character apart.

**`@sys` sets `PATH` as an array, `@stubs-in-path` prepends.** Those are
different operations on the same variable and they compose: the merged array
sorts, and the prepend goes in front of all of it.

### 11.4 `inherit-env` moves passthrough out of profiles, and that is an improvement

Today `env = ["ANTHROPIC_API_KEY"]` lives in `@claude`, so *selecting a profile*
is what puts a host credential inside. Moving it to `config.toml` changes who
decides: the human writes the line, once, for their own machine.

That is worth having on its own terms. It also shrinks the thing this document
has been complaining about since §3 — passthrough is the leak class, and a
profile can no longer reach for it silently.

**One honest objection.** CLAUDE.md says *"`snug config` holds preferences, never
grants"*, and copying a host value into the sandbox looks more like a grant than
a preference. The counter-argument is that the host's environment is not
something a profile can know — it is a fact about the invoking shell, so the
human is the only one in a position to name it. I think that holds, but it is a
rule being amended rather than applied, and it should be amended out loud.

`forbiddenEnv` still applies to `inherit-env`, unconditionally rather than only
when the host happens to have the variable set (§1(e)). And per §3a.6 the list
needs to grow — `PYTHONPATH`, `GIT_EXEC_PATH`, the `GIT_CONFIG_*` family,
`LESSOPEN` and `BASH_FUNC_*` are all measured code-execution vectors that are not
on it today.

### 11.5 The failures

```toml
# 1. Two prepends. The rule the owner set.
[profile.stubs-in-path]
environ-prepend = { PATH = "/run/snug/bin" }
[profile.mytools]
environ-prepend = { PATH = "/opt/bin" }
```
```
snug: @stubs-in-path and mytools both prepend to PATH (/run/snug/bin and
       /opt/bin). Only one profile may prepend — prepending is a claim about
       which binary wins, and two claims cannot both hold.
       Use environ = { PATH = [...] } if the order does not matter to you.
```

**The cost, stated plainly:** `@stubs-in-path` is in `defaults`, so it holds the
prepend slot on every ordinary run. A user profile that wants the slot has to
displace it — `--no-defaults`, or a `defaults` list without it. That is the price
of the rule being simple, and it is visible rather than silent.

```toml
# 2. Two scalars disagree.
[profile.a]
environ = { SHELL = "/usr/bin/bash" }
[profile.b]
environ = { SHELL = "/usr/bin/zsh" }
```
```
snug: profiles a and b both set SHELL, to /usr/bin/bash and /usr/bin/zsh.
       A scalar has one value. Select one profile, or make them agree.
```
Setting it to the *same* value in both is fine — that is what keeps `include`
usable.

```toml
# 3. A separator written by hand.
environ = { PATH = "/usr/bin:/usr/sbin" }
```
```
snug: PATH is a list; write it as an array — PATH = ["/usr/bin", "/usr/sbin"].
       snug joins list variables with the right separator, and a hand-written
       one can smuggle in an empty element, which in PATH means the current
       directory.
```

```toml
# 4. A value naming something the profile does not grant.
[profile.broken]
tmpfs = ["{home}/.config"]
environ = { XDG_DATA_HOME = "{home}/.local/share" }
```
```
snug: profile broken sets XDG_DATA_HOME=/home/u/.local/share, which it does not
       grant. Add it to tmpfs/ro/rw, or drop the variable — a variable naming a
       path that does not exist inside is worse than an absent one.
```

```toml
# 5. A name snug owns.
environ = { SNUG_PROFILES = "@sys", PS1 = "$(id)" }
```
Refused: `SNUG_*` is what `--dry-run` and the injected `~/.claude/CLAUDE.md` are
read against, and `PS1` is executed by bash (§3a.4). The refusal has to cover
**prefixes**, not just names — `BASH_FUNC_*`, `GIT_CONFIG_*`, `LD_*` — which
today's `map[string]bool` cannot express.

### 11.6 What is still open

- **The `env` key has to go.** `environ` replaces it and `inherit-env` takes its
  meaning, so any existing user profile with `env = [...]` breaks. It should be a
  named error pointing at `inherit-env`, in the shape of the retired `@null`.
- **Naming.** `environ` / `environ-prepend` next to `ro`, `rw`, `tmpfs`,
  `symlink` is the only hyphenated pair in the language. `env` / `env-prepend`
  would match, and `env` is free once passthrough moves out.
- **Is `append` needed?** Nothing has asked for it. Leaving it out keeps exactly
  one ordered operation, which is what makes the "once" rule easy to state.
- **`XDG_RUNTIME_DIR`** has obligations, not just a value (mode 0700, owned by
  the user — §3a.3), so it belongs to whichever profile creates a directory
  meeting them. The schema forces that question to be answered rather than
  letting the variable float.
- §3a.5(a), the environment outranking a pinned config file, is untouched by any
  of this and still wants its own fix.

---

## Sources

- [makeWrapper / wrapProgram implementation](https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/setup-hooks/make-wrapper.sh)
- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [flatpak-run(1)](https://www.man7.org/linux/man-pages/man1/flatpak-run.1.html), [Flatpak metadata](https://github.com/flatpak/flatpak/wiki/Metadata)
- [Lmod: rules for PATH-like variables (reference counting)](https://lmod.readthedocs.io/en/latest/077_ref_counting.html), [TCL modulefile functions](https://lmod.readthedocs.io/en/latest/051_tcl_modulefiles.html)
- [NixOS properties: mkOrder / mkBefore / mkAfter / mkForce](https://nixos.wiki/wiki/NixOS:Properties), [nixpkgs lib/modules.nix](https://github.com/NixOS/nixpkgs/blob/master/lib/modules.nix)
- [Nickel: merging records](https://nickel-lang.org/user-manual/merging/)
- [The CUE language specification](https://cuelang.org/docs/reference/spec/), [CUE: configuration use case](https://cuelang.org/docs/concept/configuration-use-case/)
