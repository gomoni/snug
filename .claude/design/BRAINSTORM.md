# BRAINSTORM — what a profile may say about the environment

**Status: exploration, not a decision.** Filed so the reasoning is not
re-derived later, in the shape of `PARAMETERISED-PROFILES.md`, which this
document leans on in §4.

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

**(b) `/run/snug/bin` is a Go constant, and on `main` it is gated only on
`p.Podman`.** `Resolve` appends `PodmanStubDir` after the sorted set whenever a
podman profile is selected. So the *mechanism* generalises — any profile may
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

**This is not a defect on `main`** — `main` authors no XDG variable at all, so
there is nothing to point at nothing. It is a **trap for whoever implements
them**, and it is the most concrete thing in this document, because the obvious
implementation walks straight into it: five assignments in `Resolve` next to the
other authored values, which is exactly where they do not belong.

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

So `forbiddenEnv` is not an ad-hoc blocklist of scary names. It is a **type
judgement**: semi-structured variables may be *authored* by snug and must never
be *passthrough* or *merged*. Stating it that way tells you what else belongs
there without waiting to be bitten — anything whose value is a grammar rather
than a datum.

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
| **sanitised** | meaningless — nothing to filter | **the capability being asked for** | **never** |

A table with holes in it is a better specification than prose, because the holes
are the design. Two of the illegal cells are exactly what `forbiddenEnv` refuses
today; the third — sanitised scalar — is simply nonsense, and a language that can
express nonsense will eventually be asked to.

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
**Against:** `authors` lets a profile set an arbitrary value, which is a new power
— today only snug authors. It needs the same name refusal `forbiddenEnv` applies,
now justified by type rather than by list membership, plus a points-inside check
on profile-authored values. A real widening; wants a `redteam` run.

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

Independent of all of it, and fixable now: **§1(e)**, the conditional
`forbiddenEnv` guard. Move the refusal out of the `v != ""` guard, or better,
check it at parse time next to `checkName` and `DisallowUnknownFields`, so the
verdict never depends on the invoking shell.

## 9. What would have to be true before any of it ships

- A test that `resolve([a,b]) == resolve([b,a])` for **environment**, not only
  mounts. `TestResolveIsMonotone` compares `Access` per `Guest`; there is no
  equivalent for `Env`, and every candidate here makes one mandatory.
- A test that an undeclared shadow is refused, **with a positive control** — a
  declared one that resolves — so the refusal cannot pass on a resolver that
  refuses everything.
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

## Sources

- [makeWrapper / wrapProgram implementation](https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/setup-hooks/make-wrapper.sh)
- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [flatpak-run(1)](https://www.man7.org/linux/man-pages/man1/flatpak-run.1.html), [Flatpak metadata](https://github.com/flatpak/flatpak/wiki/Metadata)
- [Lmod: rules for PATH-like variables (reference counting)](https://lmod.readthedocs.io/en/latest/077_ref_counting.html), [TCL modulefile functions](https://lmod.readthedocs.io/en/latest/051_tcl_modulefiles.html)
- [NixOS properties: mkOrder / mkBefore / mkAfter / mkForce](https://nixos.wiki/wiki/NixOS:Properties), [nixpkgs lib/modules.nix](https://github.com/NixOS/nixpkgs/blob/master/lib/modules.nix)
- [Nickel: merging records](https://nickel-lang.org/user-manual/merging/)
- [The CUE language specification](https://cuelang.org/docs/reference/spec/), [CUE: configuration use case](https://cuelang.org/docs/concept/configuration-use-case/)
