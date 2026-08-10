# Implementing `environ` — the plan

**Spec:** [ENVIRONMENT-VARIABLES.md](ENVIRONMENT-VARIABLES.md). Where this file
and that one disagree, that one wins *except* at the four points marked
**CALL** below, each of which resolves a place where the design contradicts
itself or is silent. Every CALL says what was chosen and why.

Audience: `go-implementer`, then `sandbox-tester`, then `redteam`. It is written
so it can be executed without having read the reviews.

---

## 0. Measurements taken while writing this

Run against the installed toolchain, not from memory. Re-verify before relying
on any of it.

```
bubblewrap 0.11.2                    go-toml/v2 v2.4.3 (go.mod:5)

bwrap --setenv 'A=B' c ...        →  bwrap: setenv failed          (exit 1)
bwrap --setenv NO_COLOR '' ...    →  NO_COLOR=                     (present, empty)
```

Two consequences. `--setenv` **can** deliver a present-but-empty value, so
§4.6(a)'s fix needs no new flag and never needs `--unsetenv`. And a `=` in a
name is caught by glibc — but bwrap's message names neither the variable nor the
profile nor the file, which is exactly why §2.3's grammar check has to be at
parse time and not left to the backstop.

go-toml v2.4.3, decoding `[profile.x.environ.*]` into a struct of five map
fields, with `DisallowUnknownFields()`:

| written | result |
|---|---|
| `[profile.x.environ.deny]` | **strict error**, and `StrictMissingError.String()` points a caret at `[profile.x.environ.deny]`. §1.1(b) holds. |
| `[profile.x.environ.set]` with `"A=B" = "c"` and `"" = "d"` | **accepted**, both keys land in the map. §2.3 is load-bearing, not theoretical. |
| `environ.merge` `PATH = "/a:/b"` into `map[string]any` | accepted as a `string` |
| `environ.merge` `PATH = ["/a","/b"]` into `map[string]any` | accepted as `[]any` of `string` |
| `environ.inherit` `EDITOR = false` | **accepted** — the `true`-only rule must be code, not a type |
| `environ.set` `A = 1` | decode error, but the message is go-toml's and names no profile |
| `environ = { set = {\n A = "1",\n} }` (multi-line inline) | **accepted** |

That last row matters and is a **CALL**: §1.1 says the flat/inline form is
spec-invalid but accepted here, and suggests "snug rejecting the form
deliberately". **It is not implementable post-decode** — the decoded value is
byte-identical to the header form, and go-toml hands us no syntax provenance.
Rejecting it needs a second, independent pass over the document text. **Out of
scope.** Record it in `TODO.md` as a portability note (a profile written that
way works here and breaks on a TOML 1.0 parser), and *do not* write a comment
anywhere claiming snug refuses it — CLAUDE.md, "a gate that is documented but
not implemented is not a gate".

---

## 1. The type changes

### 1.1 What `Policy.Env` becomes

Today: `internal/policy/types.go:129`

```go
Env map[string]string
```

That cannot carry §2.8: which verb produced a value, which profile, the band
order inside a list, or what a `sanitise` dropped. It becomes:

```go
// internal/policy/types.go
Env map[string]EnvVar        // key == EnvVar.Name

// internal/policy/env.go (new)
type EnvVerb uint8
const (
    VerbSnug EnvVerb = iota   // snug's own authorship (§1.1). Renders "(snug)".
    VerbSet; VerbMerge; VerbPrepend; VerbInherit; VerbSanitise
)
func (v EnvVerb) String() string   // "(snug)" "set" "merge" "prepend" "inherit" "sanitise"

type EnvEntry struct {
    Value string
    Verb  EnvVerb
    From  []string // contributing profiles, UNIONED AND SORTED — see below
    Note  string   // VerbSnug only: "base", "podman stub", ""
}

type EnvDrop struct {
    Value string   // a host element sanitise removed, named not counted (§2.8)
    Var   string
    From  []string
}

type EnvVar struct {
    Name    string
    List    bool     // rendered by joining Entries with Sep
    Sep     string   // "" for a scalar
    Entries []EnvEntry // band order; deduped to the earliest band (§2.6)
    Dropped []EnvDrop
}
func (v EnvVar) Value() string  { /* scalar: Entries[0].Value; list: join */ }
func (v EnvVar) Present() bool  { return len(v.Entries) > 0 }
```

**Why a map of structs and not a new named type.** `policy.Environ` already
exists as the injected host-lookup interface. A `policy.Env`/`policy.Environment`
type sitting two letters away from it in the same package is exactly the
one-word-two-things confusion the `(builtin)` → `(snug)` rename was done to
remove. So there is **no new noun**: `Policy.Env` stays a map, and the writers
become `Policy` methods that mirror `Policy.Replace`:

```go
func (p *Policy) AuthorEnv(name, value string)                        // scalar, VerbSnug
func (p *Policy) AuthorEnvList(name string, values []string, note string) // appends a VerbSnug band
func (p *Policy) EnvValue(name string) (string, bool)
func (p *Policy) EnvNames() []string      // sorted
func (p *Policy) EnvPairs() [][2]string   // sorted; SKIPS !Present()
func (p *Policy) AuthoredEnvNames() []string
```

`AuthorEnv`/`AuthorEnvList` are the **only** writers of a `VerbSnug` entry, the
same way `Policy.Replace` is the only writer of `Mount.Authored`. That is what
makes §1.1's ownership set derivable (§1.3).

**`EnvEntry.From` is a `[]string`, unioned and sorted — deliberately unlike
`Mount.From`'s treatment in tests.** `Mount.From` is excluded from `canon()`
because provenance is not part of the join. Here it must be *included*, because
§2.8 prints per-entry provenance as a trust artifact: if which profile gets
credited for a `merge` entry depended on fold order, `--dry-run` would lie and
no existing test would see it. Union is idempotent, so rendering it cannot
perturb the fixpoint.

### 1.2 Every reader, and what happens to it

Direct map indexing of `p.Env` now yields an `EnvVar`, so **every one of these
fails to compile** — which is the point. This is an audited migration, not a
silent one.

| site | today | becomes |
|---|---|---|
| `internal/policy/bwrap.go:122-130` | `--clearenv`, then sorted `--setenv k v` | `for _, kv := range p.EnvPairs()`. `--clearenv` stays first and unchanged. An `EnvVar` with zero entries emits **nothing** — §2.2: nothing survives a sanitise ⇒ UNSET, not empty. Never emit `--unsetenv`; after `--clearenv` there is nothing to unset and it would only be noise in the golden. |
| `internal/policy/resolve.go:396-437` | 13 `p.Env["X"] = ...` | `p.AuthorEnv("X", ...)`. `PATH` at :406-410 becomes two `AuthorEnvList` calls (stub dir, then base). |
| `internal/policy/resolve.go:361` | `p.Env["GIT_CONFIG_GLOBAL"] = ...` | `p.AuthorEnv(...)` |
| `internal/policy/resolve.go:282-289` | the `prof.Env` fold | replaced wholesale by the environ fold (step 6) |
| `cmd/snug/identity.go:151,200,201` | `SSH_AUTH_SOCK`, `GH_CONFIG_DIR`, `GH_HOST` | `pol.AuthorEnv(...)` |
| `cmd/snug/container.go:58,59,76` | `CONTAINER_HOST`, `DOCKER_HOST`, `DOCKER_BUILDKIT` | `pol.AuthorEnv(...)` |
| `cmd/snug/dryrun.go:83-92` | flat `NAME=value` list | §2.8 rendering (step 9) |
| `cmd/snug/config.go:241` | `show("env", p.Env)` — this is `policy.Profile.Env`, the profile's `env = [...]`, **not** `Policy.Env` | renders the environ block (step 11) |
| `internal/policy/resolve_test.go:610,639-645`, `podmanstub_test.go:68` | `p.Env["PATH"]` | `p.EnvValue("PATH")` |
| `internal/policy/resolve_test.go:179-186` | `canon()` | see below |

### 1.3 `canon()` is what proves the model, so it must render everything

`resolve_test.go:173-194` feeds `TestResolveIsCommutative` and
`TestResolveIsIdempotent`. Its own doc comment already records the lesson:

> It used to render Mounts and Env only, so `TestResolveIsCommutative` could not
> see a break in `Net.Address` … **A commutativity test that does not render a
> field does not test it.**

Applied again here: canon must render **every field `--dry-run` renders**, in
order:

```
env PATH list sep=":" 
env PATH  [0] /opt/bin                 prepend  [mytools]
env PATH  [1] /home/u/.cargo/bin       merge    [@rust]
env PATH  [2] /usr/bin                 (snug)   base
env PATH  drop /srv/pkgconfig          [@pkgconfig]
env EDITOR scalar
env EDITOR [0] vim                     inherit  [@claude]
```

Rendering only the joined value would hide a fold-order dependence in *credit*,
which is precisely what §2.8 puts on screen.

**And the fixtures must exercise it, or widening canon asserts nothing** — the
same trap the canon comment already warns about for the network scalars.
`testRegistry()` (`resolve_test.go:74-127`) gains profiles using all five verbs,
and they must be added to `TestResolveIsCommutative`'s `all` list at
`resolve_test.go:201`. Keep them **off** `testDefaults` so the `.bwrap.txt`
goldens still describe a sandbox a real user gets.

### 1.4 The ownership set (§1.1), derived rather than retyped

§1.1 demands the snug-owned list be "derived from the code and asserted by a
test", because an earlier hand-typed draft missed the six post-`Resolve`
writers — and those are the dangerous half (`environ.set DOCKER_HOST =
"ssh://…"` makes the client `exec ssh`, §3.2).

Ship **both** of these:

1. `policy.SnugOwnedEnv` — a sorted `[]string`, consulted at parse time by
   `internal/profile`. It has to exist as data, because parse time cannot run a
   resolve.
2. `cmd/snug/ownedenv_test.go` — a **static** check. Parse
   `../../internal/policy/*.go` and `./*.go` with `go/parser`, collect the first
   argument of every call to `AuthorEnv` / `AuthorEnvList`, and assert that set
   equals `policy.SnugOwnedEnv` exactly. A non-literal first argument is a hard
   failure: *"a computed variable name cannot be checked; write the literal"*.
   `cmd/snug` is the right home because it sits above both packages;
   `go/parser` is stdlib, so no dependency and `internal/policy` stays pure.
3. A second, execution-based test that resolves with a fixture selecting
   everything, runs the identity and container env writers, and asserts every
   name it observes is in the list. This one catches a *stale* entry; the AST
   one catches a *missing* entry. Neither alone is enough — an execution-only
   test passes for a writer on a path it never exercises, which is CLAUDE.md's
   `pasta.avx2` failure shape.

**§1.1's count is wrong.** It says "nineteen keys" and lists twenty:

```
resolve.go  HOME SHELL USER LOGNAME TMPDIR PS1 PATH TERM TZ LANG
            SNUG SNUG_PROFILES SNUG_TARGET GIT_CONFIG_GLOBAL      (14)
identity.go SSH_AUTH_SOCK GH_CONFIG_DIR GH_HOST                    (3)
container.go CONTAINER_HOST DOCKER_HOST DOCKER_BUILDKIT            (3)
```

Do not hand-count and do not write a count into a comment. Let the AST test say.

### 1.5 The type table

`internal/policy/envtypes.go`, unexported, beside `forbiddenEnv`
(`resolve.go:492-496`, moved here):

```go
type emptyKind uint8
const (
    emptyNA emptyKind = iota
    emptyIgnored   // PKG_CONFIG_PATH, PERL5LIB, NODE_PATH — sanitise is safe
    emptyCWD       // PATH, LD_LIBRARY_PATH, CDPATH, PYTHONPATH — §4.3, hazardous
    emptyOperator  // MANPATH — removing an element can ADD directories; sanitise ILLEGAL
    emptySystem    // TERMINFO_DIRS, INFOPATH — means "the system location"
)

type envType struct {
    list        bool
    sep         string // ":" ; ld.so gives LD_LIBRARY_PATH ":" or ";" — see below
    altSep      string // a second separator the CONSUMER also accepts, "" if none
    path        bool   // path-valued ⇒ §2.5's coupling rule applies
    empty       emptyKind
    sanitisable bool   // §3.3's ⚠/✗ column
}
var envTypes = map[string]envType{ /* §3.2, §3.3, §3.4 verbatim */ }
```

Unknown name ⇒ **scalar** (§2.1): a scalar merges with nothing, so it can only
conflict, never silently combine.

`altSep` exists because §3.3's `LD_LIBRARY_PATH` / `LD_PRELOAD` rows are the
reason the separator lives in the type: `ld.so(8)` gives them two separator sets
and neither is escapable. Those two are forbidden outright anyway, but the field
must exist so the separator-in-value check (§2.7 case 3) rejects `;` in a name
where `;` is a separator for *some* consumer.

Exported entry point, so `internal/profile` can call it while the table stays
snug's:

```go
func ValidateEnvGrants(g EnvGrants) error
```

### 1.6 `Profile` gains one field

`internal/policy/profile.go` — `Env []string` (:69-70) and `Path []string`
(:72-89) are retired in step 12. The new field:

```go
// EnvGrants is a profile's `environ` block. Unordered, like every other grant.
// Argv ordering is a COMPILER concern (§2.4's bands) and never appears here.
type EnvGrants struct {
    Set      map[string]string
    Merge    map[string][]string
    Prepend  map[string][]string
    Inherit  []string  // sorted set of NAMES; the TOML `= true` carries no value
    Sanitise []string  // sorted set of NAMES
}
```

`Inherit`/`Sanitise` are `[]string` and not `map[string]bool` on purpose: a bool
in the model reads like a switch that could be turned off, and `= false` must be
a refusal (§2.2 below), not a stored state.

---

## 2. Decisions the design leaves open

Four **CALL**s. Each is a place the spec contradicts itself or is silent; the
implementer must not have to guess.

**CALL 1 — a TOML string on a list variable is one element, for `merge` as well
as `prepend`; the refusal is about the SEPARATOR, not the shape.**

§2.2 and §2.7 case 1 accept `prepend` written as a bare string
(`PATH = "/opt/bin"`). §2.7 case 3 refuses `merge` written as a bare string,
with a message saying "environ.merge needs an array". Those cannot both be the
rule. Resolution: **both verbs accept a string or an array; a string is exactly
one element; snug never splits (§2.2).** What is refused is any *element* —
string or array member — containing that variable's `sep` or `altSep`. This is
strictly stronger than §2.7 case 3 as written, because `PATH = ["/usr/bin:/usr/sbin"]`
is the identical smuggle and the shape-based rule does not catch it. The error
keeps case 3's substance:

```
snug: profile x merges PATH = "/usr/bin:/usr/sbin", which contains ':' — the
       separator snug joins PATH with. Write the elements:
         PATH = ["/usr/bin", "/usr/sbin"]
       snug never splits a value, so a hand-written separator can smuggle in an
       empty element, which in PATH means the current directory.
```

**CALL 2 — `set` and `inherit` on one scalar name are a conflict unless the
values are equal.** The spec does not say. "set beats inherit" would be a
priority field wearing a verb's clothes, which invariant 1 forbids. So it joins
the one rule §2.7 already states for `set`: equal claims agree, unequal claims
are a symmetric error naming every claimant and both verbs. `inherit` of a name
absent on the host contributes nothing and therefore never conflicts.

**CALL 3 — `TERM`, `TZ` and `LANG` are snug-owned; §3.2's `set` cells for them
are dead.** §1.1's list (normative: "no profile may write a name snug writes")
includes all three, while §3.2 marks `TERM` `set ⚠`, `TZ` `set ⚠`, `LANG`
`set ✓`. §1.1 wins. Two consequences worth stating: the "`TZ` requires granting
`/usr/share/zoneinfo`" guard §2.5 asks for is **unreachable for profiles**, so
it is not a refusal — it becomes one of §4.2's `--dry-run` *marks* on an
authored value (step 9); and §3.2's rows still carry real information (the
*type* is scalar), so leave them.

**CALL 4 — `PIP_*` and `npm_config_*` are forbidden for `inherit` only;
`GIT_CONFIG_*`, `LD_*` and `BASH_FUNC_*` are forbidden for both.** §2.7 case 5
lists five prefixes to refuse; §3.2 marks `PIP_CONFIG_FILE` and
`NPM_CONFIG_USERCONFIG` as `set ✓` under "generate, don't bind". Both are right
about different things: §4.5's finding is that the *host's* environment outranks
a pinned config file, which is an argument about **inherit**, while a `set` in a
reviewed profile naming a path the same profile grants is exactly the shape
"generate, don't bind" wants. So the prefix table carries the same
`forbidBoth` / `forbidInheritOnly` split §2.1 gives the middle bucket.

```go
type forbidKind uint8
const ( forbidBoth forbidKind = iota; forbidInheritOnly )

var forbiddenEnv = map[string]forbidKind{
  // value is code, at any verb (§4.4 + ld.so(8)'s secure-execution list)
  "LD_PRELOAD": forbidBoth, "LD_AUDIT": forbidBoth, "LD_LIBRARY_PATH": forbidBoth,
  "GCONV_PATH": forbidBoth, "LOCPATH": forbidBoth, "NLSPATH": forbidBoth,
  "HOSTALIASES": forbidBoth, "RESOLV_HOST_CONF": forbidBoth, "RES_OPTIONS": forbidBoth,
  "TZDIR": forbidBoth, "MALLOC_TRACE": forbidBoth, "GETCONF_DIR": forbidBoth,
  "NIS_PATH": forbidBoth,
  "GIT_SSH_COMMAND": forbidBoth, "GIT_EXEC_PATH": forbidBoth,
  "GIT_EXTERNAL_DIFF": forbidBoth, "GIT_EDITOR": forbidBoth,
  "PS0": forbidBoth, "PS2": forbidBoth, "PS3": forbidBoth, "PS4": forbidBoth,
  "PROMPT_COMMAND": forbidBoth,          // §3.5: fires before anything is typed
  // reviewable as `set`, a hole in --clearenv as `inherit` (§2.1's middle bucket)
  "BASH_ENV": forbidInheritOnly, "ENV": forbidInheritOnly,
  "PERL5OPT": forbidInheritOnly, "NODE_OPTIONS": forbidInheritOnly,
  "PYTHONSTARTUP": forbidInheritOnly, "PYTHONBREAKPOINT": forbidInheritOnly,
  "LESSOPEN": forbidInheritOnly, "PYTHONPATH": forbidInheritOnly,
}
var forbiddenEnvPrefixes = []struct{ p string; k forbidKind }{
  {"LD_", forbidBoth}, {"BASH_FUNC_", forbidBoth}, {"GIT_CONFIG_", forbidBoth},
  {"PIP_", forbidInheritOnly}, {"npm_config_", forbidInheritOnly},
}
```

`PS1` is absent from both — it is snug-owned (§1.1), refused there, which is the
stronger statement. `SNUG*` is likewise covered by ownership: `SNUG`,
`SNUG_PROFILES` and `SNUG_TARGET` are all in `SnugOwnedEnv`, so no prefix rule
is needed and none should be added (a prefix rule would let a *name* pass
ownership and be caught by a weaker mechanism).

Two more small things the spec is silent on, decided here without ceremony:

- `environ.inherit` with `= false` is **refused by name**: *"`inherit` takes
  `true`; there is no way to un-inherit, because nothing was inherited to begin
  with. Remove the line."* Storing `false` would be a negation key that parsed.
- `environ.sanitise` uses the same `NAME = true` shape as `inherit`, for the
  same reason: the profile supplies no value, only a name.

---

## 3. Ordered steps

Each is independently committable and leaves `make gate` green. **Step 3 is the
first that changes observable behaviour, and therefore the first golden diff.**

### Step 1 — build the review artifact that does not exist yet

**No production change.** This is first because of a gap that would otherwise
make most of this work unreviewable:

> The `internal/policy/testdata/*.bwrap.txt` goldens are generated from
> `testRegistry()` (`resolve_test.go:74`), a **fake**. Nothing in
> `internal/profile/profiles/base.toml` has a golden. So step 10's change to
> `@home` and `@claude` — the whole user-visible payload of this work — would
> ship with **no golden diff at all**, which CLAUDE.md says to treat as
> "probably untested".

- Export `profile.Builtins() (Registry, error)` — `builtin.go:13`, currently
  unexported. It is the registry with no host layers, deterministic, and useful
  beyond the test.
- Add `cmd/snug/envgolden_test.go` with a local fake `policy.Environ` (a dirs
  map, mirroring `internal/policy`'s `fakeEnv`; duplicate the ~40 lines rather
  than exporting a test fake from production code) and goldens
  `cmd/snug/testdata/env.<name>.txt` for: `defaults`, `defaults + @claude`,
  `@sys @cwd-rw @podman-socket`. Content = the rendered `ENVIRONMENT` block.
- `SNUG_TARGET`/`SNUG_PROFILES` make the fixture paths visible in the golden;
  pin `Target`/`Home` to fixed fake paths (`/home/u/proj/sub`, `/home/u`), never
  `t.TempDir()`.

### Step 2 — `Policy.Env` becomes structured; ownership machinery lands

Everything in §1.1–§1.4 and §1.6's `EnvGrants` type (unpopulated). All 20 write
sites move to `AuthorEnv`/`AuthorEnvList`; all read sites move to `EnvValue`/
`EnvPairs`. `canon()` widened per §1.3. `SnugOwnedEnv` + the AST test + the
execution test.

**Golden diff: none, and that is expected.** This is the one step in the plan
entitled to produce no diff — it is a pure refactor and adds no capability. If
it produces one, the refactor is not faithful and that is the bug.

### Step 3 — `Environ.LookupEnv`, and `forbiddenEnv` stops being host-conditional

§4.6(a) and §4.4, which share one line.

- `Environ` gains `LookupEnv(string) (string, bool)`; `OSEnviron` and `fakeEnv`
  implement it.
- `resolve.go:283` — `if v := env.Getenv(e); v != ""` becomes a presence check.
  `NO_COLOR=` on the host now reaches the sandbox as `--setenv NO_COLOR ''`,
  which §3.2's flag row says is the correct semantics and which the measurement
  in §0 confirms bwrap delivers.
- `resolve.go:284` — the `forbiddenEnv[e]` check moves **out** of the presence
  guard. Today a profile carrying `env = ["LD_PRELOAD"]` is *accepted* on a host
  where `LD_PRELOAD` happens to be unset and refused where it is set: the same
  profile passes review on one machine and fails on another.
- Leave `envOr` (`resolve.go:498-503`) alone. `USER=""` is not a flag variable
  and falling back to `"user"` for an empty one is right. Say so in a comment so
  the next reader does not "fix" it.

**FIRST GOLDEN DIFF.** Two files:
- `internal/policy/testdata/refusals.txt` gains an unconditional
  `forbidden_env_unset_on_host` case.
- `cmd/snug/testdata/env.*.txt` — add a present-but-empty variable to the
  fixture host (`NO_COLOR=""`) so `@claude`'s `env` list actually exercises it.
  The diff should read: one new line `NO_COLOR=` in the `@claude` golden, and
  nothing else anywhere.

If either file shows more than that, stop and find out why.

### Step 4 — the type table, the name grammar, the split forbid list

`internal/policy/envtypes.go` (§1.5), `checkEnvName` (§2.3),
`ValidateEnvGrants` (§1.5), the `forbidKind` split (CALL 4). Applied
immediately to the legacy `env = [...]` key, which is semantically `inherit`.

`checkEnvName`, each refusal with its own message (§2.3):

```
name ::= [A-Za-z_][A-Za-z0-9_]*
```
empty name · contains `=` · contains NUL · contains a newline · leading digit ·
any other character outside the grammar · a name in `SnugOwnedEnv` · a name or
prefix in the forbid table for this verb.

`=` gets its own message, because `NAME=VALUE` is the wire format of the
environment itself: a key containing `=` is a second assignment smuggled inside
the first.

**Golden diff:** `refusals.txt` gains one case per rule. `@claude` today
inherits `ANTHROPIC_API_KEY ANTHROPIC_BASE_URL EDITOR VISUAL PAGER NO_COLOR`
(`base.toml:269`) — none is forbidden, so `env.*.txt` must not move. Verify that;
if it does move, the forbid table is too wide.

### Step 5 — parse the five verbs

`internal/profile/file.go`: `rawProfile` gains

```go
Environ *rawEnviron `toml:"environ"`

type rawEnviron struct {
    Set      map[string]string `toml:"set"`
    Merge    map[string]any    `toml:"merge"`     // string | []any — CALL 1
    Prepend  map[string]any    `toml:"prepend"`
    Inherit  map[string]bool   `toml:"inherit"`
    Sanitise map[string]bool   `toml:"sanitise"`
}
```

`any` is required: §0 measured that only `any` accepts both the string and the
array spelling. The converter must give its own error for `PATH = [1,2]` and
`PATH = true` — go-toml's own decode errors name no profile and no file.

Legacy keys are **rewritten**, not duplicated: `env = [...]` →
`EnvGrants.Inherit`, `path = [...]` → `EnvGrants.Merge["PATH"]`. `Profile.Env`
and `Profile.Path` are deleted in this step and `resolve.go:271-289` reads only
`EnvGrants`. A deprecation warning to stderr naming the file and the
replacement; **non-fatal** here (fatal is step 12).

`ValidateEnvGrants` is called from `parse()`, next to `checkName` — §2.3's "so
`snug profile show` reports it too and the verdict never depends on the invoking
host".

**Golden diff:** none expected; the rewrite is value-identical. The review
artifact for this step is the parse test table, not a golden. Say so in the
commit message so it does not read as an untested change.

### Step 6 — resolution: conflicts, bands, dedup, sanitise

The engine. New `internal/policy/envresolve.go`.

*Where it runs inside `Resolve`.* After the mount fold **and** after step 4's
authored mounts and the `Replace` calls for the identity files and
`/etc/resolv.conf`, because `sanitise`'s predicate is "is this guest path
granted" and it must see the whole mount set. Before the `AuthorEnv` block at
`resolve.go:396`, so snug's bands land last. §2.5's coupling check does **not**
depend on this position — it is over profile *text* — which is one of the
reasons §2.5 chose text.

*Conflicts, accumulated then checked.* §2.7's *"the error must name every
claimant, not two of them. Accumulate claims during the fold and check after it
completes, so there is no fold order to keep order-independent."* Collect
`map[name][]claim{profile, value}` during the fold; after it, group by value; if
more than one distinct value, error naming **every** claimant, sorted. Applies
to `set` (§2.7 case 2), to `prepend` (equality over the whole ordered sequence
after `{var}` expansion, so `["/a","/b"]` vs `["/b","/a"]` still fails), and to
set-vs-inherit (CALL 2).

*Bands* (§2.4), and the band is structural — nothing a profile writes chooses it:

```
prepend  →  merge (sorted)  →  sanitise (HOST ORDER, not sorted)  →  (snug)  →  base
```

*Dedup to the earliest band* (§2.6), single pass keeping first occurrence. This
is §4.6(c)'s fix: today `path = ["/nonexistent/bin","/bin"]` yields
`/bin:/nonexistent/bin:/usr/bin:/bin:…` with `/bin` twice.

*`sanitise`* (§2.6), and each of these is a separate assertion in the tests:
- **drop, never rewrite** — an element survives iff, read verbatim as a *guest*
  path, some grant covers it.
- **`ro` is enough.** No mode bits, no `stat`. It is a truthfulness filter, not
  a capability filter — a surviving element may name an empty bind. Put that
  sentence in the code comment.
- **unset and empty both mean absent — for lists only.** Write it inline in the
  list path, **not** as a shared helper: §3.2's flag scalars are "set to any
  value, including empty", so the collapse is exactly inverted for them. "Right
  for one type, wrong for the other" is how this class of bug ships.
- **survivors keep host order.** Not sorted. §3.3 documents `GOPATH`, where
  element 0 is privileged. There is no commutativity cost: host order is one
  external sequence, not a fold artifact.
- **nothing survives ⇒ the variable is UNSET**, not set empty (§2.2/§4.3). This
  is the single place where getting it wrong *adds* a hole rather than failing
  to close one.
- refused at parse time for any name whose `envType.empty == emptyOperator`
  (`MANPATH`) — removing an element there can *add* directories.

*Monotonicity, stated precisely, in the doc comment:* the **entry set** of a
list variable is monotone — adding a profile can only add entries, and
`sanitise`'s predicate is "is this path granted", which only grows. The **order**
is not: a `prepend` pushes another profile's merged entry later, and merge-vs-
merge is decided by ASCII. That is the same effective-behaviour
non-monotonicity CLAUDE.md already carves out for mount depth, and it belongs
in the same paragraph rather than being left to be discovered. Two tests:
`TestEnvIsMonotoneAsASet` and `TestPrependReordersWithoutRemoving`, the second
existing so nobody reads the first as proving more than it does — the same
relationship `TestDeeperGrantOverridesShallowerAccess` has to
`TestResolveIsMonotone`.

**Golden diff:** `refusals.txt` gains the conflict cases. `env.*.txt` should not
move (no builtin duplicates a PATH entry yet). Add a `testRegistry()` fixture
that *does* duplicate, so dedup is asserted somewhere.

### Step 7 — the `resolveVia` split

Prerequisite for step 8, and a fix in its own right. `validate.go:314-324`:

```go
func resolveVia(links map[string]string, g string) (via, resolved string) {
	for link, target := range links {          // map iteration: NONDETERMINISTIC
		if g == link { continue }              // right for a mountpoint...
		if strings.HasPrefix(g, link+"/") { return link, ... }
	}
```

Two defects. It returns the **first** map match, which is nondeterministic when
one link prefixes another (`/lib` and `/lib64`); and it skips `g == link`, which
is correct for a mountpoint and wrong for a `PATH` element that is literally
`/bin`.

One map, two entry points:
- `resolveViaDeepest(links, g)` — deepest match wins, `g == link` **skipped**.
  Replaces the existing call site. Deterministic; no behaviour change for any
  shipped profile, which the goldens should confirm.
- `resolveLinkForEnv(links, g)` — deepest match wins, `g == link` **matched**.
  Used by step 8 only.

Do not fold them into one function with a bool. The two questions differ and the
comment has to be able to say which is which.

### Step 8 — §2.5's grant-coupling rule, resolve stage

**Read §2.5 before writing a line, and put its framing in the code comment,
because otherwise someone will cite this check as a boundary:**

> It is a **coupling rule, not an existence check**. The profile that names a
> path must be the profile that put a node on the chain to it, so a reviewer
> reading one profile sees both acts. It cannot prove the path exists —
> `internal/policy` may not touch the filesystem, a `tmpfs` grant creates an
> *empty* directory, and a bind's contents are host state. The value is inert,
> and the payload can set any variable it likes once running. **It stops a
> profile lying; it does not stop anything reaching.**

Scope: values a profile **writes** (`set`/`merge`/`prepend`) at names the type
table marks `path`. `inherit` and `sanitise` are exempt — the value is the
host's. `EDITOR=vim` is out of scope. `TZ` is out of scope of this rule *and*
unreachable anyway (CALL 3).

Mechanics, all six rows of §2.5's table:

| question | implementation |
|---|---|
| exact or coverage? | coverage, downward, no depth limit: lexical `/`-boundary containment on guest paths |
| symlinks? | resolved first, never a grant themselves — rewrite the value through the profile's own symlink map with `resolveLinkForEnv`, then check |
| includes? | **the transitive closure, yes. The selected set, no.** |
| `optional`? | checked against profile **TEXT**, not resolved mounts |
| `host:guest`? | the **guest** side |
| refuse or warn? | **refuse**, for profiles |

Build, once before the fold, `map[profile][]guestSpec` = the expanded `ro`/`rw`/
`tmpfs` guest paths of that profile *and its `include` closure over `reg`*, plus
the same closure's `symlink` map. Reuse `expand()` (`resolve.go:683`).

**Why the closure but not the selected set, and why it needs a named test.** If
the selected set counted, `resolve([a])` could refuse what `resolve([a,b])`
admits — adding a profile would change another profile's verdict. Not a
visibility break, but one step from it, and it is one edit away. Test name:
`TestCouplingVerdictDoesNotDependOnTheSelectedSet`.

Accepted cost, from §2.5: coverage makes `@home` a rubber stamp for all of
`$HOME`, and `@podman-socket` includes `sys`+`home` so the check is vacuous for
it under `/usr` and `{home}`. Correct — that profile *did* bring them, on a line
`--dry-run` and `$SNUG_PROFILES` both render. A false positive yields a variable
naming an empty directory: a usability bug, not a hole.

**Golden diff:** `refusals.txt` gains §2.7 case 4.

### Step 9 — `--dry-run` renders §2.8

`cmd/snug/dryrun.go:83-92` becomes the §2.8 block: per-entry verb and profile,
list bands top-to-bottom in resolution order, `sanitise` drops **named not
counted**.

```
ENVIRONMENT  (--clearenv, then:)
  EDITOR           vim                             inherit   @claude
  HOME             /home/michal                    (snug)
  PATH             /opt/bin                        prepend   mytools
                   /home/michal/.cargo/bin         merge     @rust
                   /run/snug/bin                   (snug)    podman stub
                   /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  @pkgconfig
                   (2 host entries dropped: /opt/x/lib/pkgconfig, /srv/pkgconfig)
```

The `PATH` bands read top to bottom in resolution order, so **the rendering is
the §2.4 diagram**. If the two ever disagree, the renderer is lying — say that
in the code comment.

Plus §4.2's repair, which is the other half of this step: **mark any authored
value whose path nothing grants.** `snug --dry-run --no-defaults -p @parent-ro .`
prints `HOME`, `SHELL` and four `PATH` entries naming directories that do not
exist inside, today with no comment. The mark is computed against the
**resolved mounts** (unlike §2.5's text-only check) and that asymmetry is
deliberate: refusing must not be host-dependent, but *marking* may be, and here
it must be, or the mark is not about the actual sandbox. Render it as
`← not granted` on the line.

Do **not** convert this into a refusal. §4.3: `PATH` and `HOME` have no safe
absent state — leave `PATH` unset and bash substitutes `DEFAULT_PATH_VALUE`,
which ends in `.`, which is the target. §4.2's earlier draft concluded the
opposite and would have converted a confusion bug into a reachable hole.

**Golden diff:** `cmd/snug/testdata/env.*.txt` is rewritten wholesale. This is
the largest diff in the change and the one a human will actually read.

### Step 10 — `base.toml`

- `[profile.home.environ.set]` — `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`,
  `XDG_STATE_HOME`, `XDG_DATA_HOME` (§1.2).
- **`@home` must also gain `{home}/.local/share` to its `tmpfs` list**
  (`base.toml:112` has four entries; §1.2's worked profile has five). Without it
  `XDG_DATA_HOME` fails step 8's coupling check — which is the rule doing its
  job on the very first profile that uses it. This is a real grant change and
  needs its own abuse sentence in the file.
- `@claude`: `env = [...]` (`base.toml:269`) → `[profile.claude.environ.inherit]`;
  `path = [...]` (`base.toml:277`) → `[profile.claude.environ.merge] PATH = [...]`.
- Every new grant gets the abuse sentence, per the working agreement. For the
  XDG block: *"a hostile process inside the sandbox can use these to make any
  tool that honours XDG write its state into the ephemeral tmpfs — which is the
  point; nothing here reaches a host path, and each names a directory `@home`
  itself creates."* For `ANTHROPIC_API_KEY` under `inherit`, the existing
  profile comment already carries it; make sure it survives the move.

**Golden diff:** `cmd/snug/testdata/env.*.txt` — four new `XDG_*` lines in every
selection including `@home`, which is all of them. Plus one new `--tmpfs` line
in `internal/policy/testdata/*.bwrap.txt` **if and only if** `testRegistry()`'s
`@home` fixture is updated to match; it should be, or the fake registry starts
describing a sandbox no user gets (`resolve_test.go:88`).

### Step 11 — `snug profile show` renders the environ block

`cmd/snug/config.go:241` currently does `show("env", p.Env)` and — worth
noticing — never rendered `path` at all. Replace with a block rendering all
five verbs. `snug profile show` is part of §2.3's argument for parse-time
checking; it should also *display* what it checked.

### Step 12 — retire `env` and `path`

**§4.6(b) first, and this is why.** Today `Load()` (`internal/profile/file.go:223`)
returns on the first bad file, so one unparseable file in `profiles.d` takes the
whole registry down, `@sys` included, and `snug profile list` — the one command
that would tell the user what still works — is exactly what stops working. This
change *adds a whole new class of parse error* (bad verb/type agreement, bad
name, retired key), so it converts (b) from a latent outage into the expected
outcome of the migration. Turning `env = [...]` into a hard error while one such
file kills `@sys` is not an acceptable sequence.

The shape of (b)'s fix, from the design: **diagnostic commands (`profile list`,
`profile show`, `config`, `doctor`) report the broken file loudly and continue
with what did load; anything that runs a sandbox stays fatal.** One caveat or it
becomes a silent downgrade — `unknown profile` must consult the skipped-file
record, so `-p thatprofile` says *"the file defining it failed to parse"* and not
*"unknown profile"*.

Then retire, in the shape of `@null` and `publish_auto`. Note that
`publish_auto` was retired by *deleting the struct field* and letting
`DisallowUnknownFields` fire — that yields the generic "unknown key" message,
which is **not** what §6 asks for here ("a named error pointing at the
replacement"). So keep `Env`/`Path` as fields on `rawProfile` and error
explicitly when non-empty:

```
snug: <file>: profile "x" uses `env = [...]`, which snug no longer accepts.
       It is now [profile.x.environ.inherit] with NAME = true per variable:
         [profile.x.environ.inherit]
         EDITOR = true
       The prefix changed deliberately: a silently CHANGED meaning is worse than
       a removed key.
```

```
snug: <file>: profile "x" uses `path = [...]`, which snug no longer accepts.
       It is now [profile.x.environ.merge] on PATH:
         [profile.x.environ.merge]
         PATH = ["{home}/.local/bin"]
       Use environ.prepend instead if you need to be ahead of every other
       profile — at most one profile may hold the front of a variable.
```

Tests: `TestRetiredEnvKeyNamesTheFix`, `TestRetiredPathKeyNamesTheFix`, each with
a **positive control** (the replacement spelling parses) — otherwise the refusal
reads as a ban on the capability rather than on the retired spelling, which is
exactly the control `TestRetiredPublishAutoIsAHardError` already carries.

---

## 4. Golden-file impact, collected

| file | step | what the diff should look like |
|---|---|---|
| `cmd/snug/testdata/env.*.txt` (**new**) | 1 | created, capturing today's flat output |
| `internal/policy/testdata/refusals.txt` | 3,4,6,8,12 | grows only; no existing entry may change text |
| `cmd/snug/testdata/env.*.txt` | 3 | one line: `NO_COLOR=` in the `@claude` selection |
| `cmd/snug/testdata/env.*.txt` | 9 | rewritten wholesale — the §2.8 layout. **The review artifact for the whole change.** |
| `cmd/snug/testdata/env.*.txt` | 10 | four `XDG_*` lines per selection |
| `internal/policy/testdata/*.bwrap.txt` | 10 | one `--tmpfs /home/u/.local/share` line, *if* the fixture `@home` is updated to match the real one |
| `internal/policy/testdata/*.bwrap.txt` | all others | **must not move.** The `--setenv` block is `--clearenv` plus one line per present variable, sorted, exactly as today |

Steps 2 and 5 produce no golden diff, and both say so in their commit message
with the reason (pure refactor; parser only, nothing selects the syntax yet).
Every other step produces one. A step in this plan that unexpectedly produces
*no* diff has not been tested.

---

## 5. What must NOT change

1. **snug authors `HOME`, `PATH` and `SHELL` unconditionally.** §4.2/§4.3: there
   is no safe absent state. Unset `PATH` and bash substitutes a compiled-in
   default ending in `.`, which inside snug is the target — a hostile process
   drops a file named `git` in the project root and it runs. `HOME` is where the
   identity generator writes `~/.gitconfig`, `~/.ssh/config` and `known_hosts`,
   so a profile able to move it silently defeats identity pinning. The repair
   for the confusion is to **mark** (step 9), never to stop authoring.
2. **`--clearenv` stays, first, unconditional** (`bwrap.go:122`). And
   `--unsetenv` is never emitted.
3. **`cmd.Env = []string{}`** in `internal/sandbox/exec.go:140` and
   `netns.go:69`. A guarantee about the payload's environment is not a guarantee
   about the sandbox's PID 1; that hole leaked 106 host variables once.
4. **`PS1` stays snug's and stays distinctive.** Not profile-writable, and
   `inherit PS1` refused — command substitution fires before the user types
   anything (§3.5). It is not a security control and must not be described as
   one; it is the answer to "am I inside?", which is the question where guessing
   wrong is expensive.
5. **`SNUG`, `SNUG_PROFILES`, `SNUG_TARGET` stay snug's.** They are what
   `--dry-run` and the injected `~/.claude/CLAUDE.md` are read against; a profile
   that could set them can lie to the artifacts a human reads to decide whether
   to trust the sandbox.
6. **`internal/policy` stays pure.** No filesystem for the coupling check — §2.5
   is explicit: *"if anyone proposes an existence check, that is where a
   filesystem fact would have to travel, and the answer is no."*
7. **No `unset`, no `append`-with-removal, no priority field, no ordering
   dependence between profiles.** §5's three-way survey exists so that a
   proposal borrowing a vocabulary by analogy is read for what it imports.
   Read any proposal asking *"what is the `unset` here?"*; the answer must be
   *there isn't one*.
8. **`Policy.Replace` / `Mount.Authored` semantics.** Untouched. `AuthorEnv` is
   modelled on it, not a second mechanism for it.
9. **`BwrapFlags` contains no `--`** (existing test). Nothing in this work
   appends to the argv after the memfd snapshot.
10. **Order-independence of the whole resolved policy.** `resolve([a,b]) ==
    resolve([b,a])`, byte-for-byte through `canon()`, with the env structure
    rendered in full.

---

## 6. §4.6's three live bugs

**(a) A variable set to the empty string is silently dropped — IN SCOPE, step 3.**
`resolve.go:283`'s `v != ""` makes set-but-empty indistinguishable from unset,
so `NO_COLOR=` means "disable colour" and snug silently re-enables it. In scope
for three independent reasons: it shares its one-line fix (`Environ.LookupEnv`)
with §4.4's host-conditional refusal; `environ.inherit` cannot be implemented
correctly without presence semantics; and §3.2's flag row is unimplementable
without it. Doing it separately would mean writing the same line twice.

**(b) One unparseable file disables the whole registry — OUT of scope as an
independent fix, but a HARD PREREQUISITE for step 12.** It is a pre-existing bug
and nothing in the format depends on it. But this work adds a new class of parse
error to files users already have, and step 12 turns `env = [...]` — a key that
is in shipped documentation and in real `profiles.d` files — into a hard error.
With (b) unfixed, that sequence means one stale user file takes down `@sys` and
`snug profile list` at the same moment. So: not part of the format, sequenced
immediately before the migration, with its own commit and its own test. If
schedule pressure forces a cut, cut step 12, never (b).

**(c) `PATH` entries are not deduplicated, and an ungranted directory is accepted
in silence — IN SCOPE, split across steps 6 and 8.** The two halves are the
format's own rules, not adjacent bugs: dedup-to-earliest-band is §2.6 and is
what makes `prepend`'s guarantee literally true, and the silent acceptance of
`/nonexistent/bin` is exactly what §2.5's coupling rule changes. Implementing
bands without dedup would ship §2.6 half-done.

**Also recorded, not fixed:** §4.5 — the environment outranks a pinned config
file (`GIT_CONFIG_KEY_0=core.sshCommand` beats a clean `GIT_CONFIG_GLOBAL`).
Untouched by this work and it wants its own investigation. `environ.set` does
**not** make it worse (a profile is reviewed text in a trusted layer), but a
reader will assume it does; keep the `TODO.md` entry current so nobody
"discovers" it as a regression of this change.

---

## 7. Risks, ranked, and what to tell `redteam`

**1. `environ.set` is the only genuinely new power here** — the design says so
itself. A profile can now write an arbitrary scalar into the environment of every
process in the sandbox. The entire containment argument rests on two mechanisms:
the `SnugOwnedEnv` refusal being *complete* (§1.4's AST test) and the
`forbiddenEnv` name+prefix table being *right*. Compounding it: invariant 3 is
already weak here — `$XDG_CONFIG_HOME/snug/profiles.d` is trusted
unconditionally, so pointing that variable at a checked-out repo loads that
repo's profiles.

*Attack this first.* Reach a snug-owned or forbidden name anyway: case
variation (`Path`, `ld_preload`); a prefix gap (`LD` with no underscore,
`GIT_CONFIG` exactly, `SNUGX`); Unicode lookalikes and non-ASCII that the
grammar should already refuse; trailing NUL or newline; whitespace padding;
`environ.set` on `DOCKER_HOST = "ssh://you@host/…"` on a run with no podman
profile (§3.2: `ssh://` makes the client `exec ssh`); the same for
`CONTAINER_HOST`; `GIT_CONFIG_COUNT`/`KEY_0`/`VALUE_0` reaching
`core.sshCommand`; and the whole chain via `XDG_CONFIG_HOME` pointed into a
hostile repo.

**2. The `=` smuggle and the name grammar.** `--setenv 'A=B' c` is refused by
bwrap (measured, §0) — but that is a backstop with an unusable message, and the
grammar is what has to hold. Try `"PATH=/evil:" = "x"`, an empty key, a key that
is only digits, and a key with an embedded newline reaching the argv.

**3. `sanitise` producing an empty element, or an empty `PATH`.** §4.3 is
explicit that this is *the one place where getting it wrong adds a hole rather
than failing to close one*. `sandbox-tester` owes a named regression test: sanitise
a `PATH` down to one surviving element, assert no empty element anywhere in the
rendered value, **with a positive control** — a planted binary in the target *is*
found when an empty element is present, so the test cannot pass on a sandbox that
never started. Then have `redteam` try to reach that state from a profile.

**4. Fold-order dependence in the conflict machinery.** The `set`/`prepend`
claim accumulator is the newest thing in the resolver that could make
`resolve([a,b]) != resolve([b,a])`. `TestResolveIsCommutative` covers it only if
the fixtures use all five verbs (§1.3) — check the fixtures before trusting the
green.

**5. §4.6(b) amplification** — covered above; the risk is operational, not a
sandbox escape, but it is the one that produces "snug stopped working entirely"
on a user's machine.

**6. The multi-line inline `environ = {…}` form parses here and cannot be
detected post-decode.** Portability trap, not a hole. Recorded in `TODO.md`; no
comment anywhere may claim it is refused.

**7. §4.1's untested precondition.** *"`snug . -- podman` resolves against the
sandbox `PATH`, not the host"* — measured true, and nothing tests it. A refactor
to a host-side `exec.LookPath` would leave every test green and make the negative
case *succeed*, which would read like a feature. `sandbox-tester` owes: a binary
only on the host `PATH` must not run; one in a profile's directory must; a name
in both must resolve to the profile's.

---

## 8. Definition of done

The five in CLAUDE.md, in order. Specifically for this change:

- `make gate` green at every step, not just the last.
- `make integration` with `SNUG_REQUIRE_SANDBOX=1`, plus the new named tests from
  §7 items 3 and 7, and the design's own list: second `prepend` refused with a
  positive control; `--dry-run` renders §2.8; env commutativity across all five
  verbs.
- `VERIFY.md` gains the by-hand equivalent — at minimum `snug --dry-run` showing
  the `ENVIRONMENT` block with provenance, and the `--no-defaults -p @parent-ro`
  case showing the §4.2 marks.
- `redteam` runs before it lands. This changes the policy model; it is not
  optional.
- Every confirmed finding fixed or written into `TODO.md` with its severity, and
  every one becomes a permanent named regression test.
