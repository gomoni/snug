# Environment variables — the configuration format

**Status: shipped.** `internal/policy/env*.go` is the implementation and the
truth; this document is the format and the evidence behind each rule. §1–§3
format, §4 the measurements that forced each rule, §5 what was considered and
rejected — read that one only to reopen something. **§6 is genuinely open**:
`env = [...]` and `path = [...]` are still live keys (`internal/profile/file.go`)
and both are slated for a named error, not a silent change of meaning.

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
| `environ.prepend` | profile | **lists** | at most one *value* per variable across the selected set; identical claims agree, **different ones are an error** |
| `environ.inherit` | profile | any | copy host value verbatim |
| `environ.sanitise` | profile | **lists** | copy host value, keep only elements policy grants |

There is no sixth key. `environ.declare` — a NAME SET licensing `set` and
`inherit` for a name snug's roster has no row for — was designed, built and
removed before it shipped: `environ.set MY_VAR = "x"` in a profile with a name, a
file path and an author already IS that author declaring the name, `EnvEntry.From`
records it and `--dry-run` renders it, so the hatch made them sign twice. See
§2.1 for what governs an unrostered name instead.

**And a sixth thing that is not a verb: snug's own authorship.** **snug is not
bound by the verbs' rules when writing its own variables.** The list is twenty
keys, and it must be **derived from the code rather than retyped** — an earlier
draft retyped it, gave the count as nineteen, and missed six:

```
resolve.go   HOME SHELL USER LOGNAME TMPDIR PS1 PATH TERM TZ LANG
             SNUG SNUG_PROFILES SNUG_TARGET GIT_CONFIG_GLOBAL
identity.go  SSH_AUTH_SOCK GH_CONFIG_DIR GH_HOST          ← written AFTER Resolve
container.go CONTAINER_HOST DOCKER_HOST DOCKER_BUILDKIT   ← written AFTER Resolve
```

**Ownership refuses the verbs that REPLACE a value, not every verb.** An earlier
draft said flatly "no profile may write a name snug writes" and listed `PATH` —
which contradicts §1.2's `@rust`, §2.4's band diagram and §2.8's rendering, all
of which require `environ.merge PATH` to be legal. The reading under which every
one of those is true:

- **For a scalar, that is every verb a profile has.** `HOME`, `SHELL`, `PS1`,
  `SNUG*` and the rest are refused outright, because writing them means replacing
  them.
- **For a list, snug's authorship is a *band* (§2.4), so contributing is not
  replacing.** `merge`, `prepend` and `sanitise` add a band ahead of snug's base
  and displace nothing; `set` and `inherit` are refused by the *type* rules,
  which already say a list takes neither.

What stays unconditional is **the base `PATH`**, not the variable. `PATH` is the
only list among the twenty owned names — verified — so the exemption is exactly
one variable wide, and `TestPATHIsSharedButNotReplaceable` pins both halves.

The six post-`Resolve` writers are the dangerous half. A hand-maintained list
that omits them makes `environ.set DOCKER_HOST = "ssh://attacker/..."` legal on
any run where no podman profile is selected — and §3.2 records that `ssh://`
makes the client **exec `ssh`**. So the refusal must be asserted equal to the set
of keys snug actually writes, with a test that fails when a new writer appears.

This is not an exemption invented for convenience; it is the distinction the
codebase already draws for mounts and CLAUDE.md already states: *a profile
mounting over another profile's grant is masking and is refused; snug replacing a
path with its own generated content is replacement and is allowed.* `Mount` has
an `Authored` field and `Policy.Replace` is its single writer. The environment
needs the same, and omitting it is easy to do — which
made the format contradict itself in three places (§1.2 note, §2.5, §4.2).

Nested, not five root keys. Written as table headers, not inline tables. Three
reasons, heaviest first — and one that was claimed and does not hold.

**(a) Keep root namespace nouns.** `environ` sit beside `ro`, `rw`, `tmpfs`, `symlink`. Verbs one level down describe operations *within* a thing, not compete with grants for root.

**(b) Unknown verb refused for free.** `environ` = struct with known fields, so `DisallowUnknownFields` catch `environ.deny` exactly as it catch unknown root key. "A negation key cannot be smuggled in" apply one level down, no new code.

**(c) `append` later cost a nested field, not a sixth root key.**

**"The flat spelling does not parse" is FALSE, and it is a measurement taken
against the wrong parser.** Multi-line inline tables are invalid in **TOML 1.0**
and `python3 -m tomllib` refuses them — but snug uses `go-toml/v2 v2.4.3`, which
**accepts** them. Check the parser snug actually links, not the spec:

```
environ-set = {                 python3 tomllib:      Invalid initial character for a key part
  XDG_CONFIG_HOME = "...",      go-toml/v2 v2.4.3:    accepted, parses to a nested map
  XDG_CACHE_HOME  = "...",
}
```

**Check the version the project actually builds with, not the one a scratch
module resolves to** — a scratch module pins whatever it likes, and a
"verification" against v2.2.3 says nothing about the version in `go.mod`.

What survives is smaller and worth stating on its own: the flat form is
spec-invalid but *silently accepted here*, so a profile written that way works on
this host and breaks on any TOML 1.0 parser. That is a portability trap, not a
parse error — a weaker argument for nesting than (a)–(c), and an argument for
snug rejecting the form deliberately rather than inheriting whatever the
dependency allows this month.

Greppability survive — why verbs beat inferring operation from value type: `grep -rn 'environ.prepend' ~/.config/snug/profiles.d/` find every ordered claim on host, because header spell whole path. That would **not** hold for nested inline form.

### 1.2 Worked profiles

```toml
# NOTE: @sys sets NO environment. SHELL and the four base PATH entries are
# snug's (§1.1), not a profile's — showing them here contradicts §1.1. A profile
# that wants a tool on PATH grants the directory and merges it, like @rust below.
[profile.sys]
description = "The system's binaries, libraries and a curated /etc."
ro = ["/usr", "/etc/ssl", "/etc/pki", "/etc/passwd"]
symlink = [{ at = "/bin", target = "usr/bin" }, { at = "/sbin", target = "usr/sbin" }]


[profile.rust]
description = "cargo's binaries on PATH"
ro = ["{home}/.cargo/bin"]

[profile.rust.environ.merge]
PATH = ["{home}/.cargo/bin"]


[profile.home]
description = "$HOME is an empty tmpfs at the host path. Writable, ephemeral."
tmpfs = ["{home}", "{home}/.config", "{home}/.cache",
         "{home}/.local/state", "{home}/.local/share"]

[profile.home.environ.set]
XDG_CONFIG_HOME = "{home}/.config"
XDG_CACHE_HOME  = "{home}/.cache"
XDG_STATE_HOME  = "{home}/.local/state"
XDG_DATA_HOME   = "{home}/.local/share"


[profile.claude]
description = "Claude Code's configuration and credentials"

[profile.claude.environ.inherit]
ANTHROPIC_API_KEY = true
EDITOR            = true
```

```toml
# ~/.config/snug/config.toml — preferences, no grants
defaults = ["@sys", "@home", "@cwd-rw", "@parent-ro"]
prompt   = "{lock} snug[{profiles}]:{cwd}$ "
```

Three things the layout does:

**`@home` binds authorship to the grant.** Variables sit next to the `tmpfs` that
creates the directories. Rule: every path a *profile* writes must be granted by
that same profile. This is a rule about profiles only — snug's own variables
(§1.1) are not subject to it, which is what makes `HOME` and the base `PATH`
still unconditional. See §4.2.

**There is deliberately no `@stubs-in-path` profile.** Two drafts proposed one —
first prepending `/snug/bin`, then as a switch granting nothing. Both are
wrong, and the second instructively so: **the abuse sentence cannot be written.**
The stub is read-only, snug-generated, refuses everything outside its allowlist,
and `/usr/bin/podman` is untouched and still reachable by absolute path. A profile
that is not a grant is what the `@null` decision retired — *"a profile that grants
nothing is a preference wearing a profile's clothes"* — and it would appear in
`$SNUG_PROFILES` and `snug profile tree` as though it were a hole.

It also adds nothing. The two existing gates already select the exact
intersection, measured four ways: a genuine podman binary, no stub; a shim but no
podman profile, no stub; no podman at all, no stub plus a named warning; both
conditions, stub. A third condition ANDed on adds no discrimination — only a way
to break it, because `defaults = [...]` **replaces** the built-in list wholesale,
so anyone who trims their defaults silently loses the stub and gets back the
cryptic host-shim failure. That is a silent-downgrade path the profile would
create and that does not exist today.

What the profile was reaching for is *telling the human*, and `--dry-run` already
does it: a `COMMANDS` block naming the shim, the reason, the allowlist and the
read-only property, plus `exec /snug/bin/podman (snug)` in `FILESYSTEM`. §2.8
finishes the job by giving the `PATH` line the same provenance. **The answer is
provenance in `--dry-run`, not a name in `$SNUG_PROFILES`.**

**`@claude` keeps `inherit`, and moving `inherit`/`sanitise` to `config.toml`
is refused.** It is a regression: `ANTHROPIC_API_KEY`
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
environ.merge on EDITOR  →  EDITOR is a scalar, not a list — use environ.set.
environ.set   on PATH    →  PATH is a list — use environ.merge, or environ.prepend
                            if the order matters. environ.set on a list would
                            replace every other profile's entries, which snug
                            does not allow.
```

~~Unknown name default to **scalar** — conservative reading: a scalar merges with
nothing, so it can only conflict, never silently combine.~~ **Amended by issue
#44.** "Conservative" was the wrong word: the table reported a TYPE for a name it
had never been taught, and three red-team rounds found three sets of names it had
not been taught about while the space it was chasing ("every variable some tool,
in some version, turns into an exec") stayed unbounded. `envTypes` is now the
ROSTER, and it answers one question — **what IS this variable** — for two kinds
of profile:

- **A profile snug SHIPS may write only a name with a row.** Enforced in
  `internal/profile`'s `mark` — the one place the `@` mark is added, for the same
  reason the mark itself lives there — and expressed with
  `policy.IsUncheckedEnv`, the predicate the screens draw their mark from, so the
  rule reads *a profile snug ships may not hand over a name the screen would mark
  unchecked*. A roster row is where the sentence saying what the variable lets a
  tool DO gets reviewed, and a shipped profile owes that review because there is
  no human standing behind it.
- **A profile a HUMAN wrote may write a name with no row**, at `set` and
  `inherit`. It is carried, and every entry it produces renders `← unchecked` in
  `--dry-run` and in `snug profile show`, from the same predicate. Nothing about
  the name is claimed, and the screens say so.

The three LIST verbs take no name with no row, from anybody: `merge`, `prepend`
and `sanitise` need the separator and the meaning of an empty element, which is
exactly what a roster row carries and a profile cannot supply — inferring them
from the shape of a value is what §3 exists not to do. Everything else applies to
an unrostered name unchanged: the grammar, `checkEnvOwnership`, and the
control-character rule on the value. See `internal/policy/envtypes.go` — the code
is the list, and this paragraph is a summary of it.

**`inherit` is refused for every list variable, without exception.** Copying a
host search path wholesale imports directories that do not exist inside — what
§2.7 case 4 refuses for `set`, and what `sanitise` exists to do properly.
`inherit` is the scalar form; `sanitise` is the list form. It is a rule, not a
per-row column — carrying it on every table row is how it gets lost in a
rewrite.

**`forbiddenEnv` is gone. It is `envNotes`, and it refuses nothing** — see §2.9,
which is the whole of the argument. The table survived intact, name for name and
measurement for measurement; what changed is the sink. A name in it is
**annotated** on `--dry-run` and on `snug profile show` instead of being refused
at parse time, because snug has only allowlists and the author of a profile is a
human on the trusted side of the boundary. The reasoning that put each name in
the table is exactly why each name carries a sentence today.

**The split by verb is what carries this, and it matters more here than in a
refusal.** `set` carries a
value from a reviewable file in the trusted profile layer; `inherit` carries
whatever the host process had at launch, put there by whatever invoked snug.
**`inherit` is a hole punched in `--clearenv`; `set` is not.** A refusal made
that difference visible for free. With neither refused, the difference IS the
sentence: `envNote` carries one string for the authored verbs and one for the
host verbs, and the middle bucket — `BASH_ENV`, `ENV`, `PYTHONSTARTUP`,
`PYTHONBREAKPOINT`, `LESSOPEN` — is where they differ:
`BASH_ENV = "{home}/.snug-init"` with the file granted by the same profile is
coherent and reviewable, while the same name inherited names a file chosen on the
host, outside any profile. A note table flattened to one string per name would
lose exactly what `forbidKind` carried.

**Annotated at every verb** are the names snug owns (which are *also* refused by
ownership, which is stronger), the prefixes `LD_*`, `BASH_FUNC_*` and
`GIT_CONFIG_*`, the ten glibc strips §4.4 takes from `ld.so(8)`, the git and ssh
transport hooks (`GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`,
`GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_EXEC_PATH`, `GIT_EXTERNAL_DIFF`, `GIT_EDITOR`,
`GIT_SEQUENCE_EDITOR`), `GIT_PAGER`, `GIT_TEMPLATE_DIR`, `GIT_DIR` and
`GIT_COMMON_DIR` (a directory whose hooks are code — `GIT_COMMON_DIR` was the
sibling `GIT_DIR`/`GIT_TEMPLATE_DIR` missed the first time),
`GIT_ALLOW_PROTOCOL`/`GIT_PROTOCOL_FROM_USER` (re-enabling the `ext::` transport
is the transport), the interpreter option channels (`JAVA_TOOL_OPTIONS`,
`_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `RUBYOPT`), the prompt hooks other than
`PS1` (`PS0`, `PS2`, `PS3`, `PS4`, `PROMPT_COMMAND`), the compiler/toolchain
wrapper class found by a second red-team pass — `MAKEFLAGS`, `GOFLAGS`, `CC`,
`TAR_OPTIONS`, `RSYNC_RSH`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`
and the `CARGO_*` prefix (carved out at `CARGO_HOME`, the one pointer in that
namespace) — and the interpreter-hook class **promoted out of the middle bucket**
by the same pass: `PYTHONPATH`, `PYTHONUSERBASE`, `NODE_OPTIONS` and `PERL5OPT`
all run unconditionally on interpreter start (`sitecustomize.py`/
`usercustomize.py`, `--require`, `-M`), which is a stronger claim than
"reviewable as set" survives — measured, not reasoned about.

Two of those are worth reading twice, because the annotation model changed their
reach and their reach only. `PYTHONPATH` is a **list**: `forbidBoth` would refuse
`environ.merge`/`environ.prepend` on it as a side effect of refusing the name,
but it is mergeable, so those two verbs are legal and annotated — the **only
list-verb capability the annotation model adds**. `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `CDPATH` and `GOFLAGS` gained nothing at all: they are lists
the roster marks neither mergeable nor sanitisable, so every verb is still
refused — on TYPE grounds, which is snug declining an operation rather than
denying anyone anything.

**Annotated differently at `inherit`** is the prefix `PIP_*` — §4.5's finding
that a tool's environment outranks the file snug generated for it, and nothing
under it has been measured to exec a program (unlike `npm_config_*`, below).
`npm_config_*` started in that bucket and was **promoted to the same sentence at
every verb**, carved out at `NPM_CONFIG_USERCONFIG`, for the identical reason
`CARGO_*` was: `npm_config_script_shell`/`npm_config_node_gyp` name a program npm
executes, not merely a config value that outranks a file — measured in every case
spelling npm's own case-insensitive lookup honours, which is also why a single
shared table (`prefixCaseFold`) decides case-folding for every prefix in both the
annotation table and the sink-sweep predicate that reads the same names
(`policy.IsInlineConfigEnv`) — two tables each keeping an independent copy of
"does this tool fold case" is how they drift apart. The
carve-outs are the POINTERS, and both tables now name the same set, asserted by
`TestPointerExemptionsAgreeBetweenTheTwoTables`: a pointer gets no family
sentence at the verbs that AUTHOR it, because authoring one is the mechanism
"generate, don't bind" asks for.

**`EDITOR`/`VISUAL`/`PAGER` are annotated, and that is the answer to the open
issue, not a deferral.** `GIT_EDITOR`'s documented fallback chain is `GIT_EDITOR`
→ `core.editor` → `VISUAL` → `EDITOR`, so refusing the `GIT_*` spellings never
closed a class — it closed the invisible half of one. All six spellings carry a
sentence now, which is the only form of "closing" that does not withdraw a grant
`@claude` uses on every run. §3.2's row and the decision below it stand;
https://github.com/gomoni/snug/issues/35 and
https://github.com/gomoni/snug/issues/45 are both answered by the annotation.

The git group is where the split earns its keep, and it was not got right first
time: the red team found `GIT_SSH` passing while `GIT_SSH_COMMAND` sat two
entries above it in the same table, and used it to hijack a real `git fetch` in a
sandbox whose ssh identity a *different* profile had pinned. The rule is not "the
newest spelling of the name" — it is **the value is code**, and now: *say so, at
every spelling*. A missing sentence is the modern shape of that same defect. The
type table says what may be *merged*; the annotation table says what a tool DOES
with the value, at any type — `LD_PRELOAD` is a list and is annotated. Two
tables, both read, neither replacing the other. Collapsing them gets two wrong
answers at once (add `PS1`, drop `LD_LIBRARY_PATH`). §4.4 is a list to be
**extended**, not retired.

### 2.2 snug never splits a string on a separator

String = exactly one element. Profile cannot write `"/usr/bin:"`, cannot produce `"/usr/bin::/bin"` by dropping element, cannot smuggle `;` into `LD_LIBRARY_PATH`. snug join with right separator for variable and refuse empty element.

**If nothing survives a `sanitise`, the variable is UNSET, not set empty.** §4.3
is why: an empty `PATH` is the current directory, and an empty `LD_LIBRARY_PATH`
is not the same thing as an absent one to the loader.

Close §4.3 hazards by construction, not by implementer remembering. `environ.prepend` with `PATH = "/opt/bin"` = one-element prepend, not string to parse; several at once = array, and order within one profile unambiguous because one profile wrote it.

### 2.3 A variable name must look like a variable name

TOML keys are arbitrary strings, so nothing in the *syntax* stops
`[profile.x.environ.set]` carrying `"A=B" = "c"`, an empty key, or a name with a
newline in it — and those go straight to `--setenv NAME VALUE`. Profile names
have `checkName` for precisely this reason; variable names need the same.

The rule, matching what `execve(2)` and every shell already assume:

```
name  ::=  [A-Za-z_][A-Za-z0-9_]*
```

Refused, each with its own message: an empty name; anything containing `=`, NUL
or a newline; a leading digit; and any name snug owns (§1.1). **Checked at parse
time**, next to `checkName` and `DisallowUnknownFields`, so `snug profile show`
reports it too and the verdict never depends on the invoking host.

*Note which refusals these are: the ones about what a name would BREAK (the
wire format, a screen row), not about what a human may have. `forbiddenEnv` is
not consulted — §2.9.*

`=` is the one worth naming separately. `NAME=VALUE` is the wire format of the
environment itself, so a key containing `=` is not a weird name — it is a second
assignment smuggled inside the first, and the only reason it is not exploitable
today is that no key accepts a variable name yet.

### 2.4 What `prepend` actually guarantees, and what it does not

A list variable is rendered in **bands**, and the band is structural — nothing a
profile writes can change which band its entry lands in:

```
prepend (at most one profile)  →  merge (sorted)  →  sanitise (host order, filtered)
                               →  snug's generated  →  base
```

This is what `resolve.go` does today, with `prepend` added in front.

**Be precise about the guarantee; the obvious reading overclaims it.**
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

### 2.5 The grant-coupling rule, decided

§1.2 says a profile must grant the paths it names. A review showed the loose
version is unimplementable, and the fix is a reframing rather than a detail:

> **It is a coupling rule, not an existence check.** The profile that names a
> path must be the profile that put a node on the chain to it, so a reviewer
> reading one profile sees both acts. It cannot prove the path exists —
> `internal/policy` may not touch the filesystem, a `tmpfs` grant creates an
> *empty* directory, and a bind's contents are host state.

Put that in the code comment, because otherwise someone will cite the check as a
boundary. **It is not one.** The value is inert, and the payload can set any
variable it likes once running. It stops a profile *lying*; it does not stop
anything *reaching*.

Scope: it binds only values a profile **writes** (`set`/`merge`/`prepend`), and
only for names the type table marks path-valued. `EDITOR=vim` is out of scope.
`TZ` is out of scope *of this rule* — `Asia/Tokyo` is a zoneinfo name, not a path
— and needs its own guard ("setting `TZ` requires granting
`/usr/share/zoneinfo`"), which is a different check with a different message.

| question | decision |
|---|---|
| exact path or coverage? | **coverage, downward, no depth limit** — lexical `/`-boundary containment on guest paths |
| do `symlink` grants count? | **resolved first, never a grant themselves** — rewrite the value through the profile's symlink map, then check coverage |
| do `include`d grants count? | **yes, the transitive closure. The selected set does NOT.** |
| `optional` grants? | **checked against profile TEXT, not resolved mounts** |
| `host:guest` specs? | **the guest side** |
| refuse or warn? | **refuse, for profiles** |

**Why coverage and not exact match.** `SHELL=/usr/bin/bash` against `ro=["/usr"]`
must pass, and there is no principled depth at which to stop. "Granting `/` buys
everything" is already moot: `Validate` refuses a non-authored mount at `/`.
Coverage does make `@home` a rubber stamp for all of `$HOME` — accepted, because
`environ` cannot create a mount, so a false positive yields a variable naming an
empty directory: a usability bug, not a hole. Exact match would force authors to
write `ro` grants they do not want, and a rule shipped profiles cannot satisfy
gets a carve-out.

**Why the include closure but not the selected set.** `include` is the profile's
own text, static and host-independent. If the selected set counted, `resolve([a])`
could refuse what `resolve([a,b])` admits — adding a profile would change another
profile's verdict. Not a visibility break, but one step from it, and it must be
refused **by name with a test**, because it is one edit away. The cost is real:
`@podman-socket` includes `sys`+`home`, so for paths under `/usr` and `{home}`
the check is vacuous for it. Correct — that profile *did* bring them, on a line
`--dry-run` and `$SNUG_PROFILES` both render.

**Why profile text, not resolved mounts.** An absent `optional` grant produces no
mount at all, and `@claude` marks **every** `ro` entry optional — so checking
resolved mounts would make a profile's *legality* host-dependent. That is exactly
the §4.4 defect, adopted as a design. Text-only also lets `snug profile show`
render a verdict with no target.

**Why refuse for profiles but only mark for snug (§4.2).** Not favouritism —
different floors. `HOME`/`PATH`/`SHELL` have **no safe absent state** (§4.3), so
refusing would make the sandbox worse. A profile has no such floor: refusing
`CARGO_HOME=/opt/cargo` costs one line. **Where refusing makes the sandbox worse,
mark; where it costs only an author's line, refuse.**

Two stages, because one location cannot do it. **Parse time**: name grammar,
verb/type agreement, snug-owned and forbidden names, hand-written separators.
**Resolve time**, after `{var}` expansion: coverage, purely lexical over the
profile's own expanded guest specs plus the symlink map. No new `Environ` method
is needed — and if anyone proposes an existence check, that is where a filesystem
fact would have to travel, and the answer is no.

*Implementation trap:* `validate.go`'s `resolveVia` is **not reusable as-is**. It
skips `g == link` (right for a mountpoint, wrong for a `PATH` element that is
literally `/bin`) and returns the first map match, which is nondeterministic when
one link prefixes another. One map, two entry points; the environ one must match
`g == link` and pick the **deepest** link.

### 2.6 What `sanitise` does, decided

| question | decision |
|---|---|
| host path vs guest path? | **drop, never rewrite.** An element survives iff, read verbatim as a *guest* path, a grant covers it |
| what access counts? | **`ro` is enough.** No mode bits, no `stat` |
| what *kind* counts? | **a bind, generated data or a granted symlink.** An element whose deepest covering mount is `KindTmpfs`, `KindProc` or `KindDev` is dropped |
| host unset vs empty? | **both mean absent**, and neither may change a verdict |
| with `merge` on one name? | **legal, never an error** — both are unions |
| where in the order? | **a fourth band, after `merge`** |

**Drop, never rewrite**, because the host→guest map is not a function: `KindData`
mounts have no host path at all, and `Mount.Host` is already canonicalised. With
`@tmp-shared`, `/tmp/x/lib` is kept and `/tmp/snug-1000-xxx/lib` is dropped —
which is also the intuitive answer from inside, where `/tmp` *is* the shared
directory. **Without `@tmp-shared` both are dropped**, because `/tmp` is then a
tmpfs and the kind rule below applies; the two answers differ because the two
sandboxes differ, which is the filter reporting the policy rather than the host. The cost is that genuinely-real elements get dropped; §2.7 prints them
**named**, and the repair is one visible `merge` line.

**`ro` is enough, and the honest scope is narrower than the name.** `sanitise`
removes elements naming paths the sandbox has no grant for. It is a
**truthfulness filter, not a capability filter** — it cannot promise a surviving
`PATH` element contains an executable, because the mount may be an empty bind.

**A tmpfs is not enough, and this is the same rule rather than a second one.**
The filter's contract is *"copy the host value, keep only what policy grants"* —
so the question at each element is *does the sandbox have the **host's content**
at this path*, and a tmpfs answers no: it grants an **empty** directory. An
element covered only by one was never a truthful survivor, and the correction is
the existing predicate giving a correct answer to the question it already asks.
The **deepest** covering mount decides, so a bind nested inside a tmpfs is kept
while the tmpfs directory above it is dropped. Do not read that as "keep if any
mount exists at or below" — that is a second, downward walk, and it re-admits the
element the rule exists to remove.

**`@claude` does NOT stage `{home}/.local/bin`, and the reason belongs here of
all places** — an example built on "which `@claude` really does stage" would be
describing a hole rather than the rule. `@claude`
staged a read-only bind inside a *writable* directory and then put that directory
on `PATH` with `merge` — and no amount of correctness in this filter could reach
it, because `sanitise` only ever inspects the **host's** value for an imported
variable and a `merge` entry is written in a profile. The binary now lands in
`policy.StagedBinDir` (`/snug/bin`), which is unwritable from inside. The
nesting rule above is unchanged and still right; what changed is that its
best-known example was itself a hole, in the half of the environment this
document does not govern.

*Why it matters, and the bound on the claim.* Under `@home`, `{home}` and four
subdirectories are tmpfs, and `/tmp` is tmpfs in every policy. So a host `PATH`
carrying `/tmp/x/bin` reaching the `PATH` snug writes would land at a directory
that is **empty and writable inside**, in a band **ahead of** `/usr/bin`. The payload creates the directory, drops a file called `git` in it,
and the next `git` a human or another agent runs inside is that file. Verified
end to end (marker `SHADOWED-GIT-RAN`).

***`/proc` and `/dev` are dropped too, and getting that arm wrong is the most
instructive part of this section.*** They were kept at first, on the reasoning
that both are "kernel- and bwrap-populated, not empty" — true of the
**directory**, false of what `/proc`'s magic symlinks **resolve to**. The filter
is lexical and does not follow symlinks, so the walk stops at `/proc` while the
kernel walks `/proc/self/root/tmp/x/bin` to the writable tmpfs and
`/proc/self/cwd` to the target, where the shadow file also persists to the host.
Both reproduced. The general form is worth keeping in mind well beyond this
filter: **a lexical predicate answers about the path it was handed, the kernel
answers about the path it resolves, and wherever those differ is where the attack
is.** `..`, trailing slashes and repeated slashes were probed and are not
exploitable, because the walk cleans before it starts.

`KindSymlink` still survives, and the line between the two is not arbitrary: a
`KindSymlink` is a link some **grant** authored, pointing where that grant says,
and following it here would be a second resolution rule with its own failure
modes. `/proc`'s magic links are authored by the **kernel**, point at whatever
the reading process happens to have open, and are not a grant at all.

The narrower fix was chosen over "drop anything writable" deliberately, and the
reason bounds what this claims: *the payload can rewrite `PATH` at will, so no
filter closes shadowing. What the filter owes is that the environment **snug
itself** hands over does not ship the shadow slot pre-installed.* Dropping every
writable element would also drop the target's own `bin/`, which is a truthful
element — a real bind of real host content — and would chase an invariant the
sandbox cannot hold. A writable **bind** therefore still survives, target
included, and the residual shadow slots that leaves are recorded in §4.3.

**Unset and empty collapse to absent** for lists. But write it as a rule for
lists only, **not a shared helper**: §3.2's flag scalars (`NO_COLOR`, `CI`) are
"set to any value, including empty", so the collapse is exactly wrong for them.
"Right for one type, wrong for the other" is how this class of bug ships.

**After `merge`**, because a `merge` is a declaration by a profile the human
selected and a `sanitise` is a filtered copy of ambient host state — a
declaration must beat ambient state, or the host's `PKG_CONFIG_PATH` arbitrates
between two profiles. It also means adding a `sanitise` can only ever *append*.
**Survivors keep host order; they are not sorted.** Two reviewers disagreed here
and this is the resolution: `sanitise`'s contract is *"copy the host value, keep
only what policy grants"*, so sorting is a second, silent transformation nobody
asked for — and §3.3 documents a variable where position is semantic (`GOPATH`,
element 0 privileged). There is no commutativity cost: host order is one external
sequence, not a fold artifact. The objection — that the resolved value becomes a
function of a host string — is true of `sanitise` either way; sorting does not
remove the dependence, it only mangles the value.

*Monotone, and that is the non-obvious half:* the filter predicate is "is this
path granted", and grants only ever grow, so adding a profile can only make
**more** host elements survive.

*But once the kind decides the verdict, that argument acquires a dependency.* The
one shape that would break monotonicity is a **tmpfs appearing beneath an
existing bind**, which would turn a kept element into a dropped one. It cannot
happen only because `rejectMasking` refuses it (`validate.go`). A tmpfs nested
inside another tmpfs is legal and harmless here — the element was already
dropped. So `sanitise`'s monotonicity now **rests on the masking rule**, a
coupling that is invisible in either file, which is why
`TestSanitiseMonotonicityRestsOnRejectMasking` exists: relax the masking rule one
day and the environment stops being monotone, loudly rather than quietly.

**Duplicates collapse to their earliest band.** That keeps `prepend`'s guarantee
literally true, and it fixes a live bug — today a profile `path` entry is not
deduped against the base, measured:

```
snug --dry-run -p tpath .      # path = ["/nonexistent/bin", "/bin"]
  PATH=/bin:/nonexistent/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

`/bin` twice, and an ungranted directory accepted in silence — which is the
present-day state §2.5's rule changes.

### 2.7 The errors

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
a prepend, so `defaults` does not consume the slot. Getting that backwards
leaves no way to prepend on an ordinary run short of `--no-defaults`.
Two profiles wanting the front is a genuine disagreement and is worth an error;
snug quietly holding it forever would not have been.

```toml
# 2. Two scalars disagree.
[profile.a.environ.set]
XDG_DATA_HOME = "{home}/.local/share"

[profile.b.environ.set]
XDG_DATA_HOME = "{home}/.share"
```
```
snug: profiles a and b both set XDG_DATA_HOME, to /home/u/.local/share and
       /home/u/.share. A scalar has one value. Select one profile, or make
       them agree.
```
The *same* value in both is fine. **The reason usually given for it is wrong** and
worth correcting: not "to keep `include` usable" — `expand` folds includes into a
set keyed by profile name, so a diamond contributes its `set` exactly once and
never reaches an agreement check. The real reason is independently-authored
duplication: two profiles both writing `XDG_CONFIG_HOME = "{home}/.config"` is
plausible and harmless.

**The same rule applies to `prepend`, and the tempting answer is wrong.** Two
profiles naming the *identical* directory do not disagree about who is first, and
the resolved policy is byte-identical either way — refusing it refuses a
non-conflict. Making agreement legal collapses a rule rather than adding one:
`prepend` then behaves exactly like `set`, `identity`, `address`, `gateway` and
`mtu` — a single-valued slot where equal claims join and unequal claims are a
symmetric error. One rule, six users. Equality is over the whole ordered sequence
after `{var}` expansion, so `["/a","/b"]` against `["/b","/a"]` is still a
disagreement about order and still fails.

*The error must name every claimant, not two of them.* Accumulate claims during
the fold and check after it completes, so there is no fold order to keep
order-independent. Today's scalar conflicts do not: with three profiles where two
agree, the message names the alphabetically-last agreeing profile and never
mentions the first — a fold artifact with no meaning to the reader.

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
Refused. `SNUG_*` = what `--dry-run` and injected `~/.claude/CLAUDE.md` read against, so profile that can set it can lie to artifacts a human read to decide whether to trust sandbox. `PS1` executed by bash (§3.5). Refusal must cover **prefixes** — `BASH_FUNC_*`, `GIT_CONFIG_*`, `LD_*`, `npm_config_*`, `PIP_*`, `CARGO_*` — which today's `map[string]bool` cannot express.

```toml
# 6. A verb that does not exist.
[profile.evil.environ.deny]
PATH = "/usr/bin"
```
Refused by `DisallowUnknownFields`, same as any unknown key.

### 2.8 What `--dry-run` shows

Provenance per entry = product. Mounts already render this way; environment should match, with verb and profile that supplied it:

```
ENVIRONMENT  (--clearenv, then:)
  EDITOR           vim                             inherit   @claude
  HOME             /home/u                    (snug)
  PATH             /opt/bin                        prepend   mytools
                   /home/u/.cargo/bin         merge     @rust
                   /snug/bin                   (snug)    podman stub
                   /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  @pkgconfig
                   (2 host entries dropped: /opt/x/lib/pkgconfig, /srv/pkgconfig)
  SHELL            /usr/bin/bash                   (snug)
  XDG_CONFIG_HOME  /home/u/.config            set       @home
```

Three things a flat list cannot say: **which verb** produced the value, **which
profile**, and for `sanitise`, **what was dropped** — named, not counted. A filter
that silently removes two of three elements is the exact shape of failure this
document exists to avoid, and a bare "1 of 3 kept" does not let anyone check it.

`(snug)` is the provenance for snug's own authorship (§1.1), matching what mounts
already print. The `PATH` bands read top to bottom in resolution order, so the
rendering *is* the §2.4 diagram — which is the point: if the two ever disagree,
the renderer is lying.

Note `HOME` and `SHELL` carry `(snug)` and no verb. They are not profile-writable
(§1.1), and §4.2's repair is that this block also **marks** an authored value
whose path nothing grants.

**A second mark, added after §4.2 shipped: `← writable from inside`, on `PATH`
entries only.** §4.2's mark answers *is anything there*; this one answers *can
the payload write there*, and both draw on `coveringMount` so there is still one
answer to "what is at this path".

It exists because the block was rendering two entries with the identical property
in opposite ways, four lines apart — a profile's `merge` of a writable directory
kept and unmarked, directly above a `sanitise` drop line explaining that a
writable directory is a shadow slot. The filter was right in both cases:
`sanitise` judges only the **host's** value for an imported variable, and can
never reach a `merge` entry written in a file. But a reader cannot see that
distinction on the screen, and the gap is not academic: `@claude`'s
`{home}/.local/bin` is exactly the shape that sits in it unmarked.

The scope is the substance. `PATH` entries are searched for **commands**, so a
writable one is a slot the payload can fill; a writable `CARGO_HOME` or
`XDG_CACHE_HOME` is what those variables are *for*, and marking them would teach
the reader to skip the mark on the one line that matters. The two marks cannot
collide: the writable mark needs a covering mount, and the `not granted` mark
means there is none.

It stays a **mark, not a refusal**, for the same reason §4.2's does — and the
reason is now sharper than "restriction is not snug's job". A human's own profile
may deliberately put a writable directory on `PATH`; that is their declaration,
an accepted residual. What snug may never do is *ship*
one, and that is enforced separately and absolutely, by a test over the builtins
(`TestNoBuiltinPutsAWritableDirectoryOnPATH`) rather than by anything on screen.

---

### 2.9 The annotation contract, and why the roster holds no permission bits

This is the decision the second pass over issue #44 made, stated once so the rest
of this document can refer to it.

**snug has only allowlists and never denylists.** The base state is an empty
environment: `cmd.Env = []string{}` plus bwrap's `--clearenv`. A profile is a
named hole in it. There is therefore nothing to deny — the thing a denylist would
deny was never there — and a table that refused a NAME was snug refusing *its own
user* a hole in *their own* sandbox. The author of a profile stands on the far
side of the line the sandbox draws: snug constrains the payload, never the person
configuring it. **You get what you configure**, and what snug owes in return is
that the screen you approve it on says what you approved.

So: `forbiddenEnv`, `forbiddenEnvPrefixes` and the roster's own `noInherit` bit
are all **annotations** now (`policy.EnvNote`), rendered by `--dry-run`'s
ENVIRONMENT block and by `snug profile show`. Measured, over the 113 names snug
has a table entry for: **147 (name, verb) pairs across 82 names are
allowed-with-annotation rather than refused, and nothing goes the other way.**
The prefix families are unbounded, so the real figure is "every name under `LD_*`,
`GIT_CONFIG_*`, `PIP_*`, `CARGO_*` and `npm_config_*`" as well.

**The roster holds type facts only.** Scalar or list, the separator, the
alternate separator, what an empty element means, whether the value is a path,
whether the elements compose. If a field you are about to add answers "may a
profile do this", it does not belong in `envType`; if it answers "what IS this
variable", it does. `noInherit` was the one field that failed that test — its
message read "snug refuses to take this from the host", which is a verdict about
an author — and `noSet` (the mirror, proposed for `EDITOR`/`VISUAL`/`PAGER` in
issue #45) was never built and now never will be.

**What still refuses, and there are exactly three kinds.** None of them is a rule
about what a human may have:

| kind | what it says | where |
|---|---|---|
| **ownership** | snug writes this name itself | `checkEnvOwnership`, `SnugOwnedEnv` |
| **type** | snug cannot carry out this verb on this variable correctly | `checkEnvVerbType`, `checkUnrosteredName` |
| **transport** | this name or value would corrupt a mechanism or forge a screen row | `checkEnvName`, `checkEnvValue`, `checkEnvElement` |

Ownership is narrower than it looks and deliberately so: a rostered LIST returns
`nil` early, which is what lets a profile `merge` onto `PATH`. It is "snug's
SCALARS are untouchable", not "snug's names are". Type is the one that keeps
`LD_PRELOAD` unreachable at every verb, and it does so without a denylist. And
`checkEnvElement` reads the roster for the separator, so it protects **rostered
names only** — for a name snug has no row for there is no separator to smuggle,
and no list verb to smuggle it into.

**Three statements, one row, fixed order.** A rendered row can now carry up to
three marks, and none replaces another — this is the same defect two independent
reviews found one commit earlier, one indirection out:

```
unchecked   about the NAME    snug has no roster row, so no type
annotation  about the VALUE   what the tool will DO with it
not granted about the VALUE   spelled like an absolute path, nothing inside covers it
```

Widest claim first. `unchecked` and the annotation can co-occur and do not
contradict each other: `set PIP_INDEX_URL` has no type row (so snug has no
opinion about what the variable IS) and matches an annotated family (so snug does
have one about what pip does with it). Pinned by
`TestUncheckedMarkJoinsRatherThanReplacesTheGrantMark`, which drives a fixture
carrying all three at once (`GIT_SSH_COMMAND`, unrostered, annotated, ungranted).

**An annotation must never become a grant, and `IsUncheckedEnv` is where that
nearly happens.** Answering from the roster OR the forbidden table is harmless
only while that table refuses, because a refused pair never reaches a screen.
`internal/profile`'s `checkBuiltinEnvRoster` is written on that predicate, so
folding the *annotation* table in would have made every annotated name — sixty of
them, `GIT_SSH_COMMAND` and `RUSTC_WRAPPER` included — a name a profile snug
SHIPS may write, in the same commit that stopped refusing them for everybody
else. Measured, both ways. `snugKnowsEnvName` now reads the roster alone, and
`TestAnAnnotationDoesNotMakeANameCheckedForABuiltin` pins it.

**The residual, stated rather than closed.** `checkBuiltinEnvRoster` is now the
only thing keeping `GIT_SSH_COMMAND` out of a profile snug ships, and it holds
because that name has no roster ROW — not because anyone decided a builtin may
not write it. Add a row to an annotated name (to give it a type so a list verb
works, the plausible reason) and the builtin gate opens silently while the
annotation stays. Extending the rule to "nor a name snug would annotate" was
considered and **rejected on measurement**: `@claude` inherits `EDITOR`,
`VISUAL`, `PAGER` and `ANTHROPIC_BASE_URL`, all four annotated, so a blanket
refusal fails at `Builtins()` and takes every snug command with it. Instead the
annotated (name, verb) pairs a shipped profile writes are a **pinned inventory**
(`TestAnnotatedEnvPairsAShippedProfileWritesArePinned`, `internal/profile`), so
opening the gate moves a list a human reads — the project's stated review
mechanism, the same argument as the golden argv files. It is not a gate and does
not pretend to be.

**The review artifact.** `internal/policy/testdata/annotations.txt` is the golden
of every sentence, at every verb a profile can actually write. It exists because the boundary
lives in the thing a human READS: against a refusal, a change to the boundary
showed up as a changed refusal in `refusals.txt`; against an annotation, it shows
up as a changed sentence, so the sentence is the artifact, and a sentence with
no golden is prose drifting away from the measurement it was written from. Five
rows left `refusals.txt` in the commit that added that file.

**What this does not change.** `policy.IsInlineConfigEnv` and
`TestNoBuiltinHandsOverAnInlineConfigVariable` are untouched, and their scope is
now exactly what CLAUDE.md says the rule is: *the environment snug ITSELF hands
over must not ship the override pre-installed*. That sweep is builtin-only. A
user profile handing over `GIT_CONFIG_KEY_0` is legal, annotated, and outside its
remit — as it always was, since the sweep never resolved a user profile.

## 3. The variable types that drive the verbs

Everything `char*`; that all they share. Three types, and type decide which verbs apply.

### 3.1 Reading the tables

Both tables use the same marks:

| mark | means |
|---|---|
| **✓** | the verb is allowed on this variable |
| **⚠** | allowed, with the stated constraint — never "probably fine" |
| **✗** | refused at load time, with the reason in the note |
| **—** | not applicable to this type at all |

**Read every ✗ below against §2.9: half of them are annotations, not refusals.**
A ✗ that says *snug cannot carry out this verb correctly* — `merge` on a scalar,
`sanitise` on `MANPATH`, `inherit` on any list, any list verb on a name with no
row — is still a refusal, and comes from `checkEnvVerbType`. A ✗ that said *a
profile may not take this from the host* is an **annotation** now: the `inherit ✗`
column on `XDG_*`, `CARGO_HOME`, `DOCKER_CONFIG`, `NPM_CONFIG_USERCONFIG` and
`PIP_CONFIG_FILE` marked the roster's `noInherit` bit, which the model does not
carry: those rows are legal and marked. The reasoning in each note is what the
sentence says; only the column differs.

`sanitise` and `merge` are list-only, `set` is scalar-only, and `inherit` is
scalar-only (§2.1). `prepend` gets no column because it is allowed wherever
`merge` is: the question it answers is *who is first*, not *what type is this*.

### 3.2 Scalars

Scalars have no order to get wrong, so the whole ordering argument passes them
by. What they do have is the `set`-versus-`inherit` question, and for the
path-valued ones the §2.7-case-4 rule: a value naming something nothing grants is
worse than an absent value.

| variable | path? | set | inherit | note |
|---|---|---|---|---|
| `HOME`, `SHELL`, `USER`, `LOGNAME`, `TMPDIR`, `PS1`, `SNUG*` | yes/no | **—** | **✗** | snug's (§1.1); no profile may write them |
| `EDITOR`, `VISUAL`, `PAGER` | no | ✓ | ✓ | exec vectors, but the host's own choice — **legal at both verbs, with no identity-conditional refusal, and ANNOTATED at both** (§2.9). See the note below |
| `TERM` | no | ⚠ | ✓ | the standard exception to authoring: the host terminal is a fact snug cannot know |
| `LANG`, `LC_*` | no | ✓ | ✓ | genuine scalars; `LC_ALL` > `LC_<cat>` > `LANG` is a consumer rule, not a merge rule |
| `TZ` | **sort of** | ⚠ | ⚠ | **two-branch grammar — see below** |
| `NO_COLOR`, `CI` | no | ⚠ | ⚠ | **flags: empty is not unset.** `NO_COLOR` is "set to any value, including empty", so the usual "drop it if empty" rule inverts |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` | yes | ✓ | **✗ → annotated** | must name a granted path; empty **is** unset per spec (§3.4) |
| `XDG_RUNTIME_DIR` | yes | ⚠ | **✗ → annotated** | carries obligations, not just a value — mode 0700, owned by the user |
| `SSH_AUTH_SOCK`, `GIT_CONFIG_GLOBAL`, `GH_CONFIG_DIR` | yes | **—** | **✗** | authored by the machinery that creates the socket or file |
| `CARGO_HOME`, `DOCKER_CONFIG`, `NPM_CONFIG_USERCONFIG`, `PIP_CONFIG_FILE` | yes | ✓ | **✗ → annotated** | "generate, don't bind" — the value is a path, never a credential. No annotation at `set`: authoring a pointer is the mechanism, not the hazard |
| `CONTAINER_HOST`, `DOCKER_HOST` | **no — URLs** | **—** | **✗** | `ssh://` makes the client exec `ssh`; scalar-shaped, parsed, exec-capable |

**Amended by §2.9: those three rows are ANNOTATED at both verbs now.** The
sentence below — the residual this section wrote down and carried as issue #35 —
is the sentence `policy.EnvNote` renders on `--dry-run` and on `snug profile
show` for `EDITOR`, `VISUAL` and `PAGER`, and for the `GIT_*` spellings beside
them. That is the closure this section said it could not have without withdrawing
a grant `@claude` uses: the reader is told, at every spelling, and no verb is
taken away from anybody. Issue #45 asked for the mirror (`noSet`) and is answered
the same way. The rest of this subsection is the argument that got there and is
kept.

**The `EDITOR`/`VISUAL`/`PAGER` row said "refused inside `@git-ro`-style
identity" for a whole milestone, and nothing ever refused anything.** No env
check anywhere reads `Policy.Identity`; `grep -rnE 'EDITOR|VISUAL|PAGER'` over
the non-test Go files returns two `GIT_*` entries in `forbiddenEnv` and one
comment. It was a documented gate with nothing behind it — the exact defect
CLAUDE.md records twice ("when you write 'requires X' in a comment, grep for X
before you believe it"), reproduced in this document rather than in code.

The clause is **deleted rather than implemented**, and that is a decision, not
an omission. Implementing it would withdraw a grant from every profile that
inherits those three — `@claude` inherits all three today — and would do it
conditionally on another profile being selected, which is a profile's grant
changing meaning because of its neighbours. That is the shape invariant 1
exists to refuse. So the three stay legal, and the residual is written down
where it can be argued with:

> A profile may set `PAGER` or `EDITOR` to a command, and git will run it —
> `PAGER="sh -c '…'" git log` was measured hijacked, and git's fallback chains
> are `GIT_EDITOR → core.editor → VISUAL → EDITOR` and `GIT_PAGER → core.pager
> → PAGER`. The `GIT_*` spellings are refused (§4.4's list) and the generic
> ones are not, so **`forbiddenEnv` does not close the exec class for git; it
> closes the invisible half of it.** Profiles are the trusted layer, so this is
> a composability defect — one profile weakening what another established —
> rather than an escape. Carried as https://github.com/gomoni/snug/issues/35.

**Reconsidered, not re-decided, during the pass that closed `GIT_COMMON_DIR`
and the `RUSTC_*`/`CARGO_*` pair (issue #26 review).** Those two were the same
sibling-miss shape — a specific spelling refused, a general one it falls back
to left open — and the reviewer asked, correctly, why `EDITOR`/`VISUAL` were
not fixed alongside `GIT_EDITOR` in the same change, offering an *unconditional*
`forbidBoth` rather than the identity-conditional refusal rejected above — which
sidesteps the invariant-1 objection by not being conditional on a neighbour. It
is not implemented, and the reason is the other objection in this section, confirmed by measurement rather than argued afresh: `@claude`
(`internal/profile/profiles/base.toml`, `[profile.claude.environ.inherit]`)
inherits `EDITOR` and `VISUAL` today, and `forbidBoth` refuses `VerbInherit`
unconditionally — so this specific fix does not add a table row, it breaks a
shipped, tested builtin profile's `ValidateEnvGrants` outright. Closing it
therefore still requires the withdrawal this section already named as the
real cost, now concretely: either `@claude` stops inheriting `EDITOR`/`VISUAL`
(a grant taken back from the one profile that uses it) or the gap stays. That
is a decision about what `@claude` may inherit, not a missing denylist entry,
and stays out of scope for a change whose remit was closing measured
prefix/sibling gaps. Still open, still https://github.com/gomoni/snug/issues/35.

**`TZ` is the sharpest scalar, and it is this document's own rule biting.** It is
not a plain string: it is either a file reference resolved under `TZDIR`, or an
inline POSIX rule. When the file is unreachable glibc does **not** fail — it
re-reads the same value as a rule string. Measured:

```
env -i TZ=Asia/Tokyo                    date -d @0 +"%z %Z"  →  +0900 JST
env -i TZDIR=/nonexistent TZ=Asia/Tokyo date -d @0 +"%z %Z"  →  +0000 Asia
```

`Asia` became a timezone abbreviation with a zero offset. Every timestamp in the
sandbox is silently wrong, on no channel at all. A profile that sets `TZ` without
granting `/usr/share/zoneinfo` has made a guarantee it does not keep — invariant
5 says that is worse than refusing, which is why the cell is `⚠` and not `✓`.

### 3.3 Lists, and the empty-element column that decides `sanitise`

"→ CWD" mean empty element resolve to current directory, which inside snug = target: writable thing hostile payload control.

| variable | sep | empty element | merge | sanitise |
|---|---|---|---|---|
| `PATH` | `:` | **→ CWD** | ✓ | ⚠ rebuild only |
| `LD_LIBRARY_PATH` | **`:` or `;`** | **→ CWD** | ✗ | ✗ |
| `LD_PRELOAD` | **`:` or space** | n/a | ✗ | ✗ |
| `MANPATH` | `:` | **an OPERATOR** — leading = prepend system path, trailing = append, `::` = insert here | ⚠ | **✗** |
| `CDPATH` | `:` | **→ CWD, positionally** | ✗ | ✗ |
| `PKG_CONFIG_PATH` | `:` | **ignored** | ✓ | ✓ |
| `PYTHONPATH` | `:` | **→ CWD** | **✗** | ✗ |
| `PERL5LIB` | `:` | **ignored** | ✓ | ✓ |
| `NODE_PATH` | `:` | **ignored** | ✓ | ✓ |
| `CLASSPATH` | `:` / `;` | unverified | ⚠ | ⚠ |
| `GOPATH` | `:` | element 0 privileged; empty first ⇒ empty `GOMODCACHE` | ⚠ | ⚠ |
| `INFOPATH` | `:` | trailing only = system default | ⚠ | ⚠ |
| `TERMINFO_DIRS` | `:` | = the system location | ✓ | ⚠ |
| `GOFLAGS` | **space** | n/a | ✗ | ✗ |

**The discriminator for `sanitise` is this column, not the type.** An empty
element is safe where it is *ignored*, hazardous where it means *CWD*, and
illegal where it is an *operator*. So a type that carries a separator must also
carry the empty-element kind — otherwise the sanitiser is written once and is
wrong for a third of its inputs.

`PYTHONPATH`'s `merge` column is `✗`, not the `⚠` it looks like it should be:
`sitecustomize.py` on **any** element runs at interpreter start (§2.1, §4.4), so
it belongs in the forbidden-name table rather than the "reviewably mergeable"
one — and that table refuses **every** verb, `merge`/`prepend` included, not
only `set`/`inherit`.

**That column is now wrong, and it is the ONLY row in either table where the
annotation change widened what a profile may write.** The refusal came from the
name table, not from the type, and the name table refuses nothing (§2.9). The
type still says `mergeable: true`, so `environ.merge`/`environ.prepend` on
`PYTHONPATH` are legal and annotated. Read the column as ⚠ with the sentence
attached. `sanitise` stays `✗` and is unaffected: that one comes from the
`sanitisable` column, because an empty element here is the current directory,
which inside snug is the target. No shipped profile merges it, then or now.

`MANPATH` sharpest: empty element = instruction, so *removing* element can *add* directories. Measured — man-db announce the choice:

```
env -i MANPATH=/a     manpath  →  ignoring /etc/manpath.config    → /a
env -i MANPATH=:/a    manpath  →  prepending /etc/manpath.config  → /usr/share/man:/a
env -i MANPATH=/a::/b manpath  →  inserting /etc/manpath.config   → /a:/usr/share/man:/b
```

`LD_LIBRARY_PATH` and `LD_PRELOAD` = why separator live in type, not parser: `ld.so(8)` give them two different separator sets, neither escapable.

### 3.4 XDG — five scalars and two lists

| variable | type | default when not set **or empty** |
|---|---|---|
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` | scalar path | `$HOME/.config`, `.cache`, `.local/state`, `.local/share` |
| `XDG_RUNTIME_DIR` | scalar path | **no default value** |
| `XDG_DATA_DIRS` | **list**, `:` | `/usr/local/share/:/usr/share/` |
| `XDG_CONFIG_DIRS` | **list**, `:` | `/etc/xdg` |

Three things spec settle. **Empty is unset** — unlike `PATH`, XDG variables have genuine no-op value. **Relative paths must be ignored** — make these only two lists here where naive sanitiser safe *by specification*. And **`XDG_RUNTIME_DIR` carry obligations** — owned by user, mode 0700, session lifetime — so authoring it *is* a grant, and it belong to whichever profile create a directory meeting them.

Note `XDG_CONFIG_HOME` (scalar, `environ.set`) against `XDG_CONFIG_DIRS` (list, `environ.merge`). One character apart, different verbs — exactly what type table exist to catch.

### 3.5 Semi-structured: no verb — except `PS1`

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

*Machine-readable = separate channel, already solved:* `SNUG=1` and `SNUG_PROFILES` are what an agent or script should test. Prompt for humans; do not make it carry both jobs.

---

## 4. Why — the measured evidence

Every measurement executed against `main` (`408e8e4`), and **every one of them is
still reported in the present tense on purpose**: this section is the evidence
that argued for the design, not a description of the tree you are reading. Where
the implementation has since closed one, the subsection carries a `**Closed by**`
line naming the commit. A subsection with no such line is still live on `main`.

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

  HOME=/home/u                     ← no @home: does not exist
  SHELL=/usr/bin/bash                   ← no @sys:  does not exist
  PATH=/usr/bin:/bin:/usr/sbin:/sbin    ← no @sys:  none of the four exist
```

Not a hole — twenty-minutes-of-confusion class. But **three existing
violations**, not hypothetical.

**The repair is to MARK them, not to stop authoring them.** The opposite
conclusion — author only what the profile grants — converts a confusion bug into
a reachable hole, because §4.3 shows `PATH` has no safe
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

**Closed by `86fea49` (Step 3).** The refusal does not consult the host, so a
profile's verdict is the same on every machine, and the table is
`internal/policy/envtypes.go`, split by verb (§2.1) and carrying the prefix
rules `LD_`, `BASH_FUNC_`, `GIT_CONFIG_`, `PIP_`, `npm_config_`. It has
since been extended once more, by `68c6363`, after the red team demonstrated that
`GIT_SSH` passed while `GIT_SSH_COMMAND` — its exact equivalent — was refused two
entries above it. As this section says, the list is to be **extended**, not
retired.

**Status of the "Missing, each measured to execute" list above, checked
against `internal/policy/envtypes.go` during the issue #26 review round.**
`GIT_EXEC_PATH`, `GIT_CONFIG_PARAMETERS` (via the `GIT_CONFIG_` prefix),
`GIT_EXTERNAL_DIFF`, `GIT_EDITOR`, `LESSOPEN` and `BASH_FUNC_*` are all
covered — `LESSOPEN` and `PYTHONBREAKPOINT` deliberately in the middle bucket
(§2.1) rather than the "value is code" class, which was always the intended
treatment for a value the tool merely *reads* rather than unconditionally
executes. `EDITOR`/`VISUAL` were the one pair from this list still genuinely
open.

**Amended by §2.9, and the amendment reverses what "covered" means in this
paragraph.** None of these names is refused any more; every one of them is
ANNOTATED, at every verb, `EDITOR` and `VISUAL` included. So the list above is
complete for the first time — and the thing it is complete *at* changed from
"refused" to "the reader is told". The middle bucket did not dissolve into the
code class: it is the pair of sentences an `envNote` carries, one for a value a
profile wrote and one for a value taken from the host. Read §2.9 before citing
any sentence in this section as a boundary.

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

**Wanted its own investigation and its own fix — got both, as GitHub issue
#26.** The verdict: no fix exists for the payload-authored route (the value
enters git at the command-line scope, above every config file, and every
mitigation tested lives in the same channel the attacker already owns); what
snug owes and now asserts mechanically is that the environment snug ITSELF
hands over never ships one of these inline-config names pre-installed
(`policy.IsInlineConfigEnv`,
`TestNoBuiltinHandsOverAnInlineConfigVariable`). See
`.claude/design/GIT-CONFIG.md` §9 for the measurement and the threat model,
and CLAUDE.md's "Generate, don't bind" bullet for the pointer-vs-inline-setting
rule that came out of it.

---

### 4.6 Three live bugs, none of which needs this format to be fixed

Found while reviewing the design, all measured on `main`. They are recorded here
because this is where they surfaced, **not** because they depend on anything
proposed above. If the format never ships, these still want fixing.

**(a) A variable set to the empty string is silently dropped, and for flags that
inverts the meaning.** `resolve.go:283` reads
`if v := env.Getenv(e); v != ""`, so set-but-empty is indistinguishable from
unset:

```
NO_COLOR=  snug --dry-run -p @claude .   →  no NO_COLOR at all
NO_COLOR=1 snug --dry-run -p @claude .   →  NO_COLOR=1 / --setenv NO_COLOR 1
```

`NO_COLOR`'s specification is "set to **any** value, including empty", so
`NO_COLOR=` means *disable colour* and snug silently re-enables it. §3.2's flag
row is already right about the semantics; the code is wrong. The fix is an
`Environ.LookupEnv(k) (string, bool)` and a presence check — and it is the same
one line that carries §4.4's host-conditional refusal, so both go together.

**Closed by `86fea49` (Step 3)**, together with §4.4, exactly as predicted above.
One caveat the fix had to keep straight: the collapse is inverted for lists,
where unset and empty both mean absent, so `sanitiseHostList` keeps its own
check rather than sharing a helper (§2.6).

**(b) One unparseable file in `profiles.d` disables the entire registry,
builtins included.** `Load()` returns on the first bad file rather than
collecting. Measured with a single file containing one unknown key:

```
snug profile list        →  the parse error, and nothing else
snug --dry-run -p @sys . →  the same error; @sys is unreachable
```

So a file the user may not have edited takes down `@sys`, and `snug profile list`
— the one command that would tell them what still works — is exactly what stops
working. This is a live outage path, and it is also what would make any future
change to the variable type table frightening: reclassifying one name turns into
a total registry failure on every host whose profile used the old verb.

The shape of the fix, which is the interesting part: **diagnostic commands
(`profile list`, `config`, `doctor`) should report the broken file loudly and
continue with what did load; anything that runs a sandbox stays fatal.** One
caveat or it becomes a silent downgrade — `unknown profile` must consult the
skipped-file record, so `-p thatprofile` says *"the file defining it failed to
parse"* rather than *"unknown profile"*.

**Closed by `99d5c10` (Step 12a)**, including the caveat: a name defined only by
a file that failed to parse is reported as such, not as unknown.

**(c) `PATH` entries are not deduplicated, and an ungranted directory is accepted
in silence.** A profile with `path = ["/nonexistent/bin", "/bin"]`:

```
snug --dry-run -p tpath .
  PATH=/bin:/nonexistent/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

`/bin` twice — once from the profile, once from `basePATH` — and
`/nonexistent/bin` accepted with no message despite the profile granting nothing
there. Harmless today, and it is the present-day state that §2.5's coupling rule
and §2.6's dedup-to-earliest-band both change. Worth its own fix regardless: a
duplicated entry means the rendered value depends on how many profiles happened
to name a directory, which is a fold artifact.

**Closed by `2078b69` (Step 6)** for the duplicate, and by §2.5's coupling rule
for the ungranted directory.

---

## 5. Sidenote — what was considered and rejected

Short on purpose. Reopen one only with a reason.

**Prior art.** makeWrapper (`--set` / `--prefix ENV SEP VAL` / `--unset`, argv
order, imperative). systemd (`Environment=` / `PassEnvironment=` /
`UnsetEnvironment=`, later wins). flatpak (`[Environment]` sets, including to an
empty value; removal is `unset-environment` / `--unset-env` — empty-means-unset
was the pre-1.10 behaviour and is now back-compat only). Environment Modules
(`prepend-path`, `-d` for the delimiter, reference counting for unload, and **no**
priority) and Lmod (the same plus an optional **priority** argument). NixOS
modules (`mkDefault`/`mkForce` = override priority 1000/50, `mkBefore`/`mkAfter` =
order rank 500/1500). Nickel (symmetric merge, numeric priorities). CUE
(unification = greatest lower bound; commutative, associative, idempotent;
**conflict is an error, no override**). Kubernetes (`env`/`envFrom`, last wins —
documented for `envFrom`; for duplicate keys inside `env` it is kubelet behaviour
rather than a validated rule).

Two conclusions shaped the format, and both were **overstated in an earlier
draft**. The corrected versions are narrower and still decisive.

*Ordering.* Not "everyone buys commutativity back with a number". Systems where
**one author controls the sequence** just use the sequence — makeWrapper takes
argv order, Environment Modules takes load order, and neither needs a priority. A
number appears exactly where units are **independently authored** and no sequence
exists: Lmod's optional priority, NixOS's `mkOrder`. snug's profiles are
independently authored, which is why sorting alone is not an answer and why the
real choice is between a number and a refusal. Lmod needed reference counting on
top, and its docs concede that *when duplicates are allowed* it "does not remember
which module inserted which directory where".

*Subtraction.* Not "everyone except CUE and Kubernetes". Three-way: **real
removal** (makeWrapper `--unset`, systemd `UnsetEnvironment=`, flatpak
`unset-environment`, Modules/Lmod `remove-path`); **override only** — NixOS
`mkForce` and Nickel `force` win a priority comparison and never delete a
definition; and **neither** (CUE, Kubernetes). The conclusion survives and is
sharper for being right: borrowing a vocabulary by analogy imports removal from
the first group and a priority field from the second, and invariant 1 forbids
both. Read any proposal asking *"what is the `unset` here?"*; the answer must be
*there isn't one*.

Putting the separator in the signature is not unique to makeWrapper either —
Environment Modules has `prepend-path -d` and Lmod takes a delimiter argument. So
§3.3's requirement is not novel, which is the point worth keeping.

**Rejected approaches.**

- *Sort and hope* — today's behaviour. Commutative and meaningless (§4.1).
- *A priority number* (`rank = 100`) — honest, familiar, and it is the priority
  field invariant 1 was written against. Ties put you back where you started.
- *Declared shadowing* (`shadows = ["podman"]`) — conflict detected by comparing
  directory **contents**. Need filesystem read, so `internal/policy` stop being
  pure, and stay *partial* because `/snug/bin/podman` not exist at resolve
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
  to **semantics**: nothing needs a `deny` key when a profile can write
  `filter (λd → d != "/usr/bin") host.PATH`. Subtraction stop being a key you
  forgot to forbid and become a function composed from safe primitives, and
  invariant 1 would have to be re-proved against a language on every release of
  a dependency. CUE closest fit and still fail: its unification *is* the lattice
  this format want, but it is a full language with imports, and invariant 3 say
  trusted profile set come from outside the sandboxed material. **Borrow CUE's
  semantics; do not take the dependency.**

---

## 6. Open

- **The `env` key has to go.** `environ.inherit` takes its meaning, so existing
  profiles with `env = [...]` break. Make it a named error pointing at the
  replacement, in shape of the retired `@null`. Keeping prefix `environ` rather
  than reusing `env` deliberate: a silently *changed* meaning worse than a
  removed key.
- **Is `environ.append` needed?** Nothing has asked. Leaving it out keeps exactly
  one ordered operation — what makes "at most one across the set" easy to state
  and check. Adding it means answering whether prepend and append coexist (they
  do — different ends) and whether two appends conflict (yes, same argument).
- ~~Is `environ.inherit` a preference or a grant?~~ **Settled: a grant, so it
  stays in a profile.** Moving it to `config.toml` would need CLAUDE.md's
  "config holds preferences, never grants" amended, which is the wrong
  direction — see §1.2. Config keeps `defaults` and `prompt`, which really are
  preferences.
- **`path` must be retired alongside `env`.** `path = [...]` does exactly what
  `environ.merge` on `PATH` would, and `@claude` uses it today. Shipping both is
  two mechanisms for one idea — what the `default`-profile decision exists to
  prevent. Same named-error treatment.
- **`XDG_RUNTIME_DIR`** needs an owner — whichever profile create a directory
  meeting the spec's obligations.
- §4.5 (the environment outranking a pinned config file) is untouched by any of
  this and wants its own fix.
- **§4.6's three bugs are independent of the format.** (a) set-empty is dropped,
  (b) one bad profile file disables the whole registry, (c) `PATH` entries are
  not deduplicated. None needs this design to land, and (a) shares its one-line
  fix with §4.4.

## Tests

**They exist; the suite is the truth and this section is not.** The resolver
invariants and the verb behaviour are in `internal/policy/envresolve_test.go`,
`envtypes_test.go`, `envallowlist_test.go`, `envnotes_test.go` and
`envcoupling_test.go`; the `--dry-run` rendering is pinned by
`internal/cli/testdata/env.*.txt`.

One requirement from that list is worth keeping as prose, because it is the
reasoning rather than a name: **§4.3's `PATH` sanitise is the one place here
where getting it wrong ADDS a hole rather than fails to close one**, so its
regression test needs the positive control that a planted binary in the target
*is* found when an empty element is present. `envresolve_test.go:158` carries
the same hazard from the other side — an empty element in the HOST's value must
never be carried through.

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