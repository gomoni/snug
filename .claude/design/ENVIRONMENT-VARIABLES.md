# Environment variables — the configuration format

**Status: accepted; implementation in progress.** §1–§3 = format. §4 = measured evidence forcing each rule. §5 = sidenote on considered-and-rejected — read only to reopen something.

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

**And a sixth thing that is not a verb: snug's own authorship.** **No profile may
write a name snug writes, and snug is not bound by the verbs' rules when writing
them.** The list is nineteen keys, and it must be **derived from the code rather
than retyped**, because an earlier draft retyped it and missed six:

```
resolve.go   HOME SHELL USER LOGNAME TMPDIR PS1 PATH TERM TZ LANG
             SNUG SNUG_PROFILES SNUG_TARGET GIT_CONFIG_GLOBAL
identity.go  SSH_AUTH_SOCK GH_CONFIG_DIR GH_HOST          ← written AFTER Resolve
container.go CONTAINER_HOST DOCKER_HOST DOCKER_BUILDKIT   ← written AFTER Resolve
```

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
needs the same, and an earlier draft of this document did not have it — which
made the format contradict itself in three places (§1.2 note, §2.5, §4.2).

Nested, not five root keys. Written as table headers, not inline tables. Three
reasons, heaviest first — and one that was claimed and does not hold.

**(a) Keep root namespace nouns.** `environ` sit beside `ro`, `rw`, `tmpfs`, `symlink`. Verbs one level down describe operations *within* a thing, not compete with grants for root.

**(b) Unknown verb refused for free.** `environ` = struct with known fields, so `DisallowUnknownFields` catch `environ.deny` exactly as it catch unknown root key. "A negation key cannot be smuggled in" apply one level down, no new code.

**(c) `append` later cost a nested field, not a sixth root key.**

**Retracted: "the flat spelling does not parse".** An earlier draft made this the
heaviest argument, on a measurement taken against the wrong parser. Multi-line
inline tables are invalid in **TOML 1.0** and `python3 -m tomllib` refuses them —
but snug uses `go-toml/v2 v2.4.3`, which **accepts** them:

```
environ-set = {                 python3 tomllib:      Invalid initial character for a key part
  XDG_CONFIG_HOME = "...",      go-toml/v2 v2.4.3:    accepted, parses to a nested map
  XDG_CACHE_HOME  = "...",
}
```

The scratch module used to "verify" this pinned v2.2.3, not the version in
`go.mod`. **Check the version the project actually builds with, not the one the
test module resolved to.**

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
# snug's (§1.1) — an earlier draft showed them here, which contradicted §1.1 in
# the same document. A profile that wants a tool on PATH grants the directory
# and merges it, like @rust below.
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
first prepending `/run/snug/bin`, then as a switch granting nothing. Both are
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
read-only property, plus `exec /run/snug/bin/podman (snug)` in `FILESYSTEM`. §2.8
finishes the job by giving the `PATH` line the same provenance. **The answer is
provenance in `--dry-run`, not a name in `$SNUG_PROFILES`.**

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
environ.merge on EDITOR  →  EDITOR is a scalar, not a list — use environ.set.
environ.set   on PATH    →  PATH is a list — use environ.merge, or environ.prepend
                            if the order matters. environ.set on a list would
                            replace every other profile's entries, which snug
                            does not allow.
```

Unknown name default to **scalar** — conservative reading: a scalar merges with
nothing, so it can only conflict, never silently combine.

**`inherit` is refused for every list variable, without exception.** Copying a
host search path wholesale imports directories that do not exist inside — what
§2.7 case 4 refuses for `set`, and what `sanitise` exists to do properly.
`inherit` is the scalar form; `sanitise` is the list form. An earlier draft
carried this as a column on every table row and lost it in a rewrite; it is a
rule, not a row.

**`forbiddenEnv` survives, orthogonal to the type table — but it splits by
verb.** `set` carries a value from a reviewable file in the trusted profile
layer; `inherit` carries whatever the host process had at launch, put there by
whatever invoked snug. **`inherit` is a hole punched in `--clearenv`; `set` is
not.** So one middle bucket — `BASH_ENV`, `ENV`, `PERL5OPT`, `NODE_OPTIONS`,
`PYTHONSTARTUP`, `PYTHONBREAKPOINT`, `LESSOPEN`, `PYTHONPATH` — is **allowed for
`set` and refused for `inherit`**: `BASH_ENV = "{home}/.snug-init"` with the file
granted by the same profile is coherent and reviewable, while the same name
inherited points at a host path. That composes §2.5's grant rule with the forbid
list instead of maintaining two independent lists. Names snug owns, `LD_*` and
`BASH_FUNC_*` are refused for both. The type table
says what may be *merged*; the forbidden list says what may never be *inherited at
all*, at any type, because the value is code — `LD_PRELOAD` is a list and is
refused. Two rules, both applied, neither replacing the other. An earlier draft
tried to collapse them and got two wrong answers at once (add `PS1`, drop
`LD_LIBRARY_PATH`). §4.4 is a list to be **extended**, not retired.

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
or a newline; a leading digit; and any name snug owns (§1.1) or `forbiddenEnv`
covers. **Checked at parse time**, next to `checkName` and
`DisallowUnknownFields`, so `snug profile show` reports it too and the verdict
never depends on the invoking host.

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
| host unset vs empty? | **both mean absent**, and neither may change a verdict |
| with `merge` on one name? | **legal, never an error** — both are unions |
| where in the order? | **a fourth band, after `merge`** |

**Drop, never rewrite**, because the host→guest map is not a function: `KindData`
mounts have no host path at all, and `Mount.Host` is already canonicalised. With
`@tmp-shared`, `/tmp/x/lib` is kept and `/tmp/snug-1000-xxx/lib` is dropped —
which is also the intuitive answer from inside, where `/tmp` *is* the shared
directory. The cost is that genuinely-real elements get dropped; §2.7 prints them
**named**, and the repair is one visible `merge` line.

**`ro` is enough, and the honest scope is narrower than the name.** `sanitise`
removes elements naming paths the sandbox has no grant for. It is a
**truthfulness filter, not a capability filter** — it cannot promise a surviving
`PATH` element contains an executable, because the mount may be an empty bind.

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
a prepend, so `defaults` does not consume the slot — which an earlier draft got
wrong, leaving no way to prepend on an ordinary run short of `--no-defaults`.
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

**The same rule applies to `prepend`, and an earlier draft had it wrong.** Two
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
Refused. `SNUG_*` = what `--dry-run` and injected `~/.claude/CLAUDE.md` read against, so profile that can set it can lie to artifacts a human read to decide whether to trust sandbox. `PS1` executed by bash (§3.5). Refusal must cover **prefixes** — `BASH_FUNC_*`, `GIT_CONFIG_*`, `LD_*`, `npm_config_*`, `PIP_*` — which today's `map[string]bool` cannot express.

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
  HOME             /home/michal                    (snug)
  PATH             /opt/bin                        prepend   mytools
                   /home/michal/.cargo/bin         merge     @rust
                   /run/snug/bin                   (snug)    podman stub
                   /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  @pkgconfig
                   (2 host entries dropped: /opt/x/lib/pkgconfig, /srv/pkgconfig)
  SHELL            /usr/bin/bash                   (snug)
  XDG_CONFIG_HOME  /home/michal/.config            set       @home
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

---

## 3. The variable types that drive the verbs

Everything `char*`; that all they share. Three types, and type decide which verbs apply.

### 3.1 Reading the tables

Both tables use the same marks, which an earlier draft never defined:

| mark | means |
|---|---|
| **✓** | the verb is allowed on this variable |
| **⚠** | allowed, with the stated constraint — never "probably fine" |
| **✗** | refused at load time, with the reason in the note |
| **—** | not applicable to this type at all |

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
| `EDITOR`, `VISUAL`, `PAGER` | no | ✓ | ✓ | exec vectors, but the host's own choice; refused inside `@git-ro`-style identity, see §4.4 |
| `TERM` | no | ⚠ | ✓ | the standard exception to authoring: the host terminal is a fact snug cannot know |
| `LANG`, `LC_*` | no | ✓ | ✓ | genuine scalars; `LC_ALL` > `LC_<cat>` > `LANG` is a consumer rule, not a merge rule |
| `TZ` | **sort of** | ⚠ | ⚠ | **two-branch grammar — see below** |
| `NO_COLOR`, `CI` | no | ⚠ | ⚠ | **flags: empty is not unset.** `NO_COLOR` is "set to any value, including empty", so the usual "drop it if empty" rule inverts |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` | yes | ✓ | **✗** | must name a granted path; empty **is** unset per spec (§3.4) |
| `XDG_RUNTIME_DIR` | yes | ⚠ | **✗** | carries obligations, not just a value — mode 0700, owned by the user |
| `SSH_AUTH_SOCK`, `GIT_CONFIG_GLOBAL`, `GH_CONFIG_DIR` | yes | **—** | **✗** | authored by the machinery that creates the socket or file |
| `CARGO_HOME`, `DOCKER_CONFIG`, `NPM_CONFIG_USERCONFIG`, `PIP_CONFIG_FILE` | yes | ✓ | **✗** | "generate, don't bind" — the value is a path, never a credential |
| `CONTAINER_HOST`, `DOCKER_HOST` | **no — URLs** | **—** | **✗** | `ssh://` makes the client exec `ssh`; scalar-shaped, parsed, exec-capable |

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
- §4.5 (the environment outranking a pinned config file) is untouched by any of
  this and wants its own fix.
- **§4.6's three bugs are independent of the format.** (a) set-empty is dropped,
  (b) one bad profile file disables the whole registry, (c) `PATH` entries are
  not deduplicated. None needs this design to land, and (a) shares its one-line
  fix with §4.4.

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
- `--dry-run` renders §2.8, and golden file changes.
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