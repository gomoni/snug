# Environment variables — internals and evidence

The format, the verbs, the type roster, ordering, `sanitise` and the `--dry-run`
marks are documented for users in `docs/src/environment.md` and the generated
`docs/src/reference/environment-names.md`. This file holds what the book is
not for: which code enforces what, the attacker-side reasoning behind each rule,
and the measurements. `internal/policy/env*.go` is the truth.

Section numbers are cited from code and other design files; they are stable
and not contiguous.

## 1. Structure

### 1.1 snug's own authorship

**snug is not bound by the verbs when writing its own variables.** Two kinds,
split by what the write is conditional on. Both lists are derived from code:
`internal/cli/ownedenv_test.go` asserts owned + conditional equals the set of
names every `AuthorEnv`/`AuthorEnvList` call writes, so a new writer fails the
build until placed, and that every conditional name snug authored has its
predicate true on that policy.

- **Owned** (`SnugOwnedEnv`): no profile may write one, in any run, refused at
  parse time. `TERM`, `TZ` and `LANG` are written only when the host has a value
  and are owned all the same: a verdict keyed on that would pass a profile on one
  host and refuse it on another, so the only host-independent verdict is the
  unconditional one.
- **Conditional** (`conditionalEnvs`): snug writes one only when a profile key
  turns its feature on. Elsewhere a profile may `set`/`inherit` it, annotated
  (§2.9). In a selection that turns the feature on, a profile's line on it is a
  symmetric conflict naming the profile's line and the profiles whose key made
  snug the author. Two rules make the verdict host-independent: the predicate
  reads the **selection**, never whether snug wrote the name (`identity.gh.user`
  writes no `GH_CONFIG_DIR` on a dry run with no token), and the claim is the
  profile's **text**, never what the host held. The conflict also covers names a
  tool reads **in place of** snug's: `GH_TOKEN`, `GITHUB_TOKEN`,
  `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN` beat the token in the
  generated `hosts.yml`; `CONTAINER_CONNECTION` beats `CONTAINER_HOST`
  (measured, gh 2.96.0 and podman 6.0.2).
  A profile snug ships may write none of them (`checkBuiltinConditionalEnv`):
  snug's value is the narrowed hole (one-key agent proxy, filtering container
  proxy, generated config); a shipped profile pointing the name elsewhere would
  ship the wide version.

Why conditional and not owned: owning these protected nobody hostile.
`environ.*` comes only from the trusted profile set (invariant 3) and the payload
can export `DOCKER_HOST` for itself. What ownership did protect is kept by the
conflict: without it a profile's line on a slot snug fills is discarded with no
trace (invariant 5) — replaced outright by `AuthorEnv` for names written after
`Resolve`, carried beside snug's entry and never used for those written inside it.

**Ownership refuses the verbs that REPLACE a value.** For a scalar that is every
verb. For a list, snug's authorship is a band (§2.4), so `merge`, `prepend` and
`sanitise` add a band ahead of snug's base and displace nothing; `set`/`inherit`
are refused by the type rules. `PATH` is the only list snug writes, so the
exemption is one variable wide; `TestPATHIsSharedButNotReplaceable` pins both
halves. This is the distinction mounts already draw: a profile mounting over
another's grant is masking and refused; snug replacing a path with generated
content is replacement and allowed (`Mount.Authored`, `Policy.Replace`).

**`environ.types`** (`EnvKind`, `internal/policy/envdeclare.go`) licenses only the
declaring profile's own lines, so no profile's verdict depends on another file.
A shipped profile cannot declare (`checkTypesOfBuiltinNames`, `internal/profile`,
the one package that holds the builtins). A compatible declaration of a rostered
name is admitted and inert, so a row added later for a name somebody declared
breaks their profile only if it contradicts them. A declared `path-list` assumes
the empty element is an instruction (MANPATH's, §3.3), which is why `sanitise` is
refused on it. There is no key naming names without a type: `environ.set X = "x"`
in a file with an author already is the declaration.

**Header form, not inline tables.** Reasons, heaviest first: (a) `environ` sits
beside `ro`/`rw`/`tmpfs`, so root namespace stays nouns; (b) `environ` is a struct
with known fields, so `DisallowUnknownFields` refuses `environ.deny` exactly as it
refuses an unknown root key, with no new code; (c) `grep -rn 'environ.prepend'`
finds every ordered claim because the header spells the whole path. The flat
spelling `environ = { set = { ... } }` is **valid TOML 1.1.0** (newlines and
trailing commas in inline tables) and `go-toml/v2` in `go.mod` states TOML 1.1.0
conformance; measured through that version, every spelling decodes with a nil
error. Refusing it would need a second pass over the document text, because the
decoded value is identical and go-toml exposes no syntax provenance. snug does
not do this; **no comment may claim snug refuses the flat form.** A `python3 -m
tomllib` refusal is a TOML 1.0 parser.

**No `@stubs-in-path` profile.** Its abuse sentence cannot be written (the stub
is read-only, generated, allowlisted; `/usr/bin/podman` is still reachable by
absolute path), and a profile that grants nothing is a preference wearing a
profile's clothes. The two existing gates already select the exact intersection
(genuine podman and shim, stub; otherwise none, with a warning), and a third
ANDed condition only adds a break: `defaults = [...]` replaces the built-in list,
so trimming it would silently lose the stub. The answer is provenance in
`--dry-run`, not a name in `$SNUG_PROFILES`.

**`inherit`/`sanitise` stay in profiles, not `config.toml`.** `ANTHROPIC_API_KEY`
enters only when `@claude` is selected; a host-wide config line would put it in
every sandbox, inverting CLAUDE.md's bound on adapters. `profiles.d` and
`config.toml` sit at the same trust level, so moving only widens the scope.

## 2. Behaviour

### 2.1 Roster and the verb/variable agreement

`envTypes` is the ROSTER and answers one question: what IS this variable. An
unknown name is not a scalar by default: three red-team rounds each found a set of
names a default type had not been taught about, while the space ("every variable
some tool turns into an exec") stayed unbounded.

- A profile snug **ships** may write only a name with a row, enforced in
  `internal/profile`'s `mark` via `policy.IsUnknownEnv`. A roster row is where the
  sentence saying what the variable lets a tool DO is reviewed, and a shipped
  profile owes that review because no human stands behind it.
- A profile a **human** wrote may write an unrostered name at `set`/`inherit`; it
  renders `← unknown` from the same predicate. The three list verbs need a row or
  a same-profile `path-list` declaration, because they need the separator and the
  empty-element meaning, which inferring from a value's shape would guess.

`inherit` is refused for every list, as a rule rather than a per-row column
(carrying it per row is how it gets lost in a rewrite): copying a host search path
imports directories that do not exist inside; `sanitise` is the list form.

**`set` carries a value from a reviewable file in the trusted layer; `inherit`
carries whatever the host process had at launch. `inherit` is a hole punched in
`--clearenv`; `set` is not.** `envNote` therefore carries one sentence for authored
verbs and one for host verbs. For `BASH_ENV`, `ENV`, `PYTHONSTARTUP`,
`PYTHONBREAKPOINT`, `LESSOPEN` they differ: `BASH_ENV = "{home}/.snug-init"` with
the file granted by the same profile is reviewable, while the same name inherited
names a file chosen on the host, outside any profile.

Annotation reach, by the measurement that put each in its class (the table is
`internal/policy/envtypes.go`; this lists the classes):

- Every verb: names snug owns, `LD_*`, `BASH_FUNC_*`, `GIT_CONFIG_*`, the ten
  glibc strips from `ld.so(8)`, git/ssh transport hooks (`GIT_SSH`,
  `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, `GIT_ASKPASS`, `SSH_ASKPASS`,
  `GIT_EXEC_PATH`, `GIT_EXTERNAL_DIFF`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`),
  `GIT_PAGER`, `GIT_TEMPLATE_DIR`, `GIT_DIR`, `GIT_COMMON_DIR` (a directory whose
  hooks are code), `GIT_ALLOW_PROTOCOL`/`GIT_PROTOCOL_FROM_USER` (re-enabling
  `ext::` is the transport), interpreter option channels (`JAVA_TOOL_OPTIONS`,
  `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `RUBYOPT`), prompt hooks other than `PS1`,
  the toolchain wrapper class (`MAKEFLAGS`, `GOFLAGS`, `CC`, `TAR_OPTIONS`,
  `RSYNC_RSH`, `RUSTC*`, `CARGO_*` carved out at `CARGO_HOME`), and the
  interpreter hooks `PYTHONPATH`, `PYTHONUSERBASE`, `NODE_OPTIONS`, `PERL5OPT`,
  which run on every interpreter start (`sitecustomize.py`/`usercustomize.py`,
  `--require`, `-M`), measured.
- `npm_config_*` is annotated at every verb, carved out at
  `NPM_CONFIG_USERCONFIG`: `npm_config_script_shell`/`npm_config_node_gyp` name a
  program npm executes. Measured in every case spelling npm's case-insensitive
  lookup honours, which is why one table (`prefixCaseFold`) decides case folding
  for the annotation table and for `policy.IsInlineConfigEnv`. The pointer
  carve-outs are the same set in both tables
  (`TestPointerExemptionsAgreeBetweenTheTwoTables`): authoring a pointer is the
  "generate, don't bind" mechanism, not the hazard.
- `PIP_*` is annotated at `inherit` only: the environment outranks the file snug
  generated (§4.5), and nothing under it has been measured to exec a program.
- `EDITOR`/`VISUAL`/`PAGER` at every verb: git's fallback chains are
  `GIT_EDITOR` → `core.editor` → `VISUAL` → `EDITOR` and `GIT_PAGER` →
  `core.pager` → `PAGER`, so annotating only `GIT_*` closes the visible half.
- `PYTHONPATH` is a list; `merge`/`prepend` on it are legal and annotated — the
  only list-verb capability annotation adds. `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  `CDPATH`, `GOFLAGS` are lists the roster marks neither mergeable nor
  sanitisable, so every verb stays refused on TYPE grounds.

The rule is not "the newest spelling": it is **the value is code, so say so at
every spelling**. The red team found `GIT_SSH` passing while `GIT_SSH_COMMAND`
sat above it, and hijacked a real `git fetch` in a sandbox whose ssh identity
another profile pinned. The type table says what may be merged; the annotation
table says what a tool DOES at any type (`LD_PRELOAD` is a list and is
annotated). Collapsing them gets two wrong answers at once. The annotation table
is a list to be extended, not retired.

### 2.2 snug never splits a string

A string is one element. A profile cannot write `"/usr/bin:"`, produce
`"/usr/bin::/bin"` by dropping an element, or smuggle `;` into `LD_LIBRARY_PATH`;
snug joins with the variable's separator and refuses an empty element, closing the
§4.3 hazards by construction. If nothing survives a `sanitise`, the variable is
UNSET, not set-empty (an empty `PATH` is the current directory; `LD_LIBRARY_PATH`
empty is not absent to the loader), and snug never emits `--unsetenv`.

### 2.3 Name grammar

TOML keys are arbitrary strings and go straight to `--setenv NAME VALUE`, so
`checkEnvNameAt` enforces `[A-Za-z_][A-Za-z0-9_]*` at parse time (so `snug
profile show` reports it and the verdict is host-independent). `=` is the one to
name: `NAME=VALUE` is the wire format, so a key containing it is a second
assignment smuggled inside the first. These refusals are about what a name would
BREAK (wire format, a screen row), not about what a human may have.

### 2.4 What `prepend` guarantees

Bands are structural; nothing a profile writes changes which band an entry lands
in: `prepend` (one claim) → `merge` (sorted) → `sanitise` (host order, filtered) →
snug's generated → base. `prepend` guarantees the front, nothing more. It does not
make merge order-free: merged entries are sorted, so between two profiles ASCII
decides and `/opt/bin` beats `/usr/bin` without anyone using `prepend`. Base
entries are structurally last. If you care which of two profiles wins, `prepend`
is the only way to say so, and only one gets it. That is an effective-behaviour
non-monotonicity of the same shape as mount depth, stated rather than
discovered. The slot is a user's: snug's own contribution is authored, not a
prepend, so `defaults` does not consume it. Identical claims after `{var}`
expansion agree (equality is over the whole ordered sequence), making `prepend`
behave like `set`, `identity`, `address`, `gateway` and `mtu`: one single-valued
slot, equal claims join, unequal is a symmetric error naming every claimant.
Claims accumulate during the fold and are checked after it, so no fold order leaks
into the message.

### 2.5 Grant coupling is not a boundary

The rule is a **coupling rule, not an existence check**: the profile that names a
path must be the one that put a node on the chain to it, so a reviewer of one
profile sees both acts. It cannot prove the path exists (`internal/policy` may
not touch the filesystem; a `tmpfs` grant creates an empty directory; a bind's
contents are host state). **It is not a boundary**: the value is inert and the
payload can set any variable once running. It stops a profile lying; it does not
stop anything reaching. Put that in the code comment so no one cites the check as
a boundary.

Decisions: coverage downward, no depth limit, lexical `/`-boundary containment on
guest paths; symlinks are resolved first and never a grant themselves; the
`include` closure counts, the selected set does not (otherwise `resolve([a])`
could refuse what `resolve([a,b])` admits, one edit from a visibility break, and
it must stay refused by name with a test); `optional` grants are checked against
profile TEXT, not resolved mounts (`@claude` marks every `ro` optional, so a
resolved-mount check would make legality host-dependent, and text-only lets
`snug profile show` render a verdict with no target); `host:guest` uses the guest
side. Coverage makes `@home` a rubber stamp for `$HOME`: accepted, because
`environ` cannot create a mount, so a false positive is a variable naming an empty
directory, a usability bug rather than a hole. Refuse for profiles, mark for
snug's own: `HOME`/`PATH`/`SHELL` have no safe absent state (§4.2), a profile has
no such floor and refusing costs one line.

Two stages: parse time (name grammar, verb/type agreement, owned names, hand-written
separators), resolve time after `{var}` expansion (coverage, lexical over the
profile's expanded guest specs plus the symlink map). No new `Environ` method; an
existence check would be where a filesystem fact has to travel, and the answer is
no. `validate.go`'s `resolveVia` is not reusable as-is: it skips `g == link` (right
for a mountpoint, wrong for a `PATH` element that is literally `/bin`) and returns
the first match, nondeterministic when one link prefixes another. The environ entry
point must match `g == link` and pick the **deepest** link.

### 2.6 `sanitise` internals

- **Drop, never rewrite**: the host→guest map is not a function (`KindData` mounts
  have no host path; `Mount.Host` is canonicalised). An element survives iff, read
  verbatim as a guest path, a grant covers it. The same string can be kept in one
  sandbox and dropped in another because the filter reports the policy, not the host.
- `ro` is enough; no mode bits, no `stat`. It is a **truthfulness filter, not a
  capability filter**: a surviving `PATH` element may be an empty bind.
- Kind: the **deepest** covering mount decides; `KindTmpfs`, `KindProc`,
  `KindDev` drop; bind, generated data, granted symlink keep. "Keep if any mount
  exists at or below" is a second, downward walk that re-admits the removed element.
- **Why tmpfs drops** (verified end to end, marker `SHADOWED-GIT-RAN`): under
  `@home`, `{home}` and four subdirectories are tmpfs, and `/tmp` is tmpfs in every
  policy. A host `PATH` carrying `/tmp/x/bin` landing in snug's `PATH` would name a
  directory that is empty and writable inside, ahead of `/usr/bin`; the payload
  drops a file called `git` there. The bound on the claim: the payload can rewrite
  `PATH` at will, so no filter closes shadowing. What the filter owes is that the
  environment snug itself hands over does not ship the shadow slot pre-installed.
  A writable **bind** (the target's own `bin/`) still survives: it is truthful host
  content, and dropping all writable elements would chase an invariant the sandbox
  cannot hold.
- **`/proc` and `/dev` drop too.** Keeping them reasoned "kernel-populated, not
  empty" — true of the directory, false of what `/proc`'s magic links resolve to.
  The filter is lexical; the kernel walks `/proc/self/root/tmp/x/bin` to the
  writable tmpfs and `/proc/self/cwd` to the target, both reproduced. General
  form: **a lexical predicate answers about the path it was handed, the kernel
  about the path it resolves; where they differ is where the attack is.** `..`,
  trailing and repeated slashes were probed and are not exploitable (the walk
  cleans first). `KindSymlink` survives because a grant authored it and following
  it would be a second resolution rule; `/proc`'s links are kernel-authored.
- `@claude` stages its binary in `policy.StagedBinDir` (`/snug/bin`), unwritable
  from inside, rather than a read-only bind inside a writable directory on
  `PATH`: `merge` entries are written in a profile, and no `sanitise` correctness
  reaches them.
- Unset and empty both mean absent, for lists only; the collapse is exactly wrong
  for flags (`NO_COLOR`, `CI`: "set to any value, including empty"), so
  `sanitiseHostList` keeps its own check instead of a shared helper.
- After `merge`: a `merge` is a declaration by a selected profile, `sanitise` a
  filtered copy of ambient host state, and a declaration must beat ambient state.
  So a `sanitise` can only append. Survivors keep host order, unsorted: sorting is
  a second silent transformation, and position is semantic for `GOPATH` (element
  0 privileged). Duplicates collapse to their earliest band, keeping `prepend`'s
  guarantee literally true.
- Monotone because grants only grow. The one shape that breaks it, a tmpfs
  appearing beneath an existing bind, cannot occur only because `rejectMasking`
  refuses it, so `TestSanitiseMonotonicityRestsOnRejectMasking` makes a relaxed
  masking rule fail loudly.

### 2.9 Annotation contract

**snug has only allowlists.** The base state is an empty environment
(`cmd.Env = []string{}` plus `--clearenv`); a profile is a named hole; a table
that refused a NAME was snug refusing its own user a hole in their own sandbox.
The author stands on the far side of the line the sandbox draws: snug constrains
the payload, never the person configuring it. What snug owes is that the screen
the profile is approved on says what was approved. `forbiddenEnv`, its prefixes and
the roster `noInherit` bit are `policy.EnvNote` annotations, rendered by
`--dry-run` and `snug profile show`. Measured over the 113 names with a table
entry: 147 (name, verb) pairs across 82 names are allowed-with-annotation and
nothing goes the other way; prefix families are unbounded on top.

**The roster holds type facts only**: scalar or list, separator, alternate
separator, empty-element meaning, path-ness, composability. If a field answers "may
a profile do this" it does not belong in `envType`; "what IS this variable" does.

**Exactly three refusal kinds, none a rule about what a human may have:**

| kind | says | where |
|---|---|---|
| ownership | snug writes this name itself, every run or in this selection | `checkEnvOwnership`, `SnugOwnedEnv`; `checkConditionalEnv`, `conditionalEnvs`; `checkEnvTypes` |
| type | snug cannot carry out this verb on this variable correctly | `checkEnvVerbType`, `checkUnrosteredName`, `checkDeclaredVerbType` |
| transport | this name/value would corrupt a mechanism or forge a screen row | `checkEnvName`, `checkEnvValue`, `checkEnvElement` |

Ownership returns `nil` early for a rostered list, which is what lets a profile
`merge` onto `PATH`. `checkEnvElement` reads the roster or the profile's
declaration for the separator; a name with neither has no separator to smuggle.

**A rendered row carries up to four statements, none replacing another**, widest
first: `unknown` (about the NAME), `declared` (the NAME), annotation (the VALUE:
what the tool does), `not granted` (the VALUE: absolute-looking, nothing covers
it). They co-occur without contradiction (`set PIP_INDEX_URL`: no type row, yet an
annotated family). `TestUnknownMarkJoinsRatherThanReplacesTheGrantMark` drives a
fixture with all three (`GIT_SSH_COMMAND`). On `PATH` entries only, `← writable
from inside` marks a shadow slot; `not granted` means nothing is there, `writable`
means something is there and the payload can add to it, and they are not mutually
exclusive (a dangling link on writable ground is both; `not granted` takes
precedence, `TestGrantMarkPrecedesGrantedWhenBothConditionsHold`). It is PATH-only
because a writable `CARGO_HOME` is what that variable is for, and marking it
teaches the reader to skip the mark where it matters. It is a mark, not a refusal:
a human may deliberately put a writable directory on `PATH`; what snug may never do
is **ship** one (`TestNoBuiltinPutsAWritableDirectoryOnPATH`).

**An annotation must never become a grant.** `IsUnknownEnv` answering from the
roster OR the annotation table would make every annotated name (sixty, including
`GIT_SSH_COMMAND` and `RUSTC_WRAPPER`) one a shipped profile may write.
`snugKnowsEnvName` reads the roster alone, pinned by
`TestAnAnnotationDoesNotMakeANameCheckedForABuiltin`.

**The residual, stated.** `checkBuiltinEnvRoster` alone keeps `GIT_SSH_COMMAND`
out of a shipped profile, and it holds because that name has no roster ROW, not
because anyone decided a builtin may not write it. Adding a row to an annotated
name opens the gate silently. Extending the rule to "nor any annotated name" was
rejected on measurement: `@claude` inherits `PAGER` and `ANTHROPIC_BASE_URL`, both
annotated, so a blanket refusal fails `Builtins()` and every command with it.
Instead the annotated pairs a shipped profile writes are a pinned inventory
(`TestAnnotatedEnvPairsAShippedProfileWritesArePinned`, `internal/profile`), so
opening the gate moves a list a human reads. It is not a gate.

**`EDITOR`/`PAGER` in `@claude`.** A profile may set `PAGER` or `EDITOR` to a
command and git runs it (`PAGER="sh -c '…'" git log` measured hijacked). Nothing
untrusted chooses the value, so this is one profile weakening another, not an
escape. Measured inside `@claude`: `command -v vi vim nano` finds nothing and
`less`/`more` exist, so an inherited `EDITOR` names an absent program while
`PAGER=less` names a present one. `EDITOR` and `VISUAL` are withdrawn from
`[profile.claude.environ.inherit]` and `PAGER` stays: the grant was wider than the
need (invariant 2's corollary). An identity-conditional refusal would be a grant
changing meaning with its neighbours, the shape invariant 1 refuses.

**Review artifact:** `internal/policy/testdata/annotations.txt` is the golden of
every sentence at every verb a profile can write; against an annotation the
boundary is the sentence a human reads, and a sentence with no golden is prose
drifting from its measurement. `policy.IsInlineConfigEnv` and
`TestNoBuiltinHandsOverAnInlineConfigVariable` are builtin-only: the environment
snug itself hands over must not ship the override pre-installed; a user profile
handing over `GIT_CONFIG_KEY_0` is legal and annotated.

## 3. Measurements behind the roster

### 3.2 Scalars

`TZ` is not a plain string: a file reference under `TZDIR` or an inline POSIX
rule, and when the file is unreachable glibc re-reads the same value as a rule.

```
env -i TZ=Asia/Tokyo                    date -d @0 +"%z %Z"  →  +0900 JST
env -i TZDIR=/nonexistent TZ=Asia/Tokyo date -d @0 +"%z %Z"  →  +0000 Asia
```

Every timestamp is silently wrong on no channel at all, so a value chosen without
granting `/usr/share/zoneinfo` would be a guarantee not kept (invariant 5). No
profile chooses one: `TZ` is owned and copied from the host. `TZDIR` is annotated
with this measurement.

`XDG_RUNTIME_DIR` carries obligations (owned by the user, mode 0700, session
lifetime), so authoring it is a grant, and it belongs to whichever profile creates a
directory meeting them. `CONTAINER_HOST`/`DOCKER_HOST` are URLs, not paths;
podman dials an `ssh://` URL itself and does not read `DOCKER_HOST` at all
(measured, podman 6.0.2). `BROWSER` is the login bridge's client
(`/snug/lib/snug/browser`, snug's own executable) when `login = ["claude"]`;
Claude Code execs the program with the URL as its argument. A raw `SSH_AUTH_SOCK` signs with every key
the agent holds.

### 3.3 Empty elements decide `sanitise`

The discriminator is the empty-element column, not the type. An empty element is
safe where ignored, hazardous where it means the current directory (inside snug
the writable target), illegal where it is an operator; a type carrying a
separator must also carry the empty-element kind or the sanitiser is wrong for a
third of its inputs. `PYTHONPATH`'s `sitecustomize.py` on any element runs at
interpreter start, and its empty element is the current directory, so `sanitise`
is refused on it (from the `sanitisable` column) while `merge`/`prepend` are legal
and annotated. `MANPATH` is the sharpest: removing an element can ADD directories.
man-db announces the choice:

```
env -i MANPATH=/a     manpath  →  ignoring /etc/manpath.config    → /a
env -i MANPATH=:/a    manpath  →  prepending /etc/manpath.config  → /usr/share/man:/a
env -i MANPATH=/a::/b manpath  →  inserting /etc/manpath.config   → /a:/usr/share/man:/b
```

`LD_LIBRARY_PATH` (`:` or `;`) and `LD_PRELOAD` (`:` or space) are why the
separator lives in the type, not the parser: `ld.so(8)` gives them two different
sets, neither escapable. `GOPATH` element 0 is privileged and an empty first
element empties `GOMODCACHE`. `CLASSPATH`'s empty element is unverified. XDG
variables are the exception: empty is unset and relative paths must be ignored per
spec, so a naive sanitiser is safe there by specification.

### 3.5 Semi-structured names take no verb, except `PS1`

`LS_COLORS`, `TERMCAP`, `DBUS_SESSION_BUS_ADDRESS`, `GIT_CONFIG_PARAMETERS`,
`IFS`: no verb accepts them, so there is nothing to refuse; a tool wanting colour
sets `LS_COLORS` itself. Why they cannot be merged: `PS0`–`PS4` are a template
language on which bash performs command substitution (`promptvars`, default on,
measured); `PROMPT_COMMAND` runs before every prompt; `LS_COLORS` values contain
`;`, a separator in `LD_LIBRARY_PATH`; `IFS` is a set of delimiters; `BASH_FUNC_*`
is a name pattern carrying exported shell functions, and **function lookup
precedes `PATH` entirely**, so it defeats every ordering question here.

`PS1` is owned, and not as a security control: anything inside can set it. Refusing
the user's configuration buys nothing against a hostile payload and hurts the human
asking "am I inside?". `environ.inherit = ["PS1"]` stays refused because command
substitution fires before the user types anything. The preference is a constrained
template (`prompt = "..."` in `config.toml`, fixed placeholders, bash's own
escapes, no command substitution). The template is still a display string, so `\r`
or a cursor escape can erase what precedes it. Machine-readable is a separate
channel: `SNUG=1` and `SNUG_PROFILES`.

## 4. Evidence

### 4.2 Authoring and granting are two acts

`HOME` is assigned unconditionally while the directory is created by `@home`;
`SHELL` and `PATH` name things `@sys` grants. With `--no-defaults -p @parent-ro`
none of them exist. Not a hole, a confusion bug. The repair is to MARK, not to stop
authoring: `PATH` has no safe absent state (§4.3), and `HOME` is where the identity
generator writes `~/.gitconfig`, `~/.ssh/config` and `known_hosts`, so a profile
able to move it would silently defeat identity pinning. `--dry-run` flags any
authored value whose path nothing grants (invariant 5's shape).

### 4.3 An empty element is not nothing

```
env -i PATH="/usr/bin:"      sh -c 'victim'  →  PWD-BINARY-RAN
env -i PATH="/usr/bin::/bin" sh -c 'victim'  →  PWD-BINARY-RAN
env -i PATH="/usr/bin:/bin"  sh -c 'victim'  →  command not found
env -i PATH="/usr/bin:" /usr/bin/env victim  →  PWD-BINARY-RAN   ← execvp(3), not the shell
```

An empty `PATH` element is the current directory, in snug the target. A naive
sanitiser (string replace: `/usr/bin:/hostonly/bin` → `/usr/bin:`) is a feature
sold as tightening that would let a hostile process drop `git` in the project root
and have it run. Hence §2.2. There is also no safe *absent* state: unset is the
floor for `execvp`, but bash substitutes a compiled-in default ending in `.`:

```
env -i bash --noprofile --norc -c 'echo "${PATH-UNSET}"'
  /usr/local/bin:/usr/bin:/bin:.        ← DEFAULT_PATH_VALUE
```

so `PATH` must always be authored. `snug . -- cmd` resolves `cmd` against the
sandbox `PATH`, not the host's: bwrap `--clearenv`s, `--setenv`s `PATH`, then
`execvp`s inside the namespaces (`PATH=/…/hostonly:$PATH snug . -- hostmarker` →
`bwrap: execvp hostmarker: No such file or directory`). A refactor to a host-side
`exec.LookPath` would keep every test green and make the negative case succeed
(`test/integration/sandbox_test.go`).

### 4.5 The environment outranks the file

"Generate, don't bind" pins a tool's config file and leaves its environment, a
higher-precedence source:

```
env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_PARAMETERS="'user.name'='StillInjected'" git config --get user.name
  StillInjected

env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=AlsoInjected \
       git config --get user.name
  AlsoInjected
```

*A hostile process inside the sandbox can set `GIT_CONFIG_KEY_0=core.sshCommand`
and have the next `git fetch`, including one a user or agent runs, execute its
command, with `GIT_CONFIG_GLOBAL` pointing at a clean generated file.* Not a
sandbox-boundary break (the payload already runs code); a break in identity
pinning. Same shape for npm (`npm_config_*` outranks `.npmrc`) and pip (`PIP_*`
outranks the file). No fix exists for the payload-authored route (the value enters
git at command-line scope above every config file, and every mitigation tested
lives in the channel the attacker owns); what snug owes and asserts is that the
environment it hands over never ships such a name (`policy.IsInlineConfigEnv`,
`TestNoBuiltinHandsOverAnInlineConfigVariable`). See `GIT-CONFIG.md` §9 and
`GENERATED-CONFIG.md` §7.

## 5. Rejected

Reopen one only with a reason.

- *Sort and hope*: commutative and meaningless.
- *A priority number* (`rank = 100`): the priority field invariant 1 was written
  against; ties put you back where you started. Systems with one author controlling
  the sequence (makeWrapper, Environment Modules) use the sequence; a number
  appears where units are independently authored (Lmod, NixOS `mkOrder`), as snug's
  are, so the real choice is a number or a refusal.
- *Declared shadowing* (`shadows = ["podman"]`): compares directory contents, needs
  filesystem reads, and stays partial because `/snug/bin/podman` does not exist at
  resolve time. "One prepend across the set" gives the same guarantee from
  declarations.
- *Order from structure*: mounts need no priority because depth decides; nothing
  in a search path plays that role. Provenance gives a band, not a total order.
- *An expression language* (Dhall, CUE, Nickel, Starlark, KCL, Pkl): the one worth
  understanding. `DisallowUnknownFields` is a **syntactic** guarantee (a negation
  key cannot be smuggled in, checked by listing keys). A language moves it to
  **semantics**: nothing needs `deny` when a profile can write `filter (λd → d !=
  "/usr/bin") host.PATH`, and invariant 1 would be re-proved against a language on
  every dependency release. CUE is the closest fit (unification is the lattice this
  format wants; conflict is an error, no override) but has imports, against
  invariant 3. Borrow CUE's semantics; do not take the dependency.
- *Subtraction vocabulary*: makeWrapper `--unset`, systemd `UnsetEnvironment=`,
  flatpak `unset-environment` and Modules `remove-path` remove; NixOS `mkForce` and
  Nickel `force` override by priority; CUE and Kubernetes do neither. Borrowing by
  analogy imports removal or a priority field, which invariant 1 forbids. Asked
  "what is the `unset` here?", the answer is there isn't one.
- *A separator key on `environ.types`*, or a declared `sanitise` or empty-element
  kind: these are measurements of a consumer and a key would have the author state
  them unmeasured. `PATH` and `PYTHONPATH` share separator and path-ness and differ
  in sanitisability.
- *Types in `config.toml` or a registry-level `[types]` table*: `config.toml` holds
  preferences, never grants, and a shared table makes one file's verdict depend on
  another's.
- *Parameterised profiles as the ordering mechanism*: solves membership, not order.

## 6. Open

- Is `environ.append` needed? Nothing has asked. Leaving it out keeps one ordered
  operation, which is what makes "at most one across the set" easy to state.
- `XDG_RUNTIME_DIR` needs an owner: whichever profile creates a directory meeting
  the spec's obligations.

## Tests

The suite is the truth: `internal/policy/envresolve_test.go`, `envtypes_test.go`,
`envallowlist_test.go`, `envnotes_test.go`, `envcoupling_test.go`; `--dry-run`
rendering in `internal/cli/testdata/env.*.txt`. The `PATH` sanitise of §4.3 is the
one place where getting it wrong ADDS a hole, so its regression test needs the
positive control that a planted binary in the target *is* found when an empty
element is present; `envresolve_test.go` carries the same hazard from the other
side (an empty element in the HOST's value must never be carried through).

## Sources

[makeWrapper](https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/setup-hooks/make-wrapper.sh) ·
[systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) ·
[flatpak-run(1)](https://www.man7.org/linux/man-pages/man1/flatpak-run.1.html) ·
[Lmod ref counting](https://lmod.readthedocs.io/en/latest/077_ref_counting.html) ·
[NixOS properties](https://nixos.wiki/wiki/NixOS:Properties) ·
[Nickel merging](https://nickel-lang.org/user-manual/merging/) ·
[CUE spec](https://cuelang.org/docs/reference/spec/) ·
[POSIX ch. 8](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap08.html) ·
[ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html) ·
[XDG Base Directory Specification](http://specifications.freedesktop.org/basedir/latest/) ·
[Bash variables](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
