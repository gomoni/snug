# Design note — parameterised profiles

**Status: postponed by decision. Not scheduled.** Filed so the reasoning is not
re-derived later. Read this before starting; several conclusions are not obvious
and two of them are independent bug reports (see "Findings that are not about
parameterisation", at the end).

---

## The short version

The owner's sketch:

```
[[profile.-srv-rw]]
rw_dirs = /srv, /foo, /bar
```

**Read the body, not the name.** A "parameter" `/srv` whose body grants `/srv`,
`/foo` *and* `/bar` is not a parameterised profile — it is an ad-hoc list of
grants that wanted a name. **That already works today, with no new code:**

```toml
# ~/.config/snug/profiles.d/mine.toml
[profile.srv-rw]
description = "The three directories my build reaches outside the project."
rw = ["/srv", "/foo", "/bar"]
```

`Load()` reads `$XDG_CONFIG_HOME/snug/profiles.d/*.toml`, `merge` lets it add
names, `snug profile show srv-rw` renders it, and `include = ["srv-rw"]` builds
on it. **A user-written profile file is already the mechanism for any grant
stable enough to deserve a name** — which is exactly the "policy a mere human can
specify" requirement.

The residual demand is grants *not* stable enough to name — one-off, per
invocation. That is a flag's job, and flags are ~40 lines.

Parameterisation earns its place in exactly two cases, neither buildable today:

1. **A bundle of grants sharing one argument** — `worktree:PATH` → `ro {path}` +
   `rw {path}/target` + an env var. Nothing on the roadmap wants this yet.
2. **`net-publish:PORT`** — see "Why to keep the door open" below. This one is
   genuinely elegant and arrives with networking.

---

## The identity insight — it holds

The owner's instinct was that encoding arguments into the canonical name keeps
identity a single string, so `expand`'s set dedup, commutativity and idempotence
survive untouched. **That is correct**, and it is much cheaper than making
identity `(name, args)` — which would thread a tuple key through `expand`,
`Profiles`, `From`, `SNUG_PROFILES` and the dry-run renderer for no gain.

```
canon(base, bindings) = base + ":" + join(",", [expanded(p) for p in params in DECLARATION order])
```

Every param rendered, including defaulted ones, after full `{variable}`
expansion. Consequences, all wanted:

- `-p cache` and `-p cache:/home/u/.cache/snug` are **one** member
- `-p dir-rw:{target}` and `-p dir-rw:/home/u/proj/sub` are **one** member
- `-p dir-rw:/srv` twice is **one**; `/srv` and `/data` are **two**

**Proof sketch.** `inst(token) → (name, *Profile)` is a pure function of the
token and `vars` (which derives from `Context`, never from the selection), so the
same token always yields the same pair. `expand` inserts into `out[name]` with an
early return on presence, so `out` is a set keyed by `name` and insertion is
idempotent — *provided `canon` is injective on bindings*. The fold in `Resolve`
is unchanged: a join over semilattices, commutative, associative, idempotent.

### Three provisos

1. **`Resolve` must be reordered.** `canon` needs expanded values, which need
   `vars`, which needs the canonicalised target — computed in step 2, *after*
   `expand` runs in step 1. Step 2 moves above step 1 and `expand` gains a `vars`
   parameter. Knock-on: exported `policy.Expand` (called by `needsHostTmpDir`)
   runs before the host tmpdir exists, so its contract narrows to "which
   templates are reachable, ignoring arguments". Document that; it is one loop
   away from being wrong.
2. **The separator must be injective.** Args `["a,b"]` and `["a","b"]` both
   render `t:a,b`, and then the value stored under a key depends on insertion
   order — commutativity gone. **Rule: an argument may not contain `,`, `:` or
   NUL**, with an explicit error, not silent escaping. Corollary: **arity is
   fixed and list-valued params are forbidden**; multiplicity is expressed by
   selecting twice.
3. **Registry lookup stops being a bare map index** — but `Resolve`'s signature
   need not change; do the `token → (base, args)` split inside.

Also easy to ship by accident: `Policy.Selected` is copied verbatim from the
argument today, and `Implied()` diffs it against `Profiles`. If `Selected` holds
raw tokens while `Profiles` holds canonical names, **every instance the human
explicitly named renders as "pulled in by include"** in `--dry-run`.

---

## The trust question — the crux

Invariant 3 says the trusted profile set comes from outside the sandboxed
material. Parameterisation adds a *second* thing that authors a grant, so:

> **Both the template and the argument must originate outside the sandboxed
> material.** Effective trust is `template.Trusted && argsTrusted`.

| argument origin | `argsTrusted` |
|---|---|
| `-p dir-rw:/srv` on the CLI | **true** — the human typed it |
| a literal in `include` in a trusted-layer file | inherit that file's `Trusted` |
| a literal in `include` in a `--config` file | **false** (§2.7: convenience, not promotion) |
| `defaults` in `~/.config/snug/config.toml` | **true** |

`Profile.Trusted` is currently set and never read. Templates make reading it
mandatory.

### Where arguments must never come from

- **Environment variables. Never.** No `{env:FOO}`, no `$FOO`, no
  `SNUG_PROFILE` input variable. Specific and non-hypothetical reason:
  **direnv auto-loads `.envrc` from the repository you are standing in.** A
  hostile repo shipping `export SNUG_PROFILE=dir-rw:/` would author its own
  sandbox boundary from inside the material being sandboxed, with the human
  never typing anything. `SNUG_PROFILES` is currently *written* into the sandbox
  and never read — keep it that way, and say so in a comment.
- **Files read at resolve time.** No `-p dir-rw:@paths.txt`. Same reason, plus it
  breaks the purity that keeps the security-critical tests runnable in CI.
- **Anything derived from the target's contents.** `{target}` is fine — the human
  chose the directory. What is *under* it is not.
- **`{host_tmpdir}` in an argument.** Chicken-and-egg with the pre-flight
  allocation, and meaningless besides. Allowed in a body, forbidden in an
  argument.

### The interaction that most worries the architect

**Do not ship general-purpose `ro:`/`rw:` templates as builtins before §2.7's
privileged-grant gate exists.** The moment `rw` is a builtin template name, every
`include = ["rw:/"]` in any file snug loads is a total compromise — and
`$XDG_CONFIG_HOME/snug/profiles.d` is trusted unconditionally today. Templates do
not raise the ceiling (a repo-shipped profile can already write `rw = ["/"]`) but
they lower the effort to zero.

Note also that a body of `rw = ["{path}"]` **cannot be classified statically** by
§2.7's privileged-grant rule — its privilege depends on the argument. So §2.7's
classifier must move from load time to **post-instantiation, pre-`Validate`**
time. That is a design change templates force on §2.7.

A CLI flag has none of this: `--rw /srv` is by construction from the only trusted
origin there is.

---

## Why to keep the door open: `net-publish`

Today `publish = [3000, 8080]` would be a scalar list needing a hand-written
union join. As a template:

```toml
[profile.net-publish]
include = ["net"]
params  = [{ name = "port", kind = "port" }]
publish = ["{port}"]
```

`-p net-publish:3000 -p net-publish:8080` gives two set members, each
contributing one port, and **the union falls out of set membership.** The
list-union join stops being a special case and becomes a consequence of the
identity rule. That is the strongest argument for templates.

---

## Findings that are not about parameterisation

Three things the review turned up that stand on their own.

### 1. Monotonicity is overstated — CONFIRMED BY EXECUTION

`join` is keyed by `Mount.Guest`, so it only applies at *identical* guest paths.
Grants at different depths do not join; they become two mounts, emitted
ancestor-first. **Effective access at a path is the access of the deepest mount
covering it, not the join.**

Invariant 2 relies on this ("`ro /proj` + `rw /proj/src` leaves `.git`
read-only"). The *inversion* uses the identical mechanism:

```
$ snug $T/proj -- sh -c 'touch .git/CANARY'                    # .git WRITABLE
$ snug -p protect-git $T/proj -- sh -c 'touch .git/CANARY'     # Read-only file system
```
with `[profile.protect-git] ro = ["{target}/.git"]`. **Adding a profile reduced
write access.** `TestResolveIsMonotone` does not catch it because it compares
`Access` per existing `Guest` key, and `.git` was not a key in the base policy.

The honest statement, now in CLAUDE.md:

> **Visibility is monotone and structurally guaranteed (`rejectMasking`, no
> subtraction). Effective write access at a strict subpath is deliberately NOT
> monotone — it is the "layer by access" idiom, and it works in both
> directions.**

Defensible: lowering write access is a tightening, and a profile that only
tightens is a nuisance, not an escalation. But it must be *stated*, because
DESIGN §2.4 reads as though the per-key join is the whole story.

### 2. **[latent security]** A symlink planted in the target can divert a grant

`Resolve` canonicalises the host side of every bind with `EvalSymlinks`. So a
grant of `{target}/build`, where a *previous sandbox run* left
`build -> /home/u/.ssh`, binds `~/.ssh` into the sandbox.

Not currently reachable — no builtin profile uses a `{target}`-relative subpath
grant — but it goes live the moment anyone writes one, or the moment `--rw
./build` exists. The fix needs no `Environ` change:

```go
// Symlinks ABOVE the target (/home -> /var/home) are host configuration and are
// followed as today. Symlinks at or below the target are attacker-controlled.
func underTargetIsLiteral(env Environ, canonTarget, p string) error {
    rel, ok := under(canonTarget, p)
    if !ok { return nil }
    real, err := env.EvalSymlinks(p)
    if err != nil { return err }
    if real != filepath.Join(canonTarget, rel) {
        return fmt.Errorf("%s resolves to %s: a symlink inside the sandbox's own "+
            "writable area redirects this grant, and snug will not follow it", p, real)
    }
    return nil
}
```

Comparing against the *lexical join under the canonical target* — rather than
against `p` itself — is what avoids false positives from `/home -> /var/home` on
Silverblue-style hosts. Apply the same rule to `ctx.HostTmpDir`.

### 3. `ctx.Home` is never canonicalised

`ctx.Home` is used verbatim while the target is `EvalSymlinks`'d and fail-closed.
Host sides of `{home}/...` grants get canonicalised by `add()`, but the guest
side does not. Recommendation: `EvalSymlinks(ctx.Home)` once in `Resolve`, fail
closed if absent. **This will produce a golden argv diff on any host where
`$HOME` traverses a symlink** — the correct outcome, reviewed as a security
change.

---

## Migration path, if this is ever picked up

- **M-a** CLI grant flags (`--ro PATH`, `--rw PATH`) — same-path only, no
  `host:guest` form on the flag, since path translation is the mechanism by
  which masking is attempted. Fold `ctx.Grants` after the profile loop with
  `From: []string{"(command line)"}`. Add a `GRANTS` header to `--dry-run`; do
  **not** add them to `SNUG_PROFILES` — they are not profiles.
- **M-b** `--publish PORT`, with networking.
- **M-c** §2.7: `--config`, `Profile.Trusted` actually read, privileged-grant
  classification. **Prerequisite for M-d.**
- **M-d** templates, as specified above.

Do not reparameterise `tmp-shared` or any shipped builtin in the same change, or
the golden diff stops being readable as a security review artifact. Same reason
to land the `dotdot` → `parent-ro` rename before or after, never concurrently.
(That rename has since landed; the profile is `parent-ro` everywhere now.)

## Open questions the architect flagged

- `go-toml/v2` + `DisallowUnknownFields` with an array of inline tables where
  some elements omit `default` — should be fine, worth a five-line test first.
- Whether `Params` belongs on `policy.Profile` or a separate `Template` type.
  One type keeps `Registry` and the subcommands simple; two would make "a
  template contributes no grants" a type-level fact. Held loosely.
- Whether a stderr line per widening grant is noise. It is the mirror of "no
  silent downgrade", but it changes every non-dry-run invocation using a flag.
