# snug — design index

> *snug*: fitting closely and comfortably · marked by cordiality and secure privacy · offering safe concealment · a small private room in a pub

`snug` is an unprivileged sandbox launcher for untrusted code: a build you did not write, a dependency's install hook, a test suite from a freshly cloned repository, an AI agent. It is a single Go binary that reads a policy, generates a `bubblewrap` command line and (when networking is requested) a `pasta` command line, wires up a small number of tightly-controlled host-integration helpers, runs the payload, and tears everything down.

The model is general: everything below applies equally to `snug ~/src/proj -- make test`. Where this document says "the agent", read "the sandboxed process". An AI agent is simply the sharpest instance of the problem, because it is *supposed* to run arbitrary commands — so "do not run untrusted code" is not available as advice — but a dependency's postinstall script is untrusted in exactly the same way and gets exactly the same boundary.

## What this file is

`snug` is not a single document any more: where a topic document below covers a subject, it is the truth and this file is not. What is left here is the material with no other home — the guiding principle, the policy model, and the mount algebra and networking sections that ground everything else — plus the table that hands every other subject to the document that owns it.

**Three rules for reading it.**

1. Where a section links to a topic document, that document wins. Do not re-derive from the paragraph here.
2. Where a section is marked **DESIGNED, NOT BUILT**, no code implements it. Those markers are load-bearing: describing unbuilt machinery in the present tense has cost a milestone before.
3. Where this file and the code disagree, the code wins and this file is wrong — say so in a commit rather than leaving it. `internal/policy/types.go`, `internal/profile/profiles/base.toml`, `scripts/` and the goldens under `internal/policy/testdata/` are the executable statements of most of what is described here.

Kept sections are not renumbered: code comments and other documents cite `INDEX §4.2`, `§3.3` and a dozen more by number, and a renumbering would break every one silently.

## The topic documents

| document | the question it answers |
|---|---|
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | What snug is *for*, and the only authority on it: the protected asset (files, identity, loopback and desktop surface, persistence), the goals, the adversary — a confused, prompt-injected or hostile payload, and a hostile repository — and the non-goals stated with their measurements: the session mesh (an ACCOUNT boundary snug's MACHINE boundary cannot close), sibling access under one uid, the operator's terminal, mutable state, user-provided holes and the three shapes snug does refuse (mechanism, ownership, type — never "too dangerous for you"), and kernel bugs. Where a claim elsewhere disagrees with it about what snug protects, it is right. |
| [`ENGINE-NETNS.md`](ENGINE-NETNS.md) | Why a container started through `@podman-socket` has the *engine's* network and not the sandbox's — and what moving the engine into the sandbox's netns costs. §0 is the canonical write-up of that finding; §5.1 specifies the engine's **derived** mount view and what a graft costs. What was decided about it lives where it is enforced: `policy.EngineCapBounding` (the twelve capabilities and each one's abuse sentence), `internal/dockerproxy` (the endpoint and namespace-mode refusals), `internal/cli/containerpreflight.go` (the refuse-don't-degrade gates). |
| [`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md) | The stage, as built: `@net` forks a second long-lived process that creates the sandbox's network namespace, pins it, leaves it, and forks bwrap back into it — and, where a container engine is selected, forks that engine into the same namespace as bwrap's sibling. What was measured first, what each decision overruled, and what the reviews found. The throwaway proof of concept that took the first measurements has been deleted; its numbers are inline there, in §1. |
| [`ENGINE-WIRING.md`](ENGINE-WIRING.md) | How the long-lived container engine composes with the one-shot stage: forked eagerly by P1 as a sibling of bwrap, `setns`'d into the sandbox's N, confined to twelve capabilities, its socket on `/tmp` because podman masks `/run`, and torn down on every path. The design pass behind `internal/stage`'s `__inengine` and `startEngine`, both reached from the one `start` request. |
| [`NOCGO.md`](NOCGO.md) | Why snug builds with `CGO_ENABLED=0`, what that costs, and the measurements that made it affordable — including why `setns` into a user or mount namespace is closed to pure Go and why that turned out not to matter. |
| [`STORAGE-CONF.md`](STORAGE-CONF.md) | What pins each part of the container engine's store, measured against two podman versions: the image-only-in-one-store oracle, why containers/storage reads no config from inside `graphroot`, what `CONTAINERS_STORAGE_CONF` replaces and what it does not — and that `--root` discards every `[storage.options*]` key, so the `mount_program` snug generates never reaches the driver. |
| [`GENERATED-CONFIG.md`](GENERATED-CONFIG.md) | **The rule** for configuring a tool inside the sandbox: classify the file as data or command table, allowlist never denylist, R-SCALAR, R-NOPATH, reconstruct from parsed values rather than editing host bytes, and name every drop. `GIT-CONFIG.md`, `CLAUDE-SETTINGS.md` and `SIGNATURE-POLICY.md` are its three instances; npm, cargo, docker and pip start here. |
| [`GIT-CONFIG.md`](GIT-CONFIG.md) | Why `~/.gitconfig` is generated rather than bound, measured: `includeIf` evaluated by snug, `hasconfig:` refused, the whitelist and what is deliberately off it, and the seven wildmatch divergences the oracle test now catches. |
| [`SIGNATURE-POLICY.md`](SIGNATURE-POLICY.md) | Why the container engine's `policy.json` is a PROJECTION of the host's rather than a permissive file snug writes over it: the measured containers/image schema rules snug mirrors, why a non-empty `dir` scope refuses, why `sigstoreSigned` refuses, and where the key copies live. |
| [`CLAUDE-SETTINGS.md`](CLAUDE-SETTINGS.md) | Why `~/.claude/settings.json` is generated rather than bound: the key inventory measured against claude 2.1.232, the ten-scalar allowlist, the `env` door to `ANTHROPIC_API_KEY` it closed, and the plugin-hook channel it does **not** close (issue #68). |
| [`SECRETS.md`](SECRETS.md) | Which credentials reach a sandbox and why: the credential-versus-capability rule, the severity model, the three mechanisms (agent proxy, smaller credential, wrapper) with the test that picks one, what snug owes when it runs a tool on the payload's behalf, and the shapes that are refused with the measurement that refused them. |
| [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md) | Which container CLI actually works inside the sandbox, measured — and the `podman` stub that replaces a host-escape shim. |
| [`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md) | The environment configuration format: five `environ` verbs, the variable type table, resolution order, and the measured evidence behind each rule. |
| [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md) | What `/proc`, `/sys` and `/dev` expose, measured against a real host. |
| [`TARGET-LOCK.md`](TARGET-LOCK.md) | The per-target `flock` keyed on `sha256(realpath)` and resolved from the uid alone (never `$XDG_RUNTIME_DIR` — that split was the #122 fail-open). A run takes it SHARED: it records that a sandbox is live on the target for `snug proxy` and `snug engine gc`, and refuses nothing. The orphan sweep asks no target-wide question — it judges each run record on its own owner. |

Outside this directory: [`../../CLAUDE.md`](../../CLAUDE.md) is the working agreement and the list of expensive environment facts, [`../../scripts/`](../../scripts/) is the checklist — `make verify` runs the executable half and [`../../scripts/README.md`](../../scripts/README.md) indexes it and carries the by-hand one, and the [GitHub issues](https://github.com/gomoni/snug/issues) are the live list of known gaps and deferred work — each carries a severity label and the measurement that confirmed it.

**Status of the verification claims below:** every kernel/tool behaviour marked **VERIFIED** was executed on the development host (openSUSE, kernel 7.1.4, `bubblewrap 0.11.2`, `pasta 20260612`, running *inside* a rootless-podman `distrobox` container) at the time it was written. Age is a risk; `make verify` is the re-runnable form, and `scripts/README.md` says what each check asserts.

---

## 0. The guiding principle

> **Share nothing. Then punch explicit, named, minimal holes until the sandbox is useful.**

Everything in this design is a consequence of that sentence.

The base state of a `snug` sandbox is *not* "the host filesystem with some things masked". It is **an empty tmpfs root, an empty network namespace, and an empty environment**. Nothing is inherited. A profile is a *named hole*. There is no such thing as a "deny rule" in `snug`, because there is nothing to deny — the thing you would deny was never there.

This has three consequences that shape the whole system:

1. **Monotonicity is free.** Since the base is empty, every operation a profile can express is additive. There is no syntax for removal, so composition cannot tighten. (§2.4)
2. **"Hiding" is emergent, not implemented.** The `@parent-ro` profile does not hide your other projects; it simply never grants them. There is no masking pass, no `--tmpfs` overlay trick in the emitter, no ordering hazard from hiding. (§3)
3. **A missing capability is a feature, and is stated as such.** No X11 socket, no Wayland socket, no D-Bus, no host loopback, no `~/.ssh` — not gaps to apologise for, but the default. Where a hole is worth opening it gets a named profile that documents what it costs; where it is not (GUI, audio, D-Bus) the absence is simply the answer — see [`host-bridge.md`](../agents/host-bridge.md), "Out of scope: GUI, audio, D-Bus".

---

## 2. The policy model

**This section is the only home of the model.** The executable statement of it is `internal/policy/types.go` (the lattices), `resolve.go` (the fold) and `resolve_test.go` (the algebraic laws). Where the Go below has drifted from the code, the code is right.

### 2.1 Shape

A **Policy** is a *set of grants*. A **Profile** is a named, composable generator of grants. Resolution is **set union with a per-key join**. There is no removal operator, no ordering-dependent override, and no deny list.

`internal/policy/types.go` is the executable form of every type used below — `Access`, `Kind`, `Mount`, `NetMode`, `SSHMode`, `PodmanMode` and `Policy` itself — and is right where this section and it disagree.

### 2.2 Resolution

```go
// Resolve is pure, total on valid input, commutative and idempotent in `sel`.
func Resolve(sel []*Profile, ctx Context) (*Policy, error)
```

The algorithm:

1. **Expand `include` transitively** into a *set* of profiles (depth-first, cycle-detected). Because the result is a set, `include` is idempotent and diamond includes are harmless.
2. **Expand path variables** (`{target}`, `{target_parent}`, `{home}`, `~`) against `ctx`.
3. **Canonicalise host paths** with `EvalSymlinks`, and lexically clean guest paths.
4. **Fold the grant multiset into `map[Guest]Mount`** with this join — **RULE 1, the same-path rule**:

```
join(a, b) where a.Guest == b.Guest:
    if a.Kind    != b.Kind     -> ERROR (two kinds of node at one path)
    if a.Host    != b.Host     -> ERROR (bind: two host sources. symlink: two targets.)
    if a.Perms   != b.Perms    -> ERROR
    if a.Content != b.Content  -> ERROR
    else                        -> a with Access = a.Access.Join(b.Access)
                                       Optional  = a.Optional && b.Optional
                                       From      = union(a.From, b.From)
```

**Two grants join iff they describe the identical node.** Every error names both profiles and both values, so *"it broke"* becomes *"I know which line to delete"*.

***`ro` + `rw` must stay a join, and the reason is structural, not convenience.*** `Access` is the only field whose value domain is a semilattice; every other field answers *"what node exists here"*, and two answers to that have no join, only an error. §2.4's third leg — `Resolve(A ∪ B) ⊒ Resolve(A)` — is a statement about the access lattice. Make differing access fatal and `Resolve` stops being a total join, at which point monotonicity is no longer something the model *is*, only something we hope it does.

***The `Host` comparison is NOT guarded by kind, and guarding it is a real hole.*** Narrowed to `a.Kind == KindBind && a.Host != b.Host` it misses symlinks: for a `KindSymlink`, `Host` **is the link target**, so a narrowed comparison would never compare it, letting one profile silently displace another's symlink target — which §2.4 says is structurally impossible. `Host` is `""` for every kind with no host side, so comparing it unconditionally is free.

5. **Join scalars** using each key's declared permissive-ward join, or refuse symmetrically where the key has no permissive direction (§2.3).
6. **Union the env allowlist**; conflicting explicit `setenv` values are an ERROR. The environment has its own document — [`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md).
7. **Validate** (§3.4), which is where the *nesting* rules live: same-path conflicts are settled here, nested ones there. There is no clamp stage: the resolved policy is final (§2.5).

**Why it is commutative:** every fold operation is a commutative, associative, idempotent binary join, or an *error* (which is symmetric). `From` is excluded from equality, so accumulating provenance does not perturb the fixpoint. Emission order is derived from the *result* (§3.2), never from profile order.

**Why it is idempotent:** `join(a, a) == a` for every join used. Selecting `[sys, sys, target-rw]` is identical to `[target-rw, sys]`.

**Three different orders get conflated, and only one of them exists at runtime.**

| order | status |
|---|---|
| *selection* — the order `-p` names profiles | already irrelevant; kept only so `--dry-run` can say "you asked for this" vs "an include pulled it in" |
| *fold* — the order profiles are visited | sorted by name, and **no resolved value may depend on it**. Sorting is a determinism device, not a tie-break |
| *emission* — the order mounts reach bwrap's argv | depth-ascending and **load-bearing** (§3.2). A compiler concern that must never surface in the file format |

The fold is **sorted, deliberately not randomised**, and that is the stronger form of the requirement rather than a weaker one: randomising it in production would make a resolver bug *intermittent*, and a security tool that is wrong occasionally is worse than one that is wrong reproducibly. Randomness belongs in the test suite, where a shuffle is a property test and a flake is a finding — `TestResolveIsCommutative` shuffles 200 selections and compares the whole resolved policy, scalars included.

**Selecting a profile twice is already a no-op** for resolution: `expand` builds a *set*.

### 2.3 Why scalars do not break monotonicity

The prior generation (`agent-sandbox`) let a profile *override* a scalar, with the including profile winning. That is order-dependent and can tighten. `snug` forbids it. **Every scalar key's value domain must be a join-semilattice, and resolution uses the permissive-ward join.**

| Key | Domain | Join | Permissive direction |
|---|---|---|---|
| `network` | `isolated < egress` | `max` | more reachability |
| `listen_names` | name set | union (a SET) | more doors |
| `podman` | `off < socket < build` | `max` | more engine surface |
| `dns` | `bool` | `OR` | working DNS |
| `git` | `off < extract` | `max` | more of the host's git config carried |
| `ro` / `rw` | path sets | union + `Access.Join` | more access |

**No key in the model is last-writer-wins**, and `mtu` is the one that would most easily become it — taking whichever profile the sorted fold reached last, which is exactly the shape of dependence §2.2 forbids. There is no "more open" MTU, so it cannot be a join either: two profiles disagreeing is a **symmetric ERROR naming both profiles and both values**, as `identity` is. It remains a pasta cosmetic — it changes how the sandbox's stack segments, never what it can reach — and the refusal costs nothing, because selecting two profiles that each pin a different MTU was never a coherent request.

`listen_names` is a **set** for the same reason every other set-valued key is: two profiles naming `"web"` declare ONE door, and the resolved value must not depend on which profile the fold reached first.

**The rule for any new scalar:** a genuine permissive-ward join, or an error naming both profiles. Nothing in between.

Keys that would only ever *weaken* the sandbox in a way profiles must not control — notably `seccomp` — **are not profile keys at all**. `--no-seccomp` is a CLI flag only. A human may weaken; a file may not.

`network = "isolated"` is therefore a no-op, and there is deliberately no `network = "offline"`. **Offline is the absence of the `@net` profile.** If you write `include = ["@net", "@net-offline"]`, the result is `@net` — and that is correct, not a bug: you asked for the union of two grant sets, one of which was empty. To be offline, do not include `@net`.

### 2.4 Monotonicity by construction — the actual argument

Three properties together make "a profile can never tighten the sandbox" a *structural* fact rather than a review convention:

1. **The base is empty, and the emitter has no removal operation.** `snug`'s bwrap emitter can produce `--bind`, `--ro-bind`, `--dev-bind`, `--tmpfs`, `--symlink`, `--proc`, `--dev`, `--file`, `--ro-bind-data`, `--dir`, `--setenv`. There is no `--mask`, no deny path, no "hide" verb, because nothing needs hiding — **VERIFIED**: `bwrap`'s new root is a fresh, empty tmpfs. With `--ro-bind /usr /usr` and a bind of one project directory, `ls /home/u/projects` lists exactly `work` and nothing else, with no `--tmpfs` anywhere in the command line. Siblings are invisible because they were never mounted.
2. **The grant language cannot express negation.** TOML keys are `ro`, `rw`, `tmpfs`, `symlink`, `listen_names`, `include`, plus the scalars `network`, `podman`, `git`, `dns`, `mtu` and the `identity`/`environ` blocks. There is no `mask`, no `hide`, no `deny`, no `remove`, no `!`-prefix, no `unset`. This is enforced by strict decoding: unknown keys are a fatal parse error, so a future key cannot be smuggled in by a config written for a different tool.
3. **Resolution is a join over semilattices.** For any profile sets *A* and *B*, `Resolve(A ∪ B) ⊒ Resolve(A)` and `⊒ Resolve(B)` — the result is above both in the grant lattice. Adding a profile can only move you up.

The one place order matters is *emission*, and emission order is computed from the resolved set by a deterministic sort (§3.2), not from the order profiles were named. So the argv is a pure function of the resolved policy.

**Read the precise form of this claim in CLAUDE.md invariant 1.** The loose sentence "adding a profile never makes anything worse" is false in two named ways: snug's own `KindData` writes can displace a profile's grant at an identical path, and a *deeper* grant with weaker access lowers effective write access at a subpath (§2.5). Both are intended; neither is what `TestResolveIsMonotone` proves.

### 2.5 There is no restriction operation — anywhere

**Profiles only ever grant. There is no un-grant — not in a profile, not on the command line, nowhere. To grant less, select fewer profiles.**

```
Policy_final = Resolve(profiles)
```

That is the whole pipeline. Only the human, on the CLI, may tighten what a profile granted — never a profile itself — and `snug` has no mechanism for it: there is no flag and no field that reduces a resolved policy. `snug` stays minimal; `bwrap` is the swiss knife.

What that costs, stated plainly: a read-only project is obtained by not selecting `@target-rw` — `snug --no-defaults -p @sys -p @home -p @parent-ro <dir>` — which is verbose on purpose. A read-only target is possible but highly nonstandard, and the verbosity is proportionate to how rarely it is wanted.

What it buys: an invariant with no exceptions. "Nothing anywhere reduces what a resolved policy grants" is a property a reader can check by grepping for a demote and finding none, and two AST sweeps assert directly (`TestEveryAccessWriteIsAJoinWithThePreviousValue` and `TestMountCollectionsHaveThreeWriters`, `internal/policy/norestriction_test.go`, from #271 via #355/#361) — the second catching the shape the first cannot see, a `Derive()` that lowers access by building fresh mounts rather than by assigning to an `Access` field. `TestPolicyHasNoRestrictionOperation` asserts only that `Access.Join` takes the max, which is why it was never sufficient on its own. One with a carve-out can only be checked by understanding where the carve-out applies.

#### Visibility is monotone. Effective write access at a strict subpath is not.

That is the honest sentence, and it is written here rather than left implicit because the behaviour exists whether or not it is documented — confirmed against a live sandbox, not inferred from the argv.

**The rule, stated once: the DEEPEST mount covering a path decides what is true at that path.** `join` is keyed by `Mount.Guest`, so it only fires at *identical* paths. Grants at different depths do not join — they become two mounts, and bwrap applies them in depth order (§3.2), so the innermost one wins.

It runs in both directions, and both are load-bearing:

| arrangement | effect | who depends on it |
|---|---|---|
| `ro {parent}` + `rw {target}` | target is writable inside a read-only parent | `@target-rw` over `@parent-ro`, which is `snug -p @parent-ro <dir>` — the parent is not in the defaults |
| `rw {target}` + `ro {target}/.git` | `.git` is read-only inside a writable target | the arrangement invariant 2 recommends for "X but not Y" |
| tmpfs `$HOME` + a file at a path inside it | a file inside a writable ephemeral home | `@git`'s generated `.gitconfig`, `@claude`'s projected `settings.json`, every generated identity file — the generated ones are `KindData` that snug authors; `@claude`'s `ro ~/.claude/skills` and `ro ~/.claude/plugins` are profile-expressed binds at paths inside the same tmpfs |

So the second row — a profile *lowering* effective write access at a strict subpath — is not removable without breaking the third. Forbidding "a deeper grant may not be less permissive" would break `@git`, `@claude` and every pinned identity on the first invocation, because each puts a read-only node at a path inside a writable tmpfs.

**What is and is not conceded by writing this down.** It is a subtraction verb with a spelling (`ro = ["{target}/.git"]` inside a writable target), and §2.5 deleted `--read-only` and `Clamp` precisely so no exception would exist. But the two are not the same act: the clamp moved *the whole policy* down the lattice after resolution, while this is one grant being *more specific* than another. Nothing becomes invisible; the path is still there, still readable, and `rejectMasking` still refuses anything that would hide content (§3.4). A profile that only lowers write access at a path it names is a **nuisance, not an escalation** — and unlike the clamp, it is visible: it is a line in `--dry-run`'s FILESYSTEM block with a profile name next to it, and `--dry-run`'s headline annotation walks the same deepest-mount rule so it cannot report `(writable)` over a demoted subtree, nor `(read-only)` over a writable one.

**Do not read `TestResolveIsMonotone` as proving more than it does.** It compares `Access` per existing `Guest` key, and a deeper key did not exist in the base policy, so it cannot see this at all. `TestADeeperReadOnlyGrantDemotesASubpathOfTheWritableTarget` pins the scope explicitly — it exists to stop the first test being over-read.

---

## 3. Path and mount algebra

**This section is the only home of the mount rules.** `internal/policy/validate.go` is the executable form.

### 3.1 "access .." is subtraction-free

The requirement — *for `snug /some/other/project/sub`: `/some/other/project` readable, `sub` writable, and everything else under `/some` and `/some/other` invisible* — is achieved by granting nothing else.

**VERIFIED.** With this argv and no hiding operation whatsoever:

```
bwrap --unshare-all \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib64 /lib64 --symlink usr/lib /lib \
  --proc /proc --dev /dev \
  --ro-bind /home/u/projects/work/team /home/u/projects/work/team \
  --bind    /home/u/projects/work/team/snug /home/u/projects/work/team/snug \
  -- /bin/sh
```

the sandbox observes:

```
/                              -> bin dev home lib lib64 proc usr
/home                          -> u
/home/u                        -> projects
/home/u/projects               -> work       # 12 other projects invisible
/home/u/projects/work          -> team       # 6 siblings invisible
```

`bwrap` auto-creates every intermediate mountpoint inside its root tmpfs. Those skeleton directories are the *only* thing that exists at each ancestor level. This is why `@parent-ro` is one line of TOML.

Two refinements `snug` applies:

- **`--remount-ro /` as the final filesystem operation.** **VERIFIED**: the root tmpfs and its auto-created skeleton directories are writable by default; `--remount-ro /` makes them read-only and is explicitly non-recursive, so `/tmp`, `$HOME`, and the project bind keep their own flags. Result: `touch /ZZ` and `touch /home/u/ZZ` fail; `/tmp`, `$HOME` and the project remain writable. Without it, an agent can litter a shadow filesystem that looks real and confuses it. Note what non-recursive also means: it does **not** cover procfs, which stays `rw` — see [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md).
- **Explicit skeleton permissions.** `bwrap` creates auto-mountpoint parents as `0700` (**VERIFIED**: `/home/u/projects/work` came out `drwx------`). That is fine when the sandbox uid owns them, but `snug` emits `--perms 0755 --dir <path>` for every ancestor it can predict, so the tree is traversable regardless of `--uid`/`--gid` choices.

### 3.2 Emission order

`bwrap` applies filesystem operations in argv order, and later operations mount *over* earlier ones. `snug` produces a canonical order from the resolved set:

```go
sort.Slice(mounts, func(i, j int) bool {
    di, dj := depth(mounts[i].Guest), depth(mounts[j].Guest)
    if di != dj { return di < dj }           // ancestors strictly before descendants
    return mounts[i].Guest < mounts[j].Guest // lexicographic tiebreak: deterministic
})
```

**Depth-ascending is sufficient and necessary.** Necessary: `--ro-bind /home/u/proj` must precede `--bind /home/u/proj/sub`, or the writable bind is shadowed. Sufficient: the only ordering constraint in a subtraction-free model is containment, and containment implies strictly greater depth. Ties cannot conflict, because two grants at the same `Guest` path were already joined or rejected in §2.2.

**Ordering is a compiler concern and must never surface in the file format.** This is the one place in `snug` where order is load-bearing, and it is computed *from the resolved set* — a set that has no order of its own (§2.2). A TOML key whose meaning depended on where it appeared in the file, or on which profile was named first, would move an argv-generation detail up into the policy model, where it would then have to be reasoned about every time two profiles are composed. `BwrapFlags` is a pure function of the resolved `Policy`: `snug -p a -p b` and `snug -p b -p a` produce byte-identical output, and the golden files assert exactly that.

**This sort is also what makes the deepest-mount rule true** (§2.5): the innermost grant is emitted last, so it is the one in effect at its own path.

**VERIFIED**: `--ro-bind /home/.../cv` followed by `--bind /home/.../cv/snug` yields a read-only parent (`touch ../ZZ` → `Read-only file system`) with a writable child. The reverse order silently loses the writable child, which is why the sort is not optional.

The full phase order:

```
0. namespace + process flags     (--unshare-all, --uid, --hostname, --die-with-parent, fds)
1. filesystem grants             (depth-ascending, as above)
2. --proc /proc, --dev /dev      (fixed depth 1, emitted in phase 1's sort)
3. generated files               (--ro-bind-data / --perms --file), depth-sorted with phase 1
4. --remount-ro /                LAST filesystem op
5. --clearenv + --setenv ...
6. --chdir <target>
7. -- <command>
```

**VERIFIED**: generated files mount cleanly *on top of* a read-only bind — `--ro-bind /etc /etc` followed by `--ro-bind-data 7 /etc/resolv.conf` produces the generated content, while `/etc` itself stays read-only. Mounting over a path inside a read-only bind does not require write access to the underlying filesystem, because `bwrap` performs the mount in its own mount namespace before dropping into the payload.

### 3.3 Symlink resolution

Two distinct problems, two distinct rules.

**Host-side (the `Host` field).** Every host path is canonicalised with `filepath.EvalSymlinks` at resolve time. `snug` binds the *realpath* but mounts it at the *requested guest path*. This means `~/projects` being a symlink to `/data/projects` works, and it means a symlink planted inside the writable project cannot later be used to widen a grant, because grants were canonicalised before the sandbox ever started. A related latent issue — a symlink planted in the target diverting a grant that names a path *inside* it — is closed by `underTargetIsLiteral` (`internal/policy/resolve.go`), which refuses a grant at or below the target whose realpath moved; symlinks ABOVE the target are host configuration and are still followed.

**Guest-side (the `Guest` field).** `bwrap` cannot create a mountpoint at a symlink destination: it aborts with `bwrap: Can't create file at <path>: No such file or directory` when the destination component is a symlink. Generalised, the hazard is: `snug` emits `--symlink usr/bin /bin`, then a later grant asks to bind something at `/bin/tool`; that path now resolves *through* our own symlink into the read-only `/usr` bind, and the mount fails or, worse, lands somewhere unintended.

This is also why substituting a host binary is done by **PATH precedence, not overmounting** — see [`sandbox-policy.md`](../agents/sandbox-policy.md)'s "Facts this layer is built on" and [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md) §6, where it is the only mechanism available rather than the tidier of two.

`snug`'s rule, enforced in `Validate()` before any argv is emitted:

1. Build the sandbox's *own* symlink map from the resolved `KindSymlink` grants.
2. Resolve each `Guest` path through that map (plus the host's realpath for guest paths that alias host paths).
3. **Reject** any grant whose resolved `Guest` lands strictly inside another grant that is `AccessRO` and `KindBind` — with an error naming both grants and both provenances.
4. **Rewrite** any grant whose `Guest` traverses a `snug`-created symlink to its resolved form, and re-run the depth sort.

This turns a runtime `bwrap` abort into a resolve-time error with a readable message, and it is directly unit-testable against a fake `Environ`.

**A link target must be a clean path with no `..` component, refused at the fold.** Every guest walk here joins a target lexically, while the kernel resolves `..` after the component before it, so the two disagree whenever that component is a file, a missing name or another link. Measured: `/pbin -> /lnk/../..<ro dir>` read as the ro grant on `--dry-run` with no shadow-slot mark, while the payload's `git` ran from the tmpfs the kernel actually reached. Refusing the spelling is what keeps the walk and the kernel on one answer.

**The HOST's symlinks inside a bound tree divert a mountpoint exactly as `snug`'s own do, and that half is `rejectRelocatedGrant`.** The rule above reads `snug`'s `KindSymlink` grants. It does not read the host content a covering bind supplies for the components *below* it — and `bwrap` does, because it resolves a destination INSIDE the sandbox, one component at a time, against whatever is mounted there at that moment. `guestLanding` walks every non-`Authored` mount's guest path the same way and refuses any whose landing is not its own guest path, naming the link, the link's text, the landing, and `grant <landing> instead`. MEASURED on `bubblewrap 0.12.0` (issue #588): `--ro-bind $S/w/mnt $S/G/sub/mnt`, with a host `$S/cover/sub -> $S/w` inside a cover bound at `$S/G`, created its mountpoint at `$S/w/mnt` and served an earlier profile's `rw` grant read-only — exit 0, no refusal, and `--dry-run` rendering the row at `$S/G/sub/mnt`.

The refusal is what makes **`m.Guest` the landing** for every mount `rejectMasking`, `nearestCovering`, `checkNesting` and the depth sort see, so their lexical comparison of guest paths IS a landing comparison. It also removes what a "lands at" column in `--dry-run` would have disclosed: no policy `snug` will run has a mount whose landing differs from its guest path, so the FILESYSTEM block is true by construction rather than by annotation, and a column that is always empty is one nobody reads when it finally is not.

Two exemptions, both structural. The **final component** is never followed: `bwrap` opens the destination without following it (`Can't mount on symlink destination …`, above), so a symlink there is `bwrap`'s refusal rather than a redirection — which is also why `@target-rw` over `@parent-ro`, one component deeper, never `Lstat`s anything. **`Authored`** mounts are `snug`'s own writing and are judged instead by `rejectGeneratedOntoHost`'s walk, which starts at the covering grant's root and returns a host path; the two walks share exactly one step, `linkLanding`, because the namespace a link's text is read in is the part that was got wrong once (#580).

### 3.4 Validation

Before emitting anything, `Validate()` checks:

- Every `Guest` is absolute and lexically clean; no `.`, `..`, or empty components survive.
- No `Guest` is `/` with `KindBind`.
- The target directory exists, is a directory, and its canonical path is granted `AccessRW`. **Fail closed** — no target means no policy, never a permissive default.
- Symlink hazards (§3.3).
- At least one of `/usr` or `/bin` is granted, otherwise nothing can execute — reported as *"no runtime granted; add the `@sys` profile"* rather than a confusing `exec: no such file`.
- **RULE 4** — nothing but `snug` may put a node at `/proc` or `/dev` (below).
- **RULE 2** — nesting, judged on the outer mount (below).
- Relocation (§3.3) — a non-`Authored` grant whose destination lands anywhere other than its own guest path, checked before the two rules above so both may compare guest paths lexically.

`Validate` is the one refuser of an assembled policy, no companion. That is what lets `--dry-run` render a policy it would not run (`Resolve` returns `(p, err)` for `Validate`'s own refusal and `(nil, err)` for everything else). It is also run **a second time**, in `internal/cli`, after the staging layer has added the mounts that had to be created on the host first: the staged Claude credentials, the generated `gh` `hosts.yml`, the ssh-agent and container proxy sockets. Those are added after `Resolve` returned, so without the second pass they were never validated at all.

#### RULE 4 — `/proc` and `/dev` are `snug`'s, and a profile may not take them

`snug` authors `/proc`, `/dev` and `/tmp` *after* the profile fold, and yields to whatever is already there. That yield is intended for **`/tmp` only** — a profile replacing the private tmpfs with a host directory it names is how handing a file to a host tool works. For `/proc` and `/dev`, a non-authored mount is a **refusal** naming the profile: the yield is implemented by `yieldTo`, so the error can name the profile that lost rather than silently discarding its grant.

#### RULE 2 — nesting is judged on the OUTER mount's content

A grant *inside* another grant is only masking if the outer mount **has content at the inner path**. So the outer kind decides:

| outer | inner allowed? | why |
|---|---|---|
| `KindTmpfs` | **yes** | a fresh tmpfs exposes nothing, so nothing can be hidden by mounting inside it |
| `KindBind` of *H* | **yes** iff the inner is a bind of *H/rel* | re-granting the same tree at stronger access is a superset (`@target-rw` over `@parent-ro`); anything else substitutes content |
| `KindProc`, `KindDev` | **no** | populated by the kernel and by bwrap; a mount inside substitutes host content for kernel content |
| `KindData` | **no** | a grant beneath a regular file is meaningless |
| anything | **yes** if the inner is `snug`'s own authored replacement | RULE 3, below |

The `KindTmpfs` row is not a convenience: every shipped profile that puts a file into the ephemeral `$HOME` puts it inside `@home`'s tmpfs — `@git`'s `.gitconfig`, `@claude`'s `settings.json`, every generated identity file — so treating a tmpfs as maskable breaks three profiles on the first invocation.

Only the **nearest** covering mount is consulted. It is the one that actually supplies content at that path, and anything further up was already judged when it was itself the inner mount, because the walk is depth-ascending.

#### RULE 3 — authorship is a FIELD, not a convention

`Mount.Authored` marks a mount `snug` wrote itself rather than one a profile granted, and `rejectMasking` exempts on it. There are three production writers — `Policy.Replace`, `Policy.Graft` (which writes `p.Grafts`, judged separately by `checkGraft`) and `yieldTo` (which installs `/proc`, `/dev` and `/tmp` only when the guest is unclaimed) — so a profile can express none of them (`internal/policy/validate.go`).

This is the distinction the whole masking rule turns on, restated: **a profile mounting over another profile's grant is masking and is refused; `snug` replacing a path with its own generated content is replacement and is allowed** — the sandbox still sees a node there, just a truthful one, and `Replace` records what it displaced (`identity:work+replaces:@git`) so `--dry-run` says so.

---

## 4. Networking

This section is as load-bearing as the filesystem. A sandbox that cannot read `~/.ssh` but can `curl http://127.0.0.1:3100/` has not been sandboxed.

### 4.1 Why a network namespace, and not packet filtering

`snug` has no root. `iptables`/`nftables` rules are per-netns and require `CAP_NET_ADMIN` **in that netns**. You cannot get `CAP_NET_ADMIN` over the *host's* netns without privilege, so filtering the host netns is off the table entirely. You *can* get `CAP_NET_ADMIN` inside a netns you created in your own user namespace — but at that point you already have the netns, and the netns alone gives you a stronger, simpler property than any rule set:

**In a fresh netns there is nothing to filter.** No route to the host, no interface but `lo`, and the sandbox's `127.0.0.1` is *its own* loopback, a different loopback from the host's. Reaching the host's loopback is not "blocked", it is *not expressible*. That is a much better security property than a deny rule, and it fails safe: if `snug`'s helper dies, the sandbox loses connectivity rather than gaining it.

**The abstract AF_UNIX bonus, which people forget.** The abstract Unix socket namespace (`\0`-prefixed names, `@/tmp/.X11-unix/X0`, `@/tmp/dbus-*`, and a long tail of application IPC) is **scoped by the network namespace**, not the mount namespace. A sandbox that unshares its mount namespace but keeps the host netns can still `connect()` to every abstract socket on the host — including X11 on many setups, and D-Bus. Filesystem sandboxing does *nothing* about this; there is no path to not-mount. A private netns closes it completely and for free.

Per the guiding principle: this is a **win**, not a limitation. The default `snug` sandbox has no X11, no Wayland, no D-Bus and no host IPC, because it has no netns in common with your session and no sockets bound into its filesystem. GUI, audio and D-Bus passthrough are out of scope — see [`host-bridge.md`](../agents/host-bridge.md) — so this is the permanent state rather than a default awaiting a profile.

**One netns per sandbox.** Sandboxes never share a netns. Sharing would require joining an existing netns from outside (`setns`), which forces either a daemon to own it or a bind-mounted netns path that can leak — and it would let two sandboxes see each other's ports. Per-sandbox netns keeps the whole thing a single process tree with no persistent kernel object.

### 4.2 THE critical finding: `pasta`'s defaults re-open the hole — twice

`pasta` gives a netns a userspace TCP/IP stack with no privilege. But its defaults are tuned for "make the container work like the host", which is precisely the opposite of what `snug` wants.

**Hole 1 — `--map-host-loopback` defaults to the gateway address.** Known, and already handled by the prior generation. Without `--map-host-loopback none`, the sandbox reaches host loopback services by connecting to the gateway address.

**Hole 2 — `-T`/`-U` default to `auto`, and this is the one that bites. VERIFIED, and it defeated the previous implementation.**

`pasta`'s `-t`/`-u` (`--tcp-ports`/`--udp-ports`) forward **host → namespace**. Its `-T`/`-U` (`--tcp-ns`/`--udp-ns`) forward **namespace → host init namespace**, and *both default to `auto`*. With `-T auto`, `pasta` watches ports bound on the host's loopback and **binds the same ports inside the namespace's loopback, splicing them to the host**.

Run with the previous generation's exact flag set — `--config-net --map-host-loopback none -t none -u none` — inside the netns:

```
v4:631  REACHABLE  <-- HOLE      (cups)
v4:3100 REACHABLE  <-- HOLE
ns listeners:
LISTEN 0 128  *%lo:631   *:*
LISTEN 1 128  *%lo:3100  *:*
```

The host's `cups` and the service on `:3100` were fully reachable from inside the "isolated" namespace, at `127.0.0.1`, despite `--map-host-loopback none`. The `agent-sandbox` probe notes record seeing `*%lo:631` inside the netns and dismiss it: *"Probably an `ss`//proc artifact … but unconfirmed."* **It was not an artifact.** It was a live TCP forward, and a full HTTP conversation is possible over it.

Isolating the cause:

| flags | 127.0.0.1:631 from inside |
|---|---|
| `--map-host-loopback none` (only) | **REACHABLE** |
| `--map-host-loopback none -t none -u none` | **REACHABLE** |
| `--map-host-loopback none -T none -U none` | **blocked** |
| `--map-host-loopback none -t none -u none -T none -U none` | **blocked** (v4 and v6) |

`-T none -U none` is the flag pair that closes it. `--map-host-loopback none` is necessary but nowhere near sufficient.

**The design lesson is bigger than the flag.** `snug` must never rely on a helper's default being safe, in either direction. Two mitigations, both mandatory:

1. **Every security-relevant flag is passed explicitly**, even when it matches the current default, so a `pasta` upgrade cannot silently change posture. `--map-host-loopback none`, `-t`, `-u`, `-T none`, `-U none` are all always present in `snug`'s argv.
2. **An integration test asserts the *behaviour*, not the argv.** `TestHostLoopbackIsUnreachable` starts a listener on the host's `127.0.0.1`, launches a real sandbox, and asserts the connection is refused. Golden-argv tests would have passed on the buggy configuration; only a behavioural test catches a changed upstream default. This test is the single highest-value test in the suite.

### 4.3 Process topology, ordering, and lifetime

Two candidate topologies for creating the network namespace:

**(a) `pasta` creates the netns and spawns `bwrap` inside it**, with `bwrap` inheriting it rather than making its own.
**VERIFIED** that `pasta`'s command mode creates user + mount + ipc + pid + uts + net namespaces and maps your uid to 0 (`uid_map: 0 1000 1`). That is the problem: `pasta` has already built a user namespace with exactly **one** uid mapped, so `bwrap`'s nested `--unshare-user` inside it can only map that one uid, and any later need for a subuid range (podman) is dead on arrival. It also puts a process `snug` does not control at the root of the tree, and `pasta` is not designed to be an init.

**(b) `snug`'s own tree creates the netns; `pasta` joins it. ← what snug does.**

**Why (b):**

- The namespace set is created by a process `snug` wrote or forked, never by a helper. `snug` does not need `unshare(1)` on `PATH` at all.
- `pasta` is a *leaf* of the process tree, not its root. It can die, be restarted, or be absent without restructuring anything.
- The netns is referenced only as `/proc/<pid>/ns/net` or a pinned descriptor — never bind-mounted to a filesystem path. When the last reference goes away, the kernel destroys it. **Orphan netns leaks are impossible by construction**, because no persistent reference is ever created. (This is the difference from `ip netns add`, which bind-mounts under `/run/netns` and leaks exactly this way.) *That "by construction" is conditional on the netns holding nothing but the sandbox — [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §4 measures how it changes shape when the container engine moves in.*

#### Who actually creates it — three shapes, derived, never selected

`policy.NetnsOwner` (`internal/policy/topology.go`) is a three-point lattice and `deriveTopology` is its only producer: no TOML key, no CLI flag and no `Profile` field reaches it. Which shape a run gets follows from the resolved profile set, and `--dry-run`'s TOPOLOGY block prints it.

**`NetnsSandbox` — the floor. `bwrap` creates the netns and nothing joins it.** Offline runs: no `@net`, no container profile. One process, `--unshare-net`, no helper and no stage. That is deny-by-default applied to snug's own process tree.

**`NetnsStage` — a second long-lived process, P1, creates the netns, pins it with a descriptor, LEAVES it, and forks `bwrap` back into it through a `setns` shim.** Selected by `@net` (`NetEgress`) and — since Tier B, issue [#63](https://github.com/gomoni/snug/issues/63) — by any container profile, *including offline*, because the engine needs a stage to own its user namespace and the sandbox's own N. **[`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md) is the truth on this shape**; §2 has the full tree and §3 each decision it overruled.

`bwrap`'s argv is byte-identical to the `NetnsSandbox` case except for the enumerated `--unshare-*` set (`internal/policy/bwrap.go`, `Topology.Netns == NetnsStage`): **which process called `fork` is what determines the topology, not the argv.** `pasta` is aimed at the descriptor P1 pinned before it moved, *never* at `/proc/<P1>/ns/net` — after the move that path names P1's own empty namespace, and `pasta` attaches to it silently (SUPERVISOR-DESIGN §3.4).

**`NetnsStage` is the top of this order, and `NeedsStage()` is monotone over it.** Nothing emits `--share-net`: no topology relaxes a network namespace snug created, so the container engine runs in a netns the stage made or the run does not start.

#### The ordering

The startup order **is** the security property, and it is enforced by construction rather than by a protocol:

```
stage.Start   -> N exists, pinned by a descriptor, with nobody in it
startPasta    -> pasta attaches to that EMPTY N and configures snug0
WaitNetReady  -> the stage confirms snug0 is UP and RUNNING, from inside N
StartSandbox  -> only NOW does a payload exist
```

On a run with **no container engine**, `bwrap` is forked with **no `--block-fd` and no `--json-status-fd`**. A failure at any step before `StartSandbox` aborts the run with no payload having been forked at all, so there is no window in which the payload runs with a half-configured network, and none in which it runs with the host's netns (`TestAbortedNetworkNeverRunsThePayload`). **A payload that has not been forked cannot be released early**, which is why a container run — where `bwrap` must exist before the engine does, and so is forked before the network handshake with the engine finishes — parks it instead; [`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md) §7 carries that measurement.

**Teardown and lifetime chain.** "The tree" below is the stage, `pasta`, the engine and `bwrap` — whichever of them a given run has.

| Event | What happens |
|---|---|
| Payload exits normally | `bwrap` exits → `snug`'s `Wait` returns → `snug` `SIGTERM`s `pasta` (2 s grace, then `SIGKILL`) and collapses the stage → netns refcount hits zero → kernel reaps it. |
| Payload segfaults / is killed | Identical. `bwrap`'s reaper collects the payload, exits with the signal-derived code, `snug` propagates it. |
| `snug` gets a catchable signal that would otherwise be fatal | `armTeardown`'s handler — installed **immediately before each fork**, never after it — kills the process `snug` itself forked (`bwrap` on the floor, the stage under `NetnsStage`) and then **sweeps the host's own `/proc` for anything still alive underneath it**, rather than trusting the kernel's cascade to have armed in time. |
| **`snug` is `SIGKILL`ed** | Two independent mechanisms, because they cover different failures. The **lifeline** is an anonymous pipe `snug` holds the write end of and never writes to: the stage sees EOF the instant `snug` dies and exits, which makes `bwrap`'s own `--die-with-parent` fire (the stage is `bwrap`'s real parent across every exec in the chain). **`PR_SET_PDEATHSIG`** is the second, and load-bearing rather than decorative: the lifeline needs the stage to *run a goroutine* to notice EOF, and a **stopped** process runs no user code at all. Measured 3/3 — `SIGSTOP` the whole tree, then `SIGKILL` `snug`, and everything is gone with no leaked netns (`TestAFrozenStageTreeStillDiesWithSnug`, `TestNoLeakedHelpersAfterSIGKILL`). `pasta` carries `SysProcAttr{Pdeathsig: SIGKILL}` of its own. |
| `pasta` dies mid-run | The tap device vanishes; the sandbox is left with `lo` only. This is the **fail-safe direction** — the sandbox loses connectivity, it never gains reachability. `snug` watches `pasta`'s `Wait()`, logs an error with `pasta`'s captured stderr, and warns. It does **not** silently restart (a restart would race a new port set) and it does **not** kill the payload (which may be mid-edit). |
| `pasta` outlives the netns | **VERIFIED**: `pasta` self-reaps within a few seconds of the netns emptying, even with no signal from `snug`. `snug` still signals it explicitly rather than relying on this. |

**The residual is stated as a rule, not as a list of signal names** — naming them is exactly what went wrong last time. What stays open is every termination that runs no Go signal handler: `SIGKILL`, which never reaches userspace, and a genuine panic or runtime throw inside `snug` itself, which dies on the Go runtime's own crash path. Nothing else. `internal/sandbox/teardown.go` is where that paragraph lives in the code.

`snug` uses no `Setpgid` anywhere in the sandbox chain, so nothing `snug` does takes the tree out of the terminal's foreground process group. What that buys is narrower than "`Ctrl-C` reaches every stage", which is how this sentence read while being false in both directions.

A `Ctrl-C` reaches the **payload** only where `bwrap` was not passed `--new-session` — see `policy.NewSession()`, true when `legacy_tiocsti` is non-zero or when none of stdio is a terminal. Where it does not, `snug` **relays** the signal inward instead (`internal/sandbox`'s `relayToPayload`), and it relays to the sandbox's own **process group** — the thing a terminal signals — rather than to the payload alone. That is not a detail: a POSIX shell defers a trap until its foreground child returns, so `trap cleanup TERM; some-long-command` gets its handler run only if the CHILD is signalled too. The group id is the init's own pid, which is pidfd-pinned for the run, and both conditions are checked rather than assumed — the init must lead its own group, and that group must not be `snug`'s. Which of the two paths a run has is printed by `--dry-run`, because no argv shows it.

Reaching every *stage* was never a benefit, and the tree is deliberately built so that it does not. `snug` is the **only author of a run's death**: the stage catches and drops `SIGINT/TERM/HUP/QUIT` (`MainServe`), and both arms fork `bwrap` into an intermediate pid namespace so that `bwrap` is pid 1 and ignores them too.

There are exactly **two** deliberate `Setpgid` exceptions, and neither is in the sandbox chain. The container reaper (`internal/engine/reaper.go`) takes its own process group and no `Pdeathsig`, precisely because its job is to **outlive** a `snug` that died without stopping its containers, which is also why it is exempted from the teardown sweep by pid. `pasta` takes its own group as well — it keeps its `Pdeathsig` and is still swept as a descendant — so that a terminal's `Ctrl-C` cannot kill the network out from under a payload that is still inside its own shutdown window.
