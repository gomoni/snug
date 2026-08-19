# snug — design index

> *snug*: fitting closely and comfortably · marked by cordiality and secure privacy · offering safe concealment · a small private room in a pub

`snug` is an unprivileged sandbox launcher for untrusted code: a build you did not write, a dependency's install hook, a test suite from a freshly cloned repository, an AI agent. It is a single Go binary that reads a policy, generates a `bubblewrap` command line and (when networking is requested) a `pasta` command line, wires up a small number of tightly-controlled host-integration helpers, runs the payload, and tears everything down.

The model is general: everything below applies equally to `snug ~/src/proj -- make test`. Where this document says "the agent", read "the sandboxed process". An AI agent is simply the sharpest instance of the problem, because it is *supposed* to run arbitrary commands — so "do not run untrusted code" is not available as advice — but a dependency's postinstall script is untrusted in exactly the same way and gets exactly the same boundary.

## What this file is

This was `DESIGN.md`, a single 1768-line document written **before most of the code existed**. Topic documents have since been written from measurement, and where one of them covers a subject it is the truth and this file is not. So this is now an **index**: it keeps the material that has no other home — the policy model, the mount algebra, the bwrap and pasta argv, the package layout, the CLI, the testing strategy — and hands every other subject to the document that owns it.

**Three rules for reading it.**

1. Where a section links to a topic document, that document wins. Do not re-derive from the paragraph here.
2. Where a section is marked **DESIGNED, NOT BUILT**, no code implements it. Those markers are load-bearing: this file previously described unbuilt machinery in the present tense and that cost a milestone (§4.4).
3. Where this file and the code disagree, the code wins and this file is wrong — say so in a commit rather than leaving it. `internal/policy/types.go`, `internal/profile/profiles/base.toml`, `VERIFY.md` and the goldens under `internal/policy/testdata/` are the executable statements of most of what is described here.

**Section numbers are frozen.** Code comments and other documents cite `INDEX §4.2`, `§3.3`, `§2.7` and a dozen more by number. Sections may be emptied out into a pointer; they are not renumbered.

## The topic documents

| document | the question it answers |
|---|---|
| [`ENGINE-NETNS.md`](ENGINE-NETNS.md) | Why a container started through `@podman-socket` has the *engine's* network and not the sandbox's — and what moving the engine into the sandbox's netns costs. §0 is the canonical write-up of that finding; §5 is the plan. |
| [`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md) | The stage, as built: `@net` forks a second long-lived process that creates the sandbox's network namespace, pins it, leaves it, and forks bwrap back into it — so a later phase can put the container engine in the same namespace. What was measured first, what each decision overruled, and what the reviews found. The throwaway proof of concept that took the first measurements has been deleted; its numbers are inline there, in §1. |
| [`NOCGO.md`](NOCGO.md) | Why snug builds with `CGO_ENABLED=0`, what that costs, and the measurements that made it affordable — including why `setns` into a user or mount namespace is closed to pure Go and why that turned out not to matter. |
| [`PODMAN-STATIC.md`](PODMAN-STATIC.md) | A pinned, self-contained rootless engine, for hosts where `/usr/bin/podman` is a shim that escapes to the host. The fallback that unblocked the engine measurements. |
| [`GENERATED-CONFIG.md`](GENERATED-CONFIG.md) | **The rule** for configuring a tool inside the sandbox: classify the file as data or command table, allowlist never denylist, R-SCALAR, R-NOPATH, reconstruct from parsed values rather than editing host bytes, and name every drop. `GIT-CONFIG.md` and `CLAUDE-SETTINGS.md` are its two instances; npm, cargo, docker and pip start here. |
| [`GIT-CONFIG.md`](GIT-CONFIG.md) | Why `~/.gitconfig` is generated rather than bound, measured: `includeIf` evaluated by snug, `hasconfig:` refused, the whitelist and what is deliberately off it, and the seven wildmatch divergences the oracle test now catches. |
| [`CLAUDE-SETTINGS.md`](CLAUDE-SETTINGS.md) | Why `~/.claude/settings.json` is generated rather than bound: the key inventory measured against claude 2.1.232, the ten-scalar allowlist, the `env` door to `ANTHROPIC_API_KEY` it closed, and the plugin-hook channel it does **not** close (issue #68). |
| [`SECRETS.md`](SECRETS.md) | Which credentials reach a sandbox, why each is or is not allowed, the severity model, and brokering versus injection. |
| [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md) | Which container CLI actually works inside the sandbox, measured — and the `podman` stub that replaces a host-escape shim. |
| [`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md) | The environment configuration format: five `environ` verbs, the variable type table, resolution order, and the measured evidence behind each rule. |
| [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md) | What `/proc`, `/sys` and `/dev` expose, measured against a real host. |
| [`PARAMETERISED-PROFILES.md`](PARAMETERISED-PROFILES.md) | Profiles that take arguments — postponed by decision, with the reasoning kept so it is not re-derived. |
| [`ONE-SANDBOX-PER-DIR.md`](ONE-SANDBOX-PER-DIR.md) | Why a run is tied to its target directory and `snug <dir>` refuses a second live sandbox on it, naming `snug attach <dir>` as the fix: the per-target `flock` keyed on `sha256(realpath)`, resolved from the uid alone (never `$XDG_RUNTIME_DIR` — that split was the #122 fail-open), and why removing a run-selector is a simplification a security tool wants. |

Outside this directory: [`../../CLAUDE.md`](../../CLAUDE.md) is the working agreement and the list of expensive environment facts, [`../../VERIFY.md`](../../VERIFY.md) is the executable by-hand checklist, and the [GitHub issues](https://github.com/gomoni/snug/issues) are the live list of known gaps and deferred work — each carries a severity label and the measurement that confirmed it.

**Status of the verification claims below:** every kernel/tool behaviour marked **VERIFIED** was executed on the development host (openSUSE, kernel 7.1.4, `bubblewrap 0.11.2`, `pasta 20260612`, running *inside* a rootless-podman `distrobox` container) at the time it was written. Age is a risk; `VERIFY.md` is the re-runnable form.

---

## 0. The guiding principle

> **Share nothing. Then punch explicit, named, minimal holes until the sandbox is useful.**

Everything in this design is a consequence of that sentence.

The base state of a `snug` sandbox is *not* "the host filesystem with some things masked". It is **an empty tmpfs root, an empty network namespace, and an empty environment**. Nothing is inherited. A profile is a *named hole*. There is no such thing as a "deny rule" in `snug`, because there is nothing to deny — the thing you would deny was never there.

This has three consequences that shape the whole system:

1. **Monotonicity is free.** Since the base is empty, every operation a profile can express is additive. There is no syntax for removal, so composition cannot tighten. (§2.4)
2. **"Hiding" is emergent, not implemented.** The `@parent-ro` profile does not hide your other projects; it simply never grants them. There is no masking pass, no `--tmpfs` overlay trick in the emitter, no ordering hazard from hiding. (§3)
3. **A missing capability is a feature, and is stated as such.** No X11 socket, no Wayland socket, no D-Bus, no host loopback, no `~/.ssh` — not gaps to apologise for, but the default. Where a hole is worth opening it gets a named profile that documents what it costs; where it is not (GUI, audio, D-Bus — §7.5) the absence is simply the answer.

---

## 1. Goals, non-goals, threat model

### 1.1 Goals

- **G1** Run an untrusted payload (a build, a test suite, a coding agent — Claude Code, Codex, aider, …) against one project directory with **no root, no setuid, no daemon, no unit files**. `snug` is a process; when it exits, nothing remains.
- **G2** Deny-by-default filesystem. The agent sees the project, the OS runtime, and exactly what a profile granted.
- **G3** The sandbox **cannot reach the host's loopback**. This is a hard requirement, not a nice-to-have (§4.1). One live qualification: a *container* started through `@podman-socket` runs on the engine's network and is not covered by this — see [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §0.
- **G4** Internet egress works by default when a `@net` profile is selected; fully-offline is the *absence* of that profile, so it is trivially achievable and cannot be accidentally re-enabled.
- **G5** Works inside `distrobox`/containers with nested user namespaces. Where a capability is genuinely missing, `snug` **fails loudly with a diagnosis**, and never silently downgrades its security posture.
- **G6** Host integration (ssh signing, container engine, tmp sharing) is possible but goes through *filtering proxies* that `snug` owns, never through raw socket passthrough.
- **G7** Total transparency: `snug --dry-run` prints the resolved policy and the exact `bwrap` and `pasta` argv. If you cannot read what it is going to do, you cannot trust it.

### 1.2 Non-goals

- **N1** `snug` is **not** a defence against kernel 0-days. It hands the agent a `write(2)` on a real kernel. A user-namespace or netlink or io_uring LPE defeats it completely, and nothing in this design pretends otherwise.
- **N2** `snug` is **not** a defence against a determined human attacker with a shell. It bounds the blast radius of software; a human with time will find the seam.
- **N3** `snug` is **not** a multi-tenant boundary. Everything runs as your uid. The sandbox and the host share a uid, so anything that escapes has your full authority. Use a VM if you need a real boundary.
- **N4** `snug` does not attempt to constrain *what* the agent does with the authority you grant it. If you grant `ssh-agent` signing for a key, the agent can push anything to anywhere that key can reach. Scoping bounds the identity, not the actions.
- **N5** No side-channel / covert-channel resistance. Timing, `/proc/cpuinfo`, and shared page cache are all visible. [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md) measures how much of this is host *fingerprinting* rather than mere noise.
- **N6** Not a general container runtime. `snug` runs *one* command tree.

### 1.3 Threat model

**The adversary is the agent process itself**, assumed to be one of:

- **T1 — a confused agent.** `rm -rf /` in the wrong directory, `git push --force` to the wrong remote, a runaway build eating the disk. The dominant real-world case.
- **T2 — a prompt-injected agent.** The agent read a `README.md`, an issue comment, a web page, or an npm postinstall script that told it to do something hostile: exfiltrate `~/.ssh/id_ed25519`, POST `~/.aws/credentials` to a webhook, add a cron entry, modify `~/.bashrc`, or `curl` the internal service on `127.0.0.1:3100`. **This is the case `snug` is designed for.**
- **T3 — malicious code the agent runs.** `npm install`, `pip install`, `cargo build`, `make`, a test suite. Same authority as the agent, no additional trust.
- **T4 — a hostile repository.** The project directory itself is attacker-controlled: symlinks pointing out of the tree, a `.snug/` directory trying to grant itself privileges, a `.git/hooks/` payload, a `Dockerfile` that bind-mounts `/`.

**What `snug` defends:**

| Asset | Defence |
|---|---|
| Credentials outside the grant set (`~/.ssh`, `~/.aws`, `~/.gnupg`, browser profiles, keyrings) | Never mounted. Not masked — *absent*. See [`SECRETS.md`](SECRETS.md) for what is *inside* the grant set and why. |
| Other projects on the same machine | Never mounted (§3). |
| Host services on `127.0.0.1` / `::1` | Private netns + `pasta` with loopback forwarding explicitly disabled (§4). Containers are the exception — [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §0. |
| Host desktop session (X11 keylogging, Wayland, D-Bus, abstract AF_UNIX) | Not mounted; abstract sockets are additionally netns-scoped (§4.2). |
| Host container engine as an escape vector | Filtering proxy over a per-sandbox engine; the host's engine never sees a client request (§7.2). |
| Host persistence (`~/.bashrc`, systemd user units, cron, `~/.config/autostart`) | Not writable. `$HOME` is an ephemeral tmpfs (§9.7). |
| SSH identity | Filtering agent proxy exposing exactly one key, no key material in the sandbox (§7.1). |

**What `snug` does not defend:** everything in §1.2. Additionally: the project directory is writable by definition, so an agent can always poison the code it is working on — review your diffs.

### 1.4 Two boundaries, and only one of them is snug's

There are two places an attacker could stand, and conflating them has already
cost review rounds.

**Inside the sandbox.** T1–T4 above. Hostile by assumption. Everything in snug is
aimed here: the empty tmpfs root, the private netns with host loopback closed,
`--clearenv` plus `cmd.Env = []string{}`, the seccomp filter, `sealInheritedFDs`,
`safeStdio`, `rejectMasking`, the `/run/snug/bin` staging rule. A defect on this
side is a snug bug and gets a `sev:` label.

**Outside it, writing profiles.** A human. Invariant 3 exists to put the trusted
profile set *outside the sandboxed material* precisely so that this human, and
not the payload, decides what is granted. snug has no opinion about what they
decide.

So a profile that grants too much is not a snug defect, and neither is a typo, a
copy-paste, or a profile that is simply wrong. `rw = ["{home}"]` really does hand
over the real `$HOME`; `environ.set EDITOR = "/tmp/upload-everything"` really does
give the next `git commit` a program the author chose. Both are security holes and
both are **user-inflicted**. The composed case is the same: `snug -p work -p
helper`, where `helper` hijacks the identity `work` pinned, is a hostile profile
the human selected — no different from selecting one with `rw {home}`.

**Why this is not a cop-out.** snug already refuses in three shapes, and none of
them is a veto over what a human may want:

- **Mechanism.** The thing cannot be represented or transported. A NUL in an
  `environ.set` value authors a bwrap flag (§2.6); a newline forges a row on a
  screen a human trusts; a hand-written separator inside a list value smuggles an
  empty element. Refusing here is not policy — it is snug declining to lie about
  what it did.
- **Ownership.** snug writes `HOME`, `PATH`, `PS1`, `SNUG_PROFILES` itself. A
  profile that could write them could unmake snug's own guarantees, `--dry-run`
  included, so no profile may.
- **Type.** `environ.sanitise` on `MANPATH` would ADD directories, because an
  empty element there is an operator (ENVIRONMENT-VARIABLES.md §3.3). Refusing is
  snug declining to perform an operation it knows does the opposite of what it
  claims. The alternative is not freedom, it is a wrong answer.

What is NOT in that list is any refusal of the form *"this grant is dangerous, so
you may not have it"*. Issue #44 removed the one place snug had drifted into
saying it: three environment denylists, converted to annotations.

**What replaces the refusal is disclosure.** The roster
(`internal/policy/envtypes.go`) is **what snug KNOWS, not what it permits**, and
every measurement it holds is owed to the human as an annotation on `--dry-run`
and `snug profile show`. The two failure modes are asymmetric and must stay so:

- **Incomplete is expected and honest.** A name snug has never been taught about
  renders `← unchecked`. The absence of a mark must never read as approval, which
  is why the mark exists at all.
- **Wrong is a defect.** A row saying a value is inert when it is executed is a
  lie in the one artifact a human uses to decide whether to run the sandbox.

The general shape, which outlives the environment work: **a hole that does not
look like one is worth more to an attacker than a hole that does.** `rw {home}`
reads as dangerous on sight and needs no annotation. `EDITOR=…` does not, and that
is exactly why it gets one. `snug doctor` may grow louder about profiles that are
dangerous but correct (issue #80); it will not refuse to run one.

**Two limits worth stating so nobody reasons past them.** The payload owns its own
environment: a profile handing over a clean `GIT_CONFIG_GLOBAL` does not stop the
payload setting `GIT_CONFIG_KEY_0` for itself, and a writable `$HOME` reaches the
same hijack through `~/.bashrc`. What snug owes is narrower and is the `sanitise`
rule — *the environment snug ITSELF hands over must not ship the override
pre-installed* — bounded by measurement, since none of it survives into a later
`snug` run. And **"you get what you configure" is not available to us about our
own profiles**: `@claude`, `@git-ro` and `@podman-socket` are snug's material, so
a shipped grant that hands over more than its abuse comment claims is a finding
against snug. That is what `redteam`'s standing inventory sweep is for, and why
`checkBuiltinEnvRoster` holds a builtin to a stricter rule than a human's profile.

---

## 2. The policy model

**This section is the only home of the model.** The executable statement of it is `internal/policy/types.go` (the lattices), `resolve.go` (the fold) and `resolve_test.go` (the algebraic laws). Where the Go below has drifted from the code, the code is right.

### 2.1 Shape

A **Policy** is a *set of grants*. A **Profile** is a named, composable generator of grants. Resolution is **set union with a per-key join**. There is no removal operator, no ordering-dependent override, and no deny list.

```go
// Package policy has no internal dependencies. It is pure: given a Config and a set of
// Profiles it computes a Policy, and given a Policy it emits argv. It starts no process,
// opens no socket, and touches the host only through an injected Environ.
package policy

// ── Access: a total order, joined by max ─────────────────────────────────────
type Access uint8

const (
    AccessNone Access = iota // the floor; a grant that grants nothing
    AccessRO                 // --ro-bind
    AccessRW                 // --bind
    AccessDev                // --dev-bind (device nodes usable). Rarely granted.
)

func (a Access) Join(b Access) Access { if b > a { return b }; return a }

// ── Kind: what sort of node exists at Guest ──────────────────────────────────
type Kind uint8

const (
    KindBind    Kind = iota // Host -> Guest bind mount
    KindTmpfs               // fresh empty writable tmpfs
    KindSymlink             // Guest is a symlink whose target is Host
    KindProc                // procfs
    KindDev                 // bwrap's synthetic /dev
    KindData                // generated file content, delivered via memfd
)

// ── Mount: one grant. Guest is the primary key. ──────────────────────────────
type Mount struct {
    Guest    string   // absolute, lexically-clean sandbox path — THE KEY
    Kind     Kind
    Host     string   // KindBind: canonical host path. KindSymlink: link target.
    Access   Access
    Optional bool     // -try semantics: silently skip when Host is absent
    Perms    *uint32  // KindData/KindTmpfs only
    Content  []byte   // KindData only; materialised into a memfd at emit time
    Authored bool     // snug's own replacement, not a profile's grant (§3.4 RULE 3)
    From     []string // provenance: which profiles contributed. Audit/explain only,
                      // NOT part of equality — so resolution stays idempotent.
}

// ── Network ──────────────────────────────────────────────────────────────────
type NetMode uint8

const (
    NetIsolated NetMode = iota // private netns, loopback only, no helper. THE FLOOR.
    NetEgress                  // private netns + pasta: internet in/out, host loopback closed
    NetHost                    // share the host netns. DANGEROUS. Requires --i-know.
)

func (m NetMode) Join(o NetMode) NetMode { if o > m { return o }; return m }

// ── Identity (vocabulary inherited from agent-sandbox, §9) ───────────────────
type SSHMode string

const (
    SSHAgentProxy SSHMode = "agent-proxy" // RECOMMENDED: filter the host agent to one key
    SSHAgentOwn   SSHMode = "agent"       // private one-key agent; prompts for the passphrase once
    SSHKeyFile    SSHMode = "key-file"    // stage the encrypted private key in. Weakest.
    SSHHostAgent  SSHMode = "host-agent"  // forward the WHOLE host agent. Discouraged.
    SSHNone       SSHMode = "none"
)

// ── Podman ───────────────────────────────────────────────────────────────────
type PodmanMode uint8

const (
    PodmanOff PodmanMode = iota
    PodmanSocket                // filtering proxy over a per-sandbox engine
    PodmanBuild                 // + the build endpoint, with a constrained context
)

// ── Policy: the single computed, immutable object ────────────────────────────
type Policy struct {
    Target   string            // canonical host path of the sandbox's writable project dir
    Home     string            // $HOME inside == $HOME outside (§9.7)
    Mounts   map[string]Mount  // keyed by Mount.Guest
    Env      map[string]string // resolved allowlist -> value; --clearenv + --setenv
    Net      NetPolicy
    Identity *Identity
    Podman   PodmanMode
    Hostname string
    Chdir    string
    Command  []string

    // No clamp field, and no Clamp type: nothing reduces a resolved policy (§2.5).
    // `--no-seccomp` is not an exception — it never enters the Policy at all; it is
    // a launch-time decision handed to internal/sandbox.
}
```

### 2.2 Resolution

```go
// Resolve is pure, total on valid input, commutative and idempotent in `sel`.
func Resolve(sel []*Profile, ctx Context) (*Policy, error)
```

The algorithm:

1. **Expand `include` transitively** into a *set* of profiles (depth-first, cycle-detected). Because the result is a set, `include` is idempotent and diamond includes are harmless.
2. **Expand path variables** (`{target}`, `{target_parent}`, `{target_ancestor:N}`, `{home}`, `~`) against `ctx`.
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

***The `Host` comparison is NOT guarded by kind, and that guard was a real hole.*** It used to read `a.Kind == KindBind && a.Host != b.Host`. For a `KindSymlink`, `Host` **is the link target**, so it was never compared: two profiles pointing one symlink at two different targets silently kept whichever name sorted first, and printed *both* as the provenance. A user profile named `0shadow` (a digit sorts before `@`) could repoint `@sys`'s `/bin -> usr/bin` at `usr/sbin` while `--dry-run` read `0shadow+@sys`, as though the two agreed — a profile displacing another profile's grant, which §2.4 says is structurally impossible. `Host` is `""` for every kind with no host side, so comparing it unconditionally is free.

5. **Join scalars** using each key's declared permissive-ward join, or refuse symmetrically where the key has no permissive direction (§2.3).
6. **Union the env allowlist**; conflicting explicit `setenv` values are an ERROR. The environment has its own document — [`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md), and §9.6.
7. **Validate** (§3.4), which is where the *nesting* rules live: same-path conflicts are settled here, nested ones there. There is no clamp stage: the resolved policy is final (§2.5).

**Why it is commutative:** every fold operation is a commutative, associative, idempotent binary join, or an *error* (which is symmetric). `From` is excluded from equality, so accumulating provenance does not perturb the fixpoint. Emission order is derived from the *result* (§3.2), never from profile order.

**Why it is idempotent:** `join(a, a) == a` for every join used. Selecting `[sys, sys, cwd-rw]` is identical to `[cwd-rw, sys]`.

**Three different orders get conflated, and only one of them exists at runtime.**

| order | status |
|---|---|
| *selection* — the order `-p` names profiles | already irrelevant; kept only so `--dry-run` can say "you asked for this" vs "an include pulled it in" |
| *fold* — the order profiles are visited | sorted by name, and **no resolved value may depend on it**. Sorting is a determinism device, not a tie-break |
| *emission* — the order mounts reach bwrap's argv | depth-ascending and **load-bearing** (§3.2). A compiler concern that must never surface in the file format |

The fold is **sorted, deliberately not randomised**, and that is the stronger form of the requirement rather than a weaker one: randomising it in production would make a resolver bug *intermittent*, and a security tool that is wrong occasionally is worse than one that is wrong reproducibly. Randomness belongs in the test suite, where a shuffle is a property test and a flake is a finding — `TestResolveIsCommutative` shuffles 200 selections and compares the whole resolved policy, scalars included.

**Selecting a profile twice is already a no-op** for resolution: `expand` builds a *set*. Only the cosmetic `PROFILES` line in `--dry-run` echoes `p.Selected` verbatim, which implies a multiset and an order the model does not have.

### 2.3 Why scalars do not break monotonicity

The prior generation (`agent-sandbox`) let a profile *override* a scalar, with the including profile winning. That is order-dependent and can tighten. `snug` forbids it. **Every scalar key's value domain must be a join-semilattice, and resolution uses the permissive-ward join.**

| Key | Domain | Join | Permissive direction |
|---|---|---|---|
| `network` | `isolated < egress < host` | `max` | more reachability |
| `publish` | `[]int` | union (a SET) | more ports |
| `podman` | `off < socket < build` | `max` | more engine surface |
| `dns` | `bool` | `OR` | working DNS |
| `ro` / `rw` / `dev` | path sets | union + `Access.Join` | more access |
| `env` | name set | union | more variables |
| `path` | dir set | union, then sorted | more PATH entries (grants nothing) |

**No key in the model is last-writer-wins.** Three used to be: `address`, `gateway` and `mtu` took whichever profile the fold reached last. That survived only *because* the fold is sorted — the alphabetically later profile won, arbitrarily and silently — which is precisely the shape of dependence §2.2 says no resolved value may have. There is no "more open" IP address, so these three cannot be joins; two profiles disagreeing is now a **symmetric ERROR naming both profiles and both values**, exactly as `identity` already was. They remain pasta cosmetics — they change which address the sandbox *sees*, never what it can reach — and the refusal costs nothing, because selecting two profiles that each pin a different synthetic address was never a coherent request.

`publish` is a **set**, and appending was a second, smaller version of the same bug: `publish = [3000]` in two profiles resolved to `[3000 3000]` and reached pasta's `-t` as a duplicate, with the rendered order depending on the fold. This table already said "union"; the code now agrees.

**The rule for any new scalar:** a genuine permissive-ward join, or an error naming both profiles. Nothing in between.

Keys that would only ever *weaken* the sandbox in a way profiles must not control — notably `seccomp` — **are not profile keys at all**. `--no-seccomp` is a CLI flag only. A human may weaken; a file may not.

`network = "isolated"` is therefore a no-op, and there is deliberately no `network = "offline"`. **Offline is the absence of the `@net` profile.** If you write `include = ["@net", "@net-offline"]`, the result is `@net` — and that is correct, not a bug: you asked for the union of two grant sets, one of which was empty. To be offline, do not include `@net`.

*One live qualification.* `@podman-socket` carries `include = ["net"]`, so selecting containers selects egress. That is interim and honest rather than a weakening — a container already had the engine's network — and it is the subject of [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §0 and §5.

### 2.4 Monotonicity by construction — the actual argument

Three properties together make "a profile can never tighten the sandbox" a *structural* fact rather than a review convention:

1. **The base is empty, and the emitter has no removal operation.** `snug`'s bwrap emitter can produce `--bind`, `--ro-bind`, `--dev-bind`, `--tmpfs`, `--symlink`, `--proc`, `--dev`, `--file`, `--ro-bind-data`, `--dir`, `--setenv`. There is no `--mask`, no deny path, no "hide" verb, because nothing needs hiding — **VERIFIED**: `bwrap`'s new root is a fresh, empty tmpfs. With `--ro-bind /usr /usr` and a bind of one project directory, `ls /home/u/projects` lists exactly `work` and nothing else, with no `--tmpfs` anywhere in the command line. Siblings are invisible because they were never mounted.
2. **The grant language cannot express negation.** TOML keys are `ro`, `rw`, `dev`, `tmpfs`, `symlink`, `env`, `path`, `publish`, `include`. There is no `mask`, no `hide`, no `deny`, no `remove`, no `!`-prefix, no `unset`. This is enforced by strict decoding: unknown keys are a fatal parse error, so a future key cannot be smuggled in by a config written for a different tool.
3. **Resolution is a join over semilattices.** For any profile sets *A* and *B*, `Resolve(A ∪ B) ⊒ Resolve(A)` and `⊒ Resolve(B)` — the result is above both in the grant lattice. Adding a profile can only move you up.

The one place order matters is *emission*, and emission order is computed from the resolved set by a deterministic sort (§3.2), not from the order profiles were named. So the argv is a pure function of the resolved policy.

**Read the precise form of this claim in CLAUDE.md invariant 1, and the counter-examples in [`PARAMETERISED-PROFILES.md`](PARAMETERISED-PROFILES.md) §1.** The loose sentence "adding a profile never makes anything worse" is false in two named ways: snug's own `KindData` writes can displace a profile's grant at an identical path, and a *deeper* grant with weaker access lowers effective write access at a subpath (§2.5). Both are intended; neither is what `TestResolveIsMonotone` proves.

### 2.5 There is no restriction operation — anywhere

**Profiles only ever grant. There is no un-grant — not in a profile, not on the command line, nowhere. To grant less, select fewer profiles.**

```
Policy_final = Resolve(profiles)
```

That is the whole pipeline. An earlier design had a *clamp*: a post-resolution stage (`--read-only`, `--offline`) that moved the policy *down* the lattice, justified by "profiles are data that may originate near untrusted material; the CLI is the human, and only the human may tighten". The asymmetry was defensible, and it is still the right answer to *"may a profile tighten?"* — no. But it was the model's one carve-out, and both the flag and the machinery behind it are now gone. `snug` stays minimal; `bwrap` is the swiss knife.

What that costs, stated plainly: a read-only project is obtained by not selecting `@cwd-rw` — `snug --no-defaults -p @sys -p @home -p @parent-ro <dir>` — which is verbose on purpose. A read-only cwd is possible but highly nonstandard, and the verbosity is proportionate to how rarely it is wanted.

What it buys: an invariant with no exceptions. "Nothing anywhere reduces what a resolved policy grants" is a property a reader can check by grepping for a demote and finding none, and a test can assert directly (`TestPolicyHasNoRestrictionOperation`). One with a carve-out can only be checked by understanding where the carve-out applies.

#### Visibility is monotone. Effective write access at a strict subpath is not.

That is the honest sentence, and it is written here rather than left implicit because the behaviour exists whether or not it is documented — confirmed against a live sandbox, not inferred from the argv.

**The rule, stated once: the DEEPEST mount covering a path decides what is true at that path.** `join` is keyed by `Mount.Guest`, so it only fires at *identical* paths. Grants at different depths do not join — they become two mounts, and bwrap applies them in depth order (§3.2), so the innermost one wins.

It runs in both directions, and both are load-bearing:

| arrangement | effect | who depends on it |
|---|---|---|
| `ro {parent}` + `rw {target}` | target is writable inside a read-only parent | the default selection — `@cwd-rw` over `@parent-ro` |
| `rw {target}` + `ro {target}/.git` | `.git` is read-only inside a writable target | the arrangement invariant 2 recommends for "X but not Y" |
| tmpfs `$HOME` + `ro ~/.gitconfig` | a read-only host file inside a writable ephemeral home | `@git-ro`, `@claude`, every generated identity file |

So the second row — a profile *lowering* effective write access at a strict subpath — is not removable without breaking the third. Forbidding "a deeper grant may not be less permissive" would break `@git-ro`, `@claude` and every pinned identity on the first invocation.

**What is and is not conceded by writing this down.** It is a subtraction verb with a spelling (`ro = ["{target}/.git"]` inside a writable target), and §2.5 deleted `--read-only` and `Clamp` precisely so no exception would exist. But the two are not the same act: the clamp moved *the whole policy* down the lattice after resolution, while this is one grant being *more specific* than another. Nothing becomes invisible; the path is still there, still readable, and `rejectMasking` still refuses anything that would hide content (§3.4). A profile that only lowers write access at a path it names is a **nuisance, not an escalation** — and unlike the clamp, it is visible: it is a line in `--dry-run`'s FILESYSTEM block with a profile name next to it, and `--dry-run`'s headline annotation walks the same deepest-mount rule so it cannot report `(writable)` over a demoted subtree, nor `(read-only)` over a writable one.

**Do not read `TestResolveIsMonotone` as proving more than it does.** It compares `Access` per existing `Guest` key, and a deeper key did not exist in the base policy, so it cannot see this at all. `TestADeeperReadOnlyGrantDemotesASubpathOfTheWritableTarget` pins the scope explicitly — it exists to stop the first test being over-read.

### 2.6 Profile file format: TOML

**`internal/profile/profiles/base.toml` is the shipped profile set and the document of record for what each profile grants.** It carries the abuse sentence for every hole. What follows is the *format*, not the catalogue — the catalogue drifted here twice.

```toml
[profile.example]
description = "One line, shown by `snug profile list`."
include  = ["sys", "home"]        # composition; expanded into a SET before folding
ro       = ["/usr", "{home}/.gitconfig"]
rw       = ["{target}"]
tmpfs    = ["{home}", "{home}/.cache"]
symlink  = [ { at = "/bin", target = "usr/bin" } ]
optional = ["{home}/.gitconfig"]  # -try semantics: skip silently when absent
network  = "egress"               # isolated < egress < host
dns      = true
publish  = [3000]                 # host 127.0.0.1 -> sandbox, named ports only
podman   = "socket"               # off < socket < build

  [profile.example.environ.set]   # snug authors the value (§9.6)
  NO_COLOR = "1"

  [profile.example.environ.inherit]  # the VALUE comes from the host
  EDITOR = true

  [profile.example.identity]      # pins ONE git/ssh/gh account (§9.1)
  gh_user   = "work"
  git_name  = "Your Name"
  git_email = "you@work.example"
  ssh_key   = "~/.ssh/id_ed25519.pub"
  ssh_mode  = "agent-proxy"
```

There is deliberately no `[profile.null]`. It was tried and removed: a profile that grants nothing is a preference wearing a profile's clothes, and it is unreachable by its own documented purpose besides — `-p` only ever ADDS to `defaults`, so `-p @null` cannot subtract them, and cannot show "the true empty base" it claimed to. The floor of the lattice does not need a name in this file; it is what `Resolve` returns for an empty selection, and it is reachable directly with `snug --no-defaults --dry-run <dir>`. `-p @null` is a retired name that errors, naming `--no-defaults`.

Nor is there a `[profile.default]`. **What a bare `snug <dir>` selects is the `defaults` *setting***, built in at `internal/profile/defaults.go` (`@sys @home @cwd-rw @parent-ro`) and replaceable wholesale by `defaults = [...]` in `~/.config/snug/config.toml`, because a default *selection* is a preference and a profile is a *grant*. `-p` adds to it; `--no-defaults` declines it.

**Names are written bare here and published with a leading `@`.** `[profile.sys]` in `base.toml` is `@sys` everywhere a human meets it — on the command line, in `--dry-run` provenance, in `$SNUG_PROFILES`. The mark means *snug ships this*, and it is added by `profile.builtins()` when the embedded file is loaded rather than written into the file. `checkName` refuses a leading `@` in **every** file it parses, `base.toml` included, so the mark is unforgeable in both directions: a builtin cannot miss it, a profile in `~/.config/snug/profiles.d` cannot claim it.

Two things follow.

- **Provenance is legible without a lookup.** Every place a profile name is rendered is a place where "is this snug's grant or one this host defined?" is the question being asked, and the bare name could not answer it.
- **The two namespaces cannot collide,** which retires a rule rather than adding one. "A config file must not redefine a builtin" was previously enforced by the merge check; now a user file saying `[profile.sys]` defines a profile of *theirs*, and `@sys` is untouched. The merge check remains for collisions between the layers below (a site profile against a user one), where a hard error is still right. This matters most where §2.7's gate is weakest — `$XDG_CONFIG_HOME` is trusted unconditionally today, and a `profiles.d` loaded from the wrong place still cannot impersonate `@sys`.

**The name charset.**

```
first character   [a-zA-Z0-9]
rest              [a-zA-Z0-9-]
```

`checkName` (`internal/profile/file.go`) is an **allowlist**: a character outside that set is a fatal parse error naming the file, the name, the offending byte and its offset. It was a denylist of five individually-broken characters until [#20](https://github.com/gomoni/snug/issues/20), which is the wrong direction — what snug has not been taught about must fail closed — and the sixth character was already reachable: measured, `[profile."a\u001b[1A\rb"]` parsed cleanly and, once selected, that name reached the `PROFILES` line of `--dry-run` verbatim, where `ESC[1A CR` erases the row above it.

The hyphen is in, decided by the owner; eight builtins depend on it (`cwd-rw`, `parent-ro`, `tmp-shared`, `git-ro`, `net-anon`, `net-host`, `podman-socket`, `podman-build`), so the naive "alphanumerics only" reading would outlaw snug's own names. Underscore stays out until asked for, on the grounds that adding a character later is additive and removing one is a breaking change. Refusing punctuation in the FIRST position is the point: every printable ASCII symbol then stays free to become a sigil later without breaking a name somebody already chose. `@` is already one, and `:` is the reserved next candidate ([`PARAMETERISED-PROFILES.md`](PARAMETERISED-PROFILES.md)).

Three things follow.

- **The grammar is enforced in exactly one function.** `nameFault` is the whole rule. The bespoke errors for a leading `-` (indistinguishable from a flag) and a leading `@` (the mark is snug's, and the fix is to drop one character) sit in *front* of it and only improve the message — both are refused by the rule as well, so deleting one costs a good error and cannot widen what parses. A rule written in two halves has been fixed in one of them twice in this project.
- **Every name a profile FILE contains obeys it, `include` targets included** — those through `checkRef`, whose grammar is the same plus an optional leading `@`, because a user's own profile including `@net` is a supported spelling. Definition and reference differ by exactly that one character and are separate functions so the difference is written down rather than assumed.
- **Rendering a profile name is now safe by construction rather than by escaping.** A name reaching `$SNUG_PROFILES`, the container store key (`engine.New` joins the set with commas too — a second consumer of the comma rule that nobody had written a rule for), `--dry-run` provenance, `snug profile show`'s header or `snug profile tree` is a registry key, and a registry key can no longer hold a control character, a space or a comma. The only place an ILLEGAL name is ever rendered is the refusal itself, which quotes it with `%q`; the renderers on those screens keep their `visibleValue` guard as a second line of defence.

A name outside the set is a **loud fatal parse error naming the file**: an existing `my_profile` or `my.tool` stops loading and says so, with `my-profile` suggested for the first. snug is pre-1.0 and there is deliberately no escape hatch — a name that stops parsing is visible, and every alternative to a hard error is a name that quietly means something else.

`include` inside a builtin is rewritten along with the names, so a builtin can only ever include another builtin. That is not a restriction being imposed — it is compiled in and cannot know a user's names — but it is a rule rather than an accident, and `profile.mark` says so.

**Why TOML** (decided by the owner; recorded for the record): it is what the previous generation converged on, `github.com/pelletier/go-toml/v2` supports `DisallowUnknownFields()` which is load-bearing for fail-closed parsing, and profiles are flat name→grant-list tables with no need for expressions. A programmable format (Starlark/HCL) would be strictly worse here: computation in a profile is exactly the thing that would make monotonicity un-provable by inspection. Whether a profile should be able to take *arguments* is a separate question, answered (postponed) in [`PARAMETERISED-PROFILES.md`](PARAMETERISED-PROFILES.md).

**`include` stays monotone** because it is expanded into a *set* before folding, and because every key it can carry has a permissive-ward join. `include` has no "override" or "exclude" counterpart. A profile can only ever be `⊒` the union of what it includes.

### 2.7 Profile lookup precedence — and why repo-local config is never auto-loaded

Profiles are loaded from, in order (all layers merged; **later layers may only add new profile names, never redefine an existing one — a redefinition is a fatal error**):

1. **Embedded builtins** — compiled into the binary, and the only profiles that carry the `@` mark (§2.6). Always present, and unshadowable by construction rather than by check: no later layer can spell an `@` name at all.
2. **`/etc/snug/profiles.d/*.toml`** — site/admin profiles.
3. **`$XDG_CONFIG_HOME/snug/profiles.d/*.toml`** (default `~/.config/snug/profiles.d/`) — the user's own profiles. **This is the trusted layer.**

**There is no fourth layer.** `snug` **never** auto-loads `./.snug/`, `./snug.toml`, or anything else from inside or beside the target directory. Asserted by `TestRepoLocalConfigIsNeverAutoLoaded`.

The prior generation stated the reason in a comment and it is correct: repo-local config is a persistence-attack vector. Under `snug`'s threat model (T2/T4) it is worse than that — it is a *complete* defeat. A hostile repository that ships `.snug/profiles.toml` redefining a profile the user's `defaults` already select — `[profile.cwd-rw] ro = ["/"]` — would grant itself read of the entire host on the very first `snug ~/src/hostile-repo`. The material inside the sandbox must never be able to author the sandbox's boundary.

This is a monotonicity-adjacent property, and worth naming: **the trusted profile set must originate outside the material being sandboxed.** Monotonicity guarantees that composing profiles cannot tighten; it says nothing about *who gets to compose*. Both are needed.

#### DESIGNED, NOT BUILT — the explicit-config gate

Everything from here to the end of §2.7 describes machinery that **does not exist**. There is no `--config` flag, no `SNUG_CONFIG`, and no privileged-grant classifier; `Profile.Trusted` is set and never read. The residual gap is https://github.com/gomoni/snug/issues/27 and is stated in CLAUDE.md invariant 3: `$XDG_CONFIG_HOME` is trusted unconditionally, so pointing that variable into a checked-out repository does load that repository's profiles. Low severity — it is the host user's own environment variable, not something the sandboxed process controls — but **do not cite §2.7 as a gate that exists.**

The intended shape, kept because it is still the answer:

```
snug --config ./snug.toml ~/src/proj          # explicit path
SNUG_CONFIG=./snug.toml snug ~/src/proj       # explicit env
```

An explicitly-loaded config file would be a *convenience*, not a full trust promotion — the human typed one word and cannot be expected to have audited a 200-line TOML file that a `git pull` may have changed since they last looked. Four grant classes would count as **privileged**:

- `network = "host"`
- `podman = "socket"` / `"build"`
- any `rw`/`ro`/`dev` grant whose canonical path escapes `{target}`'s ancestor chain and is not under `/usr`, `/etc`, or `/opt`

A privileged grant appearing in a non-trusted-layer config would be a **fatal error** naming the file, the profile, and the grant. To use it, the human must move that profile into `~/.config/snug/profiles.d/`, which is an act of the human on the human's own machine, outside any repository.

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

**Host-side (the `Host` field).** Every host path is canonicalised with `filepath.EvalSymlinks` at resolve time. `snug` binds the *realpath* but mounts it at the *requested guest path*. This means `~/projects` being a symlink to `/data/projects` works, and it means a symlink planted inside the writable project cannot later be used to widen a grant, because grants were canonicalised before the sandbox ever started. The residual TOCTOU (host path replaced between resolve and mount) is documented and accepted: closing it requires `openat2(RESOLVE_BENEATH)` plumbing through `--bind-fd`, which is possible future hardening (`bwrap` has `--bind-fd FD DEST` and `--ro-bind-fd FD DEST` for exactly this). [`PARAMETERISED-PROFILES.md`](PARAMETERISED-PROFILES.md) §2 records a related latent issue: a symlink planted in the target can divert a grant that names a path *inside* it.

**Guest-side (the `Guest` field).** This is where the prior generation lost a day. Its `podman-shim` bind at `/usr/bin/podman` aborted the whole sandbox with `bwrap: Can't create file at /usr/bin/podman: No such file or directory`, because on that host `/usr/bin/podman` was a symlink and **`bwrap` cannot create a mountpoint at a symlink destination**. Generalised, the hazard is: `snug` emits `--symlink usr/bin /bin`, then a later grant asks to bind something at `/bin/tool`; that path now resolves *through* our own symlink into the read-only `/usr` bind, and the mount fails or, worse, lands somewhere unintended.

This is also why substituting a host binary is done by **PATH precedence, not overmounting** — see CLAUDE.md's rule of that name and [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md) §6, where it is the only mechanism available rather than the tidier of two.

`snug`'s rule, enforced in `Validate()` before any argv is emitted:

1. Build the sandbox's *own* symlink map from the resolved `KindSymlink` grants.
2. Resolve each `Guest` path through that map (plus the host's realpath for guest paths that alias host paths).
3. **Reject** any grant whose resolved `Guest` lands strictly inside another grant that is `AccessRO` and `KindBind` — with an error naming both grants and both provenances.
4. **Rewrite** any grant whose `Guest` traverses a `snug`-created symlink to its resolved form, and re-run the depth sort.

This turns a runtime `bwrap` abort into a resolve-time error with a readable message, and it is directly unit-testable against a fake `Environ`.

### 3.4 Validation

Before emitting anything, `Validate()` checks:

- Every `Guest` is absolute and lexically clean; no `.`, `..`, or empty components survive.
- No `Guest` is `/` with `KindBind`.
- The target directory exists, is a directory, and its canonical path is granted `AccessRW`. **Fail closed** — no target means no policy, never a permissive default.
- Symlink hazards (§3.3).
- At least one of `/usr` or `/bin` is granted, otherwise nothing can execute — reported as *"no runtime granted; add the `@sys` profile"* rather than a confusing `exec: no such file`.
- **RULE 4** — nothing but `snug` may put a node at `/proc` or `/dev` (below).
- **RULE 2** — nesting, judged on the outer mount (below).

`Validate` is the *only* refuser, which is what lets `--dry-run` render a policy it would not run (`Resolve` returns `(p, err)` for a validation failure and `(nil, err)` for everything else). It is also run **a second time**, in `internal/cli`, after the staging layer has added the mounts that had to be created on the host first: the staged Claude credentials, the generated `gh` `hosts.yml`, the ssh-agent and container proxy sockets. Those are added after `Resolve` returned, so without the second pass they were never validated at all.

#### RULE 4 — `/proc` and `/dev` are `snug`'s, and a profile may not take them

`snug` authors `/proc`, `/dev` and `/tmp` *after* the profile fold, and yields to whatever is already there. That yield is intended for **`/tmp` only** — `@tmp-shared` replacing the private tmpfs with a host directory is how that profile works. For the other two it was an accident of a single `mustJoin` helper serving two opposite intentions, and it accepted `ro = ["/proc"]`, handing the sandbox the *host's* procfs instead of one bound to its own pid namespace.

The helper is now `yieldTo`, and a non-authored mount at `/proc` or `/dev` is a **refusal** naming the profile. `/proc` and `/dev` still go through the yield rather than being overwritten, for one reason: it lets the error name the profile that did it instead of silently discarding its grant.

#### RULE 2 — nesting is judged on the OUTER mount's content

A grant *inside* another grant is only masking if the outer mount **has content at the inner path**. So the outer kind decides:

| outer | inner allowed? | why |
|---|---|---|
| `KindTmpfs` | **yes** | a fresh tmpfs exposes nothing, so nothing can be hidden by mounting inside it |
| `KindBind` of *H* | **yes** iff the inner is a bind of *H/rel* | re-granting the same tree at stronger access is a superset (`@cwd-rw` over `@parent-ro`); anything else substitutes content |
| `KindProc`, `KindDev` | **no** | populated by the kernel and by bwrap; a mount inside substitutes host content for kernel content |
| `KindData` | **no** | a grant beneath a regular file is meaningless |
| anything | **yes** if the inner is `snug`'s own authored replacement | RULE 3, below |

The `KindTmpfs` row is not a convenience: every shipped profile that exposes a host file into the ephemeral `$HOME` is a bind inside `@home`'s tmpfs — `@git-ro`'s `.gitconfig`, `@claude`'s `settings.json`, every generated identity file — so treating a tmpfs as maskable breaks three profiles on the first invocation.

Only the **nearest** covering mount is consulted. It is the one that actually supplies content at that path, and anything further up was already judged when it was itself the inner mount, because the walk is depth-ascending.

#### RULE 3 — authorship is a FIELD, not a convention

`Mount.Authored` is set **only** by `Policy.Replace`, which is the only permitted writer of `p.Mounts` once `Resolve` has assembled them. `rejectMasking` exempts on `Authored`.

This is the distinction the whole masking rule turns on, restated: **a profile mounting over another profile's grant is masking and is refused; `snug` replacing a path with its own generated content is replacement and is allowed** — the sandbox still sees a node there, just a truthful one, and `Replace` records what it displaced (`identity:work+replaces:@git-ro`) so `--dry-run` says so.

Two spellings of this were tried and are worse:

- ***Exempt `Kind == KindData`.*** True today ("no TOML key produces a `KindData` grant") but a *proxy* for the property that matters, and one that had already drifted: `/proc`, `/dev`, `/tmp` and the proxy sockets are `snug`'s too and are not `KindData`, while a future TOML key producing `KindData` would inherit the exemption for free.
- ***Exempt `provenance == "(snug)"`.*** Exempts nothing: the authored mounts carry four different provenance strings — `(snug)`, `identity:<name>`, `@claude`, `(containers)` — so a single string match covers none of them and breaks `@claude`.

---

## 4. Networking

This section is as load-bearing as the filesystem. A sandbox that cannot read `~/.ssh` but can `curl http://127.0.0.1:3100/` has not been sandboxed.

### 4.1 Why a network namespace, and not packet filtering

`snug` has no root. `iptables`/`nftables` rules are per-netns and require `CAP_NET_ADMIN` **in that netns**. You cannot get `CAP_NET_ADMIN` over the *host's* netns without privilege, so filtering the host netns is off the table entirely. You *can* get `CAP_NET_ADMIN` inside a netns you created in your own user namespace — but at that point you already have the netns, and the netns alone gives you a stronger, simpler property than any rule set:

**In a fresh netns there is nothing to filter.** No route to the host, no interface but `lo`, and the sandbox's `127.0.0.1` is *its own* loopback, a different loopback from the host's. Reaching the host's loopback is not "blocked", it is *not expressible*. That is a much better security property than a deny rule, and it fails safe: if `snug`'s helper dies, the sandbox loses connectivity rather than gaining it.

**The abstract AF_UNIX bonus, which people forget.** The abstract Unix socket namespace (`\0`-prefixed names, `@/tmp/.X11-unix/X0`, `@/tmp/dbus-*`, and a long tail of application IPC) is **scoped by the network namespace**, not the mount namespace. A sandbox that unshares its mount namespace but keeps the host netns can still `connect()` to every abstract socket on the host — including X11 on many setups, and D-Bus. Filesystem sandboxing does *nothing* about this; there is no path to not-mount. A private netns closes it completely and for free.

Per the guiding principle: this is a **win**, not a limitation. The default `snug` sandbox has no X11, no Wayland, no D-Bus and no host IPC, because it has no netns in common with your session and no sockets bound into its filesystem. GUI, audio and D-Bus passthrough are out of scope (§7.5), so this is the permanent state rather than a default awaiting a profile.

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
2. **An integration test asserts the *behaviour*, not the argv.** `TestHostLoopbackIsUnreachable` starts a listener on the host's `127.0.0.1`, launches a real sandbox, and asserts the connection is refused (§12.4). Golden-argv tests would have passed on the buggy configuration; only a behavioural test catches a changed upstream default. This test is the single highest-value test in the suite.

### 4.3 Process topology, ordering, and lifetime

Two candidate topologies for creating the network namespace:

**(a) `pasta` creates the netns and spawns `bwrap` inside it.** `pasta [OPTS] -- bwrap --unshare-all --share-net ...`.
**VERIFIED** that `pasta`'s command mode creates user + mount + ipc + pid + uts + net namespaces and maps your uid to 0 (`uid_map: 0 1000 1`). That is the problem: `pasta` has already built a user namespace with exactly **one** uid mapped, so `bwrap`'s nested `--unshare-user` inside it can only map that one uid, and any later need for a subuid range (podman) is dead on arrival. It also puts a process `snug` does not control at the root of the tree, and `pasta` is not designed to be an init.

**(b) `snug`'s own tree creates the netns; `pasta` joins it. ← what snug does.**

**Why (b):**

- The namespace set is created by a process `snug` wrote or forked, never by a helper. `snug` does not need `unshare(1)` on `PATH` at all.
- `pasta` is a *leaf* of the process tree, not its root. It can die, be restarted, or be absent without restructuring anything.
- The netns is referenced only as `/proc/<pid>/ns/net` or a pinned descriptor — never bind-mounted to a filesystem path. When the last reference goes away, the kernel destroys it. **Orphan netns leaks are impossible by construction**, because no persistent reference is ever created. (This is the difference from `ip netns add`, which bind-mounts under `/run/netns` and leaks exactly this way.) *That "by construction" is conditional on the netns holding nothing but the sandbox — [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §4 measures how it changes shape when the container engine moves in.*

#### Who actually creates it — three shapes, derived, never selected

`policy.NetnsOwner` (`internal/policy/topology.go`) is a three-point lattice and `deriveTopology` is its only producer: no TOML key, no CLI flag and no `Profile` field reaches it. Which shape a run gets follows from the resolved profile set, and `--dry-run`'s TOPOLOGY block prints it.

**`NetnsSandbox` — the floor. `bwrap` creates the netns and nothing joins it.** Offline runs: no `@net`, no container profile. One process, `--unshare-net`, no helper and no stage. That is deny-by-default applied to snug's own process tree.

```
snug                                      (host userns, host netns, host mount ns)
└── bwrap --args A -- <payload>           A is a memfd carrying the whole flag list:
     │                                    --unshare-{user,ipc,pid,uts,net}, --die-with-parent,
     │                                    --seccomp S, --info-fd I, and every mount
     └── the sandbox: own userns, netns, pidns, ipcns, utsns, mountns
```

**`NetnsStage` — a second long-lived process, P1, creates the netns, pins it with a descriptor, LEAVES it, and forks `bwrap` back into it through a `setns` shim.** Selected by `@net` (`NetEgress`) and — since Tier B, issue [#63](https://github.com/gomoni/snug/issues/63) — by any container profile, *including offline*, because the engine needs a stage to own its user namespace and the sandbox's own N. **[`SUPERVISOR-DESIGN.md`](SUPERVISOR-DESIGN.md) is the truth on this shape**; §2 has the full tree and §3 each decision it overruled. The short form:

```
P0  snug                                    (host userns, host netns, host mount ns)
 ├── pasta --netns /proc/<P1>/fd/<n> --userns /proc/<P1>/ns/user --config-net ...
 │        started SECOND, while N still has no process in it at all
 └── P1  snug __stage-setup → __stage-serve  THE NAMESPACE HOLDER
      │   U (one uid mapped) + N (created by the clone, PINNED by a descriptor,
      │   then LEFT) + its own mount ns. No listener, no socket on any path.
      └── snug __innetns <fd> bwrap ...      a setns shim, one execve deep
           └── bwrap (in N)                  the sandbox, unchanged in every respect
                └── payload
```

`bwrap`'s argv is byte-identical to the `NetnsSandbox` case except for the enumerated `--unshare-*` set (`internal/policy/bwrap.go`, `Topology.Netns == NetnsStage`): **which process called `fork` is what determines the topology, not the argv.** `pasta` is aimed at the descriptor P1 pinned before it moved, *never* at `/proc/<P1>/ns/net` — after the move that path names P1's own empty namespace, and `pasta` attaches to it silently (SUPERVISOR-DESIGN §3.4).

**`NetnsHost` — the host's own netns, `--share-net`, behind `--i-know`.** No stage for the network's sake; `@net-host` together with a container profile still gets one, for the subuid range alone.

#### The ordering — and the handshake that used to provide it

The startup order **is** the security property, and it is enforced by construction rather than by a protocol:

```
stage.Start   -> N exists, pinned by a descriptor, with nobody in it
startPasta    -> pasta attaches to that EMPTY N and configures snug0
WaitNetReady  -> the stage confirms snug0 is UP and RUNNING, from inside N
StartSandbox  -> only NOW does a payload exist
```

`bwrap` is forked with **no `--block-fd` and no `--json-status-fd`**. A failure at any step before `StartSandbox` aborts the run with no payload having been forked at all, so there is no window in which the payload runs with a half-configured network, and none in which it runs with the host's netns (`TestAbortedNetworkNeverRunsThePayload`).

What made this order possible had been recorded as a blocker: confirming the interface is up needs a process *inside* N to read `/proc/<pid>/net/dev`, and before `bwrap` there is none. But **a socket's network namespace is fixed when the socket is created and does not follow the process** — measured, with both controls — so the socket the stage opens in N still answers for N after the stage has left, and `stage.WaitNetReady` asks over the control socket (SUPERVISOR-DESIGN §7).

> **SUPERSEDED — the `--json-status-fd` / `--block-fd` handshake.** Until the stage landed, `bwrap` was started **first** and told to park its payload until `pasta` had attached, because `pasta` needs a netns and only `bwrap` could make one: `snug` created two pipes and passed `--json-status-fd J --block-fd B`, read `{"child-pid": N, ...}` off `J`, started `pasta` against `/proc/N/ns/net`, polled `/proc/N/net/dev` until a device other than `lo` appeared, then wrote one byte to `B`.
>
> **VERIFIED end to end at the time**, inside a distrobox container: `bwrap --json-status-fd 9` emitted `{ "child-pid": 59817, ... }`; `pasta --netns /proc/59817/ns/net --userns /proc/59817/ns/user --config-net ...` attached with rc=0; the sandbox then had a configured interface, working DNS, `curl https://example.com → 200`, and `127.0.0.1:631` / `127.0.0.1:3100` / `[::1]:3100` all refused. That measurement was correct when it was taken and is kept here only so a reader who meets the flags in an old comment can place them. **Nothing in `snug` emits either flag today** — `internal/sandbox/parked.go`, `readChildPID` and `waitForNetDevice` are gone with them.
>
> **Why it went, rather than being tightened.** The parked interval was a real defect, not merely an extra moving part: `bwrap` releases a parked payload on EOF exactly as readily as on a byte, and `snug`'s own death closes the write end — so a `SIGKILL` of `snug` inside the window ran the payload with no network *and* left an orphaned sandbox. Measured 5/5. Reordering does not narrow that window; it removes the thing that had one. **A payload that has not been forked cannot be released early.**
>
> Read the deletion as covering exactly that half. The *other* clause of the same finding — a signalled `snug` leaving `bwrap`'s init reparented and holding the payload, during the ~40 ms before `bwrap` arms `--die-with-parent` on it — was open on **both** topologies and predates the stage. What covers it is `internal/sandbox/teardown.go`'s guard, armed around each fork; issue [#13](https://github.com/gomoni/snug/issues/13) carries the measurements, and issue [#111](https://github.com/gomoni/snug/issues/111) the correction that `kill -QUIT` reproduced it while three documents said only `SIGKILL` could.

**Teardown and lifetime chain.** "The tree" below is the stage, `pasta`, the engine and `bwrap` — whichever of them a given run has.

| Event | What happens |
|---|---|
| Payload exits normally | `bwrap` exits → `snug`'s `Wait` returns → `snug` `SIGTERM`s `pasta` (2 s grace, then `SIGKILL`) and collapses the stage → netns refcount hits zero → kernel reaps it. |
| Payload segfaults / is killed | Identical. `bwrap`'s reaper collects the payload, exits with the signal-derived code, `snug` propagates it. |
| `snug` gets a catchable signal that would otherwise be fatal | `armTeardown`'s handler — installed **immediately before each fork**, never after it — kills the process `snug` itself forked (`bwrap` on the floor, the stage under `NetnsStage`) and then **sweeps the host's own `/proc` for anything still alive underneath it**, rather than trusting the kernel's cascade to have armed in time. `teardownSignals` carries every signal a Go handler can reach, measured one at a time rather than assumed: `TERM INT HUP QUIT ABRT TRAP SYS SEGV BUS FPE ILL STKFLT`. |
| **`snug` is `SIGKILL`ed** | Two independent mechanisms, because they cover different failures. The **lifeline** is an anonymous pipe `snug` holds the write end of and never writes to: the stage sees EOF the instant `snug` dies and exits, which makes `bwrap`'s own `--die-with-parent` fire (the stage is `bwrap`'s real parent across every exec in the chain). **`PR_SET_PDEATHSIG`** is the second, and load-bearing rather than decorative: the lifeline needs the stage to *run a goroutine* to notice EOF, and a **stopped** process runs no user code at all. Measured 3/3 — `SIGSTOP` the whole tree, then `SIGKILL` `snug`, and everything is gone with no leaked netns (`TestAFrozenStageTreeStillDiesWithSnug`, `TestNoLeakedHelpersAfterSIGKILL`). `pasta` carries `SysProcAttr{Pdeathsig: SIGKILL}` of its own. |
| `pasta` dies mid-run | The tap device vanishes; the sandbox is left with `lo` only. This is the **fail-safe direction** — the sandbox loses connectivity, it never gains reachability. `snug` watches `pasta`'s `Wait()`, logs an error with `pasta`'s captured stderr, and warns. It does **not** silently restart (a restart would race a new port set) and it does **not** kill the payload (which may be mid-edit). On a *signalled* teardown the guard claims the death first, so a `Ctrl-C`'d run does not print a false degradation notice on the way out (issue [#112](https://github.com/gomoni/snug/issues/112)). |
| `pasta` outlives the netns | **VERIFIED**: `pasta` self-reaps within a few seconds of the netns emptying, even with no signal from `snug`. `snug` still signals it explicitly rather than relying on this. |

**The residual is stated as a rule, not as a list of signal names** — naming them is exactly what went wrong last time. What stays open is every termination that runs no Go signal handler: `SIGKILL`, which never reaches userspace, and a genuine panic or runtime throw inside `snug` itself, which dies on the Go runtime's own crash path. Nothing else. `internal/sandbox/teardown.go` is where that paragraph lives in the code.

`snug` uses no `Setpgid` anywhere in the sandbox chain: the tree must stay in the terminal's foreground process group so `Ctrl-C` reaches every stage and job control works for an interactive shell inside the sandbox. (Lesson carried from `agent-sandbox`.) There is exactly one deliberate exception and it is not in that chain — the container reaper (`internal/engine/reaper.go`) takes its own process group and no `Pdeathsig`, precisely because its job is to **outlive** a `snug` that died without stopping its containers, which is also why it is exempted from the teardown sweep by pid (issue [#113](https://github.com/gomoni/snug/issues/113)).

### 4.4 The engine inside the sandbox's netns — built, Tier B

**Status: shipped.** Tier B ([#63](https://github.com/gomoni/snug/issues/63)) landed on 2026-08-18 and was measured against a real engine. `@podman-socket` no longer includes `net`; the stage forks the container engine into **this sandbox's own N** (`internal/stage`'s `startengine`/`__inengine`, `EnterEngine`, joining by `setns`) and drops its capabilities to `policy.EngineCapBounding` — twelve, enumerated in `--dry-run`'s TOPOLOGY block, `CAP_NET_ADMIN` **not** among them.

The consequence, and it is the whole point of the move: **a container's network is the sandbox's network, in both directions.** With `@net`, the internet; without it, nothing. `@podman-socket` alone, a pull fails with "network is unreachable"; `@podman-socket -p @net`, the same pull succeeds and a container's `wget` reaches the internet. A `version`/`info` call succeeds in **both** cases — the engine exists and answers either way, only egress differs. (`TestPodmanSocketDoesNotImplyEgress` is the structural half; `TestPodmanSelectsAStage` pins that a container profile selects a stage at all.)

**This section is the worked example of its own hazard, twice over, which is why the history stays.** It once described this topology in the present tense for a whole milestone while no code had ever done it — and the consequence was live and user-visible: with `@podman-socket` selected and no `@net`, `--dry-run` printed "No egress" while a container reached the whole internet through the *host* engine it actually ran on. Then, after Tier B shipped the topology for real, the corrected text drifted the other way and went on describing the engine as host-side and the move as a plan, which is the same defect with the sign flipped and the harder one to catch, because a paragraph that reads as a correction reads as trustworthy ([#149](https://github.com/gomoni/snug/issues/149)). **Both directions are the same failure: prose quoting a mechanism is a copy of state held in the code.**

**What the shape buys, and what it costs.**

- **Containers share N host-mode.** `HostConfig.NetworkMode = "host"` is the **one** namespace mode the proxy now allows, and Tier B inverted what it means: it says "join the engine's current netns", and the engine's current netns is N. Every other namespace mode stays refused unconditionally — `PidMode = "host"` above all, because `__inengine` does **not** unshare pid, so the engine's own pid namespace *is* the real host's and a container joining it would be a genuine escape Tier B does nothing to close (`internal/dockerproxy/create.go`).
- **No per-container bridge and no port publishing.** The engine holds no `CAP_NET_ADMIN`, so it cannot reconfigure N to publish one even if asked; `podman run -p N:80` is refused by the proxy and `--dry-run` says so in the CONTAINERS block. Read [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §2's per-container-bridge measurement as the feasibility proof it always was, **not** as the shipped shape — the settled decision went the other way.
- **A stage, even offline.** A container profile raises `Netns` to `NetnsStage` and `Subuid` to `SubuidFull`, so an offline `@podman-socket` run still starts a stage (§4.3) and still delegates the full subuid range. That is a real cost, stated in the TOPOLOGY block rather than buried here: the sandbox's user namespace has a privileged ancestor for the whole run.
- **The mount view is still enforced, not structural.** The engine's mount namespace is a private **copy of the host tree**, not the sandbox's view. What stops a container binding an ungranted path is the proxy's bind filter (§7.2), which reads this same resolved `Policy` — a named, tested deferral. Tier C ([#125](https://github.com/gomoni/snug/issues/125)) is what makes the view itself structural.

**[`ENGINE-NETNS.md`](ENGINE-NETNS.md) remains the truth on this subject** — the original finding (§0), the measurements the inversion was argued from (§1–§2), what it costs and where it does not work at all (§3, distrobox shims and subuid/cgroup delegation), and which guarantees change shape (§4). Its §0 banner carries the two corrections the wiring pass found that its own reasoning did not predict: podman does not self-mount `/run` in this root-in-U, full-subuid shape (so `__inengine` mounts a bare tmpfs there), and `CLONE_NEWCGROUP` changes what `/proc/self/cgroup` *reports* without changing what the inherited `/sys/fs/cgroup` mount is rooted at (so `__inengine` mounts a fresh `cgroup2` over it).

### 4.5 The exact `pasta` argv

For the `@net` profile:

```
pasta \
  --config-net \                        # configure address/routes/MTU in N. NOT implied when
                                        #   joining via --netns (VERIFIED: without it the tap
                                        #   interface exists but stays DOWN with no address)
  --map-host-loopback none \            # do not translate any address to the host's loopback
  -t none \                             # host -> ns TCP forwards. `publish = [...]` renders
                                        #   `127.0.0.1/3000,8080` here instead
  -u none \                             # host -> ns UDP forwards: none
  -T none \                             # ns -> host-init TCP forwards: NONE. *** THE FIX ***
  -U none \                             # ns -> host-init UDP forwards: NONE. *** THE FIX ***
  --dns-forward 169.254.1.1 \           # intercept DNS to this link-local address and re-issue
                                        #   from the HOST side (§4.7)
  --ns-ifname snug0 \                   # stable, recognisable interface name inside the sandbox
  --no-netns-quit \                     # mandatory for a /proc/<pid>/ns/net target: pasta would
                                        #   otherwise try to watch the netns *directory* and exit
  --quiet \                             # snug owns the diagnostics
  --foreground \                        # stay OUR child: Pdeathsig works, Wait() detects early
                                        #   failure, teardown is deterministic. pasta daemonises
                                        #   by default, which would break all three.
  --netns  /proc/<CHILD>/ns/net \       # the sandbox's netns, by /proc path — never bind-mounted
  --userns /proc/<CHILD>/ns/user        # required: joining a netns needs CAP_SYS_ADMIN in the
                                        #   userns that owns it
```

`-a`/`-n`/`-g` (`@net-anon`) and `--mtu` are appended when the policy sets them.

Deliberately **not** passed:

- `--map-guest-addr` — defaults to `none`, and `snug` wants no host→guest special address. Its absence is asserted behaviourally, not by trusting the default.
- `-a`/`-g`/`-n` by default — `pasta` copies the host's addresses and routes into the namespace, so the sandbox sees the host's LAN address (**VERIFIED**: `192.168.1.120/24` inside the ns). This is a minor information disclosure. `snug` exposes it as the opt-in `@net-anon` profile rather than a default, because overriding it diverges the sandbox's view from the host's and can confuse tooling. **VERIFIED** that `-a 10.13.13.2 -n 24 -g 10.13.13.1` works with egress intact (`curl → 301`).
- `--mtu` by default — `pasta` defaults to 65520 (**VERIFIED** inside the sandbox), which is correct: `pasta` is a userspace stack that does its own segmentation, and a large namespace-side MTU avoids pointless fragmentation. Exposed as a knob for pathological networks.

### 4.6 Network profiles

| Selection | Compiles to | Cost |
|---|---|---|
| *(none)* | `bwrap --unshare-all`, no `pasta`. Netns with `lo` only. | No network at all. This is the floor and requires no helper binary — *provided no container profile is selected*: one of those raises the topology to `NetnsStage` and starts a stage even offline (§4.4). |
| `@net` | topology (b) + the argv in §4.5 | Full internet in/out. Host loopback unreachable. Host cannot reach sandbox ports. |
| `publish = [3000, 8080]` in a profile | `@net`, `-t 127.0.0.1/3000,8080` | Those ports, bound inside the sandbox, become reachable on the **host's** `127.0.0.1` — and only there. **VERIFIED**: a listener answered `200` from the host at `127.0.0.1:18099` and was **refused** at `192.168.1.120:18099`. The LAN never sees it. |
| `@net-anon` | `@net` + `-a/-n/-g` from a private range | Sandbox does not learn the host's LAN address. |
| `@podman-socket` / `@podman-build` | topology (b) via the **stage**, engine forked into N, no `pasta` of its own | No egress on its own. Selects a stage and the full subuid range; a container gets exactly the sandbox's network, whatever that is (§4.4). |
| `@net-host` | `bwrap --unshare-all --share-net`, **no `pasta`** | **Everything.** Host loopback, every abstract AF_UNIX socket (X11, D-Bus), the LAN as the host. Requires `--i-know` on the command line *and* prints a warning. Exists so that "I need to debug a host service" does not become "so I stopped using snug". |

**There is deliberately no `@net-publish` profile and no `publish_auto`.** One shipped once and was removed. The reason: with `-t auto`, **the sandbox chooses which host loopback ports appear**. That inverts the guiding principle — the agent, not the human, would author a host-visible surface, and a prompt-injected agent could squat `127.0.0.1:8080` ahead of your own dev server and intercept your browser. With `publish = [3000]` the human named the port and the hole is exactly one port wide. `base.toml`'s comment above the `publish` key is the standing statement of this; this is the decision in the whole networking section most likely to be revisited.

### 4.7 DNS, on both kinds of host

The sandbox's `/etc/resolv.conf` is a **generated file delivered from an anonymous memfd via `--ro-bind-data`**. Not a bind of the host's file (which may name an unreachable address), not a tmpfs the agent can rewrite, and not a host temporary file (which would be a real file on disk with a race). It contains exactly:

```
nameserver 169.254.1.1
search .
options edns0
```

**VERIFIED** inside a full sandbox: `cat /etc/resolv.conf` shows exactly this, and `curl https://example.com` returns `200`.

`169.254.1.1` is a link-local address that `pasta` intercepts with `--dns-forward`. `pasta` sits in the **host** network namespace on its socket side (that is what gives the sandbox egress at all), so it re-issues the query from the host, to whatever the host's real resolver is. This makes both host configurations work with **one identical sandbox-side configuration**:

- **Plain `resolv.conf` (this host, `nameserver 192.168.1.1`).** `pasta`'s `--dns-host` defaults to the first nameserver in the host's `/etc/resolv.conf`, read at startup from `snug`'s (i.e. the host's) mount namespace. Queries go to `192.168.1.1` from the host netns. **VERIFIED** by a raw DNS query from inside the namespace: `DNS RESPONSE bytes=61 ancount=2`.
- **`systemd-resolved` (`nameserver 127.0.0.53`).** `127.0.0.53` is unreachable *from the sandbox* — which is exactly the property we spent §4.2 establishing, and we must not undo it. But `pasta` is not in the sandbox. `pasta`'s socket side is in the host netns, where `127.0.0.53` is perfectly reachable. `--dns-forward 169.254.1.1` therefore works unchanged: the sandbox talks to a link-local address that does not exist, `pasta` catches it and talks to `systemd-resolved` on the host's behalf. **No host-loopback hole is opened**, because the sandbox never gets a route to `127.0.0.53`; it only gets an answer.

**Offline.** With no `@net` profile there is no `pasta` and no DNS. `/etc/resolv.conf` is still generated, so resolver libraries fail immediately and legibly instead of hanging on a 5-second timeout.

`search .` (rather than copying the host's search domains) prevents the sandbox from learning the host's internal domain names, and prevents accidental resolution of bare hostnames against a corporate suffix.

### 4.8 IPv6, MTU, address, hostname

- **IPv6** is enabled by default. `pasta --config-net` copies the host's v6 configuration; **VERIFIED**, the sandbox got global and link-local v6 addresses and a default v6 route, and `[::1]:3100` (host loopback over v6) was **refused**. Both `--map-host-loopback` and `-T`/`-U` take up to two addresses, one per family, and `none` covers both.
- **MTU** is `pasta`'s default 65520 (**VERIFIED** on the namespace interface). Knob: `mtu = 1500`.
- **The sandbox's own address** is, by default, the host's — `pasta` copies host addresses into the namespace. Stated plainly because it is a (small) information disclosure: the agent learns your LAN IP. `@net-anon` fixes it.
- **Hostname.** `--unshare-all` includes a UTS namespace, and `snug` sets `--hostname snug`. **VERIFIED**: `hostname` inside returns `snug` while the host remains `laptop`. This is worth doing for a reason beyond cosmetics: shell prompts, `tmux` status lines and agent transcripts all show it, so **you can always tell at a glance whether you are inside a sandbox**. `snug` additionally exports `SNUG=1`, `SNUG_PROFILES=<list>` and a distinctive `PS1`.
- **`/etc/hosts` is NOT generated** and is not granted by `@sys`, so the sandbox has no hosts file at all. That was once described here as generated; it never was. It is a real (small) gap — a tool that expects `localhost` to resolve from a file rather than from the resolver will not find it — recorded here rather than fixed silently.

### 4.9 Fallback matrix — and the rule that governs it

**The rule: `snug` never silently falls back to a weaker security posture. Ever.**

A silent downgrade is worse than a failure, because the user believes a guarantee that no longer holds. The only subsystem permitted to degrade quietly-ish is seccomp, and even that prints a warning, because seccomp is defence-in-depth on top of the namespace boundary rather than the boundary itself.

| Condition | Detection | Behaviour | Message |
|---|---|---|---|
| Unprivileged userns unavailable (`kernel.unprivileged_userns_clone=0`, AppArmor `apparmor_restrict_unprivileged_userns=1`, `max_user_namespaces=0`) | preflight probe | **FATAL.** `snug` cannot function. | Names the exact sysctl and the exact value needed, plus the Ubuntu 24.04 AppArmor case. |
| `bwrap` not on `PATH` | `LookPath` | **FATAL** | `snug requires bubblewrap (bwrap). Install: <distro hint>.` |
| `@net` requested, `pasta` not installed | `LookPath` | **FATAL** | names `pasta` and says why running with no network — or worse, the host's — is not offered as a fallback. Asserted by an integration test: it must never exit 0. |
| `@net` requested, `pasta` fails to attach | non-zero `Wait()` or no non-`lo` device within the readiness window | **FATAL**, payload never released (§4.3) | `pasta` stderr is reproduced verbatim. |
| `--unshare-net` refused (deeply nested userns, some seccomp-restricted CI) | `bwrap` exit + stderr | **FATAL** | names `@net-host --i-know` as the explicit, knowingly-large alternative. |
| **Inside `distrobox`/podman container** | `/run/.containerenv` or `/.dockerenv` present | **Works.** No special handling. | Everything in this document was verified inside a rootless-podman distrobox: nested userns, netns creation, `pasta` attach, egress, DNS, loopback isolation. `snug doctor` reports the nesting for context. |
| Seccomp unavailable | probe + install error | **Degrade with a warning.** | `seccomp filter unavailable (<reason>); continuing WITHOUT it. The namespace boundary is unaffected; ptrace/keyctl/TIOCSTI hardening is not active.` |
| `podman` profile, no usable `podman` binary | `LookPath` + `podmanClientUsable` (host-escape shim detection) | **FATAL** for a missing binary. The shim case is **currently a warning** and [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §3 argues it must become a refusal. | Never degrades to "no engine but the profile said yes". |
| SELinux enforcing | `getenforce` | Works; container binds get `:z` (§8.3) | Reported in the status line. |

`snug doctor` runs every probe and prints a table, so a user can diagnose a host before their first run rather than during it.

### 4.10 Interaction with the podman-socket profile

**A container started through the proxied socket runs in the sandbox's own netns**, because the engine does (§4.4). A container's network posture is therefore `snug`'s, not the engine's — the sentence that stood here for two milestones said the opposite, and said it after it had stopped being true.

*This section used to be the whole story and is now a cross-reference, deliberately.* One subject, one home: §4.4 is what the topology is, [`ENGINE-NETNS.md`](ENGINE-NETNS.md) is how it was measured and what it costs, and §7.2 is the endpoint filter. What belongs here is only the interaction:

- **Egress follows the sandbox's exactly.** No `@net`, no container egress — and `--dry-run` says so truthfully, which is the property the original finding was about (`TestPodmanSocketDoesNotImplyEgress`).
- **There are no published ports to reach, in either direction.** Not "the sandbox cannot reach its own containers' published ports": the engine holds no `CAP_NET_ADMIN`, so no mapping is ever set up, and `PortBindings`/`PublishAllPorts` are refused at the proxy. A container listening in N is on the sandbox's own loopback already, with nothing to publish it *to*.
- **Selecting containers changes the process topology, not just the socket.** A stage and a delegated subuid range, offline included — §4.3 and §4.4 for what that buys and costs.
- **The refusals that bound it are §7.2's**, and one of them inverted with Tier B: `NetworkMode = "host"` is now *allowed* and means "join N". Every other host/`container:`/`ns:` namespace mode stays refused, `PidMode` most of all.

---

## 5. `bwrap` argv generation

**This section is the only home of the argv.** `internal/policy/bwrap.go` emits it and `internal/policy/testdata/*.bwrap.txt` are the reviewed goldens.

### 5.1 Namespaces

```
--unshare-all          # user, ipc, pid, net, uts, cgroup — everything bwrap supports
[--share-net]          # ONLY under @net-host
--uid <host uid>
--gid <host gid>
--hostname snug
--die-with-parent
[--new-session]        # ONLY where the kernel still allows TIOCSTI
```

`--unshare-all` rather than a selective list, on principle: the selective form is a denylist of namespaces to keep, and this design does not do denylists. `--share-net` is the single documented exception.

**`--new-session` is conditional, and deliberately so.** It gives the sandbox its own TTY session, which blocks TIOCSTI input injection into the launching terminal — but it also breaks job control for an interactive shell inside the sandbox. `/proc/sys/dev/tty/legacy_tiocsti` is `0` on this kernel, so the flag buys nothing here and `snug` omits it; where that sysctl is `1`, `snug` adds it and `--dry-run` says so. The decision is never made silently.

**`--uid`/`--gid` are set to the invoking user's real ids, not 0.** Mapping to 0 inside the userns is common and tempting (it makes `chown` work), but it means every file the agent creates in the project is owned by a uid that maps back to *you* while the agent *believes* it is root — and it makes `sudo`-shaped mistakes look plausible. Same uid inside and outside means file ownership is boring and correct, and `id` shows a normal user.

### 5.2 `/proc`, `/dev`, `/sys`, `/tmp`

- `--proc /proc`. A fresh procfs bound to the sandbox's own PID namespace. Without a PID namespace this would leak the host process table; with `--unshare-all` it shows only the sandbox's own processes.
- `--dev /dev`. `bwrap`'s synthetic minimal `/dev` plus a private `devpts`. No `--dev-bind /dev /dev` — that would hand over every block device, `/dev/kmsg`, `/dev/mem`, and the input devices. It is writable tmpfs and does not persist, which is easy to forget when saying "the target is the only writable thing".
- **`/sys` is not mounted at all**, and no builtin grants it. `/sys` read-only still exposes a lot of host topology (network interfaces, PCI devices, DMI/serial numbers, thermal data) and is a recurring source of container escapes when combined with anything writable. The compatibility cost is real: some tooling reads `/sys/fs/cgroup` or `/sys/devices/system/cpu` for parallelism hints. A one-line user profile (`ro = ["/sys"]`) is the escape hatch; snug does not ship one.
- `--tmpfs /tmp` by default (private, ephemeral, dies with the sandbox). The `@tmp-shared` profile replaces it with a bind of a per-project host directory (§7.3).

**What each of these actually exposes was audited by execution, and the answer is longer than this list — [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md).** Its headline: no escape (every classic `/proc` write primitive is refused), but a fingerprinting surface larger than any OCI runtime's default, including `boot_id`, `btime`/`uptime` (the time namespace is *not* unshared by `--unshare-all`), `/proc/asound` and `/proc/bus/pci`. Do not restate `/dev`'s or `/proc`'s contents from memory; that document enumerates them.

### 5.3 On `/etc`: enumerate, do not bind wholesale

**This section originally argued the opposite, and the argument was wrong. It is kept here as a correction because the flaw in it is instructive.**

The original reasoning was: *`snug` runs as your uid, so binding `/etc` grants the sandbox exactly the bytes you could already `cat` from a shell. It confers no new authority.* Every clause of that is true, and it is still beside the point, because it reasons only about **confidentiality**. `/etc/profile.d/*` and `/etc/bash.bashrc` are not read by the sandbox — they are **executed** by every shell inside it. Binding all of `/etc` therefore hands the host distribution a code-injection channel into the agent's startup. That is a new authority, on an axis the original argument never considered.

It is not hypothetical. On the development host (a `distrobox` container), `/etc/profile.d/distrobox_profile.sh` contains:

```sh
test -z "${DBUS_SESSION_BUS_ADDRESS:-}" && export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -ru)/bus"
```

Because `--clearenv` did its job, the script sees an empty environment, *reconstructs* the bus address from the uid, and calls `host-spawn` — which then fails, repeatedly and visibly, against a bus the sandbox correctly cannot reach. The noise is harmless. The mechanism is not: a script shipped by the host got to run arbitrary code inside the sandbox and rewrite its environment. `distrobox` exists to maximise host integration; `snug` exists to minimise it, and inheriting its startup scripts inherits its goal.

So `@sys` enumerates. The current list is in `base.toml` — roughly the dynamic linker (`ld.so.*`), the TLS trust store, `nsswitch.conf`/`passwd`/`group`, and locale/timezone/distro detection.

**VERIFIED** in a real sandbox: a curated `/etc` instead of 109 entries, no startup noise, and `python3 -c "import ssl; len(ssl.create_default_context().get_ca_certs())"` returns 145 certificates; `git`, `go`, `date +%Z` and `whoami` all behave.

Two entries on that list were found by breakage rather than by reading, which is the maintenance cost made concrete:

- **`/etc/crypto-policies`** — `openssl.cnf` line 81 is `.include = /etc/crypto-policies/back-ends/opensslcnf.config`. Without it every TLS client dies with `MODULE_INITIALIZATION_ERROR`, which names neither the file nor the include.
- **`/var/lib/ca-certificates`** — `/etc/ssl/certs` is a symlink *out of* `/etc` into it. Granting `/etc/ssl` alone yields a trust store that resolves to nothing. This is precisely the symlink-out-of-a-granted-directory hazard from §3.3, met in the wild on the first try.

When adding to this list, test it: `python3 -c "import ssl; print(len(ssl.create_default_context().get_ca_certs()))"`.

**What snug generates on top of the enumerated set is exactly one file today: `/etc/resolv.conf`** (§4.7). This section previously also claimed generated `/etc/hosts`, `/etc/passwd`, `/etc/group` and a per-sandbox random `/etc/machine-id`. **None of those exist.** `passwd` and `group` are bound read-only from the host, so the sandbox *can* enumerate the machine's accounts; `base.toml` marks them "generated by snug in a later milestone". And the machine-id claim came with a conclusion — "so the sandbox cannot fingerprint the host" — that [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md) falsifies independently: `boot_id`, `btime`/`uptime` and the PCI/sound topology fingerprint the host regardless of what `/etc/machine-id` says.

There is deliberately **no `etc-full` builtin**. A profile granting the whole tree is one line —

```toml
[profile.etc-full]
ro = ["/etc"]
```

— that any user can drop in `~/.config/snug/profiles.d/`. Shipping it as a builtin bought nothing except a maintenance obligation and a thing to explain, and what it costs is a cost the person writing that line is choosing knowingly. Same minimalism as having no `--read-only` (§2.5): the tool stays small, and the escape hatch is the profile format itself.

### 5.4 Seccomp

A classic-BPF denylist, assembled in **pure Go** (`golang.org/x/net/bpf` + `golang.org/x/sys/unix` for arch-correct syscall numbers), written to an anonymous `memfd`, and passed via `--seccomp FD`. No `cc` dependency, cross-arch by construction. Default `ALLOW`.

Denied with `EPERM`: `ptrace`, `bpf`, `userfaultfd`, `add_key`, `keyctl`, `request_key`, `perf_event_open`, `pidfd_getfd`, `process_vm_readv`, `process_vm_writev`; `ioctl(_, TIOCSTI, _)` (terminal input injection); `unshare`/`clone` with `CLONE_NEWUSER` (nested-userns escape primitive).

`pidfd_getfd`/`process_vm_readv`/`process_vm_writev` (issue #23) are the ptrace-free spellings of descriptor theft and direct memory read/write — but denying them does **not** make co-resident payloads safe from each other, and no comment describing them may be read as claiming it does. Both have an open **procfs** spelling that no syscall filter can name: `/proc/<pid>/fd/N` reopen (`PTRACE_MODE_READ`, which Yama does not gate) for the descriptor half, and `/proc/<pid>/mem` (`open`+`pread`/`pwrite`) for the memory half — red-teamed sibling-to-sibling, with Yama's `PR_SET_PTRACER_ANY` waived, to both read and overwrite another payload's memory with this filter active. Tracked as issue #47. What the two denied syscalls buy regardless: `pidfd_getfd` is the only route to a sibling's **connected socket**, and the `process_vm_*` denial closes the syscall-level route even though the procfs one remains. That socket clause used to read "*non-file* open file descriptions (a connected socket gives `ENXIO` on a procfs reopen; pipes, memfds, deleted and `O_TMPFILE` files have no path to reopen at all)" and three quarters of it was false — issue #115 measured a sibling reopening a memfd, a pipe, a deleted file and an `O_TMPFILE` file through `/proc/<pid>/fd/N`, contents intact: each has a backing inode, and `open(2)` on the magic link re-derives a working descriptor once `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)` passes, which same-uid does and which Yama never gates (it checks `PTRACE_MODE_ATTACH` only, at every `ptrace_scope`). The socket survives for a structural reason rather than a permission one — sockfs installs `sock_no_open`, so the reopen is `ENXIO` for root as well — which is what makes SUPERVISOR-DESIGN.md's control-channel argument still stand. Pinned by `TestKnownOpenResidualSiblingReopensAnythingButASocket`.

Denied with **`ENOSYS`: `clone3`** — and the errno is the entire point, not a detail. `clone3`'s flags live behind a pointer that classic BPF cannot dereference, so the flag check that catches `unshare`/`clone` cannot be written for it and the whole syscall has to go. Denying it with `EPERM` **broke the world**: glibc's `pthread_create` falls back to `clone()` only on `ENOSYS`, so every threaded program failed, and the symptom was `curl https://example.com` returning `000` while `getent hosts` worked — a seccomp bug wearing a DNS bug's clothes. `ENOSYS` is what a kernel without `clone3` returns, so every caller already has a tested fallback. **When denying a syscall, return the errno callers already handle.**

Inherited gap, documented and **not** silently "fixed": non-native architectures are `ALLOW`ed, so the x86_64 i386-compat path is unfiltered. [`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md) P13 is the measured account of what that does and does not buy an attacker. Closing it properly needs `SECCOMP_RET_TRAP`/`user_notif` machinery and a supervisor thread — a possible future item, not a claim made today.

**VERIFIED** on this host: `/proc/sys/kernel/seccomp/actions_avail` = `kill_process kill_thread trap errno user_notif trace log allow`. Seccomp is the only subsystem allowed to degrade (§4.9): it is defence-in-depth *on top of* the namespace boundary, and a host that cannot install a filter is not a host where the boundary has failed. `TestSeccompIsActuallyInstalled` reads `Seccomp:` out of `/proc/self/status` from inside, because a `--seccomp` flag that is *present* in the argv proves nothing — see the `--` bug in CLAUDE.md.

### 5.5 The fd model

`bwrap`'s `--file FD`, `--ro-bind-data FD`, `--seccomp FD`, `--args FD`, `--info-fd FD` all read or write fds `bwrap` inherits, and **`bwrap` does not close inherited fds**. In Go, `exec.Cmd.ExtraFiles[i]` becomes child fd `3+i`. (`--block-fd` and `--json-status-fd` belonged on this list until the stage landed; §4.3 records what replaced them. `snug` emits neither now.) `snug` therefore:

1. Walks `/proc/self/fd` and marks every fd `> 2` CLOEXEC that it did not deliberately open, so no non-`CLOEXEC` fd from a grandparent leaks into the sandbox. **An open directory descriptor ignores the mount namespace entirely** — `openat(2)` walks from the descriptor's own vfsmount — so a leaked dirfd is a complete bypass of every grant.
2. Substitutes `/dev/null` for any of fds 0/1/2 that is a **directory**. Those three must pass through for stdio, and that exemption was itself the hole: the red team read `~/.aws` and wrote into an ungranted directory through `/proc/self/fd/0`. (`TestDirectoryOnStdinCannotEscape`.)
3. Allocates `ExtraFiles` in deterministic append order and emits the matching numbers.
4. Hands `bwrap` the **write** end of a pipe as `--info-fd FD`, keeps the read end, and decodes `bwrap`'s one-line JSON answer off it in the background: `child-pid` plus six namespace inodes, written before the payload is exec'd. That is how `snug attach` learns what to join — no procfs scanning, no `PPid` walking, no race — and it needs no protocol change under the stage, because the descriptor rides the same pass-through as every other entry in `ExtraFiles`. A `bwrap` that never answers leaves the run unattachable and **warns**; it does not fail the run.
5. Passes **the entire flag list via `--args FD`** (NUL-separated, from a memfd) rather than as real argv. Three reasons: it sidesteps `ARG_MAX` for large policies; the sandbox's own `/proc/<pid>/cmdline` does not display the full policy to the agent; and it removes every shell-quoting concern from `snug --dry-run`'s round-trip. **Nothing may be appended to the flag slice after the memfd snapshot** — a comment marks the point, because that bug has bitten twice.
6. Passes `cmd.Env = []string{}` to `bwrap` itself. `--clearenv` covers the payload, not bwrap's own process, and bwrap becomes PID 1 of the sandbox's pidns: with a nil `Env`, Go passes `os.Environ()` and the payload reads the entire host environment out of `/proc/1/environ`. (`TestNoHostEnvironmentViaPid1`.)
7. Runs `bwrap` to completion rather than `exec`-replacing, so deferred teardown runs and the exit code can be propagated.

---

## 6. Lessons from `agent-sandbox`

The previous generation (`/home/u/projects/work/team/agent-sandbox`, ~45 Go files, 624-line `DESIGN.md`) is the source of most of the hard-won detail here. This section is history and rationale; nothing in it is a live specification.

### 6.1 What carries over unchanged

- **The anti-drift thesis, which is the single best idea in the prior design.** One `Policy` value, computed once, is the sole author of *both* the `bwrap` argv *and* the container-proxy's decisions. The set of host paths a container may bind therefore cannot widen past what the sandbox itself exposes — divergence is impossible by construction, not by review. `snug` keeps this verbatim, and extends it: the same `Policy` now also authors the `pasta` argv.
- **`include` composes upward.** Kept, with the resolution semantics tightened (§2.3).
- **The filtering ssh-agent proxy with `ssh_mode = "agent-proxy"`.** Kept as the recommended answer (§7.1).
- **The `[identity]` block vocabulary** (`gh_user`, `gh_host`, `git_name`, `git_email`, `ssh_key`, `ssh_mode`). Kept as-is.
- **The fd model** (`ExtraFiles` → `3+i`), **pure-Go seccomp BPF via memfd**, **strict JSON decoding with `DisallowUnknownFields()` + trailing-data check** as the API-drift guard, **strip-and-inject mount rewriting**, **component-wise (not string-prefix) containment checks**, **`StoreKey` store math**, **SELinux `:z` relabel**, **`Setpgid` on the engine but nowhere in the sandbox chain**.
- **Two bugs whose regression tests carry over verbatim**: `bwrap` cannot create a mountpoint at a symlink destination (§3.3); and a proxy that buffers streaming response headers deadlocks foreground `docker run`, because the client calls `ContainerWait` before `ContainerStart` — `Flush()` immediately after `WriteHeader`.

### 6.2 What is deliberately dropped

- **The daemon (`engined`).** The prior project had already removed it, for a structural reason worth restating: podman must live inside the run's own netns, so the netns must be *owned by the run*, so there is one process tree per run and nothing to share. **What is lost:** a warm, shared container engine across runs. **How `snug` compensates:** per-sandbox storage is *persistent on disk* keyed by profile+target (§8), so the recurring cost is engine startup rather than re-pulling images; and the engine is started **lazily**, only when the sandbox's first request reaches the proxy socket.
- **`allowlist_root = false`** — the escape hatch that inverted the model back to "whole host read-only plus masks". **Removed with no replacement.** It is not expressible: it requires a `mask` concept, and `snug` has no subtraction. This is the single largest deviation from the prior config, and it is the point of the rewrite. If you want the whole host readable, say `ro = ["/"]` in a profile in your *own* config directory, and `snug --dry-run` will show you exactly what you did.
- **`mask = [...]`** — a deny list. Removed for the same reason. In the prior design, `mask` was needed because the base was permissive; with an empty base there is nothing to mask.
- **The `@null` profile as an explicit lattice floor.** Tried, then removed — see §2.6.
- **Scalar override by include order.** Replaced by permissive-ward joins (§2.3).
- **`offline` and `network = "offline"`.** Offline is the absence of `@net` (§2.3).
- **The `AGENT_*` env-var surface** as a primary interface. The CLI and profiles are the interface.

### 6.3 Where the prior TOML vocabulary is kept vs changed

| Prior key | `snug` | Why |
|---|---|---|
| `include` | **kept** | Composition is the model. |
| `ro`, `rw` | **kept** | Direct grants. `dev` added. |
| `env` | **kept** | Allowlist. |
| `match` | **kept in the design, not built** (§9.2) | Convenient; the failure mode must be stated. |
| `[identity]` + all fields | **kept** | Already the right answer. |
| `expose = [ports]` | **renamed `publish`**, scoped to `127.0.0.1` | `expose` reads like "make visible to the world"; the semantics are the opposite. Scoping to host loopback is a genuine posture change (§4.6). |
| `network = "host"\|"offline"\|"private"` | **kept as `"host"\|"egress"\|"isolated"`**, joined by max | `private` was ambiguous about egress. `offline` removed. |
| `docker`, `docker_build` | **`podman = "off"\|"socket"\|"build"`** | One key, one lattice, and the name matches the engine. |
| `allowlist_root`, `mask` | **removed** | §6.2 |
| `seccomp` | **removed from profiles**, CLI only | Profiles may not weaken defence-in-depth (§2.3). |
| — | **new**: `tmpfs`, `symlink`, `optional`, `path`, `dns`, `address`, `mtu`, `description`, `claude_credentials`, `claude_notice` | §2.6 |

### 6.4 The correction

`agent-sandbox` ships `pasta --config-net --map-host-loopback none -t none -u none --no-netns-quit -f --netns …` (`internal/netns/pasta.go`, in a comment block headed *"Every flag is load-bearing"*). It does not pass `-T none -U none`, so **the host's entire loopback service set is reachable from inside its "private" network namespace** (§4.2). Its own probe notes recorded the symptom (`*%lo:631` visible inside the netns) and filed it as a probable `ss`/`procfs` artifact. It was not. `snug` fixes the flags, and — more importantly — adopts the structural response: security-relevant defaults are never trusted, and the guarantee is asserted by a behavioural integration test rather than by reading a man page (§12.4).

---

## 7. Host integration surfaces

Every surface below is off by default and reached by naming a profile. Each is a *proxy* `snug` owns, never a raw passthrough — except `@tmp-shared`, which is a plain bind by nature.

### 7.1 ssh — the filtering agent proxy

**Recommendation: `ssh_mode = "agent-proxy"`, unconditionally, for every real workflow.** The alternatives exist to be rejected in writing. [`SECRETS.md`](SECRETS.md) §3.4 generalises this shape into the pattern the rest of the credential work is measured against.

| Mode | What it does | Verdict |
|---|---|---|
| **`agent-proxy`** | `snug` binds a private socket, hands it to the sandbox as `SSH_AUTH_SOCK`, and forwards to the host's **already-unlocked** agent, exposing exactly one pinned key. | **Recommended.** No key material in the sandbox. No passphrase prompt. The sandbox cannot enumerate or use your other keys. |
| `agent` | A private one-key agent; `ssh-add` prompts once at startup. | Fallback when no host agent is running. Key material lives in a process `snug` owns, still not in the sandbox. |
| `key-file` | Stage the (encrypted) private key into the sandbox. | **Weakest.** The key bytes are inside the blast radius. Only for keys you would not mind rotating. |
| `host-agent` | Bind the host `SSH_AUTH_SOCK` straight through. | **Discouraged**, and `snug` requires `--i-know`. Every key, every identity, no filtering. This is the one where the gate was documented in three places and enforced in none — see CLAUDE.md. |
| `none` | No ssh. | The default. |

**The proxy's rules.** It speaks the agent protocol (`golang.org/x/crypto/ssh/agent`), fresh upstream dial per connection (the protocol is not safe to interleave), and is fail-closed on anything it does not understand:

| Message | Behaviour |
|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES` | **Answered locally.** Returns exactly the one pinned public key and its comment — never forwarded upstream, so the host agent's other keys are not merely filtered out of the reply, they are never requested. Advertised even if the key is not currently unlocked, so the sandbox always offers it. |
| `SSH_AGENTC_SIGN_REQUEST` | **Forwarded** if and only if the blob matches the pinned public key byte-for-byte (`crypto/subtle.ConstantTimeCompare`). Any other key blob → `SSH_AGENT_FAILURE`, audited. If the key is locked, the *host* agent handles the unlock prompt at sign time. |
| `ADD_IDENTITY`, `ADD_ID_CONSTRAINED`, `ADD_SMARTCARD_KEY*` | **Refused.** The sandbox must not be able to plant a key in your host agent. |
| `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `REMOVE_SMARTCARD_KEY` | **Refused.** Denial-of-service against your host agent. |
| `LOCK`, `UNLOCK` | **Refused.** |
| `EXTENSION` (incl. `session-bind@openssh.com`) | **Refused.** `session-bind` is how OpenSSH implements agent-forwarding restrictions; permitting extensions is an open-ended surface. Refusing it means `ssh -A` *from* the sandbox does not chain the agent onward — which is the desired outcome. |
| Anything else / malformed | `SSH_AGENT_FAILURE`, audited, connection closed. |

**What this cannot do, stated plainly:** it cannot restrict *what* is signed. A sign oracle for a key is authority to use that key for anything. Pinning to one key bounds the blast radius to one identity; it does not bound the actions. This is inherent to every agent forwarder and is not a `snug` limitation to be fixed later.

`~/.ssh` itself is **never** mounted. `snug` generates a minimal `~/.ssh/config` and `~/.ssh/known_hosts` from a memfd (the pinned host's key only), so `git push` works without the sandbox seeing your host inventory.

### 7.2 The podman/docker socket proxy

`DOCKER_HOST`/`CONTAINER_HOST` inside the sandbox point at a `snug`-owned unix socket. The upstream is a **per-sandbox** engine (§8), never the host's. The proxy is a thin transport; every decision is made in the `policy`/`dockerproxy` pair, so the mount rules and the sandbox's own mounts have one author (§6.1).

*Which client to use inside is a separate, measured question — [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md). The short answer is `docker`, and `podman` on a host where it is a host-escape shim gets a snug-authored stub that says so.*

Normalisation first: strip the `/v1.x` API-version prefix, split into segments, and **reject instantly on any `.` or `..` segment**, so `/containers/../build` cannot masquerade as an allowed prefix. Default verdict on no match: **reject 403**.

| Class | Endpoints |
|---|---|
| **Allowed (passthrough)** | `_ping`, `version`, `info`, `events`, `system/df`; container lifecycle/inspect/logs/wait/stats; `images` pull/list/inspect/tag/push/prune/rm; networks; volumes list/inspect/rm |
| **Filtered** (strict-decode → sanitise → re-encode) | `POST /containers/create`, `POST /volumes/create`, `POST /images/create`, `POST /build` (only with `podman = "build"`) |
| **Rejected, with an audited reason** | `exec`, `commit`, `session`, `grpc`, `distribution`, `images/load`, `images/create?fromSrc`, `containers/{id}/{exec,attach,update}`, `containers/{id}/archive` (GET/PUT/HEAD — a direct host-filesystem read/write channel) |

`POST /containers/create`, in order:

1. **Strict decode** into pinned `container.CreateRequest` types with `DisallowUnknownFields()` **and** a trailing-data check. Any unknown key — a future-API field that could grant an unmodelled capability — is a 403. Cost: a genuinely-new benign field from a newer client also 403s. Deliberate; bump the pinned dependency to widen.
2. **Reject-list** the escape fields and the network fields. `HostConfig.NetworkMode` ∈ {`container:*`, `ns:*`} — but **`NetworkMode = "host"` is allowed, and Tier B is why**: it means "join the engine's current netns", and since [#63](https://github.com/gomoni/snug/issues/63) that netns is the sandbox's own N (§4.4). It is the single exception; every other namespace mode below stays refused for `host` as well. Then `PortBindings`/`PublishAllPorts`; `Sysctls`, `DNS*`, `ExtraHosts`; `UsernsMode`, `PidMode`, `IpcMode`, `UTSMode`, `CgroupnsMode` set to any `host`/`container:` value; `Privileged`, `CapAdd`, `Devices`, `DeviceRequests`, `DeviceCgroupRules`, any `SecurityOpt`, custom `Runtime`, `Annotations` (podman honours `run.oci.*`), `VolumesFrom`, non-nil `MaskedPaths`/`ReadonlyPaths`.
3. **Strip and inject.** `nil` out `Binds`, `VolumesFrom`, `VolumeDriver`, `Config.Volumes`, `Tmpfs`; set `Mounts` to exactly the canonical bind set derived from the `Policy` — normally the one writable target, `rprivate`, RW, `:z` on SELinux hosts.
4. **The bind-mount rule that answers the brief directly:** *a container may bind a host path if and only if the sandbox itself can see that path at the same or greater access.* Because both faces read the same `Policy.Mounts`, this is a lookup, not a parallel rule set. Each requested source is resolved with a **daemon-namespace realpath** (longest existing prefix `EvalSymlinks`'d, remainder rejoined lexically) and then checked **component-wise** against the containment ceiling — defeating symlinks the agent planted in the writable project. Legacy `-v` `Binds` strings are refused wholesale (option-smuggling surface), as is `type=volume` (the backing store is unknowable at bind time) and `shared`/`rshared` propagation.
5. **Security injection and re-encode.** Force `SecurityOpt=["no-new-privileges:true"]`, `Privileged=false`, then `json.Marshal` **from `snug`'s own struct**. Re-encoding is a second, independent drift guard: only fields `snug` set reach the engine.

**Container-to-container networking works, but not the way this line used to say.** The `networks` endpoints are allowed — creating a network object and connecting to it cannot escape N, and the engine holds no `CAP_NET_ADMIN` to bring a bridge up in the first place, so containment rests on N rather than on a special-cased refusal list. What makes multi-container workflows (app + database) work is that **every container shares N**, so they reach each other on the sandbox's own loopback with no network object involved at all.

`POST /volumes/create` permits driver `""`/`local` with **zero** `DriverOpts` and a nil `ClusterVolumeSpec`. That one rule kills `type=none,o=bind,device=/host`, `device=/dev/*`, and `o=addr=` NFS/CIFS remotes at their source — the separate call that plants a host-path volume later referenced as `Mounts[type=volume]`.

`POST /build` (only with `podman = "build"`) — **the shape is not what this section originally described.** Corrected against a recording of the real podman CLI 5.8.3, because the docs and this design note both had it wrong:

- The CLI posts to **`/v5.x/libpod/build`**, not the docker-compat `/v1.41/build`. Both are handled; a filter written only for the compat path would have covered a path no real client uses.
- **Every policy-relevant option is a QUERY PARAMETER.** The body is only the context tar, so there is no body to misread.
- The context tar is **forwarded unread**: the client assembled it inside the sandbox from files the sandbox can already read, so it reaches nothing new.
- `RUN --mount=type=secret` needs no rejection. The CLI reads the file **itself**, client-side, and ships the bytes in the tar under a generated name. It therefore names no host path and grants no read the sandbox did not already have.

The filter is a **default-deny allowlist over the query string** (`buildParams` in `internal/dockerproxy/build.go`), for the same reason `allowed()` is one: build options are a large, fast-moving set, and one snug has not been taught about must fail closed. Each host-reaching parameter and the flag that produces it:

| flag | parameter | judged by |
|---|---|---|
| `-v /etc:/x` | `volume` | the step-4 mount rule, unchanged |
| `--build-context x=/etc` | `additionalbuildcontexts` | the same rule, read-only; a URL is refused outright |
| `--device` | `devices` | refused |
| `--network=host` | `networkmode` **and** `nsoptions` | both, separately |
| `--cgroup-parent` | `cgroupparent` | refused |
| `--add-host` | `extrahosts` | refused |
| `--isolation` | `isolation` | default only |
| `--security-opt seccomp=` | `seccomp` | `unconfined` refused; a path gets the mount rule |
| a git/URL context | `remote` | refused |
| `--file ../x` | `dockerfile` | must stay inside the context |

**`--network=host` is the one to look at twice**, and it is why this table exists. It sets `networkmode=2` *and* an `nsoptions` entry with `Host:true`, and either alone re-opens the host network — the identical shape to §4.2's pasta flags, where passing three of the four closing options left every host loopback service reachable. Both are checked, each pinned by its own test message so neither can cover for the other's absence.

Every outcome — allow, rewrite, reject — is one audit line. Streaming and hijacked endpoints (attach, `logs --follow`, `wait`) are proxied byte-for-byte with headers flushed immediately (§6.1).

### 7.3 Shared `/tmp`

`@tmp-shared` allocates a per-project directory on the host with mode `0700` and binds it as the sandbox's `/tmp`, replacing the default private tmpfs. Use case: handing a file to a host tool, or a large build cache that should survive a crash. The directory name is derived from a hash of the target, so it is stable across runs of the same project and two projects never share one.

It refuses to bind a path that is a symlink, is not owned by the invoking uid, or has group/other write bits — the classic `/tmp` races.

**The directory persists.** It is not removed at teardown; `base.toml` says so ("Survives the sandbox") and the abuse sentence follows from it: anything the sandbox writes there is visible to the host, and to any other snug run on the same project. Do not select it and then treat `/tmp` as private. (An earlier draft here described teardown removal and a `--keep-tmp` flag. Neither exists.)

### 7.4 D-Bus — don't

**Recommendation: no D-Bus profile ships.** Not the session bus, not the system bus, not a filtering proxy.

The session bus is an RPC surface onto your entire desktop: `org.freedesktop.portal.*` (open arbitrary files with a *user-visible dialog* that a patient agent can win), `org.gnome.Shell.Eval` on some setups, `org.freedesktop.secrets` (your keyring), `org.freedesktop.Notifications`, `org.freedesktop.systemd1` on the user bus (start a transient unit *outside* the sandbox — a complete escape). Filtering it means maintaining an allowlist over an extensible, introspectable, service-defined interface set whose membership changes when you install software. That is a losing maintenance position, and a filtering D-Bus proxy that is 95% correct is a sandbox that is 0% sound.

A coding agent does not need D-Bus. If a specific need appears, the right answer is a purpose-built proxy for that one interface, designed then, with its own threat model — not a general bus hole. Additionally, the private netns already blocks the abstract-socket path to D-Bus for free (§4.1), so `snug` would have to work to open this hole.

### 7.5 GUI, audio and D-Bus — out of scope

An earlier draft of this section specified `wayland` and `x11` profiles as explicit, knowingly-large holes. **That is no longer planned**, and the design is removed rather than left sitting here looking like a roadmap item.

The reasoning is the same as §7.4's for D-Bus, and it generalises: passing a display, audio or bus socket into the sandbox either hands over the protocol wholesale — X11 in particular has no client isolation at all, so any client can keylog and screenshot every other — or requires a filtering proxy for an extensible, service-defined interface set. That is a project in its own right, and a proxy that is 95% correct is a sandbox that is 0% sound.

The private network namespace already excludes all of them by construction, because abstract AF_UNIX sockets are netns-scoped (§4.1). **That is a property to preserve, not a gap to close.** A coding agent does not need a display.

If a concrete need ever appears, it should be designed then, for that one interface, with its own threat model — not anticipated here.

---

## 8. Per-sandbox podman storage

### 8.1 Layout

```
store   = $XDG_DATA_HOME/snug/engines/<key>/storage
runroot = $XDG_RUNTIME_DIR/snug/engines/<key>/rr
socket  = $XDG_RUNTIME_DIR/snug/engines/<key>/...          (private, upstream)

key = <profile-set-hash>-<StoreKey(target)>
StoreKey(p) = strings.TrimPrefix(strings.ReplaceAll(p, "/", "-"), "-")
```

The engine is started as `podman system service --root <store> --runroot <runroot> …`, fully disjoint from the host's rootless podman. **The host's store, images and networks are never touched.**

The store is keyed by **profile set + target**, so: the same project with the same profiles reuses its images (warm start); a different project gets a different store (no cross-project image or volume leakage); and a *more privileged* profile set never inherits a store built under a less privileged one.

*One caveat if the engine ever moves into the sandbox's netns:* [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §3 measured that root-in-userns podman ends up masking `$XDG_RUNTIME_DIR`, so the socket cannot stay under `/run/user/<uid>` on that path.

### 8.2 Lifecycle

The engine is started **lazily**, on the first request that reaches the proxy socket, so a run that never uses containers pays nothing. It runs in its own process group (`Setpgid`) so teardown's group-kill reaps only this engine's tree and never the host's other rootless containers. Teardown: `podman --root … stop`, then group-`SIGTERM`, grace, group-`SIGKILL`, then unlink the sockets. `internal/engine/{lifeline,reaper,reap}.go` own this, and they exist because `conmon` double-forks out of snug's process tree by design.

The store persists on disk. **There is no `snug prune`** — it is described in §11 as a design item and has not been built; stale stores are removed by hand today.

The `runroot` is under `$XDG_RUNTIME_DIR`, i.e. `tmpfs`, so a hard-killed `snug` leaves no stale lock surviving a reboot.

### 8.3 SELinux and runtime

Carried over verbatim, because both were learned the hard way. On an enforcing host the injected bind must be relabelled or the container's `svirt` domain cannot access it: `selinux_relabel` defaults to `z` (shared, one-time, stable), with `Z` (private, new MCS categories every run — measured ~45 µs/file *every* run vs one-time for `z`), `disable`, and `off`. The relabel is carried on every policy-approved bind as a policy-authored `HostConfig.Binds` string (the sole docker-compat carrier for `:z`), and the bind-string builder fails closed on any `:` or `,` in a source or target so no client-bind smuggling surface is opened. `CONTAINER-CLIENT.md` §4.4 records what this looks like from the user's side when it goes wrong.

The OCI runtime is **unpinned** by default — the engine uses whatever `containers.conf` says. The prior "prefer crun, fall back to runc by `PATH` presence" heuristic mis-picked on hosts that ship a `crun` binary podman cannot exec (this dev host: `crun --version` works, `--runtime crun` fails `EINVAL`).

---

## 9. Identity, agent files, environment, and `$HOME`

### 9.1 ssh / git / gh — one pinned identity per profile

`[profile.X.identity]` pins one account. `snug` then:

- runs the filtering ssh-agent proxy (§7.1) and sets `SSH_AUTH_SOCK` to it;
- generates `~/.gitconfig` from a memfd containing `user.name`, `user.email`, and an `insteadOf` rule rewriting `https://github.com/` to `git@github.com:` so pushes go over the pinned key rather than prompting for a token — **and sets `GIT_CONFIG_GLOBAL`**, because git merges its global config from *two* files (`~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`) and generating one of them was not enough;
- generates a private `gh` config directory holding exactly the pinned account and points `GH_CONFIG_DIR` at it — so the env var carries a path, not a token. The staged `hosts.yml` is deliberately **writable**, because `gh` rewrites it on first use and a read-only copy fails with "failed to write config after migration";
- generates `~/.ssh/config` and `~/.ssh/known_hosts` for the pinned host.

Result: inside the sandbox, `gh api user` and `git push` act as exactly that account, and no other identity is reachable. `~/.ssh`, `~/.config/gh`, and `~/.netrc` are never mounted.

**snug also replaces the SYSTEM-WIDE `ssh_config` wherever the host's system-wide `ssh_config` is inside the sandbox** (`policy.SystemSSHConfigPaths`), on every run — identity pinned or not — and the reason is not cosmetic. Only one uid is mapped, so every root-owned file reads as 65534 inside, and OpenSSH refuses a configuration file owned by neither root nor the caller. On a host whose system-wide config lives under the `/usr` bind — openSUSE's `/usr/etc/ssh` — *every* `ssh` inside the sandbox died with `Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf`, `git clone git@github.com:…` included, whether or not `[identity]` was set. The fix is gated on coverage rather than on identity: `@sys` does not grant `/etc/ssh` at all (it enumerates fourteen `/etc` entries and `ssh` is not among them), so on a Debian/Fedora-shaped host the file is not visible inside to begin with and ssh already works — the replacement only fires where a grant actually exposes a host copy at one of those paths. It does not check who owns that copy — owner-gating was considered and rejected, because it would make the emission depend on a mode bit and `--dry-run` host-state-dependent in a way a reader cannot check — so a human profile binding its OWN config at one of those paths is replaced too, disclosed by `replaces:`; their answer is `~/.ssh/config`, which snug does not author unless an identity is pinned. Replacing the file once is the same escape `ssh -F` gives, applied in one place instead of by every caller. `--dry-run` shows it as an `SSH` block plus a `replaces:<profile>` suffix on the FILESYSTEM row when it displaced content a profile's bind supplied at that path.

*Accepted cost:* the host's ssh defaults are dropped inside — on this host, openSUSE's crypto-policy include. The alternative was ssh not running. Revisit if a host turns up where those defaults are load-bearing rather than cosmetic.

*Ask the same question of every other root-owned file the sandbox exposes.* `git` needed `safe.directory = *` for the sibling of this reason, and the next tool with an ownership check will need its own answer.

**The generalisation of all of this — "generate, don't bind, and put the secret in a file rather than the environment" — is a standing rule in CLAUDE.md, and [`SECRETS.md`](SECRETS.md) is where each credential is placed against a severity model.**

### 9.2 `match` — DESIGNED, NOT BUILT

`match = ["~/projects/work/**"]` would auto-select a profile by target path. **No code implements it**; the key is not parsed and nothing consults it. It is kept here because the design is right and the failure mode is the interesting part.

**Recommendation, if it is ever built: keep it, but never let it select a privileged profile, and always print what it chose.**

The failure mode is real and must be written down: **the target path chooses the credentials.** Clone a hostile repository into `~/projects/work/evil` and it is handed your work identity — an ssh signing oracle and a `gh` token — because of where it sits on disk. Nothing about the repository was consulted.

Mitigations the design requires:

1. `match` may not select a profile carrying any privileged grant (§2.7).
2. Auto-selection **always** prints one line before launch: `snug: profile 'work' auto-selected by match '…'; identity gh_user=work, ssh_key=personal.pub…`. Silent credential selection is the actual danger; a visible line makes the mistake self-evident.
3. Exactly one profile may match; two matches is a fatal error rather than a precedence rule.
4. `--profile X` always wins over `match`, and `--no-match` disables it.

### 9.3 Claude Code's files

Read-only, from the host: the CLI itself (`~/.local/bin/claude`, `~/.local/share/claude`), and `~/.claude/skills` + `~/.claude/plugins` re-exposed on top of the `~/.claude` tmpfs so they load and run normally. **Every one of those binds is `optional`**, so on a host that has never run Claude Code the same paths are ordinary writable files on that tmpfs.

`~/.claude/settings.json` is no longer one of those binds — issue #17 moved it to the GENERATED group below. The host's file is a COMMAND TABLE: `hooks` (shell commands on ~34 tool/session lifecycle events), `apiKeyHelper` (a program whose stdout IS an API key), `statusLine`, `env`, `mcpServers`, `enabledPlugins` and `extraKnownMarketplaces` all name a program to run, a credential to print, or code to fetch. A read-only bind stopped the sandbox EDITING that file and SUPPLIED every one of those anyway — the `~/.gitconfig` argument (`GIT-CONFIG.md`), one tool over. snug now reads the host's file as data, keeps an allowlist of scalar preferences that carry no execution (`policy.ClaudeSettingAllowlist` is the list; it is deliberately not counted here, and the injected `~/.claude/CLAUDE.md` enumerates the real names at runtime rather than restating a number that could drift from it), and writes the file the sandbox sees — unconditionally, on every host, whether or not the host has ever run Claude Code. `.claude/design/CLAUDE-SETTINGS.md` has the full key inventory and the residual this does not close: a plugin's own manifest under `~/.claude/plugins` (still bound read-only) carries its own `hooks` block, loaded independently of `settings.json` — see issue #68.

Writable, **staged as a copy**, never bound — one file, and it is the only one that is load-bearing:

```
~/.claude/.credentials.json    mode 0600
```

Writable, **generated**, never copied:

```
~/.claude.json                 mode 0600, at most three keys, no host bytes:
                                 hasCompletedOnboarding = true
                                 autoUpdates            = false
                                 projects.<target>.hasTrustDialogAccepted = true
                                   — ONLY when the host's ~/.claude.json already
                                     records that exact path as trusted

~/.claude/settings.json        mode 0600, an ALLOWLIST of the host's — ten
                                 scalar keys (model, theme, editorMode, verbose,
                                 alwaysThinkingEnabled, autoCompactEnabled,
                                 includeCoAuthoredBy, prefersReducedMotion,
                                 spinnerTipsEnabled, skipWorkflowUsageWarning).
                                 Writable (Claude Code rewrites settings files
                                 at runtime, the `gh` precedent); a private
                                 tmpfs copy, so the rewrite dies with the
                                 session. Unconditional: always present, on
                                 every host, whether or not one has a file to
                                 read from.
```

**The trust key is carried, never asserted.** snug reads the host's file for that
one boolean about the one directory named on the command line, and writes no
`projects` key at all when the answer is no (host file absent, unparseable, or
simply not naming the path — all the same answer, and none of them fails the
run). Matching is exact against the canonicalised target, so a subdirectory of a
trusted target still prompts and a trusted subdirectory does not trust its
parent; both directions fail towards the prompt. Written unconditionally — as it
was for one commit — it removes Claude Code's "Quick safety check" for a fresh
clone of an unfamiliar repository, and measured A/B on a target whose only
content is `.claude/settings.json` with a `SessionStart` hook, the hook then
**fires** at startup with the staged Anthropic OAuth token in the same sandbox.
`SECRETS.md` §3.5 carries the table. Both arms are in `--dry-run`'s `CLAUDE`
block and both are goldened (`internal/cli/testdata/claude-block*.txt`).

The staging list said `~/.claude.json` too, for a milestone, on the justification that "without it Claude re-onboards and shows the login prompt". **Measured false** (claude 2.1.232, issue #19): with the file absent Claude Code connects and works, while removing `.credentials.json` gives "Not logged in · Please run /login" at once. What the file was actually buying is smaller and is not a credential — it suppresses the theme picker and the trust dialog, both of which block on **every** run because `$HOME` is a fresh tmpfs, and the theme picker's answer is written to `~/.claude/settings.json` — itself GENERATED and writable now (issue #17) — so it could not persist across runs either way, for the identical reason `~/.claude.json`'s own answer cannot. Three generated keys buy exactly that. What is no longer handed over is 62 KB of host inventory: every project path on the machine, `oauthAccount` (email, org name and UUID, account UUID), `machineID`, `userID`, `mcpServers`, and the host's per-project `allowedTools`. Two costs, both intended and both stated in the injected `CLAUDE.md`, in `base.toml`'s abuse block and in `--dry-run`'s `CLAUDE` block: MCP servers configured on the host are not configured inside, and a tool approved in a host session is asked again in the sandbox. The generated file is also **unconditional** — it reads nothing from the host, so the sandbox's Claude state no longer varies with the host's.

Staging means the sandbox writes to a private copy on a tmpfs. **This has a real cost, and it is paid rather than mitigated: a token refreshed inside the sandbox does not persist to the host, and nothing copies it back.** There is no sync-back — verified by a fixed-string sweep of the tree for `syncBack`, `SyncBack`, `writeBack` and `WriteBack`, which finds nothing. This paragraph described one for a milestone ("at teardown it compares the staged copy to the host original and, if the sandbox wrote a structurally valid credentials file, copies it back atomically") and no such code was ever written; a design doc describing a mechanism that does not exist is worse than one that omits it, because the reader budgets for a risk nobody is running and stops looking for the one they are. If it is ever built, the structural-validation guard is the design and R4 is the row it belongs in. **`~/.claude.json` would still never be synced back**, and that is now trivially true rather than a rule to enforce: nothing host-derived goes in — one boolean comes *out* of the host's file and no bytes go the other way — so there is nothing to sync out. The reason it must stay that way is unchanged: the file's `mcpServers` slot names programs, and writing it from sandbox-authored bytes would inject a tool that runs *outside* the sandbox on your next host-side session.

Everything else under `~/.claude` (history, projects, sessions, transcripts) stays ephemeral. [`SECRETS.md`](SECRETS.md) §1.1 places each of these on the severity model. The one that was not a file — `@claude` naming `ANTHROPIC_API_KEY` in its `env` list, putting an org key into `/proc/self/environ` — has since been removed; Claude authenticates from the staged credentials file instead.

### 9.4 The injected `~/.claude/CLAUDE.md`

A generated file, delivered read-only from an anonymous memfd (no host temporary file, no race). It is composed at launch from a base plus paragraphs selected by the *actual* resolved policy, so a run whose podman engine failed to start truthfully reads "no engine" rather than advertising one. Content, roughly:

> You are running inside `snug`, an unprivileged sandbox. `$SNUG=1`, hostname `snug`.
>
> **Filesystem.** Only `<target>` is writable and persists. `<target-parent>` is readable. `$HOME`, `/tmp`, `/dev` and `~/.claude` are writable but **ephemeral — they are gone when this session ends**. Put anything meant to survive in the project tree. Everything else is read-only or absent. Secrets (`~/.ssh`, `~/.gnupg`, cloud credentials), personal data, and every other project on this machine are not hidden — they were never mounted. They read as absent. Do not try to reach them; there is nothing there and it wastes your turns.
>
> **Network.** *(when `@net`)* You have internet access. You **cannot** reach services on the host's `127.0.0.1` — this is intentional and is not a misconfiguration. *(when offline)* You have no network. Do not attempt to fetch anything.
>
> **Containers.** *(when wired)* `docker`/`podman` work through a filtering proxy against a sandbox-private engine. Bind mounts of paths this sandbox cannot see are rejected, as are `--privileged`, `--network=host`, and device passthrough. Published container ports are **not** reachable from here; use container-to-container networking. *(when not wired)* There is no container engine.
>
> **Tooling.** Personal skills and plugins are re-exposed read-only — invoke them normally, do not try to edit them. Host `~/.claude` settings, history, prior sessions and MCP server configuration are **not** carried in; do not rely on host-configured MCP tools.
>
> **Identity.** *(when pinned)* git/ssh/gh are scoped to `<gh_user>`. Exactly one ssh key is available for signing; you cannot enumerate or use others.

The point is not politeness. Every sentence here removes a class of wasted turns *and* a class of confusing failure that an agent might otherwise try to "fix" by disabling something.

### 9.5 `~/.config` subsetting

**Recommendation: read-only, and by explicit grant only — never a blanket `~/.config` bind.**

`~/.config` is where applications keep tokens (`~/.config/gh/hosts.yml`, `~/.config/gcloud`, `~/.config/op`, `~/.config/containers/auth.json`), and it is also where a persistence payload goes (`~/.config/autostart`, `~/.config/systemd/user`). A blanket bind is a credential dump and a persistence vector in one.

`snug` ships exactly one `~/.config` grant, in `@git-ro`. Anything else is a line the human writes in their own profile. `~/.config` inside the sandbox is otherwise a **writable tmpfs**, so applications that expect to write there work and their writes evaporate.

### 9.6 Environment variables

**Superseded — [`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md) is the design and the measurement.** It specifies five verbs nested under one `environ` section in a profile — `set`, `merge`, `prepend`, `inherit`, `sanitise` — with `prepend` limited to one value per variable across the selected set. snug authors its own variables and is not bound by the verbs; snug never splits a string on a separator; and the variable type table (separator, and what an empty element means) decides which verb a name admits. There is deliberately no profile for snug's own `PATH` contribution.

The two sentences that belong in an index: `--clearenv` first, then an explicit `--setenv` per variable — the host environment is *discarded*, not filtered, so there is no pattern to get wrong. And `--clearenv` is not the last word, because a bound `/etc` means `/etc/profile.d/*` runs inside any sandbox whose payload is a login shell.

`snug` refuses to let a profile name `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND` or `NODE_OPTIONS` in its `env` list. These are code-injection vectors into every process the sandbox launches. ENVIRONMENT-VARIABLES.md §4.4 records that the check currently fires only when the host happens to set the variable, which makes the *validation* non-deterministic even though the value never gets in.

**A credential must never appear in an `env` list**, whatever the name. `/proc/self/environ` is passively readable by every process in the sandbox and inherited by every child, which is why the rule is "put the secret in a file, not the environment". `TestNoBuiltinPassesASecretThroughTheEnvironment` enforces it by name for every shipped profile.

`snug` sets when wired: `SSH_AUTH_SOCK` (the proxy), `DOCKER_HOST`/`CONTAINER_HOST` (the proxy), `GH_CONFIG_DIR`, `GIT_CONFIG_GLOBAL`.

### 9.7 `$HOME` inside the sandbox

**`$HOME` is the same absolute path as on the host (`/home/u`), and it is an empty tmpfs.**

Same path, because: agent tooling, `git`, `node`, and the project's own config bake absolute paths; the target directory frequently lives under `$HOME` and must keep its identity so that error messages, `git` remotes, and the injected `CLAUDE.md` all agree with what the human sees outside; and stack traces and build caches that leak paths stay comparable.

A tmpfs, because: it must be writable (every tool expects to write dotfiles), and it must not persist (persistence in `$HOME` is the primary agent-escape-into-your-next-session vector — `.bashrc`, `.profile`, `.config/autostart`, `.local/bin` shadowing a command on your `PATH`).

**VERIFIED**: `--tmpfs /home/u` combined with `--remount-ro /` gives a writable `$HOME` on a read-only skeleton, and the ordering (tmpfs at depth 2 emitted before binds at depth 3+) falls out of the depth sort with no special case.

**The writable surface is eight paths, not one.** The target bind is the only one that *persists*; `/tmp`, `$HOME`, `$HOME/.cache`, `$HOME/.config`, `$HOME/.local/state`, `$HOME/.local/share` and `/dev` are all writable tmpfs that die with the sandbox. Say "the only writable thing that persists", never "the only writable thing".

This paragraph also listed `$XDG_RUNTIME_DIR` for a milestone, and **no profile grants it** — measured, the variable is unset inside and `/run/user/$(id -u)` does not exist. Two errors in one sentence, in opposite directions: a real tmpfs missing (`$HOME/.local/share`, added to `@home` in PR #10) and an imaginary one present. Enumerate rather than assert — `VERIFY.md` §3 carries the probe that reads `/proc/self/mounts`.

---

## 10. Go module and package layout

```
snug/
├── go.mod                          module github.com/gomoni/snug
├── Makefile                        build, gate, integration, golden-update
├── VERIFY.md                       the executable by-hand checklist
├── .claude/design/INDEX.md         this document
│
├── cmd/snug/
│   └── main.go                     thin binary entry point; calls cli.Main() and nothing else
│
├── internal/cli/                   everything main.go used to be, importable and testable
│   ├── main.go                     signal trap, run orchestration, os.Exit(code)
│   ├── config.go                   `snug profile list|show|tree|dot`, `snug config`
│   ├── doctor.go                   `snug doctor` host capability report (§4.9)
│   ├── dryrun.go                   `snug --dry-run` renderer (§11.2)
│   ├── identity.go                 pinned identity: generated gitconfig/ssh/gh (§9.1)
│   ├── claude.go                   @claude staging and the injected CLAUDE.md (§9.3, §9.4)
│   ├── container.go                container proxy wiring (§7.2)
│   ├── podmanshim.go               host-escape shim detection + the podman stub
│   └── tmpdir.go                   @tmp-shared host directory (§7.3)
│
├── internal/profile/               TOML profiles: parse, merge layers, lookup precedence
│   ├── file.go                     File/Profile TOML structs; strict decode; checkName
│   ├── builtin.go                  //go:embed profiles/base.toml; adds the @ mark
│   ├── defaults.go                 what a bare `snug <dir>` selects (§2.6)
│   └── profiles/base.toml          THE shipped profile set, with an abuse sentence each
│
├── internal/policy/                THE CORE. Pure. Imports nothing internal.
│   ├── types.go                    Access, Kind, Mount, NetPolicy, Identity, Policy
│   ├── resolve.go                  Resolve(): expand, canonicalise, join, env (§2.2)
│   ├── validate.go                 symlink hazards, masking rules, fail-closed (§3.4)
│   ├── environ.go                  Environ interface — all host lookups, injectable
│   ├── profile.go                  the Profile type the resolver folds
│   ├── bwrap.go                    Policy.BwrapArgs() (§5)
│   ├── net.go                      Policy.PastaArgs(childPID) (§4.5)
│   ├── identity.go                 generated .gitconfig / .ssh/config content (§9.1)
│   └── podmanstub.go               the generated podman stub (CONTAINER-CLIENT.md)
│
├── internal/sandbox/               process lifecycle
│   ├── exec.go                     bwrap exec: fd sweep, safeStdio, --args memfd (§5.5)
│   ├── netns.go                    the fd handshake and pasta supervision (§4.3)
│   └── seccomp.go                  pure-Go BPF assembly -> memfd (§5.4)
│
├── internal/engine/                per-sandbox podman service: start/stop/StoreKey (§8)
├── internal/dockerproxy/           fail-closed HTTP proxy: proxy.go, create.go, build.go (§7.2)
├── internal/sshproxy/              filtering ssh-agent proxy (§7.1)
│
└── test/integration/               real-bwrap behavioural tests, build-tagged (§12.3, §12.4)
```

Golden argv files live beside the code that emits them, in `internal/policy/testdata/*.bwrap.txt`.

Acyclic import DAG: `profile → policy ← {sandbox, engine, dockerproxy, sshproxy} ← cmd`. `policy` imports only the standard library and `golang.org/x/sys`. It is the bottom of the graph precisely so that the anti-drift invariant (§6.1) has exactly one home, and so the security-critical tests run in CI with no privileges.

Dependencies: `github.com/pelletier/go-toml/v2` (strict decode), `github.com/docker/docker` (pinned moby types), `golang.org/x/crypto/ssh/agent`, `golang.org/x/sys`, `golang.org/x/net/bpf`. No cgo.

---

## 11. CLI surface

```
snug [flags] [dir] [-- cmd ...]
```

`dir` defaults to `.`. A bare `snug <dir>` selects the **`defaults` setting** — built-in `@sys @home @cwd-rw @parent-ro` (`internal/profile/defaults.go`), replaced wholesale by `defaults = [...]` in `~/.config/snug/config.toml`. `-p` **adds** to it; `--no-defaults` declines it. There is no `[profile.default]`, because a default selection is a preference and a profile is a grant — one idea, one mechanism. `@net` is not in the list and must not be added: offline is the *absence* of the `@net` profile, so it cannot be re-enabled by accident.

There is no flag that grants less. A read-only project means not selecting `@cwd-rw`: `snug --no-defaults -p @sys -p @home -p @parent-ro <dir>`. Verbose on purpose (§2.5).

**Built today** (`snug --help` is the authority):

| Flag | Meaning |
|---|---|
| `-p, --profile NAME` | Add a profile. Repeatable. Order is irrelevant (§2.2). |
| `--no-defaults` | Decline the `defaults` selection entirely. Start from nothing. |
| `--no-seccomp` | Human-only weakening (§2.3). |
| `--i-know` | Required by `@net-host`. |
| `-n, --dry-run` | Print the resolved policy and the `bwrap` command; start nothing. |
| `-v, --verbose` | Per-decision audit lines from the proxies on stderr. |
| `-h, --help` | |

| Command | Purpose |
|---|---|
| `snug profile list` | Profiles with descriptions. |
| `snug profile show NAME` | The expansion and provenance of every grant. |
| `snug profile tree [NAME…]` / `dot` | Which profiles imply which; the same as a graphviz graph. |
| `snug config` | The effective configuration and where each part came from. |
| `snug doctor` | Host capability report and the fallback matrix as it applies here (§4.9). |

**Designed, not built:** `--config PATH` (§2.7), `--publish PORT`, `--keep-tmp` (§7.3), `--net-strict`, `snug prune` (§8.2), a `--dry-run --json` machine format, and shell completion. Do not cite any of them as existing.

### 11.1 Exit codes

`snug` propagates the payload's exit code verbatim, so `snug ... -- make test` is usable in a pipeline. `snug`'s own failures use `64`–`78` (sysexits-style) to stay distinguishable: `64` usage, `69` a required host capability is unavailable, `70` an internal error, `77` a policy conflict.

### 11.2 `snug --dry-run` — the trust surface

This is not a debugging convenience; **it is the mechanism by which a human can trust `snug` at all.** A sandbox you cannot read is a sandbox you are guessing about. `snug --dry-run` starts no process, binds no socket, and creates no file — and it renders even a policy `Validate` refused, because "why won't it run" is exactly when you need to see it (`TestDryRunShowsARefusedPolicy`).

It prints, in blocks: the **target** and `$HOME` with their access; the **profiles** selected and which arrived via `include`; the **filesystem** — one line per grant, with the provenance profile beside it, annotated by the deepest-mount rule so it cannot claim `(writable)` over a demoted subtree; a **NOT GRANTED** block naming paths a reasonable person would expect and confirming they are absent; the **network** posture, including that host loopback and abstract sockets are unreachable and what would open host→sandbox; **containers**, when wired, including that a container has the sandbox's own network and no port mapping; the **environment**; and finally the exact `pasta` and `bwrap` command lines.

The `NOT GRANTED` block is the only advisory part — it is generated by probing for paths a person would expect rather than derived from the policy — and it is labelled as such. It is also what makes the deny-by-default model *legible* rather than something you take on faith.

**Do not transcribe a sample of this output into a design document.** One lived here for a milestone and drifted into describing flags snug does not pass and files it does not generate. Run the command, or read `internal/policy/testdata/*.bwrap.txt`, which is the reviewed golden and the artifact a security change is judged by.

---

## 12. Testing strategy

### 12.1 Pure unit tests — the resolver (no build tag, runs everywhere)

`internal/policy` has no internal dependencies and injects every host lookup through `Environ`, so all of this runs on any machine including a userns-less CI container:

- **Algebraic laws, property-tested** over generated profile sets: `Resolve` is commutative (`Resolve(shuffle(S)) == Resolve(S)`), idempotent (`Resolve(S ∪ S) == Resolve(S)`), and **monotone** (`Resolve(S) ⊑ Resolve(S ∪ {p})`). The monotonicity property test is the executable form of §2.4 — read §2.4's closing paragraph for what it does *not* prove.
- Join laws per lattice: `Access`, `NetMode`, `PodmanMode`, `publish`, `env`, `path`.
- Conflict detection: same `Guest`, different `Kind`/`Host`/`Perms`/`Content` → error naming both provenances. The corpus of refusals is itself a golden (`testdata/refusals.txt`), so a rule that stops firing shows up as a diff.
- Symlink hazards (§3.3): a grant whose `Guest` resolves inside a read-only bind is rejected at resolve time, not at `bwrap` time. Includes the `podman`-as-symlink regression.
- Emission order: depth-ascending; a shuffled input produces a byte-identical argv.
- Path variables: `{target}`, `{target_parent}`, `{target_ancestor:N}`, `~`, `{home}`.
- Fail-closed: no target, non-directory target, unresolvable target, include cycle, unknown profile, unknown TOML key, a user profile claiming the `@` mark.
- The container proxy decision corpus: privileged/host-namespace rejects, strip-and-inject, volume-driver smuggling, `fromSrc` import, `../` path masquerading, planted-symlink canonicalisation, unknown-field drift, and the build query-string allowlist.

### 12.2 Golden-file argv tests (no build tag)

`internal/policy/testdata/*.bwrap.txt`, one per interesting profile combination, generated against a **fake `Environ`** with a fixed host layout so they are byte-stable across machines. `go test ./internal/policy -update` regenerates; a diff in review is a diff in the sandbox's boundary and is reviewed as such.

Coverage today: the floor (empty selection), `@sys`, `@parent-ro`, the `defaults` set, and `@podman-socket`.

**A `pasta` golden needs a dedicated assertion beyond the diff:** `--map-host-loopback none`, `-T none` and `-U none` must be present in *every* generated `pasta` argv. A test that checks these three flags by name, with a comment pointing at §4.2, is cheap insurance against exactly the regression that shipped last time.

### 12.3 Behavioural sandbox tests (`//go:build integration`)

`test/integration/sandbox_test.go` really runs `bwrap` and asserts observations from inside.

- **Visible:** the target is writable; the parent is readable and not writable; the root skeleton is read-only; `/dev` is writable but neither persists nor escapes.
- **Not visible:** ungranted paths are absent; `..` grants the parent and nothing above.
- **Ordering:** `-p` adds to the defaults rather than replacing them; a shuffled order produces the same sandbox.
- **The demote:** a deeper read-only grant demotes a subpath of the writable target (§2.5) — the test that exists so `TestResolveIsMonotone` is not over-read.
- **Hardening:** seccomp is *installed* (not merely requested), the hardening syscalls are denied, a nested user namespace is refused, threaded programs still work (the `clone3`/`ENOSYS` regression), a directory on stdin cannot escape, and PID 1 carries no host environment.
- **Refusals:** masking by overmount, an unknown profile key, a user profile claiming `@`, repo-local config, the retired `@null` name, and that a refused policy is never executed.

**Every negative test has a positive control.** A leak check once matched `/proc/<pid>/comm` against the literal `"pasta"`; passt ships CPU-dispatched binaries so the real `comm` is `pasta.avx2`, the count was always zero, and `after > before` could never be true. It passed cleanly for as long as it existed. Assert the thing you are measuring is actually present before asserting it did not grow, and make every payload emit a marker so "the sandbox did not reach X" cannot pass on a sandbox that never started.

### 12.4 The network isolation tests — the highest-value tests in the suite

`//go:build integration`. These exist because §4.2 happened.

```
TestHostLoopbackIsUnreachable
  1. bind a TCP listener on the host's 127.0.0.1:<ephemeral> that serves a known token
  2. also bind on [::1]:<ephemeral>
  3. launch a real sandbox with the `@net` profile
  4. from inside: connect to BOTH, over v4 and v6
  5. assert: connection refused / network unreachable, and the token NEVER appears
```

Both families, deliberately: v4 and v6 loopback are closed by different flags. This is the test that fails on the previous generation's flag set. It is behavioural, not argv-based, and it is therefore immune to a `pasta` upstream default change — which is exactly the failure mode that produced the bug.

Companions, all present: `TestOfflineHasOnlyLoopback`, `TestSandboxHasItsOwnWorkingLoopback`, `TestEgressWorks`, `TestAbstractSocketsAreUnreachable` (the netns-scoping property from §4.1, which nothing else covers), `TestSandboxPortsAreNotPublishedByDefault`, `TestPublishedPortsAreReachable`, `TestNetHostIsRefusedWithoutIKnow`, `TestAbortedNetworkNeverRunsThePayload`, and `TestNoLeakedHelpersAfterSIGKILL`.

### 12.5 Live host-integration tests — DESIGNED, NOT BUILT

There is no `live` build tag and no `SNUG_LIVE` gate in the tree. The design, kept because the prior generation's equivalent caught two bugs no unit test could:

- Real `podman` engine start/stop; assert an **empty** container list (proving store disjointness) and a byte-identical host store afterwards.
- A real `docker` CLI inside the sandbox against the proxy, including a **foreground** `docker run` (this is what caught the header-flush deadlock) whose container sees exactly the injected bind with the client's `-v /etc` and `-v $HOME` stripped.
- The ssh-agent proxy against a real `ssh-agent`: `ssh-add -l` shows exactly one key; a sign request for another key fails; `ssh-add -d` fails.
- A real agent launched in a throwaway repository, probing the boundary itself. This is the canonical "prove it works with a real agent" check and the one that finds what a designer did not think to test.

`TestPodmanBuildIsFilteredEndToEnd` in the integration tier covers part of the second bullet today. [`CONTAINER-CLIENT.md`](CONTAINER-CLIENT.md) §2 and §9 are the by-hand equivalent of the rest.

### 12.6 CI

```yaml
# always, everywhere — no privileges needed
- gofmt -l . && go vet ./... && go build ./... && go test ./...   # §12.1, §12.2

# where userns is available
- go test -tags integration ./test/integration/...                # §12.3, §12.4
```

**Running where userns is unavailable.** The pure and golden tiers are the majority of the suite by assertion count and need nothing but a Go toolchain — a deliberate architectural payoff of keeping `internal/policy` dependency-free with an injected `Environ`.

- **GitHub Actions `ubuntu-latest`** permits unprivileged userns, but Ubuntu 24.04+ ships `kernel.apparmor_restrict_unprivileged_userns=1`, which breaks `bwrap`. `doctor` names that exact sysctl in its failure message so the diagnosis is one line rather than an afternoon.
- **Docker-based runners** need `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` and often `--device /dev/net/tun` for `pasta`.
- **A skipped integration tier must be loud.** A green build where the network isolation tests silently skipped is exactly the same failure mode as a silent security downgrade, and gets the same treatment.

---

## 13. Worked example

**Removed, deliberately.** A step-by-step transcript of `snug -p @sys -p @cwd-rw -p @parent-ro -p @net /home/u/proj/sub` lived here, with the full bwrap argv written out by hand. It drifted: it showed `--new-session` unconditionally, generated `/etc/hosts`, `/etc/passwd`, `/etc/group` and `/etc/machine-id` that snug does not generate, and a `PATH` snug does not set. A hand-written transcript of generated output is a second implementation nobody runs.

The live equivalents, in order of authority:

1. `snug --dry-run <dir>` — the actual resolved policy and the actual argv, for your host.
2. `internal/policy/testdata/*.bwrap.txt` — the reviewed goldens, byte-stable against a fake host.
3. `VERIFY.md` — every line a command with its expected output, including the observations the old §13 step 5 listed (siblings absent, `touch` refused on the parent and on `/`, host loopback refused, `/sys` ENOENT).

The *mechanism* the example illustrated — how the netns gets created and configured before a payload exists, and the teardown chain that ends it — is §4.3, which is where it belongs. (The example predates the stage and showed the `--json-status-fd` / `--block-fd` handshake; §4.3 records that as superseded.)

---

## 14. Roadmap

**The [GitHub issues](https://github.com/gomoni/snug/issues) are the live list.** This is the milestone history, kept for orientation.

| | | status |
|---|---|---|
| **M1** | the sandbox: profile loading, the policy model, the bwrap emitter, the fd model, seccomp, `--dry-run`, `doctor`. Offline only, which is a coherent and secure product. | **done** |
| **M2** | networking: the fd handshake, `PastaArgs`, pasta supervision and teardown, generated `resolv.conf`, `@net` / `@net-anon` / `@net-host`. `TestHostLoopbackIsUnreachable` was the acceptance criterion and nothing shipped without it green. | **done** |
| **M3** | identity and agent files: the ssh-agent proxy, `[identity]`, generated gitconfig/ssh config/known_hosts, scoped `gh`, `@claude` with staged credentials and the injected `CLAUDE.md`. | **done** |
| **M4** | containers: per-sandbox engine and store, the filtering proxy, SELinux relabel, `@podman-socket`. | **done**, with the engine on the host's network — [`ENGINE-NETNS.md`](ENGINE-NETNS.md) |
| **M5** | `podman build`: a default-deny allowlist over the build endpoint's query string, `@podman-build`. | **done** |
| **M6** | hardening and ergonomics: `--bind-fd`/`openat2(RESOLVE_BENEATH)` for the resolve→mount TOCTOU (§3.3); `clone3` via `SECCOMP_RET_USER_NOTIF`; `snug prune`; shell completion; `--dry-run --json`; `--net-strict`. | open |

The named work in flight is tracked as issues, with a design document each: the environment ([`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md)), secrets ([`SECRETS.md`](SECRETS.md)), the engine netns ([`ENGINE-NETNS.md`](ENGINE-NETNS.md)), and the pseudo-filesystem recommendations ([`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md)).

---

## 15. Risks and open questions

The issues carry the *known gaps with severities*; this is the list of things that are structural rather than fixable.

- **R1 — Kernel is the boundary, and it is a big boundary.** Every guarantee here rests on user namespaces, seccomp, and `bwrap`. A userns LPE ends the discussion. Stated in §1.2; restated here because it is the risk that matters most and the one most easily forgotten after reading several thousand words about mount ordering.
- **R2 — Helper defaults change under us.** §4.2 is a lived example. Mitigation: pass every security-relevant flag explicitly, and assert *behaviour* in integration tests rather than reading man pages. Residual risk: a flag `snug` does not know about is added with an unsafe default.
- **R3 — The proxy's strict decode is brittle by design.** A newer `docker` client sending a new benign field gets a 403. Deliberate (it is the drift guard), but it will generate confused bug reports. Mitigation: the rejection message names the unknown field and says "this is fail-closed".
- **R4 — Credential sync-back does not exist, and this row described it as shipped for a milestone.** Swept for as fixed strings (`syncBack`, `SyncBack`, `writeBack`, `WriteBack`): no such code, in `internal/cli` or anywhere else. So there is **no host-write channel from inside** today, and the residual is the opposite one: a token refreshed in the sandbox is silently lost when it exits. If sync-back is built, the scope is one file, `~/.claude/.credentials.json`, and structural validation is the guard that makes the risk arguable — at which point this row becomes true and the risk becomes real. The sensitive-by-configuration file, `~/.claude.json`, is not *staged* at all: it is generated (issue #19), reading exactly one boolean out of the host's copy and no bytes into the sandbox, so "it never syncs back" is a property rather than a rule to enforce.
- **R5 — Ubuntu/AppArmor userns restrictions and Docker-based CI** will make `snug` unusable for some users out of the box. Mitigated by `doctor` naming the exact sysctl, not by working around it.
- **R6 — The curated `/etc` list is a maintenance obligation** (§5.3). Two entries were found by breakage rather than by reading, and there will be more. The failure mode is legible but unhelpful (`MODULE_INITIALIZATION_ERROR`), which is why the test command is written next to the list.
- **R7 — Moving the engine into the sandbox's netns requires subuid and cgroup delegation** that some corporate images and CI runners do not have, and is defeated outright by a host-escape `podman` shim. Measured in [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §3. `snug` must refuse rather than degrade, because the difference is invisible to the user.
- **R8 — `--remount-ro /` interacts with anything that expects to create top-level directories.** Some build systems do. The failure is legible (`Read-only file system` on a path the human can see in `--dry-run`) and the fix is a one-line profile grant, but it will be hit.
- **R9 — The fingerprinting surface is larger than any OCI runtime's default** ([`PSEUDOFS-AUDIT.md`](PSEUDOFS-AUDIT.md)). No escape, but `boot_id`, `uptime`/`btime` and the PCI/sound topology all identify the host, and the time namespace is not unshared.

**Open questions**, each a decision that real use is most likely to reverse:

- **Q1 — Should `publish` gain an `auto` form after all?** §4.6 argues no, on the principle that the agent should not author a host-visible surface. One shipped once and was removed; this is the most likely decision to be revisited.
- **Q2 — Credential sync-back scope.** Should it extend beyond Claude's credentials to, say, a `gh` token refresh? Current answer: no, add cases only with a demonstrated need and a structural validator each time. [`SECRETS.md`](SECRETS.md) §5 is where this is settled.
- **Q3 — Multiple simultaneous sandboxes on the same target.** Two `snug` runs against the same directory both get write access and will fight. `bwrap` has a `--lock-file`. Leaning: warn by default, `--exclusive` to refuse.
- **Q4 — The 32-bit compat arch** is a documented seccomp gap (§5.4). Closing it needs `SECCOMP_RET_USER_NOTIF` and a supervisor thread. Worth it, or is the namespace boundary sufficient?
- **Q5 — `bwrap` PR #766 (`--netns FD`)** would let `bwrap` *join* a preexisting netns. It changes nothing for the topology snug uses today but would simplify the engine-in-netns work considerably by removing an `unshare(1)` sandwich. Watch item, not a dependency.
- **Q6 — Does the sandbox need `/sys/fs/cgroup` for parallelism detection?** Currently no `/sys` at all. If build tools misdetect badly, a narrow `ro = ["/sys/fs/cgroup"]` profile is the minimal answer — but `/sys` is a recurring escape surface and any grant here deserves its own review.
- **Q7 — Should `snug --dry-run` be able to *diff* two profile sets?** `--diff @sys+@cwd-rw @sys+@cwd-rw+@podman-socket` printing only the added grants would make "what does this profile actually cost me" a one-command question.

---

## 16. Where to start implementing

**Removed.** This section opened "Nothing exists in the `snug` repository yet beyond `CLAUDE.md` and this document" and gave a five-step build order. All five steps are done; M1–M5 shipped. The orientation it provided now lives in three places that stay true: §10 for the package layout, `CLAUDE.md` for the invariants and the agent roster, and the issue list for what is actually next.
