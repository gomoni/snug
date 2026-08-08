# snug — Design

> *snug*: fitting closely and comfortably · marked by cordiality and secure privacy · offering safe concealment · a small private room in a pub

`snug` is an unprivileged sandbox launcher for untrusted code: a build you did not write, a dependency's install hook, a test suite from a freshly cloned repository, an AI agent. It is a single Go binary that reads a policy, generates a `bubblewrap` command line and (when networking is requested) a `pasta` command line, wires up a small number of tightly-controlled host-integration helpers, runs the payload, and tears everything down.

The model is general: everything below applies equally to `snug ~/src/proj -- make test`. Where this document says "the agent", read "the sandboxed process". An AI agent is simply the sharpest instance of the problem, because it is *supposed* to run arbitrary commands — so "do not run untrusted code" is not available as advice — but a dependency's postinstall script is untrusted in exactly the same way and gets exactly the same boundary.

**Status of this document:** every kernel/tool behaviour asserted here was verified by execution on the development host (openSUSE, kernel 7.1.4, `bubblewrap 0.11.2`, `pasta 20260612`, running *inside* a rootless-podman `distrobox` container). Findings that contradict documentation or prior implementations are flagged with **VERIFIED**.

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
- **G3** The sandbox **cannot reach the host's loopback**. This is a hard requirement, not a nice-to-have (§4.1).
- **G4** Internet egress works by default when a `@net` profile is selected; fully-offline is the *absence* of that profile, so it is trivially achievable and cannot be accidentally re-enabled.
- **G5** Works inside `distrobox`/containers with nested user namespaces. Where a capability is genuinely missing, `snug` **fails loudly with a diagnosis**, and never silently downgrades its security posture.
- **G6** Host integration (ssh signing, container engine, tmp sharing) is possible but goes through *filtering proxies* that `snug` owns, never through raw socket passthrough.
- **G7** Total transparency: `snug --dry-run` prints the resolved policy and the exact `bwrap` and `pasta` argv. If you cannot read what it is going to do, you cannot trust it.

### 1.2 Non-goals

- **N1** `snug` is **not** a defence against kernel 0-days. It hands the agent a `write(2)` on a real kernel. A user-namespace or netlink or io_uring LPE defeats it completely, and nothing in this design pretends otherwise.
- **N2** `snug` is **not** a defence against a determined human attacker with a shell. It bounds the blast radius of software; a human with time will find the seam.
- **N3** `snug` is **not** a multi-tenant boundary. Everything runs as your uid. The sandbox and the host share a uid, so anything that escapes has your full authority. Use a VM if you need a real boundary.
- **N4** `snug` does not attempt to constrain *what* the agent does with the authority you grant it. If you grant `ssh-agent` signing for a key, the agent can push anything to anywhere that key can reach. Scoping bounds the identity, not the actions.
- **N5** No side-channel / covert-channel resistance. Timing, `/proc/cpuinfo`, and shared page cache are all visible.
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
| Credentials outside the grant set (`~/.ssh`, `~/.aws`, `~/.gnupg`, browser profiles, keyrings) | Never mounted. Not masked — *absent*. |
| Other projects on the same machine | Never mounted (§3). |
| Host services on `127.0.0.1` / `::1` | Private netns + `pasta` with loopback forwarding explicitly disabled (§4). |
| Host desktop session (X11 keylogging, Wayland, D-Bus, abstract AF_UNIX) | Not mounted; abstract sockets are additionally netns-scoped (§4.2). |
| Host container engine as an escape vector | Filtering proxy; the engine never sees a raw client request (§7.2). |
| Host persistence (`~/.bashrc`, systemd user units, cron, `~/.config/autostart`) | Not writable. `$HOME` is an ephemeral tmpfs (§8.4). |
| SSH identity | Filtering agent proxy exposing exactly one key, no key material in the sandbox (§7.1). |

**What `snug` does not defend:** everything in §1.2. Additionally: the project directory is writable by definition, so an agent can always poison the code it is working on — review your diffs.

---

## 2. The policy model

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
    KindOverlay             // read-only lower + invisible tmpfs upper (--overlay-src/--tmp-overlay)
)

// ── Mount: one grant. Guest is the primary key. ──────────────────────────────
type Mount struct {
    Guest    string   // absolute, lexically-clean sandbox path — THE KEY
    Kind     Kind
    Host     string   // KindBind/KindOverlay: canonical host path. KindSymlink: link target.
    Access   Access
    Optional bool     // -try semantics: silently skip when Host is absent
    Perms    *uint32  // KindData/KindTmpfs only
    Content  []byte   // KindData only; materialised into a memfd at emit time
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

type NetPolicy struct {
    Mode        NetMode
    PublishAuto bool   // pasta -t 127.0.0.1/auto : host loopback sees every port the sandbox binds
    Publish     []int  // pasta -t 127.0.0.1/<ports> : host loopback sees exactly these
    DNS         bool   // install pasta --dns-forward + a generated /etc/resolv.conf
    Address     string // optional pasta -a: give the sandbox a synthetic address instead of the host's
    MTU         int    // 0 = pasta default (65520)
    Hostname    string
}

// ── Identity (vocabulary inherited from agent-sandbox, §9) ───────────────────
type SSHMode string

const (
    SSHAgentProxy SSHMode = "agent-proxy" // RECOMMENDED: filter the host agent to one key
    SSHAgentOwn   SSHMode = "agent"       // private one-key agent; prompts for the passphrase once
    SSHKeyFile    SSHMode = "key-file"    // stage the encrypted private key in. Weakest.
    SSHHostAgent  SSHMode = "host-agent"  // forward the WHOLE host agent. Discouraged.
    SSHNone       SSHMode = "none"
)

type Identity struct {
    GhUser, GhHost      string
    GitName, GitEmail   string
    SSHKey              string // path to the PUBLIC key that pins the identity
    SSHMode             SSHMode
}

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
6. **Union the env allowlist**; conflicting explicit `setenv` values are an ERROR.
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

`network = "isolated"` is therefore a no-op, and there is deliberately no `network = "offline"`. **Offline is the absence of the `@net` profile.** If you write `include = ["@net", "@net-offline"]`, the result is `@net` — and that is correct, not a bug: you asked for the union of two grant sets, one of which was empty. To be offline, do not include `@net`. `snug --dry-run` states this in plain words when it detects the pattern.

### 2.4 Monotonicity by construction — the actual argument

Three properties together make "a profile can never tighten the sandbox" a *structural* fact rather than a review convention:

1. **The base is empty, and the emitter has no removal operation.** `snug`'s bwrap emitter can produce `--bind`, `--ro-bind`, `--dev-bind`, `--tmpfs`, `--symlink`, `--proc`, `--dev`, `--file`, `--ro-bind-data`, `--dir`, `--overlay-src`, `--tmp-overlay`, `--setenv`. There is no `--mask`, no deny path, no "hide" verb, because nothing needs hiding — **VERIFIED**: `bwrap`'s new root is a fresh, empty tmpfs. With `--ro-bind /usr /usr` and a bind of one project directory, `ls /home/michal/projects` lists exactly `plainsof` and nothing else, with no `--tmpfs` anywhere in the command line. Siblings are invisible because they were never mounted.
2. **The grant language cannot express negation.** TOML keys are `ro`, `rw`, `dev`, `tmpfs`, `env`, `publish`, `include`. There is no `mask`, no `hide`, no `deny`, no `remove`, no `!`-prefix, no `unset`. This is enforced by strict decoding: unknown keys are a fatal parse error, so a future key cannot be smuggled in by a config written for a different tool.
3. **Resolution is a join over semilattices.** For any profile sets *A* and *B*, `Resolve(A ∪ B) ⊒ Resolve(A)` and `⊒ Resolve(B)` — the result is above both in the grant lattice. Adding a profile can only move you up.

The one place order matters is *emission*, and emission order is computed from the resolved set by a deterministic sort (§3.2), not from the order profiles were named. So the argv is a pure function of the resolved policy.

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

**Do not read `TestResolveIsMonotone` as proving more than it does.** It compares `Access` per existing `Guest` key, and a deeper key did not exist in the base policy, so it cannot see this at all. `TestDeeperGrantOverridesShallowerAccess` pins the scope explicitly — it exists to stop the first test being over-read.

### 2.6 Profile file format: TOML

There is deliberately no `[profile.null]`. It was tried and removed (MVY0): a
profile that grants nothing is a preference wearing a profile's clothes, and it
is unreachable by its own documented purpose besides — `-p` only ever ADDS to
`defaults`, so `-p @null` cannot subtract them, and cannot show "the true empty
base" it claimed to. The floor of the lattice does not need a name in this file;
it is what `Resolve` returns for an empty selection, and it is reachable
directly with `snug --no-defaults --dry-run <dir>`.

```toml
# ── the OS runtime ──
[profile.sys]
description = "Read-only OS runtime: /usr, /etc, CA trust, usr-merge symlinks."
ro = [
  "/usr",
  "/etc",                       # see §5.3 for why whole-/etc is the right call
  "/var/lib/ca-certificates",   # SUSE
  "/usr/share/ca-certificates", # Debian
  "/etc/pki",                   # Fedora/RHEL
  "/opt",
]
optional = ["/var/lib/ca-certificates", "/usr/share/ca-certificates", "/etc/pki", "/opt"]
symlink = [
  { at = "/bin",   target = "usr/bin"   },
  { at = "/sbin",  target = "usr/sbin"  },
  { at = "/lib",   target = "usr/lib"   },
  { at = "/lib64", target = "usr/lib64" },
]

# ── an ephemeral, writable HOME ──
[profile.home]
description = "$HOME is an empty tmpfs at the same path as on the host. Ephemeral."
tmpfs = ["{home}", "{home}/.cache", "{home}/.config", "{home}/.local/state"]

# ── the project ──
[profile.cwd-rw]
description = "The target directory is writable and persists."
include = ["home"]
rw = ["{target}"]

[profile.parent-ro]
description = """
The target's PARENT is readable. Everything else under every higher ancestor stays
invisible — not because it is hidden, but because it is never granted."""
ro = ["{target_parent}"]

# ── shared tmp ──
[profile.tmp-shared]
description = "A per-sandbox subdirectory of the host /tmp appears as the sandbox's /tmp."
rw = ["{host_tmpdir}:/tmp"]     # "host:guest" form; {host_tmpdir} is allocated by snug

# ── networking (§4) ──
[profile.net]
description = "Private netns with internet egress via pasta. Host loopback unreachable."
network = "egress"
dns = true

[profile.net-publish]
description = "As `@net`, plus: ports the sandbox binds become reachable on the HOST's 127.0.0.1."
include = ["net"]
publish_auto = true

[profile.net-host]
description = """
DANGEROUS. Shares the HOST network namespace. The sandbox can reach every service on
127.0.0.1 and every abstract AF_UNIX socket, including X11 and D-Bus. Requires --i-know."""
network = "host"

# ── containers (§7.2, §8) ──
[profile.podman-socket]
description = "A filtering Docker/Podman HTTP proxy over a per-sandbox engine + storage."
podman = "socket"

[profile.podman-build]
description = "As podman-socket, plus a constrained /build endpoint."
include = ["podman-socket"]
podman = "build"

# ── agents ──
[profile.claude]
description = "Claude Code: binary + skills + plugins RO, credentials RW, injected CLAUDE.md."
include = ["sys", "home"]
ro = [
  "{home}/.local/bin/claude",
  "{home}/.local/share/claude",
  "{home}/.claude/settings.json",
  "{home}/.claude/skills",
  "{home}/.claude/plugins",
]
optional = ["{home}/.claude/skills", "{home}/.claude/plugins"]
claude_credentials = true       # snug stages ~/.claude/.credentials.json + ~/.claude.json RW (§9.3)
claude_notice      = true       # snug injects a generated ~/.claude/CLAUDE.md (§9.4)
env = ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "EDITOR", "VISUAL", "PAGER", "NO_COLOR"]

[profile.git-ro]
ro = ["{home}/.config/git", "{home}/.gitconfig"]
optional = ["{home}/.config/git", "{home}/.gitconfig"]

# ── what a bare `snug <dir>` selects ──
# NOT a profile. It is the `defaults` setting in ~/.config/snug/config.toml,
# because a default SELECTION is a preference and not a grant:
#
#   defaults = ["@sys", "@home", "@cwd-rw", "@parent-ro"]
#
# Built-in value in internal/profile/defaults.go; setting it replaces that list
# wholesale. `-p` adds to whatever it resolved to, `--no-defaults` declines it.

# ── identity scoping (§9.1) ──
[profile.plainsof]
include = ["@net", "@claude", "@git-ro"]
match   = ["~/projects/plainsof/**"]
  [profile.plainsof.identity]
  gh_user   = "plainsof"
  git_name  = "Michal Vyskocil"
  git_email = "michal.vyskocil@plainsof.com"
  ssh_key   = "~/.ssh/key3_vyskocilme_id_ed25519.pub"
  ssh_mode  = "agent-proxy"
```

**Names are written bare here and published with a leading `@`.** `[profile.sys]` above is `@sys` everywhere a human meets it — on the command line, in `--dry-run` provenance, in `$SNUG_PROFILES`. The mark means *snug ships this*, and it is added by `profile.builtins()` when the embedded file is loaded rather than written into the file. `checkName` refuses a leading `@` in **every** file it parses, this one included, so the mark is unforgeable in both directions: a builtin cannot miss it, a profile in `~/.config/snug/profiles.d` cannot claim it.

Two things follow.

- **Provenance is legible without a lookup.** Every place a profile name is rendered is a place where "is this snug's grant or one this host defined?" is the question being asked, and the bare name could not answer it.
- **The two namespaces cannot collide,** which retires a rule rather than adding one. "A config file must not redefine a builtin" was previously enforced by the merge check; now a user file saying `[profile.sys]` defines a profile of *theirs*, and `@sys` is untouched. The merge check remains for collisions between the layers below (a site profile against a user one), where a hard error is still right. This matters most where §2.7's gate is weakest — `$XDG_CONFIG_HOME` is trusted unconditionally today, and a `profiles.d` loaded from the wrong place still cannot impersonate `@sys`.

`include` inside a builtin is rewritten along with the names, so a builtin can only ever include another builtin. That is not a restriction being imposed — it is compiled in and cannot know a user's names — but it is a rule rather than an accident, and `profile.mark` says so.

**Why TOML** (decided by the owner; recorded for the record): it is what the previous generation converged on, `github.com/pelletier/go-toml/v2` supports `DisallowUnknownFields()` which is load-bearing for fail-closed parsing, and profiles are flat name→grant-list tables with no need for expressions. A programmable format (Starlark/HCL) would be strictly worse here: computation in a profile is exactly the thing that would make monotonicity un-provable by inspection.

**`include` stays monotone** because it is expanded into a *set* before folding, and because every key it can carry has a permissive-ward join. `include` has no "override" or "exclude" counterpart. A profile can only ever be `⊒` the union of what it includes.

### 2.7 Profile lookup precedence — and why repo-local config is never auto-loaded

Profiles are loaded from, in order (all layers merged; **later layers may only add new profile names, never redefine an existing one — a redefinition is a fatal error**):

1. **Embedded builtins** — compiled into the binary, and the only profiles that carry the `@` mark (§2.6). `@sys`, `@home`, `@cwd-rw`, `@parent-ro`, `@tmp-shared`, `@net`, `@net-publish`, `@net-host`, `@podman-socket`, `@podman-build`, `@claude`, `@git-ro`. Always present, and unshadowable by construction rather than by check: no later layer can spell an `@` name at all. There is deliberately no `default` among them, and no `null` either (MVY0): what a bare `snug <dir>` selects is the `defaults` *setting* (§11), not a grant, and the lattice floor is what `Resolve` returns for an empty selection rather than something a profile has to name.
2. **`/etc/snug/profiles.d/*.toml`** — site/admin profiles.
3. **`$XDG_CONFIG_HOME/snug/profiles.d/*.toml`** (default `~/.config/snug/profiles.d/`) — the user's own profiles. **This is the trusted layer.**

**There is no fourth layer.** `snug` **never** auto-loads `./.snug/`, `./snug.toml`, or anything else from inside or beside the target directory.

The prior generation stated the reason in a comment and it is correct: repo-local config is a persistence-attack vector. Under `snug`'s threat model (T2/T4) it is worse than that — it is a *complete* defeat. A hostile repository that ships `.snug/profiles.toml` redefining a profile the user's `defaults` already select — `[profile.cwd-rw] ro = ["/"]` — would grant itself read of the entire host on the very first `snug ~/src/hostile-repo`. The material inside the sandbox must never be able to author the sandbox's boundary.

This is a monotonicity-adjacent property, and worth naming: **the trusted profile set must originate outside the material being sandboxed.** Monotonicity guarantees that composing profiles cannot tighten; it says nothing about *who gets to compose*. Both are needed.

Repo-local profiles are still usable, but only by deliberate human act:

```
snug --config ./snug.toml ~/src/proj          # explicit path
SNUG_CONFIG=./snug.toml snug ~/src/proj       # explicit env
```

**Recommendation on dangerous grants from an explicitly-named config: restrict them.** An explicitly-loaded config file is a *convenience*, not a full trust promotion — the human typed one word (`--config ./snug.toml`) and cannot be expected to have audited a 200-line TOML file that a `git pull` may have changed since they last looked. `snug` therefore classifies four grant classes as **privileged**:

- `network = "host"`
- `podman = "socket"` / `"build"`
- any `rw`/`ro`/`dev` grant whose canonical path escapes `{target}`'s ancestor chain and is not under `/usr`, `/etc`, or `/opt`

A privileged grant appearing in a non-trusted-layer config is a **fatal error** naming the file, the profile, and the grant. To use it, the human must move that profile into `~/.config/snug/profiles.d/`, which is an act of the human on the human's own machine, outside any repository. `--allow-privileged-config` exists as a one-shot escape hatch and prints a loud warning; it is not settable from a file.

---

## 3. Path and mount algebra

### 3.1 "access .." is subtraction-free

The requirement — *for `snug /some/other/project/sub`: `/some/other/project` readable, `sub` writable, and everything else under `/some` and `/some/other` invisible* — is achieved by granting nothing else.

**VERIFIED.** With this argv and no hiding operation whatsoever:

```
bwrap --unshare-all \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib64 /lib64 --symlink usr/lib /lib \
  --proc /proc --dev /dev \
  --ro-bind /home/michal/projects/plainsof/cv /home/michal/projects/plainsof/cv \
  --bind    /home/michal/projects/plainsof/cv/snug /home/michal/projects/plainsof/cv/snug \
  -- /bin/sh
```

the sandbox observes:

```
/                              -> bin dev home lib lib64 proc usr
/home                          -> michal
/home/michal                   -> projects
/home/michal/projects          -> plainsof            # 12 other projects invisible
/home/michal/projects/plainsof -> cv                  # 6 siblings invisible
```

`bwrap` auto-creates every intermediate mountpoint inside its root tmpfs. Those skeleton directories are the *only* thing that exists at each ancestor level. This is why `@parent-ro` is one line of TOML.

Two refinements `snug` applies:

- **`--remount-ro /` as the final filesystem operation.** **VERIFIED**: the root tmpfs and its auto-created skeleton directories are writable by default; `--remount-ro /` makes them read-only and is explicitly non-recursive, so `/tmp`, `$HOME`, and the project bind keep their own flags. Result: `touch /ZZ` and `touch /home/michal/ZZ` fail; `/tmp`, `$HOME` and the project remain writable. Without it, an agent can litter a shadow filesystem that looks real and confuses it. Cheap, and it makes "writable places are exactly the explicit grants" literally true.
- **Explicit skeleton permissions.** `bwrap` creates auto-mountpoint parents as `0700` (**VERIFIED**: `/home/michal/projects/plainsof` came out `drwx------`). That is fine when the sandbox uid owns them, but `snug` emits `--perms 0755 --dir <path>` for every ancestor it can predict, so the tree is traversable regardless of `--uid`/`--gid` choices.

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

**VERIFIED**: generated files mount cleanly *on top of* a read-only bind — `--ro-bind /etc /etc` followed by `--ro-bind-data 7 /etc/resolv.conf` and `--ro-bind-data 8 /etc/passwd` produces the generated content, while `/etc` itself stays read-only. Mounting over a path inside a read-only bind does not require write access to the underlying filesystem, because `bwrap` performs the mount in its own mount namespace before dropping into the payload.

### 3.3 Symlink resolution

Two distinct problems, two distinct rules.

**Host-side (the `Host` field).** Every host path is canonicalised with `filepath.EvalSymlinks` at resolve time. `snug` binds the *realpath* but mounts it at the *requested guest path*. This means `~/projects` being a symlink to `/data/projects` works, and it means a symlink planted inside the writable project cannot later be used to widen a grant, because grants were canonicalised before the sandbox ever started. The residual TOCTOU (host path replaced between resolve and mount) is documented and accepted: closing it requires `openat2(RESOLVE_BENEATH)` plumbing through `--bind-fd`, which is a possible M6 hardening (`bwrap` has `--bind-fd FD DEST` and `--ro-bind-fd FD DEST` for exactly this).

**Guest-side (the `Guest` field).** This is where the prior generation lost a day. Its `podman-shim` bind at `/usr/bin/podman` aborted the whole sandbox with `bwrap: Can't create file at /usr/bin/podman: No such file or directory`, because on that host `/usr/bin/podman` was a symlink and **`bwrap` cannot create a mountpoint at a symlink destination**. Generalised, the hazard is: `snug` emits `--symlink usr/bin /bin`, then a later grant asks to bind something at `/bin/tool`; that path now resolves *through* our own symlink into the read-only `/usr` bind, and the mount fails or, worse, lands somewhere unintended.

`snug`'s rule, enforced in `Validate()` before any argv is emitted:

1. Build the sandbox's *own* symlink map from the resolved `KindSymlink` grants.
2. Resolve each `Guest` path through that map (plus the host's realpath for guest paths that alias host paths).
3. **Reject** any grant whose resolved `Guest` lands strictly inside another grant that is `AccessRO` and `KindBind` — with an error naming both grants and both provenances.
4. **Rewrite** any grant whose `Guest` traverses a `snug`-created symlink to its resolved form, and re-run the depth sort.

This turns a runtime `bwrap` abort into a resolve-time error with a readable message, and it is directly unit-testable against a fake `Environ`.

### 3.4 Validation

Before emitting anything, `Validate()` checks:

- Every `Guest` is absolute and lexically clean; no `.`, `..`, or empty components survive.
- No `Guest` is `/` with `KindBind` unless the `unsafe-root` builtin is selected (which does not ship).
- The target directory exists, is a directory, and its canonical path is granted `AccessRW`. **Fail closed** — no target means no policy, never a permissive default.
- Symlink hazards (§3.3).
- At least one of `/usr` or `/bin` is granted, otherwise nothing can execute — reported as *"no runtime granted; add the `@sys` profile"* rather than a confusing `exec: no such file`.
- `Podman != PodmanOff` implies a topology that can host an engine (§4.4, §8).
- **RULE 4** — nothing but `snug` may put a node at `/proc` or `/dev` (below).
- **RULE 2** — nesting, judged on the outer mount (below).

`Validate` is the *only* refuser, which is what lets `--dry-run` render a policy it would not run (`Resolve` returns `(p, err)` for a validation failure and `(nil, err)` for everything else). It is also run **a second time**, in `cmd/snug`, after the staging layer has added the mounts that had to be created on the host first: the staged Claude credentials, the generated `gh` `hosts.yml`, the ssh-agent and container proxy sockets. Those are added after `Resolve` returned, so without the second pass they were never validated at all.

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
2. **An integration test asserts the *behaviour*, not the argv.** `TestHostLoopbackUnreachable` starts a listener on the host's `127.0.0.1`, launches a real sandbox, and asserts the connection is refused (§12.4). Golden-argv tests would have passed on the buggy configuration; only a behavioural test catches a changed upstream default. This test is the single highest-value test in the suite.

### 4.3 Process topology, ordering, and lifetime

Two candidate topologies:

**(a) `pasta` creates the netns and spawns `bwrap` inside it.** `pasta [OPTS] -- bwrap --unshare-all --share-net ...`.
**VERIFIED** that `pasta`'s command mode creates user + mount + ipc + pid + uts + net namespaces and maps your uid to 0 (`uid_map: 0 1000 1`). That is the problem: `pasta` has already built a user namespace with exactly **one** uid mapped, so `bwrap`'s nested `--unshare-user` inside it can only map that one uid, and any later need for a subuid range (podman) is dead on arrival. It also puts a process `snug` does not control at the root of the tree, and `pasta` is not designed to be an init.

**(b) `bwrap` creates the netns; `pasta` joins it. ← CHOSEN as the default topology.**

```
snug                                        (host userns, host netns, host mount ns)
├── bwrap --unshare-all --die-with-parent \
│         --json-status-fd J --block-fd B ... -- <agent>
│      └── the sandbox: own userns, netns, pidns, ipcns, utsns, mountns
└── pasta --netns /proc/<child-pid>/ns/net --userns /proc/<child-pid>/ns/user \
           --config-net ...                 (host netns on the socket side; tap side in N)
```

**VERIFIED end to end**, inside a distrobox container: `bwrap --json-status-fd 9` emits a single-line JSON document `{ "child-pid": 59817, ... }`; `pasta --netns /proc/59817/ns/net --userns /proc/59817/ns/user --config-net ...` attaches with rc=0; the sandbox then has a configured interface, working DNS, `curl https://example.com → 200`, and `127.0.0.1:631` / `127.0.0.1:3100` / `[::1]:3100` all refused.

**Why (b):**

- `bwrap` owns the namespace set. One tool, one mental model, one set of flags to audit. `snug` does not need `unshare(1)` on `PATH` at all in the default path.
- No subuid delegation required. `bwrap`'s single-uid map is all the default path needs, which matters for constraint 3 (distrobox, CI, locked-down hosts where `/etc/subuid` is not delegated).
- `pasta` is a *leaf* of the process tree, not its root. It can die, be restarted, or be absent without restructuring anything.
- The netns is referenced only as `/proc/<pid>/ns/net` — never bind-mounted to a filesystem path. When the last process in it exits, the kernel destroys it. **Orphan netns leaks are impossible by construction**, because no persistent reference is ever created. (This is the difference from `ip netns add`, which bind-mounts under `/run/netns` and leaks exactly this way.)

**The ordering handshake.** `bwrap` must create the netns before `pasta` can join, but the payload must not run before `pasta` has attached — otherwise the agent's first `curl` races the tap device. `bwrap` provides both halves:

1. `snug` creates two pipes and starts `bwrap` with `--json-status-fd J --block-fd B`.
2. `bwrap` sets up namespaces, writes `{"child-pid": N, ...}` to `J`, and then **blocks on `B`** before executing the payload.
3. `snug` reads `N`, starts `pasta` with `--netns /proc/N/ns/net --userns /proc/N/ns/user`, and polls `/proc/N/net/dev` until a device other than `lo` appears (readable across the netns boundary from `snug`, same uid, same owning userns).
4. `snug` writes one byte to `B`. The payload runs, with the network already up.

Failure at any step before (4) means `snug` closes `B` unwritten and kills `bwrap`. The payload **never executes**. There is no window in which the agent runs with a half-configured network, and no possibility of running with the host netns.

**Teardown and lifetime chain.**

| Event | What happens |
|---|---|
| Agent exits normally | `bwrap` exits → `snug`'s `Wait` returns → `snug` `SIGTERM`s `pasta` (2s grace, then `SIGKILL`) → netns refcount hits zero → kernel reaps it. |
| Agent segfaults / is killed | Identical. `bwrap`'s reaper collects the payload, exits with the signal-derived code, `snug` propagates it. |
| `snug` receives `SIGINT`/`SIGTERM` | `signal.NotifyContext` → context cancel → ordered teardown: release/kill `bwrap`, stop `pasta`, stop proxies, unlink sockets. |
| **`snug` is `SIGKILL`ed** | `bwrap --die-with-parent` `SIGKILL`s the payload (`PR_SET_PDEATHSIG` on `bwrap`'s child, armed by `bwrap` itself). `pasta` is started with `SysProcAttr{Pdeathsig: SIGKILL}`, so the kernel kills it too. Netns reaped. **Nothing survives, with no cooperation from `snug`.** |
| `pasta` dies mid-run | The tap device vanishes; the sandbox is left with `lo` only. This is the **fail-safe direction** — the sandbox loses connectivity, it never gains reachability. `snug` watches `pasta`'s `Wait()`, logs an error with `pasta`'s captured stderr, and prints a one-line warning into the sandbox's terminal. It does **not** silently restart (a restart would race a new port set) and it does **not** kill the agent (which may be mid-edit). `--net-strict` makes a `pasta` death fatal for callers who prefer that. |
| `pasta` outlives the netns | **VERIFIED**: `pasta` self-reaps within a few seconds of the netns emptying, even with no signal from `snug`. `snug` still signals it explicitly rather than relying on this. |

`snug` never uses `Setpgid` anywhere in this tree: the whole tree must stay in the terminal's foreground process group so `Ctrl-C` reaches every stage and job control works for an interactive shell inside the sandbox. (Lesson carried from `agent-sandbox`.)

### 4.4 Topology A — the podman variant

Topology (b)'s virtue (a single-uid userns, no subuid) is exactly what makes it unable to host a rootless container engine: `podman` inside a namespace with one mapped uid fails with `cannot set user namespace`. If the sandbox is to reach its own containers' published ports, the engine must live in the **same netns as the sandbox** while retaining a **subuid range**.

So when `Podman != PodmanOff`, `snug` re-execs itself into a second topology:

```
snug                                                    (host)
└── unshare --user --mount --map-root-user --map-auto -- snug __stage=h1
    H1: userns U with a FULL subuid map, own mount ns, HOST netns
     ├── unshare --net -- snug __stage=h2
     │   H2: same U, private netns N
     │    ├── podman system service  (per-sandbox store, §8) — in U and N
     │    ├── the filtering proxy    (unix socket; crosses netns freely)
     │    └── bwrap --unshare-all --share-net ... -- <agent>
     │          (unshares everything EXCEPT net → inherits N)
     └── pasta --netns /proc/<H2>/ns/net    (in U, host netns, child of H1)
```

`--map-auto` needs `/etc/subuid`/`/etc/subgid` delegation (this host: `michal:1001:64535`). `snug` preflights this and **refuses**, with the exact missing delegation named, rather than degrading. Two additional requirements carried from `agent-sandbox`, both found the hard way: H1 must `mount(MS_REC|MS_PRIVATE, "/")` or podman's overlay store fails with `failed to make mount private`; and H2 must prove `readlink /proc/self/ns/net != readlink /proc/<H1>/ns/net` before proceeding, so a forged stage marker cannot produce a run that claims isolation while sitting in the host netns.

**This is the only reason topology A exists.** Without `podman`, `snug` uses topology (b), which needs neither `unshare(1)` nor subuid delegation.

### 4.5 The exact `pasta` argv

For the default `@net` profile, topology (b):

```
pasta \
  --config-net \                        # configure address/routes/MTU in N. NOT implied when
                                        #   joining via --netns (VERIFIED: without it the tap
                                        #   interface exists but stays DOWN with no address)
  --map-host-loopback none \            # do not translate any address to the host's loopback
  -t none \                             # host -> ns TCP forwards: none. `@net-publish` overrides
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

Deliberately **not** passed:

- `--map-guest-addr` — defaults to `none`, and `snug` wants no host→guest special address. Its absence is asserted behaviourally, not by trusting the default.
- `-a`/`-g`/`-n` — by default `pasta` copies the host's addresses and routes into the namespace, so the sandbox sees the host's LAN address (**VERIFIED**: `192.168.1.120/24` inside the ns). This is a minor information disclosure. `snug` exposes it as an opt-in knob rather than a default, because overriding it diverges the sandbox's view from the host's and can confuse tooling. **VERIFIED** that `-a 10.13.13.2 -n 24 -g 10.13.13.1` works with egress intact (`curl → 301`), so `[profile.net-anon] address = "10.13.13.2/24"` is a supported one-liner.
- `--mtu` — `pasta` defaults to 65520 (**VERIFIED** inside the sandbox), which is correct: `pasta` is a userspace stack that does its own segmentation, and a large namespace-side MTU avoids pointless fragmentation. Exposed as a knob for pathological networks.

### 4.6 Network profiles

| Profile | Compiles to | Cost |
|---|---|---|
| *(none)* | `bwrap --unshare-all`, no `pasta`. Netns with `lo` only. | No network at all. This is the floor and requires no helper binary. |
| `@net` | topology (b) + the argv in §4.5 | Full internet in/out. Host loopback unreachable. Host cannot reach sandbox ports. |
| `@net-publish` | `@net`, but `-t 127.0.0.1/auto` | Every port the sandbox binds becomes reachable on the **host's** `127.0.0.1` — and only there. **VERIFIED**: with `-t 127.0.0.1/auto`, a listener on `:18099` inside the ns answered `200` from the host at `127.0.0.1:18099` and was **refused** at `192.168.1.120:18099`. The LAN never sees it. |
| `publish = [3000, 8080]` | `@net`, `-t 127.0.0.1/3000,8080` | As above but only the named ports. Preferred. |
| `@net-anon` | `@net` + `-a/-n/-g` from a private range | Sandbox does not learn the host's LAN address. |
| `@net-host` | `bwrap --unshare-all --share-net`, **no `pasta`** | **Everything.** Host loopback, every abstract AF_UNIX socket (X11, D-Bus), the LAN as the host. Requires `--i-know` on the command line *and* prints a five-line warning. Exists so that "I need to debug a host service" does not become "so I stopped using snug". |

**Recommended default: `@net` with `-t none`, not `-t auto`.** The owner asked that the host be able to reach sandbox ports "if that is easy" — and it is easy, one flag. `snug` still defaults it off, for a specific reason: with `-t auto`, **the sandbox chooses which host loopback ports appear**. That inverts the guiding principle — the agent, not the human, would author a host-visible surface, and a prompt-injected agent could squat `127.0.0.1:8080` ahead of your own dev server and intercept your browser. With `-t 127.0.0.1/3000` the human named the port and the hole is exactly one port wide.

The ergonomic cost is one word. `snug --dry-run` prints `network: egress; host→sandbox: closed (add profile '@net-publish' or publish=[…] to open)`, and `@net-publish` remains a first-class, documented, one-word profile for people who want the convenience. This is a deliberate, stated departure from the owner's "should", with the mechanism to get the other behaviour trivially available.

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

Two additional cases:

- **`--dns-host` override.** If the host's first nameserver is itself unusable from `pasta`'s position (a container with a broken `resolv.conf`), `[profile.net] dns_host = "1.1.1.1"` pins it, and `snug doctor` flags the situation.
- **Offline.** With no `@net` profile there is no `pasta` and no DNS. `/etc/resolv.conf` is generated as an empty file with a comment (`# snug: no network profile selected; DNS is intentionally unavailable`) so that resolver libraries fail immediately and legibly instead of hanging on a 5-second timeout.

`search .` (rather than copying the host's search domains) prevents the sandbox from learning the host's internal domain names, and prevents accidental resolution of bare hostnames against a corporate suffix.

### 4.8 IPv6, MTU, address, hostname

- **IPv6** is enabled by default. `pasta --config-net` copies the host's v6 configuration; **VERIFIED**, the sandbox got global and link-local v6 addresses and a default v6 route, and `[::1]:3100` (host loopback over v6) was **refused**. Both `--map-host-loopback` and `-T`/`-U` take up to two addresses, one per family, and `none` covers both. `[profile.net-v4] ipv4_only = true` compiles to `-4` for networks where v6 is broken.
- **MTU** is `pasta`'s default 65520 (**VERIFIED** on the namespace interface). Knob: `mtu = 1500`.
- **The sandbox's own address** is, by default, the host's — `pasta` copies host addresses into the namespace. Stated plainly because it is a (small) information disclosure: the agent learns your LAN IP. `@net-anon` fixes it.
- **Hostname.** `--unshare-all` includes a UTS namespace, and `snug` sets `--hostname snug` (or `snug-<basename target>`). **VERIFIED**: `hostname` inside returns `snug` while the host remains `zelva`. This is worth doing for a reason beyond cosmetics: shell prompts, `tmux` status lines and agent transcripts all show it, so **you can always tell at a glance whether you are inside a sandbox**. `snug` additionally exports `SNUG=1` and `SNUG_PROFILES=<list>`.
- `/etc/hosts` is generated (`127.0.0.1 localhost snug`, `::1 localhost ip6-localhost`) rather than bound, so the sandbox does not inherit host entries that name internal services.

### 4.9 Fallback matrix — and the rule that governs it

**The rule: `snug` never silently falls back to a weaker security posture. Ever.**

A silent downgrade is worse than a failure, because the user believes a guarantee that no longer holds. The only subsystem permitted to degrade quietly-ish is seccomp, and even that prints a warning, because seccomp is defence-in-depth on top of the namespace boundary rather than the boundary itself.

| Condition | Detection | Behaviour | Message |
|---|---|---|---|
| Unprivileged userns unavailable (`kernel.unprivileged_userns_clone=0`, AppArmor `apparmor_restrict_unprivileged_userns=1`, `max_user_namespaces=0`) | preflight probe: `bwrap --unshare-user --ro-bind /usr /usr -- /bin/true` | **FATAL.** `snug` cannot function. | Names the exact sysctl and the exact value needed, plus the Ubuntu 24.04 AppArmor case. |
| `bwrap` not on `PATH` | `LookPath` | **FATAL** | `snug requires bubblewrap (bwrap). Install: <distro hint>.` |
| `@net` requested, `pasta` not installed | `LookPath` | **FATAL** | `profile '@net' requires pasta (from the passt package). Without it snug will not silently run you with no network or, worse, the host's network. Install pasta, or drop the '@net' profile to run offline.` |
| `@net` requested, `pasta` fails to attach | non-zero `Wait()` or no non-`lo` device within 3s | **FATAL**, payload never released (§4.3) | `pasta` stderr is reproduced verbatim. |
| `--unshare-net` refused (deeply nested userns, some seccomp-restricted CI) | `bwrap` exit + stderr | **FATAL** | `cannot create a network namespace here. Run with --net-host --i-know if you accept that the sandbox will see the host's loopback, or drop networking.` |
| **Inside `distrobox`/podman container** | `/run/.containerenv` or `/.dockerenv` present | **Works.** No special handling. | Everything in this document was verified inside a rootless-podman distrobox: nested userns, netns creation, `pasta` attach, egress, DNS, loopback isolation. `snug doctor` reports the nesting for context. |
| Seccomp unavailable (`/proc/sys/kernel/seccomp/actions_avail` missing, or filter install fails) | probe + install error | **Degrade with a warning.** | `seccomp filter unavailable (<reason>); continuing WITHOUT it. The namespace boundary is unaffected; ptrace/keyctl/TIOCSTI hardening is not active.` |
| `podman` profile, no `/etc/subuid` delegation | preflight `unshare --user --map-auto -- true` | **FATAL** | Prints the exact line to add to `/etc/subuid` and `/etc/subgid`. |
| `podman` profile, no `podman` binary | `LookPath` | **FATAL** | Never degrades to "no engine but the profile said yes". |
| SELinux enforcing | `getenforce` | Works; container binds get `:z` (§8.3) | Reported in the status line. |

`snug doctor` runs every probe and prints a table, so a user can diagnose a host before their first run rather than during it.

### 4.10 Interaction with the podman-socket profile — stated honestly

**In topology (b), containers started through the proxied socket do not run in the sandbox's netns.** They run in whatever netns the *engine* is in. This has consequences that must not be glossed over:

1. **The sandbox cannot reach its own containers.** `docker run -p 8080:80 nginx && curl localhost:8080` **fails**. The port was published on the engine's side of the world; the sandbox's `127.0.0.1` is a different loopback.
2. **A container can potentially reach things the sandbox cannot.** Its network posture is the *engine's*, not `snug`'s. (Mitigating fact: rootless `podman`'s own `pasta` invocation on this host is `--config-net --dns-forward 169.254.1.1 -t none -u none -T none -U none --no-map-gw --quiet --netns … --map-guest-addr 169.254.1.2` — podman closes both holes correctly, including `-T none -U none`. But `snug` must not depend on someone else's configuration for its own guarantee.)

`snug`'s answer is twofold.

**(i) The proxy forbids everything that would widen the container's network beyond the engine's default.** Absolute rejections, each audited with a reason:

- `HostConfig.NetworkMode` ∈ {`host`, `container:*`, `ns:*`} — host-mode networking is a direct escape.
- `HostConfig.PortBindings` non-empty and `PublishAllPorts` — publishing puts a listener somewhere the sandbox cannot see, so it is useless *and* it creates a host-visible surface the human did not authorise.
- `HostConfig.Sysctls`, `HostConfig.DNS*`, `HostConfig.ExtraHosts` — resolver redirection.
- `HostConfig.UsernsMode`, `PidMode`, `IpcMode`, `UTSMode`, `CgroupnsMode` set to any `host`/`container:` value.
- `HostConfig.Privileged`, `CapAdd`, `Devices`, `DeviceRequests`, `DeviceCgroupRules`, any `SecurityOpt`, custom `Runtime`, `Annotations` (podman honours `run.oci.*`), `VolumesFrom`, non-nil `MaskedPaths`/`ReadonlyPaths`.

Container-to-container networking on a `snug`-created bridge network **is** allowed, so multi-container workflows (app + database) work. Only the sandbox↔container path is broken, and the injected `~/.claude/CLAUDE.md` says so in one sentence so the agent does not waste turns discovering it.

**(ii) Topology A fixes it properly, and is what `@podman-socket` actually selects (§4.4).** With the engine inside the sandbox's netns N, published ports land on **N's** loopback: the agent *can* `curl localhost:8080`, and the host **cannot** — the prior generation verified exactly this (`podman run -p 18082:80` inside N: reachable from a sibling in N, connection *refused* from the host). This is why `@podman-socket` costs a whole extra topology, and it is worth it. When topology A is unavailable (no subuid delegation), `snug` **refuses** rather than falling back to topology (b)'s degraded container networking, because the difference is user-visible and would be attributed to a bug.

---

## 5. `bwrap` argv generation

### 5.1 Namespaces

```
--unshare-all          # user, ipc, pid, net, uts, cgroup — everything bwrap supports
[--share-net]          # ONLY in topology A, to inherit the netns H2 already created
--uid <host uid>
--gid <host gid>
--hostname snug
--die-with-parent
--new-session          # own TTY session: prevents TIOCSTI-style input injection into the
                       #   parent terminal even if the seccomp rule is unavailable
```

`--unshare-all` rather than a selective list, on principle: the selective form is a denylist of namespaces to keep, and this design does not do denylists. `--share-net` is the single documented exception and only appears in topology A, where the netns is created one level up.

**`--uid`/`--gid` are set to the invoking user's real ids, not 0.** Mapping to 0 inside the userns is common and tempting (it makes `chown` work), but it means every file the agent creates in the project is owned by a uid that maps back to *you* while the agent *believes* it is root — and it makes `sudo`-shaped mistakes look plausible. Same uid inside and outside means file ownership is boring and correct, and `id` shows a normal user.

### 5.2 `/proc`, `/dev`, `/sys`, `/tmp`

- `--proc /proc`. A fresh procfs bound to the sandbox's own PID namespace. Without a PID namespace this would leak the host process table; with `--unshare-all` it shows only the sandbox's own processes.
- `--dev /dev`. `bwrap`'s synthetic minimal `/dev`: `null`, `zero`, `full`, `random`, `urandom`, `tty`, plus a private `devpts`. **Verified contents** on this host. No `--dev-bind /dev /dev` — that would hand over every block device, `/dev/kmsg`, `/dev/mem`, and the input devices.
- **`/sys` is not mounted at all.** This is deliberate and is a real, if small, compatibility cost: some tooling reads `/sys/fs/cgroup` or `/sys/devices/system/cpu` for parallelism hints. `snug` mitigates by exporting `NPROC`-shaped env hints, and ships `[profile.sysfs] ro = ["/sys"]` for the cases that genuinely need it. `/sys` read-only still exposes a lot of host topology (network interfaces, PCI devices, DMI/serial numbers, thermal data) and is a recurring source of container escapes when combined with anything writable, so it is opt-in.
- `--tmpfs /tmp` by default (private, ephemeral, dies with the sandbox). The `@tmp-shared` profile replaces it with a bind of a per-sandbox host directory (§7.3).

### 5.3 On `/etc`: enumerate, do not bind wholesale

**This section originally argued the opposite, and the argument was wrong. It is kept here as a correction because the flaw in it is instructive.**

The original reasoning was: *`snug` runs as your uid, so binding `/etc` grants the sandbox exactly the bytes you could already `cat` from a shell. It confers no new authority.* Every clause of that is true, and it is still beside the point, because it reasons only about **confidentiality**. `/etc/profile.d/*` and `/etc/bash.bashrc` are not read by the sandbox — they are **executed** by every shell inside it. Binding all of `/etc` therefore hands the host distribution a code-injection channel into the agent's startup. That is a new authority, on an axis the original argument never considered.

It is not hypothetical. On the development host (a `distrobox` container), `/etc/profile.d/distrobox_profile.sh` contains:

```sh
test -z "${DBUS_SESSION_BUS_ADDRESS:-}" && export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -ru)/bus"
```

Because `--clearenv` did its job, the script sees an empty environment, *reconstructs* the bus address from the uid, and calls `host-spawn` — which then fails, repeatedly and visibly, against a bus the sandbox correctly cannot reach. The noise is harmless. The mechanism is not: a script shipped by the host got to run arbitrary code inside the sandbox and rewrite its environment. `distrobox` exists to maximise host integration; `snug` exists to minimise it, and inheriting its startup scripts inherits its goal.

So `@sys` enumerates. The list is what things actually need, and it is short:

```
/etc/ld.so.cache /etc/ld.so.conf /etc/ld.so.conf.d      dynamic linker
/etc/ssl /etc/pki /etc/ca-certificates /etc/crypto-policies
/var/lib/ca-certificates /usr/share/ca-certificates      TLS trust
/etc/nsswitch.conf /etc/passwd /etc/group                identity, name lookup
/etc/localtime /etc/os-release /etc/alternatives         locale, distro detection
```

**VERIFIED** in a real sandbox: 12 `/etc` entries instead of 109, no startup noise, and `python3 -c "import ssl; len(ssl.create_default_context().get_ca_certs())"` returns 145 certificates; `git`, `go`, `date +%Z` and `whoami` all behave.

Two entries on that list were found by breakage rather than by reading, which is the maintenance cost (R6) made concrete:

- **`/etc/crypto-policies`** — `openssl.cnf` line 81 is `.include = /etc/crypto-policies/back-ends/opensslcnf.config`. Without it every TLS client dies with `MODULE_INITIALIZATION_ERROR`, which names neither the file nor the include.
- **`/var/lib/ca-certificates`** — `/etc/ssl/certs` is a symlink *out of* `/etc` into it. Granting `/etc/ssl` alone yields a trust store that resolves to nothing. This is precisely the symlink-out-of-a-granted-directory hazard from §3.3, met in the wild on the first try.

When adding to this list, test it: `python3 -c "import ssl; print(len(ssl.create_default_context().get_ca_certs()))"`.

The files snug generates are still overridden on top of the enumerated set:

- `/etc/resolv.conf` — generated (§4.7)
- `/etc/hosts` — generated (§4.8)
- `/etc/passwd`, `/etc/group` — generated, containing only `root` (with `/usr/sbin/nologin`) and the sandbox user, so the agent cannot enumerate every account on the machine
- `/etc/machine-id` — generated, per-sandbox random, so the sandbox cannot fingerprint the host

There is deliberately **no `etc-full` builtin**. A profile granting the whole tree is one line —

```toml
[profile.etc-full]
ro = ["/etc"]
```

— that any user can drop in `~/.config/snug/profiles.d/`. Shipping it as a builtin bought nothing except a maintenance obligation and a thing to explain, and what it costs (every `/etc/profile.d` script and `/etc/bash.bashrc` then *runs* inside the sandbox, so the distribution injects code into the agent's shell) is a cost the person writing that line is choosing knowingly. snug ships the curated `/etc` that things actually need. Same minimalism as having no `--read-only` (§2.5): the tool stays small, and the escape hatch is the profile format itself.

### 5.4 Seccomp

A classic-BPF denylist, assembled in **pure Go** (`golang.org/x/net/bpf` + `golang.org/x/sys/unix` for arch-correct syscall numbers), written to an anonymous `memfd`, and passed via `--seccomp FD`. No `cc` dependency, cross-arch by construction. This is a direct port of `agent-sandbox`'s filter, which was itself validated byte-for-byte against a C oracle.

Denied with `EPERM`: `ptrace`, `bpf`, `userfaultfd`, `add_key`, `keyctl`, `request_key`, `perf_event_open`; `ioctl(_, TIOCSTI, _)` (terminal input injection); `unshare`/`clone` with `CLONE_NEWUSER` (nested-userns escape primitive). Default `ALLOW`.

Inherited gaps, documented and **not** silently "fixed": non-native architectures are `ALLOW`ed (so the x86_64 i386-compat path is a bypass), and `clone3`'s flags live behind a pointer that classic BPF cannot dereference, so `clone3` is unfiltered. Closing either requires `SECCOMP_RET_TRAP`/`user_notif` machinery that would need a supervisor thread — a possible M6, not a claim made today.

**VERIFIED** on this host: `/proc/sys/kernel/seccomp/actions_avail` = `kill_process kill_thread trap errno user_notif trace log allow`. Seccomp is the only subsystem allowed to degrade (§4.9): it is defence-in-depth *on top of* the namespace boundary, and a host that cannot install a filter is not a host where the boundary has failed.

### 5.5 The fd model

`bwrap`'s `--file FD`, `--ro-bind-data FD`, `--seccomp FD`, `--args FD`, `--block-fd FD`, `--json-status-fd FD` all read fds `bwrap` inherits, and **`bwrap` does not close inherited fds**. In Go, `exec.Cmd.ExtraFiles[i]` becomes child fd `3+i`. `snug` therefore:

1. Walks `/proc/self/fd` and closes every fd `> 2` that it did not deliberately open (a port of `close_extra_fds`), so no non-`CLOEXEC` fd from a grandparent leaks into the sandbox.
2. Allocates `ExtraFiles` in deterministic append order and emits the matching numbers.
3. Passes **the entire flag list via `--args FD`** (NUL-separated, from a memfd) rather than as real argv. Three reasons: it sidesteps `ARG_MAX` for large policies; the sandbox's own `/proc/<pid>/cmdline` does not display the full policy to the agent; and it removes every shell-quoting concern from `snug --dry-run`'s round-trip.
4. Runs `bwrap` to completion rather than `exec`-replacing, so deferred teardown runs and the exit code can be propagated.

---

## 6. Lessons from `agent-sandbox`

The previous generation (`/home/michal/projects/plainsof/cv/agent-sandbox`, ~45 Go files, 624-line `DESIGN.md`) is the source of most of the hard-won detail here.

### 6.1 What carries over unchanged

- **The anti-drift thesis, which is the single best idea in the prior design.** One `Policy` value, computed once, is the sole author of *both* the `bwrap` argv *and* the container-proxy's decisions. The set of host paths a container may bind therefore cannot widen past what the sandbox itself exposes — divergence is impossible by construction, not by review. `snug` keeps this verbatim, and extends it: the same `Policy` now also authors the `pasta` argv.
- **The `@null` profile as an explicit lattice floor.** Tried, then removed (MVY0): it was unreachable by its own documented command (`-p` only adds to `defaults`) and duplicated the `defaults`/`--no-defaults` decision the same way `[profile.default]` duplicated it (§2.6). The floor — grants nothing, will not run a shell — is what `Resolve` returns for an empty selection; `snug --no-defaults --dry-run <dir>` shows it directly, no profile required.
- **`include` composes upward.** Kept, with the resolution semantics tightened (§2.3).
- **The filtering ssh-agent proxy with `ssh_mode = "agent-proxy"`.** Kept as the recommended answer (§7.1).
- **The `[identity]` block vocabulary** (`gh_user`, `gh_host`, `git_name`, `git_email`, `ssh_key`, `ssh_mode`). Kept as-is.
- **The fd model** (`ExtraFiles` → `3+i`, `close_extra_fds`), **pure-Go seccomp BPF via memfd**, **strict JSON decoding with `DisallowUnknownFields()` + trailing-data check** as the API-drift guard, **strip-and-inject mount rewriting**, **component-wise (not string-prefix) containment checks**, **`StoreKey` store math**, **SELinux `:z` relabel**, **`Setpgid` on the engine but nowhere in the sandbox chain**.
- **Two bugs whose regression tests carry over verbatim**: `bwrap` cannot create a mountpoint at a symlink destination (§3.3); and a proxy that buffers streaming response headers deadlocks foreground `docker run`, because the client calls `ContainerWait` before `ContainerStart` — `Flush()` immediately after `WriteHeader`.

### 6.2 What is deliberately dropped

- **The daemon (`engined`).** Constraint 2. The prior project had already removed it, for a structural reason worth restating: podman must live inside the run's own netns, so the netns must be *owned by the run*, so there is one process tree per run and nothing to share. **What is lost:** a warm, shared container engine across runs — two `snug` invocations cannot see each other's containers, and each run pays engine-start latency. **How `snug` compensates:** per-sandbox storage is *persistent on disk* keyed by profile+target (§8), so the recurring cost is engine startup (~hundreds of ms) rather than re-pulling images; and the engine is started **lazily**, only when the sandbox's first request reaches the proxy socket, so a run that never uses containers pays nothing.
- **`allowlist_root = false`** — the escape hatch that inverted the model back to "whole host read-only plus masks". **Removed with no replacement.** It is not expressible: it requires a `mask` concept, and `snug` has no subtraction. This is the single largest deviation from the prior config, and it is the point of the rewrite. If you want the whole host readable, say `ro = ["/"]` in a profile in your *own* config directory, and `snug --dry-run` will show you exactly what you did.
- **`mask = [...]`** — a deny list. Removed for the same reason. In the prior design, `mask` was needed because the base was permissive; with an empty base there is nothing to mask.
- **Scalar override by include order.** Replaced by permissive-ward joins (§2.3). The prior behaviour ("the including profile's scalars win over what it builds on") is order-dependent and can tighten, which is exactly the property snug must not have.
- **`offline` and `network = "offline"`.** Offline is the absence of `@net` (§2.3).
- **The `AGENT_*` env-var surface** as a primary interface. Env vars remain for CI, but the CLI and profiles are the interface.

### 6.3 Where the prior TOML vocabulary is kept vs changed

| Prior key | `snug` | Why |
|---|---|---|
| `include` | **kept** | Composition is the model. |
| `ro`, `rw` | **kept** | Direct grants. `dev` added. |
| `env` | **kept** | Allowlist. |
| `match` | **kept**, with a caveat (§9.2) | Convenient; the failure mode must be stated. |
| `[identity]` + all fields | **kept** | Already the right answer. |
| `expose = [ports]` | **renamed `publish`**, scoped to `127.0.0.1` | `expose` reads like "make visible to the world"; the semantics are the opposite. Scoping to host loopback is a genuine posture change (§4.6). |
| `network = "host"\|"offline"\|"private"` | **kept as `"host"\|"egress"\|"isolated"`**, joined by max | `private` was ambiguous about egress. `offline` removed. |
| `docker`, `docker_build` | **`podman = "off"\|"socket"\|"build"`** | One key, one lattice, and the name matches the engine. |
| `allowlist_root` | **removed** | §6.2 |
| `mask` | **removed** | §6.2 |
| `seccomp` | **removed from profiles**, CLI only | Profiles may not weaken defence-in-depth (§2.3). |
| `oci_runtime`, `selinux_relabel`, `selinux_restore`, `max_procs`, `mem_kb` | **kept in `[defaults]`** | Host-adaptation knobs, not grants; they live outside the profile lattice. |
| — | **new**: `tmpfs`, `symlink`, `optional`, `publish_auto`, `dns`, `address`, `mtu`, `description`, `claude_credentials`, `claude_notice` | §2.6 |

### 6.4 Open questions the prior design already answered

- **ssh identities** — answered by `ssh_mode = "agent-proxy"`. Adopted and specified concretely in §7.1.
- **`~/.config` subsetting** — the prior design granted `~/.config/git` read-only via the `@git-ro` preset and nothing else. `snug` keeps exactly that shape (§9.5).
- **Claude Code's files** — the prior design established that auth needs *both* the staged writable `~/.claude/.credentials.json` **and** `~/.claude.json` (without the latter Claude re-onboards and shows the login prompt), that `settings.json`/`skills`/`plugins` load read-only, and that the rest of `~/.claude` should stay ephemeral. `snug` keeps all of it and adds one correction (§9.3).
- **The injected `~/.claude/CLAUDE.md`** — the prior design generated it dynamically from a base file plus a paragraph reflecting the actual container state, delivered via `--ro-bind-data` from a memfd so a requested-but-degraded run truthfully reads "no engine". Kept and extended to networking (§9.4).

### 6.5 The correction

`agent-sandbox` ships `pasta --config-net --map-host-loopback none -t none -u none --no-netns-quit -f --netns …` (`internal/netns/pasta.go`, in a comment block headed *"Every flag is load-bearing"*). It does not pass `-T none -U none`, so **the host's entire loopback service set is reachable from inside its "private" network namespace** (§4.2). Its own probe notes recorded the symptom (`*%lo:631` visible inside the netns) and filed it as a probable `ss`/`procfs` artifact. It was not. `snug` fixes the flags, and — more importantly — adopts the structural response: security-relevant defaults are never trusted, and the guarantee is asserted by a behavioural integration test rather than by reading a man page (§12.4).

---

## 7. Host integration surfaces

Every surface below is off by default and reached by naming a profile. Each is a *proxy* `snug` owns, never a raw passthrough — except `@tmp-shared`, which is a plain bind by nature.

### 7.1 ssh — the filtering agent proxy

**Recommendation: `ssh_mode = "agent-proxy"`, unconditionally, for every real workflow.** The alternatives exist to be rejected in writing.

| Mode | What it does | Verdict |
|---|---|---|
| **`agent-proxy`** | `snug` binds a private socket, hands it to the sandbox as `SSH_AUTH_SOCK`, and forwards to the host's **already-unlocked** agent, exposing exactly one pinned key. | **Recommended.** No key material in the sandbox. No passphrase prompt. The sandbox cannot enumerate or use your other keys. |
| `agent` | A private one-key agent; `ssh-add` prompts once at startup. | Fallback when no host agent is running. Key material lives in a process `snug` owns, still not in the sandbox. |
| `key-file` | Stage the (encrypted) private key into the sandbox. | **Weakest.** The key bytes are inside the blast radius. Only for keys you would not mind rotating. |
| `host-agent` | Bind the host `SSH_AUTH_SOCK` straight through. | **Discouraged**, and `snug` requires `--i-know`. Every key, every identity, no filtering. |
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

`DOCKER_HOST`/`CONTAINER_HOST` inside the sandbox point at a `snug`-owned unix socket. The upstream is a **per-sandbox** engine (§8), never the host's. The proxy is a thin transport; every decision is made by `Policy.Decide` in the `policy` package, so the mount rules and the sandbox's own mounts have one author (§6.1).

Normalisation first: strip the `/v1.x` API-version prefix, split into segments, and **reject instantly on any `.` or `..` segment**, so `/containers/../build` cannot masquerade as an allowed prefix. Default verdict on no match: **reject 403**.

| Class | Endpoints |
|---|---|
| **Allowed (passthrough)** | `_ping`, `version`, `info`, `events`, `system/df`; container lifecycle/inspect/logs/wait/stats; `images` pull/list/inspect/tag/push/prune/rm; networks; volumes list/inspect/rm |
| **Filtered** (strict-decode → sanitise → re-encode) | `POST /containers/create`, `POST /volumes/create`, `POST /images/create`, `POST /build` (only with `podman = "build"`) |
| **Rejected, with an audited reason** | `exec`, `commit`, `session`, `grpc`, `distribution`, `images/load`, `images/create?fromSrc`, `containers/{id}/{exec,attach,update}`, `containers/{id}/archive` (GET/PUT/HEAD — a direct host-filesystem read/write channel) |

`POST /containers/create`, in order:

1. **Strict decode** into pinned `container.CreateRequest` types with `DisallowUnknownFields()` **and** a trailing-data check. Any unknown key — a future-API field that could grant an unmodelled capability — is a 403. Cost: a genuinely-new benign field from a newer client also 403s. Deliberate; bump the pinned dependency to widen.
2. **Reject-list** the escape fields and the network fields (§4.10).
3. **Strip and inject.** `nil` out `Binds`, `VolumesFrom`, `VolumeDriver`, `Config.Volumes`, `Tmpfs`; set `Mounts` to exactly the canonical bind set derived from the `Policy` — normally the one writable target, `rprivate`, RW, `:z` on SELinux hosts.
4. **The bind-mount rule that answers the brief directly:** *a container may bind a host path if and only if the sandbox itself can see that path at the same or greater access.* Because both faces read the same `Policy.Mounts`, this is a lookup, not a parallel rule set. In the opt-in submount mode, each requested source is resolved with a **daemon-namespace realpath** (longest existing prefix `EvalSymlinks`'d, remainder rejoined lexically) and then checked **component-wise** against the containment ceiling — defeating symlinks the agent planted in the writable project. Legacy `-v` `Binds` strings are refused wholesale (option-smuggling surface), as is `type=volume` (the backing store is unknowable at bind time) and `shared`/`rshared` propagation.
5. **Security injection and re-encode.** Force `SecurityOpt=["no-new-privileges:true"]`, `Privileged=false`, then `json.Marshal` **from `snug`'s own struct**. Re-encoding is a second, independent drift guard: only fields `snug` set reach the engine.

`POST /volumes/create` permits driver `""`/`local` with **zero** `DriverOpts` and a nil `ClusterVolumeSpec`. That one rule kills `type=none,o=bind,device=/host`, `device=/dev/*`, and `o=addr=` NFS/CIFS remotes at their source — the separate call that plants a host-path volume later referenced as `Mounts[type=volume]`.

`POST /build` (only with `podman = "build"`) — **IMPLEMENTED, and the shape is not what this paragraph originally described.** Corrected against a recording of the real podman CLI 5.8.3, because the docs and this design note both had it wrong:

- The CLI posts to **`/v5.x/libpod/build`**, not the docker-compat `/v1.41/build`. Both are handled; a filter written only for the compat path would have covered a path no real client uses.
- **Every policy-relevant option is a QUERY PARAMETER.** The body is only the context tar. So the libpod/compat schema split that forces `bodyBearing` to refuse libpod bodies elsewhere does not apply here — there is no body to misread.
- The context tar is **forwarded unread**: the client assembled it inside the sandbox from files the sandbox can already read, so it reaches nothing new.
- `RUN --mount=type=secret` needs no rejection. The CLI reads the file **itself**, client-side, and ships the bytes in the tar under a generated name (`--secret id=s,src=/etc/hostname` became `secrets=["id=s,src=podman-build-secret-4284765652"]`). It therefore names no host path and grants no read the sandbox did not already have.

The filter is a **default-deny allowlist over the query string** (`buildParams` in `internal/dockerproxy/build.go`), for the same reason `allowed()` is one: build options are a large, fast-moving set, and one snug has not been taught about must fail closed. Each host-reaching parameter and the flag that produces it:

| flag | parameter | judged by |
|---|---|---|
| `-v /etc:/x` | `volume` | the §7.2 step-4 mount rule, unchanged |
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

`@tmp-shared` allocates `/tmp/snug-<uid>-<hash(target)>-<random>/` on the host with mode `0700` and binds it as the sandbox's `/tmp`, replacing the default private tmpfs. Use case: handing a file to a host tool, or a large build cache that should survive a crash.

`snug` removes the directory at teardown unless `--keep-tmp` is given. It refuses to bind a path that is a symlink, is not owned by the invoking uid, or has group/other write bits — the classic `/tmp` races. The hash of the target makes the directory stable across runs of the same project, so a build cache warms.

### 7.4 D-Bus — don't

**Recommendation: no D-Bus profile ships.** Not the session bus, not the system bus, not a filtering proxy.

The session bus is an RPC surface onto your entire desktop: `org.freedesktop.portal.*` (open arbitrary files with a *user-visible dialog* that a patient agent can win), `org.gnome.Shell.Eval` on some setups, `org.freedesktop.secrets` (your keyring), `org.freedesktop.Notifications`, `org.freedesktop.systemd1` on the user bus (start a transient unit *outside* the sandbox — a complete escape). Filtering it means maintaining an allowlist over an extensible, introspectable, service-defined interface set whose membership changes when you install software. That is a losing maintenance position, and a filtering D-Bus proxy that is 95% correct is a sandbox that is 0% sound.

A coding agent does not need D-Bus. If a specific need appears, the right answer is a purpose-built proxy for that one interface, designed then, with its own threat model — not a general bus hole. Additionally, the private netns already blocks the abstract-socket path to D-Bus for free (§4.1), so `snug` would have to work to open this hole.

### 7.5 GUI, audio and D-Bus — out of scope

An earlier draft of this section specified `wayland` and `x11` profiles as
explicit, knowingly-large holes. **That is no longer planned**, and the design
is removed rather than left sitting here looking like a roadmap item.

The reasoning is the same as §7.4's for D-Bus, and it generalises: passing a
display, audio or bus socket into the sandbox either hands over the protocol
wholesale — X11 in particular has no client isolation at all, so any client can
keylog and screenshot every other — or requires a filtering proxy for an
extensible, service-defined interface set. That is a project in its own right,
and a proxy that is 95% correct is a sandbox that is 0% sound.

The private network namespace already excludes all of them by construction,
because abstract AF_UNIX sockets are netns-scoped (§4.1). **That is a property
to preserve, not a gap to close.** A coding agent does not need a display.

If a concrete need ever appears, it should be designed then, for that one
interface, with its own threat model — not anticipated here.

## 8. Per-sandbox podman storage

### 8.1 Layout

```
store   = $XDG_DATA_HOME/snug/engines/<key>/storage
runroot = $XDG_RUNTIME_DIR/snug/engines/<key>/rr
socket  = $XDG_RUNTIME_DIR/snug/run-<runid>/podman.sock     (private, upstream)
proxy   = $XDG_RUNTIME_DIR/snug/run-<runid>/docker.sock      (what the sandbox sees)

key = <profile-set-hash>-<StoreKey(target)>
StoreKey(p) = strings.TrimPrefix(strings.ReplaceAll(p, "/", "-"), "-")
```

The engine is started as `podman system service --root <store> --runroot <runroot> ... unix://<socket>`, fully disjoint from the host's rootless podman. **The host's store, images and networks are never touched** — the prior generation asserted this with a live test that diffs the host store before and after, and that test carries over (§12.5).

The store is keyed by **profile set + target**, so: the same project with the same profiles reuses its images (warm start); a different project gets a different store (no cross-project image or volume leakage); and a *more privileged* profile set never inherits a store built under a less privileged one.

### 8.2 Lifecycle

The engine is started **lazily**, on the first request that reaches the proxy socket, so a run that never uses containers pays nothing. It runs in its own process group (`Setpgid`) so teardown's group-kill reaps only this engine's tree and never the host's other rootless containers. Teardown: `podman --root … stop --all --time 5`, then group-`SIGTERM`, 5s grace, group-`SIGKILL`, then unlink the sockets. The store persists on disk; `snug prune` removes stores not used in N days.

The `runroot` is under `$XDG_RUNTIME_DIR`, i.e. `tmpfs`, so a hard-killed `snug` leaves no stale lock surviving a reboot. A stale `runroot` from a same-boot crash is detected by a lock probe and cleared.

### 8.3 SELinux and runtime

Carried over verbatim, because both were learned the hard way. On an enforcing host the injected bind must be relabelled or the container's `svirt` domain cannot access it: `selinux_relabel` defaults to `z` (shared, one-time, stable), with `Z` (private, new MCS categories every run — measured ~45 µs/file *every* run vs one-time for `z`), `disable`, and `off`. The relabel is carried on every policy-approved bind as a policy-authored `HostConfig.Binds` string (the sole docker-compat carrier for `:z`), and the bind-string builder fails closed on any `:` or `,` in a source or target so no client-bind smuggling surface is opened.

The OCI runtime is **unpinned** by default — the engine uses whatever `containers.conf` says. The prior "prefer crun, fall back to runc by `PATH` presence" heuristic mis-picked on hosts that ship a `crun` binary podman cannot exec (this dev host: `crun --version` works, `--runtime crun` fails `EINVAL`). `oci_runtime` in `[defaults]` is the escape hatch.

---

## 9. Identity, agent files, environment, and `$HOME`

### 9.1 ssh / git / gh — one pinned identity per profile

`[profile.X.identity]` pins one account. `snug` then:

- runs the filtering ssh-agent proxy (§7.1) and sets `SSH_AUTH_SOCK` to it;
- generates `~/.gitconfig` from a memfd containing `user.name`, `user.email`, and an `insteadOf` rule rewriting `https://github.com/` to `git@github.com:` so pushes go over the pinned key rather than prompting for a token;
- injects `GH_TOKEN`/`GITHUB_TOKEN` for that account only, read from the host `gh` config at launch (never mounted);
- generates `~/.ssh/config` and `~/.ssh/known_hosts` for the pinned host.

Result: inside the sandbox, `gh api user` and `git push` act as exactly that account, and no other identity is reachable. `~/.ssh`, `~/.config/gh`, and `~/.netrc` are never mounted.

### 9.2 `match` — keep it, with the failure mode stated

`match = ["~/projects/plainsof/**"]` auto-selects a profile by target path. **Recommendation: keep it, but never let it select a privileged profile, and always print what it chose.**

The failure mode is real and must be written down: **the target path chooses the credentials.** Clone a hostile repository into `~/projects/plainsof/evil` and it is handed your work identity — an ssh signing oracle and a `gh` token — because of where it sits on disk. Nothing about the repository was consulted.

Mitigations `snug` applies:

1. `match` may not select a profile carrying any privileged grant (§2.7). A matched profile may pin `[identity]`, but a profile that also opens `podman` or `@net-host` must be named explicitly.
2. Auto-selection **always** prints one line before launch: `snug: profile 'plainsof' auto-selected by match '~/projects/plainsof/**'; identity gh_user=plainsof, ssh_key=key3…`. Silent credential selection is the actual danger; a visible line makes the mistake self-evident.
3. Exactly one profile may match; two matches is a fatal error rather than a precedence rule.
4. `--profile X` always wins over `match`, and `--no-match` disables it.

### 9.3 Claude Code's files

Read-only, from the host:

```
~/.local/bin/claude, ~/.local/share/claude    the CLI itself
~/.claude/settings.json                       settings
~/.claude/skills, ~/.claude/plugins           personal skills/plugins, re-exposed RO on top of
                                              the ~/.claude tmpfs so they load and run normally
```

Writable, **staged as copies**, never bound:

```
~/.claude/.credentials.json    mode 0600, --perms 0600 --file <fd>
~/.claude.json                 account/onboarding state — WITHOUT it Claude re-onboards and
                               shows the login prompt (a real finding from the prior project)
```

Staging means the sandbox writes to a private copy on a tmpfs. **This is a deliberate correction to the prior design's implicit behaviour and it has a real cost: a token refreshed inside the sandbox does not persist to the host.** `snug` handles it explicitly — at teardown, if `--sync-credentials` is set (default **on** for `~/.claude/.credentials.json`, **off** for `~/.claude.json`), `snug` compares the staged copy to the host original and, if the sandbox wrote a *structurally valid* credentials file, copies it back atomically. Structural validation (it parses, it has the expected fields, it is not larger than a sane bound) is the guard against a compromised agent writing arbitrary content into a host file. `~/.claude.json` is not synced back because it carries MCP server configuration — a natural target for injecting a tool that runs *outside* the sandbox on your next host-side session.

Everything else under `~/.claude` (history, projects, sessions, transcripts) stays ephemeral. Note honestly: `~/.claude.json` also carries MCP configs which may include tokens, so mounting it read-only is a real, if bounded, disclosure — the same one the prior model already made.

### 9.4 The injected `~/.claude/CLAUDE.md`

A generated file, delivered read-only from an anonymous memfd via `--ro-bind-data` (no host temporary file, no race). It is composed at launch from a base plus paragraphs selected by the *actual* resolved policy, so a run whose podman engine failed to start truthfully reads "no engine" rather than advertising one. Content, roughly:

> You are running inside `snug`, an unprivileged sandbox. `$SNUG=1`, hostname `snug`.
>
> **Filesystem.** Only `<target>` is writable and persists. `<target-parent>` is readable. `$HOME`, `/tmp` and `~/.claude` are writable but **ephemeral — they are gone when this session ends**. Put anything meant to survive in the project tree. Everything else is read-only or absent. Secrets (`~/.ssh`, `~/.gnupg`, cloud credentials), personal data, and every other project on this machine are not hidden — they were never mounted. They read as absent. Do not try to reach them; there is nothing there and it wastes your turns.
>
> **Network.** *(when `@net`)* You have internet access. You **cannot** reach services on the host's `127.0.0.1` — this is intentional and is not a misconfiguration. Ports you bind are *(not visible to the host / visible to the host on 127.0.0.1)*. *(when offline)* You have no network. Do not attempt to fetch anything.
>
> **Containers.** *(when wired)* `docker`/`podman` work through a filtering proxy against a sandbox-private engine. Bind mounts of paths this sandbox cannot see are rejected, as are `--privileged`, `--network=host`, and device passthrough. *(topology-b caveat, when applicable)* Published container ports are **not** reachable from here; use container-to-container networking. *(when not wired)* There is no container engine.
>
> **Tooling.** Personal skills and plugins are re-exposed read-only — invoke them normally, do not try to edit them. Host `~/.claude` settings, history, prior sessions and MCP server configuration are **not** carried in; do not rely on host-configured MCP tools.
>
> **Identity.** *(when pinned)* git/ssh/gh are scoped to `<gh_user>`. Exactly one ssh key is available for signing; you cannot enumerate or use others.

The point is not politeness. Every sentence here removes a class of wasted turns *and* a class of confusing failure that an agent might otherwise try to "fix" by disabling something.

### 9.5 `~/.config` subsetting

**Recommendation: read-only, and by explicit grant only — never a blanket `~/.config` bind.**

`~/.config` is where applications keep tokens (`~/.config/gh/hosts.yml`, `~/.config/gcloud`, `~/.config/op`, `~/.config/containers/auth.json`), and it is also where a persistence payload goes (`~/.config/autostart`, `~/.config/systemd/user`). A blanket bind is a credential dump and a persistence vector in one.

`snug` ships exactly one `~/.config` grant by default: `[profile.git-ro] ro = ["~/.config/git", "~/.gitconfig"]`. Anything else is a line the human writes in their own profile. `~/.config` inside the sandbox is otherwise a **writable tmpfs**, so applications that expect to write there work and their writes evaporate.

### 9.6 Environment variables

`--clearenv`, then an explicit `--setenv` per variable. The allowlist is not a filter over the host environment — the host environment is *discarded*, and each variable is reconstructed. There is no pattern to get wrong.

`snug` always sets: `HOME`, `PATH` (a fixed value, not the host's — the host `PATH` names directories that do not exist inside and may name a writable one), `USER`, `LOGNAME`, `SHELL`, `TERM`, `LANG`, `TZ`, `XDG_RUNTIME_DIR` (a tmpfs), `TMPDIR`, `SNUG=1`, `SNUG_PROFILES`, `SNUG_TARGET`, `PS1` marker.

`snug` sets when wired: `SSH_AUTH_SOCK` (the proxy), `DOCKER_HOST`/`CONTAINER_HOST` (the proxy), `GH_TOKEN`, `GIT_*`.

Profiles opt in by name: `env = ["ANTHROPIC_API_KEY", "EDITOR", "PAGER", "NO_COLOR", "HTTPS_PROXY"]` — the *value* is taken from the host at launch.

Never passed, even if listed: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND`, `NODE_OPTIONS`. These are code-injection vectors into every process the sandbox launches, and they are the one place `snug` overrides an explicit grant — with a loud error at resolve time rather than a silent drop, so the human learns why.

### 9.7 `$HOME` inside the sandbox

**`$HOME` is the same absolute path as on the host (`/home/michal`), and it is an empty tmpfs.**

Same path, because: agent tooling, `git`, `node`, and the project's own config bake absolute paths; the target directory frequently lives under `$HOME` and must keep its identity so that error messages, `git` remotes, and the injected `CLAUDE.md` all agree with what the human sees outside; and stack traces and build caches that leak paths stay comparable.

A tmpfs, because: it must be writable (every tool expects to write dotfiles), and it must not persist (persistence in `$HOME` is the primary agent-escape-into-your-next-session vector — `.bashrc`, `.profile`, `.config/autostart`, `.local/bin` shadowing a command on your `PATH`).

**VERIFIED**: `--tmpfs /home/u` combined with `--remount-ro /` gives a writable `$HOME` on a read-only skeleton, and the ordering (tmpfs at depth 2 emitted before binds at depth 3+) falls out of the depth sort with no special case.

---

## 10. Go module and package layout

```
snug/
├── go.mod                          module snug; go 1.26
├── Makefile                        build, gate, live-test, golden-update
├── .claude/design/DESIGN.md                  this document
│
├── cmd/snug/
│   ├── main.go                     signal trap, stage dispatch, os.Exit(code)
│   ├── args.go                     parseArgs(argv, getenv) -> policy.Config — PURE, testable
│   ├── dryrun.go                   `snug --dry-run` renderer (§11.2)
│   ├── doctor.go                   `snug doctor` host capability report (§4.9)
│   └── stage.go                    topology-A re-exec stage dispatch (§4.4)
│
├── internal/profile/               TOML profiles: parse, merge layers, lookup precedence
│   ├── file.go                     File/Profile TOML structs; strict decode
│   ├── builtin.go                  //go:embed profiles/*.toml — the shipped profile set
│   ├── discover.go                 embedded -> /etc -> XDG; NEVER repo-local (§2.7)
│   ├── privileged.go               the privileged-grant classifier (§2.7)
│   └── profiles/*.toml             sys, home, cwd-rw, parent-ro, net, claude, podman-*, …
│
├── internal/policy/                THE CORE. Pure. Imports nothing internal.
│   ├── types.go                    Access, Kind, Mount, NetPolicy, Identity, Policy
│   ├── resolve.go                  Resolve(): expand, canonicalise, join, validate (§2.2)
│   ├── join.go                     the join laws, one function per lattice (§2.3)
│   ├── validate.go                 symlink hazards, containment, fail-closed checks (§3.4)
│   ├── environ.go                  Environ interface — all host lookups, injectable
│   ├── bwrap.go                    Policy.BwrapArgs() -> ([]string, []*os.File) (§5)
│   ├── pasta.go                    Policy.PastaArgs(childPID int) -> []string (§4.5)
│   ├── decision.go                 Verdict/Decision — the container proxy's instruction type
│   ├── allow.go                    endpoint routing + allowlist (§7.2)
│   ├── create.go                   decideContainerCreate: reject-list, strip-and-inject
│   ├── volume.go                   decideVolumeCreate, decideImageCreate
│   ├── build.go                    decideBuild (podman = "build")
│   └── canon.go                    daemon-namespace realpath, component-wise containment
│
├── internal/netns/                 topology: fd handshake, pasta supervision, stage bootstrap
│   ├── topologyb.go                DEFAULT: bwrap creates netns, pasta joins (§4.3)
│   ├── topologya.go                podman variant: subuid userns + unshare --net (§4.4)
│   ├── pasta.go                    start/supervise/stop pasta; Pdeathsig; bounded stderr
│   └── ready.go                    /proc/<pid>/net/dev readiness poll; block-fd release
│
├── internal/sandbox/               process lifecycle. Imports policy + netns + proxies.
│   ├── run.go                      Runner.Run — the orchestrator (§10.1)
│   ├── exec.go                     bwrap exec: close_extra_fds, ExtraFiles, --args memfd
│   ├── seccomp.go                  pure-Go BPF assembly -> memfd (§5.4)
│   ├── stage.go                    memfd staging of generated files + writable copies
│   └── engine.go                   per-sandbox podman service: start/stop/StoreKey (§8)
│
├── internal/dockerproxy/           thin fail-closed HTTP transport over policy.Decide (§7.2)
├── internal/sshproxy/              filtering ssh-agent proxy (§7.1)
│
└── test/
    ├── golden/                     *.bwrap.txt, *.pasta.txt — golden argv
    └── integration/                real-bwrap tests, build-tagged (§12)
```

Acyclic import DAG: `profile → policy ← {netns, dockerproxy, sshproxy} ← sandbox ← cmd`. `policy` imports only the standard library and `golang.org/x/sys`. It is the bottom of the graph precisely so that the anti-drift invariant (§6.1) has exactly one home.

Dependencies: `github.com/pelletier/go-toml/v2` (strict decode), `github.com/docker/docker` (pinned moby types), `golang.org/x/crypto/ssh/agent`, `golang.org/x/sys`, `golang.org/x/net/bpf`. No cgo.

### 10.1 `Runner.Run`

```
 1. cfg  := parseArgs(argv, getenv)                      pure
 2. set  := profile.Discover(...).Select(cfg.Profiles)   lookup precedence, privileged check
 3. pol  := policy.Resolve(set, ctx)                     pure; fail-closed; final
 4. if cfg.Explain { render(pol); return 0 }             dry run — no process, no socket
 5. preflight()                                          userns, bwrap, pasta, subuid, seccomp
 6. topology := pol.Topology()                           b (default) | a (podman)
 7. if pol.Identity.SSHMode == agent-proxy:              bind sshproxy socket, go Serve
 8. if pol.Podman != off:                                bind dockerproxy socket, go Serve (lazy engine)
 9. sec := BuildSeccomp()                                memfd; degrade+warn on failure
10. args, fds := pol.BwrapArgs()                         --args memfd + ExtraFiles
11. child := exec bwrap (--json-status-fd, --block-fd)   payload BLOCKED
12. if pol.Net.Mode == egress:
       pasta := startPasta(pol.PastaArgs(child.Pid))     Pdeathsig=SIGKILL
       waitForNetDev(child.Pid) or ABORT (payload never released)
13. release the block-fd                                 payload runs
14. code := wait(bwrap)
15. deferred reverse-order teardown: pasta, engine, proxies, sockets, tmp
16. os.Exit(code)
```

---

## 11. CLI surface

```
snug [flags] [dir] [-- cmd ...]
```

`dir` defaults to `.`; `cmd` defaults to `@claude` when the `@claude` profile is active, else `$SHELL -l`.

A bare `snug <dir>` selects the **`defaults` setting**, not a profile: built-in `["@sys", "@home", "@cwd-rw", "@parent-ro"]` (internal/profile/defaults.go), replaced wholesale by `defaults = [...]` in `~/.config/snug/config.toml`. `-p` **adds** to it; `--no-defaults` declines it. There is no `[profile.default]`, because a default selection is a preference and a profile is a grant — one idea, one mechanism. `@net` is not in the list and must not be added: offline is the *absence* of the `@net` profile, so it cannot be re-enabled by accident.

There is no flag that grants less. A read-only project means not selecting `@cwd-rw`: `snug --no-defaults -p @sys -p @home -p @parent-ro <dir>`. Verbose on purpose (§2.5).

| Flag | Meaning |
|---|---|
| `-p, --profile NAME` | Add a profile. Repeatable. Order is irrelevant (§2.2). |
| `--no-defaults` | Decline the `defaults` selection entirely. Start from nothing. Running without the standard set is unusual enough to deserve an explicit switch. |
| `--config PATH` | Load an additional profile file explicitly. Privileged grants restricted (§2.7). |
| `--publish PORT` | Add to `NetPolicy.Publish`. Repeatable. |
| `--no-seccomp` | Human-only weakening (§2.3). |
| `--i-know` | Required by `@net-host`, `host-agent`, `--allow-privileged-config`. |
| `--keep-tmp` | Do not remove the `@tmp-shared` directory at teardown. |
| `-v, --verbose` | Per-decision audit lines from both proxies on stderr. |

Subcommands:

| Command | Purpose |
|---|---|
| `snug --dry-run [dir]` | **Dry run.** Print the resolved policy and the exact `bwrap` and `pasta` command lines. Starts nothing. |
| `snug doctor` | Host capability report and the fallback matrix as it applies here (§4.9). |
| `snug profiles [NAME]` | List profiles with descriptions; `NAME` shows the expansion and provenance of every grant. |
| `snug prune` | Remove per-sandbox podman stores unused for N days. |

### 11.1 Exit codes

`snug` propagates the payload's exit code verbatim, so `snug ... -- make test` is usable in a pipeline. `snug`'s own failures use `64`–`78` (sysexits-style) to stay distinguishable: `64` usage, `69` a required host capability is unavailable, `70` an internal error, `77` a policy conflict or a privileged grant refused.

### 11.2 `snug --dry-run` — the trust surface

This is not a debugging convenience; **it is the mechanism by which a human can trust `snug` at all.** A sandbox you cannot read is a sandbox you are guessing about. `snug --dry-run` starts no process, binds no socket, and creates no file.

```
$ snug --dry-run --profile @sys --profile @cwd-rw --profile @parent-ro --profile @net /home/u/proj/sub

snug 0.1.0 — dry run, nothing was started

TARGET   /home/u/proj/sub          (canonical; writable)
HOME     /home/u                   (tmpfs, ephemeral)
PROFILES @sys @cwd-rw @parent-ro @net  (+ @home, via @cwd-rw)
TOPOLOGY b — bwrap creates the netns, pasta joins it

FILESYSTEM  (deny-by-default; every line below is a grant, there are no deny rules)
  ro    /usr                                       @sys
  ro    /etc                                       @sys
  ro    /opt                                    ?  @sys          (optional, present)
  link  /bin -> usr/bin                            @sys
  link  /sbin -> usr/sbin                          @sys
  link  /lib -> usr/lib                            @sys
  link  /lib64 -> usr/lib64                        @sys
  proc  /proc                                      (snug)
  dev   /dev                                       (snug)
  tmpfs /tmp                                       (snug)
  tmpfs /home/u                                    @home
  tmpfs /home/u/.cache /home/u/.config …           @home
  ro    /home/u/proj                               @parent-ro
  rw    /home/u/proj/sub                           @cwd-rw
  data  /etc/resolv.conf   (generated, 61 B)       @net
  data  /etc/hosts /etc/passwd /etc/group          (snug)
  ro-/  everything else is READ-ONLY skeleton      --remount-ro /

  NOT GRANTED (never mounted, reads as absent):
    /home/u/.ssh  /home/u/.gnupg  /home/u/.aws  /home/u/.config/gh  /home/u/Documents
    /home/u/proj/../*  (11 sibling directories under /home/u)
    /sys  /tmp/.X11-unix  $XDG_RUNTIME_DIR/wayland-0  the session D-Bus socket

NETWORK
  mode            egress (private netns, one per sandbox)
  host loopback   UNREACHABLE  (--map-host-loopback none, -T none, -U none)
  abstract unix   UNREACHABLE  (netns-scoped: X11, D-Bus)
  egress          full, IPv4 + IPv6
  dns             169.254.1.1 -> pasta -> host resolver (works with systemd-resolved)
  host -> sandbox CLOSED       (add profile 'net-publish', or publish=[3000], to open)
  address         copied from host (192.168.1.120) — add 'net-anon' to hide it
  mtu             65520 (pasta default)

ENVIRONMENT  (--clearenv, then:)
  HOME=/home/u  PATH=/usr/bin:/bin  USER=u  SHELL=/bin/bash  TERM=xterm-256color
  SNUG=1  SNUG_PROFILES=cwd-rw,home,net,parent-ro,sys  SNUG_TARGET=/home/u/proj/sub

INTEGRATION
  ssh-agent  off        podman  off        tmp  private tmpfs        gui  off

── pasta ────────────────────────────────────────────────────────────────────────
pasta --config-net --map-host-loopback none -t none -u none -T none -U none \
      --dns-forward 169.254.1.1 --ns-ifname snug0 --no-netns-quit --quiet --foreground \
      --netns /proc/$CHILD/ns/net --userns /proc/$CHILD/ns/user

── bwrap ────────────────────────────────────────────────────────────────────────
bwrap --args 3 -- /bin/bash -l
  # fd 3 (NUL-separated), expanded:
  --unshare-all --uid 1000 --gid 1000 --hostname snug --die-with-parent --new-session
  --json-status-fd 4 --block-fd 5 --seccomp 6
  --ro-bind /usr /usr
  --ro-bind /etc /etc
  --ro-bind-try /opt /opt
  --symlink usr/bin /bin
  --symlink usr/sbin /sbin
  --symlink usr/lib /lib
  --symlink usr/lib64 /lib64
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --perms 0755 --dir /home
  --tmpfs /home/u
  --ro-bind-data 7 /etc/hosts
  --ro-bind-data 8 /etc/passwd
  --ro-bind-data 9 /etc/group
  --ro-bind-data 10 /etc/resolv.conf
  --ro-bind-data 11 /etc/machine-id
  --tmpfs /home/u/.cache
  --tmpfs /home/u/.config
  --tmpfs /home/u/.local/state
  --ro-bind /home/u/proj /home/u/proj
  --bind /home/u/proj/sub /home/u/proj/sub
  --remount-ro /
  --clearenv
  --setenv HOME /home/u --setenv PATH /usr/bin:/bin --setenv USER u --setenv LOGNAME u
  --setenv SHELL /bin/bash --setenv TERM xterm-256color --setenv LANG en_US.UTF-8
  --setenv XDG_RUNTIME_DIR /tmp/xdg --setenv TMPDIR /tmp
  --setenv SNUG 1 --setenv SNUG_PROFILES cwd-rw,home,net,parent-ro,sys
  --setenv SNUG_TARGET /home/u/proj/sub
  --chdir /home/u/proj/sub
```

The `NOT GRANTED` block is generated by probing the host for paths a reasonable person would expect to be there and confirming they are absent from the grant set. It is the only part of `--dry-run` that is advisory rather than authoritative, and it is labelled as such — but it is what makes the deny-by-default model *legible* rather than something you take on faith.

---

## 12. Testing strategy

### 12.1 Pure unit tests — the resolver (no build tag, runs everywhere)

`internal/policy` has no internal dependencies and injects every host lookup through `Environ`, so all of this runs on any machine including a userns-less CI container:

- **Algebraic laws, property-tested** (`testing/quick` over generated profile sets): `Resolve` is commutative (`Resolve(shuffle(S)) == Resolve(S)`), idempotent (`Resolve(S ∪ S) == Resolve(S)`), and **monotone** (`Resolve(S) ⊑ Resolve(S ∪ {p})` for every builtin `p`). The monotonicity property test is the executable form of §2.4 and is the most important test in the package.
- Join laws per lattice: `Access`, `NetMode`, `PodmanMode`, `publish`, `env`.
- Conflict detection: same `Guest`, different `Kind` → error naming both provenances.
- Symlink hazards (§3.3): a grant whose `Guest` resolves inside a read-only bind is rejected at resolve time, not at `bwrap` time. Includes the `podman`-as-symlink regression.
- Emission order: depth-ascending; a shuffled input produces a byte-identical argv.
- Path variables: `{target}`, `{target_parent}`, `{target_ancestor:2}`, `~`, `{home}`.
- Fail-closed: no target, non-directory target, unresolvable target, include cycle, unknown profile, unknown TOML key, privileged grant from a non-trusted layer.
- The proxy decision corpus, ported wholesale from `agent-sandbox`'s adversarial regression suite: privileged/host-namespace rejects, strip-and-inject, volume-driver smuggling, `fromSrc` import, `../` path masquerading, planted-symlink canonicalisation, unknown-field drift.

### 12.2 Golden-file argv tests (no build tag)

`test/golden/*.bwrap.txt` and `test/golden/*.pasta.txt`, one pair per interesting profile combination, generated against a **fake `Environ`** with a fixed host layout so they are byte-stable across machines. `make golden-update` regenerates; a diff in review is a diff in the sandbox's boundary and is reviewed as such.

Golden coverage: the floor (empty selection, no `@null` — MVY0); `@sys`; `@sys+@cwd-rw`; the §13 worked example; `+@tmp-shared`; `+@podman-socket` (topology A); `+@claude` (staged fds); `@net-publish`; `@net-host`.

**The `pasta` golden file has a dedicated assertion beyond the diff:** `--map-host-loopback none`, `-T none` and `-U none` must be present in *every* generated `pasta` argv except `@net-host` (which generates none at all). A test that checks these three flags by name, with a comment pointing at §4.2, is cheap insurance against exactly the regression that shipped last time.

### 12.3 Behavioural sandbox tests (`//go:build integration`)

These really run `bwrap` and assert observations from inside. Structure: a table of (profiles, target layout, probe script, expected output).

- **Visible:** the target is writable; the parent is readable and not writable; `/usr/bin/env` executes; `/etc/resolv.conf` has the generated content; `$HOME` is writable; `hostname` is `snug`; `id` shows the generated `passwd` entry.
- **Not visible:** sibling directories of the target are absent from `ls`; ancestors above the parent list exactly one entry; `~/.ssh` is `ENOENT`; `/sys` is `ENOENT`; `/tmp/.X11-unix` is `ENOENT`; the root skeleton is read-only.
- **Ordering:** with a shuffled `--profile` order, the observed filesystem is identical.
- **Monotonicity, observed:** for each builtin `p`, everything readable under `S` is readable under `S ∪ {p}`. This tests the *emitted* sandbox, not just the resolver, and would catch an emitter bug that the pure property test cannot.

### 12.4 The network isolation tests — the highest-value tests in the suite

`//go:build integration`. These exist because §4.2 happened.

```
TestHostLoopbackUnreachable
  1. bind a TCP listener on the host's 127.0.0.1:<ephemeral> that serves a known token
  2. also bind on [::1]:<ephemeral>
  3. launch a real sandbox with the `@net` profile
  4. from inside: connect to BOTH, over v4 and v6
  5. assert: connection refused / network unreachable, and the token NEVER appears
```

This is the test that fails on the previous generation's flag set. It is behavioural, not argv-based, and it is therefore immune to a `pasta` upstream default change — which is exactly the failure mode that produced the bug.

Companions:

- `TestEgressWorks` — `curl https://example.com` returns 200 (skipped without `SNUG_TEST_NET=1`).
- `TestDNSWorks` — resolution succeeds through `169.254.1.1`; a variant with a synthetic `resolv.conf` naming `127.0.0.53` asserts the systemd-resolved path.
- `TestAbstractSocketUnreachable` — the host binds an abstract AF_UNIX socket; the sandbox cannot `connect()` to it. This is the netns-scoping property from §4.1, and nothing else in the suite covers it.
- `TestNoPublishByDefault` — a listener inside the sandbox is **not** reachable from the host.
- `TestPublishScopedToLoopback` — with `@net-publish`, a sandbox listener is reachable at host `127.0.0.1:<p>` and **refused** at the host's LAN address. (This exact assertion was verified by hand: `200` vs `000`.)
- `TestNoOrphans` — after a `SIGKILL` of `snug`, no `pasta` process, no sandbox process, no netns, and no socket survives. Run with a process-table and `/proc/*/ns/net` diff.
- `TestNoSilentDowngrade` — with `pasta` removed from `PATH`, `snug --profile @net` exits non-zero and its stderr names `pasta`. It must **never** exit 0.

### 12.5 Live host-integration tests (`//go:build live`, opt-in)

Gated behind `SNUG_LIVE=1`, wrapped by `make live-test` in a host snapshot/diff. Ported from `agent-sandbox`, where they caught two bugs no unit test could:

- Real `podman` engine start/stop; assert an **empty** container list (proving store disjointness) and a byte-identical host store afterwards.
- A real `docker` CLI inside the sandbox against the proxy: `/build` → 403, `/info` → 200, `pull`, and a **foreground** `docker run` (this is what caught the header-flush deadlock) whose container sees exactly the injected bind with the client's malicious `-v /etc` and `-v $HOME` stripped.
- The ssh-agent proxy against a real `ssh-agent`: `ssh-add -l` shows exactly one key; a sign request for another key fails; `ssh-add -d` fails.
- `scripts/selfcheck.sh` — launch a real agent in a throwaway repository, with permission prompts disabled *inside the sandbox*, and have it probe the boundary itself: reads allowed, writes confined, secrets absent, host loopback unreachable, `docker run` works, `build`/`--privileged` refused. This is the canonical "prove it works with a real agent" check and it is the one that finds the things a designer did not think to test. It is also the clearest demonstration of the point of the project: the agent is *supposed* to be unconstrained inside the box.

### 12.6 CI

```yaml
# always, everywhere — no privileges needed
- gofmt -l . && go vet ./... && go build ./... && go test ./...
    # covers §12.1 (incl. the monotonicity property tests) and §12.2

# where userns is available
- go test -tags integration ./test/integration/...   # §12.3, §12.4

# nightly / manual only
- SNUG_LIVE=1 make live-test                          # §12.5
```

**Running where userns is unavailable.** The pure and golden tiers are the majority of the suite by assertion count and need nothing but a Go toolchain — that is a deliberate architectural payoff of keeping `internal/policy` dependency-free with an injected `Environ`.

For the integration tier, `snug doctor --json` runs first and the job either proceeds or `t.Skip`s with the concrete reason. Concretely:

- **GitHub Actions `ubuntu-latest`** permits unprivileged userns, but Ubuntu 24.04+ ships `kernel.apparmor_restrict_unprivileged_userns=1`, which breaks `bwrap`. The workflow sets `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` in a setup step, and `doctor` names that exact sysctl in its failure message so the diagnosis is one line rather than an afternoon.
- **Docker-based runners** need `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` and often `--device /dev/net/tun` for `pasta`.
- **A skipped integration tier must be loud.** The job summary prints `INTEGRATION TESTS SKIPPED: <reason>` and the merge gate requires the tier to have *run* on at least one runner. A green build where the network isolation tests silently skipped is exactly the same failure mode as a silent security downgrade, and gets the same treatment.

---

## 13. Worked example

```
$ snug --profile @sys --profile @cwd-rw --profile @parent-ro --profile @net /home/u/proj/sub
```

Host facts: uid/gid 1000, `$HOME=/home/u`, `/home/u/proj` contains `sub` plus 11 sibling directories, `/home/u` contains `.ssh`, `.gnupg`, `.aws`, `Documents`, and 9 other projects. `@cwd-rw` pulls in `@home`.

**Step 1 — `bwrap` starts, payload blocked.** `snug` creates two pipes, opens memfds for the generated files and the seccomp filter, and runs:

```
bwrap --args 3 -- /bin/bash -l
```

with fd 3 carrying (NUL-separated; shown expanded):

```
--unshare-all
--uid 1000
--gid 1000
--hostname snug
--die-with-parent
--new-session
--json-status-fd 4
--block-fd 5
--seccomp 6
--ro-bind /usr /usr
--ro-bind /etc /etc
--ro-bind-try /opt /opt
--symlink usr/bin /bin
--symlink usr/sbin /sbin
--symlink usr/lib /lib
--symlink usr/lib64 /lib64
--proc /proc
--dev /dev
--tmpfs /tmp
--perms 0755 --dir /home
--tmpfs /home/u
--ro-bind-data 7  /etc/hosts
--ro-bind-data 8  /etc/passwd
--ro-bind-data 9  /etc/group
--ro-bind-data 10 /etc/resolv.conf
--ro-bind-data 11 /etc/machine-id
--tmpfs /home/u/.cache
--tmpfs /home/u/.config
--tmpfs /home/u/.local/state
--ro-bind /home/u/proj /home/u/proj
--bind /home/u/proj/sub /home/u/proj/sub
--remount-ro /
--clearenv
--setenv HOME /home/u
--setenv PATH /usr/bin:/bin
--setenv USER u
--setenv LOGNAME u
--setenv SHELL /bin/bash
--setenv TERM xterm-256color
--setenv LANG en_US.UTF-8
--setenv TZ Europe/Prague
--setenv XDG_RUNTIME_DIR /tmp/xdg
--setenv TMPDIR /tmp
--setenv SNUG 1
--setenv SNUG_PROFILES cwd-rw,home,net,parent-ro,sys
--setenv SNUG_TARGET /home/u/proj/sub
--chdir /home/u/proj/sub
```

Note the grants are emitted in depth-ascending order (`/usr`, `/etc`, `/opt`, `/bin`… at depth 1; `/home/u` at depth 2; `/home/u/proj` at depth 3; `/home/u/proj/sub` at depth 4), which is why `--ro-bind /home/u/proj` precedes `--bind /home/u/proj/sub`, and why `/home` and `/home/u` never need an explicit hiding operation. `SNUG_PROFILES` is sorted, because resolution is order-independent and the output should say so.

**Step 2 — read the child pid.** `bwrap` writes to fd 4:

```
{ "child-pid": 214537, "cgroup-namespace": …, "ipc-namespace": …, "mnt-namespace": …,
  "net-namespace": …, "pid-namespace": …, "uts-namespace": … }
```

and then blocks on fd 5. The payload has not run.

**Step 3 — `pasta` joins the netns.**

```
pasta --config-net \
      --map-host-loopback none \
      -t none -u none \
      -T none -U none \
      --dns-forward 169.254.1.1 \
      --ns-ifname snug0 \
      --no-netns-quit \
      --quiet \
      --foreground \
      --netns  /proc/214537/ns/net \
      --userns /proc/214537/ns/user
```

**Step 4 — readiness.** `snug` polls `/proc/214537/net/dev` until an interface other than `lo` appears (typically <100 ms). On timeout or an early `pasta` exit, `snug` closes fd 5 unwritten and kills `bwrap`; the payload never runs.

**Step 5 — release.** `snug` writes one byte to fd 5. `bash -l` starts, in a sandbox where — **all of the following verified by executing this exact shape on this host**:

```
hostname                          -> snug
ip -o -4 addr show scope global   -> 2: snug0  inet 192.168.1.120/24 …
ip -o link | sed -n 2p            -> mtu 65520
connect 127.0.0.1:631             -> refused          (host cups)
connect 127.0.0.1:3100            -> refused          (host service)
connect [::1]:3100                -> refused
cat /etc/resolv.conf              -> nameserver 169.254.1.1 / search . / options edns0
curl https://example.com          -> 200
ls -a /home/u                     -> . ..  (+ the tmpfs dotdirs)  — .ssh/.gnupg/.aws absent
ls -a /home/u/proj                -> . .. sub  + the 11 siblings ARE visible (parent-ro grants the parent)
ls /sys                           -> ENOENT
touch /home/u/proj/sub/x          -> ok
touch /home/u/proj/x              -> Read-only file system
touch /ZZ                         -> Read-only file system
```

**Step 6 — teardown.** `bash` exits → `bwrap` exits → `snug` `SIGTERM`s `pasta` → netns refcount reaches zero → the kernel reaps it. No files, no sockets, no namespaces, no processes remain. If `snug` had been `SIGKILL`ed instead, `--die-with-parent` and `Pdeathsig` produce the identical end state with no cooperation from `snug`.

---

## 14. Roadmap

Each milestone is independently shippable and independently useful.

**M1 — the sandbox (no network helper).**
`internal/profile`, `internal/policy` (types, resolve, join, validate, bwrap emitter), `internal/sandbox` (exec, fd model, seccomp), `cmd/snug` (`run`, `--dry-run`, `doctor`, `profile`, `config`). Profiles: `@sys`, `@home`, `@cwd-rw`, `@parent-ro`, `@tmp-shared`, `@git-ro`. Networking is `--unshare-all` with no helper — **offline only**, which is a coherent and secure product. Tests: the whole of §12.1, §12.2, §12.3.
*Ships:* `snug ~/src/proj -- make test` in a genuinely isolated filesystem.

**M2 — networking.**
`internal/netns` topology B, `Policy.PastaArgs`, the fd handshake, `pasta` supervision and teardown, DNS generation, profiles `@net` / `@net-publish` / `@net-anon` / `@net-host`. Tests: **all of §12.4** — `TestHostLoopbackUnreachable` is the acceptance criterion for this milestone and nothing ships without it green.
*Ships:* the full default posture.

**M3 — identity and agent files.**
`internal/sshproxy`, `[identity]` resolution, generated `.gitconfig`/`.ssh/config`/`known_hosts`, `GH_TOKEN` scoping, the `@claude` profile with staged credentials, the injected `~/.claude/CLAUDE.md`, `match` with its guardrails, the env allowlist.
*Ships:* `snug` as a daily driver for a coding agent with a scoped identity.

**M4 — containers.**
Topology A (subuid userns + `unshare --net` + engine inside the sandwich netns), `internal/sandbox/engine.go` (per-sandbox store, `StoreKey`, lazy start, group teardown), `internal/dockerproxy` + `policy/{allow,create,volume,canon}.go`, SELinux relabel, `@podman-socket`. Tests: §12.5 live tier.
*Ships:* the agent can use containers, including reaching its own containers' published ports, with the host engine untouched.

**M5 — `podman build`.** DONE.
`internal/dockerproxy/build.go`, a default-deny allowlist over the build endpoint's query string, `@podman-build`. See §7.2 — the endpoint's real shape was established by recording the podman CLI, and differs from what this roadmap assumed.
*Ships:* `podman build` works, and cannot bind a host path, take a device, or join the host network.

**M6 — hardening and ergonomics.**
`--bind-fd`/`openat2(RESOLVE_BENEATH)` to close the resolve→mount TOCTOU (§3.3); `clone3` filtering via `SECCOMP_RET_USER_NOTIF`; `snug prune`; shell completion; a `snug --dry-run --json` machine format; `--net-strict`.

---

## 15. Risks and open questions

### Risks

- **R1 — Kernel is the boundary, and it is a big boundary.** Every guarantee here rests on user namespaces, seccomp, and `bwrap`. A userns LPE ends the discussion. Stated in §1.2; restated here because it is the risk that matters most and the one most easily forgotten after reading 5,000 words about mount ordering.
- **R2 — Helper defaults change under us.** §4.2 is a lived example. Mitigation: pass every security-relevant flag explicitly, and assert *behaviour* in integration tests rather than reading man pages. Residual risk: a flag `snug` does not know about is added with an unsafe default. Partial mitigation: `snug doctor` records `pasta --version` and CI runs the isolation tests against the installed version.
- **R3 — The proxy's strict decode is brittle by design.** A newer `docker` client sending a new benign field gets a 403. Deliberate (it is the drift guard), but it will generate confused bug reports. Mitigation: the rejection message names the unknown field and says "this is fail-closed; file an issue to widen the pinned API".
- **R4 — Credential sync-back (§9.3) writes to a host file from sandbox-authored bytes.** Structurally validated, but it is a real host-write channel from inside. It is opt-outable and its default (`credentials.json` yes, `.claude.json` no) is chosen so the sensitive-by-configuration file is the one that never syncs.
- **R5 — Ubuntu/AppArmor userns restrictions and Docker-based CI** will make `snug` unusable for some users out of the box. Mitigated by `doctor` naming the exact sysctl, not by working around it.
- **R6 — The whole-`/etc` bind (§5.3)** is a judgement call. It is defensible ("grants nothing you could not already read") but it does hand the agent a large surface for reconnaissance, and on unusual hosts a uid-readable secret could live there. `sys-min` exists; the default may need to flip if evidence accumulates.
- **R7 — Topology A's subuid requirement** means `@podman-socket` simply does not work on hosts without `/etc/subuid` delegation, including some corporate images and some CI runners. `snug` refuses rather than degrading, which is correct but will read as a regression to users of the previous generation.
- **R8 — `--remount-ro /` interacts with anything that expects to create top-level directories.** Some build systems do. The failure is legible (`Read-only file system` on a path the human can see in `--dry-run`) and the fix is a one-line profile grant, but it will be hit.

### Open questions

- **Q1 — Should `@net` default to `-t 127.0.0.1/auto` after all?** §4.6 argues no, on the principle that the agent should not author a host-visible surface. This is the single most likely decision to be reversed by real use, and it is a one-constant change. Revisit after M2 with actual usage.
- **Q2 — Credential sync-back scope.** Should it extend beyond Claude's credentials to, say, a `gh` token refresh? Current answer: no, add cases only with a demonstrated need and a structural validator each time.
- **Q3 — Multiple simultaneous sandboxes on the same target.** Two `snug` runs against the same directory today both get write access and will fight. Should `snug` take a `--lock-file` on the target (`bwrap` has the flag) and refuse the second, or warn? Leaning: warn by default, `--exclusive` to refuse.
- **Q4 — `clone3` and the 32-bit compat arch** are documented seccomp gaps inherited from `agent-sandbox`. Closing `clone3` needs `SECCOMP_RET_USER_NOTIF` and a supervisor thread. Worth it, or is the namespace boundary sufficient? Deferred to M6 pending evidence that anything real exploits it.
- **Q5 — `bwrap` PR #766 (`--netns FD`)** would let `bwrap` *join* a preexisting netns. Open upstream since 2026-07-16 with no maintainer verdict. It changes nothing for topology B (which uses inheritance) but would simplify topology A considerably by removing the `unshare(1)` sandwich. Watch item, not a dependency.
- **Q6 — Does the sandbox need `/sys/fs/cgroup` for parallelism detection?** Currently no `/sys` at all, with `NPROC` hints as compensation. If build tools misdetect badly, a narrow `ro = ["/sys/fs/cgroup"]` profile is the minimal answer — but `/sys` is a recurring escape surface and any grant here deserves its own review.
- **Q7 — Should `snug --dry-run` be able to *diff* two profile sets?** `snug --dry-run --diff sys+cwd-rw sys+cwd-rw+podman-socket` printing only the added grants would make "what does this profile actually cost me" a one-command question. Cheap; likely M6.

---

## 16. Where to start implementing

Nothing exists in the `snug` repository yet beyond `CLAUDE.md` and this document. Create these first, in this order, reading the named prior-generation files before each.

1. `internal/policy/types.go` + `resolve.go` — the lattice and the resolution algorithm (§2). Everything depends on these and they have no dependencies of their own.
2. `internal/policy/bwrap.go` — the argv emitter (§3.2, §5). Read `agent-sandbox/internal/policy/bwrap.go` first for the fd model, the `--file` numbering, and the symlink-mountpoint regression.
3. `internal/policy/pasta.go` + `internal/netns/topologyb.go` — the networking core (§4). Read `agent-sandbox/internal/netns/pasta.go` and `netns.go` for the supervision, `Pdeathsig` and readiness-poll mechanics — **but do not copy its flag list**: it is missing `-T none -U none` and is therefore exposed to host loopback (§4.2, §6.5).
4. `internal/profile/profiles/*.toml` + `discover.go` — the builtin profiles and the lookup precedence that must never include a repo-local layer (§2.6, §2.7). Read `agent-sandbox/config.toml` and `internal/config/resolve.go` for the vocabulary being evolved.
5. `test/integration/net_test.go` — `TestHostLoopbackUnreachable` and friends (§12.4). This is the acceptance gate for M2 and the single test that would have caught the previous generation's bug.
