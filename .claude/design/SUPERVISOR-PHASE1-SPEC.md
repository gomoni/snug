# Phase 1 — the stage. Implementation specification

This is the buildable form of [SUPERVISOR-PLAN.md](SUPERVISOR-PLAN.md) §"Phase 1
— the stage". It is written to be executed by someone who has read
[CLAUDE.md](../../CLAUDE.md) and this file and nothing else: every file path,
every signature and the order the work happens in are here.

Its inputs are the plan, the two Phase 0 measurement runs (0b and 0c, summarised
in §1), and two independent designs produced from the same brief — one through
the policy lens, one through the host-integration lens. Where those two
disagreed, §3 picks one and says why the other lost. **Nothing here is an
average of the two.** Where this document contradicts the plan, it says so and
gives the measurement that forced it.

The rule that governs the whole phase, restated because everything below is in
service of it:

> **Phase 1 adds no user-visible capability.** The same guarantees, the same
> integration suite passing unedited, one new block in `--dry-run`. Any
> behavioural divergence is a bug in the refactor rather than an interaction
> with a new feature, and this is the only phase where that separation is
> available.

---

## 1. Entry condition, and what is MEASURED

**Phase 0b came back GREEN.** P1 can leave the network namespace it creates, the
sandbox stays in it, pasta can still be aimed at it, and both SUPERVISOR §5
holes — an abstract socket bound by a snug helper being readable from the
sandbox, and the control socket path being listed by `ss -xl` inside — close,
each with the hole-open case run first as its positive control. So the netns
move is **in scope for Phase 1**, and the plan's fallback ("if it does not hold,
nothing else changes") does not apply.

Marked exactly as the evidence is:

| fact | status |
|---|---|
| P1 can `setns` back into N after leaving it; children forked through a setns shim land in N | **MEASURED** (0b, `poc/nsd`, `./run-netns.sh` → pass=42 fail=0, three identical consecutive runs) |
| `unshare(CLONE_NEWNET)` is **per-task**. One thread moves; `/proc/self/ns/net` reports the OLD namespace; which threads moved is scheduler-dependent | **MEASURED** (0b, isolated standalone program: 1 of 11 threads moved, leader reported the old namespace) |
| The only join point at which a multithreaded Go process moves as a whole is `execve` immediately after the unshare, on a locked thread | **MEASURED** (0b: after the `__stage2` re-exec, 0 of 6 threads left in N) |
| The pinned descriptor on N must **not** be CLOEXEC at the moment of that exec; it is marked CLOEXEC afterwards | **MEASURED** (0b; the plan's step 2, taken literally, destroys the only reference to N) |
| pasta **refuses** `--netns /proc/self/fd/3` — it drops privileges before opening the path | **MEASURED** (0b: `Couldn't open network namespace /proc/self/fd/3: Permission denied`) |
| pasta aimed at `/proc/<P1>/fd/<n>` — the descriptor P1 pinned before it moved — works: egress 200 from N and from the sandbox, host loopback 000 | **MEASURED** (0b) |
| Aiming pasta at `/proc/<P1>/ns/net` after the move succeeds **silently** and attaches to the wrong namespace (sandbox egress 000, P1's own netns 200) | **MEASURED** (0b, `--pasta-naive`) |
| With P1 outside N and a sandbox running, the only processes in N are bwrap, bwrap's child, and the sandbox's init. No snug supervisor process. N holds no listening TCP/UDP socket | **MEASURED** (0b, with positive controls) |
| N dies with P1 when pinned only by a descriptor: after `kill -9` on P0, stage, sandbox and both netns are gone | **MEASURED** (0b; positive control: 3 processes in N before the kill) |
| bwrap's `--unshare-all` creates user/mnt/pid/ipc/uts/net/cgroup and brings `lo` UP inside; the enumerated set minus `--unshare-net` creates the other six and **inherits the parent's netns** | **MEASURED** here, today, `bwrap 0.11.2` |
| Under the stage, nothing brings `lo` up in N — bwrap's `loopback_setup` runs only for a netns bwrap itself created | **MEASURED** (host-integration design; mechanism confirmed by the row above) |
| pasta's `--netns` and `--userns` are independent options | **MEASURED** here (`pasta --help`, passt 20260612) |
| A single-uid map in U (`0 <hostuid> 1`) is enough for `bwrap --uid 1000` to give the payload uid 1000 with host-uid-owned writes | **MEASURED, but not against snug's own `BwrapFlags`.** This is the one load-bearing measurement taken outside the real code path. §4 Step 0 re-measures it before anything depends on it. |
| pasta's forwarding side is outside N | **INFERRED** from egress working at all. pasta sets itself non-dumpable, so `readlink /proc/<pasta>/ns/net` is EACCES and no test can sweep it. Any test claiming "only bwrap and the sandbox init are in N" must say this rather than imply coverage it does not have. |
| The `stage1 → __stage2` re-exec does not clear `PR_SET_PDEATHSIG` | **INFERRED** (no privileged transition, so no `secureexec`). Do not depend on it: the lifeline pipe is the teardown mechanism either way. |
| `/proc/<bwrap-child>/net/dev` stays readable from P0 under the stage | **INFERRED.** Step 5 measures it and names the fallback. |
| bwrap's `--unshare-all` uses the `-try` spellings for `user` and `cgroup` | **INFERRED** from bwrap's flag list. §3.1's chosen spelling makes it not matter for Phase 1; §9 records it as a TODO. |

**Phase 0c came back RED** on the graft. That is a Phase 3 input and it changes
nothing here, except that §9 carries the one shipped-snug defect it found.

---

## 2. The topology Phase 1 builds

```
P0  snug                          host userns, host netns, host mount tree
 │   resolves the policy, builds every descriptor the sandbox needs, clones P1,
 │   writes its uid map, runs pasta at N, holds the lifeline, then supervises
 │
 ├── pasta --netns /proc/<P1>/fd/<n> --userns /proc/<P1>/ns/user
 │
 └── P1  snug __stage1 → __stage2  THE NAMESPACE HOLDER
      │   U: user ns, ONE uid mapped (root inside)
      │   N: network ns, private — created by the clone, PINNED by a descriptor,
      │      and then LEFT: after __stage2, P1 is in a fresh empty netns of its own
      │   + own mount ns (MS_REC|MS_PRIVATE) and cgroup ns
      │   NO control socket on any filesystem. NO listener.
      │
      └── snug __innetns <fd> bwrap ...    a setns shim, one execve deep
           └── bwrap (in N)                THE SANDBOX, unchanged in every respect
                └── payload
```

Everything not in that diagram is Phase 2 or Phase 3.

**A bare `snug <dir>` starts no stage.** The stage exists only where the netns
must be created by something other than bwrap, which in Phase 1 means
`NetEgress` alone. Offline runs and `--i-know` host-network runs take today's
code path byte for byte — no second process, no privileged ancestor user
namespace, no new anything. That is deny-by-default (invariant 2) applied to
snug's own process tree, and it is what keeps the offline goldens and the whole
offline half of the integration suite untouched.

*Abuse sentence for the phase as a whole, and it goes in the `--dry-run`
topology block:*

> a hostile process inside the sandbox gains no new reach — the stage is in
> neither its network namespace nor its pid namespace, binds nothing it can
> name, and holds no descriptor it can open — but its user namespace now has a
> **privileged ancestor** (U, root-in-userns with `CAP_SYS_ADMIN` over N and over
> the sandbox's own mounts) that lives for the whole run, so a userns-escape bug
> is worth more here than it was.

---

## 3. The conflicts, resolved

Six of these are disagreements between the two designs; the rest are places
where both designs overrule the plan.

### 3.1 The bwrap argv under the stage: enumerate, do not reuse `--share-net`

**Chosen.** Under `Topology.Netns == NetnsStage`, `BwrapFlags` emits

```
--unshare-user-try --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try
```

and **omits `--unshare-net`**. Under every other topology it emits
`--unshare-all` exactly as today. `--share-net` continues to be emitted **only**
for `Net.Mode == NetHost`, unchanged, one line of code untouched.

**The other position** was to keep `--unshare-all --share-net` for the stage
case, on the ground that an enumeration is a keep-list and bwrap.go's own
comment forbids keep-lists: a bwrap that grows a new namespace type would
silently stop unsharing it, which is the invariant-5 shape on an upgrade.

That objection is real, and it loses to two things it cannot answer.

- It puts **two meanings on one flag**. `--share-net` today means "the host's
  network namespace, and the CLI demanded `--i-know` for it". Under that
  proposal it would also mean "N". A `grep --share-net` across the goldens, the
  argv block of `--dry-run` and every future review then stops distinguishing
  the most dangerous network posture snug can produce from the ordinary one, and
  no test can restore the distinction, because the strings are identical.
- It forces `TestShareNetOnlyForHostMode` (`internal/policy/net_test.go:157`) to
  be **edited** — a test whose whole content is "host mode is the only mode that
  inherits a netns". Exit criterion 1 says a behavioural test that had to be
  edited to pass is a guarantee that changed. Here nothing about host networking
  changed at all, so editing it would be spending the discipline for nothing.

The keep-list objection is answered, not dismissed, by
`TestBwrapUnshareSetIsExhaustive` (§6): it parses `bwrap --help` for every
`--unshare-<name>`, and fails if our stage set does not cover all of them except
`net`. A build against a bwrap that grew a namespace type goes red rather than
quiet.

**And the spelling is deliberately `-try` for `user` and `cgroup`**, matching
what `--unshare-all` expands to, so the stage path introduces no new failure
mode on a host where those namespaces are unavailable. The strict spellings
would be *better* — a host with unprivileged user namespaces disabled currently
gets no user namespace and no error — but that is a live defect on the
**non-stage** path too, and fixing it inside a phase whose contract is "adds and
removes nothing" is how a user-visible regression gets smuggled in. §9 records
it as a TODO with its severity.

*Invariant touched:* 2 (a selective list is a denylist — mitigated by the
exhaustiveness test) and 5.
*Abuse sentence:* a hostile process inside the sandbox cannot tell, and cannot
cause, the difference between "the netns my parent made" and "the host's" — but
a reviewer must be able to, and `--share-net` is the only word that says so.

### 3.2 The stage runs only when it is needed

**Chosen.** `Topology.NeedsStage()` is a derived predicate, true exactly when
`Topology.Netns == NetnsStage`. `NetIsolated` and `NetHost` start no stage.

**The other position** handled `NetHost` by cloning P1 *without* `CLONE_NEWNET`,
so a stage exists for every run and there is one process shape to reason about.

It loses because an unconditional stage hands every default `snug <dir>` a
privileged ancestor user namespace in exchange for **no capability at all**.
Review §2.1 states the cost precisely: the value of a userns-escape bug goes up a
lot, and the sandbox has a privileged ancestor for the first time. Paying that on
a run that asked for nothing is deny-by-default violated in snug's own process
tree. The "one code path" argument does not apply: `sandbox.Run` dispatches on
`Topology.Netns` and the stage arm takes a value only `stage.Start` can produce,
so there is a conditional, not a duplicate to keep in sync.

Consequence to write down rather than discover: `NeedsStage()` is **not**
monotone over the `NetnsOwner` lattice — it is false at the floor, true in the
middle, false at the top. That is correct and must be stated in the doc comment,
because it looks alarming: raising `NetnsStage → NetnsHost` removes the stage
while strictly *widening* the grant. The lattice orders reachability; the stage
is a construction detail, not a grant.

*Invariant touched:* 2, 4.

### 3.3 Phase 1 opens no control listener at all

**Chosen.** The P0↔P1 channel is an inherited `socketpair(AF_UNIX,
SOCK_SEQPACKET|SOCK_CLOEXEC)`. No pathname, no listener, no run directory, no
`accept` loop, nothing for anything running as your uid to connect to. The
**protocol** — strict decoder, typed request struct, default-deny dispatch — is
written now, because it is the enforcement point Phase 2 inherits; only the
listener is deferred.

This overrules the plan's Phase 1 Work list, which specifies the listener now.
Both designs reached the same conclusion independently: Phase 1's only client is
P1's own parent, which can be handed a descriptor at the clone, and a socket
with no operation is pure attack surface — the single largest item in exit
criterion 7's remit.

The two designs differed on one detail: whether to write the protocol machinery
at all in Phase 1, or to print `control none` and write nothing. **Write it.**
The strict-decode discipline is cheap now and is exactly the thing that would
otherwise be bolted on under Phase 2's schedule pressure, and Phase 2 then
changes the topology golden's `control` line from `none` to a path — a visible,
reviewed security change rather than something that was already there.

*Invariant touched:* 4 (no daemon: no filesystem object, nothing to connect to,
dies with either end).
*Abuse sentence:* nothing running as your uid can reach the stage, because there
is no name to reach it by.

### 3.4 `PastaArgs` changes signature. The plan says it does not; the plan is wrong

**Chosen.**

```go
// internal/policy/net.go
type PastaTarget struct {
	NetnsPath  string // what pasta opens for --netns
	UsernsPath string // what pasta opens for --userns
}

func PastaTargetChild(childPID int) PastaTarget          // today: /proc/<pid>/ns/{net,user}
func PastaTargetStage(stagePID, netnsFD int) PastaTarget // /proc/<P1>/fd/<n> + /proc/<P1>/ns/user

func (p *Policy) PastaArgs(t PastaTarget) []string
```

The plan says the signature is unchanged and a caller passes the stage's pid.
0b measured that this is not achievable: after the move, `/proc/<P1>/ns/net` is
P1's own empty namespace, pasta reports success, and the sandbox gets 000. The
plan's own suggested repair — hand pasta the descriptor — is measured **refused**
(EACCES; pasta drops privileges before opening the path). And no single process
is both in N and in the user namespace that owns N: bwrap's child is in N but its
userns is a descendant of U with no authority over it. One pid cannot produce
both paths, so it must not be asked to.

Both designs agreed on this and differed only in naming. `PastaTarget` wins over
`NetnsRef` because it says what it is for.

The closing set (`--map-host-loopback none -t none -u none -T none -U none`) does
not move, is not reformatted, and the PoC's hand-typed copy does not enter the
tree. `internal/policy` remains the sole author of the pasta argv (invariant 6).

*Invariant touched:* 6.

### 3.5 The stage brings `lo` up itself, in Go

Only one design raised this, and it is a silent regression of an existing
guarantee if missed: today's offline sandbox has `lo` UP with `127.0.0.1/8`
because bwrap configures the netns **it created**. Under the stage bwrap does not
create the netns, so nothing configures loopback and every `NetEgress` sandbox
loses working loopback — a thing a user finds, not a test.

Except that a test does find it: `TestSandboxHasItsOwnWorkingLoopback`
(`test/integration/sandbox_test.go:2174`) must pass **unedited**, and it is the
positive control for this fix.

Implementation is `SIOCGIFFLAGS`/`SIOCSIFFLAGS` with `IFF_UP` on `lo`, on a plain
`AF_INET` datagram socket, in P1 **while it is still in N** (i.e. in `__stage1`,
before the move). Never by executing `ip(8)` — that would add a host binary
dependency snug does not have. The kernel assigns `127.0.0.1/8` and `::1/128`
itself once the interface is up, so no address code is needed.

*Invariant touched:* 5 (a capability that silently is not there).

### 3.6 No subuid delegation in Phase 1, and one uid mapped in U

Both designs agree Phase 1 delegates no subuids: in Phase 1 the engine still runs
on the host, so a delegated range is a capability with no consumer, granted under
`--no-defaults`, traceable to no profile (review §1.3), and it would make
`snug -p @podman-socket` fail on any host with no `/etc/subuid` entry.

One design went further and deletes `newuidmap`/`newgidmap` **and the stage0
privileged re-exec** by writing a single-uid map through Go's
`SysProcAttr.UidMappings`. That is the right shape — it keeps "no root, no
setuid" literally true on the Phase 1 path, and it removes the CLOEXEC-clearing
dance that produced review finding F1 — but the measurement behind it was taken
with a hand-built bwrap invocation, not with snug's real `BwrapFlags` and its
two-user-namespace structure.

**Chosen: adopt it, gated on Step 0 re-measuring it against the real code path.**
If Step 0 comes back red, Phase 1 falls back to `writeFullMaps` +
`newuidmap`/`newgidmap` + the stage0 re-exec, review §1.3's grant-with-no-profile
returns, and it goes in `TODO.md` with its severity rather than being carried
silently. Do not build anything downstream of Step 0 before Step 0 has run.

*Invariant touched:* 2, 4.

### 3.7 The remaining picks, briefly

| question | chosen | the other position, and why it lost |
|---|---|---|
| `Topology` shape | three total-order lattices (`NetnsOwner`, `SubuidMode`, `AttachMode`), each with a `Join` matching `Access.Join` byte for byte, **derived** by one pure function at the end of `Resolve` | A single "topology mode" enum. Couples three independent capabilities onto one axis, so Phase 3 raising the subuid floor would raise the netns and attach floors with it. |
| where `Topology` comes from | `deriveTopology(NetMode, PodmanMode)`, called once at the end of `Resolve` | Folding a per-profile contribution inside the main loop. Creates a second place a profile could raise the topology without raising a visible grant, and re-opens the commutativity proof obligation for no benefit. |
| `sealInheritedFDs` | moves to `internal/fdseal`, keep-list **derived from the `*exec.Cmd` being forked**, all forks on one goroutine locked to a dedicated OS thread | The one-line `fcntl(5, F_SETFD, FD_CLOEXEC)` the redteam offered. Explicitly refused by the review's own verdict: F1 is not fd 5, it is that the forking process is now long-lived with a table that drifts. |
| teardown assertion | on the **namespace object** — the netns inode swept across `/proc/*/task/*/ns/net` and every readable `mountinfo` for an `nsfs` entry. P0 does **not** pin N | A process count (E11's shape), and a P0-side descriptor on N so the test has a handle. Both wrong: the first is blind to a netns pinned by a bind mount with no process attached; the second makes N outlive P1 by construction and puts a second reference to N in the one process that also holds the host netns. |
| stage lifetime | one-shot: the stage exits after exactly one `start` request **whatever its outcome**. `everRan` disappears as a concept | Porting the PoC's reference count with `everRan` moved earlier. Correct but still expressible; one-shot makes the review's §1.4 hole inexpressible instead of fixed. |
| commit split | two: **A** = `Topology` + `Validate` rule + `canon()` line + the `--dry-run` block + new topology goldens, describing *today* (zero diff to any existing golden); **B** = the stage, raising `NetEgress` to `NetnsStage` | One commit landing `Topology` with the future derivation and a block reading "netns stage (not yet built)". A screen that lies about the present in order to be tidy about the future. |

---

## 4. The work, in order

Every path is relative to the worktree root. Do not start a step before the one
above it is green.

### Step 0 — the measurement gate (no tree changes)

In `poc/nsd`, add a `--single-uid-map` flag that writes `0 <hostuid> 1` through
`SysProcAttr.UidMappings` instead of `writeFullMaps`, and re-run the E2 check
**against snug's real invocation**: build `bin/snug`, and have the PoC start it
as the sandbox child rather than a hand-built bwrap.

Assert, with the full-map case as the control:

1. the payload's uid inside is 1000;
2. a file it creates on the target bind is owned by host uid 1000;
3. `bwrap` does not fail on `--uid`/`--gid`;
4. the sandbox's `/proc/self/status` shows `NoNewPrivs=1`, `CapEff=0`,
   `Seccomp=2` — i.e. nothing about the payload's confinement moved.

Green → §3.6 stands and Steps 3–4 are written without `newuidmap`.
Red → record what failed in this document, take the full-map fallback, and open
the `TODO.md` entry named in §9.

Also delete the stale build outputs and fix `poc/nsd/.gitignore`, which lists
`nsd`, `nsdjoin`, `nsowner` but not `nsdmount`, `nsdgraft` or `snug-under-test`.

### Step 1 — `internal/policy`: `Topology` (COMMIT A)

New file `internal/policy/topology.go`:

```go
// NetnsOwner says who created the network namespace the payload runs in. It is
// a total order joined by max: more reachability wins, exactly like NetMode.
type NetnsOwner uint8

const (
	NetnsSandbox NetnsOwner = iota // bwrap creates it. Today's shape, and the floor.
	NetnsStage                     // P1 creates it, pins it, LEAVES it, forks bwrap back in.
	NetnsHost                      // the host's own. --share-net, --i-know.
)

func (o NetnsOwner) Join(b NetnsOwner) NetnsOwner
func (o NetnsOwner) String() string // "sandbox" | "stage" | "host"

// SubuidMode records WHETHER the host's subuid range is delegated to U. It
// never records how big it is: /etc/subuid on this host reads
// `michal:1001:64535`, so the conventional 65536-at-100000 layout is wrong here
// and a size in the model is a fact the next unusual host falsifies.
type SubuidMode uint8

const (
	SubuidNone SubuidMode = iota
	SubuidFull
)

func (m SubuidMode) Join(o SubuidMode) SubuidMode
func (m SubuidMode) String() string // "none" | "full"

type AttachMode uint8

const (
	AttachNone AttachMode = iota
	AttachPayloads
)

func (m AttachMode) Join(o AttachMode) AttachMode
func (m AttachMode) String() string // "none" | "payloads"

type Topology struct {
	Netns  NetnsOwner
	Subuid SubuidMode
	Attach AttachMode
}

func (t Topology) Join(o Topology) Topology
func (t Topology) String() string // "netns=sandbox subuid=none attach=none"

// NeedsStage reports whether this policy requires a second long-lived process.
// It is deliberately NOT monotone over Netns: false at the floor, true in the
// middle, false at the top. Raising NetnsStage -> NetnsHost removes the stage
// while strictly WIDENING the grant, because the lattice orders reachability
// and the stage is a construction detail rather than a grant.
func (t Topology) NeedsStage() bool { return t.Netns == NetnsStage }

// deriveTopology is the ONLY producer of a Topology. No Profile field, no TOML
// key, no CLI flag reaches it — a field set from the CLI instead of derived
// from the resolved profile set re-creates default_profile, which "Decisions
// made" already reversed once.
func deriveTopology(n NetMode, pm PodmanMode) Topology
```

In Commit A, `deriveTopology` maps `NetEgress → NetnsSandbox`, because that is
what snug does today and the block must be honest about the present. Commit B
changes that one line.

`NetHost → NetnsHost` from Commit A onward, and `Subuid` is `SubuidNone` for
every input including `PodmanBuild`. `pm` is taken and deliberately unused, with
a comment saying Phase 3 raises it and naming `TestPhase1DelegatesNoSubuids`.

Then:

- `internal/policy/types.go`: add `Topology Topology` to `Policy`, immediately
  after `Podman`, with a doc comment saying it is derived and pointing at
  `deriveTopology`.
- `internal/policy/resolve.go`: at the **end** of `Resolve`, after `p.Net` and
  `p.Podman` are fully folded and before `Validate` is called, set
  `p.Topology = deriveTopology(p.Net.Mode, p.Podman)`.
- `internal/policy/validate.go`: add a rule refusing any policy where
  `p.Topology != deriveTopology(p.Net.Mode, p.Podman)`, with a message that names
  the fix ("build the fixture through Resolve, or set Topology with
  deriveTopology"). This closes the zero-value hazard on hand-built policies —
  several unit tests construct `&Policy{...}` directly.
- `internal/policy/resolve_test.go`: **`canon()` gains a topology line.** This is
  the single easiest thing in the change to forget, and forgetting it makes
  `TestResolveIsCommutative` silently not cover the new field — the `pasta.avx2`
  shape. Add, next to the existing `podman` line:

  ```go
  fmt.Fprintf(&b, "topology %s\n", p.Topology)
  ```

### Step 2 — `--dry-run`: the topology block (COMMIT A)

`cmd/snug/dryrun.go`: a new `describeTopology(out *os.File, p *policy.Policy)`,
called from `dryRun` immediately after `describeNetwork`. It prints, always —
including for the one-process case, where saying so is the point:

- how many long-lived processes snug will run, and which;
- whether the sandbox's user namespace has a privileged ancestor, and what that
  ancestor holds (`CAP_SYS_ADMIN` over N and over the sandbox's own mounts);
- whether the subuid range is delegated (`subuid: none` in Phase 1);
- `control: none (no socket, no listener, nothing to connect to)`;
- the lifetime rule: the stage exits when its payload does, and dies with snug
  even if snug is SIGKILLed (the lifeline pipe);
- the abuse sentence from §2.

"No daemon, no service files" is a claim the human already believes from the
README. A process that outlives the command belongs on screen with its lifetime
rule.

New goldens, `cmd/snug/testdata/topology.{isolated,egress,host}.txt`, generated
by a test in the shape of `envgolden_test.go` — this block only, resolved against
`profile.Builtins()`. There is no whole-`--dry-run` golden in the tree, which is
exactly what makes exit criterion 1's split achievable: **Commit A adds three
files and changes none.**

Verify that by regenerating everything (`go test ./internal/policy -update`,
`go test ./cmd/snug -update`) and confirming a zero diff on the seven existing
goldens plus `internal/policy/testdata/refusals.txt`.

### Step 3 — `internal/fdseal` (COMMIT B)

New package. Move `sealInheritedFDs` out of `internal/sandbox/exec.go:332` into
`internal/fdseal/fdseal.go`, unchanged in behaviour, with the API:

```go
// SealFor marks every descriptor this process holds CLOEXEC except stdio and
// the ones cmd is about to hand to its child. The keep-list is DERIVED from the
// command being forked rather than written down, because the process doing the
// forking is now long-lived and a hand-written list in such a process is a list
// that drifts — which is finding F1 stated as a class rather than as fd 5.
func SealFor(cmd *exec.Cmd) error
```

`internal/sandbox/exec.go` calls `fdseal.SealFor(cmd)` where it calls
`sealInheritedFDs(extra)` today. The behaviour is identical (the keep-list is
`cmd.ExtraFiles`), so no test moves.

### Step 4 — `internal/stage` (COMMIT B)

New package, `//go:build linux`. Three source files and one golden.

**Fixed descriptor numbers, and they are constants with names.** Nothing travels
in the environment: `/proc/self/environ` is passively readable by every process
in the sandbox, and a number in an env var is one `--setenv` away from being one.

```go
const (
	fdControl = 3 // SOCK_SEQPACKET socketpair, P1's end
	fdLife    = 4 // lifeline: read end of an anonymous pipe; P0 holds the write end
	// 5 .. 5+K-1: the sandbox's own descriptors, in bwrap's ExtraFiles order,
	//             passed straight through from P0 so the fd numbers already
	//             baked into the args memfd stay correct.
	fdNetnsN  = 63 // the pinned descriptor on N. Chosen high so it never collides
	               // with the pass-through block, whose size is policy-dependent.
)
```

**P0 side** (`stage.go`):

```go
type Config struct {
	// Netns must be policy.NetnsStage. Anything else is a programming error and
	// Start refuses rather than guessing.
	Netns policy.NetnsOwner

	// Sandbox are the descriptors bwrap needs, in the exact order P0 put them in
	// ExtraFiles when it built the argv. The stage passes them through unchanged;
	// it never renumbers, because the numbers are already inside the args memfd.
	Sandbox []*os.File

	Stdin, Stdout, Stderr *os.File
}

// Stage is opaque and only Start can produce one. That is the type-level half of
// exit criterion 2: `sandbox.Run` requires a *Stage on its stage arm, so "bwrap
// forked from P0 into a topology that says NetnsStage" does not compile.
type Stage struct{ /* unexported */ }

func Start(cfg Config) (*Stage, error)

// Target is what pasta must be aimed at. NetnsPath is /proc/<P1>/fd/63 — the
// descriptor P1 pinned BEFORE it moved — never /proc/<P1>/ns/net, which after
// the move names P1's own empty namespace and which pasta will accept silently.
func (s *Stage) Target() policy.PastaTarget

// PinnedNetns is the "net:[...]" id P1 reported for N at readiness. It is what
// every namespace assertion compares against, and it is compared against a
// non-empty string: a readlink that failed prints nothing, and an empty string
// is != any real namespace id, which is how a sandbox that never started reads
// as PASS.
func (s *Stage) PinnedNetns() string

// StartSandbox sends the one request this phase's protocol has, and blocks until
// P1 reports the fork happened. The stage will not serve a second one.
func (s *Stage) StartSandbox(bwrapPath string, argv []string) error

// Wait returns the payload's raw wait status, so P0 can convert it exactly as
// wait() converts an *exec.ExitError today.
func (s *Stage) Wait() (syscall.WaitStatus, error)

// Close drops the lifeline. P1 reads EOF and tears down its children.
func (s *Stage) Close() error
```

`Start` does, in this order:

1. `socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0)` and `os.Pipe()` for the
   lifeline.
2. `exec.Cmd{Path: /proc/self/exe, Args: ["snug", "__stage1"]}` with
   `ExtraFiles = [p1ControlEnd, lifelineRead] ++ cfg.Sandbox`,
   `Stdin/Stdout/Stderr = cfg.Stdin/…` (so bwrap inherits the payload's stdio),
   `Env = []string{}` (the `/proc/1/environ` lesson: P1 is not the sandbox's PID
   1, but it is a process the payload's ancestors can be asked about, and there
   is nothing it needs from the host environment),
   `SysProcAttr{Cloneflags: CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWCGROUP,
   UidMappings: [{0, hostUID, 1}], GidMappings: [{0, hostGID, 1}],
   GidMappingsEnableSetgroups: false, Pdeathsig: SIGKILL}`.
   `Pdeathsig` is belt-and-braces only; the lifeline is the mechanism.
3. `fdseal.SealFor(cmd)`, then `cmd.Start()`.
4. Close P0's copies of the child's ends.
5. Read the `ready` message off the control socket, with a deadline. Refuse if
   `netns_fd != fdNetnsN`, if `netns` is empty, or if `netns == userns`'s owner
   in a way that says the move did not happen.

**P1 side** (`stage1.go`, `stage2.go`), reached from `cmd/snug/main.go`'s hidden
verb dispatch (§4 Step 6). Both refuse immediately if the expected descriptors
are not present and are not reachable as ordinary CLI.

`__stage1`, in this order — and **the order is the specification**:

1. Assert `os.Getuid() == 0` (uid 0 in U) and that the capability set is
   non-empty. `/proc/<pid>/status` renders uids in the READER's user namespace,
   so this check is only meaningful from inside.
2. `mount("", "/", "", MS_REC|MS_PRIVATE, "")`.
3. Bring `lo` up (§3.5) — **while still in N**. After the move this configures
   the wrong namespace.
4. `runtime.LockOSThread()`.
5. Open `/proc/thread-self/ns/net`. **Not `/proc/self/ns/net`**: `/proc/self` is
   the thread group leader, and after a per-thread unshare it reports the
   namespace this thread just left. Reading the wrong one is how "the move
   worked" gets asserted about a process that never moved.
6. `dup3(f, fdNetnsN, 0)` — flags 0, so the new descriptor is **not** CLOEXEC.
   It has to survive the very execve that makes the move stick. The plan's step 2
   says "mark it CLOEXEC" here, and taken literally that destroys the only
   reference to N.
7. `unshare(CLONE_NEWNET)`, then re-read `/proc/thread-self/ns/net` and refuse if
   it is unchanged.
8. `syscall.Exec("/proc/self/exe", []string{"snug", "__stage2"}, []string{})`
   with nothing in between. `/proc/self/exe`, never a path from the environment —
   the review found `$NSD_SELF` re-executed after the uid map is written to be a
   same-uid replacement window.

`__stage2`:

1. Mark `fdNetnsN` CLOEXEC. This is the first moment CLOEXEC means what the plan
   intends: from here the only way that descriptor reaches a child is by being
   named in `ExtraFiles`.
2. **Sweep `/proc/self/task/*/ns/net` and refuse to continue unless zero threads
   are in the pinned namespace.** Reading `/proc/self/ns/net` here is checking
   nothing — measured, it reports the old namespace, scheduler-dependently.
3. Validate the descriptor with `NS_GET_NSTYPE`.
4. Start `watchLifeline` on `fdLife`.
5. Send `ready` on `fdControl`, carrying the pinned netns id, the userns id and
   `netns_fd`.
6. Serve exactly one request, then exit — whatever that request's outcome.

**The forker.** All forks in P1 run on one goroutine locked to a dedicated OS
thread that never exits. In Phase 1 there is exactly one fork, so this buys
nothing today and is established now because Phase 2 adds more: it serialises
forks, stabilises `PR_SET_PDEATHSIG` semantics (pdeathsig fires on the parent
*thread*'s exit and Go does not promise which thread forked), and makes the
seal/fork pair atomic with no lock discipline to remember.

The fork itself:

```go
cmd := exec.Command("/proc/self/exe", append(
	[]string{"__innetns", strconv.Itoa(3 + len(sandboxFDs)), bwrapPath}, bwrapArgv...)...)
cmd.ExtraFiles = append(append([]*os.File{}, sandboxFDs...), netnsN)
cmd.Env = []string{}
cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
fdseal.SealFor(cmd)
cmd.Start()
```

`ExtraFiles` puts the sandbox's descriptors at 3..3+K-1 — exactly the numbers P0
baked into the args memfd — and the netns descriptor last, so the shim's own
argument is the only number that has to be computed. **P1 closes the sandbox's
descriptors the instant the fork returns**, leaving four: control, lifeline,
netns, and the forker's own. A test asserts that count with a positive control
that it held more before the fork.

Sealing marks P1's own long-lived descriptors CLOEXEC, and that is safe for one
structural reason worth stating: **P1 never execs again after `__stage2`.**

`__innetns` (`innetns.go`) is the setns shim, and it must be annotated as hard as
bwrap's `--` separator is:

1. `runtime.LockOSThread()`;
2. read `/proc/thread-self/ns/net`;
3. `setns(fd, CLONE_NEWNET)` — per-task exactly as `unshare` is, so the same
   unshare-then-exec discipline applies. There is no single-thread requirement;
   that is a `CLONE_NEWUSER` rule and does not reach here;
4. re-read and refuse if unchanged;
5. **close the descriptor** — nothing downstream of this point ever holds a
   reference to N, and 0b's measurement that nothing downstream of bwrap does
   depends on this line;
6. `syscall.Exec` the real program. Touch nothing else: every other inherited
   descriptor is bwrap's and must pass through.

**The protocol** (`proto.go`): newline-delimited JSON in one SEQPACKET message,
64 KiB ceiling, typed structs decoded with `DisallowUnknownFields()` plus the
trailing-data check, default-deny dispatch — the `internal/dockerproxy` house
style. Phase 1 has one inbound op (`start`, carrying `bwrap` path, argv, and the
count of pass-through descriptors) and two outbound events (`ready`, `exited`).
A second inbound message tears the stage down.

Two things are absent from the schema **on purpose**, and absence is stronger
than validation: there is no field for a capability drop (a client cannot express
the request), and no field naming a target sandbox by pid (Phase 2's target will
be an opaque handle P1 issued).

**The golden.** `internal/stage/testdata/stage.spec.txt`, asserted by
`TestGoldenStageSpec`, records the clone flags, the uid/gid map lines, the fixed
fd numbers, and the enumerated bwrap unshare set. The plan's §4 is right that
"golden argv diffs are the review artifact" covers one of several authorities
after this lands; this is the cheap half of closing that.

### Step 5 — `internal/sandbox`: `Run` dispatches on the topology (COMMIT B)

`internal/sandbox/exec.go`. Everything up to and including the args memfd is
unchanged — `safeStdio`, the `--` discipline, the "nothing may be appended after
this point" comment, all of it. The change is who forks.

```go
if p.Topology.NeedsStage() {
	st, err := stage.Start(stage.Config{Netns: p.Topology.Netns, Sandbox: extra,
		Stdin: stdin, Stdout: stdout, Stderr: stderr})
	...
	defer st.Close()
	if err := st.StartSandbox(bwrap, argv); err != nil { ... }
} else {
	// today's code, byte for byte
}
```

`internal/sandbox/netns.go`:

- `startPasta(p, childPID)` becomes `startPasta(p, target policy.PastaTarget,
  childPID int)`. `childPID` survives only because `waitForNetDevice` polls
  `/proc/<childPID>/net/dev`, which is bwrap's inner child and **is** in N, so it
  needs nobody to be in N and needs no change.
- Update the topology comment at the top of the file. It currently describes
  "Topology B" as the only shape; there are now two, and the file is where a
  reader goes to find out which.

**Ordering stays today's**: bwrap first, `readChildPID`, then pasta, then release
the block-fd. Under the stage pasta's target is available at readiness and could
start earlier, but keeping the order is the minimum diff, keeps
`waitForNetDevice` untouched, and the payload is parked on `--block-fd`
throughout either way. Phase 3 will want pasta up before any payload exists; that
is Phase 3's problem and §8 records it.

`abort()` is unchanged and still kills the parked child by pid before anything
closes `blockW`. P1 creates no pid namespace, so the pid P0 read from
`--json-status-fd` is a host pid and `kill(2)` still reaches it.

**Measurement checkpoint.** `/proc/<childPID>/net/dev` being readable from P0 is
INFERRED. Measure it in the first end-to-end run. If it is not, the fallback is to
ask P1 over the control channel (the PoC's `waitForNetDeviceInN` does exactly
this) — and that is a protocol addition, so it must be designed, not patched in.

Exit status: P1 forwards the raw wait status; P0 converts it identically to
today's `wait()` (`WIFEXITED` → the code, otherwise -1, which is what
`(*exec.ExitError).ExitCode()` returns for signal death). `snug … -- make test`
in a pipeline and Ctrl-C are the class of thing a user finds rather than a test,
so they get a `VERIFY.md` line (§7).

### Step 6 — `cmd/snug/main.go`: hidden verb dispatch (COMMIT B)

Before flag parsing, before anything else: if `os.Args[1]` is `__stage1`,
`__stage2` or `__innetns`, dispatch to `stage.Main1()`, `stage.Main2()` or
`stage.EnterNetns(os.Args[2:])` and never return. They do not appear in `--help`,
they are not profiles, and each refuses immediately when the descriptors it
requires are absent.

`cmd/snug/dryrun.go:102` — `p.PastaArgs(0)` becomes
`p.PastaArgs(policy.PastaTargetChild(0))` under `NetnsSandbox` and
`p.PastaArgs(policy.PastaTargetStage(0, 63))` under `NetnsStage`, with the
placeholder note adjusted to say which reference the real run uses. This is not
cosmetic: the pasta argv on screen must name the same *kind* of reference the run
will use, or `--dry-run` stops being the thing a human can trust.

---

## 5. Tests expected to pass UNEDITED

Exit criterion 1 splits behavioural from golden and holds each to a different
standard. This is the behavioural half, enumerated so a diff touching any of it
is a defect until explained.

**Every test in `test/integration/sandbox_test.go`.** Phase 1 adds no
user-visible capability, so there is no legitimate reason for one to move. The
ones that are load-bearing here, with what each proves about the refactor:

| test | what it proves about the stage |
|---|---|
| `TestSandboxHasItsOwnWorkingLoopback` | §3.5's `lo` fix works. This is its positive control. |
| `TestHostLoopbackIsUnreachable` | the closing set still reaches N through the new pasta target |
| `TestEgressWorks` | pasta attached to N and not to P1's own empty netns — the `--pasta-naive` failure would show up here as 000 |
| `TestAbstractSocketsAreUnreachable` | the host's abstract namespace is still out; 0b closed the N-side half |
| `TestOfflineHasOnlyLoopback`, `TestSandboxPortsAreNotPublishedByDefault`, `TestPublishedPortsAreReachable` | the offline and publish paths are untouched |
| `TestNoHostEnvironmentViaPid1` | `cmd.Env = []string{}` still holds one process further out |
| `TestSeccompIsActuallyInstalled`, `TestSeccompDeniesTheHardeningSyscalls`, `TestNestedUserNamespaceIsRefused`, `TestThreadedProgramsStillWork` | the filter survives the extra process, and `clone3 → ENOSYS` still lets glibc fall back |
| `TestDirectoryOnStdinCannotEscape` | `safeStdio` still runs in P0 and its result still reaches bwrap through P1 |
| `TestAbortedNetworkNeverRunsThePayload` | the abort path still kills the parked child before any close releases it |
| `TestNoLeakedHelpersAfterSIGKILL` | passes unedited — **and is structurally blind to a leaked stage.** It counts pasta processes. Do not read it as covering teardown; §6 adds the test that does. |
| `TestPodmanBuildIsFilteredEndToEnd` | `@podman-socket` runs under the stage (it includes `net`) with the proxy unchanged |

**`internal/policy`**: `TestSandboxIsOffline`, `TestShareNetOnlyForHostMode`,
`TestNetModeJoinsPermissiveWard`, `TestResolveIsCommutative`,
`TestResolveIsIdempotent`, `TestResolveIsMonotone`,
`TestPolicyHasNoRestrictionOperation`, every refusal test, every env test.

**`cmd/snug`**: `env.*.txt` and `show.*.txt` goldens unchanged;
`TestNoBuiltinPutsAWritableDirectoryOnPATH` and the shadow-slot tests unchanged.

### Edited, mechanically, and only for a signature

`internal/policy/net_test.go` — five `PastaArgs` call sites (lines 37, 70, 88,
89, 123). `p.PastaArgs(1234)` becomes `p.PastaArgs(PastaTargetChild(1234))` and
**nothing else moves**. The closing set assertions in
`TestPastaArgsAlwaysCloseHostLoopback` must survive byte for byte; a signature
refactor is a plausible place to lose them.

### Golden files expected to change

| file | when | the diff |
|---|---|---|
| `cmd/snug/testdata/topology.{isolated,egress,host}.txt` | **new**, commit A | three new files; nothing else in commit A moves |
| `cmd/snug/testdata/topology.egress.txt` | commit B | `netns sandbox` → `netns stage`, plus the stage's lines appearing |
| `internal/policy/testdata/podman-socket.bwrap.txt` | commit B | line 1: `--unshare-all` → five `--unshare-*` lines. **This is the only existing golden that moves in the whole phase**, because `podman-socket` is the only golden case that resolves to `NetEgress`. |
| `internal/stage/testdata/stage.spec.txt` | **new**, commit B | the clone flags, uid map, fd numbers and unshare set |

Everything else — `sys`, `defaults`, `parent-ro`, `sanitise`, `floor`,
`refusals.txt` — is expected to be byte-identical. Regenerate and confirm a zero
diff rather than assuming it.

**And say this in the commit message for B**, because the first green golden
after a bad refactor reads as coverage: after this change an *unchanged* bwrap
golden is compatible with a completely different network posture. The argv no
longer determines it; which process called `fork` does.

---

## 6. New tests (owned by `sandbox-tester`)

Unit, in `internal/policy`:

1. `TestTopologyJoinIsMonotoneAndCommutative` — the lattice laws per field, in
   the shape of `TestNetModeJoinsPermissiveWard`.
2. `TestAddingAProfileNeverLowersATopologyField` — over the fake registry.
   Required because `TestResolveIsMonotone` compares `Access` per existing
   `Guest` key and **will not** catch a topology regression. Nobody should read
   the existing test as covering the new field.
3. `TestTopologyIsDerivedNotSettable` — no `Profile` field, no TOML key and no
   CLI flag produces a `Topology`. Same shape as
   `TestPolicyHasNoRestrictionOperation`: it is checkable by finding none.
4. `TestValidateRefusesAnInconsistentTopology`.
5. `TestPhase1DelegatesNoSubuids` — `deriveTopology(NetEgress, PodmanBuild).Subuid
   == SubuidNone`, with a doc comment saying Phase 3 must edit this deliberately.
   Same device as `TestPodmanSocketIncludesNetAsAnInterimHonestyFix`.
6. `TestNeedsStageIsFalseForOfflineAndHost`.
7. `TestCanonCoversTopology` — asserts `canon()`'s output mentions the field, so
   the commutativity test cannot silently stop covering it.

Integration, in `test/integration`, each with a positive control and a payload
that emits a marker so "the sandbox did not reach X" cannot pass on a sandbox
that never started:

8. `TestBwrapUnshareSetIsExhaustive` — parses `bwrap --help` for every
   `--unshare-<name>`, asserts the stage set covers all but `net`, and asserts
   `--share-net` never appears under `NetnsStage`. This is the guard that makes
   §3.1's keep-list acceptable; if it is ever made unit-only with a hardcoded
   list, the guard silently becomes the thing it was protecting against.
9. `TestSandboxNetnsIsTheStagesPinnedNetns` — **exit criterion 2.** The payload
   prints its own `readlink /proc/self/ns/net`; it must equal the id the stage
   published and must differ from P0's. Both sides refused if empty — an empty
   string is `!=` any real namespace id, which is how a sandbox that never
   started reads as PASS (review §3.2).
10. `TestNoStageThreadRemainsInTheSandboxNetns` — sweeps
    `/proc/<stage>/task/*/ns/net`, not `/proc/<stage>/ns/net`. Positive control:
    the stage has more than one thread to be wrong about.
11. `TestOnlyBwrapAndTheSandboxAreInN` — sweeps `/proc/*/task/*/ns/net` for the
    pinned inode. Positive control: the sweep finds bwrap. The test must state in
    its doc comment that pasta is **not covered** — it sets itself non-dumpable,
    so no sweep can see it, and "pasta's forwarding side is outside N" stays
    INFERRED.
12. `TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage` — **exit
    criterion 3**, review F1. Positive control: the payload has descriptors at
    all and the stage holds at least four.
13. `TestTheStageHoldsFourDescriptorsAtTheFork` — control, lifeline, netns,
    forker. Positive control: it held more before the fork.
14. `TestTheStageExitsWhenTheSandboxFailsToStart` — **exit criterion 4.** Force a
    bwrap failure by putting a failing `bwrap` first on the child's PATH; assert
    the stage process is gone within the test's budget. Positive control: the
    stage existed.
15. `TestTheStageLeavesNoNamespaceObjectAfterSIGKILL` — **exit criterion 5.**
    After `kill -9` on snug, the pinned netns inode appears in no
    `/proc/*/task/*/ns/net` and in no readable `mountinfo` `nsfs` line. Assert on
    the **object**, never a process count: a netns pinned by a bind mount with no
    process attached is invisible to counting, and that is precisely the failure
    Phase 3's engine will produce. Positive control: it appeared before the kill.
16. `TestOfflineStartsNoStage` — a bare `snug <dir>` runs one bwrap and no
    `__stage` process. Positive control: a `@net` run does start one.

---

## 7. `VERIFY.md`

Per plan §3c, every automated test above that carries reasoning gets a by-hand
equivalent — a command with its expected output. At minimum:

- the netns comparison from criterion 2: two `readlink` calls and their expected
  relationship, with the instruction to refuse an empty side;
- the thread sweep, spelled `/proc/<stage>/task/*/ns/net`, with the note that
  `/proc/<stage>/ns/net` answers a different question and will lie;
- the teardown check from criterion 5, on the namespace object;
- `snug <dir> -- sh -c 'exit 42'; echo $?` → `42`, and the signal-death case, and
  Ctrl-C reaching the payload — the exit-status contract across the extra
  process, which is the class of thing a user finds rather than a test;
- `ping -c1 127.0.0.1` inside a `@net` sandbox, as the by-hand form of the `lo`
  fix.

---

## 8. Deferred, with reasons

Nothing in the plan's Phase 1 Work list is dropped silently. These are moved, and
each says where to.

| deferred | to | why |
|---|---|---|
| **The control listener** — pathname socket, accept loop, run-directory guards, the 108-byte `sockaddr_un` budget check | Phase 2 | Phase 1 has no client for it; attach is the feature that needs one. The spec Phase 2 inherits: `$XDG_RUNTIME_DIR/snug/stage-<pid>`, distinct from `runtimeDir()`'s `run-<pid>`; a `Validate`-time refusal of any `Mount.Host` at or under it; **no `/tmp` fallback**; `prepareHostTmpDir`'s guards *shared* rather than copied; bind under `umask(0177)` in a 0700 directory. |
| **`newuidmap`/`newgidmap` and the subuid delegation** | Phase 3 | §3.6. No consumer until the engine moves into the stage. `Topology.Subuid` exists, is derived, and `TestPhase1DelegatesNoSubuids` makes the flip conscious. |
| **The stage0 privileged re-exec** | deleted, conditional on Step 0 | With a single-uid map there is no privileged transition, so no `secureexec` and no CLOEXEC-clearing dance. If Step 0 is red it comes back and so does review §1.3. |
| **`Topology.Attach` being raised, and by what** | Phase 2 | Not a CLI flag (the `default_profile` trap) and not "a stage exists" (that would make `@net` silently enable attach, and net and attach are unrelated). The remaining candidate is a profile with its own abuse sentence, which per the project's own rule needs a case argued first. The floor and the `Join` land now so Phase 2 has to change a golden to raise it. |
| **A pidfd table for children** | Phase 2 | Phase 1 has exactly one child. `SysProcAttr.PidFD` is used on the bwrap fork and the descriptor is kept; every kill/wait goes through `os.Process`, which is already pidfd-backed. A table is a Phase 2 shape. The raw-pid exceptions stay exactly the three the plan names: bwrap's `--json-status-fd`, pasta's `--netns`/`--userns` paths, and `newuidmap`'s argv (absent in Phase 1). **§3a loses ground rather than gaining it and should say so**: `PastaArgs`' pid-bearing path was already the named exception, and it now carries an fd number across a process boundary as well. |
| **A `--dry-run` `attach` block** | Phase 2 | Nothing to describe. |
| **The injected `~/.claude/CLAUDE.md` mentioning the topology** | Phase 2 | The payload cannot see the stage and nothing it can do changes. It must be revisited when a co-resident payload becomes possible, where "you are one of several processes in one trust domain" is a fact an agent should act on. |
| **Starting pasta before bwrap** | Phase 3 | Phase 1 keeps today's order for the minimum diff. Phase 3 wants pasta up before any payload exists, and the attractive mechanism — a socket created in N before P1 leaves stays bound to N forever — is elegant and **unmeasured**. Measure it before designing around it. |
| **`TestGoldenEngineView`, `TestGoldenAttachSpec`** | Phases 3, 2 | `TestGoldenStageSpec` lands now; the other two need the things they describe. |
| **CLAUDE.md's two "abstract sockets unreachable by construction" sentences** | Phase 3 | Phase 1 does **not** require them to change: 0b closed both SUPERVISOR §5 bullets with the hole-open case as its control, and the only snug processes in N are bwrap and the sandbox's own init. Confirm this reading again before Phase 3, where it may stop being true and where criterion 4 requires the sentences to change in the same commit. |

One CLAUDE.md change **is** owed by this phase, in commit B: a bullet in "Facts
about this environment" recording that `unshare(CLONE_NEWNET)` is per-task, that
`/proc/self/ns/net` reports the old namespace after it, that the only whole-process
join point is `execve` on a locked thread, and that any verification must sweep
`/proc/<pid>/task/*/ns/net`. That is exactly the kind of expensive-to-learn fact
the file exists to hold, and it cost 0b a scheduler-dependent false green.

---

## 9. `TODO.md` entries this phase owes

Per the definition of done, every confirmed finding is fixed or written down with
a severity. These are found-and-not-fixed-here:

1. **`MS_REC|MS_PRIVATE` in P1 has no test in Phase 1**, and the obvious
   assertion cannot be one: a mount namespace created in the same clone as a user
   namespace already shows zero `shared:` peer groups on this kernel, so the
   check passes with the call deleted. Its only real test arrives with the
   Phase-3 graft. Severity: low here, high the moment a graft exists.
2. **`runtimeDir()` (`cmd/snug/identity.go:19`) has none of
   `prepareHostTmpDir`'s guards** and falls back to a predictable
   `/tmp/snug/run-<pid>` when `XDG_RUNTIME_DIR` is unset. MEASURED:
   `os.MkdirAll` follows a pre-planted symlink-to-directory and does not chmod an
   existing one, so the ssh-agent proxy socket lands in the attacker's directory
   with the attacker's mode. Severity: low (same host, pid guess, sticky `/tmp`),
   but it is the directory Phase 2's control socket must **not** live in.
3. **bwrap's `--unshare-all` uses the `-try` spellings for `user` and
   `cgroup`**, so on a host with unprivileged user namespaces disabled the
   sandbox silently gets none. INFERRED from bwrap's flag list — measure before
   acting. Severity: medium (invariant 5), and it is a non-stage-path defect, not
   Phase 1's to fix inside a phase that must add and remove nothing.
4. **`pidfd_getfd(2)` is absent from `deniedSyscalls`** and was measured working
   inside a real sandbox (NOCGO-RESEARCH). Independent of this plan; the fix is
   to deny `pidfd_getfd` only and leave `pidfd_open` allowed.
5. **A user profile with `tmpfs = ["/run"]` plus `@podman-socket` is ACCEPTED by
   `Validate`** (0c, in shipped snug): the sandbox starts and the payload writes
   `/run/snug/bin/git` and runs it. `snugsOwn` is keyed on the exact guest path,
   so a mount at an **ancestor** of `StagedBinDir` is not refused. Detected
   loudly by `--dry-run` via `IsShadowSlot` ("IS WRITABLE from inside, which it
   must never be"), so it is detected-but-not-refused rather than silent.
   Severity: medium. The fix — extend the refusal from "a mount AT `StagedBinDir`"
   to "a mount covering `StagedBinDir`" — is the same fix Phase 3 needs anyway.
6. **P1 must stay dumpable** for pasta to open `/proc/<P1>/fd/<n>`, and
   `hidepid=2` breaks it. That `PR_SET_DUMPABLE=0` belongs on the sandbox's init
   in Phase 2 and **never** on P1 is a constraint that must be written into the
   code, not just here. The dependency is not new — today's `waitForNetDevice`
   and `--userns` need the same — but its reason is now load-bearing.
7. If Step 0 is red: **the subuid range is delegated with no profile behind it**
   (review §1.3), restored. Severity: medium.

---

## 10. Exit criteria, restated as a checklist

1. Behavioural tests in §5 green and **unedited**; the golden diff is exactly the
   four files in §5, and commit A's diff is exactly the new block.
2. `TestSandboxNetnsIsTheStagesPinnedNetns` green, plus the thread sweep. The
   bwrap argv is byte-identical in both topologies for everything except the
   unshare set, so **golden argv is necessary and not sufficient here** and the
   behavioural assertion is the whole coverage.
3. `TestNoDescriptorInThePayloadResolvesToAnInodeOpenInTheStage` green, and the
   four-descriptor assertion with its positive control.
4. The stage is one-shot: `TestTheStageExitsWhenTheSandboxFailsToStart` green,
   and `everRan` appears nowhere.
5. `TestTheStageLeavesNoNamespaceObjectAfterSIGKILL` green, asserting on the
   namespace object.
6. `--dry-run` prints the topology block, and it is honest in both commits.
7. **`redteam` has run against the merged stage**, aimed at what this phase
   actually creates — not at the PoC, which is a different program: P1's
   descriptor table at the moment of the fork; the `__stage1`/`__stage2`/
   `__innetns` re-exec path and whether anything reachable can influence what it
   execs; whether a sandboxed payload can name, reach or influence the socketpair;
   whether anything in the payload's reach can observe or enter N; and the
   exit-status and signal paths across the extra process. Every confirmed finding
   fixed or in `TODO.md` with a severity, and every one a named regression test.
8. `VERIFY.md` covers §7 by hand.
9. `make gate` and `make integration` (`SNUG_REQUIRE_SANDBOX=1`) green.
