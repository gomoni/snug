# Round 2 — the verdict on the Phase 1 fixes

Round 1 found five things wrong with the merged stage. This round fixed all five,
wrote regression tests for all five, and then ran three independent red teams at
the result. This document consolidates what came back.

Its inputs are the two fix agents' reports, the ratchet agent's fault-injection
pass, and three red-team runs done without sight of each other. Where a fixer and
a red team disagree, this document says which one it believes and why. **It does
not average them.** Everything marked MEASURED below was executed on this host
during the round; two of the round's central claims were re-measured
independently while writing this file, and those are marked as such.

The short version: **four of five are closed, one is not, and the one that is not
is the one whose fix report says it is.**

---

## 1. The five findings, one at a time

### F1 — the args memfd, read-write, in the payload: **CLOSED**

The fix went at the class rather than the symptom. `internal/fdseal` derived its
keep list from `cmd.ExtraFiles` and exempted it from the CLOEXEC sweep, and that
exemption *was* the leak: Go's `syscall/exec_linux.go` installs a child's
descriptors with `dup3(source, target, 0)` and **never closes the source**, so
every source numbered above its target survived into the child as a second copy.
P1 receives P0's descriptors at 5..9 and bwrap wants them at 3..7; sources 8 and
9 survived, and 9 was the args memfd. The keep list is now empty by construction
and `internal/stage/innetns.go` seals again at the one raw `syscall.Exec` in the
chain.

All three red teams enumerated the payload's descriptor table by execution, on
between one and five policies each, and all three got the same answer: **exactly
0, 1, 2.** One of them went further and read `/proc/1/fd` from inside the sandbox
— bwrap is pid 1 of the sandbox's pid namespace, same uid, dumpable, so it is
listable — and found only stdio plus bwrap's own eventfd. bwrap closes the args
memfd, the seccomp fd, `--json-status-fd` and `--block-fd` before it execs. The
sandbox's pid namespace holds only bwrap and the payload, so there is no
neighbour to read from, and `/proc/<P1>` is not in the sandbox's `/proc` at all.

Two things about this that should be written down rather than assumed:

- **The surviving exemption is stdio, and it is not empty.** `safeStdio`
  substitutes `/dev/null` for a *directory* on 0/1/2. A regular host **file** on
  stdio stays readable and writable through `/proc/self/fd/N` inside the sandbox
  regardless of any grant. That is the launcher's own redirection and is
  arguably correct, but it is the other half of the exemption CLAUDE.md's own
  bullet warns about ("when you exempt something from a security sweep, ask what
  the exemption itself lets through"), and no test states it.
- **`startPasta` is the one fork in the tree with no `fdseal.SealFor` call**
  (`internal/sandbox/netns.go:113`). Harmless today — every descriptor P0 holds
  is CLOEXEC by construction (`MemfdCreate(..., MFD_CLOEXEC)`, `os.Pipe`) — and
  exactly the class F1 says not to leave to care.

### F2 — the deadlock and the fail-open abort: **one half closed, one half OPEN**

This finding had two defects in it and they came apart in the fix. They also come
apart in the verdict.

#### F2a, the deadlock: **closed for the demonstrated spelling only**

Root cause: `netHelper.done` was a buffered channel carrying the wait error with
three readers, `waitForNetDevice` consumed the single value, and `stop()` blocked
forever on a second receive. `done` is now **closed** rather than written to,
with `waitErr` published before the close. The ratchet agent reverted the channel
to the old design and got a genuine 30-second timeout out of
`TestAStalledPastaNeitherHangsNorRunsThePayload`; restoring made it green in
1.9s. That is a real fix with a real test.

But `stop()`'s final `<-h.done` after `Kill()` is **still unbounded**, for a
different reason, and a red team hung snug on it with a goroutine dump pinning
`netns.go:180`. `cmd.Stderr` is a `*strings.Builder`, so Go creates a pipe and
`cmd.Wait()` blocks until the stderr copier sees EOF; `Kill()` kills only the
direct child, and any surviving descendant holds the write end open forever. A
fake pasta shaped `sleep 600 & exit 0` — the shape any wrapper script has —
hangs snug for as long as you leave it, with the payload parked, and the human's
only remaining move is SIGKILL, which then runs the payload 3/3.

The same red team is honest that it **could not** construct this with the real
passt binary: snug passes `--foreground` and a foreground pasta does not fork.
So it is a robustness defect and not attacker-reachable, and it is low. It is
recorded because the comment the fix added at that exact line — "the last one
returns immediately on a pasta that was already dead when stop was called —
which is precisely the case that used to hang" — is now the second true-sounding
sentence in this area that a measurement contradicts, and because the committed
test's fake (`sleep 0.3; exit 1`) has no surviving descendant and therefore
narrowly avoids the spelling that still breaks.

#### F2b, the fail-open abort: **STILL OPEN, and this is the finding of the round**

The fix introduced `internal/sandbox/parked.go`: one guard, deferred the instant
the child pid is known, used by both arms of `Run`, handling SIGINT/SIGTERM/
SIGHUP/SIGQUIT while parked only, killing the parked child by pid and then
waiting for the sandbox's pid namespace to collapse before anything closes. Every
word of that is true of the guard **once it is armed**. The defect is *when* it
is armed.

`park(childPID, …)` is registered only after `readChildPID(statusR)` returns —
`internal/sandbox/exec.go:178` on the single-process arm and `:253` on the stage
arm. bwrap forks the payload, and parks it on `--block-fd`, well before it writes
its `--json-status-fd` document. Between those two moments a payload exists
inside the sandbox, snug holds the only write end of the block pipe, and nothing
at all is installed: SIGTERM has its default disposition, snug dies in
microseconds, the pipe EOFs, and the payload runs.

Two red teams found this independently, from different directions, with different
signals. **That convergence is the strongest signal in the run**, exactly as the
memfd leak was last round.

| lens | how it was reached | result |
|---|---|---|
| red team A | SIGKILL sweep at fixed delays after launch, then a concurrency run | payload ran and an orphan survived from d≈0.02s to d≈0.11s; under 10 concurrent runs with random delays, 7/10 orphaned sandboxes and 7/10 markers written |
| red team B | SIGTERM at a fixed 60 ms offset, launched through a harness that resets the disposition to `SIG_DFL` and `setsid`s | payload ran 10/10, orphaned bwrap left 10/10; sub-millisecond reap proves no `abort()` ran |

**Re-measured while writing this document, on this host, with `bin/snug` built
from this worktree.** Positive control first — an ordinary `snug -p @net` run
writes the marker, rc=0. Then, SIGTERM at 60 ms, six runs:

```
POSITIVE CONTROL rc=0 marker=True
  run 0..5   rc=-15   payload_ran=True   orphans=1
TOTAL delay=0.06 sig=SIGTERM: payload ran 6/6, orphaned sandbox 6/6
```

And at 20 ms, four runs — a different failure, not an absence of one:

```
  run 0..3   rc=-15   payload_ran=False  orphans=3/4
```

with the orphan, watched for six seconds rather than one, still there:

```
488782  8553  S  /usr/bin/bwrap --args 7 -- /bin/sh -c echo pwned > …/PWNED; sleep 30
marker: False
```

So there are two distinct failure modes in the pre-arm window, and they should
not be collapsed: at ~40–110 ms the orphaned sandbox **runs the payload**; at
~20 ms the orphaned sandbox does not run the payload but **outlives snug
indefinitely** (ppid 8553 is the subreaper — no snug, no `__stage2`, no pasta
remain). The second is invariant 4 broken on its own terms: the helper did not
die with the sandbox; the sandbox outlived every snug process.

**Who I believe, and why the fix report is not wrong so much as narrow.** The fix
agent measured "0/10 for each of three signals, against a control build at 4/5",
and I believe that measurement. It was taken with a stalled fake pasta, which
widens the window *after* `readChildPID` has already returned — the same shape
`TestKillingSnugWhileThePayloadIsParkedDoesNotRunIt` has, which signals only
after `findDescendant(..., isComm("bwrap"), 10s)` returns and therefore pays a
whole `/proc` scan before it fires. Both measurements are correct about different
intervals. The guard works; it is installed too late to cover the interval that
matters most, and the test cannot see the gap because it measures the interval
the guard already covers.

This is **not a Phase 1 regression.** Red team A reproduced the SIGKILL half
against `main` at 0349b09, 3/3. Red team B built HEAD via `git archive` and
measured SIGTERM at 20 ms running the payload 6/6 there versus 0/6 on this
worktree, and 6/6 on both at 60 ms. Phase 1's fix narrowed the window; it did not
close it.

The narrowest fix both red teams converge on: arm a guard **before the payload
can exist** — a pid-less `park(0, …)` registered immediately after
`st.StartSandbox`/`cmd.Start`, filled in with the child pid when `readChildPID`
returns — or move the block-fd release decision behind a guard installed before
bwrap is forked at all.

#### F2b, second correction: the recorded mechanism is measurably wrong

`parked.go`'s doc comment and the matching `TODO.md` entry both attribute the
surviving SIGKILL residual to a *race*: "bwrap's `--die-with-parent` has to
travel two process hops … while the EOF is immediate, so it loses the race", and
"a SIGKILL has to land inside a few tens of milliseconds to hit it". A red team
isolated the mechanism from snug entirely, with a matched pair, killing the outer
bwrap **two full seconds** after start — long past any fork-time arming race:

```
CONTROL  (no --block-fd, init not parked):  kill outer bwrap → OUTER dead, INIT dead
PARKED   (--block-fd on a fifo, no EOF):    kill outer bwrap → OUTER dead, INIT ALIVE
                                            then EOF the pipe → INIT execs the payload
```

bwrap does not arm the sandbox init's `--die-with-parent` until the `--block-fd`
read returns. The init is **unprotected for the whole parked window**, not for a
few tens of milliseconds at the start of it. This matters more than an
informational correction usually does, for two reasons: it is the load-bearing
justification for where `TestTheStageLeavesNoNamespaceObjectAfterSIGKILL` places
its kill (`stage_test.go:836-846`), and it is the sentence in `TODO.md` that sets
the residual's severity and points at the fix. A future reader who believes
"millisecond-wide arming race" will reasonably widen the readiness bar and
silently re-open the coverage gap. The correct sentence is: *bwrap does not
protect a sandbox init that is still parked on `--block-fd`, for as long as it is
parked.*

#### F2b, third defect, new: `parked` overrides an inherited `SIG_IGN`

`park` calls `signal.Notify` unconditionally. Where the launcher had that signal
at `SIG_IGN` — which bash gives background jobs for SIGINT and SIGQUIT, and which
is the normal case for CI wrappers and `nohup`-shaped launchers — two things go
wrong at once. snug now catches a signal it was told to ignore, aborts the
sandbox and kills the payload; and `signal.Reset(s)` restores the *inherited*
disposition, which is `SIG_IGN`, so the `syscall.Kill(os.Getpid(), s)` that
follows is a no-op and snug does not exit. MEASURED by a red team: `SigIgn` bit
1 goes 0 → 1 across the handler, snug is still alive 21.3 s later with both
bwraps already gone, while a control launched with SIGINT at `SIG_DFL` exits
`rc=-2` in 0.05 s. Low severity — not reachable by the payload — but it compounds
the unbounded `stop()` above into a process killable only by SIGKILL, and SIGKILL
there runs the payload.

#### One sub-mechanism I will not claim as proven

`abort()`'s `awaitCollapsed` wait is justified by a measurement of "1 run in 5
still ran with the kill alone". The ratchet agent removed only that wait and
could not reproduce a distinguishable failure across 15 trials. Neither result
disproves the other — a 1-in-5 race is environment-dependent and a 15-trial
sample is thin — and the wait is correct on the kernel's own ordering
(`zap_pid_ns_processes` reaps every namespace member before the init becomes a
zombie) whether or not the race reproduces today. Keep it. But its stated
frequency is one agent's single measurement and should not be quoted as settled.

### F3 — the capability bounding set: **CLOSED**

The cleanest fix of the round. Root cause was not in snug's argv at all: bwrap
drops the bounding set only when it judges *its parent* unprivileged, and under
the stage the parent is uid 0 in a userns with a full capability set. The fix
emits `--cap-drop ALL` unconditionally on every topology, routed through the
resolved policy — invariant 6, and CLAUDE.md's own "pass every security-relevant
flag explicitly even when it matches the current default".

Verified three ways this round. Two red teams read `CapBnd` out of
`/proc/<pid>/status` rather than inferring it from the argv, and got
`0000000000000000` on `NetnsSandbox`, `NetnsStage`, `NetnsHost`,
`@podman-socket`, and `--no-seccomp -p @net` (the drop is independent of the
filter), for both the payload and the sandbox's pid 1. The ratchet agent removed
the flag and got the golden diff immediately (six `testdata/*.bwrap.txt` files,
one line each) plus the integration test failing on the **stage subtest only**,
with `CapBnd 000001ffffffffff` — the exact reported value — while the offline
subtest stayed green, which is precisely the claim the fix made about where
bwrap's inference was already correct.

### F4 — the `--dry-run` bwrap block: **CLOSED for what it claims**

The defect was measured before it was fixed, with the positive control first: a
host listener answering on `127.0.0.1:19511`, then the argv **exactly as
`--dry-run` printed it** for `-p @net` landing in the operator's own network
namespace (`net:[4026531833]`, identical to the host's) and **reaching** host
loopback, while real `snug -p @net` sat in `net:[4026532433]` and was refused.

The chosen fix keeps the argv byte-faithful and puts prose at both ends of it,
and — importantly — the note closes with a by-hand check that actually settles
the question (two `readlink`s that must differ, with an empty answer declared a
failed check rather than a pass) rather than only warning about one that does
not. A red team tried to find a rendering the note does not cover and could not:
there is only one (`describeBwrap`), it is keyed on `p.Topology.Netns` rather
than on a string match, and `@podman-socket` — which reaches `NetnsStage`
through an `include` rather than through `-p @net` — gets it. Both new tests
were falsified against the pre-fix body.

Residual, informational and one layer down from what was fixed: the printed argv
still omits `--seccomp` and carries placeholder fd numbers (`--ro-bind-data 10
/etc/resolv.conf`), on **every** topology. The isolated and host branches now
print "this argv determines the network posture on its own", which is true of the
netns and only of the netns — a reviewer who hand-runs the isolated argv gets a
sandbox with `Seccomp: 0` and nothing on screen says so. Same class as F4, not
the same severity, and the fix is a sentence in the same voice.

### F5 — the fd bounds check: **CLOSED, and it was never reachable**

`checkFDBudget` is called on both sides of the control socket, `maxPassthrough`
is derived from the two constants rather than re-typed, the error names the fix
(raise `fdNetnsN`, do not lower the count), and the budget is now a line in the
stage golden. A red team confirmed it cannot be driven anywhere near 58: a real
`@net` policy uses 6 descriptors and `@podman-socket` 7, and no TOML key produces
a `KindData` mount, so the quantity is not attacker-influenced. Correctly
guarded, informational as rated, and the ratchet agent added the missing
`stage.Start` call-site test on top.

---

## 2. What is new this round

Deduplicated across the three lenses, ranked. Where two agents found the same
thing independently, it is flagged — that is the pattern that produced last
round's strongest result.

### N1 [medium] The parked guard is armed after the payload already exists

**Found independently by two of the three red teams**, by different signals
(SIGKILL sweep; SIGTERM at a fixed early offset) and re-measured a third time
while writing this document. SIGTERM to a snug 60 ms into a `-p @net` run
executes the payload, writes to the persistent target, and leaves an orphaned
bwrap — 6/6 here, 10/10 and 7/10-under-concurrency in the red-team runs — on a
run that reported `rc=-15`. Full detail in §1 F2b above. Realistic triggers, all
mundane and all outside the payload's control: Ctrl-C on a slow start, a CI job
cancel, `timeout -s KILL`, `systemd` stopping a unit, the OOM killer, a human
`kill -9` on a snug that looks stuck.

What the orphaned payload keeps is *not* weakened confinement — measured
`CapEff 0`, `CapBnd 0`, `NoNewPrivs 1`, `Seccomp 2`, no `~/.ssh`, host loopback
refused, no egress once pasta dies with P0 — it is unbounded execution time and
persistent write access to the target, plus a netns object that lives as long as
the orphan does.

### N2 [medium] An orphaned sandbox survives snug in the same window even when the payload does not run

Measured here at d≈20 ms: marker absent after six seconds, `bwrap --args 7 --` still
running, reparented to the subreaper, with no snug and no stage left. Same window,
same root cause, different symptom, and it is invariant 4 in its plainest form.
It is invisible to both existing leak tests — `TestNoLeakedHelpersAfterSIGKILL`
counts pasta processes (which correctly die), and
`TestTheStageLeavesNoNamespaceObjectAfterSIGKILL` deliberately waits for the
*payload* to appear before killing and therefore never enters this window.

### N3 [informational, but load-bearing] The recorded mechanism for the SIGKILL residual is wrong

`--die-with-parent` is not "losing a race"; it is not armed on the sandbox init at
all until the `--block-fd` read returns. Matched-pair measurement in §1 F2b. It
is informational only in the sense that nothing new is reachable — and it is the
sentence that decides where a future editor puts a kill point and what fix they
reach for, so it should be corrected in `parked.go`, in `TODO.md`, and in the
comment at `test/integration/stage_test.go:836-846`.

### N4 [low] `netHelper.stop()`'s post-`Kill` receive is unbounded

`cmd.Wait()` waits on the stderr pipe, which a surviving pasta descendant holds
open. Not reachable with the real passt (`--foreground`, no fork). Detail in §1
F2a. Bound the final receive, or hand pasta an `*os.File` for stderr so the wait
does not depend on a descendant closing a pipe.

### N5 [low] `parked` overrides an inherited `SIG_IGN` and then swallows its own re-raise

Detail in §1 F2b. Two consequences: a signal the launcher deliberately ignored
now kills a payload mid-run, and snug then does not exit.

### N6 [informational] Two concurrent stage sandboxes are isolated — and nothing tests it

The third red team's only finding, and it is a coverage gap rather than an
exposure. Two simultaneous `@net` sandboxes get distinct netns
(`net:[4026533348]` vs `net:[4026533626]`), B cannot reach a listener A binds on
`127.0.0.1` or on A's own `snug0` address, and each P1 has its own pasta aimed at
its own `/proc/<P1>/fd/63`. The shared fixed fd numbers (3/4/63) live in separate
process tables. `grep -niE 'two sandbox|concurrent|simultaneous|cross'` over
`test/integration` returns nothing: every named stage test operates on a single
sandbox. This is the one piece of genuinely new mechanisable ground the stage
topology creates, and it holds.

### N7 [informational] F1's surviving exemption is a regular host file on stdio

`safeStdio` substitutes `/dev/null` for a directory only. Pre-existing, arguably
correct, unstated by any test. §1 F1.

### N8 [informational] The printed bwrap argv still omits `--seccomp` on every topology

§1 F4. The new note is scoped to the netns and is accurate; the complete
topologies' new parenthetical is true of the netns and reads as broader than it
is.

### N9 [informational] `fdNetnsN = 63` silently requires `RLIMIT_NOFILE > 63`, and no error says so

Measured by a red team at `ulimit -n` 64/40/20/12: every case fails **closed**,
with no payload, which is the important half. But the three errors it produces
(`creating the control socketpair: too many open files`; `__stage1: pinning N at
fd 63: bad file descriptor`; `stage: bwrap did not start: fork/exec
/proc/self/exe: bad file descriptor`) name neither the constant nor the fix. The
one place in this phase that misses "errors name the fix".

### N10 [informational] `startPasta` is the one fork with no `fdseal.SealFor`

§1 F1. Harmless today by construction; the class F1 exists to close.

### N11 [informational] `readChildPID` has no timeout

Noticed while a red team was feeding snug fake bwrap binaries. Two fake shapes —
write a bogus child pid, or never report — hang snug indefinitely, but only
because a shell fake keeps `statusW` open; that is an artifact of the fake and
not of snug. Worth knowing that nothing bounds that read.

### Recorded so it is not rediscovered as a regression

A same-uid **host** process can reach `/proc/<P1>/fd/63` by name and `setns` into
the sandbox's netns, because `cap_capable` grants `CAP_SYS_ADMIN` in a user
namespace whose owner uid matches its own euid. P1 must stay dumpable for pasta
to work at all; the same is true of `/proc/<bwrap-child>/ns/net` on the pre-stage
path; and the sandboxed payload cannot see `/proc/<P1>` at all, being in a
separate pid namespace. Out of scope by the threat model, already recorded in
SUPERVISOR-PHASE1-SPEC §9 item 6.

### What held, worth pinning

Every red team ran the project's headline negatives against the new topology with
its live positive control first, and all of them held: host loopback TCPv4 and
TCPv6 refused against listeners that answered from the host; the host's LAN
address and gateway refused; abstract sockets unreachable by name and absent from
`/proc/net/unix` inside; egress working; `lo` up with `127.0.0.1/8` and `::1/128`
(§3.5's fix is real). Namespace escalation from inside the new topology — which
now has a privileged ancestor userns — failed on every route tried:
`unshare(CLONE_NEWUSER/NEWNET/NEWNS)` EPERM, `NS_GET_PARENT` and `NS_GET_USERNS`
EPERM, setgroups deny, ptrace EPERM, `Seccomp 2` with one filter on the stage
path. `/proc/1/environ` is empty inside the stage sandbox even when snug was
launched with `SSH_AUTH_SOCK` and a test token set — the 106-variable leak stays
closed one process further out. Exit status survives the extra process (`exit 42`
→ 42, `kill -TERM $$` → 143). Killing P1, the outer bwrap or the sandbox init, in
the parked window or in steady state, collapses the whole tree cleanly. A pasta
that is SIGKILLed mid-run fails **safe**: the sandbox loses connectivity and never
gains reachability, with the warning snug promises. And the Phase-1 control
channel has no pathname anywhere, so §3.3's "nothing running as your uid can
reach the stage, because there is no name to reach it by" is structurally true
today.

---

## 3. Which regression tests were proven able to fail

This project's canonical failure is a test that could never have failed passing
cleanly for as long as it existed. The ratchet agent fault-injected every fix and
recorded which way each test moved. That pass is the most valuable artifact of
the round, and its honest negatives are the most valuable part of it.

**Proven able to fail, each red under fault injection and green on restore:**

| test | the fault that made it red |
|---|---|
| `TestSealingClosesTheSOURCEDescriptorsExecPassesDown` | re-exempting `cmd.ExtraFiles` in `SealFor`. It also carries its own positive control — an unsealed fork asserting the leak is reproducible on this Go version — so it cannot pass vacuously if Go ever starts closing its sources. |
| `TestThePayloadInheritsNothingButStdio` | `sealExcept` made a no-op: failed with `9 -> /memfd:snug-args (deleted)`, byte-identical to the original finding. **Partially proven only** — see below. |
| `TestAStalledPastaNeitherHangsNorRunsThePayload` | the old buffered `done` channel: genuine 30 s timeout. |
| `TestKillingSnugWhileThePayloadIsParkedDoesNotRunIt` | signal interception disabled entirely: red 3/3 signals, every time. **Partially proven only** — see below. |
| `TestTheCapabilityBoundingSetIsEmptyOnEveryTopology` | `--cap-drop ALL` removed: red on the stage subtest with `CapBnd 000001ffffffffff`, green on the offline subtest, plus the six-file golden diff. |
| `TestGoldenBwrapNote` | `describeBwrap` reverted: red on all three `NetnsOwner` cases. |
| `TestTheStagedArgvIsNotPrintedAsSelfContained` | same fault: reported all four missing phrases by name. Its premise controls query the argv **slice**, not the rendered text, because the note itself contains the strings `--unshare-net` and `--unshare-all`. |
| `TestTheFDBudgetRefusesACollisionWithThePinnedNetns` | `checkFDBudget` made a no-op. |
| `TestStageStartRefusesASandboxLargeEnoughToReachThePinnedNetns` | deleting `Start`'s own `checkFDBudget` call — and proven **non-redundant**, since the older unit test stayed green under that fault. |

**Proven only partially, and each caveat matters:**

- `TestThePayloadInheritsNothingButStdio` did **not** go red under the naive
  fault (re-exempting `ExtraFiles` in `SealFor`, i.e. the original bug pattern).
  A second sealing layer in `innetns.go` closed most of the leaked sources anyway
  in this build's fd layout. That is genuine defence in depth rather than a
  vacuous test — the unit test is the sensitive control on that mechanism — but
  it means the integration test is not the guard on `SealFor` that its name
  suggests.
- `TestKillingSnugWhileThePayloadIsParkedDoesNotRunIt` did **not** go red under
  the narrower fault of removing `awaitCollapsed` alone, across 15 trials. And,
  per §1 F2b, it signals only after a `/proc` scan, so it measures the ~10 ms the
  fix covers and skips the ~60 ms it does not. It is a real test of a real
  property; it is not a test of the window the finding is actually about.

**Not proven able to fail, named explicitly:**

- **`TestSealForRefusesAClosedExtraFile`** — added with the F1 fix, never
  fault-injected. A hypothesis until it is.
- **Everything gated behind `SNUG_TEST_NET=1`** — `TestEgressWorks` did not run
  in the ratchet pass at all (the gate is deliberate and the agent correctly
  declined to reach the public internet). That is an entire class of assertions,
  including the one that would catch pasta attached to the wrong namespace, that
  nobody exercised this round.
- **`TestPodmanBuildIsFilteredEndToEnd`** fails on this host for reasons
  reproduced identically on a pristine `git archive HEAD` tree and with
  `--cap-drop ALL` removed — a host/engine condition, not a regression. But
  `@podman-socket` is a `NetnsStage` case, so the one end-to-end test that
  exercises the stage topology under the container proxy is currently telling us
  nothing.
- The spec's §6 item 10, `TestNoStageThreadRemainsInTheSandboxNetns`, exists as a
  sub-assertion inside `TestSandboxNetnsIsTheStagesPinnedNetns` (via
  `threadNetnsIDs`) rather than as a named test. Adequate, but a `grep` for the
  name in the spec finds nothing.

---

## 4. What Phase 1's exit criteria still require

Against SUPERVISOR-PHASE1-SPEC §10.

| # | criterion | state |
|---|---|---|
| 1 | behavioural tests green and unedited; golden diff exactly the four files | **partially met.** No existing test was edited, and no golden moved beyond the expected set — except that `--cap-drop ALL` correctly touched six `internal/policy/testdata/*.bwrap.txt` files rather than the one the spec predicted. That is a *legitimate* security change with a reviewed one-line-per-file diff, but it is a diff §5 did not anticipate and it should be read as such rather than as a re-baseline. |
| 2 | `TestSandboxNetnsIsTheStagesPinnedNetns` plus the thread sweep | **met.** Green, with the thread sweep folded in, and independently re-measured by two red teams (distinct netns ids, egress up, host loopback refused, with the payload emitting a marker first). |
| 3 | no descriptor in the payload resolves to an inode open in the stage; four-descriptor assertion with its control | **met.** F1 closed, verified by execution on three topologies and five policies by agents who could not see each other's work. |
| 4 | the stage is one-shot; `everRan` appears nowhere | **met.** `TestTheStageExitsWhenTheSandboxFailsToStart` green, and a red team drove it independently with a fake bwrap exiting 3 (`snug` exit 69, `reading bwrap status: EOF`, no stage left, payload never ran). |
| 5 | teardown asserts on the namespace object | **met for the window it tests, and that window has a hole.** The test is green and correct. It kills after the payload appears, so it never enters the pre-arm window where an orphan lives and pins the netns for as long as it lives (N1/N2). |
| 6 | `--dry-run` prints the topology block, honest in both commits | **met**, and improved by F4's note. Residual N8 is a truthfulness gap one layer down, not a failure of this criterion. |
| 7 | `redteam` has run against the merged stage; every confirmed finding fixed or in `TODO.md` with a severity, each a named regression test | **NOT met.** Three runs happened, which more than discharges the "has run" half. But N1, N2, N4 and N5 are confirmed and are neither fixed nor written down, and none has a regression test. §5 below is the writing-down half; the tests and the fix are still owed. |
| 8 | `VERIFY.md` covers §7 by hand | **partially met.** §12 landed with 121 new lines: the netns comparison, the thread sweep with its "`/proc/<pid>/ns/net` answers a different question and will lie" note, teardown on the namespace object, the exit-status contract, and `lo`. Missing: `grep -c CapBnd VERIFY.md` is **0**, so F3's guarantee has no by-hand line; the parked-window signal check has none; and the F4 note's own two-`readlink` recipe — which the fix agent verified as printed — is not in VERIFY.md either, though §12 has an equivalent. |
| 9 | `make gate` and `make integration` (`SNUG_REQUIRE_SANDBOX=1`) green | **not met.** `make gate` is green (§6). `make integration` is not clean: `TestPodmanBuildIsFilteredEndToEnd` fails for a host/engine reason reproduced on a pristine HEAD tree, and `TestEgressWorks` is skipped behind `SNUG_TEST_NET=1`. Neither is caused by this branch. Both mean the criterion as written cannot currently be evaluated on this host. |

**Cannot be evaluated yet:** criterion 9's `make integration` half, until either the
engine condition behind `TestPodmanBuildIsFilteredEndToEnd` is understood or the
test is quarantined with a reason; and any claim about egress correctness under
the stage, until someone runs the `SNUG_TEST_NET=1` half deliberately.

---

## 5. `TODO.md` entries, ready to paste

These go under the existing `## Supervisor Phase 1 — found-and-not-fixed-here`
section. The first one **replaces** the existing
`### The parked-payload window survives SIGKILL of snug…` entry, because that
entry's mechanism and its window are both measurably wrong and leaving it in
place next to a correction is worse than either alone.

```markdown
### The parked-payload window: the guard is armed too late, and the recorded mechanism was wrong

Severity: **medium**. Pre-existing on `main` (measured there too), narrowed but
not closed by `internal/sandbox/parked.go`.

bwrap releases a payload parked on `--block-fd` on **EOF just as readily as on a
byte**, and snug's own death closes the write end. `parked.go` closes that for
every code path and for SIGINT/SIGTERM/SIGHUP/SIGQUIT — but the guard is
registered only after `readChildPID` returns (`internal/sandbox/exec.go:178` and
`:253`), and bwrap forks the payload and parks it well before it writes its
`--json-status-fd` document. In that interval nothing at all is installed.

MEASURED on this host, three times independently (two red teams and once while
writing SUPERVISOR-ROUND2.md), with an ordinary run writing the marker as the
positive control and a marker written by the payload so no negative can pass on
a sandbox that never started:

| SIGTERM to snug at | result |
|---|---|
| 20 ms | payload does NOT run, but an orphaned `bwrap` survives snug indefinitely (6 s and counting), reparented to the subreaper, with no snug, no `__stage2` and no pasta left — 3/4 |
| 40–110 ms | payload RUNS, writes the persistent target, and the orphaned sandbox keeps running unsupervised — 6/6 at 60 ms here, 10/10 and 7/10-under-concurrency in the red-team runs, on runs that reported `rc=-15` |

The payload's confinement is NOT weakened in either case (measured `CapEff 0`,
`CapBnd 0`, `NoNewPrivs 1`, `Seccomp 2`, no `~/.ssh`, host loopback refused, no
egress once pasta dies with P0). What it keeps is unbounded execution time,
persistent write access to the target, and a netns object that lives as long as
the orphan.

**Correcting the record.** The previous version of this entry, and the doc
comment in `parked.go`, and the comment at `test/integration/stage_test.go:836-846`,
all say the orphan is bwrap's `--die-with-parent` losing a two-hop race in "a few
tens of milliseconds". MEASURED false, with a matched pair killing the outer
bwrap two full seconds after start: with no `--block-fd` the init dies with its
parent; with `--block-fd` held open by a third process the init stays ALIVE and
later execs the payload. **bwrap does not arm the sandbox init's
`--die-with-parent` until the `--block-fd` read returns** — the init is
unprotected for the whole parked window, not for a moment at the start of it.
Fix these three sentences before anyone reasons from them: the wrong mechanism
points at "widen the readiness bar", which does nothing.

Narrowest fix, and both red teams converged on it: arm a pid-less guard
immediately after `st.StartSandbox`/`cmd.Start` — one that simply refuses to let
snug exit with `blockW` open — and fill in the child pid when `readChildPID`
returns. The real fix stays topological: under `NetnsStage` the namespace exists
before bwrap does, so pasta can start before any payload is forked and nothing is
ever parked. SUPERVISOR-PHASE1-SPEC §4 Step 5 kept today's ordering as the
minimum diff and §8 defers the reordering to Phase 3, because confirming the
interface is up without a process inside N is a control-protocol addition.

SIGKILL of snug in the same window is the same defect and cannot be caught; it
needs no separate entry.

**Regression test owed** (`sandbox-tester`): signal snug at a FIXED, EARLY offset
rather than after a `/proc` scan — `TestKillingSnugWhileThePayloadIsParkedDoesNotRunIt`
waits for `findDescendant(..., isComm("bwrap"), 10s)`, which costs tens of
milliseconds and therefore only ever measures the interval the guard already
covers. Assert both halves: the marker is absent, AND no descendant of the killed
snug survives 2 s later. It fails today on both, at 60 ms, with SIGTERM.
```

```markdown
### `netHelper.stop()`'s post-Kill receive is unbounded

Severity: **low** — not reachable with the real passt, which snug runs with
`--foreground` and which therefore does not fork.

`internal/sandbox/netns.go:106` sets `cmd.Stderr = &errbuf` (a
`*strings.Builder`), so Go creates a pipe and `cmd.Wait()` blocks until the
stderr copier sees EOF. `Kill()` at `:179` kills only the direct child; any
surviving descendant keeps the write end open, so `h.done` never closes and the
receive at `:180` never returns. MEASURED with a fake pasta shaped
`sleep 600 & exit 0` — the shape any wrapper script has: snug hangs indefinitely
with the payload parked, expected to fail in ~5.3 s with a named error, killed at
25 s by `timeout` instead, goroutine dump pinning `netns.go:180`. SIGKILL of a
snug in that state runs the payload 3/3.

The F2 fix changed `done` from a value-carrying buffered channel to a closed one,
which correctly fixes the three-readers bug; it left the wait unbounded. The
comment added at that line — "the last one returns immediately on a pasta that
was already dead when stop was called" — is true of a dead pasta with no
descendants and false of this one.

Fix: bound the final receive (`select { case <-h.done: case <-time.After(…): }`),
and/or give pasta an `*os.File` stderr so `cmd.Wait()` does not depend on a
descendant closing a pipe.

**Regression test owed:** the existing
`TestAStalledPastaNeitherHangsNorRunsThePayload` with its fake changed to
`sleep 600 &\nexit 0` must still finish inside `cmdTimeout`. Its current fake
(`sleep 0.3; exit 1`) has no surviving descendant and narrowly avoids the
spelling that still breaks.
```

```markdown
### `parked` overrides an inherited `SIG_IGN`, then swallows its own re-raise

Severity: **low** — not reachable by the sandboxed payload.

`park` calls `signal.Notify` unconditionally. bash gives background jobs
`SIG_IGN` for SIGINT and SIGQUIT, which is the normal case for CI wrappers and
`nohup`-shaped launchers, so two things go wrong at once: snug catches a signal
the launcher deliberately ignored and kills the payload mid-run; and
`signal.Reset(s)` restores the *inherited* disposition (`SIG_IGN`), so the
`syscall.Kill(os.Getpid(), s)` that follows is a no-op and snug does not exit.
MEASURED: `SigIgn` bit 1 goes 0 → 1 across the handler, snug alive at +21.3 s with
both bwraps already gone, against a control launched with SIGINT at `SIG_DFL`
exiting `rc=-2` in 0.05 s.

This falsifies `parked.go`'s stated contract — "so snug's own exit status is
exactly what the signal would have produced" — whenever the launcher had that
signal ignored. It also compounds the unbounded `stop()` above into a process
killable only by SIGKILL, and SIGKILL there runs the payload.

Fix: do not `Notify` a signal whose inherited disposition is `SIG_IGN` (query it
before installing), or exit explicitly with 128+N after the re-raise fails.

**Measurement note for whoever tests this:** every signal measurement must run
through a launcher that explicitly sets `SIG_DFL` before exec. Go's
`signal.Notify` hides the inherited disposition (`SigIgn` reads 0 once `park` is
armed), and two of a red team's results were artifacts of the harness until it
did this.
```

```markdown
### Two concurrent stage sandboxes are isolated, and nothing tests it

Severity: **informational** — a coverage gap, not an exposure.

MEASURED: two simultaneous `@net` sandboxes get distinct netns
(`net:[4026533348]` vs `net:[4026533626]`); B cannot connect to a listener A
binds on `127.0.0.1:9911` or on A's own `snug0` address (both
`ConnectionRefusedError`, with A's listener reachable from within A as the
positive control); each `snug __stage2` has its own pasta aimed at its own
`/proc/<its-P1>/fd/63`; the shared fixed fd numbers (3/4/63) live in separate
process tables. `grep -niE 'two sandbox|concurrent|simultaneous|cross'` over
`test/integration` returns nothing — every named stage test operates on a single
sandbox.

This is the one piece of genuinely new mechanisable ground the stage topology
creates. **Regression test owed:** two concurrent `@net` sandboxes have distinct
`/proc/self/ns/net`; B cannot reach a listener A binds on loopback or on its
`snug0` address; killing one leaves the other's netns and pasta intact.
```

```markdown
### Smaller Phase 1 residuals, all informational

- **A regular host FILE on stdio is still reachable through `/proc/self/fd/N`
  inside the sandbox, regardless of any grant.** `safeStdio` substitutes
  `/dev/null` only for a DIRECTORY. Pre-existing and arguably correct — it is the
  launcher's own redirection — but it is the surviving half of the 0/1/2
  exemption F1 closed everywhere else, and no test states it.
- **`startPasta` (`internal/sandbox/netns.go:113`) is the one fork in the tree
  with no `fdseal.SealFor(cmd)` call.** Harmless today: every descriptor P0 holds
  is CLOEXEC by construction. Exactly the class F1 says not to leave to care.
- **The printed bwrap argv omits `--seccomp` and carries placeholder fd numbers
  on every topology.** F4's note fixed the network posture; a reviewer who
  hand-runs the *isolated* argv still gets `Seccomp: 0` and nothing on screen says
  so, while the new parenthetical says the argv "determines the network posture on
  its own" — true of the netns, and only of the netns. Fix: extend the
  parenthetical on the complete topologies to name what the argv still does not
  carry, in the same voice as the stage note.
- **`fdNetnsN = 63` silently requires `RLIMIT_NOFILE > 63` on the stage path.**
  MEASURED at `ulimit -n` 64/40/20/12: every case fails CLOSED with no payload,
  which is the important half — but none of the three errors
  (`creating the control socketpair: too many open files`; `__stage1: pinning N
  at fd 63: bad file descriptor`; `bwrap did not start: fork/exec /proc/self/exe:
  bad file descriptor`) names the constant or the fix. The one place in this phase
  that misses "errors name the fix".
- **`readChildPID` has no timeout.** Two fake-bwrap shapes (write a bogus child
  pid; never report) hang snug — but only because a shell fake keeps `statusW`
  open, which is an artifact of the fake and not of snug. Recorded so nobody
  rediscovers it as a live hang.
- **`VERIFY.md` has no by-hand line for `CapBnd`** (`grep -c CapBnd VERIFY.md`
  → 0), and none for the parked-window signal check. §12 covers the netns
  comparison, the thread sweep, teardown on the namespace object, the exit-status
  contract and `lo`; F3's guarantee and F2's have nothing.
```

---

## 6. `make gate`

Run in `/home/michal/projects/plainsof/cv/snug/.claude/worktrees/forkexec-supervisor`:

```
gofmt -l . | (! grep .)
go vet ./...
go vet -tags integration ./test/integration/...
go test ./...
ok  github.com/gomoni/snug/cmd/snug
ok  github.com/gomoni/snug/internal/dockerproxy
ok  github.com/gomoni/snug/internal/engine
ok  github.com/gomoni/snug/internal/fdseal
ok  github.com/gomoni/snug/internal/policy
ok  github.com/gomoni/snug/internal/profile
ok  github.com/gomoni/snug/internal/sandbox
ok  github.com/gomoni/snug/internal/sshproxy
ok  github.com/gomoni/snug/internal/stage
```

**Green**, exit 0. Re-run with `-count=1` so a stale cache could not carry it —
also green, exit 0. (That precaution is not decoration: a stale test cache
initially hid a real failure during the F1 fix.)

`make integration` is **not** clean, and neither failure belongs to this branch:
`TestPodmanBuildIsFilteredEndToEnd` fails on a host/engine condition reproduced
identically on a pristine `git archive HEAD` tree, and `TestEgressWorks` is
skipped behind the deliberate `SNUG_TEST_NET=1` opt-in.

---

## 7. Is Phase 1 done?

**No.**

Not because the refactor is wrong — it is not. The stage holds under three
independent adversaries. Host loopback stays closed through the new pasta
reference, abstract sockets stay unreachable, the payload holds exactly stdio,
the capability bounding set is empty on every topology, the privileged ancestor
userns resisted every escalation route tried, `/proc/1/environ` stays empty one
process further out, exit status survives the extra hop, and teardown from steady
state is clean on every process in the tree. Four of the five round-1 findings
are genuinely closed, and F3's fix in particular is the shape this project wants:
root cause named, routed through the resolved policy, one line per golden file as
the review artifact.

It is not done because of exit criterion 7, and specifically because of what
criterion 7 caught. A confirmed medium finding — SIGTERM during sandbox setup
executes the payload and orphans the sandbox, measured 6/6 here and 10/10 by the
agent that found it — is currently neither fixed nor written down, and the
regression test that exists for the property signals too late to see it. That is
the exact shape this project has a rule about: `make gate` proves the code does
what the author meant; it cannot prove the sandbox holds. Round 2's fix report
says F2 is fixed and falsified against its own hole, and it is, against the hole
it measured. The red teams measured a different hole reachable by the same
sentence in the finding's own statement of the property — *"the payload executes
and writes to the target, on a run snug never reported as successful"* — and
reached it by a different route.

The single most important thing left is **arming the parked guard before the
payload can exist**, together with a regression test that signals at a fixed,
early offset rather than after a `/proc` scan. Everything else in §5 is
low-severity or informational and can travel as written-down debt. That one
cannot: it is the property F2 was closed on, and it is currently open.

Secondary, and cheap: correct the `--die-with-parent` mechanism in the three
places that state it, before someone reasons from it and widens a readiness bar
that has nothing to do with the problem.
