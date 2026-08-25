# snug

Bubblewrap-based sandbox for running untrusted code: builds, dependency install
hooks, test suites, and AI agents among them. Nothing in the model is
agent-specific — an agent is just one more thing you would rather not hand your
`~/.ssh` to.

**The full design is [.claude/design/INDEX.md](.claude/design/INDEX.md).** Read it before implementing
anything. This file is the working agreement: the invariants that must not be
broken, who does what, and the facts about this environment that were expensive
to learn.

## The guiding principle

> **Share nothing. Then punch explicit, named, minimal holes until the sandbox
> is useful.**

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. A profile is a *named hole*.

There is no "deny rule" in snug, because there is nothing to deny — the thing you
would deny was never there. `@parent-ro` does not hide your other projects; it simply
never grants them. This is why a missing capability (no X11, no Wayland, no
D-Bus, no host loopback, no `~/.ssh`) is a **feature to state plainly**, not a
gap to apologise for.

## Invariants

Break any of these and the project has lost its point.

1. **Monotonicity — stated precisely, because the loose version is false.**

   *Visibility is monotone, and structurally so.* No deny rules, no `mask`, no
   negation, no priority/override fields. Adding a profile can never make a path
   stop being visible: `rejectMasking` refuses anything mounted on top of what
   another grant exposes, and the grant language cannot express subtraction.

   *One exception, and it is snug's own writing, not a profile's.* Generated
   `KindData` mounts (`/etc/resolv.conf`, the identity files `~/.gitconfig`,
   `~/.ssh/config`, `known_hosts`) are assigned **directly into `p.Mounts`** at
   the end of `Resolve` — they skip `join`, and `rejectMasking` exempts
   `KindData` by kind. 

2. **Deny by default.** Every visible path traces to exactly one explicit grant.
   **Corollary — wanting "X but not Y" means X was too coarse a grant.** The
   urge to exclude is a design smell pointing at the grant above it, not a
   missing feature. Two ways out, both additive:
   - *Enumerate.* Grant the parts of X you meant. This is why `@sys` lists
     fourteen `/etc` entries instead of binding all 109.
   - *Layer by access.* Grant the tree read-only and the parts you want to
     write separately. Access joins by max, so `ro /proj` + `rw /proj/src`
     leaves `.git` read-only without any rule mentioning `.git`.

3. **The trusted profile set comes from outside the sandboxed material.**
   Repo-local config is never auto-loaded. A hostile repo shipping `.snug/` is
   an attacker granting themselves permissions — a complete defeat of the threat
   model.

4. **No root, no setuid, no daemon.** Helpers are children that die with the
   sandbox and leave nothing behind. **"No daemon" means no process the user did
   not start and no state that survives them — not "exactly one process".**
   `@net` runs a second one, the stage; its cost is under "Decisions made →
   Networking".

5. **No silent downgrade, ever.** If a requested capability is unavailable, snug
   says so and exits. A user believing a guarantee that no longer holds is worse
   than a failure. (Seccomp is the single exception, and it still warns.)

6. **One `Policy`, one author.** The same resolved policy generates the bwrap
   argv, the pasta argv, *and* the container proxy's decisions. Divergence
   between what the sandbox can see and what a container may mount is then
   impossible by construction rather than by review.

7. Do not downgrade the host security - ie copy the host's SSL, SSH and other
   configuration. This principle expects snug understand and interprets host's
   program configuration and never passes it directly.


## Development agents

`.claude/agents/` — use them; they carry the context that keeps the invariants
intact. `.claude/design/` holds the design and research material they work from
(INDEX.md, the pseudo-filesystem audit, the secrets analysis, parked designs).
There is deliberately **no `docs/` tree**: a generated user guide was tried and
removed, because the prose churned faster than the code it described and nobody
was going to keep it honest. `VERIFY.md` at the root is the exception, and it
earns it by being executable — every line is a command with its expected output.

**Every new document starts in `.claude/scratchpad/`, which is in `.gitignore`**
— not "start it in design/ and remember not to commit it", but somewhere a
routine `git add -A` cannot reach, because that is exactly how an untracked plan
got committed twice in one session. **An instruction a routine command can
quietly undo is not a rule; the `.gitignore` entry is what makes it one.**

Plans, review write-ups, red-team round reports and working notes live there and
stay there. A document is *promoted* into `.claude/design/` by a deliberate `git
mv`, only once it is either **the** design for a subject (one per subject, no
`-PLAN` or `-REVIEW` twin beside it) or a research record whose measurements stay
useful after the work lands (`NOCGO.md`, `ENGINE-NETNS.md`).
Findings never wait on promotion: a confirmed finding becomes a GitHub issue with
its severity label, which is the milestone rule anyway.

| agent | owns |
|---|---|
| `sandbox-policy` | The policy model and the bwrap argv. Invoke *before* writing policy code. Guards monotonicity. Advisory: like `redteam` it has **no edit tools**, so the decision is written down and reviewed before `go-implementer` turns it into code. **It defaults to opus and is the priciest agent here — pass `model: "sonnet"` for lookups** ("which mount covers this path", "what does this profile grant", "why is X visible"), and keep opus for judgement: changing a grant, changing how resolution works, deciding whether something breaks an invariant. |
| `host-bridge` | Every deliberate hole: netns/pasta, ssh-agent proxy, podman socket proxy, shared tmp. Decides the shape of a hole and says no when it is wider than the need. |
| `redteam` | Our own adversary: tries to escape the sandbox we build, with the maintainer's authority, so we find the holes first. Deliberately has no edit tools, so discovery stays separate from the code being graded. |
| `sandbox-tester` | The committed suite: resolver invariants, golden argv, integration tests that assert negatives. |
| `go-implementer` | Ordinary Go work. Explicitly forbidden from inventing policy — hands security decisions back. |

`redteam` and `sandbox-tester` are a pipeline, not two testers: **every escape
the red team confirms becomes a permanent named regression test.** A hole should
only ever be closable once.

## Definition of done for a milestone

All five, in order. A milestone is not finished until the last one is.

1. `make gate` green — gofmt, vet, and the full test suite.
2. `make integration` green (`SNUG_REQUIRE_SANDBOX=1`), with a new named test for
   whatever the milestone added. `VERIFY.md` gets the human-readable
   equivalent — it is the by-hand checklist and is not made redundant by the
   automated one.
3. **`redteam` has attacked it.** Not optional, not "if there's time". Every
   milestone that adds a hole gets a run before it lands, and so does any change
   to the policy model, mount generation, the seccomp filter, or a
   host-integration surface.
4. Every confirmed finding is either fixed, or **filed as a GitHub issue** with
   its severity label (`sev:high`/`sev:medium`/`sev:low`) and the measurement
   that confirmed it — never silently carried. The issue body carries the
   reproduction, because the reproduction is the valuable half. There is no
   `TODO.md`: it grew into 1800 lines mixing open work with shipped work written
   in the future tense, and the rule that grew it is this one.
5. Every confirmed finding becomes a permanent named regression test owned by
   `sandbox-tester`. A hole should only ever be closable once.

**Why this is a rule and not a suggestion.** Across two runs the red team found
five real issues, and *every one* was in code that had been written and tested,
with the tests passing:

## Working agreement

- **Write the abuse sentence first.** Before implementing any grant: "a hostile
  process inside the sandbox can use this to ___". It goes in the profile TOML as
  a comment. If you cannot write it, the grant is not ready.
- **Write the account AS the work happens, not afterwards — and when a detail
  cannot be recovered exactly, write "not recovered" rather than reconstructing
  it.** An account written after the fact is rebuilt from a memory of the
  OUTCOME, so the details that get smoothed are precisely the ones the outcome
  does not depend on — which is the set a later reader relies on, because the
  outcome is the part they already have. A reproduction tidied into plausibility
  lands on a ticket carrying the authority of something that was run.
  **Correct in place and leave the wrong version visible**; a silent fix erases
  the evidence that the shape recurs, which is worth more than any one instance.
  This is not the copy-of-state rule: that one is about prose going stale LATER,
  this one is about prose that is wrong WHEN WRITTEN.

  The sharpest case is an **ordering claim**, because nothing in the code records
  the order — the code records the intent. Clear one by observing the order from
  outside the code that claims it, then ask what ENFORCES it. "Does A run before
  B" can only confirm; "can anything make B run early, or A run late" can refute,
  and a payload that delays a teardown past a sweep breaks the claim without
  breaking a line of code.
- **When you write down a limitation, ask what it GRANTS as well as what it
  costs.** A true ergonomics footnote sat in `base.toml` for a milestone —
  "containers run in the ENGINE's network namespace, not the sandbox's…
  `podman run -p 8080:80` will NOT work". From the user's side, an annoyance;
  from an attacker's, the same sentence says *a container has the engine's
  network, so a sandbox with no `@net` reaches the internet through one*
  (`.claude/design/ENGINE-NETNS.md` §0). **A limitation and a hole are frequently
  the same fact facing two directions.**

- **Comment rules live in the agent files** — `.claude/agents/go-implementer.md`
  § Comments, test deltas in `sandbox-tester.md` — and they bind the main thread
  editing code directly, which is exactly where nothing loads them for you. The
  half that is not style is the rule above aimed at code: **never write a
  measurement, errno, quoted string or issue number you did not read this
  task.** Nothing checks a `#NNN` in a comment, there are hundreds, and an
  invented one is indistinguishable from a real one — a reconstructed
  reproduction one file closer to the code than the ticket it would otherwise
  land on. The commit that first wrote that rule misquoted `reap.go` inside it
  ("nothing of mine is here"; the string is "nothing of mine is running"), which
  is the measured base rate for catching this by eye: zero, until someone
  grepped.

- **Pull requests: caveman prose, and never a session link.** A PR body is
  technical prose that prefers brevity and accuracy over narration — drop
  articles and filler, keep every measurement, path, flag and exact error
  string. **Never put a `claude.ai/code/session` URL in a PR body, a commit
  message, an issue or a comment.** It is a link nobody outside this machine can
  open, it dates the artifact, and it points at a transcript rather than at the
  code. Cite the issue, the file and the measurement instead.
- **Golden argv diffs are the review artifact.** A change to a golden file is a
  change to the security boundary and is read as such. A security change that
  produces no golden diff is probably untested.
- **Test the negative.** A test proving the sandbox is *useful* proves nothing
  about whether it is *safe*. Sibling not visible; symlink does not resolve out;
  host loopback refused; abstract sockets unreachable; no orphans after SIGKILL.
- **Keep `internal/policy` pure.** No globals, no filesystem, no `exec` — host
  lookups go through an injected `Environ`. This is what lets the
  security-critical tests run in CI with no privileges.
- **Errors name the fix.** "failed to create user namespace (see
  /proc/sys/kernel/unprivileged_userns_clone)" beats "operation not permitted".
  snug runs in odd environments and a bad message there costs an hour.
- `snug --dry-run` is not a debugging convenience — it is *the* mechanism by
  which a human can trust snug at all. Keep it honest and keep it complete.
  (There is no `snug explain`; this line named it for several milestones after
  the rename. Prose quoting a command name is a copy of state held in `main.go`.)

## Decisions made

Check .claude/design/INDEX.md for more details.
