# scripts/

Programs a human runs against a sandbox, not code snug builds or imports.
Nothing here is on any import path, nothing here needs privileges, and each one
exists because a property is easier to *observe* than to argue about.

There are two kinds, and they are separated by directory rather than by a
naming convention the runner would have to parse.

## Checks — `NNNN-slug.sh`, `NNNN-slug.py`

A check asserts a property from outside and has a pass/fail. It prints what it
asserted; the expected output lives in its assertions, not in prose beside it.
`make verify` walks them in numeric order.

| script | asserts |
|---|---|
| [`0012-doctor-names-each-wrong-host.sh`](0012-doctor-names-each-wrong-host.sh) | five wrong-host conditions each get doctor's own headline and fix, not another's: `apparmor_restrict_unprivileged_userns=1`, a container masking `/proc`, no `/dev/net/tun`, runc-without-crun under disabled cgroups, and no `/etc/subuid` line |
| [`0020-a-weak-host-warns-and-still-runs.sh`](0020-a-weak-host-warns-and-still-runs.sh) | the five inherited kernel knobs are disclosed and never refused, and the drop-in is a function of the table rather than of this boot — 4 applied, 5 written (issue #526) |
| [`0032-claude-opens-with-no-dialog-and-no-hook.sh`](0032-claude-opens-with-no-dialog-and-no-hook.sh) | the trust dialog is pre-answered and a hostile repo's `.claude/settings.json` hooks and `.mcp.json` servers are reinterpreted away before Claude Code reads either — with the same fixture's hook firing on the bare host as the control |
| [`0033-an-unnamed-plugins-hook-does-not-fire.sh`](0033-an-unnamed-plugins-hook-does-not-fire.sh) | an installed plugin's `hooks.json` is not even read inside when `@claude`'s allowlist does not name it, though its tree stays bound read-only (issue #68) |
| [`0034-projected-credential-still-authenticates.sh`](0034-projected-credential-still-authenticates.sh) | the staged `~/.claude/.credentials.json` carries exactly five fields, never a refresh token, and a live turn on it still authenticates (issue #58) |

**`NNNN` is an allocation sequence, not a VERIFY.md section number.** Sections
carry suffixes (`9a`, `9c-ter`, `9c-quater`, `23b`) that no numeric prefix can
express, and one section is frequently several independent checks. A number is
allocated on creation and never reused, **including by a check that has since
left this directory**: `0010`, `0011`, `0021`, `0030` and `0031` became Go tests
and their numbers stay retired, so a reference to `0011` in a commit message or
an issue means one thing forever. The gaps are deliberate: related checks share
a decade.

**Exit 79 is SKIP**, and it is 79 rather than the conventional 77 because snug's
own `exitPolicy` IS 77 (`internal/cli/main.go`). A script that ended on an
uncaptured `snug` refusal would otherwise report SKIP — a check that cannot
fail. 79 is outside sysexits' 64–78 range entirely, so it cannot be one of
snug's. A check declares its own preconditions and SKIPs naming the one that was
not met; it never assumes the host it was written on.

## Payloads — `payloads/`

A payload is a program run INSIDE a sandbox. It has no pass/fail of its own, so
`make verify` does not walk it; a check or a Go test runs it and grades what it
printed.

| payload | run it | [`VERIFY.md`](VERIFY.md) |
|---|---|---|
| [`payloads/http-door-server.py`](payloads/http-door-server.py) | as the payload of a run whose profile declares a `listen_names` door | §20 |
| [`payloads/pid-nesting.py`](payloads/pid-nesting.py) | twice — `inside` as the payload, `host` beside it | §21 |

`payloads/http-door-server.py` is also the answer to "how do I serve something
from in here", because `python3 -m http.server` cannot be: snug never forwards a
port, it hands the payload a socket that is already listening on the host.

## What belongs here, and what belongs in Go

**A check CI can run on every push belongs in `test/integration`, not here.** A
check living in both places is a second copy of state, and the copy nobody runs
is the one that goes stale.

What is left for this directory is what CI genuinely cannot run: a check whose
answer is per-machine (this host's kernel knobs), one that needs state CI
structurally lacks (a `claude` binary, a live authenticated credential, two
accounts), or one that needs a human's `sudo`. Plus the payloads, which are
programs rather than assertions.

**So CI does not run `make verify`, and that is the rule holding rather than a
gap.** The rule says every check here is one CI cannot run; a CI step walking
them could therefore only ever SKIP, and a step that can only skip is exactly
the shape the floors in this repository exist to refuse. What CI grades instead
is `test/guard/scripts_test.go`, which grades the DIRECTORY — duplicate numbers,
a file that is not executable, a check missing from this index, a script
spelling SKIP as 77 — none of which running the checks would catch. Five checks
went the other way and are named in the retirement paragraph above:

| was | is now |
|---|---|
| `0010` | `TestDoctorsExitCodeFollowsTheRowsItPrinted`, `TestFixSubuidIsSafeToCallFromAnErrexitInitHook` (`test/integration`) |
| `0011` | `TestDoctorSaysNoOnAHostWhereUserNamespacesDoNotWork` (`test/integration`) |
| `0021` | `TestAnAbsentKnobIsReportedAsAbsentAndIsNeverFixed`, `TestTheThreeWaysAKnobHasNoValueAreToldApart` (`internal/cli`) — already there, so the script was the second copy |
| `0030` | `TestEngineGCSeesEveryGenerationOfStoreName` (`internal/cli`) |
| `0031` | `TestClaudeInheritsAPagerAndNeitherEditorVariable` (`test/integration`) |

## The migration rule

[`VERIFY.md`](VERIFY.md) beside this file is markdown that nothing executes —
`wc -l scripts/VERIFY.md` says how much of it is left — and the claim earning it
its exemption from the no-`docs/` rule, "every line is a command with its
expected output", was the claim nothing enforced. A command plus the output it produced once is a copy of state: stale
the moment the code moves, and the staleness found by whoever finally walks it.

So:

- **Every new check is a script here or a Go test. Never a new VERIFY.md
  section.**
- **A VERIFY.md section is migrated when it is touched, never edited in
  place**, and migrated means DELETED from that file in the same change.
  Migrated means one of three things, and the third is the common one: it
  becomes a script here, it becomes a Go integration test, or it becomes
  nothing at all because a Go test already asserts it. A section left standing
  beside the test that replaced it is the copy-of-state failure again, one
  indirection further along.
- What survives in `VERIFY.md` is what nothing runs: a claim needing two
  logged-in accounts, a live `gh`, a `sudo truncate`, a real engine host, or a
  measurement of one machine. Each surviving section says in its first
  paragraph which tests cover the rest of its subject and which claim of its
  own has no owner — a section that cannot write that sentence does not belong
  there.

That rule is what stops this from becoming a chore list with a row per
unmigrated section: those sections are in `VERIFY.md`, which is where a reader
already looks, and a count of them written down here would be stale by the next
migration.
