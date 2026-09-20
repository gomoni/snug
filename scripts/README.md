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
| [`0010-doctor-exit-follows-its-own-rows.sh`](0010-doctor-exit-follows-its-own-rows.sh) | `snug doctor`'s exit code agrees with the rows it printed — a ❌ is fatal, a ⚠️ is not — and `snug fix subuid` is safe to call from an `errexit` init_hook |
| [`0011-the-userns-row-can-say-no.sh`](0011-the-userns-row-can-say-no.sh) | the user-namespace row is measured, not inferred from an exit code: on a fabricated host where namespace creation is blocked it says ❌ and exits 69 (issue #98) |
| [`0020-a-weak-host-warns-and-still-runs.sh`](0020-a-weak-host-warns-and-still-runs.sh) | the five inherited kernel knobs are disclosed and never refused, and the drop-in is a function of the table rather than of this boot — 4 applied, 5 written (issue #526) |
| [`0021-a-missing-knob-is-not-an-unset-one.sh`](0021-a-missing-knob-is-not-an-unset-one.sh) | a knob this kernel does not HAVE is never reported as one the host failed to set, and never gets a line in the drop-in (issue #526) |

**`NNNN` is an allocation sequence, not a VERIFY.md section number.** Sections
carry suffixes (`9a`, `9c-bis`, `9c-quater`, `23b`) that no numeric prefix can
express, and one section is frequently several independent checks. A number is
allocated on creation and never reused, so a reference to `0011` means one thing
forever. The gaps are deliberate: related checks share a decade.

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

| payload | run it | VERIFY.md |
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
answer is per-machine (this host's kernel knobs, this host's `doctor` report),
one that needs state CI structurally lacks (two live accounts, a loaded
ssh-agent), or one that needs a human's `sudo`. Plus the payloads, which are
programs rather than assertions.

## The migration rule

`VERIFY.md` is markdown that nothing executes — `wc -l VERIFY.md` says how much
of it is left — and the claim earning it its exemption from the no-`docs/` rule,
"every line is a command with its expected output", was the claim nothing
enforced. A command plus the output it produced once is a copy of state: stale
the moment the code moves, and the staleness found by whoever finally walks it.

So:

- **Every new check is a script here or a Go test. Never a new VERIFY.md
  section.**
- **A VERIFY.md section is migrated when it is touched, never edited in
  place.** Migrated means one of three things, and the third is common: it
  becomes a script here, it becomes a Go integration test, or it is deleted
  because a Go test already asserts it.
- What survives in `VERIFY.md` is the prose that is genuinely not executable —
  §2 "Read before you run", §16 "What can this run destroy?", "Where the
  reasoning is thinnest". Reasoning, not readings.

That rule is what stops this from becoming a chore list with a row per
unmigrated section: those sections are in `VERIFY.md`, which is where a reader
already looks, and a count of them written down here would be stale by the next
migration.
