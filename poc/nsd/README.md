# nsd — proof of concept for the supervisor topology

Throwaway code that exists to answer questions by execution. The design it
supports is [.claude/design/SUPERVISOR.md](../../.claude/design/SUPERVISOR.md);
read that first. Nothing here is meant to be merged into `snug` — it is in its
own Go module so `./...` and `make gate` never see it.

```
./run.sh          all experiments, PASS/FAIL, ~40s
./run.sh E3       one of them
KEEP=1 ./run.sh E3   leave the stage running afterwards to poke at it
```

Last full run on this host: **pass=49 fail=0**.

## What is here

| file | what |
|---|---|
| `main.go` | subcommand dispatch |
| `stage.go` | P0 (launcher: clone, `newuidmap`, pasta, lifeline) and P1 (the namespace holder) |
| `control.go` | the control protocol, the bwrap child, the attach op, the sandbox init |
| `join/nsdjoin.c` | the `setns` helper — C because Go cannot `setns(CLONE_NEWUSER)` |
| `join/nsowner.c` | prints which user namespace owns each of a pid’s namespaces |
| `join/nsdmount.c` | builds a mount view derived from the sandbox’s, with one host path grafted in |
| `run.sh` | every claim in the design doc, re-measured, each with a positive control |

## By hand

```
./nsd up --run /tmp/nsd-run --bind /tmp/work --net &
./nsd ctl /tmp/nsd-run info
./nsd ctl /tmp/nsd-run sandbox
./nsd ctl /tmp/nsd-run attach 0 1 /usr/bin/id -u     # 0 = the running sandbox, 1 = drop capabilities
./nsd ctl /tmp/nsd-run run /usr/sbin/ip -o -4 addr   # a child of the stage, in N but outside the sandbox
./nsdjoin <pid> 1 /bin/sh                            # the same injection, unmediated
./nsowner <pid>                                      # who owns which namespace
```

## Deliberately missing

No pty, no interactive relay, no seccomp on attached processes, no engine, no
error handling worth the name, and the control protocol trusts its caller
completely. Every one of those is discussed in the design doc; none of them
changes what was measured.
