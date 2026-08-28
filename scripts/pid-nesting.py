#!/usr/bin/env python3
"""Observe the sandbox's pid-namespace nesting, from both sides of it.

    # terminal 1 — the payload
    snug $SC/proj/sub -- python3 /path/to/snug/scripts/pid-nesting.py inside

    # terminal 2, within 20s — the host
    python3 scripts/pid-nesting.py host

VERIFY.md §21 carries the expected output of both.

WHY BOTH SIDES, AND WHY THE HOST SIDE IS THE ONE THAT PROVES ANYTHING. snug's
offline arm forks bwrap into a pid namespace of its own (NP), and bwrap's own
--unshare-pid then nests the sandbox's namespace (Q) below it — three levels
where a plain bwrap has two. From INSIDE, that is invisible on purpose: a host
pid never appears in Q's procfs whether the nesting exists or not, so the
`inside` probe reads identically with and without it. The load-bearing line is
the host one, `bwrap ns/pid != snug ns/pid`, which is false without the nesting
and true with it.

The `inside` probe is still worth running, for the negative it states: the
intermediate bwrap is ENOENT rather than EPERM there — procfs exposes only
members of the namespace it was mounted for — so neither its fd directory nor
its mem is reachable by a payload that learns its host pid some other way.

The two sides meet through a file, because they cannot see each other's process
tree: `host` writes bwrap's host pid where `inside` polls for it. That is the
sandbox's own working directory by default (writable under @cwd-rw), overridden
with PID_FILE, or skipped entirely by passing HOST_BWRAP_PID in the environment.

Nothing here needs privileges. Nothing here writes anything but that one file.
"""
import glob
import os
import sys
import time

# Not tempfile: the two sides share a filesystem only where the target bind
# makes them, so the default has to be a path inside the sandbox.
PID_FILE = os.environ.get("PID_FILE") or os.path.join(os.getcwd(), "BWRAP_PID")


def ns(pid, kind):
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError as e:
        return f"<{e.strerror}>"


def comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return "<gone>"


def children(pid):
    # /proc/<pid>/task/<tid>/children needs CONFIG_PROC_CHILDREN, which is what
    # internal/initwalk reads too. A kernel without it prints a one-line tree
    # and no verdict, rather than a wrong verdict.
    out = []
    for path in glob.glob(f"/proc/{pid}/task/*/children"):
        try:
            with open(path) as f:
                out += [int(x) for x in f.read().split()]
        except OSError:
            pass
    return out


def descend(pid, depth=0, seen=None):
    seen = set() if seen is None else seen
    if pid in seen:
        return
    seen.add(pid)
    print(f"  {'  ' * depth}{pid:>8}  {comm(pid):<10}"
          f"  ns/pid={ns(pid, 'pid')}  ns/user={ns(pid, 'user')}")
    for child in children(pid):
        descend(child, depth + 1, seen)


def host():
    snugs = [int(d.rsplit("/", 1)[1]) for d in glob.glob("/proc/[0-9]*")
             if comm(int(d.rsplit("/", 1)[1])) == "snug"]
    if not snugs:
        sys.exit("no running snug found — start one first, e.g. "
                 "snug $SC/proj/sub -- sleep 300 &")

    print(f"host  ns/pid={ns('self', 'pid')}  ns/user={ns('self', 'user')}")
    for snug in snugs:
        print(f"\nsnug {snug}:")
        descend(snug)

        bwraps = [p for p in children(snug) if comm(p) == "bwrap"]
        if not bwraps:
            print("  no bwrap child: this is the STAGED arm (@net), whose bwrap "
                  "is forked by the stage and is not nested — see the tree above")
            continue
        bwrap = bwraps[0]
        nested = ns(bwrap, "pid") != ns(snug, "pid")
        print(f"\n  snug   ns/pid = {ns(snug, 'pid')}")
        print(f"  bwrap  ns/pid = {ns(bwrap, 'pid')}   <- NP")
        for init in children(bwrap):
            print(f"  init   ns/pid = {ns(init, 'pid')}   <- Q")
        print(f"  => nesting {'PRESENT' if nested else 'ABSENT'}")
        try:
            with open(PID_FILE, "w") as f:
                f.write(str(bwrap))
            print(f"  wrote {PID_FILE} for the payload to probe")
        except OSError as e:
            print(f"  could not write {PID_FILE}: {e}; "
                  f"pass HOST_BWRAP_PID={bwrap} to the payload instead")


def inside():
    print(f"pid inside : {os.getpid()}")
    print(f"uid/gid    : {os.getuid()}/{os.getgid()}")
    for kind in ("pid", "user", "net", "mnt"):
        print(f"ns/{kind:<7} : {ns('self', kind)}")
    print(f"pids seen  : {sorted(int(d.rsplit('/', 1)[1]) for d in glob.glob('/proc/[0-9]*'))}")
    print(f"pid 1 is   : {comm(1)}")
    with open("/proc/self/status") as f:
        status = dict(line.split(":", 1) for line in f.read().splitlines() if ":" in line)
    for key in ("NSpid", "CapEff", "CapBnd", "NoNewPrivs", "Seccomp"):
        print(f"{key:<11}: {status.get(key, '<absent>').strip()}")

    probe = os.environ.get("HOST_BWRAP_PID")
    deadline = time.time() + 20
    while not probe and time.time() < deadline:
        try:
            with open(PID_FILE) as f:
                probe = f.read().strip()
        except OSError:
            time.sleep(0.1)
    if not probe:
        print(f"\nno HOST_BWRAP_PID and nothing at {PID_FILE} after 20s — "
              "run the host side while this one waits")
        return

    print(f"\nthe intermediate bwrap, host pid {probe}:")
    for path in (f"/proc/{probe}", f"/proc/{probe}/fd", f"/proc/{probe}/mem"):
        try:
            os.stat(path)
            print(f"  stat {path:<20} -> VISIBLE")
        except OSError as e:
            print(f"  stat {path:<20} -> {e.strerror}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "inside"
    if mode not in ("host", "inside"):
        sys.exit(f"unknown mode {mode!r}: say 'host' or 'inside'")
    (host if mode == "host" else inside)()
