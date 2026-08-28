#!/usr/bin/env python3
"""Show, in plain words, how deep the sandbox's pid namespace sits.

    # terminal 1 — the payload
    snug $SC/proj/sub -- python3 /path/to/snug/scripts/pid-nesting.py inside

    # terminal 2, within 20s — the host
    python3 scripts/pid-nesting.py host

It reads like `snug doctor`: a ✅ or ❌ per claim, the evidence under it.
VERIFY.md §21 carries the expected output of both.

WHY BOTH SIDES, AND WHY THE HOST SIDE IS THE ONE THAT PROVES ANYTHING. snug's
offline arm forks bwrap into a pid namespace of its own (NP), and bwrap's own
--unshare-pid then nests the sandbox's namespace (Q) below it — three levels
where a plain bwrap has two. From INSIDE, that is invisible on purpose: a host
pid never appears in Q's procfs whether the nesting exists or not, so the
`inside` probe reads identically with and without it. The load-bearing line is
the host one, bwrap's pid namespace differing from snug's, which is false
without the nesting and true with it.

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


def ok(line):
    print(f"  ✅ {line}")


def bad(line):
    print(f"  ❌ {line}")


def warn(line):
    print(f"  ⚠️  {line}")


def detail(line):
    print(f"     {line}".rstrip())


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


def descend(pid, own, depth=0, seen=None, parent=""):
    """One line per process, marking only where a NEW pid namespace begins.

    Marking every process that is "not the host's" says the same thing four
    times and hides the two lines that matter — the two levels snug creates.
    """
    seen = set() if seen is None else seen
    if pid in seen:
        return
    seen.add(pid)
    mine = ns(pid, "pid")
    if mine.startswith("<"):
        # Unreadable is NOT a new level: pasta's own /proc entry reads
        # "Permission denied" here, and calling that a namespace boundary
        # would put a mark on the one line we know least about.
        note = "(this process's namespace is not readable from here)"
    elif depth == 0:
        note = "the host's own pid namespace"
    elif mine != parent:
        note = "← a NEW pid namespace starts here"
    else:
        note = ""
    detail(f"{'  ' * depth}{pid:>7}  {comm(pid):<12}{mine:<22}{note}")
    for child in children(pid):
        descend(child, own, depth + 1, seen, mine)


def host():
    snugs = [int(d.rsplit("/", 1)[1]) for d in glob.glob("/proc/[0-9]*")
             if comm(int(d.rsplit("/", 1)[1])) == "snug"]
    print("\nLooking for a running snug\n")
    if not snugs:
        bad("no running snug found")
        detail("start one first, then run this again while it is up:")
        detail("    snug $SC/proj/sub -- sleep 300 &")
        sys.exit(1)

    own = ns("self", "pid")
    for snug in snugs:
        ok(f"found snug, pid {snug}")
        print()
        detail("who is running, and which pid namespace each one lives in:")
        print()
        descend(snug, own)
        print()

        bwraps = [p for p in children(snug) if comm(p) == "bwrap"]
        if not bwraps:
            warn("no bwrap directly under snug — this is the @net sandbox")
            detail("Its bwrap is started by the stage instead, and it is NOT nested;")
            detail("the tree above shows the whole chain. Only the offline arm nests.")
            print()
            continue

        bwrap = bwraps[0]
        if ns(bwrap, "pid") == own:
            bad("bwrap is in the same pid namespace as snug — the sandbox is NOT nested")
            detail("This is what snug looked like before issue #101: two levels, not three.")
            detail(f"snug  {own}")
            detail(f"bwrap {ns(bwrap, 'pid')}")
            print()
            continue

        ok("the sandbox sits one level deeper than snug — the nesting is there")
        detail(f"snug   {ns(snug, 'pid'):<22}the host's, same as this terminal")
        detail(f"bwrap  {ns(bwrap, 'pid'):<22}snug made this one; bwrap is pid 1 in it")
        for init in children(bwrap):
            detail(f"init   {ns(init, 'pid'):<22}the sandbox's own, below bwrap's")
        detail("")
        detail("So nothing inside the sandbox has a number for bwrap at all, and when")
        detail("bwrap dies the kernel tears down everything at its level with it.")
        print()

        try:
            with open(PID_FILE, "w") as f:
                f.write(str(bwrap))
            ok(f"told the payload which pid to look for (bwrap is host pid {bwrap})")
            detail(f"📍 {PID_FILE}")
        except OSError as e:
            warn(f"could not write {PID_FILE}: {e}")
            detail(f"Run the payload with HOST_BWRAP_PID={bwrap} in its environment instead.")
        print()


def inside():
    print("\nInside the sandbox\n")
    pids = sorted(int(d.rsplit("/", 1)[1]) for d in glob.glob("/proc/[0-9]*"))
    ok(f"you are pid {os.getpid()}, and the whole visible world is {pids}")
    detail(f"pid 1 is {comm(1)} — bwrap's own init, the only thing above you")

    with open("/proc/self/status") as f:
        status = dict(line.split(":", 1) for line in f.read().splitlines() if ":" in line)

    def field(key):
        return status.get(key, "").strip()

    if set(field("CapEff") + field("CapBnd")) <= {"0"}:
        ok("no capabilities at all — CapEff and CapBnd are both empty")
    else:
        bad(f"this process holds capabilities: CapEff {field('CapEff')}, "
            f"CapBnd {field('CapBnd')}")
    if field("NoNewPrivs") == "1":
        ok("no_new_privs is set — nothing here can gain privilege by exec'ing")
    else:
        bad("no_new_privs is NOT set")
    if field("Seccomp") == "2":
        ok("a seccomp filter is installed and enforcing (mode 2)")
    else:
        warn(f"seccomp is in mode {field('Seccomp') or '<unknown>'}, not 2")
    ok(f"running as uid {os.getuid()}, gid {os.getgid()}")

    print()
    detail("the namespaces you are in:")
    for kind in ("pid", "user", "net", "mnt"):
        detail(f"   {kind:<6}{ns('self', kind)}")
    print()

    probe = os.environ.get("HOST_BWRAP_PID")
    deadline = time.time() + 20
    while not probe and time.time() < deadline:
        try:
            with open(PID_FILE) as f:
                probe = f.read().strip()
        except OSError:
            time.sleep(0.1)
    if not probe:
        warn("nobody told me which pid to look for, so the last check is skipped")
        detail(f"Run `python3 scripts/pid-nesting.py host` on the host while this waits,")
        detail(f"or pass HOST_BWRAP_PID=<pid>. Expected the answer at {PID_FILE}.")
        print()
        return

    missing = []
    for path in (f"/proc/{probe}", f"/proc/{probe}/fd", f"/proc/{probe}/mem"):
        try:
            os.stat(path)
        except OSError as e:
            missing.append((path, e.strerror))
    if len(missing) == 3:
        ok(f"the bwrap that built this sandbox (host pid {probe}) does not exist in here")
        for path, why in missing:
            detail(f"{path:<20}{why}")
        detail("")
        detail("Absent, not forbidden: procfs only lists processes of the namespace it")
        detail("was mounted for, so there is no fd list to read and no memory to attach.")
    else:
        bad(f"host pid {probe} is visible from inside the sandbox")
        detail("A process at bwrap's level should have no /proc entry here at all.")
    print()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "inside"
    if mode not in ("host", "inside"):
        sys.exit(f"unknown mode {mode!r}: say 'host' or 'inside'")
    (host if mode == "host" else inside)()
