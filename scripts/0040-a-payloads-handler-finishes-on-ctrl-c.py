#!/usr/bin/env python3
# 0040 — a payload's own signal handler gets to finish when a HUMAN presses
# Ctrl-C, on both topologies, and the payload is signalled exactly once.
#
# WHY THIS IS NOT A GO TEST. The property depends on which of two delivery
# paths the run has, and that is decided by whether snug's stdio is a terminal
# (internal/sandbox/ttydelivery.go, internal/policy/newsession.go). A Go test in
# test/integration has no terminal, so it always takes the RELAY path — which
# test/integration/payloadgrace_test.go does own, and says so. The path a human
# actually uses is the other one: the terminal delivers to the whole foreground
# process group, snug deliberately relays NOTHING, and the payload must still
# get its window. Only a real pty produces that, so only this can check it.
#
# It also checks the thing the relay path cannot: that the payload sees ONE
# SIGINT per keypress. On a shared session the terminal has already delivered,
# so a snug that relayed anyway would turn one keypress into two — and two is
# what "force quit" means to compose, npm, pytest and vite.
#
# SKIP (79): no pty available, or no bwrap/pasta.

import errno
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time

SNUG = os.environ.get("SNUG", "./bin/snug")
SKIP = 79  # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
TRIALS = int(os.environ.get("TRIALS", "3"))
BUDGET = 1.0  # internal/sandbox's payloadGraceBudget


def skip(why):
    print("SKIP: " + why)
    sys.exit(SKIP)


def have(binary):
    return shutil.which(binary) is not None


# The handler does REAL work — 300ms — because a handler that only writes a
# flag fits inside the window that existed by accident before issue #595, and
# would pass against the broken code. That is how #595's own reproduction came
# to measure the wrong thing.
PAYLOAD = (
    "c=0; "
    "trap 'c=$((c+1)); echo SIGINT-$c >&2; sleep 0.3; echo HANDLER-DONE >&2; exit 7' INT; "
    "echo READY; "
    "i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done"
)


def one(profiles, tgt):
    argv = [SNUG] + profiles + [tgt, "--", "/bin/sh", "-c", PAYLOAD]
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
        os._exit(127)

    out, ready, sent, rc, t_sig = b"", None, False, None, None
    t0 = time.time()
    while True:
        now = time.time()
        if ready is not None and not sent and now - ready >= 0.5:
            os.write(fd, b"\x03")  # a real Ctrl-C, through the line discipline
            sent, t_sig = True, now
        if now - t0 > 40:
            os.kill(pid, 9)
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError as e:
                if e.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                break
            out += chunk
            if ready is None and b"READY" in out:
                ready = time.time()
        done, status = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            rc = status
            break
    if rc is None:
        _, rc = os.waitpid(pid, 0)
    os.close(fd)
    text = out.decode("utf-8", "replace")
    return {
        "code": os.waitstatus_to_exitcode(rc),
        "text": text,
        "elapsed": (time.time() - t_sig) if t_sig else -1.0,
        "entered": "SIGINT-1" in text,
        "finished": "HANDLER-DONE" in text,
        "twice": "SIGINT-2" in text,
    }


def check(name, profiles):
    tgt = tempfile.mkdtemp(prefix="snug-0040-")
    try:
        bad = 0
        for i in range(TRIALS):
            r = one(profiles, tgt)
            problems = []
            if not r["entered"]:
                problems.append("handler never ran")
            if not r["finished"]:
                problems.append("handler ran but did not finish its 300ms")
            if r["twice"]:
                problems.append("payload saw TWO SIGINTs for ONE keypress "
                                "(snug relayed on top of the terminal)")
            if r["code"] != 7:
                problems.append("exit %d, want the payload's own 7" % r["code"])
            if r["elapsed"] > BUDGET + 5:
                problems.append("took %.2fs to exit, past the %.1fs budget"
                                % (r["elapsed"], BUDGET))
            if problems:
                bad += 1
                print("  trial %d: FAIL — %s" % (i + 1, "; ".join(problems)))
                print("    output: %s" % r["text"].replace("\r\n", " | ")[:300])
            else:
                print("  trial %d: ok — handler finished, one signal, exit 7, %.2fs"
                      % (i + 1, r["elapsed"]))
        return bad
    finally:
        shutil.rmtree(tgt, ignore_errors=True)


def main():
    if not os.path.exists(SNUG):
        skip("%s is not built (run `make build`)" % SNUG)
    if not have("bwrap"):
        skip("no bwrap on this host")
    try:
        p, f = pty.fork()
        if p == 0:
            os._exit(0)
        os.waitpid(p, 0)
        os.close(f)
    except OSError as e:
        skip("this host cannot allocate a pty: %s" % e)

    # A run must actually work here, or every assertion below passes for the
    # wrong reason. This is the same control scripts/0020 opens with.
    probe = subprocess.run([SNUG, tempfile.mkdtemp(prefix="snug-0040-probe-"),
                            "--", "/bin/true"], capture_output=True, text=True)
    if probe.returncode != 0:
        skip("a plain snug run fails on this host, so nothing below would mean "
             "anything: %s" % probe.stderr.strip()[:200])

    failures = 0
    print("offline:")
    failures += check("offline", [])
    if have("pasta"):
        print("staged (@net):")
        failures += check("staged", ["-p", "@net"])
    else:
        print("staged (@net): skipped, no pasta on this host")

    if failures:
        print("asserted: FAILED — %d trial(s) did not give the payload its window" % failures)
        return 1
    print("asserted: a real Ctrl-C reaches the payload ONCE, its handler finishes "
          "300ms of work, and snug reports the payload's own exit code (both arms)")
    return 0


sys.exit(main())
