#!/bin/bash
# Phase 0b — "P1 outside N". SUPERVISOR-PLAN.md §1, which is marked UNMEASURED.
#
# The claim: P1 creates N by clone but does not have to stay in it. It pins N,
# unshares into a fresh empty netns of its own, and puts back into N only the
# children that belong there.
#
# The same two rules as run.sh hold here, and the second one bit during this
# work: a naive `want` with both sides empty PASSES, so `same()` below refuses an
# empty side exactly as `differs()` does.
#
#   1. Never assert an exit code as a negative. Assert a MARKER the payload
#      emitted — boxwant() below prefixes every in-sandbox probe with one and
#      fails the check if it is missing.
#   2. Never compare two namespace ids without refusing the empty case.
#
# Everything is measured TWICE: once with the move off (that is run.sh's
# topology, and it is the positive control — the holes must be OPEN there) and
# once with it on. A payoff that cannot be shown absent first is not a payoff.
#
#   ./run-netns.sh          all of it
#   ./run-netns.sh N3       one section
set -u

cd "$(dirname "$0")"
RUN=${RUN:-/tmp/nsd-netns-run}
WORK=${WORK:-/tmp/nsd-netns-work}
ONLY=${1:-}
pass=0; fail=0

ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
want() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi; }
section() { echo; echo "== $*"; }
run()  { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

same() { # same <desc> <a> <b> — an empty side is a failure, not a match
  if [ -z "$2" ] || [ -z "$3" ]; then bad "$1 (a value was empty — did it start?)"
  elif [ "$2" = "$3" ]; then ok "$1"
  else bad "$1 (want '$2', got '$3')"; fi
}
differs() { # differs <desc> <a> <b> — an empty side is a failure, not a difference
  if [ -z "$2" ] || [ -z "$3" ]; then bad "$1 (a value was empty — did it start?)"
  elif [ "$2" != "$3" ]; then ok "$1"
  else bad "$1 (both are '$2')"; fi
}

build() { go build -o nsd . || exit 1; }

up() { # up [flags...]
  pkill -x nsd 2>/dev/null; sleep 0.4
  rm -rf "$RUN" "$WORK"; mkdir -p "$RUN" "$WORK"
  ./nsd up --run "$RUN" --bind "$WORK" "$@" >"$RUN/up.log" 2>&1 &
  for _ in $(seq 200); do [ -f "$RUN/ready" ] && break; sleep 0.05; done
  P1=$(cat "$RUN/ready" 2>/dev/null)
  P0=$(ps -o ppid= -p "${P1:-0}" 2>/dev/null | tr -d ' ')
  PINNED=$(ctl info | sed -n 's/^pinned_netns=//p')
  P1NET=$(ctl info | sed -n 's/^netns=//p')
}
down() { [ -n "${KEEP:-}" ] && return 0; pkill -x nsd 2>/dev/null; sleep 0.4; }
ctl() { ./nsd ctl "$RUN" "$@" 2>&1; }

startbox() {
  local out
  if ! out=$(ctl sandbox 2>&1); then
    bad "PRECONDITION: the sandbox failed to start: $out"; INIT=NOSANDBOX; return 1
  fi
  INIT=$(ctl info | sed -n 's/^sandbox_init_pid=//p')
  if [ -z "$INIT" ]; then bad "PRECONDITION: sandbox started but reported no init pid"; INIT=NOSANDBOX; return 1; fi
}

# boxwant runs a shell fragment in a REAL sandbox (a bwrap child of P1, built
# from the same argv as the long-lived one) and asserts on its output. The marker
# is the point: "the sandbox could not reach X" must not be satisfiable by a
# sandbox that never started.
boxwant() { # boxwant <desc> <expected> <shell>
  local raw out
  raw=$(ctl boxcmd /usr/bin/sh -c "echo NSDNET-MARK; $3" 2>&1)
  case "$raw" in
    *NSDNET-MARK*) ;;
    *) bad "$1 (the sandbox never ran: $(echo "$raw" | tr '\n' ' '))"; return;;
  esac
  # Drop the marker AND the client's own diagnostic. `nsd ctl` prints the
  # payload's output and THEN "nsd: exit status N" on stderr for any non-zero
  # exit, so a probe whose whole point is a failing curl arrives as two lines.
  out=$(printf '%s\n' "$raw" | grep -v '^NSDNET-MARK$' | grep -v '^nsd: ')
  want "$1" "$2" "$out"
}

atleast() { # atleast <desc> <n> <actual> — for counts with no single right value
  if [ -z "$3" ]; then bad "$1 (no count — did it start?)"
  elif [ "$3" -ge "$2" ] 2>/dev/null; then ok "$1 ($3)"
  else bad "$1 (want at least $2, got '$3')"; fi
}

build

# ---------------------------------------------------------------------------
if run N0; then
section "N0  CONTROL — with P1 IN N (run.sh's topology) both holes are OPEN"
  up
  same    "P1 reports no move" "0" "$(ctl info | sed -n 's/^p1_outside_n=//p')"
  startbox
  same    "the sandbox is in P1's netns" "$P1NET" "$(readlink /proc/$INIT/ns/net)"
  ctl bindabstract p1-secret >/dev/null 2>&1
  boxwant "HOLE OPEN: an abstract socket bound by P1 is readable from the sandbox" \
          "SECRET-FROM-P1" \
          '/usr/bin/python3 -c "
import socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
    s.connect(chr(0)+\"p1-secret\"); print(s.recv(64).decode())
except Exception as e: print(\"REFUSED\",e)"'
  boxwant "HOLE OPEN: P1's control socket path is listed by ss -xl in the sandbox" "1" \
          "/usr/sbin/ss -xl | grep -c 'nsd-netns-run/control.sock'"
  down
fi

# ---------------------------------------------------------------------------
if run N1; then
section "N1  question (a) and (b): P1 leaves N, the sandbox stays in it"
  up --p1-outside-n
  same    "P1 reports the move" "1" "$(ctl info | sed -n 's/^p1_outside_n=//p')"
  differs "P1's own netns is not the namespace it pinned" "$P1NET" "$PINNED"
  same    "P1's netns is what /proc says it is" "$P1NET" "$(readlink /proc/$P1/ns/net)"
  # The check that /proc/self/ns/net cannot make. unshare(CLONE_NEWNET) moves one
  # THREAD; only the execve that follows moves the process. Sweep the whole
  # thread group or this is unproven.
  atleast "positive control: P1 has more than one thread to be wrong about" "2" \
          "$(ls /proc/$P1/task 2>/dev/null | grep -c .)"
  want    "NO thread of P1 is left in N" "0" \
          "$(for t in /proc/$P1/task/*; do readlink $t/ns/net; done 2>/dev/null | grep -cF "$PINNED")"
  want    "every thread of P1 is in P1's own netns" "0" \
          "$(for t in /proc/$P1/task/*; do readlink $t/ns/net; done 2>/dev/null | grep -vcF "$P1NET")"

  # (a) P1 still reaches N: a child put back by setns lands in the pinned one.
  same    "(a) a child started via setns is in N" "$PINNED" \
          "$(ctl run /usr/bin/readlink /proc/self/ns/net)"
  # The control for (a): the same child WITHOUT the setns stays with P1.
  same    "(a) control: the same child without setns stays in P1's netns" "$P1NET" \
          "$(ctl runstage /usr/bin/readlink /proc/self/ns/net)"

  startbox
  # (b) stated exactly as the plan states it: two readlinks, both directions.
  same    "(b) readlink /proc/<sandbox>/ns/net == the pinned N" \
          "$PINNED" "$(readlink /proc/$INIT/ns/net)"
  differs "(b) readlink /proc/<P1>/ns/net != readlink /proc/<sandbox>/ns/net" \
          "$(readlink /proc/$P1/ns/net)" "$(readlink /proc/$INIT/ns/net)"
  boxwant "(b) and the sandbox says the same thing from the inside" "$PINNED" \
          "/usr/bin/readlink /proc/self/ns/net"

  # The descriptor must not travel: __innetns closes it before exec, so nothing
  # downstream of bwrap holds a reference to N.
  want    "positive control: P1 itself holds a descriptor on N" "1" \
          "$(ls -l /proc/$P1/fd 2>/dev/null | grep -cF "$PINNED")"
  want    "no descriptor on N survives into the sandbox's init" "0" \
          "$(ls -l /proc/$INIT/fd 2>/dev/null | grep -cF "$PINNED")"
  down
fi

# ---------------------------------------------------------------------------
if run N2; then
section "N2  question (c): pasta has to be aimed by a PINNED reference"
  (python3 -m http.server 18098 --bind 127.0.0.1 >/dev/null 2>&1 &)
  sleep 0.7
  want "host control: the loopback listener answers on the host" "200" \
       "$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18098/)"
  up --p1-outside-n --net
  startbox
  same    "the sandbox is still in N with pasta attached" "$PINNED" "$(readlink /proc/$INIT/ns/net)"
  boxwant "egress from the sandbox works" "200" \
          "/usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}\n' http://example.com"
  want    "egress from N works for a setns child too" "200" \
          "$(ctl run /usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}\n' http://example.com)"
  want    "and P1's OWN netns is empty — no egress there" "000" \
          "$(ctl runstage /usr/bin/curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://example.com | head -1)"
  want    "P1's own netns has only lo" "1" \
          "$(ctl runstage /usr/bin/cat /proc/self/net/dev | tail -n +3 | grep -c .)"
  boxwant "host loopback from the sandbox: still refused" "000" \
          "/usr/bin/curl -s -m 3 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18098/"

  # SUPERVISOR §5 asks for exactly this, and it is the one part of "no snug
  # process in N" that can be measured rather than reasoned about. pasta cannot
  # be inspected from outside — it sets itself non-dumpable, so
  # readlink /proc/<pasta>/ns/net is EACCES — so ask N instead of asking pasta.
  boxwant "with pasta attached, N holds no listening TCP or UDP socket at all" "0" \
          "/usr/sbin/ss -tulnH | grep -c ."
  (ctl run /usr/bin/python3 -m http.server 18097 --bind 0.0.0.0 >/dev/null 2>&1 &)
  sleep 1.2
  boxwant "positive control: ss in the sandbox DOES see a listener bound in N" "1" \
          "/usr/sbin/ss -tulnH | grep -c ':18097'"
  down
  pkill -f 'http.server 18098'
fi

# ---------------------------------------------------------------------------
if run N4; then
section "N4  the trap the plan names: aiming pasta the OLD way after the move"
  up --p1-outside-n --net --pasta-naive
  startbox
  want    "P0 still reports pasta up — the failure is silent" "1" \
          "$(grep -c 'pasta up' "$RUN/up.log")"
  want    "pasta went to P1's own netns: egress THERE works" "200" \
          "$(ctl runstage /usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}\n' http://example.com)"
  boxwant "so the sandbox, which is in N, has NO egress" "000" \
          "/usr/bin/curl -s -m 6 -o /dev/null -w '%{http_code}\n' http://example.com"
  down
fi

# ---------------------------------------------------------------------------
if run N3; then
section "N3  question (d): the payoff — is P1 unreachable from inside N"
  up --p1-outside-n
  startbox
  # Positive control for the whole section: a helper that IS in N, bound to an
  # abstract name, must be reachable. Otherwise "not reachable" is a statement
  # about the probe and not about the namespace.
  (ctl run /usr/bin/python3 -c '
import socket,os,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind("\0in-n-helper"); s.listen(1)
if os.fork()==0:
    c,_=s.accept(); c.send(b"SECRET-FROM-N"); c.close(); sys.exit(0)
' >/dev/null 2>&1 &)
  # And a pathname listener in N, so the ss -xl check has something to find.
  (ctl run /usr/bin/python3 -c '
import socket,os
try: os.unlink("/tmp/nsd-in-N.sock")
except OSError: pass
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind("/tmp/nsd-in-N.sock"); s.listen(1)
import time; time.sleep(60)
' >/dev/null 2>&1 &)
  ctl bindabstract p1-secret >/dev/null 2>&1
  sleep 1.0

  boxwant "positive control: an abstract socket bound IN N is readable from the sandbox" \
          "SECRET-FROM-N" \
          '/usr/bin/python3 -c "
import socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
    s.connect(chr(0)+\"in-n-helper\"); print(s.recv(64).decode())
except Exception as e: print(\"REFUSED\",e)"'
  boxwant "CLOSED: the abstract socket P1 bound is NOT reachable" \
          "REFUSED [Errno 111] Connection refused" \
          '/usr/bin/python3 -c "
import socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
    s.connect(chr(0)+\"p1-secret\"); print(s.recv(64).decode())
except Exception as e: print(\"REFUSED\",e)"'
  want    "control: P1 really did bind it, in its own netns" "1" \
          "$(ctl runstage /usr/bin/ss -xl | grep -c 'p1-secret')"

  boxwant "positive control: ss -xl in the sandbox DOES list a pathname socket bound in N" "1" \
          "/usr/sbin/ss -xl | grep -c 'nsd-in-N.sock'"
  boxwant "CLOSED: ss -xl in the sandbox does NOT list P1's control socket" "0" \
          "/usr/sbin/ss -xl | grep -c 'nsd-netns-run/control.sock'"
  want    "control: the control socket does exist and answers on the host" "pong" "$(ctl ping)"
  boxwant "and its path is still not in the sandbox's mount namespace" "ABSENT" \
          "if [ -e '$RUN/control.sock' ]; then echo PRESENT; else echo ABSENT; fi"
  down
fi

# ---------------------------------------------------------------------------
if run N5; then
section "N5  teardown, with N now pinned by a DESCRIPTOR rather than by P1 living in it"
  up --p1-outside-n --net
  startbox
  # Not "1": N holds bwrap, the sandbox init and pasta. The number is not the
  # point — that N is occupied before the kill is.
  atleast "positive control: something is in N before the kill" "1" \
       "$(ls -l /proc/*/ns/net 2>/dev/null | grep -cF "$PINNED")"
  want "positive control: the sandbox init is alive before the kill" "1" \
       "$(ls -d /proc/$INIT 2>/dev/null | grep -c .)"
  kill -9 "$P0"; sleep 1.5
  want "the stage is gone" "0" "$(ls -d /proc/$P1 2>/dev/null | grep -c .)"
  want "the sandbox init is gone" "0" "$(ls -d /proc/$INIT 2>/dev/null | grep -c .)"
  want "N is gone — the pinning descriptor died with P1" "0" \
       "$(ls -l /proc/*/ns/net 2>/dev/null | grep -cF "$PINNED")"
  want "P1's own netns is gone too" "0" \
       "$(ls -l /proc/*/ns/net 2>/dev/null | grep -cF "$P1NET")"
  down
fi

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
