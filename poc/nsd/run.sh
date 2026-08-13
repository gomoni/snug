#!/bin/bash
# Every claim in SUPERVISOR.md, re-measured.
#
# A negative result on a sandbox that never started is not a result, and this
# script claimed that property before it had it: four checks used to PASS with no
# sandbox and no attach at all (see SUPERVISOR-REVIEW.md §3). Two rules now hold
# it up, and any new check must obey both.
#
#   1. Never assert an exit code as a negative. `nsd` collapses every
#      client-side failure — no sandbox, refused setns, a socket it could not
#      even dial — to exit 1, which is also what `test -e` returns for a file
#      that is not there. Assert a MARKER the payload emits instead: see probe().
#   2. Never compare two namespace ids with a bare `!=`. readlink prints nothing
#      for a pid that does not exist, and an empty string differs from
#      everything. Use differs(), which refuses an empty side.
#
#   ./run.sh            all experiments
#   ./run.sh E4         one of them
set -u

cd "$(dirname "$0")"
RUN=${RUN:-/tmp/nsd-run}
WORK=${WORK:-/tmp/nsd-work}
ONLY=${1:-}
pass=0; fail=0

ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
want() { # want <description> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}
section() { echo; echo "== $*"; }   # NOT named head(): a function called head shadows /usr/bin/head in every pipeline below
run()  { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

build() {
  go build -o nsd . || exit 1
  cc -O2 -o nsdjoin join/nsdjoin.c || exit 1
  cc -O2 -o nsowner join/nsowner.c || exit 1
  cc -O2 -o nsdmount join/nsdmount.c || exit 1
}

up() { # up [--net]
  pkill -x nsd 2>/dev/null; sleep 0.3
  rm -rf "$RUN" "$WORK"; mkdir -p "$RUN" "$WORK"
  ./nsd up --run "$RUN" --bind "$WORK" "$@" >"$RUN/up.log" 2>&1 &
  for _ in $(seq 100); do [ -f "$RUN/ready" ] && break; sleep 0.05; done
  P1=$(cat "$RUN/ready")
  P0=$(ps -o ppid= -p "$P1" | tr -d ' ')
}
down() { [ -n "${KEEP:-}" ] && return 0; pkill -x nsd 2>/dev/null; sleep 0.3; }
ctl() { ./nsd ctl "$RUN" "$@" 2>&1; }
inbox() { ctl attach 0 1 "$@"; }   # in the sandbox, capabilities dropped

differs() { # differs <description> <a> <b> — an empty side is a failure, not a difference
  if [ -z "$2" ] || [ -z "$3" ]; then
    bad "$1 (a namespace id was empty — did it start?)"
  elif [ "$2" != "$3" ]; then ok "$1"
  else bad "$1 (both are '$2')"
  fi
}

startbox() { # start the sandbox and set INIT, or say so loudly
  local out
  out=$(ctl sandbox 2>&1)
  if [ $? -ne 0 ]; then bad "PRECONDITION: the sandbox failed to start: $out"; INIT=NOSANDBOX; return 1; fi
  INIT=$(ctl info | sed -n 's/sandbox_init_pid=//p')
  if [ -z "$INIT" ]; then bad "PRECONDITION: the sandbox started but reported no init pid"; INIT=NOSANDBOX; return 1; fi
  # INIT is deliberately a sentinel and not empty on failure: every check below
  # reads /proc/$INIT/..., and an empty pid there silently yields an empty
  # string that compares equal to another empty string.
}

probe() { # probe <path> — PRESENT or ABSENT, from inside the sandbox, or nothing
  # A marker, not an exit code. If the attach never happened this prints the
  # client's error and no assertion against it can pass.
  inbox /bin/sh -c "if [ -e '$1' ]; then echo NSDPROBE-PRESENT; else echo NSDPROBE-ABSENT; fi"
}

build

if run E1; then
section "E1  the stage: full subuid map, own netns, capabilities restored by re-exec"
  up
  # Read the uid from INSIDE the namespace: /proc/<pid>/status is rendered in the
  # READER's user namespace, so from the host it says 1000 either way.
  want "stage runs as uid 0 in its own user namespace" "0" "$(ctl run /usr/bin/id -u)"
  want "uid_map has both the host uid and the subuid range" "2" "$(grep -c . /proc/$P1/uid_map)"
  want "gid_map has both" "2" "$(grep -c . /proc/$P1/gid_map)"
  want "capabilities present in its own userns" "000001ffffffffff" "$(awk '/^CapEff/{print $2}' /proc/$P1/status)"
  differs "netns differs from the host's" \
          "$(readlink /proc/$P1/ns/net)" "$(readlink /proc/self/ns/net)"
  want "control socket answers from the host" "pong" "$(ctl ping)"
  down
fi

if run E2; then
section "E2  the sandbox is a child of the stage: netns inherited, host uid carried"
  up
  startbox
  want "sandbox netns is the stage's netns" "$(readlink /proc/$P1/ns/net)" "$(readlink /proc/$INIT/ns/net)"
  differs "sandbox has its own user namespace" \
          "$(readlink /proc/$INIT/ns/user)" "$(readlink /proc/$P1/ns/user)"
  want "payload sees the host uid, not 0" "1000" "$(inbox /usr/bin/id -u)"
  want "a file it writes on the bind is owned by the host user" "1000" \
       "$(stat -c %u "$WORK/written-by-sandbox" 2>/dev/null)"
  down
fi

if run E3; then
section "E3  attach: a new process injected into a running sandbox from outside"
  up
  startbox
  want "attached process is in the sandbox mount namespace" \
       "$(readlink /proc/$INIT/ns/mnt)" "$(inbox /usr/bin/readlink /proc/self/ns/mnt)"
  want "attached process is in the sandbox pid namespace" \
       "$(readlink /proc/$INIT/ns/pid)" "$(inbox /usr/bin/readlink /proc/self/ns/pid)"
  want "it sees the sandbox's tmpfs, not the host's /tmp" "init was here" \
       "$(inbox /usr/bin/cat /tmp/marker-from-init)"
  # Positive control first: assert the path IS there to be seen, on the host,
  # or "the sandbox cannot see it" is a statement about the host and not about
  # the sandbox. HOSTONLY is whatever exists; $HOME/.ssh when it does.
  HOSTONLY="$HOME/.ssh"; [ -e "$HOSTONLY" ] || HOSTONLY="$HOME"
  want "control: the ungranted path exists on the host" "yes" \
       "$([ -e "$HOSTONLY" ] && echo yes || echo no)"
  want "it does NOT see an ungranted host path" "NSDPROBE-ABSENT" "$(probe "$HOSTONLY")"

  # Positive control on the ORDER, which is the whole trick.
  out=$(NSDJOIN_ORDER=user,mnt,pid,ipc,uts,net,cgroup ./nsdjoin "$INIT" 1 /usr/bin/true 2>&1)
  case "$out" in
    *"setns"*"not permitted"*) ok "user-namespace-first order is refused by the kernel (control)";;
    *) bad "expected EPERM joining the user namespace first, got: $out";;
  esac
  down
fi

if run E4; then
section "E4  attach must drop what it is handed: setns into a userns grants every capability"
  up
  startbox
  want "undropped: bounding set is full — a file-capability binary would be a way back up" \
       "000001ffffffffff" "$(ctl attach 0 0 /usr/bin/grep CapBnd /proc/self/status | awk '{print $2}')"
  want "undropped: no_new_privs is NOT set" "0" \
       "$(ctl attach 0 0 /usr/bin/grep NoNewPrivs /proc/self/status | awk '{print $2}')"
  want "dropped: bounding set empty" "0000000000000000" \
       "$(ctl attach 0 1 /usr/bin/grep CapBnd /proc/self/status | awk '{print $2}')"
  want "dropped: no_new_privs set" "1" \
       "$(ctl attach 0 1 /usr/bin/grep NoNewPrivs /proc/self/status | awk '{print $2}')"
  want "NOT YET DONE either way: no seccomp filter on an attached process" "0" \
       "$(ctl attach 0 1 /usr/bin/grep Seccomp: /proc/self/status | awk '{print $2}')"
  down
fi

if run E5; then
section "E5  network: egress works, host loopback does not, in the namespace and in the sandbox"
  (python3 -m http.server 18099 --bind 127.0.0.1 >/dev/null 2>&1 &)
  sleep 0.7
  want "host control: the listener answers on the host" "200" \
       "$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18099/)"
  up --net
  startbox
  want "egress from the namespace" "200" \
       "$(ctl run /usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}' http://example.com)"
  want "egress from the sandbox" "200" \
       "$(inbox /usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}' http://example.com)"
  want "host loopback from the namespace: refused" "000" \
       "$(ctl run /usr/bin/curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18099/ | head -1)"
  want "host loopback from the sandbox: refused" "000" \
       "$(inbox /usr/bin/curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18099/ | head -1)"
  down
  pkill -f 'http.server 18099'
fi

if run E6; then
section "E6  the new hole this topology opens: the stage now SHARES the sandbox's netns"
  up
  startbox
  # A host-side helper binds an ABSTRACT socket in the namespace the sandbox shares.
  ctl run /usr/bin/python3 -c '
import socket,os,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind("\0nsd-secret"); s.listen(1)
if os.fork()==0:
    c,_=s.accept(); c.send(b"SECRET-FROM-A-HOST-SIDE-HELPER"); c.close(); sys.exit(0)
' >/dev/null 2>&1 &
  sleep 0.7
  got=$(inbox /usr/bin/python3 -c '
import socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
    s.connect("\0nsd-secret"); print(s.recv(64).decode())
except Exception as e: print("REFUSED",e)
')
  # These two assert the HOLE, not its absence. Abstract sockets are scoped to
  # the network namespace, and under this topology the stage and the engine are
  # IN the sandbox's network namespace. Today's snug guarantee ("abstract sockets
  # unreachable") survives only because nothing else lives in that namespace.
  case "$got" in
    *SECRET-FROM-A-HOST-SIDE-HELPER*)
      ok "HOLE CONFIRMED: an abstract socket bound by a host-side helper is reachable from the sandbox";;
    *) bad "expected the abstract socket to be reachable, got: $got";;
  esac
  if inbox /usr/bin/ss -xl | grep -q "$RUN/control.sock"; then
    ok "HOLE CONFIRMED: the stage control socket's PATH is listed inside the sandbox (ss -xl)"
  else
    bad "expected the control socket to be listed"
  fi
  want "control: the socket exists on the host" "NSDPROBE-PRESENT" \
       "$([ -e "$RUN/control.sock" ] && echo NSDPROBE-PRESENT || echo NSDPROBE-ABSENT)"
  want "but it cannot be connected to: the path is not in the sandbox's mount ns" \
       "NSDPROBE-ABSENT" "$(probe "$RUN/control.sock")"
  down
fi

if run E7; then
section "E7  the engine-shaped child: same U and N, its own private copy of the HOST mount tree"
  up
  out=$(ctl runmnt /usr/bin/sh -c 'echo NET=$(readlink /proc/self/ns/net); ls -d '"$HOME"'/.ssh >/dev/null 2>&1 && echo HOSTTREE=yes')
  want "engine child stays in the sandbox's netns" "NET=$(readlink /proc/$P1/ns/net)" "$(echo "$out" | sed -n 1p)"
  want "engine child sees the host filesystem, unlike the sandbox" "HOSTTREE=yes" "$(echo "$out" | sed -n 2p)"
  down
fi

if run E9; then
section "E9  two payloads in one sandbox — the tmux shape"
  up
  startbox
  (inbox /usr/bin/sh -c 'echo from-payload-A > /tmp/shared; sleep 30' >/dev/null 2>&1 &)
  sleep 0.7
  want "a second attached payload sees the first one's file on the shared tmpfs" "from-payload-A" \
       "$(inbox /usr/bin/cat /tmp/shared)"
  want "and sees it in the same pid namespace" "1" \
       "$(inbox /usr/bin/sh -c 'ps -eo comm= | grep -c "^sleep$"')"
  want "the host does NOT see that file" "1" \
       "$(test -e /tmp/shared >/dev/null 2>&1; echo $?)"
  down
fi

if run E10; then
section "E10 the engine in a view DERIVED from the sandbox, with storage grafted in"
  up
  echo hostfile > "$WORK/from-host"
  startbox
  STORE="$HOME/.local/share/containers/storage"
  out=$(ctl graft "$STORE" /storage /usr/bin/sh -c '
     ls /storage >/dev/null 2>&1 && echo GRAFT=yes
     ls -d '"$HOME"'/.ssh >/dev/null 2>&1 && echo HOSTTREE=yes || echo HOSTTREE=no
     cat /work/from-host 2>/dev/null || echo NOWORK
     test -e /proc/self/mountinfo && echo PROC=yes || echo PROC=no')
  want "the host path is grafted into the derived view" "GRAFT=yes" "$(echo "$out" | sed -n 1p)"
  want "the rest of the host tree is NOT there — this is the sandbox's view" "HOSTTREE=no" "$(echo "$out" | sed -n 2p)"
  want "the sandbox's own grants ARE there" "hostfile" "$(echo "$out" | sed -n 3p)"
  want "but /proc belongs to the sandbox's pid namespace, so the engine has none" "PROC=no" "$(echo "$out" | sed -n 4p)"
  want "the graft does NOT propagate into the sandbox" "0" "$(inbox /usr/bin/sh -c 'ls /storage 2>/dev/null | wc -l')"
  want "it does leave an empty directory behind, though" "0" \
       "$(inbox /usr/bin/test -d /storage >/dev/null 2>&1; echo $?)"
  down
fi

if run E11; then
section "E11 P1 is not a daemon: it dies when its last payload does"
  up
  ctl sandbox 2 >/dev/null          # sandbox whose payload exits after 2s
  INIT=$(ctl info | sed -n 's/sandbox_init_pid=//p')
  NETNS=$(readlink /proc/$P1/ns/net | tr -d 'net:[]')
  want "positive control: the stage is serving while the payload runs" "pong" "$(ctl ping)"
  sleep 3.5
  want "the stage exited on its own" "0" "$(ls -d /proc/$P1 2>/dev/null | grep -c .)"
  want "so did the launcher" "0" "$(ls -d /proc/$P0 2>/dev/null | grep -c .)"
  want "the network namespace is gone" "0" "$(ls -l /proc/*/ns/net 2>/dev/null | grep -cF "$NETNS")"
  want "and it did NOT stay up waiting for a client" "1" \
       "$(ctl ping >/dev/null 2>&1; echo $?)"
  down
fi

if run E8; then
section "E8  teardown: SIGKILL the launcher, nothing survives"
  up --net
  startbox
  NETNS=$(readlink /proc/$P1/ns/net | tr -d 'net:[]')
  (ctl attach 0 1 /usr/bin/sleep 300 >/dev/null 2>&1 &)
  sleep 0.7
  want "positive control: the sandbox init is alive before the kill" "1" \
       "$(ls -d /proc/$INIT 2>/dev/null | grep -c .)"
  kill -9 "$P0"; sleep 1.5
  want "the stage is gone" "0" "$(ls -d /proc/$P1 2>/dev/null | grep -c .)"
  want "the sandbox init is gone" "0" "$(ls -d /proc/$INIT 2>/dev/null | grep -c .)"
  want "no process is left in the network namespace" "0" \
       "$(ls -l /proc/*/ns/net 2>/dev/null | grep -cF "$NETNS")"
  want "no attached payload left" "0" "$(pgrep -x nsdjoin 2>/dev/null | wc -l)"
  down
fi

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
