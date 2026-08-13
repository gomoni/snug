#!/bin/bash
# 0c — the graft collisions, measured against a REAL snug sandbox.
#
# SUPERVISOR.md §8 calls the grafts for /etc/containers, /run and /var/tmp "the
# same mechanism repeated". This script exists to find out whether that is true.
# It is separate from run.sh on purpose: run.sh measures the PoC's own sandbox,
# which is a bare bwrap with a WRITABLE tmpfs root and nothing staged in it, and
# every question below is about what snug's sandbox actually contains —
# /run/snug/bin first on PATH, a read-only root, grants under /run.
#
# The two rules from run.sh's header apply here unchanged and are the reason
# most of these checks are two lines rather than one:
#
#   1. Never assert an exit code as a negative. A graft that never happened and
#      a graft that happened and was invisible both exit 0.
#   2. Every negative has a positive control FIRST. "the derived view has no
#      staged claude" is a statement about the sandbox only if the sandbox had
#      one to lose, so G0 measures that before anything is grafted.
#
#   ./run-graft.sh          all of it
#   ./run-graft.sh G3       one section
#   KEEP=1 ./run-graft.sh   leave the sandbox up afterwards
#
# It re-execs itself under `unshare -Urm` because the graft needs what P1 will
# have and a shell does not: CAP_SYS_ADMIN in a user namespace that is an
# ancestor of the one owning the sandbox's mounts. That is the stage, reduced to
# the one property this measurement depends on.
set -u

cd "$(dirname "$0")"
WORK=${WORK:-/tmp/nsd-graft-work}
ONLY=${1:-}
pass=0; fail=0

ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
note() { echo "  ....  $*"; }
want() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi; }
has()  { # has <description> <needle> <haystack>
  case "$3" in *"$2"*) ok "$1";; *) bad "$1 (no '$2' in: $(echo "$3" | tr '\n' '|'))";; esac
}
section() { echo; echo "== $*"; }
run()  { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# ---------------------------------------------------------------- build & stage

if [ -z "${NSDGRAFT_STAGE:-}" ]; then
  cc -O2 -o nsdgraft join/nsdgraft.c || exit 1
  cc -O2 -o nsdjoin  join/nsdjoin.c  || exit 1
  ( cd ../.. && go build -o poc/nsd/snug-under-test ./cmd/snug ) || exit 1
  # --propagation private: nothing this script mounts may reach the host.
  exec unshare -Urm --propagation private env NSDGRAFT_STAGE=1 "$0" "$@"
fi

SNUG=./snug-under-test

cleanup() { [ -n "${KEEP:-}" ] && return 0; kill "${SNUGPID:-0}" 2>/dev/null; }
trap cleanup EXIT

# ------------------------------------------------------------------- the target

rm -rf "$WORK"; mkdir -p "$WORK"

# The payload writes every in-sandbox control to a file and then sleeps, so the
# controls are taken by the sandbox itself rather than inferred from outside.
"$SNUG" --profile @claude "$WORK" -- /bin/sh -c '
  {
    echo "MNT=$(readlink /proc/self/ns/mnt)"
    echo "PATH=$PATH"
    echo "CLAUDE=$(command -v claude)"
    echo "STAGED=$(ls /run/snug/bin 2>/dev/null | tr "\n" " ")"
    echo "TOUCH=$( (touch /run/snug/bin/git) 2>&1 | sed "s/.*: //" )"
    echo "ETCCONTAINERS=$( [ -e /etc/containers ] && echo PRESENT || echo ABSENT )"
    echo "VARTMP=$( [ -e /var/tmp ] && echo PRESENT || echo ABSENT )"
    echo "RUNMOUNT=$(awk "\$2==\"/run\"{print \$1}" /proc/self/mounts)"
  } > '"$WORK"'/inside.txt
  echo READY > '"$WORK"'/ready
  exec sleep 604801' </dev/null >"$WORK/snug.log" 2>&1 &
SNUGPID=$!

for _ in $(seq 200); do [ -f "$WORK/ready" ] && break; sleep 0.05; done
if [ ! -f "$WORK/ready" ]; then
  echo "  FAIL  PRECONDITION: the sandbox never started; $WORK/snug.log says:"
  sed 's/^/        /' "$WORK/snug.log"
  exit 1
fi

get() { sed -n "s/^$1=//p" "$WORK/inside.txt"; }
MNTID=$(get MNT)
SPATH=$(get PATH)

TARGET=""
for p in /proc/[0-9]*; do
  [ "$(readlink "$p/ns/mnt" 2>/dev/null)" = "$MNTID" ] || continue
  TARGET="${p##*/}"
done
if [ -z "$TARGET" ]; then
  echo "  FAIL  PRECONDITION: no host-visible pid is in the sandbox's mount namespace"
  exit 1
fi

# inbox — run a command INSIDE the sandbox with a payload's authority.
inbox() { ./nsdjoin "$TARGET" 1 "$@" 2>&1; }
# derived — run a command in a view DERIVED from the sandbox's, with grafts.
#   derived <flags> <graft>... -- <cmd>...
derived() { ./nsdgraft "$@" 2>&1; }
# Every derived command runs with the sandbox's OWN environment, because a
# process the supervisor forks into that view inherits snug's PATH, not ours.
sh_in_sandbox_env() { echo /usr/bin/env -i "PATH=$SPATH" HOME=/nonexistent /bin/sh -c; }

# ------------------------------------------------------------- G0 the controls

if run G0; then
section "G0  positive controls — what the sandbox actually has, measured from inside it"
  want "the sandbox started and reported its mount namespace" "1" \
       "$([ -n "$MNTID" ] && echo 1 || echo 0)"
  want "snug staged an executable in /run/snug/bin" "claude " "$(get STAGED)"
  want "PATH's first element is /run/snug/bin" "/run/snug/bin" "${SPATH%%:*}"
  want "and 'claude' resolves to the staged copy" "/run/snug/bin/claude" "$(get CLAUDE)"
  want "which is NOT writable from inside" "Read-only file system" "$(get TOUCH)"
  want "there is no mount at /run — it is a directory on the root tmpfs" "" "$(get RUNMOUNT)"
  want "/etc/containers does not exist in the sandbox" "ABSENT" "$(get ETCCONTAINERS)"
  want "/var/tmp does not exist in the sandbox" "ABSENT" "$(get VARTMP)"
  want "positive control: the joiner can reach the sandbox at all" "sandbox" \
       "$(inbox /bin/sh -c 'echo sandbox')"
fi

# ------------------------------------------- G1/G2 the two grafts that cannot land

if run G1; then
section "G1  /etc/containers — the graft cannot even be created"
  want "positive control: /etc/containers exists on the host" "1" \
       "$([ -d /etc/containers ] && echo 1 || echo 0)"
  out=$(derived "$TARGET" /etc/containers:/etc/containers -- /bin/sh -c 'echo EXECED')
  has "the graft is refused by the sandbox's read-only root" \
      "GRAFT=/etc/containers mkdir=ERR:Read-only file system" "$out"
  has "positive control: the command in the derived view still ran" "EXECED" "$out"
  # And it cannot be forced. The two grafts below are in ONE invocation on
  # purpose: the /run graft is the positive control for the other one's EPERM.
  # move_mount succeeding in this view proves the process holds mount authority
  # over it, so the refusal of the remount is not missing privilege — the root
  # mount's read-only flag is LOCKED, and a locked flag cannot be cleared in a
  # derived namespace however much CAP_SYS_ADMIN the deriver has.
  out=$(derived -r "$TARGET" /etc/containers:/etc/containers /run:/run -- /bin/sh -c \
        'ls /etc/containers 2>&1 | head -1')
  has "the derived root CANNOT be remounted writable" "ROOTRW=ERR:Operation not permitted" "$out"
  has "so the graft still cannot be created" \
      "GRAFT=/etc/containers mkdir=ERR:Read-only file system" "$out"
  has "positive control: a graft at an EXISTING path in the same view lands" \
      "GRAFT=/run mkdir=EEXIST move_mount=OK" "$out"

  # The cost SUPERVISOR §6 records — "the graft leaves an empty directory on the
  # sandbox's writable tmpfs" — is a property of the PoC's WRITABLE root. Against
  # a real snug sandbox the only place a graft destination can be created is a
  # writable GRANT, and there the mkdir does not stop at a tmpfs: it persists to
  # the host, because the grant is a bind of a host directory.
  out=$(derived "$TARGET" "/etc/containers:$WORK/graftpoint" -- /bin/sh -c "ls $WORK/graftpoint | head -1")
  has "a graft onto a writable grant DOES land" "mkdir=OK move_mount=OK" "$out"
  has "and the host's /etc/containers is readable there" "certs.d" "$out"
  want "the SANDBOX does not see the graft's contents" "0" \
       "$(inbox /bin/sh -c "ls $WORK/graftpoint 2>/dev/null | wc -l")"
  want "but the mkdir DID reach it: an empty directory is now in the sandbox" "PRESENT" \
       "$(inbox /bin/sh -c "[ -d $WORK/graftpoint ] && echo PRESENT || echo ABSENT")"
  want "and on the HOST, because that grant is a bind of a host directory" "PRESENT" \
       "$([ -d "$WORK/graftpoint" ] && echo PRESENT || echo ABSENT)"
fi

if run G2; then
section "G2  /var/tmp — the same, and for the same reason"
  want "positive control: /var/tmp exists on the host" "1" \
       "$([ -d /var/tmp ] && echo 1 || echo 0)"
  out=$(derived "$TARGET" /var/tmp:/var/tmp -- /bin/sh -c 'echo EXECED')
  has "the graft is refused by the sandbox's read-only root" \
      "GRAFT=/var/tmp mkdir=ERR:Read-only file system" "$out"
  has "positive control: the command in the derived view still ran" "EXECED" "$out"
fi

# ------------------------------------------------------- G3 /run over the grants

if run G3; then
section "G3  /run — the graft lands, on top of three grants, and takes PATH with it"
  cmd=$(sh_in_sandbox_env)
  out=$(derived "$TARGET" /run:/run -- $cmd '
      echo "STAGED=$(ls /run/snug/bin 2>/dev/null | tr "\n" " ")"
      echo "CLAUDE=$(command -v claude)"
      echo "PATH0=${PATH%%:*}"
      echo "SSHSOCK=$( [ -S /run/user/1000/gcr/ssh ] && echo PRESENT || echo ABSENT )"
      echo "KEYRING=$( [ -S /run/user/1000/keyring/ssh ] && echo PRESENT || echo ABSENT )"
      echo "DBUS=$( [ -S /run/user/1000/bus ] && echo PRESENT || echo ABSENT )"
      echo "WAYLAND=$( [ -S /run/user/1000/wayland-0 ] && echo PRESENT || echo ABSENT )"
      echo "PODMAN=$( [ -S /run/user/1000/podman/podman.sock ] && echo PRESENT || echo ABSENT )"')
  has "the graft lands: /run already exists, so mkdir is EEXIST, not a refusal" \
      "GRAFT=/run mkdir=EEXIST move_mount=OK" "$out"
  has "PATH still leads with /run/snug/bin" "PATH0=/run/snug/bin" "$out"
  has "but nothing is staged there any more" "STAGED=" "$out"
  has "so the staged 'claude' no longer resolves — PATH's head is gone" "CLAUDE=" "$out"
  echo "  ---- and what the graft brought IN, with the host's own controls:"
  for s in /run/user/1000/gcr/ssh /run/user/1000/keyring/ssh /run/user/1000/bus \
           /run/user/1000/wayland-0 /run/user/1000/podman/podman.sock; do
    note "host: $s $([ -S "$s" ] && echo PRESENT || echo ABSENT)"
  done
  has "the host ssh-agent socket (\$SSH_AUTH_SOCK) is in the derived view" "SSHSOCK=PRESENT" "$out"
  has "so is the session D-Bus socket" "DBUS=PRESENT" "$out"
  has "so is the Wayland socket" "WAYLAND=PRESENT" "$out"
  has "so is the host's rootless podman socket" "PODMAN=PRESENT" "$out"
  want "the SANDBOX still sees its staged claude — the graft did not propagate" "claude" \
       "$(inbox /bin/sh -c 'ls /run/snug/bin')"
fi

# ------------------------------- G4 the head of PATH becomes writable, and is used

if run G4; then
section "G4  a WRITABLE graft at /run — the shadow slot, one layer below Validate"
  mkdir -p "$WORK/evilrun/snug/bin"
  cmd=$(sh_in_sandbox_env)
  # Nothing is planted first: the file is created from INSIDE the derived view,
  # with capabilities dropped, which is the authority a payload has.
  out=$(derived -d "$TARGET" "$WORK/evilrun:/run" -- $cmd '
      printf "#!/bin/sh\necho SHADOWED-CLAUDE\n" > /run/snug/bin/claude 2>&1 \
        && chmod 755 /run/snug/bin/claude && echo WROTE=OK || echo WROTE=FAIL
      echo "PATH0=${PATH%%:*}"
      echo "RESOLVES=$(command -v claude)"
      claude')
  has "the graft lands at /run" "GRAFT=/run mkdir=EEXIST move_mount=OK" "$out"
  has "PATH's head is unchanged and is now inside the graft" "PATH0=/run/snug/bin" "$out"
  has "an unprivileged process in the derived view can CREATE the staged bin dir" "WROTE=OK" "$out"
  has "and 'claude' now resolves to it" "RESOLVES=/run/snug/bin/claude" "$out"
  has "and running 'claude' runs the planted file" "SHADOWED-CLAUDE" "$out"
  want "positive control: the file it planted persists on the host side of the graft" "1" \
       "$([ -x "$WORK/evilrun/snug/bin/claude" ] && echo 1 || echo 0)"
  want "the sandbox's own claude is untouched — this is the derived view only" "claude" \
       "$(inbox /bin/sh -c 'ls /run/snug/bin')"
fi

if run G5; then
section "G5  a fresh tmpfs at /run — the plan's exact wording, same outcome"
  mkdir -p "$WORK/tmpfs-src"
  if ! mount -t tmpfs tmpfs "$WORK/tmpfs-src" 2>/dev/null; then
    bad "could not mount a tmpfs in the stage's own mount namespace (skipped)"
  else
    cmd=$(sh_in_sandbox_env)
    out=$(derived -d "$TARGET" "$WORK/tmpfs-src:/run" -- $cmd '
        mkdir -p /run/snug/bin 2>/dev/null && echo MKDIR=OK || echo MKDIR=FAIL
        printf "#!/bin/sh\necho SHADOWED-FROM-TMPFS\n" > /run/snug/bin/claude \
          && chmod 755 /run/snug/bin/claude && echo WROTE=OK || echo WROTE=FAIL
        echo "RESOLVES=$(command -v claude)"
        claude')
    has "the tmpfs graft lands at /run" "GRAFT=/run mkdir=EEXIST move_mount=OK" "$out"
    has "an unprivileged process creates /run/snug/bin inside it" "MKDIR=OK" "$out"
    has "and plants an executable there" "WROTE=OK" "$out"
    has "PATH's head resolves to the planted file" "RESOLVES=/run/snug/bin/claude" "$out"
    has "which runs" "SHADOWED-FROM-TMPFS" "$out"
    umount "$WORK/tmpfs-src" 2>/dev/null
  fi
fi

# --------------------------------------------------------- G6 is anything watching

if run G6; then
section "G6  is there any refusal, anywhere?"
  dry=$("$SNUG" --profile @claude --dry-run "$WORK" 2>&1)
  want "positive control: --dry-run explains the staged bin dir" "1" \
       "$(echo "$dry" | grep -c 'run/snug/bin is snug.s own')"
  want "no line of --dry-run mentions /etc/containers" "0" "$(echo "$dry" | grep -c '/etc/containers')"
  want "no line of --dry-run mentions /var/tmp" "0" "$(echo "$dry" | grep -c '/var/tmp')"
  want "the word 'graft' does not occur in internal/ or cmd/" "0" \
       "$(grep -rli graft ../../internal ../../cmd 2>/dev/null | wc -l)"
  # Validate's own refusal DOES exist for the shape one layer up. That is the
  # comparison the gate turns on: a PROFILE cannot do this, a graft can.
  want "positive control: a profile mounting at /run/snug/bin IS refused by Validate" "1" \
       "$(grep -c 'StagedBinDir: .it is a plain directory' ../../internal/policy/validate.go)"
fi

# ------------------------------- G7 the same collision, expressed as a policy object

if run G7; then
section "G7  what a POLICY object at /run would and would not catch"
  # Phase 3 proposes grafts become map[string]Mount. This section measures what
  # the existing machinery does with a Mount at /run, by writing one as a user
  # profile — the shape a graft object would have in p.Mounts. (It goes through
  # $XDG_CONFIG_HOME, which invariant 3 notes is trusted unconditionally; that
  # weakness is what makes the probe possible without touching internal/.)
  CFG="$WORK/cfg"
  mkdir -p "$CFG/snug/profiles.d"
  drun() { XDG_CONFIG_HOME="$CFG" "$SNUG" "$@" --dry-run "$WORK" 2>&1; }

  printf '[profile.graft-run]\ndescription = "the graft, as a Mount"\nro = ["/run"]\n' \
    > "$CFG/snug/profiles.d/graft.toml"
  out=$(drun --profile @claude --profile graft-run)
  has "a Mount at /run over @claude's NON-authored staged bin IS refused" \
      "REFUSED: profile @claude puts a bind of" "$out"
  has "and the refusal names the collision" "at /run/snug/bin/claude, which is inside /run" "$out"

  out=$(drun --profile @podman-socket --profile graft-run)
  want "but with @podman-socket the SAME mount is accepted: every grant under /run is Authored" "0" \
       "$(echo "$out" | grep -c '^REFUSED')"
  has "positive control: the mount really is in the resolved policy" "ro     /run" "$out"
  has "and --dry-run still promises the staged bin dir is snug's own" \
      "/run/snug/bin is snug's own and is NOT writable from inside" "$out"

  # The writable spelling. IsShadowSlot DOES see this one, because it asks
  # coveringMount and a Mount at /run covers /run/snug/bin. That is the whole
  # difference between a graft and a grant: a graft is not in that map.
  printf '[profile.graft-run]\ndescription = "the graft, as a Mount"\ntmpfs = ["/run"]\n' \
    > "$CFG/snug/profiles.d/graft.toml"
  out=$(drun --profile @podman-socket --profile graft-run)
  want "a tmpfs at /run is also accepted by Validate" "0" "$(echo "$out" | grep -c '^REFUSED')"
  has "but IsShadowSlot catches it and --dry-run says so" \
      "/run/snug/bin IS WRITABLE from inside, which it must never be" "$out"
  out=$(XDG_CONFIG_HOME="$CFG" "$SNUG" --profile @podman-socket --profile graft-run "$WORK" \
        -- /bin/sh -c '
          echo MARKER-RAN
          printf "#!/bin/sh\necho SHADOWED\n" > /run/snug/bin/git && chmod 755 /run/snug/bin/git \
            && echo WROTE=OK
          echo "GIT=$(command -v git)"
          git' </dev/null 2>&1)
  has "positive control: the sandbox actually ran" "MARKER-RAN" "$out"
  has "the payload writes into the head of PATH" "WROTE=OK" "$out"
  has "and shadows a real command" "GIT=/run/snug/bin/git" "$out"
  has "which runs" "SHADOWED" "$out"
fi

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
