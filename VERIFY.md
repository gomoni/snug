# Verifying snug by hand

A sandbox you have not personally tried to break is a sandbox you are trusting
on someone's word. This is the checklist for not doing that.

Every command below was run on the development host and produced the output
shown. If yours differs, that is a finding — see [If a check fails](#if-a-check-fails).

Setup used throughout:

```bash
cd /path/to/snug
make build

SC=$(mktemp -d)
mkdir -p $SC/proj/sub $SC/proj/sibling $SC/other
echo secret > $SC/other/CANARY
echo top    > $SC/CANARY-TOP
```

`$SC/proj/sub` is the sandbox target. `$SC/proj/sibling` sits beside it,
`$SC/other` is one level above, and `$SC/CANARY-TOP` is two.

---

## 0. The gate

```bash
make gate        # gofmt, go vet, go test ./...
```

Expect: all packages `ok`. These tests need no privileges and no namespaces —
that is deliberate, so the security-critical parts are checkable anywhere.

## 1. Can this host run it at all

```bash
./bin/snug doctor
```

Expect ✅ on bubblewrap, user namespaces, and a private network namespace. A ❌
names the exact sysctl or package to fix. Running inside distrobox/podman is
reported and supported.

## 2. Read before you run

```bash
./bin/snug --dry-run $SC/proj/sub
```

This starts nothing. Read the `FILESYSTEM` block: **every line is a grant, and
the sandbox is the sum of exactly those lines.** Then check the rest of this
document against what it claimed. If `--dry-run` and reality ever disagree, that
is the most serious class of bug in this project, because every other guarantee
is read off this output.

## 3. The writable surface

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c '
for d in / /home /usr /etc /var /proc; do
  touch $d/ZZ 2>/dev/null && echo "WRITABLE: $d  <-- FAIL" || echo "ro: $d"
done'
```

Expect every line `ro:`. Anything reported WRITABLE is a real finding.

The complete writable surface is **seven** paths, and only the first survives
the sandbox:

| path | kind | persists? |
|---|---|---|
| the target directory | bind, rw | **yes** — this is the point |
| `/tmp` | tmpfs | no |
| `$HOME` | tmpfs | no |
| `$HOME/.cache`, `$HOME/.config`, `$HOME/.local/state` | tmpfs | no |
| `/dev` | tmpfs (bwrap's synthetic `/dev`) | no |

`/dev` being writable surprises people (it surprised the author — it was found
by this checklist, not by design review). It is bwrap's own minimal `/dev` on a
private tmpfs, so it is contained. Confirm that yourself rather than believing
it:

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c 'echo pwned > /dev/ESCAPE_PROBE'
ls /dev/ESCAPE_PROBE                                    # host: No such file
./bin/snug $SC/proj/sub -- /bin/sh -c 'ls /dev/ESCAPE_PROBE'   # next run: gone
```

Expect both to report the file missing. The write never reached the host and did
not survive the sandbox.

## 4. What must be absent

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c "
ls $SC/CANARY-TOP ; ls $SC/other ; ls ~/.ssh ; ls /sys"
```

Expect four × `No such file or directory`. Note the wording: these paths are
**absent**, not permission-denied. They were never mounted, so there is nothing
there to deny access to.

Try the same for anything else you care about — `~/.gnupg`, `~/.aws`,
`~/.config/gh`, your other projects.

## 5. What `@parent-ro` actually grants

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c "ls $SC/proj"
```

Expect `sibling  sub` — **both**. This is correct and intentional: `@parent-ro`
grants the target's *parent*, so the target's siblings are readable. That is
what makes `../other-package` work in a monorepo.

What must not be reachable is anything **above** the parent, which is what
check 4 confirms with `$SC/other` and `$SC/CANARY-TOP`.

If you do not want siblings readable, drop `@parent-ro`:

```bash
./bin/snug --no-defaults -p @sys -p @cwd-rw $SC/proj/sub -- /bin/sh -c "ls $SC/proj"
```

Expect `No such file or directory`.

## 6. The environment is rebuilt, not inherited

```bash
./bin/snug $SC/proj/sub -- /usr/bin/printenv | sort
```

Expect ~14 variables, all of them snug's own (`HOME`, `PATH`, `SNUG`,
`SNUG_PROFILES`, `SNUG_TARGET`, …). Specifically expect **no**
`DBUS_SESSION_BUS_ADDRESS`, no `SSH_AUTH_SOCK`, no `XDG_RUNTIME_DIR`, no API
tokens.

Caveat worth knowing: `--clearenv` is not the last word. `/etc/profile.d/*`
runs inside a login shell and can put variables back. That is why `@sys`
enumerates `/etc` instead of binding it wholesale — see DESIGN §5.3.

### 6b. …including via PID 1 (regression check)

```bash
export CANARY_TOKEN="sk-must-not-appear"
./bin/snug $SC/proj/sub -- /bin/sh -c 'tr "\0" "\n" < /proc/1/environ | grep -c .'
./bin/snug $SC/proj/sub -- /bin/sh -c 'tr "\0" "\n" < /proc/1/environ | grep -E "CANARY|SSH_AUTH|SECRET"'
```

Expect `0` and no matches.

This one earned its place. bwrap is PID 1 in the sandbox's own PID namespace and
runs as your uid, so `/proc/1/environ` is readable from inside. `--clearenv`
only clears the environment given to the *payload* — it says nothing about
bwrap's own. Before this was fixed, the payload's `env` was spotlessly clean
while `/proc/1/environ` handed over 106 host variables including
`SSH_AUTH_SOCK`. Found by the `redteam` agent, not by review, and invisible to
the golden-argv tests.

### 6a. You can tell you are inside

```bash
./bin/snug $SC/proj/sub
```

Expect the prompt `🔒 snug:~/...$` and `hostname` reporting `snug`. Because snug
does not grant `/etc/bash.bashrc`, the shell is spartan — no completion, no
distro prompt — which is expected. The lock prompt is set by snug itself so that
neither a human nor an agent has to guess whether a shell is sandboxed. Type
`exit` to leave.

## 6c. The seccomp filter is actually installed

Requested is not the same as active. Check the kernel's view first:

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c 'grep ^Seccomp: /proc/self/status'
```

Expect `Seccomp: 2` (filter mode). A `0` means no filter, whatever snug claimed —
this exact reading is what caught `--seccomp` being passed *after* bwrap's `--`
separator, where it was silently treated as an argument to the payload.

Then check it denies the right things:

```bash
cat > $SC/proj/sub/probe.py <<'EOF'
import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
for name, nr in [("ptrace",101),("keyctl",250),("perf_event_open",298),
                 ("add_key",248),("bpf",321),("userfaultfd",323)]:
    ctypes.set_errno(0); libc.syscall(nr, 0,0,0,0,0); e = ctypes.get_errno()
    print("%-16s %s" % (name, os.strerror(e) if e else "ALLOWED"))
EOF

./bin/snug $SC/proj/sub -- python3 probe.py                 # all: Operation not permitted
./bin/snug --no-seccomp $SC/proj/sub -- python3 probe.py    # host behaviour returns
./bin/snug $SC/proj/sub -- /bin/sh -c 'unshare -U /bin/true' # Operation not permitted
```

Syscall numbers above are x86_64. Note the cost, which is deliberate: with the
filter on you cannot run snug inside snug, or rootless podman inside it.

## 7. The network namespace

```bash
# host listener the sandbox must not reach
python3 -m http.server 18099 --bind 127.0.0.1 &
sleep 1; curl -s -o /dev/null -w "host sees it: %{http_code}\n" http://127.0.0.1:18099/

./bin/snug $SC/proj/sub -- /bin/sh -c '
  cat /proc/net/dev | awk "NR>2{print \$1}" | tr -d " "
  timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/18099" 2>/dev/null \
    && echo "REACHED HOST <-- FAIL" || echo "host loopback: refused (correct)"'

kill %1
```

Expect `host sees it: 200`, then `lo:` as the only interface, then
`host loopback: refused`. The sandbox's `127.0.0.1` is its own loopback, a
different one from the host's.

M0 is offline by design — there is no egress either. That is not a bug; it is
the floor, and networking arrives as an explicit profile in M2.

## 8. Profile order is irrelevant

```bash
A=$(./bin/snug --dry-run -p @sys -p @cwd-rw -p @parent-ro $SC/proj/sub | sed -n '/── bwrap/,$p' | md5sum)
B=$(./bin/snug --dry-run -p @parent-ro -p @cwd-rw -p @sys $SC/proj/sub | sed -n '/── bwrap/,$p' | md5sum)
[ "$A" = "$B" ] && echo "identical: ok" || echo "DIFFERENT <-- FAIL"
```

Expect `identical: ok`. Order-dependence would mean the sandbox you get depends
on how you typed the command, and "profiles only relax" would stop being
checkable.

## 9. A profile cannot take anything away

Use a throwaway config dir so you do not touch your real one:

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d

mkdir -p $X/empty
cat > $X/snug/profiles.d/evil.toml <<EOF
[profile.hide-ssl]
description = "try to mask part of another profile's grant"
tmpfs = ["/etc/ssl"]

[profile.etc-full]
description = "all of /etc — not a builtin; one line in your own profiles.d"
ro = ["/etc"]

[profile.hide-profiled]
description = "try to mask a path nested inside another grant"
tmpfs = ["/etc/profile.d"]

[profile.mask-misc]
description = "mask by binding an unrelated empty dir over it"
ro = ["$X/empty:/usr/share/misc"]

[profile.greedy]
description = "try to grant the whole host"
ro = ["/"]
EOF

XDG_CONFIG_HOME=$X ./bin/snug -p hide-ssl               $SC/proj/sub -- /bin/true
XDG_CONFIG_HOME=$X ./bin/snug -p etc-full -p hide-profiled $SC/proj/sub -- /bin/true   # etc-full is defined in evil.toml above, not a builtin
XDG_CONFIG_HOME=$X ./bin/snug -p mask-misc              $SC/proj/sub -- /bin/true
XDG_CONFIG_HOME=$X ./bin/snug -p greedy                 $SC/proj/sub -- /bin/true

rm -rf $X
```

Expect four refusals:

```
snug: conflict at /etc/ssl: tmpfs (from hide-ssl) vs bind (from @sys)

snug: profile hide-profiled puts an empty tmpfs at /etc/profile.d, which is inside /etc
      from profile etc-full. That hides what /etc already exposes there, and profiles
      may only ever grant.

snug: profile mask-misc puts a bind of .../empty at /usr/share/misc, which is inside
      /usr from profile @sys. That hides what /usr already exposes there...

snug: refusing to bind / (from greedy)
```

The third is a regression check. `rejectMasking` originally inspected only
tmpfs grants, so a *bind* of an unrelated directory walked straight through it —
`/usr/share/misc` went from three entries to zero, silently. Found by the
`redteam` agent.

Confirm the legitimate nesting still works, since the fix could easily have
broken it — the default selection lays `@cwd-rw`'s writable target over `@parent-ro`'s
read-only parent, which is re-granting the same tree, not masking:

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c 'ls /usr/share/misc | wc -l; touch ./x && echo "target writable ok"'
```

Also try an unknown key, which must be fatal rather than ignored:

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d
printf '[profile.x]\nmask = ["/etc"]\n' > $X/snug/profiles.d/x.toml
XDG_CONFIG_HOME=$X ./bin/snug -p x $SC/proj/sub -- /bin/true
rm -rf $X
```

Expect a parse error naming the unknown key. A silently-ignored `mask` would let
someone believe their sandbox is tighter than it is.

## 9b. The `@` namespace belongs to snug

`@` marks a profile snug ships. Nothing else may wear it, so a name in
`--dry-run` or in `$SNUG_PROFILES` tells you whose grant it is without a lookup.

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d

# a profile of your own is fine, and is the control: if this fails, the
# refusals below prove nothing about the sigil
printf '[profile.mysys]\nro = ["/usr"]\n' > $X/snug/profiles.d/mine.toml
XDG_CONFIG_HOME=$X ./bin/snug --dry-run -p mysys $SC/proj/sub >/dev/null && echo "control ok"

# claiming the mark is refused at load, whether or not it collides
printf '[profile."@sys"]\nro = ["/"]\n' > $X/snug/profiles.d/mine.toml
XDG_CONFIG_HOME=$X ./bin/snug --dry-run $SC/proj/sub
printf '[profile."@mine"]\nro = ["/usr"]\n' > $X/snug/profiles.d/mine.toml
XDG_CONFIG_HOME=$X ./bin/snug --dry-run $SC/proj/sub

rm -rf $X

# and the mistake the convention creates is answered with the fix
./bin/snug --dry-run -p sys $SC/proj/sub
```

Expect: `control ok`; then two refusals naming the offending profile and saying
the mark means snug ships it; then `unknown profile "sys" ... you probably meant
"@sys"`. Note the third one fails at *load* — snug will not start at all while
such a file is on the search path, rather than quietly ignoring that one file.

## 9c. A build cannot reach past the sandbox

Needs a working container engine. The podman CLI cannot run inside the sandbox
on a host where /usr/bin/podman is a distrobox shim — snug says so at length —
so this drives the API, which is the surface under test anyway: every escape
below is a query parameter, not a CLI flag.

```bash
cp /path/to/snug/test/integration/buildProbe.py $SC/proj/sub/probe.py   # or paste it
./bin/snug -p @podman-build -p @net $SC/proj/sub -- python3 probe.py
```

Expect, in order: `ordinary build: 200` followed by `BUILT-INSIDE-SNUG` (the
control — without a build that really works, every refusal below is equally true
of a proxy that refuses everything), then `403` for the host bind, for both
spellings of `--network=host`, and for an option snug does not know.

`--network=host` sets TWO parameters and either alone re-opens the host network,
which is the same shape as the pasta flags in check 7. Both are refused, and the
suite pins each to its own message so neither can cover for the other.

## 9d. `@podman-socket` admits that it grants the network

Needs no engine — this is a `--dry-run` check, and `--dry-run` is the artifact
the guarantee is read off, which is exactly where MVY5 was wrong.

```bash
./bin/snug --dry-run -p @podman-socket $SC/proj/sub | grep -E '^ *\+|^NETWORK|^CONTAINERS'
./bin/snug --dry-run $SC/proj/sub                   | grep -E '^NETWORK|^CONTAINERS'
```

Expect from the first: `+ @net  (pulled in by include; …)`, then the **egress**
NETWORK block, then a `CONTAINERS` block saying the container runs in the
engine's netns and that the pasta guarantees above it do not cover containers.

Expect from the second — this is the positive control, and it is the half that
matters: a bare `snug <dir>` still prints `NETWORK  isolated` and **no**
`CONTAINERS` block at all. `@net` reaching `defaults` would be the real
regression here, and a check that only looked at the first command could not
tell the difference.

Both lines are interim. When the engine moves into the sandbox's netns, the
first command must stop showing `+ @net` — at which point this check inverts and
`@podman-socket` alone must print `NETWORK  isolated`.

## 10. A repository cannot grant itself anything

```bash
cd $SC/proj/sub
mkdir -p .snug
printf '[profile.evil-cwd]\nro = ["/"]\n' > .snug/profiles.toml
cp .snug/profiles.toml ./snug.toml

/path/to/snug/bin/snug . -- /bin/sh -c 'ls / ; ls ~'

rm -rf .snug snug.toml
```

The name is deliberately one the `defaults` already select, so auto-loading the
file would either widen the sandbox or abort as a redefinition. Expect neither:
the normal restricted view, and the host root must **not** appear. snug
never auto-loads config from beside the target, because a hostile repository
shipping its own profile would be granting itself permissions on the first run.

**Known gap, do not mistake this for a full guarantee.** `$XDG_CONFIG_HOME` is
trusted unconditionally, so pointing it into a repository *does* load that
repository's profiles:

```bash
mkdir -p $SC/proj/sub/.config/snug/profiles.d
printf '[profile.evil]\ninclude=["@sys"]\nrw=["/etc"]\n' \
  > $SC/proj/sub/.config/snug/profiles.d/evil.toml
XDG_CONFIG_HOME=$SC/proj/sub/.config ./bin/snug --dry-run -p evil $SC/proj/sub | grep '/etc'
```

This resolves, and `--dry-run` honestly shows `rw /etc`. It is low severity —
`XDG_CONFIG_HOME` is your own environment variable, not something the sandboxed
agent can set — but the `--config` gate described in DESIGN §2.7 is not built
yet. Found by the `redteam` agent.

## 11. Nothing is left behind

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c 'sleep 30' &
sleep 2
pgrep -a bwrap                 # one process
kill -9 %1; sleep 1
pgrep -a bwrap || echo "no leftovers: ok"
```

Expect the bwrap process to be gone. `--die-with-parent` kills the payload even
when snug is SIGKILLed and cannot clean up after itself.

---

## If a check fails

1. Re-run it with `--dry-run` and compare what snug *claimed* against what you
   *observed*. Those two disagreeing is itself the most important finding.
2. Capture the exact commands and both outputs.
3. Note which grant is responsible — `--dry-run` prints the contributing profile
   at the end of each `FILESYSTEM` line.
4. That reproduction becomes a permanent regression test. The rule in this
   project is that a hole should only ever be closable once.

## What this checklist does not cover

M0 is filesystem isolation, offline. Deliberately absent, so do not read their
absence as a failure: seccomp, networking (pasta), the ssh-agent proxy,
containers, GUI sockets. Each is a hole, each arrives with its own profile, and
each gets attacked by the `redteam` agent before it lands.

It also does not cover the threats snug does not defend against at all: kernel
0-days, and a determined human attacker with a shell. See DESIGN §1.2.
