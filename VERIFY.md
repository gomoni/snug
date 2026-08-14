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

The complete writable surface is **eight** paths, and only the first survives
the sandbox:

| path | kind | persists? |
|---|---|---|
| the target directory | bind, rw | **yes** — this is the point |
| `/tmp` | tmpfs | no |
| `$HOME` | tmpfs | no |
| `$HOME/.cache`, `$HOME/.config`, `$HOME/.local/state`, `$HOME/.local/share` | tmpfs | no |
| `/dev` | tmpfs (bwrap's synthetic `/dev`) | no |

Do not trust that table — it is prose, and prose drifts. It said **seven** for a
milestone after `@home` grew `{home}/.local/share`. Enumerate the set instead:

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c '
awk '"'"'$4 ~ /^rw(,|$)/ {print $2}'"'"' /proc/self/mounts |
  sed -e "s#^/dev/.*#/dev#" -e "s#^$HOME#\$HOME#" -e "s#^/tmp/tmp\.[A-Za-z0-9]*#\$SC#" |
  grep -v "^/proc" | sort -u; echo PROBE-RAN'
```

Expect exactly these nine lines:

```
$HOME
$HOME/.cache
$HOME/.config
$HOME/.local/share
$HOME/.local/state
$SC/proj/sub
/dev
/tmp
PROBE-RAN
```

The three `sed` expressions only normalise names that vary per host and per run:
bwrap's synthetic device nodes collapse to `/dev`, your real `$HOME` and the
`mktemp` directory get their symbolic names back. `/proc` is dropped because it
is a procfs, not a writable surface in the sense this section means. `PROBE-RAN`
is the positive control — without it an empty result reads as a pass on a
sandbox that never started.

A line you do not recognise is a finding. A missing line means a grant went
away, which is a documentation bug at least.

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

Do it once more with a variable you set yourself, and with the positive control,
because a count of zero is also what a typo produces:

```bash
SECRET_TOKEN=leakme ./bin/snug $SC/proj/sub -- env | grep -c SECRET_TOKEN   # 0
SECRET_TOKEN=leakme sh -c 'env | grep -c SECRET_TOKEN'                      # 1
```

One thing on that screen looks like a leak and is not: `XDG_CONFIG_HOME` reads
`/home/u/.config` even when the host's was somewhere else entirely. `@home`
authors it, and inside, that path is an empty tmpfs.

Caveat worth knowing: `--clearenv` is not the last word. `/etc/profile.d/*`
runs inside a login shell and can put variables back. That is why `@sys`
enumerates `/etc` instead of binding it wholesale — see INDEX §5.3.

### 6d. Every variable says where it came from

```bash
./bin/snug --dry-run $SC/proj/sub -- true | sed -n '/^ENVIRONMENT/,/^$/p'
```

Expect one line per variable, each carrying a **verb** and a **profile**:
`(snug)` for the ones snug authors, `set`/`merge`/`prepend`/`inherit`/`sanitise`
plus the profile name for the ones a profile asked for. `PATH` is several lines,
one per band, reading top to bottom in resolution order — a profile's entries,
then snug's stub directory if there is one, then the base. That ordering **is**
the model's; if the screen and the resolver ever disagree, the screen is lying.

Where a `sanitise` dropped host elements, the line below names them — named, not
counted. "2 of 3 kept" is not something anybody can check. Drops are grouped by
**why**, one line per reason: "nothing grants that path" for an element with no
covering grant at all, and "only an empty writable tmpfs is mounted there" for
an element whose only covering mount is a `KindTmpfs` — the directory really is
inside the sandbox and really is empty, so keeping the element would ship a
shadow slot pre-installed ahead of `/usr/bin`.

There are three reasons and one run can show all of them, which is the way to
check they never collapse into one another:

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d
printf '[profile.sanp]\n\n[profile.sanp.environ.sanitise]\nPATH = true\n' \
  > $X/snug/profiles.d/sanp.toml

PATH="/tmp/attacker/bin:/proc/self/cwd:/srv/nothing:/usr/bin:/bin" \
XDG_CONFIG_HOME=$X ./bin/snug --dry-run --no-defaults \
  -p @sys -p @home -p @cwd-rw -p sanp $SC/proj/sub | sed -n '/^  PATH/,/^  PS1/p'
rm -rf $X
```

```
  PATH             /usr/bin /bin                   sanitise  sanp
                   /usr/sbin /sbin                 (snug)    base
                   (1 host entry dropped — nothing grants that path: /srv/nothing)
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/attacker/bin)
                   (1 host entry dropped — only a kernel pseudo-filesystem is mounted there, and its magic symlinks leave it: /proc/self/cwd)
```

`/srv/nothing` is not in the sandbox at all; the other two **are**, and are
writable, and empty — which is what makes them dangerous rather than merely
useless. §6f is that third reason at length.

### 6e. An authored value naming an ungranted path says so

```bash
./bin/snug --dry-run --no-defaults -p @parent-ro $SC/proj/sub -- true \
  | sed -n '/^ENVIRONMENT/,/^$/p'
```

Expect `HOME`, `SHELL` and the four `PATH` entries to carry `← not granted`.
This selection is refused (nothing can run in it), and `--dry-run` renders it
anyway — which is the only way to see the mark.

snug authors `HOME`, `PATH` and `SHELL` in *every* sandbox and must keep doing
so: unset `PATH` and bash substitutes a compiled-in default ending in `.`, which
inside snug is the target. So the repair for "this names a directory that is not
in here" is to **say so**, never to stop authoring it. If a future version
refuses instead, it has converted twenty minutes of confusion into a reachable
hole.

### 6e2. A writable `PATH` entry says so too

The mark above says *nothing is there*. This one says *something is there and
the payload can add to it* — the two are different facts and must never render
as one.

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d $X/tools
cat > $X/snug/profiles.d/both.toml <<EOF
[profile.both]
rw = ["$X/tools"]

[profile.both.environ.merge]
PATH = ["$X/tools"]

[profile.both.environ.sanitise]
PATH = true
EOF

PATH="/tmp/attacker/bin:/usr/bin:/bin" XDG_CONFIG_HOME=$X \
  ./bin/snug --dry-run -p both $SC/proj/sub | sed -n '/^  PATH/,/^  PS1/p'
rm -rf $X
```

Expect:

```
  PATH             /tmp/tmp.XXXXXXXX/tools         merge     both  ← writable from inside
                   /usr/bin /bin                   sanitise  both
                   /usr/sbin /sbin                 (snug)    base
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/attacker/bin)
```

Read those four lines together, because they are the point. Both marked paths
are directories the payload can write to and that precede `/usr/bin`. One is
dropped by the filter and one is kept — correctly, because `sanitise` judges
only the *host's* value for an imported variable and never a profile's own
`merge` — and before the mark existed the screen showed one being removed for a
hazard while the other sat unremarked four lines above. That is how `@claude`'s
`{home}/.local/bin` survived a milestone in plain sight (§6g).

The `rw` bind is deliberate and is the *worse* of the two cases: it is not a
tmpfs that dies with the sandbox, so a `git` written into that slot **persists
to the host**. Note also that this profile is a legal one — `rw` grants the
directory, so the grant-coupling rule is satisfied and nothing refuses it. The
mark is the only thing standing between a human and that arrangement, which is
why it is a mark and not a refusal: a *human's own* profile may do this
deliberately, an accepted residual. What snug may never
do is ship it (§6g).

Check the scope too: the mark is `PATH`-only, because `PATH` entries are
searched for **commands**. A writable `XDG_CACHE_HOME` is correct and must stay
unmarked — confirm the four `XDG_*` lines in the same block carry no mark, or
the mark has become noise the reader will learn to skip.

### 6f. `/proc`'s magic symlinks do not resurrect the shadow slot

`environ.sanitise` copies a host list variable and keeps only elements policy
grants; no shipped profile uses it on `PATH` today, so this drops in a
throwaway one that does. `coveringMount` is a **lexical** walk over guest
paths — it does not follow symlinks — so it used to stop at `/proc` (a
`KindProc` mount, "kernel- and bwrap-populated, not empty") and KEEP any
element under it, while the KERNEL resolves `/proc/self/cwd` to wherever the
reading process's cwd actually is. Inside snug that is the **target** — a real
bind mount, not a copy, so anything written through that PATH entry persists
to the host after the sandbox exits.

```bash
X=$(mktemp -d); mkdir -p $X/snug/profiles.d
printf '[profile.sanpath]\n\n[profile.sanpath.environ.sanitise]\nPATH = true\n' \
  > $X/snug/profiles.d/sanpath.toml

# Simulates a hostile repo leaving a same-named binary in the target, the way
# a compromised dependency-install hook or a previous agent turn could.
cat > $SC/proj/sub/id <<'SH'
#!/bin/sh
echo SHADOWED-ID-RAN-VIA-PROC-CWD
SH
chmod +x $SC/proj/sub/id

XDG_CONFIG_HOME=$X PATH="/proc/self/cwd:/usr/bin:/bin" \
  ./bin/snug --no-defaults -p @sys -p @cwd-rw -p sanpath $SC/proj/sub -- id

rm -f $SC/proj/sub/id
rm -rf $X
```

Expect the real `uid=... gid=... groups=...` line from `/usr/bin/id` —
**never** `SHADOWED-ID-RAN-VIA-PROC-CWD`. Confirm with `--dry-run` (swap `--
id` for `--dry-run ... -- true | sed -n '/^ENVIRONMENT/,/^$/p'`) that `PATH`
carries a drop line naming `/proc/self/cwd`, reason "only a kernel
pseudo-filesystem is mounted there, and its magic symlinks leave it" — a
different fact from `DropTmpfsOnly`'s "only an empty writable tmpfs is
mounted there", and the two must never read the same.

### 6g. Nothing snug puts on `PATH` is writable from inside

§6f closes the slot a *host* `PATH` element could open. This closes the one
**snug itself** could hand over. The two are different halves of the same rule
and only one of them is a filter.

```bash
probe='echo SNUG-PROBE-RAN; IFS=:
       for d in $PATH; do
         [ "$d" = /usr/bin ] && break
         mkdir -p "$d" 2>/dev/null
         touch "$d/shadow" 2>/dev/null && echo "WRITABLE $d"
       done'

./bin/snug             $SC/proj/sub -- /bin/sh -c "$probe"
./bin/snug -p @claude  $SC/proj/sub -- /bin/sh -c "$probe"
```

Expect `SNUG-PROBE-RAN` and **no** `WRITABLE` line from either. The marker is
the point: without it, a sandbox that failed to start would print nothing and
read as a pass.

`mkdir -p` before `touch` is not tidiness. A `PATH` element that does not exist
*yet* on a writable tmpfs is still a slot — the payload creates the directory
and the shell finds it on the next lookup — and probing with `touch` alone
fails there with ENOENT, which reads exactly like a refusal.

Then check the staging directory directly, and that the binary really came from
it:

```bash
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c '
  echo "PATH=$PATH"; command -v claude
  touch /run/snug/bin/git || echo "touch REFUSED"
  echo x > /run/snug/bin/git || echo "redirect REFUSED"'
```

Expect `/run/snug/bin` first on `PATH`, `command -v claude` answering
`/run/snug/bin/claude`, and **both** write attempts refused with
`Read-only file system` — `touch` and the shell redirect are different syscall
paths and a check of one is not a check of the other.

This earned its place by having shipped. `@claude` bound its binary read-only
at `{home}/.local/bin/claude` and merged `{home}/.local/bin` onto `PATH`; the
bind was sound and the *directory* was `@home`'s writable tmpfs. A payload
could drop a `git` there and own every later command in the sandbox, including
whatever a human typed at the prompt. `sanitise` cannot reach it — that filter
only inspects the **host's** value for an imported variable, never a `merge`
entry written in a file — and `make gate` was green throughout. It was found by
reading, which is why it now has both an integration test
(`TestSnugStagesNoCommandInAWritableDirectory`) and this check.

### 6h. A profile cannot author a mount through an environment value

`--setenv NAME VALUE` is three elements of a flag list that snug NUL-joins into
the args memfd, and bwrap's `--args` splits on NUL. `VALUE` is last in the
triple, so a NUL inside it re-syncs bwrap's parser onto whatever follows. A raw
NUL never gets this far — go-toml refuses control characters in a basic string —
but the `\u0000` **escape** does, and produces the same byte. That spelling is
what anyone re-testing needs.

```bash
mkdir -p $SC/cfg/snug/profiles.d
printf '%s\n' '[profile.nully]' 'description = "harmless-looking"' \
  '[profile.nully.environ.set]' \
  'EDITOR = "vim\u0000--ro-bind\u0000'$HOME'/.ssh\u0000'$HOME'/.ssh"' \
  > $SC/cfg/snug/profiles.d/nully.toml

XDG_CONFIG_HOME=$SC/cfg ./bin/snug -p nully $SC/proj/sub -- ls $HOME/.ssh
XDG_CONFIG_HOME=$SC/cfg ./bin/snug --dry-run -p nully $SC/proj/sub
```

Expect **both** to refuse, naming the NUL, the profile, the verb and the
variable — and no sandbox to start. Before the fix the first command listed the
host's ssh keys, `--dry-run` printed `~/.ssh` under **NOT GRANTED**, and the
FILESYSTEM block showed no such mount: there was no `Mount`, so `Validate`,
`rejectMasking` and the provenance model were all blind to it. The same shape
with `--tmpfs` masked `@sys`'s `ro /usr` — a *profile* expressing subtraction,
which invariant 1 calls structurally impossible.

Then the control, which is what makes the above mean anything — the identical
profile with `EDITOR = "vim"` must run, put `EDITOR=vim` in the sandbox, and
still not have `~/.ssh`.

### 6i. A profile cannot mount over the staging directory

`/run/snug/bin` is unwritable because it is a plain directory on the root tmpfs
and `--remount-ro /` covers it. A mount there is a *separate* mount, which that
remount does not cover — and snug then puts the now-writable directory first on
`PATH` itself, in its own `(snug)` provenance, without the profile ever naming
`PATH`.

```bash
printf '%s\n' '[profile.stagey]' 'description = "stage a tool"' \
  'tmpfs = ["/run/snug/bin"]' 'ro    = ["/etc/hostname:/run/snug/bin/mytool"]' \
  > $SC/cfg/snug/profiles.d/stagey.toml

XDG_CONFIG_HOME=$SC/cfg ./bin/snug -p stagey $SC/proj/sub -- \
  sh -c 'echo "#!/bin/sh" > /run/snug/bin/git && echo WROTE-A-COMMAND-INTO-PATH'
```

Expect a refusal naming `/run/snug/bin` and the profile. Before the fix: the
sandbox started, the write succeeded, and the shadowed `git` ran. The `rw`-bind
spelling was worse — the shadowed command persisted to the host directory.

Drop the `tmpfs` line and re-run: staging one file *inside* the directory is the
legitimate shape (`@claude` does it on every run), so that must still work, with
`/run/snug/bin` first on `PATH` and the write still refused.

### 6j. All five verbs at once, and the payload agrees with the screen

One profile using every verb, so the bands can be read against each other rather
than one at a time:

```bash
mkdir -p $SC/five/snug/profiles.d $SC/tools/bin $SC/tools/override
cat > $SC/five/snug/profiles.d/mytools.toml <<EOF
[profile.mytools]
description = "five verbs at once"
ro = ["$SC/tools/bin", "$SC/tools/override"]

[profile.mytools.environ.set]
EDITOR = "/usr/bin/vim"

[profile.mytools.environ.merge]
PATH = ["$SC/tools/bin"]

[profile.mytools.environ.prepend]
PATH = ["$SC/tools/override"]

[profile.mytools.environ.inherit]
COLORTERM = true

[profile.mytools.environ.sanitise]
PKG_CONFIG_PATH = true
EOF

COLORTERM=truecolor PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/tmp/nope/pc \
XDG_CONFIG_HOME=$SC/five ./bin/snug --dry-run -p mytools $SC/proj/sub \
  | sed -n '/^ENVIRONMENT/,/^$/p'
```

```
  COLORTERM        truecolor                       inherit   mytools
  EDITOR           /usr/bin/vim                    set       mytools
  PATH             /tmp/tmp.XXXXXXXXXX/tools/override prepend   mytools
                   /tmp/tmp.XXXXXXXXXX/tools/bin   merge     mytools
                   /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  mytools
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/nope/pc)
```

Every line names its verb **and** its profile — no anonymous values — and
`prepend` sits ahead of `merge`, both ahead of `base`.

The screen agreeing with itself proves nothing. Put two different binaries of
the same name in the two directories and see which one the sandbox runs:

```bash
printf '#!/bin/sh\necho FAKE-TOOL-FROM-OVERRIDE\n' > $SC/tools/override/mytool
printf '#!/bin/sh\necho FAKE-TOOL-FROM-BIN\n'      > $SC/tools/bin/mytool
chmod +x $SC/tools/override/mytool $SC/tools/bin/mytool

COLORTERM=truecolor XDG_CONFIG_HOME=$SC/five ./bin/snug -p mytools $SC/proj/sub -- mytool
```

Expect `FAKE-TOOL-FROM-OVERRIDE`. `prepend` won, and the name resolved against
the sandbox's `PATH` rather than the host's — the property `snug . -- podman`
depends on.

### 6k. A host variable set to empty arrives set

```bash
mkdir -p $SC/nc/snug/profiles.d
printf '[profile.nc]\n\n[profile.nc.environ.inherit]\nNO_COLOR = true\n' \
  > $SC/nc/snug/profiles.d/nc.toml

NO_COLOR= XDG_CONFIG_HOME=$SC/nc ./bin/snug -p nc $SC/proj/sub -- sh -c 'env | grep -c "^NO_COLOR="'
         XDG_CONFIG_HOME=$SC/nc ./bin/snug -p nc $SC/proj/sub -- sh -c 'env | grep -c "^NO_COLOR=" || true'
```

Expect `1` then `0`: host-set-to-empty arrives set-to-empty, host-unset does not
arrive at all. `NO_COLOR` is specified as "set to **any** value, including
empty", so treating empty as absent silently re-enabled colour — and the same
shape holds for `CI`, `DEBUG` and every other flag variable. The check is worth
running because both the bug and the fix print nothing on any other screen.

### 6l. The refusals fire at parse time, one file at a time

These need no sandbox and no privileges — the file is rejected as it is read.
Give each profile its **own** config dir: a file that fails to parse takes its
own file down, and any later command that runs a sandbox is then fatal, which
would mask the next case.

```bash
one() {  # one <name> <toml-body>
  D=$SC/one; rm -rf $D; mkdir -p $D/snug/profiles.d
  printf '%s' "$2" > $D/snug/profiles.d/$1.toml
  XDG_CONFIG_HOME=$D ./bin/snug --dry-run -p $1 $SC/proj/sub 2>&1 | head -4
}

one c '[profile.c]

[profile.c.environ.set]
PATH = "/evil"
'
one d '[profile.d]

[profile.d.environ.set]
GIT_SSH = "/tmp/x"
'
one e '[profile.e]

[profile.e.environ.merge]
PATH = ["/opt/nowhere/bin"]
'
```

The first two are file-load failures, so each is reported under
`snug: 1 profile file(s) in the search path did not load:` with the file named
and then the reason:

```
profile "c": environ.set on PATH, which is a list — use environ.merge, or
  environ.prepend if the order matters. …
profile "d": environ.set names GIT_SSH, which snug refuses for this verb: the
  value is code, executed by every process the sandbox launches. Remove the line
```

The third parses fine and fails at resolution, so it is snug's own error with no
file preamble: `profile "e" merges PATH=/opt/nowhere/bin, which it does not
grant.` That is the grant-coupling rule, and the mistake most people make first.

Worth trying by hand, because these are the boundaries most likely to be wrong:

- `TERM`, `HOME`, `SNUG_PROFILES` under `environ.set` — refused, snug owns them;
- `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `GIT_PAGER`, `GIT_DIR`, `GIT_TEMPLATE_DIR`,
  `LD_PRELOAD`, `JAVA_TOOL_OPTIONS`, `RUBYOPT` — refused for the same reason;
- `BASH_ENV` under `set` — **allowed** (a reviewable value in a trusted layer);
  under `inherit` — refused. That split is deliberate, and is the one to decide
  whether you agree with;
- a lowercase name, a name with a hyphen, a name starting with a digit —
  refused by the grammar.

What that list does **not** close is git's exec class as a whole: `PAGER`,
`EDITOR` and `VISUAL` stay legal by ENVIRONMENT-VARIABLES §3.2 and git falls
back to them, so `PAGER='sh -c …' git log` runs the command.
https://github.com/gomoni/snug/issues/35 carries it, and a test pins it so withdrawing those three has to be a deliberate §3.2
decision rather than a table edit.

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
                 ("add_key",248),("bpf",321),("userfaultfd",323),
                 ("pidfd_getfd",438),("process_vm_readv",310),
                 ("process_vm_writev",311)]:
    ctypes.set_errno(0); libc.syscall(nr, 0,0,0,0,0); e = ctypes.get_errno()
    print("%-16s %s" % (name, os.strerror(e) if e else "ALLOWED"))
EOF

./bin/snug $SC/proj/sub -- python3 probe.py                 # all: Operation not permitted
./bin/snug --no-seccomp $SC/proj/sub -- python3 probe.py    # host behaviour returns
./bin/snug $SC/proj/sub -- /bin/sh -c 'unshare -U /bin/true' # Operation not permitted
```

Syscall numbers above are x86_64. Note the cost, which is deliberate: with the
filter on you cannot run snug inside snug, or rootless podman inside it. The
three added for issue #23 (`pidfd_getfd`, `process_vm_readv`,
`process_vm_writev`) are refused with `nr=0` — a bogus first argument — which is
enough to prove the filter denies the syscall itself rather than validating its
arguments; do not read `ALLOWED` here as "the real call would have succeeded",
only `Operation not permitted` here is meaningful.

Then check `--dry-run` actually says so — the fix's other half, since the point
of issue #23 was that nothing on screen distinguished a filtered run from an
unfiltered one:

```bash
./bin/snug --dry-run $SC/proj/sub | grep -A3 '^SECCOMP'
./bin/snug --dry-run --no-seccomp $SC/proj/sub | grep -A3 '^SECCOMP'
```

Expect the first to start `SECCOMP  active — denies (EPERM), derived from
deniedSyscalls in`, listing `pidfd_getfd`, `process_vm_readv` and
`process_vm_writev` among the names, and the second to start `SECCOMP
DISABLED (--no-seccomp)`. The two must read differently — that difference is
the whole point of the line.

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

A sandbox with no `@net` is offline by design — there is no egress either. That
is not a bug; it is the floor, and egress arrives only by naming `@net` (§9d is
the one interim exception, and it says so on the screen).

## 8. Profile order is irrelevant

```bash
A=$(./bin/snug --dry-run -p @sys -p @cwd-rw -p @parent-ro $SC/proj/sub | sed -n '/── bwrap/,$p' | md5sum)
B=$(./bin/snug --dry-run -p @parent-ro -p @cwd-rw -p @sys $SC/proj/sub | sed -n '/── bwrap/,$p' | md5sum)
[ "$A" = "$B" ] && echo "identical: ok" || echo "DIFFERENT <-- FAIL"
```

Expect `identical: ok`. Order-dependence would mean the sandbox you get depends
on how you typed the command, and "profiles only relax" would stop being
checkable.

## 8b. Disagreements are fatal, and name every claimant in a stable order

Two profiles, one scalar, two values:

```bash
mkdir -p $SC/ab/snug/profiles.d
printf '[profile.a]\n\n[profile.a.environ.set]\nEDITOR = "/usr/bin/vim"\n'  > $SC/ab/snug/profiles.d/a.toml
printf '[profile.b]\n\n[profile.b.environ.set]\nEDITOR = "/usr/bin/nano"\n' > $SC/ab/snug/profiles.d/b.toml

XDG_CONFIG_HOME=$SC/ab ./bin/snug --dry-run -p a -p b $SC/proj/sub; echo "exit=$?"
XDG_CONFIG_HOME=$SC/ab ./bin/snug --dry-run -p b -p a $SC/proj/sub; echo "exit=$?"
```

```
snug: profiles a and b disagree about EDITOR:
         b (environ.set) says "/usr/bin/nano"
         a (environ.set) says "/usr/bin/vim"
       A scalar has one value and snug will not choose: …
exit=77
```

**The two runs must print the same bytes.** The claimants are sorted, not
fold-ordered; if `-p b -p a` names them differently, resolution is not
commutative and that is a model bug rather than a cosmetic one — §8 with the
environment attached.

Same shape for the slot only one profile may hold:

```bash
mkdir -p $SC/pq/snug/profiles.d
printf '[profile.p]\nro = ["/usr/share"]\n\n[profile.p.environ.prepend]\nPATH = ["/usr/share"]\n' > $SC/pq/snug/profiles.d/p.toml
printf '[profile.q]\nro = ["/usr/lib"]\n\n[profile.q.environ.prepend]\nPATH = ["/usr/lib"]\n'     > $SC/pq/snug/profiles.d/q.toml

XDG_CONFIG_HOME=$SC/pq ./bin/snug --dry-run -p p -p q $SC/proj/sub
```

```
snug: profiles p and q prepend to PATH, and they do not agree:
         q wants ["/usr/lib"]
         p wants ["/usr/share"]
```

The quoting is load-bearing, not decoration: agreement is over the whole ordered
sequence, and an element may contain a space, so `/opt/a /opt/b` on one line
could be two elements or one. Keying that comparison on a space-join made two
different sequences compare equal and silently deleted one profile's entry —
`["/opt/a" "/opt/b"]` versus `["/opt/a b"]` is the distinction being drawn.

Note both profiles here **grant** what they prepend. Drop either `ro =` line and
the coupling error from §6l fires first instead.

## 8c. A file that does not parse degrades diagnostics, never a sandbox

```bash
mkdir -p $SC/bad/snug/profiles.d
printf '[profile.oops]\nnosuchkey = 1\n' > $SC/bad/snug/profiles.d/oops.toml

XDG_CONFIG_HOME=$SC/bad ./bin/snug profile list;         echo "exit=$?"
XDG_CONFIG_HOME=$SC/bad ./bin/snug $SC/proj/sub -- true; echo "exit=$?"
XDG_CONFIG_HOME=$SC/bad ./bin/snug --dry-run -p oops $SC/proj/sub
```

`profile list` prints the diagnostic on stderr — with the offending line and a
`~~~~ unknown field` caret — **and the builtins on stdout**, then exits 77.
Running a sandbox refuses outright with the same code, and so does `--dry-run`.

That split is the design: **diagnostics degrade, sandboxes do not.** A sandbox
built from whatever happened to load is a guess about its own boundary. Note
that `profile list` exits 77 despite producing useful output, which is
deliberate for scripts.

Check the last command's wording specifically: asking for `-p oops` must say the
file defining it failed to parse, **never** "unknown profile". The second
message would send someone to fix a typo in their command line while the real
grant sat unloaded — a silent downgrade wearing a helpful error's clothes.

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
the guarantee is read off, which is exactly where it was wrong
(`.claude/design/ENGINE-NETNS.md` §0).

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
agent can set — but the `--config` gate described in INDEX §2.7 is not built
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

## 12. The stage — a `@net` sandbox has a second process ahead of it

Since Phase 1 (`.claude/design/SUPERVISOR-DESIGN.md`), a `-p @net` run
starts a second long-lived process (P1, "the stage") that creates the sandbox's
network namespace, pins it, leaves it, and forks bwrap back into it. This is the
by-hand form of that phase's exit criteria — `snug --dry-run` shows the same
facts under a `TOPOLOGY` block; this section confirms them against the kernel,
not against snug's own claim about itself.

```bash
./bin/snug --dry-run -p @net $SC/proj/sub | sed -n '/^TOPOLOGY/,/^$/p'
```

Expect `netns owner     stage`, `processes       4 — snug, a stage (P1)…`, and a
`control` block naming an anonymous `SOCK_SEQPACKET` socketpair and saying it is
unreachable from the sandbox. The count includes snug itself and pasta: an
earlier version counted differently in each arm and named neither. Compare
against a run with no `@net`:

```bash
./bin/snug --dry-run $SC/proj/sub | sed -n '/^TOPOLOGY/,/^$/p'
```

Expect `processes       2 — snug and bwrap. No stage, no privileged ancestor
namespace.` — a bare `snug <dir>` starts no stage at all.

**The sandbox's netns is not P0's**, and neither side may be trusted if it
reads empty:

```bash
readlink /proc/self/ns/net
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c 'readlink /proc/self/ns/net'
```

Expect two different `net:[…]` ids. (Development host: `net:[4026531833]` vs
`net:[4026532443]`.)

**The thread sweep — this is the check `/proc/<pid>/ns/net` cannot make.**
`unshare(CLONE_NEWNET)` is per-task (see CLAUDE.md), so the only trustworthy way
to ask "did every thread of the stage leave the sandbox's namespace" is to sweep
every thread individually — reading the stage's own `/proc/<pid>/ns/net` names
only the thread group leader and, mid-move, would lie.

```bash
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c 'sleep 30' &
SNUGPID=$!
sleep 1
STAGE=$(ps -o pid,ppid,comm --ppid $SNUGPID | awk '$3=="exe"{print $1}')
BWRAP=$(ps -o pid,ppid,comm --ppid $STAGE  | awk '$3=="bwrap"{print $1}')
N=$(readlink /proc/$BWRAP/ns/net)
echo "N (the sandbox's netns) = $N"
find /proc/$STAGE -mindepth 4 -maxdepth 4 -path '*/task/*/ns/net' \
  -exec readlink {} \; 2>/dev/null | sort | uniq -c
kill -9 $SNUGPID; wait $SNUGPID 2>/dev/null
```

Expect the stage's own thread sweep to show only ITS namespace (a fresh one it
made when it left N) — `N` must not appear in that list at all. (Development
host: 6 threads, all reporting one namespace distinct from `N`.) The `exe`
comm is not a typo: the kernel sets `/proc/<pid>/comm` from the file actually
`execve`d — always `/proc/self/exe` in this chain — never from `argv[0]`, which
is where `snug __stage-setup` / `snug __stage-serve` shows up instead
(`ps -o pid,args --ppid $SNUGPID` / `cat /proc/$STAGE/cmdline | tr '\0' ' '`).

**Teardown — on the namespace object, not a process count.** A netns pinned only
by a bind mount with no process attached would be invisible to a process
sweep, so the check that matters is the same thread sweep, taken again after a
SIGKILL, and expected to fall to zero:

```bash
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c 'sleep 30' &
SNUGPID=$!
sleep 1
STAGE=$(ps -o pid,ppid,comm --ppid $SNUGPID | awk '$3=="exe"{print $1}')
BWRAP=$(ps -o pid,ppid,comm --ppid $STAGE  | awk '$3=="bwrap"{print $1}')
N=$(readlink /proc/$BWRAP/ns/net)
find /proc -mindepth 5 -maxdepth 5 -path '*/task/*/ns/net' \
  -exec readlink {} \; 2>/dev/null | grep -Fc "$N"   # before: > 0

kill -9 $SNUGPID; sleep 1

find /proc -mindepth 5 -maxdepth 5 -path '*/task/*/ns/net' \
  -exec readlink {} \; 2>/dev/null | grep -Fc "$N"   # after: 0
```

Expect a positive count before the kill (the positive control — bwrap and the
sandbox's own init are genuinely in `N`) and `0` after: SIGKILL on snug takes
the whole tree with it, and the namespace itself — which nothing bind-mounts
anywhere — goes with the last reference.

**The ordering that removed the parked window.** pasta attaches to the network
namespace before bwrap is forked, so during startup no payload exists to be
released early. The by-hand check is that a pasta which never configures an
interface leaves snug with a stage and NO bwrap — and that killing snug there,
with SIGKILL, still never runs the payload:

```bash
FAKE=$(mktemp -d); printf '#!/bin/sh\nexec sleep 300\n' > $FAKE/pasta; chmod +x $FAKE/pasta
rm -f $SC/proj/sub/PWNED
PATH=$FAKE:$PATH ./bin/snug -p @net $SC/proj/sub -- \
  /bin/sh -c 'echo pwned > "$SNUG_TARGET/PWNED"' &
SNUGPID=$!
sleep 2
ps -o pid,args --ppid $SNUGPID          # expect a stage; expect NO bwrap anywhere below it
pgrep -c -P $(pgrep -P $SNUGPID | head -1) || true
kill -9 $SNUGPID; sleep 1
ls $SC/proj/sub/PWNED                   # expect: No such file or directory
```

Expect a `snug __stage-serve` under snug and **no bwrap at all** — bwrap is not
forked until the interface is up. Then expect the marker to be absent after a
SIGKILL. If bwrap is present at that point the ordering has regressed and the
window is back; `TestKillingSnugDuringStartupNeverRunsThePayload` is the
automated form and asserts all four signals including SIGKILL.

**Teardown when the stage cannot run any code.** The check above proves the
lifeline pipe works. The lifeline needs the stage to run a goroutine to notice
EOF, so it says nothing about a stage that has been stopped — and a stopped
process is not a dead one. `PR_SET_PDEATHSIG` is what covers that case, and a
comment in the tree once asserted it does not survive the stage's own re-exec,
which would have made this the one teardown path with no mechanism at all.
Freeze the whole tree first, and never let it run again:

```bash
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c 'sleep 30' &
SNUGPID=$!
sleep 1
TREE=$(pgrep -P $SNUGPID; for c in $(pgrep -P $SNUGPID); do pgrep -P $c; done)
BWRAP=$(ps -o pid,comm -p $TREE | awk '$2=="bwrap"{print $1; exit}')
N=$(readlink /proc/$BWRAP/ns/net)
kill -STOP $TREE
ps -o pid,state,comm -p $TREE          # positive control: every state must be T

kill -9 $SNUGPID; sleep 2

ps -o pid,state,comm -p $TREE 2>/dev/null   # expect: nothing (or Z)
find /proc -mindepth 5 -maxdepth 5 -path '*/task/*/ns/net' \
  -exec readlink {} \; 2>/dev/null | grep -Fc "$N"   # expect: 0
```

Expect every member in state `T` before the kill — without that the run proves
only that the lifeline works — and nothing alive afterwards. If processes
survive, `Pdeathsig: syscall.SIGKILL` has gone missing from
`internal/stage/stage.go`. `TestAFrozenStageTreeStillDiesWithSnug` is the
automated form, and it was confirmed to go red when that line is removed:
4 orphaned processes, 3 of them still in `N`.

**The exit-status contract survives the extra process:**

```bash
./bin/snug $SC/proj/sub -- sh -c 'exit 42'; echo "exit: $?"          # 42
./bin/snug $SC/proj/sub -- sh -c 'kill -TERM $$'; echo "exit: $?"    # 143 (128+15)
timeout --signal=INT -k2 2 \
  ./bin/snug -p @net $SC/proj/sub -- \
    sh -c 'trap "echo caught-sigint; exit 7" INT; sleep 30'
```

Expect `42`, then `143`, then `caught-sigint` printed before `timeout` gives
up — an interrupt delivered to snug's whole process group (which is exactly
what a terminal's own Ctrl-C does; `timeout` without `--foreground` reproduces
it without one) reaches the payload through P0, the stage, and bwrap, none of
which call `setpgid`.

**`lo` actually comes up inside the netns the STAGE created**, not bwrap — this
is the one place Phase 1 changed a working guarantee's mechanism without
changing its behaviour, and it is worth checking rather than trusting:

```bash
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c '
  (python3 -m http.server 8099 --bind 127.0.0.1 &>/dev/null &)
  sleep 1
  curl -s -o /dev/null -w "sandbox lo: %{http_code}\n" http://127.0.0.1:8099/'
```

Expect `sandbox lo: 200`. Before this phase, bwrap brought `lo` up itself
because it created the netns it ran in; under the stage, bwrap does not create
`N`, so nothing brings `lo` up unless the stage does it itself while it is
still inside — losing this silently is exactly the kind of regression a user
finds, not a golden diff.

---

## 13. Two accounts on one host — an identity is a pin, not a preference

The claim: a sandbox pinned to one GitHub account acts as that account through
**both** channels — `gh` and git-over-ssh — and cannot act as the other. Two
sandboxes side by side, two accounts, no crossing.

Nothing new is needed to express it. One `[identity]` block per profile pins the
ssh key, the gh account and the git author together; two profiles are two
accounts. Write them somewhere that is not the repository being sandboxed
(invariant 3) — `~/.config/snug/profiles.d/accounts.toml`:

```toml
[profile.acct-a]
include = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@net"]
  [profile.acct-a.identity]
  ssh_mode  = "agent-proxy"
  ssh_key   = "{home}/.ssh/ACCOUNT-A.pub"   # the PUBLIC half
  gh_user   = "ACCOUNT-A"
  git_name  = "Your Name"
  git_email = "a@example.com"

[profile.acct-b]
include = ["@sys", "@home", "@cwd-rw", "@parent-ro", "@net"]
  [profile.acct-b.identity]
  ssh_mode  = "agent-proxy"
  ssh_key   = "{home}/.ssh/ACCOUNT-B.pub"
  gh_user   = "ACCOUNT-B"
  git_name  = "Your Name"
  git_email = "b@example.com"
```

`gh` must be inside for the staged token to be usable, and on a host where it is
not under `/usr` — a tarball in `~/bin`, which is common — `@sys` does not carry
it. Grant it into the one directory snug stages commands in:

```toml
[profile.gh-cli]
ro = ["{home}/bin/gh_X.Y.Z_linux_amd64/bin/gh:/run/snug/bin/gh"]
```

Both accounts must be logged in on the host (`gh auth status`), and the key for
each must be loaded in your ssh-agent. Then, per account:

```bash
./bin/snug -p acct-a $SC/proj/sub -- /bin/sh -c '
  echo "gh:     $(gh api user --jq .login)"
  echo "ssh:    $(ssh -o BatchMode=yes -T git@github.com 2>&1 | head -1)"
  echo "author: $(git config --global user.email)"'
```

Expect all three to name the SAME account, and `-p acct-b` to name the other:

```
gh:     ACCOUNT-A
ssh:    Hi ACCOUNT-A! You've successfully authenticated, but GitHub does not provide shell access.
author: a@example.com
```

The negative is the half that matters, and it is three separate refusals:

```bash
./bin/snug --dry-run -p acct-a -p acct-b $SC/proj/sub
# snug: profiles "acct-a" and "acct-b" pin different identities; select only one

./bin/snug --dry-run -p acct-badkey $SC/proj/sub     # ssh_key names a missing file
# snug: pinned ssh key: open /home/u/.ssh/does-not-exist.pub: no such file or directory

./bin/snug --dry-run -p acct-baduser $SC/proj/sub    # gh_user gh is not logged in to
# snug: no gh token for no-such-account-here on github.com.
```

The third one used to be silent — you got a sandbox with no credential, no
`GH_CONFIG_DIR` and nothing on screen, which is invariant 5's "no silent
downgrade" broken in the quietest possible way.

Inside a pinned sandbox, `ssh-add -l` must list exactly one key, and it must be
that account's:

```bash
./bin/snug -p acct-a $SC/proj/sub -- ssh-add -l
```

Expect one line. Every other key in your host agent is not merely unusable — it
is not enumerable, which is the difference between `agent-proxy` and forwarding
the agent.

### 13b. ssh runs at all — the check that was missing

`ssh` inside the sandbox is not a given, and on this host it was broken for
every account and every profile until it was measured:

```bash
./bin/snug $SC/proj/sub -- sh -c 'ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED'
```

Without a pinned identity, expect `SSH-REFUSED` on a host whose system-wide
`ssh_config` is root-owned — and the reason is worth reading, because it
generalises past ssh:

```bash
./bin/snug $SC/proj/sub -- ssh -G github.com
# Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf
./bin/snug $SC/proj/sub -- stat -c '%u %n' /usr/etc/ssh/ssh_config
# 65534 /usr/etc/ssh/ssh_config
```

The sandbox maps one uid, so every root-owned file under the read-only `/usr`
bind reads as **65534** inside it, and OpenSSH refuses a configuration file
owned by neither root nor the caller. `git clone git@github.com:…` failed the
same way, which made pinning an identity useless on such a host.

With an identity pinned, snug replaces the system-wide file with one it authors:

```bash
./bin/snug -p acct-a $SC/proj/sub -- sh -c '
  ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
  stat -c "owner=%u" /usr/etc/ssh/ssh_config; id -u'
```

Expect `SSH-OK` and `owner=1000` (your uid). `--dry-run` shows it as a `data`
row with `identity:<profile>` provenance, next to the generated `~/.gitconfig`.

What it costs, and say it out loud: the host's system-wide ssh defaults — on
this host openSUSE's crypto-policy include — do not apply inside. ssh's
compiled-in defaults do.

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

Deliberately absent, so do not read their absence as a failure: GUI, audio and
D-Bus passthrough. No profile ships for them and none is planned — the private
netns excludes them by construction, which is a property to keep rather than a
gap to close.

It also does not cover the threats snug does not defend against at all: kernel
0-days, and a determined human attacker with a shell. See INDEX §1.2.

## Where the reasoning is thinnest

Not checks — the places to push on if you are reviewing rather than verifying.

1. **`sanitise` is off by default and no shipped profile uses it.** Every check
   above that exercises it writes a throwaway profile first. Decide whether that
   bound is doing real work or is only how things happen to be today.
2. **The `--dry-run` marks and the `sanitise` filter answer different
   questions.** A `PATH` entry can be shown without a `← not granted` mark and
   still be dropped, and one can be kept and marked `← writable from inside`.
   That is argued in the code and in §6e2, and it is the sort of subtlety that
   reads as a bug at 11pm.
3. **A refusal that is later relaxed must not silently restore a false
   sentence.** §6i's arrangement is refused at `Validate`, so the branch that
   prints the opposite in `--dry-run` should be unreachable. It is kept anyway,
   for exactly the case where someone narrows the refusal.
