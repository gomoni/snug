# Verifying snug by hand

A sandbox you have not personally tried to break is a sandbox you are trusting
on someone's word. This is the checklist for not doing that.

Every command below was run on the development host and produced the output
shown. If yours differs, that is a finding — see [If a check fails](#if-a-check-fails).

What it checks is that **the sandbox holds**, which is not the same question as
whether your profiles are safe. snug does not second-guess a profile: `rw
["{home}"]` and `environ.set EDITOR = "/tmp/evil"` are holes you opened, they are
on screen in `--dry-run`, and no check below will fail on them. See
[`.claude/design/INDEX.md`](.claude/design/INDEX.md) §1.4 and the README's *What
snug does not defends against*.

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

**The user-namespace line is measured, not inferred from an exit code**
(issue #98). To see it answer a host it cannot serve — and to check that the
line can say no at all, which is the half a green tick never proves:

```bash
unshare --user --map-root-user -- sh -c '
  echo 0 > /proc/sys/user/max_user_namespaces
  unshare --user --map-root-user -- /bin/true      # positive control
  ./bin/snug doctor; echo "exit=$?"'
```

Expect the control to fail with `unshare failed: No space left on device` — the
proof that namespace creation really is blocked — and then `snug doctor` to
print `❌ cannot create a user namespace here`, quoting bwrap's own ENOSPC, and
exit 69. It must **never** print `✅ unprivileged user namespaces work` there.
It did until #98: the probe passed `--unshare-all`, whose `-try` spellings skip
silently and exit 0, and the check read the exit code alone.

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

Expect one **row** per variable, each carrying a **verb** and a **profile**:
`(snug)` for the ones snug authors, `set`/`merge`/`prepend`/`inherit`/`sanitise`
plus the profile name for the ones a profile asked for. `PATH` is several rows,
one per band, reading top to bottom in resolution order — a profile's entries,
then snug's stub directory if there is one, then the base. That ordering **is**
the model's; if the screen and the resolver ever disagree, the screen is lying.

A row is one line **plus** an indented line for each mark snug has to add to it
(§6e, §6j2). On this default selection there are none, and that is worth
noticing rather than skipping: nothing snug ships hands over a value it has a
measurement about. The four `XDG_*` rows are the deliberate exception — see
issue #84, and the comment on `internal/cli/testdata/env.defaults.txt`, which is the
artifact that decision is reviewed against.

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

Expect `HOME`, `SHELL` and the four `PATH` entries to carry `← not granted`,
each on its **own indented line under the row**:

```
  HOME             /home/u                         (snug)
                     ← not granted
  PATH             /usr/bin /bin /usr/sbin /sbin   (snug)    base
                     ← not granted
  SHELL            /usr/bin/bash                   (snug)
                     ← not granted
```

This selection is refused (nothing can run in it), and `--dry-run` renders it
anyway — which is the only way to see the mark.

A row can carry three marks at once, and while they were concatenated onto the
row the widest real ones measured 264, 272 and 277 columns — three or four
unindented wrapped fragments inside an aligned table, with the verdict about
*this* value at the end of the third. The indent is 21 rather than 19 for a
reason worth knowing: 19 is where a continuation band and a drop line start, and
a value may contain a `←`, so the two are told apart by column and not by the
arrow. §6j2 exercises the three-mark case.

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
  PATH             /tmp/tmp.XXXXXXXX/tools         merge     both
                     ← writable from inside
                   /usr/bin /bin                   sanitise  both
                   /usr/sbin /sbin                 (snug)    base
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/attacker/bin)
```

Note the two indents, because this row is where they are easiest to confuse: the
mark sits at 21 and belongs to the band above it; the second and third bands, and
the drop line, sit at 19 and are `PATH`'s own further entries.

Read those five lines together, because they are the point. Both marked paths
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
  touch /snug/bin/git || echo "touch REFUSED"
  echo x > /snug/bin/git || echo "redirect REFUSED"'
```

Expect `/snug/bin` first on `PATH`, `command -v claude` answering
`/snug/bin/claude`, and **both** write attempts refused with
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
still not have `~/.ssh`. Its `--dry-run` row now reads

```
  EDITOR           vim                             set       nully
                     ← the value is a command; git runs it for a commit message
                       via GIT_EDITOR -> core.editor -> VISUAL -> EDITOR
                       (measured)
```

and that mark is not a refusal — see §6j. The refusal above is about the NUL,
which breaks a MECHANISM (it authors a bwrap flag); the mark here is about what
git does with a perfectly well-formed value.

### 6i. A profile cannot mount over the staging directory

`/snug/bin` is unwritable because it is a plain directory on the root tmpfs
and `--remount-ro /` covers it. A mount there is a *separate* mount, which that
remount does not cover — and snug then puts the now-writable directory first on
`PATH` itself, in its own `(snug)` provenance, without the profile ever naming
`PATH`.

```bash
printf '%s\n' '[profile.stagey]' 'description = "stage a tool"' \
  'tmpfs = ["/snug/bin"]' 'ro    = ["/etc/hostname:/snug/bin/mytool"]' \
  > $SC/cfg/snug/profiles.d/stagey.toml

XDG_CONFIG_HOME=$SC/cfg ./bin/snug -p stagey $SC/proj/sub -- \
  sh -c 'echo "#!/bin/sh" > /snug/bin/git && echo WROTE-A-COMMAND-INTO-PATH'
```

Expect a refusal naming `/snug/bin` and the profile. Before the fix: the
sandbox started, the write succeeded, and the shadowed `git` ran. The `rw`-bind
spelling was worse — the shadowed command persisted to the host directory.

Drop the `tmpfs` line and re-run: staging one file *inside* the directory is the
legitimate shape (`@claude` does it on every run), so that must still work, with
`/snug/bin` first on `PATH` and the write still refused.

### 6i-2. `/snug` is a namespace, not a list of paths (issue #206)

The check above names one directory. The rule is wider: **nothing a profile
writes may mount anywhere under `/snug`**, including paths snug has not put
anything at yet. `/snug/engine` is Tier C's graft destination and does not exist
in any sandbox today — it must already be refused.

```bash
printf '%s\n' '[profile.grabby]' 'description = "a path snug has not used yet"' \
  'tmpfs = ["/snug/engine"]' \
  > $SC/cfg/snug/profiles.d/grabby.toml

XDG_CONFIG_HOME=$SC/cfg ./bin/snug -p grabby $SC/proj/sub -- true
```

Expect a refusal naming `/snug` and the profile. The point is that nobody had to
add `/snug/engine` to a list first: a rule stated over the namespace covers the
path the day the name is chosen.

Now the **tombstone**. snug's paths lived under `/run/snug` before #206, and a
profile written then must not keep validating while staging into a directory
that is no longer on `PATH`:

```bash
printf '%s\n' '[profile.oldway]' 'description = "stage where snug used to keep its paths"' \
  'ro = ["/etc/hostname:/run/snug/bin/mytool"]' \
  > $SC/cfg/snug/profiles.d/oldway.toml

XDG_CONFIG_HOME=$SC/cfg ./bin/snug -p oldway $SC/proj/sub -- true
```

Expect a refusal that **names `/snug/bin`** — the replacement, not just the
problem. A rename whose old name merely stops working is a trap; the refusal is
what makes it a rename.

Also worth seeing once, and note WHICH run: the skeleton directories are derived
from the mounts a run actually has, so a **default** sandbox has no `--dir /snug`
either — nothing is staged there. Select something that stages a binary, and the
directories appear while `--dir /run` does not:

```bash
./bin/snug --dry-run -p @podman-socket $SC/proj/sub | grep -E '^  --dir'
```

Expect `--dir /snug` and `--dir /snug/bin` and **no `--dir /run` at all**. `/run`
existed only because snug's own paths lived under it.

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
                     ← unchecked: snug has no type for this name
  EDITOR           /usr/bin/vim                    set       mytools
                     ← the value is a command; git runs it for a commit message
                       via GIT_EDITOR -> core.editor -> VISUAL -> EDITOR
                       (measured)
  PATH             /tmp/tmp.XXXXXXXXXX/tools/override prepend   mytools
                   /tmp/tmp.XXXXXXXXXX/tools/bin   merge     mytools
                   /usr/bin /bin /usr/sbin /sbin   (snug)    base
  PKG_CONFIG_PATH  /usr/lib64/pkgconfig            sanitise  mytools
                   (1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/nope/pc)
```

Every row names its verb **and** its profile — no anonymous values — and
`prepend` sits ahead of `merge`, both ahead of `base`.

**Two different marks, and they are two different statements.** `COLORTERM`
carries `← unchecked` and `EDITOR` does not: snug's roster
(`internal/policy/envtypes.go`) has a TYPE for `EDITOR`, `PATH` and
`PKG_CONFIG_PATH` and none for `COLORTERM`, so the screen says which values snug
knows what to do with and which it merely carried. `EDITOR` carries the OTHER
mark, the annotation, which says what a tool will DO with the value — here, that
git will run it. Neither mark is a refusal, and a row can carry three at once:
that is §6j2.

`snug profile show mytools` renders the same two marks on the same names, from
the same functions (`policy.IsUncheckedEnv`, `policy.EnvNote`) — the screens must
not disagree, so neither computes anything of its own.

Two things this does NOT mean. **A user profile is not refused anything here.**
`set FOO = "x"` in a file with an author and a path is already that author naming
the hole, and so is `set GIT_SSH = "/tmp/x"`: snug shares nothing by default and
a profile is how a human opens a named hole in their own sandbox — there is no
denylist anywhere in the model. What snug owes is that the screen says what the
hole is. And **a profile snug SHIPS is still refused** a name with no roster row:
try adding `COLORTERM = true` to a builtin's `environ.inherit` in
`internal/profile/profiles/base.toml` and every snug command fails at
`Builtins()`, naming the profile and the variable, because a roster row is where
the sentence saying what the variable lets a tool DO gets reviewed and there is
no human standing behind a profile compiled into the binary.

`environ.declare` was a per-profile escape hatch that existed for one milestone
and was removed before it shipped; a profile still carrying one is refused at
parse time with an unknown-key error, which is `DisallowUnknownFields` working
as designed.

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

### 6j2. A pointer says what the file it names IS, and a row can carry three marks

The profile below is the one a red team wrote against snug's own advice: it
aims four "generate, don't bind" pointers at paths *inside the target*, which
`rw = ["{target}"]` duly grants — and the target is the one writable thing a
hostile payload controls.

```bash
mkdir -p $SC/three/snug/profiles.d
cat > $SC/three/snug/profiles.d/toolchain.toml <<EOF
[profile.toolchain]
description = "a toolchain profile"
rw = ["$SC/proj/sub"]

[profile.toolchain.environ.set]
GIT_SSH           = "/var/lib/toolchain/ssh"
CARGO_HOME        = "$SC/proj/sub/.toolchain/cargo"
DOCKER_CONFIG     = "$SC/proj/sub/.toolchain/docker"
GIT_CONFIG_SYSTEM = "$SC/proj/sub/.toolchain/gitsystem"
EOF

XDG_CONFIG_HOME=$SC/three ./bin/snug --dry-run -p toolchain $SC/proj/sub \
  | sed -n '/^ENVIRONMENT/,/^  HOME/p'
```

Expect (paths abbreviated):

```
  CARGO_HOME       …/proj/sub/.toolchain/cargo     set       toolchain
                     ← the config.toml under this path names a program cargo
                       runs — build.rustc-wrapper ran in place of rustc, as the
                       sandbox's own uid (measured, cargo 1.97.1)
  DOCKER_CONFIG    …/proj/sub/.toolchain/docker    set       toolchain
                     ← credsStore in this directory's config.json is a program
                       docker executes, and it runs before docker reaches a
                       daemon (measured, docker 29.4)
  GIT_CONFIG_SYSTEM …/proj/sub/.toolchain/gitsystem set      toolchain
                     ← unchecked: snug has no type for this name
                     ← git reads a command table from this file:
                       core.sshCommand, credential.helper and alias.x = !cmd all
                       name programs it runs (measured, git 2.55.0)
  GIT_SSH          /var/lib/toolchain/ssh          set       toolchain
                     ← unchecked: snug has no type for this name
                     ← git runs this as the transport for every fetch and push —
                       the older spelling of GIT_SSH_COMMAND, measured to hijack
                       a real `git fetch`
                     ← not granted
```

Nothing here is refused, and nothing should be: a human's profile may aim a
pointer wherever they like. **Three of those rows said NOTHING AT ALL for a
milestone**, because a pointer was exempt from its family's annotation and the
exemption was read as "no sentence" rather than "not the family's sentence". Each
was one config file from exec as the sandbox's own uid, measured on this host:
`build.rustc-wrapper` under `CARGO_HOME` ran in place of rustc; `credsStore`
under `DOCKER_CONFIG` ran `docker-credential-<name>` on a plain `docker pull`,
before the daemon socket; `alias.x = !cmd` and `core.sshCommand` in the file
`GIT_CONFIG_SYSTEM` names both ran.

The last row is the three-mark case: `unchecked` (about the NAME — no roster
row), the annotation (what git DOES with the value), then `not granted` (about
this VALUE as a path — nothing inside covers `/var/lib/toolchain`). Read top to
bottom, widest claim first. Concatenated onto one row, as they used to be, that
line was 264 columns.

`snug profile show toolchain` renders the same sentences, inline, in its own
prose block — same words, different geometry, and only one of those two is a
property worth keeping.

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

**Only the first is a file-load failure now.** It is reported under
`snug: 1 profile file(s) in the search path did not load:` with the file named
and then the reason:

```
profile "c": environ.set on PATH, which is a list — use environ.merge, or
  environ.prepend if the order matters. …
```

**The second one LOADS, and that is the point.** `GIT_SSH` names the program git
runs as its transport, and a profile setting it is a human opening that hole in
their own sandbox — snug has no denylist to refuse it with. What it gets is both
marks, on both screens:

```bash
XDG_CONFIG_HOME=$D ./bin/snug --dry-run -p d $SC/proj/sub | grep GIT_SSH
XDG_CONFIG_HOME=$D ./bin/snug profile show d
```

```
  GIT_SSH          /tmp/x                          set       d
                     ← unchecked: snug has no type for this name
                     ← git runs this as the transport for every fetch and push —
                       the older spelling of GIT_SSH_COMMAND, measured to hijack
                       a real `git fetch`
```

Read the two marks apart: `unchecked` is about the NAME (snug has no type for
it), and the sentence after it is about what the tool DOES with the value. Both
are true, and they answer different questions. `internal/policy/testdata/
annotations.txt` is the full table of the second kind.

The third parses fine and fails at resolution, so it is snug's own error with no
file preamble: `profile "e" merges PATH=/opt/nowhere/bin, which it does not
grant.` That is the grant-coupling rule, and the mistake most people make first.

Worth trying by hand, because these are the boundaries most likely to be wrong —
and note how few of them are refusals of a NAME:

- `TERM`, `HOME`, `SNUG_PROFILES` under `environ.set` — **refused**, snug owns
  them. This is the one refusal of a name that survives, and it is about snug's
  own authorship rather than about the author of the profile;
- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `CDPATH`, `GOFLAGS` at any verb — **refused**,
  but for a completely different reason: they are LISTS whose elements do not
  compose, so snug refuses the OPERATION, not the name. `environ.sanitise
  MANPATH` is the sharpest example — removing an element there ADDS directories;
- `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `GIT_PAGER`, `GIT_DIR`, `GIT_TEMPLATE_DIR`,
  `JAVA_TOOL_OPTIONS`, `RUBYOPT`, `RUSTC_WRAPPER`, `MAKEFLAGS`, `BASH_FUNC_x`,
  `GIT_CONFIG_KEY_0` — **allowed and annotated**, at `set` and at `inherit`. Read
  the sentence each produces; that is the whole of what snug does about them;
- `BASH_ENV` under `set` and under `inherit` — allowed at both, with a
  **different** sentence at each, because the difference between them is where
  the value comes from. That split is deliberate and is the one to decide whether
  you agree with;
- `BASH_ENV = "init.sh"` — **refused**, and it is a TYPE refusal rather than a
  fourth kind. Inside snug the working directory is `--chdir <target>`, the one
  writable thing the payload controls, so a relative value does not name a file
  at all: it names whichever file of that name the payload was last standing
  next to. `BASH_ENV = "{target}/init.sh"` is accepted and says exactly what the
  author meant — **a refusal with an accepted spelling of the same intent is not
  a denial**, which is the test to apply to every refusal on this list. `ENV` and
  `PYTHONSTARTUP` behave identically; `PYTHONBREAKPOINT = "mod:fn"` and
  `LESSOPEN = "|cmd %s"` stay accepted, because measured, their values are not
  paths at all;
- a lowercase name, a name with a hyphen, a name starting with a digit —
  refused by the grammar. A name or value with a control character in it —
  refused too (§6h): those break a mechanism, which is a different thing again.

The three kinds are worth keeping apart when you read a refusal: **ownership**
(snug writes this itself), **type** (snug cannot perform this verb on this
variable correctly), and **transport** (the name or value would corrupt the
environment or forge a line on a screen). There is no fourth kind, and there is
no rule anywhere that says a human may not have something.

Note what that costs, stated so you can disagree with it: `PAGER='sh -c …' git
log` runs the command, and so does the `GIT_PAGER` spelling, and nothing stops a
profile writing either. https://github.com/gomoni/snug/issues/35 and
https://github.com/gomoni/snug/issues/45 are both about this, and both are
answered by the annotation rather than by a withdrawal — because withdrawing
`EDITOR`/`VISUAL`/`PAGER` means taking them off `@claude`, which is a grant a
human asked for.

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

### 6m. `~/.claude.json` is generated, not copied

```bash
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'wc -c < ~/.claude.json; cat ~/.claude.json'
```

Expect a file of a few hundred bytes with **two** keys — `autoUpdates` and
`hasCompletedOnboarding` — for a directory you have never opened Claude Code on,
and a third, a `projects` object naming **only** that directory, when your host's
own `~/.claude.json` already records it as trusted. On the box this was written
on the host's own `~/.claude.json` is 62 274 bytes; the sandbox's was 284.

Check both arms, because the difference is the whole of the trust decision. Pick
a directory your host HAS trusted (any entry with `hasTrustDialogAccepted` in
your own `~/.claude.json`) and one it has not:

```bash
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'cat ~/.claude.json'   # untrusted
./bin/snug -p @claude <a-directory-you-have-trusted> -- /bin/sh -c 'cat ~/.claude.json'
```

Expect no `projects` key in the first and exactly one entry, that directory, in
the second. `snug --dry-run -p @claude <dir>`'s `CLAUDE` block says which arm you
are in, in words, before anything runs.

Then check that none of the host's is in it. Skip this pair if you have never
run Claude Code on this host:

```bash
python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude.json")));print(d["machineID"])'
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'grep -c "<the machineID printed above>" ~/.claude.json'
```

Expect `0`. The host's file is an inventory — every project path on the machine,
`oauthAccount` (email, org name and UUID, account UUID), `machineID`, `userID`,
`mcpServers`, and the per-project tool approvals you granted on the host. None of
it is a credential, which is exactly why it was copied in verbatim for a
milestone (issue #19) behind a comment that said Claude re-runs its first-run
flow without it.

**The measurement that decided the shape**, and the one worth doing by hand,
because it is the half the issue got wrong. Pick a directory that **is** in your
host's project list, i.e. one you have already answered the trust dialog for:

```bash
./bin/snug -p @claude -p @net <a-directory-you-have-trusted> -- claude
```

Expect Claude Code to open straight on its prompt: no seven-option theme picker,
no "Quick safety check: Is this a project you created or one you trust?", and no
`Auto-update failed` banner. The theme picker is gone because snug generated the
key; the safety check is gone because **you** answered it, on the host, and snug
carried that answer for this one path.

**Now the same command on a directory you have never trusted**, which is the
review workflow `@claude` exists for:

```bash
./bin/snug -p @claude -p @net $SC/proj/sub -- claude
```

Expect the theme picker still gone and the trust dialog **back**: "Quick safety
check: Is this a project you created or one you trust?", blocking on a two-option
picker. That is correct and must not be "fixed". Make the point concrete with a
hostile fixture — a repository whose only content is a startup hook:

```bash
mkdir -p $SC/hostile/.claude
cat > $SC/hostile/.claude/settings.json <<EOF
{"hooks":{"SessionStart":[{"hooks":[{"type":"command",
  "command":"touch $SC/hostile/HOOK-FIRED"}]}]}}
EOF
./bin/snug -p @claude $SC/hostile -- claude     # answer nothing; Ctrl-C out
ls $SC/hostile/HOOK-FIRED
```

Expect the trust dialog, and `ls` to report **No such file**: the repository's own
hook did not run. Measured on the build that wrote the trust key unconditionally,
the same fixture opened on "Welcome back!" with no dialog and `HOOK-FIRED`
present — the repo's code executing at startup, in a sandbox holding the staged
Anthropic OAuth token. Delete the generated state and the theme picker comes back
too on **every** run: `$HOME` is a fresh tmpfs each time, and the picker's answer
is written to `~/.claude/settings.json`, which snug now GENERATES on every run
rather than binding (issue #17) — the file is a command table (`hooks`,
`apiKeyHelper`, `env`, `mcpServers`, `enabledPlugins` all name a program to run,
a credential to print, or code to fetch), so a read-only bind of the host's
would still hand every one of those over rather than stop them. See exactly
what crosses:

```bash
./bin/snug -p @claude $SC/proj/sub -- cat ~/.claude/settings.json
```

Expect a small JSON document containing your `model` and `theme` and nothing
else you recognise from your host file — in particular no `hooks`,
`apiKeyHelper`, `env`, `enabledPlugins` or `extraKnownMarketplaces`. Then:

```bash
diff <(./bin/snug -p @claude $SC/proj/sub -- cat ~/.claude/settings.json) ~/.claude/settings.json
```

Expect a difference on every executing key, and agreement on the carried ones.
And the writability arm — it is a private tmpfs copy, so nothing here reaches
the host:

```bash
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'echo "{}" > ~/.claude/settings.json; echo ok'
md5sum ~/.claude/settings.json   # unchanged on the host
```

**And the measurement that stays open after this fix**, on a host with a
hook-carrying plugin installed:

```bash
./bin/snug -p @claude <a-directory-you-have-trusted> -- claude
```

Watch for the plugin's `SessionStart` hook firing (a file it writes, or a
status message it prints). `@claude` still binds `{home}/.claude/plugins`
read-only, and a plugin manifest — plus `installed_plugins.json`, independently
of `settings.json` — carries its own `hooks` block that Claude Code loads
automatically. Filtering `settings.json` does not touch that channel. See
https://github.com/gomoni/snug/issues/68.

What you should also expect, and it is not breakage: `/mcp` shows nothing from
your host user config — a `.mcp.json` committed in the target is a different
thing and is still read, because it lives in the project tree — and a tool
you approved in a host session is asked again here. Both are consequences of not
copying the host's file, and both are stated in the `~/.claude/CLAUDE.md` snug
injects, so the agent does not spend turns diagnosing them.

### 6n. The staged credential carries no refresh token (issue #58)

`~/.claude/.credentials.json` is the one file `@claude` stages that is a
CREDENTIAL rather than a configuration, and it used to be copied verbatim —
access token and refresh token both. The difference is the blast radius of a
credential stolen from inside: an access token expires in hours, a refresh
token mints new ones for as long as it lives. On the host this was measured on,
5h 20m against 26 days.

```bash
./bin/snug -p @claude $SC/proj/sub -- python3 -c \
  'import json,os;print(sorted(json.load(open(os.path.expanduser("~/.claude/.credentials.json")))["claudeAiOauth"]))'
```

Expect exactly:

```
['accessToken', 'expiresAt', 'rateLimitTier', 'scopes', 'subscriptionType']
```

`refreshToken` and `refreshTokenExpiresAt` must not be there. Compare with the
host's own file — same command without snug — which has all seven. **Assert the
SET, not the absence of one name:** a field added upstream tomorrow is dropped
rather than carried, and noticing that is the point of a projection.

Then the half that matters more than the field list — that it still WORKS:

```bash
./bin/snug -p @claude -p @net $SC/proj/sub -- claude -p 'Reply with exactly: PROJECTED-CREDENTIAL-WORKS'
```

Expect `PROJECTED-CREDENTIAL-WORKS`. This is a live authenticated turn on the
staged token, and it is the measurement the whole change rests on.

`snug --dry-run -p @claude <dir>`'s `CLAUDE` block states the same thing in
words, under `creds`, before anything runs — including the arm where nothing was
staged at all, and **including the number**:

```
         creds      ~/.claude/.credentials.json is PROJECTED from the host's —
                    a generated file, not a copy
                    carried: accessToken expiresAt scopes subscriptionType rateLimitTier
                    NOT carried: refreshToken refreshTokenExpiresAt
                    expires:  2026-08-19T15:56:00+02:00 (in 5h00m)
                    Nothing in here can mint a NEW token, so a stolen copy is
                    bounded by the expiry above — hours — rather than by the
                    refresh token's, which is weeks. It is a timer, not a
                    kill switch: it can still outlive this sandbox
```

Read that last sentence as written. The bound is a **timer, not a kill switch**:
there is no revocation faster than expiry, so a stolen token still buys its
remaining life — hours, against a sandbox that often lives for minutes. What
changed is the *scale*: hours instead of the refresh token's weeks.

**Check it on a host whose `$HOME` is a symlink**, if you have one (`/home ->
/var/home` is the default on Silverblue- and MicroOS-shaped systems). The
`creds` line must still read `PROJECTED`. It once read `staged NOTHING …` there
while the same screen's `FILESYSTEM` block and bwrap argv showed the token being
handed over — a trust screen denying a credential that is present.

**And check the three files snug must refuse to read**, all at
`~/.claude/.credentials.json` in a throwaway `$HOME`: a FIFO (`mkfifo`), a
symlink to `/dev/zero`, and a file over 64 KiB. Each must print a `snug: not
staging …` line naming the reason and return. The FIFO is the one that matters:
unguarded, it blocks in `open(2)` forever — no sandbox, no exit code, nothing on
any screen.

**The cost, and check you can live with it.** With `@net` and a host token close
to expiry this is now a hard failure where the refresh used to recover quietly.
Expect a `snug:` line naming the fix before the run starts:

```
snug: the staged Anthropic access token expired 2026-08-19T15:27:00+02:00.
      snug stages the access token only, not the refresh token, so nothing inside
      the sandbox can renew it (issue #58).
      Fix: run `claude` on the host to refresh it, then start snug again.
```

**And the failure that must NOT be silent.** Corrupt a copy of the host file and
point snug at it (never edit your real one):

```bash
H=$(mktemp -d); mkdir -p $H/.claude; echo 'not json' > $H/.claude/.credentials.json
HOME=$H ./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'ls -a $HOME/.claude/'
```

Note `$HOME` inside single quotes, so it expands **inside** the sandbox rather
than on your host. Expect a `snug: not staging …` line, and no
`.credentials.json` in the listing:

```
. .. CLAUDE.md settings.json
```

Then the control, without the fake home — otherwise "the file is absent" would
pass just as well on a run where staging stopped working altogether:

```bash
./bin/snug -p @claude $SC/proj/sub -- /bin/sh -c 'ls -a $HOME/.claude/'
. .. CLAUDE.md .credentials.json plugins settings.json
```

A build that stages the host bytes in the first case has fallen back to the old
behaviour, which is the one regression that would undo this change with nothing
on screen to say so.

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

### What denying `pidfd_getfd` actually buys (issue #115)

The filter's own comment used to say the denial was the only route to "a
socket, a pipe, a memfd, a deleted file", because procfs could reopen none of
the four. Three of the four were wrong, and this is how you see it: two
**sibling** processes inside one sandbox, no ptrace, no denied syscall — just
`open(2)` on `/proc/<pid>/fd/N`.

```bash
cat > $SC/proj/sub/reopen.py <<'PY'
import os, socket, sys, time
if sys.argv[1] == "holder":
    fds = {}
    f = open("ctl", "w+"); f.write("M-control"); f.flush(); fds["control"] = f.fileno()
    m = os.memfd_create("s", 0); os.write(m, b"M-memfd"); fds["memfd"] = m
    r, w = os.pipe(); os.write(w, b"M-pipe"); fds["pipe"] = r
    d = os.open("del", os.O_RDWR | os.O_CREAT, 0o600); os.write(d, b"M-deleted"); os.unlink("del"); fds["deleted"] = d
    a, b = socket.socketpair(); b.send(b"M-socket"); fds["socket"] = a.fileno()
    print(os.getpid(), " ".join("%s=%d" % kv for kv in fds.items()), flush=True)
    time.sleep(10)
else:
    for spec in sys.argv[3:]:
        k, n = spec.split("=")
        p = "/proc/%s/fd/%s" % (sys.argv[2], n)
        try:
            fd = os.open(p, os.O_RDONLY); print(k, "REOPENED", os.read(fd, 64)); os.close(fd)
        except OSError as e:
            print(k, "REFUSED", e.strerror)
PY

./bin/snug $SC/proj/sub -- /bin/sh -c '
  python3 reopen.py holder > h.out 2>&1 &
  while ! [ -s h.out ]; do sleep 0.05; done
  python3 reopen.py thief $(cat h.out)'
```

Expect exactly:

```
control REOPENED b'M-control'
memfd REOPENED b'M-memfd'
pipe REOPENED b'M-pipe'
deleted REOPENED b'M-deleted'
socket REFUSED No such device or address
```

Read the five lines in three groups. `control` is the **positive control** — a
plain, still-linked file, reopened by a sibling that never had the descriptor;
if it does not say `REOPENED`, the probe is broken and the last line proves
nothing. `memfd`/`pipe`/`deleted` are the **finding**: each was named in
`seccomp.go` as unreachable through procfs, and each hands over its bytes.
`socket` is the **whole residual** the denial buys, and the errno matters —
`ENXIO`, because sockfs has no open method, not `EACCES` from some permission
check. That is why it holds for root too, and why SUPERVISOR-DESIGN.md's
control-channel argument still stands.

The automated equivalent is
`TestKnownOpenResidualSiblingReopensAnythingButASocket`; both are deliberately
asserting that a reach is **open** (issue #47), except for the last line.

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

## 7b. What the sandbox is told about DNS, and whether the screen agrees (issues #28, #162)

Two questions on one screen, and until issue #28 they were answered by a
hardcoded line rather than by the policy: *which resolver does the sandbox
actually get*, and *does `--dry-run` describe that run*. `@net-anon` makes the
second question load-bearing, because it is the profile whose whole purpose is
that the sandbox does not learn where the host sits.

```bash
echo "HOST:"; grep ^nameserver /etc/resolv.conf

for p in @net @net-anon; do
  echo "== $p =="
  ./bin/snug --dry-run -p $p $SC/proj/sub -- true | grep -A3 '^ *dns '
  ./bin/snug -p $p $SC/proj/sub -- /bin/sh -c 'grep ^nameserver /etc/resolv.conf'
done

./bin/snug -p @net-anon $SC/proj/sub -- /bin/sh -c \
  'getent hosts example.com >/dev/null && echo RESOLVED || echo RESOLVE-FAILED'
```

Expect, on a host whose own resolvers are routable (an ordinary LAN router, the
common case):

- `@net` names **the host's own resolvers** in both places — on the screen and
  in the file — with the screen saying plainly that a LAN resolver address
  discloses the network the host sits on. That is a disclosure matching a grant:
  `@net` copies the host's address by design and says so on the next line.
- `@net-anon` names **`169.254.1.1` in both places**, and **neither** of the
  host's resolver addresses anywhere. This is the fix for issue #162: the
  profile used to hide the host's LAN address and then hand back the host's LAN
  resolver, which discloses the same prefix — the router is normally the
  resolver.
- `RESOLVED`. The property is withholding the *host's* resolver, not withholding
  DNS; pasta re-issues the query from the host side. If this prints
  `RESOLVE-FAILED`, the disclosure was traded for a broken sandbox and that is a
  regression, not a tightening.

On a `systemd-resolved` host (every resolver on `127.0.0.53`) both profiles show
`169.254.1.1`, because interception is the only arm available — the comparison
above distinguishes nothing there, which is why the automated version of this
check skips such a host rather than passing on it.

The cross-check is the point of running both commands rather than either one.
A screen that agrees with a file is worth more than either alone: issue #28 was
exactly a screen that described an interception the sandbox was not doing.

**`@net-host` has a dns line now, and that is the point of issue #164.** It
shares the host's network namespace and runs no pasta, so it used to be handed
the interception address with nothing behind it — DNS simply did not work — and
the NETWORK block printed no dns line at all, so nothing said so:

```bash
./bin/snug --dry-run -p @net-host --i-know $SC/proj/sub -- true | grep -A2 '^ *dns '
./bin/snug -p @net-host --i-know $SC/proj/sub -- /bin/sh -c \
  'grep ^nameserver /etc/resolv.conf; timeout 5 getent hosts example.com >/dev/null \
     && echo RESOLVED || echo RESOLVE-FAILED'
```

Expect the screen and the file to name **the host's own resolvers**, and
`RESOLVED`. On a `systemd-resolved` host that means `127.0.0.53` appears inside,
and that is correct rather than a leak: the netns *is* the host's, so that
address is reachable, and naming it discloses strictly less than the namespace
this profile has already handed over. `169.254.1.1` must not appear — no pasta
runs here to intercept it.

**And the forwarder's destination is named.** Under `@net-anon` the dns line
reads `169.254.1.1 -> pasta -> <addr>`, where `<addr>` is the host's first
nameserver, pinned by snug with `--dns-host` rather than left to pasta's own
default (issue #166). Check it against the argv:

```bash
./bin/snug --dry-run -p @net-anon $SC/proj/sub -- true | grep -E '^ *dns |--dns-host'
```

Both must name the same address. They are two authors of one fact and this is
the line where they are made to agree.

**Two more lines in the same block, fixed by issue #165's v6 pair.** Under
`@net-anon` the block now prints an `address v4` row and an `address v6` row,
each carrying its own synthetic value — `10.13.13.2/24` and
`fd00:5e79:1::2/64`. Check that against the interface:

```bash
ip -br addr show scope global
./bin/snug -p @net-anon $SC/proj/sub -- /bin/sh -c 'ip -br addr show dev snug0; ip -6 route show default'
```

Expect the sandbox's `snug0` to carry **only** `10.13.13.2/24` and
`fd00:5e79:1::2/64` (plus a link-local address whose EUI-64 comes from a
per-run random tap MAC) — **none of the host's own addresses, in either
family** — and a default route via `fd00:5e79:1::1`, never a `proto ra` route
through the router's own link-local address. That is issue #165, fixed: the
v4-only address used to leave pasta's IPv6 default in place (copy the
addresses from the interface holding the default route), so the sandbox kept
the host's own GLOBAL v6 addresses verbatim — the weaker (RFC1918) half hidden,
the stronger (globally routable, geolocatable) half disclosed. If either of the
host's addresses from the first command ever reappears in the second, that is
the regression this line exists to catch.

**The host's own address becomes reachable *because* it is hidden — issue
#176, and it is documented, not closed.** Anonymising an address takes it off
the sandbox's own interface, so a connection to it stops being refused by the
sandbox's own kernel and instead leaves the netns for pasta to open on the
real host. `@net` is the control that makes this checkable: the same address
must be refused there and reached under `@net-anon`.

```bash
python3 -m http.server -b "$(hostname -I | awk '{print $1}')" 8199 &
HOSTPY=$!
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c \
  "curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://$(hostname -I | awk '{print $1}'):8199/ || echo REFUSED"
./bin/snug -p @net-anon $SC/proj/sub -- /bin/sh -c \
  "curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://$(hostname -I | awk '{print $1}'):8199/ || echo REFUSED"
kill $HOSTPY
```

Expect `REFUSED` (or a curl connect-error line) under `@net`, and `200` under
`@net-anon`. **Host loopback stays closed in both** — `127.0.0.1`/`::1` are
never reachable, and that is the property this project promises regardless of
which profile is selected; only the host's *own, non-loopback* address moves.

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

## 9a. `profile show` names the network hole, not only the path holes (issue #195)

`snug profile show` is the screen a human reads to decide **whether** to select a
profile, which puts it upstream of every `--dry-run`. It rendered every key that
names a path and dropped every key that does not, so a profile granting full
internet egress read as a profile granting nothing:

```console
$ ./bin/snug profile show @net
profile     @net
            Internet access via a private network namespace. Host loopback unreachable.
defined in  builtin:base.toml

  network          egress
                   the sandbox reaches the whole internet, from a private netns.
                   Host loopback and abstract sockets stay unreachable.
  dns              yes
                   a generated /etc/resolv.conf names a resolver inside the
                   sandbox
```

```console
$ ./bin/snug profile show @podman-socket | grep -A2 podman
  podman           socket
                   starts a container engine and delegates your whole subuid
                   range, even with no network profile selected
```

What to check:

1. `@net` names `network` and `dns`, `@net-anon` names both synthetic address
   pairs, `@podman-socket` names `podman`. Before #195 all three printed nothing
   about any of it.
2. Each row carries the **consequence**, not just the value. "egress" is a word;
   "the sandbox reaches the whole internet" is the thing being agreed to.
3. `@sys` prints **no** capability rows at all — it grants only paths, and an
   empty block would be noise on the profile people read most.
4. Every capability row fits 80 columns. The consequences are wrapped by hand,
   so this is a claim that can rot; `TestProfileShowCapabilityRowsFitAnEightyColumnScreen`
   is the automated half.

The structural half is `TestProfileShowRendersEveryProfileField`, which walks
`policy.Profile` by reflection and fails on any field that is neither rendered
nor exempted with a reason. The nine missing rows were not the defect — **nothing
noticing** was, and a hand-written renderer falls one behind the struct once per
feature.

## 9a. NOT GRANTED is not wrong in the reassuring direction (issue #59)

`--dry-run` is the mechanism by which a human can trust snug at all, so a row
there that overstates what is denied is the worst kind of wrong. `covered()`
walked **upward** only, so a bind *beneath* a candidate never marked that
candidate covered:

```console
$ ./bin/snug --dry-run -p @sys -p @home -p @claude . | sed -n '/NOT GRANTED/,/^$/p'
  NOT GRANTED (never mounted — these read as absent, they are not hidden;
  where it says "host's", snug generates its own file at that path instead):
    ~/.ssh  ~/.gnupg  ~/.aws  ~/.config/gh  ~/.kube  ~/.docker  ~/.netrc  ~/.mozilla  ~/.local/share/keyrings
    ~/.claude  PARTIAL — 1 host path beneath it is bound (see FILESYSTEM)
      the rest of it is not granted, and snug generates its own content here
    /sys  /tmp/.X11-unix  the Wayland socket  the session D-Bus socket
```

Before the fix, `~/.claude` sat in the bare run at the top — reading as "none of
this is here" — while the FILESYSTEM block above bound `~/.claude/plugins`
read-only. Measured content under there: 406 KB of plugin catalogue plus a
third-party git repository whose `.git/config` is a command table.

What to check:

1. `~/.claude` is on its **own** line and says `PARTIAL`, not in the bare run.
2. It names both halves — what **is** bound, and that the rest is not. "Granted"
   alone would be a lie in the other direction.
3. `~/.ssh` and the rest are still bare names. A fix that marked everything
   PARTIAL would satisfy check 1 and destroy the block's meaning.
4. Cross-check the count against FILESYSTEM: the number in the row is the number
   of `bind` rows whose host path is strictly beneath `~/.claude`. Generated
   (`data`) rows are not binds and are deliberately not counted — that is what
   the "snug generates its own content here" clause is for.

The sibling counter uses the same walk and got the same fix: a sibling with
something bound beneath it is reported separately rather than counted as an
entry that reads as absent.

## 9. A project directly in an ephemeral directory is refused (issue #179)

`~/myproject` is an extremely common layout and snug will not sandbox it. The old
refusal was a raw kind conflict that named two profiles and no working command:

```console
$ mkdir ~/proj && ./bin/snug --dry-run ~/proj
snug: refusing to sandbox /home/michal/proj: it sits directly in /home/michal, which @home provides as an empty, ephemeral tmpfs.
       So the parent snug would grant IS that directory, and a read-only bind of it
       cannot coexist with the tmpfs. Move the project one level down:
           mv /home/michal/proj /home/michal/src/ && snug /home/michal/src/proj
       A selection without @parent-ro does resolve; snug does not offer it here. A
       project sitting directly in an ephemeral directory is the wrong thing to
       sandbox, and one answer beats a fork somebody guesses at.
```

The target being one of those directories is a different sentence, because there
is genuinely nothing to select:

```console
$ ./bin/snug --dry-run ~
snug: refusing to sandbox /home/michal: it IS a directory @home provides as an empty, ephemeral tmpfs.
       No selection sandboxes this path — a profile must bind the target to make it
       visible, and that collides with the tmpfs however you choose. Sandbox a
       project directory instead:
           mkdir -p /home/michal/src/myproject && snug /home/michal/src/myproject
```

What to check:

1. **It is not keyed on `$HOME`.** `@home` provides five ephemeral directories,
   so `~/.cache/build` and `~/.config/nvim` refuse identically, naming the
   directory that is actually ephemeral:

```console
$ mkdir -p ~/.cache/build && ./bin/snug --dry-run ~/.cache/build | head -1
snug: refusing to sandbox /home/michal/.cache/build: it sits directly in /home/michal/.cache, which @home provides ...
```

2. **The refusal survives an explicit selection.** This resolves cleanly and is
   still refused, which is the ruling:

```console
$ ./bin/snug --dry-run --no-defaults -p @sys -p @home -p @cwd-rw ~/proj | head -1
snug: refusing to sandbox /home/michal/proj: ...
```

   The message says a selection without `@parent-ro` *does* resolve, rather than
   implying none exists. Hiding a true option would be worse than the message it
   replaced.

3. **`/tmp` targets still work**, and this is the check that matters most because
   it is how this file and the whole integration suite build targets. snug's own
   `/tmp` is a tmpfs too; only `$HOME`-rooted ones refuse:

```console
$ ./bin/snug --dry-run "$(mktemp -d)" >/dev/null && echo OK
OK
```

4. So does an ordinary project one level down — the layout the message points at:

```console
$ ./bin/snug --dry-run ~/src/anything >/dev/null && echo OK
OK
```

**Why the rule lives in two places.** `join` reports a kind conflict during the
fold, so a check that ran afterwards would never speak for the default selection
— the exact case #179 is about. The rule therefore runs before the fold over the
tmpfs *grants*, and `Validate` carries the same rule over the resolved *mounts*
for a policy built without going through `Resolve`. Two halves of one rule is the
shape this project has a standing complaint about, so
`TestBothHalvesOfTheEphemeralRuleAgree` asserts they never disagree.

## 9a. A profile that takes over snug's own /tmp says so (issue #223)

`yieldTo` installs snug's own `/proc`, `/dev` and `/tmp` **only if nothing else
claims that path**. That is how `@tmp-shared` works. What is not intended is
`@parent-ro` reaching `/tmp` by accident of where the target sits:

```console
$ ./bin/snug --dry-run "$(mktemp -d)" | sed -n '/^  ro     \/tmp /,/^  ro     \/usr/p'
  ro     /tmp                                           @parent-ro
                     ← this is the HOST's /tmp, not snug's private one — a
                       profile claimed the path, so the tmpfs snug would have
                       put here never landed. $TMPDIR points inside it,
                       READ-ONLY, which most tooling breaks on
```

A `mktemp -d` target has `/tmp` as its parent, so this is the ordinary shape, not
an exotic one — it is how `VERIFY.md` and the integration suite build targets.

What to check:

1. The row is marked. Before #223 it rendered as a bare `ro /tmp @parent-ro`,
   indistinguishable from any other read-only bind.
2. **The writable surface is seven for this run, not the eight this file and
   CLAUDE.md quote.** `/tmp` is the host's and read-only. That is the whole point
   of the mark: a guarantee that quietly stopped holding.
3. An ordinary target gets **no** mark:

```console
$ ./bin/snug --dry-run ~/src/anything | grep -A1 'tmpfs  /tmp'
  tmpfs  /tmp                                           (snug)
  ro     /usr                                           @sys
```

   A warning on every run is a warning nobody reads.
4. `@tmp-shared`'s writable takeover keeps the "this is the host's" note and
   loses the READ-ONLY clause, because that clause would be false.

**Said rather than refused, deliberately.** `snug /tmp/x` is ordinary, so a
refusal would break snug's own test workflow unless it could distinguish "the
yield was asked for" from "the yield happened by accident" — and this layer
cannot. `--dry-run` being honest is the mechanism the project already relies on.

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

## 9d. `@podman-socket` without `@net` is offline, containers included

This is the inversion the previous version of this check predicted (issue
#63, Tier B): the engine now runs in the sandbox's OWN network namespace, so
`@podman-socket` alone no longer pulls in `@net`, and offline is once again
the ABSENCE of a profile rather than something the profile switches back on.
Needs no engine — this is a `--dry-run` check, and `--dry-run` is the
artifact the guarantee is read off, which is exactly where it was wrong
before (`.claude/design/ENGINE-NETNS.md` §0).

```bash
./bin/snug --dry-run -p @podman-socket $SC/proj/sub | grep -E '^ *\+|^NETWORK|^CONTAINERS|^  engine'
./bin/snug --dry-run -p @podman-socket -p @net $SC/proj/sub | grep -E '^NETWORK|^CONTAINERS'
```

Expect from the first: **no** `+ @net` line, the **isolated** NETWORK block
("No egress. No host loopback." — and now true for containers too), a
`CONTAINERS` block saying a container has no egress either, and a TOPOLOGY
`engine` line naming the sandbox's own netns and the 12-entry capability
bounding set — the real cost of selecting a container engine, on screen even
offline.

Expect from the second — the positive control: the **egress** NETWORK block,
and a `CONTAINERS` block whose egress clause now agrees with it.

Both directions matter: a check that only ran the first command could not
tell "offline" apart from "the profile stopped resolving containers at all".

**With a real engine** (podman installed and not a host-escape shim — see
`snug doctor`), the same property holds for a REAL run, not just the screen:

```bash
snug -p @podman-socket $SC/proj/sub -- \
  sh -c 'curl --unix-socket ${DOCKER_HOST#unix://} -sX POST "http://x/v1.41/images/create?fromImage=alpine&tag=3.20"'
```

Expect a network error from the PULL itself ("network is unreachable" or a
DNS failure) — the engine's own process is in N, so it has no egress before a
container is even created. Add `-p @net` and expect the pull to succeed.
Positive control: `curl --unix-socket ... http://x/v1.41/version` succeeds
either way — the engine exists and answers locally; only egress differs.

## 9e. A profile name is refused as a NAME, not as a missing profile

9b covers the `@` namespace; this covers the rest of the grammar, and it covers
it at every place a *human* supplies a name. A profile name is
`[a-zA-Z0-9]` followed by `[a-zA-Z0-9-]`, optionally behind the mark — an
allowlist, so a character snug has not been taught about fails closed.

The distinction being checked is between two different sentences. `unknown
profile "foo"` means *snug looked and there is none*; the refusals below mean
*that is not a name*, and they arrive before the registry is consulted, before
`--dry-run` renders anything, and before a namespace exists. Since issue #67 a
validated name is a TYPE (`policy.ProfileName`) whose only constructor applies
the grammar, so these three sites are the three doors and there is no fourth
inside snug's own code.

```bash
# the control FIRST: a legal name still works, or the refusals prove nothing
./bin/snug --dry-run -p @git-ro $SC/proj/sub | head -4

# door 1 and 2: -p and --profile=
./bin/snug --dry-run -p 'a b'        $SC/proj/sub
./bin/snug --dry-run --profile=a.b   $SC/proj/sub
./bin/snug --dry-run -p my_profile   $SC/proj/sub
./bin/snug --dry-run -p '@'          $SC/proj/sub

# the ESC case issue #20 was opened for: the refusal must SHOW the byte, not
# emit it. Pipe through cat -v — if the terminal eats a row, that is the bug.
./bin/snug --dry-run -p "$(printf 'a\033[1A\rFORGED')" $SC/proj/sub 2>&1 | cat -v

# door 3: the `defaults` setting. A refused name here must be FATAL — falling
# back to the built-in four would widen the sandbox past what the file asked
# for, which is invariant 5.
X=$(mktemp -d); mkdir -p $X/snug
printf 'defaults = ["@sys", "@cwd-rw"]\n' > $X/snug/config.toml
XDG_CONFIG_HOME=$X ./bin/snug config | head -6            # control: accepted
printf 'defaults = ["@sys", "a b"]\n'    > $X/snug/config.toml
XDG_CONFIG_HOME=$X ./bin/snug config; echo "exit $?"
rm -rf $X
```

Expect: the control prints a normal dry run naming `@git-ro`. Each refusal names
the offending byte and its offset — `" "` at 1, `"."` at 1, `"_"` at 2 — and
`my_profile` additionally suggests `"my-profile"`, because the hyphen is in the
set and the underscore is not. `-p '@'` says the mark needs a name after it. The
ESC case shows the literal four characters `\x1b` and no row is erased (`cat -v`
also renders snug's em-dashes as `M-bM-^@M-^T`; that is `cat -v`, not snug).
Each of these is a *usage* error, so the flag help follows it and the exit code
is 64. None of them says `unknown profile`, and none reaches the FILESYSTEM
block — the name never gets as far as the registry.

The `defaults` control prints `"@sys" "@cwd-rw"` and the file's path; the second
run exits **77** naming `entry 2` and the config file, rather than silently
resolving the built-in list.

## 9f. A container never sees the HOST's real /etc/resolv.conf (issue #126)

`EnterEngine` mounts a private COPY of the whole host tree before it execs
podman, and up through issue #126 nothing touched that copy's own
`/etc/resolv.conf` — so it was still the HOST's real one (LAN nameservers, the
search domain), and podman generated every container's own resolv.conf FROM
it. An offline sandbox's own `/etc/resolv.conf` is correctly empty of
nameservers; a container it started got the host's anyway, through a channel
`internal/dockerproxy`'s bind filter never sees because it is not a
client-requested mount. The first half of the fix bind-mounts snug's own
GENERATED `/etc/resolv.conf` — the identical content the sandbox payload gets
— over the engine's private copy before exec.

**The bind is no longer what decides a CONTAINER's DNS, and that matters when
you read the result.** It is best-effort: issue #128 measured an ordinary host
where `/etc/resolv.conf` is itself a bind over a deleted inode, so mounting
onto it returns ENOENT and every container run failed. What now decides a
container's DNS is snug's GENERATED `containers.conf` —
`dns_servers`/`dns_searches`/`dns_options`/`base_hosts_file`, written from the
same resolved `policy.NetPolicy`, pointed at by both `CONTAINERS_CONF` and
`CONTAINERS_CONF_OVERRIDE` — which needs no mount at all. The bind now decides
only the ENGINE's own lookups: without it, an offline engine tries the host's
resolvers and times out slowly instead of failing fast. Preflight **P7** says
so before the run starts, and the message says exactly that — if it ever says
"containers may see host DNS", the message is wrong.

**Needs a real engine** (podman installed and not a host-escape shim — see
`snug doctor`; `$SNUG_PODMAN` to pin one explicitly).

```bash
snug -p @podman-socket $SC/proj/sub -- sh -c '
  echo "SANDBOX:"; cat /etc/resolv.conf
'
```

Expect the sandbox's own `/etc/resolv.conf` to carry no nameserver offline
("DNS is intentionally unavailable"). Then, in the same sandbox, build and run
a `FROM scratch` container whose only job is to `cat /etc/resolv.conf` (the
committed regression, `test/integration/testdata/resolvprobe`, does exactly
this over the compat API — see
`TestContainerGetsGeneratedResolvConfNotTheHosts` for the scripted version of
this check with a from-scratch image, since the docker/podman CLI itself does
not run inside the sandbox — `warnAboutPodmanClient` explains why). Expect the
container's own `/etc/resolv.conf` to name **no** address this host's real
`/etc/resolv.conf` (run `cat /etc/resolv.conf` on the HOST, outside the
sandbox, for comparison) names as a nameserver — the leak issue #126 fixed.
Add `-p @net` and expect the container's resolv.conf to now agree with the
SANDBOX's own (pasta's resolver, or the host's routable nameservers relayed
through egress) — expected once egress is granted, and a different fact from
the host-LAN-topology leak offline.

Also `cat /etc/hosts` in the container. Expect `localhost` entries and, with
`-p @net`, podman's own `host.containers.internal`/`host.docker.internal` —
and **no** name out of the HOST's `/etc/hosts`. Compare against `cat
/etc/hosts` on the host. Read that result honestly: on the compat API path
podman synthesizes this file rather than copying it, so it was already clean
before `base_hosts_file = "none"` was set; the key is what makes it clean
STRUCTURALLY, on any path and any podman version, rather than by accident of
the schema the proxy happens to allow. The copy WAS measured on podman's CLI
path, which nothing inside a snug sandbox can reach today.

### 9g. Preflight P7 — can this host replace the engine's own resolv.conf?

```bash
snug -p @podman-socket $SC/proj/sub -- true
```

On a healthy host: no P7 message at all. On a host with issue #128's broken
mount: a `snug:` warning naming `/etc/resolv.conf`, saying **containers are
not affected** and that the ENGINE will time out slowly offline, and the run
CONTINUES. A refusal here would be refusing over a degradation that leaks
nothing. To see the probe's own answer directly:

```bash
go test ./internal/cli/ -run AsksTheHost -v 2>&1 | grep 'P7:'
```

Expect one line, either `P7: this host CAN bind over /etc/resolv.conf` or
`P7: this host CANNOT ... : mounting a file over /etc/resolv.conf: ...`, or a
SKIP saying the probe cannot run here at all — a host that cannot create the
throwaway user namespace (CI's unit-test container is one) has not answered the
question, and snug stays silent rather than reporting "cannot bind". If it ever
says `making / private`, the probe never reached its question either — that is
the probe's machinery failing, not the host's answer, and it would warn on
every host.

### 9h. The HOST's containers.conf authors nothing in a container (issue #132)

podman reads a user `containers.conf` from `$XDG_CONFIG_HOME/containers/` or,
when that is unset — which is the engine's situation, since snug hands it only
`PATH`, `HOME` and `XDG_RUNTIME_DIR` — from `$HOME/.config/containers/`. Keys
there author binds, volumes, device nodes and environment for **every**
container, none of it client-requested, so the proxy's bind filter never sees
it and `--dry-run` never mentions it.

snug points `CONTAINERS_CONF` at its own generated file, which makes podman
ignore the system and user files entirely. To see the channel this closes, plant
one and watch it work **without** snug:

```bash
D=$(mktemp -d); S=$(mktemp -d); echo HOST-SECRET-MARKER > $S/token
mkdir -p $D/.config/containers
cp ~/.local/opt/podman-static/home/.config/containers/policy.json $D/.config/containers/
cat > $D/.config/containers/containers.conf <<EOF
[containers]
mounts = ["type=bind,source=$S,destination=/leak,ro=true"]
default_ulimits = ["nofile=13571:13571"]
EOF
env -u CONTAINERS_CONF -u XDG_CONFIG_HOME HOME=$D   ~/.local/opt/podman-static/usr/local/bin/podman run --rm alpine:3.20 cat /leak/token
```

Expect `HOST-SECRET-MARKER`. Then set `CONTAINERS_CONF` at a file containing
`[containers]` and `mounts = []` and expect the same command to fail with
`can't open '/leak/token'`.

**Read `default_ulimits` as the sharper half.** `mounts` is also closed by
snug's own enumeration, so its absence cannot tell "the host's file was
replaced" from "our value won". `default_ulimits` is deliberately **not**
enumerated (issue #136), so it is stopped only by replacement — if
`Max open files 13571` ever appears in `/proc/self/limits` inside a container,
`CONTAINERS_CONF` has stopped suppressing and every unenumerated key is live
again. `TestHostContainersConfAuthorsNothingInAContainer` is the scripted
version, with the same discriminator.

**Two files `CONTAINERS_CONF` does NOT cover** — `registries.conf` (steers
where an image comes from) and `policy.json` (decides whether an image may be
used at all). Both were measured live, filed as #137, and closed the same way:
see §9i. The channel itself is still worth seeing, because it is what §9i
proves is shut:

```bash
echo 'THIS IS NOT VALID TOML {{{' > $D/.config/containers/registries.conf
env -u CONTAINERS_REGISTRIES_CONF -u XDG_CONFIG_HOME HOME=$D   ~/.local/opt/podman-static/usr/local/bin/podman pull alpine:3.20
```

Expect a parse error naming that path — which is the proof it was read.

### 9i. Image provenance is snug's, not this host's (issues #137, #142)

`CONTAINERS_CONF` closed `containers.conf`. Three more channels reach the
engine through a home directory, and each has its own lever: `registries.conf`
(where an image comes from), `policy.json` (whether it may be used at all), and
the registry CREDENTIALS the engine authenticates with. `--dry-run` states all
of it in the `IMAGES` block:

```bash
./bin/snug --dry-run -p @podman-socket $SC/proj | sed -n '/^IMAGES/,/^[A-Z][A-Z]/p'
```

Expect `docker.io and nothing else`, `signatures  NOT verified`, and
`logins      NONE`.

**The credential is the sharp one.** A developer host has
`~/.docker/config.json`, and podman falls through to it because
`$XDG_RUNTIME_DIR/containers/auth.json` is absent by construction on a snug run.
Prove the channel, then prove it is shut, with a name you are already logged in
to:

```bash
P=~/.local/opt/podman-static
E="CONTAINERS_STORAGE_CONF=$P/etc/snug/storage.conf PATH=/usr/bin"

# the channel: the host's own home resolves the host's own credential
env -i $E HOME=$HOME       $P/usr/local/bin/podman login --get-login <a registry you use>
# what snug does instead
env -i $E HOME=$HOME REGISTRY_AUTH_FILE=/dev/null $P/usr/local/bin/podman login --get-login <the same registry>
```

Expect your username, then `Error: not logged into ...`. `REGISTRY_AUTH_FILE`
is the lever snug sets (at an empty file of its own, not `/dev/null`), and it
works regardless of how a given podman decides what "the user's home" is —
which the `HOME` override alone does not: it was measured on podman 5.8.4 only.

`TestTheEngineResolvesNoHostRegistryCredential`,
`TestAHostRegistriesConfDoesNotSteerTheEnginesPull` and
`TestTheEngineCarriesItsOwnSignaturePolicy` are the scripted versions. Each
runs its CONTROL first — the same podman, the same planted file, snug's
variable removed — and skips loudly rather than passing when the control does
not fire.

**The cost, stated because it is a capability the sandbox does not have:** no
private image can be pulled from inside, and `podman login` has nothing to
persist to.

### 9j. The container engine holds its own pid namespace (issue #125, C0)

`enginefork.go` clones the engine with `CLONE_NEWPID` and `EnterEngine` mounts
a fresh procfs bound to it — the prerequisite the rest of Tier C's derived
mount view needs (a fresh procfs cannot be mounted at all without a pid
namespace the caller's own userns owns). Three things follow, and each is
worth seeing by hand.

**Needs a real engine** (podman installed and not a host-escape shim — see
`snug doctor`; `$SNUG_PODMAN` to pin one explicitly).

**1. The engine's own pid namespace differs from the host's.**

```bash
snug -p @podman-socket $SC/proj/sub -- sleep 300 &
sleep 2
ENGINE_PID=$(pgrep -f 'podman-[0-9]+\.sock' | head -1)
readlink /proc/$ENGINE_PID/ns/pid
readlink /proc/self/ns/pid
kill %1
```

Expect the two `pid:[...]` inodes to differ. Pre-C0 they were identical (the
engine shared the host's bootstrap namespace); the adjacent negative — that
this same host-visible engine pid still does not resolve inside the
**sandbox's own** pid namespace — is `TestNoAbstractSocketsWithEngineInN`.

**2. Killing the engine ALONE fells its containers.** This is the property
that actually depends on `CLONE_NEWPID` rather than merely asserting it took:
pid 1 of a pid namespace dying collapses the whole namespace, SIGKILLing every
member — which now includes conmon's double-forked grandchild, the
container's own init.

```bash
snug -p @podman-build $SC/proj/sub -- sh -c '
  echo "FROM scratch" > Containerfile
  echo "ENTRYPOINT [\"/bin/sleep\"]" >> Containerfile   # any static sleep works
' # build a throwaway long-running container the way testdata/holder does,
  # or just run TestKillingOnlyTheEngineFellsItsContainers -v for the scripted
  # version — it is easier to get right than a one-off shell snippet, and it
  # is the committed positive control.
go test -tags integration -run TestKillingOnlyTheEngineFellsItsContainers -v ./test/integration/
```

Expect PASS, with the logged control line showing the container's token pids
alive on the host **before** the kill. Read the test's own doc comment for the
measured A/B: pre-C0 the container was still running 10+ seconds after the
engine's SIGKILL; with C0 it is gone within one 250ms poll tick. The test also
asserts snug **itself** stays alive throughout, which is what isolates this
mechanism from `internal/engine/reaper.go`'s own (now redundant, but not
removed) pipe-triggered cleanup — that helper only arms when snug dies, and
this test never kills snug.

**3. conmon's own parent, read from the HOST's procfs, is the engine.**

```bash
go test -tags integration -run TestConmonPPidIsTheEngine -v ./test/integration/
```

Expect PASS. This is the structural fact under both properties above: conmon
(an ordinary fork, no `CLONE_NEWPID` of its own) shares the engine's pid
namespace and is a direct child of it, while the container's own process — one
hop further down, inside crun's nested namespace — is in neither. A future
`--pid=host` decision (issue #145) would need to re-check this exact relation.

### 9k. The engine's run directory is split by writability (issue #125, C2b)

`conf/` holds only files snug generated and the engine reads; `sock/` holds the
one thing the engine creates. Tier C grafts each half into the engine's own
mount namespace **with an access**, so without the split there is no directory
that can be read-only — and the `AccessRO` arm of the graft model would ship
with nothing exercising it.

With a container run live in one terminal, from another:

```bash
ls /tmp/snug-$(id -u)-*/
ls /tmp/snug-$(id -u)-*/conf/ /tmp/snug-$(id -u)-*/sock/
stat -c '%a %U %n' /tmp/snug-$(id -u)-*/conf /tmp/snug-$(id -u)-*/sock
```

Expect exactly `conf` and `sock` at the top and **nothing else** — a generated
file in neither is one the split does not classify, and under Tier C it would be
silently writable inside the engine. `conf/` holds `containers.conf`,
`registries.conf`, `storage.conf`, `auth.json`, `resolv.conf` and `home/`;
`sock/` holds only `podman-<pid>.sock`. Both are `700` and owned by you: they go through
`createRunDir`, not `MkdirAll`, so each gets the same refuse-to-reuse and
ownership checks the parent got — `/tmp` is commonly world-writable and that
reasoning does not weaken one directory down.

Worth reading once while you are here: `auth.json` is deliberately empty, and
`writeAuthFile`'s own comment states the cost — no registry login is possible
from inside. Under Tier C it sits in a read-only graft, so that sentence stops
depending on nobody trying.

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

### 11b. …including when the signal lands during startup

Section 11 kills a sandbox that has been up for two seconds, which is the easy
case: bwrap has long since armed `--die-with-parent` on its own init. Issue #13
is the other one. bwrap arms that late — roughly 40 ms in — and before then,
killing the process snug forked does **not** take the init with it. Measured at
the time: the init survived, reparented to the surrounding container's
subreaper, holding the payload and the network namespace, still writing to the
target *after* snug was gone.

Run it on both topologies. `$TOK` is what makes the survivor findable: an
orphan has been reparented out of snug's tree, so `pgrep -P` cannot see it.

The other half of the evidence is a **write dated after snug's death**, not a
write. The payload rewrites its marker in a loop and the check compares the
marker against a stamp file touched the instant snug is gone. The distinction
is not pedantry: the first version of the automated equivalent asserted the
marker was merely absent, and CI failed it at 280 ms and 300 ms because by then
the payload had legitimately written it *before* the signal landed — a correct
teardown looking exactly like a leak.

**`SIGQUIT` is in the loop, and it is the one to watch.** The guard used to
register `TERM`, `INT` and `HUP` — "what a supervisor sends" — and issue #111
measured what that reasoning cost: `kill -QUIT`, the standard gesture for
dumping a Go program's goroutines, reproduced this bug bit-for-bit in the same
window, on both topologies, while three separate documents said `SIGKILL` was
the only residual. Every catchable signal that could orphan a sandbox is now
caught.

**Do not detect survivors with `grep "$TOK" /proc/*/cmdline`.** The token is in
grep's own argv and the shell expands the glob in the process that becomes
grep, so grep finds itself and every line reports a phantom survivor — a
by-hand check that always looks half-failed is one nobody runs twice
(issue #114). Search in the shell instead, as below.

```bash
for args in "" "-p @net"; do
  for sig in TERM INT HUP QUIT; do
    for off in 0.02 0.05 0.10 0.30; do
      T=$(mktemp -d); TOK=snug13$RANDOM
      ./bin/snug $args "$T" -- /bin/sh -c \
        "while :; do echo x > \"\$SNUG_TARGET/m-$TOK\"; sleep 0.1; done" >/dev/null 2>&1 &
      SNUG=$!
      sleep $off; kill -$sig $SNUG; wait $SNUG 2>/dev/null
      touch "$T/.died"
      sleep 1
      SURV=""
      for f in /proc/[0-9]*/cmdline; do
        c=$(tr '\0' ' ' < "$f" 2>/dev/null) || continue
        case "$c" in *"$TOK"*) p=${f#/proc/}; SURV="$SURV ${p%/cmdline}";; esac
      done
      echo "args='$args' sig=$sig off=${off}s wrote-after-death=$([ "$T/m-$TOK" -nt "$T/.died" ] && echo YES || echo no) survivors=[$SURV]"
      for p in $SURV; do kill -9 "$p" 2>/dev/null; done
      rm -rf "$T"
    done
  done
done
```

Expect `wrote-after-death=no survivors=[]` on every line. Anything else is
issue #13 back: a `YES` means something wrote to the target after snug exited,
and a non-empty `survivors` names the process still holding the sandbox. Kill
only those pids — never `pkill bwrap`, which on a host with Flatpak matches
processes snug never started.

What is **not** in this check, and will not pass it, is stated as a rule rather
than as a list of signal names: every termination that does not run a Go signal
handler. That is `SIGKILL`, which never reaches userspace, and a genuine panic
or runtime throw inside snug itself, which dies on the Go runtime's own crash
path. Nothing else — the handler set covers every orphaning signal that can be
delivered to it, including the fault-named ones (`SEGV`, `BUS`, `FPE`, `ILL`,
`STKFLT`), which are catchable when SENT with `kill(2)` and still crash
normally when they arise from a real fault.

The automated equivalent is `TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox`.
It sweeps **four** measured offsets rather than a fixed step (see
`orphanSweepOffsets` for why those four), across twelve signals and both
topologies, sampling the offset dimension for the nine signals whose delivery
is already asserted per-signal by
`TestTheTeardownGuardCatchesEverySignalItRegisters` in `internal/sandbox`.

### 11c. …and a clean teardown says nothing

A `-p @net` sandbox stopped with Ctrl-C printed *"the network helper exited
(signal: killed); the sandbox now has loopback only"* on **every** run
(issue #112). Nothing had degraded: snug's own teardown sweep killed pasta one
line before it was going to be asked to stop anyway, and the watcher that
reports a pasta crash could not tell the difference. The cost is not the noise
— it is that a notice printed on every ordinary exit is a notice nobody reads
on the exit where pasta really did fail.

```bash
T=$(mktemp -d)
./bin/snug -p @net "$T" -- /bin/sh -c 'echo INSIDE; sleep 60' >o.txt 2>e.txt & S=$!
sleep 1; kill -TERM $S; wait $S; echo "rc=$?"
echo "stdout: $(cat o.txt)"; echo "stderr: [$(cat e.txt)]"
```

Expect `rc=143`, `stdout: INSIDE`, and **`stderr: []`** — empty.

Now the control, because "snug printed nothing" is equally true of a snug that
*cannot* print it. Kill pasta out from under a live run and the notice must
appear.

**Scope the search to snug's own children, and do not skip that.** Two ways a
looser search goes wrong here, both measured on this host. This box runs its
own `/usr/bin/pasta` for the distrobox — signalling that one takes the
machine's networking down and has nothing to do with snug. And a shell loop
matching `*pasta*` across all of `/proc` matches **its own command line**,
which is the self-match that made §11b's old survivor detector useless. snug's
pasta is a direct child of snug, so `PPid == $S` is both the correct filter and
the safe one. Match on `cmdline`, never on `comm`: the binary that runs here
reports `pasta.avx2`.

```bash
T=$(mktemp -d)
./bin/snug -p @net "$T" -- /bin/sh -c 'echo INSIDE; sleep 30' >o.txt 2>e.txt & S=$!
sleep 2
for f in /proc/[0-9]*/cmdline; do
  p=${f#/proc/}; p=${p%/cmdline}
  [ "$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null)" = "$S" ] || continue
  case "$(tr '\0' ' ' < "$f" 2>/dev/null)" in *pasta*) echo "killing snug's pasta: $p"; kill -TERM "$p";; esac
done
sleep 2; cat e.txt
kill -TERM $S 2>/dev/null; wait $S 2>/dev/null
```

Expect one `killing snug's pasta: <pid>` line and then `the network helper
exited … loopback only`. If the first check is silent and this one is too, the
notice has been lost rather than fixed. The automated pair is
`TestASignalledNetSandboxReportsNoFalseDegradation`.

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

### 12b. The C2 gate — a killed snug cannot release a parked container payload (issue #125)

A container run (`-p @podman-socket`/`-p @podman-build`) cannot start the
engine before bwrap has built the sandbox's mount tree, so the payload is
PARKED (`--block-fd`) until the engine is confirmed up, and P0 alone holds
the byte that releases it (`--sync-fd` on the same pipe). Both checks below
use `$SNUG_PODMAN` (trusted outright, never re-resolved through PATH) pointed
at a throwaway stand-in that creates a real listening `unix://` socket at the
path snug's own argv names.

**The delay and the first-response status must be BAKED INTO the script
file, not read from the environment.** `$SNUG_PODMAN` is exec'd with the
EXPLICIT, minimal environment `internal/engine.Engine.Spec` built (PATH,
HOME, XDG_RUNTIME_DIR, `CONTAINERS_*`) — never this shell's own — so a
wrapper that reads `$FAKE_DELAY` at run time silently sees nothing and
behaves as though it were never set. Write a fresh script per scenario
instead. **It must also refuse to run when no `unix://` argument is
present**, rather than binding an empty path: `internal/engine`'s own
teardown (`engine.go`'s `stopLocked`) invokes this SAME binary a second time
with a plain `stop --all --filter …` argv that names no socket at all, and
`socket.bind('')` in Python silently succeeds as an ABSTRACT-namespace
autobind socket — `accept()` on it then blocks forever, and `stopLocked`'s
own `stop.Run()` has no timeout, so a wrapper without this guard hangs the
whole check. This is an artifact of a hand-rolled stand-in speaking a wider
protocol than it means to, not a snug defect — the committed Go binary
(`test/integration/testdata/fakepodman`) refuses the same way, cleanly:
`net.Listen("unix", "")` returns an error rather than an abstract socket.

```bash
fakepodman() {  # fakepodman DELAY STATUS -> writes $1's own wrapper script
  local dir=$1 delay=$2 status=$3
  cat > $dir/podman <<EOF
#!/bin/sh
SOCK=""
for a in "\$@"; do case "\$a" in unix://*) SOCK=\${a#unix://};; esac; done
if [ -z "\$SOCK" ]; then echo "fakepodman: no unix:// argument" >&2; exit 2; fi
sleep $delay
mkdir -p "\$(dirname "\$SOCK")"
exec python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('\$SOCK'); s.listen(5)
while True:
    c, _ = s.accept()
    c.recv(4096)  # read BEFORE writing/closing — see the note above the RST it avoids
    c.sendall(b'HTTP/1.1 $status X\r\n\r\n')
    if '$status' != '200': c.close()
"
EOF
  chmod +x $dir/podman
}
```

**1. SIGKILL of snug while the payload is parked must never run it** —
`TestAKilledSnugCannotReleaseTheParkedPayload`'s own headline, with the fake
engine delayed long enough to guarantee snug dies while still parked:

```bash
FAKE=$(mktemp -d); fakepodman $FAKE 3 200
rm -f $SC/proj/sub/PWNED
SNUG_PODMAN=$FAKE/podman ./bin/snug -p @podman-socket $SC/proj/sub -- \
  /bin/sh -c 'echo pwned > "$SNUG_TARGET/PWNED"' &
SNUGPID=$!
sleep 0.8
STAGE=$(ps -o pid,ppid,comm --ppid $SNUGPID | awk '$3=="exe"{print $1}')
ps -o pid,ppid,comm --ppid $STAGE           # expect a bwrap below the stage: PRECONDITION
kill -9 $SNUGPID; sleep 2
ls $SC/proj/sub/PWNED                       # expect: No such file or directory
```

Expect the marker absent. Run it several times — this is a race, and the
committed test runs it five times per CLAUDE.md's own discipline for exactly
that reason. The POSITIVE CONTROL and the ADJACENT NEGATIVE (an ordinary,
released run's payload holds no descriptor beyond stdio — the leak an
arbitrary extra fd would have caused instead of `--sync-fd`) are not
practical to reproduce by hand with the same rigor as the committed test's
own `ls -l /proc/self/fd/` check; read that test rather than re-deriving it.

**2. The one-shot property** — the stage answers at most one `netready` and
one `start`, and a second request sent after `start` is never consumed, not
even ignored-and-answered. There is no pathname socket to reach the control
channel from outside snug's own process, so this one is not meaningfully
hand-checkable; `TestTheStageReadsNoRequestAfterStart`
(`internal/stage/onerequest_test.go`) drives it directly against the
unexported control socket from within the package.

**3. An abort while parked must kill bwrap AND the init** — while parked,
bwrap has not yet armed `--die-with-parent` on its own init (measured), so an
abort that kills only the outer bwrap and trusts the kernel's own cascade
leaves the init alive, still parked, still releasable. Point the fake engine
at an immediate non-200 response, which fails `OnEngineReady` (the lifeline
dial) right after the payload is confirmed parked. Backgrounded with a
timeout, per the pattern above and section 12's own checks — the container
engine's own teardown (`eng.Stop()`) runs `podman stop` against this same
stand-in on the ordinary path too, so this waits it out rather than assuming
a bare foreground call returns promptly:

```bash
FAKE=$(mktemp -d); fakepodman $FAKE 0 503
rm -f $SC/proj/sub/PWNED
SNUG_PODMAN=$FAKE/podman ./bin/snug -p @podman-socket $SC/proj/sub -- \
  /bin/sh -c 'echo pwned > "$SNUG_TARGET/PWNED"' > /tmp/gate3.log 2>&1 &
SNUGPID=$!
for i in $(seq 1 100); do kill -0 $SNUGPID 2>/dev/null || break; sleep 0.1; done
kill -0 $SNUGPID 2>/dev/null && { echo "STILL RUNNING after 10s"; kill -9 $SNUGPID; }
wait $SNUGPID 2>/dev/null; echo "exit: $?"
ls $SC/proj/sub/PWNED                       # expect: No such file or directory
pgrep -a bwrap                              # expect: nothing of this run
tail -3 /tmp/gate3.log
```

Expect a nonzero exit, the tail saying the engine "would not accept the
keepalive" stream, no
marker, and no surviving `bwrap` process. `TestKillingOnlyBwrapLeavesAReleasableInit`
is the automated form, and it is confirmed to catch the regression: with the
explicit pidfd kill removed from `internal/stage/gate.go`'s `parked.kill()`,
the outer bwrap dies (from the ordinary abort path) but its own forked init
is left running, still parked — the exact shape the fix in `gate.go` exists
to close.

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
ro = ["{home}/bin/gh_X.Y.Z_linux_amd64/bin/gh:/snug/bin/gh"]
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
every account and every profile — pinned identity or none at all — until it
was measured:

```bash
./bin/snug $SC/proj/sub -- sh -c 'ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED'
```

Expect `SSH-OK`, with **no profile and no pinned identity** — snug replaces
the host's system-wide `ssh_config` on every run whose deepest covering grant
supplies one, not only on an identity run. `--dry-run` shows why: an `SSH`
block, and a `data /usr/etc/ssh/ssh_config … (snug)+replaces:@sys` row in
FILESYSTEM (`@sys`'s `/usr` bind is what would otherwise deliver the host's
root-owned copy).

```bash
./bin/snug -p acct-a $SC/proj/sub -- sh -c '
  ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
  stat -c "owner=%u" /usr/etc/ssh/ssh_config; id -u'
```

Expect `SSH-OK` here too, and `owner=1000` (your uid) either way — the file's
owner and content do not depend on whether an identity is pinned. `--dry-run`
shows the SAME provenance, `(snug)+replaces:@sys`, on both runs; it never
reads `identity:acct-a`, because nothing about the bytes names an account.

The by-hand control that proves the refusal mechanism is still live — i.e.
that snug is not merely getting lucky, ssh really does reject a root-owned
config it did not author — is to point ssh at the drop-in snug's replacement
skips:

```bash
./bin/snug $SC/proj/sub -- ssh -F /usr/etc/ssh/ssh_config.d/50-suse.conf -G github.com
# Bad owner or permissions on <whichever root-owned file this drop-in Includes;
# on openSUSE that is /etc/crypto-policies/back-ends/openssh.config, itself
# root-owned and reachable through @sys's separate /etc/crypto-policies grant>
```

Still refused, and the exact path in the message is host-specific (whatever
this drop-in's own `Include` chain names) — the point is that it is STILL a
refusal. snug replaces the top-level `ssh_config`, not the whole `Include`d
chain (deliberately: every file an `Include` would pull in is root-owned too,
so no replacement of the drop-in is attempted; see
`policy.SystemSSHConfig`'s doc comment). That refusal, still reachable on
demand, is what shows `SSH-OK` above is the replacement working rather than
the ownership check having quietly stopped applying.

What it costs, and say it out loud: the host's system-wide ssh defaults — on
this host openSUSE's crypto-policy include — do not apply inside, on every
run this fires on, not only identity runs. Concretely, `RequiredRSASize`
drops from the host's `2048` to OpenSSH's compiled-in `1024`:

```bash
./bin/snug $SC/proj/sub -- ssh -G github.com | grep requiredrsasize
# requiredrsasize 1024
```

### 13c. The runtime directory: a planted symlink is refused, and a stale one is swept

The ssh-agent proxy's socket (and the podman proxy's) lives under
`$XDG_RUNTIME_DIR/snug/run-<pid>/`, and issue #61 part (c) is about what
protects that path before snug ever gets there: something that got to
`$XDG_RUNTIME_DIR` first could plant a symlink at the `snug` name and
redirect every socket into a directory it controls. Needs a pinned identity
to exercise (a plain default run never calls `runtimeDir`), so this reuses
the throwaway agent from §13's own key.

```bash
export XDG_RUNTIME_DIR=$(mktemp -d)
ln -s /tmp "$XDG_RUNTIME_DIR/snug"          # the attack: plant it first
./bin/snug -p acct-a $SC/proj/sub -- echo MARKER
```

Expect a refusal naming the symlink, exit non-zero, and no `MARKER` on
screen — the guard fires before the sandbox exists, not after:

```
snug: runtime directory: refusing …/snug: it is a symlink — something on
this host planted it before snug got here; remove it by hand and re-run snug
```

Remove the trap and the identical command must now succeed:

```bash
rm "$XDG_RUNTIME_DIR/snug"
./bin/snug -p acct-a $SC/proj/sub -- echo MARKER
# MARKER
```

Issue #85 is what happens on the way OUT, or rather does not: `SIGKILL`
cannot be caught, so a killed run's `run-<pid>` directory survives, and the
next unrelated run sweeps it on its way in.

```bash
export XDG_RUNTIME_DIR=$(mktemp -d)
./bin/snug -p acct-a $SC/proj/sub -- sleep 30 &
sleep 1
dead=$(ls "$XDG_RUNTIME_DIR"/snug)
kill -9 %1; wait
ls "$XDG_RUNTIME_DIR/snug/$dead"            # still there: SIGKILL cannot clean up
./bin/snug -p acct-a $SC/proj/sub -- true    # an unrelated later run
ls "$XDG_RUNTIME_DIR/snug" | grep -q "$dead" && echo "STILL THERE: bug" || echo "swept: ok"
```

Expect `swept: ok`. A concurrently live run's directory must NOT be swept —
without checking that half, "the stale one is gone" also passes on a sweep
that deletes everything it finds:

```bash
export XDG_RUNTIME_DIR=$(mktemp -d)
./bin/snug -p acct-a $SC/proj/sub -- sleep 30 &
sleep 1
live=$(ls "$XDG_RUNTIME_DIR"/snug)
./bin/snug -p acct-a $SC/proj/sub -- true    # a second run, sweeps nothing here
ls "$XDG_RUNTIME_DIR/snug" | grep -q "$live" && echo "still alive: ok" || echo "REMOVED A LIVE RUN: bug"
kill -9 %1; wait
```

Expect `still alive: ok`.

---

## 14. `snug attach` — a second shell in the *same* sandbox, equally confined

`snug attach [dir]` joins a live run by its **target directory** (bare `attach`
uses the current directory). It **gates nothing**: any same-uid host process can
join these namespaces anyway, measured five ways on both topologies, and the help
text says so. Its value is therefore not a permission but that it enters
*confined* — the run's own seccomp filter, an empty capability set, the run's
environment — where a naive `nsenter` enters with none of them. These checks prove
attach lands in the right sandbox **and** arrives confined.

The sub-checks run in order and share `$T` (the target) and `$SNUG` (the run's
pid) from 14a. Start there.

### 14a. It lands in the SAME sandbox — the decisive check, the private tmpfs

```bash
T=$(mktemp -d)
./bin/snug "$T" -- /bin/sh -c 'echo proof-$$ > /tmp/attach-proof; while :; do sleep 1; done' &
SNUG=$!
sleep 2
./bin/snug attach "$T" -- /bin/sh -c 'cat /tmp/attach-proof'      # prints proof-<pid>
```

Expect the same bytes the run wrote. `/tmp` is the sandbox's **private tmpfs**; a
marker written *after* it started can only be read by a process in its mount
namespace. A fresh, unrelated `snug` has an empty `/tmp` — so this is what
distinguishes "the same sandbox" from "a sandbox that looks like it".

### 14b. The namespaces are literally the same

```bash
echo "run:";    ./bin/snug attach "$T" -- /bin/sh -c 'readlink /proc/1/ns/{mnt,net,pid,user,ipc,uts}'
echo "attach:"; ./bin/snug attach "$T" -- /bin/sh -c 'readlink /proc/self/ns/{mnt,net,pid,user,ipc,uts}'
```

The inode numbers match. attach joins by these exact inodes and **refuses on any
mismatch**, so equality is enforced by construction — this is how you see it for
yourself. (`/proc/1` inside is bwrap's own init; the attached process shares its
pid namespace, so `pid` matches too.)

### 14c. The attached process is confined exactly as the payload

```bash
./bin/snug attach "$T" -- /bin/sh -c 'grep -E "NoNewPrivs|Seccomp:|CapEff|CapBnd" /proc/self/status'
```

Expect `NoNewPrivs: 1`, `Seccomp: 2`, `CapEff: 0000000000000000`,
`CapBnd: 0000000000000000` — identical to the payload's own four lines. A naive
`nsenter` would show `Seccomp: 0` and a full `CapBnd` (`000001ffffffffff`). That
difference is the entire feature.

### 14d. The installed filter is real — behaviour, not a flag

```bash
./bin/snug attach "$T" -- /bin/sh -c 'unshare -U true 2>&1 || echo "userns refused: ok"'
```

Expect the refusal. `--seccomp` has been "passed, accepted, and never installed"
before (bwrap stops parsing at `--`), so this asserts the filter *does something*,
not that a flag was present.

### 14e. The environment is the run's, not the host's

```bash
SECRET=leak-me ./bin/snug attach "$T" -- /bin/sh -c 'echo "SECRET=${SECRET:-not-present}"'
```

Expect `SECRET=not-present`. A host variable in attach's *own* environment must
not reach `/proc/<pid>/environ` inside the sandbox's pid namespace — the same PID-1
leak that once handed a payload 106 host variables, asked here of the attach path.

### 14f. Teardown — the pid namespace is the leash

```bash
./bin/snug attach "$T" -- /bin/sh -c 'while :; do sleep 1; done' &
ATT=$!
sleep 1
kill -9 $SNUG                                    # kill the ORIGINAL run
sleep 1
kill -0 $ATT 2>/dev/null && echo "BUG: attach outlived the sandbox" || echo "attach died with the sandbox: ok"
rm -rf "$T"
```

Expect `attach died with the sandbox: ok`. Killing the run collapses the pid
namespace, which SIGKILLs the payload and the attached command; the attach client
then has nothing left to relay and exits. Nothing is left behind — attach adds no
new orphan class. (Conversely, SIGKILLing the *attach client* leaves the run
untouched; the client's bridge child carries `PR_SET_PDEATHSIG`.)

### 14g. The refusals

```bash
./bin/snug attach /tmp/no-run-here 2>&1 || echo "refused: ok"
```

Expect `no live snug run found for /tmp/no-run-here — nothing is currently
sandboxing this directory`. A stale `state.json` whose owning process is gone is
not a match: the run directory's advisory lock must be *held* for the run to be
attachable. Note the current build addresses runs **only** by target directory —
two live runs on the *same* directory are reported as an ambiguity it cannot yet
resolve; whether a second run on one directory should be refused at launch instead
is an open decision, not a check to write against today's behaviour.

### 14h. Interactive attach gives a working job-control shell

Every check above drives attach non-interactively (`/bin/sh -c '...'`, stdin
redirected) — none of them exercise the pty/job-control path at all. This one
does, from a real terminal:

```bash
T=$(mktemp -d)
./bin/snug "$T" -- /bin/sh -c 'while :; do sleep 1; done' &
SNUG=$!
sleep 1
./bin/snug attach "$T"
```

Expect an interactive shell prompt with **no** `cannot set terminal process
group (-1): Inappropriate ioctl for device` or `no job control in this shell`
message on entry, and ordinary job control working: `sleep 100 &`, `fg`,
`Ctrl-Z`, `bg`, `jobs`. This is the by-hand equivalent of
`TestAttachPTYGivesJobControl`: the pty allocated for the session becomes its
controlling terminal (`setsid()` + `ioctl(TIOCSCTTY)` in
`internal/attach/child.go`), which is what job control needs. Exit the shell,
then:

```bash
kill -9 $SNUG; rm -rf "$T"
```

**Known limitation — a SIGKILLed attach client leaves your terminal raw.**
`restoreTerminal` (`internal/cli/attachstdio.go`) is `defer`red immediately
after the pty is set up, so it runs on every *catchable* exit from `snug
attach` — a normal return, the attached command dying, an early error — and
puts the client's terminal termios back exactly as it found it. `SIGKILL` is
not catchable, so the one path that cannot run it is `snug attach` itself
being killed with `-9` mid-session:

```bash
T=$(mktemp -d)
./bin/snug "$T" -- /bin/sh -c 'while :; do sleep 1; done' &
SNUG=$!
sleep 1
./bin/snug attach "$T" &
ATTACH=$!
sleep 1
kill -9 $ATTACH
```

Expect the shell you ran this from to now echo nothing you type and show no
line editing — it is stuck in raw mode. This is a terminal-ergonomics gap,
not a confinement one: the sandbox and its payload are entirely unaffected
(they are torn down by the run's own `PR_SET_PDEATHSIG` machinery, not by
this). Recover with:

```bash
reset            # or: stty sane
kill -9 $SNUG; rm -rf "$T"
```


## 15. snug never writes its generated files onto the host

Issue #186. A writable grant covering a path snug GENERATES into used to turn
snug's own setup into a host overwrite: bwrap's `--file` copies onto its
destination, so `settings.json`, the staged `.credentials.json` and the injected
`CLAUDE.md` landed on the host's copies and destroyed them. No payload acted and
no grant was exceeded — snug did the writing, on the way in.

Use a throwaway `HOME`. That is not politeness; the run this check reproduces
happened against a real one.

```console
$ h=$(mktemp -d)/u && mkdir -p "$h/.ssh"
$ echo "HOST-ORIGINAL" > "$h/.ssh/known_hosts"
$ cfg=$(mktemp -d) && mkdir -p "$cfg/snug/profiles.d"
$ cat > "$cfg/snug/profiles.d/sshrw.toml" <<'EOF'
[profile.sshrw]
description = "rw over the directory snug generates into"
rw = ["{home}/.ssh"]
EOF
$ cat > "$cfg/snug/profiles.d/pinned.toml" <<'EOF'
[profile.pinned]
description = "an identity, so the ssh files are generated"
[profile.pinned.identity]
ssh_mode = "agent-proxy"
ssh_key = "/path/to/some/id_ed25519.pub"
EOF
$ HOME=$h XDG_CONFIG_HOME=$cfg snug -p pinned -p sshrw /tmp/some-target -- true
snug: profile sshrw grants rw on .../.ssh (the host's .../.ssh), and snug generates
      .../.ssh/known_hosts inside it.
       snug writes generated content with bwrap's --file, which COPIES onto its destination,
       so this policy would overwrite .../.ssh/known_hosts on the HOST — outside the sandbox,
       with no undo.
       ...
       Fix: drop the rw grant on .../.ssh, or deselect pinned, which generates at ...
$ cat "$h/.ssh/known_hosts"
HOST-ORIGINAL
```

What to check:

1. The run is **refused**, exit non-zero, before anything starts.
2. The host's file is **byte-identical** afterwards.
3. The refusal names **both** grants — the `rw` one and the profile that
   generates there — because snug cannot know which one you meant. It is a
   refusal rather than a demotion: silently downgrading the grant to `ro` would
   be a restriction operation, and invariant 1 does not have one.
4. Drop `-p sshrw` and the same command runs, generating `~/.ssh/config` and
   `known_hosts` **inside**, with the host's copies still untouched.

## 16. What can this run destroy? — the check before a red-team payload

Issues #185 and #186. The obvious form of this check asks *am I inside a
sandbox?*. It was built, and deleted, because the measurement killed it:

```console
$ snug "$t" -p sshrw -- sh -c './inside-snug; echo "guard says: exit=$?"
    echo PWNED-FROM-INSIDE > "$HOME/.ssh/id_ed25519"'
guard says: exit=0                      <- true: a real snug sandbox
$ cat "$FAKE/.ssh/id_ed25519"
PWNED-FROM-INSIDE                       <- the host's private key, one command later
```

The verdict was true and useless. **"Inside" is not a safety property; the mount
policy is.** A sandbox granting `rw` on `{home}/.ssh` is inside and lethal.

`bin/blast-radius` asks the other question — *is anything worth losing reachable
from here* — and reads nothing snug produces, so it holds when snug is broken,
half-built, or being actively attacked.

```console
$ bin/blast-radius                       # on the host, where the assets are
blast-radius: REACHABLE FROM HERE — /home/you/.gnupg (WRITABLE — this run can destroy it)
[exit 1]

$ HOME=$(mktemp -d) bin/blast-radius -v  # the sanctioned way to work
blast-radius: ok — the host canary is not visible
blast-radius: ok — no key material, cloud credential or token store is visible
blast-radius: ok — no host Claude credential is visible
blast-radius: ok — the transcript archive and hook scripts are not writable from here
[exit 0]

$ snug . -- sh -c 'blast-radius; echo exit=$?'          # an ordinary sandbox
exit=0

$ snug "$t" -p sshrw -- sh -c 'blast-radius; echo exit=$?'   # the lethal policy
blast-radius: REACHABLE FROM HERE — .../.ssh/id_ed25519 (WRITABLE — this run can destroy it)
exit=1
```

What to check:

1. It **refuses on the host** and **passes with a scratch `HOME`** — the second
   is the workflow `redteam` is required to use, so a guard that refused there
   would be one somebody deletes.
2. It **refuses inside a real sandbox whose policy reaches a host asset**. That
   is the case its predecessor passed, and the reason this file's §16 was
   rewritten.
3. It passes inside an ordinary sandbox, where `$HOME` is a fresh tmpfs.
4. Use it in the same invocation as the payload:
   `snug <dir> -- sh -c 'blast-radius && <the destructive thing>'`.

The structural version beats the check: **pin `HOME` to a scratch directory for
any run that creates a sandbox**, and a wrong grant, a snug bug and a wrong shell
all land in a throwaway directory. `bin/blast-radius --install-canary` marks the
real home so the guard can recognise it.

Only `redteam` carries this rule. Every other agent works on the host as its
ordinary mode and is right to.

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
