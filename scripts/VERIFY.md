# Verifying snug by hand

A sandbox you have not personally tried to break is a sandbox you are trusting
on someone's word. This is the checklist for not doing that.

Every command below was run on the development host and produced the output
shown. If yours differs, that is a finding — see [If a check fails](#if-a-check-fails).

**What is left here is what nothing runs.** The rest of this checklist became Go
tests, the numbered scripts in [this directory](./) and
`scripts/payloads/`; the claim that earned the prose its exemption from the
no-`docs/` rule — every line is a command with its expected output — was the
claim nothing enforced, and a command plus the output it produced once is a copy
of state, stale the moment the code moves. Deleting a section the moment a test
asserts it is what stops that from recurring.

- **Every new check is a script in [this directory](./) or a Go test in
  `test/integration`. Never a new section here.** A check CI can run on every
  push belongs in Go; what belongs here is what CI cannot run, because the
  answer is per-machine or it needs state CI structurally lacks.
- **A section is migrated when it is touched, never edited in place**, and
  migrated means DELETED from here in the same change — into a script, into a Go
  test, or into nothing at all because a Go test already asserts it.
  [`README.md`](README.md) beside this file is the index.
- A section that survives says, in its first paragraph, which tests cover the
  rest of its subject and which claim of its own has no owner. A section that
  cannot write that sentence does not belong here.

Run the executable half with `make verify` and `make integration`.

**Every command in this file is run from the repository root**, not from this
directory — `make build`, `./bin/snug`, `scripts/payloads/pid-nesting.py`. The
file moved; the working directory it assumes did not.

What it checks is that **the sandbox holds**, which is not the same question as
whether your profiles are safe. snug does not second-guess a profile: `rw
["{home}"]` and `environ.set EDITOR = "/tmp/evil"` are holes you opened, they are
on screen in `--dry-run`, and no check below will fail on them. See
[`.claude/design/INDEX.md`](../.claude/design/INDEX.md) §1.4 and the README's *What
snug does not defends against*.

Setup used throughout:

```bash
cd /path/to/snug
make build

SC=$(mktemp -d)
mkdir -p $SC/proj/sub $SC/proj/sibling $SC/other
echo secret > $SC/other/CANARY
echo top    > $SC/CANARY-TOP

X=$(mktemp -d)        # a throwaway $XDG_CONFIG_HOME for profiles written below
```

`$SC/proj/sub` is the sandbox target. `$SC/proj/sibling` sits beside it,
`$SC/other` is one level above, and `$SC/CANARY-TOP` is two. `$X` is where a
check that needs its own profile writes one — never the repository under test,
which is invariant 3.

---

## 0. The gate

```bash
make gate        # gofmt, go vet, go test ./...
```

Expect: all packages `ok`. These tests need no privileges and no namespaces —
that is deliberate, so the security-critical parts are checkable anywhere.

## 1. Can this host run it at all

`make verify` runs the numbered checks in [this directory](./), which is where
this question now lives. A check prints what it asserted; a SKIP names the
precondition your host did not meet.

The one arm not migrated, because emptying a live host's `/etc/subuid` is not a
thing to do unattended: to watch the delegated-range ⚠️ say no, and to check
that a ⚠️ leaves the exit code alone,

```bash
sudo cp /etc/subuid /etc/subuid.bak && sudo truncate -s 0 /etc/subuid
./bin/snug doctor; echo "exit=$?"
sudo cp /etc/subuid.bak /etc/subuid
```

Expect `⚠️  no delegated subuid/subgid range — container profiles will refuse
to start`, **`exit=0`**, and a 🔧 line naming a range this namespace can
actually map — not the conventional `100000`, which maps nothing inside a
keep-id box because the uid_map ends at 65535.

## 2. Read before you run

```bash
./bin/snug --dry-run $SC/proj/sub
```

This starts nothing. Read the `FILESYSTEM` block: **every line is a grant, and
the sandbox is the sum of exactly those lines.** Then check the rest of this
document against what it claimed. If `--dry-run` and reality ever disagree, that
is the most serious class of bug in this project, because every other guarantee
is read off this output.

### 2c. `--explain` says what the sandbox is NOT (issue #541)

Every sentence below is pinned by `internal/cli/visible_test.go`, and
`TestExplainInvertsEverySentenceWhenTheCapabilityIsGranted` asserts each one
flips when a profile grants the thing it denies. Read it once anyway — it is the
product, and a reader who has not seen it does not know what they have.

`--dry-run` renders what IS. On a deny-by-default model the absences leave no
row anywhere, so a human cannot derive them by reading the grants — and the
absences are the product. `--explain` states them, in prose, and starts nothing:

```bash
./bin/snug --explain $SC/proj/sub | sed -n '/WHAT IS NOT IN HERE/,/dies with the sandbox/p'
```

Measured:

```
WHAT IS NOT IN HERE
  No X11 and no Wayland: a GUI program will not open a window, and nothing
  inside can read your screen or your keystrokes.
  No D-Bus, session or system. No host abstract sockets of any kind.
  No host loopback. A service you are running on 127.0.0.1 is unreachable
  from inside, under every profile, including the networked ones.
  No ~/.ssh. Your private keys are not in this filesystem at all.
  No root, no setuid, and no process snug did not start — everything here
  dies with the sandbox.
```

`/dev/shm` is writable because POSIX shared memory needs it, and it is contained
on a private tmpfs sized by `tmpfs_size`. Confirm both halves yourself
rather than believing it:

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c 'echo pwned > /dev/shm/ESCAPE_PROBE'
ls /dev/shm/ESCAPE_PROBE                                     # host: No such file
./bin/snug $SC/proj/sub -- /bin/sh -c 'ls /dev/shm/ESCAPE_PROBE'   # next run: gone
```

Both report the file missing — the write never reached the host, and it did not
survive the sandbox.

## 4. What must be absent

```bash
./bin/snug $SC/proj/sub -- /bin/sh -c "
ls $SC/CANARY-TOP ; ls $SC/other ; ls ~/.ssh ; ls /sys"
```

Expect four × `No such file or directory`. Note the wording: these paths are
**absent**, not permission-denied. They were never mounted, so there is nothing
there to deny access to. `TestUngrantedPathsAreAbsent` asserts this set; what no
test can enumerate is YOUR set.

Try the same for anything else you care about — `~/.gnupg`, `~/.aws`,
`~/.config/gh`, your other projects.

### 4b. A grant whose source is a SOCKET or a FIFO is refused (issues #219, #287)

A socket and a FIFO are the third and fourth nouns, after the file a tool reads
and the config file a tool INTERPRETS, and `ro` restrains neither of them: the
kernel clears `MAY_WRITE` for a socket, a FIFO and a device node before it ever
consults the read-only bit, so read-only stops the sandbox *replacing* the node
and does nothing about *speaking through* it. The private netns does not help
either — a unix socket is filesystem, not network. Measured in #219: from a
sandbox holding a read-only bind of a home directory, a payload enumerated the
host's ssh-agent and signed with it, having simply re-derived the path
`--clearenv` had stripped. Measured in #287: a payload **wrote** through a FIFO
mounted read-only and a host process on the other end received the bytes,
while `touch` on a regular file in the same read-only bind got `EROFS` in the
same run.

```bash
D=$(mktemp -d)
python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" $D/agent.sock
mkfifo $D/pipe
: > $D/a-file; mkdir $D/a-dir
mkdir -p $X/snug/profiles.d
printf '[profile.binder]\ndescription = "one bind"\nro = ["%s:{home}/mounted"]\n' \
  $D/pipe > $X/snug/profiles.d/b.toml
XDG_CONFIG_HOME=$X ./bin/snug --dry-run -p binder $SC/proj/sub; echo "exit=$?"
```

Expect a refusal, on `--dry-run` and not only at launch, naming what to select
instead **and** what the check does not cover:

```
snug: profile binder binds /home/<you>/mounted, whose source is a FIFO (a named pipe).
       Read-only does not restrain an endpoint. `ro` stops the sandbox REPLACING the
       node and does nothing about SPEAKING THROUGH it: the kernel clears MAY_WRITE
       for a socket, a FIFO and a device node before it ever consults the read-only
       bit, so MNT_READONLY guards the filesystem, not the process on the other end.
       Measured on a read-only bind: a payload wrote through a FIFO and a host process
       received the bytes, while `touch` on a regular file in the same bind got EROFS
       (issue #287). A socket got the host's ssh-agent enumerated and used for a
       signature through exactly this shape (issue #219). The private network
       namespace does not help either — a unix socket is filesystem, not network.
       If you want the sandbox to sign with ONE key, do not mount an agent socket.
       Put an identity block in your own profile and select it with -p:
           [profile.work.identity]
           key   = "{home}/.ssh/id_ed25519.pub"   # the PUBLIC half
           agent = "proxy"
       snug then runs a proxy that offers that one key, enumerates nothing, and needs
       no mount. If you want a container engine, select '@podman-socket', whose
       socket is a filtering proxy rather than the engine itself.
       NOTE THE LIMIT of this refusal: it sees the node a grant NAMES, and only if it
       exists now. Granting a DIRECTORY still grants every socket and every FIFO
       anyone puts in it later, and nothing checks that — it is how issue #287 was
       measured, through @parent-ro alone.
exit=77
```

Point `ro` at `$D/agent.sock` instead of `$D/pipe` and the SAME message comes
back with one word changed — `whose source is a unix SOCKET.` — which is the
whole point: one predicate, two nouns, issue #289's fix (naming a real `identity`
block instead of the nonexistent `@ssh-agent` profile) reads identically for
both.

**The positive controls are the same profile with a different source.** Point
`ro` at `$D/a-file` and then at `$D/a-dir`: both must resolve cleanly. Without
them, "the endpoint was refused" is equally true of a check that refuses that
path whatever is at it — and the refusal is detected by `stat` (`S_IFSOCK` /
`S_IFIFO`), never by matching path text, which is what stops it being the
catalogue shape #207 deleted.

**THE LIMIT, and it is half the rule — for BOTH nouns.** Bind the DIRECTORY
holding that socket and that FIFO instead:

```bash
printf '[profile.binder]\ndescription = "one bind"\nro = ["%s:{home}/mounted"]\n' \
  $D > $X/snug/profiles.d/b.toml
XDG_CONFIG_HOME=$X ./bin/snug --dry-run -p binder $SC/proj/sub; echo "exit=$?"
```

Expect **exit=0**. A `stat` at resolve time sees only endpoints that exist
then, and a grant of a directory is a grant of every socket AND every FIFO
anyone puts in it afterwards — the directory case is unchecked for both
nouns, not only for the socket. That case is checked by nothing, it is stated
in the refusal text and in the code, and it is pinned by
`TestABindOfADirectoryHoldingAnEndpointIsStillAccepted` so that closing it
means changing a test that says the old behaviour out loud.

**And the residual is reachable through `@parent-ro` alone**, with no endpoint
grant anywhere — one profile name and nothing else. `$SC/proj` is that
profile's grant (identity-mapped: same absolute path inside as out), so a FIFO
planted there before the sandbox starts is visible inside at the same path.
Since issue #550 it takes the `-p`, which is the change in this check and not a
change in the residual:

```bash
mkfifo $SC/proj/escape.fifo
cat $SC/proj/escape.fifo &        # the host reader, holding it open
./bin/snug -p @parent-ro $SC/proj/sub -- /bin/sh -c \
  "mkfifo $SC/proj/newfifo 2>&1; printf hi > $SC/proj/escape.fifo"
wait
```

Expect the `mkfifo` half to fail with `Read-only file system` — measured:

```
mkfifo: cannot create fifo '/tmp/tmp.xxxxxxxxxx/proj/newfifo': Read-only file system
```

— and the `printf` half to complete silently, with `hi` landing on the
backgrounded host `cat` reading `$SC/proj/escape.fifo`, because `@parent-ro`
grants that directory read-only and the FIFO planted inside it existed before
the sandbox started. This is `TestAFifoInAGrantedDirectoryStillReachesTheHost`
(`test/integration`), and it is the reason this section is not the whole
story: the two bounds on the residual are that the payload cannot MANUFACTURE
a fresh endpoint inside a read-only grant (the `mkfifo` failure above), only
speak into one a host process already created and is holding open, and that
there is no mount flag that closes this the way `nodev` closes the device
case — this is a kernel-level residual, not laziness.

snug's OWN sockets are exempt and must be: the ssh-agent proxy (an `identity`
block with `identity.ssh.agent = "proxy"`) and the container proxy are sockets,
and they are the narrower alternatives this refusal exists to stop a mount
from replacing. The exemption is keyed on `Mount.Authored`, which only
`Policy.Replace` sets and nothing a profile can write reaches.

## 6. The environment is rebuilt, not inherited

What the environment IS — the verbs, the bands, the marks, the refusals, the
generated `~/.claude.json`, `settings.json` and credential — is asserted by
`internal/policy`'s environment tests, the `TestGoldenEnvironment` fixtures and
`test/integration/claude*_test.go`. What is left here is what those cannot
reach.

Caveat worth knowing: `--clearenv` is not the last word. `/etc/profile.d/*`
runs inside a login shell and can put variables back. That is why `@sys`
enumerates `/etc` instead of binding it wholesale — see INDEX §5.3.

### 6g-bis. What the `claude` binary does with the regenerated plugin manifest (issue #68)

**The tests assert what snug WRITES, and that is the whole of what this
repository asserts.** What the real `claude` binary DOES with the regenerated
manifest — a plugin absent from it does not fire its `SessionStart` hook, one
present does — was MEASURED on claude 2.1.238 and is recorded in
`.claude/design/CLAUDE-SETTINGS.md`; no test drives it. Observing it needs the
proprietary binary, which no distribution ships, and every other third-party
program this suite runs (`bwrap`, `podman`, `crun`, `git`, `ssh`, `python3`,
`pasta`) is packaged. So the gate on the binary's side carries a version number
and no ratchet: `enabledPlugins` already moved from `~/.claude.json` to
`settings.json` once, and a move like it would not turn anything here red.

### 6n-bis. A credential minted INSIDE one session is unreachable from another

`TestOneSessionsClaudeCredentialIsNotReadableFromAnother` asserts the two
negatives — no canary in session B's filesystem sweep, no reach through
`/proc/<pid>/root` — with a host positive control. What it uses two targets for,
this uses one.

**And the direction this does NOT close**, which matters because the two
sessions then share that target. B cannot read A's credential; B can arrange for
A to hand it over. Measured, three runs on one target with a synthetic
credential: a `@target-rw` run with no credential of its own writes
`.git/hooks/pre-commit` carrying `cp "$HOME/.claude/.credentials.json"
./.stolen-token`; a later `@claude` run does an ordinary `git commit`, git fires
the hook, and the first run reads the second's `accessToken` out of the target.
What bounded that was the credential projection and nothing else — the file the hook
copied carries no `refreshToken`, so what moved expires in hours rather than in
29 days. Use two directories if that is not a trade you want.

## 8b. Disagreements are fatal, and name every claimant in a stable order

Both refusals — the scalar one and the PATH-prepend one — are pinned as golden
refusals (`env_two_sets_disagree`, `env_prepend_order_disagreement`) and
`TestEnvConflictRefusalIsCommutative` requires the bytes to be identical however
the profiles are ordered. What is not in a test is why the refusal quotes each
element separately.

The quoting is load-bearing, not decoration: agreement is over the whole ordered
sequence, and an element may contain a space, so `/opt/a /opt/b` on one line
could be two elements or one. Keying that comparison on a space-join made two
different sequences compare equal and silently deleted one profile's entry —
`["/opt/a" "/opt/b"]` versus `["/opt/a b"]` is the distinction being drawn.

Note both profiles here **grant** what they prepend. Drop either `ro =` line and
the coupling error for an uncoupled `merge` fires first instead.

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

One of the four refusals `TestMaskingByNestedBindIsRejected` pins is a
regression check rather than a rule. `rejectMasking` originally inspected only
tmpfs grants, so a *bind* of an unrelated directory walked straight through it —
`/usr/share/misc` went from three entries to zero, silently. Found by the
`redteam` agent.

## 9a. Every tmpfs snug emits is bounded, not just `/tmp` (issue #281)

The takeover itself — the mark, the wording, the cost of one writable path — is
`internal/cli/yieldedpath_test.go`. What no test counts is how many bounded
tmpfs mounts a default selection emits: it resolves to `@sys @home @target-rw`,
and `[profile.home]` grants five more on top of `/tmp` itself.

```console
$ ./bin/snug --dry-run ~/src/anything | grep -c 'tmpfs .*max '
6
```

## 9c-ter. The engine's view is DERIVED — no host tree in it

`TestTheEnginesViewIsDerivedAndCarriesNoHostTree` reads a live engine's
`/proc/<pid>/mountinfo` and asserts every mount in it is either the sandbox's
own or snug's own addition. The engine's argv agrees, and that half is checked
by nothing:

```bash
./bin/snug -p @podman-socket $SC/proj/sub -- sleep 60 &
ENG=$(pgrep -f 'podman.*system service' | head -1)
tr '\0' ' ' < /proc/$ENG/cmdline; echo
```

Expect `--root /snug/engine/store --runroot /snug/engine/runroot` and a
`unix:///snug/engine/sock/...` socket — GUEST paths. A host path here would be
one the engine cannot resolve.

## 9c-quater. A bind source swapped between create and start is refused AT CREATE (issue #284)

The rule and the TOCTOU it closes are `internal/policy/enginebind_test.go` and
`TestASwappedBindSourceCannotReachTheEngineGrafts`. What those do not show is
the kernel rename semantics the rule is built on, and that is worth seeing once.

Why an intermediate directory is enough to lose the whole chain — an ancestor
of both the `@parent-ro` and the `@target-rw` mount carries them with it when it
is renamed:

```bash
mkdir -p ~/snugtest/x/y/proj/sub
snug ~/snugtest/x/y/proj/sub -- sh -c 'mv "$HOME/snugtest" other && echo RENAME-OK'
```

Expect `RENAME-OK`.

Positive control — a source whose every name IS anchored still mounts:

```bash
snug -p @podman-socket $SC/proj/sub -- sh -c '
  export PATH=/snug/bin:$PATH
  podman create -v /usr:/u:ro alpine:3.20 true
'
```

Expect a container ID. `/usr` is a read-only mount root under a root tmpfs
nothing grants, so no name on its path can be re-pointed. The other half of
the rule, measured — a mount root cannot be renamed from inside:

```bash
mkdir -p ~/snugtest2/sub
snug ~/snugtest2/sub -- sh -c 'cd "$HOME"; mv snugtest2 other'
```

Expect `mv: cannot move 'snugtest2' to 'other': Device or resource busy`.

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

`TestContainerGetsGeneratedResolvConfNotTheHosts` and
`TestContainerResolvConfAgreesWithTheSandboxUnderNet` assert the resolv.conf
halves, offline and under `@net`. The `/etc/hosts` half is asserted only
offline, so the `@net` arm is still a by-hand read:

`cat /etc/hosts` in a container. Expect `localhost` entries and, with
`-p @net`, podman's own `host.containers.internal`/`host.docker.internal` —
and **no** name out of the HOST's `/etc/hosts`. Compare against `cat
/etc/hosts` on the host. Read that result honestly: on the compat API path
podman synthesizes this file rather than copying it, so it was already clean
before `base_hosts_file = "none"` was set; the key is what makes it clean
STRUCTURALLY, on any path and any podman version, rather than by accident of
the schema the proxy happens to allow. The copy WAS measured on podman's CLI
path, which nothing inside a snug sandbox can reach today.

### 9h. The HOST's containers.conf authors nothing in a container (issue #132)

**Two files `CONTAINERS_CONF` does NOT cover** — `registries.conf` (steers
where an image comes from) and `policy.json` (decides whether an image may be
used at all). Both were measured live, filed as #137, and closed the same way:
see `TestTheEngineCarriesItsOwnSignaturePolicy` and
`TestAHostRegistriesConfDoesNotSteerTheEnginesPull`. The channel itself is
still worth seeing, because it is what those prove is shut:

```bash
H=$(mktemp -d); mkdir -p $H/.config/containers
echo 'THIS IS NOT VALID TOML {{{' > $H/.config/containers/registries.conf
env -u CONTAINERS_REGISTRIES_CONF -u XDG_CONFIG_HOME HOME=$H   podman pull alpine:3.20
```

Expect a parse error naming that path — which is the proof it was read.

### 9k. The engine's run directory is split by writability (issue #125, C2b)

The split itself is `TestEngineRunDirSplitsByWritability`. Worth reading once
while you are here: `auth.json` is deliberately empty, and
`writeAuthFile`'s own comment states the cost — no registry login is possible
from inside. Under Tier C it sits in a read-only graft, so that sentence stops
depending on nobody trying.

### 9s. `snug engine gc` sees every generation of store name, and never deletes what another uid owns (issues #349, #308)

`internal/targetkey.Hash` now labels the digest: a store is
`sha256_<64 hex>`, so a later algorithm change is a new prefix rather than a
silent reinterpretation of 64 hex characters. The cost of a rename is that
`engine gc` can stop SEEING what snug itself wrote, which leaves no tool at
all for the accumulation the command exists to reclaim.

```bash
snug engine gc --dry-run | tail -4
```

Both older generations must be counted. On the machine this was written on:

```
1443 store(s), >= 2.8 GB. Nothing selected, nothing removed.
  554 unattributed (target unknown)   >= 946.1 MB   -> --unattributed
  889 attributed                      >= 1.8 GB   -> --older-than <dur>, or name a key
```

The split is the point, not the totals. The 554 are the 16-hex truncation that
predates `store.json` entirely — no breadcrumb exists for them, so snug cannot
say whose they are and `--older-than` must not touch them. The rest carry a
breadcrumb whose target hashes to the LABELLED form of their own bare-hex name,
so they stay ATTRIBUTED across the rename; before that tolerance they all
moved to unattributed at once, which silently made `--older-than` a no-op on
1.8 GB.

A key in no generation at all is refused with the shape it wanted, and the
message is not pinned by any test:

```bash
snug engine gc zzz
```

```
snug: zzz is not shaped like a store key ("sha256_" followed by 64 lowercase
hex characters, or a bare 64-character digest for a store written before that
label) — run `snug engine gc --dry-run` to list valid keys
```

## 10. A repository cannot grant itself anything

That repo-local config is never auto-loaded is
`TestRepoLocalConfigIsNeverAutoLoaded`. This is the hole beside it.

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

Whether anything survives a signal — every catchable one, at every startup
offset, on both topologies — is `test/integration/orphan_test.go` and
`TestNoBwrapSurvivesSIGKILLOnceSettled`. What is left here is the reasoning
those tests encode but do not explain.

### 11c-bis. …and an orphan that outlived its snug is killed by the NEXT run (issue #236)

Section 11b is about the signals snug can catch. `SIGKILL` never reaches
userspace, so nothing snug does at the time can help: the init survives,
reparented, holding a pid, net, user and mount namespace — and inside the wider
part of the window, still running the payload. They accumulate; one development
box had 23, the oldest 12 h old.

The answer is deferred rather than real-time, the same trade issue #85 made for
the run directory: the next `snug` run cleans it up.

Make one on purpose, and it must be the **staged** arm — `-p @net`. On the
offline arm snug's own intermediate pid namespace (`__inpidns`) collapses when
snug is killed and takes the init with it: `SIGKILL` at a fixed offset of 50,
100, 150, 200, 250, 300 and 350 ms produced **0 orphans out of 3 at every
offset**. The staged arm has no such namespace between snug and bwrap, and
there the window is real — 3 of 3 at 150 ms and 3 of 3 at 200 ms, 0 of 3 at
100 ms (nothing to leak yet) and 0 of 3 at 300 ms (`--die-with-parent` is
armed by then). The state file lands inside that window, so waiting for it and
killing immediately afterwards is the reliable way in — **5 attempts out of 5**.
`TestTheNextRunSweepsAnOrphanedSandboxInit` is that recipe as a test.

**Why this cannot reach a live sandbox**, and it is worth checking rather than
believing: start a run in one terminal, run `snug` on a different directory in
another, and the first is untouched — `TestSweepDoesNotKillALiveRunWhoseLockFileWasRemoved`
is that check. Each record names
its own owner, and the sweep acts only where that owner is gone; it consults
no target lock at all, which is what lets it reap a dead run's orphan while a
peer on the SAME target is still live
(`TestTheSweepReapsADeadPeersInitWhileALivePeerHoldsTheTargetLock`). The second
condition is that the
recorded start time still matches `/proc/<pid>/stat` field 22, which is the
pid-reuse guard the record carries a start time for.

### 11c-ter. The init is nameable before bwrap reports it, on both arms (issue #236)

The record snug writes names the init by pid, start time and the namespace it
belongs to. That third column is the identity guard. bwrap itself shares the stage's user
namespace, so "the first child of bwrap in a user namespace that is not ours"
is the init and cannot be bwrap. A record built on a weaker test would name a
process `killOrphanInit` later SIGKILLs.

`TestTheStagedInitIsTheForeignUsernsChildOfItsBwrap` asserts exactly this, so a
future bwrap that changed the shape fails the suite rather than the sweep.

The same pass removes the stale state file, which nothing did before: one was
published per run and removed by nobody, so this box had accumulated 1099 of
them.

One leftover this does **not** reach: an init that never answers `--info-fd`,
parked in `read()` on one of bwrap's **own** eventfds (its uid-map sync). No
record can name it — the pid is the one bwrap has not reported yet. That is
upstream's window. The other one, a **gated** run's parked payload waiting on
snug's `--block-fd` (a **pipe**, which is what tells the two apart from
outside), IS reached now, by the record 11c-ter checks.

## 12. The stage — a `@net` sandbox has a second process ahead of it

What the stage is, what it holds and what dies with it is
`test/integration/stage_test.go` and the `topology.*` goldens. One thing is in
neither.

**The sandbox's netns is not P0's**, and neither side may be trusted if it
reads empty:

```bash
readlink /proc/self/ns/net
./bin/snug -p @net $SC/proj/sub -- /bin/sh -c 'readlink /proc/self/ns/net'
```

Expect two different `net:[…]` ids. (Development host: `net:[4026531833]` vs
`net:[4026532443]`.)

## 13. Two accounts on one host — an identity is a pin, not a preference

The claim: a sandbox pinned to one GitHub account acts as that account through
**both** channels — `gh` and git-over-ssh — and cannot act as the other. Two
sandboxes side by side, two accounts, no crossing.

Nothing new is needed to express it. One `[identity]` block per profile pins the
ssh key, the gh account and the git author together — one sub-block per tool, and
nothing inherited between them. Two profiles are two accounts. Write them
somewhere that is not the repository being sandboxed (invariant 3) —
`~/.config/snug/profiles.d/accounts.toml`:

```toml
[profile.acct-a]
include = ["@sys", "@home", "@target-rw", "@parent-ro", "@net"]
  [profile.acct-a.identity.ssh]
  key   = "{home}/.ssh/ACCOUNT-A.pub"   # the PUBLIC half
  agent = "proxy"
  [profile.acct-a.identity.git]
  name  = "Your Name"
  email = "a@example.com"
  [profile.acct-a.identity.gh]
  user  = "ACCOUNT-A"

[profile.acct-b]
include = ["@sys", "@home", "@target-rw", "@parent-ro", "@net"]
  [profile.acct-b.identity.ssh]
  key   = "{home}/.ssh/ACCOUNT-B.pub"
  agent = "proxy"
  [profile.acct-b.identity.git]
  name  = "Your Name"
  email = "b@example.com"
  [profile.acct-b.identity.gh]
  user  = "ACCOUNT-B"
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

The negative is the half that matters. The two-profile conflict is
`TestIdentityDifferentBlocksStillRefuseNamingBoth`; these two are not asserted
anywhere, because each needs a host condition — a missing key file, and a `gh`
that is not logged in:

```bash
./bin/snug --dry-run -p acct-badkey $SC/proj/sub     # identity.ssh.key names a missing file
# snug: pinned ssh key: open /home/u/.ssh/does-not-exist.pub: no such file or directory

./bin/snug --dry-run -p acct-baduser $SC/proj/sub    # identity.gh.user gh is not logged in to
# snug: no gh token for no-such-account-here on github.com.
```

The second used to be silent — you got a sandbox with no credential, no
`GH_CONFIG_DIR` and nothing on screen, which is invariant 5's "no silent
downgrade" broken in the quietest possible way.


### 13a-2. A signing key is a SECOND pin, and the run refuses without it (issue #453)

`identity.git.signing_key` names the key `gpg.format = ssh` signs commits with. On
a normal setup it is not the key you push with, so it is a second field and a
second pin. It sits under `git` because git is what signs with it, even though the
ssh proxy is what holds the pin.

Add it to `acct-a`'s git block, with a key your agent holds:

```toml
  [profile.acct-a.identity.git]
  signing_key = "{home}/.ssh/id_ed25519_sign.pub"
```

That a commit signed this way verifies against snug's own generated
`allowed_signers`, and that every unprincipled spelling of the email is
refused, is `test/integration/identity_test.go` and
`TestRefuseUnprincipledSigningEmailCatchesEverySpelling`.

**The negative that bounds it.** A commit signed by ANY OTHER key still reads as
untrusted inside, including a colleague's real signature, because the authored
list has one entry. Check it by verifying a commit from a repository you did not
sign:

```bash
./bin/snug -p acct-a $SC/proj/sub -- git verify-commit <a commit signed by someone else>
```

Expect a non-zero exit and `No principal matched`. That is the grant's boundary,
not a gap.

**And one negative that does NOT hold.** The authentication key alone cannot be
used to sign as the signing identity and the reverse — stating that is the
honest half: the
ssh-agent protocol carries no purpose field, so with both keys pinned anything
inside can ask the proxy to use either for either job. The pin bounds which
keys, never what they are used for.


### 13d. The per-target lock and an interrupted state write are swept too

`13c` covers the run directory. The per-TARGET files are elsewhere and were
covered by nothing: one `target-sha256_<hex>.lock` per target ever sandboxed,
kept for the life of the boot, plus `target-sha256_<hex>.<pid>.json.tmp-<pid>`
whenever a SIGKILL interrupts a state write (`writeTargetFile` removes only the
temp name carrying its own pid).

They live in the UID-derived directory and deliberately NOT under
`$XDG_RUNTIME_DIR` (issue #122), so this one counts the real directory rather
than a fixture:

```bash
ls /run/user/$(id -u)/snug | wc -l           # before
./bin/snug $SC/proj/sub -- true
ls /run/user/$(id -u)/snug
```

Expect exactly the current run's own two files, `target-sha256_<hex>.<pid>.json`
(the pid being the `snug` that published it) and `target-sha256_<hex>.lock`, and
nothing else. Measured on one development box
after two days of suite runs: **741 -> 2**, of which 738 were lock files and one
was a `.json.tmp-<pid>`.


## 14. A second session is a second sandbox

There is no way to put a process inside a sandbox that is already running. Run
`snug` again on the same directory and you get another sandbox: its own user,
mount, pid, ipc, uts and net namespaces, its own tmpfs `$HOME`, its own `/tmp`,
its own environment. What the two share is the host-backed writable surface
their profiles grant, and `--dry-run`'s SHARED block enumerates it. That both
runs start, what the SHARED block names and omits, and that one run's sweep
reaps a dead peer's orphan while a live peer holds the target lock are
`TestTwoLiveSandboxesOnOneDirectory`,
`TestDryRunSharedBlockNamesTheSurfaceASecondSandboxWouldMeet` and
`TestTheSweepReapsADeadPeersInitWhileALivePeerHoldsTheTargetLock`. What is left
here is the part no test states.

### 14e. From outside, `nsenter` is still yours

Nothing here is a permission snug grants or withholds. A same-uid host process
can join a running sandbox's namespaces with `nsenter` and always could — the
kernel gates that by uid. What snug no longer does is BUILD that path and hand
it to you as a confined shell, because the leak runs both ways: a process in the
payload's namespaces reads `/proc/<pid>/environ` and `/proc/<pid>/fd` of every
other process there, in both directions, and `PR_SET_DUMPABLE 0` does not
survive `execve`.


## 15. snug never writes its generated files onto the host

Issue #186. A writable grant covering a path snug GENERATES into used to turn
snug's own setup into a host overwrite: bwrap's `--file` copies onto its
destination, so `settings.json`, the staged `.credentials.json` and the injected
`CLAUDE.md` landed on the host's copies and destroyed them. No payload acted and
no grant was exceeded — snug did the writing, on the way in.

The refusal, the host files staying byte-identical and the way forward the
message names are `TestSnugRefusesToWriteItsGeneratedFilesOntoTheHost`. If you
reproduce it by hand, use a throwaway `HOME`. That is not politeness; the run
this check reproduces happened against a real one.

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
half-built, or being actively attacked. Its three verdicts — on the real home,
on a scratch home, and inside a sandbox whose policy reaches a host asset — are
`test/guard/blastradius_test.go` and `test/integration/blastradius_test.go`.

The structural version beats the check: **pin `HOME` to a scratch directory for
any run that creates a sandbox**, and a wrong grant, a snug bug and a wrong shell
all land in a throwaway directory. `bin/blast-radius --install-canary` marks the
real home so the guard can recognise it.

Only `redteam` carries this rule. Every other agent works on the host as its
ordinary mode and is right to.

## 17. The engine binary a payload can NAME, not only the bytes it can write

Issue #369, row 6's confirmed finding. `CheckEngineBinary` asks *can the payload
write these bytes*, and canonicalisation answers that correctly — which is why
the regular-file case always worked. What canonicalisation destroys is the
ability to ask *did the payload CHOOSE these bytes*, and for a symlink the two
questions have different answers. Measured before the fix: a payload-writable
`$TARGET/podman -> /usr/bin/true` was accepted and exec'd as this run's engine,
failing 30s later at the socket timeout, while a regular file at the same path
was refused.

Use a throwaway `HOME` that is **not** under the target's parent, or `@parent-ro`
refuses first for an unrelated reason (§ the `$HOME`-ancestor refusal).

**Not covered here, and it is the sharper of the two doors.** The same
predicate guards `$SNUG_PODMAN_ROOT`, so a toolchain root named through a
payload-writable symlink is refused too — but a by-hand attempt at it hits the
engine-binary arm first whenever the binary itself sits inside the writable
tree, which is the obvious way to build the case. Isolating it needs a clean
binary outside every grant with only the ROOT named through the writable
symlink; the unit tests do that (`TestEngineToolchainJudgesTheNameNotOnlyTheTarget`)
and a round is owed on the door itself, which was **derived by reading and never
measured**.

## 18. The `--dry-run` screen judges the same string the run does (issue #422)

Section 17's own "not covered here" paragraph named the sibling door and left
it unmeasured: `$SNUG_PODMAN_ROOT` named through a payload-writable symlink
that resolves into the writable target. The gap it turned out to have was not
in the run — `EngineToolchain` already resolved before judging — it was in the
**screen**: `buildContainersReport` called `CheckEngineToolchainTree` on the
raw, unresolved spelling, which a symlink outside every grant defeats
lexically. Confirmed against `origin/main` (5ca7627) before the fix, alongside
this branch. `TestDryRunExitsZeroWithARefusingToolchainRoot` is that control
now, and `TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot` pins
the refusal naming the RESOLVED root.

**What this cannot isolate by hand, for the reason section 17 already gives
for the sibling door.** `EngineToolchain` was never the bug — it already
resolved before judging, on `origin/main` too — so a real (non-`--dry-run`)
run refuses either way, and by-hand it refuses via `preflightToolchainRoot`'s
earlier "root must contain the resolved engine binary" gate rather than via
the writability check this section is about, on both binaries: the same
structural obstacle as section 17, one door over. The unit test
(`TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot`,
`internal/cli`) calls `EngineToolchain` directly, bypassing that earlier gate,
and is where the run-vs-screen equivalence for this exact refusal is actually
proven.

## 19. The engine tier really runs, on a machine that is not this one (issue #395)

Every CI job before this one ran on `ubuntu-latest`, which has no engine snug
will accept, so all the engine tests SKIPped and the suite was green having
measured nothing. This section is the by-hand half: it runs the same container
the `engine` job runs, on your own machine.

```console
$ make integration-engine
```

Needs `docker` or `podman` and a host where
`kernel.apparmor_restrict_unprivileged_userns` is 0 — the script refuses in one
second, naming the sysctl, rather than letting bwrap fail twenty tests later. It
launches `registry.opensuse.org/opensuse/tumbleweed:latest`, installs podman
6.x, and runs the suite as a NON-ROOT user with a delegated subuid range. There
is no root run and no `--privileged`.

Expect, near the end:

```
engine tests: 42 ran, floor 42 — podman version 6.0.2 at /usr/bin/podman
```

`SNUG_ENGINE_FLOOR` is a MINIMUM, not a total, and it is **per environment**: 42
in this container, 33 for a bare `make integration-sandbox` on this development
host, where the engine cannot start a container at all (#401) and a chunk of the
engine tests legitimately skip. So a count above the floor is normal and a count
below it fails the run.

What must never appear is a low count with a green exit — that is the defect this
whole section exists to make impossible, and `SNUG_REQUIRE_ENGINE=1` plus the
floor is what makes the run FAIL instead:

```
engine tests: 0 ran, floor 42 — podman version 6.0.2 at /bin/podman
ERROR: SNUG_REQUIRE_ENGINE is set and only 0 engine tests ran, below the floor of 42.
```

`snug doctor` runs first inside the container, and on a correctly-set-up host
prints (MEASURED, run 32945827262):

```
🩺 snug doctor

  ✅ bubblewrap 0.11.2
  ✅ unprivileged user namespaces work
  ✅ private network namespace — loopback only
  ✅ the stage starts — clone, uid map, loopback, and the netns move
  ✅ pasta 20260612.a9c61ff-1.3
  ✅ podman client is usable inside a sandbox
  ✅ podman's helper binaries are all findable
  ✅ TIOCSTI disabled kernel-wide — job control works inside the sandbox
  📦 running inside a docker container — supported
  ✅ profiles load cleanly

🎉 This host can run snug.
```

That transcript is ten ticks; issue #483 added an eleventh,
`✅ a delegated subuid/subgid range the container engine can use`, between the
helper-binaries and TIOCSTI lines. It is not in the transcript because the
transcript is a measurement, and this container has not been re-measured since.

The transcript also PREDATES the report being grouped into `🧰 programs`,
`🐧 kernel` and `🏠 host configuration`, so its flat order is not what a run
prints today. Same reason it is left alone: rewriting a measurement into what
it would have said is the one thing a measurement must not be. The current
grouping is what `scripts/0012-doctor-names-each-wrong-host.sh` reads.

Timing, same run: 5m04s for the whole job, of which the suite is 220.370s. The
fixed cost underneath is small — image pull 11s, zypper ~20s, setup-go 9s,
`make build` 12s — which is why no image caching is used.

### 19b. An infrastructure failure says so, without the log

Everything this job needs from the network happens before a single test runs.
Each step classifies its own failure and exits **75** (`EX_TEMPFAIL`), so the
exit code carries the verdict instead of relaying zypper's 4:

```bash
SNUG_ENGINE_RUNTIME=/bin/false make integration-engine; echo "exit=$?"
```

Expect `NO TEST RAN. This is the container registry, not a snug regression.`
and `exit=75`. Under `GITHUB_ACTIONS` the same failure also emits an
`::error title=openSUSE infrastructure, not snug::` annotation, which is the
only part visible without opening the log.

The job still goes RED — invariant 5 with CI as the capability: a refresh that
leaves the container unusable must not read as green. What changes is that a
red run says which kind of red it is. MEASURED over 57 concluded engine jobs
(2026-08-26T15:22Z … 2026-08-28T07:29Z): 8 failures, 5 real test failures at
199–215s and 3 at 24–32s that were one openSUSE mirror event caught three times
in 54 minutes (runs 33112408141, 33116498388, 33116787758 — byte-identical text
down to the repodata hash).

## 20. `@http-proxy`: a door only a human can open (issues #470, #471)

A profile DECLARES a door; the sandbox cannot open one. snug creates the
listening unix socket on the host before the sandbox starts and hands the
descriptor in, so the payload may `accept()` and can never bind a second one.
Nothing is reachable until a human runs `snug proxy`.

```bash
mkdir -p $X/snug/profiles.d
cat > $X/snug/profiles.d/door.toml <<'PROF'
[profile.mydev]
description = "an http door for my dev server"
listen_names = ["web"]
PROF
XDG_CONFIG_HOME=$X ./bin/snug -p mydev $SC/proj/sub -- /bin/sh -c \
  'env | grep -i listen; ls -l /proc/self/fd/3'
```

Expect the escape sentence on YOUR terminal before anything runs, and the
socket-activation protocol inside:

```
snug: http door "web" is declared. Nothing is reachable yet — run `snug proxy` to open it.
      Opening one serves whatever the sandbox answers into YOUR browser, on an origin
      your browser treats as local. THAT IS A SANDBOX ESCAPE and snug does not bound it.
      The cost lands while the proxy runs, not only when you open the URL.
LISTEN_FDS=1
LISTEN_PID=2
LISTEN_FDNAMES=web
/proc/self/fd/3 -> socket:[...]
```

**`LISTEN_FDS` is a COUNT, not a descriptor number** — the descriptors are 3, 4,
… in `LISTEN_FDNAMES` order, so one door means `LISTEN_FDS=1` on fd 3.

`LISTEN_PID` matching the payload's own pid is the load-bearing one: snug cannot
predict a pid inside a fresh pid namespace, so a two-line staged script does
`export LISTEN_PID=$$; exec "$@"` — `exec` preserves the pid. A wrong value makes
every conforming client SILENTLY ignore the descriptor, which is a door onto a
sandbox where nothing ever accepts.

### 20a. Serving something real, and what the server has to be

The server must ACCEPT on the descriptor rather than bind a port.
`scripts/payloads/http-door-server.py` is a working one; `python3 -m http.server` cannot
be used at all, and servers you cannot edit (Java, .NET, anything in a container)
need the adapter in issue #476.

```bash
cp scripts/payloads/http-door-server.py $SC/proj/sub/serve.py
echo '<!doctype html><link rel="stylesheet" href="/style.css"><h1>hello</h1>' > $SC/proj/sub/index.html
echo 'body{color:red}' > $SC/proj/sub/style.css
XDG_CONFIG_HOME=$X ./bin/snug -p mydev $SC/proj/sub -- python3 serve.py
XDG_CONFIG_HOME=$X ./bin/snug proxy $SC/proj/sub          # another terminal
```

`snug proxy` prints the URL only AFTER the listener is bound — a URL printed
before the bind is refused for a moment and is a lie outright if the bind fails:

```
      Open:  http://127.77.164.95:8099/33249ab6d4315a41202de7c32c20bea4/
      Stop:  Ctrl-C
```

### 20b. `?snug-token=` is a BOOTSTRAP, not a path the app lives under

MEASURED with the token as a path prefix first: the page loads and then **every
absolute reference in it misses** — the browser asks the origin ROOT for
`/style.css`, which carries no token and is refused 403 before the backend sees
it. That breaks every framework emitting absolute URLs.

It is therefore a QUERY parameter. The first request carrying it is compared
constant-time, gets a cookie, and is redirected (303) to the same path with the
parameter REMOVED — so the address bar lands on the app's own URL, the token is
never seen again, and the app never sees it at all:

```bash
curl -s -c /tmp/jar -L -o /dev/null -w 'page  %{http_code} -> %{url_effective}\n' "$URL"
curl -s -b /tmp/jar -o /dev/null -w 'style %{http_code}\n' "http://$ADDR/style.css"
curl -s          -o /dev/null -w 'style without the cookie %{http_code}\n' "http://$ADDR/style.css"
```

```
page  200 -> http://127.77.164.95:8080/
style 200
style without the cookie 403
```

The cookie is `HttpOnly` (the page's own scripts cannot read the credential back
out) and `SameSite=Strict`, which is doing security work rather than tidiness: a
browser will not attach it to a request a cross-site page initiated, so the
credential is absent exactly when the initiator is one this door refuses.

### 20c. The measured admission matrix

Against a live door with a hostile backend sending `Access-Control-Allow-Origin: *`:

| request | result |
|---|---|
| the human's own (no `Sec-Fetch-Site`) | `200`, the payload's body |
| `Sec-Fetch-Site: none` / `same-origin` | `200` |
| `Sec-Fetch-Site: cross-site` / `same-site` | `403` |
| `Origin: https://evil.example` | `403` |
| the door's own `Origin` | `200` |
| the cookie missing, or holding a wrong token | `403` |
| a rebound `Host` (`--resolve evil.test:8099:<addr>`) | `403` |
| `Upgrade: websocket` | `501` — WebSocket and SSE are not proxied in this version |
| `CONNECT` | `403` — the door is not a forward proxy |
| the backend's `Access-Control-Allow-*` | **stripped** (0 occurrences in the response) |

The `Sec-Fetch-Site` rows are the point: `Host` allowlisting authenticates the
TARGET, never the INITIATOR, so a page you already have open reaches the door
with a perfectly correct `Host`. Its absence is allowed because curl and older
browsers send none, and treating absence as a lie would refuse the human's own
request.

### 20d. Teardown, and one routine error that looks alarming

**`BrokenPipeError` in the payload is ROUTINE**, not a bug: the door closes the
backend connection when the human stops `snug proxy`, when its round-trip
deadline passes, or when the browser goes away. Stock `socketserver` prints a
full traceback for it; `scripts/payloads/http-door-server.py` handles it, and MEASURED —
interrupting `snug proxy` mid-transfer produced the traceback before that
handling and produces nothing after it, with the payload still serving.

### 20e. What this does NOT do

The door's outside leg is a loopback TCP listener, and loopback TCP is not
access-controlled — every uid on the machine can reach it while the proxy runs.
The `0600` unix socket protects the INSIDE leg only. What snug buys by refusing a
raw forwarded port is that the hole's lifetime is the human's command rather than
the whole run, plus the initiator checks above.

## 21. The offline arm's bwrap is pid 1 of a namespace of its own (issue #101)

The offline arm's nesting, and the ENOENT a payload gets when it tries to name
the intermediate bwrap, are
`TestOfflineArmsIntermediateBwrapIsUnaddressableFromThePayload`. The other arm
is asserted by nothing.

**The staged arm (`@net`) is not nested, and the script says so** rather than
reporting an absence it did not check. Its bwrap is forked by the stage, in the
host's pid namespace:

```bash
./bin/snug -p @net . -- sleep 20 &
python3 scripts/payloads/pid-nesting.py host
```

```
  ✅ found snug, pid 93214

     who is running, and which pid namespace each one lives in:

       93214  snug        pid:[4026531836]      the host's own pid namespace
         93226  exe         pid:[4026531836]
           93249  bwrap       pid:[4026531836]
             93258  bwrap       pid:[4026533218]      ← a NEW pid namespace starts here
               93261  sleep       pid:[4026533218]
         93237  pasta.avx2  <Permission denied>   (this process's namespace is not readable from here)

  ⚠️  no bwrap directly under snug — this is the @net sandbox
     Its bwrap is started by the stage instead, and it is NOT nested;
     the tree above shows the whole chain. Only the offline arm nests.
```

`exe` is the re-exec'd stage. `pasta`'s own namespace links are not readable by
this script; it prints the errno rather than guessing at a reason, and no line of
this check depends on them.

## 23b. Standing up a live engine on a host whose default store is broken

The lifecycle verbs themselves — create, start, stop, restart, kill, `rm -f`,
named volumes, and `podman rm --depend` being refused — are
`TestContainerLifecycleVerbsWorkAgainstALiveEngine`,
`TestANamedVolumeOutlivesItsContainer` and `TestTheDependCascadeIsRefused`. They
need a live engine, so they run where §19 runs. Getting one up by hand is the
part that is per-machine: on this box one comes up with an isolated store — the host's default store is in the broken-lock state #465
names, and `/proc/self/cgroup` reads `0::/../../app.slice/...` so podman looks for
`/sys/app.slice/.../cgroup.controllers`:

```bash
podman --root /tmp/s459/root --runroot /tmp/s459/runroot \
       --cgroup-manager=cgroupfs --runtime crun \
       system service --time 0 unix:///tmp/s459/engine.sock
```

`runc` refuses `--cgroups=disabled` ("requested OCI runtime runc is not compatible
with NoCgroups: invalid argument"); crun accepts it. Keep the socket path SHORT —
`sun_path` holds 108 bytes and the failure surfaces as podman's generic "Cannot
connect to Podman".

## 25. A profile cannot bind the host's /proc, /dev or /sys (issue #527)

The rule itself — by type and not only by name, recursively, and the lookalike
paths it must NOT catch — is `internal/policy/kerneltree_test.go`. What the
sandbox's own `/dev` and `/sys` look like is `TestDevIsWritableButNeitherPersistsNorEscapes`
and `TestUngrantedPathsAreAbsent`. One clause has no owner: that `/proc/self/fd`
still resolves inside.

```bash
./bin/snug $SC/proj/sub -- sh -c 'ls /proc/self/fd >/dev/null && echo procfd-ok'
```

## 28. The stage's three parked descriptors are where fds.go says (issue #525)

`TestTheThreeParkedDescriptorsOnALiveStage` reads a live stage's
`/proc/<pid>/fd` and asserts fd 66, 67 and 68 are what `fds.go` says. A claim is
not enough by itself, because some of the runtime's descriptors are
opened BEFORE `main` and cannot be preempted by anything snug does: the cgroup
CPU limit file `defaultGOMAXPROCSInit` opens and keeps (one under cgroup v2,
two under v1), and netpoll's pair when a timer is armed that early. `fd 62..65`
is the slack left free for them — four numbers between the largest permitted
block and fd 66 — and `TestTheFDBudgetPolicySnugAcceptsIsOneTheStageCanActuallyBuild`
is where you can see them land in it.

Two things about running this by hand. `pgrep -f __stage-serve` matches EVERY
snug on the machine, so quit your other sandboxes first, or the listing you get
is somebody else's run rather than the one you just started. It also matches
the SHELL you type it in, whose own command line now contains the string — put
the pipeline in a script file, or take the stage from `pgrep -P $!` after
backgrounding snug, and you get the process you meant rather than your own
`bash -c`.

## 29. A run with no terminal cannot write to yours; a run with one can (issue #528)

There is no filter over terminal bytes and there will not be one: a filter is a
catalogue of dangerous spellings that has to stay complete forever.
`THREAT-MODEL.md` §3.6 states the shared terminal as a non-goal. The automated
equivalents are `TestNonInteractiveRunCannotWriteToTheOperatorTerminal` and
`TestKnownOpenResidualPayloadWritesToASharedTerminal` (integration), which
build their own pty so they never depend on how the suite was launched — the
second is a table over the pty on stdin alone, stdout alone, stderr alone and
all three, asserting the channel is open in every one and `/dev/console` exists
in the stdout ones only. `TestNewSessionHasTwoIndependentReasons`
(`internal/policy`) covers the argv and `TestDescribeTTYNamesEveryReasonAndTheResidual`
(`internal/cli`) the four screens.

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
   That is argued in the code, in `TestWritableMarkIsPathOnlyAndDistinctFromNotGranted`
   and in `TestDropLinesNameTheirReason`, and it is the sort of subtlety that
   reads as a bug at 11pm.
3. **A refusal that is later relaxed must not silently restore a false
   sentence.** A profile mounting over `/snug/bin` is refused at `Validate`
   (`TestAProfileCannotMountOverTheStagingDirectory`), so the branch that
   prints the opposite in `--dry-run` should be unreachable. It is kept anyway,
   for exactly the case where someone narrows the refusal.
