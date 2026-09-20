# scripts/

Programs a human runs against a sandbox, not code snug builds or imports.
Nothing here is on any import path, nothing here needs privileges, and each one
exists because a property is easier to *observe* than to argue about.

Three kinds. The first two are separated by directory rather than by a naming
convention the runner would have to parse; the third is the section at the
bottom of this file, because it is prose a human follows rather than anything
that could be run.

## Checks — `NNNN-slug.sh`, `NNNN-slug.py`

A check asserts a property from outside and has a pass/fail. It prints what it
asserted; the expected output lives in its assertions, not in prose beside it.
`make verify` walks them in numeric order.

| script | asserts |
|---|---|
| [`0012-doctor-names-each-wrong-host.sh`](0012-doctor-names-each-wrong-host.sh) | five wrong-host conditions each get doctor's own headline and fix, not another's: `apparmor_restrict_unprivileged_userns=1`, a container masking `/proc`, no `/dev/net/tun`, runc-without-crun under disabled cgroups, and no `/etc/subuid` line |
| [`0020-a-weak-host-warns-and-still-runs.sh`](0020-a-weak-host-warns-and-still-runs.sh) | the five inherited kernel knobs are disclosed and never refused, and the drop-in is a function of the table rather than of this boot — 4 applied, 5 written (issue #526) |
| [`0032-claude-opens-with-no-dialog-and-no-hook.sh`](0032-claude-opens-with-no-dialog-and-no-hook.sh) | the trust dialog is pre-answered and a hostile repo's `.claude/settings.json` hooks and `.mcp.json` servers are reinterpreted away before Claude Code reads either — with the same fixture's hook firing on the bare host as the control |
| [`0033-an-unnamed-plugins-hook-does-not-fire.sh`](0033-an-unnamed-plugins-hook-does-not-fire.sh) | an installed plugin's `hooks.json` is not even read inside when `@claude`'s allowlist does not name it, though its tree stays bound read-only (issue #68) |
| [`0034-projected-credential-still-authenticates.sh`](0034-projected-credential-still-authenticates.sh) | the staged `~/.claude/.credentials.json` carries exactly five fields, never a refresh token, and a live turn on it still authenticates (issue #58) |

**`NNNN` is an allocation sequence, not a checklist section number.** Sections
carry suffixes (`9a`, `9c-ter`, `9c-quater`, `23b`) that no numeric prefix can
express, and one section is frequently several independent checks. A number is
allocated on creation and never reused, **including by a check that has since
left this directory**, so a number in a commit message or an issue means one
thing forever. The gaps in the sequence are that rule holding, plus the
convention that related checks share a decade.

**Exit 79 is SKIP**, and it is 79 rather than the conventional 77 because snug's
own `exitPolicy` IS 77 (`internal/cli/main.go`). A script that ended on an
uncaptured `snug` refusal would otherwise report SKIP — a check that cannot
fail. 79 is outside sysexits' 64–78 range entirely, so it cannot be one of
snug's. A check declares its own preconditions and SKIPs naming the one that was
not met; it never assumes the host it was written on.

## Payloads — `payloads/`

A payload is a program run INSIDE a sandbox. It has no pass/fail of its own, so
`make verify` does not walk it; a check or a Go test runs it and grades what it
printed.

| payload | run it | graded by |
|---|---|---|
| [`payloads/http-door-server.py`](payloads/http-door-server.py) | as the payload of a run whose profile declares a `listen_names` door | a human, in *`@http-proxy`: a door only a human can open* below |
| [`payloads/pid-nesting.py`](payloads/pid-nesting.py) | twice — `inside` as the payload, `host` beside it | `TestOfflineArmsIntermediateBwrapIsUnaddressableFromThePayload` and `TestStagedArmsBwrapIsNotNested` own the property; `TestTheNestingScriptStillReadsALiveSandbox` owns whether the script still works |

`payloads/http-door-server.py` is also the answer to "how do I serve something
from in here", because `python3 -m http.server` cannot be: snug never forwards a
port, it hands the payload a socket that is already listening on the host.

## What belongs here, and what belongs in Go

**A check CI can run on every push belongs in `test/integration`, not here.** A
check living in both places is a second copy of state, and the copy nobody runs
is the one that goes stale.

What is left for this directory is what CI genuinely cannot run: a check whose
answer is per-machine (this host's kernel knobs), one that needs state CI
structurally lacks (a `claude` binary, a live authenticated credential, two
accounts), or one that needs a human's `sudo`. Plus the payloads, which are
programs rather than assertions.

**So CI does not run `make verify`, and that is the rule holding rather than a
gap.** The rule says every check here is one CI cannot run; a CI step walking
them could therefore only ever SKIP, and a step that can only skip is exactly
the shape the floors in this repository exist to refuse. What CI grades instead
is `test/guard/scripts_test.go`, which grades the DIRECTORY — duplicate numbers,
a file that is not executable, a check missing from this index, a script
spelling SKIP as 77 — none of which running the checks would catch.

## By hand: what nothing here can run

Everything below needs state this repository cannot arrange: two logged-in
GitHub accounts, a live `gh`, a `sudo truncate` against `/etc/subuid`, a real
container engine, a browser a human clicks in, or a measurement of one machine.
Anything that could be asserted instead has been, and the section that asserted
it was deleted rather than left standing beside its test — a checklist entry
next to the test that replaced it is a second copy of state, and the copy
nobody runs is the one that rots.

**Every command below runs from the repository root**, not from this directory.

A sandbox you have not personally tried to break is a sandbox you are trusting
on someone's word. What these check is that **the sandbox holds**, which is not
the same question as whether your profiles are safe: snug does not second-guess
a profile, so `rw ["{home}"]` and `environ.set EDITOR = "/tmp/evil"` are holes
you opened, they are on screen in `--dry-run`, and nothing below will fail on
them. See [`.claude/design/INDEX.md`](../.claude/design/INDEX.md) §1.4 and the
README's *What snug does not defend against*.

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
check needing its own profile writes one — never the repository under test,
which is invariant 3.

### Can this host run it at all

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

### Two accounts on one host — an identity is a pin, not a preference

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


#### A signing key is a SECOND pin, and the run refuses without it (issue #453)

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


#### The per-target lock and an interrupted state write are swept too

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


### What can this run destroy? — the check before a red-team payload

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

### The engine tier really runs, on a machine that is not this one (issue #395)

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

#### An infrastructure failure says so, without the log

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

### `@http-proxy`: a door only a human can open (issues #470, #471)

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

#### Serving something real, and what the server has to be

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

#### `?snug-token=` is a BOOTSTRAP, not a path the app lives under

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

#### The measured admission matrix

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

#### Teardown, and one routine error that looks alarming

**`BrokenPipeError` in the payload is ROUTINE**, not a bug: the door closes the
backend connection when the human stops `snug proxy`, when its round-trip
deadline passes, or when the browser goes away. Stock `socketserver` prints a
full traceback for it; `scripts/payloads/http-door-server.py` handles it, and MEASURED —
interrupting `snug proxy` mid-transfer produced the traceback before that
handling and produces nothing after it, with the payload still serving.

#### What this does NOT do

The door's outside leg is a loopback TCP listener, and loopback TCP is not
access-controlled — every uid on the machine can reach it while the proxy runs.
The `0600` unix socket protects the INSIDE leg only. What snug buys by refusing a
raw forwarded port is that the hole's lifetime is the human's command rather than
the whole run, plus the initiator checks above.

### Standing up a live engine on a host whose default store is broken

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

### If a check fails

1. Re-run it with `--dry-run` and compare what snug *claimed* against what you
   *observed*. Those two disagreeing is itself the most important finding.
2. Capture the exact commands and both outputs.
3. Note which grant is responsible — `--dry-run` prints the contributing profile
   at the end of each `FILESYSTEM` line.
4. That reproduction becomes a permanent regression test. The rule in this
   project is that a hole should only ever be closable once.

### What this checklist does not cover

Deliberately absent, so do not read their absence as a failure: GUI, audio and
D-Bus passthrough. No profile ships for them and none is planned — the private
netns excludes them by construction, which is a property to keep rather than a
gap to close.

It also does not cover the threats snug does not defend against at all: kernel
0-days, and a determined human attacker with a shell. See INDEX §1.2.

### Where the reasoning is thinnest

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
