# The Claude login bridge — `browser = "claude-login"`

Claude Code's `/login` opens a browser on an authorize URL whose callback is
`http://localhost:<port>/callback`, a listener inside the sandbox's own network
namespace. The host browser cannot reach that listener and the sandbox has no
browser, so without help `/login` inside works only by pasting the code from
the manual URL claude prints. The login bridge is the narrow hole that lets the
browser flow complete: the sandbox may hand snug **one** URL of **one** pinned
shape, snug opens a URL it rebuilt from its own constants in the host user's
browser, and relays **one** rebuilt callback request back in.

Owner: `host-bridge`. Code:

| piece | where |
|---|---|
| the key, the shim, `BROWSER`, Resolve refusals | `internal/policy/types.go` (`BrowserMode`), `resolve.go`, `browserbridge.go`, `envconditional.go`, `snugns.go` (`BrowserFIFOGuest`, `BrowserShimGuest`) |
| the predicate and rebuild (pure) | `internal/loginbridge/authorize.go`, `callback.go`, `query.go`, `pinned.go` |
| limits | `internal/loginbridge/limits.go` |
| host listener, relay | `internal/loginbridge/bridge.go`, `procnet.go` |
| opener | `internal/loginbridge/opener.go` |
| relay sockets created in N | `internal/stage/relay.go`, the `netready` arm of `serve.go`, `WaitNetReady` in `stage.go`, `recvEventFDs` in `conn.go` |
| P0 wiring: preflight, FIFO, reader, startup note | `internal/cli/loginbridge.go`, `main.go` |
| `--dry-run`, JSON, `--explain` | `internal/cli/loginbridgedryrun.go`, `dryrunjson.go`, `explain.go` |

The abuse sentence is the comment above `[profile.claude]` in
`internal/profile/profiles/base.toml`; it is the authority on what the hole
costs, and this document does not restate it.

## 1. The flow

1. Inside, `BROWSER=/snug/bin/snug-browser`. Claude Code execs it with the
   authorize URL as its one argument; the shim writes that line to
   `/snug/browser.fifo`.
2. snug (P0) reads the line and runs it through `loginbridge.ParseAuthorize`:
   one pinned shape, everything else refused with a named reason (§3).
3. `Bridge.Handle` checks the limits (§7), checks that something inside listens
   on `127.0.0.1:<port>` (§5), binds `127.0.0.1:<port>` and `[::1]:<port>` on
   the host, and runs `xdg-open` on `Flow.AuthorizeURL()` — the URL rebuilt
   from snug's constants plus the three validated values (challenge, state,
   port). There is no snug page in between: the browser goes straight to
   `https://claude.com/cai/oauth/authorize`.
4. The human approves on claude.com; the browser is redirected to
   `http://localhost:<port>/callback?code=…&state=…`, which lands on snug's
   host listener.
5. snug checks the peer is the human's own uid, the `Host` header, and the
   callback against the flow's state (§6), then writes **one rebuilt request**
   (`GET /callback?code=…&state=…`, `Host` and `Connection` only) into the
   sandbox through a TCP socket the stage created **inside** the sandbox's
   netns (§4). It reads back only the status code and answers the browser with
   a page of its own. Then it closes everything for that flow.

The sandbox keeps its private netns. pasta's argv does not change: nothing is
forwarded into the namespace, and host loopback stays unreachable from inside.

## 2. How it is granted

- **An ordinary feature key, `browser = "off" | "claude-login"`**, joined by
  max (`BrowserMode`). `ParseBrowserMode` refuses any other spelling quoting
  the accepted set (`unknown browser mode "…" (want off or claude-login)`), at
  profile parse time and so in `snug profile show` as well.
- **No builtin sets it, `@claude` included.** `@claude` is what every Claude
  run selects; the hole exists only where a user profile spells
  `browser = "claude-login"` itself, never by riding along with
  `-p @claude -p @net`.
- No CLI flag. The key is a TOML value only.
- **Resolve refuses** the key on in a selection
  - without egress: `profile "X" sets browser = "claude-login", but nothing in
    this selection grants the network: the callback is relayed into the
    sandbox's own network namespace and the token exchange needs the internet.
    Add -p @net.`
  - without a visible `/bin/sh` (`shellIsVisible`): `BrowserBridgeShellError`,
    which names the shell and `@sys`.
- With the key on, Resolve stages the shim as a `KindData`, read-only, 0755
  mount at `/snug/bin/snug-browser` and authors `BROWSER` pointing at it.
  `BROWSER` is a `conditionalEnvs` row: a profile that `set`s or `inherit`s
  `BROWSER` in a selection with the key on is a conflict naming both
  (ENVIRONMENT-VARIABLES.md §1.1). `browser` is not in
  `ClaudeSettingAllowlist`, so the generated `settings.json` never carries
  Claude Code's `settings.browser`, which would outrank `$BROWSER`.

## 3. Transport sandbox → snug, and the predicate

### 3.1 A FIFO, because the client is `/bin/sh`

The only client snug can count on inside is `/bin/sh` — `curl` and `python3`
are not guaranteed by `@sys` — and `sh` cannot speak AF_UNIX. A FIFO needs only
`>`.

- P0 creates `browser.fifo`, mode 0600, in the per-run directory
  (`runDir.Socket`), opens it `O_RDWR|O_CLOEXEC` — a FIFO opened read-write
  never blocks the opener and never reports EOF when the sandbox's writer
  exits — and binds it at `/snug/browser.fifo` with `Policy.BindSocket`
  (RunScoped, after Resolve). `--dry-run` binds the planned path the same way
  (`planBrowserFIFO`), so its argv carries the same `--bind`.
- The shim (`browserBridgeShim`) refuses anything but exactly one argument and
  `printf '%s\n' "$1" > /snug/browser.fifo`. **The shim is not the bound; the
  predicate is.** Anything inside may write the FIFO directly.
- The reader (`readLoginLines`) takes newline-terminated lines of at most 4096
  bytes; a longer one is discarded up to the next newline and counts as one
  refusal. **Nothing is ever written back**: the sandbox gets no answer, so
  snug is no oracle for "is host port N free". Claude prints its manual URL
  regardless, so a refused open leaves the paste flow intact.
- **A second reader inside can steal lines, and snug cannot see a stolen
  one.** Anything in the sandbox may open the FIFO for reading too. The cost
  is the sandbox's own login convenience, never the run: no hang, no crash,
  and a later request is seen once the stealer is gone
  (`TestASecondFIFOReaderInsideCostsOnlyTheBridge`). A stealer that takes the
  tail of a line also costs the next line, which joins the pending partial
  and is refused.

### 3.2 `ParseAuthorize` — refuse, never normalise

| param | accepted raw value |
|---|---|
| prefix | `https://claude.com/cai/oauth/authorize?`, byte-exact |
| `code` | `true` |
| `client_id` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` |
| `response_type` | `code` |
| `redirect_uri` | `http%3A%2F%2Flocalhost%3A` + five digits, no leading zero, 32768–60999 + `%2Fcallback` |
| `scope` | `+`-separated, exactly the seven raw tokens `org%3Acreate_api_key` `user%3Aprofile` `user%3Ainference` `user%3Asessions%3Aclaude_code` `user%3Amcp_servers` `user%3Afile_upload` `user%3Aplugins`, each once, any order |
| `code_challenge` | 43 × `[A-Za-z0-9_-]` |
| `code_challenge_method` | `S256` |
| `state` | 43 × `[A-Za-z0-9_-]` |

Rules, each its own refusal reason:

1. Non-empty, at most 2048 bytes, every byte 0x21–0x7E.
2. No `#` anywhere.
3. The console URL (`https://platform.claude.com/oauth/authorize?`) refuses
   with its own reason: its scope set was never measured, so it is left
   unbuilt.
4. Prefix byte-exact, so an uppercase host, trailing dot, port, userinfo, extra
   path segment or `%`-escape in the path all fail one comparison.
5. The query splits on `&` only (never `net/url`, which also splits on `;` and
   drops a segment with no `=`); no empty segment, exactly one `=` per
   segment, no empty key, no key twice.
6. The key set is exactly the eight above. `orgUUID`, `login_hint`,
   `login_method` and anything unknown refuse by name.
7. Values compare raw: `%3a` refuses, a raw `:` in a scope token refuses,
   `127.0.0.1` in `redirect_uri` refuses.
8. Scope is the measured set, not a subset: a subset would be a narrower token
   but is a URL no real client produced. An empty scope token and a repeated
   one have their own reasons; any other difference gets `the scope set
   differs from the seven snug pins — this claude may be newer than snug; open
   the URL claude printed and paste the code`. A Claude Code that changes its
   scopes fails loudly and one constant (`scopeTokens`) is updated.

**Rebuild.** `Flow.AuthorizeURL()` writes the prefix and the eight parameters
in the measured order from snug's constants plus challenge, state and port.
The sandbox's string never reaches `xdg-open`.

## 4. Relay sockets inside N

P0 cannot `setns` into the sandbox's netns N: it holds no `CAP_SYS_ADMIN` in
the owning user namespace U, and joining U from multithreaded Go is EINVAL
(NOCGO.md). A socket's netns is fixed at creation, so the stage, which can
join N, makes the sockets and P0 holds them.

- `request{Op: "netready"}` carries `RelaySockets` (0 on every run without the
  key; P0 asks for `stage.MaxRelaySockets` = 3 with it). P1 refuses a count
  outside 0–3. After the interface is up and the host addresses are sealed,
  `relaySocketsInN` runs on a locked goroutine: `setns(N, CLONE_NEWNET)`, N ×
  `socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC)`, and returns **without
  unlocking**, so the runtime destroys the thread that joined N. On the thread
  group leader — which the Go runtime wedges rather than exits — it hands the
  work to a fresh goroutine instead. P1 then polls `threadsInNamespace` until
  no thread of its own is in N (2 s, `relayThreadGoneTimeout`), or refuses.
- The `netready` event carries the sockets as `SCM_RIGHTS`; P1 closes its
  copies whether or not the send succeeded. No new op, no second request.
- P0 receives with `MSG_CMSG_CLOEXEC` into a control buffer with room for one
  descriptor more than the maximum (so an over-send is seen, and `MSG_CTRUNC`
  refuses), then **verifies from outside** (`verifyRelaySockets`): requested,
  claimed and delivered counts agree; each is `AF_INET`/`SOCK_STREAM`; and
  `SIOCGSKNS` names the same `net:[…]` the stage's `ready` event pinned. Any
  mismatch refuses the run.
- `sandbox.Options.RelaySockets` / `OnRelaySockets` carry them to
  `loginBridge`; a non-zero count with no network, or with no callback, is
  refused in `sandbox.Run`.
- **The address is a constant.** `loginBridge.Dial` only ever connects a socket
  to `127.0.0.1:<port>`; the sandbox chooses the port and nothing else. A
  socket is spent even when the connect fails.

## 5. The port check — consistency, not a bound

- 32768–60999 is the kernel's default ephemeral range, and the payload has no
  capability in U to change N's. The real narrowing: snug can never be told to
  hold host `localhost:5432` or `:8080`.
- Before binding, `ListeningOn` reads `/proc/<sandbox init pid>/net/tcp` (pid
  from `Options.OnInit`) for a `LISTEN` row on `127.0.0.1:<port>`. The payload
  can listen on any port, so this proves consistency, not safety: it turns
  "nothing listens" into a refusal instead of a dead browser tab.

## 6. Host listener and callback

**Bind.** `127.0.0.1:<port>` and `[::1]:<port>` (`IPV6_V6ONLY` set explicitly),
only while a flow is live; never `0.0.0.0`. Binding both before opening means
no other uid can squat the family snug skipped, and browsers resolve
`localhost` to `::1` as well. `EADDRINUSE` on either refuses with nothing bound
(`localhost:<P> is in use on this host; run /login again and claude picks
another port`); `EADDRNOTAVAIL`/`EAFNOSUPPORT` on `::1` (no v6 loopback) gives v4
only; any other error refuses.

**Per connection**, in order:

| check | failure answer |
|---|---|
| at most 8 connections in flight | accepted and closed, no answer |
| addresses are TCP | `403` |
| peer uid: the client's row in `/proc/self/net/tcp{,6}` (v4-mapped spelling tried too) must exist, agree, and equal `os.Getuid()` | `403` (unresolvable or another uid; fails closed) |
| request head within 10 s and 8 KiB; request line `METHOD TARGET HTTP/1.x`; well-formed headers; exactly one `Host` | `400` |
| `Host` is `localhost:<P>`, `127.0.0.1:<P>` or `[::1]:<P>` (DNS rebinding) | `400` |
| `ParseCallback`: `GET`, origin-form, path exactly `/callback`, query keys exactly {`code`, `state`}, state constant-time equal to the flow's, code 1–1024 bytes of unreserved characters or `%XX` | `404`; **the flow stays open** |
| the flow already relayed or ended | `404` |
| relay fails | `502`, and the flow ends |
| relayed | `200`, `snug delivered the login callback to the sandbox; it answered HTTP <NNN>. You can close this tab.`; the flow ends |

The uid gate closes the multi-user host: the authorize URL, state included, is
in the shim's and the opener's argv, readable by any host uid under the default
`hidepid=0`; without the gate another uid could approve on ITS account and
deliver that code (authorization-code injection → the sandbox logged in as the
attacker).

Every answer is `writePage`: snug's own text, HTML-escaped, `text/html;
charset=utf-8`, `Content-Security-Policy: default-src 'none'; form-action
'none'; frame-ancestors 'none'`, `Cache-Control: no-store`, `Referrer-Policy:
no-referrer`, `X-Content-Type-Options: nosniff`, `Connection: close`, no
`Set-Cookie`, no `Location`. No byte of it comes from the sandbox.

**The relay.** On one relay socket, connected to `127.0.0.1:<P>` in N, snug
writes exactly `RelayRequest`:

```
GET /callback?code=<code raw>&state=<flow's state> HTTP/1.1\r\n
Host: localhost:<P>\r\n
Connection: close\r\n
\r\n
```

**No browser header crosses.** Cookies are not port-isolated (RFC 6265 §8.5), so
a forwarded browser request to `localhost:<P>` would carry every cookie any host
localhost service set. The code is relayed in its raw query-encoded form —
decoding and re-encoding would be a second parser. The answer is read under a
15 s deadline: a status line within 8 KiB, parsed to an integer, the rest
discarded up to 64 KiB. Relaying the sandbox's answer instead would run its
HTML on origin `http://localhost:<P>` in the host browser, or follow its `302`
anywhere.

## 7. Limits

`internal/loginbridge/limits.go`; the screens read the same constants.

| constant | value | what it bounds |
|---|---|---|
| `MaxLiveFlows` | 1 | one pending login at a time |
| `SupersedeAfter` | 30 s | a new open replaces a pending flow only once that flow is 30 s old, and never one whose callback is relayed or in flight |
| `MaxOpensPerRun` | 5 | browser tabs the sandbox can cause; counted when a flow starts, whatever the opener then does |
| `MaxRelaysPerRun` | 3 | callbacks relayed, = relay sockets asked of the stage; `Handle` refuses once either is used up |
| `FlowTTL` | 10 min | how long the host port is held for a flow that saw no callback |
| `OpenerPatience` | 30 s | how long snug waits for `xdg-open` to exit |

A flow that ends early — the opener failed, or a callback was relayed — frees
the slot at once; the 30 s applies only to replacing a live one.

The 8 connection slots bound concurrency, not persistence: a process of the
same uid can re-fill them each 10 s head deadline until `FlowTTL`, delaying
the callback. It cannot inject one — state, the uid gate and the Host check
still apply (`TestSlowConnectionsDelayTheCallbackButNeverBlockItForever`
tests one round).

## 8. The opener

- `xdg-open` is resolved once with `LookPath` at preflight; the absolute path is
  executed and shown on `--dry-run`.
- Its argv is `xdg-open <rebuilt authorize URL>`, its environment
  `os.Environ()` — snug's own, stated explicitly: this starts the host user's
  browser, and nothing in it comes from the sandbox.
- stdin `/dev/null`; stdout and stderr go to a `memfd`, not a pipe — a browser
  the opener starts inherits them, and a pipe snug stopped reading would kill
  that browser with SIGPIPE. On a non-zero exit the first 4 KiB are shown
  (`VisibleText`), the flow is cancelled and stderr names the paste fallback.
- `fdseal.SealFor(cmd)`, so no relay socket or FIFO descriptor leaks into it.
- `Setsid`, and deliberately **no `Pdeathsig`**: with no browser running, the
  opener may become the user's browser, and killing it with the sandbox would
  close the user's own windows. An opener still running after 30 s is left to a
  goroutine that reaps it. **The browser `xdg-open` starts may outlive the run**;
  that is accepted, and stated in the profile comment, `--explain` and
  `--dry-run`'s TOPOLOGY block.

### Why there is no snug confirmation page

The browser goes straight to claude.com, and the human gate is Anthropic's
authorize page. That is a remote default, not something snug's tests can see:
**if a user is ever redirected without a click (measurement (b), §11, found a
click required), the bridge is a sandbox-triggered silent token mint and a
snug confirmation page must come back** — a page on the same host listener that
the sandbox cannot click (host loopback is sealed from inside, and the uid gate
admits only the human's connections) and a POST to reach claude.com.

A confirmation in snug's terminal is not an option: the payload shares that tty
and can draw a fake prompt and read the keystroke first (THREAT-MODEL §3.6).

## 9. Screens and refusals

**Preflight** (`browserPreflight`, real runs only; exit 77):

- no `xdg-open` on PATH → `browser = "claude-login" opens your browser with
  xdg-open, and there is none on PATH. Install xdg-utils — or drop browser =
  "claude-login" from the profile that sets it: /login inside still works by
  opening the URL claude prints and pasting the code`
- neither `DISPLAY` nor `WAYLAND_DISPLAY` → `browser = "claude-login" needs a
  graphical session to open your browser, and neither DISPLAY nor
  WAYLAND_DISPLAY is set in snug's environment. Run snug from your desktop
  session — or drop …` with the same fallback.

**Startup note**, always printed on a real run through `notes.escape`:
`snug: browser = "claude-login": the sandbox can ask snug to open a Claude login
page in your browser.` / `snug opens only the one URL shape it pins, rebuilt
from its own constants — if you did not just type /login, close the page.`

**Runtime**, stderr, sandbox-derived text through `VisibleText`:

- open refusals (predicate or `Handle`): `snug: login bridge: refused an open
  request from the sandbox — <reason>. Nothing was opened.` First 5, then
  `further refusals suppressed.` `Handle`'s reasons: shutting down; `this run
  has used its 5 login opens; restart snug`; `this run has relayed its 3 login
  callbacks; restart snug`; `a login is pending (opened <n>s ago)`; `nothing
  inside listens on 127.0.0.1:<P>`; the port-in-use and bind errors of §6.
- listener notices (refused peers, bad heads, 404s, relay failures): their own
  count, first 5, then `further connection refusals suppressed.`
- a flow abandoned at the TTL says snug released the port; an opener failure
  names the paste fallback; a delivered callback prints the sandbox's status
  code.

**`--dry-run`**: FILESYSTEM rows for `/snug/bin/snug-browser` (generated, ro)
and `/snug/browser.fifo` (run-scoped); `BROWSER` with snug provenance; in
NETWORK, `renderBrowserBridge` — the pinned base, client id and seven scopes,
the callback listener, the opener path (or `NONE — a real run would REFUSE to
start: …` when preflight would fail) and the limits; in TOPOLOGY,
`describeBrowserTopology` — `xdg-open` per login, detached, the browser it
starts is yours and may outlive the run. It is not in `longLivedProcesses`:
it is per login, and counting it would make a process count `ps` cannot
confirm. JSON: `browser_bridge {mode, opener, opener_error, fifo, max_opens,
max_relays}`, absent with the key off.

**`--explain`**: a paragraph in the network section, and the "no process snug
did not start" sentence qualified with "except the browser xdg-open starts for
a login".

**Golden argv.** The Resolve-level bwrap diff against `@claude @net` is exactly
the shim's data mount and `--setenv BROWSER`; the FIFO `--bind` is added after
Resolve. The pasta argv is byte-equal to `@claude @net`'s: no `-t`, no
`--host-lo-to-ns-lo`.

## 10. Teardown

| component | lives in | normal exit | snug SIGKILL |
|---|---|---|---|
| FIFO reader | P0 goroutine | `loginBridge.close` closes the fd, the run directory removal unlinks the FIFO | kernel closes the fd; the FIFO file stays in the run directory, the same fate as the run's sockets |
| host listeners | P0, only while a flow lives | closed at flow end, TTL, or `Bridge.Close` | kernel closes both |
| relay sockets in N | P0 descriptors, CLOEXEC | closed by `close` | kernel closes them; they hold a reference to N only while P0 lives, and P0 is upstream of bwrap |
| `setns` thread in P1 | P1, transient | destroyed at goroutine exit, then verified absent | — |
| `xdg-open` | its own session | reaped by a goroutine | reparented; normally already gone |

A failure in P1 while making the sockets answers `netready` with an error and
the run is refused. A panic in P0 collapses the run. Nothing touches pasta, the
netns count or abstract-socket isolation.

## 11. Measured end to end, and what is still open

One real login through the bridge, `scripts/0035-claude-login-through-the-browser.sh`:
Claude Code 2.1.289 inside `snug -p @claude -p @net -p login`, the host's
Firefox (flatpak, reached through `xdg-open` from a distrobox) already signed
in to claude.ai. `claude auth login` completed, `claude -p` answered in the
same run, and the host's `~/.claude/.credentials.json` was unchanged.

- **(b) The authorize page asked for a click.** The human answered that
  claude.com showed Authorize and waited for it. This is a remote default:
  if claude.com ever redirects without a click, the snug confirmation page
  returns (§8). Re-run `scripts/0035` to re-check it.
- **(e) The callback carried exactly `code` and `state`.** snug logged
  `delivered the login callback to the sandbox; it answered HTTP 302`, and
  `ParseCallback` refuses any other key and any missing one. The set is
  `callbackKeys` in `callback.go`; a refused callback names the whole key set.
- Not measured: the ephemeral port range read inside a real snug run
  (the integration tests only show the probe's kernel-chosen port passed the
  range check); whether Claude Code execs `$BROWSER` directly or through a
  shell — `argc=1` was measured with a path value, a value with spaces is
  untested, and snug never writes one.

## 12. Measurements

Claude Code 2.1.283, read from the binary (`strings`) and measured with a
logging `BROWSER` shim inside `snug -p @claude -p @net`; no login completed:

- `startOAuthFlow` builds two authorize URLs from one `state` and one
  `code_challenge`: a manual one with
  `redirect_uri=https://platform.claude.com/oauth/code/callback`, printed with
  `Paste code here if prompted >`, and a loopback one with
  `redirect_uri=http://localhost:<port>/callback`, handed to the opener and
  never printed. A code from the loopback URL is redeemable only through the
  listener (redirect_uri mismatch at the token endpoint otherwise).
- Opener on Linux: `settings.browser`, else `$BROWSER`, else `xdg-open`; with
  none and no display it spawns nothing.
- The shim received `argc=1` and the URL whose shape §3.2 pins; the scope
  carries `org:create_api_key`. Claude's listener was already bound when the
  opener ran, on `127.0.0.1` only (not `::1`).

Kernel facts the design rests on, measured on the development host:

- `cat /proc/sys/net/ipv4/ip_local_port_range` → `32768 60999`, and the same
  under `unshare -rn`. A listener under `unshare -rn` on `127.0.0.1:47097` was
  visible to the parent in `/proc/<child>/net/tcp` as `0100007F:B7F9 … 0A …
  1000`.
- A child that `unshare(CLONE_NEWUSER|CLONE_NEWNET)` (no uid map), brought `lo`
  up and listened, created an AF_INET stream socket and sent it over a
  SEQPACKET socketpair. The parent's `ioctl(fd, SIOCGSKNS)` named the child's
  `net:[…]`, not its own; `connect(127.0.0.1:port)` on the received socket
  reached the child's listener and got `HTTP/1.1 200 OK`; a fresh socket in the
  parent's netns to the same port got `Connection refused`.
- Accepting on `127.0.0.1:0` and looking up the peer's row in
  `/proc/self/net/tcp` gave the caller's uid; `[::1]` bound on the same port as
  the v4 listener.
- `bwrap --bind <host fifo> /x.fifo --unshare-all -- /bin/sh -c 'printf "%s\n"
  … > /x.fifo'` exited 0 and the host reader got the line.

## 13. Tests

Pure, CI (`internal/loginbridge`): `TestTheMeasuredURLRebuildsByteForByte`,
`TestAuthorizeRefusals`, `TestParseAuthorizeEmptyLine`, `TestParseCallbackAccepts`,
`TestParseCallbackAcceptsPercentEscapedCode`, `TestCallbackRefusals`,
`TestParseCallbackCodeLengthBounds`, `TestTheRelayedRequestCarriesNoBrowserHeader`,
`TestTheBrowserGetsSnugsPageNotTheSandboxs`, `TestAnotherUIDIsRefused`,
`TestAnUnresolvablePeerIsRefused`, `TestBadHostHeaderIsRefused`,
`TestHostPortInUseOpensNothing`, `TestFlowLimits`,
`TestOpenerGetsTheRebuiltURLAndHostEnv`, `TestPeerUIDFindsTheClientRow`,
`TestParseStatus`.

Policy and profile: `TestBrowserBridgeNeedsEgress`, `TestBrowserBridgeNeedsAShell`,
`TestBrowserBridgeStagesTheShimAndBROWSER`, `TestWithoutBrowserThereIsNoShimOrBROWSER`,
`TestBrowserIsAConditionalName`, `TestKeyAbsenceNeverWidens` (browser row),
`TestUnknownFeatureModeIsRefusedAtParseTime` (browser rows).

Stage (`internal/stage/relay_test.go`): `TestNetreadyHandsBackSocketsInN`,
`TestNetreadyRefusesMoreThanThreeRelaySockets`, `TestP1HoldsNoRelaySocketAfterNetready`,
`TestNoP1ThreadIsLeftInN`, `TestRelaySocketsAreCloexecInP0`,
`TestNetreadyWithoutRelaySocketsIsUnchangedOnTheWire`,
`TestWaitNetReadyRefusesSocketsItDidNotAskFor`.

CLI: `TestBrowserPreflightRefusals`, `TestBrowserPreflightExitsPolicy`,
`TestLoginReaderRefusalsAreCappedAndSanitised`,
`TestLoginReaderOverlongLineIsOneRefusalAndResyncs`,
`TestLoginReaderAcceptedLineHitsHandOff`, `TestLoginReaderCountsAHandlerRefusalWithItsOwn`,
`TestLoginBridgeFIFOIsPrivateBoundAndClosesCleanly`,
`TestRunWithoutTheKeyHasNoBridgeAndAsksForNoRelaySockets`,
`TestDryRunArgvCarriesTheBrowserFIFOBind`, `TestGoldenBwrapClaudeLogin`,
`TestBrowserBridgeGoldenDiffIsExactlyTheShimAndBROWSER`,
`TestClaudeLoginPastaArgvEqualsClaudeNet`, `TestGoldenBrowserBridgeScreens`,
`TestGoldenBrowserBridgeJSON`, `TestBrowserBridgeRowsAreAbsentWhenTheKeyIsOff`,
`TestBrowserBridgeDryRunShowsTheFilesystemRowsAndEnv`,
`TestBrowserBridgeScreenShowsARefusalTheRunWouldMake`,
`TestAnUnknownModeInAProfileIsRefusedNotNarrowed` (browser row),
`TestAFeatureKeyAuthorsAndNeverBindsAHostPath` (`k-browser`).

Integration (`test/integration/loginbridge_test.go`, `SNUG_REQUIRE_SANDBOX=1`),
with `testdata/loginprobe` as the sandbox half of `/login` and
`testdata/fakeopener` as a host `xdg-open` playing the browser:
`TestTheLoginBridgeRelaysOneRebuiltCallback`, `TestTheLoginBridgeRefusesANonClaudeURL`,
`TestTheLoginBridgeRefusesAPortNothingListensOn`, `TestAWrongStateGets404AndTheFlowSurvives`,
`TestTheLoginBridgeLeavesHostLoopbackClosed`, `TestWithoutTheBrowserKeyThereIsNoBridge`,
`TestTheLoginBridgeDiesWithSnug`, `TestTheLoginBridgeRefusesWithoutADisplay`,
`TestTheShimAndFIFOAreReadOnlyOrScoped`.

Not CI-able (`scripts/`): `0035-claude-login-through-the-browser.sh` (the real
claude and browser; the host credential file byte-identical before and after;
prints measurements (b) and (e)) and `0036-another-uid-cannot-deliver-the-callback.sh`
(needs a second uid).
