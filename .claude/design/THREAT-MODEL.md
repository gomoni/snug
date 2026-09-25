# snug — threat model: goals and non-goals

**Status: authoritative.** This is the document that says what snug is *for*.
Part 1 sketched goals and part 2 non-goals. When a claim elsewhere in the tree
disagrees with this file about what snug protects, this file is right and the
other claim is stale — fix it.

## 0 What this document is

snug began as `agent-sandbox.sh`: a way to run `claude` without handing it
`~/.ssh` and access to other files. The asset it protects has not changed
since.

> It protects access to the user's filesystem unless an explicit named hole is
> dug in.

[xkcd 1200](https://www.xkcd.com/1200/) is the whole argument. The valuable
things on a personal machine are not `/` and not the root password; they are
`~/.ssh`, `~/.aws`, the browser profile, the keyring, the other projects, the
documents — the files that are *yours*. Neither classical unix permissions nor
advanced Linux systems like SELinux protect the user's data.

At the same time — for programs running inside the sandbox — it should look
like there is NO sandbox at all, and that it runs inside a stripped-down Linux
system.

## 1 The protected asset

"Host state" is everything the user has on the machine that a sandboxed program
should not be able to read, alter, or act through:

- **Files** — the home directory and everything under it that a profile did not
  name: credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`), other
  projects, documents, shell history.
- **Identity** — the ability to sign, push, or authenticate *as the user*: ssh
  keys, git/GitHub credentials, cloud tokens, the ssh-agent, API keys in the
  environment.
- **Loopback and desktop surface** — host services on `127.0.0.1`, the Wayland/
  X11 socket, the session D-Bus, PulseAudio: each a route to keylog, read the
  keyring, or drive host processes.
- **Persistence** — anywhere a program could write something the *host* will
  later execute: `~/.bashrc`, autostart, cron, `~/.local/bin` on `PATH`.
- **Host container engine as an escape vector** — a filtering proxy stands over
  a per-sandbox engine; the host's own engine never sees a client request.

`org.freedesktop.systemd1` on the session D-Bus bus is the sharpest instance of
the desktop-surface row above: it can start a transient unit *outside* the
sandbox — a complete escape — which is why no D-Bus profile ships (§3.4).

The base state is an empty tmpfs root, an empty network namespace, and an empty
environment. Nothing is inherited. Every one of the goals below is a mechanism
that keeps some slice of host state out of the sandbox unless a profile — a
*named hole* — explicitly grants it.

### Goals

- **G1** Run an untrusted payload (a build, a test suite, a coding agent —
  Claude Code, Codex, aider, …) against one project directory with **no root,
  no setuid, no daemon, no unit files**. `snug` is a process; when it exits,
  nothing remains.
- **G2** Deny-by-default filesystem. The agent sees the project, the OS
  runtime, and exactly what a profile granted.
- **G3** The sandbox **cannot reach the host's loopback**. This is a hard
  requirement, not a nice-to-have. A *container* started through
  `@podman-socket` runs in the sandbox's **own** netns, so it is covered by
  this too — it reaches exactly what the sandbox reaches and no more (see
  [`ENGINE-NETNS.md`](ENGINE-NETNS.md) §0).
- **G4** Internet egress works by default when a `@net` profile is selected;
  fully-offline is the *absence* of that profile, so it is trivially
  achievable and cannot be accidentally re-enabled.
- **G5** Works inside `distrobox`/containers with nested user namespaces.
  Where a capability is genuinely missing, `snug` **fails loudly with a
  diagnosis**, and never silently downgrades its security posture.
- **G6** Host integration (ssh signing, container engine, tmp sharing) is
  possible but goes through *filtering proxies* that `snug` owns, never
  through raw socket passthrough.
- **G7** Total transparency: `snug --dry-run` prints the resolved policy and
  the exact `bwrap` and `pasta` argv. If you cannot read what it is going to
  do, you cannot trust it.

## 2 Threats

### 2.0 The adversary

**The adversary is the agent process itself**, assumed to be one of:

- **T1 — a confused agent.** `rm -rf /` in the wrong directory, `git push
  --force` to the wrong remote, a runaway build eating the disk. The dominant
  real-world case.
- **T2 — a prompt-injected agent.** The agent read a `README.md`, an issue
  comment, a web page, or an npm postinstall script that told it to do
  something hostile: exfiltrate `~/.ssh/id_ed25519`, POST `~/.aws/credentials`
  to a webhook, add a cron entry, modify `~/.bashrc`, or `curl` the internal
  service on `127.0.0.1:3100`. **This is the case `snug` is designed for.**
- **T3 — malicious code the agent runs.** `npm install`, `pip install`,
  `cargo build`, `make`, a test suite. Same authority as the agent, no
  additional trust.
- **T4 — a hostile repository.** The project directory itself is
  attacker-controlled: symlinks pointing out of the tree, a `.snug/`
  directory trying to grant itself privileges, a `.git/hooks/` payload, a
  `Dockerfile` that bind-mounts `/`.

### 2.1 Access to $HOME is not granted by default

`snug` never grants access to most of `$HOME` via a bubblewrap-based sandbox.
That means `~/.ssh`, `~/.aws` and similar are never available. The same
principle covers `~/Documents` or `~/Downloads`.

Access is supposed to be minimal (`rw` only to the target dir) and explicit —
reading the target's parent, and with it every sibling project, takes selecting
`@parent-ro`, which a bare `snug <dir>` does not.

### 2.2 Access to secrets is proxied

A Linux development system without `ssh` is not very useful. The case of `ssh`
is solved by a builtin `ssh-agent` which exposes a subset of ssh keys to the
containment.

The same happens to `claude` tokens and settings: snug reinterprets most
well-known files — settings, hooks and so on.

### 2.3 Exposing secrets

`snug` NEVER exposes secrets via environment variables.

It SHALL avoid storing them as files where there is a way around it.

### 2.4 Hiding /proc and /dev

As an extra, access to the Linux filesystem is filtered and controlled.

### 2.5 Disallowing container escape

Normal `docker` or `podman` cannot work inside the sandbox and would be the
easiest escape vector.

`snug` solves this by providing a private `podman` engine, which uses the same
network namespace as the main sandbox.

## 3 Non-goals

`snug` is and will never be an all-in-one security tool. There are simply
threats this does not solve. Some may get implemented and move up in the
future, some won't.

Three more, stated briefly because they hold without a measurement to attach.
`snug` is **not** a defence against a determined human attacker with a shell:
it bounds the blast radius of software, and a human with time will find the
seam. It does **not** attempt to constrain *what* the agent does with the
authority a grant hands it — if you grant `ssh-agent` signing for a key, the
agent can push anything to anywhere that key can reach; scoping bounds the
identity, not the actions (§2.2). And it is **not** a general container
runtime: `snug` runs *one* command tree.

### 3.1 Network security

There is no proxy deployed, and code inside the sandbox can have unrestricted
network access.

So code can download bad podman images, mine bitcoin, try to hack HuggingFace
(DO NOT DO IT), or try to escape the containment using claude's remote
abilities. And `snug` itself is not going to prevent this.

**The remote abilities deserve naming, because they are the one non-goal on this
page that reaches beyond this machine.** With `@claude`, the sandbox holds a
working credential and egress — both deliberate; they are what the profile is
for — and Claude Code's session mesh reaches other sessions of the same ACCOUNT
over the network. Measured from inside a live sandbox: `curl` to
`https://api.anthropic.com/v1/messages` returns **405**, the wrong verb on a
POST endpoint, i.e. the request arrived.

It is not a sandbox escape — no filesystem, no kernel, no host process, no
namespace. It is an authority escape **iff the peer is less confined than the
sender**. Another snug session gains nothing; a cloud session runs in
Anthropic's own sandbox; a **Remote Control session on another machine** is the
sharp case, being unsandboxed with that machine's files and credentials.

**snug's boundary is the MACHINE. The session mesh is the ACCOUNT.** That is
why this is a non-goal and not a bug: closing it needs a filtering proxy over
TLS to Anthropic, distinguishing "the agent doing its job" from "the agent
messaging a peer" on the same host, same credential, same protocol — the shape
[`host-bridge.md`](../agents/host-bridge.md) already refuses for D-Bus, in
these words: *a filtering proxy that is 95% correct is a sandbox that is 0%
sound*. The
alternatives are removing the credential or the egress, which is removing the
feature.

**The LOCAL half is closed, structurally.** Cross-session messaging on one
machine is unix sockets, not the API — the opposite of the obvious hypothesis,
which is why it was measured rather than reasoned about. `/tmp` inside is snug's
private tmpfs, so `/tmp/cc-socks/` holds only this session's own socket. No
shipped profile puts anything else there, and the one thing that can — a
profile binding a host directory at `/tmp` — binds the directory it NAMES,
never the host's `/tmp` itself, so it does not open the channel either
(`test/integration/hosttmpvisibility_test.go` runs both arms against a decoy in
the host's real `/tmp`). It holds because the guiding principle paid out on a
surface nobody had looked at.

**snug SETS two of Claude Code's own controls, and they are not a boundary.**
The generated user-scope `~/.claude/settings.json` carries
`crossSessionInbound = "refuse"` and `isolatePeerMachines = true`
(`policy.ClaudeAuthoredSettings`). The host's own values for both are dropped,
like every other remote-surface key, so snug is overriding Claude Code's
*default* and not a carried human decision.

Both are enforced CLIENT-side. A payload holding the credential can reach the
API without the client, it controls its own command line (`--settings` layers
rather than replaces; `--setting-sources project,local` drops user scope), and
that file is writable inside the sandbox. So: a default, not a guarantee, and
invariant 5 is about not letting a user believe otherwise. The bounded thing
they do buy: against a prompt-injected model they are upstream gates in front
of the tools it would use, and `crossSessionInbound` is enforced in the
*receiving* client — so a payload in one snug sandbox cannot address a session
in another, at an enforcement point it does not hold. That closes
sandbox-to-sandbox lateral movement into a different `rw` target, a case §3.1
does not otherwise name.

**`permissions.deny` naming `SendMessage`/`ListAgents` is refused, and the
reason is the denylist argument, not R-SCALAR.** Measured in claude 2.1.246 the
outbound peer surface is at least three tools — `SendMessageTool`,
`SendFileTool` and `ObserverReport` — so denying two names leaves peer file
transfer open, which is the worse half. `policy.ClaudeExecutingKeys`' own doc
comment already refuses this shape: a denylist naming one spelling is bypassed
by the other, in the upstream's own documentation, with no attacker required.
`isolatePeerMachines` is upstream's gate over the whole surface, message and
file transfer together, and it is `bypassImmune` — the check survives
bypass-permissions mode and cannot be auto-approved by the classifier.

Project scope authors nothing, and that is measured rather than chosen: a
repo-scope value may only *tighten* ("a repo may only tighten, so your own
\"accept\" cannot override it"), so the user-scope value already applies and
the same claim in three files would be three things to keep true.

### 3.2 Resource management

`snug` itself does not control filesystem quotas, rlimits, or cgroups.

### 3.3 Mutable state

`snug` is not a hermetic tool. By default it gives you write access to the
target directory, and the embedded podman engine persists its storage per
target directory too.

The scenario in which a first run leaves an _evil_ payload (like a CLAUDE.md or
a bad OCI image) that a subsequent run then uses is not considered a breach.
Unless such payloads allow a containment escape, they are fine from the tool's
point of view.

A run that pulls or builds a bad image leaves it in the store, and a later run
on the same target may use it. That gains no host reach the later run's own
policy did not already grant, which is why it is a non-goal rather than a
threat. The store is keyed on the target alone, so selecting fewer profiles
does not give you a clean one — deleting the store directory does.

### 3.4 User-provided holes

Passing in a socket that snug does not control is outside the tool's scope. In
general `snug` very rarely refuses a configuration because it is insecure — the
one refusal that is a judgement rather than a conflict is a target sitting
directly in `$HOME`, or in any directory a profile replaces with an empty
tmpfs.

In other words, feel free to grant access to the D-Bus socket — just do not be
surprised when this leads to a containment escape.

**There are two places an attacker could stand, and conflating them has
already cost review rounds.** Inside the sandbox is T1–T4 (§2.0); everything
in snug is aimed there. Outside it, writing profiles, is a human — invariant 3
puts the trusted profile set outside the sandboxed material precisely so that
this human, and not the payload, decides what is granted, and snug has no
opinion about what they decide. A profile that grants too much is not a snug
defect, and neither is a typo, a copy-paste, or a profile that is simply
wrong: `rw = ["{home}"]` really does hand over the real `$HOME`, and both are
**user-inflicted**.

**Why this is not a cop-out.** snug already refuses in three shapes, and none
of them is a veto over what a human may want:

- **Mechanism.** The thing cannot be represented or transported. A NUL in an
  `environ.set` value authors a bwrap flag; a newline forges a row on a screen
  a human trusts; a hand-written separator inside a list value smuggles an
  empty element. Refusing here is not policy — it is snug declining to lie
  about what it did.
- **Ownership.** snug writes `HOME`, `PATH`, `PS1`, `SNUG_PROFILES` itself. A
  profile that could write them could unmake snug's own guarantees,
  `--dry-run` included, so no profile may.
- **Type.** `environ.sanitise` on `MANPATH` would ADD directories, because an
  empty element there is an operator ([`ENVIRONMENT-VARIABLES.md`](ENVIRONMENT-VARIABLES.md) §3.3).
  Refusing is snug declining to perform an operation it knows does the
  opposite of what it claims.

What is NOT in that list is any refusal of the form *"this grant is
dangerous, so you may not have it"*. Issue #44 removed the one place snug had
drifted into saying it: three environment denylists, converted to
annotations.

**What replaces the refusal is disclosure.** The roster
(`internal/policy/envtypes.go`) is **what snug KNOWS, not what it permits**,
and every measurement it holds is owed to the human as an annotation on
`--dry-run` and `snug profile show`. The two failure modes are asymmetric and
must stay so: **incomplete is expected and honest** — a name snug has never
been taught about renders `← unchecked`, and the absence of a mark must never
read as approval; **wrong is a defect** — a row saying a value is inert when
it is executed is a lie in the one artifact a human uses to decide whether to
run the sandbox.

**Two limits worth stating so nobody reasons past them.** The payload owns its
own environment: a profile handing over a clean `GIT_CONFIG_GLOBAL` does not
stop the payload setting `GIT_CONFIG_KEY_0` for itself, and a writable `$HOME`
reaches the same hijack through `~/.bashrc`. What snug owes is narrower — the
`sanitise` rule, that the environment snug ITSELF hands over must not ship the
override pre-installed. And **"you get what you configure" is not available
to us about our own profiles**: `@claude`, `@git` and `@podman-socket` are
snug's material, so a shipped grant that hands over more than its abuse
comment claims is a finding against snug, which is what `checkBuiltinEnvRoster`
holds a builtin to a stricter rule than a human's profile for.

### 3.5 Sibling access

Two same-uid siblings inside one sandbox reach each other's fds and memory
through `/proc/<pid>/fd/N` and `/proc/<pid>/mem` — neither is syscall-shaped, so
no seccomp filter can name them. A file another payload holds open can be
re-opened with its contents intact, including a pipe, a memfd, a deleted file
and an unnamed temporary one; its memory can be read *and written*.

This follows from two payloads sharing one pid namespace under one uid, and it
holds for as long as that is what a sandbox is. It is not waiting on a fix, and
the seccomp filter is not a partial answer to it: what the filter's refusal of
`pidfd_getfd` keeps out of a sibling's reach is an open *socket*, which procfs
cannot re-open, and nothing else.

There is a structural answer — snug's own init inside a nested pid namespace, so
that co-resident payloads cannot see each other's processes at all. That is an
idea and not a plan: it is not scheduled and it is not promised here. Until it
exists, everything running inside one sandbox is one trust domain. Two payloads
that must not reach each other need two sandboxes.

**One level out, the same reasoning gives the sandbox's OWNER everything.** A
process running as the uid that started snug reaches inside with `nsenter`,
`/proc/<pid>/root` and a debugger, because the kernel gates those by uid and
snug never added a second gate. The line runs between sandboxes, not between the
human and a process they started. This is why `state.json` may carry a sandbox's
init pid and its namespace ids and may not carry a command, an argv, an
executable path or a host-environment value a profile passed through: the first
pair is what a same-uid reader already has, the second set would be a secret
written to disk for their benefit (`internal/cli/runstate.go`,
`internal/cli/targetstate.go`).

**Going non-dumpable is not a way out of it, in either direction.**
`PR_SET_DUMPABLE = 0` reassigns the FILES under `/proc/<pid>` to uid 0 while the
DIRECTORY keeps the real uid, so a non-dumpable process stays visible and stays
attributable to its owner — measured, and recorded at
`internal/sandbox/teardown.go` because snug's own teardown sweep depends on it:
a payload cannot hide from the reap by making itself non-dumpable. The same
measurement is what makes a same-uid peer's reach unavoidable rather than
merely unfixed, and issue #61's matrix settled the other half of it — hardening
a target (`CapEff` 0, `NoNewPrivs` 1, `dumpable` 0) does not stop a peer holding
`CAP_SYS_PTRACE`; taking that capability away from the PEERS is the gate that
works, which is what `policy.StageCapDrop` does.

### 3.6 The operator's terminal

A payload the operator hands their terminal to — the ordinary interactive run,
where the sandbox writes to the same screen the human is watching — can write
anything a terminal reads as a command rather than as text. OSC 52 sets the
clipboard; other sequences ask the emulator for its title, its colours or the
cursor position, and the emulator's answer arrives on a descriptor the sandbox
can read. Sharing a terminal is sharing a bidirectional channel with whatever
program is drawing on it.

snug does not filter those bytes and will not. A filter over a terminal stream
is a catalogue of dangerous spellings that has to stay complete forever, and an
incomplete one grants the confidence without the protection.

What is closed is the run with no terminal on it — a hook, a CI job, a piped
invocation. There the sandbox leads a session of its own, so it cannot reach
the terminal that started snug at all, and nothing is given up in exchange
because nothing inside wanted a terminal. Anything else shares a terminal
because it was given one: a payload that must not reach the operator's screen
is run without one.

### 3.7 Linux

Kernel bugs are out of scope.

### 3.8 Knowledge about the sandbox

`snug` pretends it's a stripped-down Linux system, but never tries to hide that
it is one. The `~/.claude/CLAUDE.md` provided when the `@claude` profile is
enabled says so, snug's own files sit under the read-only `/snug` mount, and
some environment variables reveal it too.
