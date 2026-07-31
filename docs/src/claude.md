# Running Claude Code

```bash
snug -p @claude -p @net ~/src/proj -- claude
```

Nothing in snug's model is agent-specific — an agent is just one more thing you
would rather not hand your `~/.ssh` to. `@claude` exists because it is a common
case worth smoothing.

## What it does

| | |
|---|---|
| the binary, settings, skills, plugins | mounted **read-only** |
| `.credentials.json`, `~/.claude.json` | staged as **writable copies** |
| `~/.claude/CLAUDE.md` | **generated** for this run |

Credentials are copies, not binds: a token refreshed inside goes to a tmpfs and
never reaches the host, and a compromised agent cannot rewrite your host
credentials. The cost, stated plainly: a token refreshed inside is lost when the
sandbox exits.

`~/.claude.json` is staged as well as the credentials because without it Claude
decides it has never been run and shows a login prompt.

## The injected CLAUDE.md

snug writes a `~/.claude/CLAUDE.md` **generated from the actual resolved policy**,
so a run whose network was refused truthfully says there is no network. Every
sentence in it removes a class of wasted turns — an agent that knows `~/.ssh` is
absent by design does not spend three turns trying to fix it.

## Adding an identity

`@claude` grants no git or ssh identity. Combine it with one of your own:

```bash
snug -p @claude -p gh-work -p @net ~/src/work-project
```

See [identities](identity.md) — and note that one sandbox gets one account.

## What it cannot reach

Your host session history, prior transcripts, other projects, and your MCP
servers. `~/.claude.json` carries MCP configuration, so the sandbox can *see*
that configuration, but the servers themselves are not mounted and their sockets
are not reachable — host-configured MCP tools generally will not work inside.
