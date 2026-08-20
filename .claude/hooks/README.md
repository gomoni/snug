# Development scaffolding. Not part of snug.

These three files are hooks for one particular coding assistant, used while
developing this repository. **They are not snug, they are not a component of
snug, and they are not this project's model of security.** If you are reading
the design and trying to work out what snug believes, close this directory: the
answer is in [CLAUDE.md](../../CLAUDE.md) and
[.claude/design/INDEX.md](../design/INDEX.md), and it is the opposite of what is
in here.

This file exists because that confusion is real and was raised by the
maintainer (issue #203). The guiding principle says there is no deny rule in
snug *because there is nothing to deny — the thing you would deny was never
there*. Invariant 2's corollary says the urge to exclude is a design smell
pointing at the grant above it. Then a reader walks into this directory and
finds a path deny-list. Without this note, the reasonable conclusion is that the
project does not mean those sentences.

It does mean them. These are a different kind of control, for a different
problem, and the difference is the point:

|  | snug | these hooks |
|---|---|---|
| shape | grant, additive | deny-list, subtractive |
| enforcement | kernel — namespaces, mounts, seccomp | string matching on an argv |
| scope | every process in the sandbox | one tool of one harness |
| failure mode | refuses and says so | silently does not match |

## What they are for

Two host-damage incidents, both on 2026-08-19 (issues #185, #197): the host's
`~/.claude` was destroyed through a writable grant, and a name-matched kill
closed every Flatpak the maintainer had open and took down the rootless-podman
distrobox this project is developed inside.

**Both came from the main thread, not from a subagent.** That is the whole
justification for this layer and it is worth stating precisely, because it is
what no other layer covers: the rules in `.claude/agents/*.md` are read by
subagents, and neither incident involved one. A hook refuses whoever is asking.

- `deny-host-credential-paths.py` — refuses a destructive command aimed at the
  host's credential and configuration paths (#185).
- `deny-host-process-selectors.py` — refuses a kill or container command that
  picks its target by *matching* rather than by naming it (#197).
- `shellcmd.py` — the shared answer to "where can a command appear in this
  string", used by both.

## What they cannot do

Read this before trusting one, and note that the second point is the one people
get wrong:

- **They see the argv and nothing else.** Text moved off the argv is invisible —
  `--body-file`, a shell variable, a here-document body, an interpreter's stdin.
  That is equally true of a citation and of a real command.
- **They are registered for the Bash tool alone.** The identical operation
  performed through a file-editing tool is not graded at all. This is not
  theoretical: it is how the issue comment describing it was written.
- **They match a mistake, not an adversary.** A determined command evades them
  trivially, and the answer to a hostile agent is not a better matcher — it is
  not running one.

**They are a speed bump, not a boundary.** The measured record supports reading
them that way: across one morning they refused six pieces of harmless work and
made zero true catches (#199, since fixed). Whether a speed bump in this shape
is the right thing to keep at all is the open question on #203.

The structural answer, which does not depend on any of this, is `bin/blast-radius`
— *what is reachable from here* — plus `redteam.md`'s rule that any run creating
a sandbox pins `HOME` to a scratch directory. If that rule were reliably
followed, these hooks would be guarding an empty set.

## Scope: this repository only, deliberately

They are registered in `.claude/settings.json`, which is repo-local, so **they do
not exist for a session working in any other repository** — and `pkill -x bwrap`
is exactly as destructive from there.

That asymmetry is a decision, not an oversight (#203 item 4). Entrenching this
surface in the maintainer's own user-level configuration would spread scaffolding
that #203 is actively questioning, so the narrower scope stands while that ticket
is open. Anyone who wants the wider coverage today can copy the two entries into
their own settings with absolute paths; the hooks read nothing from the
repository.

## If you are changing something here

Don't, without checking #203 first — the live question is whether this directory
should exist, not how to make the matcher cleverer. In particular, "the hook
could also check X" is the wrong direction: every extension makes a subtractive
deny-list a larger part of a repository whose thesis is that confinement is
structural.

`test/guard/` owns the tests. Both hooks are mutation-checked, and after #199
assume your own fixtures are the weak point until a mutation proves otherwise —
two fixtures written there turned out to prove nothing while the suite stayed
green.
