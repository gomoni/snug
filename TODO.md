# TODO

Only things that are genuinely outstanding. Anything already true of the code
belongs in CLAUDE.md or the code itself, not here.

## Postponed by decision

### Parameterised profiles

Deliberately deferred to a later stage — not rejected. It touches the identity
rule, which is where commutativity and idempotence live, so it is not something
to attach to the side of a milestone.

The shape, from the owner:

```
[[profile.-srv-rw]]
rw_dirs = /srv, /foo, /bar
```

Two things worth keeping from the discussion:

- **Why profiles and not CLI flags.** The obvious cheap alternative is
  `snug --ro /data --rw /build`, which needs no change to the model at all. It
  was rejected, correctly: *"bwrap itself is a powerful tool, yet humans can't be
  expected to write all the parameters by hand. The point of this tool is to
  enable a policy which can be specified by a mere human."* A flag you retype
  every invocation is bwrap with better spelling — ad-hoc, unreviewable,
  uncomposable, and gone when the shell history scrolls. The product is a named,
  reusable, reviewable policy. Do not solve this with flags.
- **The identity insight.** If a profile instance's canonical name ENCODES its
  arguments (`rw:/srv`, or `-srv-rw` in the sketch above), identity stays a
  single string. `expand`'s set-based dedup keeps working, so `rw:/srv` twice is
  one member and `rw:/srv` vs `rw:/data` are two — commutativity and idempotence
  survive untouched. That is far cheaper than making identity `(name, args)`,
  which would put a fingerprint on the core property tests.

**The design note is `docs/PARAMETERISED-PROFILES.md`. Read it before starting.**
Headline: the sketched example is not actually parameterisation — a profile
granting /srv, /foo and /bar is an ad-hoc list of grants wanting a name, and
that already works today by writing `~/.config/snug/profiles.d/mine.toml`. The
identity insight holds, with three provisos. Arguments must never come from
environment variables (direnv would let a repo author its own boundary).

## Pending

### Rename the `dotdot` profile to `parent-ro`

`dotdot` is cute and opaque. `parent-ro` says what it does and matches the `-ro`
suffix already used by `git-ro`. Rename everywhere, including `docs/DESIGN.md`,
which also calls the concept "access ..".

Held back only because a redteam run was in flight and renaming a profile
mid-run would produce phantom "unknown profile" failures in its report. Do it
once that lands.

### Prompt could show an unusually wide profile set

`PS1` is `🔒 snug:\w\$ `. A marker when something wide is active — `etc-full`
today, `net-host` or `x11` later — would make a permissive sandbox visible at a
glance rather than only in `--dry-run`.

## Independent bugs found while reviewing that idea

Neither is about parameterisation; both stand on their own.

### **[latent security]** A symlink in the target can divert a grant

`Resolve` canonicalises the host side of every bind, so a grant of
`{target}/build` — where a previous sandbox run left `build -> ~/.ssh` — would
bind `~/.ssh` into the sandbox. Not reachable today (no builtin uses a
`{target}`-relative subpath grant) but live the moment anyone writes one.

Fix sketched in `docs/PARAMETERISED-PROFILES.md`: refuse a grant at or below the
target whose `EvalSymlinks` result differs from the lexical join under the
canonical target. Comparing against the lexical join rather than against the
path itself is what avoids false positives from `/home -> /var/home`. Apply the
same rule to `{host_tmpdir}`.

### `ctx.Home` is never canonicalised

The target is `EvalSymlinks`'d and fail-closed; `$HOME` is used verbatim. Host
sides of `{home}/...` grants get canonicalised by `add()`, the guest side does
not. Fix is one call in `Resolve`. Expect a golden argv diff on any host where
`$HOME` traverses a symlink — correct, and to be reviewed as a security change.

## Known gaps in what the docs claim

Both are documented where they bite; listed here so they are not forgotten.

- **`--config` and privileged-grant gating do not exist.** DESIGN §2.7 describes
  them; `profile.Profile.Trusted` is set and never read. Consequence found by
  the redteam agent: `$XDG_CONFIG_HOME` is trusted unconditionally, so pointing
  it at a checked-out repository loads that repository's profiles. Low severity
  — it is the host user's own env var, not something the sandboxed agent
  controls. CLAUDE.md invariant 3 states the real behaviour.
- **Seccomp does not cover non-native architectures.** The x86_64 i386-compat
  path falls through to ALLOW, so a 32-bit binary bypasses the filter. Closing
  it means denying the compat arch outright, which breaks 32-bit binaries;
  the trade was taken deliberately and is documented in
  `internal/sandbox/seccomp.go`. (`clone3` and the x32 ABI WERE gaps and are now
  closed — clone3 is denied outright since classic BPF cannot read its flags,
  and x32 syscall numbers are rejected by their high bit.)
