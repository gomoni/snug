# Profile format

Profiles are TOML, in `~/.config/snug/profiles.d/*.toml`. Decoding is **strict**:
an unknown key is a fatal error, never a silently ignored line.

```toml
[profile.example]
description = "shown by `snug profile list`"
include     = ["@net", "@git-ro"]     # compose; expands as a SET
ro          = ["/srv/data"]
rw          = ["/srv/build"]
tmpfs       = ["{home}/.cache/mytool"]
optional    = ["/srv/data"]           # skip silently when absent on this host
env         = ["EDITOR", "PAGER"]     # re-admit host variables past --clearenv
path        = ["{home}/.local/bin"]   # add to PATH; grants nothing on its own
symlink     = [{ at = "/bin", target = "usr/bin" }]

network     = "egress"                # "isolated" | "egress" | "host"
dns         = true
publish     = [3000]                  # host 127.0.0.1 -> sandbox
address     = "10.13.13.2/24"
gateway     = "10.13.13.1"
mtu         = 1500

podman      = "socket"                # "off" | "socket" | "build"

  [profile.example.identity]
  gh_user   = "you"
  gh_host   = "github.com"
  git_name  = "Your Name"
  git_email = "you@example.com"
  ssh_key   = "{home}/.ssh/id_ed25519.pub"
  ssh_mode  = "agent-proxy"           # "none" | "agent-proxy" | "host-agent"
```

## Variables

| variable | expands to |
|---|---|
| `{target}` | the sandboxed directory, canonicalised |
| `{target_parent}` | its parent |
| `{home}` | your `$HOME`, canonicalised |
| `{host_tmpdir}` | the per-project host directory `@tmp-shared` allocates |
| `~/...` | shorthand for `{home}/...` |

## Grant forms

`ro` and `rw` take a path, or `host:guest` to mount it somewhere else inside:

```toml
rw = ["{host_tmpdir}:/tmp"]
```

Access **joins by maximum** at the same path, and grants at different depths
become separate mounts — so `ro` on a tree plus `rw` on part of it leaves the
rest read-only without any rule mentioning what to exclude.

## What the format cannot express

There is no `mask`, `deny`, `hide`, `remove`, `unset` or `exclude`, and no
priority or override field. The grant language cannot express subtraction. This
is not an omission to be filled in later — it is what makes composing profiles
safe without reading all of them.

Masking by overmount is refused too: a profile may not mount an empty tmpfs on
top of something another profile's grant exposes.

If you want *"X but not Y"*, X was too coarse. Grant the parts of X you meant, or
grant X read-only and the parts you want writable separately.

## Names

Any name you like, except: no leading `-` (indistinguishable from a flag), no
leading `@` (reserved for profiles snug ships), no comma (they separate names in
`$SNUG_PROFILES`), no colon (reserved for a parked design where profiles take
arguments), no whitespace, and not empty.
