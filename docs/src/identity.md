# Identity

An identity pins the one account each tool acts as inside the sandbox. That
protects what is most worth protecting: no ssh key, git configuration, `gh`
login or token is mounted.

It is also simply convenient. Inside, each tool has exactly one account, and
it is the default: no `ssh -i`, no `gh auth switch`. A sandbox for your work
account cannot push as your personal one, so nothing can act as the wrong
account. Two accounts are two profiles, one per run:

```sh
snug -p work     ~/src/app
snug -p personal ~/src/app
```

`snug` pins each tool separately as it does not and cannot check that the ssh key
and the `gh` user are the same account. See [Rules](#rules).

snug **generates** every file involved from the `identity` key. It reads the
host's configuration as data and writes only keys that cannot run a program.

## `identity`

```toml
[profile.work]
include = ["@net"]

  [profile.work.identity.ssh]
  host  = "ghe.example.com"
  key   = "{home}/.ssh/work.pub"
  agent = "proxy"

  [profile.work.identity.git]
  name        = "Your Name"
  email       = "you@example.com"
  signing_key = "{home}/.ssh/work_sign.pub"

  [profile.work.identity.gh]
  host = "ghe.example.com"
  user = "you-at-work"

[profile.personal]
include = ["@net"]

  [profile.personal.identity.ssh]
  key   = "{home}/.ssh/personal.pub"
  agent = "proxy"

  [profile.personal.identity.gh]
  user = "you"
```

`identity` itself holds up to three optional blocks: `ssh`, `git` and `gh`.
Blocks from different profiles combine, but each block has one value per run.
A second, different value of the same block is refused, naming both profiles:

```text
$ snug -p work -p personal ~/src/app
snug: profiles "personal" and "work" pin different identity.ssh; select only one of them, or make the two blocks identical
```

### `identity.ssh`

| key | value | default |
|---|---|---|
| `host` | the host you push to | `github.com` |
| `key` | path to the **public** key ssh logs in with | none |
| `agent` | `"proxy"` or `"none"` | `"none"` |

With `agent = "proxy"`, `SSH_AUTH_SOCK` inside points at a filtering proxy
to your host agent. It offers only the pinned keys and no key material enters
the sandbox, and your other keys can be neither used nor listed.

snug generates `~/.ssh/config` and a `known_hosts` holding only `host`.
With the proxy, the generated git config also rewrites `https://HOST/` to
`git@HOST:`, so clones over https push over ssh.

### `identity.git`

| key | value |
|---|---|
| `name` | commit author name |
| `email` | commit author email |
| `signing_key` | path to the **public** key used for `gpg.format = ssh` signing |

snug generates `~/.gitconfig` from this block and points `GIT_CONFIG_GLOBAL`
at it. It never reads the host git config. snug generates it when an `ssh` or
`git` block is set and without either there is no `~/.gitconfig`, and `git commit`
inside has no author.

With `signing_key`, snug generates the signing configuration and turns
commit signing on. The private key stays in your host agent, so it needs
`identity.ssh.agent = "proxy"`, and the profile that sets `signing_key` must
also set `identity.ssh`. The proxy then offers both keys, and it cannot tell
a commit signature from a login: the signing key also logs in wherever it is
trusted. snug checks before starting that the agent will actually sign with
it.

`email` must be a single address.

#### Other git settings

A profile is not a configuration surface for the programs inside, so
`identity.git` holds only the three keys above. Write any other setting
(`init.defaultBranch`, `pull.rebase`) in a file of your own and grant it
read-only at `/etc/gitconfig`:

```toml
[profile.git-prefs]
ro = ["{home}/.config/snug/sandbox.gitconfig:/etc/gitconfig"]
```

git reads it below the generated `~/.gitconfig`, so the pinned keys still win.
`~/.gitconfig` and `~/.config/git/config` do not work for this.

### `identity.gh`

| key | value | default |
|---|---|---|
| `host` | the host `gh` gets a token for | `github.com` |
| `user` | the account whose token is staged | none |

snug stages that account's token in a private `hosts.yml` and sets
`GH_CONFIG_DIR` to its directory. `gh` itself must be inside; see
[Staging a single program](filesystem.md#staging-a-single-program-snugbin).

### Rules

- **`host` is written in both blocks.** `identity.ssh.host` and
  `identity.gh.host` are independent and nothing is inherited between them.
  Naming one while the other block is in use is an error. Just write the same
  value twice if it is the same host.
- **`gh.host` without `gh.user` is an error** as it would stage whichever
  account your host `gh` happens to be logged in to.
- snug does **not** checks that the ssh key and the `gh` user are the same
  account. Inside the sandbox, check with:

  ```sh
  ssh -T git@github.com
  gh api user --jq .login
  ```
