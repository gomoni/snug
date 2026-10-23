# Variables

As usual with computers, the concept of variables, symbols or special
characters appears sooner or later. snug supports special placeholders such as
`{home}` and `{target}`, which are called _variables_. All in all this is only
simple string _interpolation_: each placeholder is replaced by its actual
value.

Note that despite `{home}`, environment variables such as `$HOME` are not
expanded.

| variable | value |
|---|---|
| `{target}` | the directory given on the command line, symlinks resolved, see [Host symlinks](filesystem.md#host-symlinks) |
| `{target_parent}` | the parent of `{target}` because `@parent-ro` existed forever in `snug` |
| `{home}` | your account's home directory (read by `getent passwd`), symlinks resolved, see [Host symlinks](filesystem.md#host-symlinks) and [The home directory](filesystem.md#the-home-directory) |
| `~/` | `{home}/`, only as the first two characters |
| `{lbrace}` | a literal `{` |
| `{rbrace}` | a literal `}` |
| `{colon}` | a literal `:` |

Variables expand in `ro`, `rw`, `tmpfs`, `symlink`, `optional`, the `path` of a
[`file`](filesystem.md#file) and in `environ` values. A `{` always opens a name, and an unknown
name is refused. There is no escaping; use the special variables shown above.

## The colon

> One does not use colon in his paths!

If you must (Open Build Service uses `:` both in URL identifiers and in
physical file names), be aware that `{colon}` makes a grant for a path
containing `:` possible: `ro = ["/home/u/home{colon}obs:/opt/obs"]`.

You can't use the `{colon}` hack for `merge` or `prepend`. It is refused, as
this is simply not possible and would break most tools.

| path to grant | spec | result |
|---|---|---|
| `/mnt/a:b` | `/mnt/a:b` | refused: `both sides must be absolute paths`; split into host `/mnt/a`, guest `b` |
| `/tmp/{foo}` | `/tmp/{foo}` | refused: `unknown variable {foo}` |
| `/mnt/a:b` | `/mnt/a{colon}b` | works; `/mnt/a:b` on both sides |
| `/tmp/{foo}` | `/tmp/{lbrace}foo}` | works; `/tmp/{foo}` on both sides |
| `/mnt/a:b` | `/mnt` | works; grants the whole parent |
| `/w/x:y`, snug run on it | `{target}` | works; `/w/x:y` on both sides |
| `/tmp/{foo}`, snug run on it | `{target}` | works; `/tmp/{foo}` on both sides |
