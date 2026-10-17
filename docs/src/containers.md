# Containers

Passing the host's `docker.sock` into a sandbox means there is no sandbox any
more. `@net` has no power there: a container can mount anything from the host,
and `--privileged` works too.

Container workflows are too important to ignore, so snug does this instead:

- A podman engine starts in a sibling sandbox that shares the sandbox's
  network namespace, and so its `pasta` setup.
- The engine runs with more privilege than the sandbox, which it needs to
  work: its own user namespace with your whole subordinate uid and gid range.
- A filtering proxy sits between the sandbox and the engine. It refuses every
  operation the engine could perform but the sandbox itself could not.

## `podman`

The built-in profiles `@podman-socket` and `@podman-build` set the `podman`
key, include `@sys` and `@home`, and grant the host's `/etc/containers`
read-only.
See [Feature keys and built-ins](profiles.md#feature-keys-and-built-ins).

| value | effect |
|---|---|
| `"off"` | no engine |
| `"socket"` | an engine and a proxy; `CONTAINER_HOST` and `DOCKER_HOST` point at the proxy |
| `"build"` | as `"socket"`, plus image build support with a filtered option set |

## What a container can reach

- **Network:** the sandbox's own. With `@net` a container has egress;
  without it, none. Publishing a port (`-p`) is refused.
- **Files:** a bind mount (`-v`) is forwarded only if nothing in the sandbox
  can swap its source for something else before the container starts. This
  prevents a TOCTOU (time-of-check to time-of-use) attack.
  - A path the sandbox can read but not write, such as `/usr`, works.
  - The source must be an absolute path. `-v "$PWD":/work` mounts the target
    directory as `/work` inside the container.
  - A subdirectory of a writable target is refused. Mount the target and use
    the subdirectory inside the container, or grant the subdirectory as its
    own mount in a profile, with the target read-only:
    ```toml
    [profile.data-rw]
    ro = ["{target}"]
    rw = ["{target}/data"]
    ```
    Run it without `@target-rw`, which would make the target writable again:
    `snug --no-defaults -p @sys -p @home -p data-rw -p @podman-socket DIR`.
- **Storage:** see [Storage per target directory](#storage-per-target-directory).

## Client

The proxy filters the docker-compatible API, and `docker` is the client it
is written for. The `podman` client speaks podman's own API, of which the
proxy forwards only a part: `podman build`, `podman run -d`, `podman wait`,
`podman logs` and `podman rm` work, but `podman run` without `-d` is refused,
because it attaches to the container and the proxy does not forward attach.

## Storage per target directory

Every target directory gets its own container storage. Images, containers
and named volumes live in `$XDG_DATA_HOME/snug/engines/KEY/` (default
`~/.local/share/snug/engines/KEY/`), where `KEY` is a hash of the target's
path. Two different target dirs never see each other's images or volumes.

The storage persists after the run ends and is shared by every later run on the
same directory. snug sets no quota on it, and a run may use the images and
named volumes that earlier runs left there. Keeping each target's storage
separate is the boundary.

Containers belong to the run that created them. `snug` labels every container a
run creates, and refuses any request that names a specific container or exec
session unless it carries this run's label. That covers start, stop, kill,
exec, attach, logs, inspect, rename, rm, and every other per-container request.
Without the rule, a later run of the same project could start an earlier run's
container, exec into it as root and read what it holds.

When a run ends, its containers stop, but their records stay in the storage.
A later run still sees them in `docker ps -a` or `podman ps -a`, with their names, images,
commands and mounts, but gets a refusal for anything else:

```sh
$ podman start leftover
Error: snug refused this request: container leftover (0a7974e228db…) was not created by this sandbox run, …
```

Remove your containers before the run ends (`docker rm`), or reclaim the
whole storage later with `snug engine gc`.

## Host requirements

The engine needs delegated subordinate uid and gid ranges, configured
correctly. `snug doctor` reports whether they are. `snug fix subuid` prints
the ranges this host needs, and `snug fix subuid -w` writes them to
`/etc/subuid` and `/etc/subgid`.
