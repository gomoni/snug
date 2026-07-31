# Containers and builds

```bash
snug -p @podman-socket -p @net ~/src/proj    # run containers
snug -p @podman-build  -p @net ~/src/proj    # ...and build images
```

`CONTAINER_HOST` and `DOCKER_HOST` inside the sandbox point at a socket **snug
owns**. Behind it is a filtering proxy, and behind that a `podman` engine that is
private to this sandbox: its own store, its own runroot, dying with the sandbox.
Your host's images, containers and volumes are untouched and unreachable.

## The rule

> A container may bind a host path **if and only if the sandbox itself can see
> that path**, at the same or greater access.

Because the same resolved policy authors both the `bubblewrap` command line and
the proxy's decisions, those two cannot drift — it is a lookup, not a parallel
set of rules.

```console
$ podman run -v /etc:/etc alpine ...
Error: snug refused this request: this sandbox cannot see /etc as writable, so a
container may not mount it either. Grant it to the sandbox first, or mount a path
inside /home/you/src/proj
```

Refused, not silently stripped: a request that vanished would leave you unable to
tell a policy decision from a bug.

Also refused: `--privileged`, host/container namespace modes, device passthrough,
`--volumes-from`, alternate runtimes, published ports, sysctls, DNS and host
overrides, and log drivers that can write a file on the host.

## Building

`@podman-build` adds `podman build`, and it is a separate profile because a build
is a **second, larger option surface** — someone who only wants to run containers
should not have to carry it. A build can otherwise ask for host binds, a host
path as a named context, devices, host networking and its own seccomp profile,
none of which go through the container config.

Each of those is judged, and anything snug has not been taught about is refused
by name:

```console
$ podman build --network=host .
Error: snug refused this request: build parameter networkmode: "2" is not
permitted; a build may not join the host's network namespace
```

## The limitation to know about

Containers run in the **engine's** network namespace, not the sandbox's. So:

```bash
podman run -p 8080:80 nginx     # then, from the sandbox:
curl localhost:8080             # will NOT work
```

Use container-to-container networking. Making published ports reachable needs the
engine inside the sandbox's namespace, which is a later milestone.

## If `podman` does not work inside

On a host where `/usr/bin/podman` is a distrobox shim, the *client* cannot work
from inside the sandbox — it forwards over a bus the sandbox correctly cannot
see. snug detects this and says so, at length, naming the cause. The engine and
the proxy are fine; it is only the CLI binary. Any docker-compatible client, or
the API at `$CONTAINER_HOST` directly, works unchanged.
