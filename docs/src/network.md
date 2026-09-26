# Network

Every sandbox has its own network namespace with loopback only. For
internet access, include `@net`, which is `network = "egress"` and `dns = true`
(see [Feature keys and built-ins](profiles.md#feature-keys-and-built-ins)):

```toml
[profile.build]
include = ["@net"]
```

## Keys

| key | value | default | across profiles |
|---|---|---|---|
| `network` | `"egress"` | none | maximum (egress wins) |
| `dns` | boolean | `false` | any `true` wins |
| `mtu` | integer | pasta's default | must agree |
| `listen_names` | array of door names | none | union |

### `network`

`"egress"` connects the namespace to the internet through `pasta`, a helper
process outside the sandbox. From inside:

- the internet is reachable
- host loopback (`127.0.0.1`, `::1`) and every address the host owns are
  unreachable
- `ip addr` lists the addresses of **every** host interface — bridges, VPNs —
  which discloses the networks the host is attached to, without reaching
  them.

### `dns`

`true` generates an `/etc/resolv.conf` that forwards to the host's resolver.
It takes effect only with `network = "egress"`.

### `mtu`

Passed to `pasta` as `--mtu`. It takes effect only with `network = "egress"`.

## HTTP doors: `listen_names`

An HTTP door lets your host applications (like a browser) reach a server running inside the
sandbox. snug creates the socket and hands it in using the systemd
socket-activation protocol. The server accepts on it, and nothing reaches it
until you open the door with `snug proxy` on the host. It needs no
`network`.

```toml
[profile.web]
listen_names = ["web"]
```

- snug creates the listening socket on the host before the sandbox starts and
  passes it to the command with the systemd socket-activation protocol.
  `LISTEN_FDS` holds the count, `LISTEN_FDNAMES` the names in order.
- The descriptor is a Unix socket that is already listening. The server must
  accept on it instead of binding a port, so `python3 -m http.server` does not
  work. [`http-door-server.py`](https://github.com/gomoni/snug/blob/main/scripts/payloads/http-door-server.py)
  is a working example:

  ```sh
  $ cp http-door-server.py ~/src/site/
  # run HTTP server in a sandbox - note @net is not specified
  $ snug -p web ~/src/site -- python3 http-door-server.py
  # snug open the door
  $ snug proxy ~/src/site
  # here we are, Dave
  ```

- Nothing is reachable until you run `snug proxy DIR` on the host, which
  prints a URL carrying a one-time token.
- A door name is lowercase letters, digits and single interior dashes, at most
  32 characters.
- snug starts the command through a two-line `/bin/sh` script that sets
  `LISTEN_PID` to the command's own pid, which only the sandbox knows. The
  selection must grant `/bin/sh` (`@sys` does).
