# Networking

Each sandbox gets its **own network namespace** with a `pasta` helper. Egress is
unrestricted; the host's `127.0.0.1` is not merely blocked but *not expressible*
— the sandbox's loopback is a different loopback.

```bash
snug -p @net ~/src/proj
```

That namespace also isolates **abstract AF_UNIX sockets**, which is what keeps
X11 and D-Bus out for free. Filesystem sandboxing does nothing about those —
there is no path to not-mount.

## Offline is the absence of a profile

Not a setting, not a flag: you get no network by not selecting `@net`. It
therefore cannot be switched back on by adding something, which is the property
worth having.

## Profiles

| profile | what changes |
|---|---|
| `@net` | Full egress, IPv4 and IPv6. Host loopback unreachable. |
| `@net-anon` | As `@net`, but the sandbox gets a synthetic address instead of the host's, so it does not learn your LAN IP. |
| `@net-host` | **Shares the host's namespace.** Every service on your `127.0.0.1`, every abstract socket including X11 — which means keylogging and screenshots of your desktop — and the LAN as you. Requires `--i-know`. |

`@net-host` is not "networking with fewer restrictions"; it is a process with a
different filesystem view. It exists so that "I need to debug a host service"
does not become "so I stopped using snug".

## Publishing a port back to the host

Off by default. Opening it means naming the ports yourself, in your own profile:

```toml
[profile.myports]
include = ["@net"]
publish = [3000, 8080]     # bound to the host's 127.0.0.1 only, never the LAN
```

There is deliberately no "publish whatever the sandbox binds". That would let the
*sandbox* choose what appears on your loopback, and a prompt-injected agent could
squat `127.0.0.1:8080` ahead of your own dev server and intercept your browser.

A `@net-publish` profile that did exactly that used to ship — and it never
forwarded a single port, because pasta scans for bound ports once at its own
startup, before the payload exists. It was removed rather than repaired: a
capability that cannot work and should not work is one to stop offering.

## DNS

`/etc/resolv.conf` is **generated**, never bound. The host's may name
`127.0.0.53` (systemd-resolved), which the sandbox must not be able to reach;
only routable nameservers survive into the sandbox, and otherwise pasta forwards.

With no network profile, it is generated as an empty file with a comment, so
resolver libraries fail immediately and legibly instead of hanging for five
seconds.
