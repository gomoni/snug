# scripts/

Programs a human runs against a sandbox, not code snug builds or imports.
Nothing here is on any import path, nothing here needs privileges, and each one
exists because a property is easier to *observe* than to argue about.

Every script is invoked by a numbered section of [`VERIFY.md`](../VERIFY.md),
which carries the output it produced on the development host. That is the point
of the pairing: the script is the instrument, VERIFY.md is the reading.

| script | run it | VERIFY.md |
|---|---|---|
| `http-door-server.py` | as the payload of a run whose profile declares a `listen_names` door | §20 |
| `pid-nesting.py` | twice — `inside` as the payload, `host` beside it | §21 |

`http-door-server.py` is also the answer to "how do I serve something from in
here", because `python3 -m http.server` cannot be: snug never forwards a port,
it hands the payload a socket that is already listening on the host.
