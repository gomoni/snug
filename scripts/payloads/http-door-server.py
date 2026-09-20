#!/usr/bin/env python3
"""Serve a directory through a snug http door.

Run it as the payload of a sandbox whose profile declares one:

    # ~/.config/snug/profiles.d/webdemo.toml
    [profile.webdemo]
    description = "serve this directory to my own browser"
    listen_names  = ["web"]

    $ snug -p webdemo ~/src/site -- python3 examples/http-door-server.py
    $ snug proxy ~/src/site        # in another terminal; prints the URL

WHY THIS IS NOT `python3 -m http.server`. snug never forwards a port. It creates
the listening socket itself, on the HOST, before the sandbox starts, and hands
this process the already-listening descriptor — so a payload can only ACCEPT on
the door it was given and can never bind a second one. That is the whole
security property, and the cost is these forty lines.

Three details, each of which is a real failure if you leave it out:

  * The descriptor is a UNIX socket, not TCP. SimpleHTTPRequestHandler's logger
    does client_address[0], which raises IndexError on the empty peer address a
    unix socket has, and the door then answers 502 "malformed response".
  * We must NOT call UnixStreamServer.__init__: it binds and listens. The socket
    already exists and is already listening.
  * BrokenPipeError is ROUTINE here, not a bug. The door closes the backend
    connection when the human stops `snug proxy`, when its round-trip deadline
    passes, or when the browser goes away — and stock socketserver prints a
    frightening traceback for it.
"""
import http.server
import os
import socket
import socketserver
import sys

# The systemd socket-activation protocol snug speaks: LISTEN_FDS is a COUNT, and
# the descriptors are 3, 4, ... in the order LISTEN_FDNAMES names them. So one
# door means LISTEN_FDS=1 and the descriptor is fd 3.
LISTEN_FDS_START = 3


def door_fd(want=None):
    """The descriptor for door `want`, or the only one if a run has just one."""
    n = int(os.environ.get("LISTEN_FDS", 0))
    if n < 1:
        sys.exit("no LISTEN_FDS in the environment: run this as a snug payload, "
                 "under a profile with listen_names = [...]")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if want is None:
        if n > 1:
            sys.exit(f"this run has {n} doors ({', '.join(names)}); name one: "
                     f"python3 {sys.argv[0]} {names[0]}")
        return LISTEN_FDS_START
    if want not in names:
        sys.exit(f"no door named {want!r}; this run has {', '.join(names)}")
    return LISTEN_FDS_START + names.index(want)


class Handler(http.server.SimpleHTTPRequestHandler):
    def address_string(self):
        # A unix socket has no peer address; the stock logger indexes into it.
        return "snug-door"

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            # The door went away mid-response. Expected, not an error.
            self.close_connection = True


class DoorServer(socketserver.UnixStreamServer):
    def __init__(self, fd, handler):
        # BaseServer, deliberately: UnixStreamServer.__init__ would bind and
        # listen, and this socket is already bound and already listening.
        socketserver.BaseServer.__init__(self, None, handler)
        self.socket = socket.socket(fileno=fd)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


if __name__ == "__main__":
    fd = door_fd(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"serving {os.getcwd()} on inherited fd {fd}", flush=True)
    try:
        DoorServer(fd, Handler).serve_forever()
    except KeyboardInterrupt:
        pass
