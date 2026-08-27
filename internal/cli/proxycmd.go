package cli

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/httpdoor"
)

func proxyUsage() {
	fmt.Fprint(os.Stderr, `snug proxy — serve a sandbox's http door to your own browser

usage:
  snug proxy [dir] [-p PORT[:DOOR]]

Opens a door a profile DECLARED with listen_names. The sandbox cannot open one
itself, and nothing is reachable until this command runs.

  -p, --port PORT       serve on this HOST port
  -p, --port PORT:DOOR  ...and say which door, when the run declares several
  -p, --port :DOOR      the door, on its default port
  -h, --help            this

Host-first like docker's -p, with the one difference that only this side has a
port: a snug door is named, and there is no port inside the sandbox at all.

One door per command: opening a hole is a decision, and a second "snug proxy"
in another terminal is that decision made twice rather than once.
`)
}

// proxyCmd is the human's half of @http-proxy, and being a separate command run
// by a human is the security property rather than an ergonomic choice: the
// payload declares nothing, opens nothing and cannot reach this code — the
// sandbox has no access to the run state it reads.
func proxyCmd(argv []string) int {
	target, door, port, err := parseProxyArgs(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n\n", err)
		proxyUsage()
		return exitUsage
	}
	if target == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}
	// The same canonicalisation `snug attach` uses, for the same reason: a run
	// publishes its state under the target's REALPATH, so a symlink or a
	// trailing slash must not be able to miss a run that is right there.
	real, exists, err := canonicalAttachTarget(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: resolving %s: %v\n", abs, err)
		return exitUsage
	}
	if !exists {
		fmt.Fprintf(os.Stderr, "snug: no live snug run found for %s (it does not exist)\n", abs)
		return exitPolicy
	}
	st, err := selectLiveRun(real)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	if st.RunDir == "" {
		fmt.Fprintf(os.Stderr, "snug: the run sandboxing %s published no runtime directory, so its "+
			"http doors cannot be found. A run started by an older snug does not carry one.\n", real)
		return exitPolicy
	}

	doors, err := readHTTPDoors(st.RunDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: the run sandboxing %s declared no http door (%v).\n"+
			"      Add `listen_names = [\"web\"]` to a profile it selects, and start it again.\n",
			real, err)
		return exitPolicy
	}
	chosen, err := pickHTTPDoor(doors, door)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}

	// The escape sentence, on the human's own terminal, BEFORE anything binds.
	// Not only in the generated CLAUDE.md preamble: that file lives in the
	// project tree, which is writable, and the threat model's payload may be an
	// agent following instructions planted there. The party that would otherwise
	// relay this is the party assumed to be compromised.
	//
	// The URL is NOT here. It is printed from the door's Ready callback, once the
	// listener is actually bound — a URL printed before the bind is refused for a
	// moment, and is a lie outright if the bind then fails.
	fmt.Fprintf(os.Stderr, `snug: opening http door %q for the sandbox on %s.

      THIS IS A SANDBOX ESCAPE and snug does not bound it. Whatever the sandbox
      answers is served into YOUR browser, on an origin your browser treats as
      local. A page you already have open can reach this door too — snug refuses
      requests that admit a cross-site initiator and requires the token in the
      URL below, and those checks are the whole bound.

      The origin accumulates browser state (service workers, caches, permission
      grants) that outlives the sandbox. The address and token are new every run,
      so a stale one is never reached again.

`, chosen.Name, real)

	// --port moves the HOST side only. It is not a bound on anything: the door's
	// address is already unique per run, so the port is simply which number the
	// human types. A collision still REFUSES rather than relocating.
	if port != 0 {
		chosen.Addr = netip.AddrPortFrom(chosen.Addr.Addr(), uint16(port))
	}

	d, err := httpdoor.New(httpdoor.Config{
		Addr:     chosen.Addr,
		Token:    chosen.Token,
		DoorName: chosen.Name,
		// One fresh backend connection per client request — the door package's
		// requirement, and the dial is here because the socket path is run state
		// this package owns.
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", chosen.SocketPath)
		},
		Log: os.Stderr,
		Ready: func() {
			fmt.Fprintf(os.Stderr, "      Open:  %s\n      Stop:  Ctrl-C\n\n", chosen.URL())
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitInternal
	}

	// SIGINT and SIGTERM stop the door and nothing else. The sandbox keeps
	// running: this command is the human's, and closing it is how they close the
	// hole without ending the work going on inside.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := d.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUnavail
	}
	fmt.Fprintf(os.Stderr, "snug: http door %q closed. Nothing is listening for it now.\n", chosen.Name)
	return 0
}

// pickHTTPDoor resolves --door against what the run published.
//
// A run with one door needs no flag; a run with several REFUSES rather than
// picking, because "the first one" would be an arbitrary choice about which
// hole the human just opened.
func pickHTTPDoor(doors []httpDoor, want string) (httpDoor, error) {
	if len(doors) == 0 {
		return httpDoor{}, fmt.Errorf("this run published no http doors")
	}
	if want == "" {
		if len(doors) == 1 {
			return doors[0], nil
		}
		names := make([]string, len(doors))
		for i, d := range doors {
			names[i] = d.Name
		}
		return httpDoor{}, fmt.Errorf("this run declares %d http doors (%s) — name the one to "+
			"open with --door, because which hole gets opened is not something snug should "+
			"guess at", len(doors), strings.Join(names, ", "))
	}
	for _, d := range doors {
		if d.Name == want {
			return d, nil
		}
	}
	names := make([]string, len(doors))
	for i, d := range doors {
		names[i] = d.Name
	}
	return httpDoor{}, fmt.Errorf("this run declares no http door named %q; it has %s",
		want, strings.Join(names, ", "))
}

// splitPortSpec parses docker's shape, host-first: "8080", "8080:api", ":api".
//
// The deliberate difference from docker's `-p 8080:80` is that only ONE side is
// a port. A snug door is NAMED, and there is no port inside the sandbox at all —
// the payload is handed a descriptor, so there is nothing for the right-hand
// side to be except which door.
func splitPortSpec(spec string) (port int, name string, err error) {
	raw, name, _ := strings.Cut(spec, ":")
	if raw == "" && name == "" {
		return 0, "", fmt.Errorf("--port %q names neither a port nor a door", spec)
	}
	if raw == "" {
		return 0, name, nil // ":api" — that door, default port
	}
	n, cerr := strconv.Atoi(raw)
	if cerr != nil || n < 1 || n > 65535 {
		return 0, "", fmt.Errorf("--port %q: %q is not a port number in 1..65535. The port is "+
			"the HOST side; a door is named, not numbered, and has no port inside", spec, raw)
	}
	return n, name, nil
}

func parseProxyArgs(argv []string) (target, door string, port int, err error) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-h" || a == "--help":
			proxyUsage()
			os.Exit(0)

		case a == "-p" || a == "--port":
			if i+1 >= len(argv) {
				return "", "", 0, fmt.Errorf("%s needs a port, or PORT:DOOR", a)
			}
			i++
			port, door, err = splitPortSpec(argv[i])
			if err != nil {
				return "", "", 0, err
			}
		case strings.HasPrefix(a, "--port="):
			port, door, err = splitPortSpec(strings.TrimPrefix(a, "--port="))
			if err != nil {
				return "", "", 0, err
			}
		case strings.HasPrefix(a, "-"):
			return "", "", 0, fmt.Errorf("unknown flag %q", a)
		default:
			if target != "" {
				return "", "", 0, fmt.Errorf("more than one directory given (%q and %q)", target, a)
			}
			target = a
		}
	}
	return target, door, port, nil
}
