// Command snug runs a command inside an unprivileged bubblewrap sandbox that
// starts out sharing nothing.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"snug/internal/policy"
	"snug/internal/profile"
	"snug/internal/sandbox"
)

// Exit codes are sysexits-flavoured so snug's own failures stay distinguishable
// from the payload's, whose code is propagated verbatim.
const (
	exitUsage    = 64
	exitUnavail  = 69
	exitInternal = 70
	exitPolicy   = 77
)

type config struct {
	profiles  []string
	target    string
	command   []string
	dryRun    bool
	readOnly  bool
	noSeccomp bool
	noDefault bool
	iKnow     bool
	verbose   bool
}

func main() {
	argv := os.Args[1:]

	// Subcommands first. They are reserved words; to sandbox a directory that
	// happens to be named one of them, write it as a path: `snug ./config`.
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		switch argv[0] {
		case "doctor":
			os.Exit(doctor())
		case "profile":
			os.Exit(profileCmd(argv[1:]))
		case "config":
			os.Exit(configCmd(argv[1:]))
		case "help":
			usage()
			os.Exit(0)
		}
	}

	cfg, err := parseArgs(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n\n", err)
		usage()
		os.Exit(exitUsage)
	}
	os.Exit(run(cfg))
}

func usage() {
	fmt.Fprint(os.Stderr, `snug — run a command in a sandbox that shares nothing by default

usage:
  snug [flags] [dir] [-- command ...]     run a sandbox on dir (default: .)
  snug profile list                       list available profiles
  snug profile show NAME                  show what a profile grants
  snug profile tree [NAME...]             show which profiles imply which
  snug profile dot [NAME...]              the same as a graphviz graph
  snug config                             show the resolved configuration
  snug doctor                             check whether this host can run snug

flags:
  -p, --profile NAME   add a profile (repeatable; order is irrelevant)
      --no-default     start from nothing instead of the default profile
                       (-p adds to the default; --no-default replaces it)
      --read-only      demote every writable grant to read-only
      --no-seccomp     run without the seccomp filter (debugging; weakens defence in depth)
      --i-know         acknowledge a knowingly-large hole (required by net-host)
  -n, --dry-run        print the resolved policy and the bwrap command, run nothing
  -v, --verbose        audit lines from the ssh-agent proxy
  -h, --help           this

Profiles only ever relax the sandbox. To grant less, select fewer profiles;
there is no key that takes something away. See docs/DESIGN.md.
`)
}

func parseArgs(argv []string) (config, error) {
	cfg := config{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			cfg.command = argv[i+1:]
			return cfg, nil
		case a == "-p" || a == "--profile":
			if i+1 >= len(argv) {
				return cfg, fmt.Errorf("%s needs a profile name", a)
			}
			i++
			cfg.profiles = append(cfg.profiles, argv[i])
		case strings.HasPrefix(a, "--profile="):
			cfg.profiles = append(cfg.profiles, strings.TrimPrefix(a, "--profile="))
		case a == "--no-default":
			cfg.noDefault = true
		case a == "--read-only":
			cfg.readOnly = true
		case a == "-v" || a == "--verbose":
			cfg.verbose = true
		case a == "--i-know":
			cfg.iKnow = true
		case a == "--no-seccomp":
			// Weakening lives on the CLI, never in a profile: a human may
			// lower defences, a config file may not (DESIGN §2.3).
			cfg.noSeccomp = true
		case a == "-n" || a == "--dry-run":
			cfg.dryRun = true
		case a == "-h" || a == "--help":
			usage()
			os.Exit(0)
		case strings.HasPrefix(a, "-"):
			return cfg, fmt.Errorf("unknown flag %q", a)
		default:
			if cfg.target != "" {
				return cfg, fmt.Errorf("more than one directory given (%q and %q)", cfg.target, a)
			}
			cfg.target = a
		}
	}
	return cfg, nil
}

func run(cfg config) int {
	reg, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

	// -p ADDS to the default rather than replacing it. `snug -p git-ro` means
	// "the usual sandbox, plus my git config" — which is both what the flag's
	// help text says and the only reading consistent with the model, where
	// naming a profile can never take anything away. --no-default is how you
	// start from nothing.
	selected := defaultProfiles()
	if cfg.noDefault {
		selected = nil
	}
	selected = append(selected, cfg.profiles...)
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "snug: no profile selected, so nothing at all is granted — "+
			"a sandbox with no profile cannot run anything.\n"+
			"      Drop --no-default, or name a profile with -p. See: snug profile list")
		return exitPolicy
	}

	target := cfg.target
	if target == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}

	env := policy.OSEnviron{}
	home, _ := os.UserHomeDir()
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	command := cfg.command
	if len(command) == 0 {
		// Not a login shell: `bash -l` sources the host's /etc/profile.d, whose
		// scripts assume a full desktop session and emit noise (or worse, try to
		// reach services that are deliberately absent). The environment the
		// sandbox needs is set explicitly by the policy anyway.
		command = []string{shell}
	}

	hostTmp := ""
	if need, err := needsHostTmpDir(reg, selected); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	} else if need {
		hostTmp, err = prepareHostTmpDir(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitPolicy
		}
	}

	ctx := policy.Context{
		Target:          abs,
		HostTmpDir:      hostTmp,
		Home:            home,
		Shell:           shell,
		Term:            os.Getenv("TERM"),
		Lang:            os.Getenv("LANG"),
		TZ:              os.Getenv("TZ"),
		Command:         command,
		LegacyTIOCSTI:   legacyTIOCSTI(),
		HostNameservers: hostNameservers(),
		KnownHosts:      knownHostsFor(identityHost(reg, selected)),
		PinnedPubKey:    pinnedPubKey(reg, selected),
	}

	pol, err := policy.Resolve(reg, selected, ctx, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	// A knowingly-large hole needs a deliberate act, not just a profile name.
	// The warning is five lines because the cost genuinely is that large, and
	// because someone who reads it and proceeds has made an informed choice.
	if pol.Net.Mode == policy.NetHost && !cfg.iKnow {
		fmt.Fprintln(os.Stderr, `snug: refusing to share the host network namespace without --i-know.

      With host networking the sandbox can reach:
        - every service on your 127.0.0.1, including ones with no authentication
        - every abstract AF_UNIX socket — X11 included, which means it can log
          your keystrokes and screenshot any window on your desktop
        - the LAN, with the host's identity

      This is not a sandbox with networking; it is a process with a different
      filesystem view. If you meant "the sandbox needs internet", use the 'net'
      profile instead. To proceed anyway, add --i-know.`)
		return exitPolicy
	}

	claudeFiles(pol, home)

	idCleanup, err := startIdentity(pol, cfg.verbose, cfg.iKnow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	defer idCleanup()

	pol.Apply(policy.Clamp{ReadOnly: cfg.readOnly})

	args := pol.BwrapArgs(env.Uid(), env.Gid())

	if cfg.dryRun {
		dryRun(pol, args, cfg)
		return 0
	}

	code, err := sandbox.Run(pol, env.Uid(), env.Gid(), sandbox.Options{
		NoSeccomp: cfg.noSeccomp,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUnavail
	}
	return code
}

// hostNameservers reads the host's resolvers. Only the routable ones survive
// into the sandbox; see policy.NetPolicy.ResolvConf.
func hostNameservers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

// legacyTIOCSTI reports whether this kernel still allows the TIOCSTI ioctl. If
// it does not, snug can skip --new-session and the sandbox keeps job control.
// A missing knob means an older kernel where TIOCSTI is available.
func legacyTIOCSTI() bool {
	b, err := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if err != nil {
		return true // fail safe: assume the ioctl exists
	}
	return strings.TrimSpace(string(b)) != "0"
}
