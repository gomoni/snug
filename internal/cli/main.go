// Package cli is snug's command-line implementation: flag parsing, profile
// loading, policy resolution, the identity and container proxies, and
// --dry-run's trust artifact. It used to be package main in cmd/snug, which
// meant none of it — including the credential/command-table whitelist in
// gitconfig.go and the credential staging in claude.go — could be imported or
// tested from anywhere else. cmd/snug/main.go is now a thin binary entry
// point that does nothing but call Main below.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/sandbox"
	"github.com/gomoni/snug/internal/stage"
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
	// profiles holds what -p named, already through the grammar: parseArgs is
	// one of snug's four doors into policy.ProfileName (the others are a TOML
	// table key, an `include` entry and the `defaults` setting). A name that
	// does not parse is a usage error here rather than an `unknown profile` from
	// the resolver several hundred lines later.
	profiles []policy.ProfileName
	target   string
	command  []string
	dryRun   bool
	// removed (snug stays minimal; bwrap is the swiss knife). dryrun.go
	noSeccomp  bool
	noDefaults bool
	iKnow      bool
	verbose    bool
}

// Main is the whole CLI, run from cmd/snug/main.go's own main(). It calls
// os.Exit itself and never returns, exactly as the package-main function it
// replaces did — see cmd/snug/main.go for why the split stops there rather
// than threading an exit code back through an extra return.
func Main() {
	argv := os.Args[1:]

	// Hidden verbs, dispatched before ANYTHING else — flag parsing, profile
	// loading, none of it. They are not subcommands: they do not appear in
	// --help, they are not profiles, and they are reachable only through the
	// re-exec chain internal/stage builds (P0 -> __stage-setup -> __stage-serve ->
	// __innetns -> bwrap). Each refuses immediately when the descriptors it
	// requires are absent (SUPERVISOR-DESIGN.md §4 Step 6), so invoking
	// one directly from a shell fails loudly rather than doing something
	// undefined with whatever fd 3 happens to be.
	if len(argv) > 0 {
		switch argv[0] {
		case "__stage-setup":
			exitOnStageError(stage.MainSetup())
		case "__stage-serve":
			exitOnStageError(stage.MainServe())
		case "__innetns":
			exitOnStageError(stage.EnterNetns(argv[1:]))
		}
	}

	// Subcommands next. They are reserved words; to sandbox a directory that
	// happens to be named one of them, write it as a path: `snug ./config`.
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		switch argv[0] {
		case "doctor":
			os.Exit(doctor())
		case "profile":
			os.Exit(profileCmd(argv[1:]))
		case "config":
			os.Exit(configCmd(argv[1:]))
		case "attach":
			os.Exit(attachCmd(argv[1:]))
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

// exitOnStageError is the hidden verbs' whole error handling: they are not
// user-facing commands, so there is no usage text to print, only "it failed
// and here is why". A nil err means the verb ran its one job to completion
// (MainServe returning after "exited" is sent, or EnterNetns's own syscall.Exec
// having failed to even reach a return); either way this call does not return.
func exitOnStageError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
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
  snug attach [dir]                       join a sandbox that is already running

flags:
  -p, --profile NAME   add a profile (repeatable; order is irrelevant)
      --no-defaults    select nothing at all to begin with
                       (-p adds to the defaults setting; --no-defaults declines it)
      --no-seccomp     run without the seccomp filter (debugging; weakens defence in depth)
      --i-know         acknowledge a knowingly-large hole (required by @net-host)
  -n, --dry-run        print the resolved policy and the bwrap command, run nothing
  -v, --verbose        audit lines from the ssh-agent proxy
  -h, --help           this

A leading @ marks a profile snug ships — "@sys", "@net", "@claude". Yours, from
~/.config/snug/profiles.d, are written without it, so a grant's origin is legible
wherever a profile name appears and the two sets can never collide.

A bare "snug <dir>" selects the defaults setting: @sys @home @cwd-rw @parent-ro.
See "snug config" for the effective list and where it came from.

Profiles only ever GRANT. There is no un-grant — not in a profile, not on the
command line, nowhere. To grant less, select fewer profiles. See .claude/design/INDEX.md.
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
			name, err := policy.NewProfileName(argv[i])
			if err != nil {
				return cfg, err
			}
			cfg.profiles = append(cfg.profiles, name)
		case strings.HasPrefix(a, "--profile="):
			name, err := policy.NewProfileName(strings.TrimPrefix(a, "--profile="))
			if err != nil {
				return cfg, err
			}
			cfg.profiles = append(cfg.profiles, name)
		case a == "--no-defaults":
			cfg.noDefaults = true
		case a == "-v" || a == "--verbose":
			cfg.verbose = true
		case a == "--i-know":
			cfg.iKnow = true
		case a == "--no-seccomp":
			// Weakening lives on the CLI, never in a profile: a human may
			// lower defences, a config file may not (INDEX §2.3).
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
	reg, bad, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	// FATAL here, and only here-shaped commands. See internal/cli/badfiles.go: this
	// is the path that starts a sandbox, and a sandbox assembled from whichever
	// profile files happened to parse is a silent downgrade.
	if err := refuseBadFiles(bad); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

	// -p ADDS to the `defaults` setting rather than replacing it. `snug -p
	// @git-ro` means "the usual sandbox, plus my git config" — which is both what
	// the flag's help text says and the only reading consistent with the model,
	// where naming a profile can never take anything away. (`snug -p @git-ro`
	// once replaced the selection instead, producing a sandbox with no /usr that
	// could not execute anything.) --no-defaults is how you start from nothing.
	selected, _ := defaultProfiles()
	if cfg.noDefaults {
		selected = nil
	}
	selected = append(selected, cfg.profiles...)

	target := cfg.target
	if target == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}

	// One live sandbox per target directory (issue #119). This is the earliest
	// point at which the target is knowable, and the refusal must start NOTHING
	// — no host tmp dir, no staged credentials, no ssh-agent or container proxy,
	// no stage, no netns, no bwrap — so the lock is taken here, before any of
	// that. A dry run creates nothing and must never be refused, so it takes no
	// lock. Invariant 5: the refusal is fatal and there is no fallback to a
	// second run.
	if !cfg.dryRun {
		unlock, err := lockTarget(abs)
		if err != nil {
			var busy *targetBusyError
			if errors.As(err, &busy) {
				// The named-fix refusal: another live run holds this target.
				fmt.Fprint(os.Stderr, busy.message(target))
				return exitUnavail
			}
			// A hard error (a runtime directory that fails the ownership,
			// mode or symlink guards secureSubroot enforces) is the same
			// refusal the per-run lock produces from startIdentity /
			// startContainers, and takes the same exit code — this path
			// simply reaches those guards earlier.
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitPolicy
		}
		defer unlock()
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
	} else if need && cfg.dryRun {
		// Name it, do not create it. A dry run that leaves a directory behind
		// contradicts its own first line, and the path is all --dry-run needs to
		// show what would be mounted. The ownership and symlink checks below the
		// MkdirAll are deliberately NOT run here: they inspect host state a dry
		// run has not touched, and failing on them would make --dry-run refuse a
		// policy the real run might well accept.
		hostTmp = hostTmpDirPath(abs)
	} else if need {
		hostTmp, err = prepareHostTmpDir(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitPolicy
		}
	}

	// Reading the host's git config can fail in ways that must not be silent —
	// no git installed, a file git refuses to parse — so it happens here, where
	// the error can still be reported, rather than inside the pure resolver.
	hostGit, err := hostGitValues(reg, selected, home, abs, cfg.verbose, cfg.dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
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
		HostGit:         hostGit,
		HostShims:       detectHostShims(),
	}

	pol, err := policy.Resolve(reg, selected, ctx, env)
	if err != nil {
		// Resolve's contract (see its doc comment): a Validate failure returns
		// the policy it refused ALONGSIDE the error, precisely so --dry-run can
		// show what was refused instead of just saying "no". Every other
		// failure returns a nil policy, so there is nothing to show. Either
		// way, a non-nil err means this policy must never be executed — it is
		// never run below, whichever branch fires.
		if cfg.dryRun && pol != nil {
			args := pol.BwrapArgs(env.Uid(), env.Gid())
			dryRun(pol, args, cfg, err)
		}
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
      filesystem view. If you meant "the sandbox needs internet", use the '@net'
      profile instead. To proceed anyway, add --i-know.`)
		return exitPolicy
	}

	// The run's own private directory, published for the whole run so `snug
	// attach` can find it — created on EVERY real run now, not only when
	// identity or containers need it (issue #61 part (c)/(e)). --dry-run
	// starts nothing, so it must not create one either (dryrun.go's ATTACH
	// block names the PATTERN it would use, never a directory that exists).
	//
	// This is a runtimeDir()-shaped refusal, and it is FATAL rather than a
	// warning: the alternative reading — "a debugging convenience must not
	// stop a sandbox from starting" — does not survive contact with
	// runtimeDir's own refusals, which are all "a directory snug owns is
	// wrong" (an ownership mismatch, a planted symlink, a mode a hostile
	// umask weakened), and invariant 5 says continuing past one of those is
	// exactly the shape "no silent downgrade" forbids.
	//
	// Registered here, BEFORE startIdentity/startContainers's own cleanups,
	// so LIFO defer ordering removes THIS directory LAST — after the
	// ssh-agent and container proxy sockets it holds have already been
	// closed by their own cleanups, not out from under a live listener.
	var runDir string
	if !cfg.dryRun {
		d, rerr := runtimeDir()
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n\n"+
				"      This run cannot publish its state, so `snug attach` could never find it —\n"+
				"      refusing to start rather than running a sandbox nothing else can reach.\n", rerr)
			return exitPolicy
		}
		runDir = d
	}
	defer func() {
		if runDir != "" {
			os.RemoveAll(runDir)
		}
	}()

	claudeFiles(pol, home, cfg.verbose)

	idCleanup, err := startIdentity(pol, cfg.verbose, cfg.iKnow, cfg.dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	defer idCleanup()

	ctrCleanup, err := startContainers(pol, cfg.verbose, cfg.dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	defer ctrCleanup()

	// Re-validate. Everything above this line ADDS mounts to a policy Resolve
	// already validated — the staged Claude credentials, the generated gh
	// hosts.yml, the ssh-agent and container proxy sockets — and it does so after
	// Resolve returned, so none of it had been through Validate at all. They all
	// go through policy.Replace and are therefore Authored, which is precisely
	// what makes them legitimate; running Validate again is how that claim gets
	// checked rather than asserted. It must be cheap and it must be silent on a
	// policy that was fine, so a passing run is byte-identical to before.
	if err := pol.Validate(env); err != nil {
		if cfg.dryRun {
			dryRun(pol, pol.BwrapArgs(env.Uid(), env.Gid()), cfg, err)
		}
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

	args := pol.BwrapArgs(env.Uid(), env.Gid())

	if cfg.dryRun {
		dryRun(pol, args, cfg, nil)
		return 0
	}

	code, err := sandbox.Run(pol, env.Uid(), env.Gid(), sandbox.Options{
		NoSeccomp: cfg.noSeccomp,
		// OnInfo publishes state.json once bwrap has reported its own
		// --info-fd answer. A failure here is warn-only, deliberately unlike
		// the runtimeDir() refusal above: by the time this callback runs, a
		// payload already exists (or is about to, on the staged topology),
		// and there is no clean way left in this architecture to un-start
		// one without reintroducing the parked-payload window this file's
		// own history (runStaged's doc comment) already removed on purpose.
		OnInfo: func(info sandbox.RunInfo) {
			if werr := writeRunState(runDir, pol, info); werr != nil {
				fmt.Fprintf(os.Stderr, "snug: this run will not be attachable (%v)\n", werr)
			}
		},
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
