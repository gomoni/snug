package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// sshProbeHost is the host name the probe resolves options for. It is in the
// .invalid TLD (RFC 2606), so it can never name a real machine, and `ssh -G`
// does no name resolution and opens no connection for it anyway — measured:
// 67ms, exit 0, no DNS traffic. No positive Host or Match pattern a human
// writes for a real machine matches it, so the probe returns the global
// section — plus every block whose pattern is negated (`Host * !x`), which
// matches this name too. See probeSSHConfig, WHAT IS CARRIED.
const sshProbeHost = "snug-probe.invalid"

// sshProbeTimeout bounds the probe. Issue #42 asks what happens when ssh
// hangs, and this is the answer: the run refuses and names the probe (#688
// F2). It is generous because the thing that can be slow is not ssh — see the
// Match exec paragraph on probeSSHConfig.
const sshProbeTimeout = 5 * time.Second

// sshProbe is what probeSSHConfig learned from this host's ssh. The zero
// value is a host with no ssh.
type sshProbe struct {
	binary  string           // the ssh asked, symlinks resolved
	chain   []string         // system-wide ssh_config files it reads
	top     string           // the top-level one among them, not an Include
	values  policy.SSHValues // whitelisted global values
	revoked []byte           // global RevokedHostKeys file; nil when it names none
	// revokedPath is where revoked was read from, for --dry-run only.
	revokedPath string
}

// probeSSHConfig asks this host's ssh two questions in one invocation: WHICH
// configuration files it reads, so snug can replace a spelling nobody wrote
// down (issue #42), and WHAT they resolve to, so the file snug writes in
// place of the host's can carry the non-executable half of it rather than
// throwing the host's crypto policy away (issue #43).
//
// WHAT IS CARRIED is what the host's ssh resolves for a name no Host or Match
// pattern matches: the whitelisted values, and the file RevokedHostKeys names,
// read here and staged by the policy. Host blocks for other names are not
// carried, except a pinned identity.ssh.host's (probeSSHPin). A block with a
// negated pattern (`Host * !x`, `Match !host x`) DOES match the probe name, so
// its values are carried and apply to x inside the sandbox, where the host's
// ssh never applies them to x. --dry-run's SSH block says so. No config file
// is parsed to tell the cases apart. A RevokedHostKeys file that
// cannot be read, or is not named by an absolute path, refuses the run: the
// sandbox's ssh would otherwise accept a key the host's has revoked.
//
// WHY ASK RATHER THAN LIST. policy.SystemSSHConfigPaths knows two spellings.
// A host that spells it a third way — FreeBSD's and Homebrew's
// /usr/local/etc/ssh, a /nix/store path — gets issue #40's failure back and
// gets it SILENTLY: ssh inside the sandbox dies with `Bad owner or
// permissions` naming a file the human never wrote, and snug's own SSH block
// says nothing, because it only speaks for a path that was actually replaced.
// A list that grows once per platform is a rule written somewhere it can be
// forgotten; asking ssh is cheaper than writing an ssh_config parser.
//
// WHAT IT COSTS, stated plainly because it is a new host-side effect and
// nothing else in snug has one of this shape:
//
//   - `ssh -G` PARSES THE INVOKING USER'S ~/.ssh/config, and a `Match exec
//     "…"` in it RUNS. Measured, not reasoned: a config carrying
//     `Match exec "touch …"` created the file under a bare `ssh -G host`.
//     There is no flag that skips the user's file but keeps the system one —
//     `-F` replaces the WHOLE chain (with -F /dev/null, measured, ssh reads
//     /dev/null and nothing else), and $HOME is not consulted at all: ssh
//     takes the home directory from getpwuid, so overriding the variable
//     changes nothing (also measured).
//   - So the probe runs whatever the HOST USER's own ssh config says, on the
//     host, at snug startup, once per run — once more when identity.ssh is
//     pinned, since probeSSHPin asks again for the pinned host. When the
//     sandbox's PATH ssh is another file, resolveSandboxSSH asks both
//     questions again with THAT binary, run on the host. That file is not reachable by
//     sandboxed material: no shipped profile grants ~/.ssh, and Validate
//     refuses any bind covering $HOME (#220), so a payload can neither write
//     the file nor plant an Include target it names. It is the user's own
//     file, run by the user's own ssh, exactly as `git push` over ssh would
//     run it a moment later — but it is snug that triggers it here, which is
//     why it is written down rather than left to be discovered.
//
// It asks the first ssh on the HOST user's PATH. The sandbox may run a
// different one; resolveSandboxSSH asks that one too (probeSSHBinary). A host
// with no ssh returns nothing, with nothing on screen. Any OTHER failure — a timeout, a probe that exits
// non-zero, a value snug cannot write back — REFUSES the run (#688 F2, F3):
// the sandbox's ssh would otherwise run on its compiled-in defaults, which on a
// crypto-policy host are weaker than the host's (measured: requiredrsasize 1024
// against the host's 2048, aes192-ctr and umac-64 back in the lists), and an
// `aside` the human sees only under -v is a silent downgrade.
func probeSSHConfig(home string, n *notes) (sshProbe, error) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return sshProbe{}, nil
	}
	p, err := probeSSHBinary(ssh, home, n)
	// The binary is named even on a refusal, so the caller can tell whether
	// the sandbox runs this same file.
	p.binary = resolveSSHBinary(ssh)
	return p, err
}

// probeSSHBinary is probeSSHConfig's question asked of one ssh binary.
func probeSSHBinary(ssh, home string, n *notes) (sshProbe, error) {
	// -G resolves and prints the configuration without connecting; -vvv makes
	// it name every file it read while doing so, and which of them an Include
	// pulled in (debug3, see parseSSHTopConfig). BatchMode keeps a probe from
	// ever becoming a prompt. One invocation answers both questions: WHICH
	// file (stderr) and WHAT IT SAYS (stdout).
	stdout, stderr, err := runSSHProbe(ssh, "-G", "-vvv", "-o", "BatchMode=yes", sshProbeHost)
	if err != nil {
		return sshProbe{}, sshProbeError(sshProbeHost, err, stderr)
	}
	chain := parseSSHConfigChain(stderr, home)
	top := parseSSHTopConfig(stderr, home)
	values, err := parseSSHValues(stdout)
	if err != nil {
		return sshProbe{}, err
	}
	revoked, err := readGlobalRevokedHostKeys(stdout)
	if err != nil {
		return sshProbe{}, err
	}
	if n.isVerbose() {
		if len(chain) == 0 {
			n.aside("snug: ssh named no system-wide config file\n")
		} else {
			n.aside("snug: ssh reads system-wide config from %s\n",
				policy.VisibleText(strings.Join(chain, " ")))
		}
		n.aside("snug: ssh config carried into the sandbox: %s\n", sshValuesLine(values))
	}
	return sshProbe{binary: resolveSSHBinary(ssh), chain: chain, top: top, values: values, revoked: revoked,
		revokedPath: globalRevokedHostKeysPath(stdout)}, nil
}

// resolveSSHBinary is an ssh path with its symlinks resolved, the form
// policy.Policy.SandboxSSHHost is in, so the two compare as strings. A PATH
// listing /bin before /usr/bin yields /bin/ssh, and the sandbox's lookup
// lands on /usr/bin/ssh through @sys's /bin symlink: unresolved, the two
// would differ for one file. When resolution fails the path is returned as
// found.
func resolveSSHBinary(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}

// readGlobalRevokedHostKeys reads the file `ssh -G` output names as
// RevokedHostKeys, or returns nil when it names none.
//
// A relative path refuses rather than being opened: it would be opened
// against snug's own working directory, which can be the sandboxed tree.
func readGlobalRevokedHostKeys(stdout string) ([]byte, error) {
	path := globalRevokedHostKeysPath(stdout)
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		return nil, revokedHostKeysError(path, errors.New("it is not an absolute path"))
	}
	data, err := hostread.Required(path, maxKnownHostsBytes)
	if err != nil {
		return nil, revokedHostKeysError(path, err)
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// globalRevokedHostKeysPath is the RevokedHostKeys value in `ssh -G` output,
// or "" when it is absent or none.
func globalRevokedHostKeysPath(stdout string) string {
	for line := range strings.SplitSeq(stdout, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		if key == "revokedhostkeys" {
			if value == "none" {
				return ""
			}
			return value
		}
	}
	return ""
}

func revokedHostKeysError(path string, err error) error {
	return fmt.Errorf("this host's ssh names %s as RevokedHostKeys, and snug cannot carry it "+
		"into the sandbox: %v. Fix the file, or the RevokedHostKeys line",
		policy.VisibleText(path), err)
}

// runSSHProbe runs one bounded `ssh -G` and returns what it printed.
func runSSHProbe(ssh string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ssh, args...)
	// WaitDelay bounds the wait for cmd.Run's own I/O goroutines once the
	// context kills ssh itself: a `Match exec` child inheriting the stdout or
	// stderr pipe would otherwise hold Run open past sshProbeTimeout for as
	// long as that child lives (internal/getent.Run's WaitDelay is the same
	// fix for the same shape).
	cmd.WaitDelay = time.Second
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// cmd.Env stays nil, so the probe inherits the HOST user's environment —
	// the opposite of every other exec in this project, and deliberate. The
	// `cmd.Env = []string{}` rule (internal/sandbox/exec.go) exists because
	// bwrap becomes PID 1 of the sandbox and the payload can read
	// /proc/1/environ; nothing here enters a sandbox, and a probe run with an
	// empty environment would answer a question about a machine the user does
	// not have (no LANG, no PATH for a `Match exec`, no SSH_* the user set).
	//
	// Stdin stays nil, which exec makes /dev/null: a `Match exec` command in
	// the user's config inherits it, and a probe is not a place for something
	// to start reading the terminal snug was launched from.
	err = cmd.Run()
	if ctx.Err() != nil {
		err = fmt.Errorf("it did not finish within %s", sshProbeTimeout)
	}
	return out.String(), errb.String(), err
}

// sshProbeError names the failed probe and what ssh itself said: the last
// stderr line that is not -v's debug chatter, which is where ssh puts the
// reason ("Bad owner or permissions on …", "No user exists for uid …").
func sshProbeError(host string, err error, stderr string) error {
	said := ""
	for line := range strings.SplitSeq(stderr, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "debug") {
			said = line
		}
	}
	if said != "" {
		err = fmt.Errorf("%v: %s", err, policy.VisibleText(said))
	}
	return fmt.Errorf("could not read this host's ssh configuration: `ssh -G %s` failed (%v). "+
		"Without it the sandbox's ssh would run on OpenSSH's compiled-in defaults, which can be "+
		"weaker than this host's. Run `ssh -G %s` yourself and fix what it reports; a slow or "+
		"failing `Match exec` in ~/.ssh/config is the usual cause",
		host, err, host)
}

// parseSSHValues keeps the whitelisted keys out of `ssh -G` output.
//
// The format is one `key value` per line, key lowercased by ssh itself, and
// snug never writes an ssh_config parser: the tool that owns the grammar does the
// tokenising, and snug decides policy over the result.
//
// Includes and Match blocks are resolved by ssh before it prints, so an
// `Include` in the host's file needs no handling here, and neither do the
// `^`/`+`/`-` list modifiers: what comes back is already expanded.
//
// A whitelisted value that is not shaped like what the key takes REFUSES the
// run, never escaped and never dropped (#688 F3): dropping it hands the key to
// the sandbox ssh's compiled-in default. policy.SSHValueOK is the predicate,
// and the renderers apply it again — this is the last place a host string can
// be stopped before it is a directive in a file the sandbox's ssh obeys.
func parseSSHValues(out string) (policy.SSHValues, error) {
	v := policy.SSHValues{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		if !slices.Contains(policy.SSHKeyWhitelist, key) {
			continue
		}
		if _, seen := v[key]; seen {
			continue
		}
		if !policy.SSHValueOK(key, value) {
			return nil, fmt.Errorf("this host's ssh resolves %s to %s, which snug cannot write "+
				"back into the ssh config it generates for the sandbox, and leaving it out would "+
				"run the sandbox's ssh on its compiled-in default for it. Check `ssh -G` output "+
				"for %s",
				policy.SSHKeySpelling(key), policy.VisibleText(value), key)
		}
		v[key] = value
	}
	return v, nil
}

// sshValuesLine renders the extraction for the verbose log. The KEYS are
// snug's own (the whitelist); the VALUES came off a host binary's stdout, and
// a screen is where text snug did not write gets escaped rather than refused —
// the same contract gitValuesLine has.
func sshValuesLine(v policy.SSHValues) string {
	if len(v) == 0 {
		return "(nothing — ssh printed none of the keys snug carries)"
	}
	var b strings.Builder
	for _, k := range policy.SortedSSHKeys() {
		val, ok := v[k]
		if !ok {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%s=%s", k, policy.VisibleText(val))
	}
	return b.String()
}

// parseSSHConfigChain picks the system-wide files out of `ssh -G -v`'s debug
// output. Kept separate from the exec so the interesting half is a pure
// function with a table test: the exec has one behaviour per host, the parser
// has to survive every host.
//
// The line shape, measured on OpenSSH_10.3p1:
//
//	debug1: Reading configuration data /home/michal/.ssh/config
//	debug1: Reading configuration data /usr/etc/ssh/ssh_config
//	debug1: Reading configuration data /usr/etc/ssh/ssh_config.d/50-suse.conf
//	debug1: Reading configuration data /etc/crypto-policies/back-ends/openssh.config
//
// printed TWICE per invocation (ssh parses the chain a second time after
// resolving the host name), which is why the result is deduplicated.
//
// Three of those four lines are not what snug wants, and the filters are the
// point rather than tidiness:
//
//   - the user's own ~/.ssh/config is not a system file (and snug generates
//     that one itself when an identity is pinned);
//   - the two Include'd files under it need no replacing, because the file
//     snug authors in place of the top-level one carries no Include line, so
//     they are never read inside the sandbox;
//   - and refusing everything not named ssh_config is what keeps a line like
//     `Include /tmp/anything.conf` in a host config from choosing where snug
//     authors bytes.
//
// policy.systemSSHConfigCandidates applies the same rules again before any of
// this can become a mount. Two filters, deliberately, for the same reason
// GitConfigFrom drops control characters.
func parseSSHConfigChain(debug, home string) []string {
	const marker = "Reading configuration data "
	var out []string
	for _, line := range strings.Split(debug, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		p := strings.TrimSpace(line[i+len(marker):])
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			continue
		}
		if filepath.Base(p) != "ssh_config" {
			continue
		}
		if home != "" && underHome(home, p) {
			continue
		}
		if slices.Contains(out, p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseSSHTopConfig picks the top-level system-wide ssh_config out of
// `ssh -G -vvv` stderr: the first file that passes parseSSHConfigChain's
// filters and that no Include pulled in.
//
// `-v` alone does not tell them apart: every file, included or not, gets the
// same "Reading configuration data" line, and the user's own ~/.ssh/config
// (read first) can Include a file named ssh_config that would then come
// before the system one. At debug3 each Include announces its file first,
// measured on OpenSSH_10.6p1:
//
//	debug3: /usr/etc/ssh/ssh_config line 31: Including file /usr/etc/ssh/ssh_config.d/50-suse.conf depth 0
//	debug1: Reading configuration data /usr/etc/ssh/ssh_config.d/50-suse.conf
//
// so a path announced that way is never the top-level file. An ssh that does
// not print the debug3 line gives the first filtered entry, which is wrong
// only where ~/.ssh/config Includes a file named ssh_config.
func parseSSHTopConfig(debug, home string) string {
	const marker = "Including file "
	included := map[string]bool{}
	for _, line := range strings.Split(debug, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		rest := line[i+len(marker):]
		if j := strings.LastIndex(rest, " depth "); j >= 0 {
			rest = rest[:j]
		}
		included[strings.TrimSpace(rest)] = true
	}
	for _, p := range parseSSHConfigChain(debug, home) {
		if !included[p] {
			return p
		}
	}
	return ""
}

// underHome reports whether p is home itself or anything beneath it — a
// component test, not a string prefix, because /home/us is not under /home/u.
func underHome(home, p string) bool {
	home = strings.TrimSuffix(filepath.Clean(home), "/")
	return p == home || strings.HasPrefix(p, home+"/")
}

// resolveSandboxSSH makes the carried ssh configuration the SANDBOX's ssh's.
// ctx was built from probing the first ssh on the host's PATH, and pol is
// Resolve's answer to it. The sandbox runs whatever its own PATH finds
// (pol.SandboxSSHHost), which can be another file: a wrapper script, a nix or
// Homebrew ssh, /usr/local/bin/ssh. Values and a KRL read from the wrong
// binary leave the sandbox's ssh on its compiled-in defaults while --dry-run
// claims a config was written. So when the two differ, that binary is probed
// — the global question and, when identity.ssh is pinned, the pinned host's
// (probeSSHPinWith), so the generated ~/.ssh/config and its known_hosts and
// KRL come from the same ssh as the system file — and the selection resolved
// again, once. A second disagreement refuses rather than looping. With no
// ssh on the sandbox's PATH the pin is asked nothing, as on a host with no
// ssh.
//
// The re-probe RUNS the sandbox's ssh ON THE HOST, so it refuses when this
// sandbox can write that file: a payload would choose what snug executes,
// unsandboxed, on the next run.
//
// held are the refusals of the first probes, which asked the host PATH's
// ssh. They refuse only where that ssh's answers are used:
//
//   - the sandbox runs the same file: both refuse;
//   - the sandbox runs another ssh: neither; its own probes decide;
//   - the sandbox's PATH has no ssh: the global probe's refusal stands only
//     if the re-resolution still writes a system ssh_config (a bind
//     supplying the host's file), because that file would carry the host
//     PATH ssh's values. The pin's does not: the pin is then asked nothing,
//     as on a host with no ssh, and that answer refuses on its own terms.
//
// rerr is Resolve's error, handled by the caller as before; serr is a refusal
// of this step.
func resolveSandboxSSH(reg map[policy.ProfileName]*policy.Profile, selected []policy.ProfileName,
	ctx policy.Context, env policy.Environ, pol *policy.Policy, home, pinHost string, pinned bool,
	held heldSSHErrs, n *notes,
) (_ *policy.Policy, rerr, serr error) {
	if pol.SandboxSSHHost == ctx.HostSSHBinary {
		if err := errors.Join(held.probe, held.pin); err != nil {
			return nil, nil, err
		}
		return pol, nil, nil
	}
	if pol.SandboxSSHHost == "" {
		// No ssh on the sandbox's PATH: nothing is written where no grant
		// supplies a file. A bind that supplies the host's root-owned file is
		// still replaced, with the host PATH ssh's values.
		ctx.HostSSHBinary = ""
	} else {
		held.probe = nil
		if pol.SandboxWritesHost(pol.SandboxSSHHost) {
			return nil, nil, fmt.Errorf("the sandbox's ssh is %s (host file %s), which this sandbox can "+
				"write, and snug would have to run it on the host to read its configuration. Grant "+
				"that directory read-only, or take it off the profile's path",
				policy.VisibleText(pol.SandboxSSHGuest), policy.VisibleText(pol.SandboxSSHHost))
		}
		probe, err := probeSSHBinary(pol.SandboxSSHHost, home, n)
		if err != nil {
			return nil, nil, err
		}
		ctx.HostSSHConfigs, ctx.HostSSHTopConfig = probe.chain, probe.top
		ctx.HostSSHConfig, ctx.HostSSHRevoked = probe.values, probe.revoked
		ctx.HostSSHRevokedPath = probe.revokedPath
		ctx.HostSSHBinary = pol.SandboxSSHHost
	}
	if pinned {
		pin, err := probeSSHPinWith(ctx.HostSSHBinary, home, pinHost)
		if err != nil {
			return nil, nil, err
		}
		ctx.KnownHosts, ctx.HostSSHPinConfig, ctx.RevokedHostKeys = pin.knownHosts, pin.values, pin.revoked
	}
	again, err := policy.Resolve(reg, selected, ctx, env)
	if err != nil {
		return again, err, nil
	}
	if held.probe != nil && len(again.SystemSSHConfigs) > 0 {
		return nil, nil, held.probe
	}
	if again.SandboxSSHHost != ctx.HostSSHBinary {
		return nil, nil, fmt.Errorf("snug bug: the sandbox's ssh changed between two resolutions of one "+
			"selection (%s, then %s); refusing rather than carrying configuration for the wrong binary",
			policy.VisibleText(pol.SandboxSSHHost), policy.VisibleText(again.SandboxSSHHost))
	}
	return again, nil, nil
}

// heldSSHErrs are the first probes' refusals, held until the sandbox's ssh is
// known (resolveSandboxSSH).
type heldSSHErrs struct{ probe, pin error }
