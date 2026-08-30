package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// sshProbeHost is the host name the probe resolves options for. It is in the
// .invalid TLD (RFC 2606), so it can never name a real machine, and `ssh -G`
// does no name resolution and opens no connection for it anyway — measured:
// 67ms, exit 0, no DNS traffic. It is also the reason the probe returns the
// GLOBAL section of the host's config rather than some Host block's overrides:
// no pattern a human writes is going to match this name.
const sshProbeHost = "snug-probe.invalid"

// sshProbeTimeout bounds the probe. Issue #42 asks what happens when ssh
// hangs, and this is the answer: the chain comes back empty and the fixed
// SystemSSHConfigPaths list is what the run uses, which is where snug was
// before discovery existed. It is generous because the thing that can be slow
// is not ssh — see the Match exec paragraph on sshConfigChain.
const sshProbeTimeout = 5 * time.Second

// probeSSHConfig asks this host's ssh two questions in one invocation: WHICH
// configuration files it reads, so snug can replace a spelling nobody wrote
// down (issue #42), and WHAT they resolve to, so the file snug writes in
// place of the host's can carry the non-executable half of it rather than
// throwing the host's crypto policy away (issue #43).
//
// WHY ASK RATHER THAN LIST. policy.SystemSSHConfigPaths knows two spellings.
// A host that spells it a third way — FreeBSD's and Homebrew's
// /usr/local/etc/ssh, a /nix/store path — gets issue #40's failure back and
// gets it SILENTLY: ssh inside the sandbox dies with `Bad owner or
// permissions` naming a file the human never wrote, and snug's own SSH block
// says nothing, because it only speaks for a path that was actually replaced.
// A list that grows once per platform is a rule written somewhere it can be
// forgotten; asking ssh is the same shape as asking git to tokenise a config
// file instead of writing an INI parser (extractGitConfig).
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
//     host, at snug startup, once per run. That file is not reachable by
//     sandboxed material: no shipped profile grants ~/.ssh, and Validate
//     refuses any bind covering $HOME (#220), so a payload can neither write
//     the file nor plant an Include target it names. It is the user's own
//     file, run by the user's own ssh, exactly as `git push` over ssh would
//     run it a moment later — but it is snug that triggers it here, which is
//     why it is written down rather than left to be discovered.
//
// A host with no ssh at all returns nothing, with nothing on screen: there is
// no ssh inside the sandbox to fail either, and the fixed list still covers
// the ordinary spellings. Any OTHER failure — a timeout, a probe that exits
// non-zero — IS named on stderr, because that is the case where snug tried to
// find out and could not, and the human is the only one who can tell whether
// their host is one of the exotic ones.
func probeSSHConfig(home string, n *notes) ([]string, policy.SSHValues) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshProbeTimeout)
	defer cancel()

	// -G resolves and prints the configuration without connecting; -v makes it
	// name every file it read while doing so. BatchMode keeps a probe from ever
	// becoming a prompt. One invocation answers both questions: WHICH file
	// (stderr) and WHAT IT SAYS (stdout).
	cmd := exec.CommandContext(ctx, ssh, "-G", "-v", "-o", "BatchMode=yes", sshProbeHost)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
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
	if err := cmd.Run(); err != nil {
		n.aside("snug: could not ask ssh which configuration files it reads (%v), "+
			"so snug falls back to the two spellings it knows (%s) and to OpenSSH's\n"+
			"      compiled-in algorithm defaults. On a host that spells it a third way, ssh "+
			"inside the sandbox will fail with `Bad owner or permissions`.\n",
			err, strings.Join(policy.SystemSSHConfigPaths, " and "))
		return nil, nil
	}
	chain := parseSSHConfigChain(stderr.String(), home)
	values := sshValuesDelta(parseSSHValues(stdout.String()), sshDefaultValues(ctx, ssh))
	if n.isVerbose() {
		if len(chain) == 0 {
			n.aside("snug: ssh named no system-wide config file\n")
		} else {
			n.aside("snug: ssh reads system-wide config from %s\n",
				policy.VisibleText(strings.Join(chain, " ")))
		}
		n.aside("snug: ssh config carried into the sandbox: %s\n", sshValuesLine(values))
	}
	return chain, values
}

// sshDefaultValues is OpenSSH's compiled-in configuration, measured rather
// than assumed: `-F /dev/null` makes ssh read that file and NOTHING else — not
// the user's config, not the system-wide one (measured on OpenSSH_10.3p1, and
// it is why -F cannot be used to skip only the user's file).
//
// It exists so snug can carry the DIFFERENCE. Without it the generated file
// would restate the sandbox ssh's own defaults on every host, which is a
// larger file, a larger golden diff, and a standing claim that snug knows
// better than the binary — on a host that customises nothing there is nothing
// to restore.
//
// A failure here returns nothing, and the caller then treats every effective
// value as a difference. That is the fail-SAFE direction for this particular
// comparison: it carries MORE of the host's own policy, never less, and every
// value still has to pass the whitelist and sshValueOK.
func sshDefaultValues(ctx context.Context, ssh string) policy.SSHValues {
	cmd := exec.CommandContext(ctx, ssh, "-G", "-F", os.DevNull, "-o", "BatchMode=yes", sshProbeHost)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseSSHValues(string(out))
}

// parseSSHValues keeps the whitelisted keys out of `ssh -G` output.
//
// The format is one `key value` per line, key lowercased by ssh itself, and
// snug never writes an ssh_config parser: this is the same division of labour
// extractGitConfig has with `git config --list` — the tool that owns the
// grammar does the tokenising, and snug decides policy over the result.
//
// Includes and Match blocks are resolved by ssh before it prints, so an
// `Include` in the host's file needs no handling here, and neither do the
// `^`/`+`/`-` list modifiers: what comes back is already expanded.
//
// A value that is not shaped like an algorithm list or an integer is dropped
// and NAMED, never escaped. policy.sshValueOK applies the identical predicate
// when rendering — two filters for the same reason the git extractor and
// GitConfigFrom both drop control characters: this is the last place a host
// string can be stopped before it is a directive in a file the sandbox's ssh
// obeys.
func parseSSHValues(out string) policy.SSHValues {
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
		if !sshValueShape(value) {
			fmt.Fprintf(os.Stderr, "snug: dropping ssh %s: the value is not shaped like an "+
				"algorithm list or a number (%s), so snug does not carry it into the config "+
				"it generates; the sandbox's ssh uses its compiled-in default for it\n",
				key, policy.VisibleText(value))
			continue
		}
		v[key] = value
	}
	return v
}

// sshValueShape is the extractor's copy of policy.sshValueOK's predicate. It
// is duplicated deliberately rather than exported: the two answer the same
// question at two sinks, and the one in policy is what actually gates the
// bytes — this one exists so the drop can be NAMED on stderr, which a pure
// package cannot do.
func sshValueShape(v string) bool {
	if v == "" || len(v) > 4096 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ',' || r == '-' || r == '_' || r == '.' || r == '@' || r == '+':
		default:
			return false
		}
	}
	return true
}

// sshValuesDelta keeps only what this host says that OpenSSH's compiled-in
// defaults do not. On the development host that is exactly the crypto
// policy's contribution — measured:
//
//	requiredrsasize             1024 -> 2048
//	ciphers, macs, kexalgorithms, casignaturealgorithms,
//	pubkeyacceptedalgorithms, hostbasedacceptedalgorithms, gssapikexalgorithms
//
// and nothing else, which is the whole of what issue #43 says the sandbox
// loses. RequiredRSASize is the entry with security content: without it the
// sandbox's ssh accepts a 1024-bit RSA host or user key that the host's ssh
// refuses.
func sshValuesDelta(effective, defaults policy.SSHValues) policy.SSHValues {
	out := policy.SSHValues{}
	for k, v := range effective {
		if d, ok := defaults[k]; ok && d == v {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sshValuesLine renders the extraction for the verbose log. The KEYS are
// snug's own (the whitelist); the VALUES came off a host binary's stdout, and
// a screen is where text snug did not write gets escaped rather than refused —
// the same contract gitValuesLine has.
func sshValuesLine(v policy.SSHValues) string {
	if len(v) == 0 {
		return "(nothing — this host resolves to OpenSSH's compiled-in defaults)"
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
// this can become a mount. Two filters, deliberately, for the same reason the
// git extractor and GitConfigFrom both drop control characters.
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

// underHome reports whether p is home itself or anything beneath it — a
// component test, not a string prefix, because /home/us is not under /home/u.
func underHome(home, p string) bool {
	home = strings.TrimSuffix(filepath.Clean(home), "/")
	return p == home || strings.HasPrefix(p, home+"/")
}
