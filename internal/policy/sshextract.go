package policy

import (
	"fmt"
	"sort"
	"strings"
)

// SSHKeyWhitelist is every key snug will carry from the host's system-wide
// ssh_config into the file it generates in its place. Nothing on this list
// names a program, a file, a socket or a credential: each one names
// ALGORITHMS, except RequiredRSASize, which is an integer, RekeyLimit,
// which is two (bytes and seconds, as `ssh -G` prints them), and
// StrictHostKeyChecking, which is one of four words.
//
// It is a WHITELIST and must stay one, for the reason ssh_config is replaced
// at all: it is a COMMAND TABLE. ProxyCommand, LocalCommand, `Match exec`,
// KnownHostsCommand, PermitLocalCommand, PKCS11Provider and
// SecurityKeyProvider all name programs for ssh to run, and IdentityFile,
// IdentityAgent, UserKnownHostsFile and ControlPath all name paths — the
// third noun, a SOCKET, is in that list too. Read-only does not demote a
// command table into data; it supplies it (CLAUDE.md). So snug reads the
// host's file as DATA and generates the sandbox's.
//
// WHAT IS DELIBERATELY ABSENT, and why, in the shape of the git
// config's signing-key rule (GitConfigFrom): anything whose value names something that has
// to EXIST inside the sandbox. `IdentityFile` is the ssh spelling of
// `commit.gpgsign = true` — a key that is not inside turns every connection
// into a failure, which is worse than a connection made with the compiled-in
// defaults. Nothing here can fail that way: an algorithm list is satisfied by
// the ssh binary itself, and a sandbox that has a system ssh_config to replace
// has that binary from the same bound tree (see SystemSSHConfigFrom).
//
// The whitelist is the set of values CARRIED FROM THE HOST. The
// `RevokedHostKeys` line SystemSSHConfigFrom writes is not one: it is a path
// snug authors, pointing at content snug staged, like UserKnownHostsFile and
// RevokedHostKeys in Identity.SSHConfig. The host's path string is never
// written.
var SSHKeyWhitelist = []string{
	"ciphers",
	"macs",
	"kexalgorithms",
	"hostkeyalgorithms",
	"pubkeyacceptedalgorithms",
	"casignaturealgorithms",
	"hostbasedacceptedalgorithms",
	"gssapikexalgorithms",
	"requiredrsasize",
	"rekeylimit",
	"stricthostkeychecking",
}

// sshKeySpelling is how each whitelisted key is written in the generated file.
// `ssh -G` prints keys lowercased; ssh_config(5) spells them in mixed case and
// so does every host file a human will compare this against. The parser does
// not care, the reader does.
var sshKeySpelling = map[string]string{
	"ciphers":                     "Ciphers",
	"macs":                        "MACs",
	"kexalgorithms":               "KexAlgorithms",
	"hostkeyalgorithms":           "HostKeyAlgorithms",
	"pubkeyacceptedalgorithms":    "PubkeyAcceptedAlgorithms",
	"casignaturealgorithms":       "CASignatureAlgorithms",
	"hostbasedacceptedalgorithms": "HostbasedAcceptedAlgorithms",
	"gssapikexalgorithms":         "GSSAPIKexAlgorithms",
	"requiredrsasize":             "RequiredRSASize",
	"rekeylimit":                  "RekeyLimit",
	"stricthostkeychecking":       "StrictHostKeyChecking",
}

// SSHValues is the whitelisted subset of this host's system-wide ssh
// configuration, keyed by the lowercase key name, as `ssh -G` prints it. The
// caller extracts it — running a host binary is not the resolver's job — and
// this package only renders it.
//
// It carries EVERY whitelisted key the host's ssh printed, not the difference
// from OpenSSH's compiled-in defaults (#688 F6): a delta assumes the sandbox's
// ssh has the host's defaults, and an older or differently patched build would
// apply its own, possibly wider, ones to every key the delta left out.
type SSHValues map[string]string

// SortedSSHKeys is the whitelist in a stable order, for rendering and for the
// --dry-run block that names what was carried.
func SortedSSHKeys() []string {
	out := append([]string(nil), SSHKeyWhitelist...)
	sort.Strings(out)
	return out
}

// SSHValueOK reports whether v is a value snug is willing to write for the
// whitelisted key: an algorithm list, for RequiredRSASize and RekeyLimit the
// decimal integers `ssh -G` prints, and for StrictHostKeyChecking one of the
// four words it prints. The extractor in internal/cli refuses
// the run on a value that fails it, and the renderers here skip one, so a
// value that reaches a generated file has passed it twice.
//
// It is written as an ALLOWED SET rather than a list of dangerous characters,
// which is the lesson gitQuote's five measured failures paid for: a value
// snug writes into a file a tool parses needs the question "what can this
// value MEAN to the parser" answered once, not per character someone thought
// of. ssh_config's grammar ends a directive at a newline, starts a comment at
// `#`, and treats whitespace and `"` as structure — none of which can survive
// this predicate, except RekeyLimit's one separating space, which is the
// grammar's own. A legitimate algorithm name is [A-Za-z0-9] plus `-`, `_`,
// `.`, `@` and `+`, joined by commas.
func SSHValueOK(key, v string) bool {
	switch key {
	case "requiredrsasize":
		return sshDigits(v)
	case "rekeylimit":
		size, secs, ok := strings.Cut(v, " ")
		return ok && sshDigits(size) && sshDigits(secs)
	case "stricthostkeychecking":
		// How `ssh -G` prints it: yes and no come back as true and false,
		// and off as false (OpenSSH_10.6p1).
		return v == "true" || v == "false" || v == "ask" || v == "accept-new"
	}
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

func sshDigits(v string) bool {
	if v == "" || len(v) > 20 {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// carriedSSHKeys is which whitelisted keys a given SSHValues actually
// contributes to the generated file: present, and shaped like something snug
// is willing to write. It is the same predicate SystemSSHConfigFrom applies,
// factored out so the screen cannot claim a key the file does not carry.
func carriedSSHKeys(v SSHValues) []string {
	var out []string
	for _, k := range SortedSSHKeys() {
		if val, ok := v[k]; ok && SSHValueOK(k, val) {
			out = append(out, k)
		}
	}
	return out
}

// SSHKeySpelling renders a whitelisted key the way ssh_config(5) writes it,
// for a screen that names what was carried. An unknown key comes back
// unchanged; only SSHKeyWhitelist entries ever reach it.
func SSHKeySpelling(k string) string {
	if s, ok := sshKeySpelling[k]; ok {
		return s
	}
	return k
}

// SystemSSHConfig is the generated replacement with nothing carried over: the
// shape a host that customises nothing gets, and the shape every host got
// before issue #43.
func SystemSSHConfig() []byte { return SystemSSHConfigFrom(nil, false) }

// SystemSSHConfigFrom is the generated replacement for the system-wide
// ssh_config. It is authored by snug where a bind supplies the host's copy,
// and where no grant supplies one but the sandbox's PATH finds an ssh — see
// replaceSystemSSHConfig for the rule that decides WHEN. revoked says the host's global RevokedHostKeys file
// is staged at SystemRevokedHostKeysGuest, and adds the line naming it. This
// has NOTHING to do with a pinned identity: the failure it fixes is a
// configuration-chain problem, not a credential one, and it fires (or does
// not) the same way whether or not [identity] is set.
//
// WHY THIS EXISTS, twice over. Where no grant supplies a system file (@sys
// does not grant /etc/ssh), the sandbox's ssh would run on its compiled-in
// defaults, which can be weaker than the host's: this file carries the
// host's values instead. And where a grant does supply one, measured rather
// than reasoned: the sandbox maps exactly
// one uid, so every root-owned file under a read-only bind reads as 65534
// inside it. OpenSSH refuses to use a configuration file owned by neither
// root nor the invoking user, and the refusal is fatal rather than a
// warning:
//
//	$ git clone git@github.com:owner/repo.git
//	Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf
//
// So ssh — and therefore git-over-ssh, scp, and rsync -e ssh — did not run
// inside snug at all on such a host, for every profile, identity pinned or
// not. `ssh -F <file>` always worked, because -F makes ssh skip the
// system-wide file entirely; this replacement is that same escape, applied
// once by snug instead of relying on every caller to remember a flag. git
// hits the identical root cause on a different file and takes the same
// SHAPE of fix (`safe.directory = *`) — the next tool with an ownership
// check on a root-owned file will need its own answer, but this is the
// pattern to look for.
//
// WHAT IT CARRIES, and why that is not a hole (issue #43). Until this
// existed the replacement was comment-only, and the cost was real: on a
// crypto-policy distro the sandbox lost the policy's algorithm lists and,
// with security content, RequiredRSASize 2048 -> OpenSSH's compiled-in 1024,
// so the sandbox's ssh would accept a 1024-bit RSA key the host's would
// refuse. Now snug reads the host's EFFECTIVE values with `ssh -G`, keeps
// SSHKeyWhitelist — algorithm lists and integers, nothing that names a
// program, a file or a socket — and writes them here. Two properties hold it
// down:
//
//   - EVERY whitelisted value is written, not the difference from the
//     compiled-in defaults (#688 F6), so the file states the host's policy
//     whole and does not depend on the sandbox's ssh sharing the host's
//     defaults.
//   - The lists are EXPANDED by the same ssh that will read them back. `ssh
//     -G` resolves `^`/`+`/`-` modifiers, so no modifier syntax survives into
//     this file, and the binary that expanded them is the sandbox's own
//     PATH ssh, probed on the host (internal/cli). A sandbox whose ssh is some
//     OTHER, older build could refuse an algorithm name it does not know —
//     loudly ("Bad SSH2 cipher spec"), never silently, and disclosed in the
//     SSH block of --dry-run.
//
// A value snug does not recognise REFUSES the run in internal/cli, and is
// skipped here rather than escaped (SSHValueOK): falling back to the sandbox
// ssh's compiled-in default for it would be the silent downgrade #688 F3
// measured.
//
// This is a REPLACEMENT, not masking: snug authors it, the sandbox still
// sees a file at that path, and no profile's grant is silently subtracted
// (CLAUDE.md, "PATH precedence, not overmounting"). It appears in --dry-run
// as a `data` row with `(snug)` provenance, plus a `replaces:<profile>`
// suffix when it displaced content a profile's bind supplied at that path —
// see Policy.Replace and replaceSystemSSHConfig. Where no grant supplied a
// file there, it is a `(snug)` row alone.
//
// The carried values are what the host's ssh resolves for a name no Host or
// Match pattern matches (internal/cli's probe). Host blocks for other names
// are not carried, except the pinned host's, which the generated
// ~/.ssh/config sets first. A block with a negated pattern (`Host * !x`,
// `Match !host x`) DOES match that name, so inside it applies to x too, where
// the host's ssh never applies it. That residual is stated in the file and in
// --dry-run's SSH block.
//
// replaceSystemSSHConfig does not check who owns the host file it replaces —
// owner-gating was considered and rejected (issue #40:
// it makes emission depend on a mode bit and --dry-run host-state-dependent
// in a way a reader cannot check). So a human profile binding its OWN config
// at one of these paths is replaced too, disclosed by `replaces:` like any
// other displacement; their answer is `~/.ssh/config`, which snug does not
// author unless an identity is pinned.
//
// A second, independent reason to replace it: ssh_config is a COMMAND TABLE
// (ProxyCommand, LocalCommand, Match exec, KnownHostsCommand,
// PermitLocalCommand, PKCS11Provider, SecurityKeyProvider all name programs
// to run), and @sys's /usr bind supplies the host's copy of one
// unavoidably — /usr cannot be enumerated finely enough to leave it out.
// Replacing it means the sandbox's ssh obeys only bytes snug authored. Do
// NOT oversell this: the file is the host admin's, the payload cannot write
// it (a read-only data mount inside a read-only bind, under
// --remount-ro /), and anything it named would run inside the sandbox with
// the sandbox's own authority — no escalation is being closed here, this is
// legibility and robustness.
//
// ABUSE: a hostile process inside the sandbox can use this to read the
// host's algorithm preferences, RequiredRSASize, and which host keys the host
// has revoked (the staged RevokedHostKeys file). That is public material and
// a list of distrust, no credential: the algorithms are what every server it
// connects to is told in the clear during the handshake, and a revocation
// list names keys nobody should accept. It cannot write either file, a
// read-only data mount under --remount-ro /, and it gains no reach: ssh
// already ran inside on the bound binary, and this only makes it check hosts
// as strictly as the host's ssh does.
func SystemSSHConfigFrom(v SSHValues, revoked bool) []byte {
	var b strings.Builder
	b.WriteString("# Generated by snug, replacing this host's system-wide ssh_config.\n")
	b.WriteString("#\n")
	b.WriteString("# The sandbox maps exactly one uid, so a root-owned file under a\n")
	b.WriteString("# read-only bind reads as 65534 inside it. OpenSSH refuses a\n")
	b.WriteString("# configuration file owned by neither root nor the caller — fatally,\n")
	b.WriteString("# not as a warning — so ssh, and therefore git-over-ssh, scp and\n")
	b.WriteString("# rsync -e ssh, would not run inside the sandbox at all on a host whose\n")
	b.WriteString("# system-wide ssh_config lives under a granted tree. Where no grant\n")
	b.WriteString("# supplies a system file, this one exists so the sandbox's ssh never\n")
	b.WriteString("# falls back to compiled-in defaults weaker than the host's. This has\n")
	b.WriteString("# nothing to do with pinning an identity; git hits the same root cause\n")
	b.WriteString("# on a different file and takes the same shape of fix\n")
	b.WriteString("# (safe.directory = *).\n")
	b.WriteString("#\n")
	b.WriteString("# It has no Include line for the same reason: every file it would pull\n")
	b.WriteString("# in is root-owned too.\n")
	b.WriteString("#\n")
	b.WriteString("# If snug pinned an identity it also generated ~/.ssh/config; otherwise\n")
	b.WriteString("# this file is the only ssh configuration in the sandbox.\n")
	b.WriteString("#\n")
	b.WriteString("# The values below are what this host's ssh resolves for a name no\n")
	b.WriteString("# Host or Match pattern matches. Host blocks for other names are not\n")
	b.WriteString("# carried, except a pinned host's, in ~/.ssh/config. A block with a\n")
	b.WriteString("# negated pattern (Host * !x, Match !host x) matches that name, so\n")
	b.WriteString("# here it applies to x too.\n")
	if revoked {
		b.WriteString("#\n")
		b.WriteString("# RevokedHostKeys names a copy of the file this host's ssh names as\n")
		b.WriteString("# RevokedHostKeys, staged by snug.\n")
		fmt.Fprintf(&b, "RevokedHostKeys %s\n", SystemRevokedHostKeysGuest)
	}

	var carried []string
	for _, k := range SortedSSHKeys() {
		val, ok := v[k]
		if !ok || !SSHValueOK(k, val) {
			continue
		}
		carried = append(carried, k)
	}
	if len(carried) == 0 {
		b.WriteString("#\n")
		b.WriteString("# This host has no ssh to ask, so there was nothing to carry over.\n")
		return []byte(b.String())
	}

	b.WriteString("#\n")
	b.WriteString("# The directives below are this host's own, read with `ssh -G` and kept\n")
	b.WriteString("# because they name ALGORITHMS and nothing else — no program, no file,\n")
	b.WriteString("# no socket. Everything the host's file could say that names something\n")
	b.WriteString("# to run or to open (ProxyCommand, Match exec, KnownHostsCommand,\n")
	b.WriteString("# PKCS11Provider, IdentityFile, IdentityAgent, ControlPath) is left\n")
	b.WriteString("# behind: a read-only bind of a command table supplies it rather than\n")
	b.WriteString("# stopping it, which is why this file is generated at all.\n")
	for _, k := range carried {
		fmt.Fprintf(&b, "%s %s\n", sshKeySpelling[k], v[k])
	}
	return []byte(b.String())
}
