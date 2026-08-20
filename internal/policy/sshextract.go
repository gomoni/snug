package policy

import (
	"fmt"
	"sort"
	"strings"
)

// SSHKeyWhitelist is every key snug will carry from the host's system-wide
// ssh_config into the file it generates in its place. Nothing on this list
// names a program, a file, a socket or a credential: each one names
// ALGORITHMS, except RequiredRSASize, which is an integer.
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
// WHAT IS DELIBERATELY ABSENT, and why, in the shape GitKeyWhitelist's
// signing-key omission takes: anything whose value names something that has
// to EXIST inside the sandbox. `IdentityFile` is the ssh spelling of
// `commit.gpgsign = true` — a key that is not inside turns every connection
// into a failure, which is worse than a connection made with the compiled-in
// defaults. Nothing here can fail that way: an algorithm list is satisfied by
// the ssh binary itself, and a sandbox that has a system ssh_config to replace
// has that binary from the same bound tree (see SystemSSHConfigFrom).
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
}

// SSHValues is the whitelisted subset of this host's system-wide ssh
// configuration, keyed by the lowercase key name, as `ssh -G` prints it. The
// caller extracts it — running a host binary is not the resolver's job — and
// this package only renders it.
//
// It carries only the values that DIFFER from OpenSSH's compiled-in defaults
// (internal/cli measures both), which is what keeps the generated file empty
// of directives on a host that customises nothing.
type SSHValues map[string]string

// SortedSSHKeys is the whitelist in a stable order, for rendering and for the
// --dry-run block that names what was carried.
func SortedSSHKeys() []string {
	out := append([]string(nil), SSHKeyWhitelist...)
	sort.Strings(out)
	return out
}

// sshValueOK is the second filter on a value, after the extractor's. It admits
// exactly the shape every whitelisted key has — an algorithm list or an
// integer — and nothing else.
//
// It is written as an ALLOWED SET rather than a list of dangerous characters,
// which is the lesson gitQuote's five measured failures paid for: a value
// snug writes into a file a tool parses needs the question "what can this
// value MEAN to the parser" answered once, not per character someone thought
// of. ssh_config's grammar ends a directive at a newline, starts a comment at
// `#`, and treats whitespace and `"` as structure — none of which can survive
// this predicate. A legitimate value cannot contain them either: an algorithm
// name is [A-Za-z0-9] plus `-`, `_`, `.`, `@` and `+`, joined by commas.
//
// The remedy here is a DROP, which is a downgrade (that key falls back to the
// sandbox ssh's compiled-in default), so the predicate deliberately does not
// try to be clever: an unrecognisable value means snug does not understand
// what it is carrying, and carrying it anyway is how a generated file becomes
// a directive nobody wrote.
func sshValueOK(v string) bool {
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

// carriedSSHKeys is which whitelisted keys a given SSHValues actually
// contributes to the generated file: present, and shaped like something snug
// is willing to write. It is the same predicate SystemSSHConfigFrom applies,
// factored out so the screen cannot claim a key the file does not carry.
func carriedSSHKeys(v SSHValues) []string {
	var out []string
	for _, k := range SortedSSHKeys() {
		if val, ok := v[k]; ok && sshValueOK(val) {
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
func SystemSSHConfig() []byte { return SystemSSHConfigFrom(nil) }

// SystemSSHConfigFrom is the generated replacement for the system-wide
// ssh_config. It is authored by snug in EVERY sandbox whose deepest covering
// grant actually supplies a host file at the path — see replaceSystemSSHConfig
// for the coverage rule that decides WHEN. This has NOTHING to do with a
// pinned identity: the failure it fixes is a configuration-chain problem, not
// a credential one, and it fires (or does not) the same way whether or not
// [identity] is set.
//
// WHY THIS EXISTS, measured rather than reasoned: the sandbox maps exactly
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
// SSHKeyWhitelist — algorithm lists and an integer, nothing that names a
// program, a file or a socket — and writes them here. Two properties hold it
// down:
//
//   - Only values DIFFERING from the compiled-in defaults are carried
//     (internal/cli measures both), so on a host that customises nothing this
//     file is byte-identical to the comment-only one it replaces.
//   - The lists are EXPANDED by the same ssh that will read them back. `ssh
//     -G` resolves `^`/`+`/`-` modifiers, so no modifier syntax survives into
//     this file, and the binary that expanded them is the binary in the
//     bound tree the replaced config came from. A sandbox whose ssh is some
//     OTHER, older build could refuse an algorithm name it does not know —
//     loudly ("Bad SSH2 cipher spec"), never silently, and disclosed in the
//     SSH block of --dry-run.
//
// A value snug does not recognise is DROPPED rather than escaped (sshValueOK):
// the key then falls back to the sandbox ssh's compiled-in default, which is
// exactly where it was before #43.
//
// This is a REPLACEMENT, not masking: snug authors it, the sandbox still
// sees a file at that path, and no profile's grant is silently subtracted
// (CLAUDE.md, "PATH precedence, not overmounting"). It appears in --dry-run
// as a `data` row with `(snug)` provenance, plus a `replaces:<profile>`
// suffix when it displaced content a profile's bind supplied at that path —
// see Policy.Replace and replaceSystemSSHConfig.
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
// ABUSE: a hostile process inside the sandbox can use this to run `ssh` —
// and therefore `git` over ssh, `scp` and `rsync -e ssh` — where it
// previously died parsing the host's root-owned config; it gains no
// credential by it, because without a pinned identity there is no key, no
// agent socket and no known_hosts inside, so it can only reach hosts that
// would accept it with no secret of yours, over egress @net already granted
// and with the same reach a plain TCP client already had. It cannot modify
// the file. What it can READ is the host's algorithm preferences and
// RequiredRSASize — the same facts `ssh -Q` and the bound /usr already tell
// it, and the same ones every server it connects to is told in the clear
// during the handshake.
func SystemSSHConfigFrom(v SSHValues) []byte {
	var b strings.Builder
	b.WriteString("# Generated by snug, replacing this host's system-wide ssh_config.\n")
	b.WriteString("#\n")
	b.WriteString("# The sandbox maps exactly one uid, so a root-owned file under a\n")
	b.WriteString("# read-only bind reads as 65534 inside it. OpenSSH refuses a\n")
	b.WriteString("# configuration file owned by neither root nor the caller — fatally,\n")
	b.WriteString("# not as a warning — so ssh, and therefore git-over-ssh, scp and\n")
	b.WriteString("# rsync -e ssh, did not run inside the sandbox at all on a host whose\n")
	b.WriteString("# system-wide ssh_config lives under a granted tree. This has nothing\n")
	b.WriteString("# to do with pinning an identity; git hits the same root cause on a\n")
	b.WriteString("# different file and takes the same shape of fix (safe.directory = *).\n")
	b.WriteString("#\n")
	b.WriteString("# It has no Include line for the same reason: every file it would pull\n")
	b.WriteString("# in is root-owned too.\n")
	b.WriteString("#\n")
	b.WriteString("# If snug pinned an identity it also generated ~/.ssh/config; otherwise\n")
	b.WriteString("# ssh's compiled-in defaults are all that apply.\n")

	var carried []string
	for _, k := range SortedSSHKeys() {
		val, ok := v[k]
		if !ok || !sshValueOK(val) {
			continue
		}
		carried = append(carried, k)
	}
	if len(carried) == 0 {
		b.WriteString("#\n")
		b.WriteString("# This host's ssh resolves every algorithm list and RequiredRSASize to\n")
		b.WriteString("# OpenSSH's compiled-in defaults, so there was nothing to carry over\n")
		b.WriteString("# and the sandbox's ssh reaches the same values on its own.\n")
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
	b.WriteString("#\n")
	b.WriteString("# Only values that DIFFER from OpenSSH's compiled-in defaults are here.\n")
	for _, k := range carried {
		fmt.Fprintf(&b, "%s %s\n", sshKeySpelling[k], v[k])
	}
	return []byte(b.String())
}
