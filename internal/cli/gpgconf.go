package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// gpgConfFiles is the host's gpg configuration as gpg itself would read it:
// the system-wide file and the ONE user file gpg picks, each as raw bytes and
// the path they came from. An absent file is a nil content and an empty path.
// The system file's host path is also its guest path: the sandbox runs the
// same gpg, with the same compiled-in sysconfdir.
type gpgConfFiles struct {
	system     []byte
	systemPath string
	user       []byte
	userPath   string
}

// probeGPGConf finds the configuration the host's gpg CLIENT runs on, so the
// sandbox's gpg makes the same digest, cipher and trust choices.
//
// WHY NOT `gpgconf --list-options gpg`: it does not list the options that
// matter. Measured on gpg 2.5.24 with a GNUPGHOME whose gpg.conf set
// personal-digest-preferences, digest-algo, cert-digest-algo, weak-digest,
// personal-cipher-preferences, compliance, trust-model, require-compliance and
// keyserver, the listing carried values for compliance, trust-model and
// keyserver only. So snug reads the files, and asks gpgconf only where they
// are: its homedir honours GNUPGHOME, its sysconfdir is the compiled-in
// /etc/gnupg.
//
// Which user file: gpg reads the first that exists of gpg.conf-<version>,
// gpg.conf-<major>.<minor>, gpg.conf-<major> and gpg.conf, and only that one
// — measured on 2.5.24, where gpg.conf-2.5.24 beat gpg.conf-2.5, gpg.conf-2.5
// beat gpg.conf, gpg.conf-2 beat gpg.conf, and a gpg.conf-2.5.2 or
// gpg.conf-2.4 was ignored. The system directory has no versioned variant: a
// /etc/gnupg/gpg.conf-2.5 was ignored beside /etc/gnupg/gpg.conf.
//
// Every failure is an error: a probe that could not run, a version it cannot
// read, a file that exists and cannot be read. Each would otherwise leave the
// sandbox's gpg on compiled-in defaults the host may have tightened. One of
// them is stricter than gpg: gpg skips a file it may not read (measured, mode
// 000: a gpg.conf gives compiled-in defaults, a gpg.conf-2.5 falls back to
// gpg.conf), and snug refuses instead of copying that.
func probeGPGConf() (gpgConfFiles, error) {
	var f gpgConfFiles
	gpgconf, err := exec.LookPath("gpgconf")
	if err != nil {
		return f, errors.New("identity.gpg needs gpgconf on the host to find gpg's " +
			"configuration, and no gpgconf is on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gpgHostTimeout)
	defer cancel()
	// Bare `--list-dirs`, read by name: with names as arguments gpgconf
	// prints the values in ITS order, not theirs (measured: `--list-dirs
	// homedir sysconfdir` printed /etc/gnupg first).
	out, err := exec.CommandContext(ctx, gpgconf, "--list-dirs").Output()
	if err != nil {
		return f, fmt.Errorf("identity.gpg: `gpgconf --list-dirs` failed: %v", err)
	}
	dirs := map[string]string{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			dirs[k] = v
		}
	}
	// A `%` is gpgconf's percent-escaping of a `:` or `%` in the path;
	// refused rather than decoded, as snug has never measured it.
	homedir, sysconfdir := dirs["homedir"], dirs["sysconfdir"]
	if !cleanAbs(homedir) || !cleanAbs(sysconfdir) ||
		strings.Contains(homedir+sysconfdir, "%") {
		return f, fmt.Errorf("identity.gpg: `gpgconf --list-dirs` gave homedir %q and sysconfdir %q, "+
			"and snug needs both as plain absolute paths", policy.VisibleText(homedir),
			policy.VisibleText(sysconfdir))
	}

	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return f, errors.New("identity.gpg needs gpg on the host, and none is on PATH")
	}
	vout, err := exec.CommandContext(ctx, gpg, "--batch", "--version").Output()
	if err != nil {
		return f, fmt.Errorf("identity.gpg: `gpg --version` failed: %v", err)
	}
	version, err := parseGPGVersion(string(vout))
	if err != nil {
		return f, err
	}

	f.systemPath = filepath.Join(sysconfdir, policy.GPGSystemConfName)
	if f.system, err = readGPGConf(f.systemPath); err != nil {
		return f, err
	}
	if f.system == nil {
		f.systemPath = ""
	}
	for _, name := range gpgUserConfNames(version) {
		p := filepath.Join(homedir, name)
		b, err := readGPGConf(p)
		if err != nil {
			return f, err
		}
		if b != nil {
			f.user, f.userPath = b, p
			break
		}
	}
	return f, nil
}

func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// maxGPGConfBytes bounds each gpg.conf read. A hand-written gpg.conf is a few
// dozen lines; a megabyte is not one.
const maxGPGConfBytes = 1 << 20

// readGPGConf is a file's bytes, or nil when gpg would find nothing there.
// ENOENT is the only absence: a dangling symlink gives it too, and gpg reads
// one as absent (measured). A FIFO, a device, a directory or an oversized file
// is refused by hostread rather than read.
func readGPGConf(p string) ([]byte, error) {
	b, err := hostread.Required(p, maxGPGConfBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity.gpg: cannot read %s (%v), so snug cannot carry the "+
			"host's gpg settings into the sandbox and will not start it on gpg's compiled-in "+
			"defaults instead.\n      Make it a readable file, or remove it if gpg is not meant "+
			"to read it", policy.VisibleText(p), err)
	}
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

var gpgVersionLine = regexp.MustCompile(`^gpg \(GnuPG[^)]*\) ([0-9]+(?:\.[0-9]+)*)$`)

// parseGPGVersion is the dotted version on `gpg --version`'s first line,
// "gpg (GnuPG) 2.5.24" on the development host.
func parseGPGVersion(out string) (string, error) {
	first, _, _ := strings.Cut(out, "\n")
	m := gpgVersionLine.FindStringSubmatch(strings.TrimSpace(first))
	if m == nil {
		return "", fmt.Errorf("identity.gpg: `gpg --version` begins %q, and snug needs the "+
			"dotted version to know which gpg.conf-<version> gpg reads", policy.VisibleText(first))
	}
	return m[1], nil
}

// gpgUserConfNames is the order gpg looks for its user file: the full version,
// then shorter by one component at a time, then the bare name.
func gpgUserConfNames(version string) []string {
	var out []string
	for v := version; v != ""; {
		out = append(out, policy.GPGSystemConfName+"-"+v)
		i := strings.LastIndexByte(v, '.')
		if i < 0 {
			break
		}
		v = v[:i]
	}
	return append(out, policy.GPGSystemConfName)
}

// probeAndStageGPGConf is probeGPGConf followed by stageGPGConf.
func probeAndStageGPGConf(pol *policy.Policy) error {
	f, err := probeGPGConf()
	if err != nil {
		return err
	}
	return stageGPGConf(pol, f)
}

// stageGPGConf mounts the generated gpg.conf files: the user one always, so
// --dry-run shows what the sandbox's gpg reads even on a host that sets
// nothing, and the system one only where the host has one, so the sandbox's
// gpg sees the same files present as the host's.
func stageGPGConf(pol *policy.Policy, f gpgConfFiles) error {
	userHost := f.userPath
	if userHost == "" {
		userHost = "(none: no gpg.conf in the host's GNUPGHOME)"
	}
	user, err := policy.GPGConfFrom(f.user, userHost, false)
	if err != nil {
		return fmt.Errorf("identity.gpg: %v", err)
	}
	if f.system != nil {
		system, err := policy.GPGConfFrom(f.system, f.systemPath, true)
		if err != nil {
			return fmt.Errorf("identity.gpg: %v", err)
		}
		pol.Replace(policy.Mount{
			Guest: f.systemPath, Kind: policy.KindData, Access: policy.AccessRO,
			Content: system, From: []string{identityProvenance(pol, "gpg")},
		})
	}
	pol.Replace(policy.Mount{
		Guest: pol.Home + "/" + policy.GPGConfGuest, Kind: policy.KindData,
		Access: policy.AccessRO, Content: user,
		From: []string{identityProvenance(pol, "gpg")},
	})
	return nil
}
