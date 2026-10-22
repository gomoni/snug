package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

const goldenGPGFingerprint = "6732361300BBFDAE7F22972CD4381E1CE2880244"

// gpgGoldenPolicy resolves the builtin defaults plus one profile pinning
// goldenGPGFingerprint with the given scope, and stages what a dry run stages:
// the agent socket from startGPGIdentity and, standing in for the host's
// `gpg --export`, a fixed keyring. The host gpg is pointed at an empty
// throwaway GNUPGHOME so nothing on the machine running the suite is read.
func gpgGoldenPolicy(t *testing.T, scope string) *policy.Policy {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("GNUPGHOME", shortGnupgHome(t))
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["signer"] = &policy.Profile{Name: "signer", Identity: &policy.Identity{
		GPG: policy.IdentityGPG{Fingerprint: goldenGPGFingerprint, Scope: scope}}}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "signer")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	cleanup, err := startGPGIdentity(p, p.Identity, false, true)
	if err != nil {
		t.Fatalf("startGPGIdentity: %v", err)
	}
	t.Cleanup(cleanup)
	// What a real run adds once the host gpg exports the key. The dry run
	// above could not, and said so on stderr.
	stageGPGKeyring(p, []byte("PUBLIC-KEYRING-FIXTURE"))
	p.InstallAnchors()
	if err := p.Validate(newEnvFakeEnv()); err != nil {
		t.Fatalf("Validate after staging: %v", err)
	}
	return p
}

// shortGnupgHome is an empty 0700 directory under /tmp: gpg refuses a
// homedir with loose permissions and a long path would pass the socket limit.
func shortGnupgHome(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// TestGoldenGPGArgv is the review artifact for identity.gpg's bwrap argv: the
// 0700 tmpfs at ~/.gnupg, the proxy socket and the PUBLIC keyring inside it,
// GNUPGHOME, and — for a sign scope only — the generated gitconfig. It would
// show a diff if the host's ~/.gnupg, a private key path, or a secret keyring
// ever appeared. The pubring bytes are a fixture; what the host gpg would
// export is covered by TestHostGPGEndToEnd.
func TestGoldenGPGArgv(t *testing.T) {
	cases := []struct {
		name, scope, golden string
		gitconfig           bool
	}{
		{"sign+decrypt", "decrypt,sign", "identity-gpg.bwrap.txt", true},
		{"decrypt only", "decrypt", "identity-gpg-decrypt.bwrap.txt", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := gpgGoldenPolicy(t, tc.scope)
			got := runDirPID.ReplaceAllString(goldenFormat(p.BwrapArgs(1000, 1000)), "run-N")

			for _, want := range []string{"--perms 0700\n--size 1073741824\n--tmpfs /home/u/.gnupg\n", "GNUPGHOME",
				"/home/u/.gnupg/S.gpg-agent", "/home/u/.gnupg/pubring.kbx"} {
				if !strings.Contains(got, want) {
					t.Errorf("argv lacks %q:\n%s", want, got)
				}
			}
			// The keyring is data behind an fd: the host's own ~/.gnupg is not
			// bound by any line, and no line names a private key store.
			for _, line := range strings.Split(got, "\n") {
				if strings.Contains(line, "private-keys") || strings.Contains(line, "secring") ||
					strings.Contains(line, "trustdb") {
					t.Errorf("argv names key material: %q", line)
				}
			}
			if has := strings.Contains(got, "/home/u/.gitconfig"); has != tc.gitconfig {
				t.Errorf("generated ~/.gitconfig present = %v, want %v for scope %q", has, tc.gitconfig, tc.scope)
			}
			checkGolden(t, tc.golden, got, "this is the argv for a sandbox that may use one OpenPGP key through a filtering agent proxy")
		})
	}
}

// TestGoldenGPGDryRunBlocks is what a human reads before trusting identity.gpg:
// the GPG block naming the key and what each scope lets the sandbox do, and
// the FILESYSTEM block showing the 0700 ~/.gnupg, the socket and the keyring.
// A sign grant and a decrypt grant are different abuse sentences, so both are
// pinned, and the decrypt-only screen must not claim signing.
func TestGoldenGPGDryRunBlocks(t *testing.T) {
	for _, tc := range []struct{ name, scope, golden string }{
		{"sign+decrypt", "decrypt,sign", "gpg.dryrun.txt"},
		{"decrypt only", "decrypt", "gpg-decrypt.dryrun.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := gpgGoldenPolicy(t, tc.scope)
			var b bytes.Buffer
			describeGPG(&b, buildGPGReport(p))
			block := b.String()
			if !strings.Contains(block, goldenGPGFingerprint) {
				t.Errorf("GPG block does not name the pinned key:\n%s", block)
			}
			if strings.Contains(block, "sign ") != strings.Contains(tc.scope, "sign") {
				t.Errorf("GPG block's sign line disagrees with scope %q:\n%s", tc.scope, block)
			}

			screen := captureFile(t, func(f io.Writer) {
				dryRun(newEnvFakeEnv(), f, p, []string{"/bin/sh"}, config{}, nil, nil)
			})
			fs := strings.TrimRight(blockBetween(t, screen, "FILESYSTEM", "NOT GRANTED"), " \n") + "\n"
			for _, want := range []string{".gnupg", "S.gpg-agent", "pubring.kbx"} {
				if !strings.Contains(fs, want) {
					t.Errorf("FILESYSTEM block lacks %q:\n%s", want, fs)
				}
			}
			if !strings.Contains(screen, "\nGPG ") {
				t.Errorf("the dry-run screen has no GPG block:\n%s", screen)
			}
			checkGolden(t, tc.golden, runDirPID.ReplaceAllString(block, "run-N"),
				"this is what a human reads to decide whether a profile may sign or decrypt as them")
			checkGolden(t, strings.Replace(tc.golden, ".dryrun.txt", ".filesystem.txt", 1),
				runDirPID.ReplaceAllString(fs, "run-N"), "this is the FILESYSTEM block of a sandbox with a gpg proxy")
		})
	}
}

// TestGoldenShowGPGCapabilities is `profile show` for a gpg pin: one row per
// scope, each naming what that scope lets the sandbox do. It reproduces the
// render closure config.go builds, as TestGoldenShowIdentityCapabilities does.
func TestGoldenShowGPGCapabilities(t *testing.T) {
	prof := &policy.Profile{Name: "signer", Identity: &policy.Identity{
		GPG: policy.IdentityGPG{Fingerprint: goldenGPGFingerprint, Scope: "decrypt,sign"}}}
	var b strings.Builder
	show := func(label string, vals []string) {
		for i, v := range vals {
			head := ""
			if i == 0 {
				head = label
			}
			fmt.Fprintf(&b, "  %-16s %s\n", head, visibleValue(v))
		}
	}
	showCapabilities(prof, show)
	got := b.String()
	for _, want := range []string{"gpg key " + goldenGPGFingerprint + " (sign)",
		"gpg key " + goldenGPGFingerprint + " (decrypt)"} {
		if !strings.Contains(got, want) {
			t.Errorf("profile show lacks the row %q:\n%s", want, got)
		}
	}
	checkGolden(t, "show-identity-gpg.capabilities.txt", got,
		"this is the screen a human reads to decide whether to select a profile that may sign or decrypt as them")
}

// TestDryRunJSONMarksOnlyDataFilesExecutable: the 0700 on the generated
// ~/.gnupg tmpfs carries an execute bit, and "executable" is the machine
// format's word for staged CODE. Read off Perms alone, it flagged a directory
// as code. Positive control: the ~/.gnupg mount IS in the document with kind
// tmpfs, so the false could not come from the mount being absent.
func TestDryRunJSONMarksOnlyDataFilesExecutable(t *testing.T) {
	p := gpgGoldenPolicy(t, "decrypt,sign")
	env := newEnvFakeEnv()
	rep := buildReport(env, p, p.BwrapArgs(0, 0), config{json: true}, nil,
		func() engine.SignaturePolicySummary { return engine.SignaturePolicySummary{} })
	rep.Seccomp = jsonGoldenSeccomp
	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	var doc struct {
		Mounts []struct {
			Guest      string `json:"guest"`
			Kind       string `json:"kind"`
			Executable bool   `json:"executable"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	found := false
	for _, m := range doc.Mounts {
		if m.Guest == "/home/u/.gnupg" {
			found = true
			if m.Kind != "tmpfs" {
				t.Errorf("~/.gnupg kind = %q, want tmpfs", m.Kind)
			}
			if m.Executable {
				t.Error("the 0700 tmpfs at ~/.gnupg is reported executable")
			}
		}
	}
	if !found {
		t.Fatalf("control: ~/.gnupg is not among the document's mounts: %+v", doc.Mounts)
	}
}

// TestDryRunJSONCarriesTheGPGGrant: the human screen's GPG block names the key
// and the scope, so the --json document must too — a CI gate cannot assert on a
// fact only the human screen carries.
func TestDryRunJSONCarriesTheGPGGrant(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  []string
	}{
		{"decrypt,sign", []string{"sign", "decrypt"}},
		{"decrypt", []string{"decrypt"}},
	} {
		p := gpgGoldenPolicy(t, tc.scope)
		var b bytes.Buffer
		if err := renderJSON(&b, Report{Outcome: "ok", GPG: buildGPGReport(p)}); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			GPG *jsonGPG `json:"gpg"`
		}
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.GPG == nil || doc.GPG.Fingerprint != goldenGPGFingerprint ||
			strings.Join(doc.GPG.Scope, ",") != strings.Join(tc.want, ",") ||
			!strings.HasSuffix(doc.GPG.Proxy, "/.gnupg/S.gpg-agent") {
			t.Errorf("scope %q: json gpg = %+v", tc.scope, doc.GPG)
		}
	}
}
