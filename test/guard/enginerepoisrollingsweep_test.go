package guard

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ── THE ENGINE TIER READS A ROLLING TUMBLEWEED, BY RULING (issue #478) ───────
//
// The engine job exists to report when a NEW version of the software snug
// drives breaks snug — podman, crun, passt, bubblewrap. podman 5.x -> 6.x is
// the measured example of how large that change can be: the supported set
// refuses the 5.8.4 that ubuntu-latest ships, which is why the job runs
// Tumbleweed at all. A tree frozen at a dated snapshot answers a question
// nobody asked, and it answers it GREEN.
//
// Pinning `repo-oss` to `http://download.opensuse.org/history/<snapshot>/` was
// proposed with its measurement and refused. Reasoning lives at
// test/engine-container.sh's IMAGE= and is not repeated here.
//
// WHY THIS IS A TEST. The pin is attractive precisely when CI is annoying: it
// arrives as a one-line edit during an openSUSE incident, it turns the job
// green, and nothing else in the tree notices that the engine under test has
// stopped moving. The failure it causes is invisible for weeks and then
// arrives as "CI was green" on a break a developer already hit by hand. A
// comment does not catch that; the edit would be made by someone who has just
// read a red log, not this file.
//
// What is asserted is narrow on purpose — the two spellings that stop the
// engine moving:
//
//  1. the default image tag is `:latest`, in the script and in the dockerfile's
//     BASE_IMAGE;
//  2. no `/history/<snapshot>/` repository URL and no `zypper addrepo` anywhere
//     in the engine tier's three files.
//
// What is NOT asserted: that SNUG_ENGINE_IMAGE cannot be OVERRIDDEN. CI's own
// cache passes a baked `local/snug-engine-ci:latest`, and a developer pointing
// the script at a pinned image to reproduce one break is doing the right
// thing. The ruling is about the DEFAULT, which is what runs unattended.
var (
	engineImageDefaultRe = regexp.MustCompile(`(?m)^IMAGE=\$\{SNUG_ENGINE_IMAGE:-(\S+)\}$`)
	dockerfileBaseRe     = regexp.MustCompile(`(?m)^ARG BASE_IMAGE=(\S+)$`)
)

var enginePinSpellings = []struct{ needle, why string }{
	{"download.opensuse.org/history/", "a `/history/<snapshot>/` tree is a frozen repository: it cannot serve a podman newer than the snapshot, so the job stops being able to report a break"},
	{"zypper ar ", "an added repository is a second source the ruling did not judge"},
	{"zypper addrepo", "an added repository is a second source the ruling did not judge"},
}

func TestTheEngineTierReadsARollingTumbleweed(t *testing.T) {
	dockerfileRel := filepath.Join("test", "engine-container.dockerfile")
	files := map[string]string{
		engineScriptRel: repoFile(t, engineScriptRel),
		dockerfileRel:   repoFile(t, dockerfileRel),
		ciPath:          repoFile(t, ciPath),
	}

	for _, rel := range []string{engineScriptRel, dockerfileRel, ciPath} {
		body := files[rel]
		for _, p := range enginePinSpellings {
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue // the refusal is documented; documenting it is not doing it
				}
				if strings.Contains(line, p.needle) {
					t.Errorf("%s pins the engine tier's packages:\n\t%s\n%s\n"+
						"issue #478 ruled the repositories stay ROLLING. If this is a deliberate "+
						"reversal it is a maintainer ruling and this test is what it must change.",
						rel, strings.TrimSpace(line), p.why)
				}
			}
		}
	}

	for rel, re := range map[string]*regexp.Regexp{
		engineScriptRel: engineImageDefaultRe,
		dockerfileRel:   dockerfileBaseRe,
	} {
		m := re.FindStringSubmatch(files[rel])
		if m == nil {
			t.Fatalf("no default image line matching %s found in %s — if it was respelled, "+
				"this test's regexp is what must be updated, and the property it guards "+
				"(issue #478: the engine tier's DEFAULT image is rolling) still holds",
				re, rel)
		}
		if !strings.HasSuffix(m[1], ":latest") {
			t.Errorf("%s defaults the engine image to %q, which is not a rolling tag.\n"+
				"issue #478 ruled the engine tier reads a rolling Tumbleweed so the job can "+
				"report a break caused by a NEW podman; a pinned default reports nothing and "+
				"reports it green.", rel, m[1])
		}
	}
}
