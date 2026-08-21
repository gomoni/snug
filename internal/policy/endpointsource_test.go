package policy

import (
	"strings"
	"testing"
)

// resolveWithSource resolves a policy whose one extra profile binds host at
// {home}/mounted, with the fixture host told what KIND of thing host is.
func resolveWithSource(t *testing.T, kind string) error {
	t.Helper()
	const host = "/home/u/thing"

	env := newFakeEnv()
	switch kind {
	case "socket":
		env.sockets = map[string]bool{host: true}
	case "fifo":
		env.fifos = map[string]bool{host: true}
	case "file":
		env.files[host] = true
	case "dir":
		env.dirs[host] = true
	default:
		t.Fatalf("no such fixture kind %q", kind)
	}

	reg := testRegistry()
	reg["binder"] = &Profile{Name: "binder", RO: []string{host + ":/home/u/mounted"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), env)
	return err
}

// TestBindOfAnEndpointSourceIsRefused is issues #219 and #287's decided
// mechanism: a grant whose SOURCE is a unix socket OR a FIFO is refused,
// detected by mode rather than by path text.
//
// THE FOUR CASES ARE ONE TEST because the refusal has to be about the
// ENDPOINTNESS and nothing else. The same profile, the same guest path, the
// same host path — only what is AT that path changes. A file and a directory
// there must resolve cleanly, or the refusal is really about the path and
// would fire on grants it has no business refusing. socket and fifo are the
// two nouns rejectEndpointSource actually detects; file and dir are the
// POSITIVE CONTROLS, and without them a rejectEndpointSource that refused
// every bind at that path — regardless of what is there — would pass the
// negative half unnoticed.
func TestBindOfAnEndpointSourceIsRefused(t *testing.T) {
	for _, tc := range []struct {
		kind    string
		refused bool
	}{
		{"socket", true},
		{"fifo", true},
		{"file", false},
		{"dir", false},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			err := resolveWithSource(t, tc.kind)
			if tc.refused {
				if err == nil {
					t.Fatalf("a bind whose source is a %s was accepted. Read-only does not "+
						"restrain an endpoint: it stops the sandbox replacing the node and does "+
						"nothing about speaking THROUGH it — measured for a socket (issue #219, "+
						"a payload enumerated and signed with the host's ssh-agent) and for a "+
						"FIFO (issue #287, a payload wrote through it and a host reader received "+
						"the bytes while a plain file in the same read-only bind got EROFS)", tc.kind)
				}
				return
			}
			if err != nil {
				t.Errorf("a bind of a %s at the same path was refused: %v", tc.kind, err)
			}
		})
	}
}

// TestEndpointRefusalNamesTheRealRemediation is issue #289's regression test.
//
// An earlier version of this message named '@ssh-agent' — a profile snug does
// not ship, since the ssh-agent proxy is an [identity] block
// (`ssh_mode = "agent-proxy"`) selected by naming the profile that carries it,
// never a builtin of its own. `snug -p @ssh-agent` fails with
// `snug: unknown profile "@ssh-agent"`, so the refusal was pointing a human at
// a fix that did not exist, for a full milestone before anyone noticed. This
// pins BOTH halves: the message names the real remediation, and it does not
// name the profile that never resolves.
func TestEndpointRefusalNamesTheRealRemediation(t *testing.T) {
	for _, tc := range []struct{ kind, noun string }{
		{"socket", "SOCKET"},
		{"fifo", "FIFO"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			err := resolveWithSource(t, tc.kind)
			if err == nil {
				t.Fatalf("a bind whose source is a %s was accepted", tc.kind)
			}
			msg := err.Error()

			for _, want := range []string{
				// sandbox-tester: #289's real assertion goes here
				`ssh_mode = "agent-proxy"`,
				"ssh_key",
				"@podman-socket",
				"NOTE THE LIMIT",
				"DIRECTORY",
				tc.noun, // the noun actually found at THIS fixture's source
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("the %s refusal does not mention %q — errors name the fix, and this "+
						"one must also name its own gap and its own finding:\n%s", tc.kind, want, msg)
				}
			}

			if strings.Contains(msg, "@ssh-agent") {
				t.Errorf("the refusal names '@ssh-agent', a profile snug does not ship (issue "+
					"#289) — selecting it is the real symptom this regresses to:\n"+
					"    snug: unknown profile \"@ssh-agent\"\n"+
					"got instead:\n%s", msg)
			}
		})
	}
}

// TestSnugsOwnSocketsAreNotRefused is the exemption, and it is load-bearing
// rather than a convenience: snug's own proxy sockets ARE sockets.
//
// The ssh-agent proxy exposes one pinned key and enumerates nothing; the
// container proxy filters every request. Those are precisely the narrower
// alternatives the refusal exists to stop a mount from replacing, so refusing
// them would break both profiles — and would do it at the SECOND Validate, the
// one internal/cli runs after the proxies are bound, which is a failure mode
// that never reaches a unit test.
//
// Keyed on Authored, which Policy.Replace sets and nothing a profile can write
// reaches, so a profile cannot borrow the exemption. The second half of this
// test is what proves that: the same socket, same path, WITHOUT Authored, is
// refused.
func TestSnugsOwnSocketsAreNotRefused(t *testing.T) {
	const sock = "/run/user/1000/snug/run-1/ssh-agent.sock"

	env := newFakeEnv()
	env.sockets = map[string]bool{sock: true}

	p := mustResolve(t, "@sys", "@cwd-rw")
	p.BindSocket(sock, AgentSocketGuest, "(identity)")
	if err := p.Validate(env); err != nil {
		t.Fatalf("snug's own proxy socket was refused: %v\n\nEvery ssh_mode=\"agent-proxy\" "+
			"and @podman-socket run would fail at internal/cli's second Validate", err)
	}

	// The same mount without authorship — what a profile could express — must
	// still be refused, or the exemption is a hole rather than an author
	// distinction.
	p2 := mustResolve(t, "@sys", "@cwd-rw")
	p2.Mounts[AgentSocketGuest] = Mount{
		Guest: AgentSocketGuest, Host: sock, Kind: KindBind,
		Access: AccessRW, From: []string{"someprofile"},
	}
	if err := p2.Validate(env); err == nil {
		t.Error("an unauthored bind of the same socket was accepted: the exemption is keyed " +
			"on something a profile can produce, which makes it a loophole rather than the " +
			"author distinction it is meant to be")
	}
}

// TestASymlinkToAnEndpointIsRefused is issue #287's other half of #219's
// symlink question: a grant whose SOURCE is a SYMLINK to a FIFO must be
// refused exactly as a grant naming the FIFO directly would be.
//
// env.Stat is os.Stat (never os.Lstat) and so FOLLOWS the final symlink —
// which is what bwrap's own --ro-bind does too, since it opens the path
// rather than the link. This test pins that the fixture and the real bind
// mechanism agree: a fake environment that answered Stat by inspecting the
// SYMLINK itself (always a regular file, mode-wise) would let this case
// through, and would be lying about what bwrap actually opens.
func TestASymlinkToAnEndpointIsRefused(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u/link"] = "/home/u/agent-fifo"
	env.fifos = map[string]bool{"/home/u/agent-fifo": true}

	reg := testRegistry()
	reg["binder"] = &Profile{Name: "binder", RO: []string{"{home}/link:/home/u/mounted"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), env)
	if err == nil {
		t.Fatal("a bind whose source is a SYMLINK to a FIFO was accepted — resolution " +
			"canonicalises the host side with EvalSymlinks before rejectEndpointSource ever " +
			"stats it, so the mount is stored at the FIFO's own resolved path and the refusal " +
			"must fire exactly as it would for a grant naming the FIFO directly")
	}
	if !strings.Contains(err.Error(), "FIFO") {
		t.Errorf("the refusal does not say FIFO — a symlink to an endpoint must be refused for "+
			"the SAME reason as the endpoint itself, not a different or vaguer one: %v", err)
	}
}

// TestEndpointRefusalIsNotAPathList pins the shape the maintainer's decision
// turns on (issues #219 and #287, and #207's deleted catalogue before both).
//
// The catalogue died because a maintained list of path strings is defeated by
// spelling one path five ways — #189 measured three of five going unmarked. A
// stat does not care how a path was spelled, so the same socket or FIFO
// reached by a differently-spelled path is refused just the same. If this test
// ever needs a path ADDED to make it pass, the implementation has drifted back
// into the catalogue shape #207 deleted.
func TestEndpointRefusalIsNotAPathList(t *testing.T) {
	for _, tc := range []struct{ kind, spelling string }{
		{"socket", "/home/u/agent.sock"},
		{"socket", "/home/u/.ssh/S.gpg-agent"},
		{"socket", "/home/u/some/deeply/nested/thing-that-is-not-in-any-list"},
		{"socket", "/home/u/docker.sock"},
		// The FIFO spellings, deliberately reusing one of the socket paths'
		// OWN shape (S.gpg-agent — gpg-agent really does offer a FIFO-shaped
		// control channel alongside its socket on some hosts) plus one with no
		// resemblance to anything on any list.
		{"fifo", "/home/u/.gnupg/S.gpg-agent"},
		{"fifo", "/home/u/deeply/nested/pipe"},
	} {
		t.Run(tc.kind+"/"+tc.spelling, func(t *testing.T) {
			env := newFakeEnv()
			switch tc.kind {
			case "socket":
				env.sockets = map[string]bool{tc.spelling: true}
			case "fifo":
				env.fifos = map[string]bool{tc.spelling: true}
			}
			reg := testRegistry()
			reg["binder"] = &Profile{Name: "binder", RO: []string{tc.spelling + ":/home/u/mounted"}}
			_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), env)
			if err == nil {
				t.Errorf("a %s at %s was accepted — the check is matching path text rather "+
					"than asking the filesystem what is there", tc.kind, tc.spelling)
			}
		})
	}
}
