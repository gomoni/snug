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

// TestBindOfASocketSourceIsRefused is issue #219's decided mechanism: a grant
// whose SOURCE is a unix socket is refused, detected by mode rather than by
// path text.
//
// THE THREE CASES ARE ONE TEST because the refusal has to be about the
// socketness and nothing else. The same profile, the same guest path, the same
// host path — only what is AT that path changes. A file and a directory there
// must resolve cleanly, or the refusal is really about the path and would fire
// on grants it has no business refusing.
func TestBindOfASocketSourceIsRefused(t *testing.T) {
	err := resolveWithSource(t, "socket")
	if err == nil {
		t.Fatal("a bind whose source is a unix socket was accepted. Read-only does not " +
			"restrain a socket: it stops the sandbox replacing it and does nothing about " +
			"speaking to whatever listens on it, which is how a payload enumerated the " +
			"host's ssh-agent and signed with it (issue #219)")
	}
	msg := err.Error()

	for _, want := range []string{
		"SOCKET",         // says what was found
		"@ssh-agent",     // names the narrower thing to select instead
		"NOTE THE LIMIT", // and what the check does not cover
		"DIRECTORY",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q — errors name the fix, and this one must "+
				"also name its own gap:\n%s", want, msg)
		}
	}

	// POSITIVE CONTROLS. Without these, a rejectSocketSource that refused every
	// bind at that path would pass the assertion above.
	for _, kind := range []string{"file", "dir"} {
		if err := resolveWithSource(t, kind); err != nil {
			t.Errorf("a bind of a %s at the same path was refused: %v", kind, err)
		}
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
		t.Fatalf("snug's own proxy socket was refused: %v\n\nEvery @ssh-agent and "+
			"@podman-socket run would fail at internal/cli's second Validate", err)
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

// TestSocketRefusalIsNotAPathList pins the shape the maintainer's decision
// turns on (issue #219, and #207's deleted catalogue before it).
//
// The catalogue died because a maintained list of path strings is defeated by
// spelling one path five ways — #189 measured three of five going unmarked. A
// stat does not care how a path was spelled, so the same socket reached by a
// differently-spelled path is refused just the same. If this test ever needs a
// path added to make it pass, the implementation has drifted back into a list.
func TestSocketRefusalIsNotAPathList(t *testing.T) {
	for _, spelling := range []string{
		"/home/u/agent.sock",
		"/home/u/.ssh/S.gpg-agent",
		"/home/u/some/deeply/nested/thing-that-is-not-in-any-list",
		"/home/u/docker.sock",
	} {
		t.Run(spelling, func(t *testing.T) {
			env := newFakeEnv()
			env.sockets = map[string]bool{spelling: true}
			reg := testRegistry()
			reg["binder"] = &Profile{Name: "binder", RO: []string{spelling + ":/home/u/mounted"}}
			_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), env)
			if err == nil {
				t.Errorf("a socket at %s was accepted — the check is matching path text rather "+
					"than asking the filesystem what is there", spelling)
			}
		})
	}
}
