package dockerproxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryRefusedFieldExplainsItself: a refusal a user meets is the only
// explanation they get, and CLAUDE.md's rule is that errors name the fix. A
// field on the reject-list with no reason refuses with a bare "not permitted".
func TestEveryRefusedFieldExplainsItself(t *testing.T) {
	for _, k := range refusedHostConfig {
		reason, ok := refusalReason[k]
		if !ok {
			t.Errorf("HostConfig.%s is refused with no reason; the user gets \"not permitted\" and nothing else", k)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("HostConfig.%s has an empty reason", k)
		}
	}
	// The inverse, so a field deleted from the reject-list does not leave an
	// orphan reason behind to be read as though it still applied.
	for k := range refusalReason {
		found := false
		for _, r := range refusedHostConfig {
			if r == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("refusalReason has an entry for %q, which is not on refusedHostConfig — "+
				"a reason for a refusal that no longer happens", k)
		}
	}
}

// TestNoRefusalReasonDescribesTheHostSideEngine is the regression for issue
// #154 §B.
//
// Before Tier B (issue #63) the container engine ran on the host, so "the
// sandbox cannot reach it" was the honest reason for refusing PortBindings.
// The engine now runs inside the sandbox's own network namespace, and the
// sentence survived the move: it told a user that a published port lands
// somewhere unreachable and creates a host-visible surface, when the truth is
// that a container already shares the sandbox's netns and the engine holds no
// CAP_NET_ADMIN to publish anything at all. Nothing caught it, because the
// create-refusal table asserts only the "X is not permitted" prefix and never
// the reason — so the reason was untested prose next to tested code.
//
// This checks the CLASS rather than the one string: no refusal may explain
// itself by placing the engine, or a container, on the far side of a boundary
// that Tier B removed. It is deliberately a phrase blocklist with a positive
// control below, not a golden of the current wording — the point is to catch a
// stale MODEL, not to freeze the prose.
func TestNoRefusalReasonDescribesTheHostSideEngine(t *testing.T) {
	// Each phrase encodes "the engine is somewhere the sandbox is not".
	stale := []string{
		"the sandbox cannot reach",
		"engine's side of the world",
		"host-visible surface",
		"outside this sandbox's own",
		// Tier C (issue #125) made the engine's /dev the sandbox's own
		// synthetic tree with no host device nodes; #257 corrected the Devices
		// reason that still said device passthrough "reaches hardware the
		// sandbox cannot see". Same class — a reason placing the engine on the
		// far side of a boundary a later tier removed — so it guards here
		// (issue #146, #257).
		"hardware the sandbox cannot see",
		"reaches hardware",
	}

	for field, reason := range refusalReason {
		lower := strings.ToLower(reason)
		for _, phrase := range stale {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("HostConfig.%s's refusal reason contains %q, which describes the "+
					"pre-Tier-B world where the engine ran on the host (issue #63, #154).\n"+
					"reason: %s", field, phrase, reason)
			}
		}
	}

	// POSITIVE CONTROL. Without this the test above passes on an empty map,
	// on a map whose reasons are all "", and on a build where refusalReason
	// was renamed out from under it — every one of which reads as "no stale
	// model found".
	if len(refusalReason) < 10 {
		t.Fatalf("refusalReason has only %d entries; the sweep above proves nothing", len(refusalReason))
	}
	// POSITIVE CONTROL, per phrase: every stale phrase must be caught by a
	// sentence shaped like the defect it guards, so a phrase that matches
	// nothing cannot masquerade as coverage.
	poisoned := []string{
		"published ports land where the sandbox cannot reach them",
		"the engine's side of the world is unreachable, a host-visible surface outside this sandbox's own netns",
		"device passthrough reaches hardware the sandbox cannot see",
	}
	for _, phrase := range stale {
		caught := false
		for _, reason := range poisoned {
			if strings.Contains(strings.ToLower(reason), strings.ToLower(phrase)) {
				caught = true
				break
			}
		}
		if !caught {
			t.Errorf("no poisoned control sentence contains %q, so adding it to the stale list "+
				"proves nothing", phrase)
		}
	}
}

// TestPortRefusalsNameTheRealMechanism pins the replacement, not just the
// absence of the old one: a reader who hits this refusal must learn WHY
// publishing is meaningless here, or they will go looking for a flag that
// turns it on. There is none, and there cannot be one without granting the
// engine CAP_NET_ADMIN.
func TestPortRefusalsNameTheRealMechanism(t *testing.T) {
	for _, field := range []string{"PortBindings", "PublishAllPorts"} {
		reason, ok := refusalReason[field]
		if !ok {
			t.Fatalf("HostConfig.%s has no refusal reason at all", field)
		}
		if !strings.Contains(reason, "network namespace") {
			t.Errorf("HostConfig.%s's reason does not say the container shares this sandbox's "+
				"network namespace, which is the whole reason publishing is moot:\n%s", field, reason)
		}
	}
	// Only PortBindings claims the capability half: PublishAllPorts is
	// refused for the simpler reason and does not need to repeat it.
	if !strings.Contains(refusalReason["PortBindings"], "CAP_NET_ADMIN") {
		t.Errorf("HostConfig.PortBindings' reason does not name CAP_NET_ADMIN, so a reader "+
			"cannot tell whether publishing is forbidden by snug or impossible for the "+
			"engine — it is both, and the second is the one that cannot be relaxed:\n%s",
			refusalReason["PortBindings"])
	}
}

// TestEveryNamespaceModeExplainsItself is TestEveryRefusedFieldExplainsItself's
// twin for the per-key namespace-mode table (issue #145): a refusal a user
// meets is the only explanation they get, so every key in namespaceModeKeys
// needs a non-empty reason, and every reason in namespaceModeReason needs to
// still be a key that is actually refused — an orphan entry is a reason for a
// refusal that no longer happens, exactly as stale as an orphan in
// refusalReason would be.
func TestEveryNamespaceModeExplainsItself(t *testing.T) {
	for _, k := range namespaceModeKeys {
		reason, ok := namespaceModeReason[k]
		if !ok {
			t.Errorf("HostConfig.%s is a namespace-mode key with no entry in namespaceModeReason; "+
				"the user gets a bare %%q of the mode they sent and nothing else", k)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("HostConfig.%s has an empty namespace-mode reason", k)
		}
	}
	for k := range namespaceModeReason {
		found := false
		for _, nk := range namespaceModeKeys {
			if nk == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("namespaceModeReason has an entry for %q, which is not in namespaceModeKeys — "+
				"a reason for a namespace refusal that no longer happens", k)
		}
	}
}

// TestPidModeRefusalNamesTheDereference is TestPortRefusalsNameTheRealMechanism's
// analogue for PidMode (issue #145): a reader who hits this refusal must learn
// there is no flag and no narrower spelling, or they go hunting for one — the
// same "pin the replacement, not just the absence of the old one" rule.
//
// Three phrases the reason MUST contain, because they are the mechanism, not
// decoration: "/proc/" (the dereference path itself), "mount namespace" (what
// gets reached — a filesystem escape, not merely "more pids"), and
// "no capability" (the credential story: plain uid, nothing to revoke).
//
// Two phrases it must NOT contain, because they describe a world Tier B
// already ended: "the host's process table" and "the real host's pid
// namespace" both say the joined namespace is the MACHINE's, when since issue
// #125's C0 it is the ENGINE's — the same class of staleness
// TestNoRefusalReasonDescribesTheHostSideEngine polices for the reject-list.
func TestPidModeRefusalNamesTheDereference(t *testing.T) {
	reason, ok := namespaceModeReason["PidMode"]
	if !ok {
		t.Fatal("HostConfig.PidMode has no namespace-mode reason at all")
	}

	for _, must := range []string{"/proc/", "mount namespace", "no capability"} {
		if !strings.Contains(reason, must) {
			t.Errorf("PidMode's reason does not contain %q, so a reader cannot tell HOW joining "+
				"the engine's pid namespace reaches its filesystem:\n%s", must, reason)
		}
	}
	for _, mustNot := range []string{"the host's process table", "the real host's pid namespace"} {
		if strings.Contains(reason, mustNot) {
			t.Errorf("PidMode's reason contains %q, which describes the pre-C0 world where the "+
				"engine had no pid namespace of its own — since issue #125's C0 it does, and this "+
				"phrase sends a reader looking for a host-pidns flag that isn't the mechanism "+
				"any more:\n%s", mustNot, reason)
		}
	}
}

// TestNoNamespaceReasonClaimsTheEnginesPidNamespaceIsTheHosts is
// TestNoRefusalReasonDescribesTheHostSideEngine's C0 twin (issue #145, the
// #154 §B regression shape applied to the namespace-mode table rather than
// the reject-list): no namespace-mode reason may claim the engine's pid
// namespace still IS the host's, or that the engine does not unshare pid, or
// that refusing PidMode is the only thing standing between a container and a
// full host-pidns escape — every one of those became false the moment issue
// #125's C0 gave the engine CLONE_NEWPID, and a reason that still said so
// would send a reader hunting for a "the real fix" that already landed.
//
// A phrase blocklist with a positive control, same shape as its sibling: the
// point is to catch a stale MODEL, not to freeze the prose.
func TestNoNamespaceReasonClaimsTheEnginesPidNamespaceIsTheHosts(t *testing.T) {
	stale := []string{
		"the engine's own pid namespace is the real host",
		"does not unshare pid",
		"a full host-pidns escape",
		// Tier C (issue #125) made the engine's mount namespace its DERIVED
		// view, not a copy of the host tree; #257 corrected the PidMode reason
		// that still said so. Guard the revert here, in the same map, so the
		// correction has coverage rather than depending on nobody putting it
		// back (issue #146, #257).
		"private copy of the whole host tree",
		"copy of the host tree",
	}

	for field, reason := range namespaceModeReason {
		lower := strings.ToLower(reason)
		for _, phrase := range stale {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("HostConfig.%s's namespace-mode reason contains %q, which claims the "+
					"engine's pid namespace still is the host's — false since issue #125's C0.\n"+
					"reason: %s", field, phrase, reason)
			}
		}
	}

	// POSITIVE CONTROL. Without this the sweep above passes on an empty map,
	// on a map whose reasons are all "", and on a build where
	// namespaceModeReason was renamed out from under it.
	if len(namespaceModeReason) < 5 {
		t.Fatalf("namespaceModeReason has only %d entries; the sweep above proves nothing",
			len(namespaceModeReason))
	}
	// POSITIVE CONTROL, per phrase: each stale phrase must be caught by a
	// sentence shaped like the defect it guards, or a phrase could be added to
	// the list, match nothing, and read as coverage while proving nothing.
	poisoned := []string{
		"PidMode=host is refused because the engine's own pid namespace is the real host " +
			"pid namespace, since __inengine does not unshare pid — this is a full host-pidns escape",
		"PidMode=host reaches pid 1, whose mount namespace is a private copy of the whole host tree",
		"PidMode=host lands in the engine, whose view is a copy of the host tree",
	}
	for _, phrase := range stale {
		caught := false
		for _, reason := range poisoned {
			if strings.Contains(strings.ToLower(reason), strings.ToLower(phrase)) {
				caught = true
				break
			}
		}
		if !caught {
			t.Errorf("no poisoned control sentence contains %q, so adding it to the stale list "+
				"proves nothing — it would match no real defect either", phrase)
		}
	}
}

// stageCloneflagsRE extracts the RHS of internal/stage/fds.go's
// `const stageCloneflags = ...` declaration — up to the blank line that ends
// it, since the expression itself spans two source lines (each flag joined by
// `|`).
var stageCloneflagsRE = regexp.MustCompile(`(?s)const stageCloneflags = (.*?)\n\n`)

// engineCloneflagsRE extracts the RHS of internal/stage/enginefork.go's
// `Cloneflags: ...,` field inside startEngine's SysProcAttr literal.
var engineCloneflagsRE = regexp.MustCompile(`Cloneflags:\s*([^,\n]*),`)

// TestIpcAndUtsReasonsMatchTheEnginesActualCloneflags is what makes issue
// #182 (adding CLONE_NEWIPC|CLONE_NEWUTS to the engine fork) a SAFE change
// rather than one that silently falsifies two refusal reasons.
//
// namespaceModeReason["IpcMode"] and ["UTSMode"] both say, in prose, "the
// engine does not unshare IPC/UTS, so host here really is the machine's" —
// and that prose is a COPY of state actually held in two clone(2) flag sets:
// internal/stage/fds.go's stageCloneflags (P1's own fork) and
// internal/stage/enginefork.go's startEngine Cloneflags (the engine's own,
// separate fork). Prose about a clone flag that nothing re-checks is exactly
// the shape CLAUDE.md warns about ("the abuse sentence is written once and
// nothing re-reads it as the code grows around it") — this is the re-read.
//
// It reads the ACTUAL source text of both files (invariant 6's "one author"
// argument applied to prose instead of code: the constant is the state, this
// test is not a second copy of it) rather than importing the unexported
// constants — internal/stage does not export either, and it should not have
// to just so a doc-sync test in another package can see them.
func TestIpcAndUtsReasonsMatchTheEnginesActualCloneflags(t *testing.T) {
	stageSrc, err := os.ReadFile(filepath.Join("..", "stage", "fds.go"))
	if err != nil {
		t.Fatal(err)
	}
	engineSrc, err := os.ReadFile(filepath.Join("..", "stage", "enginefork.go"))
	if err != nil {
		t.Fatal(err)
	}

	stageMatch := stageCloneflagsRE.FindSubmatch(stageSrc)
	if stageMatch == nil {
		t.Fatal("control: stageCloneflagsRE did not find internal/stage/fds.go's stageCloneflags " +
			"declaration — it was renamed or reshaped, and this test needs to be updated to match")
	}
	engineMatch := engineCloneflagsRE.FindSubmatch(engineSrc)
	if engineMatch == nil {
		t.Fatal("control: engineCloneflagsRE did not find internal/stage/enginefork.go's " +
			"startEngine Cloneflags field — it was renamed or reshaped, and this test needs to be " +
			"updated to match")
	}

	stageFlags := string(stageMatch[1])
	engineFlags := string(engineMatch[1])

	// POSITIVE CONTROL: both extracted expressions actually name flags, so a
	// broken regex matching an empty capture does not pass this test by
	// finding nothing to search.
	if !strings.Contains(stageFlags, "CLONE_NEW") || !strings.Contains(engineFlags, "CLONE_NEW") {
		t.Fatalf("control: extraction found no CLONE_NEW* flag at all — stage=%q engine=%q, "+
			"the regex is matching the wrong text", stageFlags, engineFlags)
	}

	for _, flag := range []string{"CLONE_NEWIPC", "CLONE_NEWUTS"} {
		if strings.Contains(stageFlags, flag) || strings.Contains(engineFlags, flag) {
			t.Errorf("the ipc/uts refusal reasons say \"the engine does not unshare\" — it now "+
				"does (%s found in a clone flag set: stage=%q engine=%q); rewrite them", flag,
				stageFlags, engineFlags)
		}
	}
}
