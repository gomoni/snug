package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/targetkey"
)

// Paths are the four host directories a run's engine uses, as VALUES rather
// than as directories that exist. They are what the store/runroot/sock/conf
// grafts are built from (GraftPathsInto), and computing them is separate from
// creating them for one reason: --dry-run has to be able to SHOW those grafts
// while creating nothing at all (issues #252 and #21).
//
// The toolchain is deliberately not here. It is a preflight ANSWER
// (containerpreflight.go's P9), not a path derived from the run's key, and
// --dry-run runs no preflight — see startContainers's own comment on why a
// debugging command does no host probing. So a dry run can name four of the
// five grafts and says so rather than inventing the fifth.
type Paths struct {
	// Store persists across runs and is SHARED with every other sandbox on
	// the SAME TARGET DIRECTORY, whatever profiles it selected (issue #276:
	// the profile selection was removed from the key — see engineKey's own
	// doc comment for why it may never come back). It is keyed rather than
	// pid-unique on purpose: that sharing is what makes a warm start warm.
	Store string
	// Runroot is keyed the same way, and must be: podman's libpod database
	// lives in the store and refuses a later run whose runroot disagrees with
	// the one it recorded.
	Runroot string
	// SockDir and ConfDir are this RUN's own, under its own run directory,
	// split by writability (issue #125, C2b): the engine creates its socket in
	// one and only ever reads the generated config in the other.
	SockDir string
	ConfDir string
}

// engineKey is the TARGET's hash, and nothing else — see issue #276. It used
// to also hash the sorted profile set, which meant adding one inert profile
// to a selection moved a project to a cold store for no reason a user could
// see, and it made the runroot's name (below, under world-writable /tmp)
// LESS predictable only by as much entropy as the profile set added, which
// was never the guarantee actually protecting it (that guarantee is
// VerifyOwnedAndPrivate's uid+mode check — see New).
//
// # The soundness rule, for whoever proposes a coarser key next
//
// Let L(x) be the equivalence class the per-target lock enforces
// (internal/cli's lockTarget, keyed on sha256(realpath) — see
// ONE-SANDBOX-PER-DIR.md) and S(x) the store's own partition — two targets
// share a key iff engineKey returns the same string for both. The property
// snug depends on is S(a) = S(b) ⟹ L(a) = L(b): the store's partition must be
// AT LEAST AS FINE as the lock's, so "at most one live user of a given store"
// falls out of an invariant snug already enforces, rather than needing its
// own proof. Today S = L exactly, because both hash the identical canonical
// target string. A key COARSER than the lock — a global store, or any key
// that merges two different targets into one hash — is the UNSOUND
// direction: it would let a second run reach a store a live sandbox still
// owns, and no test catches that by construction the way this one does.
//
// pol.Target is ALREADY canonical: policy.Resolve runs EvalSymlinks on it
// (internal/policy/resolve.go) before storing it, and types.go's own doc
// comment says so. This function must NOT call EvalSymlinks a second time —
// that would only create drift between two supposedly-identical forms of the
// same string, which is the defect issue #276 falsified rather than one it
// introduces. Residual, named rather than claimed closed: Resolve
// canonicalises once, and bwrap walks {target} again later when the sandbox
// actually starts, so a symlink flipped in the window between the two makes
// the store key name one project while the bind lands on another. The
// per-target lock carries the identical window; this change neither creates
// nor widens it.
//
// It is now internal/targetkey's Hash, applied to pol.Target: see that
// package's doc comment for why every target-derived name on disk goes
// through one function, and why that function returns the FULL hex digest
// rather than a truncation. engineKey used to be its own truncated
// sha256.Sum256; KeyForTarget below is the exported, string-only half other
// packages (issue #308's `snug engine gc`) need to re-derive the identical
// key from a target string without a *policy.Policy to hand.
func engineKey(pol *policy.Policy) string {
	return KeyForTarget(pol.Target)
}

// KeyForTarget is engineKey's pure string-only half, exported so a caller
// that only has a target string — not a *policy.Policy — can compute the
// identical store key. `snug engine gc` uses it to check a breadcrumb's
// recorded target against the directory name that carries it
// (orphansweep.go's "the name is the index", applied to the store).
func KeyForTarget(target string) string {
	return targetkey.Hash(target)
}

// dataHomeDir returns $XDG_DATA_HOME, or ~/.local/share when it is unset.
// String arithmetic only — no filesystem access — so both planPaths (which
// must stay pure for --dry-run) and New's vdir walk, which creates and
// verifies what this names, compute the identical value.
func dataHomeDir() (string, error) {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}

// planPaths computes the four paths for a run whose run directory is named
// runDir. It touches nothing: every value here is string arithmetic over the
// environment, which is why --dry-run can call it.
func planPaths(pol *policy.Policy, runDirName string) (Paths, error) {
	dataHome, err := dataHomeDir()
	if err != nil {
		return Paths{}, err
	}
	key := engineKey(pol)
	runDir := filepath.Join(os.TempDir(), runDirName)
	return Paths{
		Store:   filepath.Join(dataHome, "snug", "engines", key, "storage"),
		Runroot: filepath.Join(os.TempDir(), fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key), "rr"),
		SockDir: filepath.Join(runDir, "sock"),
		ConfDir: filepath.Join(runDir, "conf"),
	}, nil
}

// PlannedPaths is planPaths for the --dry-run path, and the run-directory name
// it uses is the one a real run's FIRST engine gets.
//
// It does not call runDirName(): that function allocates from a per-process
// counter, so calling it here would both consume a sequence number and make
// this function impure for a caller whose whole contract is that it changes
// nothing. A dry run starts no engine, so there is exactly one name to
// predict, and predicting it is what lets --dry-run print the same paths the
// run would use.
func PlannedPaths(pol *policy.Policy) (Paths, error) {
	return planPaths(pol, fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()))
}

// GraftPathsInto records the engine's host-tree grafts — store, runroot, sock,
// conf, and the toolchain when the policy knows one — into p.
//
// It takes Paths rather than an *Engine so that BOTH callers go through the
// same writer: the real run (Engine.GraftInto, from its own created
// directories) and --dry-run (from PlannedPaths). Two functions recording
// "the engine's grafts" would be two authors of one fact, and the one that
// --dry-run used would be the one nobody ran in production — the exact shape
// that let the grafts go unprinted for a whole tier (issue #252).
//
// Every Why here is the abuse sentence for a hand-over a container run makes,
// and the reason this must reach --dry-run at all: the store graft is
// read-write, shared, and outlives the sandbox.
func GraftPathsInto(env policy.Environ, p *policy.Policy, ps Paths) error {
	for _, host := range []string{ps.Store, ps.Runroot, ps.SockDir, ps.ConfDir} {
		if err := p.OwnEngineHostPath(env, host); err != nil {
			return fmt.Errorf("declaring %s as this run's own: %w", host, err)
		}
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineStoreGuest, Host: ps.Store,
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"},
		},
		Why: "write image layers into a store that PERSISTS across runs and is shared with " +
			"every other sandbox on the SAME TARGET DIRECTORY, whatever profiles it selected " +
			"— so a run with a narrow selection inherits what a broader one pulled, and a layer " +
			"a container poisons outlives the sandbox that pulled it, and is there for the next " +
			"run of the same project",
	}); err != nil {
		return fmt.Errorf("grafting the engine's image store: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineRunrootGuest, Host: ps.Runroot,
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"},
		},
		Why: "write into the engine's runroot, which is keyed by the TARGET DIRECTORY rather " +
			"than by pid (podman's libpod database refuses a runroot that disagrees with the " +
			"one it recorded), so a LATER run of the same project inherits whatever an earlier " +
			"one left there",
	}); err != nil {
		return fmt.Errorf("grafting the engine's runroot: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineSockGuest, Host: ps.SockDir,
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"},
		},
		Why: "create or replace the socket the container proxy dials — the engine must be " +
			"able to bind it, which is why this half of the run directory is writable and the " +
			"other half is not",
	}); err != nil {
		return fmt.Errorf("grafting the engine's socket directory: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineConfGuest, Host: ps.ConfDir,
			Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
		},
		Why: "READ every configuration file snug generated for it — and only read them: this " +
			"is the half of the run directory that is read-only, so an engine that is talked " +
			"into writing cannot rewrite the storage, registry or signature policy it was " +
			"started under, nor turn the deliberately EMPTY auth file into a usable one",
	}); err != nil {
		return fmt.Errorf("grafting the engine's config directory: %w", err)
	}

	// The toolchain, only when this host has one outside every grant. A
	// distribution podman in /usr/bin needs nothing here: @sys already binds
	// the OS runtime and the engine's view is derived from the sandbox's, so
	// the binary is simply there.
	//
	// On the --dry-run path this is ALWAYS empty, because the preflight that
	// answers it does not run there. describeEngineView says so on screen
	// rather than leaving a reader to conclude there is no toolchain graft.
	toolchainRoot := p.EngineToolchainRoot
	if toolchainRoot == "" {
		return nil
	}
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineToolchainGuest, Host: toolchainRoot,
			Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
		},
		Why: "READ the engine's own program files — the binary it is about to exec and every " +
			"helper it resolves — from the host user's installation. Read-only: it is the " +
			"user's own tree rather than something snug created for this run, so a writable " +
			"graft of it would be a host-write channel out of the engine",
	}); err != nil {
		return fmt.Errorf("grafting the engine's toolchain: %w", err)
	}
	return nil
}
