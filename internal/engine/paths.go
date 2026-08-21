package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gomoni/snug/internal/policy"
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
	// Store persists across runs and is SHARED with every other sandbox
	// resolving to the same profiles+target key. It is keyed rather than
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

// engineKey is the profiles+target hash both the store and the runroot are
// named by. One function, because two spellings of this hash would silently
// give a run a cold store.
func engineKey(profiles []policy.ProfileName, target string) string {
	sorted := policy.NameStrings(profiles)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ",") + "\x00" + target))
	return hex.EncodeToString(sum[:])[:16]
}

// planPaths computes the four paths for a run whose run directory is named
// runDir. It touches nothing: every value here is string arithmetic over the
// environment, which is why --dry-run can call it.
func planPaths(profiles []policy.ProfileName, target, runDirName string) (Paths, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	key := engineKey(profiles, target)
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
func PlannedPaths(profiles []policy.ProfileName, target string) (Paths, error) {
	return planPaths(profiles, target, fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()))
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
			"every other sandbox resolving to the same profiles+target key — so a layer a " +
			"container poisons outlives the sandbox that pulled it, and is there for the next " +
			"run of the same project",
	}); err != nil {
		return fmt.Errorf("grafting the engine's image store: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: policy.EngineRunrootGuest, Host: ps.Runroot,
			Kind: policy.KindGraft, Access: policy.AccessRW, From: []string{"(snug)"},
		},
		Why: "write into the engine's runroot, which is keyed by profiles+target rather than " +
			"by pid (podman's libpod database refuses a runroot that disagrees with the one it " +
			"recorded), so it is reachable by a concurrent sandbox with the same key",
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
