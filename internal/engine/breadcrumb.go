package engine

// breadcrumb.go is engines/<key>/store.json — issue #308's answer to "why is
// this store here and when was it last used", written by snug itself,
// BESIDE storage/ and never inside it.
//
// Sibling, not child, and that is load-bearing rather than tidy: Paths.Store
// is …/engines/<key>/storage (paths.go) and THAT directory alone is what
// GraftPathsInto grafts read-write into a running sandbox — engines/<key>/
// itself is never bound in. A breadcrumb inside storage/ would be text a
// payload can author, that `snug engine gc` then prints to a human and acts
// on. Abuse sentence: a hostile process inside the sandbox can use a
// writable breadcrumb to make the GC report someone else's project, or print
// terminal escapes into the report, and steer a human into deleting a store
// they meant to keep. Putting it beside storage/ instead of inside it closes
// that: nothing the payload writes can reach this file.
//
// THREE TRUST STATES, not two — see BreadcrumbState below and CLAUDE-facing
// docs on `snug engine gc`'s report. "No breadcrumb" and "a breadcrumb lying
// about its own directory" must never collapse into the same bucket: the
// first is an ordinary gap (a store older than this file, or a run whose
// write failed), the second is corrupted or hostile input, and only the
// first is expected to drain on its own as real runs write breadcrumbs.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// BreadcrumbSchema is the store.json schema version this build writes and
// understands. A FUTURE build changing the shape bumps this; a PAST or
// unknown value is read as BreadcrumbCorrupt (never as absent-and-deletable)
// so an older or newer snug's file is never guessed at.
const BreadcrumbSchema = 1

// breadcrumbName is the file's own name, a constant rather than a literal
// repeated at each call site.
const breadcrumbName = "store.json"

// Breadcrumb is engines/<key>/store.json's whole shape. Nothing else: no
// profile selection (removed from the KEY itself by issue #276, and it does
// not belong in the breadcrumb either — a store is shared across whatever
// profiles select it) and no cached size (a number on disk is a copy of a
// fact the filesystem itself already holds, and it would go stale the moment
// a container writes another layer).
type Breadcrumb struct {
	Schema int    `json:"schema"`
	Target string `json:"target"`
	// Created is set once, on the FIRST New() for a given key, and carried
	// forward by every later write to the same key — see writeBreadcrumb.
	Created string `json:"created"`
	// LastUsed is written by SNUG, at engine start, deliberately never
	// copied from a file's mtime: everything under storage/ is
	// payload-writable, and utimensat(2) lets the payload set an arbitrary
	// mtime in EITHER direction, so an mtime-based TTL is both evadable (set
	// it to "now" forever) and triggerable (set it to "ancient" to bait a
	// human into deleting a store still in use). This field sits OUTSIDE the
	// graft, so nothing inside the sandbox can touch it — it is the only
	// recency signal `snug engine gc` can trust.
	LastUsed string `json:"last_used"`
}

// BreadcrumbState is what ReadBreadcrumb found, checked rather than trusted.
type BreadcrumbState int

const (
	// BreadcrumbMissing: no store.json. Ordinary — a store older than this
	// file, or a run whose write failed (writeBreadcrumb's own doc comment).
	// Reported as unattributed, and the set is expected to be large right
	// after this feature lands (every store created before it) and to drain
	// as real runs write breadcrumbs; it is not evidence anything is wrong.
	BreadcrumbMissing BreadcrumbState = iota
	// BreadcrumbCorrupt: present but unparseable, an unrecognised schema, or
	// a forging rune (policy.IsForgingRune) in Target. Reported as
	// unattributed AND flagged — never treated as absent-and-deletable.
	BreadcrumbCorrupt
	// BreadcrumbMismatched: parses cleanly, known schema, but
	// KeyForTarget(Target) does not equal the directory name that carries
	// it under EITHER generation that name may be in (ReadBreadcrumb also
	// accepts a legacy, pre-issue-#349 directory name whose digest matches
	// once labelled — that is snug's own rename, not a mismatch) — the same
	// "the name is the index" check orphansweep.go already applies to
	// run-state JSON, applied here to the store. A copied or hand-placed
	// file fails it. Reported as unattributed AND flagged.
	BreadcrumbMismatched
	// BreadcrumbOK: parses, known schema, key matches. Attributed.
	BreadcrumbOK
)

// Trustworthy reports whether state names an ATTRIBUTED store — the only
// state `snug engine gc` may use Target and LastUsed from.
func (s BreadcrumbState) Trustworthy() bool { return s == BreadcrumbOK }

// ReadBreadcrumb reads engines/<key>/store.json through keyDir, the
// already-opened, already-verified (owned, exactly 0700) per-key directory —
// see internal/engine's OpenStore. key is the directory's OWN name, i.e. the
// index this reads the claim against, never a value taken from the file
// itself.
func ReadBreadcrumb(keyDir *os.Root, key string) (Breadcrumb, BreadcrumbState) {
	f, err := keyDir.Open(breadcrumbName)
	if err != nil {
		// EVERY open failure is folded into BreadcrumbMissing here, not just
		// fs.ErrNotExist — safe because keyDir is ALWAYS our own directory,
		// created by verifyEngineStore's SecureSubdir at exactly 0700 and
		// opened by OpenStore through the same strict, non-creating check
		// (vdir.OpenExistingSubdir). There is no permission boundary between
		// this process and a file one level inside a directory it owns at
		// 0700, so a non-ENOENT error here would be a filesystem fault, not
		// an access question — reporting it as "no breadcrumb" rather than a
		// hard error is the same judgement call this file makes throughout:
		// an unreadable store.json degrades to unattributed, never to a
		// refusal that blocks the rest of the report.
		return Breadcrumb{}, BreadcrumbMissing
	}
	defer f.Close()

	var bc Breadcrumb
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bc); err != nil {
		return Breadcrumb{}, BreadcrumbCorrupt
	}
	if bc.Schema != BreadcrumbSchema {
		return bc, BreadcrumbCorrupt
	}
	if bc.Target == "" || strings.ContainsFunc(bc.Target, policy.IsForgingRune) {
		return bc, BreadcrumbCorrupt
	}
	want := KeyForTarget(bc.Target)
	if want != key {
		// A legacy-named directory (issue #349: pre-label, the bare 64-hex
		// digest) whose breadcrumb hashes to the CURRENT labelled form of
		// the same digest is snug's own rename landing on a directory it
		// has not renamed yet, not a hand-placed or hostile file — treat it
		// as attributed rather than flagging a mismatch that does not exist.
		if "sha256_"+key == want {
			return bc, BreadcrumbOK
		}
		return bc, BreadcrumbMismatched
	}
	return bc, BreadcrumbOK
}

// writeBreadcrumb publishes or refreshes engines/<key>/store.json, called by
// New at every engine start — "written by snug at engine start", not by the
// engine (see Breadcrumb.LastUsed's own doc comment for why).
//
// Created is preserved across refreshes: a warm store's SECOND, THIRD, ...
// run must not reset its own age, so this reads whatever is already there
// (through the same ReadBreadcrumb a report uses) and keeps its Created
// field whenever the read produced one at all — including a MISMATCHED
// breadcrumb, which still carries a real Created timestamp worth keeping,
// just not a Target worth trusting.
//
// Written through a temp file and renamed into place, 0600, following
// internal/cli/targetstate.go's writeTargetState — the same reasoning
// applies here: a reader arriving mid-write must never see a half-written
// file, and O_EXCL on the final name would be wrong because reuse is the
// ordinary case.
//
// A write failure is NOT fatal to the run — it leaves this store
// unattributed, which New reports to its caller as a non-fatal warning
// rather than swallowing silently.
func writeBreadcrumb(keyDir *os.Root, keyPath, key, target string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	created := now
	if existing, state := ReadBreadcrumb(keyDir, key); state != BreadcrumbMissing && state != BreadcrumbCorrupt {
		if existing.Created != "" {
			created = existing.Created
		}
	}

	bc := Breadcrumb{
		Schema:   BreadcrumbSchema,
		Target:   target,
		Created:  created,
		LastUsed: now,
	}
	blob, err := json.MarshalIndent(bc, "", "  ")
	if err != nil {
		return fmt.Errorf("engine store breadcrumb: rendering: %w", err)
	}
	blob = append(blob, '\n')

	tmp := fmt.Sprintf("%s.tmp-%d", breadcrumbName, os.Getpid())
	_ = keyDir.Remove(tmp) // a previous crash's leftover, not an error

	f, err := keyDir.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("engine store breadcrumb: creating %s: %w", filepath.Join(keyPath, tmp), err)
	}
	if _, werr := f.Write(blob); werr != nil {
		f.Close()
		_ = keyDir.Remove(tmp)
		return fmt.Errorf("engine store breadcrumb: writing %s: %w", filepath.Join(keyPath, tmp), werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = keyDir.Remove(tmp)
		return fmt.Errorf("engine store breadcrumb: closing %s: %w", filepath.Join(keyPath, tmp), cerr)
	}
	if rerr := keyDir.Rename(tmp, breadcrumbName); rerr != nil {
		_ = keyDir.Remove(tmp)
		return fmt.Errorf("engine store breadcrumb: renaming into place: %w", rerr)
	}
	return nil
}
