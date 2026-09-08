package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// runScopedFixturePolicy resolves a policy that carries BOTH shapes
// describeShared's own doc comment distinguishes — a RunScoped row (this
// run's own container-proxy socket, and the engine's sock/conf grafts) and a
// row that is not (the target bind, and the engine's store/runroot grafts,
// both keyed by the target hash alone) — by driving the exact path `snug
// --dry-run -p @podman-socket` takes: resolveFor, then startContainers with
// dryRun=true, which is where BindSocket and GraftPathsInto actually run
// (container.go, engine/paths.go). A policy built by hand would only be this
// test's own opinion about which fields BindSocket sets; this is the real
// writer.
func runScopedFixturePolicy(t *testing.T) *policy.Policy {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})
	ctr, err := startContainers(policy.OSEnviron{}, p, nil, false, true)
	if err != nil {
		t.Fatalf("startContainers(dryRun=true): %v", err)
	}
	t.Cleanup(ctr.cleanup)
	return p
}

// jsonRunScopedRow is the shared shape TestJSONRunScopedMatchesThePolicyForEveryRow
// and TestJSONRunScopedSharedSetAgreesWithDescribeShared both decode: fewer
// fields than jsonMount/jsonGraft carry, but only the ones a consumer needs
// to reproduce the SHARED block's own filter.
type jsonRunScopedRow struct {
	Guest     string `json:"guest"`
	Host      string `json:"host"`
	Kind      string `json:"kind"`
	Access    string `json:"access"`
	RunScoped bool   `json:"run_scoped"`
}

func decodeMountsAndGrafts(t *testing.T, doc []byte) (mounts, grafts []jsonRunScopedRow) {
	t.Helper()
	var parsed struct {
		Mounts []jsonRunScopedRow `json:"mounts"`
		Grafts []jsonRunScopedRow `json:"grafts"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("the JSON renderer did not produce a parseable document: %v", err)
	}
	return parsed.Mounts, parsed.Grafts
}

// TestRunScopedFieldsAreNeverOmitempty is FINDING 2's own reason the key must
// survive a false value: a consumer auditing what two sessions on one target
// share cannot branch on whether "run_scoped" exists, because false — an
// ordinary shared row — is exactly as informative as true.
func TestRunScopedFieldsAreNeverOmitempty(t *testing.T) {
	for _, tc := range []struct {
		typ   reflect.Type
		field string
	}{
		{reflect.TypeFor[jsonMount](), "HostIsRunScoped"},
		{reflect.TypeFor[jsonGraft](), "HostIsRunScoped"},
	} {
		f, ok := tc.typ.FieldByName(tc.field)
		if !ok {
			t.Fatalf("%s has no field %s", tc.typ, tc.field)
		}
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			t.Fatalf("%s.%s has no json tag", tc.typ, tc.field)
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name != "run_scoped" {
			t.Errorf("%s.%s marshals as %q, want \"run_scoped\"", tc.typ, tc.field, name)
		}
		if strings.Contains(opts, "omitempty") {
			t.Errorf("%s.%s is omitempty (%q): a run-scoped=false row would then read "+
				"identically to a format that never carried this key at all, which is the "+
				"exact gap this field exists to close", tc.typ, tc.field, tag)
		}
	}
}

// TestRunScopedKeyIsPresentOnEveryRowIncludingFalse decodes into
// map[string]any rather than a typed struct on purpose: a typed field is
// present in Go whether or not encoding/json wrote it, so a struct-only
// check cannot tell "the key is in the document" from "the zero value filled
// in a field the encoder never touched". This is the raw-bytes half of that
// question, on the ordinary default selection — no @podman-socket, so every
// row is expected false — which is precisely the case that used to carry NO
// key of this name at all before the fix in this change.
func TestRunScopedKeyIsPresentOnEveryRowIncludingFalse(t *testing.T) {
	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"})
	args := p.BwrapArgs(0, 0)
	var buf bytes.Buffer
	if err := dryRun(policy.OSEnviron{}, &buf, p, args, config{json: true}, nil, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}

	var raw struct {
		Mounts []map[string]any `json:"mounts"`
		Grafts []map[string]any `json:"grafts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("the JSON renderer did not produce a parseable document: %v", err)
	}
	if len(raw.Mounts) == 0 {
		t.Fatal("the document lists no mounts; the assertions below would pass over an empty set")
	}
	for _, m := range raw.Mounts {
		v, ok := m["run_scoped"]
		if !ok {
			t.Errorf("mount %v has no \"run_scoped\" key", m["guest"])
			continue
		}
		if v != false {
			t.Errorf("mount %v has run_scoped=%v on a selection with no @podman-socket, "+
				"where nothing should ever be run-scoped", m["guest"], v)
		}
	}
	// grafts[] is empty on this selection (no container profile, so no
	// engine view at all) — asserted so a change that started omitting the
	// key would not hide behind an empty array here.
	if len(raw.Grafts) != 0 {
		t.Errorf("a selection with no container profile produced %d grafts, want 0", len(raw.Grafts))
	}
}

// TestJSONRunScopedMatchesThePolicyForEveryRow is the TRUE/FALSE half FINDING
// 2 asks for, and it derives every expectation from the resolved policy
// itself — p.Mounts[guest].RunScoped, p.Grafts[guest].RunScoped — rather than
// naming a guest path here and hoping it stays the one BindSocket or
// GraftPathsInto actually marks.
func TestJSONRunScopedMatchesThePolicyForEveryRow(t *testing.T) {
	p := runScopedFixturePolicy(t)

	// POSITIVE CONTROL: the fixture must actually mix both shapes, or every
	// comparison below is trivially true regardless of whether the JSON
	// field is wired to anything.
	var haveRunScoped, haveShared bool
	for _, m := range p.Mounts {
		if m.RunScoped {
			haveRunScoped = true
		} else {
			haveShared = true
		}
	}
	for _, g := range p.Grafts {
		if g.RunScoped {
			haveRunScoped = true
		} else {
			haveShared = true
		}
	}
	if !haveRunScoped || !haveShared {
		t.Fatalf("the fixture policy does not carry both a run-scoped and a shared row "+
			"(run-scoped seen=%v, shared seen=%v); every assertion below would pass on a "+
			"policy shaped nothing like a real @podman-socket run", haveRunScoped, haveShared)
	}

	args := p.BwrapArgs(0, 0)
	var buf bytes.Buffer
	if err := dryRun(policy.OSEnviron{}, &buf, p, args, config{json: true}, nil, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}
	mounts, grafts := decodeMountsAndGrafts(t, buf.Bytes())

	fromJSON := map[string]bool{}
	for _, m := range mounts {
		fromJSON[m.Guest] = m.RunScoped
	}
	for _, m := range p.Mounts {
		got, ok := fromJSON[m.Guest]
		if !ok {
			t.Errorf("mount %q is in the policy and missing from mounts[]", m.Guest)
			continue
		}
		if got != m.RunScoped {
			t.Errorf("mount %q: mounts[].run_scoped=%v, policy.Mount.RunScoped=%v", m.Guest, got, m.RunScoped)
		}
	}

	fromJSONGraft := map[string]bool{}
	for _, g := range grafts {
		fromJSONGraft[g.Guest] = g.RunScoped
	}
	for guest, g := range p.Grafts {
		got, ok := fromJSONGraft[guest]
		if !ok {
			t.Errorf("graft %q is in the policy and missing from grafts[]", guest)
			continue
		}
		if got != g.RunScoped {
			t.Errorf("graft %q: grafts[].run_scoped=%v, policy.Graft.RunScoped=%v", guest, got, g.RunScoped)
		}
	}
}

// describeSharedGuests pulls the row paths out of describeShared's own
// rendering: the SHARED block's list of writable host paths a second sandbox
// on this target could meet this one on. It parses the SCREEN, not p.Mounts
// / p.Grafts again, for TestJSONRunScopedSharedSetAgreesWithDescribeShared's
// own reason — reading the policy on both sides would compare the JSON to
// the source it was itself derived from, which cannot show the two
// renderings disagreeing.
func describeSharedGuests(screen string) map[string]bool {
	out := map[string]bool{}
	in := false
	for _, line := range strings.Split(screen, "\n") {
		switch {
		case strings.HasPrefix(line, "         The writable host paths"):
			in = true
			continue
		case strings.HasPrefix(line, "         Where they do meet"):
			return out
		case !in:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
			continue
		}
		out[fields[0]] = true
	}
	return out
}

// jsonSharedGuests reproduces describeShared's own filter from the document
// alone: KindBind + AccessRW + !RunScoped for a mount, AccessRW + a non-empty
// Host + !RunScoped for a graft — the two predicates dryrun.go's describeShared
// itself uses (m.Kind == policy.KindBind && m.Access == policy.AccessRW &&
// !m.RunScoped, and gr.Access == policy.AccessRW && gr.Host != "" &&
// !gr.RunScoped). Anything a consumer derives this way must be exactly what a
// human reading --dry-run without --json sees, or the two renderings can
// disagree about what a second session on this target may reach — the gap
// FINDING 2 closed.
func jsonSharedGuests(mounts, grafts []jsonRunScopedRow) map[string]bool {
	out := map[string]bool{}
	for _, m := range mounts {
		if m.Kind == "bind" && m.Access == "rw" && !m.RunScoped {
			out[m.Guest] = true
		}
	}
	for _, g := range grafts {
		if g.Access == "rw" && g.Host != "" && !g.RunScoped {
			out[g.Guest] = true
		}
	}
	return out
}

// TestJSONRunScopedSharedSetAgreesWithDescribeShared is FINDING 2's actual
// claim: the set a consumer derives from mounts[]/grafts[] using run_scoped
// must equal what the human SHARED block prints, on the identical policy. Not
// "the field exists" — that two renderings of the same fact cannot drift
// apart, which is the property TestEveryFactProducerTheHumanScreenCallsIsAlsoInTheReport
// could not have caught here: describeShared reads p.Mounts/p.Grafts fields
// directly rather than calling a named producer function, so it is invisible
// to that sweep's call-graph walk by construction, not by an oversight in
// its exemption list.
func TestJSONRunScopedSharedSetAgreesWithDescribeShared(t *testing.T) {
	p := runScopedFixturePolicy(t)

	human := captureFile(t, func(w io.Writer) { describeShared(w, p) })
	humanGuests := describeSharedGuests(human)

	args := p.BwrapArgs(0, 0)
	var buf bytes.Buffer
	if err := dryRun(policy.OSEnviron{}, &buf, p, args, config{json: true}, nil, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}
	mounts, grafts := decodeMountsAndGrafts(t, buf.Bytes())
	jsonGuests := jsonSharedGuests(mounts, grafts)

	if len(humanGuests) == 0 || len(jsonGuests) == 0 {
		t.Fatalf("one of the two renderings listed NO shared rows (human %d, json %d) — a "+
			"comparison of two empty sets passes and tests nothing", len(humanGuests), len(jsonGuests))
	}
	for g := range jsonGuests {
		if !humanGuests[g] {
			t.Errorf("%q is in the JSON-derived shared set and not in describeShared's own "+
				"SHARED block — a consumer would report a path as shared that the human "+
				"screen does not", g)
		}
	}
	for g := range humanGuests {
		if !jsonGuests[g] {
			t.Errorf("%q is in describeShared's SHARED block and not in the JSON-derived "+
				"shared set — a consumer auditing this policy would miss a path the human "+
				"screen names, which is exactly FINDING 2's gap", g)
		}
	}

	// POSITIVE CONTROL on the PARSER: a guest the fixture policy does not
	// grant must not turn up in either extraction.
	if humanGuests["/definitely-not-granted"] || jsonGuests["/definitely-not-granted"] {
		t.Error("one of the two extractors found a path the policy does not grant — it is " +
			"matching something other than a shared row")
	}
}
