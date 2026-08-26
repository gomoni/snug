package cli

import (
	"strings"
	"testing"
)

// ociRuntimeCase is the whole input space of preflightOCIRuntime: three
// booleans, eight rows, enumerated rather than sampled. The table is testable
// on any host precisely because the three lookups are parameters — the case
// that produced the 500 cannot be constructed on a host that has crun.
type ociRuntimeCase struct {
	crun, runc, cgroupsDisabled bool
	wantName                    string
	wantRefusal                 bool
}

func ociRuntimeCases() []ociRuntimeCase {
	return []ociRuntimeCase{
		// crun present: it serves both modes, and is pinned only where the
		// mode needs pinning.
		{true, true, true, "crun", false},
		{true, true, false, "", false},
		{true, false, true, "crun", false},
		{true, false, false, "", false},

		// THE LOAD-BEARING NEGATIVE. runc alone, cgroups fine: runc serves
		// this, and it is the host that authoring runtime = "crun"
		// unconditionally would have broken. It must return no error AND no
		// name.
		{false, true, false, "", false},

		// runc alone, cgroups disabled: the measured 500's own host.
		{false, true, true, "", true},

		{false, false, true, "", true},
		{false, false, false, "", true},
	}
}

func (c ociRuntimeCase) name() string {
	return "crun=" + b(c.crun) + " runc=" + b(c.runc) + " cgroupsDisabled=" + b(c.cgroupsDisabled)
}

func b(v bool) string {
	if v {
		return "y"
	}
	return "n"
}

// TestPreflightRefusesCgroupsDisabledWithoutCrun is P10's table. The row that
// matters most is the one where NOTHING happens: (crun=n, runc=y,
// cgroupsDisabled=n) must return "" and no error, because runc serves that
// host today and a pin there would refuse or redirect a working run.
func TestPreflightRefusesCgroupsDisabledWithoutCrun(t *testing.T) {
	for _, c := range ociRuntimeCases() {
		t.Run(c.name(), func(t *testing.T) {
			got, err := preflightOCIRuntime(c.crun, c.runc, c.cgroupsDisabled)
			if (err != nil) != c.wantRefusal {
				t.Fatalf("preflightOCIRuntime(%v, %v, %v) error = %v, want refusal = %v",
					c.crun, c.runc, c.cgroupsDisabled, err, c.wantRefusal)
			}
			if got != c.wantName {
				t.Fatalf("preflightOCIRuntime(%v, %v, %v) name = %q, want %q",
					c.crun, c.runc, c.cgroupsDisabled, got, c.wantName)
			}
		})
	}
}

// TestDoctorAndPreflightShareOneOCIRuntimeRule is the test that stops the rule
// being copied a second time, and it is the whole repair of the divergence
// #425's crun half is about: ociRuntimeMissing held this rule with `snug
// doctor` as its only consumer, while the package that CREATES the condition
// never asked it. If a later change gives P10 its own table, this fails.
func TestDoctorAndPreflightShareOneOCIRuntimeRule(t *testing.T) {
	for _, c := range ociRuntimeCases() {
		t.Run(c.name(), func(t *testing.T) {
			_, err := preflightOCIRuntime(c.crun, c.runc, c.cgroupsDisabled)
			missing := ociRuntimeMissing(c.crun, c.runc, c.cgroupsDisabled)
			if (err != nil) != missing {
				t.Fatalf("doctor and the run disagree for crun=%v runc=%v cgroupsDisabled=%v: "+
					"ociRuntimeMissing = %v but preflightOCIRuntime error = %v. These must be "+
					"one decision with two consumers — doctor reports on it, the run refuses "+
					"on it — or a host doctor calls broken still starts an engine, and a host "+
					"doctor passes still refuses",
					c.crun, c.runc, c.cgroupsDisabled, missing, err)
			}
		})
	}
}

// TestPreflightPinsARuntimeWheneverCgroupsAreDisabled is the property that
// makes the two-file change ONE decision: writeContainersConf can never emit
// `cgroups = "disabled"` with no runtime named, because every input that
// reaches it with cgroupsDisabled set also carries "crun".
func TestPreflightPinsARuntimeWheneverCgroupsAreDisabled(t *testing.T) {
	for _, c := range ociRuntimeCases() {
		t.Run(c.name(), func(t *testing.T) {
			name, err := preflightOCIRuntime(c.crun, c.runc, c.cgroupsDisabled)
			if err != nil {
				return // refused; nothing is authored at all
			}
			switch {
			case c.cgroupsDisabled && name != "crun":
				t.Fatalf("cgroups are disabled and P10 pinned %q: podman would pick its own "+
					"runtime, and runc does not implement the mode snug just wrote", name)
			case !c.cgroupsDisabled && name != "":
				t.Fatalf("cgroups work and P10 pinned %q: both runtimes serve here, so pinning "+
					"one chooses on podman's behalf for no reason", name)
			}
		})
	}
}

// TestTheOCIRuntimeRefusalNamesTheFix holds CLAUDE.md's "errors name the fix"
// rule on both refusal arms, and holds the cgroups arm's advice to crun
// SPECIFICALLY — "crun or runc" is the advice that produced the measured 500.
func TestTheOCIRuntimeRefusalNamesTheFix(t *testing.T) {
	t.Run("cgroups disabled, runc only", func(t *testing.T) {
		_, err := preflightOCIRuntime(false, true, true)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		got := err.Error()
		for _, want := range []string{"install crun", "NoCgroups", "P5"} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal does not mention %q, so a reader cannot tell what to do "+
					"or why:\n%s", want, got)
			}
		}
		if strings.Contains(got, "crun or runc\" is the") || strings.Contains(got, "install crun or runc") {
			t.Errorf("the refusal advises \"crun or runc\", which is the advice that produced "+
				"the measured 500:\n%s", got)
		}
	})

	t.Run("neither runtime", func(t *testing.T) {
		_, err := preflightOCIRuntime(false, false, false)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if !strings.Contains(err.Error(), "install crun") {
			t.Errorf("the refusal does not name the fix:\n%s", err)
		}
	})
}
