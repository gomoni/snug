package policy

import (
	"reflect"
	"testing"
)

// includeSetRegistry is testRegistry plus profiles whose includes form the
// shapes under test, each granting a distinct read-only path so a dropped
// member shows as a missing mount.
func includeSetRegistry() map[ProfileName]*Profile {
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Include: []ProfileName{"b"}, RO: []string{"/opt/a"}}
	reg["b"] = &Profile{Name: "b", Include: []ProfileName{"a"}, RO: []string{"/opt/b"}}
	reg["solo"] = &Profile{Name: "solo", Include: []ProfileName{"solo"}, RO: []string{"/opt/solo"}}
	reg["c1"] = &Profile{Name: "c1", Include: []ProfileName{"c2"}, RO: []string{"/opt/c1"}}
	reg["c2"] = &Profile{Name: "c2", Include: []ProfileName{"c3"}, RO: []string{"/opt/c2"}}
	reg["c3"] = &Profile{Name: "c3", Include: []ProfileName{"c1"}, RO: []string{"/opt/c3"}}
	return reg
}

func withDefaults(names ...ProfileName) []ProfileName {
	return append(append([]ProfileName{}, testDefaults...), names...)
}

func includeSetEnv() *fakeEnv {
	env := newFakeEnv()
	for _, d := range []string{"/opt/a", "/opt/b", "/opt/solo"} {
		env.dirs[d] = true
	}
	return env
}

func TestIncludeCycleResolvesAsASet(t *testing.T) {
	reg := includeSetRegistry()
	env := includeSetEnv()
	via, err := Resolve(reg, withDefaults("a"), testCtx(), env)
	if err != nil {
		t.Fatalf("a <-> b is the set {a, b}, not an error: %v", err)
	}
	direct, err := Resolve(reg, withDefaults("a", "b"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	// Selected records what was typed, which is the one thing that differs.
	via.Selected, direct.Selected = nil, nil
	if !reflect.DeepEqual(via, direct) {
		t.Errorf("-p a resolved differently from -p a -p b:\n%+v\n%+v", via, direct)
	}
	for _, path := range []string{"/opt/a", "/opt/b"} {
		if _, ok := via.Mounts[path]; !ok {
			t.Errorf("%s missing: the cycle dropped a member", path)
		}
	}
}

func TestSelfIncludeResolvesAsTheProfileAlone(t *testing.T) {
	reg := includeSetRegistry()
	env := includeSetEnv()
	self, err := Resolve(reg, withDefaults("solo"), testCtx(), env)
	if err != nil {
		t.Fatalf("a self-include is the profile alone, not an error: %v", err)
	}
	reg["solo"] = &Profile{Name: "solo", RO: []string{"/opt/solo"}}
	plain, err := Resolve(reg, withDefaults("solo"), testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := self.Mounts["/opt/solo"]; !ok {
		t.Error("/opt/solo missing from the self-including profile")
	}
	if !reflect.DeepEqual(self.Mounts, plain.Mounts) {
		t.Errorf("self-include mounts differ from the profile alone:\n%+v\n%+v", self.Mounts, plain.Mounts)
	}
}

func TestLongerIncludeCycleResolvesAsASet(t *testing.T) {
	got, err := Expand(includeSetRegistry(), []ProfileName{"c1"})
	if err != nil {
		t.Fatalf("c1 -> c2 -> c3 -> c1 is a set, not an error: %v", err)
	}
	if len(got) != 3 || got["c1"] == nil || got["c2"] == nil || got["c3"] == nil {
		t.Errorf("closure = %v, want exactly {c1, c2, c3}", got)
	}
}

func TestUnknownNameInsideACycleIsStillRefused(t *testing.T) {
	reg := includeSetRegistry()
	reg["b"] = &Profile{Name: "b", Include: []ProfileName{"a", "sys"}}
	_, err := Resolve(reg, []ProfileName{"a"}, testCtx(), newFakeEnv())
	want := UnknownProfile(reg, "sys")
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("got %v, want %v", err, want)
	}
}
