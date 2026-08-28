package cli

import (
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
)

// ── the container engine's delegated subuid/subgid range ────────────────────
//
// doctor probed the podman client and podman's helper binaries and stopped one
// step short of the requirement most likely to be missing: a delegated id
// range in /etc/subuid and /etc/subgid. The check already existed —
// stage.CheckSubuidDelegation — with one caller, container preflight P2, which
// is FATAL and fires only once a run is being set up. So a host with no range
// got eleven ticks and `🎉 This host can run snug`, and then a fatal refusal
// from a different command the first time a `-p @podman-*` profile was asked
// for (issue #483).
//
// WARN, never fail, and it does not touch doctor's exit code. An offline
// sandbox genuinely does not need a delegated range: snug's own sandbox maps
// one uid with no helper (SUPERVISOR-DESIGN.md §3.6) and deriveTopology sets
// SubuidFull only from the podman branch (internal/policy/topology.go). @net
// does not need one either. Turning a usable host red for a capability nobody
// asked for is the same bug facing the other way.
func reportSubuidDelegation(check func() error, h subuidHost) {
	err := check()
	if err == nil {
		fmt.Println("  ✅ a delegated subuid/subgid range the container engine can use")
		return
	}

	fmt.Println("  ⚠️  no delegated subuid/subgid range — container profiles will refuse to start")
	fmt.Printf("     💬 %v\n", err)

	// The example the checker's own message carries is the conventional one,
	// and inside a container it names nothing at all: a keep-id box's uid_map
	// ends at 65535, so `100000:65536` is a range this namespace cannot map.
	// Suggest the line THIS namespace can actually delegate, computed from the
	// map rather than from a marker file.
	base, size, okSuggest := subuidSuggestion(h.idMap, uint64(h.uid))
	if okSuggest {
		fmt.Printf("     🔧 add this line to BOTH /etc/subuid and /etc/subgid:  %s:%d:%d\n",
			h.name, base, size)
		if base != conventionalSubuidBase {
			fmt.Printf("        (not the conventional %d — this namespace's uid_map cannot map it)\n",
				conventionalSubuidBase)
		}
	}
	if h.container != "" {
		fmt.Println("     📦 /etc/subuid lives in the container image, so it goes away on every")
		fmt.Println("        rebuild of this box and has to be added again")
	}
	fmt.Println("     🔒 only the container profiles need this; offline and net sandboxes are unaffected")
}

// subuidHost is everything the report reads about the machine, gathered by
// currentSubuidHost and passed in rather than looked up inside.
//
// Not a style preference: the first version called os.Getuid() and
// user.LookupId() from inside the printer, so its test asserted whatever the
// machine running it happened to be. Green here (uid 1000, suggestion
// `michal:1001:64535`) and RED in CI, where the runner is uid 1001 and the
// same map yields `runner:1002:64534`. A test that reads the host cannot
// assert what the host should have been told.
type subuidHost struct {
	// idMap is /proc/self/uid_map, "" when it could not be read — the
	// suggestion is then omitted rather than guessed.
	idMap string
	// uid is the caller's own id, which delegateSubuid spends on the child
	// map's namespace-0 line and so cannot also delegate.
	uid int
	// name is the owner column an /etc/subuid line needs.
	name string
	// container is containerMarker(), "" on a bare host.
	container string
}

func currentSubuidHost() subuidHost {
	return subuidHost{
		idMap:     readIDMap(),
		uid:       os.Getuid(),
		name:      subuidEntryName(),
		container: containerMarker(),
	}
}

// conventionalSubuidBase is the base every distribution's useradd writes and
// every subuid(5) example uses. It is a suggestion, not a rule the kernel
// knows: what makes a base valid is that /proc/self/uid_map can map it.
const conventionalSubuidBase = 100000

// conventionalSubuidSize is the second half of that convention, and doubles as
// the cap on anything suggested instead — a delegated range wider than 65536
// is more than any engine here asks for.
const conventionalSubuidSize = 65536

// idInterval is one contiguous run of ids, [start, start+count).
type idInterval struct{ start, count uint64 }

// subuidSuggestion returns the base and size of an /etc/subuid line this
// namespace can actually delegate, or ok=false when it can delegate nothing.
//
// A subuid range names ids IN THIS NAMESPACE, and newuidmap can only write a
// child map over ids the current namespace itself maps — so the candidates are
// exactly the ns column of /proc/self/uid_map, minus ownID, which delegateSubuid
// already spends on the "namespace id 0 → my own id" line.
//
// The conventional base wins whenever it fits. When it does not, the HIGHEST
// free run is taken rather than the widest: a low id in this namespace names
// somebody — in the measured distrobox map below, ns 999 is host uid 1000, the
// user themselves — so a wider suggestion down there would be a wider
// suggestion to delegate real accounts. Namespace id 0 is punched out for the
// same reason and never appears in a suggestion.
//
// MEASURED on this project's distrobox: uid_map is {0→1 ×1000, 1000→0 ×1,
// 1001→1001 ×64535}, the map ends at 65535 so nothing fits at 100000, and the
// line that works there is `1001:64535` — what this returns.
func subuidSuggestion(idMapContent string, ownID uint64) (base, size uint64, ok bool) {
	free := withoutID(withoutID(mergeIntervals(parseIDMapNS(idMapContent)), 0), ownID)
	for _, iv := range free {
		if iv.start <= conventionalSubuidBase &&
			conventionalSubuidBase+conventionalSubuidSize <= iv.start+iv.count {
			return conventionalSubuidBase, conventionalSubuidSize, true
		}
	}
	best := idInterval{}
	found := false
	for _, iv := range free {
		if !found || iv.start > best.start {
			best, found = iv, true
		}
	}
	if !found {
		return 0, 0, false
	}
	if best.count > conventionalSubuidSize {
		best.count = conventionalSubuidSize
	}
	return best.start, best.count, true
}

// parseIDMapNS reads the NAMESPACE column of a uid_map/gid_map — "nsStart
// hostStart count" per line — and ignores anything that is not three numbers,
// so a read that returned an error message rather than a map yields nothing
// and the caller suggests nothing (the parseNetDev rule: a probe that cannot
// look must not answer).
func parseIDMapNS(content string) []idInterval {
	var out []idInterval
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		start, err1 := strconv.ParseUint(f[0], 10, 64)
		count, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil || count == 0 {
			continue
		}
		out = append(out, idInterval{start: start, count: count})
	}
	return out
}

// mergeIntervals sorts and coalesces, so two adjacent uid_map lines read as the
// one run they are.
func mergeIntervals(in []idInterval) []idInterval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].start < in[j].start })
	out := []idInterval{in[0]}
	for _, iv := range in[1:] {
		last := &out[len(out)-1]
		if iv.start <= last.start+last.count {
			if end := iv.start + iv.count; end > last.start+last.count {
				last.count = end - last.start
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// withoutID punches one id out of the merged runs. Called twice, for two
// different reasons: the caller's own id, because delegateSubuid has already
// spent it on the child map's namespace-0 line and newuidmap refuses a map
// whose ranges overlap; and namespace id 0, which is never something to hand a
// container.
func withoutID(in []idInterval, id uint64) []idInterval {
	var out []idInterval
	for _, iv := range in {
		if id < iv.start || id >= iv.start+iv.count {
			out = append(out, iv)
			continue
		}
		if before := id - iv.start; before > 0 {
			out = append(out, idInterval{start: iv.start, count: before})
		}
		if after := iv.start + iv.count - id - 1; after > 0 {
			out = append(out, idInterval{start: id + 1, count: after})
		}
	}
	return out
}

// readIDMap returns /proc/self/uid_map, or "" when it cannot be read — the
// suggestion is then simply omitted rather than guessed.
func readIDMap() string {
	// HOSTREAD-EXEMPT: a /proc literal, a kernel pseudo-file no host path an
	// attacker controls can be substituted for.
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return ""
	}
	return string(b)
}

// subuidEntryName is the owner column an /etc/subuid line needs: the username
// when this uid has one, the number when it does not. subuid(5) accepts both.
func subuidEntryName() string {
	uid := os.Getuid()
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}
