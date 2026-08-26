package stage

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// CheckSubuidDelegation reports whether /etc/subuid and /etc/subgid each
// carry a range for the calling process's own uid/gid, and whether
// newuidmap/newgidmap can be found on PATH — everything Start's own
// SubuidFull path (delegateSubuid, below) will need, checked EARLY so a
// caller can refuse before creating anything (issue #63, Tier B preflight
// P2/P3; ENGINE-WIRING.md §4). It does not check newuidmap/newgidmap's
// AUTHORITY to actually write a multi-range map (file capabilities or
// setuid) — that surfaces, already named clearly, from the tool's own stderr
// the one time delegateSubuid actually runs it.
func CheckSubuidDelegation() error {
	hostUID, hostGID := os.Getuid(), os.Getgid()
	if _, err := lookupIDRange("/etc/subuid", hostUID); err != nil {
		return err
	}
	if _, err := lookupIDRange("/etc/subgid", hostGID); err != nil {
		return err
	}
	if _, err := findIDMapTool("newuidmap"); err != nil {
		return err
	}
	if _, err := findIDMapTool("newgidmap"); err != nil {
		return err
	}
	return nil
}

// idRange is one line of /etc/subuid or /etc/subgid: SIZE ids starting at
// BASE, delegated to the host user this process runs as.
type idRange struct {
	base, size uint32
}

// lookupIDRange reads path (/etc/subuid or /etc/subgid) and returns the FIRST
// line delegated to the calling process's own real id — matched by username
// first (the conventional spelling, "alice:100000:65536") and by the numeric
// uid/gid second (some hosts write the id instead of the name, and both are
// legal per subuid(5)).
//
// Matching only the caller's OWN id is deliberate and is not merely the
// common case: newuidmap enforces the identical rule server-side (a range
// belongs to the real uid that invoked it), so a lookup that matched a WIDER
// set of lines would just be rejected one step later with a less specific
// error. Doing the same match here first is what lets the refusal name the
// fix ("add a line for this user") instead of relayed newuidmap stderr.
func lookupIDRange(path string, id int) (idRange, error) {
	// HOSTREAD-EXEMPT: every caller passes a literal, "/etc/subuid" or
	// "/etc/subgid"; path is a parameter only so a test can point it at a
	// fixture.
	f, err := os.Open(path)
	if err != nil {
		return idRange{}, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	name := ""
	if u, err := user.LookupId(strconv.Itoa(id)); err == nil {
		name = u.Username
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			continue
		}
		owner := fields[0]
		if owner != strconv.Itoa(id) && (name == "" || owner != name) {
			continue
		}
		base, err1 := strconv.ParseUint(fields[1], 10, 32)
		size, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		return idRange{base: uint32(base), size: uint32(size)}, nil
	}
	if err := sc.Err(); err != nil {
		return idRange{}, fmt.Errorf("reading %s: %w", path, err)
	}
	entryName := strconv.Itoa(id)
	display := entryName
	if name != "" {
		entryName = name
		display = name + " (id " + strconv.Itoa(id) + ")"
	}
	return idRange{}, fmt.Errorf("%s has no range for %s; add one (e.g. `%s:100000:65536`) — "+
		"a container engine needs a delegated id range", path, display, entryName)
}

// findIDMapTool resolves newuidmap/newgidmap by absolute path — required the
// moment a delegated (multi-range) map is requested, because Go's own
// UidMappings/GidMappings can only write the single "map my own id to
// namespace id 0" line unprivileged (the -map-root-user shape); anything
// wider needs a program that reads subuid(5)/subgid(5) on the caller's
// behalf. Accepting a setuid or file-capability host tool here is the
// explicit call (maintainer decision, 2026-08-18): "no root, no setuid" is
// about snug's OWN staged binaries, not a host tool it merely invokes. Note
// this SUPERSEDES issue #63's own plan text, which asked for file
// capabilities and not setuid; the setuid host tool is the common distro
// shape and is accepted. The preflight message names it either way.
func findIDMapTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found: install shadow-utils (or your distribution's "+
			"equivalent) — the container engine needs it to receive a delegated id range "+
			"without snug running as root or setuid itself", name)
	}
	return path, nil
}

// delegateSubuid asks newuidmap/newgidmap to write pid's uid_map/gid_map with
// TWO ranges: namespace id 0 mapped to the caller's own real id (exactly what
// the single-line unprivileged self-map already did for every non-podman
// stage), and namespace ids 1..size mapped onto the delegated subuid/subgid
// range — so the process ends up root-in-U AND able to chown across the full
// range podman's storage needs, in one atomic map write.
//
// pid's uid_map/gid_map MUST be unwritten when this runs (see Start's own
// comment on why Go is told to leave SysProcAttr.UidMappings/GidMappings nil
// for this path): both files can be written exactly ONCE per user namespace,
// ever, and newuidmap fails outright on a namespace that already has a map —
// which is the same write-once rule that makes "self-map now, delegate later"
// impossible and forces the whole range to be requested here, at clone time.
func delegateSubuid(pid, hostUID, hostGID int) error {
	uidTool, err := findIDMapTool("newuidmap")
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	gidTool, err := findIDMapTool("newgidmap")
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	uRange, err := lookupIDRange("/etc/subuid", hostUID)
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	gRange, err := lookupIDRange("/etc/subgid", hostGID)
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}

	if err := runIDMapTool(uidTool, pid, []idMapLine{
		{ns: 0, host: uint32(hostUID), size: 1},
		{ns: 1, host: uRange.base, size: uRange.size},
	}); err != nil {
		return fmt.Errorf("stage: delegating the subuid range: %w", err)
	}
	if err := runIDMapTool(gidTool, pid, []idMapLine{
		{ns: 0, host: uint32(hostGID), size: 1},
		{ns: 1, host: gRange.base, size: gRange.size},
	}); err != nil {
		return fmt.Errorf("stage: delegating the subgid range: %w", err)
	}
	return nil
}

type idMapLine struct{ ns, host, size uint32 }

// runIDMapTool execs newuidmap/newgidmap with one or more "ns host size"
// triples flattened onto argv, exactly the shape both tools accept
// (`newuidmap PID NSID HOSTID COUNT [NSID HOSTID COUNT ...]`).
func runIDMapTool(tool string, pid int, lines []idMapLine) error {
	args := make([]string, 0, 2+3*len(lines))
	args = append(args, strconv.Itoa(pid))
	for _, l := range lines {
		args = append(args, strconv.Itoa(int(l.ns)), strconv.Itoa(int(l.host)), strconv.Itoa(int(l.size)))
	}
	cmd := exec.Command(tool, args...)
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", tool, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
